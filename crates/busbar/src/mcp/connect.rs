// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECT / REFRESH PATH — the leg that fetches an upstream's LIVE tool list, re-hashes it, and
//! hands the result to the trust lifecycle so a rug-pull is detected instead of merely detectable.
//!
//! ## Why this file has to exist for the drift defence to defend anything
//!
//! The dispatch gate compares an APPROVED digest against an OBSERVED one. Without a live fetch there
//! is nothing observed, so the only value available on the right-hand side is the schema hash the
//! operator wrote in config — and comparing the operator's intent against the operator's intent
//! proves that the served tool matches what was approved while being structurally incapable of
//! noticing that the upstream changed its schema underneath. That is the entire failure mode
//! per-tool hash-pinning exists to close. This module supplies the missing right-hand side.
//!
//! ## Nothing here decides trust
//!
//! Every transition is `crate::trust`'s: [`crate::trust::Approval::approve`],
//! `approve_capability`, `reject_capability`, `approve_pin`, and the DERIVED state and changes queue.
//! This module fetches, parses, and calls `ServerCatalogue::observe` / `observe_failure` — which
//! re-hash from the definitions rather than adopting a digest the upstream supplied, because an
//! upstream-supplied digest is the rug-pull with an extra step. A refresh that fails is recorded as
//! a FAILURE rather than dropped: a server we could not reach must never present as trusted, and
//! silently keeping the previous observation is exactly how it would.
//!
//! ## The refresh is OUR trigger
//!
//! An operator asks for it, or a scheduled refresh does. An upstream's own
//! `notifications/tools/list_changed` can only ever bring one forward through
//! `client::catalogue::RefreshGate`, and its contents are never read — an attacker-controlled
//! trigger may not choose the moment freely and may not choose the content at all.
//!
//! ## STATED GAP: the IDENTITY axis is not independently observed on this transport
//!
//! Drift has two axes and only one of them is exercised from here. The capability axis — the digests
//! over name, description and input schema — is fully observed: it is re-hashed from the bytes the
//! upstream actually sent. The IDENTITY axis is not: the shared HTTP client does not surface the
//! peer's certificate SPKI to this layer, so a refresh has no independent evidence of who answered.
//! Rather than fabricate an observation, the observation carries the pin the operator DECLARED, and
//! this comment is the statement that a certificate rotation is therefore invisible to this path.
//! It is invisible; it is not silently reported as verified. Closing it needs the transport to
//! surface the peer certificate, which is engine surface this increment does not add.

use super::catalogue::ServerEntry;
use super::client::catalogue::{CatalogueCache, ServerCatalogue, ToolDef, TransportPin};
use super::client::egress::{ExchangeRequest, UpstreamCredential};
use super::client::identity::ServerId;
use super::client::jsonrpc::{self, RpcOutcome};
use super::client::pool::McpConnectionPool;
use super::client::ssrf::SsrfPolicy;
use super::client::transport::HttpTransport;
use crate::trust::{Drift, TrustState};
use std::time::Duration;

/// The wall-clock budget for one refresh leg. The same order as a dispatch leg, for the same reason:
/// an upstream is not trusted to answer, and an operator verb that hangs is an operator verb that
/// gets killed and retried against a half-written cache.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(30);

/// The JSON-RPC id busbar puts on a refresh request. A constant rather than a counter because this
/// revision is stateless and correlates nothing across requests; a monotonic id here would be a
/// session counter with no session to belong to.
const REFRESH_REQUEST_ID: u64 = 1;

/// WHAT A REFRESH FOUND, in the operator's vocabulary. Every field is derived, none is stored:
/// the state and the changes queue are recomputed from the approval and the sighting on read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConnectReport {
    pub(crate) server: String,
    /// The DERIVED trust state after the refresh landed.
    pub(crate) state: TrustState,
    /// What the operator has to work before this server serves again.
    pub(crate) drift: Drift,
    /// How many tools the upstream offered. Reported so "the refresh succeeded" and "the refresh
    /// succeeded and the list is empty" are distinguishable without reading the drift.
    pub(crate) observed: usize,
    /// The failure, when the contact failed. `Some` here and a `state` of `Error` are the same fact
    /// seen twice, deliberately: the operator needs the reason and the machine needs the state.
    pub(crate) failure: Option<String>,
}

impl ConnectReport {
    /// The operator-facing word for the state. Named once so a rendering cannot invent a sixth.
    pub(crate) fn state_word(&self) -> &'static str {
        match self.state {
            TrustState::Pending => "pending",
            TrustState::Approved => "approved",
            TrustState::Quarantined => "quarantined",
            TrustState::Suspended => "suspended",
            TrustState::Error => "error",
        }
    }
}

/// Why a refresh could not even be attempted. Distinct from a refresh that was attempted and failed:
/// one is a configuration the operator has to fix, the other is a network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RefreshRefusal {
    /// The registered ids do not form a valid routing key.
    Malformed(String),
    /// The operator's credential posture cannot be honoured for an operator-driven refresh.
    Credential(String),
}

impl std::fmt::Display for RefreshRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefreshRefusal::Malformed(m) => write!(f, "{m}"),
            RefreshRefusal::Credential(m) => write!(f, "{m}"),
        }
    }
}

/// PARSE a `tools/list` result into definitions, or say why it is not one.
///
/// Strict about the shape and lenient about nothing. A missing `description` becomes the empty
/// string and a missing `inputSchema` becomes `{}`, because both are genuinely optional on the wire
/// — but both go INTO the digest at their defaulted value, so an upstream that later supplies one
/// has drifted. Treating an absent field as "not part of the identity" is how a schema is added
/// after approval without the digest moving.
pub(crate) fn parse_tool_list(result: &serde_json::Value) -> Result<Vec<ToolDef>, String> {
    let Some(items) = result.get("tools").and_then(|t| t.as_array()) else {
        return Err("the `tools/list` result carries no `tools` array".to_string());
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(name) = item.get("name").and_then(|n| n.as_str()) else {
            return Err("a `tools/list` entry carries no `name`".to_string());
        };
        // The NAME is validated as a routing component here rather than trusted, because it becomes
        // half of a bound identity. A name busbar cannot name is a tool busbar cannot route to, and
        // adopting it into the cache would put an unroutable entry in the approval queue.
        if name.trim().is_empty() {
            return Err("a `tools/list` entry carries an empty `name`".to_string());
        }
        out.push(ToolDef {
            name: name.to_string(),
            description: item
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or_default()
                .to_string(),
            input_schema: item
                .get("inputSchema")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
        });
    }
    Ok(out)
}

/// The bearer an OPERATOR-DRIVEN refresh sends, if any.
///
/// This is NOT the dispatch path's credential plan and deliberately does not call it. That planner's
/// first act is the transitive-deputy gate, which binds the outbound credential to an INBOUND
/// principal's grant — and a refresh has no inbound principal, because an operator asking busbar to
/// look at an upstream is not a caller asking busbar to spend authority on its behalf. Calling the
/// planner with a synthesised principal would be manufacturing exactly the grant the gate exists to
/// require.
///
/// `passthrough` therefore REFUSES rather than falling back: the whole meaning of that mode is that
/// the credential belongs to a caller, and there is no caller here. Fail closed.
fn refresh_credential(server: &ServerEntry) -> Result<RefreshCredential, RefreshRefusal> {
    let mode = super::upstream::credential_mode(server).map_err(RefreshRefusal::Credential)?;
    match mode {
        UpstreamCredential::None => Ok(RefreshCredential::None),
        UpstreamCredential::Static(secret) => Ok(RefreshCredential::Bearer(
            secret.expose_secret().to_string(),
        )),
        UpstreamCredential::Passthrough => Err(RefreshRefusal::Credential(format!(
            "server `{}` is configured `upstream_credentials: passthrough`, so its credential \
             belongs to a caller; an operator-driven refresh has no caller and busbar will not \
             substitute its own",
            server.id
        ))),
        UpstreamCredential::Exchange(cfg) => Ok(RefreshCredential::Exchange(ExchangeRequest {
            token_url: cfg.token_url.clone(),
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token: cfg.subject_token.clone(),
            subject_token_type: cfg.subject_token_type.clone(),
            resource: cfg.resource.clone(),
            // The down-scope for a refresh is the set of tools the OPERATOR allowed on this server,
            // which is the registration's own content rather than any caller's grant. A refresh that
            // asked for a wildcard would hold a broader token than any dispatch it enables.
            scope: refresh_scope(server),
            requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
        })),
    }
}

/// The RFC 8693 scope a refresh asks for: every capability this registration allows, namespaced,
/// sorted and deduplicated so the same registration produces the same request every time.
fn refresh_scope(server: &ServerEntry) -> String {
    let mut scopes: Vec<String> = server
        .approval
        .capabilities()
        .map(|(tool, _)| super::catalogue::namespaced(&server.id, tool))
        .collect();
    scopes.sort();
    scopes.dedup();
    scopes.join(" ")
}

/// What a refresh will send, decided before any I/O.
enum RefreshCredential {
    None,
    Bearer(String),
    Exchange(ExchangeRequest),
}

/// FETCH one upstream's live tool list and publish the observation into the cache.
///
/// Returns the derived report. A network failure is NOT an error return: it is a recorded
/// `observe_failure`, which is what demotes the server, and the report carries the reason. An
/// `Err` here means the refresh was never attempted at all.
pub(crate) async fn refresh(
    pool: &McpConnectionPool,
    cache: &CatalogueCache,
    server: &ServerEntry,
) -> Result<ConnectReport, RefreshRefusal> {
    let server_id =
        ServerId::new(&server.id).map_err(|e| RefreshRefusal::Malformed(e.to_string()))?;
    let policy = SsrfPolicy {
        allow_private: server.upstream.allow_private,
    };
    let credential = refresh_credential(server)?;
    let bearer = match credential {
        RefreshCredential::None => None,
        RefreshCredential::Bearer(b) => Some(b),
        RefreshCredential::Exchange(req) => {
            match super::upstream::exchange(pool, &req, policy).await {
                Ok(token) => Some(token),
                // A refresh that could not obtain a credential is a refresh that FAILED, not one
                // that goes out unauthenticated. Sending no credential where one was configured
                // would let an upstream answer with a public tool list and have it adopted as the
                // authoritative one.
                Err(reason) => return Ok(record_failure(cache, server, &server_id, &reason)),
            }
        }
    };

    let request = jsonrpc::tools_list(&server.url, REFRESH_REQUEST_ID, bearer.as_deref());
    let response = match HttpTransport::send(pool, &request, policy, REFRESH_TIMEOUT).await {
        Ok(r) => r,
        Err(e) => return Ok(record_failure(cache, server, &server_id, &e.to_string())),
    };
    let tools = match jsonrpc::parse_response(&response.body) {
        RpcOutcome::Result(value) => match parse_tool_list(&value) {
            Ok(tools) => tools,
            Err(reason) => return Ok(record_failure(cache, server, &server_id, &reason)),
        },
        RpcOutcome::Error { code, message } => {
            return Ok(record_failure(
                cache,
                server,
                &server_id,
                &format!("the upstream answered JSON-RPC error {code}: {message}"),
            ))
        }
        // An upstream asking busbar to spend its own authority in answer to a TOOL LIST is not a
        // negotiation busbar entertains: there is no dispatch in flight to attribute or meter it
        // against, so the ask is refused where it arrives.
        RpcOutcome::InputRequired { kind } => {
            return Ok(record_failure(
                cache,
                server,
                &server_id,
                &format!(
                    "the upstream answered `tools/list` with an input-required result asking for \
                     `{}`; a tool list is not a dispatch and busbar has no round to meter that ask \
                     against, so it is refused here",
                    kind.key()
                ),
            ))
        }
        RpcOutcome::Malformed(reason) => {
            return Ok(record_failure(
                cache,
                server,
                &server_id,
                &format!(
                    "the upstream returned HTTP {} and a body that is not a JSON-RPC response: \
                     {reason}",
                    response.status
                ),
            ))
        }
    };

    let observed = tools.len();
    // THE OBSERVED IDENTITY. See the module header's stated gap: the transport surfaces no peer
    // certificate to this layer, so the observation carries the DECLARED pin. The capability axis
    // below is genuinely observed; this axis is not, and the header says so rather than the value
    // implying otherwise.
    let presented = server.approval.pin().cloned();
    let entry = publish(cache, server, &server_id, |sc| sc.observe(presented, tools));
    Ok(ConnectReport {
        server: server.id.clone(),
        state: server.approval.state(&entry.sighting),
        drift: server.approval.drift(&entry.sighting),
        observed,
        failure: None,
    })
}

/// Record a failed contact and derive the report from it.
fn record_failure(
    cache: &CatalogueCache,
    server: &ServerEntry,
    server_id: &ServerId,
    reason: &str,
) -> ConnectReport {
    let entry = publish(cache, server, server_id, |sc| sc.observe_failure(reason));
    ConnectReport {
        server: server.id.clone(),
        state: server.approval.state(&entry.sighting),
        drift: server.approval.drift(&entry.sighting),
        observed: 0,
        failure: Some(reason.to_string()),
    }
}

/// Apply `edit` to this server's cache entry, publishing a NEW generation, and hand back the
/// resulting entry.
///
/// The entry is seeded from the LIVE registration when it is absent, so a server that has never been
/// connected still lands in the cache carrying the operator's standing approval — an entry seeded
/// empty would report `pending` for a server the operator approved declaratively.
fn publish(
    cache: &CatalogueCache,
    server: &ServerEntry,
    server_id: &ServerId,
    edit: impl FnOnce(&mut ServerCatalogue),
) -> ServerCatalogue {
    let key = server_id.as_str().to_string();
    let approval = server.approval.clone();
    cache.apply(|servers| {
        let sc = servers
            .entry(key.clone())
            .or_insert_with(|| ServerCatalogue::seeded(server_id.clone(), approval.clone()));
        // The cached copy of the intent is refreshed on every publish so the operator-facing views
        // computed off it do not lag config. The dispatch gate does not read it — see
        // `ServerCatalogue::seeded`.
        sc.approval = approval.clone();
        edit(sc);
    });
    cache
        .load()
        .server(server_id)
        .cloned()
        // `apply` published the entry above under the same key, so this is unreachable; falling back
        // to the seeded value rather than panicking keeps a poisoned-lock recovery from taking the
        // plane down on a path that has already done its work.
        .unwrap_or_else(|| ServerCatalogue::seeded(server_id.clone(), server.approval.clone()))
}

/// THE OPERATOR'S CHANGES QUEUE for one server, without a refresh: what the LAST observation says
/// against the CURRENT approval. Reading it never contacts anything, which is what makes it safe to
/// render on a dashboard.
pub(crate) fn changes(cache: &CatalogueCache, server: &ServerEntry) -> ConnectReport {
    let snapshot = cache.load();
    let sighting = match ServerId::new(&server.id)
        .ok()
        .and_then(|id| snapshot.server(&id).cloned())
    {
        Some(sc) => sc.sighting,
        None => crate::trust::Sighting::Never,
    };
    let observed = match &sighting {
        crate::trust::Sighting::Seen(o) => o.capabilities.len(),
        _ => 0,
    };
    let failure = match &sighting {
        crate::trust::Sighting::Failed(reason) => Some(reason.clone()),
        _ => None,
    };
    ConnectReport {
        server: server.id.clone(),
        state: server.approval.state(&sighting),
        drift: server.approval.drift(&sighting),
        observed,
        failure,
    }
}

/// THE APPROVAL, PROJECTED BACK ONTO THE CONFIG OVERLAY — the missing half of the round trip.
///
/// `crate::mcp::catalogue::server_entry` builds an `Approval` FROM config one way. Without this
/// function an approval worked through the changes queue has nowhere to live and is lost at the next
/// config apply, which would make every operator approval a lie with a short shelf life. The overlay
/// is operator INTENT, and an approval IS operator intent, so this is where it belongs.
///
/// The projection targets exactly the two fields the build reads back — `pin.key` and
/// `tools_allow[].schema_hash` — so the round trip is closed by construction rather than by two
/// functions agreeing. A REJECTED capability projects as `schema_hash: null`: the config grammar's
/// "allowed but no approved hash" is `pending`, which does not serve, and that is the closest honest
/// config-shaped statement of a refusal. The distinction between pending and rejected lives in the
/// cache's approval, and the config projection deliberately does not invent a grammar for it.
// NO PRODUCTION CALLER YET, and the gap is exactly one verb wide: `connect` records observations
// and `changes` renders them, but the ADOPT verbs (`approve`, `approve-pin`, per-capability
// `approve`/`reject`) are not built, so nothing yet has an approval to persist. This is the half of
// the round trip that was missing — `catalogue::server_entry` builds an approval FROM config one way
// — and it is landed with the round trip proven closed in its battery rather than left to be
// discovered when the adopt verbs land.
#[allow(dead_code)]
pub(crate) fn overlay_patch(
    server: &str,
    approval: &crate::trust::Approval<TransportPin>,
) -> serde_json::Value {
    let mut tools = serde_json::Map::new();
    for (name, capability) in approval.capabilities() {
        let hash = match capability {
            crate::trust::CapabilityApproval::At(digest) => {
                serde_json::Value::String(digest.clone())
            }
            crate::trust::CapabilityApproval::Rejected => serde_json::Value::Null,
        };
        tools.insert(name.to_string(), serde_json::json!({ "schema_hash": hash }));
    }
    let mut entry = serde_json::Map::new();
    if let Some(pin) = approval.pin() {
        entry.insert(
            "pin".to_string(),
            serde_json::json!({ "key": crate::trust::PinnedArtifact::digest(pin) }),
        );
    }
    entry.insert("tools_allow".to_string(), serde_json::Value::Object(tools));
    serde_json::json!({ "tools": { "servers": { server: serde_json::Value::Object(entry) } } })
}

// Shared fixtures for the connect batteries: a REAL fake MCP peer whose tool list can CHANGE under
// a live cache, which is the one thing a rug-pull proof cannot do without.
#[cfg(test)]
#[path = "tests/connect_support.rs"]
pub(super) mod connect_support;

#[cfg(test)]
#[path = "tests/connect_tests.rs"]
mod connect_tests;

// THE RUG-PULL PROOF ON THE HOT PATH: a schema changed under a LIVE cache, and the dispatch that is
// refused because of it — with the unchanged control beside it, because a guard with no control is
// just a closed door.
#[cfg(test)]
#[path = "tests/drift_dispatch_tests.rs"]
mod drift_dispatch_tests;
