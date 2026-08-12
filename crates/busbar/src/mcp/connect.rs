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
    /// The operator-facing word for the state. DELEGATED to [`TrustState::word`] rather than
    /// matched here: this was the only rendering until the A2A trust surface needed one, and a
    /// second match statement is how the two planes come to disagree about a string clients branch
    /// on.
    pub(crate) fn state_word(&self) -> &'static str {
        self.state.word()
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
    // Correlated against the id this refresh actually sent, three lines up. A refresh that adopted
    // an uncorrelated answer would publish somebody else's tool list as this server's catalogue,
    // which is the one observation every later dispatch is authorised against.
    let tools = match jsonrpc::parse_response(&response.body, REFRESH_REQUEST_ID) {
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
        // A tool list busbar cannot attribute to the request it made is not this server's tool
        // list. Recorded as a FAILURE — which demotes the server — rather than adopted, because
        // adopting it would let whatever answered decide what tools busbar believes this server has.
        RpcOutcome::Uncorrelated(reason) => {
            return Ok(record_failure(
                cache,
                server,
                &server_id,
                &format!(
                    "the upstream returned HTTP {} and a JSON-RPC response busbar cannot correlate \
                     to this refresh: {reason}",
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

// ══ THE TIMER'S HALF: this plane's `Sweeper`, driven by the ONE job in `crate::trust::sweep` ═════
//
// WHY IT IS HERE AND NOT IN A SCHEDULER OF ITS OWN. Schema hash-pinning with automatic drift
// quarantine was, until something drove it on a timer, a defence that depended on somebody pressing
// a button: quarantine-on-drift is automatic GIVEN a refresh, and `refresh`'s only caller was the
// admin verb. An upstream that rug-pulls a schema at 02:00 on a Saturday against a deployment whose
// operator is asleep was detected exactly never, and an attacker picks the moment.
//
// The tick, the clock, the shutdown, the panic containment and the operator-facing reporting are
// NOT here — they are `crate::trust::sweep`, once, for every plane. What is here is the only part
// that is genuinely this plane's: the fetch. It is an async JSON-RPC round trip through a shared
// connection pool that may first perform an RFC 8693 token exchange, over entries cloned out of a
// catalogue that is rebuilt on every config apply. The sibling plane's is a blocking socket read
// under a registry write lock. Forcing one function over both would be a shared shape hiding two
// behaviours, so the shared job takes exactly one method from each plane and this is ours.
//
// NO KNOB, and the shared job has none either:
//   * No server is ever skipped. The sweep asks `due` about every registration on every tick and
//     lets it answer. There is no rate limit on being CHECKED and no backoff on being checked — a
//     failing upstream is the one that most needs looking at.
//   * `operator_sync` is always `false`. THE TIMER IS NOT AN OPERATOR. The admin verb outranks it by
//     calling `refresh` outright, and nothing on this path can suppress a check the arithmetic says
//     is due.
//
// THE ONE STATED DIFFERENCE FROM THE SIBLING PLANE: A2A runs its observation through
// `trust::reverify::settle`, which can hold a CLEAN answer for a recovery backoff after a drift.
// This plane does not, because `ServerCatalogue::observe` has no arm that can decline to adopt what
// it saw, so `refresh_policy_for` sets `recovery_backoff_ms: 0` rather than carrying a number
// nothing reads. The half that matters is identical on both planes: DEMOTION IS NEVER HELD.

/// WHAT ONE REFRESH FOUND, as the shared sweep job carries it.
///
/// Two fields rather than one because a refresh that was never ATTEMPTED and a refresh that was
/// attempted and failed are different facts about different parties: one is the operator's own
/// configuration, the other is a network.
#[derive(Debug)]
pub(crate) struct RefreshDetail {
    /// What the refresh found. `None` when the server was fresh and nothing was attempted, or when
    /// the refresh could not be attempted at all.
    pub(crate) report: Option<ConnectReport>,
    /// Why the refresh could not be attempted.
    pub(crate) refusal: Option<String>,
}

impl crate::trust::sweep::SweepDetail for RefreshDetail {
    fn events(&self) -> Vec<crate::trust::sweep::SweepEvent> {
        use crate::trust::sweep::SweepEvent;
        if let Some(reason) = &self.refusal {
            return vec![SweepEvent::NotAttempted {
                reason: reason.clone(),
            }];
        }
        let Some(report) = &self.report else {
            return Vec::new();
        };
        if let Some(failure) = &report.failure {
            return vec![SweepEvent::ContactFailed {
                reason: failure.clone(),
            }];
        }
        if !report.drift.is_empty() {
            return vec![SweepEvent::Drifted {
                state: report.state_word(),
                drift: report.drift.clone(),
            }];
        }
        Vec::new()
    }
}

/// ONE SWEEP over every registered MCP server.
///
/// Takes the clock as an argument and holds no timer of its own, which is what makes the behaviour
/// testable: a test drives the same function the job drives, at times it chooses, with no sleeping
/// and nothing for a scheduler to race.
pub(crate) async fn refresh_sweep(
    app: &crate::state::App,
    now_ms: u64,
) -> Vec<crate::trust::sweep::SweepOutcome<RefreshDetail>> {
    // The registrations are read from the CATALOGUE — the operator's live intent — and not from the
    // sightings cache. A server the operator registered and nothing has ever observed has no cache
    // entry at all, and iterating the evidence would mean the one registration most in need of a
    // first look is the one the timer never reaches.
    let servers: Vec<_> = app.mcp_catalogue.servers().cloned().collect();
    let mut out = Vec::with_capacity(servers.len());

    for entry in &servers {
        let ledger = ledger_of(&app.mcp_sightings, &entry.id);
        // THE TIMER IS NOT AN OPERATOR. `operator_sync` is `false` and there is no argument on this
        // path through which a due check could be suppressed.
        let why = crate::trust::reverify::due(&ledger, &entry.refresh_policy, now_ms, false);
        if !why.should_check() {
            out.push(crate::trust::sweep::SweepOutcome {
                subject: entry.id.clone(),
                due: why,
                detail: RefreshDetail {
                    report: None,
                    refusal: None,
                },
            });
            continue;
        }

        let (report, refusal) = match refresh(&app.mcp_pool, &app.mcp_sightings, entry).await {
            Ok(report) => (Some(report), None),
            // A refusal means the refresh was never ATTEMPTED — an unroutable id, or a
            // `passthrough` credential posture whose credential belongs to a caller the timer does
            // not have. It is deliberately NOT recorded as a failed contact: nothing was contacted,
            // and writing a failure would demote a server over the operator's own configuration
            // rather than over anything the upstream did.
            Err(refusal) => (None, Some(refusal.to_string())),
        };

        // THE LEDGER IS STAMPED WHETHER OR NOT THE ANSWER WAS GOOD, and drift is counted before any
        // decision about what to believe. Detection and demotion are different acts. A refusal
        // stamps nothing: the clock records when we LOOKED, and we did not look.
        if let Some(r) = &report {
            stamp(&app.mcp_sightings, &entry.id, now_ms, !r.drift.is_empty());
        }

        out.push(crate::trust::sweep::SweepOutcome {
            subject: entry.id.clone(),
            due: why,
            detail: RefreshDetail { report, refusal },
        });
    }
    out
}

/// This server's refresh ledger, or a fresh one for a registration nothing has ever observed.
///
/// A missing cache entry yields [`crate::trust::reverify::Ledger::default`], whose `last_checked_ms`
/// is `None` — which `due` reads as `NeverChecked`, i.e. DUE NOW. That is the fail-closed direction:
/// the alternative would treat "we have no record of ever looking" as freshness.
fn ledger_of(cache: &CatalogueCache, id: &str) -> crate::trust::reverify::Ledger {
    ServerId::new(id)
        .ok()
        .and_then(|sid| cache.load().server(&sid).map(|sc| sc.ledger.clone()))
        .unwrap_or_default()
}

/// Record that we LOOKED, and whether what we saw had drifted.
///
/// Deliberately mirrors the ledger half of [`crate::trust::reverify::settle`] and stops there: the
/// half `settle` adds on top is the recovery hold, which this plane's `observe` cannot express. See
/// the stated difference above.
fn stamp(cache: &CatalogueCache, id: &str, now_ms: u64, drifted: bool) {
    let Ok(sid) = ServerId::new(id) else {
        return;
    };
    cache.apply(|servers| {
        if let Some(sc) = servers.get_mut(sid.as_str()) {
            sc.ledger.last_checked_ms = Some(now_ms);
            if drifted {
                sc.ledger.drift_observations += 1;
                sc.ledger.last_drift_ms = Some(now_ms);
            }
        }
    });
}

/// THIS PLANE'S `Sweeper`. Holds the [`crate::state::AppHandle`] rather than a snapshot of the app,
/// and that is the one place this plane's job differs from its sibling's in a way that matters: the
/// MCP catalogue is REBUILT on every config apply, so a job holding an `Arc<App>` taken at boot
/// would go on sweeping the registrations of a config the operator has already replaced — refreshing
/// servers they deleted and never looking at the ones they added. Loading the handle on each tick
/// means the sweep always sees the live generation.
pub(crate) struct RefreshSweeper(pub(crate) std::sync::Arc<crate::state::AppHandle>);

impl crate::trust::sweep::Sweeper for RefreshSweeper {
    type Detail = RefreshDetail;

    fn plane(&self) -> crate::plane::Plane {
        crate::plane::Plane::Mcp
    }

    async fn sweep(&self, now_ms: u64) -> Vec<crate::trust::sweep::SweepOutcome<RefreshDetail>> {
        // Every leg is non-blocking I/O through the shared pool, so unlike the sibling plane's card
        // fetch there is nothing here to move onto a blocking thread.
        let app = self.0.load();
        refresh_sweep(&app, now_ms).await
    }
}

// Shared fixtures for the connect batteries: a REAL fake MCP peer whose tool list can CHANGE under
// a live cache, which is the one thing a rug-pull proof cannot do without.
#[cfg(test)]
#[path = "tests/connect_support.rs"]
pub(super) mod connect_support;

// THE PROOF THAT THE DEFENCE RUNS WITH NOBODY WATCHING: a schema changed under a live cache, the
// TIMER'S OWN SWEEP (never the admin verb), and the dispatch that is refused because of it.
#[cfg(test)]
#[path = "tests/timer_dispatch_tests.rs"]
mod timer_dispatch_tests;

#[cfg(test)]
#[path = "tests/connect_tests.rs"]
mod connect_tests;

// THE RUG-PULL PROOF ON THE HOT PATH: a schema changed under a LIVE cache, and the dispatch that is
// refused because of it — with the unchanged control beside it, because a guard with no control is
// just a closed door.
#[cfg(test)]
#[path = "tests/drift_dispatch_tests.rs"]
mod drift_dispatch_tests;
