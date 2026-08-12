// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UPSTREAM LEG — the join between the SERVER direction (busbar's front door) and the CLIENT
//! direction (busbar calling out to a registered MCP server).
//!
//! Everything here is glue, and the glue is the point. Both halves already existed and each was
//! proven on its own; what did not exist was the path by which an authenticated inbound `tools/call`
//! becomes an outbound one, and the two integrity properties that only mean anything once it does:
//!
//! - the SERVER direction's inbound audience validation is the confused-deputy defence, and it
//!   defends nothing without an inbound surface that does something;
//! - the CLIENT direction's outbound down-scoping has no meaning without upstreams.
//!
//! ## The inbound principal is carried, never re-derived
//!
//! [`authorise`] takes the caller's resolved `VirtualKey` — the SAME value the catalogue filter and
//! the budget charge were computed from — and hands it to the client direction's
//! `egress::plan_credential`. Nothing here re-derives a principal, re-parses a token, or synthesises
//! a "service" identity for the outbound hop. The outbound credential is selected under the inbound
//! caller's own grant or it is not selected at all, and that sentence is the whole of the defence.
//!
//! ## The gate runs BEFORE any network I/O, and that ordering is load-bearing
//!
//! [`authorise`] is synchronous and reaches nothing. It is called before the input-required loop is
//! entered, so a caller whose grant does not cover this call cannot cause busbar to make a
//! token-exchange round trip against busbar's OWN authorization server. An unauthorised request that
//! still costs an authenticated round trip on the operator's IdP is an unauthenticated party
//! spending the operator's rate limit, and it is asserted on the token endpoint's OWN hit counter
//! rather than inferred from the refusal.
//!
//! ## Governance disabled is not a special case here either
//!
//! With governance off there is no key, so there is no grant, and `crate::mcp::method::Ctx::grant`
//! already answers "all scopes" for exactly the reason `pool_allowed` does on the LLM plane: a
//! deployment with no governance has no principal to carry a grant, and refusing everything would
//! make it unable to serve. This module takes the same posture, by synthesising the WILDCARD
//! principal rather than by skipping the gate — which matters, because a wildcard principal is
//! down-scoped to the single tool it called. Skipping the gate would have asked for everything.
//!
//! ## Re-planned on EVERY round, deliberately
//!
//! The credential is planned and minted inside the per-round call rather than once before the loop.
//! Under on-demand negotiation every defence is a per-request check, and one logical dispatch is
//! several requests: a grant narrowed part-way through must bite on the very next round. Caching the
//! minted token across rounds would be a session by another name.

use super::catalogue::{ServerEntry, ToolEntry};
use super::client::egress::{
    plan_credential, CredentialPlan, EgressDenied, ExchangeCfg, ExchangeRequest, UpstreamCredential,
};
use super::client::identity::{ServerId, ToolKey};
use super::client::jsonrpc::{self, RpcOutcome};
use super::client::pool::McpConnectionPool;
use super::client::ssrf::SsrfPolicy;
use super::client::transport::HttpTransport;
use super::inputreq::{Ask, Round};
use busbar_api::{Redacted, VirtualKey};
use std::time::Duration;

/// The wall-clock budget for ONE outbound leg — the tool call, and separately the token exchange.
///
/// A number rather than an inherited default, because an upstream MCP server is not trusted to
/// answer and a dispatch that hangs holds a concurrency slot the caller already paid for. Thirty
/// seconds is the same order the proxy path allows a provider, so a tool call and a model call fail
/// on the same timescale rather than on two an operator has to learn separately.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Everything the outbound leg needs, resolved and AUTHORISED, ready to be spent.
///
/// Constructed only by [`authorise`], which is what makes "the gate ran" a property of having the
/// value rather than a call somebody remembers to make.
#[derive(Debug)]
pub(crate) struct Authorised {
    /// The routing key — the bound identity, never a description.
    pub(crate) key: ToolKey,
    /// The upstream endpoint, as the operator registered it.
    pub(crate) url: String,
    /// The addressing posture for the dispatch-time SSRF check.
    pub(crate) policy: SsrfPolicy,
    /// The credential MODE this server is configured with.
    pub(crate) credential: UpstreamCredential,
    /// The INBOUND principal, carried through so the credential planner re-derives the same
    /// down-scope the gate was computed from.
    pub(crate) caller: VirtualKey,
}

/// Why the upstream leg could not even be set up. Distinct from an upstream FAILURE, because an
/// operator's remedy is completely different: one is a grant, the other is a network.
#[derive(Debug)]
pub(crate) enum SetupRefusal {
    /// The registered ids do not form a valid routing key. A registration that cannot be named
    /// cannot be dispatched to, and guessing at a repair here would be routing on a rendering.
    Malformed(String),
    /// The inbound principal's grant does not cover this call.
    Egress(EgressDenied),
    /// The operator's credential configuration cannot be honoured (an unresolvable secret, a
    /// `passthrough` server with no caller credential to forward). Fail CLOSED: busbar never
    /// substitutes its own ambient credential for one it was told the caller would supply.
    Credential(String),
    /// A URL or host carried INSIDE the per-request tool arguments failed the same addressing check
    /// the destination does. The routing rule makes the DESTINATION immune to attacker-chosen text;
    /// it does not make the PAYLOAD immune, and this is the arm that says so.
    Argument(String),
}

impl std::fmt::Display for SetupRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SetupRefusal::Malformed(m) => write!(f, "{m}"),
            SetupRefusal::Egress(e) => write!(f, "{e}"),
            SetupRefusal::Credential(m) => write!(f, "{m}"),
            SetupRefusal::Argument(m) => write!(f, "{m}"),
        }
    }
}

impl SetupRefusal {
    /// The stable audit reason word, named once so a new arm cannot land without one.
    pub(crate) fn audit_reason(&self) -> &'static str {
        match self {
            SetupRefusal::Malformed(_) => "malformed_identity",
            SetupRefusal::Egress(_) => "egress_denied",
            SetupRefusal::Credential(_) => "credential_unavailable",
            SetupRefusal::Argument(_) => "tool_argument_refused",
        }
    }
}

/// THE GATE. Synchronous, reaches no network, and runs before the loop is entered.
///
/// `caller` is `None` only when governance is disabled — see the module header for why that becomes
/// the WILDCARD principal rather than a skipped check.
pub(crate) fn authorise(
    server: &ServerEntry,
    selected: &ToolEntry,
    arguments: &serde_json::Value,
    caller: Option<&VirtualKey>,
) -> Result<Authorised, SetupRefusal> {
    let server_id =
        ServerId::new(&selected.server).map_err(|e| SetupRefusal::Malformed(e.to_string()))?;
    let key = ToolKey::new(server_id.clone(), &selected.tool)
        .map_err(|e| SetupRefusal::Malformed(e.to_string()))?;
    let caller = match caller {
        Some(k) => k.clone(),
        None => ungoverned_principal(),
    };
    let credential = credential_mode(server).map_err(SetupRefusal::Credential)?;
    // THE TRANSITIVE-DEPUTY CALL. `plan_credential` runs `authorise_egress` first and returns nothing to a caller
    // that fails it, so the plan below is not reachable without the grant. It is called here — where
    // there is no network — precisely so the refusal costs no round trip.
    plan_credential(&server_id, &credential, &caller, None, &key).map_err(SetupRefusal::Egress)?;
    let policy = SsrfPolicy {
        allow_private: server.upstream.allow_private,
    };
    // THE ARGUMENT GUARD, and it runs AFTER the grant deliberately: a caller with no grant learns
    // that it is ungranted and nothing about the tool's schema. The schema is the operator's
    // APPROVED one from the catalogue snapshot, not one the upstream offered at refresh time, so
    // the document the walk reads is the document the operator signed off.
    //
    // A tool that declared no schema is walked against `{"type": "object"}` rather than skipped: the
    // walk is VALUE-driven with the schema riding alongside, so an absent schema narrows what the
    // walk can call "declared" and narrows nothing else. Skipping it would make "declare no schema"
    // the way past this check.
    let schema = selected
        .input_schema
        .clone()
        .unwrap_or_else(|| serde_json::json!({ "type": "object" }));
    super::client::argguard::guard(&schema, arguments, policy)
        .map_err(|e| SetupRefusal::Argument(e.to_string()))?;
    Ok(Authorised {
        key,
        url: server.url.clone(),
        policy,
        credential,
        caller,
    })
}

/// The WILDCARD principal an ungoverned deployment dispatches as.
///
/// `allowed_scopes: None` is the store's wildcard, and it is the honest representation of "there is
/// no key here to carry a grant". It is NOT a way past the gate: a wildcard principal is
/// down-scoped, on the outbound side, to the single tool it actually called.
fn ungoverned_principal() -> VirtualKey {
    VirtualKey {
        id: "ungoverned".to_string(),
        name: "ungoverned".to_string(),
        generation_hash: String::new(),
        enabled: true,
        allowed_scopes: None,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        created_at: 0,
        revision: 0,
    }
}

/// Turn the operator's registration into the client direction's credential mode.
///
/// The subject token is resolved HERE, at dispatch, rather than at snapshot build: a secret that
/// resolves at build time is a secret whose rotation needs a restart, and a snapshot holding
/// resolved plaintext is a snapshot that cannot be compared or logged safely.
pub(super) fn credential_mode(server: &ServerEntry) -> Result<UpstreamCredential, String> {
    if matches!(
        server.upstream.credentials,
        Some(crate::auth::UpstreamCreds::Passthrough)
    ) {
        // Honest and fail-closed: this revision's ingress defines no carrier for a credential the
        // caller holds FOR THE UPSTREAM (the inbound `Authorization` is the caller's BUSBAR key, and
        // forwarding that is the one thing rule 1 forbids). So `passthrough` selects the passthrough
        // mode and the planner refuses it for want of a caller credential, which is the correct
        // answer until a carrier exists — never busbar's own credential in its place.
        return Ok(UpstreamCredential::Passthrough);
    }
    let Some(tx) = &server.upstream.token_exchange else {
        // No exchange configured: a public or network-authenticated upstream. Sending nothing is the
        // honest answer, and it is not a fallback to an ambient credential — there is none.
        return Ok(UpstreamCredential::None);
    };
    let resource = server.upstream.aud.clone().ok_or_else(|| {
        "an RFC 8693 exchange needs `aud:` as its RFC 8707 resource indicator; without one the \
         issued token is spendable at any backend the authorization server serves"
            .to_string()
    })?;
    let subject_token = crate::config::secret::resolve_builtin_string(&tx.subject_token)
        .map_err(|e| format!("busbar's own subject token for this upstream cannot resolve: {e}"))?;
    Ok(UpstreamCredential::Exchange(ExchangeCfg {
        token_url: tx.token_url.clone(),
        subject_token: Redacted::new(subject_token),
        subject_token_type: tx.subject_token_type.clone(),
        resource,
    }))
}

/// ONE ROUND of the upstream leg: plan, mint, send, parse.
///
/// The plan is re-derived here rather than carried from [`authorise`] because the caller's grant is
/// re-read per round — see the module header. `authorise` proves the gate ran before any I/O; this
/// proves it runs again on the round that actually spends.
pub(crate) async fn call(
    pool: &McpConnectionPool,
    auth: &Authorised,
    arguments: &serde_json::Value,
    request_id: u64,
) -> Result<Round, String> {
    let plan = plan_credential(
        auth.key.server(),
        &auth.credential,
        &auth.caller,
        None,
        &auth.key,
    )
    .map_err(|e| e.to_string())?;
    let bearer = match plan {
        CredentialPlan::None => None,
        CredentialPlan::Bearer(b) => Some(b.expose_secret().to_string()),
        CredentialPlan::Exchange(req) => Some(exchange(pool, &req, auth.policy).await?),
    };
    // The namespaced name is stripped to the bare tool inside the builder — the upstream has never
    // heard of busbar's namespacing and would answer `-32602` to it.
    let outbound = jsonrpc::tools_call(
        &auth.url,
        &auth.key,
        arguments,
        request_id,
        bearer.as_deref(),
    );
    let response = HttpTransport::send(pool, &outbound, auth.policy, UPSTREAM_TIMEOUT)
        .await
        .map_err(|e| e.to_string())?;
    // `request_id` AGAIN, and that is the point: the id that went out in the body is the id the
    // answer must name. Both uses are on the screen together so a reader can see that they are the
    // same value, and neither of them outlives this function — see `jsonrpc::parse_response` on why
    // the correlation is a per-dispatch argument rather than a table of pending ids.
    match jsonrpc::parse_response(&response.body, request_id) {
        RpcOutcome::Result(value) => Ok(Round::Done(value)),
        RpcOutcome::Error { code, message } => Err(format!(
            "MCP upstream answered JSON-RPC error {code}: {message}"
        )),
        // The ask is handed back to the bounded, per-round-gated loop, which decides whether busbar
        // may satisfy it. It is NEVER returned to busbar's own caller — the loop's `Outcome` has no
        // arm that could carry it outward.
        RpcOutcome::InputRequired { kind } => Ok(Round::InputRequired(Ask {
            kind: kind.key().to_string(),
            payload: serde_json::from_slice::<serde_json::Value>(&response.body)
                .ok()
                .and_then(|v| v.get("result").cloned())
                .unwrap_or_else(|| serde_json::json!({})),
        })),
        RpcOutcome::Malformed(reason) => Err(format!(
            "MCP upstream returned HTTP {} and a body that is not a JSON-RPC response: {reason}",
            response.status
        )),
        // A RESPONSE TO SOMETHING ELSE. The dispatch fails rather than adopting it: serving it
        // would answer this caller with whatever the upstream was actually replying to, and the
        // result is NOT logged into the error, because it is another conversation's payload.
        RpcOutcome::Uncorrelated(reason) => Err(format!(
            "MCP upstream returned HTTP {} and a JSON-RPC response busbar cannot correlate to this \
             call: {reason}",
            response.status
        )),
    }
}

/// PERFORM the RFC 8693 exchange and return the access token.
///
/// The token endpoint goes through the SAME pool, and therefore the same resolve-then-pin SSRF
/// check, as the tool call. An authorization server reached without that check is a destination
/// busbar sends its own subject token to on the strength of a string comparison.
pub(super) async fn exchange(
    pool: &McpConnectionPool,
    req: &ExchangeRequest,
    policy: SsrfPolicy,
) -> Result<String, String> {
    let (client, _target) = pool
        .client_for(&req.token_url, policy, UPSTREAM_TIMEOUT)
        .await
        .map_err(|e| format!("the token endpoint could not be reached: {e}"))?;
    let form = req.form_fields();
    let response = client
        .post(&req.token_url)
        .form(&form)
        .send()
        .await
        // `without_url()`: a reqwest error's Display carries the URL, which an operator may have
        // written userinfo into.
        .map_err(|e| format!("the RFC 8693 exchange failed: {}", e.without_url()))?;
    let status = response.status().as_u16();
    let body = response
        .bytes()
        .await
        .map_err(|e| format!("the RFC 8693 exchange body could not be read: {e}"))?;
    if !(200..300).contains(&status) {
        // The BODY is deliberately not echoed: an authorization server's error body can carry the
        // subject token back in a diagnostic, and this string reaches busbar's own caller.
        return Err(format!(
            "the RFC 8693 exchange was refused by the authorization server with HTTP {status}"
        ));
    }
    let parsed: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| "the RFC 8693 exchange response is not JSON".to_string())?;
    match parsed.get("access_token").and_then(|v| v.as_str()) {
        Some(t) if !t.is_empty() => Ok(t.to_string()),
        // A 200 with no usable token is a failure, not a call made with no credential: silently
        // dropping to an unauthenticated request is how an outage becomes an authorization bypass.
        _ => Err(
            "the RFC 8693 exchange returned 200 with no usable `access_token`; the call is refused \
             rather than made unauthenticated"
                .to_string(),
        ),
    }
}

// Shared fixtures for the upstream-leg batteries: a REAL fake MCP peer and a REAL fake RFC 8693
// token endpoint, both recording every byte they receive. Declared here rather than duplicated per
// file so a test that means to vary ONE thing varies one thing.
#[cfg(test)]
#[path = "tests/upstream_support.rs"]
mod upstream_support;

#[cfg(test)]
#[path = "tests/upstream_join_tests.rs"]
mod upstream_join_tests;

// PROVEN AS A PAIR — this property is meaningless with only one direction built: an inbound
// surface with no upstream cannot demonstrate that the outbound credential followed the
// inbound grant, and an upstream with no inbound caller has no grant to follow.
#[cfg(test)]
#[path = "tests/deputy_pair_tests.rs"]
mod deputy_pair_tests;
