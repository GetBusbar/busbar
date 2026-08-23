// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE GOVERNED PATH every method busbar issues to an upstream travels.
//!
//! ## Why there is exactly one of these
//!
//! `tools/call` reached an upstream through `crate::mcp::upstream::call`, which runs the egress
//! gate, mints the credential, sends through the transport vtable and correlates the answer. When
//! the rest of the client-side column landed there were two shapes available: give each verb its own
//! send site, or give all of them one. A verb with its own send site is a verb whose author decides
//! whether the gate runs, and the first one to decide "this is only a list, it needs no credential"
//! is a hole with a plausible-sounding reason in front of it.
//!
//! So: ONE function, [`issue`]. Every verb goes through it, and everything it does is the thing
//! `tools/call` already did:
//!
//! | control | where |
//! |---|---|
//! | egress gate (transitive confused deputy) | `super::egress::plan_verb_credential` → `crate::egress_auth::gate` |
//! | outbound credential, RFC 8693/8707 | the same planner, and NEVER the caller's busbar key |
//! | the supervision breaker | inside the wire — a quarantined child refuses every verb, not just calls |
//! | the durable per-call hash chain | `crate::plane::calllog::emit`, at every terminal |
//! | JSON-RPC correlation | `super::jsonrpc::parse_response` with the id this call sent |
//!
//! ## The gate runs BEFORE any I/O, and the ordering is load-bearing
//!
//! The credential is planned first and the plan is what performs the exchange, so a caller whose
//! grant does not cover this upstream is refused without busbar making a token-exchange round trip
//! against its OWN authorization server. That is `crate::mcp::upstream`'s ordering argument and it
//! does not weaken because the verb is a `prompts/list`.
//!
//! ## WHAT IS RECORDED, and the one schema decision this file takes
//!
//! `crate::plane::calllog`'s header states that `prompts/get` and `resources/read` were NOT written to
//! the chain because `McpCallRecord.tool` is a TOOL ROUTING KEY and widening it to every capability
//! is a schema decision rather than a wiring one. That decision is taken here, explicitly, and in the
//! narrow direction: the record's `tool` field carries the METHOD NAME prefixed with `verb:` — for
//! example `verb:prompts/list`. The prefix is the point. `mcp_tool` grant values are namespaced
//! routing keys of the form `{server}_{tool}` and can never contain a colon or a slash, so a
//! `verb:`-prefixed value cannot collide with, be mistaken for, or be matched by any grant an
//! operator can write. An auditor reading the chain sees which verb went out; nothing reading the
//! chain for grants can read one of these as a tool.
//!
//! The alternative was to leave these calls out of the chain, and that is worse than a widened
//! field: an outbound leg with no record is an outbound leg an investigator cannot see.

use super::egress::{plan_verb_credential, CredentialPlan};
use super::identity::ServerId;
use super::jsonrpc::{parse_response, RpcOutcome};
use super::verb::UpstreamVerb;
use super::wire::WireLeg;
use crate::mcp::upstream::Authorised;
use crate::plane::calllog::{
    CallInput, OUTCOME_DISPATCHED, OUTCOME_REFUSED, REASON_UPSTREAM_FAILED,
};

/// WHAT ONE ISSUED VERB PRODUCED.
///
/// A notification has no answer and says so with its own arm rather than with an empty `Value`,
/// because "the peer returned nothing" and "busbar never asked for anything" are different facts and
/// only one of them is a possible upstream defect.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Issued {
    /// The peer's result.
    Result(serde_json::Value),
    /// A notification was written. There is nothing to return and nothing was waited for.
    Delivered,
}

/// ISSUE one verb to one upstream, under the caller's own grant.
///
/// `request_id` is the caller's to choose and MUST be unique within a dispatch: it is written into
/// the body and read back out of the answer, and nothing stores it — see
/// [`super::jsonrpc::parse_response`] on why the correlation is a per-exchange argument rather than
/// a table of pending ids.
///
/// ## NO INBOUND CALLER YET, stated rather than softened
///
/// Reached today from `crate::mcp::tests/stdio_client_leg_tests.rs`, which drives it against a real
/// child process through the real gate. What does not exist is the SERVER-plane method that would
/// proxy a caller's `prompts/list` to an upstream's — that is `crate::mcp::method`'s surface, not
/// this module's. The gap is named here rather than papered over, and the allow is on this function
/// alone so anything else in the file losing its caller still breaks the build.
#[allow(dead_code)]
pub(crate) async fn issue(
    pool: &super::pool::McpConnectionPool,
    auth: &Authorised,
    verb: &UpstreamVerb,
    request_id: u64,
) -> Result<Issued, String> {
    // THE REGISTRATION, off the leg itself rather than off a tool key. A verb names no tool, and
    // reading the server out of one was what made an `mcp_tool` grant a prerequisite for issuing a
    // verb that requires only `mcp_server` — the subject said one grant and the constructor
    // demanded two.
    let server: &ServerId = &auth.server;
    let method = verb.method();
    let principal = auth.caller.id.clone();
    // DEFERRED (busbar 1.6.0 R2): the per-call chain lives HOST-SIDE now and is reached over a
    // `HostCtx`, which this `async` client-leg path cannot hold across its `.await`s and has no `&App`
    // to mint (issue() is `#[allow(dead_code)]` with no inbound caller — see the module header). So it
    // emits through the HOSTLESS in-core path (`emit_hostless`), the durable-cleave twin the seam keeps
    // for exactly this site until the SERVER-plane proxy method that would drive this verb supplies a
    // host; wiring the host emit in is then a one-line swap here.
    let record = |outcome: &'static str, reason: String| {
        crate::plane::calllog::emit_hostless(
            &principal,
            CallInput {
                ts: crate::store::now(),
                server: server.as_str().to_string(),
                // See the module header for why this is `verb:`-prefixed and why that prefix cannot
                // collide with any `mcp_tool` grant an operator can write.
                tool: format!("verb:{method}"),
                outcome,
                reason,
                // A verb that names no tool has no approved schema digest and no pin generation to
                // quote. Empty and zero are the honest values; inventing the digest of an unrelated
                // tool would put a hash in the chain that describes nothing.
                tool_digest: String::new(),
                pin_generation: 0,
                request_id: request_id.to_string(),
            },
        );
    };

    // (1) THE GATE, and the credential, BEFORE any I/O. See the module header.
    let plan = match plan_verb_credential(server, method, &auth.credential, &auth.caller, None) {
        Ok(plan) => plan,
        Err(denied) => {
            let reason = denied.to_string();
            record(OUTCOME_REFUSED, reason.clone());
            return Err(reason);
        }
    };
    // (1b) THE ARGUMENT GUARD, on the verb's OWN params, and BEFORE the exchange.
    //
    // `crate::mcp::upstream::authorise` puts a `tools/call`'s arguments through this walk because
    // "an argument is attacker-influenced content travelling to an operator-chosen destination,
    // which the routing rule does not and cannot address". Nothing about that sentence is true only
    // of tools. A `resources/read` carries a caller-chosen `uri`, a `completion/complete` carries a
    // caller-chosen argument value, and until this ran they reached an upstream unjudged — the
    // routing rule makes the DESTINATION immune to attacker-chosen text and does nothing whatever
    // for the PAYLOAD.
    //
    // The schema is `{"type": "object"}`: a verb's params have no operator-approved schema, and the
    // walk is VALUE-driven with the schema riding alongside, so an absent schema narrows what the
    // walk may call "declared" and narrows nothing else.
    //
    // AFTER the gate and BEFORE the exchange, which is the same ordering `authorise` uses: a caller
    // with no grant learns it is ungranted and nothing else, and a refused param still costs no
    // token-endpoint round trip on busbar's own authorization server.
    if let Err(refusal) = super::argguard::guard(
        &serde_json::json!({ "type": "object" }),
        &verb.params_for_guard(),
        auth.policy,
    ) {
        let reason = refusal.to_string();
        record(OUTCOME_REFUSED, reason.clone());
        return Err(reason);
    }
    let bearer = match plan {
        CredentialPlan::None => None,
        CredentialPlan::Bearer(b) => Some(b.expose_secret().to_string()),
        CredentialPlan::Exchange(req) => {
            match crate::mcp::upstream::exchange(pool, &req, auth.policy, auth.timeout).await {
                Ok(token) => Some(token),
                Err(e) => {
                    record(OUTCOME_REFUSED, e.clone());
                    return Err(e);
                }
            }
        }
    };

    let outbound = verb.build(&auth.url, request_id, bearer.as_deref());
    // THE DISPATCH ARM, and it is a vtable lookup rather than a branch. `upstream_wire` is the only place
    // in the tree that asks the transport axis which variant it is; from here down the leg is bytes
    // out and bytes back, identically for an HTTPS POST and for a write to a child's stdin.
    let leg = WireLeg {
        pool,
        policy: auth.policy,
        timeout: auth.timeout,
        server: server.as_str(),
        command: auth.stdio.as_ref(),
        grants: auth.grants,
    };
    // (2) THE SEND. A notification takes the one-way arm — see `super::wire::McpWire::notify` for
    // why sending one down the request path desynchronises a child's stream permanently. Both arms
    // go through `super::wire`'s counted seam rather than through `wire_for()` directly, so every
    // verb busbar issues appears on `busbar_upstream_attempts_total` without this file remembering
    // to say so.
    if verb.is_notification() {
        return match super::wire::notify(auth.transport, &leg, &outbound).await {
            Ok(()) => {
                record(OUTCOME_DISPATCHED, format!("{method} delivered"));
                Ok(Issued::Delivered)
            }
            Err(e) => {
                let reason = e.to_string();
                record(OUTCOME_REFUSED, reason.clone());
                Err(reason)
            }
        };
    }

    let response = match super::wire::send(auth.transport, &leg, &outbound).await {
        Ok(r) => r,
        Err(e) => {
            let reason = e.to_string();
            record(OUTCOME_DISPATCHED, REASON_UPSTREAM_FAILED.to_string());
            return Err(reason);
        }
    };
    // (3) CORRELATED against the id this call sent, and refused on anything else. A verb that
    // adopted an uncorrelated answer would serve one caller another caller's payload — the same
    // defect `crate::mcp::connect` refuses a tool list for.
    match parse_response(&response.body, request_id) {
        RpcOutcome::Result(value) => {
            record(OUTCOME_DISPATCHED, format!("{method} answered"));
            Ok(Issued::Result(value))
        }
        RpcOutcome::Error { code, message } => {
            let reason =
                format!("MCP upstream answered JSON-RPC error {code} to {method}: {message}");
            record(OUTCOME_DISPATCHED, REASON_UPSTREAM_FAILED.to_string());
            Err(reason)
        }
        // AN ASK, ANSWERED WITH A REFUSAL AND NEVER PROXIED. An upstream asking busbar to spend its
        // own authority in reply to a `prompts/list` has no dispatch round to be metered against —
        // the argument `crate::mcp::connect` makes for a tool list, and it holds for every verb here
        // for the same reason: there is nothing to attribute the spend to.
        RpcOutcome::InputRequired { kind } => {
            let reason = format!(
                "the upstream answered `{method}` with an input-required result asking for `{}`; \
                 busbar has no round to meter that ask against, so it is refused here and is not \
                 proxied to busbar's caller",
                kind.key()
            );
            record(OUTCOME_REFUSED, reason.clone());
            Err(reason)
        }
        RpcOutcome::Malformed(reason) => {
            let reason = format!(
                "MCP upstream returned HTTP {} to `{method}` and a body that is not a JSON-RPC \
                 response: {reason}",
                response.status
            );
            record(OUTCOME_DISPATCHED, REASON_UPSTREAM_FAILED.to_string());
            Err(reason)
        }
        RpcOutcome::Uncorrelated(reason) => {
            let reason = format!(
                "MCP upstream returned HTTP {} to `{method}` and a JSON-RPC response busbar cannot \
                 correlate to this call: {reason}",
                response.status
            );
            record(OUTCOME_DISPATCHED, REASON_UPSTREAM_FAILED.to_string());
            Err(reason)
        }
    }
}

// THE BATTERY FOR THIS MODULE LIVES IN `crate::mcp::tests/stdio_client_leg_tests.rs`, beside the
// other upstream-leg files and not here. The claim is about the JOIN — a verb reaching a real child
// process through the real gate — and a test that could construct an `Authorised` without going
// through `crate::mcp::upstream::authorise` would be proving the gate ran by asserting that it did.
