// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `notifications/roots/list_changed`, RECEIVED — the one thing a stateless server can honestly do
//! with it, and why that thing is not nothing.
//!
//! ## What the notification means, and what busbar holds that it could possibly invalidate
//!
//! A client sends `notifications/roots/list_changed` to say its filesystem roots are no longer what
//! they were. A server that caches a `roots/list` answer re-requests it. busbar holds no such cache
//! — it asks for roots as an `inputRequest` on the request that needs them, and the caller supplies
//! its CURRENT roots on the retry — so for a long time this plane's answer was "there is nothing to
//! invalidate" and the cell was waived on that sentence.
//!
//! The sentence was one word too strong. There IS a window in which busbar is holding a
//! roots-derived fact on a caller's behalf: the life of a sealed `requestState`. An exchange that
//! asked for roots mints state with a [`busbar_core::plane::approvals::DEFAULT_TTL_SECS`] window, and inside
//! that window the caller can redeem an answer it gave BEFORE its roots changed. The caller has
//! told busbar, in the protocol's own vocabulary, that the answer is stale — and a server that then
//! redeems it is dispatching on roots the client just disavowed.
//!
//! ## The mechanism: an epoch per principal, sealed into roots-bearing state
//!
//! Every authenticated principal has a ROOTS EPOCH, starting at zero. Receiving the notification
//! bumps it. When [`crate::mcp::callerask::decide`] mints state for an exchange whose configured
//! rounds include a `roots/list` ask, the CURRENT epoch is sealed into the blob; when such state is
//! presented, the sealed epoch is compared against the live one, and a mismatch refuses with
//! [`busbar_substrate::plane::approvals::Rejected::StaleRoots`] — the caller restarts the exchange and answers
//! with its current roots. State minted for exchanges that never asked for roots carries no epoch
//! and is untouched, so a chatty client cannot invalidate its own unrelated confirmations.
//!
//! ## Why this is in-process state on a plane that refuses sessions
//!
//! The revision's objection to sessions is state a client must establish and a server must hold to
//! CORRELATE requests. This map is neither: nothing establishes it (absence means epoch zero, which
//! is correct for a caller that never announced a change), nothing correlates through it, and losing
//! it on a restart fails SAFE — a lost bump un-invalidates at most one TTL window of state, on a
//! fleet where the node that receives the notification may not be the node that minted the state
//! anyway. The map is bounded by the deployment's own key population: the principal is the
//! authenticated key id (or the one honest constant on an ungoverned deployment), never a
//! caller-chosen string, so a caller cannot grow it by inventing names.

use std::collections::HashMap;
use std::sync::Mutex;

/// The wire method, spelled once. `rmcp`'s constant for this name lives on the CLIENT leg's
/// classifier ([`crate::mcp::client::peer`]); this is the SERVER direction of the same message, and
/// the two directions deliberately read one spelling each way on their own plane.
pub(crate) const METHOD_NOTIFY_ROOTS_LIST_CHANGED: &str = "notifications/roots/list_changed";

/// The per-principal roots epochs. One instance per deployment, carried across config applies on
/// [`busbar_core::state::App`] exactly as the spent-approval ledger is, and for the same reason: a bump
/// is what a CALLER said, not what the operator configured, and a config apply must not erase it.
#[derive(Debug, Default)]
pub(crate) struct RootsEpochs {
    epochs: Mutex<HashMap<String, u64>>,
}

impl RootsEpochs {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The live epoch for `principal`. Zero for a principal that has never announced a change,
    /// which is why absence from the map needs no initialisation step.
    pub(crate) fn current(&self, principal: &str) -> u64 {
        self.epochs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(principal)
            .copied()
            .unwrap_or(0)
    }

    /// Record that `principal` announced its roots changed. Every outstanding roots-bearing
    /// `requestState` sealed under the previous epoch stops verifying for this principal — and for
    /// no other, which is the assertion that makes this a per-principal fact rather than a global
    /// reset lever any caller can pull on everyone.
    pub(crate) fn note_change(&self, principal: &str) {
        let mut epochs = self.epochs.lock().unwrap_or_else(|e| e.into_inner());
        let slot = epochs.entry(principal.to_string()).or_insert(0);
        *slot = slot.saturating_add(1);
    }
}

/// SATISFY an upstream's ask, where the operator made that possible — which today is `roots/list`
/// and only that.
///
/// ## The other direction of the same capability, and why it lives in this file
///
/// The module header is about busbar-as-SERVER being told roots changed. This is busbar-as-CLIENT
/// being ASKED for roots: a fronted upstream answers busbar's `tools/call` with an
/// `InputRequiredResult` naming `roots/list`, and [`crate::mcp::inputreq::drive`] — after the
/// per-round grant gate admits it — hands the ask here. What busbar discloses is the OPERATOR'S
/// declaration (`tools.<server>.roots`), never busbar's own container filesystem: busbar's
/// deployment is not the customer's workspace, and answering from it would describe busbar to the
/// upstream instead of anything the customer meant. No declaration ⇒ the ask stays refused, with
/// the exact key in the refusal, because `Unsatisfiable`'s whole contract is that its message is
/// the remedy.
///
/// The `sampling` kind is dispatched to its own satisfier before this function is reached — see
/// [`crate::mcp::sampling`], which is this policy's shape on the other grant. `elicitation` (and
/// any kind this build has never heard of) falls through to the standing refusal below, worded as
/// it always was: there is no human to interrupt, and that decision is recorded in `qa/WAIVERS.md`
/// rather than here.
///
/// ## The shape returned
///
/// `{ "inputResponses": { <key>: { "roots": [...] } }, "requestState": <echoed> }` — MRTR's own
/// continuation members, which [`crate::mcp::client::jsonrpc::tools_call`] copies onto the retry BY
/// NAME. The `requestState` is the upstream's own opaque blob, echoed exactly: it is meaningful
/// only to the server that minted it and busbar neither inspects nor repairs it.
pub(crate) fn satisfy_upstream_ask(
    ask: &super::inputreq::Ask,
    server: &str,
    roots: &[super::config::RootCfg],
) -> Result<serde_json::Value, String> {
    if ask.kind != "roots" {
        // The standing refusal for the kinds busbar deliberately does not satisfy. The wording is
        // the one this plane has always used, because operators grep their logs for it.
        return Err(format!(
            "busbar holds the `{}` grant for this server but has no satisfier for that ask in \
             this release; the ask terminates here and is not proxied to you",
            ask.kind
        ));
    }
    if roots.is_empty() {
        return Err(format!(
            "busbar holds the `roots` grant for server `{server}` and no `tools.{server}.roots` \
             list is declared, so there is nothing busbar may disclose; the ask terminates here \
             and is not proxied to you. Declare `tools.{server}.roots:` if the operator intends \
             this server to be told about a workspace."
        ));
    }
    // The entries this ask actually made, by the map key the retry must address its answers to.
    // The kind was judged over the WHOLE map by `input_required_kind` (most privileged wins), so
    // `kind == "roots"` proves every entry names `roots/list` — the arms below that refuse a mixed
    // or empty map are therefore fail-closed readings of shapes that cannot occur, not cases with
    // a meaning.
    let Some(requests) = ask.payload.get("inputRequests").and_then(|v| v.as_object()) else {
        return Err(
            "the upstream's roots ask names no `inputRequests` entry to address an answer to; \
             the ask terminates here"
                .to_string(),
        );
    };
    let answer = serde_json::json!({
        "roots": roots
            .iter()
            .map(|r| match &r.name {
                Some(name) => serde_json::json!({ "uri": r.uri, "name": name }),
                None => serde_json::json!({ "uri": r.uri }),
            })
            .collect::<Vec<_>>(),
    });
    let mut responses = serde_json::Map::new();
    for (entry, request) in requests {
        if request.get("method").and_then(|m| m.as_str()) != Some("roots/list") {
            return Err(format!(
                "the upstream's ask mixes `roots/list` with a method busbar has no satisfier \
                 for; the ask terminates here (entry `{entry}`)"
            ));
        }
        responses.insert(entry.clone(), answer.clone());
    }
    if responses.is_empty() {
        return Err(
            "the upstream's roots ask carries an empty `inputRequests` map; the ask terminates \
             here"
                .to_string(),
        );
    }
    let mut continuation = serde_json::Map::new();
    continuation.insert(
        "inputResponses".to_string(),
        serde_json::Value::Object(responses),
    );
    if let Some(state) = ask.payload.get("requestState") {
        continuation.insert("requestState".to_string(), state.clone());
    }
    Ok(serde_json::Value::Object(continuation))
}

#[cfg(all(test, not(busbar_mcp_native)))]
#[path = "tests/roots_changed_tests.rs"]
mod roots_changed_tests;

// The SATISFIER's battery hangs on `super::upstream` rather than here: its witness is the fake
// upstream peer (`upstream_support`), and the claim is about what left busbar on that leg.
