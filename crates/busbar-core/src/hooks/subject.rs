// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REQUEST, AS A HOOK IS SHOWN IT — one subject type and one projection, shared by every hook
//! verb that fires from a protocol plane.
//!
//! # Why this is its own module, and why it is not `gate.rs`'s private detail any more
//!
//! It was. [`RequestSubject`] was `gate::GateSubject` and [`project`] was a private `fn` beside it,
//! which was correct while the GATE was the only verb any plane but the model plane could reach.
//! The consequence, written into the equality ledger as four missing cells, was that a hook could
//! REFUSE an MCP tool call or an A2A delegation and could not OBSERVE one: `.notify(` had exactly
//! two production call sites and both were under `proxy/`.
//!
//! The reason nobody closed those cells was believed to be a payload problem — that the tap contract
//! is a chat body, so no protocol could ever present itself to it. **That is true of the REWRITE
//! verb and false of the OBSERVE verb**, and this module is where the difference is made
//! structural. A rewrite REPLACES a body, and its reply
//! ([`busbar_api::RewriteReply`]) is `{messages, tools}` — a chat body, which cannot express
//! "replace this invocation's `arguments`". An observation only has to PRESENT a request, and
//! [`crate::ir::facts::IrFacts`] is exactly that presentation: a family-blind seam every protocol
//! already implements (`ir::facts` for the chat family, `ir::invoke` for the invocation family).
//! The gate has been reading requests through it since the seam landed. Nothing about the payload
//! contract stood in the tap's way; a FIRING SITE did.
//!
//! # One subject, deliberately, for the gate and the tap alike
//!
//! A tap shown a different projection from the gate would be an audit trail of something other than
//! what was screened — the same class of defect `ir/facts.rs`'s own header describes, where a
//! redactor passed a request whose real payload it never saw. So the two verbs take the SAME subject
//! type and build their projection with the SAME function, and the only difference between them is
//! what they do with the answer: the gate awaits a verdict, the tap spawns and forgets.

use crate::hooks::{PromptProjection, RoutingRequest};
use crate::ir::facts::{ContentItem, IrFacts, Slot};
use std::borrow::Cow;

/// Everything a firing site knows about one request, gathered so no argument can be transposed with
/// another. Borrowed throughout: nothing here is stored past the call.
pub(crate) struct RequestSubject<'a> {
    /// The request, behind the family-blind seam. The ONLY thing this module learns about it.
    ///
    /// `+ Sync` because this borrow is held across the gate's `.await`, and an axum handler's future
    /// must be `Send`. It is a bound on the OBJECT, not a new obligation on the IR: every IR type is
    /// plain owned data.
    pub(crate) facts: &'a (dyn IrFacts + Sync),
    /// The CONTAINER the request is addressed to — a pool, an MCP server, an A2A agent. This is
    /// the routing fact `IrFacts` deliberately cannot answer (see that trait's note on the absent
    /// `target()`), so the firing site, which resolved it, supplies it.
    pub(crate) container: &'a str,
    /// The dialect label, verbatim onto the wire. DATA: no code here compares it.
    pub(crate) ingress_protocol: &'a str,
    /// The request-spine correlation id, so a hook can join this decision to the request's other
    /// records.
    pub(crate) request_id: u64,
    /// The caller's resolved governance key, for the `user: ro` identity projection. `None` when
    /// governance is disabled or the plane resolved no key.
    pub(crate) key: Option<&'a busbar_api::VirtualKey>,
}

/// Build ONE hook's projection from the facts, gated by THAT hook's grants.
///
/// Built per hook rather than once per request because the grants are per hook: a `prompt: no` hook
/// must not merely have the content withheld from its wire, it must never have had it built, which
/// is also what keeps the cost of a shape-only hook a shape-only cost.
pub(crate) fn project<'a>(
    subject: &'a RequestSubject<'_>,
    items: &'a [ContentItem<'a>],
    send_prompt: bool,
    send_user: bool,
) -> RoutingRequest<'a> {
    let shape = subject.facts.shape();
    RoutingRequest {
        request_id: subject.request_id,
        pool: subject.container,
        ingress_protocol: subject.ingress_protocol,
        // RESERVED on the shared wire (it is projected by no transport today), so this is carried
        // for a future reader rather than claimed as a delivered signal. The target a hook can
        // actually READ rides the content projection, as the label of the item that carries the
        // arguments.
        requested_model: None,
        message_count: shape.turn_count,
        tool_count: 0,
        has_tools: shape.has_tools,
        total_chars: shape.text_chars,
        // The system slot's chars, summed over the SAME items the projection shows.
        system_chars: items
            .iter()
            .filter(|i| i.slot() == Slot::System)
            .map(|i| i.screenable_text().chars().count())
            .sum(),
        max_tokens: shape.max_tokens,
        stream: subject.facts.wants_stream(),
        prompt: send_prompt.then(|| PromptProjection {
            system: join_system(items),
            messages: items
                .iter()
                .filter(|i| i.slot() != Slot::System)
                .map(|i| (Cow::Borrowed(role_label(i.role())), i.screenable_text()))
                .collect(),
        }),
        identity: send_user.then(|| crate::hooks::CallerIdentity {
            key_id: subject.key.map(|k| k.id.clone()),
            key_name: subject.key.map(|k| k.name.clone()),
            // The BODY's end-user field, which is a different fact from the key: a protocol whose
            // requests carry none answers `None` here rather than borrowing the key's identity for
            // it.
            user: subject.facts.end_user().map(str::to_string),
        }),
        // No request-phase catalog signal is wired to this seam in this pass; the core fields above
        // are what these protocols can answer today.
        signals: Default::default(),
    }
}

/// The system slot, flattened — `None` when the request has none, which is what the wire contract
/// says absence means (a granted hook keys the grant off `messages`, never off `system`).
fn join_system<'a>(items: &'a [ContentItem<'a>]) -> Option<Cow<'a, str>> {
    let mut parts = items
        .iter()
        .filter(|i| i.slot() == Slot::System)
        .map(ContentItem::screenable_text)
        .peekable();
    let first = parts.next()?;
    if parts.peek().is_none() {
        return (!first.is_empty()).then_some(first);
    }
    let mut out = first.into_owned();
    for p in parts {
        out.push('\n');
        out.push_str(&p);
    }
    (!out.is_empty()).then_some(Cow::Owned(out))
}

/// The CANONICAL role vocabulary on the hook wire. One mapping, here, because the hook contract
/// promises a normalized IR and a dialect's own spelling (`model`, `tool_use`) reaching a hook is
/// how a rewrite hook echoed back a role its target protocol then mangled.
fn role_label(role: crate::ir::IrRole) -> &'static str {
    match role {
        crate::ir::IrRole::System => "system",
        crate::ir::IrRole::User => "user",
        crate::ir::IrRole::Assistant => "assistant",
        crate::ir::IrRole::Tool => "tool",
    }
}
