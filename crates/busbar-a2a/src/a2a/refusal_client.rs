// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE CALLER'S RENDERING OF A HOP REFUSAL** — the half of [`RelayRefusal`] a client is allowed
//! to read, kept apart from the operator's half on purpose.
//!
//! [`super::relay`] owns the refusal type and its [`std::fmt::Display`], which NAMES THE BACKEND:
//! the URL, the address its name resolved to, and the backend's own prose. That is right for a
//! journal line and wrong for a response body, and for a while it was both, because `Display` was
//! what the card-fetch arm put on the wire. An authorised caller holding a grant on an agent could
//! read `agents.<agent>.url:` back out of busbar by taking that agent's backend down — the value
//! `docs/a2a.md` states is never client-visible, and the value `super::serve`'s `BackendLeak`
//! apparatus refuses to publish a card over.
//!
//! **The rule this file keeps is mechanical rather than a matter of care: no arm interpolates a
//! field that a backend, its DNS answer or its response body can influence.** It lives in its own
//! module so that rule has a boundary somebody can see — a new arm is written HERE, beside the
//! sentence that says so, rather than appended to the relay where the operator's rendering is the
//! nearest example to copy.

use super::relay::RelayRefusal;

impl RelayRefusal {
    /// THE STABLE TOKEN A CALLER MAY QUOTE. One per arm, never reused, and the whole of what a
    /// caller carries to an operator now that [`RelayRefusal::client_text`] says nothing else.
    ///
    /// It is deliberately NOT the `BUSBAR-NNNN` journal code: a diagnostic code is an OPERATOR's
    /// index into busbar's own catalogue and renumbering it is an operator-facing change, while
    /// this is a wire fact a client may branch on. They are two vocabularies and coupling them
    /// would mean a caller's error handling breaks when a diagnostic is retired.
    pub(crate) fn client_code(&self) -> &'static str {
        match self {
            RelayRefusal::Guard(_) => "a2a.hop.endpoint_refused",
            RelayRefusal::Demoted(_) => "a2a.hop.agent_not_serving",
            RelayRefusal::Lease(_) => "a2a.hop.credential_unavailable",
            RelayRefusal::Transport { .. } => "a2a.hop.transport_failed",
            RelayRefusal::Status { .. } => "a2a.hop.backend_status",
            RelayRefusal::BodyTooLarge { .. } => "a2a.hop.reply_too_large",
            RelayRefusal::NotJson { .. } => "a2a.hop.reply_not_json",
            RelayRefusal::BackendError { .. } => "a2a.hop.backend_refused",
            RelayRefusal::Uncorrelated { .. } => "a2a.hop.reply_uncorrelated",
            RelayRefusal::Unframable { .. } => "a2a.hop.unframable",
            RelayRefusal::BreakerOpen { .. } => "a2a.hop.breaker_open",
        }
    }

    /// THE CALLER'S RENDERING, as distinct from [`std::fmt::Display`], which is the OPERATOR'S.
    ///
    /// `Display` names the backend — the URL, the resolved address, the backend's own prose — and
    /// it is right that it does: it goes to the journal, where an operator diagnosing a hop needs
    /// exactly that. It was ALSO going into the response body on the card-fetch arm
    /// (`super::receive::refuse_hop_early`), so an authorised caller with a grant on an agent could
    /// read `agents.<agent>.url:` out of a refusal by taking the backend down — the value
    /// `docs/a2a.md` states is never client-visible and that `super::serve`'s `BackendLeak`
    /// apparatus refuses to publish a CARD over.
    ///
    /// So: a stable code and a FIXED sentence per arm. The rule this rendering keeps is mechanical
    /// rather than a matter of care — **no arm interpolates a field that a backend, its DNS answer
    /// or its response body can influence.** Two arms interpolate at all, and both interpolate
    /// facts that are busbar's own and never the backend's:
    ///
    /// * `Unframable` names the BINDING WORD off the agent's registration and the METHOD the caller
    ///   itself sent. Neither is an address, and an operator reading a customer's ticket needs both
    ///   to know which of the three legs refused.
    /// * `BreakerOpen` names the AGENT ID the caller addressed and the cell's exact remaining
    ///   cooldown, which is the same number the `Retry-After` header carries.
    ///
    /// `super::receive::refuse_hop`'s own arms already carried fixed strings for this reason; this
    /// makes the property one function rather than a habit spread over call sites.
    pub(crate) fn client_text(&self) -> String {
        let sentence = match self {
            RelayRefusal::Guard(_) => {
                "busbar's egress guard refused the registered endpoint for this agent"
            }
            RelayRefusal::Demoted(_) => "this agent is not currently serving",
            RelayRefusal::Lease(_) => {
                "busbar could not present the credential this agent is configured with, so the \
                 request was not sent"
            }
            RelayRefusal::Transport { .. } => "busbar could not reach this agent's backend",
            RelayRefusal::Status { .. } => "this agent's backend refused busbar's request",
            RelayRefusal::BodyTooLarge { .. } => {
                "this agent's backend replied with more than the configured ceiling"
            }
            RelayRefusal::NotJson { .. } => {
                "this agent's backend replied with something that is not a JSON-RPC answer"
            }
            RelayRefusal::BackendError { .. } => "this agent's backend refused the request",
            RelayRefusal::Uncorrelated { .. } => {
                "this agent's backend answered something busbar cannot correlate to the request it \
                 sent, so it is refused rather than relayed"
            }
            RelayRefusal::Unframable {
                binding, method, ..
            } => {
                // THE ONE CARD-SUPPLIED WORD THIS RENDERING CARRIES, and the free-text `reason`
                // deliberately not. They are different kinds of thing: `binding` is the transport
                // name off the agent's own card and is the word an operator has to act on (a card
                // declaring a binding this build cannot speak is unreachable until somebody changes
                // it), while `reason` is a framing/parse error computed over the BACKEND'S BYTES and
                // can carry whatever a backend put in them. Carrying `reason` would make this arm a
                // general echo channel from a backend into a caller's error body, which is the
                // class of defect the whole split exists to close.
                //
                // And the word is BOUNDED before it is rendered: a card is a document a backend
                // controls, so it is clamped to a short token of an identifier-shaped alphabet.
                // An operator still reads their own `SOAP-1.2-OVER-CARRIER-PIGEON`; a backend
                // cannot write a paragraph, a URL or a control character through it.
                return format!(
                    "{}: `{}` could not be carried to this agent over its `{}` binding",
                    self.client_code(),
                    bounded_word(method),
                    bounded_word(binding),
                );
            }
            RelayRefusal::BreakerOpen {
                agent_id,
                retry_after_secs,
            } => {
                return format!(
                    "{}: agent `{agent_id}` is unavailable: its circuit breaker is open after \
                     repeated backend failures; busbar did not dispatch this request. Retry after \
                     {retry_after_secs}s",
                    self.client_code()
                )
            }
        };
        format!("{}: {sentence}", self.client_code())
    }
}

/// ONE UNTRUSTED WORD, MADE SAFE TO PUT IN A CALLER'S ERROR BODY.
///
/// [`RelayRefusal::client_text`] carries exactly two words that busbar did not author — the binding
/// name off an agent's card and the method name off the caller's own envelope — because both are
/// what makes that one refusal actionable. Neither is trusted: a card is a document a backend
/// controls and an envelope is a document a caller controls. So the word is clamped to a short
/// token of an identifier-shaped alphabet, and everything else becomes `?`. A URL cannot survive it
/// (`:` and `/` are not in the set), nor a control character, nor a paragraph.
///
/// An empty result renders as `?` rather than as nothing, so a sentence never silently loses the
/// noun it was written around.
fn bounded_word(word: &str) -> String {
    const MAX: usize = 48;
    let mut out: String = word
        .chars()
        .take(MAX)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/') {
                c
            } else {
                '?'
            }
        })
        .collect();
    // `/` is in the set because A2A's own v0.3 method vocabulary is slash-separated
    // (`tasks/pushNotificationConfig/set`), and a method a caller sent is a word this plane must be
    // able to quote back. A scheme cannot ride it out: `:` is not in the set, so a URL loses its
    // authority separator and its scheme before this ever renders.
    if out.is_empty() {
        out.push('?');
    }
    out
}
