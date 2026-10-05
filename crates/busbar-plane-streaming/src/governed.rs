// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GOVERNED-CALL PORT — how a tool call's reply reaches the node's own table.
//!
//! A tool call is part of the model's response: the session relays it to the caller as-is, the
//! caller runs the tool, and busbar executes nothing (Law 11; QUESTIONS Q98). The answer can only
//! come from the caller, so the call's leg is a *wait*, and a wait belongs to the unit the kernel
//! opened for the call — not to the session. The node holds that table ([`crate::open_calls`]): it
//! enters the wait when the session relays the call's close, wakes it when a reply names the call,
//! and sweeps the ones nobody answered. The session's whole job is to be the thing that *tells* it,
//! and this port is that telling, dependency-inverted because a plane crate that named the
//! composition root would be the I/O half deciding which unit an answer belongs to.
//!
//! A session with no table bound carries a caller-authored result upstream verbatim.

/// Why a client's tool reply woke nothing.
///
/// The root's own refusal, carried across the seam unflattened. A reply that answers nothing is a
/// client answering a call it was never asked to make, or answering one this node has already ended,
/// and the two are worth telling apart — silently dropping either makes a frame that was refused
/// indistinguishable from a frame that was never sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyRefusal {
    /// This node holds no tool calls on that session.
    NoSuchSession,
    /// The session is here, but nothing open on it is waiting on the identifier the reply carried.
    UnknownCall,
}

/// THE NODE'S OPEN-CALL TABLE, as the runtime is allowed to see it.
///
/// Two facts told and two questions asked, and no more. The runtime never asks which unit a call
/// belongs to, never asks how long the deadline is, and never decides what a refusal costs — those
/// are the kernel's, and a seam wide enough to answer them would be wide enough to get them wrong.
pub trait GovernedCalls: Send + Sync {
    /// The runtime planned `call_id` on `session` as a client-served leg, as of `now_ms`: enter its
    /// wait. The table's one writer; without it every client reply answers nothing.
    ///
    /// Returns whether a wait was entered. `false` is a leg nothing can answer.
    fn planned(&self, session: u64, call_id: &str, now_ms: u64) -> bool;

    /// A client's reply named `call_id` on `session`. Wake the unit waiting on it.
    ///
    /// # Errors
    /// Nothing on that session is waiting under that identifier — see [`ReplyRefusal`].
    fn replied(&self, session: u64, call_id: &str) -> Result<(), ReplyRefusal>;

    /// **The sweep.** End every call whose declared deadline has passed as of `now_ms`, and say how
    /// many there were.
    ///
    /// Node-wide rather than per-session: one tick sweeps the node, which is the only shape in which
    /// a session whose pump has already stopped still has its unanswered calls ended.
    fn expired(&self, now_ms: u64) -> usize;

    /// **The session is over.** Forget every call `session` still has open: a conversation that has
    /// ended cannot answer anything, so its waits end with it rather than holding a row until a
    /// deadline nobody is left to meet. Told once, by the session's teardown.
    ///
    /// A table with nothing per session to forget has nothing to do, which is the default.
    fn closed(&self, _session: u64) {}
}

/// One session's binding to the node's table — the identifier the root keys its calls by, and the
/// table itself.
///
/// The session id is carried rather than derived because the runtime has no other way to name itself
/// to the root, and two sessions may legitimately hold calls open under identical identifiers: a
/// provider mints them per conversation.
#[derive(Clone)]
pub struct GovernedSession {
    /// Which session the root knows this pump as.
    pub session: u64,
    /// The node's table.
    pub calls: std::sync::Arc<dyn GovernedCalls>,
}

impl std::fmt::Debug for GovernedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GovernedSession")
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}
