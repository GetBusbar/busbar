// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GOVERNED-CALL PORT — how a client-served tool call's reply reaches the node's own table.
//!
//! Two kinds of tool call cross a live session, and they end in different places.
//!
//! A call for a tool **this node serves** is the tool moat the design is built around
//! (`plane4-duplex-session.md` §2.2): the runtime accumulates the streamed arguments, executes the
//! tool in-process through [`crate::runtime::ToolExecutor`], and authors the `function_call_output`
//! itself. The client never sees it and could not forge it. Nothing about that path changes here.
//!
//! A call for a tool the node **does not** serve is the other half: the answer can only come from the
//! client, so the call's leg is a *wait*, and a wait belongs to the unit the kernel opened for the
//! call — not to the runtime. The root holds that table (`OpenToolCalls` on the voice node): it
//! enters the wait where the leg is planned, wakes it when a reply names the call, and sweeps the
//! ones nobody answered. The runtime's whole job is to be the thing that *tells* it — and this port
//! is that telling, dependency-inverted the same way [`crate::runtime::ToolExecutor`] is, because a
//! plane crate that named the composition root would be the I/O half deciding which unit an answer
//! belongs to.
//!
//! A node with no governed table bound keeps the pre-1.6.0 behaviour exactly: every call is served
//! in-process, and a client-authored result is carried upstream verbatim. The governed path is what a
//! composition root opts a session into.

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
/// Two questions and no more. The runtime never asks which unit a call belongs to, never asks how
/// long the deadline is, and never decides what a refusal costs — those are the kernel's, and a seam
/// wide enough to answer them would be wide enough to get them wrong.
pub trait GovernedCalls: Send + Sync {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A table that answers from a fixed set of open identifiers — enough to prove the runtime routes
    /// a reply to it and honours the answer.
    #[derive(Debug, Default)]
    pub struct FakeCalls {
        open: Mutex<Vec<(u64, String)>>,
        swept: Mutex<u64>,
    }

    impl GovernedCalls for FakeCalls {
        fn replied(&self, session: u64, call_id: &str) -> Result<(), ReplyRefusal> {
            let mut open = self.open.lock().unwrap();
            if !open.iter().any(|(s, _)| *s == session) {
                return Err(ReplyRefusal::NoSuchSession);
            }
            match open
                .iter()
                .position(|(s, c)| *s == session && c == call_id)
            {
                Some(i) => {
                    open.remove(i);
                    Ok(())
                }
                None => Err(ReplyRefusal::UnknownCall),
            }
        }

        fn expired(&self, now_ms: u64) -> usize {
            *self.swept.lock().unwrap() = now_ms;
            self.open.lock().unwrap().drain(..).count()
        }
    }

    #[test]
    fn a_reply_for_another_session_is_refused_as_no_such_session() {
        let calls = FakeCalls::default();
        calls.open.lock().unwrap().push((7, "ca".into()));
        assert_eq!(calls.replied(9, "ca"), Err(ReplyRefusal::NoSuchSession));
        assert_eq!(calls.replied(7, "cz"), Err(ReplyRefusal::UnknownCall));
        assert_eq!(calls.replied(7, "ca"), Ok(()));
        assert_eq!(calls.replied(7, "ca"), Err(ReplyRefusal::NoSuchSession));
    }
}
