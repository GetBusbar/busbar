// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NODE'S OPEN-CALL TABLE — every client-served tool call this node's sessions have open, and the
//! one port the session runtime reaches it through.
//!
//! Two kinds of tool call cross a live session. A call for a tool this node serves is executed
//! in-process and the client never authors its result. A call for a tool the node does NOT serve has
//! only one possible answerer, so its leg is a wait: the runtime plans it
//! ([`GovernedCalls::planned`]), the client's reply names the call it answers
//! ([`GovernedCalls::replied`]), and the tick beside the pump ends the ones nobody answered
//! ([`GovernedCalls::expired`]). Which answer wakes which wait is decided here, once, by
//! [`OpenToolCalls`]; the runtime learns nothing but whether a reply was taken.
//!
//! This plane installs the table itself, from its own linked entry (its `compose` step, see
//! [`crate::mount`]): one table per node, set once, bound to every session the served door opens. A
//! served session that ends forgets its calls ([`GovernedCalls::closed`]), and an answered or swept
//! call's row leaves the table with its wait — on the served path no per-call unit is left to read
//! how a call ended, so the port reads it.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::dest::ClientMode;
use busbar_contract::ids::{CorrelationRef, CorrelationValue, UnitKey};
use busbar_contract::reply::{AwaitingReplies, NotWaiting};
use busbar_contract::Millis;
use busbar_plane_streaming::governed::{GovernedCalls, ReplyRefusal};

/// The leg a provider-pushed tool call plans: deliver it to the client, and wait for the answer.
///
/// The key and the deadline are the plane's own declarations, read from it rather than restated. A
/// second spelling of either here would be a wait entered under one key and answered under another,
/// with both files looking correct on their own.
pub const TOOL_REPLY_LEG: ClientMode = ClientMode::AwaitReply {
    correlation_key: busbar_plane_streaming::plane::FACT_TOOL_CORRELATION,
    deadline_secs: busbar_plane_streaming::plane::TOOL_REPLY_DEADLINE_SECS,
};

/// Why a client's tool reply woke nothing.
///
/// Refused rather than dropped, and that is the whole of this type. A reply nobody is waiting for is
/// either a client answering a call it was never asked to make or a call this node has already
/// ended, and both are worth being able to say — a dropped frame is indistinguishable from a frame
/// that was never sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyRefused {
    /// This node holds no tool calls on that session.
    NoSuchSession,
    /// The session is here, but nothing open on it is waiting on the identifier the reply carried.
    UnknownCall,
}

/// What became of one tool call, once it stopped waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallEnd {
    /// The client answered it, carrying the identifier the call was entered under.
    Answered,
    /// Nobody answered before the deadline the leg declared.
    Unanswered,
}

/// One call the sweep found unanswered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnansweredCall {
    /// Which session it was open on.
    pub session: u64,
    /// Which unit was waiting.
    pub unit: UnitKey,
}

/// One session's open calls, and the endings its units have not read yet.
#[derive(Debug, Default)]
struct SessionCalls {
    /// The waiting table: which reply wakes which unit.
    awaiting: AwaitingReplies,
    /// How a call ended, held until the unit's exit path reads it.
    ended: HashMap<UnitKey, CallEnd>,
}

/// Every tool call this node has open, session by session.
///
/// [`AwaitingReplies`] answers "which unit does this reply wake" and is deliberately keyed by unit
/// alone; it is one session's table, and this is what holds one per session. The division matters:
/// two sessions may legitimately have calls open under identical identifiers — providers mint them
/// per conversation — and a single node-wide table would have to decide which of them a reply
/// belonged to before it had the session to decide it with.
///
/// The endings sit beside the waits rather than inside them because they outlive the wait by exactly
/// one read: the pump wakes or sweeps, and whatever ends the call is what reads what happened to it.
/// A call's ending is final — re-planning a leg for a unit that already ended does not reopen it,
/// which is what keeps a resumed unit from waiting a second time on an answer that is not coming.
#[derive(Debug, Default)]
pub struct OpenToolCalls {
    sessions: Mutex<BTreeMap<u64, SessionCalls>>,
}

impl OpenToolCalls {
    /// A node holding no calls.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enter a tool call's reply leg as waiting, in the frame that planned it.
    ///
    /// `correlation_out` is borrowed for the length of this call: the waiting table copies the
    /// identifier into its own memory here, which is the one moment it is guaranteed readable.
    ///
    /// # Errors
    /// Returns why the leg is not a wait: it delivers, the unit minted no identifier for an answer
    /// to carry, or the draft's key is not the one the leg named.
    pub fn planned(
        &self,
        session: u64,
        unit: UnitKey,
        mode: ClientMode,
        correlation_out: Option<CorrelationRef<'_>>,
        now: Millis,
    ) -> Result<(), NotWaiting> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let calls = sessions.entry(session).or_default();
        if calls.ended.contains_key(&unit) {
            // The call is over and its ending has not been read yet. Entering it again would be a
            // second wait on an answer that has already come or already timed out.
            return Ok(());
        }
        calls.awaiting.enter(unit, mode, correlation_out, now)
    }

    /// The unit a client's reply answers, taken out of the table.
    ///
    /// # Errors
    /// The session holds no calls, or nothing open on it carries that identifier under that key.
    pub fn replied(
        &self,
        session: u64,
        correlates: CorrelationRef<'_>,
    ) -> Result<UnitKey, ReplyRefused> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let calls = sessions
            .get_mut(&session)
            .ok_or(ReplyRefused::NoSuchSession)?;
        let unit = calls.awaiting.wake(correlates).ok_or(
            // Not "the only call open", and not silence either. A reply that matches nothing is
            // refused as what it is, because paying it out against whichever call happens to be
            // standing is the exact failure the whole correlation exists to prevent.
            ReplyRefused::UnknownCall,
        )?;
        calls.ended.insert(unit, CallEnd::Answered);
        Ok(unit)
    }

    /// **The sweep.** Every call whose declared deadline has passed, named so its unit can be ended.
    ///
    /// A wait that is never woken is a hold that is never settled, so this runs on the session's
    /// tick rather than being something a caller is trusted to remember. What it leaves behind is the
    /// ending the call's reader takes.
    pub fn expired(&self, now: Millis) -> Vec<UnansweredCall> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let mut swept = Vec::new();
        for (session, calls) in sessions.iter_mut() {
            for unit in calls.awaiting.expired(now) {
                calls.ended.insert(unit, CallEnd::Unanswered);
                swept.push(UnansweredCall {
                    session: *session,
                    unit,
                });
            }
        }
        swept
    }

    /// How one call ended, taken out of the table.
    ///
    /// Read once. Taking it rather than copying it is what keeps the table the size of the calls
    /// that are actually open: an ending nobody reads is a row that never comes back out.
    pub fn ending(&self, session: u64, unit: UnitKey) -> Option<CallEnd> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let calls = sessions.get_mut(&session)?;
        calls.ended.remove(&unit)
    }

    /// Whether one unit is still waiting on its answer.
    #[must_use]
    pub fn waiting(&self, session: u64, unit: UnitKey) -> bool {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions
            .get(&session)
            .is_some_and(|calls| calls.awaiting.waiting(unit).is_some())
    }

    /// How many calls are open across every session.
    #[must_use]
    pub fn open(&self) -> usize {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.values().map(|calls| calls.awaiting.len()).sum()
    }

    /// How many rows the table holds across every session: the open waits, and the endings not yet
    /// read. What a table that frees its rows returns to zero on.
    #[must_use]
    pub fn rows(&self) -> usize {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions
            .values()
            .map(|calls| calls.awaiting.len() + calls.ended.len())
            .sum()
    }

    /// Forget a session's calls, when the session itself ends.
    ///
    /// A conversation that is over cannot answer anything, so its waits end with it rather than
    /// waiting out deadlines nobody is left to satisfy.
    pub fn closed(&self, session: u64) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.remove(&session);
    }
}

/// The node's open-call table, as the session runtime reaches it.
///
/// What crosses is a session and a call identifier and no more: the runtime never learns which unit a
/// call belongs to, how long its deadline is, or what a refusal costs.
#[derive(Debug, Default)]
pub struct NodeCalls {
    table: Arc<OpenToolCalls>,
    /// The unit key each planned client-served leg is entered under. A served session runs no unit
    /// per call, so the port mints one: unique on this node, which is all the table's per-session
    /// map needs of it.
    next_unit: AtomicU64,
}

impl NodeCalls {
    /// Bind the port to one node's table.
    #[must_use]
    pub fn new(table: Arc<OpenToolCalls>) -> Self {
        NodeCalls {
            table,
            next_unit: AtomicU64::new(1),
        }
    }

    /// The table this port answers from.
    #[must_use]
    pub fn table(&self) -> &Arc<OpenToolCalls> {
        &self.table
    }
}

/// The correlation a call is waited on and answered under: the identifier the model minted, under
/// the key the plane's leg names — the one pair `planned` enters and `replied` answers.
fn tool_call(call_id: &str) -> CorrelationRef<'_> {
    CorrelationRef {
        fact_key: busbar_plane_streaming::plane::FACT_TOOL_CORRELATION,
        value: CorrelationValue::Str(call_id),
    }
}

impl GovernedCalls for NodeCalls {
    fn planned(&self, session: u64, call_id: &str, now_ms: u64) -> bool {
        let unit = UnitKey::new(self.next_unit.fetch_add(1, Ordering::Relaxed));
        self.table
            .planned(
                session,
                unit,
                TOOL_REPLY_LEG,
                Some(tool_call(call_id)),
                now_ms,
            )
            .is_ok()
    }

    fn replied(&self, session: u64, call_id: &str) -> Result<(), ReplyRefusal> {
        match self.table.replied(session, tool_call(call_id)) {
            // The wait was woken, and no unit on the served path is left to read how the call
            // ended: the port reads it, so the answered call's row leaves the table with its wait.
            Ok(unit) => {
                let _ = self.table.ending(session, unit);
                Ok(())
            }
            Err(ReplyRefused::NoSuchSession) => Err(ReplyRefusal::NoSuchSession),
            Err(ReplyRefused::UnknownCall) => Err(ReplyRefusal::UnknownCall),
        }
    }

    fn expired(&self, now_ms: u64) -> usize {
        // The sweep ends every call past the deadline its leg declared; the port reads each ending,
        // so a swept call's row leaves the table too. A count is all the pump can do anything with.
        let swept = self.table.expired(now_ms);
        for call in &swept {
            let _ = self.table.ending(call.session, call.unit);
        }
        swept.len()
    }

    fn closed(&self, session: u64) {
        self.table.closed(session);
    }
}

#[cfg(test)]
#[path = "tests/governed_table_tests.rs"]
mod tests;
