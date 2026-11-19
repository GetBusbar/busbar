// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SENDING A REQUEST AGAIN, FROM EVIDENCE: what an exchange does when its attempt fails.
//!
//! v1.5.5's HTTP library sent an unsent request again when a kept connection turned out closed.
//! 1.6.0 lost that: the keep-alive race became a failover and a breaker charge. This restores it
//! on evidence the engine holds itself: the attempt's own delivery state
//! (`crate::outbound::delivery`), decided by `crate::outbound::redial::decide`.
//!
//! * One redial per exchange, always a fresh dial (judged again, through the proxy again where
//!   one is chosen), never another kept connection.
//! * The walk is not told: the caller's read simply pends until the fresh connection answers.
//! * The request's head stays with the engine while a redial is still possible
//!   (`redial::keeps_head`), and its sealed values never leave their slots; both are wiped the
//!   moment it is not.
//! * What was decided is kept on the exchange (`evidence`, `charge`) for the walk's breaker and
//!   the unit's record: a proxy failure and a redial charge no provider.
//!
//! DECLARED by `native_conns.rs`, whose `Exchange` carries these fields and calls these functions:
//!
//!
//! ```text
//! reopen: Option<Reopen>,          // what `open_native` computed, to dial again
//! kept: bool,                      // the connection was lent (idle, or a stream on one in use)
//! redialled: bool,                 // the one redial is spent
//! resend: bool,                    // the connector must judge and dial again before the next poll
//! sealed: Option<Slots>,           // sealed values handed back for the next head
//! evidence: SmallVec<[Recorded; 2]>,   // one entry per attempt, in order
//! charge: bool,                    // the final failure charges the provider
//! ```
//!
//! and `Connector` this one:
//!
//! ```text
//! redials: AtomicU64,              // requests sent again on a fresh connection
//! ```
//!
//! and `Sending` keeps its `head` (lent to `poll_send_head`, not taken) until
//! [`Exchange::let_go_of_head`] says so.

use std::sync::{Arc, Mutex};
use std::task::Waker;

use busbar_contract::conn::ConnError;

use super::{error_of, Exchange, PendingDial, State};
use crate::conns::native_dial::NativeFailure;
use crate::conns::Answer;
use crate::outbound::delivery;
use crate::outbound::redial::{self, Recorded};
use crate::outbound::seal::Slots;

/// What `open_native` computed for an open, kept so the same request can be dialled again.
#[derive(Clone)]
pub(crate) struct Reopen {
    /// The dial, as it was planned (cloned for each dial: reference counts and one small text).
    pub(crate) dial: PendingDial,
    /// The class the target is judged in.
    pub(crate) judged_class: u32,
    /// The opener's reach to its own origin.
    pub(crate) reach: bool,
}

impl Exchange {
    /// REPLACES `Exchange::fail` at every call site. Decides from what was sent of this attempt:
    /// send again (the answer is `ConnError::Pending`: the caller's poll pends and the connector
    /// dials afresh), or fail for good with the charge and the record decided.
    pub(super) fn attempt_failed(&mut self, failure: &NativeFailure) -> ConnError {
        // What was sent of this attempt, how the far end itself ended it where it said so, whether a
        // session had begun, and whether any of its answer was handed up.
        let (sent, far_end, began, answered) = match (&self.state, self.stream) {
            (State::Dialled(conn), Some(stream)) => (
                conn.sent_state(stream),
                conn.far_end_ended(stream),
                true,
                conn.answered(stream),
            ),
            (State::Dialled(conn), None) => {
                (delivery::State::None, None, conn.session_began(), false)
            }
            (State::Judging { .. } | State::Gone, _) => (delivery::State::None, None, false, false),
        };
        let ended = crate::conns::native_dial::drive::ended_of(failure, far_end, began);
        // A busy connection is a lent one by its nature: the request goes elsewhere, nobody is charged.
        let kept = self.kept || failure.is_busy();
        let decision = redial::decide(sent, ended, kept, self.redialled);
        self.evidence.push(decision.record);
        let has_head = self.reopen.is_some()
            && self
                .sending
                .as_ref()
                .is_some_and(|sending| sending.head.is_some());
        // Nothing is ever sent again once a piece of its answer was handed to the caller.
        if decision.resend && has_head && !answered {
            // The sealed values come back from the failed connection, rewound: from the stream's slots, or
            // (a busy connection, no stream opened) as the transport's answer handed them back. A head
            // whose values were already wiped is not sent again: it would go without them.
            let sealed = match (&mut self.state, self.stream) {
                (State::Dialled(conn), Some(stream)) => conn.stream_over(stream, true),
                (State::Dialled(conn), None) => Some(conn.take_handed_back().unwrap_or_default()),
                (State::Judging { .. } | State::Gone, _) => Some(Slots::default()),
            };
            if let Some(sealed) = sealed {
                self.sealed = Some(sealed);
                // The failed connection is dropped here: closed, its buffers wiped. A busy one is live and
                // goes on serving the streams it has; it is left to them (dropping this exchange's hold).
                self.state = State::Gone;
                self.stream = None;
                if let Some(sending) = self.sending.as_mut() {
                    sending.sent = 0;
                }
                self.redialled = true;
                self.resend = true;
                self.kept = false;
                return ConnError::Pending;
            }
        }
        self.charge = decision.charge;
        self.let_go_of_head(true);
        let error = error_of(failure);
        self.failed = Some(error);
        self.cause = Some(failure.cause.clone());
        error
    }

    /// CALLED after every poll that moved the exchange (in `send` once the body is handed over,
    /// and in `read` after each piece): the head, the body's share and the sealed values are let
    /// go of as soon as the request can no longer be sent again. `force` = the exchange is over.
    pub(super) fn let_go_of_head(&mut self, force: bool) {
        let keeps = !force
            && match (&self.state, self.stream) {
                (State::Dialled(conn), Some(stream)) => redial::keeps_head(
                    conn.sent_state(stream),
                    conn.session_multiplexes(),
                    conn.answered(stream),
                    self.redialled,
                ),
                // Not sent at all yet: the head is still to go.
                _ => true,
            };
        if keeps {
            return;
        }
        let handed_over = self
            .sending
            .as_ref()
            .is_some_and(|sending| sending.sent >= sending.body.len());
        if force || handed_over {
            // Dropping the head wipes its target and every value; the body's share is let go.
            self.sending = None;
            self.reopen = None;
            self.sealed = None;
        }
        if let (State::Dialled(conn), Some(stream)) = (&mut self.state, self.stream) {
            conn.release_head(stream);
        }
    }

    /// What is recorded of the attempts, in order (a redial, a refused-unprocessed re-send, the
    /// final failure with what was sent).
    pub(crate) fn evidence(&self) -> &[Recorded] {
        &self.evidence
    }

    /// Whether the final failure charges the provider's breaker. A proxy failure, the engine's
    /// own refused head and a redial do not.
    pub(crate) fn charges(&self) -> bool {
        self.charge
    }
}

impl crate::conns::Connector {
    /// A redial is counted.
    fn count_redial(&self) {
        self.redials
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Requests this connector sent again on a fresh connection since it started.
    #[must_use]
    pub fn redials(&self) -> u64 {
        self.redials.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// CALLED by the native read, write and wait wrappers right after a poll answered
    /// `ConnError::Pending` with `exchange.resend` set: the same request is judged and dialled
    /// afresh. Never a kept connection. `waker` is woken at once: the caller's next poll drives
    /// the new dial.
    ///
    /// # Errors
    /// The proxy's own trust cannot be read: the exchange fails for good.
    pub(crate) fn redial_native(
        &self,
        exchange: &mut Exchange,
        waker: &Waker,
    ) -> Result<(), ConnError> {
        if !std::mem::take(&mut exchange.resend) {
            return Ok(());
        }
        let Some(reopen) = exchange.reopen.clone() else {
            exchange.failed = Some(ConnError::Closed);
            return Err(ConnError::Closed);
        };
        let Reopen {
            dial,
            judged_class,
            reach,
        } = reopen;
        let answer: Answer = Arc::new(Mutex::new((None, None, Vec::new())));
        let judged = self.judge_into(
            &dial.located.authority,
            dial.located.secure,
            judged_class,
            reach,
            &answer,
        );
        if let Some(verdict) = judged {
            // Answered at once: left in the answer, so `Exchange::connected` takes it like any other.
            answer.lock().expect("judgement").0 = Some(verdict);
        }
        let via = match self.via_for(dial.located.secure, &dial.located.authority) {
            Ok(via) => via,
            Err(error) => {
                exchange.failed = Some(error);
                return Err(error);
            }
        };
        exchange.state = State::Judging { answer, dial, via };
        self.count_redial();
        waker.wake_by_ref();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::delivery::State as Sent;
    use crate::outbound::redial::Ended;

    /// The decisions an exchange acts on, stated once more at the point of use: the rows the
    /// loopback tests then prove end to end.
    #[test]
    fn the_exchange_resends_only_on_the_two_rows_that_allow_it() {
        let kept_closed = redial::decide(Sent::None, Ended::Connection, true, false);
        assert!(kept_closed.resend && !kept_closed.charge && !kept_closed.walk);
        let unprocessed = redial::decide(Sent::Whole, Ended::NotProcessed, true, false);
        assert!(unprocessed.resend && !unprocessed.charge);
        for (sent, ended, kept, redialled) in [
            (Sent::Part, Ended::Connection, true, false),
            (Sent::None, Ended::Dial, false, false),
            (Sent::None, Ended::Proxy, false, false),
            (Sent::None, Ended::Connection, true, true),
            (Sent::None, Ended::Deadline, true, false),
        ] {
            assert!(
                !redial::decide(sent, ended, kept, redialled).resend,
                "{sent:?} {ended:?}"
            );
        }
    }
}
