// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHICH REQUEST DOES THIS REPLY ANSWER?
//!
//! One table, one question, and every wrong answer it can give is a cross-request delivery on the
//! tool path. So the rules are narrow and absolute:
//!
//! - An id is SPENT when it resolves. A second reply carrying it answers nothing.
//! - An id is never REUSED. The counter only goes up, so a late reply to a request that already
//!   timed out can never be delivered as the answer to a later one.
//! - The table is BOUNDED. Every unanswered request holds an entry, and a peer that never replies
//!   would otherwise grow it without end.
//! - An id we did not issue answers nothing, whatever it looks like. In particular the string
//!   spelling of a numeric id is a different id, because coercing between them would let a peer
//!   choose which request it is answering.
//!
//! ## Time is an argument
//!
//! Deadlines are passed in as monotonic milliseconds rather than read from a clock. That keeps this
//! type pure (its tests neither sleep nor flake), and it keeps the choice of clock with the
//! transport, which is the layer that has one.

use std::collections::BTreeMap;

use super::jsonrpc::{Id, Request, Response, RpcError};
use serde_json::Value;

/// A request that is waiting for its reply.
#[derive(Clone, Debug, PartialEq, Eq)]
struct InFlight {
    method: String,
    deadline_ms: u64,
}

/// A reply, matched to the request it answers.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Answered {
    pub(crate) id: Id,
    /// The method of the request this answers. Carried out of the table because the reply itself
    /// does not name it, and every caller downstream needs it to know how to read the payload.
    pub(crate) method: String,
    pub(crate) outcome: Result<Value, RpcError>,
}

/// A request whose reply never came.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Expired {
    pub(crate) id: Id,
    pub(crate) method: String,
}

/// Why a correlation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CorrelationError {
    /// The id answers nothing: never issued, already resolved, cancelled, or expired.
    UnknownId(Id),
    /// The pending table is full. The caller backs off; it does not get an unbounded table.
    TooManyInFlight { limit: usize },
    /// The id counter has no unused value left. Not reachable on a real connection, and refused
    /// explicitly anyway: the counter saturates rather than wrapping, and saturating means the last
    /// value would otherwise be handed out over and over.
    IdsExhausted,
}

impl std::fmt::Display for CorrelationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorrelationError::UnknownId(id) => {
                write!(f, "reply carries id {id}, which answers no pending request")
            }
            CorrelationError::TooManyInFlight { limit } => {
                write!(f, "already {limit} requests in flight to this peer")
            }
            CorrelationError::IdsExhausted => {
                write!(f, "this connection has no unused correlation id left")
            }
        }
    }
}

/// The pending-request table for ONE peer connection.
pub(crate) struct Correlator {
    /// The next id to hand out. Only ever increases, which is what makes an expired id
    /// unreachable rather than merely unlikely.
    next: i64,
    /// Set once `next` has been handed out at its last value, so it is never handed out twice.
    exhausted: bool,
    inflight: BTreeMap<Id, InFlight>,
    max_inflight: usize,
    timeout_ms: u64,
}

impl Correlator {
    pub(crate) fn new(max_inflight: usize, timeout_ms: u64) -> Self {
        Correlator {
            next: 1,
            exhausted: false,
            inflight: BTreeMap::new(),
            max_inflight,
            timeout_ms,
        }
    }

    /// A correlator whose counter is on its LAST value, so the exhaustion boundary can be driven
    /// without issuing i64::MAX requests to reach it.
    #[cfg(test)]
    pub(crate) fn at_last_id(max_inflight: usize, timeout_ms: u64) -> Self {
        Correlator {
            next: i64::MAX,
            ..Correlator::new(max_inflight, timeout_ms)
        }
    }

    /// How many requests are waiting for a reply.
    pub(crate) fn in_flight(&self) -> usize {
        self.inflight.len()
    }

    /// Take the next id and record the request as pending. The returned [`Request`] is the frame to
    /// send; nothing is sent from here, because this type has no transport.
    pub(crate) fn issue(
        &mut self,
        method: &str,
        params: Option<Value>,
        now_ms: u64,
    ) -> Result<Request, CorrelationError> {
        if self.inflight.len() >= self.max_inflight {
            return Err(CorrelationError::TooManyInFlight {
                limit: self.max_inflight,
            });
        }
        // The counter SATURATES rather than wrapping, because a wrapping one starts handing out ids
        // that are still in flight, which is the one thing this type must never do. Saturating means
        // the last value would repeat instead, so it is refused here rather than repeated. Reaching
        // this is not a reachable state on a real connection; it is pinned because the failure mode
        // if it ever were reached is a reply delivered to the wrong request.
        if self.exhausted {
            return Err(CorrelationError::IdsExhausted);
        }
        let id = Id::Number(self.next);
        if self.next == i64::MAX {
            self.exhausted = true;
        } else {
            self.next += 1;
        }
        self.inflight.insert(
            id.clone(),
            InFlight {
                method: method.to_string(),
                deadline_ms: now_ms.saturating_add(self.timeout_ms),
            },
        );
        Ok(Request::new(id, method, params))
    }

    /// Match a reply to its request. Removing the entry is what spends the id.
    pub(crate) fn resolve(&mut self, response: Response) -> Result<Answered, CorrelationError> {
        match self.inflight.remove(&response.id) {
            Some(entry) => Ok(Answered {
                id: response.id,
                method: entry.method,
                outcome: response.outcome,
            }),
            None => Err(CorrelationError::UnknownId(response.id)),
        }
    }

    /// Every request whose deadline has passed, reported ONCE and then dropped from the table. A
    /// reply that arrives afterwards answers nothing, which is the correct reading: the caller has
    /// already been told it timed out.
    pub(crate) fn expire(&mut self, now_ms: u64) -> Vec<Expired> {
        let due: Vec<Id> = self
            .inflight
            .iter()
            .filter(|(_, e)| e.deadline_ms <= now_ms)
            .map(|(id, _)| id.clone())
            .collect();
        due.into_iter()
            .filter_map(|id| {
                self.inflight.remove(&id).map(|e| Expired {
                    id,
                    method: e.method,
                })
            })
            .collect()
    }

    /// Give up on one request. Idempotent, because a cancel is reachable from a retry and from a
    /// shutdown at the same time.
    pub(crate) fn cancel(&mut self, id: &Id) -> Option<String> {
        self.inflight.remove(id).map(|e| e.method)
    }
}

#[cfg(test)]
#[path = "tests/correlator_tests.rs"]
mod correlator_tests;
