// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE STORE OP'S CONTEXT (the plugin ABI: every call is Ready or Pending(wake), never a blocking
//! thread). A [`StoreSlots`](super::StoreSlots) method answers a [`Step`]: its result, or "not yet"
//! with the wake it waits for. Across its PENDING turns the op keeps two things in its [`Op`]: its
//! own continuation ([`Op::park`] / [`Op::resume`]) and its ONE connection ([`Op::checkout`]). The
//! store door parks both on the op's ticket and hands them back on the op's RESUME entry.
//!
//! The rules the door enforces (REVIEWER / ARCHITECT, binding):
//! * a RESUME entry with nothing parked is FAULT: an op is never run afresh, which would re-send
//!   its side effects;
//! * PENDING with `wake_at_ns == 0` is a promise that a connector service is in flight, so a body
//!   that pends on 0 having made no connector service since its entry is FAULT (nothing would wake
//!   it);
//! * one op, one connection: a second [`Op::checkout`] answers the same stream for the same need
//!   and target and is REFUSED for any other; the SDK closes the checkout when the op answers
//!   anything but PENDING, when its ticket is cancelled, and whenever its parked state is dropped
//!   (a recycle, an instance that faulted and closed);
//! * a call on no ticket (the synchronous bridge's fallback on a dispatcher's only worker, a direct
//!   call in a test) may not pend: PENDING there is FAULT. The synchronous bridge itself calls on a
//!   ticket and waits for the completion, so a store may pend on it.
//!
//! MONEY: closing a connection undoes nothing a remote store already committed. So a cancelled or
//! failed `op_id`-carrying op is EITHER not applied OR applied, and then a retry with the SAME
//! `op_id` answers exactly what the first attempt applied (the store's durable dedupe). A caller
//! retrying a cancelled, failed or faulted op reuses its `op_id` and never mints a new one.

use std::any::Any;

use crate::abi::mechanism::ticket::Ticket;
use crate::abi::sdk::conn::{Answer, ConnFailure, Connector, Host};

/// A store op's answer: its result, or not yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step<T> {
    /// The op's result.
    Ready(T),
    /// Not yet: re-enter the op on its ticket at `wake_at_ns` (`0` = when a connector service the
    /// op made completes).
    Pending {
        /// When to re-enter; `0` = on the connector's completion.
        wake_at_ns: u64,
    },
}

/// The op's ONE connection: the need and target it was established for, and the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkout {
    /// The declared need.
    pub need: u32,
    /// The target (`None` = the need's own).
    pub target: Option<String>,
    /// The stream.
    pub stream: u64,
}

/// What the door parks on the op's ticket across a PENDING answer.
pub(crate) struct Parked {
    pub(crate) state: Option<Box<dyn Any + Send + Sync>>,
    pub(crate) checkout: Option<Checkout>,
    pub(crate) issued: u32,
    pub(crate) host: Option<Host>,
    pub(crate) ticket: Ticket,
}

impl Drop for Parked {
    /// Parked state the SDK drops (a recycle, an instance that faulted and closed) closes the op's
    /// connection with it.
    fn drop(&mut self) {
        if let (Some(c), Some(h)) = (self.checkout.take(), self.host) {
            let _ = h.connector_from(self.ticket, self.issued).close(c.stream);
        }
    }
}

/// ONE STORE OP'S CONTEXT, handed to every [`StoreSlots`](super::StoreSlots) method.
pub struct Op<'a> {
    ticket: Ticket,
    resuming: bool,
    host: Option<&'a Host>,
    state: Option<Box<dyn Any + Send + Sync>>,
    checkout: Option<Checkout>,
    /// The connector services this op has made, over all its entries.
    issued: u32,
    /// Where `issued` stood when this entry began.
    entered_at: u32,
}

impl std::fmt::Debug for Op<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Op")
            .field("ticket", &self.ticket)
            .field("resuming", &self.resuming)
            .field("checkout", &self.checkout)
            .finish_non_exhaustive()
    }
}

impl Op<'static> {
    /// An op on no ticket: the synchronous bridge's fallback on a dispatcher's only worker, a
    /// direct call in a test. It may not pend and has no connector.
    #[must_use]
    pub fn detached() -> Self {
        Self {
            ticket: Ticket::NONE,
            resuming: false,
            host: None,
            state: None,
            checkout: None,
            issued: 0,
            entered_at: 0,
        }
    }
}

impl<'a> Op<'a> {
    /// The door's op for one entry: fresh, or resuming what was parked.
    pub(crate) fn enter(ticket: Ticket, host: Option<&'a Host>, parked: Option<Parked>) -> Self {
        let mut op = Self {
            ticket,
            resuming: parked.is_some(),
            host,
            state: None,
            checkout: None,
            issued: 0,
            entered_at: 0,
        };
        if let Some(mut p) = parked {
            op.state = p.state.take();
            op.checkout = p.checkout.take();
            op.issued = p.issued;
            op.entered_at = p.issued;
        }
        op
    }

    /// What the door parks when the op answers PENDING.
    pub(crate) fn into_parked(self) -> Parked {
        Parked {
            state: self.state,
            checkout: self.checkout,
            issued: self.issued,
            host: self.host.copied(),
            ticket: self.ticket,
        }
    }

    /// Whether this entry made a connector service (a PENDING on 0 needs one in flight).
    pub(crate) fn made_a_service(&self) -> bool {
        self.issued > self.entered_at
    }

    /// Whether this op runs on a ticket, and so may answer PENDING.
    #[must_use]
    pub fn can_pend(&self) -> bool {
        !self.ticket.is_none()
    }

    /// Whether this entry is the op's RESUME (what it parked is here).
    #[must_use]
    pub const fn resuming(&self) -> bool {
        self.resuming
    }

    /// Keep `state` across this op's PENDING answer: the op's own continuation. It replaces what
    /// was kept. An op on no ticket keeps nothing (it may not pend).
    pub fn park<S: Send + Sync + 'static>(&mut self, state: S) {
        if self.can_pend() {
            self.state = Some(Box::new(state));
        }
    }

    /// Take back what [`Op::park`] kept, in the op's RESUME; `None` in a fresh entry or when
    /// another type was kept.
    pub fn resume<S: Send + Sync + 'static>(&mut self) -> Option<S> {
        match self.state.take()?.downcast::<S>() {
            Ok(s) => Some(*s),
            Err(other) => {
                self.state = Some(other);
                None
            }
        }
    }

    /// The host tables `open` was handed; `None` when none.
    #[must_use]
    pub fn host(&self) -> Option<&Host> {
        self.host
    }

    /// Make connector services for this entry, their handles counted on from what the op made
    /// before (so a resumed op re-issues a completed service with its own handle). Drop the guard
    /// before answering.
    ///
    /// # Errors
    /// [`ConnFailure::Unarmed`] with no host tables, [`ConnFailure::NoTicket`] on no ticket.
    pub fn connector(&mut self) -> Result<Services<'_, 'a>, ConnFailure> {
        let host = self.host.ok_or(ConnFailure::Unarmed)?;
        if !self.can_pend() {
            return Err(ConnFailure::NoTicket);
        }
        let conn = host.connector_from(self.ticket, self.issued);
        Ok(Services {
            conn: Some(conn),
            issued: &mut self.issued,
        })
    }

    /// The op's ONE connection, for declared need `need` to `target`: established once (the answer
    /// may be PENDING), then the same stream for every later call with the same need and target.
    /// The SDK closes it when the op ends.
    pub fn checkout(&mut self, need: u32, target: Option<&str>) -> Answer<u64> {
        self.checkout_timed(need, target, 0)
    }

    /// [`Op::checkout`], its dial bounded by `timeout_ms` (`0` = the need's own timeout, else the
    /// host's default).
    pub fn checkout_timed(
        &mut self,
        need: u32,
        target: Option<&str>,
        timeout_ms: u32,
    ) -> Answer<u64> {
        if let Some(c) = &self.checkout {
            return std::task::Poll::Ready(if c.need == need && c.target.as_deref() == target {
                Ok(c.stream)
            } else {
                Err(ConnFailure::Refused(
                    "one op holds one connection: this op's is for another need or target".into(),
                ))
            });
        }
        let mut services = match self.connector() {
            Ok(s) => s,
            Err(e) => return std::task::Poll::Ready(Err(e)),
        };
        let answer = services.establish_timed(need, target, "", timeout_ms);
        drop(services);
        if let std::task::Poll::Ready(Ok(stream)) = answer {
            self.checkout = Some(Checkout {
                need,
                target: target.map(str::to_owned),
                stream,
            });
        }
        answer
    }
}

impl Op<'_> {
    /// The op's ticket.
    pub(crate) const fn ticket(&self) -> Ticket {
        self.ticket
    }

    /// Take the op's connection out of its keeping: it is no longer closed when the op ends (a
    /// kept connection going back to its instance's set).
    pub(crate) fn take_checkout(&mut self) -> Option<Checkout> {
        self.checkout.take()
    }

    /// Make `c` the op's connection (one drawn from its instance's kept set): closed if the op
    /// ends without handing it back.
    pub(crate) fn adopt(&mut self, c: Checkout) {
        self.checkout = Some(c);
    }

    /// Close the op's connection now (it is not fit for reuse); the next [`Op::checkout`]
    /// establishes a fresh one.
    pub(crate) fn close_checkout(&mut self) {
        if let Some(c) = self.checkout.take() {
            if let Ok(mut s) = self.connector() {
                let _ = s.close(c.stream);
            }
        }
    }
}

/// An entry's connector services; on drop the op counts what they made.
pub struct Services<'o, 'h> {
    conn: Option<Connector<'h>>,
    issued: &'o mut u32,
}

impl<'h> std::ops::Deref for Services<'_, 'h> {
    type Target = Connector<'h>;
    fn deref(&self) -> &Connector<'h> {
        self.conn
            .as_ref()
            .expect("the services' connector lives until drop")
    }
}

impl<'h> std::ops::DerefMut for Services<'_, 'h> {
    fn deref_mut(&mut self) -> &mut Connector<'h> {
        self.conn
            .as_mut()
            .expect("the services' connector lives until drop")
    }
}

impl Drop for Services<'_, '_> {
    fn drop(&mut self) {
        if let Some(c) = self.conn.take() {
            *self.issued = c.issued();
        }
    }
}

#[cfg(test)]
#[path = "../tests/store_op_tests.rs"]
mod tests;
