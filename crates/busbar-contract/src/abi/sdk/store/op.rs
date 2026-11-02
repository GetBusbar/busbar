// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE STORE OP'S CONTEXT (the plugin ABI: every call is Ready or Pending(wake), never a blocking

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

impl<T> Step<T> {
    /// The result mapped by `f`; PENDING as it is.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Step<U> {
        match self {
            Step::Ready(t) => Step::Ready(f(t)),
            Step::Pending { wake_at_ns } => Step::Pending { wake_at_ns },
        }
    }
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
    /// The last still-pending service's handle, distinct from the next free handle above.
    pub(crate) replay: Option<u32>,
    pub(crate) host: Option<Host>,
    pub(crate) ticket: Ticket,
}

impl Drop for Parked {
    /// Parked state the SDK drops (a recycle, an instance that faulted and closed) closes the op's
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
    /// The next free completion-handle sequence. Replaying a pending service never lowers it.
    issued: u32,
    /// The pending logical service to reissue, if any. Completed services retain their numbers.
    replay: Option<u32>,
    /// The last counted service attempted in this entry.
    last_service: Option<u32>,
    /// Reissuing a pending handle is still a service attempt even if the high-water count stays.
    made_service: bool,
    /// The instance's read buffers its wire ops read into (none for an op with no instance).
    reads: Option<&'a super::wire::ReadBufs>,
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
    #[must_use]
    pub fn detached() -> Self {
        Self {
            ticket: Ticket::NONE,
            resuming: false,
            host: None,
            state: None,
            checkout: None,
            issued: 0,
            replay: None,
            last_service: None,
            made_service: false,
            reads: None,
        }
    }
}

impl<'a> Op<'a> {
    /// The door's op for one entry: fresh, or resuming what was parked.
    pub(crate) fn enter(
        ticket: Ticket,
        host: Option<&'a Host>,
        parked: Option<Parked>,
        reads: Option<&'a super::wire::ReadBufs>,
    ) -> Self {
        let mut op = Self {
            ticket,
            resuming: parked.is_some(),
            host,
            state: None,
            checkout: None,
            issued: 0,
            replay: None,
            last_service: None,
            made_service: false,
            reads,
        };
        if let Some(mut p) = parked {
            op.state = p.state.take();
            op.checkout = p.checkout.take();
            op.issued = p.issued;
            op.replay = p.replay;
        }
        op
    }

    /// What the door parks when the op answers PENDING.
    pub(crate) fn into_parked(self) -> Parked {
        Parked {
            state: self.state,
            checkout: self.checkout,
            issued: self.issued,
            replay: self.replay,
            host: self.host.copied(),
            ticket: self.ticket,
        }
    }

    /// The instance's read buffers (none for an op with no instance).
    pub(crate) fn reads(&self) -> Option<&'a super::wire::ReadBufs> {
        self.reads
    }

    /// Whether this entry made a connector service (a PENDING on 0 needs one in flight).
    pub(crate) fn made_a_service(&self) -> bool {
        self.made_service
    }

    /// The wire driver is retrying the same pending logical service, rather than starting a
    pub(crate) fn replay_last_service(&mut self) {
        self.replay = Some(
            self.last_service
                .expect("a pending wire service was attempted"),
        );
    }

    /// A terminal error or explicit close abandons the pending logical service. Future work
    pub(crate) fn abandon_pending_service(&mut self) {
        self.replay = None;
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
    pub fn park<S: Send + Sync + 'static>(&mut self, state: S) {
        if self.can_pend() {
            self.state = Some(Box::new(state));
        }
    }

    /// Take back what [`Op::park`] kept, in the op's RESUME; `None` in a fresh entry or when
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
    pub fn connector(&mut self) -> Result<Services<'_, 'a>, ConnFailure> {
        let host = self.host.ok_or(ConnFailure::Unarmed)?;
        if !self.can_pend() {
            return Err(ConnFailure::NoTicket);
        }
        let started_at = self.replay.unwrap_or(self.issued);
        let conn = host.connector_from(self.ticket, started_at);
        Ok(Services {
            conn: Some(conn),
            issued: &mut self.issued,
            started_at,
            replay: &mut self.replay,
            last_service: &mut self.last_service,
            made_service: &mut self.made_service,
        })
    }

    /// The op's ONE connection, for declared need `need` to `target`: established once (the answer
    pub fn checkout(&mut self, need: u32, target: Option<&str>) -> Answer<u64> {
        self.checkout_timed(need, target, 0)
    }

    /// [`Op::checkout`], its dial bounded by `timeout_ms` (`0` = the need's own timeout, else the
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
        } else if answer.is_pending() {
            self.replay_last_service();
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
    pub(crate) fn take_checkout(&mut self) -> Option<Checkout> {
        self.checkout.take()
    }

    /// Make `c` the op's connection (one drawn from its instance's kept set): closed if the op
    pub(crate) fn adopt(&mut self, c: Checkout) {
        self.checkout = Some(c);
    }

    /// Close the op's connection now (it is not fit for reuse); the next [`Op::checkout`]
    pub(crate) fn close_checkout(&mut self) {
        self.abandon_pending_service();
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
    started_at: u32,
    replay: &'o mut Option<u32>,
    last_service: &'o mut Option<u32>,
    made_service: &'o mut bool,
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
            if c.issued() > self.started_at {
                *self.issued = (*self.issued).max(c.issued());
                *self.replay = None;
                *self.last_service = Some(c.issued() - 1);
                *self.made_service = true;
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/store_op_tests.rs"]
mod tests;
