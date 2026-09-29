// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S CALLS, AS THE HOST'S TWO HALVES SHARE THEM (`BUSBAR-1.6.0.md` Part 3, §12): the
//! [`PlaneCalls`] trait the plugin loader implements over one loaded plane instance and the
//! kernel's plane driver calls through. The kernel names this, the loader names this, and neither
//! names the other. Nothing here crosses the plugin boundary: the plane's ABI is `abi::plane`.
//!
//! The pure ops (`arrive`, `refusal`) and the host's own `cancel` are ticketless: they never pend.
//! `on_piece` is submitted on a request ticket and crosses on that ticket's worker; its answer is a
//! future, so the caller's task awaits it and no thread is parked.

use std::future::Future;

use crate::abi::mechanism::call::Outcome;
use crate::abi::mechanism::ticket::Ticket;
use crate::abi::plane::{ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, RefusalIn, RefusalOut};

/// How one ticketed op ended, as the host's dispatcher judged it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answered {
    /// The authoritative outcome.
    pub outcome: Outcome,
    /// A FAILED answer that is SHORT: the caller grows its buffers and submits the op once more
    /// on the same ticket; a second short answer is FAULT.
    pub short: bool,
    /// The op ended through `cancel`: the disposition it answered. `None` when no cancel ended it,
    /// or the cancel FAULTed.
    pub disposition: Option<u32>,
}

/// One `on_piece` in flight on its ticket. Dropping it before it answered is a client drop.
pub trait PieceInFlight: Future<Output = Answered> + Send + Unpin {
    /// The answer, if it has arrived; never waits.
    fn settled(&mut self) -> Option<Answered>;

    /// The `out` the answer carried; `None` before the answer, or when the op was faulted
    /// mid-crossing.
    fn out(&self) -> Option<OnPieceOut>;
}

/// Grow the host buffers a short answer named, re-pointing the `in` at them, before the one
/// re-call.
pub type Grow<'a, I, O> = &'a mut dyn FnMut(&O, &mut I);

/// ONE PLANE INSTANCE'S CALLS, as the kernel's plane driver makes them.
pub trait PlaneCalls: Send + Sync {
    /// The dispatcher's clock, in nanoseconds: the clock a unit's deadline is on.
    fn now_ns(&self) -> u64;

    /// `arrive`, ticketless. A short answer calls `grow` and is re-called once; a second short
    /// answer is FAULT. `input` and `out` hold what the last call was handed and answered.
    fn arrive(
        &self,
        input: &mut ArriveIn,
        out: &mut ArriveOut,
        grow: Grow<'_, ArriveIn, ArriveOut>,
    ) -> Outcome;

    /// `refusal`, ticketless, with the same one re-call as [`PlaneCalls::arrive`].
    fn refusal(
        &self,
        input: &mut RefusalIn,
        out: &mut RefusalOut,
        grow: Grow<'_, RefusalIn, RefusalOut>,
    ) -> Outcome;

    /// The host's own ticketless `cancel` of `ticket`: the disposition it answered, or `None`
    /// when it did not answer READY.
    fn cancel(&self, ticket: Ticket) -> Option<u32>;

    /// A request ticket for one unit; `None` when none can be minted.
    fn mint(&self) -> Option<Ticket>;

    /// The unit is over: `ticket` goes back (at once when idle, else when its op ends).
    fn recycle(&self, ticket: Ticket);

    /// The client of `ticket` went away: an op in flight on it is cancelled on its worker, and its
    /// answer carries the disposition. A message, never a crossing on the calling thread.
    fn drop_client(&self, ticket: Ticket);

    /// Submit `on_piece` on `ticket`; it crosses on the ticket's worker. The host buffers `input`
    /// names must outlive the answer.
    fn on_piece(&self, ticket: Ticket, input: OnPieceIn, out: OnPieceOut)
        -> Box<dyn PieceInFlight>;
}
