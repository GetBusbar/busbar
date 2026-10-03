// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S CALLS, AS THE HOST'S TWO HALVES SHARE THEM (`BUSBAR-1.6.0.md` Part 3, the plane
//! driver): the [`PlaneCalls`] trait the plugin loader implements over one loaded plane instance
//! and the kernel's plane driver calls through. The kernel names this, the loader names this, and neither
//! names the other. Nothing here crosses the plugin boundary: the plane's ABI is `abi::plane`.
//!
//! A duplex session's pieces ride two request tickets, one per side; its unsolicited output is
//! named by the instance's one driver ticket's `drive` ([`PlaneCalls::ready`]).
//!
//! The pure ops (`arrive`, `refusal`) and the host's own `cancel` are ticketless: they never pend.
//! `on_piece` and `serve` are submitted on a request ticket and cross on that ticket's worker; the
//! answer is a future, so the caller's task awaits it and no thread is parked.
//!
//! THE LENT MEMORY (ARCHITECT ruling 2026-09-29, every kind): an `on_piece` `in` names the unit's
//! host buffers by raw pointer, and a crossing the watchdog answers FAULT may still be running on
//! its abandoned thread. So `on_piece` takes the buffers' owner ([`Lent`]) and the host keeps it
//! until the crossing has returned, never only until the answer. The pure ops need none: they cross
//! on the caller's own thread, which stays inside the crossing until it returns.

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::abi::mechanism::call::Outcome;
use crate::abi::mechanism::ticket::Ticket;
use crate::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, RefusalIn, RefusalOut, ServeIn, ServeOut,
};

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

/// One `serve` in flight on its ticket. Dropping it before it answered is a client drop.
pub trait ServeInFlight: Future<Output = Answered> + Send + Unpin {
    /// The `out` the answer carried; `None` before the answer, or when the op was faulted
    /// mid-crossing.
    fn out(&self) -> Option<ServeOut>;
}

/// Grow the host buffers a short answer named, re-pointing the `in` at them, before the one
/// re-call.
pub type Grow<'a, I, O> = &'a mut dyn FnMut(&O, &mut I);

/// The owner of the host memory an op's `in` points into: kept alive by the host until the op's
/// last crossing returned.
pub type Lent = Arc<dyn Any + Send + Sync>;

/// WHAT A PLANE INSTANCE DECLARES FOR ITS ADMISSION: its host label and what its Statement tail
/// states, read once at bind (the words kept for the process): its record kinds, its signing
/// declaration (domain, key-id prefix), its scope kinds and its trust keys. The kernel admits the
/// instance from these and its configured section.
#[derive(Debug, Clone, Default)]
pub struct InstanceDecl {
    /// The host's label for the instance: the key every caller-scoped host service answers by.
    pub label: Arc<str>,
    /// The record kinds it keeps.
    pub record_kinds: Vec<&'static str>,
    /// Its signing domain and key-id prefix; `None` = it signs nothing.
    pub signing: Option<(&'static str, &'static str)>,
    /// The grant kinds that admit its traffic.
    pub scope_kinds: Vec<&'static str>,
    /// The per-registration keys the kernel parses for the trust lifecycle.
    pub trust_keys: Vec<crate::plane::TrustKeyDecl>,
}

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

    /// What the instance declares for its admission.
    fn declared(&self) -> InstanceDecl;

    /// The instance's ONE driver ticket, minted: persistent, owned by the instance, outside
    /// `max_inflight`; every wake on it calls `drive`. `None` when none can be minted.
    fn driver(&self) -> Option<Ticket>;

    /// Lifecycle `tick` at `now_ns`, submitted on `driver` (the instance's driver ticket, which
    /// its head carries, so a service that pends inside `tick` is woken through `drive`): the
    /// `next_tick_ns` a READY or PENDING answer names (`0` = none), or `None` for any other answer.
    fn tick(
        &self,
        driver: Ticket,
        now_ns: u64,
    ) -> Pin<Box<dyn Future<Output = Option<u64>> + Send>>;

    /// THE READY SESSIONS (R-B): the streams the instance's `drive` named on its driver ticket
    /// since the last call, each once, waiting until one is named. Empty when the instance is not
    /// open: nothing more will be named.
    fn ready(&self) -> Pin<Box<dyn Future<Output = Vec<u64>> + Send>>;

    /// The client of `ticket` went away: an op in flight on it is cancelled on its worker, and its
    /// answer carries the disposition. A message, never a crossing on the calling thread.
    fn drop_client(&self, ticket: Ticket);

    /// Submit `on_piece` on `ticket`; it crosses on the ticket's worker. `lent` owns the host
    /// buffers `input` names; it is held until the crossing returns, even past a FAULT answer.
    fn on_piece(
        &self,
        ticket: Ticket,
        input: OnPieceIn,
        out: OnPieceOut,
        lent: Lent,
    ) -> Box<dyn PieceInFlight>;

    /// Submit `serve` (one of the snapshot's admin routes) on `ticket`, as [`PlaneCalls::on_piece`]
    /// is submitted: on the ticket's worker, `lent` held until the crossing returns.
    fn serve(
        &self,
        ticket: Ticket,
        input: ServeIn,
        out: ServeOut,
        lent: Lent,
    ) -> Box<dyn ServeInFlight>;
}
