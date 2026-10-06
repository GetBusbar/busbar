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
//! The pure ops (`arrive`, `refusal`, `project`) and the host's own `cancel` are ticketless: they
//! never pend.
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
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, ProjectIn, ProjectOut, RefusalIn, RefusalOut,
    ServeIn, ServeOut,
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

    /// The record writes of the `cancel` that ended the op (its client-drop path: a deadline, a
    /// cut or a reload while it was in flight), copied out of the cancel's buffers; empty when no
    /// cancel ended it or it wrote none (SEAM-L(r)).
    fn cancel_writes(&self) -> Vec<CancelWrite> {
        Vec::new()
    }
}

/// One record write a plane's `cancel` answered, owned: its `kind`, `op` ([`RecordWrite`]'s), key
/// and value bytes.
///
/// [`RecordWrite`]: crate::abi::plane::RecordWrite
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelWrite {
    /// [`RecordWrite::kind`](crate::abi::plane::RecordWrite::kind).
    pub kind: u32,
    /// [`RecordWrite::op`](crate::abi::plane::RecordWrite::op).
    pub op: u32,
    /// The key's bytes.
    pub key: Vec<u8>,
    /// The value's bytes.
    pub value: Vec<u8>,
}

/// What a READY `cancel` answered: its disposition and its record writes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cancelled {
    /// The `CANCEL_*` disposition.
    pub disposition: u32,
    /// Its record writes, in the plane's order.
    pub writes: Vec<CancelWrite>,
}

impl CancelWrite {
    /// Each of the first `written` writes of `records`, its spans read in `arena` (a span past
    /// it reads empty).
    #[must_use]
    pub fn owned(
        records: &[crate::abi::plane::RecordWrite],
        written: usize,
        arena: &[u8],
    ) -> Vec<CancelWrite> {
        let bytes = |s: crate::abi::mechanism::call::Span| {
            let start = s.offset as usize;
            arena
                .get(start..start.saturating_add(s.len as usize))
                .unwrap_or_default()
                .to_vec()
        };
        records
            .iter()
            .take(written)
            .map(|w| CancelWrite {
                kind: w.kind,
                op: w.op,
                key: bytes(w.key),
                value: bytes(w.value),
            })
            .collect()
    }
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

/// A door's own `validate` over a whole section (its settings, JSON): `Ok`, or the door's words.
pub type SectionJudge = Arc<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>;

/// WHAT A DOOR FACES THE WORLD WITH for one generation, as its `open` published it: the paths it
/// answers on (each with the dialect word a refusal on it wears) and the audience it binds, with its
/// protected-resource metadata document; `None` = it binds none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DoorFacing {
    /// Each claimed target, as stated (a pattern keeps its `{name}` segments), and its dialect word.
    pub claims: Vec<(String, &'static str)>,
    /// The audience it binds and its resource metadata document.
    pub admission: Option<(String, String)>,
}

/// A door's facing for a section, its other owned sections (one JSON object keyed by section name,
/// as `PlaneOpenIn::owned`; empty = none) and a public base URL (the snapshot a probe instance of it
/// publishes).
pub type FacingProbe =
    Arc<dyn Fn(&[u8], &[u8], Option<&str>) -> Result<DoorFacing, String> + Send + Sync>;

/// ONE ADMIN ROUTE a plane door states in its Statement tail (`PlaneTail::admin_routes`): the verb,
/// the target relative to the admin mount, its flags and the word it is audited under (empty =
/// never audited).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatedAdminRoute {
    /// The verb.
    pub verb: &'static str,
    /// The target, relative to the admin mount.
    pub target: &'static str,
    /// `ROUTE_PUBLIC` or `0`.
    pub flags: u32,
    /// The audit word; empty = never audited.
    pub audit_verb: &'static str,
    /// A public route's auth scheme; empty = none.
    pub style: &'static str,
}

/// THE REGISTRY FACTS A PLANE DOOR STATES (ARCHITECT RULING 2026-10-03, Q-DEL-A2A-DECL; spec #49
/// and R2-C: a plane's config section, scope kinds and the rest are DERIVED from its Statement,
/// never declared in the root). The loader reads them off a door's Statement (`sections`) and its
/// plane tail, linked or dropped alike, and the kernel folds them into its plane registry before the
/// config prepass (`busbar_kernel::plane::door::fold`). Every word is kept for the process.
#[derive(Clone)]
pub struct PlaneRegistration {
    /// The plane's registry key: the door's Statement name.
    pub key: &'static str,
    /// The section the Statement declares (`SECTION_DECLARING`): the plane's config verb.
    pub section: &'static str,
    /// The other sections the Statement owns (neither declaring nor consumed): the plane's
    /// endpoint block beside its verb, handed to its `open` as `PlaneOpenIn::owned`.
    pub owns: Vec<&'static str>,
    /// The Statement's secret-reference paths (`Statement::secret_refs`): the settings paths whose
    /// values are secret references, each `settings.<key>...`, where `*` stands for every key of
    /// the map at that point (each registration, each entry). The kernel enumerates the references
    /// they name in its section, so `--validate` and boot resolve every one.
    pub secret_refs: Vec<&'static str>,
    /// The admin routes its tail states (ARCHITECT Q-L3B-VERBS): the kernel's row mounts each on
    /// the admin router, served by the instance's `serve` op.
    pub admin_routes: Vec<StatedAdminRoute>,
    /// Their OpenAPI path fragment, each path relative to the admin mount (JSON); `None` = none.
    pub admin_openapi: Option<&'static [u8]>,
    /// The tail's label (`PlaneTail::label`).
    pub label: &'static str,
    /// The tail's subject noun.
    pub subject_noun: &'static str,
    /// The tail's admin noun.
    pub admin_noun: &'static str,
    /// The tail's audit kind.
    pub audit_kind: &'static str,
    /// The tail's signing domain and key-id prefix; `None` = it signs nothing.
    pub signing: Option<(&'static str, &'static str)>,
    /// The tail's dialects, in order (the plane's wire formats).
    pub dialects: Vec<&'static str>,
    /// The tail's scope kinds.
    pub scope_kinds: Vec<&'static str>,
    /// The tail's billable classes, each with its unit family.
    pub billable_classes: Vec<(&'static str, &'static str)>,
    /// The tail's fee units.
    pub fee_units: Vec<&'static str>,
    /// The tail's record kinds.
    pub record_kinds: Vec<&'static str>,
    /// The tail's kernel-owned trust keys.
    pub trust_keys: Vec<crate::plane::TrustKeyDecl>,
    /// The tail's sentence refusing a forwarded caller credential; `None` = it states none.
    pub caller_credential_refusal: Option<&'static str>,
    /// Whether the tail states `TAIL_FALLBACK`: the plane is the catch-all every unclaimed path
    /// falls through to, and its card is the flat one (at most one registered plane).
    pub fallback: bool,
    /// The door's own `validate` over a whole section (its settings, JSON): `Ok`, or the door's
    /// words. The kernel runs it where the section is parsed and where an admin write lands.
    pub validate: SectionJudge,
    /// What the door faces the world with for a section, its owned sections and the deployment's
    /// public base URL: the kernel mounts its claims and binds its audience from it, per generation.
    pub facing: FacingProbe,
}

impl std::fmt::Debug for PlaneRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaneRegistration")
            .field("key", &self.key)
            .field("section", &self.section)
            .finish_non_exhaustive()
    }
}

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
    /// Its chained record kinds, as its tail declares them (each `kind` an index into
    /// [`InstanceDecl::record_kinds`]): the kernel frames and verifies their chain (Part 3, the plane driver, "Record
    /// writes ... A record kind the plane declares as chained keeps its declared framing").
    pub record_chains: Vec<crate::abi::plane::RecordChain>,
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

    /// The pool a READY `arrive` named ([`ArriveOut::pool`], ARCHITECT Q-SW6), copied out of the
    /// plane's memory while that answer is the instance's last; `None` when it named none.
    fn arrived_pool(&self, out: &ArriveOut) -> Option<Vec<u8>>;

    /// The sticky-routing key a READY `arrive` stated ([`ArriveOut::affinity`], ARCHITECT Q1
    /// ArriveOut), copied out of the plane's memory while that answer is the instance's last;
    /// `None` when it stated none. Opaque: the kernel only hashes it.
    fn arrived_affinity(&self, out: &ArriveOut) -> Option<Vec<u8>> {
        let _ = out;
        None
    }

    /// The words a REFUSED `arrive` stated in its `head.error` (abi/plane "A refused arrival"),
    /// copied out of the plane's memory while that answer is the instance's last; `None` when it
    /// stated none. Opaque: the kernel hands them to the plane's `refusal` unparsed.
    fn arrived_refusal(&self, out: &ArriveOut) -> Option<Vec<u8>> {
        let _ = out;
        None
    }

    /// `refusal`, ticketless, with the same one re-call as [`PlaneCalls::arrive`].
    fn refusal(
        &self,
        input: &mut RefusalIn,
        out: &mut RefusalOut,
        grow: Grow<'_, RefusalIn, RefusalOut>,
    ) -> Outcome;

    /// `project`, ticketless, with the same one re-call as [`PlaneCalls::arrive`]: the hook kind's
    /// view of the unit's request (once per unit, when a hook is bound), and again with a
    /// request-stage hook's rewrite for the plane to apply and re-project.
    fn project(
        &self,
        input: &mut ProjectIn,
        out: &mut ProjectOut,
        grow: Grow<'_, ProjectIn, ProjectOut>,
    ) -> Outcome;

    /// The host's own ticketless `cancel` of `ticket`: the disposition it answered and the record
    /// writes it carried (SEAM-L(r)), or `None` when it did not answer READY.
    fn cancel(&self, ticket: Ticket) -> Option<Cancelled>;

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
