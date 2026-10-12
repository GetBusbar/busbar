// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TICKETS, THE HOST'S WAKE AND COMPLETION HANDLES.
//!
//! * A [`Ticket`] is `(slot, generation)`, unique per instance across ALL workers: the slot encodes
//!   `worker << INDEX_BITS | index` (host-private; a plugin never decodes it). Each worker owns a
//!   slab of generations; generation `0` is never minted, and recycling a slot bumps it, so a late
//!   wake for a recycled slot names a generation that no longer exists and is DROPPED.
//! * [`host_wake`] is the host's `WakeFn`: callable from any thread, never blocks on the plugin or
//!   on I/O (it pushes onto the owning worker's channel), never fails. It routes by decoding the
//!   slot; the worker checks the generation.
//! * A host service's result under its completion handle `(ticket, seq)` is held by
//!   [`super::services::ServiceStore`]: a re-issued handle on RESUME redeems the stored result,
//!   and nothing ever runs the service twice.

use std::sync::{OnceLock, Weak};

use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};

/// Bits of a ticket's slot that index the worker's slab.
pub(crate) const INDEX_BITS: u32 = 20;
/// The most tickets one worker's slab holds.
pub(crate) const MAX_INDEX: u32 = (1 << INDEX_BITS) - 1;
/// The most workers a dispatcher has (the rest of the slot's bits).
pub(crate) const MAX_WORKERS: u32 = 1 << (32 - INDEX_BITS);

/// `worker`'s ticket slot for slab `index`.
pub(crate) fn encode(worker: u32, index: u32) -> u32 {
    (worker << INDEX_BITS) | index
}

/// `(worker, index)` of a ticket slot.
pub(crate) fn decode(slot: u32) -> (u32, u32) {
    (slot >> INDEX_BITS, slot & MAX_INDEX)
}

/// A recycled ticket slot's generation: the one after `g`, never `0` (a ticket generation, not
/// a configuration generation).
pub(crate) fn recycled_generation(g: u32) -> u32 {
    match g.wrapping_add(1) {
        0 => 1,
        n => n,
    }
}

/// Where an instance's wakes go: the dispatcher that holds its tickets.
pub(crate) trait WakeRoute: Send + Sync {
    /// Push `t` to the worker that owns it. Never blocks on the plugin.
    fn wake(&self, t: Ticket);

    /// The host services this route's instances are served from; `None` = none.
    fn services(&self) -> Option<super::services::Served> {
        None
    }

    /// The host's I/O this route's instances are served from; `None` = none.
    fn io(&self) -> Option<std::sync::Arc<dyn busbar_contract::io_host::IoHost>> {
        None
    }

    /// The waker of an INLINE ticket's task (`super::inline`); `None` for any other ticket.
    fn inline_waker(&self, t: Ticket) -> Option<std::task::Waker> {
        let _ = t;
        None
    }
}

/// What an instance's `HostCtx` points to: the dispatcher its tickets live in, and who the instance
/// is to the host services. Leaked per instance, so a late wake never dangles; a wake before any
/// dispatcher is bound is dropped.
#[derive(Default)]
pub(crate) struct InstanceWake {
    pub(crate) route: OnceLock<Weak<dyn WakeRoute>>,
    /// The instance as the host services see it, stated once at bind.
    pub(crate) caller: OnceLock<busbar_contract::services::Caller>,
    /// The credential kinds the instance's Statement declares it reads, stated once at bind:
    /// `records.secret` serves this instance those only.
    pub(crate) credential_kinds: OnceLock<Vec<String>>,
    /// The instance's identity on the host's connection table and the table itself, set at bind
    /// when the instance's Statement declares a need (the connector slots read it).
    pub(crate) conn: OnceLock<(
        busbar_contract::conn::InstanceId,
        std::sync::Arc<dyn busbar_contract::conn::DeclaredConns>,
    )>,
    /// The settings keys the instance's manifest declares DESTINATIONS (granted once, by the
    /// opener that read the manifest): `disk.append` serves this instance those only.
    pub(crate) destinations: OnceLock<Vec<String>>,
    /// Each granted key bound to the file the instance's settings give it, re-bound by every
    /// `open` and `refresh` (`disk.append` maps a key through it).
    pub(crate) bound: std::sync::RwLock<Vec<busbar_contract::services::DiskDest>>,
}

impl std::fmt::Debug for InstanceWake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceWake")
            .field("route", &self.route)
            .field("caller", &self.caller)
            .field("credential_kinds", &self.credential_kinds)
            .field("conn", &self.conn.get().map(|(id, _)| id))
            .field("destinations", &self.destinations)
            .finish_non_exhaustive()
    }
}

/// THE HOST'S WAKE (`abi::mechanism::ticket::WakeFn`). Any thread; never blocks on the plugin;
/// never fails. A wake for an unknown worker or a stale generation is dropped (the latter by the
/// worker, which alone knows the generation).
pub(crate) extern "C" fn host_wake(ctx: HostCtx, ticket: Ticket) {
    // A generation-0 ticket (NONE) is a stale wake like any other: routed, and dropped and
    // counted by the worker, never silently lost here.
    if ctx.ptr.is_null() {
        return;
    }
    // SAFETY: every `HostCtx` the host hands out points to a leaked `InstanceWake`.
    let target = unsafe { &*ctx.ptr.cast_const().cast::<InstanceWake>() };
    if let Some(route) = target.route.get().and_then(Weak::upgrade) {
        route.wake(ticket);
    }
}
