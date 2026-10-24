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

/// Where an instance's wakes go: the dispatcher that holds its tickets.
pub(crate) trait WakeRoute: Send + Sync {
    /// Push `t` to the worker that owns it, with `supplier` the instance whose context handed the
    /// host `t` (#74: a forged generation the worker finds is that instance's; `None` = the host's
    /// own wake, blamed on no one and counted against the process's latch). Never blocks on the
    /// plugin.
    fn wake(&self, t: Ticket, supplier: Option<&'static InstanceWake>);

    /// The host services this route's instances are served from; `None` = none.
    fn services(&self) -> Option<super::services::Served> {
        None
    }

    /// The store of this route's dispatcher: the services' kept results and the driver tickets'
    /// held exchanges (`super::held`); `None` = none.
    fn store(&self) -> Option<std::sync::Arc<super::services::ServiceStore>> {
        None
    }

    /// The host's I/O this route's instances are served from; `None` = none.
    fn io(&self) -> Option<std::sync::Arc<dyn busbar_contract::io_host::IoHost>> {
        None
    }

    /// The store a service's results are kept under, whether or not this route serves the host
    /// services (the auth handle's slots run on it without them).
    fn service_store(&self) -> Option<std::sync::Arc<super::services::ServiceStore>> {
        self.services().map(|s| s.store)
    }

    /// The kernel's side of the host auth handle this route's instances are served from; `None` =
    /// none, and every auth-handle service answers REFUSED past its checks.
    fn auth_handle(&self) -> Option<std::sync::Arc<dyn super::auth_handle::AuthHandleHost>> {
        None
    }

    /// The seal the host lent this route's dispatcher (Part 2 #54); `None` = none, and a reveal of
    /// a `Secret` its instances' services would make is refused.
    fn seal(
        &self,
    ) -> Option<std::sync::Arc<dyn busbar_contract::plugin::KernelSeal + Send + Sync>> {
        None
    }

    /// The waker of an INLINE ticket's task (`super::inline`); `None` for any other ticket.
    fn inline_waker(&self, t: Ticket) -> Option<std::task::Waker> {
        let _ = t;
        None
    }

    /// THE FRAMING an op on ticket `t` was made for, as every auth-handle call names it: the
    /// framing a ticket minted for one of its ops works for (`super::inline::InlineTickets::
    /// framing_of`), else `t`'s own reading.
    fn framing_of(&self, t: Ticket) -> u64 {
        t.framing()
    }

    /// The INLINE tickets of this route's dispatcher (`super::inline`); `None` = none.
    fn inline(&self) -> Option<std::sync::Arc<super::inline::InlineTickets>> {
        None
    }
}

/// What an instance's `HostCtx` names (through [`super::handle`], never by address): the dispatcher its tickets live in, and who the instance
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
    /// How many archives the manifest declares each granted destination keeps when the host rolls
    /// it over (`declares.keep`), granted with the destinations; a key not named takes
    /// [`busbar_contract::services::DISK_ROTATE_UNDECLARED`].
    pub(crate) keep: OnceLock<std::collections::BTreeMap<String, u32>>,
    /// Each granted key bound to the file the instance's settings give it, re-bound by every
    /// `open` and `refresh` (`disk.append` maps a key through it).
    pub(crate) bound: std::sync::RwLock<Vec<busbar_contract::services::DiskDest>>,
    /// The instance's handle names nothing any more (#74): set when it is quarantined, faulted by
    /// the watchdog, closed or dropped. Checked by `handle::resolve` after the tag verifies.
    pub(crate) revoked: std::sync::atomic::AtomicBool,
    /// The instance this entry is the handle of, set once it exists: what a forgery found AFTER the
    /// call that supplied it (a forged ticket generation, judged on the worker against the supplier
    /// its wake carried) quarantines.
    pub(crate) instance: OnceLock<std::sync::Weak<super::plugin::Instance>>,
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

/// Where a ticket's wake goes, and the instance whose context supplied the ticket (#74). Carried
/// from the call that took the ticket to whatever fires the wake (a completion, a connection's
/// readiness, an I/O waker), on any thread: the supplier is never read off the thread the wake
/// fires on, so a wake firing inside another instance's crossing never blames that instance.
#[derive(Clone)]
pub(crate) struct Waking {
    pub(crate) route: Weak<dyn WakeRoute>,
    pub(crate) supplier: Option<&'static InstanceWake>,
}

impl Waking {
    /// The waking of the instance `wake` names (resolved by the caller): its dispatcher, and itself
    /// as the supplier. `None` before a dispatcher is bound.
    pub(crate) fn of(wake: &'static InstanceWake) -> Option<Self> {
        Some(Self {
            route: wake.route.get()?.clone(),
            supplier: Some(wake),
        })
    }

    /// Wake `t` through the route, naming the supplier.
    pub(crate) fn wake(&self, t: Ticket) {
        if let Some(route) = self.route.upgrade() {
            route.wake(t, self.supplier);
        }
    }
}

/// THE HOST'S WAKE (`abi::mechanism::ticket::WakeFn`). Any thread; never blocks on the plugin;
/// never fails. A wake for an unknown worker or a stale generation is dropped (the latter by the
/// worker, which alone knows the generation).
pub(crate) extern "C" fn host_wake(ctx: HostCtx, ticket: Ticket) {
    // A generation-0 ticket (NONE) is a stale wake like any other: routed, and dropped and
    // counted by the worker, never silently lost here.
    // THE HANDLE IS VERIFIED BEFORE IT NAMES ANYTHING (#74): a context the host did not mint wakes
    // nothing and is counted.
    let Some(target) = super::handle::resolve(ctx) else {
        return;
    };
    // The supplier is the context's own instance, resolved above (#74).
    if let Some(route) = target.route.get().and_then(Weak::upgrade) {
        route.wake(ticket, Some(target));
    }
}
