// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{OnceLock, Weak};

use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};

pub(crate) const INDEX_BITS: u32 = 20;

pub(crate) const MAX_INDEX: u32 = (1 << INDEX_BITS) - 1;

pub(crate) const MAX_WORKERS: u32 = 1 << (32 - INDEX_BITS);

pub(crate) fn encode(worker: u32, index: u32) -> u32 {
    (worker << INDEX_BITS) | index
}

pub(crate) fn decode(slot: u32) -> (u32, u32) {
    (slot >> INDEX_BITS, slot & MAX_INDEX)
}

pub(crate) trait WakeRoute: Send + Sync {
    fn wake(&self, t: Ticket, supplier: Option<&'static InstanceWake>);

    fn services(&self) -> Option<super::services::Served<'_>> {
        None
    }

    fn store(&self) -> Option<std::sync::Arc<super::services::ServiceStore>> {
        None
    }

    fn io(&self) -> Option<std::sync::Arc<dyn busbar_contract::io_host::IoHost>> {
        None
    }

    fn service_store(&self) -> Option<std::sync::Arc<super::services::ServiceStore>> {
        self.services().map(|s| std::sync::Arc::clone(s.store))
    }

    fn auth_handle(&self) -> Option<std::sync::Arc<dyn super::auth_handle::AuthHandleHost>> {
        None
    }

    fn seal(
        &self,
    ) -> Option<std::sync::Arc<dyn busbar_contract::plugin::KernelSeal + Send + Sync>> {
        None
    }

    fn inline_waker(&self, t: Ticket) -> Option<std::task::Waker> {
        let _ = t;
        None
    }

    fn inline(&self) -> Option<std::sync::Arc<super::inline::InlineTickets>> {
        None
    }
}

/// What an instance's `HostCtx` names (through [`super::handle`], never by address): the dispatcher its tickets live in, and who the instance
/// is to the host services. Leaked per instance, so a late wake never dangles; a wake before any
/// dispatcher is bound is dropped.
#[derive(Default)]
pub(crate) struct InstanceWake {
    pub(crate) exports: super::export_bindings::Bindings,
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
    /// Original connection authority is shared by instance teardown and the first export
    /// generation. Whichever retires it first owns the single table notification.
    pub(crate) conn_forgotten: std::sync::atomic::AtomicBool,
    /// What the connector slots hold for the instance: its streams, their facts, its dials in
    /// flight and its kept answers (`super::conn_services`), under locks of its own.
    pub(crate) conn_state: super::conn_services::ConnState,
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
    /// Last actual driver crossing of this instance, for outcome-only commit settlement wakes.
    pub(crate) conditional_driver: std::sync::Mutex<Option<Ticket>>,
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
    pub(crate) fn of(wake: &'static InstanceWake) -> Option<Self> {
        Some(Self {
            route: wake.route.get()?.clone(),
            supplier: Some(wake),
        })
    }

    pub(crate) fn wake(&self, t: Ticket) {
        if let Some(route) = self.route.upgrade() {
            route.wake(t, self.supplier);
        }
    }
}

/// THE HOST'S WAKE (`abi::mechanism::ticket::WakeFn`). Any thread; never blocks on the plugin;
/// never fails. A wake for an unknown worker or a stale generation is dropped (the latter by the
/// worker, which alone knows the generation).
#[doc(hidden)]
pub extern "C" fn host_wake(ctx: HostCtx, ticket: Ticket) {
    let Some(target) = super::handle::resolve(ctx) else {
        return;
    };

    if let Some(route) = target.route.get().and_then(Weak::upgrade) {
        route.wake(ticket, Some(target));
    }
}
