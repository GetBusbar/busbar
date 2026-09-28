// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S WAKE.
//!
//! * [`host_wake`] is the host's `WakeFn`: callable from any thread, never blocks on the plugin or
//!   on I/O (it pushes onto the owning worker's channel), never fails. It routes by decoding the
//!   slot; the worker checks the generation.

use std::sync::{OnceLock, Weak};

use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};

/// Where an instance's wakes go: the dispatcher that holds its tickets.
pub(crate) trait WakeRoute: Send + Sync {
    /// Push `t` to the worker that owns it. Never blocks on the plugin.
    fn wake(&self, t: Ticket);
}

/// What an instance's `HostCtx` points to: the dispatcher its tickets live in. Leaked per
/// instance, so a late wake never dangles; a wake before any dispatcher is bound is dropped.
#[derive(Debug, Default)]
pub(crate) struct InstanceWake {
    pub(crate) route: OnceLock<Weak<dyn WakeRoute>>,
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
