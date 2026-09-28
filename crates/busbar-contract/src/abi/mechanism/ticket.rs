// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TICKETS, WAKES AND COMPLETION HANDLES — how a call that cannot finish now says so without
//! blocking (the design's locked plugin ABI).
//!
//! * A [`Ticket`] is `(slot, generation)`. A request or stream mints one and reuses it for all its
//!   ops. The generation is bumped every time the slot is recycled, so a late wake for a recycled
//!   slot names a generation that no longer exists and is dropped.
//! * **Wakes are LATCHED:** a wake that arrives before the op answered [`super::call::Outcome::Pending`]
//!   is kept and resumes it at once. **Wakes are SPURIOUS-TOLERANT:** a resumed op that is still not
//!   done answers `Pending` again; a wake never obliges a plugin to be ready.
//! * A host service that can pend answers with a [`CompletionHandle`] `(ticket, seq)`. On resume the
//!   plugin re-issues the same handle and receives the stored result: the host never runs it twice.

use std::os::raw::c_void;

use crate::abi::host::conn::ConnSlots;

/// A ticket: `(slot, generation)`. UNIQUE PER INSTANCE across all workers, so a plugin may key its
/// per-ticket state by the whole `Ticket`. The encoding of `slot` is HOST-PRIVATE (a host may pack a
/// worker and an index into it); a plugin never decodes it.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ticket {
    /// The slot in the owning worker's ticket slab.
    pub slot: u32,
    /// The slot's generation; `0` is never minted.
    pub generation: u32,
}

impl Ticket {
    /// No ticket: the call may not pend.
    pub const NONE: Ticket = Ticket {
        slot: 0,
        generation: 0,
    };

    /// Whether this is [`Ticket::NONE`].
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.generation == 0
    }
}

/// A pending host-service result: `(ticket, seq)`, `seq` counting the services one ticket issued.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompletionHandle {
    /// The ticket the service was issued under.
    pub ticket: Ticket,
    /// The issue order within the ticket.
    pub seq: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// The host's context for one plugin instance: opaque to the plugin, handed back on `wake`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HostCtx {
    /// The host's per-instance state; never dereferenced by a plugin.
    pub ptr: *mut c_void,
}

/// `host.wake(ctx, ticket)`: callable from any thread, never blocks, never fails. A wake for a
/// stale generation is dropped. `extern "C"`: a panic escaping it aborts.
pub type WakeFn = extern "C" fn(ctx: HostCtx, ticket: Ticket);

/// The host tables handed to `open`: the mechanism's own services and the shared host tables
/// (`abi/host/`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HostTables {
    /// `size_of::<HostTables>()` at construction.
    pub size: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The context every host call is made with.
    pub ctx: HostCtx,
    /// The wake.
    pub wake: Option<WakeFn>,
    /// The connection table; NULL when the instance declared no need.
    pub conns: *const ConnSlots,
}
