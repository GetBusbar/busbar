// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # busbar-kernel — the Teller, and exactly what the loop needs
//!
//! Bytes arrive on a transport; a plane says what they mean; this crate runs the same steps on
//! every unit of work and posts the result. It knows no protocol. It has no idea what any plane
//! is for. What it owns is the ORDER, the DOOR and the EXIT: the ten steps happen in one place, a
//! unit's reservation is opened in one place, and it is taken back and settled in one place.
//!
//! ## One file per subject
//!
//! - [`teller`] — the loop. Ten steps, the two audit doors, the settlement table as a pure
//!   function, and the single exit path that takes the hold out of its cell.
//! - [`pump`] — frames in, frames out: which frame belongs to which unit, one open unit per
//!   direction, a bounded number of one-shots, the emission clock.
//! - [`inflight`] — the node-global sharded table of live units (hold cell, accrual count,
//!   cancellation, step state) and the session table beside it.
//! - [`recovery`] — bringing a hold back from a journal record after a crash and settling it.
//! - [`mod@slice`] — the node's slices of a bucket window, the concurrency leases, and the epoch fence.
//! - [`registry`] — the plugin registry, its generations, and whether two claims can both match.
//! - [`grammar`] — the closed grammars: selectors, locations, and the JSON span scanner.
//! - [`tick`] — the session tick, the node tick and its sweep, drain, and the fleet rule.
//! - [`arena`] — the per-unit 4 KiB scratch space and the per-connection credential slab.
//!
//! ## What this crate names, and what it owns
//!
//! It depends on the capability types and on the contract crate, and on nothing else in the
//! workspace. Every type that belongs to the plugin-visible contract — the frame, the stream id,
//! the direction, the selector, the location, the plugin kinds, the claim, the cap dimension, the
//! bucket, the status and finish classes — is the contract's own and is named here rather than
//! restated. Each of those values arrives from outside the kernel or leaves for outside it, so a
//! kernel-local copy would be the loop deciding about something other than what it was handed.
//!
//! What is genuinely the kernel's own stays here and says so: how specific one selector is against
//! another, which axis the boot-time overlap check groups a form onto, the pump's reduction of the
//! plane's richer answer, and the record recovery reads a hold back from.
//!
//! Every door onto the outside world — the units behind their sealed traits, the store behind the
//! slice trait, the clock — is a trait this crate declares and someone else implements. That is
//! what makes the loop testable with no transport, no store and no runtime.
//!
//! ## Where the no-allocation rule is actually met
//!
//! The design's rule is that nothing on the Teller path allocates outside the per-unit arena.
//! Honestly, as this crate stands:
//!
//! - **Met.** [`arena::Arena`] is a fixed 4 KiB buffer with a bump cursor and no heap use at all.
//!   The JSON span scanner in [`grammar`] allocates nothing, ever — it returns byte spans into the
//!   caller's buffer and decodes escapes through a stack buffer. The hold cell, the accrual
//!   counter, the cancellation token and the step state are atomics and a mutex. The settlement
//!   table, the fee rule, the sweep verdict and the fleet rule are pure functions over `Copy` data.
//!   The emission clock and the one-shot counter are integers.
//! - **Allocates once, off the path.** The in-flight and session shards, the credential slab and
//!   the registry allocate when they are built or when a connection is accepted, never per frame.
//! - **Still allocates, and is marked.** `busbar_caps::Usage` takes a `Vec` of lines, so the exit path
//!   builds one small vector per unit; the usage report is the contract's bounded `usage_lines ≤ 16`
//!   type once that lands. Every stand-in that owns a `String` (selector literals, lane and class
//!   names) allocates when config is read at boot, which is not the Teller path, but the names
//!   themselves become interned ids in the contract crate.
//!
//! ## Plain words for the money rules
//!
//! Where evidence is missing or two sources disagree, the ledger posts the LOWER amount, marks the
//! posting, and puts it on a report a person reads. That is the whole of [`teller::settle_amount`],
//! and it is a pure function precisely so it can be read as a table and tested as one.

pub mod arena;
pub mod grammar;
pub mod inflight;
pub mod pump;
pub mod recovery;
pub mod registry;
pub mod slice;
pub mod teller;
pub mod tick;

/// Milliseconds on the kernel's monotonic clock.
///
/// The kernel never reads a wall clock: every deadline, every tick interval and every lease
/// lifetime in this crate is a difference between two of these, handed in by the caller.
pub type Millis = u64;

/// Nanoseconds, for the one thing measured that finely: the pacing gap between two emitted frames.
pub type Nanos = u64;

/// The kernel's clock, as a value source rather than a capability.
///
/// A read-only source of the monotonic time in milliseconds. It is a trait so a test can drive
/// time by hand, and it is deliberately incapable of anything else.
pub trait Clock: Send + Sync {
    /// Milliseconds since some fixed point this node chose at boot.
    fn now(&self) -> Millis;
}

/// A clock a test drives by hand.
#[derive(Debug, Default)]
pub struct ManualClock {
    now: std::sync::atomic::AtomicU64,
}

impl ManualClock {
    /// A clock reading zero.
    pub fn new() -> Self {
        ManualClock::default()
    }

    /// Move time forward.
    pub fn advance(&self, by: Millis) {
        self.now.fetch_add(by, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Millis {
        self.now.load(std::sync::atomic::Ordering::Relaxed)
    }
}
