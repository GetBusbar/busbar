// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE'S MONEY SLOTS: `reserve`, `slice_release`, the three coalesced batches and the cap
//! input, transcribed from the BINDING ARCHITECT RULING in `m3-inputs.md`, "store v3 money slots"
//! (2026-09-28), and its "window caps" ruling. The model is `slice.rs`: a draw is (bucket,
//! dimension, wanted, epoch); dimension ∈ {NanoUnits, Requests, Concurrency, Class(key)}; a chain
//! draw is all or nothing.
//!
//! DEDUPE, the same on every slot here: the module rule in [`super`] ("Dedupe", S1-S4): a replay
//! with the same value fields applies nothing, returns the ORIGINAL `out` and re-writes the
//! original grants or released amounts into the NEW call's host buffers; different value fields
//! are REFUSED with [`super::DIAG_OPID_CONFLICT`]; only a READY that applied a change is recorded.

use crate::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead};

/// An operation id: 16 bytes, the minting node's id (bytes 0..8) then that node's monotonic
/// counter (bytes 8..16), both little-endian. Minted by the KERNEL, one per `reserve`, one per
/// `slice_release`, one per coalesced batch (m3-inputs "store v3 money slots", `OpId`). A store
/// treats it as opaque bytes and dedupes on it.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpId(pub [u8; 16]);

impl OpId {
    /// The id for `(node, counter)`.
    #[must_use]
    pub const fn from_parts(node: u64, counter: u64) -> Self {
        let n = node.to_le_bytes();
        let c = counter.to_le_bytes();
        Self([
            n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], c[0], c[1], c[2], c[3], c[4], c[5],
            c[6], c[7],
        ])
    }

    /// The minting node's id.
    #[must_use]
    pub const fn node(self) -> u64 {
        let b = self.0;
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }

    /// The node's counter.
    #[must_use]
    pub const fn counter(self) -> u64 {
        let b = self.0;
        u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]])
    }
}

/// [`UnitCell::dimension`]: money, in nano-units (`CapDimension::NanoUnits`).
pub const DIM_NANO_UNITS: u32 = 0;
/// [`UnitCell::dimension`]: the admission counter (`CapDimension::Requests`).
pub const DIM_REQUESTS: u32 = 1;
/// [`UnitCell::dimension`]: the live gauge (`CapDimension::Concurrent`).
pub const DIM_CONCURRENCY: u32 = 2;
/// [`UnitCell::dimension`]: a declared meter class, keyed by [`UnitCell::class_key`]
/// (`CapDimension::Class`).
pub const DIM_CLASS: u32 = 3;

/// One cell of a draw: THE fixed `bb_units[]` element (m3-inputs "store v3 money slots",
/// `UnitCell`; `window_start` per the ARCHITECT "window caps" correction, 2026-09-28).
/// `(bucket, pool, dimension, class_key, window_start)` names the cell; `amount` is how much.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UnitCell {
    /// The bucket id.
    pub bucket: AbiStr,
    /// The pool the bucket is scoped to; absent = `BucketScope::All`.
    pub pool: AbiStr,
    /// [`DIM_NANO_UNITS`] | [`DIM_REQUESTS`] | [`DIM_CONCURRENCY`] | [`DIM_CLASS`].
    pub dimension: u32,
    /// Alignment padding.
    pub _r: u32,
    /// The meter class key; present only for [`DIM_CLASS`].
    pub class_key: AbiStr,
    /// How much is wanted.
    pub amount: u64,
    /// The window this cell draws from (ms), named BY THE CALLER. `0` = no window: a gauge
    /// ([`DIM_CONCURRENCY`]) or a window that never rolls, whose cap is pushed at `0`.
    pub window_start: u64,
}

/// What one cell drew (m3-inputs "store v3 money slots", `reserve` out, `CellGrant`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CellGrant {
    /// The store's handle for the slice, spoken back on `slice_release`.
    pub slice_id: u64,
    /// How much was granted: EXACTLY the cell's `amount`. There is no partial grant ([`ReserveIn`]
    /// "GRANT SIZE", the 1.5.5 rule, STORE v3 MONEY RULINGS S5).
    pub granted: u64,
    /// When the node must stop drawing against it (ms).
    pub valid_until_ms: u64,
}

/// [`ReserveOut::reason`]: granted (READY).
pub const RESERVE_OK: u32 = 0;
/// [`ReserveOut::reason`]: a cell's window has no headroom (`SliceError::Exhausted`).
pub const RESERVE_EXHAUSTED: u32 = 1;
/// [`ReserveOut::reason`]: the node's epoch is behind the fleet's (`SliceError::StaleEpoch`).
pub const RESERVE_STALE_EPOCH: u32 = 2;
/// [`ReserveOut::reason`]: the store could not be reached (`SliceError::Unavailable`).
pub const RESERVE_UNAVAILABLE: u32 = 3;
/// [`ReserveOut::reason`]: a cell names a window no `window_caps` cap was pushed for — never an
/// implicit unlimited (m3-inputs ARCHITECT ruling "window caps", reason 4 `NoCap`).
pub const RESERVE_NO_CAP: u32 = 4;

/// `reserve`'s `in` (m3-inputs "store v3 money slots", `reserve`). Request path, may pend, [`DeadlineClass::Call`](crate::abi::mechanism::call::DeadlineClass::Call).
///
/// Each cell draws from its `(bucket, pool, dimension, class_key, window_start)` slot, capped by
/// the cap `window_caps` last set for it; one reserve is one all-or-nothing chain draw even across
/// cells in different windows ("window caps" correction). ATOMIC: if ANY cell would grant 0, the
/// store applies NOTHING and answers FAILED with a [`ReserveOut::reason`] and `grants_len == 0`. A node-local
/// store (Statement mark `MARK_EPHEMERAL`) holds one constant epoch and never answers
/// [`RESERVE_STALE_EPOCH`] (store_adapter.rs module doc, "Slices"). Deduped on `op_id`.
///
/// GRANT SIZE, PINNED TO 1.5.5 (STORE v3 MONEY RULINGS S5). 1.5.5 never granted PART of a draw:
/// its admission checked every capped bucket of the chain and either charged all of them or
/// none (v1.5.5 `crates/busbar/src/governance/state.rs:1588-1604` `try_admit`, `:1791-1800` the
/// per-metric test). So a cell grants its WHOLE `amount` or the reserve fails
/// [`RESERVE_EXHAUSTED`]; a READY grant is ALWAYS `granted == amount`, and a store never grants
/// partially. Every cell's `amount` is above `0`. `used` is the cell's slot total in its window,
/// and the test per dimension is exactly 1.5.5's:
/// * [`DIM_REQUESTS`]: exhausted iff `used + amount > cap` (state.rs:1791-1793,
///   `requests.saturating_add(1) > cap`);
/// * [`DIM_CLASS`] (the token meters): exhausted iff `used >= cap` (state.rs:1796,
///   `tokens >= cap`: best effort, the draw that crosses the cap is granted whole);
/// * [`DIM_NANO_UNITS`] (budget): exhausted iff `used >= cap || used + amount > cap`
///   (state.rs:1798-1800, `derived >= cap || derived.saturating_add(fee) > cap`);
/// * [`DIM_CONCURRENCY`]: exhausted iff `used + amount > cap`, the gauge's compare-and-increment
///   (state.rs:1662-1665, `(v < cap).then_some(v + 1)`).
///
/// `used + amount` is CHECKED arithmetic: an overflow is [`RESERVE_EXHAUSTED`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReserveIn {
    /// The head.
    pub head: InHead,
    /// The kernel-minted id of this reserve.
    pub op_id: OpId,
    /// The epoch the node believes it is in.
    pub epoch: u64,
    /// The cells.
    pub cells: *const UnitCell,
    /// How many.
    pub cells_len: usize,
    /// The HOST-owned array the grants are written into (mechanism memory class (i); ARCHITECT
    /// 2026-09-28: a request-path result's buffer is named in the `in`, never in the `out` the
    /// host zeroes). One grant per cell, in cell order.
    pub grants: *mut CellGrant,
    /// Its capacity. Below `cells_len` the store applies nothing and answers FAILED with
    /// `needed_grants = cells_len` (the short-buffer answer, M-SB, stated on [`OutHead`](crate::abi::mechanism::call::OutHead)).
    pub grants_cap: usize,
}

/// `reserve`'s `out` (m3-inputs "store v3 money slots", `reserve`; the grants themselves go into
/// [`ReserveIn::grants`]).
///
/// On READY the store has written one grant per cell into the host's array and
/// `grants_len == cells_len`. On FAILED nothing is written and `grants_len == 0`: either a
/// short buffer (`needed_grants > grants_cap`, `reason == 0`, M-SB) or a refusal of the draw
/// (`needed_grants == 0`, `reason` one of [`RESERVE_EXHAUSTED`], [`RESERVE_STALE_EPOCH`],
/// [`RESERVE_UNAVAILABLE`], [`RESERVE_NO_CAP`]). A short answer is never recorded under the
/// `op_id` (only an applied change is recorded). A refusal with a reason outside 1-4, or a `failed_cell` that is neither below `cells_len` nor
/// [`RESERVE_NO_FAILED_CELL`], is FAULT; READY with `grants_len != cells_len`, a grant other than
/// the cell's whole `amount` (a partial grant), `reason != 0` or a named `failed_cell` is FAULT
/// ([`super::check::check_reserve`]).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReserveOut {
    /// The head.
    pub head: OutHead,
    /// How many grants were written: `cells_len` on READY, `0` on FAILED.
    pub grants_len: usize,
    /// [`RESERVE_OK`] or the refusal reason.
    pub reason: u32,
    /// On FAILED, the index of the first cell that could not be granted (slice.rs
    /// `ChainRefused { at }`); [`RESERVE_NO_FAILED_CELL`] when none applies ("window caps"
    /// correction (3)).
    pub failed_cell: u32,
    /// On a short FAILED, how many grants the answer needs (`cells_len`); `0` otherwise (M-SB).
    pub needed_grants: u64,
}

/// [`ReserveOut::failed_cell`]: no cell is named (READY, or a failure no single cell caused).
pub const RESERVE_NO_FAILED_CELL: u32 = u32::MAX;

/// One slice handed back (m3-inputs "store v3 money slots", `slice_release` items).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReleaseItem {
    /// The slice, as `reserve` granted it; the slice already knows its window.
    pub slice_id: u64,
    /// How much of it the node did not spend.
    pub unspent: u64,
}

/// `slice_release`'s `in` (m3-inputs "store v3 money slots", `slice_release`). Request-path exit,
/// may pend, [`DeadlineClass::Call`](crate::abi::mechanism::call::DeadlineClass::Call). Deduped on
/// `op_id`.
///
/// CLAMPED: the store returns to each slice at most what that slice has left, never more than it
/// granted.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SliceReleaseIn {
    /// The head.
    pub head: InHead,
    /// The kernel-minted id of this release.
    pub op_id: OpId,
    /// The epoch the node believes it is in.
    pub epoch: u64,
    /// The items.
    pub items: *const ReleaseItem,
    /// How many.
    pub items_len: usize,
    /// The HOST-owned array the released amounts are written into, per item in order
    /// (mechanism memory class (i); ARCHITECT 2026-09-28: named in the `in`, never in the `out`).
    pub released: *mut u64,
    /// Its capacity. Below `items_len` the store applies nothing and answers FAILED with
    /// `needed_released = items_len` (the short-buffer answer, M-SB, stated on [`OutHead`](crate::abi::mechanism::call::OutHead)).
    pub released_cap: usize,
}

/// `slice_release`'s `out` (m3-inputs "store v3 money slots", `slice_release`; the amounts go into
/// [`SliceReleaseIn::released`]). On READY the store has written, per item in order, the amount it
/// actually took back after clamping, and `released_len == items_len`. READY with any other
/// `released_len`, or an amount over the item's `unspent`, is FAULT. FAILED (the store could not be
/// reached, a stale epoch, an unknown slice) applies nothing and writes nothing: `released_len == 0`
/// ([`super::check::check_slice_release`]).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SliceReleaseOut {
    /// The head.
    pub head: OutHead,
    /// How many amounts were written.
    pub released_len: usize,
    /// On a short FAILED, how many amounts the answer needs (`items_len`); `0` otherwise (M-SB).
    pub needed_released: u64,
}

/// One cell of the token ledger and its signed delta: the fixed (bucket, window) plus the tree's
/// `UsageDelta` shape as a JSON blob with the #81 scale discriminator (B.1 "Record blobs").
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UsageCell {
    /// The bucket id (a key's own bucket or a budget-group bucket).
    pub bucket: AbiStr,
    /// The window start.
    pub window_start: u64,
    /// The `UsageDelta`.
    pub delta: Blob,
}

/// `add_usage_batch`'s `in` (m3-inputs "store v3 money slots", batch ops; B.1 "Slots", "Writes").
/// Off path, may pend, [`DeadlineClass::WriteBehind`](crate::abi::mechanism::call::DeadlineClass::WriteBehind).
/// ONE `op_id` per coalesced batch; the cells apply in batch order, atomically per batch.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AddUsageBatchIn {
    /// The head.
    pub head: InHead,
    /// The kernel-minted id of this batch.
    pub op_id: OpId,
    /// The cells, in batch order.
    pub cells: *const UsageCell,
    /// How many.
    pub cells_len: usize,
}

/// `add_metering_batch`'s and `append_audit_batch`'s `in` (m3-inputs "store v3 money slots",
/// batch ops; B.1 "Slots", "Writes"): ONE `op_id` per coalesced batch and the records in batch
/// order (`MeteringDelta`s or `AuditRecord`s, the tree's shapes with the scale discriminator),
/// applied in order, atomically per batch. Off path, may pend,
/// [`DeadlineClass::WriteBehind`](crate::abi::mechanism::call::DeadlineClass::WriteBehind).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpBlobsIn {
    /// The head.
    pub head: InHead,
    /// The kernel-minted id of this batch.
    pub op_id: OpId,
    /// The records, in batch order.
    pub records: *const Blob,
    /// How many.
    pub records_len: usize,
}

/// One window's cap (m3-inputs ARCHITECT ruling "window caps", `WindowCap`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WindowCap {
    /// The bucket id.
    pub bucket: AbiStr,
    /// The pool scope; absent = `BucketScope::All`.
    pub pool: AbiStr,
    /// As [`UnitCell::dimension`].
    pub dimension: u32,
    /// Alignment padding.
    pub _r: u32,
    /// The meter class key; present only for [`DIM_CLASS`].
    pub class_key: AbiStr,
    /// The window this cap bounds (ms).
    pub window_start: u64,
    /// The cap.
    pub cap: u64,
    /// The configuration generation the cap was read from.
    pub config_gen: u64,
}

/// `window_caps`' `in` (m3-inputs ARCHITECT ruling "window caps"). Off path, may pend,
/// [`DeadlineClass::Call`](crate::abi::mechanism::call::DeadlineClass::Call). Deduped on `op_id`.
///
/// An UPSERT keyed by `(bucket, pool, dimension, class_key, window_start)` (`window_start` `0` =
/// no window): a HIGHER `config_gen` replaces the cap (an operator's mid-window change takes
/// effect, as 1.5.5 read caps from live config); an EQUAL `config_gen` with a different cap is a
/// conflict; a LOWER one is ignored. ATOMIC PER PUSH, like a batch: one conflict REFUSES the
/// whole push, nothing applied, with [`super::DIAG_CAP_CONFLICT`] and an `OutHead.error` text
/// that BEGINS with the decimal index of the first conflicting cap ("window caps" correction
/// (1); [`super::check::check_window_caps`]). The kernel pushes caps at `open`/`refresh` and
/// BEFORE the first `reserve` of each new window.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WindowCapsIn {
    /// The head.
    pub head: InHead,
    /// The kernel-minted id of this push.
    pub op_id: OpId,
    /// The caps.
    pub caps: *const WindowCap,
    /// How many.
    pub caps_len: usize,
}
