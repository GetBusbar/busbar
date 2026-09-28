// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE DISPATCHER (the design's §11 plugin ABI, migration step M1): the host side of the shared
//! mechanism in `busbar_contract::abi::mechanism`, generic over the kind.
//!
//! * [`load`] — ONE loader path for both origins: [`load::load_dropped`] (a cdylib on disk) and
//!   [`load::load_linked`] (a compiled-in row's `DoorFn`) run the SAME door validation and
//!   answer the same [`plugin::Plugin`]. Every refusal is a typed [`load::LoadError`].
//! * [`plugin`] — [`plugin::Plugin`]`<K>`: the instance handle, the one crossing and its outcome
//!   authority (the return value decides; a mirror that disagrees, or an unknown byte, is FAULT),
//!   the #85 envelope ingest, and `max_inflight`.
//! * [`ticket`] — tickets `(slot, generation)` unique per instance across all workers, the host's
//!   `wake`, and completion handles `(ticket, seq)`.
//! * [`worker`] — the workers: per-worker ticket slabs, latched spurious-tolerant wakes, RESUME,
//!   `wake_at_ns` timers, driver tickets, deadline classes and client drop.
//! * `watchdog` — an op that does not RETURN within its class budget faults its instance and
//!   replaces its worker.
//!
//! Nothing here names a kernel type, and nothing existing is rewired to it: the kernel adopts it
//! per kind (M3). A kind is a [`Kind`] marker naming its code, its table (`abi/<kind>/Ops`) and its
//! timeout outcome.

pub mod load;
pub mod plugin;
pub mod ticket;
mod watchdog;
pub mod worker;

use std::mem::{offset_of, size_of};
use std::sync::OnceLock;
use std::time::Instant;

use busbar_contract::abi::mechanism::call::{
    Blob, InHead, Op, OutHead, Outcome, RawOutcome, BLOB_ABSENT,
};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, OpsHead, RefreshIn, ReleaseIn, TickIn,
    TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};
use busbar_contract::abi::mechanism::KindCode;

pub use load::{load_dropped, load_linked, LoadError, ManifestFacts};
pub use plugin::{Bind, Called, Diagnostic, Dropped, EnvelopeSink, Metric, NoSink, Plugin};
pub use ticket::{Completions, Redeem};
pub use worker::{Budgets, DispatchConfig, DispatchStats, Dispatcher, Done, Reply};

/// A kind, as the dispatcher sees it: its code, its table and its timeout outcome. Implemented once
/// per kind when the kernel adopts it (M3); `Ops` is that kind's `abi/<kind>/Ops`.
pub trait Kind: Send + Sync + 'static {
    /// The kind's code; a door stating another is refused.
    const CODE: KindCode;
    /// The kind's ops table: [`OpsHead`] followed by the kind's slots, contiguous.
    type Ops: Copy;
    /// What a Call/Stream/Connection deadline answers, after `cancel`.
    const TIMEOUT: Outcome;
}

/// The byte offset of the first slot in every table.
const FIRST_SLOT: usize = offset_of!(OpsHead, validate);

/// How many slots the host's table of `K` holds (`OpsHead.slots` must equal it).
pub(crate) fn host_slots<K: Kind>() -> u32 {
    ((size_of::<K::Ops>() - FIRST_SLOT) / size_of::<Option<Op>>()) as u32
}

/// `size_of` the host's table of `K` (`OpsHead.size` must equal it).
pub(crate) fn host_table_size<K: Kind>() -> u32 {
    size_of::<K::Ops>() as u32
}

/// An `in` struct: it LEADS with an [`InHead`].
///
/// # Safety
/// The implementor is `#[repr(C)]` with an [`InHead`] as its first field, and a frame holding it may
/// move between threads (its pointers are host buffers or `'static` data).
pub unsafe trait InFrame: Copy + 'static {}

/// An `out` struct: it LEADS with an [`OutHead`].
///
/// # Safety
/// As [`InFrame`], with an [`OutHead`] first.
pub unsafe trait OutFrame: Copy + 'static {}

// SAFETY: each is `#[repr(C)]` in `abi/mechanism/` and leads with its head.
unsafe impl InFrame for InHead {}
unsafe impl InFrame for ValidateIn {}
unsafe impl InFrame for OpenIn {}
unsafe impl InFrame for GenIn {}
unsafe impl InFrame for RefreshIn {}
unsafe impl InFrame for TickIn {}
unsafe impl InFrame for DriveIn {}
unsafe impl InFrame for CancelIn {}
unsafe impl InFrame for ReleaseIn {}
unsafe impl OutFrame for OutHead {}
unsafe impl OutFrame for OpenOut {}
unsafe impl OutFrame for TickOut {}
unsafe impl OutFrame for CancelOut {}

/// One op's `in` and `out`, host-owned. A frame that can pend is boxed by the dispatcher, so its
/// address is stable across PENDING and RESUME (never the worker's scratch).
#[derive(Debug, Clone, Copy)]
pub struct Frame<I, O> {
    /// The `in`.
    pub input: I,
    /// The `out`.
    pub out: O,
}

// SAFETY: `InFrame`/`OutFrame` promise the frame may move between threads; one thread touches it
// at a time (ops on one ticket are serialized).
unsafe impl<I: InFrame, O: OutFrame> Send for Frame<I, O> {}

impl<I: InFrame, O: OutFrame> Frame<I, O> {
    /// A frame of `input` and `out`. The dispatcher writes both heads before every crossing.
    pub fn new(input: I, out: O) -> Self {
        Self { input, out }
    }

    pub(crate) fn heads(&mut self) -> (*mut InHead, *mut OutHead, u32) {
        (
            std::ptr::addr_of_mut!(self.input).cast(),
            std::ptr::addr_of_mut!(self.out).cast(),
            size_of::<O>() as u32,
        )
    }
}

/// An absent blob.
pub const NO_BLOB: Blob = Blob {
    ptr: std::ptr::null(),
    len: 0,
    fmt: BLOB_ABSENT,
    flags: 0,
};

/// A blank [`InHead`]; the dispatcher fills it before each crossing.
pub fn in_head() -> InHead {
    InHead {
        size: size_of::<InHead>() as u32,
        op: 0,
        flags: 0,
        deadline_class: 0,
        _reserved: [0; 3],
        host: HostCtx {
            ptr: std::ptr::null_mut(),
        },
        ticket: Ticket::NONE,
        deadline_ns: 0,
        trace_id: [0; 16],
        parent_span_id: 0,
        extensions: NO_BLOB,
    }
}

/// A blank [`OutHead`], pre-filled as FAULT (an `out` nobody wrote reads as a fault).
pub fn out_head() -> OutHead {
    busbar_contract::abi::mechanism::call::OutHead {
        size: size_of::<OutHead>() as u32,
        outcome: RawOutcome::of(Outcome::Fault),
        _reserved: [0; 3],
        wake_at_ns: 0,
        lease: 0,
        error: busbar_contract::abi::mechanism::call::AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        envelope: busbar_contract::abi::mechanism::call::Envelope {
            metrics: std::ptr::null(),
            metrics_len: 0,
            diags: std::ptr::null(),
            diags_len: 0,
        },
        extensions: NO_BLOB,
    }
}

/// The host's coarse monotonic clock, in nanoseconds since first use: the clock `deadline_ns`,
/// `wake_at_ns` and `TickIn::now_ns` are on.
pub fn now_ns() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_nanos() as u64
}
