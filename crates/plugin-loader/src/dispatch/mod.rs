// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE DISPATCHER (`BUSBAR-1.6.0.md` THE DESIGN, §11, the plugin ABI): the host side of the shared
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
//! * [`answer`] — one answer as a kind's validator reads it ([`Kind::check`]).
//! * [`validate`] — the mechanism's own checks of every `out` head before it is read (its size,
//!   the error text, the #85 arrays); a violation is FAULT. A kind's reply fields are checked by
//!   its own `abi/<kind>/check_<op>` through [`Kind::check`], never re-implemented here.
//! * [`worker`] — the workers: per-worker ticket slabs, latched spurious-tolerant wakes, RESUME,
//!   `wake_at_ns` timers, driver tickets, deadline classes and client drop.
//! * `watchdog` — an op that does not RETURN within its class budget faults its instance and
//!   replaces its worker.
//!
//! Nothing here names a kernel type, and nothing existing is rewired to it: the kernel adopts it
//! per kind. A kind is a [`Kind`] marker naming its code, its table (`abi/<kind>/Ops`) and its
//! timeout outcome.

pub mod answer;
pub mod auth_outbound;
pub mod conn_services;
pub mod inline;
pub mod io_slots;
pub mod kinds;
pub mod load;
pub mod log_file;
pub mod plane_calls;
pub mod plugin;
pub mod ready;
pub mod services;
pub mod ticket;
pub mod validate;
mod watchdog;
pub mod worker;

use std::mem::{offset_of, size_of};
use std::sync::OnceLock;
use std::time::Instant;

use busbar_contract::abi::mechanism::call::{
    Blob, InHead, Op, OutHead, Outcome, RawOutcome, BLOB_ABSENT,
};
use busbar_contract::abi::mechanism::check::Fault;
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, OpsHead, ReadyIn, RefreshIn, ReleaseIn,
    TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};
use busbar_contract::abi::mechanism::KindCode;

pub use answer::{Answer, Context};
pub use inline::{InlineTicket, InlineTickets};
pub use kinds::plane::PlaneCancel;
pub use load::{
    load_dropped, load_dropped_bytes, load_linked, rendering_of, rendering_of_library, LinkedRow,
    LoadError, ManifestFacts,
};
pub use log_file::{LogLevel, PluginLogConfig, PluginLogSink};
pub use plugin::{
    install_member_secrets, Bind, Called, ConnTable, Diagnostic, Dropped, EnvelopeSink,
    MemberSecretFn, Metric, NoSink, Plugin, Recall, MAX_LOG_BYTES, MAX_LOG_RECORDS,
};
pub use services::{HostServices, Later, Ran, Reading, Stored};
pub use ticket::{Completions, Redeem};
pub use validate::Violation;
pub use worker::{Adopter, Budgets, DispatchConfig, DispatchStats, Dispatcher, Done, Lent, Reply};

/// A kind, as the dispatcher sees it: its code, its table and its timeout outcome. Implemented once
/// per kind ([`kinds`]); `Ops` is that kind's `abi/<kind>/Ops`.
pub trait Kind: Send + Sync + 'static {
    /// The kind's code; a door stating another is refused.
    const CODE: KindCode;
    /// The kind's ops table: [`OpsHead`] followed by the kind's slots, contiguous.
    type Ops: Copy;
    /// What a Call/Stream/Connection deadline answers, after `cancel`.
    const TIMEOUT: Outcome;

    /// The op's name, for the log line a broken rule writes.
    fn op_name(slot: u32) -> &'static str {
        lifecycle_name(slot)
    }

    /// The instance's CONTEXT for its checks, built once from the Statement at bind (the plane's
    /// tail bounds); `None` = the kind's checks need none. An `Err` refuses the load.
    ///
    /// # Errors
    /// Why the Statement cannot bind this kind.
    fn context(statement: &Statement) -> Result<Option<Box<Context>>, String> {
        let _ = statement;
        Ok(None)
    }

    /// The credential kinds an instance of this kind declares its op reads through the host's
    /// `records.secret`, read off its [`Kind::context`]; none for a kind that declares none.
    fn credential_kinds(context: Option<&Context>) -> Vec<String> {
        let _ = context;
        Vec::new()
    }

    /// THE KIND'S ANSWER VALIDATION: the kind's pure `check_<op>` in `abi/<kind>/`, run after every
    /// answer of every op, on EVERY outcome but FAULT (each check decides which fields an outcome
    /// carries). `Err` is FAULT, logged once at warn with the plugin, the
    /// kind, the op and the rule (never a payload byte). The dispatcher never re-implements a rule.
    /// An op whose kind states no rule beyond the mechanism's answers `Ok`.
    ///
    /// # Errors
    /// The rule the answer broke.
    fn check(answer: &Answer) -> Result<(), Fault> {
        let _ = answer;
        Ok(())
    }

    /// The unit a crossing of `slot` serves, read from its `in` (`in_size` bytes, leading with
    /// its head): the kernel-minted unit key, so a host service called inside the crossing answers
    /// for that unit. `None` = the op serves no unit.
    fn unit_of(
        slot: u32,
        input: *const busbar_contract::abi::mechanism::call::InHead,
        in_size: usize,
    ) -> Option<u64> {
        let _ = (slot, input, in_size);
        None
    }

    /// Whether a FAILED answer (that passed [`Kind::check`]) is SHORT: a host buffer too small,
    /// its `needed_*` above the capacity given. The caller re-calls once with bigger buffers; a
    /// second short answer on the re-call is FAULT (the short-buffer rule on `OutHead`).
    fn short(answer: &Answer) -> bool {
        let _ = answer;
        false
    }

    /// The `drive` frame of a driver ticket of this kind ([`Dispatcher::driver`]): the kind's own
    /// `drive` `in`/`out`, built once and boxed, so its address holds across PENDING and RESUME.
    /// A kind whose `drive` is the lifecycle's answers the lifecycle's `DriveIn`/`OutHead`.
    fn drive_frame() -> Box<dyn DriveFrame> {
        Box::new(Frame::new(
            DriveIn {
                head: in_head(),
                driver: Ticket::NONE,
            },
            out_head(),
        ))
    }

    /// A `cancel` frame of this kind: the kind's own `cancel` `in`/`out` (a plane's carries record
    /// buffers, SEAM-L(r)); a kind whose `cancel` is the lifecycle's answers `CancelIn`/`CancelOut`.
    fn cancel_frame() -> Box<dyn CancelFrame> {
        Box::new(cancel_frame(Ticket::NONE))
    }
}

/// A `cancel` frame, kind-erased: the kind's own `in`/`out` ([`Kind::cancel_frame`]), the
/// lifecycle's embedded first, so every kind's head is filled the same way.
pub trait CancelFrame: Send {
    /// Stamp the frame for one `cancel` of `ticket` at deadline class `class` and answer its
    /// heads, `in` first, then `out` and the `out`'s size.
    fn prepare(&mut self, ticket: Ticket, class: u8) -> (*mut InHead, *mut OutHead, u32);

    /// The disposition its answer carried.
    fn disposition(&self) -> u32;

    /// The record writes its READY answer carried (a plane's, SEAM-L(r)); none for a kind whose
    /// `cancel` writes none.
    fn writes(&self) -> Vec<busbar_contract::plane_calls::CancelWrite> {
        Vec::new()
    }
}

impl CancelFrame for Frame<CancelIn, CancelOut> {
    fn prepare(&mut self, ticket: Ticket, class: u8) -> (*mut InHead, *mut OutHead, u32) {
        self.input = CancelIn {
            head: in_head(),
            ticket,
        };
        self.out = CancelOut {
            head: out_head(),
            disposition: 0,
            _reserved: 0,
        };
        self.input.head.size = size_of::<CancelIn>() as u32;
        self.input.head.deadline_class = class;
        self.heads()
    }

    fn disposition(&self) -> u32 {
        self.out.disposition
    }
}

/// A driver ticket's `drive` frame, kind-erased: the kind's own `in`/`out` ([`Kind::drive_frame`]).
pub trait DriveFrame: Send {
    /// Stamp the frame for one `drive` crossing on `driver` (its head: size, `flags`, the
    /// Connection class, the ticket; its `driver` field) and answer its heads, `in` first, then
    /// `out` and the `out`'s size.
    fn prepare(&mut self, driver: Ticket, flags: u32) -> (*mut InHead, *mut OutHead, u32);

    /// The names its last READY answer wrote (a plane's ready sessions); none for a kind whose
    /// `drive` names nothing.
    fn named(&self) -> &[u64] {
        &[]
    }
}

impl DriveFrame for Frame<DriveIn, OutHead> {
    fn prepare(&mut self, driver: Ticket, flags: u32) -> (*mut InHead, *mut OutHead, u32) {
        stamp_drive(&mut self.input, driver, flags, size_of::<DriveIn>());
        self.heads()
    }
}

/// Stamp a `drive` `in` whose `DriveIn` is `drive`, the whole `in` being `size` bytes.
pub fn stamp_drive(drive: &mut DriveIn, driver: Ticket, flags: u32, size: usize) {
    drive.head.size = size as u32;
    drive.head.flags = flags;
    drive.head.deadline_class =
        busbar_contract::abi::mechanism::call::DeadlineClass::Connection as u8;
    drive.head.ticket = driver;
    drive.driver = driver;
}

/// A lifecycle slot's name; `"op"` for a kind slot a kind did not name.
pub fn lifecycle_name(slot: u32) -> &'static str {
    use busbar_contract::abi::mechanism::lifecycle::slot as s;
    match slot {
        s::VALIDATE => "validate",
        s::OPEN => "open",
        s::REFRESH => "refresh",
        s::RETIRE => "retire",
        s::TICK => "tick",
        s::DRIVE => "drive",
        s::CANCEL => "cancel",
        s::RELEASE => "release",
        s::CLOSE => "close",
        s::READY => "ready",
        _ => "op",
    }
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
unsafe impl InFrame for ReadyIn {}
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

/// A `cancel` frame for `ticket`. `cancel` may not pend: its head carries NONE; the cancelled
/// ticket is its field.
pub(crate) fn cancel_frame(ticket: Ticket) -> Frame<CancelIn, CancelOut> {
    Frame::new(
        CancelIn {
            head: in_head(),
            ticket,
        },
        CancelOut {
            head: out_head(),
            disposition: 0,
            _reserved: 0,
        },
    )
}

/// The host's coarse monotonic clock, in nanoseconds since first use: the clock `deadline_ns`,
/// `wake_at_ns` and `TickIn::now_ns` are on.
pub fn now_ns() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_nanos() as u64
}
