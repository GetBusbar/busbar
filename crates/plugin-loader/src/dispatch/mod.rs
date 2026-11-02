// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

/// THE HOST'S SERVICE ENTRY POINTS, ONE SPELLING OF THE ABI: every `fn` inside is a host service
/// (`abi::host::service::ServiceFn`, the slot type of `abi::host::io::IoSlots`). The expansion
/// spells that signature whole, so it reads as an implementation of the ABI's type, never a new
/// shape. Defined before the modules so each of them can use it.
macro_rules! c_entry {
    () => {};
    (
        $(#[$m:meta])* $vis:vis fn $name:ident(
            $ctx:ident: HostCtx, $input:ident: *const c_void, $out:ident: *mut ServiceOut $(,)?
        ) -> RawOutcome { $($body:tt)* }
        $($more:tt)*
    ) => {
        $(#[$m])* $vis extern "C" fn $name($ctx: HostCtx, $input: *const c_void, $out: *mut ServiceOut) -> RawOutcome { $($body)* }
        c_entry! { $($more)* }
    };
}

pub mod answer;
pub mod auth_handle;
pub mod auth_outbound;
pub mod auth_ticks;
pub(crate) mod call;
pub(crate) mod completion_retirement;
pub(crate) mod conditional;
pub mod conn_services;
pub(crate) mod export_bindings;
pub mod framing_context;
pub mod handle;
pub(crate) mod held;
pub mod inline;
pub(crate) mod inspection;
pub mod io_slots;
pub mod kinds;
pub(crate) mod lifecycle;
pub mod load;
pub mod log_file;
pub mod migrate;
pub mod plane_calls;
pub mod plugin;
pub mod ready;
pub mod services;
pub mod snapshot;
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
    admit_linked, load_dropped, load_dropped_bytes, load_linked, rendering_of,
    rendering_of_library, rendering_of_loaded, rendering_of_macro, LinkedRow, LoadError,
    LoadedDoor, ManifestFacts,
};
pub use log_file::{LogLevel, PluginLogConfig, PluginLogSink};
pub use plugin::{
    Bind, Called, ConnTable, Diagnostic, Dropped, EnvelopeSink, Metric, NoSink, Plugin, Recall,
    MAX_LOG_BYTES, MAX_LOG_RECORDS,
};
pub use services::{HostServices, Later, Ran, Reading, Stored};
pub use validate::Violation;
pub use worker::{
    Adopter, Budgets, CounterFamily, DispatchConfig, DispatchStats, Dispatcher, Done, Lent, Reply,
    DEADLINE_WITHOUT_WAKE_TOTAL, DEFAULT_QUARANTINE_AFTER, QUARANTINED_TOTAL,
};

pub trait Kind: Send + Sync + 'static {
    const CODE: KindCode;

    type Ops: Copy;

    const TIMEOUT: Outcome;

    fn op_name(slot: u32) -> &'static str {
        lifecycle_name(slot)
    }

    fn ticketed_class(slot: u32) -> busbar_contract::abi::mechanism::call::DeadlineClass {
        let _ = slot;
        busbar_contract::abi::mechanism::call::DeadlineClass::Connection
    }

    fn optional_slot(slot: u32) -> bool {
        let _ = slot;
        false
    }

    fn optional_by_statement(slot: u32, statement: &Statement) -> bool {
        let _ = (slot, statement);
        false
    }

    fn context(statement: &Statement) -> Result<Option<Box<Context>>, String> {
        let _ = statement;
        Ok(None)
    }

    fn credential_kinds(context: Option<&Context>) -> Vec<String> {
        let _ = context;
        Vec::new()
    }

    fn admit(
        slot: u32,
        input: *const busbar_contract::abi::mechanism::call::InHead,
        in_size: usize,
        owner: u64,
    ) -> Option<Outcome> {
        let _ = (slot, input, in_size, owner);
        None
    }

    fn check(answer: &Answer) -> Result<(), Fault> {
        let _ = answer;
        Ok(())
    }

    fn unit_of(
        slot: u32,
        input: *const busbar_contract::abi::mechanism::call::InHead,
        in_size: usize,
    ) -> Option<u64> {
        let _ = (slot, input, in_size);
        None
    }

    fn short(answer: &Answer) -> bool {
        let _ = answer;
        false
    }

    fn drive_frame() -> Box<dyn DriveFrame> {
        Box::new(Frame::new(
            DriveIn {
                head: in_head(),
                driver: Ticket::NONE,
            },
            out_head(),
        ))
    }

    fn cancel_frame() -> Box<dyn CancelFrame> {
        Box::new(cancel_frame(Ticket::NONE))
    }
}

pub trait CancelFrame: Send {
    fn prepare(&mut self, ticket: Ticket, class: u8) -> (*mut InHead, *mut OutHead, u32);

    fn disposition(&self) -> u32;

    fn name_unit(&mut self, unit: u64) {
        let _ = unit;
    }

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

pub trait DriveFrame: Send {
    fn prepare(&mut self, driver: Ticket, flags: u32) -> (*mut InHead, *mut OutHead, u32);

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

pub fn stamp_drive(drive: &mut DriveIn, driver: Ticket, flags: u32, size: usize) {
    drive.head.size = size as u32;
    drive.head.flags = flags;
    drive.head.deadline_class =
        busbar_contract::abi::mechanism::call::DeadlineClass::Connection as u8;
    drive.head.ticket = driver;
    drive.driver = driver;
}

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

const FIRST_SLOT: usize = offset_of!(OpsHead, validate);

pub(crate) fn host_slots<K: Kind>() -> u32 {
    ((size_of::<K::Ops>() - FIRST_SLOT) / size_of::<Option<Op>>()) as u32
}

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

pub const NO_BLOB: Blob = Blob {
    ptr: std::ptr::null(),
    len: 0,
    fmt: BLOB_ABSENT,
    flags: 0,
};

pub fn in_head() -> InHead {
    InHead {
        size: size_of::<InHead>() as u32,
        op: 0,
        flags: 0,
        deadline_class: 0,
        _reserved: [0; 3],
        host: HostCtx::NONE,
        ticket: Ticket::NONE,
        deadline_ns: 0,
        trace_id: [0; 16],
        parent_span_id: 0,
        extensions: NO_BLOB,
    }
}

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

pub fn now_ns() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_nanos() as u64
}
