// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::cell::RefCell;
use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Diag, Envelope, InHead, MetricEntry, OutHead, Outcome, RawOutcome, BLOB_ABSENT,
    FLAG_RESUME, METRIC_ADD, METRIC_SET,
};
use busbar_contract::abi::mechanism::door::{
    Door, MetricFamily, Statement, FAMILY_COUNTER, FAMILY_GAUGE,
};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, OpenIn, OpenOut, OpsHead, TickIn, TickOut, ValidateIn, LIFECYCLE_SLOTS,
};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket, WakeFn};
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, MECHANISM_VERSION};

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod unload_witness {
    use std::sync::Mutex;

    static OBSERVER: Mutex<Option<(extern "C" fn(usize), usize)>> = Mutex::new(None);

    /// Transfer one host-owned context to this image's finalizer. The host callback remains live
    /// until process exit, and its context must remain valid even if this image stays resident.
    #[unsafe(no_mangle)]
    pub extern "C" fn busbar_test_arm_unload(
        callback: extern "C" fn(usize),
        context: usize,
    ) -> bool {
        let mut observer = OBSERVER.lock().unwrap_or_else(|e| e.into_inner());
        if observer.is_some() {
            return false;
        }
        *observer = Some((callback, context));
        true
    }

    extern "C" fn finalized() {
        let observer = OBSERVER.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some((callback, context)) = observer {
            callback(context);
        }
    }

    // SAFETY: this ELF termination section contains C function pointers, not function bodies.
    // The observer is optional, so the linked fixture's process-exit finalizer does nothing.
    #[used]
    #[unsafe(link_section = ".fini_array")]
    static FINALIZER: extern "C" fn() = finalized;
}

pub const KIND: KindCode = KindCode::Export;

pub const ANSWER: &[u8] = b"answer:";

pub const MISMATCH: &[u8] = b"mismatch";

pub const UNKNOWN: &[u8] = b"unknown";

pub const PEND_AFTER: &[u8] = b"pend:after";

pub const PEND_BEFORE: &[u8] = b"pend:before";

pub const PEND_SPURIOUS: &[u8] = b"pend:spurious";

pub const PEND_STALE: &[u8] = b"pend:stale";

pub const PEND_TIMER: &[u8] = b"pend:timer";

pub const PEND_HOLD: &[u8] = b"pend:hold";

pub const HANG: &[u8] = b"hang:";

pub const UNHANG: &[u8] = b"unhang:";

pub const PEND_HOLD_DISPOSED: &[u8] = b"pend:hold:";

pub const DRIVE_HANGS: &[u8] = b"drivehangs";

pub const DRIVE_ENTERED: &[u8] = b"driveentered";

pub const CLOSE_FAULTS: &[u8] = b"closefaults";

pub const SILENT: &[u8] = b"silent";

pub const HUGE_TEXT: &[u8] = b"hugetext";

pub const COUNT: &[u8] = b"count";

pub const ARM: &[u8] = b"arm:";

pub const KICK: &[u8] = b"kick";

pub const OVERSIZE: &[u8] = b"oversize";

pub const BAD_TEXT: &[u8] = b"badtext";

pub const BAD_ENVELOPE: &[u8] = b"badenv";

pub const REJECTED: &[u8] = b"rejected";

pub const REJECTED_REFUSED: &[u8] = b"rejectedrefused";

pub const SHORT_ANSWER: &[u8] = b"short";

pub const KIND_REJECTS: u64 = 0xDEAD;

pub const SHORT: u64 = 0x5807;

pub const FLAG_OPEN: &[u8] = b"flag:open";

pub const FLAG_OP: &[u8] = b"flag:op";

pub const PANIC: &[u8] = b"panic";

pub const FORGE: &[u8] = b"forge";

pub const FORGE_TICKET: &[u8] = b"forgeticket";

pub const GAUGE_INVOCATIONS: u32 = 2;

pub const GAUGE_EARLY: u32 = 3;

pub const GAUGE_CANCELS: u32 = 4;

pub const GAUGE_DRIVES: u32 = 5;

struct Shared<T>(T);
// SAFETY: every `Shared` static below is immutable `'static` data (pointers into other statics).
unsafe impl<T> Sync for Shared<T> {}

const fn s(b: &'static [u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}
const NO_STR: AbiStr = AbiStr::ZERO;
const NO_BLOB: Blob = Blob {
    fmt: BLOB_ABSENT,
    ..Blob::ZERO
};

const fn family(name: &'static [u8], kind: u8, labels: usize) -> MetricFamily {
    MetricFamily {
        name: s(name),
        help: NO_STR,
        unit: NO_STR,
        label_keys: if labels == 0 {
            std::ptr::null()
        } else {
            &LABEL_KEYS.0 as *const AbiStr
        },
        label_keys_len: labels,
        kind,
        ..MetricFamily::ZERO
    }
}

static LABEL_KEYS: Shared<[AbiStr; 1]> = Shared([s(b"op")]);
static FAMILIES: Shared<[MetricFamily; 6]> = Shared([
    family(b"m1_calls", FAMILY_COUNTER, 1),
    family(b"m1_level", FAMILY_GAUGE, 0),
    family(b"m1_invocations", FAMILY_GAUGE, 0),
    family(b"m1_early", FAMILY_GAUGE, 0),
    family(b"m1_cancels", FAMILY_GAUGE, 0),
    family(b"m1_drives", FAMILY_GAUGE, 0),
]);
static DIAG_IDS: Shared<[AbiStr; 1]> = Shared([s(b"m1.note")]);

static STATEMENT: Shared<Statement> = Shared(Statement {
    size: std::mem::size_of::<Statement>() as u32,
    kind: KIND as u32,
    kind_abi: KIND.abi_version(),
    max_inflight: 2,
    name: s(b"dispatch-test-plugin"),
    version: s(b"1.6.0"),
    families: &FAMILIES.0 as *const MetricFamily,
    families_len: 6,
    diag_ids: &DIAG_IDS.0 as *const AbiStr,
    diag_ids_len: 1,
    extensions: NO_BLOB,
    settings_schema: NO_BLOB,
    target_from: NO_STR,
    trust_from: NO_STR,
    ..Statement::ZERO
});

static OPS: Shared<OpsHead> = Shared(OpsHead {
    size: std::mem::size_of::<OpsHead>() as u32,
    slots: LIFECYCLE_SLOTS,
    validate: Some(validate),
    open: Some(open),
    refresh: Some(ready_only),
    retire: Some(ready_only),
    tick: Some(tick),
    drive: Some(drive),
    cancel: Some(cancel),
    release: Some(ready_only),
    close: Some(close),
});

static DOOR: Shared<Door> = Shared(unsafe {
    Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
        magic: DOOR_MAGIC,
        mechanism_version: MECHANISM_VERSION,
        size: std::mem::size_of::<Door>() as u32,
        kind: KIND as u32,
        kind_abi: KIND.abi_version(),
        statement: &STATEMENT.0 as *const Statement,
        ops: &OPS.0 as *const OpsHead,
        ready: None,
        layout: KIND.layout_fingerprint(),
    })
});

pub extern "C" fn door() -> &'static Door {
    &DOOR.0
}

busbar_contract::export_door!(door);

static ANSWER_LABELS: Shared<[AbiStr; 1]> = Shared([s(b"answer")]);
const fn metric(family_idx: u32, kind: u8, value: f64) -> MetricEntry {
    MetricEntry {
        family_idx,
        kind,
        _reserved: [0; 3],
        value,
        label_vals: std::ptr::null(),
        label_vals_len: 0,
    }
}
static METRICS: Shared<[MetricEntry; 5]> = Shared([
    MetricEntry {
        label_vals: &ANSWER_LABELS.0 as *const AbiStr,
        label_vals_len: 1,
        ..metric(0, METRIC_ADD, 1.0)
    },
    metric(9, METRIC_ADD, 1.0),
    metric(1, METRIC_SET, f64::NAN),
    metric(1, METRIC_ADD, 2.0),
    metric(1, METRIC_SET, 7.5),
]);
static DIAGS: Shared<[Diag; 2]> = Shared([
    Diag {
        severity: 1,
        text: s(b"answered"),
        ..Diag::ZERO
    },
    Diag {
        id_idx: 5,
        severity: 1,
        text: s(b"no such id"),
        ..Diag::ZERO
    },
]);

static OPEN_FLAGS: Shared<[Diag; 4]> = Shared([
    Diag {
        severity: 1,
        text: s(b"flagged at open"),
        ..Diag::ZERO
    },
    Diag {
        id_idx: busbar_contract::abi::mechanism::call::DIAG_LOG,
        severity: 1,
        text: s(b"dispatch_test_plugin: a log line at warn"),
        ..Diag::ZERO
    },
    Diag {
        severity: 0,
        text: s(b"only a note"),
        ..Diag::ZERO
    },
    Diag {
        id_idx: 5,
        severity: 2,
        text: s(b"no such id"),
        ..Diag::ZERO
    },
]);

static OP_FLAGS: Shared<[Diag; 4]> = Shared([
    Diag {
        severity: 2,
        text: s(b"refused at an op"),
        ..Diag::ZERO
    },
    Diag {
        severity: 1,
        text: s(b"a warning at an op"),
        ..Diag::ZERO
    },
    Diag {
        id_idx: busbar_contract::abi::mechanism::call::DIAG_LOG,
        severity: 2,
        text: s(b"dispatch_test_plugin: a log line at error"),
        ..Diag::ZERO
    },
    Diag {
        id_idx: 5,
        severity: 2,
        text: s(b"no such id"),
        ..Diag::ZERO
    },
]);

static UNHUNG: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

#[derive(Clone, Copy)]
struct Waker {
    wake: WakeFn,
    ctx: HostCtx,
}
// SAFETY: `WakeFn` is callable from any thread (the mechanism's rule); `ctx` is opaque to us.
unsafe impl Send for Waker {}

impl Waker {
    fn wake(self, t: Ticket) {
        (self.wake)(self.ctx, t);
    }
}

#[derive(Default)]
struct TicketState {
    invocations: u32,
    early: u32,
    ready: Arc<AtomicBool>,
}

struct Gauges(Box<[MetricEntry]>);
// SAFETY: gauge entries carry no label pointers; the box is plain owned data.
unsafe impl Send for Gauges {}

#[derive(Default)]
struct State {
    tickets: HashMap<Ticket, TicketState>,
    /// Every ticket a `pend:*` op was handed, in the order it was first handed: what `pend:stale`
    /// wakes late. `tickets` forgets a ticket the moment its op answers READY, so it holds no
    /// recycled ticket to wake.
    handed: Vec<Ticket>,
    held: Vec<(Ticket, Arc<AtomicBool>)>,
    /// `cancel`'s answer per held ticket: `Some(d)` a disposition, `None` FAULT.
    dispositions: HashMap<Ticket, Option<u32>>,
    /// Per-ticket envelope memory: valid until the next op on the same ticket.
    replies: HashMap<Ticket, Gauges>,
}

thread_local! {
    /// Ticket-less envelope memory: valid until the op returns (the host copies it at once).
    static NONE_REPLY: RefCell<Gauges> = RefCell::new(Gauges(Box::new([])));
}

struct Inst {
    wake: WakeFn,
    state: Mutex<State>,
    invocations: AtomicU32,
    cancels: AtomicU32,
    drives: AtomicU32,

    drive_hangs: AtomicBool,

    drive_entered: AtomicBool,

    close_faults: AtomicBool,
}

/// Write the outcome into the head (the mirror) and return it.
///
/// # Safety
/// `out` is a host `out` leading with an [`OutHead`].
unsafe fn say(out: *mut c_void, o: Outcome) -> RawOutcome {
    let raw = RawOutcome::of(o);
    unsafe { (*out.cast::<OutHead>()).outcome = raw };
    raw
}

fn inst<'a>(instance: *mut c_void) -> &'a Inst {
    // SAFETY: the host hands back the pointer `open` answered, until `close`.
    unsafe { &*instance.cast::<Inst>() }
}

fn arc_of(instance: *mut c_void) -> Arc<Inst> {
    let p = instance.cast::<Inst>().cast_const();
    // SAFETY: `open` made `instance` with `Arc::into_raw`; this adds a reference for a thread.
    unsafe {
        Arc::increment_strong_count(p);
        Arc::from_raw(p)
    }
}

/// Hand `values` back as gauges `(family, value)`, in memory that lives as the mechanism says.
///
/// # Safety
/// `out` leads with an [`OutHead`].
unsafe fn gauges(me: &Inst, t: Ticket, out: *mut c_void, values: &[(u32, u32)]) {
    let entries = Gauges(
        values
            .iter()
            .map(|&(f, v)| metric(f, METRIC_SET, f64::from(v)))
            .collect(),
    );
    let (ptr, len) = (entries.0.as_ptr(), entries.0.len());
    if t.is_none() {
        NONE_REPLY.with(|r| *r.borrow_mut() = entries);
    } else {
        me.state.lock().unwrap().replies.insert(t, entries);
    }
    unsafe {
        (*out.cast::<OutHead>()).envelope = Envelope {
            metrics: ptr,
            metrics_len: len,
            ..Envelope::ZERO
        };
    }
}

extern "C" fn validate(_: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let settings = (*input.cast::<ValidateIn>()).settings;
        if !settings.ptr.is_null() {
            if let Some(key) =
                std::slice::from_raw_parts(settings.ptr, settings.len).strip_prefix(HANG)
            {
                hang_until(key);
            }
        }
        let head = &*input.cast::<InHead>();
        let ok = head.ticket.is_none();
        say(out, if ok { Outcome::Ready } else { Outcome::Refused })
    }
}

extern "C" fn open(_: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let open_in = &*input.cast::<OpenIn>();

        let st = open_in.settings;
        if !st.ptr.is_null() && std::slice::from_raw_parts(st.ptr, st.len) == b"hang:open" {
            hang_until(b"open");
        }
        let Some(wake) = open_in.host.as_ref().and_then(|h| h.wake) else {
            return say(out, Outcome::Refused);
        };
        if ((*out.cast::<OutHead>()).size as usize) < std::mem::size_of::<OpenOut>() {
            return say(out, Outcome::Refused);
        }

        if !st.ptr.is_null() && std::slice::from_raw_parts(st.ptr, st.len) == b"overlong:open" {
            (*out.cast::<OpenOut>()).err_len = open_in.err_cap + 1;
            return say(out, Outcome::Failed);
        }
        let inst = Arc::new(Inst {
            wake,
            state: Mutex::new(State::default()),
            invocations: AtomicU32::new(0),
            cancels: AtomicU32::new(0),
            drives: AtomicU32::new(0),
            drive_hangs: AtomicBool::new(false),
            drive_entered: AtomicBool::new(false),
            close_faults: AtomicBool::new(false),
        });
        (*out.cast::<OpenOut>()).instance = Arc::into_raw(inst).cast_mut().cast();
        if !st.ptr.is_null() && std::slice::from_raw_parts(st.ptr, st.len) == FLAG_OPEN {
            (*out.cast::<OutHead>()).envelope = Envelope {
                diags: OPEN_FLAGS.0.as_ptr(),
                diags_len: OPEN_FLAGS.0.len(),
                ..Envelope::ZERO
            };
        }
        say(out, Outcome::Ready)
    }
}

extern "C" fn ready_only(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe { say(out, Outcome::Ready) }
}

extern "C" fn drive(instance: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let me = inst(instance);
        if me.drive_hangs.load(Ordering::SeqCst) {
            me.drive_entered.store(true, Ordering::SeqCst);
            hang_until(b"drive");
        }
        me.drives.fetch_add(1, Ordering::SeqCst);
        say(out, Outcome::Ready)
    }
}

fn hang_until(key: &[u8]) {
    while !UNHUNG.lock().unwrap().iter().any(|k| k == key) {
        std::thread::sleep(Duration::from_millis(5));
    }
}

extern "C" fn cancel(instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let me = inst(instance);
        let t = (*input.cast::<CancelIn>()).ticket;
        me.cancels.fetch_add(1, Ordering::SeqCst);
        let mut st = me.state.lock().unwrap();
        st.tickets.remove(&t);
        st.held.retain(|(h, _)| *h != t);
        match st.dispositions.remove(&t) {
            Some(None) => RawOutcome::of(Outcome::Fault),
            Some(Some(d)) => {
                (*out.cast::<CancelOut>()).disposition = d;
                say(out, Outcome::Ready)
            }
            None => say(out, Outcome::Ready),
        }
    }
}

extern "C" fn close(instance: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let mut answer = Outcome::Ready;
        if !instance.is_null() {
            if inst(instance).close_faults.load(Ordering::SeqCst) {
                answer = Outcome::Fault;
            }
            drop(Arc::from_raw(instance.cast::<Inst>().cast_const()));
        }
        say(out, answer)
    }
}

fn later(w: Waker, t: Ticket, ready: Arc<AtomicBool>, ms: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(ms));
        ready.store(true, Ordering::SeqCst);
        w.wake(t);
    });
}

fn driver_of(rest: &[u8]) -> Option<Ticket> {
    let text = std::str::from_utf8(rest).ok()?;
    let (slot, generation) = text.split_once(':')?;
    Some(Ticket {
        slot: slot.parse().ok()?,
        generation: generation.parse().ok()?,
    })
}

extern "C" fn tick(instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    // SAFETY: the host's `TickIn`/`TickOut`, leading with their heads; the blob is host-owned.
    unsafe {
        let tin = &*input.cast::<TickIn>();
        let ext = tin.head.extensions;
        let mode: &[u8] = if ext.ptr.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(ext.ptr, ext.len)
        };
        if (*out.cast::<OutHead>()).size as usize >= std::mem::size_of::<TickOut>() {
            (*out.cast::<TickOut>()).next_tick_ns = 0;
        }
        let me = inst(instance);
        if let Some(arg) = mode.strip_prefix(ANSWER) {
            return answer(me, arg, out);
        }
        if mode == FLAG_OP {
            (*out.cast::<OutHead>()).envelope = Envelope {
                diags: OP_FLAGS.0.as_ptr(),
                diags_len: OP_FLAGS.0.len(),
                ..Envelope::ZERO
            };
            return say(out, Outcome::Ready);
        }
        if let Some(rest) = mode.strip_prefix(ARM) {
            let Some(driver) = driver_of(rest) else {
                return say(out, Outcome::Refused);
            };
            arm(arc_of(instance), tin.head.host, driver);
            return say(out, Outcome::Ready);
        }
        if let Some(key) = mode.strip_prefix(HANG) {
            hang_until(key);
            return say(out, Outcome::Ready);
        }
        if mode == FORGE_TICKET {
            let t = tin.head.ticket;
            (me.wake)(
                tin.head.host,
                Ticket {
                    slot: t.slot,
                    generation: t.generation ^ 0x5a5a_5a5a,
                },
            );
            return say(out, Outcome::Ready);
        }
        if mode == FORGE {
            let forged = HostCtx {
                handle: tin.head.host.handle ^ (1 << 24),
            };
            (me.wake)(forged, tin.head.ticket);
            return say(out, Outcome::Ready);
        }
        if mode == DRIVE_HANGS {
            me.drive_hangs.store(true, Ordering::SeqCst);
            return say(out, Outcome::Ready);
        }
        if mode == CLOSE_FAULTS {
            me.close_faults.store(true, Ordering::SeqCst);
            return say(out, Outcome::Ready);
        }
        if mode == DRIVE_ENTERED {
            let on = me.drive_entered.load(Ordering::SeqCst);
            return say(out, if on { Outcome::Ready } else { Outcome::Refused });
        }
        if let Some(key) = mode.strip_prefix(UNHANG) {
            UNHUNG.lock().unwrap().push(key.to_vec());
            return say(out, Outcome::Ready);
        }
        if mode.starts_with(b"pend:") {
            return pend(me, tin, mode, out);
        }
        match mode {
            MISMATCH => {
                me.invocations.fetch_add(1, Ordering::SeqCst);
                (*out.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Failed);
                RawOutcome::of(Outcome::Ready)
            }
            UNKNOWN => {
                me.invocations.fetch_add(1, Ordering::SeqCst);
                (*out.cast::<OutHead>()).outcome = RawOutcome(9);
                RawOutcome(9)
            }
            SILENT => RawOutcome::of(Outcome::Ready),
            HUGE_TEXT => {
                (*out.cast::<OutHead>()).error = AbiStr {
                    ptr: HUGE_TEXT.as_ptr(),
                    len: isize::MAX as usize + 1,
                };
                say(out, Outcome::Failed)
            }
            COUNT => {
                let values = [
                    (GAUGE_INVOCATIONS, me.invocations.load(Ordering::SeqCst)),
                    (GAUGE_CANCELS, me.cancels.load(Ordering::SeqCst)),
                    (GAUGE_DRIVES, me.drives.load(Ordering::SeqCst)),
                ];
                gauges(me, tin.head.ticket, out, &values);
                say(out, Outcome::Ready)
            }
            KICK => {
                let held = std::mem::take(&mut me.state.lock().unwrap().held);
                for (t, ready) in held {
                    ready.store(true, Ordering::SeqCst);
                    (me.wake)(tin.head.host, t);
                }
                say(out, Outcome::Ready)
            }
            OVERSIZE => {
                (*out.cast::<OutHead>()).size = u32::MAX;
                say(out, Outcome::Ready)
            }
            BAD_TEXT => {
                (*out.cast::<OutHead>()).error = AbiStr {
                    len: 5,
                    ..AbiStr::ZERO
                };
                say(out, Outcome::Failed)
            }
            BAD_ENVELOPE => {
                (*out.cast::<OutHead>()).envelope = Envelope {
                    metrics_len: 3,
                    ..Envelope::ZERO
                };
                say(out, Outcome::Ready)
            }
            REJECTED => {
                (*out.cast::<TickOut>()).next_tick_ns = KIND_REJECTS;
                say(out, Outcome::Ready)
            }
            REJECTED_REFUSED => {
                (*out.cast::<TickOut>()).next_tick_ns = KIND_REJECTS;
                say(out, Outcome::Refused)
            }
            SHORT_ANSWER => {
                (*out.cast::<TickOut>()).next_tick_ns = SHORT;
                say(out, Outcome::Failed)
            }
            PANIC => panic!("a hand-written slot panicked"),
            _ => say(out, Outcome::Refused),
        }
    }
}

/// `answer:<byte>`: the byte, mirrored, with the test envelope and, on FAILED/REFUSED, a text.
///
/// # Safety
/// `out` leads with an [`OutHead`].
unsafe fn answer(me: &Inst, arg: &[u8], out: *mut c_void) -> RawOutcome {
    me.invocations.fetch_add(1, Ordering::SeqCst);
    let byte = std::str::from_utf8(arg)
        .ok()
        .and_then(|a| a.parse::<u8>().ok())
        .unwrap_or(0);
    let head = unsafe { &mut *out.cast::<OutHead>() };
    head.envelope = Envelope {
        metrics: &METRICS.0 as *const MetricEntry,
        metrics_len: METRICS.0.len(),
        diags: &DIAGS.0 as *const Diag,
        diags_len: DIAGS.0.len(),
    };
    let o = RawOutcome(byte);
    match o.outcome() {
        Outcome::Failed => head.error = s(b"answer failed"),
        Outcome::Refused => head.error = s(b"answer refused"),
        _ => {}
    }
    head.outcome = o;
    o
}

fn arm(me: Arc<Inst>, ctx: HostCtx, driver: Ticket) {
    let w = Waker { wake: me.wake, ctx };
    std::thread::spawn(move || {
        let base = me.drives.load(Ordering::SeqCst);
        for i in 0..3 {
            w.wake(driver);
            for _ in 0..2000 {
                if me.drives.load(Ordering::SeqCst) > base + i {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    });
}

/// `pend:<how>`: PENDING on the first call; READY once woken and ready.
///
/// # Safety
/// `out` leads with an [`OutHead`].
unsafe fn pend(me: &Inst, tin: &TickIn, mode: &[u8], out: *mut c_void) -> RawOutcome {
    let t = tin.head.ticket;
    let w = Waker {
        wake: me.wake,
        ctx: tin.head.host,
    };
    me.invocations.fetch_add(1, Ordering::SeqCst);
    let resume = tin.head.flags & FLAG_RESUME != 0;
    let mut st = me.state.lock().unwrap();
    if !resume && t.generation != 0 && !st.handed.contains(&t) {
        st.handed.push(t);
    }
    let ts = st.tickets.entry(t).or_default();
    ts.invocations += 1;
    let ready = ts.ready.clone();
    if !resume {
        match mode {
            PEND_AFTER => later(w, t, ready, 20),
            PEND_BEFORE => {
                ready.store(true, Ordering::SeqCst);
                w.wake(t);
            }
            PEND_SPURIOUS => {
                w.wake(t);
                later(w, t, ready, 60);
            }
            PEND_STALE => {
                let stale: Vec<Ticket> = st
                    .handed
                    .iter()
                    .rev()
                    .filter(|k| **k != t)
                    .take(2)
                    .copied()
                    .collect();
                for old in stale {
                    w.wake(old);
                }
                later(w, t, ready, 60);
            }
            PEND_TIMER => {
                ready.store(true, Ordering::SeqCst);
                unsafe { (*out.cast::<OutHead>()).wake_at_ns = tin.now_ns + 30_000_000 };
            }
            _ => {
                if let Some(d) = mode.strip_prefix(PEND_HOLD_DISPOSED) {
                    let d = std::str::from_utf8(d).ok().and_then(|d| d.parse().ok());
                    st.dispositions.insert(t, d);
                }
                st.held.push((t, ready));
            }
        }
        return unsafe { say(out, Outcome::Pending) };
    }
    let ts = st.tickets.get_mut(&t).expect("a resumed ticket has state");
    if !ts.ready.load(Ordering::SeqCst) {
        ts.early += 1;
        return unsafe { say(out, Outcome::Pending) };
    }
    let values = [(GAUGE_INVOCATIONS, ts.invocations), (GAUGE_EARLY, ts.early)];
    st.tickets.remove(&t);
    drop(st);
    unsafe {
        gauges(me, t, out, &values);
        say(out, Outcome::Ready)
    }
}
