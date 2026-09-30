// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DISPATCHER'S TEST PLUGIN — one source, compiled into the test build (the LINKED door) and
//! built as the `dispatch_test_plugin` example `cdylib` (the DROPPED door).
//!
//! It exports the one door ([`busbar_plugin_door`]) over the lifecycle table only, and defines NO
//! ABI shape of its own: the door, the Statement, the table and every `in`/`out` are
//! `busbar_contract::abi`'s. Its `tick` is the test's side door: the `in`'s extensions blob names
//! what to do ([`answer`], [`PEND_AFTER`] …), so one slot answers every outcome, pends and wakes in
//! every way the mechanism names (after PENDING, before it, spuriously, for stale generations, by
//! `wake_at_ns`), holds ops for a deadline, a client drop or `max_inflight`, arms a driver ticket,
//! hangs until released (the watchdog's prey) and panics. Every slot is HAND-WRITTEN with no panic
//! guard, so that panic escapes `extern "C"` and aborts the process.
//!
//! Numbers go back the way a plugin reports anything: as #85 envelope gauges (families 2..=5).

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
    CancelIn, CancelOut, OpenIn, OpenOut, OpsHead, TickIn, TickOut, LIFECYCLE_SLOTS,
};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket, WakeFn};
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, MECHANISM_VERSION};

/// The kind this test plugin states; its table is that kind's lifecycle skeleton.
pub const KIND: KindCode = KindCode::Export;

/// `tick` mode: answer the outcome byte that follows (`answer:3`), mirrored, with the test envelope.
pub const ANSWER: &[u8] = b"answer:";
/// `tick` mode: return READY, mirror FAILED.
pub const MISMATCH: &[u8] = b"mismatch";
/// `tick` mode: return and mirror the unknown byte 9.
pub const UNKNOWN: &[u8] = b"unknown";
/// `tick` mode: PENDING, then a wake from another thread once ready.
pub const PEND_AFTER: &[u8] = b"pend:after";
/// `tick` mode: ready and woken BEFORE answering PENDING (the latch).
pub const PEND_BEFORE: &[u8] = b"pend:before";
/// `tick` mode: a spurious wake at once, the real one later.
pub const PEND_SPURIOUS: &[u8] = b"pend:spurious";
/// `tick` mode: wakes for stale generations of the ticket, the real one later.
pub const PEND_STALE: &[u8] = b"pend:stale";
/// `tick` mode: no wake; `wake_at_ns = now_ns + 30ms`.
pub const PEND_TIMER: &[u8] = b"pend:timer";
/// `tick` mode: held until [`KICK`].
pub const PEND_HOLD: &[u8] = b"pend:hold";
/// `tick` mode: `hang:<key>` does not return until `unhang:<key>`.
pub const HANG: &[u8] = b"hang:";
/// `tick` mode: `unhang:<key>` releases every op hung on `<key>`.
pub const UNHANG: &[u8] = b"unhang:";
/// `tick` mode: `pend:hold:<d>` is held like [`PEND_HOLD`]; its `cancel` answers disposition `<d>`
/// (`f` = `cancel` answers FAULT).
pub const PEND_HOLD_DISPOSED: &[u8] = b"pend:hold:";
/// `tick` mode: the next `drive` hangs until `unhang:drive`.
pub const DRIVE_HANGS: &[u8] = b"drivehangs";
/// `tick` mode: READY once a hanging `drive` is inside its crossing, else REFUSED.
pub const DRIVE_ENTERED: &[u8] = b"driveentered";
/// `tick` mode: return READY WITHOUT writing the mirror (a host that did not zero `out` would read
/// its own garbage as the answer).
pub const SILENT: &[u8] = b"silent";
/// `tick` mode: FAILED with error text of `isize::MAX + 1` bytes behind a real pointer.
pub const HUGE_TEXT: &[u8] = b"hugetext";
/// `tick` mode: report the counters as gauges.
pub const COUNT: &[u8] = b"count";
/// `tick` mode: wake the driver ticket that follows (`arm:<slot>:<generation>`) three times.
pub const ARM: &[u8] = b"arm:";
/// `tick` mode: finish and wake every held op.
pub const KICK: &[u8] = b"kick";
/// `tick` mode: READY, with `OutHead.size` larger than the host's `out`.
pub const OVERSIZE: &[u8] = b"oversize";
/// `tick` mode: FAILED, with error text NULL but a length.
pub const BAD_TEXT: &[u8] = b"badtext";
/// `tick` mode: READY, with a metrics array NULL but a length.
pub const BAD_ENVELOPE: &[u8] = b"badenv";
/// `tick` mode: READY with `next_tick_ns` = [`KIND_REJECTS`] (the test kind's validator refuses it).
pub const REJECTED: &[u8] = b"rejected";
/// `tick` mode: REFUSED with `next_tick_ns` = [`KIND_REJECTS`] (the test kind's validator
/// judges a REFUSED answer too).
pub const REJECTED_REFUSED: &[u8] = b"rejectedrefused";
/// `tick` mode: FAILED with `next_tick_ns` = [`SHORT`] (the test kind reads it as a short buffer).
pub const SHORT_ANSWER: &[u8] = b"short";
/// The `next_tick_ns` the test kind's `check` refuses.
pub const KIND_REJECTS: u64 = 0xDEAD;
/// The `next_tick_ns` the test kind's `short` reads as "needs a bigger buffer".
pub const SHORT: u64 = 0x5807;
/// `tick` mode: panic. `tick` has no guard, so the process aborts.
pub const PANIC: &[u8] = b"panic";

/// Family index of the `invocations` gauge.
pub const GAUGE_INVOCATIONS: u32 = 2;
/// Family index of the `early` gauge (resumes that found the op not ready).
pub const GAUGE_EARLY: u32 = 3;
/// Family index of the `cancels` gauge.
pub const GAUGE_CANCELS: u32 = 4;
/// Family index of the `drives` gauge.
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
const NO_STR: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};
const NO_BLOB: Blob = Blob {
    ptr: std::ptr::null(),
    len: 0,
    fmt: BLOB_ABSENT,
    flags: 0,
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
        _reserved: [0; 7],
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
    kind_tail: std::ptr::null(),
    extensions: NO_BLOB,
    secret_refs: std::ptr::null(),
    secret_refs_len: 0,
    settings_schema: NO_BLOB,
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

static DOOR: Shared<Door> = Shared(Door {
    magic: DOOR_MAGIC,
    mechanism_version: MECHANISM_VERSION,
    size: std::mem::size_of::<Door>() as u32,
    kind: KIND as u32,
    kind_abi: KIND.abi_version(),
    statement: &STATEMENT.0 as *const Statement,
    ops: &OPS.0 as *const OpsHead,
});

/// THE DOOR: the `DoorFn` a compiled-in row holds.
pub extern "C" fn door() -> *const Door {
    &DOOR.0
}

// The one exported symbol, forwarding to the same door (the SDK's one export).
busbar_contract::export_door!(door);

// The #85 envelope `answer` hands back: two good metrics, three the host must drop (an index out of
// range, a non-finite value, a kind the family does not have), one good diagnostic and one bad.
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
        id_idx: 0,
        severity: 1,
        _reserved: [0; 3],
        text: s(b"answered"),
    },
    Diag {
        id_idx: 5,
        severity: 1,
        _reserved: [0; 3],
        text: s(b"no such id"),
    },
]);

/// The keys [`UNHANG`] released; per image, so the linked and the dropped build each have one.
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

/// The gauges one reply carries; boxed so their address holds until the next op on the ticket.
struct Gauges(Box<[MetricEntry]>);
// SAFETY: gauge entries carry no label pointers; the box is plain owned data.
unsafe impl Send for Gauges {}

#[derive(Default)]
struct State {
    tickets: HashMap<Ticket, TicketState>,
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
    /// [`DRIVE_HANGS`]: the next `drive` hangs until `unhang:drive`.
    drive_hangs: AtomicBool,
    /// A hanging `drive` is inside its crossing.
    drive_entered: AtomicBool,
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
            diags: std::ptr::null(),
            diags_len: 0,
        };
    }
}

extern "C" fn validate(_: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let head = &*input.cast::<InHead>();
        let ok = head.ticket.is_none();
        say(out, if ok { Outcome::Ready } else { Outcome::Refused })
    }
}

extern "C" fn open(_: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let open_in = &*input.cast::<OpenIn>();
        // Settings `hang:open`: `open` does not return until `unhang:open`.
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
        // Settings `overlong:open`: FAILED, stating a reason longer than the buffer the host lent.
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
        });
        (*out.cast::<OpenOut>()).instance = Arc::into_raw(inst).cast_mut().cast();
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

/// Block until `unhang:<key>` released `key`.
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
        if !instance.is_null() {
            drop(Arc::from_raw(instance.cast::<Inst>().cast_const()));
        }
        say(out, Outcome::Ready)
    }
}

fn later(w: Waker, t: Ticket, ready: Arc<AtomicBool>, ms: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(ms));
        ready.store(true, Ordering::SeqCst);
        w.wake(t);
    });
}

/// `arm:<slot>:<generation>` → the driver ticket.
fn driver_of(rest: &[u8]) -> Option<Ticket> {
    let text = std::str::from_utf8(rest).ok()?;
    let (slot, generation) = text.split_once(':')?;
    Some(Ticket {
        slot: slot.parse().ok()?,
        generation: generation.parse().ok()?,
    })
}

/// THE TEST OPS, multiplexed on `tick` by the `in`'s extensions blob. A panic here escapes
/// `extern "C"` and aborts the process.
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
        if mode == DRIVE_HANGS {
            me.drive_hangs.store(true, Ordering::SeqCst);
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
                    ptr: std::ptr::null(),
                    len: 5,
                };
                say(out, Outcome::Failed)
            }
            BAD_ENVELOPE => {
                (*out.cast::<OutHead>()).envelope = Envelope {
                    metrics: std::ptr::null(),
                    metrics_len: 3,
                    diags: std::ptr::null(),
                    diags_len: 0,
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

/// Wake `driver` three times, each once the previous drive ran.
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
                for g in [t.generation.wrapping_sub(1), t.generation.wrapping_add(1)] {
                    w.wake(Ticket {
                        slot: t.slot,
                        generation: g,
                    });
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
