// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR CROSSING COSTS UNDER 1µs OVER A DIRECT CALL, AT p50 AND p99 (`BUSBAR-1.6.0.md` §8,
//! "Perf gate (<1µs): ... delta<1µs p50 AND p99").
//!
//! WHAT IS MEASURED: the host's half of one crossing, `Plugin::call` on the one dispatcher, for
//! every op the plane kind's contract table marks `request_path` (`abi::plane::CONTRACTS`), against
//! the SAME slot body called directly with the same instance and the same frame. Both legs run the
//! plugin's body, so the delta is what the door adds: the frame checks, the `max_inflight` unit, the
//! watchdog's crossing record, the gate, the host's zeroing of `out` and the kind's answer check.
//!
//! WHY IT EXISTS BESIDE `crates/busbar-kernel/benches/plane_host_vtable_perf.rs`: that instrument
//! times the HOT lane's `PlaneHostVtable` slot, which the request path does not cross (row 84
//! deletes it with `abi/hot`). This is the door lane's perf witness, the lane the request path
//! crosses, and `hot-path-perf:door-crossing-under-1us` holds its clauses as code. It runs in the
//! workspace suite, so the budget is measured on every move, not only when a bench is run by hand.
//!
//! HOW: one call per sample, the two legs interleaved sample by sample so drift lands on both, and
//! the percentiles taken over each leg's own distribution. A sample is one call, not a batch mean,
//! so a preemption of the test thread lands in one sample of thousands rather than in a whole
//! batch's mean; the p99 is the crossing's tail, not the scheduler's. The suite builds the dev
//! profile, so the door's own code runs unoptimised here: a delta under budget in this build is
//! under budget in the release build too.
//!
//! The ops are taken from the contract table, not listed by hand: a request-path op the kind adds
//! without a measured case here is RED.

#[path = "fixtures/plane_driver_test_plane.rs"]
#[allow(dead_code)]
mod plane;

use std::ffi::c_void;
use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::abi::hook::{MessageView, SignalEntry, SignalValue};
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::mechanism::call::{AbiStr, Op, Outcome as AbiOutcome, RawOutcome};
use busbar_contract::abi::mechanism::lifecycle::OpenIn;
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, Ops, OutField, PlaneOpenIn, PlaneOpenOut,
    ProjectIn, ProjectOut, RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount, CONTRACTS,
    FROM_FAR_END,
};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_plugin_loader::dispatch::{
    kinds::plane::Plane, load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, InFrame,
    LinkedRow, NoSink, OutFrame, Plugin, NO_BLOB,
};

// ── the budget and the judge ─────────────────────────────────────────────────────────────────────

/// The budget: the door crossing must cost under one microsecond over a direct call.
const DOOR_BUDGET_NANOS: u64 = 1_000;

/// Samples per leg per op, each one call.
const SAMPLES: usize = 20_000;
/// Calls per leg before the first sample, so cold caches and first-touch state stay out of it.
const WARM_UP: usize = 1_000;

/// `(p50, p99)` of `samples`, indexed as the hot-lane instrument indexes its own.
fn percentiles(samples: &mut [u64]) -> (u64, u64) {
    samples.sort_unstable();
    let n = samples.len();
    (samples[n / 2], samples[((n * 99) / 100).min(n - 1)])
}

/// One leg's call, timed.
fn timed(f: &mut dyn FnMut()) -> u64 {
    let t = Instant::now();
    f();
    t.elapsed().as_nanos() as u64
}

/// The two legs' `(p50, p99)`: `direct` the slot body called directly, `door` the same body through
/// the dispatcher. Interleaved sample by sample.
fn measure(direct: &mut dyn FnMut(), door: &mut dyn FnMut()) -> ((u64, u64), (u64, u64)) {
    for _ in 0..WARM_UP {
        direct();
        door();
    }
    let mut d = Vec::with_capacity(SAMPLES);
    let mut x = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        d.push(timed(direct));
        x.push(timed(door));
    }
    (percentiles(&mut d), percentiles(&mut x))
}

/// What one op measured, and every way it is over budget (empty: under budget at both).
fn over_budget(op: u32, direct: (u64, u64), door: (u64, u64)) -> Vec<String> {
    let (direct_p50, direct_p99) = direct;
    let (door_p50, door_p99) = door;
    let p50_delta_nanos = door_p50.saturating_sub(direct_p50);
    let p99_delta_nanos = door_p99.saturating_sub(direct_p99);
    let mut over = Vec::new();
    if p50_delta_nanos >= DOOR_BUDGET_NANOS {
        over.push(format!(
            "DOOR PERF (p50): op {op} crossed for {p50_delta_nanos}ns over the direct call (budget \
             {DOOR_BUDGET_NANOS}ns); direct p50 {direct_p50}ns, door p50 {door_p50}ns"
        ));
    }
    if p99_delta_nanos >= DOOR_BUDGET_NANOS {
        over.push(format!(
            "DOOR PERF (p99): op {op} crossed for {p99_delta_nanos}ns over the direct call (budget \
             {DOOR_BUDGET_NANOS}ns); direct p99 {direct_p99}ns, door p99 {door_p99}ns"
        ));
    }
    over
}

// ── the door under measurement: the test plane's, loaded LINKED and opened ────────────────────────

/// The plane, loaded linked and opened, and the instance its `open` answered.
fn opened(dispatcher: &Dispatcher) -> (Plugin<Plane>, *mut c_void) {
    let bind = Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::Probe,
    };
    let row = LinkedRow::of(plane::door).expect("the plane states its Statement");
    let plugin = load_linked::<Plane>(&row, bind).expect("the linked door loads");
    let mut open = Frame::new(
        PlaneOpenIn {
            open: OpenIn {
                settings: NO_BLOB,
                generation: 1,
                ..blank_in()
            },
            owned: NO_BLOB,
            ..blank_in()
        },
        blank_out::<PlaneOpenOut>(),
    );
    let (called, _) = plugin.open(&mut open);
    assert_eq!(called.outcome, AbiOutcome::Ready, "the plane opens");
    let instance = open.out.open.instance;
    assert!(!instance.is_null(), "the plane's open answered an instance");
    (plugin, instance)
}

/// The test plane's own ops table: the slot bodies the direct leg calls.
fn ops() -> Ops {
    // SAFETY: the test plane's door is `'static`; a plane door's `ops` is a plane `Ops`.
    unsafe { *(*plane::door()).ops.cast::<Ops>() }
}

/// Host buffers a crossing lends, kept alive across the measured calls.
struct Bufs {
    reply: Vec<u8>,
    units: Vec<UnitCount>,
    fields: Vec<OutField>,
    arena: Vec<u8>,
    signals: Vec<SignalEntry>,
    messages: Vec<MessageView>,
}

impl Bufs {
    fn new() -> Self {
        let span = Span { offset: 0, len: 0 };
        Self {
            reply: vec![0; 4096],
            units: vec![
                UnitCount {
                    class: 0,
                    source: 0,
                    amount: 0
                };
                16
            ],
            fields: vec![
                OutField {
                    name: span,
                    value: span
                };
                8
            ],
            arena: vec![0; 4096],
            signals: vec![
                SignalEntry {
                    id: 0,
                    tag: 0,
                    value: SignalValue { u64_: 0 }
                };
                8
            ],
            messages: vec![
                MessageView {
                    role: AbiStr::over(b""),
                    text: AbiStr::over(b"")
                };
                8
            ],
        }
    }
}

const STATS: &[u8] = b"/stats";
const POST: &[u8] = b"POST";
const REASON_TEXT: &[u8] = b"in-flight cap";

/// One op's two legs over one frame: the slot body `op` called directly on `instance`, and the same
/// op through `plugin.call`. One crossing first, so the dispatcher has written the frame's heads the
/// direct leg then reads; every call of either leg must answer READY.
fn legs<I: InFrame, O: OutFrame>(
    plugin: &Plugin<Plane>,
    s: u32,
    op: Op,
    instance: *mut c_void,
    frame: Frame<I, O>,
) -> ((u64, u64), (u64, u64)) {
    let mut frame = frame;
    let fp: *mut Frame<I, O> = &mut frame;
    let mut door = || {
        // SAFETY: `fp` is this frame, alive for both closures, and the legs never run at once.
        let frame = unsafe { &mut *fp };
        let called = plugin.call(s, frame);
        assert_eq!(called.outcome, AbiOutcome::Ready, "op {s} answers READY");
    };
    door();
    let mut direct = || {
        // SAFETY: the plane's own slot body for `s`, on its own open instance, over the frame of
        // that op's `in`/`out` the dispatcher just crossed with.
        let raw = unsafe {
            op(
                black_box(instance),
                std::ptr::addr_of!((*fp).input).cast(),
                std::ptr::addr_of_mut!((*fp).out).cast(),
            )
        };
        assert_eq!(
            raw,
            RawOutcome::of(AbiOutcome::Ready),
            "op {s} answers READY"
        );
    };
    measure(&mut direct, &mut door)
}

/// Request-path op `s`'s two legs, its frame built as the request path builds it.
fn measured(
    plugin: &Plugin<Plane>,
    instance: *mut c_void,
    s: u32,
    b: &mut Bufs,
) -> ((u64, u64), (u64, u64)) {
    let ops = ops();
    let body = |o: Option<Op>| o.unwrap_or_else(|| panic!("the test plane answers op {s}"));
    match s {
        slot::ARRIVE => legs(
            plugin,
            s,
            body(ops.arrive),
            instance,
            Frame::new(
                ArriveIn {
                    target: AbiStr::over(STATS),
                    method: AbiStr::over(POST),
                    body: NO_BLOB,
                    units_buf: b.units.as_mut_ptr(),
                    units_cap: b.units.len(),
                    ..blank_in()
                },
                blank_out::<ArriveOut>(),
            ),
        ),
        slot::ON_PIECE => legs(
            plugin,
            s,
            body(ops.on_piece),
            instance,
            Frame::new(
                OnPieceIn {
                    from: FROM_FAR_END,
                    bytes: NO_BLOB,
                    reply_buf: b.reply.as_mut_ptr(),
                    reply_cap: b.reply.len(),
                    units_buf: b.units.as_mut_ptr(),
                    units_cap: b.units.len(),
                    ..blank_in()
                },
                blank_out::<OnPieceOut>(),
            ),
        ),
        slot::REFUSAL => legs(
            plugin,
            s,
            body(ops.refusal),
            instance,
            Frame::new(
                RefusalIn {
                    status: 503,
                    reason: 0,
                    text: AbiStr::over(REASON_TEXT),
                    target: AbiStr::over(STATS),
                    reply_buf: b.reply.as_mut_ptr(),
                    reply_cap: b.reply.len(),
                    fields_buf: b.fields.as_mut_ptr(),
                    fields_cap: b.fields.len(),
                    arena_buf: b.arena.as_mut_ptr(),
                    arena_cap: b.arena.len(),
                    ..blank_in()
                },
                blank_out::<RefusalOut>(),
            ),
        ),
        slot::SERVE => legs(
            plugin,
            s,
            body(ops.serve),
            instance,
            Frame::new(
                ServeIn {
                    route: 0,
                    target: AbiStr::over(STATS),
                    body: NO_BLOB,
                    reply_buf: b.reply.as_mut_ptr(),
                    reply_cap: b.reply.len(),
                    fields_buf: b.fields.as_mut_ptr(),
                    fields_cap: b.fields.len(),
                    arena_buf: b.arena.as_mut_ptr(),
                    arena_cap: b.arena.len(),
                    ..blank_in()
                },
                blank_out::<ServeOut>(),
            ),
        ),
        slot::PROJECT => legs(
            plugin,
            s,
            body(ops.project),
            instance,
            Frame::new(
                ProjectIn {
                    target: AbiStr::over(STATS),
                    body: NO_BLOB,
                    rewrite: NO_BLOB,
                    signals_buf: b.signals.as_mut_ptr(),
                    signals_cap: b.signals.len(),
                    messages_buf: b.messages.as_mut_ptr(),
                    messages_cap: b.messages.len(),
                    arena_buf: b.arena.as_mut_ptr(),
                    arena_cap: b.arena.len(),
                    ..blank_in()
                },
                blank_out::<ProjectOut>(),
            ),
        ),
        other => panic!(
            "request-path op {other} has no measured case: the <1µs claim is unproven for it until \
             one is added here"
        ),
    }
}

// ── the claims ───────────────────────────────────────────────────────────────────────────────────

/// THE INSTRUMENT FIRST: a crossing planted 2µs slower than its direct call is over budget at p50
/// and at p99, and two identical legs are under it at both.
#[test]
fn the_judge_catches_a_crossing_over_budget() {
    let spin = Duration::from_nanos(2 * DOOR_BUDGET_NANOS);
    let (direct, slow) = measure(
        &mut || {
            black_box(7_u64);
        },
        &mut || {
            let t = Instant::now();
            while t.elapsed() < spin {
                std::hint::spin_loop();
            }
        },
    );
    let caught = over_budget(0, direct, slow);
    let caught_p50 = caught.iter().any(|l| l.starts_with("DOOR PERF (p50)"));
    let caught_p99 = caught.iter().any(|l| l.starts_with("DOOR PERF (p99)"));
    assert!(
        caught_p50 && caught_p99,
        "a crossing 2µs over its direct call was not caught at both percentiles: {caught:?}"
    );
    assert!(
        over_budget(0, (500, 900), (500, 900)).is_empty(),
        "two identical legs read as over budget"
    );
}

/// Every request-path op of the plane kind crosses the one dispatcher for under 1µs over its slot
/// body called directly, at p50 and at p99.
#[test]
fn every_request_path_op_crosses_under_budget() {
    let dispatcher = Dispatcher::new(DispatchConfig::default());
    let (plugin, instance) = opened(&dispatcher);
    let mut bufs = Bufs::new();
    let request_path: Vec<u32> = CONTRACTS
        .iter()
        .filter(|c| c.request_path)
        .map(|c| c.slot)
        .collect();
    assert!(
        !request_path.is_empty(),
        "the plane contract names no request-path op; the witness would measure nothing"
    );
    // `on_piece` reads the head its unit's `arrive` left, so `arrive` is measured first.
    let mut table = Vec::new();
    let mut over = Vec::new();
    for &s in &request_path {
        let (direct, door) = measured(&plugin, instance, s, &mut bufs);
        table.push(format!(
            "op {s}: direct p50 {}ns p99 {}ns, door p50 {}ns p99 {}ns",
            direct.0, direct.1, door.0, door.1
        ));
        over.extend(over_budget(s, direct, door));
    }
    eprintln!("door crossing, per request-path op: {}", table.join("; "));
    assert!(
        over.is_empty(),
        "the door crossing is over its <1µs budget: {} (measured: {})",
        over.join(" | "),
        table.join("; ")
    );
}
