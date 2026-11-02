// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "fixtures/plane_driver_test_plane.rs"]
#[allow(dead_code)]
mod plane;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::{Arc, OnceLock};

use busbar_contract::abi::hook::{MessageView, SignalEntry, SignalValue};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome as AbiOutcome, RawOutcome, Span};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpsHead};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, CatalogIn, CatalogOut, OnPieceIn, OnPieceOut, Ops, OutField,
    PlaneOpenIn, PlaneOpenOut, ProjectIn, ProjectOut, RefusalIn, RefusalOut, ServeIn, ServeOut,
    UnitCount, CONTRACTS, FROM_FAR_END,
};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_plugin_loader::dispatch::{
    kinds::plane::Plane, load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, Frame,
    LinkedRow, NoSink, Plugin, NO_BLOB,
};

thread_local! {
    /// Whether this thread's allocations are being counted.
    static ARMED: Cell<bool> = const { Cell::new(false) };
    /// This thread's counted allocations.
    static COUNTED: Cell<u64> = const { Cell::new(0) };
}

struct Counting;

fn count_one() {
    let _ = ARMED.try_with(|armed| {
        if armed.get() {
            let _ = COUNTED.try_with(|c| c.set(c.get() + 1));
        }
    });
}

// SAFETY: every call is forwarded verbatim to the system allocator; the counters are thread-local
// `Cell`s of plain values, touched only on the allocating thread, and never read or write the memory
// being handed out.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_one();
        // SAFETY: forwarded as given.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_one();
        // SAFETY: forwarded as given.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded as given.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_one();
        // SAFETY: forwarded as given.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn counted(mut f: impl FnMut()) -> u64 {
    COUNTED.with(|c| c.set(0));
    ARMED.with(|a| a.set(true));
    f();
    ARMED.with(|a| a.set(false));
    COUNTED.with(Cell::get)
}

fn unmeasured<T>(f: impl FnOnce() -> T) -> T {
    let was = ARMED.with(|a| a.replace(false));
    let out = f();
    ARMED.with(|a| a.set(was));
    out
}

struct Shared<T>(T);
// SAFETY: written once (`OnceLock`) before any read, never mutated after; the pointers it holds
// are to `'static` plugin data.
unsafe impl<T> Sync for Shared<T> {}
// SAFETY: as above.
unsafe impl<T> Send for Shared<T> {}

fn inner() -> &'static Ops {
    static INNER: OnceLock<Shared<Ops>> = OnceLock::new();
    &INNER
        .get_or_init(|| {
            // SAFETY: a plane door's `ops` is a `'static` plane `Ops`.
            Shared(unsafe { *plane::door().ops().cast::<Ops>() })
        })
        .0
}

macro_rules! disarmed {
    ($name:ident, $field:ident) => {
        extern "C" fn $name(i: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
            let op = inner()
                .$field
                .expect(concat!("the test plane answers ", stringify!($field)));
            unmeasured(|| op(i, input, out))
        }
    };
}
disarmed!(arrive, arrive);
disarmed!(on_piece, on_piece);
disarmed!(refusal, refusal);
disarmed!(serve, serve);
disarmed!(project, project);

extern "C" fn catalog(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
    unmeasured(|| {
        let out = out.cast::<CatalogOut>();
        // SAFETY: the host lends `catalog` a whole, writable `CatalogOut`.
        unsafe {
            std::ptr::addr_of_mut!((*out).status).write_unaligned(200);
            std::ptr::addr_of_mut!((*out).head.outcome)
                .write_unaligned(RawOutcome::of(AbiOutcome::Ready));
        }
        RawOutcome::of(AbiOutcome::Ready)
    })
}

extern "C" fn door() -> &'static Door {
    static OPS: OnceLock<Shared<Ops>> = OnceLock::new();
    static DOOR: OnceLock<Shared<Door>> = OnceLock::new();
    let ops = &OPS
        .get_or_init(|| {
            Shared(Ops {
                arrive: Some(arrive),
                on_piece: Some(on_piece),
                refusal: Some(refusal),
                serve: Some(serve),
                project: Some(project),
                catalog: Some(catalog),
                ..*inner()
            })
        })
        .0;
    &DOOR
        .get_or_init(|| {
            let mut parts = plane::door().parts();
            parts.ops = (ops as *const Ops).cast::<OpsHead>();
            // SAFETY: the test plane's own `'static` Statement, over a `'static` plane table whose
            // request-path slots wrap the test plane's own.
            Shared(unsafe { Door::__from_parts(parts) })
        })
        .0
}

fn opened(dispatcher: &Dispatcher) -> Plugin<Plane> {
    let bind = Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::Probe,
    };
    let row = LinkedRow::of(door).expect("the plane states its Statement");
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
    plugin
}

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

fn crossing(plugin: &Plugin<Plane>, s: u32, b: &mut Bufs, measure: Measure) -> u64 {
    match s {
        slot::ARRIVE => {
            let mut frame = Frame::new(
                ArriveIn {
                    target: AbiStr::over(STATS),
                    method: AbiStr::over(POST),
                    body: NO_BLOB,
                    units_buf: b.units.as_mut_ptr(),
                    units_cap: b.units.len(),
                    ..blank_in()
                },
                blank_out::<ArriveOut>(),
            );
            measure(&mut || ready(s, plugin.call(s, &mut frame).outcome))
        }
        slot::ON_PIECE => {
            let mut frame = Frame::new(
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
            );
            measure(&mut || ready(s, plugin.call(s, &mut frame).outcome))
        }
        slot::REFUSAL => {
            let mut frame = Frame::new(
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
            );
            measure(&mut || ready(s, plugin.call(s, &mut frame).outcome))
        }
        slot::SERVE => {
            let mut frame = Frame::new(
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
            );
            measure(&mut || ready(s, plugin.call(s, &mut frame).outcome))
        }
        slot::PROJECT => {
            let mut frame = Frame::new(
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
            );
            measure(&mut || ready(s, plugin.call(s, &mut frame).outcome))
        }
        slot::CATALOG => {
            let mut frame = Frame::new(
                CatalogIn {
                    method: AbiStr::over(b"GET"),
                    target: AbiStr::over(STATS),
                    reply_buf: b.reply.as_mut_ptr(),
                    reply_cap: b.reply.len(),
                    fields_buf: b.fields.as_mut_ptr(),
                    fields_cap: b.fields.len(),
                    arena_buf: b.arena.as_mut_ptr(),
                    arena_cap: b.arena.len(),
                    ..blank_in()
                },
                blank_out::<CatalogOut>(),
            );
            measure(&mut || ready(s, plugin.call(s, &mut frame).outcome))
        }
        other => panic!(
            "request-path op {other} has no measured case: the zero-allocation claim is unproven \
             for it until one is added here"
        ),
    }
}

fn ready(s: u32, outcome: AbiOutcome) {
    assert_eq!(outcome, AbiOutcome::Ready, "op {s} answers READY");
}

type Measure = fn(&mut dyn FnMut()) -> u64;

fn not_measured(f: &mut dyn FnMut()) -> u64 {
    f();
    0
}

fn measured(f: &mut dyn FnMut()) -> u64 {
    counted(f)
}

fn request_path_ops() -> Vec<u32> {
    CONTRACTS
        .iter()
        .filter(|c| c.request_path)
        .map(|c| c.slot)
        .collect()
}

#[test]
fn the_witness_counts_what_it_measures_and_nothing_else() {
    let planted = counted(|| drop(std::hint::black_box(Box::new(7_u64))));
    assert!(planted >= 1, "a planted allocation was not counted");
    let in_plugin = counted(|| unmeasured(|| drop(std::hint::black_box(vec![1_u8; 64]))));
    assert_eq!(in_plugin, 0, "a plugin body's allocation was counted");
    drop(std::hint::black_box(Box::new(1_u8)));
    assert_eq!(
        counted(|| {}),
        0,
        "an allocation outside the window was counted"
    );
}

#[test]
fn every_request_path_op_is_measured() {
    let dispatcher = Dispatcher::new(DispatchConfig::default());
    let plugin = opened(&dispatcher);
    let mut bufs = Bufs::new();
    let ops = request_path_ops();
    assert!(
        !ops.is_empty(),
        "the plane contract names no request-path op; the witness would measure nothing"
    );

    for _ in 0..8 {
        for &s in &ops {
            crossing(&plugin, s, &mut bufs, not_measured);
        }
    }
    let mut allocated = Vec::new();
    for &s in &ops {
        for _ in 0..64 {
            let n = crossing(&plugin, s, &mut bufs, measured);
            if n != 0 {
                allocated.push((s, n));
                break;
            }
        }
    }
    assert_eq!(
        allocated.len(),
        0,
        "host allocations on the READY path, as (slot, count): {allocated:?}"
    );
}
