//! What the same-dialect relay is allowed to allocate.
//!
//! A request whose dialect the lane already speaks, and whose model the lane already names, is
//! relayed byte-for-byte: the bytes the client sent are the bytes the upstream gets. A relay that
//! parses a second copy of that document on its way out is doing work whose only effect is to be
//! thrown away, and no wall-clock test catches it reliably on a shared runner. An allocation COUNT
//! does — it is the same number on every machine, so it can be pinned.
//!
//! The instrument is a counting wrapper around the system allocator, counting per thread so a
//! concurrently-running test never inflates the measured count. The bound is exact, not an upper
//! bound: the measured call is a pure synchronous function over bytes, with no I/O and no clock, so
//! its count does not vary run to run. If an intentional change moves it, run with `--nocapture`,
//! read the printed count, and move the constant in the same commit — a raise IS the regression
//! unless the commit says in words why the extra allocation is the cheaper of two evils.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::ids::LaneId;
use busbar_contract::plane::{Ingress, Plane};
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::{LlmPlane, Upstream};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Allocations made by THIS thread since the counter was last read.
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

/// The system allocator, counting.
struct Counting;

// SAFETY: every call is forwarded verbatim to the system allocator; the counter is a thread-local
// `Cell` of a plain integer, touched only on the allocating thread, and never reads or writes the
// memory being handed out.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// How many allocations one call made on this thread.
fn allocations_of(f: impl FnOnce()) -> u64 {
    let before = ALLOCS.with(Cell::get);
    f();
    ALLOCS.with(Cell::get) - before
}

/// The model the lane names, and the model the request already names.
const MODEL: &str = "gpt-4o";

/// One upstream, speaking the dialect its clients speak.
const UPSTREAMS: &[Upstream] = &[Upstream {
    lane: LaneId::new("lane-openai"),
    host: "openai.invalid",
    dialect: "openai",
    model: MODEL,
}];

/// A request the lane relays unchanged: its dialect and its model are both the lane's own.
const BODY: &str = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello there"}],"max_tokens":64,"stream":false}"#;

/// COMMITTED BASELINE — the exact allocation count of ONE same-dialect, same-model
/// `encode_egress`.
///
/// Five, and every one of the five belongs to the hop ENVELOPE: the three fields it carries
/// (method, request target, content type), each copied once by the test arena, the request target
/// the dialect's writer builds as a string, and the field list's own buffer, which starts empty and
/// grows as the fields go in. The BODY is not among them, and that is the whole point of the
/// number: the relayed document is neither parsed nor copied, because it is already sitting in the
/// unit's arena exactly as it arrived. Before this gate the same call allocated nineteen times — a
/// full `serde_json::Value` of the request plus two further copies of its bytes — for no difference
/// at all in what went on the wire.
const PASSTHROUGH_ALLOCS: u64 = 5;

#[test]
fn same_dialect_relay_does_not_reparse_the_request() {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("openai"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);

    let frames = vec![harness::frame(BODY.as_bytes())];
    let mut cursor = FrameCursor::new(&frames);
    let draft = match plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("the body is this dialect's shape")
    {
        Ingress::OneShot(draft) => draft,
        other => panic!("a whole request body decodes as one complete unit, got {other:?}"),
    };
    let unit = harness::unit(draft.op, draft.body_ir, draft.facts);
    let dest = harness::destination("openai.invalid", LaneId::new("lane-openai"));

    // One warm call outside the window, so nothing a first call sets up for the process is charged
    // to the measured one.
    let warm = plane
        .encode_egress(&unit, &dest, None, &ctx)
        .expect("the lane speaks this dialect");
    assert_eq!(
        warm.body.as_slice(),
        BODY.as_bytes(),
        "a same-dialect, same-model relay sends the bytes the client sent"
    );

    let mut measured = None;
    let count = allocations_of(|| {
        measured = Some(
            plane
                .encode_egress(&unit, &dest, None, &ctx)
                .expect("the lane speaks this dialect"),
        );
    });
    println!("same-dialect relay allocations: {count}");
    assert_eq!(
        measured.expect("the call ran").body.as_slice(),
        BODY.as_bytes(),
        "a same-dialect, same-model relay sends the bytes the client sent"
    );
    assert_eq!(
        count, PASSTHROUGH_ALLOCS,
        "the same-dialect relay allocated {count} times, not {PASSTHROUGH_ALLOCS}: it is doing \
         work on a document it is about to send back unchanged"
    );
}
