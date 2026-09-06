//! What reading a request's metadata block is allowed to allocate.
//!
//! Two of the block's keys are read on every request that carries one, and both are constants. A
//! lookup that builds its search text at request time spends a heap allocation per key to spell out
//! something that was known at compile time — too small for a stopwatch to see on a shared runner,
//! and paid on every single request. An allocation COUNT sees it, and is the same number on every
//! machine, so it can be pinned.
//!
//! The bound is exact. Decoding is a pure synchronous walk over bytes with no I/O and no clock, so
//! its count does not vary run to run. If an intentional change moves it, run with `--nocapture`,
//! read the printed count, and move the constant in the same commit.

mod common;

use busbar_contract::plane::{Ingress, Plane};
use busbar_contract::wire::FrameCursor;
use busbar_plane_mcp::{facts, McpPlane};
use common::{frame, Scaffold};
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

/// One request carrying a metadata block with both of the keys the decode step reads.
fn body_with_metadata() -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{{"_meta":{{"{}":"2026-07-28","{}":"tok-1"}}}}}}"#,
        facts::META_PROTOCOL_VERSION,
        facts::META_PROGRESS_TOKEN
    )
    .into_bytes()
}

/// COMMITTED BASELINE — the exact allocation count of decoding ONE request whose metadata block
/// carries both read keys.
///
/// Two: the span table the decode resolves into the arena for the loop to read, and the box the
/// draft travels in (the plane's per-frame answer is an enum whose largest arm would otherwise be
/// copied by value at every hand-over, so the draft is heap-placed once, at decode). Nothing else
/// about reading a request of this protocol needs memory: the body is read where it lies and a
/// numeric identifier correlates as the number it is.
///
/// It was eight. The six that are gone were the search text the member lookup built for each of the
/// two keys it reads — a formatted string apiece, and formatting a string is more than one
/// allocation — to spell out names the crate was compiled holding.
const DECODE_WITH_METADATA_ALLOCS: u64 = 2;

#[test]
fn reading_the_metadata_block_builds_no_search_text() {
    let plane = McpPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let body = body_with_metadata();
    let frames = vec![frame(&body)];

    // One warm call outside the window, so nothing a first call sets up for the process is charged
    // to the measured one.
    {
        let mut cursor = FrameCursor::new(&frames);
        let decoded = plane
            .decode_ingress(&mut cursor, None, &ctx)
            .expect("the body is this protocol's shape");
        assert!(
            matches!(decoded, Ingress::OneShot(_) | Ingress::Open(_)),
            "a whole request decodes as a unit, got {decoded:?}"
        );
    }

    let mut carried = None;
    let count = allocations_of(|| {
        let mut cursor = FrameCursor::new(&frames);
        let decoded = plane
            .decode_ingress(&mut cursor, None, &ctx)
            .expect("the body is this protocol's shape");
        let draft = match decoded {
            Ingress::OneShot(d) | Ingress::Open(d) | Ingress::Handshake(d) => d,
            other => panic!("a whole request decodes as a unit, got {other:?}"),
        };
        carried = draft.facts.get(facts::FACT_PROGRESS_TOKEN);
    });
    println!("decode-with-metadata allocations: {count}");
    assert!(
        carried.is_some(),
        "the progress token in the metadata block is still read"
    );
    assert_eq!(
        count, DECODE_WITH_METADATA_ALLOCS,
        "decoding allocated {count} times, not {DECODE_WITH_METADATA_ALLOCS}: it is building text \
         it could have been compiled with"
    );
}
