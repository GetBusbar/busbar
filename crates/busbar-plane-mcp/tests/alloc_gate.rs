//! What reading a stdio child's message is allowed to allocate.
//!
//! An allocation COUNT is the same number on every machine, so work that grows with the input
//! where it should not is seen here where a stopwatch on a shared runner would miss it. (The
//! decode-allocation pin that lived here drove the unserved `Plane` impl, deleted with it under
//! plane-mcp finding 12.)

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

/// RED (finding 14, the design's no-blocking rule: bounded work): a stdio child's message arriving
/// in many small pieces is read ONCE. Re-parsing everything held on every piece builds and drops
/// the message's completed part once per piece: quadratic in its size (a multi-megabyte tool result
/// costs seconds of worker CPU per lease). Scanning only the new bytes and parsing only a whole
/// message keeps the count linear: one parse's worth of allocations and the buffer's growth.
#[test]
fn a_childs_message_read_in_small_pieces_is_parsed_once() {
    use busbar_plane_mcp::tool_program::{Frames, Message};
    use serde_json::{json, Value};
    const ITEMS: u64 = 2000;
    let content: Vec<Value> = (0..ITEMS)
        .map(|i| json!({"type": "text", "text": format!("t{i}")}))
        .collect();
    let message =
        serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 7, "result": {"content": content}}))
            .unwrap();
    let mut frames = Frames::default();
    let mut read = Vec::with_capacity(4);
    let count = allocations_of(|| {
        for piece in message.chunks(64) {
            read.extend(frames.push(piece));
        }
    });
    println!(
        "{} bytes in {} pieces: {count} allocations",
        message.len(),
        message.len().div_ceil(64)
    );
    assert_eq!(
        read,
        vec![Message::Value(serde_json::from_slice(&message).unwrap())],
        "the message is read whole, once"
    );
    assert!(
        count < 20 * ITEMS,
        "reading one {}-byte message in 64-byte pieces allocated {count} times: what is held is \
         re-parsed on every piece",
        message.len()
    );
}
