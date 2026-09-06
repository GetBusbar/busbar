//! What reading one wire frame is allowed to allocate.
//!
//! A duplex session reads fifty frames a second in each direction for the length of a call. A
//! reader that takes ownership of its input makes the caller buy a whole frame a second home before
//! anything reads it, and then keeps none of it: what a reader hands back is IR events that own
//! everything they carry. That copy is too small for a stopwatch on a shared runner and is paid on
//! every frame there is. An allocation COUNT sees it, and is the same number on every machine.
//!
//! The two routes must agree about what they read before either count means anything, so that is
//! asserted first.

use busbar_voice_codec::ir::{DecodeState, DuplexReader, OpenAiRealtimeCodec, WireEvent, WireRef};
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

/// One downlink audio frame of the dialect, in the shape a session sees them by the thousand.
const DOWNLINK: &str =
    r#"{"type":"response.output_audio.delta","delta":"AAECAwQFBgcICQoLDA0ODw=="}"#;

/// Both routes read the same frame the same way.
#[test]
fn the_borrowed_read_and_the_owned_read_agree() {
    let codec = OpenAiRealtimeCodec;
    let mut borrowed_state = DecodeState::default();
    let mut owned_state = DecodeState::default();

    let borrowed = codec.read_down_ref(WireRef(DOWNLINK.as_bytes()), &mut borrowed_state);
    let owned = codec.read_down(
        WireEvent(bytes::Bytes::copy_from_slice(DOWNLINK.as_bytes())),
        &mut owned_state,
    );
    assert_eq!(
        format!("{borrowed:?}"),
        format!("{owned:?}"),
        "the two routes read the same frame differently"
    );
    assert!(
        !borrowed.is_empty(),
        "the frame reads as at least one event"
    );
}

#[test]
fn reading_a_frame_where_it_lies_costs_one_allocation_less() {
    let codec = OpenAiRealtimeCodec;
    let mut st = DecodeState::default();

    // One warm read of each shape outside the window, so nothing a first call sets up for the
    // process is charged to a measured one.
    let _ = codec.read_down_ref(WireRef(DOWNLINK.as_bytes()), &mut st);
    let _ = codec.read_down(
        WireEvent(bytes::Bytes::copy_from_slice(DOWNLINK.as_bytes())),
        &mut st,
    );

    let borrowed = allocations_of(|| {
        let _ = codec.read_down_ref(WireRef(DOWNLINK.as_bytes()), &mut st);
    });
    let owned = allocations_of(|| {
        let _ = codec.read_down(
            WireEvent(bytes::Bytes::copy_from_slice(DOWNLINK.as_bytes())),
            &mut st,
        );
    });
    println!("frame read allocations: borrowed {borrowed}, owned {owned}");
    assert_eq!(
        owned,
        borrowed + 1,
        "the owned route allocated {owned} times and the borrowed one {borrowed}: the difference \
         between them is the one copy of the frame the owned route makes and the reader never \
         reads, so any other difference means one of the two is doing something the other is not"
    );
}
