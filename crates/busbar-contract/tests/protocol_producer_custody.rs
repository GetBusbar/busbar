// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observe explicit initialized owners before release, without scanning spare or freed memory.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::future::Future;
use std::task::{Context, Poll, Waker};

use busbar_contract::{jsonrpc, protocol::SseFrames};
use zeroize::Zeroizing;

thread_local! {
    // Keep only an address for matching. Reads always use the allocator's current live pointer.
    static WATCH: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
    static WIPED: Cell<Option<bool>> = const { Cell::new(None) };
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static REALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct InspectBeforeFree;

fn count(counter: &'static std::thread::LocalKey<Cell<usize>>) {
    let _ = COUNTING.try_with(|active| {
        if active.get() {
            let _ = counter.try_with(|count| count.set(count.get() + 1));
        }
    });
}

unsafe fn inspect(pointer: *mut u8, layout: Layout) {
    let _ = WATCH.try_with(|watch| {
        if let Some((_, len)) = watch
            .get()
            .filter(|(address, _)| *address == pointer.addr())
        {
            watch.set(None);
            let wiped = len <= layout.size()
                && (0..len).all(|index| {
                    // SAFETY: this exact live allocation's initialized prefix was registered.
                    // The allocator has not released it; no other allocation or spare byte is read.
                    unsafe { pointer.add(index).read_volatile() == 0 }
                });
            let _ = WIPED.try_with(|result| result.set(Some(wiped)));
        }
    });
}

// SAFETY: all operations delegate unchanged to System. The only payload observation is the
// registered initialized prefix through the allocator's current pointer, before release/realloc.
unsafe impl GlobalAlloc for InspectBeforeFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(&ALLOCATIONS);
        // SAFETY: the allocator caller supplies a valid layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the caller supplies its live allocation; inspect only reads a registered prefix.
        unsafe { inspect(pointer, layout) };
        // SAFETY: pointer and layout describe the allocator caller's live allocation.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count(&REALLOCATIONS);
        // SAFETY: the old allocation remains live until System.realloc below.
        unsafe { inspect(pointer, layout) };
        // SAFETY: the allocator caller supplies the live old layout and valid new size.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: InspectBeforeFree = InspectBeforeFree;

fn watch(bytes: &[u8]) {
    assert!(!bytes.is_empty());
    WATCH.with(|watched| {
        assert!(watched.get().is_none());
        watched.set(Some((bytes.as_ptr().addr(), bytes.len())));
    });
    WIPED.with(|result| result.set(None));
}

#[test]
fn the_registered_payload_witness_distinguishes_plain_and_wiping_owners() {
    let plain = b"plain-initialized-control".to_vec();
    watch(&plain);
    drop(plain);
    assert_eq!(WIPED.with(Cell::get), Some(false));

    let wiped = Zeroizing::new(b"wiped-initialized-control".to_vec());
    watch(&wiped);
    drop(wiped);
    assert_eq!(WIPED.with(Cell::get), Some(true));
}

#[test]
fn sse_growth_wipes_the_registered_old_allocation_and_preserves_pending_bytes() {
    const SEED: &[u8] = b"data: private-pending-frame";
    const LARGE_CHUNK: &[u8] = &[b'x'; 65536];
    let mut frames = SseFrames::new();
    frames.push(SEED);
    assert!(frames.next_frame().is_none());
    watch(frames.buffer());
    frames.push(LARGE_CHUNK);
    assert_eq!(WIPED.with(Cell::get), Some(true));
    assert_eq!(&frames.buffer()[..SEED.len()], SEED);
    assert_eq!(&frames.buffer()[SEED.len()..], LARGE_CHUNK);
    assert_eq!(frames.pending(), SEED.len() + LARGE_CHUNK.len());
    watch(frames.buffer());
    drop(frames);
    assert_eq!(WIPED.with(Cell::get), Some(true));
}

#[test]
fn sse_clones_pending_cancellation_and_unwind_wipe_their_final_owners() {
    const PENDING: &[u8] = b"data: private-partial-frame";
    let mut frames = SseFrames::new();
    frames.push(PENDING);
    let clone = frames.clone();
    watch(frames.buffer());
    drop(frames);
    assert_eq!(WIPED.with(Cell::get), Some(true));
    assert_eq!(clone.buffer(), PENDING);
    watch(clone.buffer());
    let mut pending = Box::pin(async move {
        let frames = clone;
        std::future::pending::<()>().await;
        drop(frames);
    });
    assert_eq!(
        pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    );
    assert_eq!(WIPED.with(Cell::get), None);
    drop(pending);
    assert_eq!(WIPED.with(Cell::get), Some(true));

    let mut frames = SseFrames::new();
    frames.push(PENDING);
    watch(frames.buffer());
    let unwound = std::panic::catch_unwind(move || {
        let _owner = frames;
        panic!("SSE owner unwind fixture");
    });
    assert!(unwound.is_err());
    assert_eq!(WIPED.with(Cell::get), Some(true));
}

fn measured_output(write: impl FnOnce() -> Vec<u8>) -> Vec<u8> {
    ALLOCATIONS.with(|count| count.set(0));
    REALLOCATIONS.with(|count| count.set(0));
    COUNTING.with(|active| active.set(true));
    let out = write();
    COUNTING.with(|active| active.set(false));
    assert_eq!(
        ALLOCATIONS.with(Cell::get),
        1,
        "only the final output is allocated"
    );
    assert_eq!(
        REALLOCATIONS.with(Cell::get),
        0,
        "no payload allocation grows"
    );
    out
}

#[test]
fn every_jsonrpc_producer_allocates_only_its_final_output_even_with_heavy_escaping() {
    const ID: &[u8] = br#""private-id""#;
    const BODY: &[u8] = br#"{"credential":"private-body"}"#;
    let text = "private\u{0}\n\r\t\"\\雪".repeat(4096);
    let result = measured_output(|| jsonrpc::result_bytes(ID, BODY));
    let request = measured_output(|| jsonrpc::request_bytes(ID, &text, Some(BODY)));
    let notification = measured_output(|| jsonrpc::notification_bytes(&text, Some(BODY)));
    let error = measured_output(|| jsonrpc::error_bytes(ID, i64::MIN, &text, Some(BODY)));
    let id: serde_json::Value = serde_json::from_slice(ID).unwrap();
    let body: serde_json::Value = serde_json::from_slice(BODY).unwrap();
    for (out, expected) in [
        (
            result,
            serde_json::json!({"id": id, "jsonrpc": "2.0", "result": body}),
        ),
        (
            request,
            serde_json::json!({"id": id, "jsonrpc": "2.0", "method": text, "params": body}),
        ),
        (
            notification,
            serde_json::json!({"jsonrpc": "2.0", "method": text, "params": body}),
        ),
        (
            error,
            serde_json::json!({"error": {"code": i64::MIN, "data": body, "message": text}, "id": id, "jsonrpc": "2.0"}),
        ),
    ] {
        assert_eq!(out, serde_json::to_vec(&expected).unwrap());

        let owner = Zeroizing::new(out);
        watch(&owner);
        drop(owner);
        assert_eq!(WIPED.with(Cell::get), Some(true));
    }
}

#[test]
fn an_sse_owner_resumes_with_the_same_frame_then_wipes_on_error_return() {
    const HEAD: &[u8] = b"data: private-resumed-frame\n";
    let ready = Cell::new(false);
    let mut frames = SseFrames::new();
    frames.push(HEAD);
    assert!(frames.next_frame().is_none());
    let mut resumed = Box::pin(async {
        let mut frames = frames;
        std::future::poll_fn(|_| {
            if ready.get() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        frames.push(b"\n");
        assert_eq!(
            frames.next_frame(),
            Some(&b"data: private-resumed-frame\n\n"[..])
        );
        watch(frames.buffer());
        Err::<(), ()>(())
    });
    assert_eq!(
        resumed
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    );
    ready.set(true);
    assert_eq!(
        resumed
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(()))
    );
    assert_eq!(WIPED.with(Cell::get), Some(true));
}
