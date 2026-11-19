// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LIB TESTS' KIT: a worker runtime and the allocation and wipe observers.

/// A current-thread runtime, as a worker runs: its reactor and its clock, and no other thread.
pub fn worker() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[derive(Clone, Copy, Default)]
struct WipeWatch {
    pointer: usize,
    len: usize,
    second: usize,
    second_len: usize,
    first_result: Option<bool>,
    second_result: Option<bool>,
}

thread_local! {
    static WIPE_WATCH: std::cell::Cell<WipeWatch> = const { std::cell::Cell::new(WipeWatch {
        pointer: 0, len: 0, second: 0, second_len: 0, first_result: None, second_result: None,
    }) };
    /// Heap allocations made on this thread (`alloc`; `alloc_zeroed` and `realloc` go through it).
    static ALLOCATIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Bytes those allocations asked for, on this thread.
    static ALLOCATED_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many heap allocations `run` makes on the calling thread.
pub fn allocations_during<T>(run: impl FnOnce() -> T) -> (T, u64) {
    let before = ALLOCATIONS.with(std::cell::Cell::get);
    let result = run();
    let after = ALLOCATIONS.with(std::cell::Cell::get);
    (result, after.wrapping_sub(before))
}

/// How many heap allocations `run` makes on the calling thread, and the bytes they ask for (a
/// zero-filled allocation goes through the same count, so zero-filled bytes are at most these).
pub fn heap_during<T>(run: impl FnOnce() -> T) -> (T, u64, u64) {
    let bytes = ALLOCATED_BYTES.with(std::cell::Cell::get);
    let (result, calls) = allocations_during(run);
    let asked = ALLOCATED_BYTES
        .with(std::cell::Cell::get)
        .wrapping_sub(bytes);
    (result, calls, asked)
}

/// THE RELEASE PROOFS (owner's ruling on allocation, addendum): the bytes the process holds through this
/// allocator now, on every thread. Under nextest each test is its own process, so a test reads its own.
static HELD_BYTES: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

/// Bytes held now (see [`HELD_BYTES`]).
pub fn held_bytes() -> isize {
    HELD_BYTES.load(std::sync::atomic::Ordering::Relaxed)
}

struct ObservingAllocator;

#[global_allocator]
static OBSERVING_ALLOCATOR: ObservingAllocator = ObservingAllocator;

// SAFETY: every allocation is delegated unchanged to System. The observer reads live allocated
// bytes immediately before the matching System deallocation, on the observing test's thread.
unsafe impl std::alloc::GlobalAlloc for ObservingAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get().wrapping_add(1)));
        let _ = ALLOCATED_BYTES.try_with(|bytes| {
            bytes.set(
                bytes
                    .get()
                    .wrapping_add(u64::try_from(layout.size()).unwrap_or(u64::MAX)),
            );
        });
        // SAFETY: the caller supplied GlobalAlloc's layout.
        let pointer = unsafe { std::alloc::GlobalAlloc::alloc(&std::alloc::System, layout) };
        if !pointer.is_null() {
            HELD_BYTES.fetch_add(
                isize::try_from(layout.size()).unwrap_or(isize::MAX),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        let _ = WIPE_WATCH.try_with(|watch| {
            let mut state = watch.get();
            if state.pointer == pointer as usize || state.second == pointer as usize {
                let len = if state.pointer == pointer as usize {
                    state.len
                } else {
                    state.second_len
                };
                // SAFETY: the owner supplied this allocation's initialized prefix, and this
                // deallocation pointer still owns the live allocation until System receives it.
                let wiped = len <= layout.size()
                    && unsafe { std::slice::from_raw_parts(pointer, len) }
                        .iter()
                        .all(|byte| *byte == 0);
                if state.pointer == pointer as usize {
                    state.first_result = Some(wiped);
                    state.pointer = 0;
                }
                if state.second == pointer as usize {
                    state.second_result = Some(wiped);
                    state.second = 0;
                    state.second_len = 0;
                }
                watch.set(state);
            }
        });
        HELD_BYTES.fetch_sub(
            isize::try_from(layout.size()).unwrap_or(isize::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        // SAFETY: the caller returned the allocation and original layout to its allocator.
        unsafe { std::alloc::GlobalAlloc::dealloc(&std::alloc::System, pointer, layout) };
    }
}

/// Observe real destruction of an owner's initialized buffer and any explicitly lent encode copy.
pub fn observe_wipe<T>(
    pointer: *const u8,
    len: usize,
    run: impl FnOnce() -> T,
) -> (T, Option<bool>, Option<bool>) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            WIPE_WATCH.with(|watch| watch.set(WipeWatch::default()));
        }
    }
    WIPE_WATCH.with(|watch| {
        watch.set(WipeWatch {
            pointer: pointer as usize,
            len,
            ..WipeWatch::default()
        })
    });
    let _reset = Reset;
    let result = run();
    let state = WIPE_WATCH.with(std::cell::Cell::get);
    (result, state.first_result, state.second_result)
}

