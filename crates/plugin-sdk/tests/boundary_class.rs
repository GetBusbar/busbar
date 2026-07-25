// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Class-level RED/GREEN harness for the plugin export boundary (redesign B §6a).
//!
//! One harness parameterized over the boundary WRAPPER (`open_boundary`/`call_boundary`/
//! `close_boundary`/`free_boundary` — the exact helpers `export_plugin!` emits), not per-symbol. A new
//! export inherits this coverage the moment it routes through the macro. The five injected conditions:
//!
//! | condition            | asserts                                                              |
//! |----------------------|---------------------------------------------------------------------|
//! | null out-pointer     | no leak (counting allocator net-zero), out_len untouched            |
//! | panic inside impl    | STATUS_PANIC (not UNSUPPORTED, not PROTOCOL), no unwind past export |
//! | unsupported op       | STATUS_UNSUPPORTED, distinct from panic                             |
//! | real error           | STATUS_ERR with the message in the buffer                          |
//! | panicking Drop       | close returns normally (no unwind), allocation reclaimed (net-zero) |
//!
//! RED-before/GREEN-after: on `main` (pre-B) `write_buf` leaked on null out, a panic mapped to
//! STATUS_PROTOCOL (indistinguishable from unsupported), and `*_close_impl` had no `catch_unwind` so a
//! panicking Drop unwound out — the null-leak, the STATUS_PANIC, and the panicking-Drop assertions all
//! fail there. After the choke point lands they all pass.

use busbar_plugin_abi::{STATUS_ERR, STATUS_OK, STATUS_PANIC, STATUS_PROTOCOL, STATUS_UNSUPPORTED};
use busbar_plugin_sdk::boundary::{
    call_boundary, close_boundary, free_boundary, open_boundary, BoundaryOutcome,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

// ── A THREAD-LOCAL counting allocator: the net live-allocation delta across an operation is the leak
//    witness on the stable toolchain (Miri would also flag the UB/leak, but this runs in CI). It is
//    thread-local — not a global atomic — so the counter is RACE-FREE under `cargo test`'s parallel
//    threads: each test's open/call/free/close alloc+free happens on ITS OWN thread, so cross-thread
//    allocations never pollute the measurement. `try_with` guards TLS teardown during thread exit. ──

struct Counting;

thread_local! {
    /// Net live bytes allocated on THIS thread (add on alloc, subtract on dealloc).
    static LIVE: Cell<isize> = const { Cell::new(0) };
}

fn bump(delta: isize) {
    // During thread teardown the TLS may be gone; ignore then (we only measure inside a test body).
    let _ = LIVE.try_with(|c| c.set(c.get() + delta));
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            bump(layout.size() as isize);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        bump(-(layout.size() as isize));
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Net live-byte delta across `f` on the current thread — zero means every allocation `f` made was
/// also freed (no leak). The measurement itself must not allocate between the two reads.
fn net_alloc_delta(f: impl FnOnce()) -> isize {
    let before = LIVE.with(|c| c.get());
    f();
    LIVE.with(|c| c.get()) - before
}

// ── A synthetic switchable "handle" whose ctor/dispatch/Drop can be told to misbehave via the JSON
//    config, driven through the SAME `boundary::*` helpers the shipping macro emits. ──────────────

/// A DISTINCTIVELY LARGE owned payload (64 KiB) so a leaked handle shows a delta ≥ this, far above any
/// few-hundred-byte panic-runtime allocation noise on the stable toolchain. A reclaimed handle nets it
/// back to ~0. (Miri catches the exact leak too; this makes the stable-CI assertion robust to the
/// panic machinery's own transient allocations.)
const HANDLE_PAYLOAD: usize = 64 * 1024;

struct TestHandle {
    /// If true, this handle's `Drop` panics — the panicking-destructor injection.
    panic_on_drop: bool,
    /// The large owned buffer whose reclamation the leak assertion witnesses.
    _payload: Vec<u8>,
}

impl TestHandle {
    fn new(panic_on_drop: bool) -> Self {
        TestHandle {
            panic_on_drop,
            _payload: vec![0u8; HANDLE_PAYLOAD],
        }
    }
}

impl Drop for TestHandle {
    fn drop(&mut self) {
        // The `_payload` field is dropped as part of dropping `self` — even though this Drop then
        // panics, `close_boundary` owns the box before the catch, so the 64 KiB is reclaimed and only
        // the panic dies here. Panic AFTER any field-drop ordering to prove the box was owned locally.
        assert!(!self.panic_on_drop, "TestHandle::drop panic injection");
    }
}

/// The ctor `open_boundary` runs. Config drives the outcome:
/// - `"panic"` → panics inside the ctor (open panic injection);
/// - `"err"`   → a defined ctor error → STATUS_ERR;
/// - `"panic_drop"` → a handle whose Drop panics;
/// - anything else → a plain handle.
fn ctor(cfg: &str) -> Result<TestHandle, BoundaryOutcome> {
    match cfg {
        "panic" => panic!("ctor panic injection"),
        "err" => Err(BoundaryOutcome::Error("ctor failed on purpose".to_string())),
        "panic_drop" => Ok(TestHandle::new(true)),
        _ => Ok(TestHandle::new(false)),
    }
}

/// The per-kind `dispatch` `call_boundary` runs. Request bytes drive the outcome:
/// - `b"panic"`       → panics inside dispatch (call panic injection);
/// - `b"unsupported"` → an undecodable-variant signal → STATUS_UNSUPPORTED;
/// - `b"err"`         → a defined backend error → STATUS_ERR;
/// - anything else    → OK with a payload echoing the request.
fn dispatch(_handle: *mut c_void, bytes: &[u8]) -> BoundaryOutcome {
    match bytes {
        b"panic" => panic!("dispatch panic injection"),
        b"unsupported" => BoundaryOutcome::Unsupported("cannot decode this variant".to_string()),
        b"err" => BoundaryOutcome::Error("backend failed on purpose".to_string()),
        other => BoundaryOutcome::Ok([b"ok:", other].concat()),
    }
}

/// Open a `TestHandle` via the real `open_boundary`; returns the opaque handle (asserts STATUS_OK).
unsafe fn open(cfg: &[u8]) -> *mut c_void {
    let mut handle: *mut c_void = ptr::null_mut();
    let mut err: *mut u8 = ptr::null_mut();
    let mut err_len: usize = 0;
    let st = open_boundary::<TestHandle>(
        cfg.as_ptr(),
        cfg.len(),
        &mut handle,
        &mut err,
        &mut err_len,
        ctor,
    );
    assert_eq!(st, STATUS_OK, "open should succeed for cfg");
    assert!(!handle.is_null());
    handle
}

unsafe fn call(handle: *mut c_void, req: &[u8], out: &mut *mut u8, out_len: &mut usize) -> i32 {
    call_boundary(handle, req.as_ptr(), req.len(), out, out_len, dispatch)
}

/// Condition 1 — null out-pointer never leaks. A `call` whose `dispatch` produces a real OK payload
/// (a `Vec` that WOULD have been boxed) with a NULL `out` must DROP that buffer, not leak it: the net
/// live-allocation delta across the call is zero, and the untouched `out_len` sentinel is preserved.
/// RED before: `write_buf` did `Box::into_raw` before the null-check → the boxed slice leaked (nonzero
/// delta). GREEN after: `OutBuf::commit` allocates strictly inside the non-null branch.
#[test]
fn null_out_pointer_never_leaks() {
    unsafe {
        let handle = open(b"plain");
        let mut out_len: usize = 0xDEAD;
        let delta = net_alloc_delta(|| {
            // NULL out slot, but a request that yields a non-empty OK payload.
            let st = call_boundary(
                handle,
                b"payload".as_ptr(),
                b"payload".len(),
                ptr::null_mut(),
                &mut out_len,
                dispatch,
            );
            assert_eq!(st, STATUS_OK);
        });
        assert_eq!(
            delta, 0,
            "a null out slot must not leak the response buffer"
        );
        assert_eq!(
            out_len, 0xDEAD,
            "out_len must be untouched when out is null"
        );
        close_boundary::<TestHandle>(handle);
    }
}

/// Condition 2 — a panic inside the impl is STATUS_PANIC, not UNSUPPORTED, not PROTOCOL, and never
/// unwinds past the export. RED before: a caught panic returned STATUS_PROTOCOL, indistinguishable
/// from an undecodable variant (the D4 root). The call is wrapped in the test's own `catch_unwind`
/// that MUST observe `Ok` — an unwind past the boundary would surface as `Err` here.
#[test]
fn panic_inside_impl_is_status_panic() {
    unsafe {
        let handle = open(b"plain");
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let observed = catch_unwind(AssertUnwindSafe(|| {
            call(handle, b"panic", &mut out, &mut out_len)
        }));
        let st = observed.expect("no panic may unwind past the export boundary");
        assert_eq!(st, STATUS_PANIC, "a caught panic must map to STATUS_PANIC");
        assert_ne!(
            st, STATUS_UNSUPPORTED,
            "a panic is NOT the unsupported signal"
        );
        assert_ne!(st, STATUS_PROTOCOL, "a panic is NOT a protocol violation");
        free_boundary(out, out_len);
        close_boundary::<TestHandle>(handle);
    }
}

/// A ctor panic is likewise STATUS_PANIC (not STATUS_PROTOCOL), and does not unwind past `open`.
#[test]
fn ctor_panic_is_status_panic() {
    unsafe {
        let mut handle: *mut c_void = ptr::null_mut();
        let mut err: *mut u8 = ptr::null_mut();
        let mut err_len: usize = 0;
        let observed = catch_unwind(AssertUnwindSafe(|| {
            open_boundary::<TestHandle>(
                b"panic".as_ptr(),
                b"panic".len(),
                &mut handle,
                &mut err,
                &mut err_len,
                ctor,
            )
        }));
        let st = observed.expect("a ctor panic must not unwind past open");
        assert_eq!(st, STATUS_PANIC);
        assert!(handle.is_null());
        free_boundary(err, err_len);
    }
}

/// Condition 3 — an unsupported op is STATUS_UNSUPPORTED, distinct from a panic (2) and an error (4).
#[test]
fn unsupported_variant_is_status_unsupported() {
    unsafe {
        let handle = open(b"plain");
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let st = call(handle, b"unsupported", &mut out, &mut out_len);
        assert_eq!(st, STATUS_UNSUPPORTED);
        assert_ne!(st, STATUS_PANIC);
        let msg = String::from_utf8_lossy(std::slice::from_raw_parts(out, out_len)).into_owned();
        assert!(msg.contains("cannot decode"), "got {msg}");
        free_boundary(out, out_len);
        close_boundary::<TestHandle>(handle);
    }
}

/// Condition 4 — a real (defined) backend error is STATUS_ERR with the message in the out buffer.
#[test]
fn real_error_is_status_err() {
    unsafe {
        let handle = open(b"plain");
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let st = call(handle, b"err", &mut out, &mut out_len);
        assert_eq!(st, STATUS_ERR);
        let msg = String::from_utf8_lossy(std::slice::from_raw_parts(out, out_len)).into_owned();
        assert!(msg.contains("backend failed on purpose"), "got {msg}");
        free_boundary(out, out_len);
        close_boundary::<TestHandle>(handle);

        // A ctor error is likewise STATUS_ERR with its message.
        let mut handle2: *mut c_void = ptr::null_mut();
        let mut err: *mut u8 = ptr::null_mut();
        let mut err_len: usize = 0;
        let st = open_boundary::<TestHandle>(
            b"err".as_ptr(),
            b"err".len(),
            &mut handle2,
            &mut err,
            &mut err_len,
            ctor,
        );
        assert_eq!(st, STATUS_ERR);
        assert!(handle2.is_null());
        let msg = String::from_utf8_lossy(std::slice::from_raw_parts(err, err_len)).into_owned();
        assert!(msg.contains("ctor failed on purpose"), "got {msg}");
        free_boundary(err, err_len);
    }
}

/// Condition 5 — a panicking Drop does not unwind past `close` and frees the allocation. The handle's
/// `Drop` allocates then panics; `close_boundary` owns the box BEFORE the catch, so the allocation is
/// reclaimed (net-zero delta across open+close) and the panic dies inside the export (the test's
/// `catch_unwind` observes `Ok`). RED before: `*_close_impl` had no catch → the panic unwound out and
/// the engine-side guard leaked the handle.
#[test]
fn panicking_drop_does_not_unwind_and_frees() {
    unsafe {
        let delta = net_alloc_delta(|| {
            let handle = open(b"panic_drop");
            let closed = catch_unwind(AssertUnwindSafe(|| close_boundary::<TestHandle>(handle)));
            assert!(
                closed.is_ok(),
                "a panicking Drop must never unwind past close_boundary"
            );
        });
        // A LEAKED handle would show a delta ≥ the 64 KiB payload; a reclaimed one nets to ~0 (only
        // small panic-runtime noise). The strict witness is `delta` far below the payload size.
        assert!(
            delta < (HANDLE_PAYLOAD as isize) / 2,
            "a panicking Drop must still free the handle (box owned before the catch); leaked {delta} bytes"
        );
    }
}

/// The happy path still round-trips (open → call OK → close), and a well-behaved buffer is freeable —
/// the choke point does not regress the normal contract, and the whole cycle is leak-free.
#[test]
fn happy_path_roundtrips_and_is_leak_free() {
    unsafe {
        let delta = net_alloc_delta(|| {
            let handle = open(b"plain");
            let mut out: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let st = call(handle, b"hi", &mut out, &mut out_len);
            assert_eq!(st, STATUS_OK);
            assert_eq!(std::slice::from_raw_parts(out, out_len), b"ok:hi");
            free_boundary(out, out_len);
            close_boundary::<TestHandle>(handle);
        });
        assert_eq!(
            delta, 0,
            "the full open→call→free→close cycle must leak nothing"
        );
    }
}
