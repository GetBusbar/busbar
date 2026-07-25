// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SINGLE export-boundary choke point every plugin C symbol routes through (redesign B).
//!
//! Every `extern "C-unwind"` plugin export used to independently re-implement the same three boundary
//! invariants, and each new symbol got one facet wrong (a leak on a null out-slot, a missing
//! `catch_unwind`, a panic mapped to the same status as an undecodable request). This module makes all
//! three structurally impossible by giving the macro exactly ONE place that:
//!
//! 1. **allocates only after a null-check** ([`OutBuf::commit`], [`publish_handle`]) — a boxed pointer
//!    is never realized before there is a confirmed non-null slot to write it into, so the null path
//!    can only ever DROP an owned `Vec`/instance, never leak a raw allocation;
//! 2. **`catch_unwind`s mandatorily** ([`run_boundary`], [`open_boundary`], [`close_boundary`],
//!    [`free_boundary`]) — no panic (from user code OR a user `Drop`) can unwind out of an export; it
//!    is always converted to a defined status or absorbed;
//! 3. **produces only a well-formed status** ([`run_boundary`] is the ONE total map from outcome →
//!    status) — a caught panic maps to the distinct [`STATUS_PANIC`], never to the
//!    [`STATUS_UNSUPPORTED`] the loader keys its safe-default fallback on.
//!
//! Plugin authors never touch this module: `export_plugin!` supplies a `ctor` + a `dispatch` closure
//! that returns a [`BoundaryOutcome`] — a type that CANNOT name a raw pointer or a status integer — and
//! the boundary helpers thread the guards. There is no seam on which an author can get a facet wrong.

use busbar_plugin_abi::{STATUS_ERR, STATUS_OK, STATUS_PANIC, STATUS_PROTOCOL, STATUS_UNSUPPORTED};
use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// The message body a caught panic reports across the boundary. Never carries user/backend detail (a
/// panic payload is not a defined error message), just a stable marker the loader surfaces as a fault.
pub(crate) const PANIC_MSG: &[u8] = b"plugin panicked (caught at the export boundary)";

/// The ONE outcome an `*_impl`/`dispatch` closure returns. It CANNOT name a raw pointer or a status
/// integer — it can only DESCRIBE an outcome; [`run_boundary`]/[`open_boundary`] turn it into
/// `(status, bytes)`. This is what removes the per-site status mapping: there is no API surface on
/// which an author could hand a panic the wrong status or a decode-failure the wrong one.
pub enum BoundaryOutcome {
    /// Success: these bytes are the OK payload. → [`STATUS_OK`].
    Ok(Vec<u8>),
    /// A DEFINED backend failure (a `StoreError`/`SecretError`/…). → [`STATUS_ERR`], message buffer.
    Error(String),
    /// The request could not be DECODED / is unsupported by this build (an undecodable request
    /// variant). → [`STATUS_UNSUPPORTED`], message buffer. This is the ONLY thing that opens the
    /// loader's safe-default fallback; it is NEVER produced for a panic or a backend error.
    Unsupported(String),
}

/// A response/error buffer to be handed to the engine. Owns a `Vec<u8>` until [`Self::commit`];
/// `commit` is the ONLY way to turn it into a raw `(ptr, len)`, and it refuses to leak on a null slot.
pub(crate) struct OutBuf(Vec<u8>);

impl OutBuf {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        OutBuf(bytes)
    }

    /// Publish the bytes into `(out, out_len)`. If EITHER slot is null there is nowhere to write a
    /// pointer the engine could ever free, so we DO NOT allocate a raw box — `self.0` (the `Vec`) drops
    /// here and nothing leaks. The alloc (`into_boxed_slice`/`Box::into_raw`) is realized ONLY on the
    /// write path and is handed to the non-null slot in the same breath, so there is no ordering a
    /// caller can pick that leaks. This is the null-out-guard-before-alloc invariant, made structural.
    ///
    /// # Safety
    /// `out`/`out_len`, when non-null, are writable per the ABI.
    pub(crate) unsafe fn commit(self, out: *mut *mut u8, out_len: *mut usize) {
        if out.is_null() || out_len.is_null() {
            // Null path: the `Vec` drops normally; no `Box::into_raw` ever happened, so no orphan.
            return;
        }
        let boxed = self.0.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed) as *mut u8;
        *out = ptr;
        *out_len = len;
    }
}

/// Publish a freshly-constructed instance as the opaque handle, or DROP it if there is no slot. Returns
/// `Ok(())` on publish; `Err(())` means "null `out_handle`" — the caller emits a protocol error AND the
/// instance has ALREADY been dropped here (freeing whatever the ctor opened), never `Box::into_raw`'d
/// without a slot. The one definition that replaces the four hand-copied `*_open_impl` handle guards.
///
/// # Safety
/// `out_handle`, when non-null, is writable per the ABI.
unsafe fn publish_handle<T: 'static>(instance: T, out_handle: *mut *mut c_void) -> Result<(), ()> {
    if out_handle.is_null() {
        drop(instance); // free the ctor's resources; never Box::into_raw without a slot.
        return Err(());
    }
    *out_handle = Box::into_raw(Box::new(instance)) as *mut c_void;
    Ok(())
}

/// Read a request/config byte buffer per the ABI. `len == 0` → `&[]` (an empty payload is legal). A
/// null pointer with `len > 0` is a caller-PROTOCOL violation (there is no buffer to read) and is
/// signaled as `Err(())`, which the call site maps to [`STATUS_PROTOCOL`] WITHOUT running user code.
///
/// # Safety
/// `(ptr, len)`, when `len > 0` and `ptr` non-null, is a readable buffer per the ABI.
unsafe fn read_buf<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], ()> {
    if len == 0 {
        Ok(&[])
    } else if ptr.is_null() {
        Err(())
    } else {
        Ok(std::slice::from_raw_parts(ptr, len))
    }
}

/// Run `f` under a MANDATORY `catch_unwind`, mapping outcome → `(status, bytes)`. A caught panic maps
/// to the distinct [`STATUS_PANIC`] (NEVER [`STATUS_UNSUPPORTED`]), so a plugin panic can never open the
/// loader's safe-default fallback. This is the ONLY function that produces a status for a call, so the
/// taxonomy is centralized and total.
fn run_boundary(f: impl FnOnce() -> BoundaryOutcome) -> (i32, Vec<u8>) {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(BoundaryOutcome::Ok(bytes)) => (STATUS_OK, bytes),
        Ok(BoundaryOutcome::Error(msg)) => (STATUS_ERR, msg.into_bytes()),
        Ok(BoundaryOutcome::Unsupported(msg)) => (STATUS_UNSUPPORTED, msg.into_bytes()),
        Err(_) => (STATUS_PANIC, PANIC_MSG.to_vec()),
    }
}

/// `busbar_call` body for ANY kind. `dispatch` is the per-kind closure that decodes `bytes` and runs
/// the op, returning a [`BoundaryOutcome`]. No kind-specific unsafe, no per-kind status mapping — the
/// null-handle guard, the buffer read, the mandatory `catch_unwind`, the status map, and the
/// alloc-after-check publish are ALL here, once.
///
/// # Safety
/// Pointers are ABI-valid: `handle` a live handle from `open` (or null), `req`/`req_len` a readable
/// buffer (or len 0), the out pointers writable.
pub unsafe fn call_boundary(
    handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
    dispatch: impl FnOnce(*mut c_void, &[u8]) -> BoundaryOutcome,
) -> i32 {
    // Both early returns below emit a BARE `STATUS_PROTOCOL` — status only, no out buffer. That empty
    // buffer is the loader's marker for "caller-protocol violation, and also how a v1-era SDK reported
    // a caught panic": it must NEVER be read as the old-SDK unsupported signal, which the v1 SDK always
    // accompanied with a `"malformed request JSON: …"` body. See `plugin-abi`'s `STATUS_PROTOCOL`.
    if handle.is_null() {
        // A null handle is a caller-protocol violation: no user code runs, distinct status, no buffer.
        return STATUS_PROTOCOL;
    }
    let bytes = match read_buf(req, req_len) {
        Ok(b) => b,
        // Null request pointer with len > 0 — a caller-protocol violation, not an old-SDK signal.
        Err(()) => return STATUS_PROTOCOL,
    };
    let (status, payload) = run_boundary(|| dispatch(handle, bytes));
    OutBuf::new(payload).commit(out, out_len);
    status
}

/// `busbar_open` body for ANY kind. `ctor_run` decodes the `&str` config and runs the constructor,
/// returning either the constructed instance or a [`BoundaryOutcome`] describing the failure. The
/// handle guard ([`publish_handle`]), the mandatory `catch_unwind`, the status map, and the
/// alloc-after-check error publish are all centralized here.
///
/// The config decode (bad UTF-8 / null-with-len) is a caller-PROTOCOL violation → [`STATUS_PROTOCOL`],
/// distinct from a ctor `Error`/`Unsupported`.
///
/// # Safety
/// Pointers are ABI-valid: `cfg`/`cfg_len` a readable buffer (or len 0), the three out pointers
/// writable.
pub unsafe fn open_boundary<T: 'static>(
    cfg: *const u8,
    cfg_len: usize,
    out_handle: *mut *mut c_void,
    out_err: *mut *mut u8,
    out_err_len: *mut usize,
    ctor_run: impl FnOnce(&str) -> Result<T, BoundaryOutcome>,
) -> i32 {
    // A null/garbled config buffer is a caller-protocol violation detected before any user code runs.
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let bytes = match read_buf(cfg, cfg_len) {
            Ok(b) => b,
            Err(()) => return Err(CtorFail::Protocol("null config pointer".to_string())),
        };
        let s = match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return Err(CtorFail::Protocol("config is not valid UTF-8".to_string())),
        };
        ctor_run(s).map_err(CtorFail::from_outcome)
    }));
    match outcome {
        Ok(Ok(instance)) => match publish_handle(instance, out_handle) {
            Ok(()) => STATUS_OK,
            Err(()) => {
                OutBuf::new(b"null out_handle pointer".to_vec()).commit(out_err, out_err_len);
                STATUS_PROTOCOL
            }
        },
        Ok(Err(CtorFail::Protocol(m))) => {
            OutBuf::new(m.into_bytes()).commit(out_err, out_err_len);
            STATUS_PROTOCOL
        }
        Ok(Err(CtorFail::Error(m))) => {
            OutBuf::new(m.into_bytes()).commit(out_err, out_err_len);
            STATUS_ERR
        }
        Ok(Err(CtorFail::Unsupported(m))) => {
            OutBuf::new(m.into_bytes()).commit(out_err, out_err_len);
            STATUS_UNSUPPORTED
        }
        Err(_) => {
            OutBuf::new(PANIC_MSG.to_vec()).commit(out_err, out_err_len);
            STATUS_PANIC
        }
    }
}

/// The open-path failure taxonomy: a caller-protocol violation (bad config buffer), or one of the
/// ctor's [`BoundaryOutcome`] failures. Kept internal to `open_boundary`; `Protocol` is the arm the
/// generic ctor never produces (only the config-decode does).
enum CtorFail {
    Protocol(String),
    Error(String),
    Unsupported(String),
}

impl CtorFail {
    fn from_outcome(o: BoundaryOutcome) -> Self {
        match o {
            BoundaryOutcome::Error(m) => CtorFail::Error(m),
            BoundaryOutcome::Unsupported(m) => CtorFail::Unsupported(m),
            // A ctor cannot succeed via `Err`; treat a stray Ok-in-Err as an error message.
            BoundaryOutcome::Ok(_) => CtorFail::Error("constructor returned an OK outcome".into()),
        }
    }
}

/// `busbar_close` for ANY kind — drop the boxed `T`, catching a panicking `Drop` so it NEVER unwinds
/// out of the `extern "C-unwind"` symbol. The box is taken with `Box::from_raw` BEFORE the
/// `catch_unwind`, so even if `drop(boxed)` panics the allocation is reclaimed and the panic dies here,
/// not on the engine side — strictly better than the engine-side guard that caught the unwind but
/// LEAKED the handle. A misbehaving `Drop` degrades to "panic absorbed, allocation freed".
///
/// # Safety
/// `handle`, when non-null, is a live handle from `open` of type `T` that has not already been closed.
pub unsafe fn close_boundary<T: 'static>(handle: *mut c_void) {
    if handle.is_null() {
        return;
    }
    let boxed = Box::from_raw(handle as *mut T); // ownership taken BEFORE the catch…
    let _ = catch_unwind(AssertUnwindSafe(move || drop(boxed)));
}

/// `busbar_free` — reclaim a buffer produced by [`OutBuf::commit`], catching a panicking dealloc
/// (defense in depth; frees run on the hot path). Freed with the same allocator that produced it.
///
/// # Safety
/// `(ptr, len)` must be exactly a pair this plugin returned via `OutBuf::commit` and not yet freed.
pub unsafe fn free_boundary(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let slice = std::slice::from_raw_parts_mut(ptr, len);
        drop(Box::from_raw(slice as *mut [u8]));
    }));
}
