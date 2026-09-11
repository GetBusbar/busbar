// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The PIPE tier of the egress family: a governed byte-DUPLEX channel a plane frames on top of.
//!
//! The raw-connection and subprocess egress tiers ([`EgressKind::RawConn`] / [`EgressKind::Subprocess`])
//! are the SAME shape — a byte duplex keyed by a [`PipeId`], distinguished only by a field on the open
//! POD, not by separate slots (the CLUSTER-3 (c) decision). This module owns the DUPLEX itself: the
//! process-wide registry a [`PipeId`] indexes, the two vtable slots that move its bytes, and the
//! teardown a reclaim calls.
//!
//! ## The framing seam: the host is byte-level, the plane frames
//!
//! `pipe_read`/`pipe_write` move RAW BYTES. Line/message framing (a `read_capped_line` over the
//! duplex) stays PLANE-side, layered on top — the host never sees a line. So a plane that speaks a
//! line-delimited protocol over the duplex writes a framed message with `pipe_write` and reads bytes
//! back with `pipe_read`, doing its own newline framing; the host governs only the CHANNEL.
//!
//! ## What is NOT here: the OPEN, and why
//!
//! Opening a governed child is POLICY and PRIVILEGE — the command allowlist, the cleared-and-resolved
//! child environment (whose referenced values are material an engine resolves and this crate must
//! never learn), the working directory, the spawn itself. None of that is ABI: it is the engine's
//! judgement about what a plane may cause to run on the host, and it stays in the engine, beside the
//! other egress tier's open. What crosses to the plane is only what the ABI defines — a [`PipeId`] and
//! two byte verbs — so this module takes an ALREADY-SPAWNED duplex ([`open_duplex`]) and hands back
//! the id. The engine registers its own arena reclaim over [`close_pipe`]; the arena type is the
//! engine's, the bytes are the seam's.

use crate::hot::host::HostCtx;
use crate::hot::{PipeId, StatusClass};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::{Child, ChildStdin, ChildStdout};
use std::sync::{Arc, LazyLock, Mutex};

/// One open governed subprocess pipe the host owns end to end. The plane holds only its [`PipeId`] and
/// moves bytes through [`pipe_read`]/[`pipe_write`]; the host owns the child's lifecycle.
struct PipeBackend {
    /// The child process; taken and killed on close. Behind a `Mutex` because the vtable fns hold only
    /// a shared `&PipeBackend` (via the registry) yet must kill/wait.
    child: Mutex<Option<Child>>,
    /// The child's stdin — the WRITE half of the duplex. `None` once closed.
    stdin: Mutex<Option<ChildStdin>>,
    /// The child's stdout — the READ half of the duplex. `None` once closed.
    stdout: Mutex<Option<ChildStdout>>,
}

impl PipeBackend {
    /// Read up to `cap` bytes from the child's stdout into `buf`. Blocks for output; `Ok(0)` is a
    /// clean end of stream (the child closed its stdout).
    ///
    /// # Safety
    /// `buf`/`cap` must describe a live writable range for the call (ABI discipline).
    unsafe fn read(&self, buf: *mut u8, cap: usize) -> (StatusClass, usize) {
        if buf.is_null() || cap == 0 {
            return (StatusClass::Refused, 0);
        }
        let mut guard = self.stdout.lock().unwrap_or_else(|e| e.into_inner());
        let Some(stdout) = guard.as_mut() else {
            return (StatusClass::Gone, 0); // closed / reclaimed underneath us.
        };
        // SAFETY: caller's contract — `buf` is writable for `cap` bytes.
        let slice = unsafe { std::slice::from_raw_parts_mut(buf, cap) };
        match stdout.read(slice) {
            Ok(n) => (StatusClass::Ok, n), // n == 0 ⇒ EOF (clean end of stream).
            Err(_) => (StatusClass::Fault, 0),
        }
    }

    /// Write `len` bytes to the child's stdin.
    ///
    /// # Safety
    /// `buf`/`len` must describe a live readable range for the call (ABI discipline).
    unsafe fn write(&self, buf: *const u8, len: usize) -> StatusClass {
        if buf.is_null() && len != 0 {
            return StatusClass::Refused;
        }
        let mut guard = self.stdin.lock().unwrap_or_else(|e| e.into_inner());
        let Some(stdin) = guard.as_mut() else {
            return StatusClass::Gone;
        };
        // SAFETY: caller's contract — `(buf, len)` is a live readable range.
        let slice = if len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(buf, len) }
        };
        match stdin.write_all(slice).and_then(|()| stdin.flush()) {
            Ok(()) => StatusClass::Ok,
            Err(_) => StatusClass::Fault,
        }
    }

    /// Tear the pipe down: drop both halves of the duplex (signalling EOF to the child), then kill and
    /// reap the child so no zombie or wedged process leaks. Idempotent — a second call finds the child
    /// taken.
    fn close(&self) {
        // Drop stdin first so a child reading its input observes EOF and can exit cleanly.
        let _ = self.stdin.lock().unwrap_or_else(|e| e.into_inner()).take();
        let _ = self.stdout.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(mut child) = self.child.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The PROCESS-WIDE registry of open pipes, keyed by a GLOBALLY unique id (the same discipline the
/// engine's egress registry holds: two concurrent dispatches each mint arena-local ids from `1`, so
/// the id the plane holds is minted from a process atomic and the backend lives here; the caller's
/// arena still owns RECLAIM, through a closer it registers over [`close_pipe`]).
///
/// A backend enters through [`open_duplex`] and leaves through [`close_pipe`]; nothing else may touch
/// the map, so "is this id live?" has exactly one answer ([`is_open`]).
static REGISTRY: LazyLock<Mutex<HashMap<u64, Arc<PipeBackend>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The next globally-unique pipe id. `0` is the reserved [`PipeId::NONE`] sentinel, so ids start at `1`.
static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn registry() -> std::sync::MutexGuard<'static, HashMap<u64, Arc<PipeBackend>>> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// REGISTER an already-spawned child as a duplex and mint its [`PipeId`]. The caller owns the decision
/// to spawn (the allowlist, the environment, the working directory — all engine policy); from here the
/// child's lifecycle is this module's, and it ends at [`close_pipe`], which the caller's arena calls.
/// The id is minted from a process atomic, so two concurrent dispatches never collide.
#[must_use]
pub fn open_duplex(child: Child, stdin: ChildStdin, stdout: ChildStdout) -> PipeId {
    let backend = Arc::new(PipeBackend {
        child: Mutex::new(Some(child)),
        stdin: Mutex::new(Some(stdin)),
        stdout: Mutex::new(Some(stdout)),
    });
    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    registry().insert(id, backend);
    PipeId(id)
}

/// Is this pipe still OPEN — i.e. does the registry still hold a backend for it? The observation verb
/// the caller's reclaim proof needs: an arena that has dropped must leave `false` here, and only the
/// module that owns the registry can answer. `false` for [`PipeId::NONE`] and for any id never minted.
#[must_use]
pub fn is_open(pipe: PipeId) -> bool {
    pipe != PipeId::NONE && registry().contains_key(&pipe.0)
}

/// Remove a pipe from the registry and close it — the body a caller's arena closer calls. Idempotent:
/// the map remove elects exactly one closer, so a second call (a double reclaim, or a close racing the
/// arena) finds nothing and reports `false` rather than killing a child twice.
pub fn close_pipe(pipe: PipeId) -> bool {
    match registry().remove(&pipe.0) {
        Some(pipe) => {
            pipe.close();
            true
        }
        None => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The two vtable slots. Each checks the host context FIRST, runs inside a MANDATORY catch_unwind, and
// FAILS CLOSED (`Fault` / `Gone` / `Refused`) on a caught panic — never a permissive value.
//
// The engine's slots recover their own host state from the `HostCtx` before doing any work; these two
// need none of it (a pipe is keyed by its `PipeId`, and the backend lives in this module's registry),
// so they check that the context is a LIVE one and go no further into it. A null `HostCtx` is never a
// live call, so it is refused rather than served — the same fail-closed posture the recovery gives,
// without naming the engine's state type.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Read raw bytes from a governed pipe into the caller's buffer. Blocks for output; `Ok` with
/// `out_written = 0` is a clean end of stream.
// Takes the raw out-param pointer the plane ABI dictates and writes through it under the caller's ABI
// contract; it cannot be marked `unsafe` without changing the `extern` fn-pointer type the slot is
// registered as, so the deref lint is allowed here exactly as at every other host-call slot.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C-unwind" fn pipe_read(
    host: HostCtx,
    pipe: PipeId,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        if host.is_null() || out_written.is_null() {
            return StatusClass::Refused;
        }
        let Some(backend) = registry().get(&pipe.0).map(Arc::clone) else {
            return StatusClass::Gone; // unknown / already closed / reclaimed.
        };
        // SAFETY: caller's `buf`/`buf_cap` describe a live writable range (ABI discipline).
        let (class, written) = unsafe { backend.read(buf, buf_cap) };
        if class == StatusClass::Ok {
            // SAFETY: `out_written` is non-null (checked) and writable for one `usize`.
            unsafe {
                *out_written = written;
            }
        }
        class
    }))
    .unwrap_or(StatusClass::Fault)
}

/// Write raw bytes to a governed pipe (the child's stdin).
// Takes the raw out-param pointer the plane ABI dictates and writes through it under the caller's ABI
// contract; it cannot be marked `unsafe` without changing the `extern` fn-pointer type the slot is
// registered as, so the deref lint is allowed here exactly as at every other host-call slot.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C-unwind" fn pipe_write(
    host: HostCtx,
    pipe: PipeId,
    buf: *const u8,
    len: usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        if host.is_null() {
            return StatusClass::Refused;
        }
        let Some(backend) = registry().get(&pipe.0).map(Arc::clone) else {
            return StatusClass::Gone;
        };
        // SAFETY: caller's `buf`/`len` describe a live readable range (ABI discipline).
        unsafe { backend.write(buf, len) }
    }))
    .unwrap_or(StatusClass::Fault)
}

#[cfg(test)]
#[path = "tests/pipe_tests.rs"]
mod tests;
