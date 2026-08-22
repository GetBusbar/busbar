// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The PIPE tier of the egress family: a governed byte-DUPLEX channel a plane frames on top of.
//!
//! The raw-connection and subprocess egress tiers ([`EgressKind::RawConn`] / [`EgressKind::Subprocess`])
//! are the SAME shape — a byte duplex keyed by a [`PipeId`], distinguished only by a field on the open
//! POD, not by separate slots (the CLUSTER-3 (c) decision). This module owns the SUBPROCESS wiring: a
//! governed child process whose stdin/stdout are the duplex, opened through the SAME `egress_open`
//! chokepoint as an HTTP hop.
//!
//! ## The framing seam: the host is byte-level, the plane frames
//!
//! `pipe_read`/`pipe_write` move RAW BYTES. Line/message framing (the stdio transport's
//! `read_capped_line` logic) stays PLANE-side, layered on top — the host never sees a line. So a
//! JSON-RPC-over-stdio plane writes a framed message with `pipe_write` and reads bytes back with
//! `pipe_read`, doing its own newline framing; the host governs only the CHANNEL.
//!
//! ## The command allowlist is HOST-side
//!
//! The open POD carries the program + argv as neutral DATA only — NO policy. The host enforces the
//! command allowlist here ([`command_admissible`]) BEFORE spawning: the program must be an ABSOLUTE
//! path (the stdio transport's own boot rule, restated at the seam) and the egress scope must permit
//! the subprocess tier. A plane cannot smuggle a relative name or a shell metacharacter through — the
//! program goes straight to `Command::new` with argv as a vector, never a shell string.

use super::{recover, HostState};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::pod::POD_VERSION;
use busbar_plugin::hot::{
    EgressDesc, EgressHead, EgressId, EgressOpen, PipeId, StatusClass,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, LazyLock, Mutex};

/// This egress scope permits the governed SUBPROCESS tier. The host, not the plane, decides whether a
/// scope may spawn a child; a scope without this bit refuses every subprocess open. (The private /
/// plaintext bits live in [`super::egress`]; this one is the pipe tier's.)
const SCOPE_ALLOW_SUBPROCESS: u32 = 1 << 2;

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

    /// Tear the pipe down: drop both stdio halves (signalling EOF to the child), then kill and reap the
    /// child so no zombie or wedged process leaks. Idempotent — a second call finds the child taken.
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

/// The PROCESS-WIDE registry of open pipes, keyed by a GLOBALLY unique id (the same discipline as the
/// egress [`REGISTRY`](super::egress): two concurrent dispatches each mint arena-local ids from `1`, so
/// the id the plane holds is minted from a process atomic and the backend lives here; the arena still
/// owns RECLAIM via a registered [`Closer`](super::scope::DispatchScope::register_pipe)).
static REGISTRY: LazyLock<Mutex<HashMap<u64, Arc<PipeBackend>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The next globally-unique pipe id. `0` is the reserved [`PipeId::NONE`] sentinel, so ids start at `1`.
static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn registry() -> std::sync::MutexGuard<'static, HashMap<u64, Arc<PipeBackend>>> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Remove a pipe from the registry and close it. Idempotent: the map remove elects exactly one closer
/// (the arena `Closer`); a second call finds nothing.
fn close_and_remove(id: u64) -> bool {
    match registry().remove(&id) {
        Some(pipe) => {
            pipe.close();
            true
        }
        None => false,
    }
}

/// Decode the packed `program + argv` blob the [`EgressDesc::target`](EgressDesc) carries for a
/// subprocess open: a sequence of records, each `u32 len` (LE) then `len` bytes. The FIRST record is
/// the program path; the rest are argv. Malformed input yields `None` (fail-closed — an undecodable
/// command is refused, never guessed into a spawn).
///
/// # Safety
/// `(ptr, len)` MUST describe a live, initialized byte range for the call.
unsafe fn decode_command(ptr: *const u8, len: usize) -> Option<(String, Vec<String>)> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: caller's contract — `(ptr, len)` is a live borrowed range.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let mut tokens: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let end = i.checked_add(4)?;
        let word = bytes.get(i..end)?;
        i = end;
        let n = u32::from_le_bytes(word.try_into().ok()?) as usize;
        let tok_end = i.checked_add(n)?;
        let tok = bytes.get(i..tok_end)?;
        i = tok_end;
        tokens.push(String::from_utf8_lossy(tok).into_owned());
    }
    let mut it = tokens.into_iter();
    let program = it.next()?;
    Some((program, it.collect()))
}

/// The HOST command allowlist: a program is admissible only when it is an ABSOLUTE path AND the egress
/// scope permits the subprocess tier. This is policy the HOST owns — the plane's [`EgressDesc`] carried
/// only data. Phase 2 resolves the scope id against operator config and adds a per-program allowlist;
/// the scaffold enforces the two invariants the stdio transport already relies on.
fn command_admissible(program: &str, scope: u32) -> bool {
    scope & SCOPE_ALLOW_SUBPROCESS != 0 && std::path::Path::new(program).is_absolute()
}

/// Open a governed SUBPROCESS pipe. Decodes + allowlist-checks the command, spawns the child with piped
/// stdio, registers the backend + the arena closer, and writes an [`EgressOpen`] whose `pipe` is the
/// duplex [`PipeId`]. Called from [`super::egress::egress_open`] for [`EgressKind::Subprocess`]; the
/// caller owns the `catch_unwind` and the null checks.
pub(super) fn open_subprocess(
    state: &HostState,
    d: &EgressDesc,
    out: *mut MaybeUninit<EgressOpen>,
) -> StatusClass {
    // SAFETY: `(target_ptr, target_len)` is a live borrowed range for the call (ABI discipline).
    let Some((program, argv)) = (unsafe { decode_command(d.target_ptr, d.target_len) }) else {
        return StatusClass::Refused;
    };
    if !command_admissible(&program, d.allowlist_scope) {
        return StatusClass::Refused; // not absolute / scope forbids the subprocess tier.
    }
    // NO SHELL: the program goes to `Command::new` and argv as a vector — never a shell string, so a
    // metacharacter in an arg has no meaning. Stderr is discarded (the duplex is stdin/stdout only).
    let child = Command::new(&program)
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(_) => return StatusClass::Fault, // spawn failed (e.g. ENOENT) — a host-side fault.
    };
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return StatusClass::Fault;
    };
    let backend = Arc::new(PipeBackend {
        child: Mutex::new(Some(child)),
        stdin: Mutex::new(Some(stdin)),
        stdout: Mutex::new(Some(stdout)),
    });

    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    registry().insert(id, Arc::clone(&backend));
    // The arena reclaims on dispatch-drop: kill + reap the child, so a cancelled dispatch cannot leak a
    // process. (We hand the plane the global id and ignore the arena's own id, like `register_egress`.)
    let _ = state.scope.register_pipe(Box::new(move || {
        close_and_remove(id);
    }));

    let open = EgressOpen {
        size: std::mem::size_of::<EgressOpen>() as u32,
        version: POD_VERSION,
        _reserved: 0,
        // A subprocess is a duplex byte channel, not a one-shot egress: the plane drives the PipeId.
        id: EgressId::NONE,
        pipe: PipeId(id),
        head: EgressHead {
            size: std::mem::size_of::<EgressHead>() as u32,
            version: POD_VERSION,
            status_code: 0, // a raw byte channel has no HTTP status.
            observed_spki_ptr: std::ptr::null(),
            observed_spki_len: 0,
        },
    };
    // SAFETY: `out` is non-null (checked by the caller) and writable for one `EgressOpen`; written on Ok.
    unsafe {
        (*out).write(open);
    }
    StatusClass::Ok
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The two vtable slots. Each recovers the HostState FIRST, runs inside a MANDATORY catch_unwind, and
// FAILS CLOSED (`Fault` / `Gone` / `Refused`) on a caught panic — never a permissive value.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Read raw bytes from a governed pipe into the caller's buffer. Blocks for output; `Ok` with
/// `out_written = 0` is a clean end of stream.
pub(crate) extern "C-unwind" fn pipe_read(
    host: HostCtx,
    pipe: PipeId,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state: &HostState = unsafe { recover(host) };
        if out_written.is_null() {
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
pub(crate) extern "C-unwind" fn pipe_write(host: HostCtx, pipe: PipeId, buf: *const u8, len: usize) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state: &HostState = unsafe { recover(host) };
        let Some(backend) = registry().get(&pipe.0).map(Arc::clone) else {
            return StatusClass::Gone;
        };
        // SAFETY: caller's `buf`/`len` describe a live readable range (ABI discipline).
        unsafe { backend.write(buf, len) }
    }))
    .unwrap_or(StatusClass::Fault)
}

#[cfg(test)]
#[path = "pipe_tests.rs"]
mod tests;
