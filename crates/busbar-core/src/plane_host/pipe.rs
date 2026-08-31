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
use busbar_plugin::hot::{EgressDesc, EgressHead, EgressId, EgressOpen, PipeId, StatusClass};
use busbar_plugin::read_sized_field;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
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

/// The result of resolving the child's environment: the fully-resolved `(name, value)` pairs the child
/// will get, or a fail-closed refusal (a malformed record, or a secret reference the host could not
/// resolve — the child is NOT spawned with a missing variable).
enum EnvOutcome {
    /// The child's whole environment, resolved. Applied under `env_clear()` so it is the ONLY
    /// environment the child sees.
    Ready(Vec<(String, String)>),
    /// A record was malformed or a secret could not be resolved — refuse the spawn.
    Refuse,
}

/// The child-environment VALUE-KIND byte in a packed env record: a literal value, or a host-resolved
/// secret reference (see [`EgressDesc::env_ptr`]).
const ENV_KIND_PLAIN: u8 = 0;
const ENV_KIND_SECRET: u8 = 1;

/// Decode + RESOLVE the packed subprocess environment the [`EgressDesc::env_ptr`] tail carries. Each
/// record is `u32 name_len` (LE), `name_len` name bytes, a `u8` value-kind, a `u32 value_len` (LE),
/// then `value_len` value bytes. A literal value is taken verbatim; a secret reference is the opaque
/// JSON of a host secret-ref the host turns into plaintext HERE (never off a plane POD), through the
/// SAME built-in resolver the in-process stdio transport uses — so a rotated secret needs no restart
/// and the plaintext never crosses the seam. Fail-closed: a malformed record or an unresolvable secret
/// refuses the whole spawn rather than starting the child with a missing variable.
///
/// # Safety
/// `(ptr, len)`, when non-null, MUST describe a live, initialized byte range for the call.
unsafe fn resolve_child_env(ptr: *const u8, len: usize) -> EnvOutcome {
    if ptr.is_null() || len == 0 {
        return EnvOutcome::Ready(Vec::new()); // no records ⇒ an empty (cleared) child environment.
    }
    // SAFETY: caller's contract — `(ptr, len)` is a live borrowed range.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let mut out: Vec<(String, String)> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let Some(name) = read_len_prefixed(bytes, &mut i) else {
            return EnvOutcome::Refuse;
        };
        let Some(&kind) = bytes.get(i) else {
            return EnvOutcome::Refuse;
        };
        i += 1;
        let Some(value_bytes) = read_len_prefixed_bytes(bytes, &mut i) else {
            return EnvOutcome::Refuse;
        };
        let value = match kind {
            ENV_KIND_PLAIN => String::from_utf8_lossy(value_bytes).into_owned(),
            ENV_KIND_SECRET => {
                // The value is the OPAQUE JSON of a host secret-ref; deserialize and resolve it HERE
                // through the built-in resolver — the same `resolve_builtin_string` the in-process
                // stdio spawn reads a `ChildEnvValue::Secret` with. A failure refuses the spawn.
                let Ok(secret_ref) =
                    serde_json::from_slice::<crate::config::SecretRef>(value_bytes)
                else {
                    return EnvOutcome::Refuse;
                };
                match crate::config::secret::resolve_builtin_string(&secret_ref) {
                    Ok(plaintext) => plaintext,
                    Err(_) => return EnvOutcome::Refuse, // unresolvable secret ⇒ fail-closed.
                }
            }
            _ => return EnvOutcome::Refuse, // an unknown value-kind is never guessed.
        };
        out.push((String::from_utf8_lossy(name).into_owned(), value));
    }
    EnvOutcome::Ready(out)
}

/// Read a `u32 len` (LE) then `len` bytes as a borrowed slice, advancing `*i`; `None` on truncation.
fn read_len_prefixed_bytes<'a>(bytes: &'a [u8], i: &mut usize) -> Option<&'a [u8]> {
    let end = i.checked_add(4)?;
    let word = bytes.get(*i..end)?;
    *i = end;
    let n = u32::from_le_bytes(word.try_into().ok()?) as usize;
    let tok_end = i.checked_add(n)?;
    let slice = bytes.get(*i..tok_end)?;
    *i = tok_end;
    Some(slice)
}

/// As [`read_len_prefixed_bytes`], but the name arm — kept a distinct helper for the read site's
/// readability (a record reads its name, its kind, then its value).
fn read_len_prefixed<'a>(bytes: &'a [u8], i: &mut usize) -> Option<&'a [u8]> {
    read_len_prefixed_bytes(bytes, i)
}

/// Read the subprocess working directory off the [`EgressDesc`] tail: `Some(dir)` when a non-empty cwd
/// was written, `None` (⇒ inherit the host's cwd) when the field is absent or empty. Read only behind
/// the sized-struct guard so a sender that predates the tail leaves the host's cwd untouched.
fn read_child_cwd(d: &EgressDesc) -> Option<String> {
    let ptr = read_sized_field!(d, EgressDesc, cwd_ptr)?;
    let len = read_sized_field!(d, EgressDesc, cwd_len)?;
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: a non-null `(cwd_ptr, cwd_len)` is a live borrowed range for the call (ABI discipline).
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// The HOST command allowlist: a program is admissible only when it is an ABSOLUTE path AND it is
/// explicitly named on the HOST-supplied program allowlist. This is policy the HOST owns end to end —
/// the plane's [`EgressDesc`] carries only DATA (never a capability), so the plane's `allowlist_scope`
/// bit is IGNORED here (FFI-F2/F3): a plane cannot self-grant the subprocess tier.
///
/// The FFI vtable slot passes an EMPTY allowlist (`&[]`) because no operator config wires a subprocess
/// program allowlist over the FFI seam today — so every plane-driven subprocess open is REFUSED
/// (fail-closed by denial; the capability is disabled at the seam, not merely narrowed). A caller that
/// legitimately owns a host-authored allowlist (the in-core stdio-transport posture, exercised in
/// tests) passes it explicitly and only its named absolute programs are admissible.
fn command_admissible(program: &str, program_allowlist: &[String]) -> bool {
    std::path::Path::new(program).is_absolute() && program_allowlist.iter().any(|p| p == program)
}

/// Open a governed SUBPROCESS pipe. Decodes + allowlist-checks the command, spawns the child with piped
/// stdio, registers the backend + the arena closer, and writes an [`EgressOpen`] whose `pipe` is the
/// duplex [`PipeId`]. Called from [`super::egress::egress_open`] for [`EgressKind::Subprocess`]; the
/// caller owns the `catch_unwind` and the null checks.
pub(super) fn open_subprocess(
    state: &HostState,
    d: &EgressDesc,
    program_allowlist: &[String],
    out: *mut MaybeUninit<EgressOpen>,
) -> StatusClass {
    // SAFETY: `(target_ptr, target_len)` is a live borrowed range for the call (ABI discipline).
    let Some((program, argv)) = (unsafe { decode_command(d.target_ptr, d.target_len) }) else {
        return StatusClass::Refused;
    };
    if !command_admissible(&program, program_allowlist) {
        // Not absolute, or not on the HOST program allowlist. The FFI seam passes an empty allowlist,
        // so this REFUSES every plane-driven subprocess spawn (FFI-F3).
        return StatusClass::Refused;
    }
    // THE CHILD'S ENVIRONMENT, resolved host-side and applied under `env_clear()` so the child gets
    // ONLY these variables — NEVER the host's own environment, which holds provider API keys, store
    // credentials and admin tokens. Inheriting them (as this path once did) would make every governed
    // subprocess a silent credential-exfiltration primitive; clearing first is the fix the in-process
    // stdio transport already applies, restated at the seam. A malformed record or an unresolvable
    // secret refuses the spawn rather than starting the child with a missing variable.
    // SAFETY: `(env_ptr, env_len)`, when present, is a live borrowed range for the call (ABI).
    let env = match unsafe {
        resolve_child_env(
            read_sized_field!(d, EgressDesc, env_ptr).unwrap_or(std::ptr::null()),
            read_sized_field!(d, EgressDesc, env_len).unwrap_or(0),
        )
    } {
        EnvOutcome::Ready(env) => env,
        EnvOutcome::Refuse => return StatusClass::Refused,
    };
    // The working directory (empty ⇒ inherit the host's own) and the stderr disposition (default
    // discard; inherit sends the child's diagnostics to the host's stderr where an operator reads
    // them), both read only behind the sized-struct guard so a sender that predates the tail keeps the
    // pre-enrichment shape (an empty environment, the host's cwd, a discarded stderr).
    let cwd = read_child_cwd(d);
    let stderr = if read_sized_field!(d, EgressDesc, stderr_inherit) == Some(1) {
        Stdio::inherit()
    } else {
        Stdio::null()
    };
    // NO SHELL: the program goes to `Command::new` and argv as a vector — never a shell string, so a
    // metacharacter in an arg has no meaning.
    let mut builder = Command::new(&program);
    builder
        .args(&argv)
        // THE WHOLE environment, not additions to the host's — `env_clear()` first, then only the
        // resolved records. See the note above.
        .env_clear()
        .envs(env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(stderr);
    if let Some(dir) = &cwd {
        builder.current_dir(dir);
    }
    let child = builder.spawn();
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
            resp_headers_ptr: std::ptr::null(), // a raw byte channel surfaces no response headers.
            resp_headers_len: 0,
            client_identity_offered: 0, // a raw byte channel offers no client identity.
            _reserved4: [0; 7],
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
pub(crate) extern "C-unwind" fn pipe_write(
    host: HostCtx,
    pipe: PipeId,
    buf: *const u8,
    len: usize,
) -> StatusClass {
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
