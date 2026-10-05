// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! M6-COLD-DELETE RESIDUE: the one JSON-lane path that has not moved yet, and nothing else.
//!
//! THE DESIGN's plugin ABI abolished the COLD/JSON lane: no store, secret, hook or export plugin
//! rides it. What is left here: the six `extern "C-unwind"` symbols, JSON over ptr+len, and one wire
//! — [`auth`]: the `kind: auth` plugin built on `export_login_plugin!` (its verify and its hosted
//! browser login, `identity-providers.<n>.browser_login`), until that plugin's door re-pin moves
//! both onto the auth door.
//!
//! It is deleted with the last plugin on it. Nothing new may ride this lane.

use std::os::raw::c_void;

pub mod auth;

/// The kind-neutral **TRANSPORT** ABI version, returned by a plugin's `busbar_abi()`. Frozen at 1:
/// this is the low-level linker contract (the six C signatures, ptr+len byte buffers, the
/// plugin-allocates/plugin-frees rule, the status codes). DISTINCT from the per-kind PAYLOAD schema
/// version (the signed manifest's `abi_version`), which bumps additively per kind. Bumping THIS is a
/// real, no-turning-back linker event — side-by-side migration, never a routine change.
pub const TRANSPORT_VERSION: u32 = 1;

/// The exported-symbol names the engine resolves after `dlopen`/`LoadLibrary`. A plugin of ANY kind
/// MUST export all SIX with these exact (kind-NEUTRAL) names and the signatures in the `*Fn` type
/// aliases below. NUL-terminated so they pass straight to `libloading`'s C-string symbol lookup. The
/// KIND a library speaks is read from [`symbol::PLUGIN_KIND`], not encoded in the symbol names.
pub mod symbol {
    /// `busbar_abi() -> u32` — the frozen TRANSPORT version handshake ([`super::TRANSPORT_VERSION`]).
    pub const ABI: &[u8] = b"busbar_abi\0";
    /// `busbar_plugin_kind() -> *const u8` — a NUL-terminated string, the ONE kind this lib speaks.
    pub const PLUGIN_KIND: &[u8] = b"busbar_plugin_kind\0";
    /// `busbar_open(cfg, cfg_len, out_handle, out_err, out_err_len) -> i32`.
    pub const OPEN: &[u8] = b"busbar_open\0";
    /// `busbar_call(handle, req, req_len, out, out_len) -> i32`.
    pub const CALL: &[u8] = b"busbar_call\0";
    /// `busbar_free(ptr, len)` — free a buffer the plugin allocated for the engine.
    pub const FREE: &[u8] = b"busbar_free\0";
    /// `busbar_close(handle)` — drop the instance.
    pub const CLOSE: &[u8] = b"busbar_close\0";
    /// `busbar_set_log_sink(sink, ctx)` — OPTIONAL, the only symbol here that is. See
    /// [`super::SetLogSinkFn`] for why its absence is not an error and not a transport bump.
    pub const SET_LOG_SINK: &[u8] = b"busbar_set_log_sink\0";
}

/// Severity for a record crossing [`LogSinkFn`]. Deliberately a plain `u32` rather than a Rust enum:
/// this crosses a C boundary between two independently-compiled objects, so it has to be a value
/// with a fixed representation. An unrecognized level is clamped by the host, never rejected — a
/// newer plugin inventing a level must not lose the message.
pub mod log_level {
    pub const ERROR: u32 = 1;
    pub const WARN: u32 = 2;
    pub const INFO: u32 = 3;
    pub const DEBUG: u32 = 4;
    /// Distinct from [`DEBUG`] on purpose. Folding the two together destroys the level in transit,
    /// so a host running at DEBUG could not filter plugin TRACE back out.
    pub const TRACE: u32 = 5;
    /// "Emit nothing." What the host passes when its own subscriber is disabled entirely, so the
    /// plugin can skip building a record no one will read.
    pub const OFF: u32 = 0;
}

/// The host-side callback a plugin invokes to emit one log record.
///
/// `ctx` is the opaque pointer the host supplied alongside this fn — a plain fn pointer carries no
/// captured state, so the host needs it to know WHICH plugin is talking. The plugin passes it back
/// verbatim and must never interpret or free it.
///
/// `extern "C"`, NOT `"C-unwind"`: this is the host's code called FROM the plugin, and a panic
/// unwinding out of it into a differently-compiled object is undefined behaviour. The host catches
/// its own panics inside.
///
/// `msg` is UTF-8, `msg_len` bytes, borrowed for the duration of the call only. The host copies
/// anything it keeps.
pub type LogSinkFn =
    unsafe extern "C" fn(ctx: *mut c_void, level: u32, msg: *const u8, msg_len: usize);

/// `busbar_set_log_sink` — the host hands the plugin somewhere to send its diagnostics.
///
/// WHY THIS EXISTS. A plugin is a cdylib that statically links its OWN copy of `tracing-core`, so it
/// gets its own dispatcher, and nothing bridges that to the host's. Every `tracing::warn!` inside a
/// loaded plugin was therefore discarded — including auth-oidc's on a FAILED TOKEN SIGNATURE
/// VERIFICATION, which is precisely the line an operator needs. Plugins worked around it with
/// `eprintln!`, which does reach the shared stderr, but bypasses the host's subscriber entirely: no
/// level filtering, no structured fields, no OTLP export, and nothing tying the line to which plugin
/// emitted it.
///
/// WHY IT IS NOT A TRANSPORT BUMP. [`TRANSPORT_VERSION`] covers the SIX required signatures and the
/// ptr+len rule; this is a SEVENTH, OPTIONAL symbol and none of the six change. The loader looks it
/// up and simply does not call it when absent, so an existing signed artifact keeps loading and
/// behaving exactly as before. Same reasoning already applied to adding `STATUS_UNSUPPORTED` /
/// `STATUS_PANIC`.
///
/// CALLED ONCE, immediately after a successful `busbar_open`, before any `busbar_call`. The sink must
/// remain valid for the life of the plugin and may be invoked from ANY thread, so a plugin storing it
/// needs a `Sync` cell.
/// `max_level` is the HOST's own maximum enabled level (a [`log_level`] constant), so the plugin can
/// filter on ITS side of the boundary. That direction matters: a plugin's dispatcher would otherwise
/// claim interest in everything, and every `trace!`/`debug!` in the plugin's whole dependency tree
/// (its SQL driver, its HTTP stack) would render a string and cross this call on the REQUEST PATH
/// only for the host to drop it. Sampled once at load; a host whose level changes later keeps
/// working, it just filters a little coarsely until the next load.
pub type SetLogSinkFn =
    unsafe extern "C-unwind" fn(sink: LogSinkFn, ctx: *mut c_void, max_level: u32);

/// The hard cap on a single response/error buffer a plugin returns, checked BEFORE allocation on both
/// sides. Defense against a buggy/hostile plugin handing back a huge length to OOM the engine. 256 MiB
/// is orders of magnitude past any real governance/auth payload, so a legitimate reply never trips it.
pub const MAX_PLUGIN_RESPONSE_LEN: usize = 256 * 1024 * 1024;

/// Status returned by `open`/`call`. The four positive/neutral codes below are DISTINCT signals the
/// loader keys different behavior on; they are never overloaded. See each const.
///
/// TRANSPORT is FROZEN at [`TRANSPORT_VERSION`] = 1: adding [`STATUS_UNSUPPORTED`]/[`STATUS_PANIC`] is
/// NOT a transport bump — the six signatures, the ptr+len rule, and the meanings of `OK`/`ERR` are
/// unchanged; `PROTOCOL` merely stops being overloaded and two positive codes are added. A v1-era SDK
/// plugin that predates these still returns `STATUS_PROTOCOL` WITH a `"malformed request JSON: …"`
/// body for an undecodable variant; the loader keys its legacy-shape acceptance on exactly that body
/// (see `plugin-loader`'s `LEGACY_V1_UNDECODABLE_PREFIX`), never on the status alone.
///
/// `OK`: the out buffer holds the success payload.
pub const STATUS_OK: i32 = 0;
/// A DEFINED backend failure — the out buffer holds a UTF-8 error message. The op RAN and returned an
/// error (a [`crate::records::RecordStoreError`]/`SecretError`/… rendered). Propagated by the loader.
pub const STATUS_ERR: i32 = 1;
/// A caller-PROTOCOL violation the plugin detected BEFORE running user code: a null handle, a null
/// request buffer with `len > 0`, a garbled ABI frame. No user code ran, so the out buffer stays
/// EMPTY. Propagated, never a fallback signal.
///
/// Value is negative for backward wire compatibility with the v1-era SDK, which overloaded this code.
/// The two v1 uses are told apart by the OUT BUFFER, and the direction matters: a v1 undecodable
/// request variant wrote `"malformed request JSON: …"` into the buffer (→ the loader's legacy
/// unsupported signal, see [`STATUS_UNSUPPORTED`]), whereas a v1 CAUGHT PANIC returned this status
/// bare, with NO buffer — exactly like a null handle. So an EMPTY buffer is never the unsupported
/// signal; reading it as one re-opens the revocation fail-open [`STATUS_PANIC`] exists to close.
pub const STATUS_PROTOCOL: i32 = -1;
/// The plugin could not DECODE this request variant — an older SDK build that predates the op. A
/// forward-compat signal the loader MAY treat as "op unsupported by this build" and fall back to a
/// safe default WHERE a fallback is defined (denylist/audit-tail/append-audit). NEVER emitted for a
/// panic or a backend failure — that distinction is what closes the revocation fail-open. Out buffer =
/// UTF-8 message.
pub const STATUS_UNSUPPORTED: i32 = 2;
/// User code PANICKED and was caught at the export boundary. A REAL failure that MUST propagate — it is
/// explicitly NOT the unsupported signal, so a plugin panic can never open the safe-default fallback
/// (the revocation-denylist fail-open is closed by this distinction). Out buffer = UTF-8 message.
pub const STATUS_PANIC: i32 = 3;

// ── C fn-pointer signatures the engine resolves ──────────────────────────────────────────────────
// Provided as type aliases so the engine's loader and the plugin's SDK agree on the exact ABI. All
// are `unsafe extern "C-unwind"`. Buffers the plugin allocates (the `out*` params) are owned by the
// engine until it calls `busbar_free` on them.
//
// WHY `"C-unwind"` (not plain `"C"`): under the workspace default `panic = "unwind"`, a Rust panic
// that tries to unwind OUT OF a plain `extern "C"` function is turned by the compiler into an
// immediate ABORT at the callee (plugin) frame — it never reaches the caller, so the engine's
// `catch_unwind` at the call site can NEVER intercept it and a panicking plugin aborts the whole
// gateway. `extern "C-unwind"` makes unwinding across this boundary DEFINED: a panic propagates as a
// forced unwind that the engine's `catch_unwind` DOES catch, turning a panicking plugin into a clean
// fail-closed error instead of a process abort. This is the load-bearing half of the panic-safety
// seam; the engine wraps every call site (open/call/close/free/handshake) in `catch_unwind` (see the
// loader), and non-`"C-unwind"` C/Go/Zig plugins still abort on unwind exactly as before (their
// runtimes don't unwind), which is the pre-existing, documented behavior for non-Rust plugins.

/// `busbar_abi` — returns the [`TRANSPORT_VERSION`] the plugin was built against.
pub type AbiFn = unsafe extern "C-unwind" fn() -> u32;

/// `busbar_plugin_kind` — returns a pointer to a NUL-terminated static string naming the ONE kind
/// this library speaks: `"store"` | `"secret"` | `"auth"` | `"hook"` | `"export"` (the full set is
/// [`kind`]).
///
/// The return carries NO LENGTH: the engine reads it with `CStr::from_ptr` and walks to the first
/// NUL byte. A pointer into a non-NUL-terminated buffer is therefore an unbounded out-of-bounds read
/// in the ENGINE's address space — undefined behavior, not a load error. So the pointer MUST come
/// from a NUL-terminated static, never from the plain `kind::STORE.as_ptr()` (a `&str`, which has
/// no terminator). Plugins built on `busbar-plugin-sdk` get the safe form from `export_plugin!` and
/// never write this by hand.
pub type PluginKindFn = unsafe extern "C-unwind" fn() -> *const u8;

/// `busbar_open` — construct an instance from a JSON config blob. On `STATUS_OK`, `*out_handle` is
/// the opaque instance pointer (passed back to `call`/`close`). On `STATUS_ERR`, `*out_err` /
/// `*out_err_len` hold a UTF-8 message the engine must `free`.
pub type OpenFn = unsafe extern "C-unwind" fn(
    cfg: *const u8,
    cfg_len: usize,
    out_handle: *mut *mut c_void,
    out_err: *mut *mut u8,
    out_err_len: *mut usize,
) -> i32;

/// `busbar_call` — run one request (JSON in `req`). On `STATUS_OK`, `*out`/`*out_len` hold the JSON
/// response; on `STATUS_ERR`, a UTF-8 error message. Either way the engine owns and must `free` the
/// out buffer.
pub type CallFn = unsafe extern "C-unwind" fn(
    handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32;

/// `busbar_free` — release a buffer the plugin allocated (`open`'s error, `call`'s payload). The
/// plugin frees with the SAME allocator it allocated with — the engine never frees plugin memory.
pub type FreeFn = unsafe extern "C-unwind" fn(ptr: *mut u8, len: usize);

/// `busbar_close` — drop the instance behind `handle`. Called once, at shutdown/unload.
pub type CloseFn = unsafe extern "C-unwind" fn(handle: *mut c_void);

/// A cold-lane plugin's boundary, LINKED rather than dropped in: the SAME functions its `cdylib`
/// exports under the [`symbol`] names, referenced where the loader would otherwise look them up.
///
/// DECISIONS #2 rule (1): a plugin is compiled in OR dropped in over one contract and one loading
/// path. For the cold kinds that contract IS these functions and the JSON they carry, so a linked
/// plugin hands the loader exactly what `dlsym` would have found, and the loader runs the one load it
/// runs for a library (transport handshake, kind cross-check, log bridge, `open`) over it. Nothing on
/// the far side of the boundary can tell which door it came in by. The SDK's export macro emits one
/// beside the symbols (`BUSBAR_COLD_ENTRY`), so every SDK-built plugin is linkable by construction.
#[derive(Clone, Copy)]
pub struct ColdEntry {
    /// [`symbol::ABI`].
    pub abi: AbiFn,
    /// [`symbol::PLUGIN_KIND`].
    pub kind: PluginKindFn,
    /// [`symbol::SET_LOG_SINK`] — optional on the dropped-in door, always present on this one. A
    /// linked plugin shares the host's `tracing` dispatcher, so what this installs is the sink its
    /// explicit log records take, never a forwarder of the host's own events back into itself.
    pub set_log_sink: SetLogSinkFn,
    /// [`symbol::OPEN`].
    pub open: OpenFn,
    /// [`symbol::CALL`].
    pub call: CallFn,
    /// [`symbol::FREE`].
    pub free: FreeFn,
    /// [`symbol::CLOSE`].
    pub close: CloseFn,
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
