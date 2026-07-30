// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Runtime loading of a durable-store backend from a **dynamic library** (`.so`/`.dll`/`.dylib`) over
//! the busbar store C ABI ([`busbar_plugin_abi`]).
//!
//! This is the engine side of "drop a plugin in the folder and it works": [`load_store`] opens a
//! library with `libloading` (portable `dlopen`/`LoadLibrary`), checks the ABI-version handshake,
//! calls the plugin's `open` with the JSON config, and returns a [`DynStore`] — a `Box<dyn Store>` any
//! governance code can use exactly like the compiled-in [`busbar_store_memory::MemoryStore`]. Every
//! `Store` call is serialized to JSON and shipped across the C boundary; because the store is
//! write-behind (off the request hot path), that serialize never touches request latency.
//!
//! The loaded library is kept alive inside the `DynStore` for as long as the store lives — unloading
//! it while the handle is in use would dangle — and the handle is `close`d before the library drops.
//!
//! For the TRUSTED load path, [`load_store_from_bytes`] takes the already-verified library BYTES (not
//! a path) so the bytes that were hash/signature-checked are byte-for-byte the bytes loaded — closing
//! the time-of-check/time-of-use gap a `verify(path)` + `dlopen(path)` pair would leave open.

use busbar_api::{
    AuditRecord, AwsCredential, MeteringDelta, MeteringRow, Store, StoreError, StoreResult,
    UsageDelta, UsageLedger, VirtualKey,
};
use busbar_plugin_abi::{
    kind as abi_kind, symbol, CallFn, CloseFn, FreeFn, PluginKindFn, StoreRequest, StoreResponse,
    MAX_PLUGIN_RESPONSE_LEN, STATUS_ERR, STATUS_OK, STATUS_PANIC, STATUS_PROTOCOL,
    STATUS_UNSUPPORTED, TRANSPORT_VERSION,
};
use libloading::Library;
use std::os::raw::c_void;
use std::path::Path;

pub mod auth;
pub mod hook;
pub mod registry;
mod stage;
pub mod tarball;

pub use auth::DynAuth;
pub use hook::DlopenPolicy;
pub use registry::{
    inventory as inventory_tarballs, scan_and_validate, supported_abi, InventoryEntry,
    LoadablePlugin, PluginRegistry, SkippedPlugin,
};
pub use stage::sweep_dead_staging;

/// INTERN a plugin name into a stable `&'static str`, reusing one allocation per unique name (L1).
///
/// `DlopenPolicy`/`DynAuth` carry `name: &'static str`, and a name string used to be `Box::leak`ed on
/// EVERY open — but `open_hook`/`open_auth` run per config/plugin reload, per `push_configure`, per
/// `fetch_status` (every Prometheus `/metrics/hooks` scrape refresh), per `fetch_schema`, and per
/// `resolve_on_error_chain`, so the leak was per-CALL and unbounded over the process lifetime, driven
/// by routine external scraping. Interning bounds it to ONE leak per DISTINCT plugin name for the life
/// of the process: a repeated open of the same plugin reuses the interned `&'static str`.
pub(crate) fn intern_name(name: &str) -> &'static str {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static INTERNED: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let set = INTERNED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = set.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(existing) = guard.get(name) {
        return existing;
    }
    // First sighting of this name: leak it ONCE, then remember it so future opens reuse this alloc.
    let leaked: &'static str = Box::leak(name.to_string().into_boxed_str());
    guard.insert(leaked);
    leaked
}

/// Run an FFI call `f` across the plugin ABI boundary under `catch_unwind`, converting a plugin panic
/// into a fail-closed `Err` string instead of a process abort. EFFECTIVE only because the ABI fn
/// pointers are `extern "C-unwind"` (see [`busbar_plugin_abi`]): a Rust plugin's panic unwinds as a
/// DEFINED forced unwind that lands here; a plain `extern "C"` boundary would have aborted at the
/// plugin frame BEFORE returning. `op` names the crossing (`open`/`call`/`close`/`free`/`abi`/`kind`)
/// for the diagnostic. Every host-side ABI call site routes through this so no crossing is unguarded.
fn ffi_guard<R>(path: &str, op: &str, f: impl FnOnce() -> R) -> Result<R, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|_| {
        format!("plugin '{path}' panicked across the ABI boundary in {op} (treated as failure)")
    })
}

/// Call the plugin's `busbar_free` on `(ptr, len)` under a panic guard. A panicking `free` is logged
/// and swallowed (the buffer is leaked rather than aborting the engine) — free runs on the request hot
/// path and on error/cleanup paths where an abort would be the worst possible outcome.
fn free_guarded(free: busbar_plugin_abi::FreeFn, path: &str, ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    if ffi_guard(path, "free", || unsafe { free(ptr, len) }).is_err() {
        // A leaked buffer is strictly better than aborting the whole gateway on a bad plugin `free`.
        tracing::warn!(
            plugin = %path,
            "plugin busbar_free panicked; leaking the buffer to keep the engine alive"
        );
    }
}

/// The resolved core C fn pointers + the opaque handle + the mapped library + staging backing, shared
/// by every kind's typed wrapper. The KIND is bound at construction (cross-checked against the signed
/// manifest) and then carried by the typed `DynStore`/`DynSecret`/`DynAuth`.
struct RawPlugin {
    handle: *mut c_void,
    call: CallFn,
    free: FreeFn,
    close: CloseFn,
    /// The plugin name/path, for diagnostics.
    path: String,
    /// The mapped library. Declared BEFORE `_backing` so it drops FIRST (fields drop in declaration
    /// order, AFTER `Drop::drop` closes the handle) — the UNLOAD-then-REMOVE order Windows requires.
    _lib: Library,
    /// The staging backing (Linux memfd / private-temp file) for a from-bytes load; `None` for a path
    /// load. MUST drop after `_lib`.
    _backing: Option<stage::Staged>,
}

// SAFETY: every kind's backend is a `Box<dyn Trait>` the trait contract requires to be `Send + Sync`;
// the handle is an opaque pointer to it and the raw fn pointers are plain code addresses.
unsafe impl Send for RawPlugin {}
unsafe impl Sync for RawPlugin {}

impl RawPlugin {
    /// The ONE generic transport primitive: serialize `req`, ship it across the kind-neutral `call`,
    /// cap-check + copy + free the response buffer, and decode it as `Resp`. Replaces the duplicated
    /// per-kind wire calls — store, secret, and auth all go through this; only the TYPES differ.
    pub(crate) fn transport_call<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
        &self,
        req: &Req,
    ) -> Result<Resp, String> {
        // Every existing caller wants only the message; the numeric ABI status is an internal detail
        // they discard. The status-aware variant below preserves it for the ONE caller (denylist
        // hydrate) that must distinguish an OLD-SDK unsupported-variant signal from a real error.
        self.transport_call_status(req).map_err(|e| e.message)
    }

    /// The status-preserving transport primitive. Identical wire behavior to [`transport_call`] but on
    /// failure returns the numeric ABI `status` alongside the message, so a caller can key a decision
    /// on the OUT-OF-BAND status (e.g. [`STATUS_PROTOCOL`] = "this plugin cannot decode this request
    /// variant") rather than on the plugin-controlled body TEXT. On the OK path the numeric status is
    /// irrelevant (the buffer is the decoded response) and never surfaced.
    pub(crate) fn transport_call_status<
        Req: serde::Serialize,
        Resp: serde::de::DeserializeOwned,
    >(
        &self,
        req: &Req,
    ) -> Result<Resp, TransportError> {
        let payload = serde_json::to_vec(req)
            .map_err(|e| TransportError::engine(format!("plugin request encode failed: {e}")))?;
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        // Catch any panic that unwinds across the `busbar_call` ABI boundary, for PARITY with the
        // hook seam (`DlopenPolicy::call`). SDK-built plugins catch panics plugin-side, but a signed
        // third-party (trust=signature, in-process) plugin NOT built with the busbar SDK that panics
        // outside a caught region would otherwise unwind across the boundary. This `catch_unwind` is
        // EFFECTIVE because the ABI fn-pointer types are `extern "C-unwind"` (plugin-abi): the unwind is
        // DEFINED and propagates here to be caught, rather than aborting at the plugin frame (which
        // plain `extern "C"` would force). All kinds (store/secret/auth) route their FFI call through
        // here, so this is the single seam that fails such a plugin CLOSED instead of aborting the
        // engine. (Non-Rust C/Go/Zig plugins don't unwind, so they still abort — unchanged.)
        let status = match ffi_guard(&self.path, "call", || unsafe {
            (self.call)(
                self.handle,
                payload.as_ptr(),
                payload.len(),
                &mut out,
                &mut out_len,
            )
        }) {
            Ok(s) => s,
            Err(e) => {
                // The plugin may have written a non-null `*out` BEFORE it panicked (a partial write is
                // undefined by the ABI but a misbehaving plugin can do it). The `?` here would skip the
                // `free_guarded` below and leak that buffer; free it on the caught-panic path so the
                // fail-closed seam does not also leak. `free_guarded` is null-safe.
                free_guarded(self.free, &self.path, out, out_len);
                return Err(TransportError::engine(e));
            }
        };
        // Cap-reject BEFORE reading; still hand the buffer back to the plugin to free (it owns it).
        if let Err(msg) = response_len_ok(out_len, &self.path) {
            free_guarded(self.free, &self.path, out, out_len);
            return Err(TransportError::engine(msg));
        }
        let bytes = if out.is_null() || out_len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(out, out_len) }.to_vec()
        };
        free_guarded(self.free, &self.path, out, out_len);
        if status == STATUS_OK {
            serde_json::from_slice(&bytes)
                .map_err(|e| TransportError::engine(format!("plugin response decode failed: {e}")))
        } else {
            // Classify the plugin-returned `status` into a SEMANTIC kind OUT OF BAND. The fallback
            // decision keys on the kind, never on a bare status integer, and a caught PANIC
            // (STATUS_PANIC) classifies to `Fault` — so a plugin crash can never open the safe-default
            // fallback. See `TransportError::from_status` for the legacy-v1 STATUS_PROTOCOL rule.
            let body = String::from_utf8_lossy(&bytes);
            Err(TransportError::from_status(status, &body, &self.path))
        }
    }
}

/// A failed transport `call`, carrying a SEMANTIC [`TransportErrorKind`] alongside the human message.
/// The kind is the out-of-band signal a caller keys on (never the plugin-controlled body text): only a
/// deliberate [`TransportErrorKind::Unsupported`] opens a safe-default fallback; a caught panic, a
/// backend error, a caller-protocol violation, and every engine-internal failure classify to kinds that
/// are explicitly NOT unsupported and always propagate. This is the revocation-denylist fail-open,
/// closed BY CONSTRUCTION.
pub(crate) struct TransportError {
    /// The semantic classification a loader caller keys on (see [`TransportErrorKind`]).
    pub(crate) kind: TransportErrorKind,
    /// The human-readable failure message (plugin body on a plugin error, engine text otherwise).
    pub(crate) message: String,
}

/// The SEMANTIC classification a loader caller keys on — never a bare integer, never body text.
pub(crate) enum TransportErrorKind {
    /// The plugin returned [`STATUS_UNSUPPORTED`], or the LEGACY v1-SDK decode-failure shape (a
    /// [`STATUS_PROTOCOL`] whose body starts with [`LEGACY_V1_UNDECODABLE_PREFIX`]): the op is not
    /// implemented by this plugin build. The ONLY kind that enables a safe-default fallback.
    Unsupported,
    /// The plugin returned [`STATUS_ERR`]: a real backend failure. Propagate.
    Backend,
    /// The plugin returned [`STATUS_PANIC`], an unknown status, or an engine-side
    /// encode/decode/cap/ffi-panic. A real failure that is explicitly NOT unsupported. Propagate — and
    /// it can NEVER masquerade as [`Self::Unsupported`], so a plugin panic cannot open the fallback.
    Fault,
    /// The plugin returned [`STATUS_PROTOCOL`] for a caller-protocol violation: a null handle, a null
    /// request pointer, or — from an SDK predating [`STATUS_PANIC`] — a caught panic. Every one of
    /// these arrives with an EMPTY out buffer. Propagate.
    Protocol,
}

/// The out-buffer prefix the v1 SDK wrote when it could not decode the request enum — the ONE shape a
/// plugin predating [`STATUS_UNSUPPORTED`] used to say "I do not know this variant".
///
/// EVERY generation of the v1 SDK spelled the request-decode failure
/// `Err((format!("malformed request JSON: {e}"), /* protocol */ true))` and then `write_buf`'d that
/// message alongside `STATUS_PROTOCOL`. So the legacy unsupported signal is a NON-EMPTY
/// `STATUS_PROTOCOL` carrying this prefix.
///
/// The inverse — an EMPTY-buffer `STATUS_PROTOCOL` — is what a null handle, a null request pointer,
/// and (in an SDK predating [`STATUS_PANIC`]) a CAUGHT PANIC produce: those paths `return
/// STATUS_PROTOCOL` before any `write_buf`. Treating the empty buffer as the legacy signal therefore
/// had the discriminator exactly BACKWARDS: it re-opened the revocation fail-open (a pre-`STATUS_PANIC`
/// store plugin that panicked inside `list_denylist` hydrated an EMPTY denylist, accepting every
/// revoked token again) while the interop it was meant to provide never fired, because a genuine v1
/// decode failure returns a non-empty body and was classified as a hard protocol violation.
///
/// The current SDK never pairs `STATUS_PROTOCOL` with a buffer at all (`boundary::call_boundary`
/// returns the bare status before any user code runs), so this prefix cannot collide with anything a
/// current-generation plugin emits.
pub(crate) const LEGACY_V1_UNDECODABLE_PREFIX: &str = "malformed request JSON:";

impl TransportError {
    /// Classify a plugin-returned `status` + response `body` into a semantic kind, and build the human
    /// message. Only two shapes are the unsupported signal: the crisp [`STATUS_UNSUPPORTED`], and the
    /// legacy v1 decode failure (a [`STATUS_PROTOCOL`] whose body starts with
    /// [`LEGACY_V1_UNDECODABLE_PREFIX`]). A caught panic, a backend error, a bare `STATUS_PROTOCOL`,
    /// and an unknown status all classify to kinds that are explicitly NOT unsupported and always
    /// propagate.
    fn from_status(status: i32, body: &str, path: &str) -> Self {
        let kind = match status {
            STATUS_UNSUPPORTED => TransportErrorKind::Unsupported,
            STATUS_ERR => TransportErrorKind::Backend,
            STATUS_PANIC => TransportErrorKind::Fault,
            // v1 interop, keyed on the shape the v1 SDK ACTUALLY emits — never on an empty buffer,
            // which is the caller-protocol / legacy-panic shape.
            STATUS_PROTOCOL if body.starts_with(LEGACY_V1_UNDECODABLE_PREFIX) => {
                TransportErrorKind::Unsupported
            }
            STATUS_PROTOCOL => TransportErrorKind::Protocol,
            _ => TransportErrorKind::Fault, // unknown status ⇒ fault, never unsupported
        };
        let message = if body.is_empty() {
            format!("plugin '{path}' call failed (status {status})")
        } else {
            body.to_string()
        };
        TransportError { kind, message }
    }

    /// An ENGINE-side failure (encode/decode/panic/cap) — NOT a status the plugin chose. ALWAYS
    /// [`TransportErrorKind::Fault`], so it can never be mistaken for the old-SDK unsupported signal.
    fn engine(message: String) -> Self {
        TransportError {
            kind: TransportErrorKind::Fault,
            message,
        }
    }

    /// Whether this failure is the "unsupported request variant" signal: the plugin could not decode
    /// the request enum because it predates the variant. CANNOT be produced by a panic — a current-SDK
    /// panic is [`STATUS_PANIC`] (Fault) and a v1-SDK panic is a bare [`STATUS_PROTOCOL`] (Protocol),
    /// so neither can open a safe-default fallback.
    fn is_unsupported(&self) -> bool {
        matches!(self.kind, TransportErrorKind::Unsupported)
    }
}

impl Drop for RawPlugin {
    fn drop(&mut self) {
        // Guard `busbar_close` against a panicking plugin destructor. This runs on the hot-reload
        // path (the OLD instance drops as its last in-flight request drains) and at clean shutdown; a
        // panic here in a plain `extern "C"` `drop` would double-panic → unconditional abort. With the
        // `extern "C-unwind"` ABI the unwind is defined and caught here, so a bad backend `Drop`
        // degrades to a logged warning + leaked handle instead of tearing down the whole gateway.
        let close = self.close;
        let handle = self.handle;
        if ffi_guard(&self.path, "close", || unsafe { close(handle) }).is_err() {
            tracing::warn!(
                plugin = %self.path,
                "plugin busbar_close panicked during drop; leaking the handle to keep the engine alive"
            );
        }
    }
}

/// Resolve + validate a mapped library against the frozen contract (transport version, kind symbol ==
/// `expected_kind` == the signed-manifest kind), then `open` it and assemble a [`RawPlugin`]. Shared
/// by every kind's `wire_up_*`. `manifest_kind` is the trust-verified signed-manifest `kind` that the
/// exported `busbar_plugin_kind()` is cross-checked against (mismatch = hard fail-closed load error).
fn wire_up_raw(
    lib: Library,
    cfg_json: &str,
    display: String,
    expected_kind: &str,
    manifest_kind: &str,
    backing: Option<stage::Staged>,
) -> Result<RawPlugin, String> {
    // Hold the mapped library + its staged backing in a guard whose fields drop in the CORRECT
    // order — `lib` BEFORE `backing` — so that on ANY early `?`/error return below the library is
    // UNLOADED before the staged file is removed (Windows refuses `remove_file` on a still-mapped DLL;
    // the inverted order silently leaked the orphan). Function parameters otherwise drop in REVERSE
    // declaration order (`backing` first), which is exactly the wrong order. On the success path we
    // `.disarm()` the guard to move both out into the `RawPlugin` (which has the same field order).
    struct LoadGuard {
        lib: Option<Library>,
        backing: Option<stage::Staged>,
    }
    impl LoadGuard {
        fn disarm(mut self) -> (Library, Option<stage::Staged>) {
            (self.lib.take().expect("lib present"), self.backing.take())
        }
    }
    impl Drop for LoadGuard {
        fn drop(&mut self) {
            // Explicit UNLOAD-then-REMOVE: drop the library first, then the staged backing.
            self.lib.take();
            self.backing.take();
        }
    }
    let guard = LoadGuard {
        lib: Some(lib),
        backing,
    };
    let lib = guard.lib.as_ref().expect("lib present");
    // ── 1. Transport handshake FIRST — refuse a non-matching transport before resolving open/call. ──
    // The `busbar_abi()` call runs plugin code, so it too rides `ffi_guard`: a plugin that panics in
    // its handshake fails the load CLOSED instead of aborting the engine during boot/reload.
    let transport = {
        let f = unsafe { lib.get::<busbar_plugin_abi::AbiFn>(symbol::ABI) }
            .map_err(|_| format!("'{display}' is not a busbar plugin (no busbar_abi symbol)"))?;
        ffi_guard(&display, "abi", || unsafe { (*f)() })?
    };
    if transport != TRANSPORT_VERSION {
        return Err(format!(
            "plugin '{display}' targets transport ABI v{transport}, engine speaks v{TRANSPORT_VERSION}"
        ));
    }

    // ── 2. Kind bound at load — read the exported kind, cross-check it against the seam AND the
    // signed manifest. Any disagreement is a hard fail-closed load error naming both. ──
    let exported_kind = read_plugin_kind(lib, &display)?;
    if exported_kind != expected_kind {
        return Err(format!(
            "plugin '{display}' exports kind '{exported_kind}' but is being loaded as '{expected_kind}'"
        ));
    }
    if exported_kind != manifest_kind {
        return Err(format!(
            "plugin '{display}' kind mismatch: exported symbol says '{exported_kind}', signed \
             manifest says '{manifest_kind}' — refusing to load"
        ));
    }

    // ── 3. Resolve the operational symbols (copied out as plain fn pointers; valid while mapped). ──
    let (open, call, free, close) = unsafe {
        let open = *lib
            .get::<busbar_plugin_abi::OpenFn>(symbol::OPEN)
            .map_err(|e| format!("plugin '{display}' missing busbar_open: {e}"))?;
        let call = *lib
            .get::<CallFn>(symbol::CALL)
            .map_err(|e| format!("plugin '{display}' missing busbar_call: {e}"))?;
        let free = *lib
            .get::<FreeFn>(symbol::FREE)
            .map_err(|e| format!("plugin '{display}' missing busbar_free: {e}"))?;
        let close = *lib
            .get::<CloseFn>(symbol::CLOSE)
            .map_err(|e| format!("plugin '{display}' missing busbar_close: {e}"))?;
        (open, call, free, close)
    };

    // ── 4. open: construct the instance from the JSON config. ──
    // Guarded: `busbar_open` runs plugin constructor code on every load (boot AND hot config-reload).
    // With the `extern "C-unwind"` ABI a panicking constructor unwinds here and fails the load CLOSED,
    // rather than aborting the whole gateway mid-reload.
    let mut handle: *mut c_void = std::ptr::null_mut();
    let mut err: *mut u8 = std::ptr::null_mut();
    let mut err_len: usize = 0;
    let status = match ffi_guard(&display, "open", || unsafe {
        open(
            cfg_json.as_ptr(),
            cfg_json.len(),
            &mut handle,
            &mut err,
            &mut err_len,
        )
    }) {
        Ok(s) => s,
        Err(e) => {
            // A plugin constructor that panics may have already written a non-null `*err` (or `*handle`
            // — but a leaked handle can only be reclaimed by `close`, and a plugin that panicked mid-open
            // has no valid instance to close, so we deliberately drop it). Free any err buffer it wrote
            // so the caught-panic fail-closed path does not leak. `free_guarded` is null-safe.
            free_guarded(free, &display, err, err_len);
            return Err(e);
        }
    };
    if status != STATUS_OK || handle.is_null() {
        let msg = if err.is_null() {
            format!("status {status}")
        } else if err_len == 0 {
            // LOW (audit): a non-null `err` with `err_len == 0` carries no message but is still an
            // allocation the plugin owns — free it (the old `err_len == 0` short-circuit leaked it).
            free_guarded(free, &display, err, err_len);
            format!("status {status}")
        } else if !open_err_is_readable(err.is_null(), err_len) {
            // The plugin declared an `err_len` this large as its OWN failure message — apply the
            // same cap `busbar_call` already applies to `out_len` via `response_len_ok` before its
            // `from_raw_parts` (`:181-188`). Skipping it here made a buggy plugin's `err_len` an
            // unsound `from_raw_parts` on an unchecked plugin-supplied length. Still free the
            // buffer (the plugin owns it) rather than reading it.
            free_guarded(free, &display, err, err_len);
            format!(
                "status {status} (error text omitted: {err_len} bytes exceeds the \
                 {MAX_PLUGIN_RESPONSE_LEN}-byte cap)"
            )
        } else {
            let m = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(err, err_len) })
                .into_owned();
            free_guarded(free, &display, err, err_len);
            m
        };
        return Err(format!("plugin '{display}' open failed: {msg}"));
    }
    // LOW (audit): on the SUCCESS path a well-behaved plugin leaves `err` null, but an ABI-violating
    // plugin may set a non-null `err` alongside `STATUS_OK`. Free it here rather than leaking it on
    // every load (the hot `fetch_status` → `open_hook` → `wire_up_raw` metrics-scrape path).
    free_guarded(free, &display, err, err_len);

    // Success: disarm the guard and move the library + backing into the RawPlugin (whose fields drop
    // in the same lib-before-backing order).
    let (lib, backing) = guard.disarm();
    Ok(RawPlugin {
        handle,
        call,
        free,
        close,
        path: display,
        _lib: lib,
        _backing: backing,
    })
}

/// Read `busbar_plugin_kind()` from a mapped library into an owned `String`.
fn read_plugin_kind(lib: &Library, display: &str) -> Result<String, String> {
    let f = unsafe { lib.get::<PluginKindFn>(symbol::PLUGIN_KIND) }.map_err(|_| {
        format!("'{display}' is not a busbar plugin (no busbar_plugin_kind symbol)")
    })?;
    // Guarded: `busbar_plugin_kind()` runs plugin code; a panic fails the load CLOSED, not an abort.
    let ptr = ffi_guard(display, "kind", || unsafe { (*f)() })?;
    if ptr.is_null() {
        return Err(format!("plugin '{display}' returned a null kind string"));
    }
    // SAFETY: the plugin contract requires a NUL-terminated 'static string.
    let cstr = unsafe { std::ffi::CStr::from_ptr(ptr as *const std::os::raw::c_char) };
    cstr.to_str()
        .map(str::to_string)
        .map_err(|_| format!("plugin '{display}' kind string is not valid UTF-8"))
}

/// A `Store` backend loaded from a dynamic library over the kind-neutral ABI. Wraps a [`RawPlugin`]
/// whose kind was bound to `store` at load, so every `Store` method is a typed `transport_call`.
pub struct DynStore {
    raw: RawPlugin,
}

impl DynStore {
    /// TEST-ONLY: the private staging file backing THIS instance, or `None` when the load touched no
    /// disk (Linux memfd, or a path load with no staging at all). Lets the staging-lifecycle tests
    /// assert on their own artifact instead of counting process-wide staging entries — see
    /// [`stage::Staged::temp_path`] for why the count was the wrong instrument.
    #[cfg(test)]
    pub(crate) fn staged_path(&self) -> Option<&std::path::Path> {
        self.raw
            ._backing
            .as_ref()
            .and_then(stage::Staged::temp_path)
    }

    /// Serialize a request, ship it across the kind-neutral C ABI, decode the response. A THIN wrapper
    /// over [`Self::call_raw_status`] (there is ONE transport path; a status-blind variant can't be
    /// accidentally used): it just discards the semantic kind and surfaces the message as a `StoreError`.
    fn call_raw(&self, req: StoreRequest) -> StoreResult<StoreResponse> {
        self.call_raw_status(req).map_err(|e| StoreError(e.message))
    }

    /// The status-preserving transport primitive: on failure returns a [`TransportError`] whose
    /// semantic [`TransportErrorKind`] a caller keys on (e.g. `is_unsupported()` for the denylist /
    /// audit-tail / append-audit safe-default fallbacks). Never keys on plugin-controlled body text.
    fn call_raw_status(&self, req: StoreRequest) -> Result<StoreResponse, TransportError> {
        self.raw
            .transport_call_status::<StoreRequest, StoreResponse>(&req)
    }

    /// THE ONE PLACE a store op is allowed a safe default when the plugin is too OLD to know the
    /// request variant. `extract` names the response variant the op expects; `on_unsupported` supplies
    /// the default for the [`TransportErrorKind::Unsupported`] case and NOTHING ELSE.
    ///
    /// Every op that tolerates an old plugin routes through here, so the fail-open surface is one
    /// function instead of four hand-written `match` arms — a fifth op cannot re-introduce the class by
    /// writing `Err(_) => <default>` (which would swallow a real backend error, a caught PANIC, and a
    /// caller-protocol violation, hydrating an empty denylist and re-accepting revoked tokens).
    fn call_with_legacy_default<T>(
        &self,
        req: StoreRequest,
        extract: impl FnOnce(StoreResponse) -> StoreResult<T>,
        on_unsupported: impl FnOnce() -> StoreResult<T>,
    ) -> StoreResult<T> {
        match self.call_raw_status(req) {
            Ok(resp) => extract(resp),
            Err(e) if e.is_unsupported() => on_unsupported(),
            Err(e) => Err(StoreError(e.message)),
        }
    }
}

/// Enforce [`MAX_PLUGIN_RESPONSE_LEN`] on a plugin-declared response length before the engine
/// allocates a buffer for it. Pure so the bound is unit-testable without a live plugin.
fn response_len_ok(out_len: usize, path: &str) -> Result<(), String> {
    if out_len > MAX_PLUGIN_RESPONSE_LEN {
        Err(format!(
            "plugin '{path}' returned an oversized response ({out_len} bytes, max \
             {MAX_PLUGIN_RESPONSE_LEN})"
        ))
    } else {
        Ok(())
    }
}

/// True when a `busbar_open` failure's plugin-declared `err_len` is safe to hand to
/// `from_raw_parts` — non-null, non-empty, and within [`MAX_PLUGIN_RESPONSE_LEN`]. Pure so the
/// bound is unit-testable without a live plugin, mirroring [`response_len_ok`]: `busbar_open`'s
/// `err_len` output is the same shape of plugin-supplied length as `busbar_call`'s `out_len`, but
/// historically skipped the cap `busbar_call` already applies before its own `from_raw_parts`.
fn open_err_is_readable(err_is_null: bool, err_len: usize) -> bool {
    !err_is_null && err_len > 0 && err_len <= MAX_PLUGIN_RESPONSE_LEN
}

/// The plugin returned a response variant that doesn't match the request — a contract violation.
fn unexpected(resp: StoreResponse) -> StoreError {
    StoreError(format!("plugin returned an unexpected response: {resp:?}"))
}

impl Store for DynStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        match self.call_raw(StoreRequest::PutKey(key.clone()))? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        match self.call_raw(StoreRequest::GetKey(id.to_string()))? {
            StoreResponse::Key(k) => Ok(k),
            other => Err(unexpected(other)),
        }
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        match self.call_raw(StoreRequest::ListKeys)? {
            StoreResponse::Keys(k) => Ok(k),
            other => Err(unexpected(other)),
        }
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        match self.call_raw(StoreRequest::DeleteKey(id.to_string()))? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        match self.call_raw(StoreRequest::GetUsage {
            bucket_id: bucket_id.to_string(),
            window_start,
        })? {
            StoreResponse::Usage(u) => Ok(u),
            other => Err(unexpected(other)),
        }
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        match self.call_raw(StoreRequest::PutUsage {
            bucket_id: bucket_id.to_string(),
            window_start,
            ledger: ledger.clone(),
        })? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        // `AddUsage` is part of the base wire (every plugin at this ABI knows it - there is no
        // "older SDK never learned this variant" fallback), so an error here is a REAL store error
        // and propagates: silently degrading the fleet-additive accumulate to a read-modify-write
        // against a live shared backend would be a correctness downgrade (lost updates), not a
        // compatibility bridge.
        match self.call_raw(StoreRequest::AddUsage {
            bucket_id: bucket_id.to_string(),
            window_start,
            delta: delta.clone(),
        })? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()> {
        match self.call_raw(StoreRequest::AddMetering(delta.clone()))? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        match self.call_raw(StoreRequest::ListMetering(bucket))? {
            StoreResponse::Metering(m) => Ok(m),
            other => Err(unexpected(other)),
        }
    }

    fn put_aws_credential(&self, cred: &AwsCredential) -> StoreResult<()> {
        match self.call_raw(StoreRequest::PutAwsCredential(cred.clone()))? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn put_key_with_aws_credential(
        &self,
        key: &VirtualKey,
        cred: &AwsCredential,
    ) -> StoreResult<()> {
        match self.call_raw(StoreRequest::PutKeyWithAwsCredential {
            key: key.clone(),
            cred: cred.clone(),
        })? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn list_aws_credentials(&self) -> StoreResult<Vec<AwsCredential>> {
        match self.call_raw(StoreRequest::ListAwsCredentials)? {
            StoreResponse::AwsCreds(c) => Ok(c),
            other => Err(unexpected(other)),
        }
    }

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        // A store predating this request variant means "this store has no durable audit". Audit
        // write-through is best-effort (the RAM ring still holds the entry), so for THAT case ONLY the
        // choke point returns `Ok(())` silently; every other failure propagates.
        self.call_with_legacy_default(
            StoreRequest::AppendAudit(entry.clone()),
            |r| match r {
                StoreResponse::Unit => Ok(()),
                other => Err(unexpected(other)),
            },
            || Ok(()),
        )
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        // Routed through the same choke point as its three siblings. This op used the status-BLIND
        // `call_raw`, so a store predating the durable-audit variant failed the whole restore instead
        // of reporting "no durable audit" — the mirror image of the `append_audit` asymmetry.
        self.call_with_legacy_default(
            StoreRequest::ListAudit,
            |r| match r {
                StoreResponse::Audit(a) => Ok(a),
                other => Err(unexpected(other)),
            },
            || Ok(Vec::new()),
        )
    }

    fn list_audit_tail(&self, limit: u64) -> StoreResult<Vec<AuditRecord>> {
        // A store predating this variant falls back to the trait default (`list_audit` +
        // tail-truncation) so restore still works: it just materializes the full list once before
        // truncating rather than bounding at the source. The fallback re-issues `list_audit`, which is
        // now itself status-aware — so a fault on the SECOND call surfaces too, instead of being
        // flattened into a bare `StoreError` by the status-blind path.
        self.call_with_legacy_default(
            StoreRequest::ListAuditTail(limit),
            |r| match r {
                StoreResponse::Audit(a) => Ok(a),
                other => Err(unexpected(other)),
            },
            || {
                let mut all = self.list_audit()?;
                let limit = limit as usize;
                if all.len() > limit {
                    all.drain(0..all.len() - limit);
                }
                Ok(all)
            },
        )
    }

    fn add_denylist(&self, sub: &str, reason: &str) -> StoreResult<()> {
        match self.call_raw(StoreRequest::AddDenylist {
            sub: sub.to_string(),
            reason: reason.to_string(),
        })? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn list_denylist(&self) -> StoreResult<Vec<String>> {
        // Revocation fail-open closure (D4). A store that cannot DECODE the `ListDenylist` request
        // variant hydrates an empty denylist rather than failing boot. Every OTHER failure — a real
        // backend error, a caught PANIC, a caller-protocol violation, an unexpected response variant —
        // PROPAGATES, so boot fails CLOSED rather than accepting previously-revoked signed tokens.
        //
        // The class rests entirely on `TransportError::from_status`: a current-SDK panic is
        // STATUS_PANIC (Fault) and a v1-SDK panic is a BARE STATUS_PROTOCOL (Protocol). Neither is
        // Unsupported, so no crash can reach this fallback.
        self.call_with_legacy_default(
            StoreRequest::ListDenylist,
            |r| match r {
                StoreResponse::Denylist(d) => Ok(d),
                other => Err(unexpected(other)),
            },
            || Ok(Vec::new()),
        )
    }
}

impl std::fmt::Debug for DynStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynStore")
            .field("path", &self.raw.path)
            .finish()
    }
}

// ── SECRET plugins (`kind: secret`) ─────────────────────────────────────────────────────────────

/// A [`busbar_api::SecretModule`] loaded from a dynamic library over the kind-neutral ABI. Wraps a
/// [`RawPlugin`] whose kind was bound to `secret` at load.
pub struct DynSecret {
    raw: RawPlugin,
}

impl busbar_api::SecretModule for DynSecret {
    fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
    ) -> busbar_api::SecretResult<Vec<u8>> {
        let req = busbar_plugin_abi::SecretRequest::Resolve {
            settings: settings.clone(),
        };
        match self
            .raw
            .transport_call::<_, busbar_plugin_abi::SecretResponse>(&req)
            .map_err(busbar_api::SecretError)?
        {
            busbar_plugin_abi::SecretResponse::Bytes(b) => Ok(b),
        }
    }
}

impl std::fmt::Debug for DynSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynSecret")
            .field("path", &self.raw.path)
            .finish()
    }
}

/// Load a SECRET module from EXACTLY the verified library `bytes` (the TOCTOU-safe entrypoint;
/// see [`load_store_from_bytes`] for the staging contract). `manifest_kind` is the trust-verified
/// signed-manifest `kind`, cross-checked against the library's exported `busbar_plugin_kind()`.
pub fn load_secret_from_bytes(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
    manifest_kind: &str,
) -> Result<Box<dyn busbar_api::SecretModule>, String> {
    let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
    let raw = wire_up_raw(
        lib,
        cfg_json,
        display.to_string(),
        abi_kind::SECRET,
        manifest_kind,
        Some(staged),
    )?;
    Ok(Box::new(DynSecret { raw }))
}

/// Load a store backend from the dynamic library at `lib_path`, passing `cfg_json` to its `open`.
///
/// Validates the ABI-version handshake before calling anything else (a library that isn't a busbar
/// store plugin, or targets a different ABI, is refused, never mis-called). Returns a ready
/// `Box<dyn Store>` or a human-readable error naming the failure.
pub fn load_store(lib_path: &Path, cfg_json: &str) -> Result<Box<dyn Store>, String> {
    let display = lib_path.display().to_string();
    // SAFETY: loading an operator-placed library is inherently trusted (its init code runs), exactly
    // like the SQLite this replaces was trusted when compiled in. The path comes from config/the
    // plugins dir, not the request path.
    let lib = unsafe { Library::new(lib_path) }
        .map_err(|e| format!("failed to load plugin '{display}': {e}"))?;
    // A bare path load has no signed manifest to cross-check; the seam's expected kind (`store`) is
    // the authority, so pass it as the manifest kind too (the exported-kind == expected-kind gate
    // still enforces the library is a store). The trust-verified from-bytes path is the real gate.
    let raw = wire_up_raw(
        lib,
        cfg_json,
        display,
        abi_kind::STORE,
        abi_kind::STORE,
        None,
    )?;
    Ok(Box::new(DynStore { raw }))
}

/// Load a store backend from EXACTLY the library `bytes` supplied — the TOCTOU-safe entrypoint.
///
/// The plugin pipeline verifies a plugin's hash/signature over the in-memory bytes it unpacked from
/// the signed tarball, then must load THOSE SAME bytes. Handing `load_store` a path would re-open a
/// file, leaving a window in which an attacker with write access could swap it between the
/// verify-read and the `dlopen` (a classic time-of-check/time-of-use gap). This function closes that
/// gap: the caller verifies the bytes ONCE and passes them here; the loader maps EXACTLY those bytes.
///
/// - **Linux**: `memfd_create` + `dlopen("/proc/self/fd/N")` — ZERO disk files, no path an attacker
///   could ever race.
/// - **macOS / Windows**: the verified bytes are written to a fresh `create_new` file inside a
///   per-process PRIVATE `0700` staging directory (`busbar-plugins-<pid>-<random>`) and loaded from
///   there. The staged file is throwaway output regenerated from the verified bytes on every load —
///   a pre-existing on-disk file is NEVER loaded. On clean shutdown the library is unloaded FIRST,
///   then the staged file removed; a crash's leftovers are removed by [`sweep_dead_staging`] at the
///   next boot. Residual (do not overstate): on these platforms the load is by PATH inside the
///   owner-created private dir, so only an attacker who already owns that dir (i.e. the same user)
///   could interfere; a hostile `TMPDIR` base remains the operator's responsibility.
///
/// `display` is a human label for diagnostics (typically the plugin's canonical name); `manifest_kind`
/// is the trust-verified signed-manifest `kind`, cross-checked against `busbar_plugin_kind()`.
pub fn load_store_from_bytes(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
    manifest_kind: &str,
) -> Result<Box<dyn Store>, String> {
    load_dyn_store_from_bytes(bytes, cfg_json, display, manifest_kind).map(|s| Box::new(s) as _)
}

/// [`load_store_from_bytes`] before the trait object boxes it away. Split out so the staging
/// lifecycle tests can reach [`DynStore::staged_path`] and assert on their OWN artifact; the public
/// entry point is this plus a `Box`.
fn load_dyn_store_from_bytes(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
    manifest_kind: &str,
) -> Result<DynStore, String> {
    let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
    let raw = wire_up_raw(
        lib,
        cfg_json,
        display.to_string(),
        abi_kind::STORE,
        manifest_kind,
        Some(staged),
    )?;
    Ok(DynStore { raw })
}

/// The platform-native filename for a store plugin built from `crate_name` (e.g. `store_sqlite_plugin`
/// → `libbusbar_store_sqlite_plugin.so` / `.dylib` / `busbar_...dll`). Used to resolve `store: <name>`
/// against the plugins directory.
pub fn plugin_library_filename(crate_snake: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        format!("{crate_snake}.dll")
    }
    #[cfg(target_os = "macos")]
    {
        format!("lib{crate_snake}.dylib")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        format!("lib{crate_snake}.so")
    }
}

/// Validate that a library is a busbar plugin the engine can speak to — it exports the TRANSPORT
/// handshake at a matching version, a supported kind, and all operational symbols — WITHOUT
/// constructing an instance (no `open`). Returns the transport ABI version. Used to vet an uploaded
/// artifact before writing it into the plugins directory, and to inventory the directory.
pub fn validate_plugin(lib_path: &Path) -> Result<u32, String> {
    let display = lib_path.display().to_string();
    // SAFETY: loading runs the library's init code — the same trust as loading it to serve, which is
    // itself the trust of compiling it in. The path is operator/admin-supplied, never request data.
    let lib = unsafe { Library::new(lib_path) }
        .map_err(|e| format!("failed to load plugin '{display}': {e}"))?;
    let transport = {
        let f = unsafe { lib.get::<busbar_plugin_abi::AbiFn>(symbol::ABI) }
            .map_err(|_| format!("'{display}' is not a busbar plugin (no busbar_abi symbol)"))?;
        ffi_guard(&display, "abi", || unsafe { (*f)() })?
    };
    if transport != TRANSPORT_VERSION {
        return Err(format!(
            "plugin '{display}' targets transport ABI v{transport}, engine speaks v{TRANSPORT_VERSION}"
        ));
    }
    // The exported kind must be one the engine supports (a range exists for it).
    let plugin_kind = read_plugin_kind(&lib, &display)?;
    if supported_abi(&plugin_kind).is_empty() {
        return Err(format!(
            "plugin '{display}' declares unsupported kind '{plugin_kind}'"
        ));
    }
    // Confirm the operational symbols resolve too, so a half-built library is caught here rather than
    // at first use.
    unsafe {
        lib.get::<busbar_plugin_abi::OpenFn>(symbol::OPEN)
            .map_err(|e| format!("plugin '{display}' missing busbar_open: {e}"))?;
        lib.get::<CallFn>(symbol::CALL)
            .map_err(|e| format!("plugin '{display}' missing busbar_call: {e}"))?;
        lib.get::<FreeFn>(symbol::FREE)
            .map_err(|e| format!("plugin '{display}' missing busbar_free: {e}"))?;
        lib.get::<CloseFn>(symbol::CLOSE)
            .map_err(|e| format!("plugin '{display}' missing busbar_close: {e}"))?;
    }
    Ok(transport)
}

/// One entry in a plugins-directory inventory: the library filename and whether it validated as a
/// busbar store plugin (with its ABI version, or the reason it didn't). Serialized by the admin
/// `GET /admin/plugins` endpoint.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PluginInfo {
    /// The library filename (not the full path).
    pub file: String,
    /// True when the library exports the store ABI at a version the engine speaks.
    pub valid: bool,
    /// The plugin's ABI version when `valid`.
    pub abi_version: Option<u32>,
    /// Why it didn't validate, when `!valid`.
    pub error: Option<String>,
}

/// Is `file` a dynamic-library name for this platform (by extension)?
fn is_library_file(file: &str) -> bool {
    let ext = if cfg!(target_os = "windows") {
        ".dll"
    } else if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    };
    file.ends_with(ext)
}

/// List the dynamic-library FILENAMES in `dir` (sorted), WITHOUT opening any of them - the pure,
/// side-effect-free directory scan. Unlike [`inventory`], this NEVER `dlopen`s a library, so an
/// untrusted plugin's init/constructor code cannot run just from enumerating the directory. The trust
/// gate (and only then the ABI [`validate_plugin`], which does `dlopen`) is applied by the caller,
/// per file, so no library's code runs until it passes trust. A missing directory is an empty list.
pub fn list_plugin_files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        if path.is_file() && is_library_file(file) {
            out.push(file.to_string());
        }
    }
    out.sort();
    out
}

/// Inventory the plugins directory: every dynamic library present, each validated (ABI handshake) so
/// the admin surface can show what's installed and whether it's loadable. A missing directory is an
/// empty inventory, not an error.
///
/// WARNING: this `dlopen`s (via [`validate_plugin`]) EVERY library to run the ABI handshake, which
/// executes each library's init/constructor code. It must therefore only be called on libraries that
/// have ALREADY passed the trust gate - never as an untrusted-directory inspection. The admin catalog
/// uses [`list_plugin_files`] + a per-file trust check instead, and `dlopen`s only what trust permits.
pub fn inventory(dir: &Path) -> Vec<PluginInfo> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        if !path.is_file() || !is_library_file(file) {
            continue;
        }
        match validate_plugin(&path) {
            Ok(v) => out.push(PluginInfo {
                file: file.to_string(),
                valid: true,
                abi_version: Some(v),
                error: None,
            }),
            Err(e) => out.push(PluginInfo {
                file: file.to_string(),
                valid: false,
                abi_version: None,
                error: Some(e),
            }),
        }
    }
    out.sort_by(|a, b| a.file.cmp(&b.file));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locate the SQLite plugin cdylib in the build's target dir, derived from the test binary's own
    /// path (robust to a custom CARGO_TARGET_DIR). Returns None if it hasn't been built — a
    /// `-p busbar`-only run may not have built it, so the caller skips rather than fails; under
    /// `cargo test --workspace` (preflight/CI) the cdylib is always present and the caller runs.
    ///
    /// CI HARDENING (mirrors the store-postgres live-DB test): CI runs `cargo test --workspace`, so
    /// the cdylib MUST be present. If it is absent while `CI` is set, that is a broken build - a HARD
    /// FAILURE here, not a silent skip, so the only over-the-ABI coverage of the durable store path
    /// cannot quietly vanish. Locally (no `CI`) a missing cdylib still skips cleanly.
    fn sqlite_plugin_path() -> Option<std::path::PathBuf> {
        let candidate = (|| {
            let exe = std::env::current_exe().ok()?; // .../target/<profile>/deps/busbar-<hash>
            let profile_dir = exe.parent()?.parent()?; // .../target/<profile>
            let name = plugin_library_filename("busbar_store_sqlite_plugin");
            let candidate = profile_dir.join(&name);
            candidate.exists().then_some(candidate)
        })();
        if candidate.is_none() && std::env::var_os("CI").is_some() {
            panic!(
                "the sqlite plugin cdylib is not built under CI: `cargo test --workspace` must build \
                 busbar_store_sqlite_plugin. Refusing to silently skip the only over-the-ABI \
                 coverage of the durable store path."
            );
        }
        candidate
    }

    /// End-to-end: load the REAL SQLite plugin cdylib over the C ABI and exercise the Store surface
    /// through the DynStore — put a key, read it back, list, delete, and round-trip usage.
    #[test]
    fn load_and_exercise_sqlite_plugin() {
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        // In-memory sqlite so the test leaves no file behind.
        let cfg = r#"{"db_path": ":memory:"}"#;
        let store = load_store(&path, cfg).expect("load sqlite plugin");

        let key = VirtualKey {
            id: "vk_dyn".into(),
            key_hash: "abc".into(),
            name: "dynamic".into(),
            allowed_pools: Some(vec!["p".into()]),
            enabled: true,
            created_at: 7,
            group: Some("growth".into()),
            labels: std::collections::BTreeMap::from([("team".into(), "growth".into())]),
        };
        store.put_key(&key).expect("put_key");

        let got = store.get_key("vk_dyn").expect("get_key").expect("present");
        assert_eq!(got.id, "vk_dyn");
        assert_eq!(
            got.group.as_deref(),
            Some("growth"),
            "the group binding survives the ABI round-trip"
        );
        assert_eq!(
            got.allowed_pools,
            Some(vec!["p".to_string()]),
            "the pool grant survives the ABI round-trip"
        );
        assert_eq!(got.labels.get("team").map(String::as_str), Some("growth"));

        assert_eq!(store.list_keys().expect("list").len(), 1);

        // The token LEDGER round-trips over the ABI: absolute put, additive add, then read back.
        let ledger = busbar_api::UsageLedger {
            requests: 3,
            billable_requests: 3,
            models: vec![busbar_api::ModelTokens {
                model: "gpt-5".into(),
                tokens: busbar_api::TierTokens {
                    input: 9,
                    output: 4,
                    cache_read: 2,
                    cache_write: 1,
                },
            }],
        };
        store.put_usage("vk_dyn", 100, &ledger).expect("put_usage");
        store
            .add_usage(
                "vk_dyn",
                100,
                &busbar_api::UsageDelta {
                    requests: 1,
                    billable_requests: 1,
                    models: vec![busbar_api::ModelTokensDelta {
                        model: "gpt-5".into(),
                        tokens: busbar_api::TierTokensDelta {
                            input: 1,
                            output: 1,
                            cache_read: 0,
                            cache_write: 0,
                        },
                    }],
                },
            )
            .expect("add_usage");
        let usage = store.get_usage("vk_dyn", 100).expect("get_usage");
        assert_eq!(usage.requests, 4);
        let t = usage.tokens_for("gpt-5").expect("model row");
        assert_eq!(
            (t.input, t.output, t.cache_read, t.cache_write),
            (10, 5, 2, 1)
        );

        store.delete_key("vk_dyn").expect("delete");
        assert!(store.get_key("vk_dyn").expect("get after delete").is_none());
    }

    /// The DURABLE AUDIT surface (#17) works over the C ABI through the real sqlite plugin: append two
    /// records and read them back oldest-first — proving the new `AppendAudit`/`ListAudit` variants
    /// serialize across the boundary and the plugin persists them. This is the dynamic-library path a
    /// `governance.store: sqlite` deployment actually uses for durable audit.
    #[test]
    fn dyn_store_durable_audit_over_abi() {
        use busbar_api::AuditRecord;
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let store = load_store(&path, r#"{"db_path": ":memory:"}"#).expect("load sqlite plugin");
        let rec = |seq: u64, prev: &str, hash: &str| AuditRecord {
            seq,
            ts: 1000 + seq,
            action: "plugin.install".into(),
            resource: format!("plugin:{seq}"),
            outcome: "applied".into(),
            principal: "admin".into(),
            prev_hash: prev.into(),
            hash: hash.into(),
        };
        store.append_audit(&rec(1, "", "h1")).expect("append 1");
        store.append_audit(&rec(2, "h1", "h2")).expect("append 2");
        let got = store.list_audit().expect("list_audit over the ABI");
        assert_eq!(got.len(), 2);
        assert_eq!(
            (got[0].seq, got[1].seq),
            (1, 2),
            "oldest-first across the ABI"
        );
        assert_eq!(
            got[1].prev_hash, "h1",
            "chain fields survive the JSON-over-C round-trip"
        );
        assert_eq!(got[0].resource, "plugin:1");
    }

    /// A non-plugin library (or a missing file) is refused with a clear error, never a crash.
    #[test]
    fn refuses_non_plugin() {
        let err = match load_store(Path::new("/definitely/not/a/plugin.so"), "{}") {
            Err(e) => e,
            Ok(_) => panic!("a missing library must not load"),
        };
        assert!(err.contains("failed to load plugin"), "got: {err}");
    }

    /// `validate_plugin` accepts the real sqlite cdylib (ABI v1) without constructing a store, and
    /// `inventory` finds it (and any sibling plugins) in the target directory as valid.
    #[test]
    fn validate_and_inventory() {
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        assert_eq!(validate_plugin(&path).expect("validate"), TRANSPORT_VERSION);

        let dir = path.parent().unwrap();
        let inv = inventory(dir);
        let sqlite = inv
            .iter()
            .find(|p| p.file.contains("busbar_store_sqlite_plugin"))
            .expect("sqlite plugin in inventory");
        assert!(sqlite.valid);
        assert_eq!(sqlite.abi_version, Some(TRANSPORT_VERSION));
        assert!(sqlite.error.is_none());
    }

    /// `inventory` of a missing directory is empty, not an error.
    #[test]
    fn inventory_missing_dir_is_empty() {
        assert!(inventory(Path::new("/no/such/plugins/dir")).is_empty());
    }

    /// The response-length cap accepts a normal reply and REFUSES an over-cap length before any
    /// allocation — defense-in-depth against a plugin declaring a huge `out_len` and OOMing the engine.
    #[test]
    fn response_len_cap_refuses_oversized() {
        assert!(response_len_ok(0, "p").is_ok());
        assert!(response_len_ok(1024, "p").is_ok());
        assert!(
            response_len_ok(MAX_PLUGIN_RESPONSE_LEN, "p").is_ok(),
            "the exact cap is allowed"
        );
        let err = response_len_ok(MAX_PLUGIN_RESPONSE_LEN + 1, "sqlite").unwrap_err();
        assert!(err.contains("oversized response"), "got {err}");
        assert!(err.contains("sqlite"), "names the offending plugin: {err}");
    }

    /// GUARD unit test on a NEW helper (`open_err_is_readable` does not exist on `main` yet, so
    /// this cannot go RED against current source — it pins the bound rather than proving a fix).
    /// The claim it supports is "the length cap is applied on both the `busbar_call` AND
    /// `busbar_open` error paths", not "an oversized open error is survived in production" — there
    /// is no fake-open seam (`dyn_store_with_fake_call` only patches `call` on an already-opened
    /// `DynStore`), so an over-the-ABI RED test is not attempted; its failure mode would be an
    /// out-of-bounds read, not a clean assertion failure.
    #[test]
    fn open_err_is_readable_refuses_an_oversized_length() {
        assert!(
            !open_err_is_readable(false, MAX_PLUGIN_RESPONSE_LEN + 1),
            "an over-cap length must be refused"
        );
        assert!(
            !open_err_is_readable(true, 64),
            "a null err pointer is never readable"
        );
        assert!(
            !open_err_is_readable(false, 0),
            "a zero length carries no message"
        );
        assert!(
            open_err_is_readable(false, 64),
            "a sane, non-null, in-cap length is readable"
        );
        assert!(
            open_err_is_readable(false, MAX_PLUGIN_RESPONSE_LEN),
            "the exact cap is allowed, matching response_len_ok"
        );
    }

    /// TOCTOU-safe load: `load_store_from_bytes` loads EXACTLY the bytes handed to it — the same bytes
    /// the caller hash/signature-verified — and exercises the store over the ABI to prove the load is
    /// live. This is the path the engine boot uses so the verified bytes and the loaded bytes are one
    /// and the same, with no path re-read in between.
    #[test]
    fn load_store_from_bytes_loads_the_given_bytes() {
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read sqlite cdylib");
        let store = load_store_from_bytes(
            &bytes,
            r#"{"db_path": ":memory:"}"#,
            "sqlite-from-bytes",
            "store",
        )
        .expect("load from verified bytes");
        let key = VirtualKey {
            id: "vk_b".into(),
            key_hash: "h".into(),
            name: "b".into(),
            allowed_pools: Some(vec!["p".into()]),
            enabled: true,
            created_at: 1,
            group: None,
            labels: std::collections::BTreeMap::new(),
        };
        store.put_key(&key).expect("put_key over from-bytes load");
        assert_eq!(
            store.get_key("vk_b").expect("get").expect("present").id,
            "vk_b"
        );
    }

    /// The TOCTOU guarantee, demonstrated end-to-end: verify a set of bytes, then SWAP the on-disk file
    /// at the original path for hostile content — and the from-bytes load is UNAFFECTED, because it
    /// never re-reads that path. Under the old `verify(path)` + `load_store(path)` shape this swap would
    /// have loaded the attacker's file; here the loaded library is the verified `bytes`, full stop.
    #[test]
    fn on_disk_swap_after_verify_does_not_change_what_loads() {
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        // "Verify" step: read the good bytes (in the engine these are hash/signature-checked here).
        let verified = std::fs::read(&path).expect("read good cdylib");

        // Attacker swaps the file at `path` for junk AFTER we verified — a classic TOCTOU swap.
        let dir = std::env::temp_dir().join(format!("busbar-toctou-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join(plugin_library_filename("busbar_store_sqlite_plugin"));
        std::fs::write(&victim, &verified).unwrap();
        // Confirm loading the victim PATH would pick up whatever is on disk...
        std::fs::write(&victim, b"\x7fELF hostile junk, not a plugin").unwrap();
        assert!(
            load_store(&victim, r#"{"db_path": ":memory:"}"#).is_err(),
            "the swapped-in junk is not a loadable plugin (path load sees the swap)"
        );
        // ..but the from-bytes load, fed the bytes we verified BEFORE the swap, loads fine.
        let store =
            load_store_from_bytes(&verified, r#"{"db_path": ":memory:"}"#, "toctou", "store")
                .expect("verified bytes still load despite the on-disk swap");
        assert!(store.list_keys().expect("list over the ABI").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No leaked artifact + unload-then-remove ordering: after a from-bytes load's store DROPS,
    /// nothing of the load remains on disk. On Linux the load is a memfd (zero disk files by
    /// construction); on macOS/Windows the staged file inside the per-process private directory is
    /// removed when the store drops — and because `DynStore` declares `_lib` before `_backing`, the
    /// library unloads BEFORE the staged file is removed (the order Windows requires: a mapped
    /// DLL's file cannot be deleted).
    ///
    /// Asserts on THIS load's own staged path, not a process-wide count of
    /// `busbar-plugins-<pid>-*` entries. The count was the wrong instrument twice over: FLAKY,
    /// because a concurrent test in this binary stages or releases files between the two samples
    /// (this test failed ~2/5 under a loaded run); and WEAK, because `after <= before` still passes
    /// while this load's file leaks, as long as some other test's file went away in the same
    /// window. The exact path is immune to concurrency and actually fails when the artifact leaks.
    #[test]
    fn from_bytes_load_leaves_no_artifact_after_drop() {
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read sqlite cdylib");
        let staged: Option<std::path::PathBuf> = {
            let store = load_dyn_store_from_bytes(
                &bytes,
                r#"{"db_path": ":memory:"}"#,
                "no-leak-check",
                "store",
            )
            .expect("load from bytes");
            assert!(store.list_keys().expect("list").is_empty());
            let staged = store.staged_path().map(std::path::Path::to_path_buf);
            // While the store is ALIVE the backing must exist — otherwise the post-drop assertion
            // below would be vacuous (nothing to remove) and would pass on a leak.
            if let Some(p) = &staged {
                assert!(
                    p.is_file(),
                    "the staged backing must exist while the store is alive: {}",
                    p.display()
                );
            }
            staged
        }; // store drops here -> library unloads, then the staged backing is released.

        match staged {
            // macOS/Windows (and the Linux memfd fallback): the file this load staged is gone.
            Some(p) => assert!(
                !p.exists(),
                "a from-bytes load must remove its OWN staged file when the store drops, but {} \
                 still exists",
                p.display()
            ),
            // Linux memfd: zero disk files by construction, so there was never a path to remove.
            None => {
                let base = std::env::temp_dir();
                let prefix = format!("busbar-plugins-{}-", std::process::id());
                let dirs = std::fs::read_dir(&base)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .filter(|e| {
                        e.file_name()
                            .to_str()
                            .is_some_and(|n| n.starts_with(&prefix))
                    })
                    .count();
                assert_eq!(
                    dirs, 0,
                    "a memfd load reports no staged path, so it must have created no staging \
                     directory either"
                );
            }
        }
    }

    /// HOT-SWAP LIFECYCLE (1.5.0): the load-bearing safety property behind a live plugin reload — a
    /// NEW instance is loaded ALONGSIDE the old (both libraries mapped at once), the OLD instance is
    /// then dropped (as an old App snapshot's last in-flight request drains), and the NEW instance
    /// keeps serving. Because each instance OWNS its `Library` (`RawPlugin._lib`), dropping the old
    /// instance unmaps ONLY the old library — the new one is untouched — and its staged backing is
    /// released, while nothing of the new load is disturbed. This is exactly the drop order a
    /// `handle.swap` relies on: instance → close handle → `_lib` unmaps → `_backing` removed.
    #[test]
    fn hot_swap_old_and_new_coexist_then_old_unmaps_new_keeps_serving() {
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read sqlite cdylib");

        // The OLD instance is serving; write a key so we can prove instance IDENTITY across the swap.
        // Load via `load_dyn_store_from_bytes` (as the fixed sibling
        // `from_bytes_load_leaves_no_artifact_after_drop` does) so each generation's OWN
        // `staged_path()` is reachable — asserting on it, not a process-wide directory count that a
        // concurrent test in this binary can shift in either direction between samples.
        let old =
            load_dyn_store_from_bytes(&bytes, r#"{"db_path": ":memory:"}"#, "old-gen", "store")
                .expect("load OLD");
        let old_path = old.staged_path().map(std::path::Path::to_path_buf);
        if let Some(p) = &old_path {
            assert!(p.is_file(), "OLD's staged backing must exist while alive");
        }
        let key = busbar_api::VirtualKey {
            id: "vk_old".into(),
            key_hash: "h".into(),
            name: "old".into(),
            allowed_pools: Some(vec!["p".into()]),
            enabled: true,
            created_at: 1,
            group: None,
            labels: std::collections::BTreeMap::new(),
        };
        old.put_key(&key).expect("old put");

        // Load the NEW instance ALONGSIDE the old — both libraries are mapped simultaneously. On
        // macOS/Windows this is two staged files at once; on Linux two memfds (no disk).
        let new =
            load_dyn_store_from_bytes(&bytes, r#"{"db_path": ":memory:"}"#, "new-gen", "store")
                .expect("load NEW alongside OLD");
        let new_path = new.staged_path().map(std::path::Path::to_path_buf);
        if let (Some(op), Some(np)) = (&old_path, &new_path) {
            assert!(
                op.is_file() && np.is_file(),
                "both generations must be simultaneously mapped: old={} new={}",
                op.display(),
                np.display()
            );
            assert_ne!(op, np, "each generation stages its OWN file");
        }
        // The NEW instance is a DISTINCT backend (fresh :memory: db): it does NOT see the old key.
        assert!(
            new.get_key("vk_old").expect("new get").is_none(),
            "the new instance is a separate backend, proving a real second load — not an alias"
        );

        // Drop the OLD instance (the old snapshot drained): its library unmaps, its staged file
        // goes — and ONLY its file: the new one must be untouched, which a process-wide count could
        // never express (a leaked old file would be indistinguishable from a released one as long
        // as some unrelated concurrent test released a file in the same window).
        drop(old);
        if let Some(p) = &old_path {
            assert!(
                !p.exists(),
                "OLD's staged file must be removed on drop: {}",
                p.display()
            );
        }
        if let Some(p) = &new_path {
            assert!(
                p.is_file(),
                "NEW's staged file must be UNTOUCHED by OLD's drop: {}",
                p.display()
            );
        }

        // The NEW instance keeps serving with no restart — its library was untouched by the old drop.
        new.put_key(&busbar_api::VirtualKey {
            id: "vk_new".into(),
            key_hash: "h".into(),
            name: "new".into(),
            allowed_pools: Some(vec!["p".into()]),
            enabled: true,
            created_at: 2,
            group: None,
            labels: std::collections::BTreeMap::new(),
        })
        .expect("new keeps serving after old unmaps");
        assert_eq!(
            new.get_key("vk_new")
                .expect("new get2")
                .expect("present")
                .id,
            "vk_new"
        );

        // Drop the NEW instance too: its own file goes as well.
        drop(new);
        if let Some(p) = &new_path {
            assert!(
                !p.exists(),
                "NEW's staged file must be removed on drop: {}",
                p.display()
            );
        }
    }

    /// NO LEAK ACROSS REPEATED RELOADS (1.5.0): loading + dropping a from-bytes instance many times
    /// (the repeated-hot-reload case) must return to the SAME staged-file count each cycle — every
    /// generation's library unmaps and its staged backing is released when the instance drops, so
    /// there is no unbounded mmap/file accumulation across reloads. This is the drop-counter-balances
    /// property proven at the loader seam (the engine-level proof is that the old App snapshot drops).
    #[test]
    fn repeated_reloads_do_not_leak_staged_libraries() {
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read sqlite cdylib");
        // Per-cycle own path, not a process-wide count: a concurrent test staging or releasing a
        // file in this binary between samples can move the count in either direction, hiding a real
        // leak or reporting a false one. Collect this run's own paths and assert each is gone after
        // its own drop, and that no two cycles reused the same path.
        let mut seen = std::collections::HashSet::new();
        for i in 0..16 {
            let s = load_dyn_store_from_bytes(
                &bytes,
                r#"{"db_path": ":memory:"}"#,
                &format!("reload-{i}"),
                "store",
            )
            .unwrap_or_else(|e| panic!("reload {i} load: {e}"));
            assert!(s.list_keys().expect("list").is_empty());
            let staged = s.staged_path().map(std::path::Path::to_path_buf);
            if let Some(p) = &staged {
                assert!(
                    p.is_file(),
                    "cycle {i}'s staged backing must exist while alive"
                );
                assert!(
                    seen.insert(p.clone()),
                    "cycle {i} reused a staged path from an earlier cycle: {}",
                    p.display()
                );
            }
            drop(s);
            if let Some(p) = &staged {
                assert!(
                    !p.exists(),
                    "reload cycle {i} leaked its staged library: {}",
                    p.display()
                );
            }
        }
    }

    /// On Linux the from-bytes load is a MEMFD load: it must not create ANY file in the temp base
    /// (the zero-disk property the spec requires on Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_from_bytes_load_touches_no_disk() {
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read sqlite cdylib");
        // The actual claim ("a memfd load reports no staged path"), not a directory census: a
        // process-wide count is quiet here only because the common Linux path never touches disk in
        // the first place, but the instrument is the same flawed one the sibling tests above moved
        // away from — a concurrent test staging a file on the non-memfd fallback path between the
        // two samples would have made this assertion fail for a reason unrelated to THIS load.
        let store =
            load_dyn_store_from_bytes(&bytes, r#"{"db_path": ":memory:"}"#, "memfd-check", "store")
                .expect("memfd load");
        assert!(store.list_keys().expect("list").is_empty());
        assert!(
            store.staged_path().is_none(),
            "a Linux memfd load must report no staged path"
        );
    }

    // ── The denylist fallback keys on the OUT-OF-BAND ABI status, not on
    // plugin-controlled body text ─────────────────────────────────────────────────────────────
    //
    // The regression uses a FAKE `busbar_call` whose returned (status, body) is chosen per-test via a
    // thread-local, wired into a genuine `RawPlugin` built on a real loaded `Library` (so the whole
    // `list_denylist` → `transport_call_status` → classification path runs end to end). We swap ONLY the
    // `call` fn pointer; the real `open`/`free`/`close`/handle from the loaded sqlite store stay valid.

    use std::cell::Cell;
    thread_local! {
        /// (status, body) the fake `busbar_call` returns for the NEXT call on this thread.
        static FAKE_CALL: Cell<(i32, &'static [u8])> = const { Cell::new((STATUS_OK, b"")) };
    }

    /// A fake `busbar_call`: allocate a buffer holding the thread-local body and return the
    /// thread-local status. Mimics the plugin side (plugin allocates, engine frees via `busbar_free`).
    unsafe extern "C-unwind" fn fake_call(
        _handle: *mut c_void,
        _req: *const u8,
        _req_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32 {
        let (status, body) = FAKE_CALL.with(|c| c.get());
        if body.is_empty() {
            *out = std::ptr::null_mut();
            *out_len = 0;
        } else {
            // Allocate with the SAME shape `fake_free` frees: a boxed slice leaked to a raw ptr.
            let boxed: Box<[u8]> = body.to_vec().into_boxed_slice();
            let len = boxed.len();
            *out = Box::into_raw(boxed) as *mut u8;
            *out_len = len;
        }
        status
    }

    /// Free a buffer `fake_call` allocated (reconstruct the boxed slice and drop it).
    unsafe extern "C-unwind" fn fake_free(ptr: *mut u8, len: usize) {
        if !ptr.is_null() && len != 0 {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
        }
    }

    /// Build a `DynStore` whose `call` is `fake_call`, reusing a real loaded store's `Library`/handle/
    /// `close` (so `RawPlugin` is genuinely valid) but our fake `free` to match `fake_call`'s allocator.
    fn dyn_store_with_fake_call() -> Option<DynStore> {
        let path = sqlite_plugin_path()?;
        // Stage a genuine `RawPlugin` (real `Library` + handle + `close`), then splice in our fake
        // `call`/`free` so the response's (status, body) is what the test chooses.
        let bytes = std::fs::read(&path).expect("read sqlite cdylib");
        // `.expect`, NOT `.ok()?`: the ONLY sanctioned reason these D4 guards may skip is "the cdylib
        // was never built" — which `sqlite_plugin_path` already turns into a hard panic under CI. A
        // STAGING failure is a different thing entirely, and swallowing it into a `None` let the whole
        // revocation fail-open suite self-disable while the run stayed green.
        let (lib, staged) = stage::load_library_from_bytes(&bytes, "fake-call-store")
            .expect("stage the sqlite cdylib for the fake-call harness");
        let mut raw = wire_up_raw(
            lib,
            r#"{"db_path": ":memory:"}"#,
            "fake-call-store".to_string(),
            abi_kind::STORE,
            abi_kind::STORE,
            Some(staged),
        )
        .expect("wire up raw");
        // Override the call + free seam so responses come from `fake_call` (freed by `fake_free`).
        raw.call = fake_call;
        raw.free = fake_free;
        Some(DynStore { raw })
    }

    /// (1) A GENUINE unsupported-variant signal — the (rebuilt) SDK returns the crisp
    /// `STATUS_UNSUPPORTED` when it cannot deserialize the `ListDenylist` request enum — falls back to
    /// an EMPTY denylist so a store predating the variant still BOOTS. The body text is irrelevant.
    #[test]
    fn denylist_unsupported_status_falls_back_empty() {
        let Some(store) = dyn_store_with_fake_call() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        FAKE_CALL.with(|c| {
            c.set((
                STATUS_UNSUPPORTED,
                b"malformed request JSON: unknown variant `ListDenylist`",
            ))
        });
        let out = store.list_denylist();
        assert_eq!(
            out.expect("unsupported variant must boot with an empty denylist"),
            Vec::<String>::new(),
        );
    }

    /// (1b) LEGACY v1-SDK interop, keyed on the shape the v1 SDK ACTUALLY emits. Every generation of
    /// the v1 SDK spelled an undecodable request variant
    /// `Err((format!("malformed request JSON: {e}"), true))` + `write_buf` → a NON-EMPTY
    /// `STATUS_PROTOCOL`. That is what must boot with an empty denylist.
    #[test]
    fn denylist_legacy_v1_decode_failure_falls_back_empty() {
        let Some(store) = dyn_store_with_fake_call() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        FAKE_CALL.with(|c| {
            c.set((
                STATUS_PROTOCOL,
                b"malformed request JSON: unknown variant `ListDenylist`, expected one of `PutKey`",
            ))
        });
        assert_eq!(
            store
                .list_denylist()
                .expect("the real v1 decode-failure shape must boot with an empty denylist"),
            Vec::<String>::new(),
        );
    }

    /// THE CLASS TEST for the revocation fail-open (D4). It enumerates every way a store plugin of ANY
    /// SDK generation can CRASH or violate the protocol, and asserts that NONE of them can empty the
    /// denylist. The discriminator that decides this is `TransportError::from_status`, so one function
    /// has to be wrong for any row here to flip — there is no per-op patch to keep in sync.
    ///
    /// The row that motivated it: an EMPTY-buffer `STATUS_PROTOCOL`. A v1 SDK mapped a CAUGHT PANIC to
    /// exactly that (`Err(_) => STATUS_PROTOCOL`, no `write_buf`), as does a null handle, as does the
    /// CURRENT SDK's `call_boundary` on a caller-protocol violation. Classifying it as the legacy
    /// unsupported signal meant a pre-`STATUS_PANIC` store plugin that panicked inside `list_denylist`
    /// hydrated an EMPTY denylist and every revoked signed token was accepted again.
    #[test]
    fn no_plugin_crash_shape_can_empty_the_denylist() {
        let Some(store) = dyn_store_with_fake_call() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        // (status, body, what the shape IS) — every one must FAIL CLOSED.
        let crashes: &[(i32, &'static [u8], &str)] = &[
            (
                STATUS_PROTOCOL,
                b"",
                "v1-SDK caught panic / null handle / current-SDK protocol violation (bare status)",
            ),
            (STATUS_PANIC, b"plugin panicked", "current-SDK caught panic"),
            (
                STATUS_PROTOCOL,
                b"null request pointer",
                "v1-SDK caller-protocol violation with a message",
            ),
            (
                busbar_plugin_abi::STATUS_ERR,
                b"backend read failed: unknown variant of corruption",
                "real backend error whose text mimics a decode failure",
            ),
            (99, b"novel status", "a status this engine has never seen"),
        ];
        for (status, body, what) in crashes {
            FAKE_CALL.with(|c| c.set((*status, body)));
            assert!(
                store.list_denylist().is_err(),
                "{what}: must fail CLOSED, never hydrate an empty denylist"
            );
            FAKE_CALL.with(|c| c.set((*status, body)));
            assert!(
                store.list_audit_tail(8).is_err(),
                "{what}: must not silently degrade the audit tail"
            );
            FAKE_CALL.with(|c| c.set((*status, body)));
            assert!(
                store.append_audit(&audit_fixture()).is_err(),
                "{what}: must not be swallowed as 'this store has no durable audit'"
            );
        }
        // Positive control: the TWO shapes that ARE the unsupported signal still open the fallback, so
        // this test cannot pass by simply refusing every fallback.
        for (status, body, what) in [
            (STATUS_UNSUPPORTED, &b"unsupported variant"[..], "crisp"),
            (
                STATUS_PROTOCOL,
                &b"malformed request JSON: unknown variant `ListDenylist`"[..],
                "legacy v1",
            ),
        ] {
            FAKE_CALL.with(|c| c.set((status, body)));
            assert_eq!(
                store.list_denylist().unwrap_or_else(|e| panic!(
                    "{what} unsupported signal must fall back: {}",
                    e.0
                )),
                Vec::<String>::new(),
            );
        }
    }

    /// The CURRENT SDK returns a BARE `STATUS_PROTOCOL` — no buffer — for a null handle or a null
    /// request pointer, and its own comment calls that "a caller-protocol violation, not an old-SDK
    /// signal". Pin that the loader agrees, so the two halves of the design cannot drift apart again.
    #[test]
    fn current_sdk_bare_protocol_is_not_unsupported() {
        assert!(
            !TransportError::from_status(STATUS_PROTOCOL, "", "p").is_unsupported(),
            "a bare STATUS_PROTOCOL is what busbar_plugin_sdk::boundary::call_boundary returns for a \
             caller-protocol violation; treating it as 'unsupported' opens the safe-default fallback"
        );
    }

    /// A minimal audit record for the crash-shape sweep.
    fn audit_fixture() -> AuditRecord {
        AuditRecord {
            seq: 1,
            ts: 2,
            action: "plugin.install".into(),
            resource: "plugin:1".into(),
            outcome: "applied".into(),
            principal: "admin".into(),
            prev_hash: String::new(),
            hash: "h".into(),
        }
    }

    /// (2) THE CLOSED FAIL-OPEN: a real backend error (`STATUS_ERR`) whose BODY happens to contain the
    /// string "unknown variant" must NOT be misclassified as old-SDK. Under the former substring match
    /// this hydrated an empty denylist (accepting revoked tokens); now it PROPAGATES → boot fails CLOSED.
    #[test]
    fn denylist_backend_error_with_unknown_variant_text_propagates() {
        let Some(store) = dyn_store_with_fake_call() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        // A crafted / coincidental backend error: STATUS_ERR, but the body contains "unknown variant".
        FAKE_CALL.with(|c| {
            c.set((
                busbar_plugin_abi::STATUS_ERR,
                b"backend read failed: table 'denylist' reported unknown variant of corruption",
            ))
        });
        let err = store.list_denylist().expect_err(
            "a STATUS_ERR must fail CLOSED even when its text contains 'unknown variant'",
        );
        assert!(
            err.0.contains("unknown variant"),
            "the propagated error keeps the backend message: {}",
            err.0
        );
    }

    /// `list_audit_tail`: a real backend error (`STATUS_ERR`) must PROPAGATE, not be masked as an
    /// old-SDK unsupported-variant signal and silently re-issued as a full `list_audit`. Before the fix
    /// the bare `Err(_)` fallback swallowed EVERY error into the full-list path, hiding a store fault
    /// (and doing extra work against a store that just failed). Now only `STATUS_PROTOCOL` falls back.
    #[test]
    fn audit_tail_backend_error_propagates_not_masked_by_fallback() {
        let Some(store) = dyn_store_with_fake_call() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        FAKE_CALL.with(|c| {
            c.set((
                busbar_plugin_abi::STATUS_ERR,
                b"backend read failed: audit table I/O error",
            ))
        });
        let err = store
            .list_audit_tail(10)
            .expect_err("a STATUS_ERR from the store must propagate, not fall back to list_audit");
        assert!(
            err.0.contains("audit table I/O error"),
            "the propagated error keeps the backend message: {}",
            err.0
        );
    }

    // ── Class-level loader discrimination harness (redesign B): the SAME matrix of injected
    // statuses × the three fallback-bearing methods, driven through the real
    // `call_raw_status` → `TransportError::from_status` → `is_unsupported()` path. A new
    // fallback-bearing method inherits this coverage the moment it keys on `is_unsupported()`. ────

    /// THE D4 REGRESSION GUARD: a plugin PANIC on `ListDenylist` arrives as `STATUS_PANIC` → `Fault`,
    /// `is_unsupported()` is false, so `list_denylist` fails CLOSED (Err) — it does NOT silently return
    /// `Ok(vec![])`. Under the pre-B taxonomy a panic returned `STATUS_PROTOCOL` and was misread as
    /// old-SDK, hydrating an EMPTY revocation denylist (accepting revoked tokens). Now structurally
    /// impossible: STATUS_PANIC and STATUS_UNSUPPORTED are different integers → different kinds.
    #[test]
    fn panic_in_list_denylist_fails_closed_not_empty() {
        let Some(store) = dyn_store_with_fake_call() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        FAKE_CALL.with(|c| {
            c.set((
                STATUS_PANIC,
                b"plugin panicked (caught at the export boundary)",
            ))
        });
        let err = store
            .list_denylist()
            .expect_err("a plugin PANIC must fail CLOSED, never hydrate an empty denylist");
        assert!(
            !err.0.is_empty(),
            "the propagated fault carries the panic message"
        );
    }

    /// The full status matrix on `list_denylist`: UNSUPPORTED → empty fallback; PANIC → Err (fault);
    /// backend ERR → Err; protocol-with-message → Err. Only the deliberate unsupported signal empties.
    #[test]
    fn denylist_status_matrix() {
        let Some(store) = dyn_store_with_fake_call() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        FAKE_CALL.with(|c| c.set((STATUS_UNSUPPORTED, b"unsupported variant")));
        assert_eq!(
            store.list_denylist().expect("unsupported → empty"),
            Vec::<String>::new()
        );

        FAKE_CALL.with(|c| c.set((STATUS_PANIC, b"panicked")));
        assert!(store.list_denylist().is_err(), "panic → fail closed");

        FAKE_CALL.with(|c| c.set((STATUS_PROTOCOL, b"null handle")));
        assert!(
            store.list_denylist().is_err(),
            "protocol-with-message → propagate (a caller violation, not old-SDK)"
        );
    }

    /// The same matrix for `append_audit`: UNSUPPORTED → Ok(()) (best-effort, RAM ring holds it); a
    /// PANIC → Err (a store crash on audit-write must surface, never be silently swallowed).
    #[test]
    fn append_audit_status_matrix() {
        let Some(store) = dyn_store_with_fake_call() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let rec = AuditRecord {
            seq: 1,
            ts: 2,
            action: "plugin.install".into(),
            resource: "plugin:1".into(),
            outcome: "applied".into(),
            principal: "admin".into(),
            prev_hash: String::new(),
            hash: "h".into(),
        };
        FAKE_CALL.with(|c| c.set((STATUS_UNSUPPORTED, b"no durable audit")));
        store
            .append_audit(&rec)
            .expect("unsupported → best-effort Ok(())");

        FAKE_CALL.with(|c| c.set((STATUS_PANIC, b"panicked")));
        assert!(
            store.append_audit(&rec).is_err(),
            "a panic on audit-write must surface, never be swallowed as unsupported"
        );
    }

    /// Direct classification proof (no FFI) of the total status → semantic-kind map. EXACTLY TWO shapes
    /// are the unsupported signal: the crisp `STATUS_UNSUPPORTED`, and the legacy v1 decode failure (a
    /// `STATUS_PROTOCOL` carrying `LEGACY_V1_UNDECODABLE_PREFIX`). A PANIC, a backend error (even one
    /// whose text says "unknown variant"), a BARE protocol violation, an unknown status, and every
    /// engine-internal error are NOT unsupported.
    #[test]
    fn transport_error_classification() {
        // The two unsupported signals: the crisp code, and the shape the v1 SDK really emitted.
        assert!(
            TransportError::from_status(STATUS_UNSUPPORTED, "unsupported", "p").is_unsupported()
        );
        assert!(TransportError::from_status(
            STATUS_PROTOCOL,
            "malformed request JSON: unknown variant `ListDenylist`",
            "p"
        )
        .is_unsupported());

        // A PANIC is a Fault, NEVER unsupported — this is what keeps a crash from opening the fallback.
        assert!(!TransportError::from_status(STATUS_PANIC, "panicked", "p").is_unsupported());
        // A backend error whose body contains "unknown variant" is NOT unsupported.
        assert!(!TransportError::from_status(
            busbar_plugin_abi::STATUS_ERR,
            "unknown variant",
            "p"
        )
        .is_unsupported());
        // A BARE STATUS_PROTOCOL — null handle, null request pointer, or a v1-SDK caught panic — is a
        // caller-protocol violation, NOT unsupported. This is the inversion that reopened D4.
        assert!(!TransportError::from_status(STATUS_PROTOCOL, "", "p").is_unsupported());
        // Nor is a STATUS_PROTOCOL carrying any OTHER message.
        assert!(!TransportError::from_status(STATUS_PROTOCOL, "null handle", "p").is_unsupported());
        // An unknown status defaults to Fault (propagate), never unsupported.
        assert!(!TransportError::from_status(99, "novel status", "p").is_unsupported());
        // An engine-internal error is always Fault.
        assert!(!TransportError::engine("plugin response decode failed".into()).is_unsupported());
        // A bare status still produces a diagnosable message naming the plugin and the status.
        let m = TransportError::from_status(STATUS_PROTOCOL, "", "libstore.so").message;
        assert!(m.contains("libstore.so") && m.contains("-1"), "{m}");
    }

    /// class-13/14 F1: `kind: secret` was the only plugin kind with ZERO over-the-ABI test coverage
    /// (`grep -rn export_secret_plugin crates/` found only the macro's own definition). Locate the
    /// hermetic `busbar-secret-example-plugin` cdylib, mirroring `sqlite_plugin_path` above — CI
    /// (`cargo test --workspace`) always builds it, so a missing cdylib there is a hard failure, not
    /// a silent skip.
    fn secret_example_plugin_path() -> Option<std::path::PathBuf> {
        let candidate = (|| {
            let exe = std::env::current_exe().ok()?;
            let profile_dir = exe.parent()?.parent()?;
            let name = plugin_library_filename("busbar_secret_example_plugin");
            let candidate = profile_dir.join(&name);
            candidate.exists().then_some(candidate)
        })();
        if candidate.is_none() && std::env::var_os("CI").is_some() {
            panic!(
                "the secret example plugin cdylib is not built under CI: `cargo test --workspace` \
                 must build busbar_secret_example_plugin. Refusing to silently skip the only \
                 over-the-ABI coverage of the DynSecret dlopen seam."
            );
        }
        candidate
    }

    /// End-to-end: load the REAL secret-example-plugin cdylib over the C ABI and exercise
    /// `SecretModule::resolve` through the `DynSecret` wrapper — a hit, a miss (fail-closed, never an
    /// empty `Ok`), and a reference whose `settings` carries no `key` at all.
    #[test]
    fn load_and_exercise_secret_example_plugin() {
        let Some(path) = secret_example_plugin_path() else {
            eprintln!("skip: secret example plugin cdylib not built (run under --workspace)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read secret example plugin cdylib");
        let module = load_secret_from_bytes(
            &bytes,
            r#"{"map": {"db-password": "hunter2"}}"#,
            "secret-example",
            "secret",
        )
        .expect("load secret example plugin over the ABI");

        let mut settings = serde_json::Map::new();
        settings.insert(
            "key".to_string(),
            serde_json::Value::String("db-password".into()),
        );
        let bytes = module.resolve(&settings).expect("known key resolves");
        assert_eq!(bytes, b"hunter2");

        let mut miss = serde_json::Map::new();
        miss.insert(
            "key".to_string(),
            serde_json::Value::String("no-such-key".into()),
        );
        assert!(
            module.resolve(&miss).is_err(),
            "an unknown key must fail closed, never resolve empty"
        );

        assert!(
            module.resolve(&serde_json::Map::new()).is_err(),
            "settings with no `key` field must fail closed"
        );
    }

    // ── kind:auth ABI-crossing coverage (busbar-auth-oidc-plugin) ──────────────────────────────────
    //
    // Before this test, `kind: auth` had zero over-the-ABI test coverage anywhere in the repo (unlike
    // `kind: secret`, which the `secret_example_plugin` test above exists specifically to cover).
    // These tests dlopen the REAL `busbar_auth_oidc_plugin` cdylib and drive it through `DynAuth`:
    // a genuine JWKS fetch over a genuine local TLS listener, a genuine ES256-signed JWT verified by
    // the plugin's own `busbar-auth-oidc` logic, and a genuine load-time config failure surfaced back
    // across the C ABI.

    /// Locate the auth-oidc-plugin cdylib, mirroring `secret_example_plugin_path`/`sqlite_plugin_path`
    /// above exactly: same target-dir derivation, same CI-hard-fail-instead-of-silent-skip policy so
    /// this, the only over-the-ABI coverage of the `kind: auth` dlopen seam, cannot quietly vanish.
    fn auth_oidc_plugin_path() -> Option<std::path::PathBuf> {
        let candidate = (|| {
            let exe = std::env::current_exe().ok()?;
            let profile_dir = exe.parent()?.parent()?;
            let name = plugin_library_filename("busbar_auth_oidc_plugin");
            let candidate = profile_dir.join(&name);
            candidate.exists().then_some(candidate)
        })();
        if candidate.is_none() && std::env::var_os("CI").is_some() {
            panic!(
                "the auth-oidc plugin cdylib is not built under CI: `cargo test --workspace` must \
                 build busbar_auth_oidc_plugin. Refusing to silently skip the only over-the-ABI \
                 coverage of the kind:auth dlopen seam."
            );
        }
        candidate
    }

    /// Install ring as the process-default rustls `CryptoProvider`, once. Idempotent: an
    /// already-installed error means some other test (or the plugin's own reqwest/rustls stack under
    /// the SAME test binary) already installed one; since everything here is ring, that's fine.
    fn install_ring_provider_once() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// A minimal real HTTPS server: one self-signed cert, one background thread, one fixed response
    /// body served to every request on every path (the test controls exactly what URL it configures,
    /// so path-routing logic would be pure overhead). No framework — just `rustls` over a blocking
    /// `TcpStream`, which is all `busbar_auth_oidc::ReqwestFetcher`'s blocking client needs to
    /// complete a real TLS handshake, request, and response. Returns `(https url to the served body,
    /// the server's cert PEM to trust via the plugin's optional `ca_cert_pem` config)`.
    fn spawn_https_fixture(body: String) -> (String, String) {
        install_ring_provider_once();

        let cert_key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
            .expect("generate self-signed cert");
        let cert_pem = cert_key.cert.pem();
        let cert_der = cert_key.cert.der().clone();
        use rustls::pki_types::pem::PemObject;
        let key_der = rustls::pki_types::PrivateKeyDer::from_pem_slice(
            cert_key.signing_key.serialize_pem().as_bytes(),
        )
        .expect("parse generated private key");

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("build TLS server config");
        let server_config = std::sync::Arc::new(server_config);

        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral test port");
        let port = listener.local_addr().expect("local_addr").port();

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let Ok(conn) = rustls::ServerConnection::new(server_config.clone()) else {
                    continue;
                };
                let mut tls = rustls::StreamOwned::new(conn, stream);
                let mut buf = [0u8; 4096];
                // Drive the handshake + read whatever of the request arrives; the response below
                // doesn't depend on the request content (fixed body, any path), so a short/partial
                // read is fine — we only need enough I/O to complete the handshake.
                let _ = std::io::Read::read(&mut tls, &mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = std::io::Write::write_all(&mut tls, response.as_bytes());
                let _ = std::io::Write::write_all(&mut tls, body.as_bytes());
                let _ = std::io::Write::flush(&mut tls);
            }
        });

        (format!("https://127.0.0.1:{port}/jwks"), cert_pem)
    }

    /// A ring ES256 signer, mirroring `busbar-auth-oidc`'s own test fixture
    /// (`crates/auth-oidc/src/tests.rs::TestKey`) so this test mints and verifies REAL tokens rather
    /// than stubbing the crypto.
    struct TestKey {
        kp: ring::signature::EcdsaKeyPair,
        rng: ring::rand::SystemRandom,
        kid: &'static str,
    }
    impl TestKey {
        fn generate(kid: &'static str) -> Self {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )
            .unwrap();
            let kp = ring::signature::EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                pkcs8.as_ref(),
                &rng,
            )
            .unwrap();
            Self { kp, rng, kid }
        }

        fn jwks(&self) -> String {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            use ring::signature::KeyPair;
            let pt = self.kp.public_key().as_ref();
            assert_eq!(pt[0], 0x04, "uncompressed point");
            let x = URL_SAFE_NO_PAD.encode(&pt[1..33]);
            let y = URL_SAFE_NO_PAD.encode(&pt[33..65]);
            serde_json::json!({
                "keys": [{
                    "kty": "EC", "crv": "P-256", "kid": self.kid, "x": x, "y": y, "use": "sig", "alg": "ES256"
                }]
            })
            .to_string()
        }

        fn mint(&self, claims: &serde_json::Value) -> String {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
            let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
            let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
            let signing_input = format!("{h}.{p}");
            let sig = self.kp.sign(&self.rng, signing_input.as_bytes()).unwrap();
            let s = URL_SAFE_NO_PAD.encode(sig.as_ref());
            format!("{signing_input}.{s}")
        }
    }

    /// End-to-end SUCCESS: dlopen the real auth-oidc-plugin cdylib, `open()` it against a config
    /// pointing at a real local HTTPS JWKS fixture (trusted via `ca_cert_pem`), then `authenticate()`
    /// a real ES256-signed JWT over the C ABI and confirm the identity + mapped groups come back
    /// correctly through `DynAuth`/`AuthOutcome::Identify`.
    #[test]
    fn load_and_exercise_auth_oidc_plugin_success() {
        let Some(path) = auth_oidc_plugin_path() else {
            eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
            return;
        };

        let key = TestKey::generate("test-kid-1");
        let (jwks_url, cert_pem) = spawn_https_fixture(key.jwks());

        const ISSUER: &str = "https://oidc-test.invalid/v2.0";
        const AUDIENCE: &str = "api://busbar-client";

        let cfg = serde_json::json!({
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "jwks_url": jwks_url,
            "ca_cert_pem": cert_pem,
        })
        .to_string();

        let bytes = std::fs::read(&path).expect("read auth-oidc plugin cdylib");
        let module = crate::auth::load_auth_from_bytes(&bytes, &cfg, "auth-oidc", abi_kind::AUTH)
            .expect("load auth-oidc plugin over the ABI (real JWKS fetch at open/first-use time)");

        assert_eq!(module.name(), "oidc");
        assert!(module.cacheable());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now + 3600,
            "nbf": now - 10,
            "sub": "subject-guid",
            "preferred_username": "alice@contoso.example",
            "name": "Alice Example",
            "groups": ["11111111-aaaa", "22222222-bbbb"],
        });
        let token = key.mint(&claims);

        match module.authenticate(Some(&token)) {
            busbar_api::AuthOutcome::Identify(p) => {
                assert_eq!(p.id, "oidc:alice@contoso.example");
                assert_eq!(p.name.as_deref(), Some("Alice Example"));
                assert_eq!(p.roles, vec!["11111111-aaaa", "22222222-bbbb"]);
            }
            other => panic!(
                "expected the real JWKS fetch + real signature verification to identify the \
                 caller, got {other:?}"
            ),
        }

        // A token signed by a DIFFERENT key (same kid) must fail closed over the real ABI too — not
        // just in `busbar-auth-oidc`'s own in-process tests.
        let forged_key = TestKey::generate("test-kid-1");
        let forged_token = forged_key.mint(&claims);
        assert!(
            matches!(
                module.authenticate(Some(&forged_token)),
                busbar_api::AuthOutcome::Reject
            ),
            "a token signed by the wrong key must be rejected across the real ABI"
        );
    }

    /// End-to-end FAILURE: a plugin `open()` error (malformed config) must surface back across the C
    /// ABI as a clean `Err`, not a panic or a silently-succeeded load — mirroring the fail-closed
    /// assertions `load_and_exercise_secret_example_plugin` makes for `kind: secret`.
    #[test]
    fn load_and_exercise_auth_oidc_plugin_bad_config_fails_over_abi() {
        let Some(path) = auth_oidc_plugin_path() else {
            eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read auth-oidc plugin cdylib");

        let err = crate::auth::load_auth_from_bytes(&bytes, "", "auth-oidc", abi_kind::AUTH)
            .err()
            .expect("empty config must fail to load, not silently succeed");
        assert!(
            err.contains("config"),
            "the plugin's own error message should survive the ABI crossing intact: {err}"
        );

        let err = crate::auth::load_auth_from_bytes(
            &bytes,
            r#"{"issuer": "https://idp.example/v2.0"}"#, // missing required `audience`
            "auth-oidc",
            abi_kind::AUTH,
        )
        .err()
        .expect("config missing a required field must fail to load");
        assert!(err.contains("invalid oidc plugin config"), "got: {err}");
    }
}
