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
    AuditRecord, CredentialMeta, CredentialSecret, McpCallRecord, MeteringDelta, MeteringRow,
    Store, StoreError, StoreResult, TaskEventRow, TaskRow, UsageDelta, UsageLedger, VirtualKey,
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
pub mod export;
pub mod fetch;
pub mod hook;
mod hostlog;
pub mod registry;
mod stage;
pub mod tarball;

pub use auth::DynAuth;
/// Re-export the HTTP-endpoint wire types (plugin route registration + dispatch) so the engine
/// (`crates/busbar`) names `busbar_plugin_loader::{Route, RouteAuth, ...}` without a direct
/// `busbar-plugin-abi` dependency — mirroring how it already reaches the loader's typed seams.
pub use busbar_plugin_abi::http_endpoint::{
    HttpEndpointRequest, HttpEndpointResponse, Route, RouteAuth, RouteMethod,
};
pub use export::{load_export_from_bytes, DynExport};
// The export PROJECTION vocabulary (the frozen `streams:` / `fields:` word-space). Re-exported for
// the same reason the http_endpoint types above are: the engine names these through the loader
// rather than taking a second, direct dependency on the ABI crate.
pub use busbar_plugin_abi::export::{ExportField, ExportStream};
pub use fetch::{fetch_plugins, FetchOutcome, FetchSpec};
pub use hook::DlopenPolicy;
pub use registry::{
    inventory as inventory_tarballs, scan_and_validate, supported_abi, InventoryEntry,
    LoadablePlugin, PluginRegistry, SkippedPlugin,
};
pub use stage::sweep_dead_staging;

/// INTERN a plugin name into a stable `&'static str`, reusing one allocation per unique name.
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

    // ── 3b. Install the host log bridge (OPTIONAL symbol; absence is normal, not an error). ──
    //
    // A plugin cdylib statically links its own `tracing-core`, so its dispatcher is not this
    // process's and nothing joins them: every `tracing::warn!` inside a loaded plugin was silently
    // discarded, including auth-oidc's on a FAILED TOKEN SIGNATURE VERIFICATION. Plugins worked
    // around it with `eprintln!`, which reaches the shared stderr but bypasses this host's
    // subscriber entirely — no level filter, no structured fields, no OTLP export, and nothing
    // saying which plugin spoke.
    //
    // Resolved with a plain `get` whose failure is IGNORED: a plugin built before this symbol
    // existed keeps loading and behaving exactly as it did, which is what makes the seventh symbol
    // additive rather than a transport bump.
    //
    // Installed BEFORE `open`, deliberately: a constructor is exactly where a plugin has something
    // worth reporting (a rejected config, a refused target), and installing afterwards would drop
    // precisely those lines.
    unsafe {
        if let Ok(set_sink) = lib.get::<busbar_plugin_abi::SetLogSinkFn>(symbol::SET_LOG_SINK) {
            // The ctx identifies WHICH plugin is talking, since a bare fn pointer carries no
            // captured state. It points at the INTERNED name, not a fresh `Box::into_raw` per load.
            //
            // That distinction is the whole point of `intern_name` (see its doc): this function runs
            // per config reload, per `push_configure`, per `fetch_schema`, and per `fetch_status` —
            // which fires on EVERY Prometheus `/metrics/hooks` scrape and every admin status poll.
            // A per-load allocation here would therefore be per-CALL and unbounded, driven by
            // routine external scraping: exactly the leak `intern_name` was written to close, and my
            // first version of this reintroduced it directly below the comment warning about it.
            // Interned, it is one allocation per DISTINCT plugin name for the life of the process.
            //
            // `&'static str` rather than `String`: the interned value already lives forever, so the
            // sink reads it as a `str` with no ownership question.
            // The host's own level, so the plugin filters BEFORE building a record. Sampled at load.
            (*set_sink)(
                hostlog::host_log_sink,
                hostlog::intern_log_ctx(&display),
                hostlog::host_max_level(),
            );
        }
    }

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
            // A non-null `err` with `err_len == 0` carries no message but is still an
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
    // On the SUCCESS path a well-behaved plugin leaves `err` null, but an ABI-violating
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

    fn scrub_key(&self, id: &str) -> StoreResult<()> {
        match self.call_raw(StoreRequest::ScrubKey(id.to_string()))? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn list_keys_since(&self, since: u64) -> StoreResult<Vec<VirtualKey>> {
        match self.call_raw(StoreRequest::ListKeysSince(since))? {
            StoreResponse::Keys(k) => Ok(k),
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

    fn purge_windows_before(&self, before: u64) -> StoreResult<u64> {
        match self.call_raw(StoreRequest::PurgeWindowsBefore(before))? {
            StoreResponse::Purged(n) => Ok(n),
            other => Err(unexpected(other)),
        }
    }

    fn purge_metering_before(&self, bucket: &str) -> StoreResult<u64> {
        match self.call_raw(StoreRequest::PurgeMeteringBefore(bucket.to_string()))? {
            StoreResponse::Purged(n) => Ok(n),
            other => Err(unexpected(other)),
        }
    }

    fn put_credential(&self, secret: &CredentialSecret) -> StoreResult<()> {
        match self.call_raw(StoreRequest::PutCredential(secret.clone()))? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> StoreResult<()> {
        match self.call_raw(StoreRequest::PutKeyWithCredential {
            key: key.clone(),
            secret: secret.clone(),
        })? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn list_credentials(&self, key_id: &str) -> StoreResult<Vec<CredentialMeta>> {
        match self.call_raw(StoreRequest::ListCredentials(key_id.to_string()))? {
            StoreResponse::Credentials(c) => Ok(c),
            other => Err(unexpected(other)),
        }
    }

    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> StoreResult<Option<CredentialSecret>> {
        match self.call_raw(StoreRequest::LookupCredentialSecret {
            kind: kind.to_string(),
            public_id: public_id.to_string(),
        })? {
            StoreResponse::CredentialSecret(c) => Ok(c),
            other => Err(unexpected(other)),
        }
    }

    fn revoke_credential(&self, id: &str, reason: &str) -> StoreResult<()> {
        match self.call_raw(StoreRequest::RevokeCredential {
            id: id.to_string(),
            reason: reason.to_string(),
        })? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn list_credentials_since(&self, since: u64) -> StoreResult<Vec<CredentialSecret>> {
        match self.call_raw(StoreRequest::ListCredentialsSince(since))? {
            StoreResponse::CredentialSecrets(c) => Ok(c),
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
        // Revocation fail-open closure. A store that cannot DECODE the `ListDenylist` request
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

    // ── A2A TASK STATE + the MCP CALL LOG ────────────────────────────────────────────────────
    //
    // THESE TEN OVERRIDES ARE THE POINT. Without them `DynStore` inherited `Store`'s defaults —
    // `put_task` returns `Ok(())` having kept nothing, `get_task` returns `None` — so a store plugin
    // that implements durable tasks flawlessly had every write DISCARDED at this seam while the call
    // reported success. `DynStore` is what the engine holds for BOTH plugin install paths, so that
    // was the production behaviour, and a test against a store crate directly cannot see it.
    //
    // Every one routes through `call_with_legacy_default` — the same choke point the denylist and
    // audit ops use — because the wire variants are ADDITIVE: a plugin whose SDK predates them
    // answers `STATUS_UNSUPPORTED`, and the honest response to "this backend does not know the op"
    // is the trait's own default, which for all ten is accept-and-keep-nothing. NOTHING ELSE is
    // defaulted: a real backend error, a caught panic and a caller-protocol violation all propagate,
    // so a durability failure can never be laundered into an empty read.

    fn put_task(&self, task: &TaskRow) -> StoreResult<()> {
        self.call_with_legacy_default(
            StoreRequest::PutTask(task.clone()),
            |r| match r {
                StoreResponse::Unit => Ok(()),
                other => Err(unexpected(other)),
            },
            || Ok(()),
        )
    }

    fn get_task(&self, task_id: &str) -> StoreResult<Option<TaskRow>> {
        self.call_with_legacy_default(
            StoreRequest::GetTask(task_id.to_string()),
            |r| match r {
                StoreResponse::Task(t) => Ok(t),
                other => Err(unexpected(other)),
            },
            || Ok(None),
        )
    }

    fn list_tasks(&self) -> StoreResult<Vec<TaskRow>> {
        self.call_with_legacy_default(
            StoreRequest::ListTasks,
            |r| match r {
                StoreResponse::Tasks(t) => Ok(t),
                other => Err(unexpected(other)),
            },
            || Ok(Vec::new()),
        )
    }

    fn purge_tasks_before(&self, before: u64) -> StoreResult<u64> {
        self.call_with_legacy_default(
            StoreRequest::PurgeTasksBefore(before),
            |r| match r {
                StoreResponse::Purged(n) => Ok(n),
                other => Err(unexpected(other)),
            },
            || Ok(0),
        )
    }

    fn append_task_event(&self, event: &TaskEventRow) -> StoreResult<()> {
        self.call_with_legacy_default(
            StoreRequest::AppendTaskEvent(event.clone()),
            |r| match r {
                StoreResponse::Unit => Ok(()),
                other => Err(unexpected(other)),
            },
            || Ok(()),
        )
    }

    fn list_task_events(&self, task_id: &str) -> StoreResult<Vec<TaskEventRow>> {
        self.call_with_legacy_default(
            StoreRequest::ListTaskEvents(task_id.to_string()),
            |r| match r {
                StoreResponse::TaskEvents(e) => Ok(e),
                other => Err(unexpected(other)),
            },
            || Ok(Vec::new()),
        )
    }

    fn append_mcp_call(&self, record: &McpCallRecord) -> StoreResult<()> {
        self.call_with_legacy_default(
            StoreRequest::AppendMcpCall(record.clone()),
            |r| match r {
                StoreResponse::Unit => Ok(()),
                other => Err(unexpected(other)),
            },
            || Ok(()),
        )
    }

    fn list_mcp_calls(&self, principal: &str) -> StoreResult<Vec<McpCallRecord>> {
        self.call_with_legacy_default(
            StoreRequest::ListMcpCalls(principal.to_string()),
            |r| match r {
                StoreResponse::McpCalls(c) => Ok(c),
                other => Err(unexpected(other)),
            },
            || Ok(Vec::new()),
        )
    }

    fn list_mcp_call_principals(&self) -> StoreResult<Vec<String>> {
        self.call_with_legacy_default(
            StoreRequest::ListMcpCallPrincipals,
            |r| match r {
                StoreResponse::McpCallPrincipals(p) => Ok(p),
                other => Err(unexpected(other)),
            },
            || Ok(Vec::new()),
        )
    }

    fn purge_mcp_calls_before(&self, before: u64) -> StoreResult<u64> {
        self.call_with_legacy_default(
            StoreRequest::PurgeMcpCallsBefore(before),
            |r| match r {
                StoreResponse::Purged(n) => Ok(n),
                other => Err(unexpected(other)),
            },
            || Ok(0),
        )
    }

    // ── THE DURABLE MCP DEMOTION RECORD + THE SPENT-APPROVAL LEDGER ──────────────────────────
    //
    // FOUR MORE OVERRIDES, for the reason the ten above are overrides. A demotion that `DynStore`
    // answered from the trait default is a demotion accepted, reported successful and discarded, so
    // the restart it exists to survive would re-open the upstream anyway — and the write would have
    // said `Ok(())` the whole time. Same for the ledger: a `redeem_ask_state` answered from the
    // default says "first redemption" to every node of a fleet, which is the double-spend the
    // durable ledger is here to stop, delivered with a green write.
    //
    // Each routes through `call_with_legacy_default` and nothing else is defaulted: a real backend
    // error, a caught panic and a caller-protocol violation all propagate.

    fn put_mcp_demotion(&self, row: &busbar_api::McpDemotionRow) -> StoreResult<()> {
        self.call_with_legacy_default(
            StoreRequest::PutMcpDemotion(row.clone()),
            |r| match r {
                StoreResponse::Unit => Ok(()),
                other => Err(unexpected(other)),
            },
            || Ok(()),
        )
    }

    fn list_mcp_demotions(&self) -> StoreResult<Vec<busbar_api::McpDemotionRow>> {
        self.call_with_legacy_default(
            StoreRequest::ListMcpDemotions,
            |r| match r {
                StoreResponse::McpDemotions(d) => Ok(d),
                other => Err(unexpected(other)),
            },
            || Ok(Vec::new()),
        )
    }

    fn clear_mcp_demotion(&self, server: &str) -> StoreResult<()> {
        self.call_with_legacy_default(
            StoreRequest::ClearMcpDemotion(server.to_string()),
            |r| match r {
                StoreResponse::Unit => Ok(()),
                other => Err(unexpected(other)),
            },
            || Ok(()),
        )
    }

    fn redeem_ask_state(&self, nonce: &str, expires_at: u64, now: u64) -> StoreResult<bool> {
        self.call_with_legacy_default(
            StoreRequest::RedeemAskState {
                nonce: nonce.to_string(),
                expires_at,
                now,
            },
            |r| match r {
                StoreResponse::Redeemed(fresh) => Ok(fresh),
                other => Err(unexpected(other)),
            },
            // "This backend does not keep a ledger", which is the trait's own default and leaves
            // the engine's in-process ledger as the only guard - exactly where a deployment with no
            // durable store already is.
            || Ok(true),
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
            deadline_ms: None,
        };
        match self
            .raw
            .transport_call::<_, busbar_plugin_abi::SecretResponse>(&req)
            .map_err(busbar_api::SecretError::internal)?
        {
            busbar_plugin_abi::SecretResponse::Bytes(b) => Ok(b),
            busbar_plugin_abi::SecretResponse::Error { kind, message } => {
                Err(busbar_api::SecretError::new(kind, message))
            }
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
#[path = "tests/lib_tests.rs"]
mod tests;
