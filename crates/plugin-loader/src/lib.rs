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
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, Store, StoreError,
    StoreResult, UsageDelta, UsageLedger, VirtualKey,
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
mod tests {
    use super::*;

    /// Locate the REAL `busbar-store-sqlite-plugin` cdylib built from a SIBLING checkout of
    /// `GetBusbar/store-sqlite` (a workspace at `../store-sqlite` relative to this repo, matching the
    /// sibling-checkout convention already used for headroom-hook/webrequest-hook and every other
    /// extracted plugin). store-sqlite now lives entirely in its own repo — there is no in-tree
    /// `kind: store` plugin left to fake, so these LOADER-mechanism tests (TOCTOU-safe loading,
    /// hot-swap coexistence, staged-file lifecycle, denylist-fallback classification — never
    /// sqlite-specific behavior, which is that repo's own job, covered by its own
    /// `store-sqlite-plugin/tests/e2e.rs`) exercise the REAL plugin instead of a fixture. Returns
    /// `None` if the sibling checkout isn't present or hasn't been built — local iteration without
    /// the sibling checked out skips cleanly.
    ///
    /// CI HARDENING: `.github/workflows/dev-gate.yml` checks out `../store-sqlite` as a sibling and
    /// runs `cargo build --release` there before running this workspace's tests, so under that
    /// workflow's `CI` env var the cdylib MUST be present — its absence there is a broken pipeline,
    /// a HARD FAILURE here rather than a silent skip, so this coverage cannot quietly vanish. The
    /// lightweight per-push `ci.yml` does NOT check out this sibling (it stays fast), so these tests
    /// skip there — real coverage runs on every push to `dev`/`*-dev` via `dev-gate.yml` instead.
    fn store_fixture_plugin_path() -> Option<std::path::PathBuf> {
        let candidate = {
            let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")); // .../busbarAI/crates/plugin-loader
            let sibling_root = manifest_dir.join("../../../store-sqlite"); // sibling of busbarAI
            let name = plugin_library_filename("busbar_store_sqlite_plugin");
            let candidate = sibling_root.join("target/release").join(&name);
            candidate.exists().then_some(candidate)
        };
        if candidate.is_none()
            && std::env::var_os("CI").is_some()
            && std::env::var_os("DEV_GATE").is_some()
        {
            panic!(
                "the store-sqlite-plugin cdylib is not built from the ../store-sqlite sibling \
                 checkout under dev-gate.yml: refusing to silently skip loader-mechanism coverage \
                 of the kind:store dlopen seam."
            );
        }
        candidate
    }

    /// A fresh, unique `db_path` config for the real store-sqlite-plugin fixture, so concurrent
    /// tests in this binary never share a SQLite file. Every one of these tests used to pass `"{}"`
    /// (the plugin's own documented "must work" empty-config default), which resolves to the
    /// FIXED relative path `busbar-governance.db` in the test process's cwd — under `cargo test`'s
    /// default parallel execution, every such test collided on the SAME file: `list_keys()`
    /// assertions failed because a concurrent test had already written keys to it, and `wire_up_raw`
    /// itself failed outright with a real SQLite `disk I/O error` under lock contention between
    /// concurrent opens — reproducible under `DEV_GATE=1 cargo test --release -p
    /// busbar-plugin-loader`.
    ///
    /// These files are deliberately NOT deleted by the test that creates them — a test can't know
    /// when it's safe to remove its own db file (the store may still be open, or a sibling process
    /// under `-j`-parallel `cargo test` invocations may share the same `$TMPDIR`), and CI runners
    /// are ephemeral (wiped between runs) so this never accumulates there. On a long-lived local
    /// dev machine it CAN accumulate across many `cargo test` invocations (observed: 174 files,
    /// ~14MB) — self-cleans that by opportunistically sweeping this
    /// process's OWN prior runs' files (matched by name pattern, not PID liveness — simpler and
    /// good enough for a `$TMPDIR` nuisance, not a correctness concern) older than an hour, once
    /// per test-binary invocation.
    fn unique_sqlite_cfg(name: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Once;
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        static SWEEP_ONCE: Once = Once::new();
        SWEEP_ONCE.call_once(|| {
            let cutoff = std::time::Duration::from_secs(3600);
            let now = std::time::SystemTime::now();
            let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
                return;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if !name.starts_with("busbar-plugin-loader-test-") || !name.ends_with(".db") {
                    continue;
                }
                let Ok(meta) = entry.metadata() else { continue };
                let Ok(modified) = meta.modified() else {
                    continue;
                };
                if now.duration_since(modified).unwrap_or_default() > cutoff {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        });
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "busbar-plugin-loader-test-{}-{name}-{n}.db",
            std::process::id()
        ));
        serde_json::json!({ "db_path": path.to_string_lossy() }).to_string()
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

    /// `validate_plugin` accepts the real store-sqlite-plugin cdylib (ABI v1) without constructing a
    /// store, and `inventory` finds it (and any sibling plugins) in the target directory as valid.
    #[test]
    fn validate_and_inventory() {
        let Some(path) = store_fixture_plugin_path() else {
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
            return;
        };
        assert_eq!(validate_plugin(&path).expect("validate"), TRANSPORT_VERSION);

        let dir = path.parent().unwrap();
        let inv = inventory(dir);
        let fixture = inv
            .iter()
            .find(|p| p.file.contains("busbar_store_sqlite_plugin"))
            .expect("sibling store-sqlite-plugin in inventory");
        assert!(fixture.valid);
        assert_eq!(fixture.abi_version, Some(TRANSPORT_VERSION));
        assert!(fixture.error.is_none());
    }

    /// `inventory` of a missing directory is empty, not an error.
    #[test]
    fn inventory_missing_dir_is_empty() {
        assert!(inventory(Path::new("/no/such/plugins/dir")).is_empty());
    }

    /// `intern_name` reuses the SAME allocation for repeated sightings of the same name (that's the
    /// whole point - bounding the leak to one per distinct name), while two DIFFERENT names get
    /// distinct interned strings. Checked via pointer identity, not just string equality, since two
    /// equal-but-differently-allocated `&'static str`s would defeat the interning claim silently.
    #[test]
    fn intern_name_reuses_the_same_allocation_for_a_repeated_name() {
        let a1 = intern_name("plugin-a-unique-for-this-test");
        let a2 = intern_name("plugin-a-unique-for-this-test");
        assert_eq!(
            a1.as_ptr(),
            a2.as_ptr(),
            "the same name must reuse the SAME leaked allocation, not leak a fresh one each call"
        );
        let b = intern_name("plugin-b-unique-for-this-test");
        assert_ne!(
            a1.as_ptr(),
            b.as_ptr(),
            "a different name is a different allocation"
        );
        assert_eq!(b, "plugin-b-unique-for-this-test");
    }

    #[test]
    fn is_library_file_matches_only_this_platforms_extension() {
        let expected_ext = if cfg!(target_os = "windows") {
            ".dll"
        } else if cfg!(target_os = "macos") {
            ".dylib"
        } else {
            ".so"
        };
        assert!(is_library_file(&format!("libfoo{expected_ext}")));
        assert!(!is_library_file("libfoo.txt"));
        assert!(!is_library_file("libfoo"));
        assert!(!is_library_file("README.md"));
        // The "only" in this test's name wasn't actually proven before: an implementation
        // accepting every platform's library extension everywhere (e.g. `.dylib` on Linux too)
        // would have passed the assertions above unchanged. Explicitly assert the OTHER platforms'
        // extensions are rejected on THIS platform.
        for other_ext in [".dll", ".dylib", ".so"] {
            if other_ext == expected_ext {
                continue;
            }
            assert!(
                !is_library_file(&format!("libfoo{other_ext}")),
                "a foreign platform's library extension ({other_ext}) must be rejected on this \
                 platform (expects {expected_ext})"
            );
        }
    }

    /// `list_plugin_files` lists only library-extension files, sorted, and NEVER dlopens anything
    /// (so it must return real filenames even for a garbage/non-plugin library file that would fail
    /// `validate_plugin`).
    #[test]
    fn list_plugin_files_filters_to_libraries_only_and_sorts() {
        let dir = std::env::temp_dir().join(format!(
            "busbar-list-plugin-files-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ext = if cfg!(target_os = "windows") {
            ".dll"
        } else if cfg!(target_os = "macos") {
            ".dylib"
        } else {
            ".so"
        };
        std::fs::write(dir.join(format!("zzz{ext}")), b"not a real library").unwrap();
        std::fs::write(dir.join(format!("aaa{ext}")), b"not a real library either").unwrap();
        std::fs::write(dir.join("readme.txt"), b"not a library at all").unwrap();
        let files = list_plugin_files(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            files,
            vec![format!("aaa{ext}"), format!("zzz{ext}")],
            "only library-extension files, sorted, no dlopen (garbage bytes never rejected here)"
        );
    }

    /// `inventory` reports BOTH a real valid plugin AND a garbage same-extension file in the same
    /// directory, correctly distinguishing valid=true/false rather than silently dropping the
    /// invalid one or crashing on it.
    #[test]
    fn inventory_reports_valid_and_invalid_libraries_in_the_same_directory() {
        let Some(real_plugin) = store_fixture_plugin_path() else {
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
            return;
        };
        let dir = std::env::temp_dir().join(format!(
            "busbar-inventory-mixed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ext = if cfg!(target_os = "windows") {
            ".dll"
        } else if cfg!(target_os = "macos") {
            ".dylib"
        } else {
            ".so"
        };
        std::fs::copy(&real_plugin, dir.join(format!("real{ext}"))).unwrap();
        std::fs::write(dir.join(format!("garbage{ext}")), b"not a real library").unwrap();
        std::fs::write(dir.join("readme.txt"), b"ignored: not a library extension").unwrap();
        let mut items = inventory(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        items.sort_by(|a, b| a.file.cmp(&b.file));
        assert_eq!(
            items.len(),
            2,
            "readme.txt must be excluded entirely: {items:?}"
        );
        let garbage = items
            .iter()
            .find(|i| i.file.starts_with("garbage"))
            .unwrap();
        assert!(!garbage.valid);
        assert!(garbage.error.is_some());
        let real = items.iter().find(|i| i.file.starts_with("real")).unwrap();
        assert!(real.valid, "the real plugin must validate: {real:?}");
        assert_eq!(real.abi_version, Some(TRANSPORT_VERSION));
    }

    /// `wire_up_raw`'s two independent kind gates must BOTH fire, and must fire for the RIGHT
    /// reason: exported-vs-expected (the ABI seam calling this as the wrong kind) and
    /// exported-vs-manifest (the signed manifest disagreeing with what the library actually
    /// exports) are two different attacks and must not be conflatable into one check.
    #[test]
    fn wire_up_raw_rejects_a_kind_mismatch_against_the_seam_and_the_manifest() {
        let Some(store_plugin) = store_fixture_plugin_path() else {
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
            return;
        };
        let bytes = std::fs::read(&store_plugin).expect("read sibling store-sqlite-plugin cdylib");

        // Seam mismatch: a real STORE library loaded through the SECRET entry point (expected_kind
        // = secret, exported_kind = store) must be refused, naming both kinds. Both kind-check
        // guards run BEFORE `busbar_open`/real backing construction, so an empty `"{}"` config here
        // never actually reaches sqlite today — but `unique_sqlite_cfg` costs nothing and removes
        // the latent risk of this test starting to collide with sibling tests on the shared
        // `busbar-governance.db` default path if that check ordering ever changes.
        let Err(err) = load_secret_from_bytes(
            &bytes,
            &unique_sqlite_cfg("kind-mismatch-seam"),
            "kind-mismatch-seam",
            abi_kind::STORE,
        ) else {
            panic!("a store library must not load as a secret module");
        };
        assert!(err.contains("store"), "must name the exported kind: {err}");
        assert!(err.contains("secret"), "must name the expected kind: {err}");

        // Manifest mismatch: expected_kind matches exported_kind (both store), but the signed
        // manifest_kind lies about it — must still be refused.
        let Err(err) = load_store_from_bytes(
            &bytes,
            &unique_sqlite_cfg("kind-mismatch-manifest"),
            "kind-mismatch-manifest",
            "secret",
        ) else {
            panic!("an exported-store/manifest-secret disagreement must be refused");
        };
        assert!(
            err.contains("kind mismatch"),
            "must name it as a manifest disagreement, not a seam mismatch: {err}"
        );
    }

    #[test]
    fn plugin_library_filename_matches_this_platforms_naming_convention() {
        let name = plugin_library_filename("busbar_foo_plugin");
        if cfg!(target_os = "windows") {
            assert_eq!(name, "busbar_foo_plugin.dll");
        } else if cfg!(target_os = "macos") {
            assert_eq!(name, "libbusbar_foo_plugin.dylib");
        } else {
            assert_eq!(name, "libbusbar_foo_plugin.so");
        }
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

    /// Pins the length cap on the `busbar_open` error path, mirroring `response_len_ok`'s on the
    /// `busbar_call` path. Covered as a unit test rather than over the ABI: there is no fake-open
    /// seam (`dyn_store_with_fake_call` only patches `call` on an already-opened `DynStore`), and
    /// the failure mode of an unchecked length is an out-of-bounds read, not a clean assertion
    /// failure.
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
        let Some(path) = store_fixture_plugin_path() else {
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read sibling store-sqlite-plugin cdylib");
        let store = load_store_from_bytes(
            &bytes,
            &unique_sqlite_cfg("fixture-from-bytes"),
            "fixture-from-bytes",
            "store",
        )
        .expect("load from verified bytes");
        let key = VirtualKey {
            id: "vk_b".into(),
            generation_hash: "h".into(),
            name: "b".into(),
            allowed_scopes: Some(vec![busbar_api::ScopeRef::pool("p")]),
            enabled: true,
            created_at: 1,
            group: None,
            labels: std::collections::BTreeMap::new(),
            expires_at: None,
            deleted_at: None,
            revision: 1,
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
        let Some(path) = store_fixture_plugin_path() else {
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
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
            load_store(&victim, &unique_sqlite_cfg("toctou-victim")).is_err(),
            "the swapped-in junk is not a loadable plugin (path load sees the swap)"
        );
        // ..but the from-bytes load, fed the bytes we verified BEFORE the swap, loads fine.
        let store =
            load_store_from_bytes(&verified, &unique_sqlite_cfg("toctou"), "toctou", "store")
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
    /// Every `busbar-plugins-<pid>-*` staging directory currently in the temp dir. The prefix is
    /// keyed on the process id, which every test in this binary shares, so this set is only
    /// meaningful as a before/after DIFFERENCE, never as an absolute count.
    fn staging_dirs_for_this_process() -> std::collections::BTreeSet<std::path::PathBuf> {
        let prefix = format!("busbar-plugins-{}-", std::process::id());
        std::fs::read_dir(std::env::temp_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(&prefix))
            })
            .map(|e| e.path())
            .collect()
    }

    /// Asserts on THIS load's own staged path, not a process-wide count of
    /// `busbar-plugins-<pid>-*` entries. The count was the wrong instrument twice over: FLAKY,
    /// because a concurrent test in this binary stages or releases files between the two samples
    /// (this test failed ~2/5 under a loaded run); and WEAK, because `after <= before` still passes
    /// while this load's file leaks, as long as some other test's file went away in the same
    /// window. The exact path is immune to concurrency and actually fails when the artifact leaks.
    #[test]
    fn from_bytes_load_leaves_no_artifact_after_drop() {
        let Some(path) = store_fixture_plugin_path() else {
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read sibling store-sqlite-plugin cdylib");
        // Snapshot before the load, so the memfd branch below can assert on what THIS load created
        // rather than on a process-wide total that a concurrent test contributes to.
        let before = staging_dirs_for_this_process();
        let staged: Option<std::path::PathBuf> = {
            let store = load_dyn_store_from_bytes(
                &bytes,
                &unique_sqlite_cfg("no-leak-check"),
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
            // There is no path to assert on here, so this is the one branch that has to look at the
            // directory. It compares against a snapshot taken BEFORE the load rather than asserting
            // an absolute count of zero: the `busbar-plugins-<pid>-*` prefix is keyed on the PROCESS
            // id, which every test in this binary shares, so an absolute count sees any staging
            // directory a concurrently-running test happens to own and fails on it. That is the
            // exact flake this test's own doc comment says the path-based assertion replaced -- but
            // the replacement only reached the `Some(p)` branch, and this is the branch Linux CI
            // always takes, so the fix landed everywhere except where it was needed. Observed
            // failing this way on qa-gate run 31094255293 having passed twice on the same commit.
            None => {
                let after = staging_dirs_for_this_process();
                let created: Vec<_> = after.difference(&before).collect();
                assert!(
                    created.is_empty(),
                    "a memfd load reports no staged path, so it must have created no staging \
                     directory either, but these appeared: {created:?}"
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
        let Some(path) = store_fixture_plugin_path() else {
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read sibling store-sqlite-plugin cdylib");

        // The OLD instance is serving; write a key so we can prove instance IDENTITY across the swap.
        // Load via `load_dyn_store_from_bytes` (as the fixed sibling
        // `from_bytes_load_leaves_no_artifact_after_drop` does) so each generation's OWN
        // `staged_path()` is reachable — asserting on it, not a process-wide directory count that a
        // concurrent test in this binary can shift in either direction between samples.
        let old =
            load_dyn_store_from_bytes(&bytes, &unique_sqlite_cfg("old-gen"), "old-gen", "store")
                .expect("load OLD");
        let old_path = old.staged_path().map(std::path::Path::to_path_buf);
        if let Some(p) = &old_path {
            assert!(p.is_file(), "OLD's staged backing must exist while alive");
        }
        let key = busbar_api::VirtualKey {
            id: "vk_old".into(),
            generation_hash: "h".into(),
            name: "old".into(),
            allowed_scopes: Some(vec![busbar_api::ScopeRef::pool("p")]),
            enabled: true,
            created_at: 1,
            group: None,
            labels: std::collections::BTreeMap::new(),
            expires_at: None,
            deleted_at: None,
            revision: 1,
        };
        old.put_key(&key).expect("old put");

        // Load the NEW instance ALONGSIDE the old — both libraries are mapped simultaneously. On
        // macOS/Windows this is two staged files at once; on Linux two memfds (no disk).
        let new =
            load_dyn_store_from_bytes(&bytes, &unique_sqlite_cfg("new-gen"), "new-gen", "store")
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
        // The NEW instance is a DISTINCT on-disk SQLite backend (each generation gets its own
        // `unique_sqlite_cfg()` db_path): it does NOT see the old key. Because each generation has a
        // genuinely separate backing file, this is real proof that NEW is a second, independent
        // load — not a cached alias of the first.
        assert!(
            new.get_key("vk_old").expect("new get").is_none(),
            "the new instance's own db_path must be a real, separate backend — not aliasing OLD's"
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
            generation_hash: "h".into(),
            name: "new".into(),
            allowed_scopes: Some(vec![busbar_api::ScopeRef::pool("p")]),
            enabled: true,
            created_at: 2,
            group: None,
            labels: std::collections::BTreeMap::new(),
            expires_at: None,
            deleted_at: None,
            revision: 1,
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
        let Some(path) = store_fixture_plugin_path() else {
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read sibling store-sqlite-plugin cdylib");
        // Per-cycle own path, not a process-wide count: a concurrent test staging or releasing a
        // file in this binary between samples can move the count in either direction, hiding a real
        // leak or reporting a false one. Collect this run's own paths and assert each is gone after
        // its own drop, and that no two cycles reused the same path.
        let mut seen = std::collections::HashSet::new();
        for i in 0..16 {
            let s = load_dyn_store_from_bytes(
                &bytes,
                &unique_sqlite_cfg(&format!("reload-{i}")),
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
        let Some(path) = store_fixture_plugin_path() else {
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read sibling store-sqlite-plugin cdylib");
        // The actual claim ("a memfd load reports no staged path"), not a directory census: a
        // process-wide count is quiet here only because the common Linux path never touches disk in
        // the first place, but the instrument is the same flawed one the sibling tests above moved
        // away from — a concurrent test staging a file on the non-memfd fallback path between the
        // two samples would have made this assertion fail for a reason unrelated to THIS load.
        let store = load_dyn_store_from_bytes(
            &bytes,
            &unique_sqlite_cfg("memfd-check"),
            "memfd-check",
            "store",
        )
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
    // `call` fn pointer; the real `open`/`free`/`close`/handle from the loaded store fixture stay valid.

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
        let path = store_fixture_plugin_path()?;
        // Stage a genuine `RawPlugin` (real `Library` + handle + `close`), then splice in our fake
        // `call`/`free` so the response's (status, body) is what the test chooses.
        let bytes = std::fs::read(&path).expect("read sibling store-sqlite-plugin cdylib");
        // `.expect`, NOT `.ok()?`: the ONLY sanctioned reason these revocation guards may skip is
        // "the cdylib was never built" — which `store_fixture_plugin_path` already turns into a hard
        // panic under CI. A STAGING failure is a different thing entirely, and swallowing it into a
        // `None` would let the whole revocation fail-open suite self-disable while the run stayed
        // green.
        let (lib, staged) = stage::load_library_from_bytes(&bytes, "fake-call-store")
            .expect("stage the sibling store-sqlite-plugin cdylib for the fake-call harness");
        let mut raw = wire_up_raw(
            lib,
            &unique_sqlite_cfg("fake-call-store"),
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
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
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
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
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

    /// THE CLASS TEST for the revocation fail-open. It enumerates every way a store plugin of ANY
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
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
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
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
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
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
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

    // ── Class-level loader discrimination harness: the SAME matrix of injected
    // statuses × the three fallback-bearing methods, driven through the real
    // `call_raw_status` → `TransportError::from_status` → `is_unsupported()` path. A new
    // fallback-bearing method inherits this coverage the moment it keys on `is_unsupported()`. ────

    /// THE REGRESSION GUARD: a plugin PANIC on `ListDenylist` arrives as `STATUS_PANIC` → `Fault`,
    /// `is_unsupported()` is false, so `list_denylist` fails CLOSED (Err) — it does NOT silently return
    /// `Ok(vec![])`. Under the earlier taxonomy a panic returned `STATUS_PROTOCOL` and was misread as
    /// old-SDK, hydrating an EMPTY revocation denylist (accepting revoked tokens). Now structurally
    /// impossible: STATUS_PANIC and STATUS_UNSUPPORTED are different integers → different kinds.
    #[test]
    fn panic_in_list_denylist_fails_closed_not_empty() {
        let Some(store) = dyn_store_with_fake_call() else {
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
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
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
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
            eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
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
        // caller-protocol violation, NOT unsupported. Reading it as unsupported is the inversion that
        // reopens the revocation fail-open.
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

    /// `kind: secret` is the one plugin kind with no other over-the-ABI test coverage. Locate the
    /// hermetic `busbar-secret-example-plugin` cdylib, mirroring `store_fixture_plugin_path` above — CI
    /// (`cargo test --workspace`) always builds it, so a missing cdylib there is a hard failure, not
    /// a silent skip.
    /// Checks BOTH the "uplifted" `<profile_dir>/<name>` copy and the raw `<profile_dir>/deps/<name>`
    /// compiler output — a SCOPED `cargo test -p busbar-plugin-loader` (what dev-gate.yml's final
    /// step runs) does not uplift the cdylib to the top-level profile dir, only to `target/deps`,
    /// so checking only `profile_dir` silently found nothing even though the cdylib really was
    /// built. Same fix already applied to `store_fixture_plugin_path` above and `hook_plugin_path`
    /// in `hook.rs`.
    fn secret_example_plugin_path() -> Option<std::path::PathBuf> {
        let candidate = (|| {
            let exe = std::env::current_exe().ok()?;
            let profile_dir = exe.parent()?.parent()?;
            let name = plugin_library_filename("busbar_secret_example_plugin");
            let uplifted = profile_dir.join(&name);
            let raw = profile_dir.join("deps").join(&name);
            [uplifted, raw]
                .into_iter()
                .filter_map(|p| {
                    std::fs::metadata(&p)
                        .and_then(|m| m.modified())
                        .ok()
                        .map(|mtime| (p, mtime))
                })
                .max_by_key(|(_, mtime)| *mtime)
                .map(|(p, _)| p)
        })();
        if candidate.is_none() && std::env::var_os("CI").is_some() {
            panic!(
                "the secret example plugin cdylib is not built under CI: `cargo test --workspace` \
                 must build busbar_secret_example_plugin (checked both the uplifted target dir and \
                 target/deps). Refusing to silently skip the only over-the-ABI coverage of the \
                 DynSecret dlopen seam."
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

    /// Locate the hermetic `busbar-export-example-plugin` cdylib, mirroring
    /// `secret_example_plugin_path` above (see its doc for the uplifted-vs-`deps` rationale). CI
    /// (`cargo test --workspace`) always builds it, so a missing cdylib there is a hard failure, not a
    /// silent skip — it is the only over-the-ABI coverage of the `DynExport` dlopen seam.
    fn export_example_plugin_path() -> Option<std::path::PathBuf> {
        let candidate = (|| {
            let exe = std::env::current_exe().ok()?;
            let profile_dir = exe.parent()?.parent()?;
            let name = plugin_library_filename("busbar_export_example_plugin");
            let uplifted = profile_dir.join(&name);
            let raw = profile_dir.join("deps").join(&name);
            [uplifted, raw]
                .into_iter()
                .filter_map(|p| {
                    std::fs::metadata(&p)
                        .and_then(|m| m.modified())
                        .ok()
                        .map(|mtime| (p, mtime))
                })
                .max_by_key(|(_, mtime)| *mtime)
                .map(|(p, _)| p)
        })();
        if candidate.is_none() && std::env::var_os("CI").is_some() {
            panic!(
                "the export example plugin cdylib is not built under CI: `cargo test --workspace` \
                 must build busbar_export_example_plugin (checked both the uplifted target dir and \
                 target/deps). Refusing to silently skip the only over-the-ABI coverage of the \
                 DynExport dlopen seam."
            );
        }
        candidate
    }

    /// END-TO-END over the REAL export-example-plugin cdylib: load it through the loader (which queries
    /// `Streams` once at load), assert it reports `[Metrics]`, then `Deliver` a metrics batch and
    /// assert the sink acks `Delivered` (an `Ok(())`). This is the exact seam the engine's
    /// observability export will consume: verified bytes in, a `DynExport` out.
    #[test]
    fn load_and_exercise_export_example_plugin() {
        use busbar_plugin_abi::export::ExportStream;
        let Some(path) = export_example_plugin_path() else {
            eprintln!("skip: export example plugin cdylib not built (run under --workspace)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read export example plugin cdylib");
        let sink = export::load_export_from_bytes(&bytes, "{}", "export-example", "export")
            .expect("load export example plugin over the ABI");

        // Streams was queried once at load and reports exactly [Metrics].
        assert_eq!(sink.streams(), &[ExportStream::Metrics]);

        // A delivery for the declared stream acks Delivered (Ok).
        sink.deliver(
            ExportStream::Metrics,
            &serde_json::json!({"samples": [{"name": "reqs", "value": 1}]}),
        )
        .expect("deliver returns Delivered");
    }
}
