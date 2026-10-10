// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN LOADER: discovery, trust and the registry ([`registry`], [`sign`], [`tarball`]); the
//! ONE loading path and the ONE dispatcher of the memory ABI ([`dispatch`]: `load_linked` /
//! `load_dropped`), through which every store, secret, auth, hook and export plugin loads,
//! compiled in or dropped in (`BUSBAR-1.6.0.md` THE DESIGN §11); and the HOT lane the planes and
//! transports that have not moved to their door still ride ([`plane`], [`transport`]).
//!
//! M6-COLD-DELETE residue: the raw JSON-lane load below ([`Image`], `RawPlugin`) serves only the
//! `kind: auth` plugin still built on it ([`auth`]: its verify and its hosted login), until that
//! plugin's door re-pin. No store, secret, hook or export plugin loads through it.

use busbar_contract::abi::cold::{
    symbol, CallFn, CloseFn, FreeFn, MAX_PLUGIN_RESPONSE_LEN, STATUS_ERR, STATUS_OK, STATUS_PANIC,
    STATUS_PROTOCOL, STATUS_UNSUPPORTED,
};
use busbar_contract::abi::cold::{PluginKindFn, TRANSPORT_VERSION};
use libloading::Library;
use std::os::raw::c_void;
use std::path::Path;

pub mod auth;
pub mod auth_axis;
pub mod auth_door;
/// THE BOOT STAGES the loader owns: what config uses, Discover, Select and the one load
/// (`BUSBAR-1.6.0.md` THE DESIGN, §3).
pub mod boot;
pub mod carrier;
/// THE PUBLISHED CONFORMANCE SUITE (TODO ABI-b4): what every real plugin repo runs against the busbar
/// commit it pins, linked and dropped in, through the one loader. Behind `conformance`: a plugin's
/// dev-dependency turns it on; no busbar build ships it. This crate's own tests drive the shipped
/// transport row through it too (`transport_door_conformance_tests`).
#[cfg(any(test, feature = "conformance"))]
pub mod conformance;
/// THE ONE DISPATCHER of the memory ABI (`BUSBAR-1.6.0.md` THE DESIGN, §11): one loader path, one
/// crossing, tickets, wakes, deadlines and the watchdog, generic over the kind.
pub mod dispatch;
/// THE ONE DURABLE-WRITE OWNER: the whole-file publish (temp, fsync, rename, fsync the holding
/// directory) every durable file write in busbar goes through — the loader's own (fetched artifacts,
/// the high-water marks, plugin log directories) and, through `busbar_kernel::durable`, the
/// kernel's and the admin surface's. It lives here because the loader is the lowest host-only crate
/// every writer links (Part 2 #33: the loader names `busbar-contract` alone, so it cannot reach a
/// kernel crate for it). Host-only: no plugin image links this crate, so its temp-name counter is
/// one per process.
pub mod durable;
pub mod export_axis;
pub mod export_door;
pub mod fetch;
mod ffi_thread;
pub mod highwater;
pub mod hook_door;
mod host;
mod hostlog;
/// NEVER SHIPPED: the framed connection-table stand-in with in-process far ends (`test-support`,
/// and the published conformance suite's `far_ends`), for a build that cannot link the process's
/// connector. No TLS library: TLS stays in the connector.
#[cfg(any(test, feature = "test-support", feature = "conformance"))]
pub mod https_conns;
pub mod observe;
pub mod plane;
pub mod registry;
/// THE SECRET AXIS over the one dispatcher: every admitted secret plugin, linked or dropped in.
pub mod secret_calls;
// The former `busbar-plugin-sign` crate, folded in whole (DECISIONS #33): signature verify +
// trust evaluation is the loader's OWN job, not a crate the loader reaches for. Pure data +
// policy, no I/O -- the I/O that acts on its verdicts is `tarball`, `fetch` and `registry`.
/// TEST ONLY: a real door restated with one `tcp` need (the bind tests' subject; no plugin).
#[cfg(test)]
#[path = "tests/needs_restated.rs"]
mod needs_restated;
pub mod sign;
mod stage;
pub mod store_adapter;
pub mod store_v3;
pub mod tarball;
/// TEST ONLY: the test connection table. Also the published conformance suite's (`conformance`):
/// a plugin repo names this crate only as a dev-dependency, so it reaches no shipped closure.
#[cfg(any(test, feature = "test-support", feature = "conformance"))]
pub mod tcp_conns;
/// TEST ONLY: a local token issuer (an ES256 key, its JWKS, signed tokens) for the tests of a host
/// that loads a token-verifying auth plugin (`test-support`).
#[cfg(any(test, feature = "test-support"))]
pub mod test_issuer;
/// TEST ONLY: the fake-call store harness the kernel's minting tests share with this crate's own.
/// Compiled for this crate's tests and under the `test-support` feature, which only
/// busbar-kernel's `[dev-dependencies]` edge turns on; never in a shipped build.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[path = "tests/test_support.rs"]
pub mod test_support;
pub mod transport;
pub mod transport_adapter;

/// THE REGISTRY AS THE KERNEL READS IT (the contract's `PluginRows`).
pub mod rows;

pub use auth::DynAuth;
use busbar_contract::abi::cold::ColdEntry;
pub use sign::EgressPolicy;

impl LinkedPlugin {
    /// A FIRST-PARTY memory-ABI plugin a build links: `name` aliased `alias`, of `kind`, at this
    /// loader's one version of the kind, published by busbar — the manifest its release tarball
    /// states — over its `door` (`plugin_door!`): the same door its `cdylib` exports.
    pub fn first_party_door(
        kind: &str,
        name: &str,
        alias: &str,
        door: busbar_contract::abi::mechanism::door::DoorFn,
    ) -> Self {
        let mut row = LinkedPlugin::door_of_kind(kind, name, door);
        row.manifest.alias = alias.into();
        row
    }
}

pub use carrier::{HotReply, ReplyStream, RequestHead, MAX_PLANE_REPLY_LEN};
pub use fetch::{fetch_plugins, FetchOutcome, FetchSpec};
pub use highwater::{HighWaterMarks, HIGH_WATER_FILE};
pub use plane::{
    link_plane, load_plane, load_plane_from_bytes, DynPlane, HotClaim, HotDeclaration, ServedPlane,
};
pub use registry::{
    inventory as inventory_tarballs, scan_and_validate, supported_abi, InventoryEntry, LinkedEntry,
    LinkedPlugin, LoadablePlugin, PluginRegistry, SkippedPlugin,
};
pub use stage::sweep_dead_staging;
pub use transport::{
    host_wake, link_transport, load_transport_from_bytes, wire_settings, Built, DeclCarrier,
    DeclFramer, DynTransport, WakeToken, HOST_WAKER,
};
pub use transport_adapter::{CarrierIo, WireTransport};

/// THE LOADER RE-EXPORTS NO CONTRACT TYPE (BOOT-LOOP step 3, ruling R2). A type the contract owns
/// is named from `busbar_contract::abi::*`, the crate that owns it; the loader path to it does not
/// compile. Each block below is one former loader re-export, and each must stay a compile error.
///
/// ```compile_fail
/// use busbar_plugin_loader::EndpointRequest;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::EndpointResponse;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::Route;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::RouteAuth;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::RouteMethod;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::CheckPhase;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::ExportField;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::ExportStream;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HostResult;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HttpRequest;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HttpResponse;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::ColdEntry;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HotDeclStr;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HotPlaneDecl;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HotHostVtable;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HotStatusClass;
/// ```
pub mod contract_types_are_named_from_the_contract {}

/// INTERN a plugin name into a stable `&'static str`, reusing one allocation per unique name.
///
/// The hook routing seam and `DynAuth` carry `name: &'static str`, and a name string used to be
/// `Box::leak`ed on EVERY open — but hook and auth opens run per config/plugin reload, per `push_configure`, per
/// `fetch_status` (every Prometheus `/metrics/hooks` scrape refresh), per `fetch_schema`, and per
/// `resolve_on_error_chain`, so the leak was per-CALL and unbounded over the process lifetime, driven
/// by routine external scraping. Interning bounds it to ONE leak per DISTINCT plugin name for the life
/// of the process: a repeated open of the same plugin reuses the interned `&'static str`.
pub fn intern_name(name: &str) -> &'static str {
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

/// `dlopen` on a worker that never retires. Mapping an image RUNS ITS ELF `.init_array` — that is
/// plugin code, on whatever thread called it, and it is as capable of arming the plugin's
/// `pthread_key` TLS destructor as any ABI symbol. Routed for the same reason [`ffi_guard`] is.
pub(crate) fn dlopen_on_worker(path: &std::ffi::OsStr) -> Result<Library, String> {
    // SAFETY (unchanged from the direct call this replaces): loading an operator-placed library runs
    // its init code, which is the same trust as compiling it in. Callers apply the trust gate first.
    match ffi_thread::on_plugin_thread(|| unsafe { Library::new(path) }) {
        Ok(r) => r.map_err(|e| e.to_string()),
        // An init constructor that PANICKED into us. Vanishingly rare, but the rendezvous must
        // produce a value rather than resume an unwind on a worker whose thread must not die.
        Err(_) => Err("the library's initializer panicked while loading".to_string()),
    }
}

/// `dlclose` on a worker that never retires. Unmapping runs the image's `.fini_array` — plugin code
/// again — and doing it on a caller thread would hand that thread plugin TLS at the exact moment the
/// image is going away, which is the crash in its purest form.
pub(crate) fn dlclose_on_worker(lib: Library) {
    #[cfg(test)]
    UNLOADS_ON_WORKER.with(|n| n.set(n.get() + 1));
    let _ = ffi_thread::on_plugin_thread(move || drop(lib));
}

#[cfg(test)]
thread_local! {
    /// TEST-ONLY: how many library unloads THIS THREAD has routed through [`dlclose_on_worker`]. An
    /// unload that happens by an implicit field/local drop instead runs the image's `.fini_array` on
    /// whatever thread dropped it, and a caller thread that later retires is the crash `ffi_thread`
    /// documents — a property no assertion on a returned value can see. Counting the routed unloads
    /// is what makes it observable.
    ///
    /// THREAD-LOCAL, not a global atomic: libtest runs siblings in parallel, and a sibling that
    /// loaded and unloaded a plugin between a global counter's two samples would satisfy a "went up"
    /// assertion while the path under test unloaded on the caller's thread — a test that passes in
    /// the red state. `dlclose_on_worker` is called on the routing thread (only the drop moves to
    /// the worker), so a per-thread count sees exactly this caller's unloads and nobody else's.
    pub(crate) static UNLOADS_ON_WORKER: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Run an FFI call `f` across the plugin ABI boundary under `catch_unwind`, converting a panic that
/// unwinds out of `f` into a fail-closed `Err` string. `op` names the crossing
/// (`open`/`call`/`close`/`free`/`abi`/`kind`) for the diagnostic. Every host-side ABI call site
/// routes through this so no crossing is unguarded.
///
/// WHAT IT CAN AND CANNOT CATCH — measured, not assumed (`loader_seam_tests`):
///
/// - An unwind raised by THIS process's Rust runtime — a compiled-in module, or host code on the
///   far side of the fn pointer — is caught and becomes `Err`. The ABI fn pointers are
///   `extern "C-unwind"`, so such an unwind is defined and reaches this frame.
/// - An unwind raised by a DLOPENED plugin's own panic runtime is NOT. A plugin cdylib statically
///   links its own copy of std, and std's `catch_unwind` recognises only exceptions its own copy
///   threw: anything else is a foreign exception, and the runtime ABORTS the process ("Rust cannot
///   catch foreign exceptions"). So for a dropped-in plugin, failing closed on a panic is the
///   PLUGIN's obligation, discharged on the plugin side of the boundary — the SDK's dispatchers
///   catch every panic in plugin code and answer `STATUS_PANIC`. A plugin not built with the SDK
///   that lets a panic escape its exported fns takes the engine down with it, and nothing on this
///   side of the seam can prevent that.
fn ffi_guard<R>(path: &str, op: &str, f: impl FnOnce() -> R) -> Result<R, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|_| {
        format!("plugin '{path}' panicked across the ABI boundary in {op} (treated as failure)")
    })
}

/// [`ffi_guard`], but the crossing runs on a worker thread that NEVER retires.
///
/// THE COST MODEL, which is why this is a separate function rather than the default. Confining a
/// crossing costs a synchronous thread handoff — measured at ~41 us against ~0.9 us inline on a
/// 2-vCPU VM. That is irrelevant for a crossing that happens once per LOAD and unacceptable for one
/// that happens once per REQUEST, so the rare crossings are confined and the hot ones are not.
///
/// A crossing belongs here when it can plausibly be the FIRST thing to touch a plugin-side
/// `thread_local!` with a destructor on the calling thread, because that is what arms the plugin's
/// `pthread_key` and puts a destructor inside the image on that thread. See `ffi_thread` for the
/// full mechanism and `where_the_plugin_arms_its_tls_key` for the measurement that decided the split.
/// The library's `busbar_abi` entry, or the refusal that names a library without one.
pub(crate) fn abi_symbol(
    lib: &Library,
    display: &str,
) -> Result<busbar_contract::abi::cold::AbiFn, String> {
    unsafe { lib.get::<busbar_contract::abi::cold::AbiFn>(symbol::ABI) }
        .map(|f| *f)
        .map_err(|_| format!("'{display}' is not a busbar plugin (no busbar_abi symbol)"))
}

/// THE PLUGIN-ABI HANDSHAKE, one home for every load path that still answers it: the JSON lane's
/// residue, the upload vet, the HOT plane loader and the HOT transport loader. Calls `busbar_abi()` under
/// the ffi guard (it runs plugin code, so a panic fails the load closed) and refuses a plugin whose
/// plugin-ABI version is not the engine's, answering the version it verified. `noun` is how the
/// refusal names it (`plugin`, `plane`, `transport`), so each path's text is unchanged byte for
/// byte.
pub(crate) fn abi_handshake(
    abi: busbar_contract::abi::cold::AbiFn,
    display: &str,
    noun: &str,
) -> Result<u32, String> {
    let abi_version = ffi_guard_confined(display, "abi", || unsafe { abi() })?;
    if abi_version != TRANSPORT_VERSION {
        return Err(format!(
            "{noun} '{display}' targets transport ABI v{abi_version}, engine speaks v{TRANSPORT_VERSION}"
        ));
    }
    Ok(abi_version)
}

fn ffi_guard_confined<R>(path: &str, op: &str, f: impl FnOnce() -> R) -> Result<R, String> {
    ffi_thread::on_plugin_thread(f).map_err(|_| {
        format!("plugin '{path}' panicked across the ABI boundary in {op} (treated as failure)")
    })
}

/// Call the plugin's `busbar_free` on `(ptr, len)` under a panic guard. A panicking `free` is logged
/// and swallowed (the buffer is leaked rather than aborting the engine) — free runs on the request hot
/// path and on error/cleanup paths where an abort would be the worst possible outcome.
fn free_guarded(free: busbar_contract::abi::cold::FreeFn, path: &str, ptr: *mut u8, len: usize) {
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

/// Reclaim the instance a FAILING `busbar_open` nevertheless published, by closing it through the
/// same guarded worker call `Drop` closes through. Returns whether a close was issued (`false` when
/// there was no instance to reclaim, the well-behaved case).
///
/// A null handle is left alone: there is nothing to close, and handing `close` a null is asking a
/// plugin to free something it never allocated.
fn reclaim_failed_open(
    close: busbar_contract::abi::cold::CloseFn,
    path: &str,
    handle: *mut c_void,
) -> bool {
    if handle.is_null() {
        return false;
    }
    let closing = handle;
    if ffi_guard_confined(path, "close", move || unsafe { close(closing) }).is_err() {
        // Same trade as `free_guarded`: a leaked handle beats aborting the gateway over a bad plugin.
        tracing::warn!(
            plugin = %path,
            "plugin busbar_close panicked while reclaiming a failed open; leaking the handle to keep the engine alive"
        );
    }
    true
}

/// The resolved core C fn pointers + the opaque handle + the mapped library + staging backing, shared
/// by every kind's typed wrapper. The KIND is bound at construction (cross-checked against the signed
/// manifest) and then carried by the typed `DynAuth` (the JSON lane's residue).
struct RawPlugin {
    handle: *mut c_void,
    call: CallFn,
    free: FreeFn,
    close: CloseFn,
    /// The plugin name/path, for diagnostics.
    path: String,
    /// The KIND bound at load (cross-checked against the signed manifest before this is built).
    ///
    /// Held so the ONE generic wire call can tell the host's observer which kind reported, WITHOUT
    /// the plugin ever sending it: a kind on the wire would be a kind a plugin could claim, and
    /// [`crate::observe::PluginObserver`] applies per-kind policy. `&'static str` because it is
    /// always one of `busbar_contract::abi::mechanism::kind`'s constants.
    kind: &'static str,
    /// Which response shape THIS plugin speaks — see [`response_shape`] and
    /// [`RawPlugin::decode_response`]. Latched on the first successful decode and never revisited.
    shape: std::sync::atomic::AtomicU8,
    /// The mapped library. `Option` only so `Drop` can TAKE it and unload it on a plugin worker
    /// (`dlclose` runs the image's `.fini_array`); it is `Some` until then for a dropped-in plugin and
    /// `None` for a linked one, whose boundary is part of this image. Declared BEFORE
    /// `_backing` so the unload still happens first — the UNLOAD-then-REMOVE order Windows requires.
    _lib: Option<Library>,
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

    /// The status-preserving transport primitive. Identical wire behavior to `transport_call` but on
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
        // Guard the `busbar_call` crossing. What this can catch is stated on `ffi_guard`: an unwind from this process's own runtime.
        // A dlopened plugin's panic is caught by the SDK on the PLUGIN side (answered as
        // `STATUS_PANIC`, classified below); one that escapes a non-SDK plugin is a foreign
        // exception to this runtime and aborts the process — no host-side guard can turn that into
        // an error. All kinds (store/secret/auth) route their FFI call through here.
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
            self.decode_response(&bytes)
        } else {
            // Classify the plugin-returned `status` into a SEMANTIC kind OUT OF BAND. The fallback
            // decision keys on the kind, never on a bare status integer, and a caught PANIC
            // (STATUS_PANIC) classifies to `Fault` — so a plugin crash can never open the safe-default
            // fallback. See `TransportError::from_status` for the legacy-v1 STATUS_PROTOCOL rule.
            let body = String::from_utf8_lossy(&bytes);
            Err(TransportError::from_status(status, &body, &self.path))
        }
    }

    /// Decode ONE `STATUS_OK` response body into `Resp`, folding the observability envelope
    /// (DECISIONS #85) on the way through.
    ///
    /// **Two accepted shapes, and they cannot be confused for one another.** A plugin built against
    /// the envelope answers `{"result":<kind response>,"metrics":[…],"diagnostics":[…]}`; a plugin
    /// built before it answers the kind's response BARE. Every kind's response enum is externally
    /// tagged by its Rust VARIANT name — `{"Streams":…}`, `{"Key":…}`, `{"Reply":…}`, or a bare
    /// string like `"Delivered"` — and not one of them has a variant named `result`, so the two
    /// forms are disjoint and the discrimination is total rather than a guess.
    ///
    /// **Why an adapter and not a floor raise.** Refusing the bare form would refuse every published
    /// first-party plugin at load — the one thing a migration may not produce. This is the same
    /// per-kind ADAPTER the tree already runs on the store's usage-ledger ops: the engine keeps ONE
    /// internal shape and the wire meets a plugin where it is. When a kind's supported FLOOR
    /// eventually rises past its envelope version, the bare arm here becomes dead and is deleted —
    /// it is a migration window, not a permanent fork.
    ///
    /// **THE PROBE RUNS ONCE PER LOAD, NEVER PER CALL.** A plugin does not change its mind about
    /// which wire it speaks, so the first successful decode LATCHES the shape and every later call
    /// parses exactly once. That is not an optimisation, it is a requirement: trying the envelope
    /// first on every call would parse-and-discard a whole response body before failing over on
    /// every request a `hook` GATE serves, and the hook kind is a 1.6.0 functional fixed point whose
    /// per-request cost may not move. Latched, the entire cost of supporting two shapes is one extra
    /// parse of one response, once, when the plugin loads.
    ///
    /// `Relaxed` throughout: the value is a pure memo of a deterministic property of the peer, two
    /// racing first-calls compute the same answer, and nothing is ordered against it.
    fn decode_response<Resp: serde::de::DeserializeOwned>(
        &self,
        bytes: &[u8],
    ) -> Result<Resp, TransportError> {
        use std::sync::atomic::Ordering::Relaxed;
        let decode_err = |e: serde_json::Error| {
            TransportError::engine(format!("plugin response decode failed: {e}"))
        };
        match self.shape.load(Relaxed) {
            // Latched: this plugin speaks the envelope. A failure here is a real failure — falling
            // back would mean a plugin that answered an envelope once and something else later, and
            // reading that as "the old shape" would hide a genuinely broken peer.
            response_shape::ENVELOPE => {
                let envelope: busbar_contract::abi::mechanism::observe::Envelope<Resp> =
                    serde_json::from_slice(bytes).map_err(decode_err)?;
                observe::fold(&self.path, self.kind, &envelope);
                Ok(envelope.result)
            }
            // Latched: this plugin predates the envelope. One parse, exactly as before #85.
            response_shape::BARE => serde_json::from_slice(bytes).map_err(decode_err),
            // First decode of this plugin's life: probe. The envelope is tried first so a
            // well-formed envelope is never mis-read; on failure the bare shape is tried and, if
            // that fails too, the ENVELOPE's error is reported, because a plugin built against the
            // current SDK is the case an operator is far more likely to be debugging and the bare
            // arm's "unknown variant `result`" would send them the wrong way.
            _ => {
                match serde_json::from_slice::<
                    busbar_contract::abi::mechanism::observe::Envelope<Resp>,
                >(bytes)
                {
                    Ok(envelope) => {
                        self.shape.store(response_shape::ENVELOPE, Relaxed);
                        observe::fold(&self.path, self.kind, &envelope);
                        Ok(envelope.result)
                    }
                    Err(envelope_err) => match serde_json::from_slice::<Resp>(bytes) {
                        Ok(bare) => {
                            self.shape.store(response_shape::BARE, Relaxed);
                            Ok(bare)
                        }
                        Err(_) => Err(decode_err(envelope_err)),
                    },
                }
            }
        }
    }
}

/// Which response shape a loaded plugin speaks, as latched on [`RawPlugin::shape`].
///
/// A `u8` in an `AtomicU8` rather than an enum because it is read on every wire call and written
/// once; the three values are spelled here so no call site writes a bare literal.
mod response_shape {
    /// Not yet decided — the next successful decode probes and latches.
    pub(super) const UNKNOWN: u8 = 0;
    /// `{ result, metrics[], diagnostics[] }` (DECISIONS #85).
    pub(super) const ENVELOPE: u8 = 1;
    /// The kind's response, unwrapped — what every plugin built before #85 answers.
    pub(super) const BARE: u8 = 2;
}

/// A failed transport `call`, carrying a SEMANTIC [`TransportErrorKind`] alongside the human message.
/// The kind is the out-of-band signal a caller keys on (never the plugin-controlled body text): only a
/// deliberate [`TransportErrorKind::Unsupported`] opens a safe-default fallback; a caught panic, a
/// backend error, a caller-protocol violation, and every engine-internal failure classify to kinds that
/// are explicitly NOT unsupported and always propagate. This is the revocation-denylist fail-open,
/// closed BY CONSTRUCTION.
pub(crate) struct TransportError {
    /// The semantic classification a loader caller keys on (see [`TransportErrorKind`]). Read by
    /// [`Self::is_unsupported`] only, which the JSON-lane auth residue's tests hold.
    #[cfg_attr(not(test), allow(dead_code))]
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
    #[cfg_attr(not(test), allow(dead_code))]
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
        if ffi_guard_confined(&self.path, "close", move || unsafe { close(handle) }).is_err() {
            tracing::warn!(
                plugin = %self.path,
                "plugin busbar_close panicked during drop; leaking the handle to keep the engine alive"
            );
        }
        // UNLOAD ON A WORKER, and do it HERE rather than letting the field drop do it: `dlclose`
        // runs the image's `.fini_array`, so on a caller thread it would hand that thread plugin TLS
        // at the moment the image goes away. Taking `_lib` keeps the ordering the field declaration
        // encodes — library first, staged backing (`_backing`, dropped after this returns) second.
        if let Some(lib) = self._lib.take() {
            dlclose_on_worker(lib);
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
    expected_kind: &'static str,
    manifest_kind: &str,
    backing: Option<stage::Staged>,
) -> Result<RawPlugin, String> {
    wire_up(
        Some(lib),
        None,
        cfg_json,
        display,
        expected_kind,
        manifest_kind,
        backing,
    )
}

/// Where a cold plugin's boundary functions come from — the ONE thing its two doors differ in
/// (DECISIONS #2 rule (1)). A dropped-in plugin is verified library BYTES the loader stages, maps and
/// looks the [`symbol`]s up in; a linked one is its [`ColdEntry`], the same functions referenced.
/// Everything after the lookup — handshake, kind cross-check, log bridge, `open`, the typed wrapper —
/// is one path, so a plugin cannot behave differently for having come in by the other door.
#[derive(Clone, Copy)]
pub enum Image<'a> {
    /// The verified library bytes of a dropped-in plugin.
    Bytes(&'a [u8]),
    /// A linked plugin's boundary.
    Linked(&'static ColdEntry),
}

/// Run the one cold-lane load over `image`: stage and map BYTES first (the dropped-in door), then
/// [`wire_up`] either way. `expected_kind` is the seam's kind, `manifest_kind` the row's statement.
pub(crate) fn load_image(
    image: Image<'_>,
    cfg_json: &str,
    display: &str,
    expected_kind: &'static str,
    manifest_kind: &str,
) -> Result<RawPlugin, String> {
    match image {
        Image::Bytes(bytes) => {
            let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
            wire_up_raw(
                lib,
                cfg_json,
                display.to_string(),
                expected_kind,
                manifest_kind,
                Some(staged),
            )
        }
        Image::Linked(entry) => wire_up(
            None,
            Some(entry),
            cfg_json,
            display.to_string(),
            expected_kind,
            manifest_kind,
            None,
        ),
    }
}

/// The load itself, over a mapped `lib` OR a linked `entry` (exactly one is `Some`): every step below
/// reads its function out of whichever it was handed, in the same order, with the same refusals.
fn wire_up(
    lib: Option<Library>,
    entry: Option<&'static ColdEntry>,
    cfg_json: &str,
    display: String,
    expected_kind: &'static str,
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
        fn disarm(mut self) -> (Option<Library>, Option<stage::Staged>) {
            (self.lib.take(), self.backing.take())
        }
    }
    impl Drop for LoadGuard {
        fn drop(&mut self) {
            // Explicit UNLOAD-then-REMOVE: unload the library first, then release the staged
            // backing. The unload goes to a plugin worker for the same reason `RawPlugin::drop`'s
            // does — `dlclose` runs the image's `.fini_array`.
            if let Some(lib) = self.lib.take() {
                dlclose_on_worker(lib);
            }
            self.backing.take();
        }
    }
    let guard = LoadGuard { lib, backing };
    let lib = guard.lib.as_ref();
    // ── 1. Transport handshake FIRST — refuse a non-matching transport before resolving open/call. ──
    // The `busbar_abi()` call runs plugin code, so it too rides `ffi_guard`: a plugin that panics in
    // its handshake fails the load CLOSED instead of aborting the engine during boot/reload.
    let abi = match (lib, entry) {
        (Some(lib), _) => abi_symbol(lib, &display)?,
        (None, Some(e)) => e.abi,
        (None, None) => return Err(format!("'{display}' has no boundary to load")),
    };
    abi_handshake(abi, &display, "plugin")?;

    // ── 2. Kind bound at load — read the exported kind, cross-check it against the seam AND the
    // signed manifest. Any disagreement is a hard fail-closed load error naming both. ──
    let exported_kind = match (lib, entry) {
        (Some(lib), _) => read_plugin_kind(lib, &display)?,
        (None, Some(e)) => kind_from_fn(e.kind, &display)?,
        (None, None) => unreachable!("refused at the handshake"),
    };
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
    let (open, call, free, close) = match (lib, entry) {
        (None, Some(e)) => (e.open, e.call, e.free, e.close),
        (None, None) => unreachable!("refused at the handshake"),
        (Some(lib), _) => unsafe {
            let open = *lib
                .get::<busbar_contract::abi::cold::OpenFn>(symbol::OPEN)
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
        },
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
    let set_sink = match (lib, entry) {
        (Some(lib), _) => unsafe {
            lib.get::<busbar_contract::abi::cold::SetLogSinkFn>(symbol::SET_LOG_SINK)
                .ok()
                .map(|f| *f)
        },
        (None, e) => e.map(|e| e.set_log_sink),
    };
    {
        if let Some(set_sink) = set_sink {
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
            // ON A PLUGIN WORKER, like every other crossing. This one was historically unguarded,
            // and it is the LAST one that should be: it installs a `tracing` dispatcher INSIDE the
            // plugin, which is about the most reliable way there is to touch a plugin-side
            // thread-local with a destructor and arm the pthread key on whatever thread ran it.
            let sink = set_sink;
            let ctx = hostlog::intern_log_ctx(&display);
            let level = hostlog::host_max_level();
            let _ = ffi_thread::on_plugin_thread(move || unsafe {
                sink(hostlog::host_log_sink, ctx, level);
            });
        }
    }

    // ── 4. open: construct the instance from the JSON config. ──
    // Guarded: `busbar_open` runs plugin constructor code on every load (boot AND hot config-reload).
    // With the `extern "C-unwind"` ABI a panicking constructor unwinds here and fails the load CLOSED,
    // rather than aborting the whole gateway mid-reload.
    let mut handle: *mut c_void = std::ptr::null_mut();
    let mut err: *mut u8 = std::ptr::null_mut();
    let mut err_len: usize = 0;
    let status = match ffi_guard_confined(&display, "open", || unsafe {
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
        // A FAILING open that still PUBLISHED a handle has constructed an instance — the SDK's own
        // macro never does this, but the ABI is spoken by plugins this tree does not compile, and
        // nothing in it says a non-`OK` status leaves `*handle` untouched. The load fails closed
        // either way; what must not also happen is the instance living on with nobody holding it,
        // its connection pool, its threads and its file handles owned by a `RawPlugin` that is never
        // built. Close it here, on a worker and under the same panic guard `Drop` closes through,
        // BEFORE the message is composed — the message is only bytes, and the instance is a
        // resource. (The caught-panic path above is deliberately NOT this: a plugin that panicked
        // inside its own constructor has no instance a `close` could validly be handed.)
        reclaim_failed_open(close, &display, handle);
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
    // every load (the `wire_up_raw` path every cold open takes).
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
        kind: expected_kind,
        shape: std::sync::atomic::AtomicU8::new(response_shape::UNKNOWN),
        _lib: lib,
        _backing: backing,
    })
}

/// Read the kind a mapped library states into an owned `String`. A memory-ABI image states it in
/// its door's head ([`busbar_contract::abi::mechanism::DOOR_SYMBOL`],
/// [`dispatch::load::kind_of_door`]): the SDK's `busbar_plugin_kind` answers for no door it
/// registered (a null kind). A plane or transport image registered through its decl answers
/// `busbar_plugin_kind()`. Any other library with no door is a 1.5.5-era JSON-contract plugin: its
/// kind symbol only CLASSIFIES it, and it is REFUSED here, naming the rebuild (no legacy loading,
/// THE DESIGN §11.8, ruling C21/ABI-o1), so no upload vet, inventory or kind gate takes it as valid.
fn read_plugin_kind(lib: &Library, display: &str) -> Result<String, String> {
    // SAFETY: `DOOR_SYMBOL` is typed `DoorFn` by the mechanism; the symbol is copied out as a plain
    // fn pointer and `lib` outlives every use of it here.
    let door = unsafe {
        lib.get::<busbar_contract::abi::mechanism::door::DoorFn>(
            busbar_contract::abi::mechanism::DOOR_SYMBOL,
        )
        .map(|s| *s)
    };
    if let Ok(door) = door {
        // Guarded: the door function is plugin code; a panic fails the read CLOSED.
        let kind = ffi_guard_confined(display, "door", || dispatch::load::kind_of_door(door))?
            .map_err(|e| format!("plugin '{display}' states no kind the host has: {e}"))?;
        return Ok(kind.word().to_string());
    }
    let f = unsafe { lib.get::<PluginKindFn>(symbol::PLUGIN_KIND) }.map_err(|_| {
        format!("'{display}' is not a busbar plugin (no busbar_plugin_kind symbol)")
    })?;
    let kind = kind_from_fn(*f, display)?;
    use busbar_contract::abi::mechanism::kind::{PLANE, TRANSPORT};
    if kind != PLANE && kind != TRANSPORT {
        return Err(format!(
            "plugin '{display}' states kind '{kind}' and exports no busbar_plugin_door — a plugin \
             built against the 1.5.5 JSON contract; {}",
            dispatch::load::REBUILD
        ));
    }
    Ok(kind)
}

/// Call a plugin's `busbar_plugin_kind()` — looked up or linked — and read the kind it names.
fn kind_from_fn(f: PluginKindFn, display: &str) -> Result<String, String> {
    // Guarded: `busbar_plugin_kind()` runs plugin code; a panic fails the load CLOSED, not an abort.
    let ptr = ffi_guard_confined(display, "kind", || unsafe { f() })?;
    // SAFETY: `ptr` came from the plugin's `busbar_plugin_kind()`, whose contract is a 'static
    // string; `kind_from_ptr` reads at most `MAX_PLUGIN_KIND_LEN + 1` bytes of it.
    unsafe { kind_from_ptr(ptr, display) }
}

/// Hard cap on the `busbar_plugin_kind()` string, NUL excluded. The kind is the ONE plugin-supplied
/// buffer in this ABI that crosses without a length, so the loader cannot cap a length the way it
/// caps a response (`MAX_PLUGIN_RESPONSE_LEN`), an open error, a plane vocabulary string or a log
/// record — it caps the SCAN instead. Every kind is a short closed-set identifier (`store`,
/// `secret`, ...); a pointer with no NUL inside this many bytes is not a kind, and is refused rather
/// than walked until some zero byte or an unmapped page turns up (the hand-written
/// `kind::EXPORT.as_ptr()` trap `busbar_contract::abi::cold` warns about).
const MAX_PLUGIN_KIND_LEN: usize = 32;

/// Read a plugin kind string from `ptr`, scanning at most [`MAX_PLUGIN_KIND_LEN`] + 1 bytes for its
/// NUL. Refuses a null pointer, a string with no NUL inside the cap, and non-UTF-8 bytes.
///
/// # Safety
/// `ptr`, when non-null, must address readable bytes up to its NUL or up to
/// `MAX_PLUGIN_KIND_LEN + 1` bytes, whichever comes first.
unsafe fn kind_from_ptr(ptr: *const u8, display: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("plugin '{display}' returned a null kind string"));
    }
    let mut len = 0;
    // SAFETY: the caller's contract covers every byte up to the NUL or the cap; the loop stops at
    // the first of the two, so it never reads past either.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
        if len > MAX_PLUGIN_KIND_LEN {
            return Err(format!(
                "plugin '{display}' kind string has no NUL terminator within \
                 {MAX_PLUGIN_KIND_LEN} bytes — refusing to load (a kind is a short \
                 NUL-terminated identifier)"
            ));
        }
    }
    // SAFETY: `len` bytes from `ptr` were just read one by one above.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| format!("plugin '{display}' kind string is not valid UTF-8"))
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
#[cold] // boot/admin-only — keeps hot text dense (never inlined into a warm path)
#[inline(never)]
pub fn validate_plugin(lib_path: &Path) -> Result<u32, String> {
    let display = lib_path.display().to_string();
    // SAFETY: loading runs the library's init code — the same trust as loading it to serve, which is
    // itself the trust of compiling it in. The path is operator/admin-supplied, never request data.
    let lib = dlopen_on_worker(lib_path.as_os_str())
        .map_err(|e| format!("failed to load plugin '{display}': {e}"))?;
    // UNLOAD ON A WORKER, on EVERY exit path. The handshake below has five of them, and letting
    // `lib` drop out of scope would `dlclose` — running the image's `.fini_array`, which is plugin
    // code — on the CALLER's thread. A `.fini_array` that touches a plugin-side `thread_local!` with
    // a destructor arms the plugin's `pthread_key` on that thread, and a caller that later retires
    // (a libtest harness thread, a Tokio blocking thread) then calls that destructor inside the
    // image it just unmapped. Every other unload in this crate (`RawPlugin::drop`, `LoadGuard::drop`)
    // is already routed; the admin inventory/upload-vet path is the one that was not.
    let verdict = validate_mapped(&lib, &display);
    dlclose_on_worker(lib);
    verdict
}

/// The handshake half of [`validate_plugin`], over an ALREADY-MAPPED library. Split out so its five
/// exit paths cannot each be responsible for routing the unload — the caller unloads once.
fn validate_mapped(lib: &Library, display: &str) -> Result<u32, String> {
    let display = display.to_string();
    let abi_version = abi_handshake(abi_symbol(lib, &display)?, &display, "plugin")?;
    // The exported kind must be one the engine supports (a range exists for it).
    let plugin_kind = read_plugin_kind(lib, &display)?;
    if supported_abi(&plugin_kind).is_empty() {
        return Err(format!(
            "plugin '{display}' declares unsupported kind '{plugin_kind}'"
        ));
    }
    // Confirm the operational symbols resolve too, so a half-built library is caught here rather than
    // at first use.
    unsafe {
        lib.get::<busbar_contract::abi::cold::OpenFn>(symbol::OPEN)
            .map_err(|e| format!("plugin '{display}' missing busbar_open: {e}"))?;
        lib.get::<CallFn>(symbol::CALL)
            .map_err(|e| format!("plugin '{display}' missing busbar_call: {e}"))?;
        lib.get::<FreeFn>(symbol::FREE)
            .map_err(|e| format!("plugin '{display}' missing busbar_free: {e}"))?;
        lib.get::<CloseFn>(symbol::CLOSE)
            .map_err(|e| format!("plugin '{display}' missing busbar_close: {e}"))?;
    }
    Ok(abi_version)
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
///
/// THE COMPARISON FOLLOWS THE FILESYSTEM'S OWN CASE RULE, which is not the same rule everywhere.
/// NTFS is case-INSENSITIVE: `FOO.DLL` and `foo.dll` name the same file, `LoadLibrary` opens either,
/// and an artifact arriving from a Windows build system or an unzip commonly carries an uppercase
/// extension. A case-SENSITIVE `ends_with(".dll")` therefore reports "no plugins installed" for a
/// directory that plainly holds one — a silent omission from the operator-facing inventory
/// (`GET /admin/plugins`), which is the surface an operator uses to answer "did my install land".
/// On unix the extension is part of the name and `.SO` is a DIFFERENT file from `.so`, so folding
/// case there would make this claim a file is a library on the strength of a name the loader would
/// not resolve. One question, each platform's own answer — the same shape as the absolute-path check
/// in `mcp::config`.
fn is_library_file(file: &str) -> bool {
    if cfg!(target_os = "windows") {
        // BYTES, not a `&str` slice: `file[file.len() - 4..]` panics when byte `len - 4` is not a
        // char boundary, and a filename is arbitrary UTF-8 — a plugins directory holding one
        // non-ASCII name would take down the inventory scan. `.dll` is ASCII, so the byte-suffix
        // comparison answers exactly the same question with no boundary to land inside.
        let b = file.as_bytes();
        return b.len() >= 4 && b[b.len() - 4..].eq_ignore_ascii_case(b".dll");
    }
    let ext = if cfg!(target_os = "macos") {
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

/// The loader's own crossings pinned against in-test fakes: the bounded kind read, the secret
/// deadline on the wire, and what the panic guard can and cannot catch.
#[cfg(test)]
#[path = "tests/loader_seam_tests.rs"]
mod loader_seam_tests;

/// DECISIONS #11's real test: ONE crate built both ways must be observationally identical. Declared
/// at the crate root rather than under `export` because it is not a test OF the export seam — it is
/// a test of the equivalence the two build shapes are supposed to have, and the export kind is
/// merely the first one with real plugins that can prove it (ARCHITECT ruling EXP2-PROOF
/// 2026-10-03: the spec's working proof of the plugin model, on the export kind's door registries).
#[cfg(test)]
#[path = "tests/export_conformance_tests.rs"]
mod export_conformance_tests;

/// The cold kinds' both-ways harness (DECISIONS #2 rule (1)): one plugin registered through the
/// linked door and the dropped-in door, its rows and its opened instance compared.
#[cfg(test)]
#[path = "tests/both_ways.rs"]
mod both_ways;

/// No rlib the test binary links exports `busbar_plugin_door` (the fat-LTO duplicate-symbol guard).
#[cfg(test)]
#[path = "tests/door_symbol_tests.rs"]
mod door_symbol_tests;

/// `kind: auth` through both doors — the auth kind's first both-ways witness (#2, steps (1)-(5)): the
/// compiled-in twin and the `cdylib`'s `busbar_call` put one wire, and the linked and dropped-in rows
/// open one module.
#[cfg(test)]
#[path = "tests/auth_conformance_tests.rs"]
mod auth_conformance_tests;

/// `kind: auth` through both doors on the memory ABI, VERIFY VERDICTS: the token cases driven to
/// every verdict (identify, reject, pass) over a second real auth plugin, one row and one answer
/// either way.
#[cfg(test)]
#[path = "tests/auth_verify_conformance_tests.rs"]
mod auth_verify_conformance_tests;

/// The dispatcher through both doors: one script, LINKED and DROPPED, byte-identical, and a RED
/// arm per mechanism rule.
/// The dispatcher's test plugin, compiled in: the LINKED door of `dispatch_tests` (the same
/// source is the `dispatch_test_plugin` example `cdylib`, the DROPPED door).
#[cfg(test)]
#[path = "../tests/fixtures/dispatch_test_plugin.rs"]
mod dispatch_test_plugin;

#[cfg(test)]
#[path = "tests/dispatch_tests.rs"]
mod dispatch_tests;

/// The plane door's test plugin, compiled in: the LINKED door of `plane_conformance_tests` (the
/// same source is the `plane_door_plugin` example `cdylib`, the DROPPED door).
#[cfg(test)]
#[path = "../tests/fixtures/plane_door_plugin.rs"]
mod plane_door_plugin;

/// The secret and export kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[path = "tests/dispatch_kind_secret_export_tests.rs"]
mod dispatch_kind_secret_export_tests;

/// The transport kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[path = "tests/dispatch_kind_transport_tests.rs"]
mod dispatch_kind_transport_tests;

/// The plane kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[path = "tests/dispatch_kind_plane_tests.rs"]
mod dispatch_kind_plane_tests;

/// The store kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[path = "tests/dispatch_kind_store_tests.rs"]
mod dispatch_kind_store_tests;

/// The hook kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[path = "tests/dispatch_kind_hook_tests.rs"]
mod dispatch_kind_hook_tests;

/// The auth kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[path = "tests/dispatch_kind_auth_tests.rs"]
mod dispatch_kind_auth_tests;

/// The both-ways harness on the memory ABI (TODO ABI-b4): one door loaded LINKED and DROPPED IN
/// through the one dispatcher, one script, two transcripts compared.
#[cfg(test)]
#[path = "tests/door_both_ways.rs"]
mod door_both_ways;

/// `kind: store` through both doors on the memory ABI: get/put identical, a broken store refused.
#[cfg(test)]
#[path = "tests/store_door_conformance_tests.rs"]
mod store_door_conformance_tests;

/// `kind: secret` through both doors on the memory ABI: resolve identical, a broken one refused.
#[cfg(test)]
#[path = "tests/secret_door_conformance_tests.rs"]
mod secret_door_conformance_tests;

/// `kind: transport` over the REAL shipped carrier, both ways: the linked door against the pinned
/// cdylib, through the published suite's carrier script, equal folds and exact crossing counts.
#[cfg(test)]
#[path = "tests/transport_door_conformance_tests.rs"]
mod transport_door_conformance_tests;

/// `kind: hook` through both doors on the memory ABI: decide identical, a broken one refused.
#[cfg(test)]
#[path = "tests/hook_door_conformance_tests.rs"]
mod hook_door_conformance_tests;
