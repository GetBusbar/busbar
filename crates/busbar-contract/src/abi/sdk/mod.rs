// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN SDK: the typed Rust wrappers over the memory ABI (`BUSBAR-1.6.0.md` THE DESIGN, one
//! place for every ABI shape, `abi/sdk/`). A plugin of any kind writes its slots against [`door`]
//! (`plugin_door!`) and exports its ONE door symbol through `export_door!`; compiled in or dropped
//! in, the host calls the same table.
//!
//! No plugin of any kind has a JSON-lane export: the COLD/JSON lane is gone. [`boundary`] and the
//! frozen symbols below are the HOT lane's residue, deleted with it.

// The SDK's `unsafe fn` bodies were written under the crate default (edition 2021: an `unsafe fn`
// body is itself an unsafe context). The shared ABI root denies `unsafe_op_in_unsafe_fn` for the two
// lanes; the SDK keeps the discipline it was written and reviewed under, unchanged by the merge.
#![allow(unsafe_op_in_unsafe_fn)]

pub mod boundary;
pub use boundary::BoundaryOutcome;
// THE URL AND HOST READER a plugin judges a destination with, the same one the host's guard reads
// through (`crate::net`, a pure helper outside `abi/`).
pub use crate::net;
// THE PLUGIN SIDE OF THE TRANSPORT LOWERING: a carrier's or a framer's slots, generated from its trait
// implementation (`export_carrier!` / `export_framer!`).
pub mod transport;
// THE DOOR MACRO (THE DESIGN, the plugin ABI; abi-v2, the SDK): the plugin side of the shared mechanism — one door,
// every slot a catch_unwind trampoline (`plugin_door!` / `export_door!`).
pub mod door;
pub mod hook;
pub use crate::{export_door, plugin_door};
// THE CALL CAPTURE: what a plugin logs during a call rides its reply as diagnostics (#85).
pub mod capture;
// THE SAFE SURFACE (THE DESIGN, plugins and the plugin ABI): a slot body with no `unsafe` — host-lent memory read and
// host buffers filled through `Lent`/`HostBuf`, the instance typed through `Instance`.
pub mod lent;
pub mod safe;
pub use lent::{open_failed, HostBuf, Lent, LentList, SignalScalar};
// A SLOT'S `out`, WRITTEN BY THE SDK: scalars set, every pointer through an SDK writer.
pub mod out;
pub use out::{Out, Scalar};
// A PLUGIN'S CONNECTIONS: the host connector for one op on one ticket, Ready|Pending, and exchange().
pub mod conn;
// ONE REQUEST, ONE REPLY over the connector: exchange() (framed) and send_and_ack() (any transport).
/// A plane's reads of a body by declared pointer, one copy for every plane.
pub mod body;
pub mod exchange;
pub use safe::{Instance, Safe, SafeSlot};
// THE HOST SERVICES, PLUGIN SIDE: the one home of every safe host-service wrapper.
pub mod services;
pub use services::{Judged, Names, Pend, Records, ServiceError, Services, Signature, Signed, Wake};
// THE ONE DIGEST A PLUGIN TAKES without linking a crypto crate of its own.
pub mod digest;
// THE AUTH KIND'S VERIFY DOOR over the safe layer (`auth_verify_door!`). An auth plugin keeps its
// inbound verdict cache inside itself (THE DESIGN, section 11.11).
pub mod auth_door;
// THE AUTH LOGIN KIT's shared checks: the id-token nonce binding v1.5.5's core ran for every login.
pub mod login;
// THE STORE KIND'S TYPED SDK: the trait a store implements to be served through the store v3 table.
pub mod store;
// PUBLISHED GENERATION DATA: the SDK owns what a plugin publishes (`abi::sdk::publish`).
pub mod publish;
pub use publish::{Generations, Keyed};
// THE LIFECYCLE, ONCE FOR EVERY KIND: the nine lifecycle slots over a kind's `Life` (`abi::sdk::life`).
pub mod life;

// The `#[macro_export]` export macros, named at this module's path too.
pub use crate::{export_carrier, export_framer, export_plane, export_plugin, export_transport};

/// The "decision observability" signal catalog: a plugin author references
/// `busbar_contract::abi::sdk::Signal::CandidateBreakerState` (etc.) at compile time to declare which
/// catalog entries their hook wants computed + projected — see `crate::signal::Signal`'s doc comment
/// for the full catalog and the append-only/non_exhaustive contract.
pub use crate::signal::{Signal, SignalBag, SignalValue};

/// Re-export used ONLY by the `export_plugin!` expansion, so a plugin crate needs no dependency of
/// its own to name the log-sink types, or the `tracing-core` its generated forwarder installs into.
#[doc(hidden)]
pub mod __abi {
    pub use crate::abi::cold::{log_level, ColdEntry, LogSinkFn, SetLogSinkFn};
    pub use tracing_core;
}

/// The boundary a LINKED build hands the loader in place of a library (the macro's
/// `BUSBAR_COLD_ENTRY`): named here so a plugin's linked-door entry can state its type.
pub use crate::abi::cold::ColdEntry;

/// The host log call — a HOST SERVICE (#83: the contract holds its shape, never an output of its
/// own). [`LogSinkFn`](crate::abi::cold::LogSinkFn) is the shape; the host hands a plugin its sink
/// through the optional `busbar_set_log_sink` symbol before `open`, and every record goes there.
/// With no sink installed a record DROPS: the contract never prints, and never installs a `tracing`
/// dispatcher — the forwarder that lights up a `cdylib`'s own `tracing` call sites is generated by
/// `export_plugin!` into the plugin image (ARCHITECT F6 queue (4)).
pub mod hostlog {
    use crate::abi::cold::{log_level, LogSinkFn};
    use std::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};

    /// The installed sink, as raw parts. Two atomics rather than a `OnceLock<(fn, ptr)>` because the
    /// host may call `busbar_set_log_sink` from any thread and [`log`] may be called concurrently
    /// from any other; both are written once, before any `busbar_call`, and only ever read after.
    static SINK: AtomicUsize = AtomicUsize::new(0);
    static CTX: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
    /// The HOST's maximum enabled level, so a record the host would discard is never built. `OFF`
    /// until a host has said what it wants.
    static MAX_LEVEL: AtomicU32 = AtomicU32::new(log_level::OFF);

    /// Record the host's sink. Called ONLY by the sink-install functions `export_plugin!` generates
    /// (the linked door's, and the dropped-in door's, which also installs the image's forwarder).
    ///
    /// # Safety
    /// `sink` must stay callable, and `ctx` valid, for the life of the plugin.
    pub unsafe fn install_sink(sink: LogSinkFn, ctx: *mut std::ffi::c_void, max_level: u32) {
        CTX.store(ctx, Ordering::Release);
        MAX_LEVEL.store(max_level, Ordering::Release);
        SINK.store(sink as usize, Ordering::Release);
    }

    /// True when the host would actually keep a record at `level`. Cheap enough to call before
    /// building the message, which is the whole point.
    pub fn enabled(level: u32) -> bool {
        // Lower constant = more severe. `OFF` (0) is below ERROR (1), so it enables nothing.
        level != log_level::OFF && level <= MAX_LEVEL.load(Ordering::Acquire)
    }

    /// Hand one record at `level` to the host's sink. No sink installed: the record drops.
    pub fn log(level: u32, msg: &str) {
        let raw = SINK.load(Ordering::Acquire);
        if raw == 0 {
            return;
        }
        // SAFETY: `raw` was stored from a valid `LogSinkFn` by `install_sink`, which the host
        // contract requires to stay callable for the plugin's life. The message is borrowed for the
        // call only.
        let sink: LogSinkFn = unsafe { std::mem::transmute::<usize, LogSinkFn>(raw) };
        let ctx = CTX.load(Ordering::Acquire);
        unsafe { sink(ctx, level, msg.as_ptr(), msg.len()) };
    }

    pub fn error(msg: &str) {
        log(log_level::ERROR, msg);
    }
    pub fn warn(msg: &str) {
        log(log_level::WARN, msg);
    }
    pub fn info(msg: &str) {
        log(log_level::INFO, msg);
    }
}

// ── HOOK-plugin glue (`kind: hook`) ───────────────────────────────────────────────────────────────
// A hook plugin is a routing policy on the hook kind's door. Its author implements the tiny
// SYNC [`HookHandler`] trait (the six ops over JSON), NOT the engine's async `RoutingPolicy`; on the
// hook door the SDK's `json_hook` bridges it onto the kind's typed ops: a hook author writes
// `decide`/`transform`/etc. and the SDK routes each op to them.

/// The sync contract a `kind: hook` plugin author implements. Each method receives the op's payload as
/// the opaque projection [`serde_json::Value`] the engine built (`hooks::wire::build`) and returns the
/// reply object the engine parses through its fail-closed normalizers. Every method has a DEFAULT so a
/// trivial hook (e.g. a gate that only ranks) implements just the ops it cares about; the rest degrade
/// to the safe "no opinion" / "unsupported" replies the engine already treats as fail-open.
///
/// A hook NEVER sees prompt/user content it was not granted: the engine only projects `prompt`/`user`
/// into `payload` when BOTH the operator grant and the signed-manifest intent allow it. The handler
/// just reads whatever keys are present.
pub trait HookHandler: Send + Sync {
    /// `decide` — rank candidates / return a verdict. Default: `{}` (abstain).
    ///
    /// Implement [`HookHandler::decide_result`] instead if your hook can FAIL as distinct from
    /// having no opinion. Returning `{}` from here says "no opinion", and the engine acts on that
    /// difference: an abstain lets the request proceed, a failure resolves the operator's
    /// `on_error` chain, whose terminal can be `reject`.
    fn decide(&self, _payload: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({})
    }

    /// `decide`, with the ability to say the hook could not answer.
    ///
    /// ADDITIVE, and defaulted to the infallible [`HookHandler::decide`] so every existing
    /// implementation keeps compiling and behaving identically. Override this one when your hook
    /// depends on something that can be down: a remote scoring service, a database, a model.
    ///
    /// `Err(message)` reaches the engine as a failure and resolves the operator's configured
    /// `on_error` chain. `Ok(value)` is a successful reply, and `Ok(json!({}))` specifically means
    /// abstain. Before this existed there was no way to express the difference, so a gate whose
    /// dependency was down answered "no opinion" and an operator who had deliberately configured
    /// `on_error: reject` never got it.
    ///
    /// The message goes to the operator's log. Do not put request content in it.
    fn decide_result(&self, payload: &serde_json::Value) -> Result<serde_json::Value, String> {
        Ok(self.decide(payload))
    }
    /// `transform` — a `prompt: rw` gate's rewrite/reject pass. Default: `{}` (abstain, original body).
    ///
    /// Implement [`HookHandler::transform_result`] instead if your rewrite can FAIL as distinct from
    /// having nothing to change — the same difference `decide`/`decide_result` draw.
    fn transform(&self, _payload: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({})
    }

    /// `transform`, with the ability to say the hook could not answer.
    ///
    /// ADDITIVE and defaulted to the infallible [`HookHandler::transform`], so every existing
    /// implementation keeps compiling and behaving identically. Override this one when the rewrite
    /// depends on something that can be down — a compressor's model endpoint, a PII screen's
    /// classifier.
    ///
    /// `Err(message)` reaches the engine as a rewrite-path FAILURE and resolves the operator's
    /// `on_error` chain. `Ok(json!({}))` remains a plain abstain: proceed with the original body.
    /// Before this existed the two were the same value, so a screening gate whose classifier was
    /// unreachable returned "no changes" and the request it was meant to stop went through with its
    /// body untouched.
    ///
    /// The message goes to the operator's log. Do not put request content in it.
    fn transform_result(&self, payload: &serde_json::Value) -> Result<serde_json::Value, String> {
        Ok(self.transform(payload))
    }
    /// `notify` — a tap observation (fire-and-forget). Default: no-op.
    fn notify(&self, _payload: &serde_json::Value) {}
    /// `configure` — accept a desired-state settings push. Return `true` to ACK the version (the engine
    /// requires the ack), `false`/anything-else to reject the push. Default: ACK (idempotent no-op).
    fn configure(
        &self,
        _settings: &serde_json::Map<String, serde_json::Value>,
        _settings_version: u64,
    ) -> bool {
        true
    }
    /// `describe` — the self-description envelope `{schema, dashboard?}`. Default: `{}` (none).
    fn describe(&self) -> serde_json::Value {
        serde_json::json!({})
    }
    /// `status` — observed settings + metrics (`{status: {...}}`). Default: `{}` (unsupported → the
    /// engine fails open).
    fn status(&self) -> serde_json::Value {
        serde_json::json!({})
    }
    /// The HTTP [`Route`]s this hook serves (a routing hook's inbound `/feedback`), collected once at
    /// load. Default: none. The engine confines a hook's routes to `/hooks/<name>/*`.
    fn routes(&self) -> Vec<Route> {
        Vec::new()
    }
    /// Serve one inbound HTTP request matched to a declared route. Default: `404`.
    fn handle_http(&self, _req: &EndpointRequest) -> EndpointResponse {
        EndpointResponse {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

// ── THE EXPORT KIND'S WIRE TYPES, re-exported for plugin authors ──────────────────────────────────

/// Re-export the export kind's stream and field vocabulary, and the scraped snapshot's family and
/// sample, so a plugin author names `busbar_contract::abi::sdk::ExportStream` (etc.) at this
/// module's path.
pub use crate::abi::export::{CheckPhase, ExportField, ExportStream, MetricFamily, MetricSample};

/// Re-export the observability envelope (#85) so a plugin author names
/// `busbar_contract::abi::sdk::PluginMetric` (etc.) without a direct `busbar-plugin` dependency, mirroring
/// every other wire type this SDK re-exports.
///
/// These are what a plugin uses to REPORT. Nothing here makes anything happen: the host validates
/// what arrives, bounds it, and decides. A plugin that wants a counter incremented says so and the
/// host increments it — which is also why a dropped-in build and a compiled-in build of the same
/// crate produce the same exposition (#11) instead of one of them reaching a recorder the other
/// cannot see.
pub use crate::abi::mechanism::observe::{
    DiagLevel, Envelope, Observations, PluginDiagnostic, PluginMetric,
};

/// Re-export the endpoint wire types (plugin route registration + dispatch) so an export/hook
/// author names `busbar_contract::abi::sdk::Route` / `EndpointRequest` (etc.) without a direct
/// `busbar-plugin` dependency.
pub use crate::abi::mechanism::endpoint::{EndpointRequest, EndpointResponse};
pub use crate::abi::mechanism::route::{Route, RouteAuth, RouteMethod};

// ── THE DROPPED-IN DOOR'S FROZEN SYMBOLS, DEFINED ONCE ─────────────────────────────────────────────
// Every frozen name the loader looks up in a plugin `cdylib` (`busbar_abi`, `busbar_plugin_kind`,
// `busbar_set_log_sink`, `busbar_open`, `busbar_call`, `busbar_free`, `busbar_close`,
// `busbar_plane_decl`, `busbar_transport_decl`, `busbar_plane_arm`) is defined HERE, in
// `busbar-contract`, exactly once
// (the SDK merged into the contract, #84, and the transport's door joined the shared one then). A
// plugin crate's `export_*!` macro defines none of them: it registers its image's ONE door ([`__door::Door`]) and these symbols
// answer through it.
//
// WHY NOT ONE SET PER PLUGIN CRATE. A first-party plugin is `crate-type = ["cdylib", "rlib"]`: one
// source, both doors (DECISIONS #2 rule (1)). The `rlib` half is what a composition root LINKS — and
// one rustc invocation emits both halves, so whatever `#[no_mangle]` symbol the crate defines is in
// the linked `rlib` too. Two such plugins linked into one binary are two strong definitions of
// `busbar_abi`. Whether that links depended on how many codegen units the crate was split into (a
// separate unit left out of the link by the archive rules): under the release profile
// (`codegen-units = 1`, `lto = "fat"`) rustc's fat LTO links every module of every crate into one
// LLVM module and refuses the second definition ("Linking globals named 'busbar_abi': symbol
// multiply defined!" → "failed to load bitcode of module"), and a non-LTO single-unit link is a
// duplicate-symbol link. Defined once here, a binary holds exactly one of each, however many plugins
// it links; a `cdylib` holds exactly one too, and rustc exports it from the `cdylib` because
// `#[no_mangle]` makes it a C-level exported symbol of an upstream crate.
//
// HOW THE SYMBOL FINDS ITS PLUGIN. The plugin's macro emits a load-time constructor (an entry in the
// platform's initializer table: `.init_array`, `__mod_init_func`, `.CRT$XCU`) that registers the
// image's door before the loader can look anything up (`dlopen` runs initializers before it
// returns). In a `cdylib` exactly one door registers. In a binary that links several plugins several
// register, and the symbols then answer as no plugin (a null kind, a protocol status) — nothing in a
// binary looks them up; the linked door is `BUSBAR_COLD_ENTRY` / the plane's decl, never these.
#[doc(hidden)]
pub mod __door {
    use crate::abi::cold::{ColdEntry, LogSinkFn, SetLogSinkFn, STATUS_PROTOCOL};
    use crate::abi::hot::{PlaneDecl, TransportDecl};
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

    /// What one plugin image is, as its dropped-in door answers for it.
    pub enum Door {
        /// A JSON-lane image (`export_plugin!`; no shipped plugin is one — residue of the frozen
        /// symbols, deleted with the HOT lane): the entry its linked door hands the loader, and the
        /// dropped-in door's sink install (the sink plus this image's `tracing` forwarder).
        Cold(&'static ColdEntry, SetLogSinkFn),
        /// A plane: the same decl its linked door hands the registry.
        Plane(&'static PlaneDecl),
        /// A transport: the function that answers its `'static` decl — the same decl its linked door
        /// hands the transport axis. A function rather than a reference so a transport that RESTATES
        /// the published `#[repr(C)]` layout in its own source (#84: a layout, not a crate) registers
        /// through this door without naming this crate's type for its decl.
        Transport(fn() -> *const TransportDecl),
    }

    /// How many doors registered in this image, and the last one. The symbols answer only when
    /// exactly one did.
    static REGISTERED: AtomicUsize = AtomicUsize::new(0);
    static DOOR: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());

    /// Register this image's door. Called only by the load-time constructor `__register_door!`
    /// emits.
    pub fn register(door: &'static Door) {
        DOOR.store(door as *const Door as *mut Door, Ordering::Release);
        REGISTERED.fetch_add(1, Ordering::AcqRel);
    }

    /// The image's door, when exactly one registered.
    pub fn the_door() -> Option<&'static Door> {
        if REGISTERED.load(Ordering::Acquire) != 1 {
            return None;
        }
        // SAFETY: `DOOR` is only ever stored by `register`, from a `&'static Door`.
        unsafe { DOOR.load(Ordering::Acquire).as_ref() }
    }

    fn cold() -> Option<&'static ColdEntry> {
        match the_door() {
            Some(Door::Cold(entry, _)) => Some(entry),
            _ => None,
        }
    }

    /// `busbar_abi` — the frozen TRANSPORT handshake, shared by every image that answers it.
    #[no_mangle]
    pub extern "C-unwind" fn busbar_abi() -> u32 {
        crate::abi::cold::TRANSPORT_VERSION
    }

    /// `busbar_plugin_kind` — a `'static` NUL-terminated string owned by this library; null when the
    /// image registered no single door (the loader refuses a null kind).
    #[no_mangle]
    pub extern "C-unwind" fn busbar_plugin_kind() -> *const u8 {
        match the_door() {
            // SAFETY: the entry's `kind` is the boundary function the plugin's macro emitted.
            Some(Door::Cold(entry, _)) => unsafe { (entry.kind)() },
            Some(Door::Plane(_)) => c"plane".as_ptr().cast(),
            Some(Door::Transport(_)) => c"transport".as_ptr().cast(),
            None => std::ptr::null(),
        }
    }

    /// `busbar_set_log_sink`.
    ///
    /// # Safety
    /// Called at most once by the busbar loader, immediately after a successful `busbar_open` and
    /// before any `busbar_call`, with a sink that stays callable for this plugin's life.
    ///
    /// OPTIONAL on both sides: a host that never calls it leaves the plugin's log records dropped
    /// (logging is a host service), and a host that looks it up on an older plugin simply does not
    /// find it. That is what keeps this additive rather than a transport bump. A plane image
    /// installs nothing (it never took a sink).
    #[no_mangle]
    pub unsafe extern "C-unwind" fn busbar_set_log_sink(
        sink: LogSinkFn,
        ctx: *mut c_void,
        max_level: u32,
    ) {
        if let Some(Door::Cold(_, install)) = the_door() {
            // SAFETY: the plugin's macro generated `install`; the caller upholds its contract.
            unsafe { install(sink, ctx, max_level) };
        }
    }

    /// `busbar_open`.
    ///
    /// # Safety
    /// Called only by the busbar loader with ABI-valid pointers; answers through the registered
    /// entry's boundary (`boundary::open_boundary`).
    #[no_mangle]
    pub unsafe extern "C-unwind" fn busbar_open(
        cfg: *const u8,
        cfg_len: usize,
        out_handle: *mut *mut c_void,
        out_err: *mut *mut u8,
        out_err_len: *mut usize,
    ) -> i32 {
        match cold() {
            Some(entry) => unsafe { (entry.open)(cfg, cfg_len, out_handle, out_err, out_err_len) },
            None => STATUS_PROTOCOL,
        }
    }

    /// `busbar_call`.
    ///
    /// # Safety
    /// Called only by the busbar loader with a live handle and ABI-valid pointers; answers through
    /// the registered entry's boundary (`boundary::call_boundary`).
    #[no_mangle]
    pub unsafe extern "C-unwind" fn busbar_call(
        handle: *mut c_void,
        req: *const u8,
        req_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32 {
        match cold() {
            Some(entry) => unsafe { (entry.call)(handle, req, req_len, out, out_len) },
            None => STATUS_PROTOCOL,
        }
    }

    /// `busbar_free`.
    ///
    /// # Safety
    /// Called only by the busbar loader with a buffer this plugin returned.
    #[no_mangle]
    pub unsafe extern "C-unwind" fn busbar_free(ptr: *mut u8, len: usize) {
        if let Some(entry) = cold() {
            unsafe { (entry.free)(ptr, len) }
        }
    }

    /// `busbar_close`.
    ///
    /// # Safety
    /// Called only by the busbar loader with a live handle, once.
    #[no_mangle]
    pub unsafe extern "C-unwind" fn busbar_close(handle: *mut c_void) {
        if let Some(entry) = cold() {
            unsafe { (entry.close)(handle) }
        }
    }

    /// `busbar_plane_decl` — the plane's `'static` decl; null for an image that is not a plane.
    ///
    /// # Safety
    /// The returned pointer is to a `'static` [`PlaneDecl`] owned by this library, whose bytes and
    /// vocabulary ranges live for the whole life of the loaded image. The loader NEVER frees it.
    #[no_mangle]
    pub unsafe extern "C-unwind" fn busbar_plane_decl() -> *const PlaneDecl {
        match the_door() {
            Some(Door::Plane(decl)) => *decl,
            _ => std::ptr::null(),
        }
    }

    /// `busbar_transport_decl` — the transport's `'static` decl; null for an image that is not a
    /// transport.
    ///
    /// # Safety
    /// The returned pointer is to a `'static` [`TransportDecl`] owned by this library, preamble first,
    /// living for the whole life of the loaded image. The loader NEVER frees it.
    #[no_mangle]
    pub unsafe extern "C-unwind" fn busbar_transport_decl() -> *const TransportDecl {
        match the_door() {
            Some(Door::Transport(decl)) => decl(),
            _ => std::ptr::null(),
        }
    }

    /// `busbar_plane_arm` — arm this plane image's contract host-service ports over the host's
    /// table (minor 30; [`crate::abi::hot::services::arm`]). `Refused` for an image that is not a
    /// plane.
    ///
    /// # Safety
    /// Called only by the busbar loader, with a `host` that outlives this image (its `'static`
    /// table) or NULL.
    #[no_mangle]
    pub unsafe extern "C-unwind" fn busbar_plane_arm(
        host: *const crate::abi::hot::PlaneHostVtable,
    ) -> crate::abi::hot::RawStatus {
        let class = match the_door() {
            // SAFETY: the caller's obligation, passed through.
            Some(Door::Plane(_)) => {
                std::panic::catch_unwind(|| unsafe { crate::abi::hot::services::arm(host) })
                    .unwrap_or(crate::abi::hot::StatusClass::Fault)
            }
            _ => crate::abi::hot::StatusClass::Refused,
        };
        crate::abi::hot::RawStatus::of(class)
    }

    /// Every frozen symbol above, referenced from a `#[used]` static in each plugin image so the
    /// linker keeps them in the `cdylib` whichever codegen unit of this crate they landed in.
    #[allow(dead_code)]
    pub struct Symbols {
        abi: extern "C-unwind" fn() -> u32,
        kind: extern "C-unwind" fn() -> *const u8,
        set_log_sink: unsafe extern "C-unwind" fn(LogSinkFn, *mut c_void, u32),
        open: unsafe extern "C-unwind" fn(
            *const u8,
            usize,
            *mut *mut c_void,
            *mut *mut u8,
            *mut usize,
        ) -> i32,
        call: unsafe extern "C-unwind" fn(
            *mut c_void,
            *const u8,
            usize,
            *mut *mut u8,
            *mut usize,
        ) -> i32,
        free: unsafe extern "C-unwind" fn(*mut u8, usize),
        close: unsafe extern "C-unwind" fn(*mut c_void),
        plane_decl: unsafe extern "C-unwind" fn() -> *const PlaneDecl,
        transport_decl: unsafe extern "C-unwind" fn() -> *const TransportDecl,
        plane_arm: crate::abi::hot::PlaneArmFn,
    }

    /// The one [`Symbols`] table.
    pub static SYMBOLS: Symbols = Symbols {
        abi: busbar_abi,
        kind: busbar_plugin_kind,
        set_log_sink: busbar_set_log_sink,
        open: busbar_open,
        call: busbar_call,
        free: busbar_free,
        close: busbar_close,
        plane_decl: busbar_plane_decl,
        transport_decl: busbar_transport_decl,
        plane_arm: busbar_plane_arm,
    };
}

/// Register a plugin image's ONE door (`$door`, a `__door::Door`) with a load-time constructor, and
/// keep the SDK's frozen symbols in the image. Emitted by `export_plugin!` and `export_plane!`;
/// never called by hand.
#[doc(hidden)]
#[macro_export]
macro_rules! __register_door {
    ($door:expr) => {
        /// This image's door (see `busbar_contract::abi::sdk::__door`).
        #[doc(hidden)]
        pub static __BUSBAR_DOOR: $crate::abi::sdk::__door::Door = $door;

        const _: () = {
            extern "C" fn __busbar_register_door() {
                $crate::abi::sdk::__door::register(&__BUSBAR_DOOR)
            }

            // No load-time initializer section is known for any other target: refuse to build there
            // rather than emit a plugin whose door never registers.
            const _: () = ::core::assert!(
                ::core::cfg!(any(
                    target_vendor = "apple",
                    target_os = "windows",
                    target_os = "linux",
                    target_os = "android",
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                    target_os = "illumos",
                    target_os = "solaris",
                )),
                "busbar plugin: no load-time initializer section is known for this target"
            );

            #[used]
            #[cfg_attr(target_vendor = "apple", link_section = "__DATA,__mod_init_func")]
            #[cfg_attr(target_os = "windows", link_section = ".CRT$XCU")]
            #[cfg_attr(
                any(
                    target_os = "linux",
                    target_os = "android",
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                    target_os = "illumos",
                    target_os = "solaris",
                ),
                link_section = ".init_array"
            )]
            static __BUSBAR_DOOR_INIT: extern "C" fn() = __busbar_register_door;

            #[used]
            static __BUSBAR_DOOR_SYMBOLS: &$crate::abi::sdk::__door::Symbols =
                &$crate::abi::sdk::__door::SYMBOLS;
        };
    };
}

/// The ONE macro that stamps a plugin's KIND and emits the SIX kind-neutral `extern "C-unwind"`
/// symbols (`busbar_abi`, `busbar_plugin_kind`, `busbar_open`, `busbar_call`, `busbar_free`,
/// `busbar_close`), hard-wiring EVERY symbol through the [`boundary`] choke point. The per-kind
/// `export_*_plugin!` convenience macros expand through this — a plugin author normally calls those.
///
/// The author supplies ONLY a `$ctor` (`fn(&str) -> Result<$handle, String>`) and a `$dispatch`
/// (`unsafe fn(*mut c_void, &[u8]) -> BoundaryOutcome`). The null-out-guard-before-alloc, the mandatory
/// `catch_unwind`, the total status mapping, and the drop-on-null handle publish are supplied by
/// `boundary::open_boundary`/`call_boundary`/`close_boundary`/`free_boundary`. There is NO seam on which
/// an author can get a boundary facet wrong: `$dispatch` returns a [`BoundaryOutcome`] that cannot name
/// a raw pointer or a status integer. The macro defines no `#[no_mangle]` symbol itself: it emits
/// `BUSBAR_COLD_ENTRY`, the boundary a host that LINKS the plugin is handed, and registers that same
/// entry as the image's door, through which the SDK's ONE set of frozen symbols (`__door`) answers
/// in the `cdylib` (DECISIONS #2 rule (1): compiled in or dropped in, one contract, one loading path).
///
/// - `$kind` — a `&'static str` kind (`"store"` | `"secret"` | `"auth"` | `"hook"`).
/// - `$dispatch` — the per-kind SDK `dispatch` adapter (`store_dispatch`/`auth_dispatch`/…).
/// - `$ctor` — the plugin's `fn(&str) -> Result<$handle, String>` constructor.
/// - `$handle` — the boxed handle type, so `close_boundary::<$handle>` frees it correctly.
#[macro_export]
macro_rules! export_plugin {
    (kind = $kind:expr, dispatch = $dispatch:path, ctor = $ctor:path, handle = $handle:ty $(,)?) => {
        // THE BOUNDARY, ONCE. Each function below is the body of one exported symbol, under a
        // mangled name, and `BUSBAR_COLD_ENTRY` references them. The linked door (the `rlib`'s entry)
        // hands the loader that entry; the dropped-in door registers the SAME entry as this image's
        // door (`__register_door!`), and the frozen `#[no_mangle]` symbols — defined ONCE, in this
        // SDK (`__door`) — answer through it. So the `dlsym` on the `cdylib` and the linked entry
        // reach the SAME code, and no plugin crate defines a frozen symbol of its own: two plugins
        // linked into one binary cannot both define `busbar_call`.

        /// `busbar_abi` — the frozen TRANSPORT handshake.
        #[doc(hidden)]
        pub extern "C-unwind" fn __busbar_cold_abi() -> u32 {
            $crate::abi::cold::TRANSPORT_VERSION
        }

        /// `busbar_plugin_kind` — a `'static` NUL-terminated string owned by this library.
        #[doc(hidden)]
        pub extern "C-unwind" fn __busbar_cold_kind() -> *const u8 {
            const KIND_NUL: &str = concat!($kind, "\0");
            KIND_NUL.as_ptr()
        }

        /// `busbar_open`.
        ///
        /// # Safety
        /// Called only by the busbar loader with ABI-valid pointers. Routes through
        /// `boundary::open_boundary`: the ctor runs under a mandatory `catch_unwind`, the handle is
        /// published only into a confirmed non-null slot (else dropped), and the status is total.
        #[doc(hidden)]
        pub unsafe extern "C-unwind" fn __busbar_cold_open(
            cfg: *const u8,
            cfg_len: usize,
            out_handle: *mut *mut ::core::ffi::c_void,
            out_err: *mut *mut u8,
            out_err_len: *mut usize,
        ) -> i32 {
            $crate::abi::sdk::boundary::open_boundary::<$handle>(
                cfg,
                cfg_len,
                out_handle,
                out_err,
                out_err_len,
                |s| $ctor(s).map_err($crate::abi::sdk::BoundaryOutcome::Error),
            )
        }

        /// `busbar_call`.
        ///
        /// # Safety
        /// Called only by the busbar loader with a live handle and ABI-valid pointers. Routes through
        /// `boundary::call_boundary`: null-handle → protocol, dispatch under mandatory `catch_unwind`,
        /// alloc-after-check buffer publish, total status.
        #[doc(hidden)]
        pub unsafe extern "C-unwind" fn __busbar_cold_call(
            handle: *mut ::core::ffi::c_void,
            req: *const u8,
            req_len: usize,
            out: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32 {
            $crate::abi::sdk::boundary::call_boundary(handle, req, req_len, out, out_len, |h, b| {
                $dispatch(h, b)
            })
        }

        /// `busbar_free`.
        ///
        /// # Safety
        /// Called only by the busbar loader with a buffer this plugin returned. Catch-wrapped dealloc.
        #[doc(hidden)]
        pub unsafe extern "C-unwind" fn __busbar_cold_free(ptr: *mut u8, len: usize) {
            $crate::abi::sdk::boundary::free_boundary(ptr, len)
        }

        /// `busbar_close`.
        ///
        /// # Safety
        /// Called only by the busbar loader with a live handle, once. Routes through
        /// `boundary::close_boundary`: the box is owned BEFORE the `catch_unwind`, so a panicking Drop
        /// frees the allocation and never unwinds out of this symbol.
        #[doc(hidden)]
        pub unsafe extern "C-unwind" fn __busbar_cold_close(handle: *mut ::core::ffi::c_void) {
            $crate::abi::sdk::boundary::close_boundary::<$handle>(handle)
        }

        /// `busbar_set_log_sink` on the LINKED door: the sink, without the `tracing` bridge a linked
        /// plugin must not install (see `hostlog::install_sink`).
        ///
        /// # Safety
        /// As `__busbar_cold_set_log_sink`.
        #[doc(hidden)]
        pub unsafe extern "C-unwind" fn __busbar_linked_set_log_sink(
            sink: $crate::abi::sdk::__abi::LogSinkFn,
            ctx: *mut ::std::ffi::c_void,
            max_level: u32,
        ) {
            unsafe { $crate::abi::sdk::hostlog::install_sink(sink, ctx, max_level) };
        }

        /// `busbar_set_log_sink` on the DROPPED-IN door: the sink, then this image's `tracing`
        /// forwarder. A `cdylib` statically links its OWN `tracing-core`, so every `tracing::warn!`
        /// in it (and in library crates that never named this SDK) reaches no host subscriber unless
        /// forwarded into the sink. The forwarder is installed HERE, in the plugin image, never by
        /// the contract. Filtering happens on this side at the host's level, so a `trace!` the host
        /// would discard is never rendered. Best-effort: a plugin that set its own global dispatcher
        /// keeps it.
        ///
        /// # Safety
        /// As `busbar_set_log_sink`: called once by the loader with a sink that stays callable, and
        /// a `ctx` that stays valid, for this plugin's life.
        #[doc(hidden)]
        pub unsafe extern "C-unwind" fn __busbar_cold_set_log_sink(
            sink: $crate::abi::sdk::__abi::LogSinkFn,
            ctx: *mut ::std::ffi::c_void,
            max_level: u32,
        ) {
            use $crate::abi::sdk::{__abi::tracing_core as tc, hostlog};
            unsafe { hostlog::install_sink(sink, ctx, max_level) };
            // Indexed by the ABI's `log_level` constants: OFF = 0, then ERROR = 1 ..= TRACE = 5.
            use tc::LevelFilter as F;
            const FILTERS: [F; 6] = [F::OFF, F::ERROR, F::WARN, F::INFO, F::DEBUG, F::TRACE];
            fn abi_level(l: &tc::Level) -> u32 {
                FILTERS.iter().position(|f| f == l).map_or(5, |i| i as u32)
            }
            struct Render(::std::string::String);
            impl tc::field::Visit for Render {
                fn record_debug(&mut self, f: &tc::Field, v: &dyn ::std::fmt::Debug) {
                    // `message` is the human sentence; every other field renders as `key=value`.
                    let sep = if self.0.is_empty() { "" } else { " " };
                    self.0 += &match f.name() {
                        "message" => ::std::format!("{}{:?}", sep, v),
                        key => ::std::format!("{}{}={:?}", sep, key, v),
                    };
                }
            }
            struct Forwarder;
            impl tc::Subscriber for Forwarder {
                fn enabled(&self, m: &tc::Metadata<'_>) -> bool {
                    hostlog::enabled(abi_level(m.level()))
                }
                // Without the hint `tracing-core` assumes TRACE and every `trace!` in the image
                // becomes a live callsite; with it they stay a static check.
                fn max_level_hint(&self) -> ::core::option::Option<F> {
                    let most = (1..=5).rev().find(|&l| hostlog::enabled(l)).unwrap_or(0);
                    ::core::option::Option::Some(FILTERS[most as usize])
                }
                fn new_span(&self, _a: &tc::span::Attributes<'_>) -> tc::span::Id {
                    tc::span::Id::from_u64(1)
                }
                fn record(&self, _s: &tc::span::Id, _v: &tc::span::Record<'_>) {}
                fn record_follows_from(&self, _s: &tc::span::Id, _f: &tc::span::Id) {}
                fn event(&self, event: &tc::Event<'_>) {
                    let level = abi_level(event.metadata().level());
                    // Re-checked: a cached callsite interest can outlive a level change, and
                    // rendering is where the cost is.
                    if hostlog::enabled(level) {
                        let mut r = Render(::std::string::String::new());
                        event.record(&mut r);
                        hostlog::log(level, &r.0);
                    }
                }
                fn enter(&self, _s: &tc::span::Id) {}
                fn exit(&self, _s: &tc::span::Id) {}
            }
            let _ = tc::dispatcher::set_global_default(tc::Dispatch::new(Forwarder));
        }

        /// The boundary for the LINKED door (`crate::abi::cold::ColdEntry`): a build that compiles
        /// this plugin in hands the loader these functions instead of a library to look them up in,
        /// and the loader runs its one cold-lane load over them (DECISIONS #2 rule (1)).
        pub static BUSBAR_COLD_ENTRY: $crate::abi::sdk::__abi::ColdEntry =
            $crate::abi::sdk::__abi::ColdEntry {
                abi: __busbar_cold_abi,
                kind: __busbar_cold_kind,
                set_log_sink: __busbar_linked_set_log_sink,
                open: __busbar_cold_open,
                call: __busbar_cold_call,
                free: __busbar_cold_free,
                close: __busbar_cold_close,
            };

        // The dropped-in door: this image's ONE registration. The frozen symbols the loader looks
        // up in the `cdylib` are the SDK's (`__door`), and they answer through this entry.
        $crate::__register_door!($crate::abi::sdk::__door::Door::Cold(
            &BUSBAR_COLD_ENTRY,
            __busbar_cold_set_log_sink
        ));
    };
}

// ── PLANE glue (`kind: plane`, 1.6.0 S4) ──────────────────────────────────────────────────────────
// A plane is the SIXTH kind and the ONE kind that does NOT speak the six-symbol JSON `call` wire: it
// is a HOT-tier protocol plane driven over the `#[repr(C)]` `crate::abi::hot::PlaneDecl` vtable.
// `export_plane!` is therefore its OWN macro (not a thin wrapper over `export_plugin!`): it stamps the
// SHARED transport handshake (`busbar_abi`) + `busbar_plugin_kind() == "plane"` so the plane rides the
// same tarball/trust discovery pipeline, plus the ONE hot-lane entrypoint `busbar_plane_decl()`
// returning the author's `'static PlaneDecl`. The plane author authors a real `PlaneDecl` (its
// `#[repr(C)]` vtable, filling the `build`/`start`/`dispatch`/… slots against `crate::abi::hot`);
// the SDK only emits the boundary symbols. This is the plane analogue of `export_store_plugin!`.

/// The whole HOT-tier plane ABI surface, re-exported so a plane crate names
/// `busbar_contract::abi::sdk::plane::PlaneDecl` (etc.) without a direct `busbar-plugin` dependency — the same
/// convenience re-export path the cold kinds get for their wire types.
pub mod plane {
    pub use crate::abi::hot::pod::{OpaqueState, RawStatus, StatusClass, POD_VERSION};
    pub use crate::abi::hot::{
        decl, host, pod, workitem, BuildCtx, EmitHandle, EmitKind, InboundHandle, InboundKind,
        IngressCarrier, OpaqueHandle, PlaneDecl, PlaneDeclFn, PlaneHostVtable, WorkItem,
    };
    pub use crate::abi::{
        check_preamble, honoured_size, write_out, AbiPreamble, ABI_MAJOR, ABI_MINOR,
    };
}

/// Re-export used ONLY by the `export_plane!` expansion, so a plane crate does not need its own
/// direct `busbar-plugin` dependency just to name `PlaneDecl` in the generated `busbar_plane_decl`
/// symbol.
#[doc(hidden)]
pub mod __plane_abi {
    pub use crate::abi::hot::PlaneDecl;
}

/// Emit a `plane`-kind cdylib from `$decl` (a `'static busbar_contract::abi::sdk::plane::PlaneDecl`, e.g. a
/// `pub static PLANE_DECL: PlaneDecl = …`). Registers `$decl` as the image's door, so the SDK's
/// frozen symbols (`__door`) answer the SHARED transport handshake `busbar_abi()`,
/// `busbar_plugin_kind() == "plane"`, and the ONE hot-lane entrypoint `busbar_plane_decl()` returning
/// a pointer to `$decl`. The SAME `$decl` `static` is usable STATICALLY (compiled-in) — depend on the
/// crate as a normal `lib` and hand `&PLANE_DECL` to the registry — so a plane is both-ways by
/// construction, exactly like the cold kinds (`DECISIONS #2/#11/#26 S4`).
///
/// The plane author owns `$decl`: the `#[repr(C)]` `PlaneDecl` whose `config_validate`/`build`/
/// `hydrate`/`start`/`admin_routes`/`openapi`/`dispatch` slots and `provided_carriers` they fill
/// against `crate::abi::hot`. The macro adds NO seam on which a boundary symbol can be got wrong.
#[macro_export]
macro_rules! export_plane {
    ($decl:path) => {
        // The dropped-in door: this image's ONE registration. `busbar_abi`, `busbar_plugin_kind()
        // == "plane"` and `busbar_plane_decl` are the SDK's frozen symbols (`__door`), answering
        // through `$decl` — so a plane crate linked into a binary beside any other plugin defines no
        // symbol of its own that could collide.
        $crate::__register_door!($crate::abi::sdk::__door::Door::Plane(&$decl));
    };
}

/// Emit a `transport`-kind cdylib from `$decl` (the transport's `'static` `#[repr(C)]` decl — the
/// published `TransportDecl` layout, whether named from `abi::hot` or restated in the transport's
/// own source). Registers it as the image's door, so the frozen symbols (`__door`) answer the SHARED
/// handshake `busbar_abi()`, `busbar_plugin_kind() == "transport"`, and the transport's ONE hot-lane
/// entrypoint `busbar_transport_decl()` returning a pointer to `$decl`.
///
/// THE ONE SHARED TRANSPORT DOOR (#3: a transport is swappable, compiled in OR dropped in; LTO-FIX
/// residue). A transport crate used to define `busbar_abi` / `busbar_plugin_kind` /
/// `busbar_transport_decl` itself, and those collided with this crate's door in any link that held
/// both. Through this macro a transport defines no frozen symbol of its own — exactly like a plane.
#[macro_export]
macro_rules! export_transport {
    ($decl:path) => {
        /// The dropped-in door's decl function: the address of the transport's `'static` decl.
        fn __busbar_transport_decl() -> *const $crate::abi::hot::TransportDecl {
            ::core::ptr::addr_of!($decl).cast()
        }
        $crate::__register_door!($crate::abi::sdk::__door::Door::Transport(
            __busbar_transport_decl
        ));
    };
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
