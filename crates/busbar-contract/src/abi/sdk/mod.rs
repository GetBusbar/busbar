// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN SDK: the typed Rust wrappers over the memory ABI (`BUSBAR-1.6.0.md` THE DESIGN, one
//! place for every ABI shape, `abi/sdk/`). A plugin of any kind writes its slots against [`door`]
//! (`plugin_door!`) and exports its ONE door symbol through `export_door!`; compiled in or dropped
//! in, the host calls the same table.
//!
//! No plugin of any kind has a JSON-lane export: the COLD/JSON lane is gone. [`boundary`]'s one
//! catch and the frozen symbols below are the HOT lane's residue, deleted with it.

// The SDK's `unsafe fn` bodies were written under the crate default (edition 2021: an `unsafe fn`
// body is itself an unsafe context). The shared ABI root denies `unsafe_op_in_unsafe_fn` for the two
// lanes; the SDK keeps the discipline it was written and reviewed under, unchanged by the merge.
#![allow(unsafe_op_in_unsafe_fn)]

pub mod boundary;
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
pub mod io;
// ONE REQUEST, ONE REPLY over the connector: exchange() (framed) and send_and_ack() (any transport).
/// A plane's reads of a body by declared pointer, one copy for every plane.
pub mod body;
pub mod exchange;
pub use safe::{Instance, Safe, SafeSlot};
// THE HOST SERVICES, PLUGIN SIDE: the one home of every safe host-service wrapper.
pub mod services;
pub use services::{
    Judged, Names, Pend, Records, ServiceError, Services, Signature, Signed, TrustItem, TrustItems,
    Wake,
};
// THE ONE DIGEST A PLUGIN TAKES without linking a crypto crate of its own.
pub mod digest;
// THE AUTH KIND'S VERIFY DOOR over the safe layer (`auth_verify_door!`). An auth plugin keeps its
// inbound verdict cache inside itself (THE DESIGN, section 11.11).
pub mod auth_door;
// THE AUTH KIND'S OUTBOUND DOOR over the safe layer (`auth_outbound_door!`, and
// `auth_door!(verify_and_outbound: ..)` for a plugin that does both).
pub mod auth_outbound;
// THE AUTH LOGIN KIT's shared checks: the id-token nonce binding v1.5.5's core ran for every login.
pub mod login;
// THE STORE KIND'S TYPED SDK: the trait a store implements to be served through the store v3 table.
pub mod store;
// PUBLISHED GENERATION DATA: the SDK owns what a plugin publishes (`abi::sdk::publish`).
pub mod publish;
pub use publish::{Generations, Keyed};
// TRUST ON SIGHT, PLANE SIDE: the state word a trust view answers and the last contact it is
// derived from, one shape for every plane that sights an upstream on the kernel's trust book.
pub mod trust;
// THE LIFECYCLE, ONCE FOR EVERY KIND: the nine lifecycle slots over a kind's `Life` (`abi::sdk::life`).
pub mod life;

// The `#[macro_export]` export macros, named at this module's path too.
pub use crate::{export_carrier, export_framer, export_plane, export_transport};

/// The "decision observability" signal catalog: a plugin author references
/// `busbar_contract::abi::sdk::Signal::CandidateBreakerState` (etc.) at compile time to declare which
/// catalog entries their hook wants computed + projected — see `crate::signal::Signal`'s doc comment
/// for the full catalog and the append-only/non_exhaustive contract.
pub use crate::signal::{Signal, SignalBag, SignalValue};

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
// Every frozen name the HOT lane's loader looks up in a plane or transport `cdylib` (`busbar_abi`,
// `busbar_plugin_kind`, `busbar_plane_decl`, `busbar_transport_decl`, `busbar_plane_arm`) is defined HERE, in
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
// binary looks them up; the linked door is the plane's or the transport's decl, never these.
#[doc(hidden)]
pub mod __door {
    use crate::abi::hot::{PlaneDecl, TransportDecl};
    use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

    /// What one plugin image is, as its dropped-in door answers for it.
    pub enum Door {
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
            Some(Door::Plane(_)) => c"plane".as_ptr().cast(),
            Some(Door::Transport(_)) => c"transport".as_ptr().cast(),
            None => std::ptr::null(),
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
        plane_decl: unsafe extern "C-unwind" fn() -> *const PlaneDecl,
        transport_decl: unsafe extern "C-unwind" fn() -> *const TransportDecl,
        plane_arm: crate::abi::hot::PlaneArmFn,
    }

    /// The one [`Symbols`] table.
    pub static SYMBOLS: Symbols = Symbols {
        abi: busbar_abi,
        kind: busbar_plugin_kind,
        plane_decl: busbar_plane_decl,
        transport_decl: busbar_transport_decl,
        plane_arm: busbar_plane_arm,
    };
}

/// Register a plugin image's ONE door (`$door`, a `__door::Door`) with a load-time constructor, and
/// keep the SDK's frozen symbols in the image. Emitted by `export_plane!` and `export_transport!`;
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

// ── PLANE glue (`kind: plane`, 1.6.0 S4) ──────────────────────────────────────────────────────────
// A plane is the SIXTH kind and the ONE kind that does NOT speak the six-symbol JSON `call` wire: it
// is a HOT-tier protocol plane driven over the `#[repr(C)]` `crate::abi::hot::PlaneDecl` vtable.
// `export_plane!` is therefore its OWN macro: it stamps the
// SHARED transport handshake (`busbar_abi`) + `busbar_plugin_kind() == "plane"` so the plane rides the
// same tarball/trust discovery pipeline, plus the ONE hot-lane entrypoint `busbar_plane_decl()`
// returning the author's `'static PlaneDecl`. The plane author authors a real `PlaneDecl` (its
// `#[repr(C)]` vtable, filling the `build`/`start`/`dispatch`/… slots against `crate::abi::hot`);
// the SDK only emits the boundary symbols.

/// The whole HOT-tier plane ABI surface, re-exported so a plane crate names
/// `busbar_contract::abi::sdk::plane::PlaneDecl` (etc.) without a direct `busbar-plugin` dependency — the same
/// convenience re-export path every kind gets for its wire types.
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
/// construction (`DECISIONS #2/#11/#26 S4`).
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
