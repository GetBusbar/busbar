// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SDK for writing a busbar **store plugin** in Rust.
//!
//! Writing a plugin is: implement [`crate::records::RecordStore`] for your backend, write a constructor
//! `fn(&str) -> Result<Box<dyn Store>, String>` (the `&str` is the JSON config the operator set),
//! call [`export_store_plugin!`] with it, and build the crate as a `cdylib`. The `cdylib` then
//! exports the six `extern "C-unwind"` symbols the engine's loader resolves (`busbar_abi`,
//! `busbar_plugin_kind`, `busbar_open`, `busbar_call`, `busbar_free`, `busbar_close` — defined once,
//! in this SDK, answering through the plugin the macro registers); every one routes through the single
//! export-boundary choke point in [`boundary`] (null-out-guard-before-alloc, mandatory `catch_unwind`,
//! and a total status map), so no per-symbol code can get an FFI-boundary invariant wrong. The author
//! supplies only a ctor + a per-kind [`dispatch`] returning a [`BoundaryOutcome`].
//!
//! ```ignore
//! use busbar_contract::abi::sdk::export_store_plugin;
//! fn open(cfg: &str) -> Result<Box<dyn busbar_contract::records::RecordStore>, String> {
//!     Ok(Box::new(MyStore::new(cfg)?))
//! }
//! export_store_plugin!(open);
//! ```
//!
//! The same crate is usable **statically**: depend on it as a normal `lib` and construct
//! `MyStore` directly — the C ABI is only the *dynamic* delivery path. That is how a build can bake
//! a plugin in (e.g. Postgres compiled straight into a custom binary) without any `cfg` sprawl.

// The SDK's `unsafe fn` bodies were written under the crate default (edition 2021: an `unsafe fn`
// body is itself an unsafe context). The shared ABI root denies `unsafe_op_in_unsafe_fn` for the two
// lanes; the SDK keeps the discipline it was written and reviewed under, unchanged by the merge.
#![allow(unsafe_op_in_unsafe_fn)]

use crate::abi::cold::{StoreRequest, StoreResponse, ABI_VERSION};
use crate::records::{RecordStore, RecordStoreError};
use std::os::raw::c_void;

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
pub mod exchange;
pub use safe::{Instance, Safe, SafeSlot};
// THE HOST SERVICES, PLUGIN SIDE: the one home of every safe host-service wrapper.
pub mod services;
pub use services::{Due, Pend, ServiceError, Services};
// THE AUTH KIND'S VERIFY DOOR over the safe layer (`auth_verify_door!`). An auth plugin keeps its
// inbound verdict cache inside itself (THE DESIGN, section 11.11).
pub mod auth_door;
// THE STORE KIND'S TYPED SDK: the trait a store implements to be served through the store v3 table.
pub mod store;
// PUBLISHED GENERATION DATA: the SDK owns what a plugin publishes (`abi::sdk::publish`).
pub mod publish;
pub use publish::Generations;
// THE LIFECYCLE, ONCE FOR EVERY KIND: the nine lifecycle slots over a kind's `Life` (`abi::sdk::life`).
pub mod life;

// The `#[macro_export]` export macros, named at this module's path too, so a plugin writes
// `busbar_contract::abi::sdk::export_store_plugin!` exactly where it wrote
// `busbar_plugin_sdk::export_store_plugin!`.
pub use crate::{
    export_auth_plugin, export_carrier, export_export_plugin, export_framer, export_hook_plugin,
    export_login_plugin, export_plane, export_plugin, export_secret_plugin, export_store_plugin,
    export_transport,
};

// Convenience alias for out-of-tree store plugins that want to name the trait without also
// depending on `busbar-api` directly. `export_store_plugin!` does NOT use this alias (it expands
// to `store_dispatch`/`StoreHandle`, never `StoreTrait`) — this is frozen SDK surface kept for
// callers outside this repo, not for anything internal to the macro.
pub use crate::records::RecordStore as StoreTrait;

/// The "decision observability" signal catalog: a plugin author references
/// `busbar_contract::abi::sdk::Signal::CandidateBreakerState` (etc.) at compile time to declare which
/// catalog entries their hook wants computed + projected — see `crate::signal::Signal`'s doc comment
/// for the full catalog and the append-only/non_exhaustive contract.
pub use crate::abi::cold::{Signal, SignalBag, SignalValue};

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

/// The handle type behind the opaque `*mut c_void` for a store plugin (a boxed trait object). Named at
/// the module level so the `export_plugin!` expansion can pass it to `close_boundary::<$ty>`.
pub type StoreHandle = Box<dyn RecordStore>;

/// The store handle behind the opaque `*mut c_void` that crosses the ABI: a boxed trait object.
type BoxedStore = StoreHandle;

/// Return the store PAYLOAD schema version this SDK builds against (the manifest `abi_version` a
/// `kind: store` plugin declares). NOT the transport version — see [`transport_version`]. See
/// `docs/plugins.md`'s `abi_version` manifest field for the engine-side boot-time check against it.
pub fn abi_version() -> u32 {
    ABI_VERSION
}

/// The frozen kind-neutral TRANSPORT version this SDK builds against — a plugin exports it as
/// `busbar_abi()`. Frozen at [`crate::abi::cold::TRANSPORT_VERSION`] (=1); distinct from the per-kind
/// payload schema version ([`abi_version`] / [`secret_abi_version`]).
pub fn transport_version() -> u32 {
    crate::abi::cold::TRANSPORT_VERSION
}

/// Run one [`StoreRequest`] against a `Store`. The single match that maps the wire enum to the trait
/// — shared by the C `call` glue and directly unit-testable without any FFI.
pub fn dispatch(
    store: &dyn RecordStore,
    req: StoreRequest,
) -> Result<StoreResponse, RecordStoreError> {
    use StoreRequest as Q;
    use StoreResponse as R;
    Ok(match req {
        Q::PutKey(k) => {
            store.put_key(&k)?;
            R::Unit
        }
        Q::GetKey(id) => R::Key(store.get_key(&id)?),
        Q::ListKeys => R::Keys(store.list_keys()?),
        Q::DeleteKey(id) => {
            store.delete_key(&id)?;
            R::Unit
        }
        Q::ScrubKey(id) => {
            store.scrub_key(&id)?;
            R::Unit
        }
        Q::ListKeysSince(since) => R::Keys(store.list_keys_since(since)?),
        Q::GetUsage {
            bucket_id,
            window_start,
        } => R::Usage(store.get_usage(&bucket_id, window_start)?),
        Q::PutUsage {
            bucket_id,
            window_start,
            ledger,
        } => {
            store.put_usage(&bucket_id, window_start, &ledger)?;
            R::Unit
        }
        Q::AddUsage {
            bucket_id,
            window_start,
            delta,
        } => {
            store.add_usage(&bucket_id, window_start, &delta)?;
            R::Unit
        }
        Q::AddMetering(d) => {
            store.add_metering(&d)?;
            R::Unit
        }
        Q::ListMetering(b) => R::Metering(store.list_metering(b)?),
        Q::PurgeWindowsBefore(before) => R::Purged(store.purge_windows_before(before)?),
        Q::PurgeMeteringBefore(bucket) => R::Purged(store.purge_metering_before(&bucket)?),
        Q::PutCredential(secret) => {
            store.put_credential(&secret)?;
            R::Unit
        }
        Q::PutKeyWithCredential { key, secret } => {
            store.put_key_with_credential(&key, &secret)?;
            R::Unit
        }
        Q::ListCredentials(key_id) => R::Credentials(store.list_credentials(&key_id)?),
        Q::LookupCredentialSecret { kind, public_id } => {
            R::CredentialSecret(store.lookup_credential_secret(&kind, &public_id)?)
        }
        Q::RevokeCredential { id, reason } => {
            store.revoke_credential(&id, &reason)?;
            R::Unit
        }
        Q::ListCredentialsSince(since) => {
            R::CredentialSecrets(store.list_credentials_since(since)?)
        }
        Q::AppendAudit(e) => {
            store.append_audit(&e)?;
            R::Unit
        }
        Q::ListAudit => R::Audit(store.list_audit()?),
        Q::ListAuditTail(limit) => R::Audit(store.list_audit_tail(limit)?),
        Q::AddDenylist { sub, reason } => {
            store.add_denylist(&sub, &reason)?;
            R::Unit
        }
        Q::ListDenylist => R::Denylist(store.list_denylist()?),

        // ── THE NEUTRAL KIND-TAGGED PLANE-RECORD SURFACE (1.6.0) ─────────────────────────────
        //
        // Maps the eight kind-tagged wire variants onto the eight neutral trait methods — the ONLY
        // durable-plane surface now (the fourteen protocol-named arms are deleted, `ABI_VERSION` was
        // raised to 3 in 1.6.0 for that, then to 4 in 1.7.0 when the plane-record types relocated;
        // see `crate::abi::cold::ABI_VERSION`). Upsert and append view a
        // [`crate::records::PlaneRecordRef`] over the request and
        // NOTHING else, which is why the write verbs carry the whole typed sidecar: `ts` and
        // `disposition` are the two columns a retention sweep reads and the two it cannot recover
        // from an opaque body, so a wire that dropped them would hand every backend behind this ABI
        // a log that reads as ts 0 and `Active` — an age-based purge then deletes everything and a
        // terminal-only purge deletes nothing. A request from an engine that predates the sidecar
        // omits those fields and serde-defaults them to exactly the neutral values this arm used to
        // hard-code, so the older path is byte-for-byte what it was.
        //
        // `parent`/`seq` are still absent from `UpsertPlaneRecord` on purpose, not as a leftover:
        // upsert kinds are top-level (`task`, `demotion`) and their envelope carries `parent: None`
        // and `seq: 0` by definition, so there is nothing to lose.
        Q::UpsertPlaneRecord {
            kind,
            id,
            ts,
            disposition,
            body,
        } => {
            store.upsert_plane_record(crate::records::PlaneRecordRef {
                kind: &kind,
                id: &id,
                parent: None,
                seq: 0,
                ts,
                disposition,
                body: &body,
            })?;
            R::Unit
        }
        Q::GetPlaneRecord { kind, id } => R::PlaneRecord(store.get_plane_record(&kind, &id)?),
        Q::AppendPlaneRecord {
            kind,
            id,
            parent,
            seq,
            ts,
            disposition,
            body,
        } => {
            store.append_plane_record(crate::records::PlaneRecordRef {
                kind: &kind,
                id: &id,
                parent: Some(&parent),
                seq,
                ts,
                disposition,
                body: &body,
            })?;
            R::Unit
        }
        Q::ListPlaneRecords { kind, selector } => {
            R::PlaneRecords(store.list_plane_records(&kind, &selector)?)
        }
        Q::ListPlaneRecordParents { kind } => {
            R::PlaneRecordParents(store.list_plane_record_parents(&kind)?)
        }
        Q::PurgePlaneRecordsBefore { kind, before } => {
            R::Purged(store.purge_plane_records_before(&kind, before)?)
        }
        Q::DeletePlaneRecord { kind, id } => {
            store.delete_plane_record(&kind, &id)?;
            R::Unit
        }
        Q::RedeemPlaneToken {
            kind,
            token,
            expires_at,
            now,
        } => R::Redeemed(store.redeem_plane_token(&kind, &token, expires_at, now)?),
        Q::PlaneTokenLive {
            kind,
            token,
            expires_at,
            now,
        } => R::TokenLive(store.plane_token_live(&kind, &token, expires_at, now)?),
    })
}

/// The per-kind `dispatch` closure `export_store_plugin!` hands to [`boundary::call_boundary`]: decode a
/// [`StoreRequest`], run it via [`dispatch`], and encode the [`StoreResponse`] into a [`BoundaryOutcome`].
/// The boundary wrapper supplies the null-handle guard, the mandatory `catch_unwind`, the status map,
/// and the alloc-after-check buffer publish — this closure only names the kind's types.
///
/// A REQUEST-decode failure is the ONLY [`BoundaryOutcome::Unsupported`] case: it is how an older plugin
/// (predating a request variant) signals "I cannot understand this variant", which the loader keys on to
/// fall back (empty denylist / full-list audit tail). A RESPONSE-encode failure is a real fault →
/// [`BoundaryOutcome::Error`], never Unsupported, or the loader would swallow it as old-SDK.
///
/// # Safety
/// `handle` is a live store handle from `open` (guaranteed non-null by the boundary wrapper).
pub unsafe fn store_dispatch(handle: *mut c_void, bytes: &[u8]) -> BoundaryOutcome {
    let store: &BoxedStore = &*(handle as *const BoxedStore);
    let request: StoreRequest = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => return BoundaryOutcome::Unsupported(format!("malformed request JSON: {e}")),
    };
    match dispatch(store.as_ref(), request) {
        Ok(resp) => match serde_json::to_vec(&resp) {
            Ok(payload) => BoundaryOutcome::Ok(payload),
            Err(e) => BoundaryOutcome::Error(format!("response encode failed: {e}")),
        },
        Err(e) => BoundaryOutcome::Error(e.0),
    }
}

// ── AUTH-plugin glue (`kind: auth`) ──────────────────────────────────────────────────────────────
// Mirrors the store glue: same six-symbol shape via `export_plugin!`, its own handle type
// (`Box<dyn AuthModule>`) and the identity-only auth wire. A denied credential is a SUCCESSFUL call
// (`Reject`/`Pass` ride the OK payload); only a malformed request / encode failure is a protocol error.

/// The auth handle behind the opaque `*mut c_void`: a boxed [`crate::auth::AuthPlugin`] — an auth
/// module that is BOTH a verifier ([`crate::auth::AuthModule`]) and a login provider
/// ([`crate::auth::LoginModule`], fail-closed by default for verify-only modules). Named at the module
/// level so the `export_plugin!` expansion can pass it to `close_boundary::<$ty>`.
pub type AuthHandle = Box<dyn crate::auth::AuthPlugin>;

pub use crate::abi::cold::auth::{AuthRequest, AuthResponse};
/// Re-export the auth wire and the two auth faces so an auth author (and the `dispatch_compiled_in`
/// twin `export_auth_plugin!` emits) names `busbar_contract::abi::sdk::AuthRequest` (etc.) without a direct
/// `busbar-plugin` dependency, mirroring the hook/export re-export path.
pub use crate::auth::{AuthModule, AuthPlugin};

/// The auth handle behind the opaque `*mut c_void`: a boxed [`crate::auth::AuthPlugin`].
type BoxedAuth = AuthHandle;

/// Fail-closed login adapter: wraps a verify-only [`crate::auth::AuthModule`] as a full
/// [`crate::auth::AuthPlugin`] by delegating the verify methods and taking [`crate::auth::LoginModule`]'s
/// default (Reject) login behavior. This is what lets `export_auth_plugin!` keep accepting a
/// `fn(&str) -> Result<Box<dyn AuthModule>, String>` ctor UNCHANGED while the exported handle is the
/// unified `Box<dyn AuthPlugin>`.
///
/// Generic over how the module is held: the dropped-in door's handle OWNS it (`Box`), and the
/// compiled-in twin `export_auth_plugin!` emits BORROWS the one its caller opened (`&`) — one adapter,
/// so the two doors cannot adapt a verify-only module differently.
struct VerifyOnlyAuth<M>(M);
impl<'a, M: std::ops::Deref<Target = dyn crate::auth::AuthModule + 'a> + Send + Sync>
    crate::auth::AuthModule for VerifyOnlyAuth<M>
{
    fn name(&self) -> &'static str {
        self.0.name()
    }
    fn authenticate(&self, candidate: Option<&str>) -> crate::auth::AuthVerdict {
        self.0.authenticate(candidate)
    }
    fn cacheable(&self) -> bool {
        self.0.cacheable()
    }
}
impl<'a, M: std::ops::Deref<Target = dyn crate::auth::AuthModule + 'a> + Send + Sync>
    crate::auth::LoginModule for VerifyOnlyAuth<M>
{
}

/// Wrap a verify-only auth module into the unified [`AuthHandle`]. Used by the `export_auth_plugin!`
/// expansion; also the boundary for future login-capable plugins (which would box directly).
pub fn adapt_auth_handle(module: Box<dyn crate::auth::AuthModule>) -> AuthHandle {
    Box::new(VerifyOnlyAuth(module))
}

/// The auth PAYLOAD schema version this SDK builds against (the manifest `abi_version` a `kind: auth`
/// plugin declares). NOT the transport version — see [`transport_version`]. Mirrors
/// `secret_abi_version()`/`hook_abi_version()` below: reads the shared const rather than a bare
/// literal, so `plugin-loader::registry`'s floor and this SDK's declared version cannot drift apart.
/// See `docs/plugins.md`'s `abi_version` manifest field for the engine-side boot-time check.
pub fn auth_abi_version() -> u32 {
    crate::abi::cold::AUTH_ABI_VERSION
}

/// Run one [`crate::abi::cold::auth::AuthRequest`] against an `AuthModule` — the single match that
/// maps the wire enum to the trait, unit-testable without FFI. An empty `credential` (no usable
/// credential presented) is passed to `authenticate(None)`.
pub fn dispatch_auth(
    module: &dyn crate::auth::AuthPlugin,
    req: crate::abi::cold::auth::AuthRequest,
) -> crate::abi::cold::auth::AuthResponse {
    use crate::abi::cold::auth::{AuthRequest, AuthResponse};
    match req {
        AuthRequest::Name => AuthResponse::Name(module.name().to_string()),
        AuthRequest::Cacheable => AuthResponse::Cacheable(module.cacheable()),
        // ABI v2: the pure redirect-vs-credential classification, resolved once at load.
        AuthRequest::LoginKind => AuthResponse::LoginKind(module.login_kind().into()),
        AuthRequest::Authenticate { credential } => {
            let candidate = if credential.is_empty() {
                None
            } else {
                Some(credential.as_str())
            };
            AuthResponse::from_outcome(module.authenticate(candidate))
        }
        // ABI v2 login primitives: convert the wire request to the engine shape, run the module's
        // LoginModule (fail-closed default for verify-only modules), map the verdict back to the wire.
        AuthRequest::BeginLogin(begin) => {
            AuthResponse::from_login_outcome(module.begin_login(&begin.into()))
        }
        AuthRequest::CompleteLogin(complete) => {
            AuthResponse::from_login_outcome(module.complete_login(&complete.into()))
        }
    }
}

/// Run one auth request and wrap the answer in the observability envelope (DECISIONS #85) — what
/// actually goes on the wire. The auth twin of [`dispatch_export_enveloped`] (#2's auth witness,
/// step (1)).
///
/// An auth module's verify and login faces report nothing on the back-channel, so the envelope is
/// BARE (`{"result": …}`): what makes it load-bearing is not what it carries today but that the
/// dropped-in door (`busbar_call`, via [`auth_dispatch`]) and the compiled-in door (the
/// `dispatch_compiled_in` twin `export_auth_plugin!` emits) run THIS function and nothing else, so the
/// two builds of one crate are byte-identical on the wire and a compiled-in build has no
/// back-channel of its own to reach. Shipped at auth payload schema v3 ([`auth_abi_version`]); the
/// loader keeps the v1 floor and reads a bare (pre-envelope) answer exactly as before.
pub fn dispatch_auth_enveloped(
    module: &dyn crate::auth::AuthPlugin,
    req: crate::abi::cold::auth::AuthRequest,
) -> Envelope<crate::abi::cold::auth::AuthResponse> {
    Envelope::bare(dispatch_auth(module, req))
}

/// [`dispatch_auth_enveloped`] over a VERIFY-ONLY module, adapted exactly as the dropped-in door
/// adapts it ([`adapt_auth_handle`]): login requests take the fail-closed default. What the twin
/// `export_auth_plugin!` emits runs, so the compiled-in door cannot adapt the module differently.
#[doc(hidden)]
pub fn dispatch_verify_only_enveloped(
    module: &dyn crate::auth::AuthModule,
    req: crate::abi::cold::auth::AuthRequest,
) -> Envelope<crate::abi::cold::auth::AuthResponse> {
    dispatch_auth_enveloped(&VerifyOnlyAuth(module), req)
}

/// The per-kind `dispatch` closure `export_auth_plugin!` hands to [`boundary::call_boundary`]: decode an
/// [`crate::abi::cold::auth::AuthRequest`], run it via [`dispatch_auth_enveloped`], and encode the
/// enveloped [`crate::abi::cold::auth::AuthResponse`] into a [`BoundaryOutcome`]. An
/// `authenticate` verdict (`Reject`/`Pass`) rides the OK payload — only an undecodable request /
/// encode failure is non-OK.
///
/// # Safety
/// `handle` is a live auth handle from `open` (guaranteed non-null by the boundary wrapper).
pub unsafe fn auth_dispatch(handle: *mut c_void, bytes: &[u8]) -> BoundaryOutcome {
    let module: &BoxedAuth = &*(handle as *const BoxedAuth);
    let request: crate::abi::cold::auth::AuthRequest = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => return BoundaryOutcome::Unsupported(format!("malformed request JSON: {e}")),
    };
    let resp = dispatch_auth_enveloped(module.as_ref(), request);
    match serde_json::to_vec(&resp) {
        Ok(payload) => BoundaryOutcome::Ok(payload),
        Err(e) => BoundaryOutcome::Error(format!("response encode failed: {e}")),
    }
}

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

/// Emit an `auth`-kind cdylib plugin from `$ctor` (a
/// `fn(&str) -> Result<Box<dyn crate::auth::AuthModule>, String>`). Expands through
/// [`export_plugin!`], stamping `busbar_plugin_kind() == "auth"` + the six neutral symbols.
#[macro_export]
macro_rules! export_auth_plugin {
    ($ctor:path) => {
        /// Adapt the verify-only ctor into the unified `Box<dyn AuthPlugin>` handle (fail-closed
        /// login default). Keeps `$ctor`'s `-> Result<Box<dyn AuthModule>, String>` signature valid
        /// under the ABI-v2 handle change.
        #[doc(hidden)]
        fn __busbar_auth_open_adapted(
            cfg: &str,
        ) -> ::core::result::Result<$crate::abi::sdk::AuthHandle, ::std::string::String> {
            ::core::result::Result::Ok($crate::abi::sdk::adapt_auth_handle($ctor(cfg)?))
        }
        $crate::export_plugin!(
            kind = "auth",
            dispatch = $crate::abi::sdk::auth_dispatch,
            ctor = __busbar_auth_open_adapted,
            handle = $crate::abi::sdk::AuthHandle,
        );
        /// THE COMPILED-IN ENTRY POINT — the twin of the `busbar_call` symbol above (#2's auth
        /// witness, step (2)). A compiled-in build reaches the module `$ctor` opened through the SAME
        /// op-dispatch and the SAME envelope the C symbol runs — `dispatch_auth_enveloped`, over the
        /// same verify-only adapter — never through a shortcut into the module, so the two builds of
        /// this crate are one plugin over one contract.
        pub fn dispatch_compiled_in(
            module: &dyn $crate::abi::sdk::AuthModule,
            req: $crate::abi::sdk::AuthRequest,
        ) -> $crate::abi::sdk::Envelope<$crate::abi::sdk::AuthResponse> {
            $crate::abi::sdk::dispatch_verify_only_enveloped(module, req)
        }
    };
}

/// Emit an `auth`-kind cdylib plugin from `$ctor` (a
/// `fn(&str) -> Result<Box<dyn crate::auth::AuthPlugin>, String>`) — a LOGIN-CAPABLE module that
/// implements BOTH [`crate::auth::AuthModule`] (verify) AND [`crate::auth::LoginModule`]
/// (BeginLogin/CompleteLogin).
///
/// This is the sibling of [`export_auth_plugin!`] for a plugin that also drives the hosted browser
/// login flow (e.g. `auth-oidc`). The crucial difference: `export_auth_plugin!` routes its ctor
/// through the verify-only `VerifyOnlyAuth` adapter, which takes [`crate::auth::LoginModule`]'s
/// fail-closed default — so a login-capable plugin exported through it would have its login
/// capability MASKED (every BeginLogin/CompleteLogin would return `Reject`). `export_login_plugin!`
/// boxes the ctor's `Box<dyn AuthPlugin>` DIRECTLY (no adapter), so [`auth_dispatch`] sees the real
/// [`crate::auth::LoginModule`] impl and the login arms work.
///
/// Both macros stamp `busbar_plugin_kind() == "auth"` and the same six neutral symbols, so the
/// plugin loader treats a login plugin exactly like any other auth plugin (its `abi_version >= 2`
/// is what the engine's capability gate reads to decide it can serve the browser flow).
#[macro_export]
macro_rules! export_login_plugin {
    ($ctor:path) => {
        /// The ctor already yields a login-capable `Box<dyn AuthPlugin>`, so it is exported DIRECTLY
        /// — NOT through the verify-only adapter, which would mask the login capability.
        #[doc(hidden)]
        fn __busbar_login_open(
            cfg: &str,
        ) -> ::core::result::Result<$crate::abi::sdk::AuthHandle, ::std::string::String> {
            $ctor(cfg)
        }
        $crate::export_plugin!(
            kind = "auth",
            dispatch = $crate::abi::sdk::auth_dispatch,
            ctor = __busbar_login_open,
            handle = $crate::abi::sdk::AuthHandle,
        );
        /// THE COMPILED-IN ENTRY POINT — the twin of the `busbar_call` symbol above, as
        /// `export_auth_plugin!` emits it: the same `dispatch_auth_enveloped` the C symbol runs.
        pub fn dispatch_compiled_in(
            module: &dyn $crate::abi::sdk::AuthPlugin,
            req: $crate::abi::sdk::AuthRequest,
        ) -> $crate::abi::sdk::Envelope<$crate::abi::sdk::AuthResponse> {
            $crate::abi::sdk::dispatch_auth_enveloped(module, req)
        }
    };
}

// ── SECRET-plugin glue (`kind: secret`) ─────────────────────────────────────────────────────────
// Mirrors the store glue one-to-one: same six-symbol shape via `export_plugin!`, same
// panic-catching impl style, its own handle type (`Box<dyn SecretModule>`) and its own tiny
// request enum.

/// The secret handle behind the opaque `*mut c_void`: a boxed [`crate::secret::SecretModule`]. Named at
/// the module level so the `export_plugin!` expansion can pass it to `close_boundary::<$ty>`.
pub type SecretHandle = Box<dyn crate::secret::SecretModule>;

/// The secret handle behind the opaque `*mut c_void`: a boxed [`crate::secret::SecretModule`].
type BoxedSecret = SecretHandle;

/// Return the SECRET ABI version this SDK builds against (`busbar_secret_abi_version`). See
/// `docs/plugins.md`'s `abi_version` manifest field for the engine-side boot-time check against it.
pub fn secret_abi_version() -> u32 {
    crate::abi::cold::SECRET_ABI_VERSION
}

/// Run one [`crate::abi::cold::SecretRequest`] against a secret module - the single match that
/// maps the wire enum to the trait, unit-testable without FFI.
pub fn dispatch_secret(
    module: &dyn crate::secret::SecretModule,
    req: crate::abi::cold::SecretRequest,
) -> Result<crate::abi::cold::SecretResponse, crate::secret::SecretModuleError> {
    match req {
        // `deadline_ms` is advisory — nothing at THIS layer enforces it — but it is handed to the
        // module, which is the only party that could act on it. The old comment described a seam
        // where the module "reads it from the request before this dispatch runs": there is no such
        // seam. `secret_dispatch` decodes the request and calls straight into here, so this match
        // was the field's first and last stop, and dropping it meant a module that CAN bound its own
        // upstream call was never told what bound to apply.
        crate::abi::cold::SecretRequest::Resolve {
            settings,
            deadline_ms,
        } => Ok(crate::abi::cold::SecretResponse::Bytes(
            module.resolve_with_deadline(&settings, deadline_ms)?,
        )),
    }
}

/// The per-kind `dispatch` closure `export_secret_plugin!` hands to [`boundary::call_boundary`]: decode
/// a [`crate::abi::cold::SecretRequest`], run it via [`dispatch_secret`], and encode the response into
/// a [`BoundaryOutcome`]. A resolve failure is a defined backend error → [`BoundaryOutcome::Error`]
/// (the message must never carry secret material).
///
/// # Safety
/// `handle` is a live secret handle from `open` (guaranteed non-null by the boundary wrapper).
pub unsafe fn secret_dispatch(handle: *mut c_void, bytes: &[u8]) -> BoundaryOutcome {
    let module: &BoxedSecret = &*(handle as *const BoxedSecret);
    let request: crate::abi::cold::SecretRequest = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => return BoundaryOutcome::Unsupported(format!("malformed request JSON: {e}")),
    };
    match dispatch_secret(module.as_ref(), request) {
        Ok(resp) => match serde_json::to_vec(&resp) {
            Ok(payload) => BoundaryOutcome::Ok(payload),
            Err(e) => BoundaryOutcome::Error(format!("response encode failed: {e}")),
        },
        // A module-level failure: encode it as a TYPED SecretResponse::Error and return
        // it via BoundaryOutcome::Ok (STATUS_OK on the wire), not the untyped STATUS_ERR string
        // channel — this is what lets a host distinguish "no such secret" from "backend
        // unreachable". If encoding that itself fails (should be unreachable — the payload is two
        // primitives), fall back to the untyped channel rather than losing the failure entirely.
        Err(e) => {
            let typed = crate::abi::cold::SecretResponse::Error {
                kind: e.kind,
                message: e.message.clone(),
            };
            match serde_json::to_vec(&typed) {
                Ok(payload) => BoundaryOutcome::Ok(payload),
                Err(enc_err) => BoundaryOutcome::Error(format!(
                    "{} (also failed to encode: {enc_err})",
                    e.message
                )),
            }
        }
    }
}

// ── HOOK-plugin glue (`kind: hook`) ───────────────────────────────────────────────────────────────
// A hook plugin is a routing policy behind the frozen six-symbol ABI. Its author implements the tiny
// SYNC [`HookHandler`] trait (the six ops over JSON), NOT the engine's async `RoutingPolicy` — the
// async/borrowed trait lives on the ENGINE side (`DlopenPolicy`), which translates each method into a
// `busbar_call`. The op-dispatch match ([`dispatch_hook`]) is the ergonomic helper the spec asks for:
// a hook author writes `decide`/`transform`/etc. and the SDK routes the op envelope to them.

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

/// The hook handle behind the opaque `*mut c_void`: a boxed [`HookHandler`]. Named at the module level
/// so the `export_plugin!` expansion can pass it to `close_boundary::<$ty>`.
pub type HookHandle = Box<dyn HookHandler>;

/// Re-export the hook wire so a hook author (and the `dispatch_compiled_in` twin
/// `export_hook_plugin!` emits) names `busbar_contract::abi::sdk::HookRequest` / `HookReply` without a direct
/// `busbar-plugin` dependency, mirroring the auth/export re-export path.
pub use crate::abi::cold::hook::{HookReply, HookRequest};

/// The hook handle behind the opaque `*mut c_void`: a boxed [`HookHandler`].
type BoxedHook = HookHandle;

/// Return the HOOK PAYLOAD schema version this SDK builds against (`busbar_plugin_kind() == "hook"`).
/// See `docs/plugins.md`'s `abi_version` manifest field for the engine-side boot-time check against it.
pub fn hook_abi_version() -> u32 {
    crate::abi::cold::hook::HOOK_ABI_VERSION
}

/// Run one [`crate::abi::cold::hook::HookRequest`] against a [`HookHandler`] — the single op-dispatch
/// match that maps the wire envelope to the trait, unit-testable without FFI. This is the ergonomic
/// helper a hook author never has to write.
pub fn dispatch_hook(
    handler: &dyn HookHandler,
    req: crate::abi::cold::hook::HookRequest,
) -> crate::abi::cold::hook::HookReply {
    use crate::abi::cold::hook::{HookReply, HookRequest};
    match req {
        HookRequest::Decide { payload } => match handler.decide_result(&payload) {
            Ok(v) => HookReply::Reply(v),
            Err(message) => HookReply::Failed { message },
        },
        HookRequest::Transform { payload } => match handler.transform_result(&payload) {
            Ok(v) => HookReply::Reply(v),
            Err(message) => HookReply::Failed { message },
        },
        HookRequest::Notify { payload } => {
            handler.notify(&payload);
            HookReply::None
        }
        HookRequest::Configure(body) => {
            if handler.configure(&body.settings, body.settings_version) {
                HookReply::ConfigureAck {
                    settings_version: body.settings_version,
                }
            } else {
                // A non-ack is signaled by echoing a version that CANNOT match the pushed one, so the
                // engine's exact-version ack rule rejects the configure (commit does not proceed).
                HookReply::ConfigureAck {
                    settings_version: body.settings_version.wrapping_add(1),
                }
            }
        }
        HookRequest::Describe => HookReply::Reply(handler.describe()),
        HookRequest::Status => HookReply::Reply(handler.status()),
        HookRequest::Routes => HookReply::Routes(handler.routes()),
        HookRequest::Endpoint { request } => HookReply::Endpoint(handler.handle_http(&request)),
    }
}

/// Run one hook request and wrap the reply in the observability envelope (DECISIONS #85) — what
/// actually goes on the wire; the hook twin of [`dispatch_export_enveloped`].
///
/// A hook reports its metrics in its `status` reply (the shape #85's envelope was modelled on), so the
/// envelope is BARE and the reply inside it is exactly [`dispatch_hook`]'s — the hook kind is a 1.6.0
/// FUNCTIONAL fixed point, and this moves its wire, never its behaviour. The dropped-in door
/// (`busbar_call`, via [`hook_dispatch`]) and the compiled-in door (the `dispatch_compiled_in` twin
/// `export_hook_plugin!` emits) both run this, so the two builds are byte-identical on the wire.
/// Shipped at hook payload schema v2 ([`hook_abi_version`]); the loader keeps the v1 floor and reads a
/// bare (pre-envelope) reply exactly as before.
pub fn dispatch_hook_enveloped(
    handler: &dyn HookHandler,
    req: crate::abi::cold::hook::HookRequest,
) -> Envelope<crate::abi::cold::hook::HookReply> {
    Envelope::bare(dispatch_hook(handler, req))
}

/// The per-kind `dispatch` closure `export_hook_plugin!` hands to [`boundary::call_boundary`]: decode a
/// [`crate::abi::cold::hook::HookRequest`], run it via [`dispatch_hook_enveloped`], and encode the
/// enveloped reply into a [`BoundaryOutcome`].
///
/// # Safety
/// `handle` is a live hook handle from `open` (guaranteed non-null by the boundary wrapper).
pub unsafe fn hook_dispatch(handle: *mut c_void, bytes: &[u8]) -> BoundaryOutcome {
    let handler: &BoxedHook = &*(handle as *const BoxedHook);
    let request: crate::abi::cold::hook::HookRequest = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => return BoundaryOutcome::Unsupported(format!("malformed request JSON: {e}")),
    };
    let resp = dispatch_hook_enveloped(handler.as_ref(), request);
    match serde_json::to_vec(&resp) {
        Ok(payload) => BoundaryOutcome::Ok(payload),
        Err(e) => BoundaryOutcome::Error(format!("response encode failed: {e}")),
    }
}

// ── EXPORT-plugin glue (`kind: export`) ────────────────────────────────────────────────────────────
// An export plugin is a telemetry SINK behind the frozen six-symbol ABI. Its author implements the tiny
// SYNC [`ExportHandler`] trait (`streams`/`deliver` over JSON); the op-dispatch match
// ([`dispatch_export`]) routes the [`ExportRequest`] envelope to it. Mirrors the hook glue one-to-one:
// same `export_plugin!` shape, its own handle type (`Box<dyn ExportHandler>`), its own request enum.

/// Re-export the export wire types so a plugin author names `busbar_contract::abi::sdk::ExportStream` (etc.)
/// without a direct `busbar-plugin` dependency, mirroring the hook/auth re-export path.
pub use crate::abi::cold::export::{
    ExportRequest, ExportResponse, HostOp, HostResult, HttpRequest, HttpResponse, MetricFamily,
    MetricSample, Rotation, RotationFault,
};
pub use crate::abi::export::{CheckPhase, ExportField, ExportStream};

/// What a sink answers a delivery (or a resume) with when it has the host act for it (export ABI
/// minor 4): finished, or these [`HostOp`]s first — the host performs them and calls
/// [`ExportHandler::resume`] with their results under the same `token`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostStep {
    /// Nothing (more) for the host to do: the delivery is done.
    Done,
    /// Perform these, in order, then resume me with `token`.
    Host {
        /// The sink's correlation token, echoed on the resume.
        token: u64,
        /// The acts.
        ops: Vec<HostOp>,
    },
    /// Answering [`ExportHandler::start`] (export ABI minor 8): started — whether this sink takes
    /// deliveries this run, and its in-flight admission (`0` / empty: the host's defaults).
    Started {
        /// `false`: take nothing this run.
        live: bool,
        /// Deliveries it may have in flight at once.
        inflight: u64,
        /// The name its admission gate is counted under.
        gate: String,
    },
}

/// Re-export the observability envelope (#85) so a plugin author names
/// `busbar_contract::abi::sdk::PluginMetric` (etc.) without a direct `busbar-plugin` dependency, mirroring
/// every other wire type this SDK re-exports.
///
/// These are what a plugin uses to REPORT. Nothing here makes anything happen: the host validates
/// what arrives, bounds it, and decides. A plugin that wants a counter incremented says so and the
/// host increments it — which is also why a dropped-in build and a compiled-in build of the same
/// crate produce the same exposition (#11) instead of one of them reaching a recorder the other
/// cannot see.
pub use crate::abi::cold::observe::{
    DiagLevel, Envelope, Observations, PluginDiagnostic, PluginMetric,
};

/// Re-export the endpoint wire types (plugin route registration + dispatch) so an export/hook
/// author names `busbar_contract::abi::sdk::Route` / `EndpointRequest` (etc.) without a direct
/// `busbar-plugin` dependency.
pub use crate::abi::cold::endpoint::{EndpointRequest, EndpointResponse};
pub use crate::abi::mechanism::route::{Route, RouteAuth, RouteMethod};

/// The sync contract a `kind: export` plugin author implements. [`streams`](ExportHandler::streams)
/// declares which observability streams THIS instance carries (asked once at load); `deliver` hands
/// one already-serialized batch for a declared stream to the sink and has a DEFAULT no-op, so a trivial
/// sink implements only `streams`.
pub trait ExportHandler: Send + Sync {
    /// The [`ExportStream`]s this instance carries. Asked once at load; the engine only routes
    /// deliveries for streams named here.
    fn streams(&self) -> Vec<ExportStream>;
    /// Accept one batch for `stream`. `payload` is the engine-built batch as an opaque JSON value.
    /// Default: no-op (a sink that reports streams but drops batches).
    fn deliver(&self, _stream: ExportStream, _payload: &serde_json::Value) {}
    /// The HTTP [`Route`]s this instance serves — its OWN compiled-in declarations, collected once at
    /// load (a metrics sink declares `GET /metrics`). Default: none (a push-only sink has no HTTP
    /// surface). The engine collision-checks + namespace-confines these before mounting.
    fn routes(&self) -> Vec<Route> {
        Vec::new()
    }
    /// Serve one inbound HTTP request matched to a declared route. Fires only for a matched route (the
    /// engine already enforced the route's auth). Default: `404` — the fallback for a sink that
    /// declared no routes / a partial impl.
    fn handle_http(&self, _req: &EndpointRequest) -> EndpointResponse {
        EndpointResponse {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// TAKE what this sink observed since the last call — the author side of the observability
    /// envelope (DECISIONS #85).
    ///
    /// A sink that rotates a file, sheds a line, or fails to open a path has produced an
    /// operator-visible FACT, and before the envelope there was nowhere on the wire to put it:
    /// `ExportResponse::Delivered` is a unit variant and the cold tier has no host-callback vtable.
    /// The only way a compiled-in sink could keep its counters was to reach the process-global
    /// recorder directly — which the same crate built as a dropped-in `cdylib` cannot do, because it
    /// links its own. That is the live #11 hole this closes.
    ///
    /// **DRAINING, not reading.** The name is the contract: the SDK calls this ONCE per `busbar_call`
    /// and puts whatever it returns on that call's envelope, so an implementation must hand over its
    /// accumulated observations and reset. Returning the same samples twice reports them twice; a
    /// counter the host folds is a DELTA, not a running total.
    ///
    /// Default: nothing to report. That is what makes the envelope additive for every sink that
    /// already exists — a handler written before #85 compiles unchanged and answers bare envelopes.
    fn drain_observations(&self) -> Observations {
        Observations::none()
    }

    /// Validate the `settings` the operator wrote for the `instance` named, while the host
    /// validates its configuration (export ABI minor 2): every problem as one complete
    /// operator-facing line (the host reports each verbatim), or none. Default: none — a sink with
    /// nothing to check accepts what it is given, as every sink did before the op.
    fn validate(&self, _instance: &str, _settings: &serde_json::Value) -> Vec<String> {
        Vec::new()
    }

    /// Accept one batch, with the host acting for the sink where it needs to (export ABI minor 4):
    /// answer [`HostStep::Host`] to have the host perform [`HostOp`]s — append to a declared
    /// destination, rotate it, flush it, carry an HTTP request (minor 5) — and receive their results on [`resume`](Self::resume).
    /// Default: [`deliver`](Self::deliver), then done — every sink written before the op.
    fn deliver_via_host(&self, stream: ExportStream, payload: &serde_json::Value) -> HostStep {
        self.deliver(stream, payload);
        HostStep::Done
    }

    /// Render the host recorder's snapshot (export ABI minor 6) into the exposition the host
    /// serves: `(content_type, body)`. Default: the Prometheus text content type with an empty
    /// body. A metrics-serving sink overrides `render` (the prometheus sink does) and renders the
    /// snapshot itself.
    fn render(&self, _families: &[MetricFamily]) -> (String, String) {
        ("text/plain; version=0.0.4".to_string(), String::new())
    }

    /// The results of the [`HostOp`]s a [`HostStep::Host`] asked for, in order, under its `token`.
    /// Answer [`HostStep::Done`], or more ops. Default: done.
    fn resume(&self, _token: u64, _results: Vec<HostResult>) -> HostStep {
        HostStep::Done
    }

    /// The host starts feeding this sink (export ABI minor 8): answer [`HostStep::Started`], or
    /// [`HostStep::Host`] first (the results come back on [`resume`](Self::resume), which then
    /// answers `Started`). Default: live, at the host's default admission.
    fn start(&self) -> HostStep {
        HostStep::Started {
            live: true,
            inflight: 0,
            gate: String::new(),
        }
    }

    /// The checks across every instance of this sink's module, `(name, settings)` in configuration
    /// order, run while the host validates its configuration — at `phase`: among its operational
    /// limits' checks, or after them (export ABI minors 8, 9): every problem as one complete line,
    /// reported verbatim. Default: none.
    fn check(&self, _phase: CheckPhase, _instances: &[(String, serde_json::Value)]) -> Vec<String> {
        Vec::new()
    }
}

/// A [`HostStep`] as the wire answers it.
fn host_step(step: HostStep) -> ExportResponse {
    match step {
        HostStep::Done => ExportResponse::Delivered,
        HostStep::Host { token, ops } => ExportResponse::Host { token, ops },
        HostStep::Started {
            live,
            inflight,
            gate,
        } => ExportResponse::Started {
            live,
            inflight,
            gate,
        },
    }
}

/// The export handle behind the opaque `*mut c_void`: a boxed [`ExportHandler`]. Named at the module
/// level so the `export_plugin!` expansion can pass it to `close_boundary::<$ty>`.
pub type ExportHandle = Box<dyn ExportHandler>;

/// The export handle behind the opaque `*mut c_void`: a boxed [`ExportHandler`].
type BoxedExport = ExportHandle;

/// Return the EXPORT PAYLOAD schema version this SDK builds against (`busbar_plugin_kind() ==
/// "export"`). Reads the shared const rather than a bare literal, so `plugin-loader::registry`'s floor
/// and this SDK's declared version cannot drift apart — mirroring `secret_abi_version()`/
/// `hook_abi_version()`.
pub fn export_abi_version() -> u32 {
    crate::abi::cold::export::EXPORT_ABI_VERSION
}

/// Run one [`ExportRequest`] against an [`ExportHandler`] — the single op-dispatch match that maps the
/// wire envelope to the trait, unit-testable without FFI. `Streams` returns the handler's declared
/// streams; `Deliver` runs the handler's sink and acks with [`ExportResponse::Delivered`].
pub fn dispatch_export(handler: &dyn ExportHandler, req: ExportRequest) -> ExportResponse {
    match req {
        ExportRequest::Streams => ExportResponse::Streams(handler.streams()),
        ExportRequest::Deliver { stream, payload } => {
            host_step(handler.deliver_via_host(stream, &payload))
        }
        ExportRequest::Resume { token, results } => host_step(handler.resume(token, results)),
        ExportRequest::Scrape { families } => {
            let (content_type, body) = handler.render(&families);
            ExportResponse::Exposition { content_type, body }
        }
        ExportRequest::Routes => ExportResponse::Routes(handler.routes()),
        ExportRequest::Endpoint { request } => {
            ExportResponse::Endpoint(handler.handle_http(&request))
        }
        // `status` is the host asking, at the moment it renders its own exposition, what this sink
        // has to report. The answer is exactly what a delivery's envelope would have carried — the
        // handler's DRAIN, moved into the result — so the host folds it down the one envelope path
        // and a sink needs no second method to take part. The trailing drain in
        // `dispatch_export_enveloped` then finds nothing left, so nothing is reported twice.
        ExportRequest::Status => {
            let drained = handler.drain_observations().into_envelope(());
            ExportResponse::Status {
                metrics: drained.metrics,
                diagnostics: drained.diagnostics,
            }
        }
        ExportRequest::Validate { instance, settings } => {
            ExportResponse::Validated(handler.validate(&instance, &settings))
        }
        ExportRequest::Start => host_step(handler.start()),
        ExportRequest::Check { instances, phase } => {
            ExportResponse::Validated(handler.check(phase, &instances))
        }
    }
}

/// Run one [`ExportRequest`] and wrap the answer in the observability envelope (#85) — what actually
/// goes on the wire.
///
/// Split from [`dispatch_export`] so the op-dispatch match and the envelope fold are separately
/// testable, and so a caller that only wants the kind-specific answer (every existing test) keeps
/// the type it had.
///
/// **ORDER IS LOAD-BEARING.** The handler runs FIRST and is drained AFTER, so observations the call
/// itself produced ride the SAME response. Draining first would report the previous call's samples
/// on this call's envelope and lose this call's entirely on the last call before shutdown.
pub fn dispatch_export_enveloped(
    handler: &dyn ExportHandler,
    req: ExportRequest,
) -> Envelope<ExportResponse> {
    let result = dispatch_export(handler, req);
    handler.drain_observations().into_envelope(result)
}

/// The per-kind `dispatch` closure `export_export_plugin!` hands to [`boundary::call_boundary`]: decode
/// an [`ExportRequest`], run it via [`dispatch_export`], and encode the [`ExportResponse`] into a
/// [`BoundaryOutcome`]. An undecodable request is the only [`BoundaryOutcome::Unsupported`] case; a
/// response-encode failure is a real fault → [`BoundaryOutcome::Error`].
///
/// # Safety
/// `handle` is a live export handle from `open` (guaranteed non-null by the boundary wrapper).
pub unsafe fn export_dispatch(handle: *mut c_void, bytes: &[u8]) -> BoundaryOutcome {
    let handler: &BoxedExport = &*(handle as *const BoxedExport);
    let request: ExportRequest = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => return BoundaryOutcome::Unsupported(format!("malformed request JSON: {e}")),
    };
    let resp = dispatch_export_enveloped(handler.as_ref(), request);
    match serde_json::to_vec(&resp) {
        Ok(payload) => BoundaryOutcome::Ok(payload),
        Err(e) => BoundaryOutcome::Error(format!("response encode failed: {e}")),
    }
}

/// Emit an `export`-kind cdylib plugin from `$ctor` (a
/// `fn(&str) -> Result<Box<dyn busbar_contract::abi::sdk::ExportHandler>, String>`). Expands through
/// [`export_plugin!`], stamping `busbar_plugin_kind() == "export"` + the six neutral symbols.
#[macro_export]
macro_rules! export_export_plugin {
    ($ctor:path) => {
        $crate::export_plugin!(
            kind = "export",
            dispatch = $crate::abi::sdk::export_dispatch,
            ctor = $ctor,
            handle = $crate::abi::sdk::ExportHandle,
        );
    };
}

/// Emit a `hook`-kind cdylib plugin from `$ctor` (a
/// `fn(&str) -> Result<Box<dyn busbar_contract::abi::sdk::HookHandler>, String>`). Expands through
/// [`export_plugin!`], stamping `busbar_plugin_kind() == "hook"` + the six neutral symbols.
#[macro_export]
macro_rules! export_hook_plugin {
    ($ctor:path) => {
        $crate::export_plugin!(
            kind = "hook",
            dispatch = $crate::abi::sdk::hook_dispatch,
            ctor = $ctor,
            handle = $crate::abi::sdk::HookHandle,
        );
        /// THE COMPILED-IN ENTRY POINT — the twin of the `busbar_call` symbol above: the handler
        /// `$ctor` opened, reached through the SAME op-dispatch and envelope the C symbol runs
        /// (`dispatch_hook_enveloped`), never through a shortcut into the handler.
        pub fn dispatch_compiled_in(
            handler: &dyn $crate::abi::sdk::HookHandler,
            req: $crate::abi::sdk::HookRequest,
        ) -> $crate::abi::sdk::Envelope<$crate::abi::sdk::HookReply> {
            $crate::abi::sdk::dispatch_hook_enveloped(handler, req)
        }
    };
}

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
        /// A cold-lane kind (store/secret/auth/hook/export): the same entry its linked door hands
        /// the loader, and the dropped-in door's sink install (`export_plugin!` generates it: the
        /// sink plus this image's `tracing` forwarder).
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

    /// `busbar_abi` — the frozen TRANSPORT handshake, shared by every kind.
    #[no_mangle]
    pub extern "C-unwind" fn busbar_abi() -> u32 {
        crate::abi::sdk::transport_version()
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
            $crate::abi::sdk::transport_version()
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

/// Emit a `secret`-kind cdylib plugin from `$ctor` (a
/// `fn(&str) -> Result<Box<dyn crate::secret::SecretModule>, String>`). Expands through
/// [`export_plugin!`], stamping `busbar_plugin_kind() == "secret"` + the six neutral symbols.
#[macro_export]
macro_rules! export_secret_plugin {
    ($ctor:path) => {
        $crate::export_plugin!(
            kind = "secret",
            dispatch = $crate::abi::sdk::secret_dispatch,
            ctor = $ctor,
            handle = $crate::abi::sdk::SecretHandle,
        );
    };
}

/// Emit a `store`-kind cdylib plugin from `$ctor` (a `fn(&str) -> Result<Box<dyn Store>, String>`).
/// Expands through [`export_plugin!`], stamping `busbar_plugin_kind() == "store"` + the six neutral
/// symbols.
#[macro_export]
macro_rules! export_store_plugin {
    ($ctor:path) => {
        $crate::export_plugin!(
            kind = "store",
            dispatch = $crate::abi::sdk::store_dispatch,
            ctor = $ctor,
            handle = $crate::abi::sdk::StoreHandle,
        );
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
