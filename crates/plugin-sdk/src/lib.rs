// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SDK for writing a busbar **store plugin** in Rust.
//!
//! Writing a plugin is: implement [`busbar_api::Store`] for your backend, write a constructor
//! `fn(&str) -> Result<Box<dyn Store>, String>` (the `&str` is the JSON config the operator set),
//! call [`export_store_plugin!`] with it, and build the crate as a `cdylib`. The macro emits the
//! six `extern "C-unwind"` symbols the engine's loader resolves (`busbar_abi`, `busbar_plugin_kind`,
//! `busbar_open`, `busbar_call`, `busbar_free`, `busbar_close`); every one routes through the single
//! export-boundary choke point in [`boundary`] (null-out-guard-before-alloc, mandatory `catch_unwind`,
//! and a total status map), so no per-symbol code can get an FFI-boundary invariant wrong. The author
//! supplies only a ctor + a per-kind [`dispatch`] returning a [`BoundaryOutcome`].
//!
//! ```ignore
//! use busbar_plugin_sdk::export_store_plugin;
//! fn open(cfg: &str) -> Result<Box<dyn busbar_api::Store>, String> {
//!     Ok(Box::new(MyStore::new(cfg)?))
//! }
//! export_store_plugin!(open);
//! ```
//!
//! The same crate is usable **statically**: depend on it as a normal `lib` and construct
//! `MyStore` directly — the C ABI is only the *dynamic* delivery path. That is how a build can bake
//! a plugin in (e.g. Postgres compiled straight into a custom binary) without any `cfg` sprawl.

use busbar_api::{Store, StoreError};
use busbar_plugin_abi::{StoreRequest, StoreResponse, ABI_VERSION};
use std::os::raw::c_void;

pub mod boundary;
pub use boundary::BoundaryOutcome;

// Convenience alias for out-of-tree store plugins that want to name the trait without also
// depending on `busbar-api` directly. `export_store_plugin!` does NOT use this alias (it expands
// to `store_dispatch`/`StoreHandle`, never `StoreTrait`) — this is frozen SDK surface kept for
// callers outside this repo, not for anything internal to the macro.
pub use busbar_api::Store as StoreTrait;

/// The "decision observability" signal catalog: a plugin author references
/// `busbar_plugin_sdk::Signal::CandidateBreakerState` (etc.) at compile time to declare which
/// catalog entries their hook wants computed + projected — see `busbar_api::Signal`'s doc comment
/// for the full catalog and the append-only/non_exhaustive contract.
pub use busbar_plugin_abi::{Signal, SignalBag, SignalValue};

/// Re-export used ONLY by the `export_plugin!` expansion, so a plugin crate does not need its own
/// direct `busbar-plugin-abi` dependency just to name the log-sink type in the generated symbol.
#[doc(hidden)]
pub mod __abi {
    pub use busbar_plugin_abi::LogSinkFn;
}

/// The handle type behind the opaque `*mut c_void` for a store plugin (a boxed trait object). Named at
/// the module level so the `export_plugin!` expansion can pass it to `close_boundary::<$ty>`.
pub type StoreHandle = Box<dyn Store>;

/// The store handle behind the opaque `*mut c_void` that crosses the ABI: a boxed trait object.
type BoxedStore = StoreHandle;

/// Return the store PAYLOAD schema version this SDK builds against (the manifest `abi_version` a
/// `kind: store` plugin declares). NOT the transport version — see [`transport_version`]. See
/// `docs/plugins.md`'s `abi_version` manifest field for the engine-side boot-time check against it.
pub fn abi_version() -> u32 {
    ABI_VERSION
}

/// The frozen kind-neutral TRANSPORT version this SDK builds against — a plugin exports it as
/// `busbar_abi()`. Frozen at [`busbar_plugin_abi::TRANSPORT_VERSION`] (=1); distinct from the per-kind
/// payload schema version ([`abi_version`] / [`secret_abi_version`]).
pub fn transport_version() -> u32 {
    busbar_plugin_abi::TRANSPORT_VERSION
}

/// Run one [`StoreRequest`] against a `Store`. The single match that maps the wire enum to the trait
/// — shared by the C `call` glue and directly unit-testable without any FFI.
pub fn dispatch(store: &dyn Store, req: StoreRequest) -> Result<StoreResponse, StoreError> {
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
        Q::PutTask(t) => {
            store.put_task(&t)?;
            R::Unit
        }
        Q::GetTask(task_id) => R::Task(store.get_task(&task_id)?),
        Q::ListTasks => R::Tasks(store.list_tasks()?),
        Q::PurgeTasksBefore(before) => R::Purged(store.purge_tasks_before(before)?),
        Q::AppendTaskEvent(e) => {
            store.append_task_event(&e)?;
            R::Unit
        }
        Q::ListTaskEvents(task_id) => R::TaskEvents(store.list_task_events(&task_id)?),
        Q::AppendMcpCall(rec) => {
            store.append_mcp_call(&rec)?;
            R::Unit
        }
        Q::ListMcpCalls(principal) => R::McpCalls(store.list_mcp_calls(&principal)?),
        Q::ListMcpCallPrincipals => R::McpCallPrincipals(store.list_mcp_call_principals()?),
        Q::PurgeMcpCallsBefore(before) => R::Purged(store.purge_mcp_calls_before(before)?),
        Q::PutMcpDemotion(row) => {
            store.put_mcp_demotion(&row)?;
            R::Unit
        }
        Q::ListMcpDemotions => R::McpDemotions(store.list_mcp_demotions()?),
        Q::ClearMcpDemotion(server) => {
            store.clear_mcp_demotion(&server)?;
            R::Unit
        }
        Q::RedeemAskState {
            nonce,
            expires_at,
            now,
        } => R::Redeemed(store.redeem_ask_state(&nonce, expires_at, now)?),

        // ── THE NEUTRAL KIND-TAGGED PLANE-RECORD SURFACE (1.6.0, ADDITIVE) ────────────────────
        //
        // Maps the eight kind-tagged wire variants onto the eight neutral trait methods. Upsert and
        // append reconstitute a [`busbar_api::PlaneRecord`] from the fields this commit's wire
        // carries; the typed sidecar columns the wire does not yet carry (`ts`/`disposition`, and
        // `parent`/`seq` on upsert) default to their neutral values here — relocating the full
        // sidecar onto the wire is the later schema commit. Nothing calls these yet.
        Q::UpsertPlaneRecord { kind, id, body } => {
            store.upsert_plane_record(&busbar_api::PlaneRecord {
                kind,
                id,
                parent: None,
                seq: 0,
                ts: 0,
                disposition: busbar_api::PlaneDisposition::Active,
                body,
            })?;
            R::Unit
        }
        Q::GetPlaneRecord { kind, id } => R::PlaneRecord(store.get_plane_record(&kind, &id)?),
        Q::AppendPlaneRecord {
            kind,
            parent,
            seq,
            body,
        } => {
            store.append_plane_record(&busbar_api::PlaneRecord {
                kind,
                id: String::new(),
                parent: Some(parent),
                seq,
                ts: 0,
                disposition: busbar_api::PlaneDisposition::Active,
                body,
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

/// The auth handle behind the opaque `*mut c_void`: a boxed [`busbar_api::AuthPlugin`] — an auth
/// module that is BOTH a verifier ([`busbar_api::AuthModule`]) and a login provider
/// ([`busbar_api::LoginModule`], fail-closed by default for verify-only modules). Named at the module
/// level so the `export_plugin!` expansion can pass it to `close_boundary::<$ty>`.
pub type AuthHandle = Box<dyn busbar_api::AuthPlugin>;

/// The auth handle behind the opaque `*mut c_void`: a boxed [`busbar_api::AuthPlugin`].
type BoxedAuth = AuthHandle;

/// Fail-closed login adapter: wraps a verify-only [`busbar_api::AuthModule`] as a full
/// [`busbar_api::AuthPlugin`] by delegating the verify methods and taking [`busbar_api::LoginModule`]'s
/// default (Reject) login behavior. This is what lets `export_auth_plugin!` keep accepting a
/// `fn(&str) -> Result<Box<dyn AuthModule>, String>` ctor UNCHANGED while the exported handle is the
/// unified `Box<dyn AuthPlugin>`.
struct VerifyOnlyAuth(Box<dyn busbar_api::AuthModule>);
impl busbar_api::AuthModule for VerifyOnlyAuth {
    fn name(&self) -> &'static str {
        self.0.name()
    }
    fn authenticate(&self, candidate: Option<&str>) -> busbar_api::AuthOutcome {
        self.0.authenticate(candidate)
    }
    fn cacheable(&self) -> bool {
        self.0.cacheable()
    }
}
impl busbar_api::LoginModule for VerifyOnlyAuth {}

/// Wrap a verify-only auth module into the unified [`AuthHandle`]. Used by the `export_auth_plugin!`
/// expansion; also the boundary for future login-capable plugins (which would box directly).
pub fn adapt_auth_handle(module: Box<dyn busbar_api::AuthModule>) -> AuthHandle {
    Box::new(VerifyOnlyAuth(module))
}

/// The auth PAYLOAD schema version this SDK builds against (the manifest `abi_version` a `kind: auth`
/// plugin declares). NOT the transport version — see [`transport_version`]. Mirrors
/// `secret_abi_version()`/`hook_abi_version()` below: reads the shared const rather than a bare
/// literal, so `plugin-loader::registry`'s floor and this SDK's declared version cannot drift apart.
/// See `docs/plugins.md`'s `abi_version` manifest field for the engine-side boot-time check.
pub fn auth_abi_version() -> u32 {
    busbar_plugin_abi::AUTH_ABI_VERSION
}

/// Run one [`busbar_plugin_abi::auth::AuthRequest`] against an `AuthModule` — the single match that
/// maps the wire enum to the trait, unit-testable without FFI. An empty `credential` (no usable
/// credential presented) is passed to `authenticate(None)`.
pub fn dispatch_auth(
    module: &dyn busbar_api::AuthPlugin,
    req: busbar_plugin_abi::auth::AuthRequest,
) -> busbar_plugin_abi::auth::AuthResponse {
    use busbar_plugin_abi::auth::{AuthRequest, AuthResponse};
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

/// The per-kind `dispatch` closure `export_auth_plugin!` hands to [`boundary::call_boundary`]: decode an
/// [`busbar_plugin_abi::auth::AuthRequest`], run it via [`dispatch_auth`], and encode the
/// [`busbar_plugin_abi::auth::AuthResponse`] into a [`BoundaryOutcome`]. An `authenticate` verdict
/// (`Reject`/`Pass`) rides the OK payload — only an undecodable request / encode failure is non-OK.
///
/// # Safety
/// `handle` is a live auth handle from `open` (guaranteed non-null by the boundary wrapper).
pub unsafe fn auth_dispatch(handle: *mut c_void, bytes: &[u8]) -> BoundaryOutcome {
    let module: &BoxedAuth = &*(handle as *const BoxedAuth);
    let request: busbar_plugin_abi::auth::AuthRequest = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => return BoundaryOutcome::Unsupported(format!("malformed request JSON: {e}")),
    };
    let resp = dispatch_auth(module.as_ref(), request);
    match serde_json::to_vec(&resp) {
        Ok(payload) => BoundaryOutcome::Ok(payload),
        Err(e) => BoundaryOutcome::Error(format!("response encode failed: {e}")),
    }
}

/// Emit an `auth`-kind cdylib plugin from `$ctor` (a
/// `fn(&str) -> Result<Box<dyn busbar_api::AuthModule>, String>`). Expands through
/// [`export_plugin!`], stamping `busbar_plugin_kind() == "auth"` + the six neutral symbols.
/// The host log bridge — how a plugin's diagnostics reach the operator.
///
/// A plugin is a cdylib that statically links its OWN `tracing-core`, so its dispatcher is not the
/// host's and nothing joins them: every `tracing::warn!` inside a loaded plugin is discarded. That
/// included auth-oidc's warning on a FAILED TOKEN SIGNATURE VERIFICATION, which is exactly the line
/// an operator needs to see. `eprintln!` reaches the shared stderr but bypasses the host's
/// subscriber, so it gets no level filtering, no structured fields, no OTLP export, and nothing
/// identifying which plugin emitted it.
///
/// The host installs a sink through the optional `busbar_set_log_sink` symbol right after `open`.
/// Until then — and forever, for a host too old to call it — [`hostlog::log`] falls back to `eprintln!`, so a
/// plugin never loses a message by using this.
pub mod hostlog {
    use busbar_plugin_abi::{log_level, LogSinkFn};
    use std::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};

    /// The installed sink, as raw parts. Two atomics rather than a `OnceLock<(fn, ptr)>` because the
    /// host may call `busbar_set_log_sink` from any thread and [`log`] may be called concurrently
    /// from any other; both are written once, before any `busbar_call`, and only ever read after.
    static SINK: AtomicUsize = AtomicUsize::new(0);
    static CTX: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
    /// The HOST's maximum enabled level. Filtering happens on THIS side of the boundary, before a
    /// record is built: a dispatcher that claimed interest in everything would make every
    /// `trace!`/`debug!` in this plugin's dependency tree allocate a string and cross the FFI call
    /// on the request path, only for the host to discard it. Defaults to `OFF` so nothing is built
    /// before a host has said what it wants.
    static MAX_LEVEL: AtomicU32 = AtomicU32::new(log_level::OFF);

    /// Record the host's sink. Called ONLY by the `busbar_set_log_sink` symbol `export_plugin!`
    /// emits — not part of a plugin's own API.
    ///
    /// # Safety
    /// `sink` must stay callable, and `ctx` valid, for the life of the plugin.
    pub unsafe fn install(sink: LogSinkFn, ctx: *mut std::ffi::c_void, max_level: u32) {
        CTX.store(ctx, Ordering::Release);
        MAX_LEVEL.store(max_level, Ordering::Release);
        SINK.store(sink as usize, Ordering::Release);
        // Light up every `tracing` call site already in this plugin, including in library crates
        // that never depended on this SDK.
        install_tracing_bridge();
    }

    /// Emit one record at `level`. Goes to the host's subscriber when a sink is installed, else to
    /// stderr — never nowhere.
    /// True when the host would actually keep a record at `level`. Cheap enough to call before
    /// building the message, which is the whole point.
    pub fn enabled(level: u32) -> bool {
        // Lower constant = more severe. `OFF` (0) is below ERROR (1), so it enables nothing.
        level != log_level::OFF && level <= MAX_LEVEL.load(Ordering::Acquire)
    }

    pub fn log(level: u32, msg: &str) {
        let raw = SINK.load(Ordering::Acquire);
        if raw == 0 {
            // No host bridge (an older host, or before `open` returned). stderr still reaches an
            // operator collecting the process's output, which is strictly better than dropping it.
            eprintln!("[busbar-plugin] {msg}");
            return;
        }
        // SAFETY: `raw` was stored from a valid `LogSinkFn` by `install`, which the host contract
        // requires to stay callable for the plugin's life. The message is borrowed for the call only.
        let sink: LogSinkFn = unsafe { std::mem::transmute::<usize, LogSinkFn>(raw) };
        let ctx = CTX.load(Ordering::Acquire);
        unsafe { sink(ctx, level, msg.as_ptr(), msg.len()) };
    }

    /// Forward this plugin's OWN `tracing` events into the host sink.
    ///
    /// This is what makes the bridge worth having. Without it, a plugin only reaches the operator
    /// from call sites rewritten to call [`log`] by hand — and the calls that matter most are the
    /// ones already written as `tracing::warn!` inside plugin LIBRARY crates that have no reason to
    /// depend on this SDK at all (auth-ldap's ambiguous-match and truncation warnings, its whole
    /// pure-lib diagnostic surface). Installing a dispatcher INSIDE the cdylib means every one of
    /// them lights up unchanged.
    ///
    /// Called automatically when the host installs a sink, so no plugin has to remember to.
    ///
    /// Best-effort: if the plugin has already set its own global dispatcher, `set_global_default`
    /// fails and we leave theirs alone rather than fighting over it.
    fn install_tracing_bridge() {
        use tracing_core::{span, Event, Metadata, Subscriber};

        fn abi_level(l: &tracing_core::Level) -> u32 {
            match *l {
                tracing_core::Level::ERROR => log_level::ERROR,
                tracing_core::Level::WARN => log_level::WARN,
                tracing_core::Level::INFO => log_level::INFO,
                tracing_core::Level::DEBUG => log_level::DEBUG,
                tracing_core::Level::TRACE => log_level::TRACE,
            }
        }

        struct Forwarder;
        impl Subscriber for Forwarder {
            fn enabled(&self, m: &Metadata<'_>) -> bool {
                super::hostlog::enabled(abi_level(m.level()))
            }

            /// Without this, `tracing-core` assumes TRACE and every `trace!` in this plugin's whole
            /// dependency tree becomes a live callsite. With it, those callsites go back to being a
            /// static check — which is what they were before any subscriber existed here.
            fn max_level_hint(&self) -> Option<tracing_core::LevelFilter> {
                Some(match MAX_LEVEL.load(Ordering::Acquire) {
                    log_level::OFF => tracing_core::LevelFilter::OFF,
                    log_level::ERROR => tracing_core::LevelFilter::ERROR,
                    log_level::WARN => tracing_core::LevelFilter::WARN,
                    log_level::INFO => tracing_core::LevelFilter::INFO,
                    log_level::DEBUG => tracing_core::LevelFilter::DEBUG,
                    _ => tracing_core::LevelFilter::TRACE,
                })
            }
            fn new_span(&self, _a: &span::Attributes<'_>) -> span::Id {
                span::Id::from_u64(1)
            }
            fn record(&self, _s: &span::Id, _v: &span::Record<'_>) {}
            fn record_follows_from(&self, _s: &span::Id, _f: &span::Id) {}
            fn event(&self, event: &Event<'_>) {
                struct Render(String);
                impl tracing_core::field::Visit for Render {
                    fn record_debug(&mut self, f: &tracing_core::Field, v: &dyn std::fmt::Debug) {
                        if !self.0.is_empty() {
                            self.0.push(' ');
                        }
                        // The `message` field is the human sentence; everything else is a
                        // structured key the operator still wants, rendered as `key=value`.
                        if f.name() == "message" {
                            self.0.push_str(&format!("{v:?}"));
                        } else {
                            self.0.push_str(&format!("{}={:?}", f.name(), v));
                        }
                    }
                }
                let level = abi_level(event.metadata().level());
                // Re-checked here as well as in `enabled`: a cached callsite interest can outlive a
                // level change, and rendering is where the cost actually is.
                if !super::hostlog::enabled(level) {
                    return;
                }
                let mut r = Render(String::new());
                event.record(&mut r);
                log(abi_level(event.metadata().level()), &r.0);
            }
            fn enter(&self, _s: &span::Id) {}
            fn exit(&self, _s: &span::Id) {}
        }

        let _ = tracing::subscriber::set_global_default(Forwarder);
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

#[macro_export]
macro_rules! export_auth_plugin {
    ($ctor:path) => {
        /// Adapt the verify-only ctor into the unified `Box<dyn AuthPlugin>` handle (fail-closed
        /// login default). Keeps `$ctor`'s `-> Result<Box<dyn AuthModule>, String>` signature valid
        /// under the ABI-v2 handle change.
        #[doc(hidden)]
        fn __busbar_auth_open_adapted(
            cfg: &str,
        ) -> ::core::result::Result<$crate::AuthHandle, ::std::string::String> {
            ::core::result::Result::Ok($crate::adapt_auth_handle($ctor(cfg)?))
        }
        $crate::export_plugin!(
            kind = "auth",
            dispatch = $crate::auth_dispatch,
            ctor = __busbar_auth_open_adapted,
            handle = $crate::AuthHandle,
        );
    };
}

/// Emit an `auth`-kind cdylib plugin from `$ctor` (a
/// `fn(&str) -> Result<Box<dyn busbar_api::AuthPlugin>, String>`) — a LOGIN-CAPABLE module that
/// implements BOTH [`busbar_api::AuthModule`] (verify) AND [`busbar_api::LoginModule`]
/// (BeginLogin/CompleteLogin).
///
/// This is the sibling of [`export_auth_plugin!`] for a plugin that also drives the hosted browser
/// login flow (e.g. `auth-oidc`). The crucial difference: `export_auth_plugin!` routes its ctor
/// through the verify-only `VerifyOnlyAuth` adapter, which takes [`busbar_api::LoginModule`]'s
/// fail-closed default — so a login-capable plugin exported through it would have its login
/// capability MASKED (every BeginLogin/CompleteLogin would return `Reject`). `export_login_plugin!`
/// boxes the ctor's `Box<dyn AuthPlugin>` DIRECTLY (no adapter), so [`auth_dispatch`] sees the real
/// [`busbar_api::LoginModule`] impl and the login arms work.
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
        ) -> ::core::result::Result<$crate::AuthHandle, ::std::string::String> {
            $ctor(cfg)
        }
        $crate::export_plugin!(
            kind = "auth",
            dispatch = $crate::auth_dispatch,
            ctor = __busbar_login_open,
            handle = $crate::AuthHandle,
        );
    };
}

// ── SECRET-plugin glue (`kind: secret`) ─────────────────────────────────────────────────────────
// Mirrors the store glue one-to-one: same six-symbol shape via `export_plugin!`, same
// panic-catching impl style, its own handle type (`Box<dyn SecretModule>`) and its own tiny
// request enum.

/// The secret handle behind the opaque `*mut c_void`: a boxed [`busbar_api::SecretModule`]. Named at
/// the module level so the `export_plugin!` expansion can pass it to `close_boundary::<$ty>`.
pub type SecretHandle = Box<dyn busbar_api::SecretModule>;

/// The secret handle behind the opaque `*mut c_void`: a boxed [`busbar_api::SecretModule`].
type BoxedSecret = SecretHandle;

/// Return the SECRET ABI version this SDK builds against (`busbar_secret_abi_version`). See
/// `docs/plugins.md`'s `abi_version` manifest field for the engine-side boot-time check against it.
pub fn secret_abi_version() -> u32 {
    busbar_plugin_abi::SECRET_ABI_VERSION
}

/// Run one [`busbar_plugin_abi::SecretRequest`] against a secret module - the single match that
/// maps the wire enum to the trait, unit-testable without FFI.
pub fn dispatch_secret(
    module: &dyn busbar_api::SecretModule,
    req: busbar_plugin_abi::SecretRequest,
) -> Result<busbar_plugin_abi::SecretResponse, busbar_api::SecretError> {
    match req {
        // `deadline_ms` is advisory-only at this layer — no enforcement here; a module
        // that can bound its own call reads it from the request before this dispatch runs.
        busbar_plugin_abi::SecretRequest::Resolve { settings, .. } => Ok(
            busbar_plugin_abi::SecretResponse::Bytes(module.resolve(&settings)?),
        ),
    }
}

/// The per-kind `dispatch` closure `export_secret_plugin!` hands to [`boundary::call_boundary`]: decode
/// a [`busbar_plugin_abi::SecretRequest`], run it via [`dispatch_secret`], and encode the response into
/// a [`BoundaryOutcome`]. A resolve failure is a defined backend error → [`BoundaryOutcome::Error`]
/// (the message must never carry secret material).
///
/// # Safety
/// `handle` is a live secret handle from `open` (guaranteed non-null by the boundary wrapper).
pub unsafe fn secret_dispatch(handle: *mut c_void, bytes: &[u8]) -> BoundaryOutcome {
    let module: &BoxedSecret = &*(handle as *const BoxedSecret);
    let request: busbar_plugin_abi::SecretRequest = match serde_json::from_slice(bytes) {
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
            let typed = busbar_plugin_abi::SecretResponse::Error {
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
    fn transform(&self, _payload: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({})
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
    fn handle_http(&self, _req: &HttpEndpointRequest) -> HttpEndpointResponse {
        HttpEndpointResponse {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

/// The hook handle behind the opaque `*mut c_void`: a boxed [`HookHandler`]. Named at the module level
/// so the `export_plugin!` expansion can pass it to `close_boundary::<$ty>`.
pub type HookHandle = Box<dyn HookHandler>;

/// The hook handle behind the opaque `*mut c_void`: a boxed [`HookHandler`].
type BoxedHook = HookHandle;

/// Return the HOOK PAYLOAD schema version this SDK builds against (`busbar_plugin_kind() == "hook"`).
/// See `docs/plugins.md`'s `abi_version` manifest field for the engine-side boot-time check against it.
pub fn hook_abi_version() -> u32 {
    busbar_plugin_abi::hook::HOOK_ABI_VERSION
}

/// Run one [`busbar_plugin_abi::hook::HookRequest`] against a [`HookHandler`] — the single op-dispatch
/// match that maps the wire envelope to the trait, unit-testable without FFI. This is the ergonomic
/// helper a hook author never has to write.
pub fn dispatch_hook(
    handler: &dyn HookHandler,
    req: busbar_plugin_abi::hook::HookRequest,
) -> busbar_plugin_abi::hook::HookReply {
    use busbar_plugin_abi::hook::{HookReply, HookRequest};
    match req {
        HookRequest::Decide { payload } => match handler.decide_result(&payload) {
            Ok(v) => HookReply::Reply(v),
            Err(message) => HookReply::Failed { message },
        },
        HookRequest::Transform { payload } => HookReply::Reply(handler.transform(&payload)),
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
        HookRequest::HttpEndpoint { request } => HookReply::Http(handler.handle_http(&request)),
    }
}

/// The per-kind `dispatch` closure `export_hook_plugin!` hands to [`boundary::call_boundary`]: decode a
/// [`busbar_plugin_abi::hook::HookRequest`], run it via [`dispatch_hook`], and encode the reply into a
/// [`BoundaryOutcome`].
///
/// # Safety
/// `handle` is a live hook handle from `open` (guaranteed non-null by the boundary wrapper).
pub unsafe fn hook_dispatch(handle: *mut c_void, bytes: &[u8]) -> BoundaryOutcome {
    let handler: &BoxedHook = &*(handle as *const BoxedHook);
    let request: busbar_plugin_abi::hook::HookRequest = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => return BoundaryOutcome::Unsupported(format!("malformed request JSON: {e}")),
    };
    let resp = dispatch_hook(handler.as_ref(), request);
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

/// Re-export the export wire types so a plugin author names `busbar_plugin_sdk::ExportStream` (etc.)
/// without a direct `busbar-plugin-abi` dependency, mirroring the hook/auth re-export path.
pub use busbar_plugin_abi::export::{ExportField, ExportRequest, ExportResponse, ExportStream};

/// Re-export the HTTP-endpoint wire types (plugin route registration + dispatch) so an export/hook
/// author names `busbar_plugin_sdk::Route` / `HttpEndpointRequest` (etc.) without a direct
/// `busbar-plugin-abi` dependency.
pub use busbar_plugin_abi::http_endpoint::{
    HttpEndpointRequest, HttpEndpointResponse, Route, RouteAuth, RouteMethod,
};

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
    fn handle_http(&self, _req: &HttpEndpointRequest) -> HttpEndpointResponse {
        HttpEndpointResponse {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        }
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
    busbar_plugin_abi::export::EXPORT_ABI_VERSION
}

/// Run one [`ExportRequest`] against an [`ExportHandler`] — the single op-dispatch match that maps the
/// wire envelope to the trait, unit-testable without FFI. `Streams` returns the handler's declared
/// streams; `Deliver` runs the handler's sink and acks with [`ExportResponse::Delivered`].
pub fn dispatch_export(handler: &dyn ExportHandler, req: ExportRequest) -> ExportResponse {
    match req {
        ExportRequest::Streams => ExportResponse::Streams(handler.streams()),
        ExportRequest::Deliver { stream, payload } => {
            handler.deliver(stream, &payload);
            ExportResponse::Delivered
        }
        ExportRequest::Routes => ExportResponse::Routes(handler.routes()),
        ExportRequest::HttpEndpoint { request } => {
            ExportResponse::Http(handler.handle_http(&request))
        }
    }
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
    let resp = dispatch_export(handler.as_ref(), request);
    match serde_json::to_vec(&resp) {
        Ok(payload) => BoundaryOutcome::Ok(payload),
        Err(e) => BoundaryOutcome::Error(format!("response encode failed: {e}")),
    }
}

/// Emit an `export`-kind cdylib plugin from `$ctor` (a
/// `fn(&str) -> Result<Box<dyn busbar_plugin_sdk::ExportHandler>, String>`). Expands through
/// [`export_plugin!`], stamping `busbar_plugin_kind() == "export"` + the six neutral symbols.
#[macro_export]
macro_rules! export_export_plugin {
    ($ctor:path) => {
        $crate::export_plugin!(
            kind = "export",
            dispatch = $crate::export_dispatch,
            ctor = $ctor,
            handle = $crate::ExportHandle,
        );
    };
}

/// Emit a `hook`-kind cdylib plugin from `$ctor` (a
/// `fn(&str) -> Result<Box<dyn busbar_plugin_sdk::HookHandler>, String>`). Expands through
/// [`export_plugin!`], stamping `busbar_plugin_kind() == "hook"` + the six neutral symbols.
#[macro_export]
macro_rules! export_hook_plugin {
    ($ctor:path) => {
        $crate::export_plugin!(
            kind = "hook",
            dispatch = $crate::hook_dispatch,
            ctor = $ctor,
            handle = $crate::HookHandle,
        );
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
/// a raw pointer or a status integer, and these SIX symbols are the ONLY `#[no_mangle]` exports.
///
/// - `$kind` — a `&'static str` kind (`"store"` | `"secret"` | `"auth"` | `"hook"`).
/// - `$dispatch` — the per-kind SDK `dispatch` adapter (`store_dispatch`/`auth_dispatch`/…).
/// - `$ctor` — the plugin's `fn(&str) -> Result<$handle, String>` constructor.
/// - `$handle` — the boxed handle type, so `close_boundary::<$handle>` frees it correctly.
#[macro_export]
macro_rules! export_plugin {
    (kind = $kind:expr, dispatch = $dispatch:path, ctor = $ctor:path, handle = $handle:ty $(,)?) => {
        /// # Safety
        /// Read only by the busbar loader as the frozen TRANSPORT handshake.
        ///
        /// `extern "C-unwind"` (matches [`busbar_plugin_abi::AbiFn`]): a panic that unwinds out of
        /// this symbol propagates as a DEFINED forced unwind the engine's `catch_unwind` can catch,
        /// rather than an immediate abort at this frame (which plain `extern "C"` would force).
        #[no_mangle]
        pub extern "C-unwind" fn busbar_abi() -> u32 {
            $crate::transport_version()
        }

        /// # Safety
        /// The returned pointer is to a `'static` NUL-terminated string owned by this library.
        #[no_mangle]
        pub extern "C-unwind" fn busbar_plugin_kind() -> *const u8 {
            const KIND_NUL: &str = concat!($kind, "\0");
            KIND_NUL.as_ptr()
        }

        /// # Safety
        /// Called at most once by the busbar loader, immediately after a successful `busbar_open`
        /// and before any `busbar_call`, with a sink that stays callable for this plugin's life.
        ///
        /// OPTIONAL on both sides: a host that never calls it leaves the plugin logging to stderr,
        /// and a host that looks it up on an older plugin simply does not find it. That is what
        /// keeps this additive rather than a transport bump.
        #[no_mangle]
        pub unsafe extern "C-unwind" fn busbar_set_log_sink(
            sink: $crate::__abi::LogSinkFn,
            ctx: *mut ::std::ffi::c_void,
            max_level: u32,
        ) {
            unsafe { $crate::hostlog::install(sink, ctx, max_level) };
        }

        /// # Safety
        /// Called only by the busbar loader with ABI-valid pointers. Routes through
        /// `boundary::open_boundary`: the ctor runs under a mandatory `catch_unwind`, the handle is
        /// published only into a confirmed non-null slot (else dropped), and the status is total.
        #[no_mangle]
        pub unsafe extern "C-unwind" fn busbar_open(
            cfg: *const u8,
            cfg_len: usize,
            out_handle: *mut *mut ::core::ffi::c_void,
            out_err: *mut *mut u8,
            out_err_len: *mut usize,
        ) -> i32 {
            $crate::boundary::open_boundary::<$handle>(
                cfg,
                cfg_len,
                out_handle,
                out_err,
                out_err_len,
                |s| $ctor(s).map_err($crate::BoundaryOutcome::Error),
            )
        }

        /// # Safety
        /// Called only by the busbar loader with a live handle and ABI-valid pointers. Routes through
        /// `boundary::call_boundary`: null-handle → protocol, dispatch under mandatory `catch_unwind`,
        /// alloc-after-check buffer publish, total status.
        #[no_mangle]
        pub unsafe extern "C-unwind" fn busbar_call(
            handle: *mut ::core::ffi::c_void,
            req: *const u8,
            req_len: usize,
            out: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32 {
            $crate::boundary::call_boundary(handle, req, req_len, out, out_len, |h, b| {
                $dispatch(h, b)
            })
        }

        /// # Safety
        /// Called only by the busbar loader with a buffer this plugin returned. Catch-wrapped dealloc.
        #[no_mangle]
        pub unsafe extern "C-unwind" fn busbar_free(ptr: *mut u8, len: usize) {
            $crate::boundary::free_boundary(ptr, len)
        }

        /// # Safety
        /// Called only by the busbar loader with a live handle, once. Routes through
        /// `boundary::close_boundary`: the box is owned BEFORE the `catch_unwind`, so a panicking Drop
        /// frees the allocation and never unwinds out of this symbol.
        #[no_mangle]
        pub unsafe extern "C-unwind" fn busbar_close(handle: *mut ::core::ffi::c_void) {
            $crate::boundary::close_boundary::<$handle>(handle)
        }
    };
}

/// Emit a `secret`-kind cdylib plugin from `$ctor` (a
/// `fn(&str) -> Result<Box<dyn busbar_api::SecretModule>, String>`). Expands through
/// [`export_plugin!`], stamping `busbar_plugin_kind() == "secret"` + the six neutral symbols.
#[macro_export]
macro_rules! export_secret_plugin {
    ($ctor:path) => {
        $crate::export_plugin!(
            kind = "secret",
            dispatch = $crate::secret_dispatch,
            ctor = $ctor,
            handle = $crate::SecretHandle,
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
            dispatch = $crate::store_dispatch,
            ctor = $ctor,
            handle = $crate::StoreHandle,
        );
    };
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
