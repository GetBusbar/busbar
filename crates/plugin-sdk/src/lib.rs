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
/// Until then — and forever, for a host too old to call it — [`log`] falls back to `eprintln!`, so a
/// plugin never loses a message by using this.
pub mod hostlog {
    use busbar_plugin_abi::{log_level, LogSinkFn};
    use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

    /// The installed sink, as raw parts. Two atomics rather than a `OnceLock<(fn, ptr)>` because the
    /// host may call `busbar_set_log_sink` from any thread and [`log`] may be called concurrently
    /// from any other; both are written once, before any `busbar_call`, and only ever read after.
    static SINK: AtomicUsize = AtomicUsize::new(0);
    static CTX: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

    /// Record the host's sink. Called ONLY by the `busbar_set_log_sink` symbol `export_plugin!`
    /// emits — not part of a plugin's own API.
    ///
    /// # Safety
    /// `sink` must stay callable, and `ctx` valid, for the life of the plugin.
    pub unsafe fn install(sink: LogSinkFn, ctx: *mut std::ffi::c_void) {
        CTX.store(ctx, Ordering::Release);
        SINK.store(sink as usize, Ordering::Release);
    }

    /// Emit one record at `level`. Goes to the host's subscriber when a sink is installed, else to
    /// stderr — never nowhere.
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
        ) {
            unsafe { $crate::hostlog::install(sink, ctx) };
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
mod tests {
    use super::*;
    use boundary::{call_boundary, close_boundary, free_boundary, open_boundary, BoundaryOutcome};
    use busbar_api::VirtualKey;
    use busbar_plugin_abi::{STATUS_ERR, STATUS_OK, STATUS_PROTOCOL, STATUS_UNSUPPORTED};
    use busbar_store_memory::MemoryStore;
    use std::os::raw::c_void;
    use std::ptr;

    // ── Test shims: drive the SHIPPING boundary exactly as `export_plugin!` expands, per kind. The
    //    macro can't be invoked in a lib crate (it stamps `#[no_mangle]` exports), so these thin
    //    wrappers route open/call/free/close through the same `boundary::*` helpers the macro uses.
    //    A test exercising these exercises the real choke point.

    unsafe fn open_impl(
        cfg: *const u8,
        cfg_len: usize,
        out_handle: *mut *mut c_void,
        out_err: *mut *mut u8,
        out_err_len: *mut usize,
        ctor: fn(&str) -> Result<BoxedStore, String>,
    ) -> i32 {
        open_boundary::<StoreHandle>(cfg, cfg_len, out_handle, out_err, out_err_len, |s| {
            ctor(s).map_err(BoundaryOutcome::Error)
        })
    }
    unsafe fn call_impl(
        handle: *mut c_void,
        req: *const u8,
        req_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32 {
        call_boundary(handle, req, req_len, out, out_len, |h, b| {
            store_dispatch(h, b)
        })
    }
    unsafe fn close_impl(handle: *mut c_void) {
        close_boundary::<StoreHandle>(handle)
    }
    unsafe fn free_impl(ptr: *mut u8, len: usize) {
        free_boundary(ptr, len)
    }
    unsafe fn secret_open_impl(
        cfg: *const u8,
        cfg_len: usize,
        out_handle: *mut *mut c_void,
        out_err: *mut *mut u8,
        out_err_len: *mut usize,
        ctor: fn(&str) -> Result<BoxedSecret, String>,
    ) -> i32 {
        open_boundary::<SecretHandle>(cfg, cfg_len, out_handle, out_err, out_err_len, |s| {
            ctor(s).map_err(BoundaryOutcome::Error)
        })
    }
    unsafe fn secret_call_impl(
        handle: *mut c_void,
        req: *const u8,
        req_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32 {
        call_boundary(handle, req, req_len, out, out_len, |h, b| {
            secret_dispatch(h, b)
        })
    }
    unsafe fn secret_close_impl(handle: *mut c_void) {
        close_boundary::<SecretHandle>(handle)
    }
    unsafe fn hook_open_impl(
        cfg: *const u8,
        cfg_len: usize,
        out_handle: *mut *mut c_void,
        out_err: *mut *mut u8,
        out_err_len: *mut usize,
        ctor: fn(&str) -> Result<BoxedHook, String>,
    ) -> i32 {
        open_boundary::<HookHandle>(cfg, cfg_len, out_handle, out_err, out_err_len, |s| {
            ctor(s).map_err(BoundaryOutcome::Error)
        })
    }
    unsafe fn hook_call_impl(
        handle: *mut c_void,
        req: *const u8,
        req_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32 {
        call_boundary(handle, req, req_len, out, out_len, |h, b| {
            hook_dispatch(h, b)
        })
    }
    unsafe fn hook_close_impl(handle: *mut c_void) {
        close_boundary::<HookHandle>(handle)
    }

    /// A test secret module: settings.name in, "resolved:<name>" bytes out; missing name errors.
    struct EchoSecret;
    impl busbar_api::SecretModule for EchoSecret {
        fn resolve(
            &self,
            settings: &serde_json::Map<String, serde_json::Value>,
        ) -> busbar_api::SecretResult<Vec<u8>> {
            match settings.get("name").and_then(|v| v.as_str()) {
                Some(n) => Ok(format!("resolved:{n}").into_bytes()),
                None => Err(busbar_api::SecretError::invalid("settings.name required")),
            }
        }
    }

    fn secret_ctor(_cfg: &str) -> Result<BoxedSecret, String> {
        Ok(Box::new(EchoSecret))
    }

    /// SECRET glue: dispatch maps the wire enum to the trait, success and failure.
    #[test]
    fn secret_dispatch_resolves_and_fails_closed() {
        let mut settings = serde_json::Map::new();
        settings.insert("name".to_string(), serde_json::Value::String("db".into()));
        match dispatch_secret(
            &EchoSecret,
            busbar_plugin_abi::SecretRequest::Resolve {
                settings,
                deadline_ms: None,
            },
        )
        .expect("resolves")
        {
            busbar_plugin_abi::SecretResponse::Bytes(b) => assert_eq!(b, b"resolved:db"),
            other => panic!("expected Bytes, got {other:?}"),
        }
        let err = dispatch_secret(
            &EchoSecret,
            busbar_plugin_abi::SecretRequest::Resolve {
                settings: serde_json::Map::new(),
                deadline_ms: None,
            },
        )
        .unwrap_err();
        assert_eq!(err.kind, busbar_api::SecretErrorKind::Invalid);
        assert!(err.message.contains("settings.name required"));
    }

    /// SECRET glue: the FFI path (open -> call -> close) round-trips a resolve and surfaces a
    /// module failure as a TYPED `SecretResponse::Error` over STATUS_OK — not the untyped
    /// STATUS_ERR string channel, so a host can distinguish failure kinds instead of pattern-matching
    /// message text.
    #[test]
    fn secret_ffi_roundtrip_open_call_close() {
        unsafe {
            let mut handle: *mut c_void = ptr::null_mut();
            let mut err: *mut u8 = ptr::null_mut();
            let mut err_len: usize = 0;
            let status = secret_open_impl(
                b"{}".as_ptr(),
                2,
                &mut handle,
                &mut err,
                &mut err_len,
                secret_ctor,
            );
            assert_eq!(status, STATUS_OK);
            assert!(!handle.is_null());

            // resolve success
            let mut settings = serde_json::Map::new();
            settings.insert("name".to_string(), serde_json::Value::String("x".into()));
            let req = serde_json::to_vec(&busbar_plugin_abi::SecretRequest::Resolve {
                settings,
                deadline_ms: None,
            })
            .unwrap();
            let mut out: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let status = secret_call_impl(handle, req.as_ptr(), req.len(), &mut out, &mut out_len);
            assert_eq!(status, STATUS_OK);
            let resp: busbar_plugin_abi::SecretResponse =
                serde_json::from_slice(std::slice::from_raw_parts(out, out_len)).unwrap();
            free_impl(out, out_len);
            match resp {
                busbar_plugin_abi::SecretResponse::Bytes(b) => assert_eq!(b, b"resolved:x"),
                other => panic!("expected Bytes, got {other:?}"),
            }

            // resolve failure -> STATUS_OK carrying a typed SecretResponse::Error (never a panic
            // across the boundary, and never the untyped STATUS_ERR channel for a module-level
            // failure — see this test's own doc comment).
            let req = serde_json::to_vec(&busbar_plugin_abi::SecretRequest::Resolve {
                settings: serde_json::Map::new(),
                deadline_ms: None,
            })
            .unwrap();
            let mut out: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let status = secret_call_impl(handle, req.as_ptr(), req.len(), &mut out, &mut out_len);
            assert_eq!(status, STATUS_OK);
            let resp: busbar_plugin_abi::SecretResponse =
                serde_json::from_slice(std::slice::from_raw_parts(out, out_len)).unwrap();
            free_impl(out, out_len);
            match resp {
                busbar_plugin_abi::SecretResponse::Error { kind, message } => {
                    assert_eq!(kind, busbar_api::SecretErrorKind::Invalid);
                    assert!(message.contains("settings.name required"), "got {message}");
                }
                other => panic!("expected Error, got {other:?}"),
            }

            secret_close_impl(handle);
        }
    }

    /// A trivial test hook handler: decide prefers `[0]`, configure acks only the pushed version.
    struct TestHook;
    impl HookHandler for TestHook {
        fn decide(&self, _payload: &serde_json::Value) -> serde_json::Value {
            serde_json::json!({"order": [0]})
        }
        fn status(&self) -> serde_json::Value {
            serde_json::json!({"status": {"metrics": []}})
        }
    }

    /// HOOK glue: `dispatch_hook` maps each op envelope to the trait — decide returns the reply
    /// object, notify returns None, configure ACKs the exact version, describe/status pass through.
    #[test]
    fn hook_dispatch_maps_ops() {
        use busbar_plugin_abi::hook::{ConfigureBody, HookReply, HookRequest};
        match dispatch_hook(
            &TestHook,
            HookRequest::Decide {
                payload: serde_json::json!({}),
            },
        ) {
            HookReply::Reply(v) => assert_eq!(v, serde_json::json!({"order": [0]})),
            other => panic!("expected Reply, got {other:?}"),
        }
        // notify is fire-and-forget → None.
        assert!(matches!(
            dispatch_hook(
                &TestHook,
                HookRequest::Notify {
                    payload: serde_json::json!({})
                }
            ),
            HookReply::None
        ));
        // configure with the default handler (acks) echoes the pushed version.
        match dispatch_hook(
            &TestHook,
            HookRequest::Configure(ConfigureBody {
                hook: "h".into(),
                settings: serde_json::Map::new(),
                settings_version: 42,
                busbar_version: "1.5.0".into(),
            }),
        ) {
            HookReply::ConfigureAck { settings_version } => assert_eq!(settings_version, 42),
            other => panic!("expected ConfigureAck(42), got {other:?}"),
        }
    }

    /// HOOK glue: the FFI path (open → call → close) round-trips a decide and a status, and a
    /// malformed request is a PROTOCOL error, never a crash.
    #[test]
    fn hook_ffi_roundtrip_open_call_close() {
        fn hook_ctor(_cfg: &str) -> Result<BoxedHook, String> {
            Ok(Box::new(TestHook))
        }
        unsafe {
            let mut handle: *mut c_void = ptr::null_mut();
            let mut err: *mut u8 = ptr::null_mut();
            let mut err_len: usize = 0;
            let st = hook_open_impl(
                b"{}".as_ptr(),
                2,
                &mut handle,
                &mut err,
                &mut err_len,
                hook_ctor,
            );
            assert_eq!(st, STATUS_OK);
            assert!(!handle.is_null());

            let req = serde_json::to_vec(&busbar_plugin_abi::hook::HookRequest::Decide {
                payload: serde_json::json!({}),
            })
            .unwrap();
            let mut out: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let st = hook_call_impl(handle, req.as_ptr(), req.len(), &mut out, &mut out_len);
            assert_eq!(st, STATUS_OK);
            let resp: busbar_plugin_abi::hook::HookReply =
                serde_json::from_slice(std::slice::from_raw_parts(out, out_len)).unwrap();
            free_impl(out, out_len);
            match resp {
                busbar_plugin_abi::hook::HookReply::Reply(v) => {
                    assert_eq!(v, serde_json::json!({"order": [0]}))
                }
                other => panic!("expected Reply, got {other:?}"),
            }

            // Malformed/undecodable request → UNSUPPORTED (an old-SDK "I can't decode this variant"
            // signal), with a message, never a crash. Distinct from a caller-protocol violation.
            let junk = b"not json";
            let mut out: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let st = hook_call_impl(handle, junk.as_ptr(), junk.len(), &mut out, &mut out_len);
            assert_eq!(st, STATUS_UNSUPPORTED);
            free_impl(out, out_len);

            hook_close_impl(handle);
        }
    }

    /// A trivial export sink: declares `[Metrics]` and counts deliveries.
    struct TestExport {
        delivered: std::sync::atomic::AtomicU64,
    }
    impl ExportHandler for TestExport {
        fn streams(&self) -> Vec<ExportStream> {
            vec![ExportStream::Metrics]
        }
        fn deliver(&self, _stream: ExportStream, _payload: &serde_json::Value) {
            self.delivered
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// EXPORT glue: `dispatch_export` maps `Streams` to the declared catalog and `Deliver` to the
    /// sink, acking `Delivered` and running the handler exactly once.
    #[test]
    fn export_dispatch_maps_ops() {
        let sink = TestExport {
            delivered: std::sync::atomic::AtomicU64::new(0),
        };
        match dispatch_export(&sink, ExportRequest::Streams) {
            ExportResponse::Streams(s) => assert_eq!(s, vec![ExportStream::Metrics]),
            other => panic!("expected Streams, got {other:?}"),
        }
        match dispatch_export(
            &sink,
            ExportRequest::Deliver {
                stream: ExportStream::Metrics,
                payload: serde_json::json!({"reqs": 1}),
            },
        ) {
            ExportResponse::Delivered => {}
            other => panic!("expected Delivered, got {other:?}"),
        }
        assert_eq!(sink.delivered.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    /// A sink that declares a `GET /metrics` route and serves it via `handle_http`.
    struct RoutedExport;
    impl ExportHandler for RoutedExport {
        fn streams(&self) -> Vec<ExportStream> {
            vec![ExportStream::Metrics]
        }
        fn routes(&self) -> Vec<Route> {
            vec![Route {
                path: "/metrics".into(),
                method: RouteMethod::Get,
                auth: RouteAuth::None,
            }]
        }
        fn handle_http(&self, req: &HttpEndpointRequest) -> HttpEndpointResponse {
            assert_eq!(req.path, "/metrics");
            HttpEndpointResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: b"busbar_up 1\n".to_vec(),
            }
        }
    }

    /// EXPORT glue: `dispatch_export` maps `Routes` to the declared routes and `HttpEndpoint` to
    /// `handle_http`, relaying the plugin's response — the additive route-registration + dispatch wire.
    #[test]
    fn export_dispatch_routes_and_http() {
        match dispatch_export(&RoutedExport, ExportRequest::Routes) {
            ExportResponse::Routes(r) => {
                assert_eq!(r.len(), 1);
                assert_eq!(r[0].path, "/metrics");
                assert_eq!(r[0].method, RouteMethod::Get);
            }
            other => panic!("expected Routes, got {other:?}"),
        }
        match dispatch_export(
            &RoutedExport,
            ExportRequest::HttpEndpoint {
                request: HttpEndpointRequest {
                    method: "GET".into(),
                    path: "/metrics".into(),
                    query: String::new(),
                    headers: vec![],
                    body: vec![],
                },
            },
        ) {
            ExportResponse::Http(resp) => {
                assert_eq!(resp.status, 200);
                assert_eq!(resp.body, b"busbar_up 1\n");
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    /// EXPORT glue: the DEFAULT `handle_http` is a 404 (a sink with no HTTP surface / partial impl).
    #[test]
    fn export_default_handle_http_is_404() {
        struct Bare;
        impl ExportHandler for Bare {
            fn streams(&self) -> Vec<ExportStream> {
                vec![ExportStream::Metrics]
            }
        }
        assert!(Bare.routes().is_empty());
        let resp = Bare.handle_http(&HttpEndpointRequest {
            method: "GET".into(),
            path: "/whatever".into(),
            query: String::new(),
            headers: vec![],
            body: vec![],
        });
        assert_eq!(resp.status, 404);
    }

    /// EXPORT: the SDK's declared payload version reads the shared const (compile-time link, not a
    /// coincidental literal) and is pinned at v2 (1.5.3 — the projection grammar: expanded stream
    /// vocabulary, `audit` removed).
    #[test]
    fn export_abi_version_reads_the_shared_const_and_is_two() {
        assert_eq!(
            export_abi_version(),
            busbar_plugin_abi::export::EXPORT_ABI_VERSION
        );
        assert_eq!(export_abi_version(), 2);
    }

    fn mem_ctor(_cfg: &str) -> Result<BoxedStore, String> {
        Ok(Box::new(MemoryStore::new()))
    }

    fn ctor_that_errors(_cfg: &str) -> Result<BoxedStore, String> {
        Err("nope".to_string())
    }

    fn key(id: &str) -> VirtualKey {
        VirtualKey {
            id: id.into(),
            generation_hash: "hash".into(),
            name: "n".into(),
            allowed_scopes: None,
            enabled: true,
            created_at: 1,
            group: None,
            labels: std::collections::BTreeMap::new(),
            expires_at: None,
            deleted_at: None,
            revision: 1,
        }
    }

    /// Drive the FFI helpers exactly as the loader would: open → call (put then get) → close, and
    /// free every buffer. Proves the whole serialize → dispatch → deserialize path over the boxed
    /// handle, against a real Store.
    #[test]
    fn ffi_roundtrip_open_call_close() {
        unsafe {
            // open
            let mut handle: *mut c_void = ptr::null_mut();
            let mut err: *mut u8 = ptr::null_mut();
            let mut err_len: usize = 0;
            let cfg = b"{}";
            let st = open_impl(
                cfg.as_ptr(),
                cfg.len(),
                &mut handle,
                &mut err,
                &mut err_len,
                mem_ctor,
            );
            assert_eq!(st, STATUS_OK);
            assert!(!handle.is_null());

            // call: PutKey
            let put = serde_json::to_vec(&StoreRequest::PutKey(key("vk_1"))).unwrap();
            let mut out: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let st = call_impl(handle, put.as_ptr(), put.len(), &mut out, &mut out_len);
            assert_eq!(st, STATUS_OK);
            free_impl(out, out_len);

            // call: GetKey -> Some(key)
            let get = serde_json::to_vec(&StoreRequest::GetKey("vk_1".into())).unwrap();
            let mut out: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let st = call_impl(handle, get.as_ptr(), get.len(), &mut out, &mut out_len);
            assert_eq!(st, STATUS_OK);
            let resp: StoreResponse =
                serde_json::from_slice(std::slice::from_raw_parts(out, out_len)).unwrap();
            match resp {
                StoreResponse::Key(Some(k)) => assert_eq!(k.id, "vk_1"),
                other => panic!("expected key, got {other:?}"),
            }
            free_impl(out, out_len);

            close_impl(handle);
        }
    }

    /// A malformed/undecodable request payload is an UNSUPPORTED signal (old-SDK "I can't decode this
    /// variant") with a message, not a crash — distinct from a caller-protocol violation and from a
    /// panic. This is the taxonomy split that closes the loader fail-open.
    #[test]
    fn ffi_bad_request_is_unsupported() {
        unsafe {
            let mut handle: *mut c_void = ptr::null_mut();
            let mut err: *mut u8 = ptr::null_mut();
            let mut err_len: usize = 0;
            assert_eq!(
                open_impl(
                    ptr::null(),
                    0,
                    &mut handle,
                    &mut err,
                    &mut err_len,
                    mem_ctor
                ),
                STATUS_OK
            );
            let junk = b"not json at all";
            let mut out: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let st = call_impl(handle, junk.as_ptr(), junk.len(), &mut out, &mut out_len);
            assert_eq!(st, STATUS_UNSUPPORTED);
            assert!(!out.is_null());
            free_impl(out, out_len);
            // A NULL handle IS a caller-protocol violation → STATUS_PROTOCOL (no user code runs).
            let st = call_impl(
                ptr::null_mut(),
                junk.as_ptr(),
                junk.len(),
                &mut out,
                &mut out_len,
            );
            assert_eq!(st, STATUS_PROTOCOL);
            close_impl(handle);
        }
    }

    /// A null `out_handle` on a SUCCESSFUL open is a protocol error, NOT a silent leak. Before the
    /// fix `open_impl` boxed the store then dropped the pointer on the floor when `out_handle` was
    /// null (STATUS_OK, handle leaked forever). Now it never allocates without a slot: the store is
    /// freed and a protocol error is returned with a message. (This drives the store variant; all
    /// four `*_open_impl` share the identical guard.)
    #[test]
    fn ffi_null_out_handle_is_protocol_error_not_leak() {
        unsafe {
            let cfg = b"{}";
            let mut err: *mut u8 = ptr::null_mut();
            let mut err_len: usize = 0;
            let st = open_impl(
                cfg.as_ptr(),
                cfg.len(),
                ptr::null_mut(), // no slot for the handle
                &mut err,
                &mut err_len,
                mem_ctor,
            );
            assert_eq!(st, STATUS_PROTOCOL);
            assert!(!err.is_null());
            let msg = std::str::from_utf8(std::slice::from_raw_parts(err, err_len)).unwrap();
            assert!(msg.contains("out_handle"), "unexpected message: {msg}");
            free_impl(err, err_len);
        }
    }

    /// `OutBuf::commit` (the successor to `write_buf`) with a null `out` must DROP the owned `Vec`, not
    /// leak it: the alloc (`into_boxed_slice`/`Box::into_raw`) lives INSIDE the non-null branch, so the
    /// null path never realizes a raw box — the leak is made structurally impossible. `out_len` is left
    /// untouched; a non-null slot returns a freeable (ptr, len) pair. Under Miri/ASan this flags the
    /// leak the old ordering caused.
    #[test]
    fn outbuf_commit_null_out_drops_without_leaking_or_writing() {
        unsafe {
            // Null `out`: nothing is written, `out_len` is left untouched, no crash (Vec dropped).
            let mut len_slot: usize = 0xDEAD;
            boundary::OutBuf::new(vec![1u8, 2, 3]).commit(ptr::null_mut(), &mut len_slot);
            assert_eq!(
                len_slot, 0xDEAD,
                "out_len must be untouched when out is null"
            );

            // Non-null `out`: the (ptr, len) pair is returned and is freeable (round-trip through
            // free_boundary proves the allocation is intact and owned by the same allocator).
            let mut ptr_slot: *mut u8 = ptr::null_mut();
            let mut len2: usize = 0;
            boundary::OutBuf::new(vec![7u8, 8, 9, 10]).commit(&mut ptr_slot, &mut len2);
            assert!(!ptr_slot.is_null());
            assert_eq!(len2, 4);
            assert_eq!(std::slice::from_raw_parts(ptr_slot, len2), &[7, 8, 9, 10]);
            free_impl(ptr_slot, len2);
        }
    }

    /// The new audit ABI variants dispatch through the trait: `AppendAudit` maps to `append_audit`
    /// (Unit response) and `ListAudit` to `list_audit` (Audit response). Against the memory store the
    /// trait defaults no-op, so append returns Unit and list returns an empty Audit vec — proving the
    /// ADDITIVE variants are wired end-to-end without breaking the existing dispatch.
    #[test]
    fn dispatch_handles_audit_variants() {
        use busbar_api::AuditRecord;
        let store = MemoryStore::new();
        let rec = AuditRecord {
            seq: 1,
            ts: 2,
            action: "hook.register".into(),
            resource: "hook:a".into(),
            outcome: "applied".into(),
            principal: "admin".into(),
            prev_hash: String::new(),
            hash: "h".into(),
        };
        match dispatch(&store, StoreRequest::AppendAudit(rec)).unwrap() {
            StoreResponse::Unit => {}
            other => panic!("expected Unit, got {other:?}"),
        }
        match dispatch(&store, StoreRequest::ListAudit).unwrap() {
            StoreResponse::Audit(v) => assert!(v.is_empty(), "memory store persists no audit"),
            other => panic!("expected Audit, got {other:?}"),
        }
    }

    /// A constructor error surfaces as STATUS_ERR with the message in the error buffer.
    #[test]
    fn ffi_ctor_error_surfaces() {
        unsafe {
            let mut handle: *mut c_void = ptr::null_mut();
            let mut err: *mut u8 = ptr::null_mut();
            let mut err_len: usize = 0;
            let st = open_impl(
                ptr::null(),
                0,
                &mut handle,
                &mut err,
                &mut err_len,
                ctor_that_errors,
            );
            assert_eq!(st, STATUS_ERR);
            assert!(handle.is_null());
            let msg = std::str::from_utf8(std::slice::from_raw_parts(err, err_len)).unwrap();
            assert_eq!(msg, "nope");
            free_impl(err, err_len);
        }
    }

    /// `auth_abi_version()` reads `busbar_plugin_abi::AUTH_ABI_VERSION` rather than a bare literal,
    /// mirroring `secret_abi_version()`/`hook_abi_version()`. The property that buys: a future bump
    /// of `AUTH_ABI_VERSION` propagates here automatically instead of silently drifting.
    #[test]
    fn auth_abi_version_reads_the_shared_const() {
        assert_eq!(auth_abi_version(), busbar_plugin_abi::AUTH_ABI_VERSION);
    }

    /// Pin the auth payload schema at v2 (1.5.2 login primitives) — the SDK builds v2.
    #[test]
    fn auth_abi_version_is_two() {
        assert_eq!(auth_abi_version(), 2);
    }

    // ── ABI v2 login dispatch (SDK server side) ────────────────────────────────────────────────

    use busbar_api::{
        AuthModule, AuthOutcome, BeginLogin, CompleteLogin, LoginHop, LoginModule, LoginOutcome,
        Principal,
    };
    use busbar_plugin_abi::auth::{
        AuthRequest, AuthResponse, BeginLoginRequest, CompleteLoginRequest,
    };

    /// A verify-only module: implements AuthModule, takes LoginModule's fail-closed defaults.
    struct VerifyOnly;
    impl AuthModule for VerifyOnly {
        fn name(&self) -> &'static str {
            "verify-only"
        }
        fn authenticate(&self, _c: Option<&str>) -> AuthOutcome {
            AuthOutcome::Pass
        }
    }
    impl LoginModule for VerifyOnly {}

    /// A login-capable module: begin → Authorize, complete → Exchange then Identify.
    struct LoginMod;
    impl AuthModule for LoginMod {
        fn name(&self) -> &'static str {
            "login-mod"
        }
        fn authenticate(&self, _c: Option<&str>) -> AuthOutcome {
            AuthOutcome::Pass
        }
    }
    impl LoginModule for LoginMod {
        fn begin_login(&self, req: &BeginLogin) -> LoginOutcome {
            LoginOutcome::Authorize(format!("https://idp/authorize?state={}", req.state))
        }
        fn complete_login(&self, req: &CompleteLogin) -> LoginOutcome {
            if req.token_response.is_some() {
                LoginOutcome::Identify(Principal::from_id("oidc:alice"))
            } else {
                LoginOutcome::Exchange(LoginHop {
                    method: "POST".into(),
                    url: "https://idp/token".into(),
                    form: vec![("client_secret".into(), String::new())],
                    secret_form_field: Some("client_secret".into()),
                    headers: vec![],
                })
            }
        }
    }

    fn begin_req() -> AuthRequest {
        AuthRequest::BeginLogin(BeginLoginRequest {
            redirect_uri: "https://busbar/auth/token".into(),
            state: "st".into(),
            code_challenge: "cc".into(),
            nonce: None,
            scopes: vec![],
        })
    }

    #[test]
    fn dispatch_begin_login_maps_authorize_url() {
        let resp = dispatch_auth(&LoginMod, begin_req());
        match resp {
            AuthResponse::AuthorizeUrl(u) => assert!(u.contains("state=st")),
            other => panic!("expected AuthorizeUrl, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_complete_login_token_exchange() {
        let resp = dispatch_auth(
            &LoginMod,
            AuthRequest::CompleteLogin(CompleteLoginRequest {
                code: Some("authcode".into()),
                ..Default::default()
            }),
        );
        match resp {
            AuthResponse::TokenExchange(hop) => {
                assert_eq!(hop.secret_form_field.as_deref(), Some("client_secret"))
            }
            other => panic!("expected TokenExchange, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_complete_login_identity() {
        let resp = dispatch_auth(
            &LoginMod,
            AuthRequest::CompleteLogin(CompleteLoginRequest {
                token_response: Some(busbar_plugin_abi::auth::HttpResponse {
                    status: 200,
                    body: "{}".into(),
                }),
                ..Default::default()
            }),
        );
        assert!(matches!(resp, AuthResponse::Identity(_)));
    }

    #[test]
    fn login_plugin_handle_preserves_login_capability() {
        // `export_login_plugin!` boxes the ctor's `Box<dyn AuthPlugin>` DIRECTLY as the AuthHandle.
        // A login-capable module keeps its login capability: BeginLogin reaches the real impl.
        let direct: AuthHandle = Box::new(LoginMod);
        assert!(
            matches!(
                dispatch_auth(direct.as_ref(), begin_req()),
                AuthResponse::AuthorizeUrl(_)
            ),
            "export_login_plugin! must NOT mask login: BeginLogin should reach the real LoginModule"
        );
        // Contrast: `export_auth_plugin!` routes through the verify-only adapter, which takes the
        // fail-closed LoginModule default — so the SAME module exported that way is masked to Reject.
        let adapted: AuthHandle = adapt_auth_handle(Box::new(LoginMod));
        assert!(
            matches!(
                dispatch_auth(adapted.as_ref(), begin_req()),
                AuthResponse::Reject
            ),
            "verify-only adapter must mask login (this is why export_login_plugin! bypasses it)"
        );
    }

    #[test]
    fn verify_only_module_defaults_begin_login_reject() {
        // A verify-only module's default LoginModule fails closed on both login ops.
        assert!(matches!(
            dispatch_auth(&VerifyOnly, begin_req()),
            AuthResponse::Reject
        ));
        assert!(matches!(
            dispatch_auth(
                &VerifyOnly,
                AuthRequest::CompleteLogin(CompleteLoginRequest::default())
            ),
            AuthResponse::Reject
        ));
    }
}
