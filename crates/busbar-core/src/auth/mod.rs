// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::fmt;

use axum::{
    body::Body,
    http::{header::AUTHORIZATION, Request, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::config::AuthCfg;
use crate::diagnostics::{
    diag_debug, diag_error, diag_warn, ADMIN_CHAIN_STALLED, ADMIN_FORBIDDEN_SUPPRESSED,
    ADMIN_MODULE_UNRESOLVED, ADMIN_OFFLOAD_SATURATED, AUTH_CHAIN_OPEN_RELAY, AUTH_CHAIN_PANICKED,
    AUTH_OFFLOAD_SATURATED, KEYS_IN_CHAIN_PASSTHROUGH_CONFLICT,
};
use crate::sigv4::{SIGV4_ALGORITHM, X_AMZ_CONTENT_SHA256, X_AMZ_DATE};

/// The two non-`Authorization` headers that native vendor SDKs use to carry their API key:
/// the Anthropic SDK sends `x-api-key`, the Gemini SDK sends `x-goog-api-key`. busbar accepts
/// either as a carrier of the SAME busbar client token / virtual key (validated identically,
/// in constant time, against the same allowlist / governance lookup). Checked AFTER
/// `Authorization: Bearer` (see `extract_client_token`).
const X_API_KEY: &str = "x-api-key";
const X_GOOG_API_KEY: &str = "x-goog-api-key";

/// The header name for the operator admin token carrier (busbar-proprietary surface).
pub(crate) const X_ADMIN_TOKEN: &str = "x-admin-token";
/// The Bearer auth-scheme token (case-insensitive match in `extract_bearer_token`).
const AUTH_SCHEME_BEARER: &str = "bearer";
/// The liveness-probe path, mounted `RouteAuth::None` on every router that serves it (see
/// [`crate::core_routes`]). One constant so the mount and the reserved-path list cannot drift.
pub(crate) const HEALTHZ_PATH: &str = "/healthz";
/// The exact `/api` path (the native-API root — every busbar-own surface mounts under it;
/// see `admin::v1::contract::API_ROOT`).
const ADMIN_PATH: &str = "/api";
/// The `/api/` prefix that all native-API sub-routes share. A path must match ADMIN_PATH exactly
/// OR start with ADMIN_PATH_PREFIX to be treated as an admin-plane request — preventing sibling
/// paths like `/apix/…` from being mis-classified. The WHOLE `/api/` root is admin-classified
/// (fail-closed): a future area (`events`, `metrics`) mounted under `/api/` is admin-guarded by
/// default and must explicitly carve out a weaker class if it ever wants one.
const ADMIN_PATH_PREFIX: &str = "/api/";
/// Fixed dummy secret used when an inbound SigV4 AccessKeyId is unknown: we still run the
/// full HMAC verification so the timing is indistinguishable from a bad-signature rejection
/// (no AccessKeyId-enumeration oracle). The `crate::sigv4` test module references this via
/// `crate::auth::DUMMY_SECRET` rather than maintaining a separate copy.
pub(crate) const DUMMY_SECRET: &str = "AWS4-DUMMY-SECRET-FOR-CONSTANT-TIME-REJECT-PATH";

// The UPSTREAM-credential mode (`upstream_credentials:`) now lives in the neutral contracts crate
// so a plane names it without reaching into busbar-core; re-exported here so every
// crate::auth::UpstreamCreds caller is unchanged.
pub use busbar_api::UpstreamCreds;

/// The caller's bearer token, threaded into request extensions by `auth_middleware` so handlers can
/// forward it upstream in passthrough mode. `None` when no usable bearer token was presented.
#[derive(Clone, Default)]
pub(crate) struct CallerToken(pub(crate) Option<String>);

// MANUAL Debug that NEVER prints the token contents. `CallerToken` wraps a caller credential and is
// threaded into request extensions, so it can be reached by any future code that debug-formats the
// extension map (or a struct that holds it). A derived `Debug` would print the plaintext token — a
// latent credential leak the moment anything debug-logs it. Redact to presence only ("present" /
// "absent"); never the length and never the value, since even the length is a (small) oracle.
impl fmt::Debug for CallerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CallerToken")
            .field(&if self.0.is_some() {
                "<present>"
            } else {
                "<absent>"
            })
            .finish()
    }
}

// The auth CONTRACT — [`Principal`], [`AuthOutcome`], the [`AuthModule`] trait, and the
// constant-time credential primitives — lives in the `busbar-api` crate (the one crate both the
// engine and every plugin build against). Re-exported here so engine-internal paths are unchanged.
pub(crate) use busbar_api::{AuthModule, AuthOutcome, Principal};

/// The whole CHAIN's verdict for one request: admitted-with-identity, admitted-anonymously (the
/// empty-chain open front door), or denied. Distinct from the per-module [`AuthOutcome`] so the
/// middleware can attach the principal (or its absence) to the request.
///
/// NOT `Eq`: the engine-only `resolved` `VirtualKey` is `PartialEq` but not `Eq` (its `Debug` is a
/// hand-written, credential-redacting impl in `busbar-api`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ChainVerdict {
    /// Admitted with identity: the IDENTITY PROVIDER that identified + the principal.
    ///
    /// 1.5.3: `module` carries the PROVIDER NAME (the `identity-providers:` key), not the backing
    /// plugin's own reported name. That is the identity `role_bindings.<name>` binds and
    /// `auth_scope_caps` keys off — so two NAMED providers sharing one plugin module (the whole point
    /// of the named-definition pattern) get INDEPENDENT bindings and ceilings instead of
    /// silently collapsing onto the plugin's single self-reported name.
    Identified {
        module: String,
        principal: Principal,
        /// ENGINE-ONLY resolved governance key. Populated ONLY by engine arms (the built-in `keys`
        /// verifier and the Bedrock SigV4 pre-step), which authenticate a busbar-MINTED credential
        /// and can therefore hand back the enforced [`VirtualKey`]. ALWAYS `None` for a plugin
        /// module: the plugin ABI ([`AuthOutcome`]) can only `Identify(Principal)` — it can never
        /// construct a `VirtualKey`. When `Some`, enforcement rides it directly and the role-binding
        /// synth is skipped (`resolved.or_else(synth)`). This field is never plugin-facing.
        resolved: Option<std::sync::Arc<crate::governance::VirtualKey>>,
    },
    Open,
    Denied,
}

// 1.5.0: the static-token allowlist module is GONE. Data-plane auth is the built-in `keys`
// signed-token verifier (engine-handled on the governance path) plus IdP auth modules; the engine
// holds only the `AuthModule` contract (re-exported above from `busbar-api`).

/// AuthMiddleware holds the resolved auth chain and the upstream-credential mode.
pub(crate) struct AuthMiddleware {
    // 1.5.3: `upstream_creds` is NO LONGER a field here. The mode moved off `auth:` onto the `pools:`
    // section (an all-pools default plus a per-pool override), because whose credential
    // reaches the upstream is a property of the route, not of the inbound auth chain. It now lives on
    // `App::upstream_credentials` (the all-pools default) and `PoolRuntime::upstream_credentials` (the
    // per-pool override), resolved per request by `App::pool_upstream_creds`.
    /// Whether the config chain names the built-in `keys` signed-key verifier. The actual
    /// verification rides the governance virtual-key path (the signed-token verifier is separate);
    /// this flag records the operator's intent for validation and reporting.
    pub(crate) keys_in_chain: bool,
    /// The AUTH CHAIN — the ordered `auth.chain` modules. `validate_token` runs it: the first module
    /// to `Identify` admits, a `Reject` denies, and if every module `Pass`es (no usable credential
    /// matched) a NON-EMPTY chain denies (fail-closed). An EMPTY chain admits unconditionally — the
    /// open front door (`chain: []`, the old none/passthrough). No `AuthMode` — the front-door policy
    /// is the chain shape, the egress policy is `upstream_creds`.
    /// Each entry is `(provider NAME, module)` — the name is the `identity-providers:` key this
    /// chain position referenced, and is what a successful `Identify` reports as
    /// [`ChainVerdict::Identified::module`].
    chain: Vec<(String, Box<dyn AuthModule>)>,
    /// Whether ANY chain module is a loaded PLUGIN — i.e. whether running this chain can perform
    /// blocking work (an FFI/IPC `transport_call`, and behind it whatever the module does: an HTTPS
    /// JWKS fetch, a token-introspection round-trip, a directory lookup). Decided once at build
    /// time because it decides how the request path calls the chain: see
    /// [`AuthMiddleware::run_chain_on_request_path`]. In-process modules are microsecond compares
    /// and are called inline; a plugin chain is offloaded off the reactor.
    has_plugin_module: bool,
}

/// The bound on CONCURRENT offloaded auth-chain calls. `spawn_blocking` on its own is not a fix: a
/// wedged auth plugin would accumulate one parked thread per in-flight request until the process's
/// shared 512-thread blocking pool is exhausted, at which point every other `spawn_blocking` in the
/// engine (the write-behind budget flush, audit appends, config transactions) stalls behind it. This
/// caps auth's share of that pool; requests past the cap wait ASYNCHRONOUSLY (no thread, and the
/// reactor keeps running) rather than adding threads.
const AUTH_OFFLOAD_MAX_INFLIGHT: usize = 64;

/// How long a request will wait for an offload permit before giving up. A chain that cannot even be
/// STARTED within this is a chain that is not verifying anyone, so the request is answered rather
/// than left hanging. Fail-closed: the answer is a denial, the same posture as every other
/// "could not verify" outcome in this file.
const AUTH_OFFLOAD_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The permit pool for [`AUTH_OFFLOAD_MAX_INFLIGHT`]. Process-wide (not per-`AuthMiddleware`) on
/// purpose: the resource being bounded is the process's one shared blocking pool, and a config
/// reload swaps the `AuthMiddleware` while in-flight offloads from the previous one are still
/// running.
static AUTH_OFFLOAD_PERMITS: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(AUTH_OFFLOAD_MAX_INFLIGHT));

/// The bound on CONCURRENT offloaded ADMIN-chain calls — a SEPARATE budget from the data-plane
/// [`AUTH_OFFLOAD_MAX_INFLIGHT`]: a wedged admin IdP (JWKS/introspection I/O in an
/// external `kind: auth` admin plugin) must not starve data-plane auth of its offload permits, and
/// vice versa. Smaller: the admin plane is operator traffic, not customer request volume.
const ADMIN_OFFLOAD_MAX_INFLIGHT: usize = 16;

/// How long an admin request waits for an offload permit (and, separately, for the offloaded chain
/// to finish) before giving up. A chain that cannot even START verifying in this window is answered
/// with a fail-closed denial rather than left to hang a reactor worker. Kept short so a wedged admin
/// IdP never stalls `/healthz` or a concurrent admin request.
const ADMIN_OFFLOAD_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The permit pool for [`ADMIN_OFFLOAD_MAX_INFLIGHT`]. Process-wide for the same reason as the
/// data-plane pool: the bounded resource is the process's one shared blocking pool, and a reload
/// swaps the `App` while prior offloads may still be running.
static ADMIN_OFFLOAD_PERMITS: std::sync::LazyLock<tokio::sync::Semaphore> =
    std::sync::LazyLock::new(|| tokio::sync::Semaphore::new(ADMIN_OFFLOAD_MAX_INFLIGHT));

/// The RESOLVED external admin auth chain (1.5.2 admin-plane OIDC): every non-builtin `admin_auth:`
/// entry, opened as a signed `kind: auth` plugin (same loader/trust pipeline as the data-plane
/// chain and store/secret plugins). Keyed by the config module name — the SAME string
/// `App::admin_chain` names and `role_bindings.<module>` binds. `admin-tokens` is deliberately
/// absent (it is an engine arm dispatched inline). Held behind an `Arc` on the `App` snapshot.
pub(crate) struct AdminAuthChain {
    pub(crate) modules: std::collections::HashMap<String, Box<dyn AuthModule>>,
    /// Whether ANY resolved admin module is a loaded plugin — i.e. whether running the admin chain
    /// can block (FFI/JWKS/introspection). Decided once at build; gates the off-reactor offload.
    pub(crate) has_plugin: bool,
}

impl fmt::Debug for AdminAuthChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminAuthChain")
            .field("modules", &self.modules.keys().collect::<Vec<_>>())
            .field("has_plugin", &self.has_plugin)
            .finish()
    }
}

impl AdminAuthChain {
    /// The empty chain (admin-tokens-only, or the open dev posture) — no external admin plugin, so
    /// the admin chain always runs inline. The default for tests and builtin-only builds.
    #[cfg(any(test, feature = "test-support"))]
    pub fn empty() -> Self {
        Self {
            modules: std::collections::HashMap::new(),
            has_plugin: false,
        }
    }

    /// Resolve every NON-BUILTIN `admin_auth:` entry as a `kind: auth` plugin via the validated
    /// `registry` — the exact trust/load pipeline the data-plane chain and store/secret plugins use.
    /// `admin-tokens` (an engine arm) and the compiled-in test stand-ins are skipped (they dispatch
    /// inline in `run_admin_chain`). SecretRef-typed settings resolve BEFORE the config crosses the
    /// ABI (ADR-0010). FAIL-CLOSED: a configured admin module that cannot load is a HARD boot/reload
    /// error, never a silently-dropped module. Runs at boot AND reload (inside `build_app_from_config`).
    pub(crate) fn build(
        cfg: &AuthCfg,
        registry: &busbar_plugin_loader::PluginRegistry,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        let mut modules: std::collections::HashMap<String, Box<dyn AuthModule>> =
            std::collections::HashMap::new();
        let mut has_plugin = false;
        for entry in &cfg.admin_auth {
            match entry.module.as_str() {
                crate::config::ADMIN_TOKENS_MODULE => {}
                // TEST-ONLY inline admin stand-ins (dispatched by name in `run_admin_chain`); never
                // resolved as plugins. Compiled out of release binaries.
                #[cfg(test)]
                "test-scope-module" | "test-groups-module" => {}
                other => {
                    let name = entry.name.as_str();
                    let resolved =
                        crate::config::secret::resolve_settings(&entry.settings, secret_resolver)
                            .map_err(|e| format!("identity-providers.{name} settings: {e}"))?;
                    let cfg_json = serde_json::Value::Object(resolved).to_string();
                    let module = registry.open_auth(other, &cfg_json).map_err(|e| {
                        format!(
                            "auth.admin_auth provider '{name}' (module '{other}') could not be \
                             loaded as a `kind: auth` plugin: {e}"
                        )
                    })?;
                    // KEYED BY PROVIDER NAME (1.5.3): `run_admin_chain` dispatches by the same name
                    // `admin_chain` lists and `role_bindings.<name>` binds, so two named providers
                    // sharing one module stay distinct admin identities.
                    modules.insert(name.to_string(), module);
                    has_plugin = true;
                }
            }
        }
        Ok(Self {
            modules,
            has_plugin,
        })
    }
}

impl fmt::Debug for AuthMiddleware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthMiddleware")
            .field("keys_in_chain", &self.keys_in_chain)
            .field("chain_len", &self.chain.len())
            .finish()
    }
}

impl AuthMiddleware {
    /// Build the auth chain by RESOLVING the configured module entries against the plugin
    /// `registry`. The built-in `keys` (signed-key verifier) is engine-handled: virtual keys
    /// authenticate on the governance path, not through a boxed module, so its entry sets a flag
    /// rather than a module. Any OTHER name is resolved as a `kind: auth` PLUGIN via
    /// [`PluginRegistry::open_auth`] (the exact trust/load pipeline store & secret plugins use) and
    /// boxed into the chain. FAIL-CLOSED: a configured auth module that cannot be loaded (missing
    /// tarball, wrong kind, untrusted under the running policy, or a `dlopen`/ABI failure) is a
    /// HARD boot error — never a silently-dropped module that would leave the front door open.
    /// `--validate`/`plugins_preflight` catches most of these manifest-only, so this is the
    /// belt-and-suspenders load-time gate. An EMPTY chain is the open front door (none/passthrough).
    ///
    /// The plugin's config JSON is its chain entry's opaque `settings:` map (verbatim, exactly like
    /// a store/secret plugin's `settings:`). The chain module's RUNTIME identity is `module.name()`
    /// (the name the loaded plugin reports over the ABI), which is what `role_bindings.<module>` and
    /// `auth.modules.<module>` caps key off — not the config alias.
    pub(crate) fn new(
        cfg: &AuthCfg,
        registry: &busbar_plugin_loader::PluginRegistry,
        secret_resolver: &crate::config::secret::SecretResolver,
    ) -> Result<Self, String> {
        let mut keys_in_chain = false;
        let mut has_plugin_module = false;
        let mut chain: Vec<(String, Box<dyn AuthModule>)> = Vec::new();
        for entry in &cfg.chain {
            match entry.module.as_str() {
                crate::config::KEYS_MODULE => {
                    keys_in_chain = true;
                }
                // TEST-ONLY external-module stand-in for the DATA-PLANE chain (the admin chain has
                // its own): `grp:<role>` identifies as a principal carrying that role, so the
                // governance re-key is e2e-testable. Compiled out of release binaries entirely.
                #[cfg(test)]
                "test-groups-module" => {
                    chain.push((entry.name.clone(), Box::new(TestGroupsModule)))
                }
                // TEST-ONLY stand-in for a real OIDC auth plugin: it verifies (here, pretends to
                // verify) an issuer's signature and identifies the bearer. It is deliberately
                // AUDIENCE-BLIND, because that is what the module ABI makes every such plugin —
                // `AuthOutcome` has no shape for "and it was minted for you". Without a module of
                // this shape in the tree, no test can tell an audience check that runs from one
                // that does not: a keys-only chain refuses a foreign token anyway, for a different
                // reason, and every assertion about the plane boundary passes vacuously.
                #[cfg(any(test, feature = "test-support"))]
                "test-idp-module" => chain.push((entry.name.clone(), Box::new(TestIdpModule))),
                other => {
                    // A `kind: auth` PLUGIN: resolve + open over the signed hybrid ABI (same trust
                    // posture, same loader as store/secret). The `settings:` map is the plugin's
                    // opaque config, pushed verbatim. FAIL-CLOSED — surface the load error so boot
                    // (or an apply/reload) aborts rather than silently dropping the module.
                    // Resolve any SecretRef-typed setting (e.g. a `licenseKey`) against the secret
                    // store BEFORE the settings cross the ABI (ADR-0010). FAIL-CLOSED: an
                    // unresolvable ref aborts the chain build rather than handing the plugin a
                    // dangling reference.
                    let resolved =
                        crate::config::secret::resolve_settings(&entry.settings, secret_resolver)
                            .map_err(|e| format!("auth.chain module '{other}' settings: {e}"))?;
                    let cfg_json = serde_json::Value::Object(resolved).to_string();
                    let module = registry.open_auth(other, &cfg_json).map_err(|e| {
                        format!(
                            "auth.chain module '{other}' could not be loaded as a `kind: auth` \
                             plugin: {e}"
                        )
                    })?;
                    chain.push((entry.name.clone(), module));
                    has_plugin_module = true;
                }
            }
        }

        if chain.is_empty() && !keys_in_chain {
            diag_warn!(
                AUTH_CHAIN_OPEN_RELAY,
                "auth.chain is empty (open relay) - only acceptable for dev; reject in production"
            );
        }

        Ok(Self {
            keys_in_chain,
            chain,
            has_plugin_module,
        })
    }

    /// TEST-ONLY convenience: build the chain against an EMPTY plugin registry (only builtins +
    /// the compiled-in `test-groups-module` resolve). Panics on a plugin-name entry — a test that
    /// needs a real `kind: auth` plugin builds a registry and calls [`new`] directly. Keeps the
    /// dozens of builtin-only test call sites from threading a registry + `.unwrap()` each.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new_builtin(cfg: &AuthCfg) -> Self {
        Self::new(
            cfg,
            &busbar_plugin_loader::PluginRegistry::empty(),
            &crate::config::secret::SecretResolver::builtins_only(),
        )
        .expect("builtin-only auth chain never fails to construct")
    }

    /// The ordered names of the auth chain's modules (`module.name()` for each). For the Admin API
    /// v1 plugin catalog — reporting which compiled-in/external auth modules are ACTIVE (in the
    /// chain). Never a secret: a module name is a plugin identifier, not a credential.
    pub(crate) fn chain_names(&self) -> Vec<&'static str> {
        self.chain.iter().map(|(_, m)| m.name()).collect()
    }

    /// Whether the front door is OPEN — an empty auth chain admits every request unconditionally
    /// (the old `none`/`passthrough`). Governance, when enabled, supersedes this.
    pub(crate) fn is_open(&self) -> bool {
        self.chain.is_empty()
    }

    /// Run the auth chain over the presented candidate credential. Empty chain -> admit with NO
    /// principal (the `none`/`passthrough` open front door — anonymous). Otherwise the first
    /// `Identify` admits with its [`Principal`], a `Reject` denies, and all-`Pass` (no module
    /// matched a presented credential) denies — fail-closed for a configured chain. Constant-time
    /// within each module; the loop order is config order.
    pub(crate) fn run_chain(&self, candidate: Option<&str>) -> ChainVerdict {
        self.run_chain_cached(candidate, None, None, None)
    }

    /// [`run_chain`] with the CREDENTIAL CACHE consulted around each `cacheable()` module.
    /// The cache stores the module's RAW verdict; the `allowed_groups:`
    /// intersection is applied AFTER retrieval, so a config change to the caps takes effect
    /// immediately even for cached identities. In-process modules report `cacheable() == false`
    /// and never touch the cache (caching a microsecond compare only widens revocation).
    /// `expected_aud` is the AUDIENCE the plane this request arrived on requires of a busbar-signed
    /// token — `None` for the residual data plane (which rejects any token that carries one), and
    /// `Some(uri)` for an audience-bound ingress (which rejects a token whose audience is absent or
    /// different). It is threaded here rather than read from a handler because the check belongs to
    /// the VERIFIER: a route added to an audience-bound plane later inherits it and cannot forget.
    pub(crate) fn run_chain_cached(
        &self,
        candidate: Option<&str>,
        cache: Option<&crate::auth_cache::CredentialCache>,
        gov: Option<&crate::governance::GovState>,
        expected_aud: Option<&str>,
    ) -> ChainVerdict {
        // The OPEN front door: no boxed chain modules AND no built-in `keys` engine arm → admit
        // anonymously. `keys_in_chain` (an engine arm, not a boxed module) keeps the door CLOSED
        // even though `self.chain` may be empty, so `chain:[keys]` runs the keys arm below rather
        // than short-circuiting to `Open`.
        if self.chain.is_empty() && !self.keys_in_chain {
            return ChainVerdict::Open;
        }
        let now = crate::store::now();
        // `Pass` puts are BUFFERED, not admitted, until the chain identifies. An all-`Pass` chain
        // ends `Denied` (below), so admitting them eagerly let an unauthenticated caller fill the
        // cache with entries that then evict real `Identify` rows under the oldest-inserted
        // eviction rule (`auth_cache.rs:106-119`). Committing only on the `Identified` return means
        // unauthenticated traffic causes no admissions at all. A cache HIT is never re-`put`: doing
        // so would refresh its TTL and quietly extend the revocation window.
        let mut pending_pass: Vec<&str> = Vec::new();
        // The FLUSH GENERATION as of BEFORE the first module is consulted. Every `put` below carries
        // it, so an admin cache flush that lands anywhere inside this chain run drops every verdict
        // the run computed — the run's verdicts all predate the flush. Without this, an
        // authentication in flight across `POST /admin/auth/cache/flush` re-inserted its PRE-flush
        // allow verdict after the flush returned `200 {"flushed": N}`, and the "instant revocation"
        // the endpoint documents revoked nothing for up to an hour. See `auth_cache::CacheGeneration`.
        let cache_gen = cache.map(crate::auth_cache::CredentialCache::generation);
        for (provider, module) in &self.chain {
            let cache_here = match (cache, candidate) {
                (Some(c), Some(cred)) if module.cacheable() => Some((c, cred)),
                _ => None,
            };
            // CACHE KEY is the PROVIDER NAME, not the plugin's self-reported name (1.5.3): two named
            // providers backed by the same module are DIFFERENT verifiers with different settings, so
            // sharing a cache row between them would let one provider's verdict admit the other's
            // credential. The name is the instance, so the cache key must be the name.
            let outcome = match cache_here.and_then(|(c, cred)| c.get(provider, cred, now)) {
                Some(hit) => hit,
                None => {
                    let o = module.authenticate(candidate);
                    if cache_here.is_some() && matches!(o, AuthOutcome::Pass) {
                        pending_pass.push(provider.as_str());
                    }
                    o
                }
            };
            match outcome {
                AuthOutcome::Identify(principal) => {
                    if let (Some(c), Some(cred), Some(g)) = (cache, candidate, cache_gen) {
                        for name in &pending_pass {
                            c.put(name, cred, &AuthOutcome::Pass, now, g);
                        }
                        if cache_here.is_some() {
                            c.put(
                                provider,
                                cred,
                                &AuthOutcome::Identify(principal.clone()),
                                now,
                                g,
                            );
                        }
                    }
                    // No per-module role filter: the NESTED role_bindings table IS the allowlist -
                    // a role this module asserts grants nothing unless
                    // `role_bindings.<this module>.<role>` binds it. A PLUGIN module never resolves
                    // a VirtualKey (the ABI can't carry one) → `resolved: None`.
                    return ChainVerdict::Identified {
                        module: provider.clone(),
                        principal,
                        resolved: None,
                    };
                }
                AuthOutcome::Reject => return ChainVerdict::Denied,
                AuthOutcome::Pass => {}
            }
        }
        // The built-in `keys` ENGINE ARM — a sibling to the boxed plugin modules above, run AFTER
        // them (a plugin that positively identified already returned). It is NOT a `Box<dyn
        // AuthModule>` on purpose: the module ABI ([`AuthOutcome`]) can only `Identify(Principal)`,
        // never hand back a resolved `VirtualKey`, so vkey resolution lives here where it can.
        // CACHE-EXEMPT: the arm never consults or writes the `CredentialCache` (revocation today is
        // per-request `verify_token` + a short denylist sync; caching a vkey verdict would widen the
        // revocation window to the cache TTL).
        if self.keys_in_chain {
            return keys_arm_verdict(gov, candidate, now, expected_aud);
        }
        ChainVerdict::Denied
    }

    /// THE REQUEST-PATH ENTRY POINT for the data-plane auth chain — the one place `auth_middleware`
    /// calls it, and the reason it is not just `run_chain_cached`.
    ///
    /// A chain module can be a loaded PLUGIN, and a plugin's `authenticate` is a synchronous FFI
    /// call that may do real I/O — the shipped OIDC module fetches JWKS over blocking HTTPS with a
    /// 10s timeout, and any introspection/directory module is a network round-trip. Called inline,
    /// that runs on a Tokio worker thread inside an `async fn`: a slow IdP parks a worker per
    /// in-flight request, and once every worker is parked NOTHING in the process is polled — not
    /// other requests, not the admin plane, not `/healthz` (which is exempt from this chain but
    /// still needs a worker to run at all). The node then fails its liveness probe and is killed, on
    /// account of an identity provider that most of the stalled traffic never even used.
    ///
    /// So a plugin chain is OFFLOADED to the blocking pool, and BOUNDED there
    /// ([`AUTH_OFFLOAD_MAX_INFLIGHT`]) so a wedged plugin cannot drain the pool the rest of the
    /// engine shares. An all-in-process chain (or an empty one) is called inline: those modules are
    /// microsecond constant-time compares, and paying a `spawn_blocking` hop per request to protect
    /// against work that cannot block would be a pure regression.
    ///
    /// FAIL-CLOSED at every failure: a panicking plugin (join error) and an offload that cannot be
    /// started are both `Denied`, never an admit.
    pub(crate) async fn run_chain_on_request_path(
        auth: &std::sync::Arc<AuthMiddleware>,
        cache: &std::sync::Arc<crate::auth_cache::CredentialCache>,
        candidate: Option<String>,
        gov: Option<std::sync::Arc<crate::governance::GovState>>,
        expected_aud: Option<String>,
    ) -> ChainVerdict {
        // Open ONLY when there are no boxed modules AND no `keys` engine arm (see `run_chain_cached`).
        if auth.chain.is_empty() && !auth.keys_in_chain {
            return ChainVerdict::Open;
        }
        if !auth.has_plugin_module {
            // All-in-process (boxed test module and/or the keys arm): no plugin can block, so run
            // inline. The keys arm needs the governance handle to verify a busbar-signed key.
            //
            // blocking-ffi-lint: allow — NO PLUGIN IS IN THE CHAIN on this arm, so `run_chain_cached`
            // has nothing to make an FFI call into. `has_plugin_module` is set `true` at exactly one
            // place — `AuthMiddleware::new`'s `other =>` arm (this file, the `has_plugin_module =
            // true;` immediately after `registry.open_auth`) — and every other arm either sets
            // `keys_in_chain` (the engine-side signed-key verifier, a constant-time compare) or
            // pushes the `#[cfg(test)]` in-process stand-in. So `!has_plugin_module` means the chain
            // holds no dlopened module at all.
            return auth.run_chain_cached(
                candidate.as_deref(),
                Some(cache),
                gov.as_deref(),
                expected_aud.as_deref(),
            );
        }
        // Warn-once transition latch: a saturated auth offload persists per request until the wedged
        // plugin recovers, and the data plane is high-cadence, so warn on the TRANSITION into the
        // saturated state and hold subsequent denials at debug. Reset when a permit is acquired again.
        static AUTH_OFFLOAD_SATURATED_WARNED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        let permit = match tokio::time::timeout(AUTH_OFFLOAD_WAIT, AUTH_OFFLOAD_PERMITS.acquire())
            .await
        {
            Ok(Ok(p)) => {
                AUTH_OFFLOAD_SATURATED_WARNED.store(false, std::sync::atomic::Ordering::Relaxed);
                p
            }
            // Timed out waiting, or the semaphore was closed. Either way the chain never ran, so
            // the credential is unverified — deny.
            _ => {
                if !AUTH_OFFLOAD_SATURATED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    diag_warn!(
                        AUTH_OFFLOAD_SATURATED,
                        "auth chain offload could not be started within {AUTH_OFFLOAD_WAIT:?} \
                     ({AUTH_OFFLOAD_MAX_INFLIGHT} already in flight); an auth plugin is not \
                     returning. Denying (fail-closed) rather than admitting unverified."
                    );
                } else {
                    diag_debug!(
                        AUTH_OFFLOAD_SATURATED,
                        "auth chain offload could not be started within {AUTH_OFFLOAD_WAIT:?} \
                     ({AUTH_OFFLOAD_MAX_INFLIGHT} already in flight); an auth plugin is not \
                     returning. Denying (fail-closed) rather than admitting unverified."
                    );
                }
                return ChainVerdict::Denied;
            }
        };
        let (auth, cache) = (auth.clone(), cache.clone());
        let joined = tokio::task::spawn_blocking(move || {
            let verdict = auth.run_chain_cached(
                candidate.as_deref(),
                Some(&cache),
                gov.as_deref(),
                expected_aud.as_deref(),
            );
            // The permit is released when the blocking work is DONE, not when the awaiting future
            // is dropped — a cancelled request must not hand its slot to another request while the
            // plugin thread it started is still wedged.
            drop(permit);
            verdict
        })
        .await;
        // Warn-once transition latch on the panic path: a panicking chain recurs per request until
        // the plugin bug is fixed. Warn on the transition; hold the rest at debug; reset on a clean join.
        static AUTH_CHAIN_PANICKED_WARNED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        match joined {
            Ok(verdict) => {
                AUTH_CHAIN_PANICKED_WARNED.store(false, std::sync::atomic::Ordering::Relaxed);
                verdict
            }
            Err(e) => {
                if !AUTH_CHAIN_PANICKED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    diag_warn!(AUTH_CHAIN_PANICKED, error = %e, "auth chain panicked; denying (fail-closed)");
                } else {
                    diag_debug!(AUTH_CHAIN_PANICKED, error = %e, "auth chain panicked; denying (fail-closed)");
                }
                ChainVerdict::Denied
            }
        }
    }

    /// Constant-time string comparison — the single timing-safe primitive, now provided by the
    /// `busbar-api` contract crate (plugins compare with the SAME primitive). Kept as an associated
    /// fn so engine call sites are unchanged.
    pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
        busbar_api::constant_time_eq(a, b)
    }

    /// Extract the token from an `Authorization: Bearer <token>` header (scheme match is
    /// case-insensitive). Splits on the first space rather than byte-slicing, so a malformed header
    /// with a multibyte character in the scheme position can't panic on a UTF-8 boundary.
    pub(crate) fn extract_bearer_token(auth_header: &str) -> Option<String> {
        let (scheme, token) = auth_header.split_once(' ')?;
        if scheme.eq_ignore_ascii_case(AUTH_SCHEME_BEARER) && !token.is_empty() {
            Some(token.to_string())
        } else {
            None
        }
    }

    /// Extract the busbar client token from whichever scheme the caller used, in a FIXED
    /// precedence order: `Authorization: Bearer <t>` first, then `x-api-key: <t>` (Anthropic SDK),
    /// then `x-goog-api-key: <t>` (Gemini SDK). The `x-api-key`/`x-goog-api-key` values are the raw
    /// token (no scheme prefix); an empty value is treated as absent so a present-but-blank header
    /// does not mask a token in a lower-precedence carrier. The returned token is validated
    /// identically and in constant time regardless of which header carried it.
    ///
    /// Bedrock SDKs authenticate with inbound AWS SigV4, NOT a bearer-style token, so this extractor
    /// deliberately does NOT read any `x-amz-*` / SigV4 `Authorization` header — a non-Bearer
    /// `Authorization` (AWS4-HMAC-SHA256 or Basic) falls through to the vendor carriers and otherwise
    /// yields `None` here. Inbound SigV4 is now handled SEPARATELY, under governance, by
    /// `verify_bedrock_sigv4` (the MinIO/S3-compatible model: an AWS-style access-key-id + secret
    /// access key issued per virtual key, whose signature busbar verifies via `crate::sigv4`). On a
    /// successful verify the same `GovCtx` a bearer auth attaches is attached, so Bedrock ingress now
    /// receives full virtual-key governance under `token`/governance mode — it no longer requires
    /// `passthrough`. This token path itself is unchanged.
    pub(crate) fn extract_client_token(req: &Request<Body>) -> Option<String> {
        let header_str = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };

        if let Some(t) = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(Self::extract_bearer_token)
        {
            return Some(t);
        }
        if let Some(t) = header_str(X_API_KEY).filter(|t| !t.is_empty()) {
            return Some(t);
        }
        if let Some(t) = header_str(X_GOOG_API_KEY).filter(|t| !t.is_empty()) {
            return Some(t);
        }
        None
    }

    /// Validate the request's token by running the AUTH CHAIN. `token` accepts a credential extracted
    /// from ANY supported carrier (see `extract_client_token`); the comparison is identical and
    /// constant-time regardless of which header carried it. No `AuthMode` branch here — the front-door
    /// policy is entirely encoded in the chain shape (`[]` admits, `[tokens]` validates).
    // Thin admit/deny view over `run_chain` — kept for tests and callers that don't need the
    // principal. The middleware itself calls `run_chain` (it attaches the principal).
    #[allow(dead_code)]
    pub(crate) fn validate_token(&self, token: Option<&str>) -> bool {
        !matches!(self.run_chain(token), ChainVerdict::Denied)
    }
}

/// The built-in `keys` ENGINE-ARM verdict for one request (see `run_chain_cached`). Verifies a
/// busbar-MINTED signed virtual key against governance and, on success, hands back the ENFORCED
/// [`VirtualKey`] in [`ChainVerdict::Identified::resolved`] — the one place a data-plane verdict
/// carries a resolved key (a plugin module never can). Outcomes, preserving today's behavior:
/// - no credential presented → `Denied` (fail-closed; the arm is the terminal authenticator).
/// - no governance handle → `Denied` (cannot verify a busbar-signed key).
/// - a present token that resolves to an ENABLED key → `Identified { resolved: Some(key) }`.
/// - a present token that does NOT resolve to an enabled key (unknown / expired / rotated /
///   REVOKED / **disabled**) → `Denied`. A disabled key is REJECTED here, never handed to the
///   role-binding synth to be silently re-admitted (`verify_token` already filters non-enabled keys
///   to `None`, so this arm can only ever return `resolved: Some(enabled_key)` or a denial — it
///   never emits `Identified { resolved: None }`).
fn keys_arm_verdict(
    gov: Option<&crate::governance::GovState>,
    candidate: Option<&str>,
    now: u64,
    expected_aud: Option<&str>,
) -> ChainVerdict {
    let Some(token) = candidate.filter(|t| !t.is_empty()) else {
        return ChainVerdict::Denied;
    };
    let Some(gov) = gov else {
        return ChainVerdict::Denied;
    };
    // THE PLANE BOUNDARY, enforced in the verifier (1.6.0 P1). `expected_aud` is `None` on the
    // residual data plane, and the verifier then rejects any token that CARRIES an audience — an
    // MCP token is inadmissible on the LLM plane. On an audience-bound ingress it is that plane's
    // canonical URI, and the verifier rejects a token whose audience is absent or different: the
    // RFC 8707 confused-deputy defence, which is what stops a token an agent legitimately obtained
    // for some other resource from being spendable against busbar's pools and budget.
    match gov.verify_token(token, now, expected_aud) {
        Some(key) => ChainVerdict::Identified {
            module: crate::config::KEYS_MODULE.to_string(),
            principal: principal_from_vkey(&key),
            resolved: Some(key),
        },
        None => ChainVerdict::Denied,
    }
}

/// The data-plane [`Principal`] for a resolved [`VirtualKey`]: id = the stable key id, name = its
/// label, no roles (a vkey is a direct grant, not a group membership resolved through
/// role_bindings). Shared by the bearer `keys` arm and the Bedrock SigV4 pre-step so both attach an
/// identical principal.
fn principal_from_vkey(key: &crate::governance::VirtualKey) -> Principal {
    Principal {
        id: key.id.clone(),
        name: Some(key.name.clone()),
        roles: Vec::new(),
        ttl_secs: None,
    }
}

/// The ingress a request targets — which plane by MOUNT, and in which wire dialect — resolved from
/// the path and the deployment's mount table. Auth runs BEFORE routing, so those two are the only
/// signals available for shaping a native 401 envelope.
///
/// A THIN delegation to the CANONICAL `crate::plane::PlaneDispatch::ingress_of`, which is the ONE
/// resolver: a private copy here (there was one, and before that a wire-identical duplicate of the
/// path classifier) is the exact indistinguishability tell where one handler shapes `/model/foo/bar`
/// as bedrock and another as openai — or where auth answers a MOUNTED MCP path in an OpenAI
/// envelope because it could not see the mount.
fn ingress_for_path(app: &crate::state::App, path: &str) -> crate::plane::Ingress {
    app.planes.ingress_of(path)
}

/// The auth-failure wire message for an inferred ingress protocol — a THIN delegation to the
/// CANONICAL `crate::proto::vendor_auth_failure_message` so the auth path and any other site that
/// shapes a native bad-credential body cannot drift on the vendor copy. The string lands verbatim in
/// the native error body (`error.message` for anthropic/openai/gemini/responses, the bare top-level
/// `message` for cohere, the `message` field alongside `__type` for bedrock — every writer echoes
/// it unchanged), so it MUST read like the copy the REAL vendor returns for a bad/missing credential
/// and carry NO busbar-internal vocabulary ("virtual key", "client token", "allowlist", "disabled",
/// "passthrough", …). The wording is chosen PURELY from the inferred protocol and is deliberately
/// independent of WHY auth failed (missing token vs. wrong token vs. disabled virtual key vs.
/// admin-token mismatch) — surfacing that distinction on the wire is itself an oracle. Call sites
/// therefore pass no reason string.
fn vendor_auth_failure_message(proto: &str) -> &'static str {
    crate::proto::vendor_auth_failure_message(proto)
}

/// The HTTP status and protocol-agnostic error `kind` a bad/missing credential yields for an
/// inferred ingress protocol. The pair is chosen to MATCH what the genuine vendor returns for a
/// bad API key, because the status code and the writer-mapped `error.type`/`error.status` are both
/// deterministic protocol tells a native SDK keys its typed exception off:
/// - bedrock → HTTP 403 + "auth": a real SigV4 rejection is 403 AccessDenied (NOT 401).
/// - gemini  → HTTP 400 + "invalid_request_error": the Generative Language API does NOT return
///   401/UNAUTHENTICATED for a bad API key; it returns HTTP 400 with `error.status:
/// "INVALID_ARGUMENT"` (google.rpc.Code; the gemini writer maps `invalid_request_error` →
///   INVALID_ARGUMENT and echoes `code: 400`). A 401/UNAUTHENTICATED body would be a tell the
///   google-genai SDK never sees from real Google on the bad-key path.
/// - openai / responses → HTTP 401 + "authentication_error": the genuine OpenAI/Responses bad-key
///   401 body carries `error.code: "invalid_api_key"`, and the official SDKs surface that value as
///   `AuthenticationError.code`. Emitting `code: null` is a deterministic proxy tell a native SDK
///   keys its typed-exception comparison off. The openai/responses writers pair
///   `code: "invalid_api_key"` ONLY with `error.type: "authentication_error"` (see
///   `proto::openai_family::bearer_error_code`); the alternate `invalid_request_error` type maps
///   to `code: null`. We therefore pass `authentication_error` here so the wire body carries the
///   real `code: "invalid_api_key"` pairing — matching the modern OpenAI bad-key shape the writers
///   document — rather than the `code: null` tell.
/// - anthropic / cohere / unknown → HTTP 401 + "authentication_error": the standard
///   bad-credential shape for those vendors.
///
/// Not a disposition/breaker match, so an unknown future proto falls back to the Anthropic-family
/// 401 authentication_error, keeping the request path panic-free.
///
/// Thin wrapper: dispatches through `ProtocolWriter::auth_failure_status_and_kind` so the
/// per-protocol decision lives in the writer vtable, not in this agnostic function. `BedrockWriter`
/// overrides to (403, "auth"); `GeminiWriter` to (400, "invalid_request_error"); all others use the
/// default (401, "authentication_error"). An unknown future proto falls back to the default.
pub(crate) fn auth_failure_status_and_kind(proto: &str) -> (StatusCode, &'static str) {
    crate::proto::decl_for(proto)
        .map(|d| d.auth_failure_status_and_kind)
        .unwrap_or((StatusCode::UNAUTHORIZED, crate::proxy::KIND_AUTHENTICATION))
}

/// Build an auth-failure response carrying the inferred ingress protocol's NATIVE error envelope.
/// Auth runs before routing, so the protocol is inferred from the request path. A native vendor SDK
/// hitting busbar in `token`/governance mode with a bad credential gets the vendor's JSON error
/// shape (`application/json`) instead of a bare `text/plain` 401 — removing a deterministic proxy
/// tell. Falls back to the generic envelope for an unknown path.
///
/// The wire `message` comes from `vendor_auth_failure_message(proto)` — vendor-plausible copy keyed
/// solely off the inferred protocol — NOT from the call site. Callers must never thread a
/// busbar-internal reason ("invalid or disabled virtual key", "unauthorized", "admin unauthorized")
/// onto the wire: that vocabulary is a protocol tell and an auth-model disclosure, and the
/// invalid-vs-disabled / missing-vs-wrong distinction is itself an oracle. A caller may still log
/// the real reason server-side; it just never reaches the client body.
///
/// Status and the writer `kind` are protocol-shaped too (see `auth_failure_status_and_kind`): a real
/// AWS Bedrock SigV4 auth failure returns HTTP 403 (not 401) and carries `x-amzn-ErrorType` /
/// `x-amzn-RequestId`; a real Gemini bad-key returns HTTP 400 INVALID_ARGUMENT (not 401
/// UNAUTHENTICATED); the other vendors use 401 authentication_error. (Bedrock ingress is documented
/// as unsupported under token/governance mode, so that branch is only reachable under a
/// misconfiguration — but when it is reached, the envelope must still match native AWS.)
///
/// No unwrap / expect / panic on this request path: `ingress_error` degrades a serialization failure
/// to a generic JSON object internally.
///
/// The envelope is built by `crate::ingress::native::native_error`, the single source of truth for
/// shaping an answer from a resolved ingress: on the residual it selects the protocol writer, sets
/// `application/json` and attaches the Bedrock `x-amzn-RequestId` / `x-amzn-errortype` headers via
/// the `ProtocolWriter::attach_error_response_headers` vtable method; on a MOUNTED plane it answers
/// in that plane's own dialect instead of handing a JSON-RPC client a vendor envelope. Using the
/// shared builder means the auth path, the forward path, and the route/fallback path CANNOT diverge
/// on error shape or headers. Bedrock's auth-failure modeled exception is `AccessDeniedException`;
/// the header attach derives the same `x-amzn-errortype` from the `kind` we pass
/// (`auth` → `AccessDeniedException`), so the wire body `__type` and the header agree.
fn unauthorized_response(app: &crate::state::App, path: &str) -> Response {
    let ingress = ingress_for_path(app, path);
    // The dialect names the VENDOR whose bad-credential status, `kind` and copy a client expects. A
    // mounted plane names its own wire format, which has no vendor writer, so both lookups take
    // their neutral defaults (401 + `authentication_error`) and the body is JSON-RPC's — the same
    // two facts a plane-specific 401 would have had to restate.
    let dialect = crate::ingress::native::envelope_dialect(ingress);
    let message = vendor_auth_failure_message(dialect);
    let (status, kind) = auth_failure_status_and_kind(dialect);
    crate::ingress::native::native_error(ingress, status, kind, message)
}

/// Extract the operator admin token from the `x-admin-token` header, treating a present-but-blank
/// value as ABSENT. This mirrors the empty-filter (`.filter(|t| !t.is_empty())`) that
/// `extract_client_token` applies to the `x-api-key` / `x-goog-api-key` carriers, closing the same
/// class of empty-credential bug on the admin carrier: a blank header never reaches the constant-time
/// compare below, so it cannot match even if a future change paired the configured admin token with
/// an empty string (the empty-token collision the `GovState` constructor guard in `governance.rs` is
/// separately meant to prevent — that guard is not owned here). `None` when the header is absent,
/// non-UTF-8, or blank.
fn extract_admin_header_token(req: &Request<Body>) -> Option<String> {
    req.headers()
        .get(X_ADMIN_TOKEN)
        .and_then(|v| v.to_str().ok())
        .filter(|t| !t.is_empty())
        .map(String::from)
}

/// Request-extension carrier for the authenticated [`Principal`]. Relocated to `busbar-api` in
/// Phase-B B0-a (beside [`Principal`]) so an extracted plane crate names it without a path back to
/// core; re-exported here so every in-core call site (`crate::auth::AuthPrincipal`) is unchanged.
/// Its `actor_id()` accessor and tuple field were promoted from `pub(crate)` to `pub` in the move —
/// the type is now cross-crate, but it still never carries the credential.
pub use busbar_api::AuthPrincipal;

/// TEST-ONLY data-plane module (see the `test-groups-module` chain arm): credential `grp:<g>`
/// identifies as `test:<g>` carrying exactly that group; anything else defers (`Pass`).
#[cfg(test)]
struct TestGroupsModule;

#[cfg(test)]
impl AuthModule for TestGroupsModule {
    fn name(&self) -> &'static str {
        "test-groups-module"
    }
    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome {
        match candidate.and_then(|t| t.strip_prefix("grp:")) {
            Some(group) => {
                let mut p = Principal::from_id(format!("test:{group}"));
                p.roles = vec![group.to_string()];
                AuthOutcome::Identify(p)
            }
            None => AuthOutcome::Pass,
        }
    }
}

/// TEST-ONLY data-plane module standing in for an operator's OIDC auth plugin: it identifies ANY
/// non-empty credential and asks nothing about audience, exactly as the plugin ABI forces a real one
/// to. See the `test-idp-module` chain arm for why the tree needs one.
#[cfg(any(test, feature = "test-support"))]
struct TestIdpModule;

#[cfg(any(test, feature = "test-support"))]
impl AuthModule for TestIdpModule {
    fn name(&self) -> &'static str {
        "test-idp-module"
    }
    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome {
        match candidate.filter(|c| !c.is_empty()) {
            Some(_) => AuthOutcome::Identify(Principal::from_id("idp:subject".to_string())),
            None => AuthOutcome::Pass,
        }
    }
}

/// Execute the ADMIN auth chain (`admin_auth:`) over the extracted admin credential carriers.
/// Mirrors `AuthMiddleware::run_chain` (first Identify admits, Reject denies, all-Pass denies,
/// empty chain = the explicit open posture) but takes BOTH carriers — an admin credential
/// legitimately arrives as `Authorization: Bearer` or `X-Admin-Token`, and the constant-time
/// both-carriers fold lives inside the module. Unknown / compiled-out names are skipped with a
/// loud log (config_validate rejects them at boot).
// With admin-tokens compiled out (and outside test builds) no chain arm reads the carriers — the
// loop still runs for the unknown-name log + fail-closed deny, so the parameters stay.
#[cfg_attr(not(any(feature = "auth-admin-tokens", test)), allow(unused_variables))]
fn run_admin_chain(
    app: &crate::state::App,
    bearer: Option<&str>,
    header: Option<&str>,
) -> (ChainVerdict, Option<crate::admin::v1::contract::Scope>) {
    if app.admin_chain.is_empty() {
        return (ChainVerdict::Open, None);
    }
    // One composite credential string for the cache key: an admin credential legitimately rides
    // two carriers, and both participate in the identity of "what was presented".
    let composite = match (bearer, header) {
        (None, None) => None,
        (b, h) => Some(format!("b:{}\nh:{}", b.unwrap_or(""), h.unwrap_or(""))),
    };
    let now = crate::store::now();
    // Captured BEFORE the first module runs — see the identical capture in `run_chain_cached` and
    // `auth_cache::CacheGeneration`. This is the plane the hazard actually bites on: an external
    // `kind: auth` admin module runs on the blocking pool with a multi-second budget (the shipped
    // OIDC module does a JWKS HTTPS round-trip with a 10s timeout), so the flush-then-reinsert
    // window here is seconds wide.
    let cache_gen = app.credential_cache.generation();
    for name in &app.admin_chain {
        // The built-in admin-tokens module is in-process and NEVER cached (caching a microsecond
        // compare only widens the rotation window); external admin modules are the cache's case.
        let cacheable = name != "admin-tokens";
        if let Some(cred) = composite.as_deref().filter(|_| cacheable) {
            if let Some(outcome) = app.credential_cache.get(name, cred, now) {
                match outcome {
                    AuthOutcome::Identify(principal) => {
                        let cap = module_admin_scope_cap(app, name);
                        return (
                            ChainVerdict::Identified {
                                module: name.clone(),
                                principal,
                                resolved: None,
                            },
                            cap,
                        );
                    }
                    AuthOutcome::Reject => return (ChainVerdict::Denied, None),
                    AuthOutcome::Pass => continue,
                }
            }
        }
        let outcome = match name.as_str() {
            #[cfg(feature = "auth-admin-tokens")]
            "admin-tokens" => busbar_auth_admin_tokens::authenticate_admin_tokens(
                app.governance
                    .as_ref()
                    .and_then(|g| g.admin_token_hash())
                    .as_deref(),
                bearer,
                header,
            ),
            // TEST-ONLY external-module stand-in: lets the e2e suite exercise group-mapped,
            // NON-full principals (unreachable with admin-tokens alone). Credential grammar:
            // `grp:<group>` identifies as a principal carrying exactly that group. Compiled out
            // of release binaries entirely.
            #[cfg(test)]
            "test-scope-module" => match bearer.or(header).and_then(|t| t.strip_prefix("grp:")) {
                Some(group) => {
                    let mut p = Principal::from_id(format!("test:{group}"));
                    p.roles = vec![group.to_string()];
                    AuthOutcome::Identify(p)
                }
                // Not my credential shape — defer to the next module (the PAM contract).
                None => AuthOutcome::Pass,
            },
            // Any other name is an EXTERNAL `kind: auth` admin plugin, resolved at load into
            // `app.admin_modules` (keyed by config name — the same `name` this loop iterates).
            // Dispatch to it; a name with no resolved module (impossible after a successful boot —
            // `AdminAuthChain::build` fails closed on an unresolvable name) falls through to `Pass`.
            other => match app.admin_modules.modules.get(other) {
                Some(module) => module.authenticate(bearer.or(header)),
                None => {
                    diag_error!(
                        ADMIN_MODULE_UNRESOLVED,
                        module = other,
                        "admin_auth names a module with no resolved plugin; skipping (boot resolves \
                         every non-builtin admin module, fail-closed)"
                    );
                    AuthOutcome::Pass
                }
            },
        };
        if let Some(cred) = composite.as_deref().filter(|_| cacheable) {
            app.credential_cache
                .put(name, cred, &outcome, now, cache_gen);
        }
        match outcome {
            AuthOutcome::Identify(principal) => {
                // Carry the identifying MODULE out (role_bindings are nested by module) plus the
                // module's admin-scope ceiling for the authorization step. There is no per-module
                // role filter: the nested bindings table IS the allowlist.
                let cap = module_admin_scope_cap(app, name);
                return (
                    ChainVerdict::Identified {
                        module: name.clone(),
                        principal,
                        resolved: None,
                    },
                    cap,
                );
            }
            AuthOutcome::Reject => return (ChainVerdict::Denied, None),
            AuthOutcome::Pass => {}
        }
    }
    (ChainVerdict::Denied, None)
}

/// Run the admin chain, OFFLOADING it off the reactor when it names an external `kind: auth` admin
/// plugin (`admin_modules.has_plugin`) — a plugin's `authenticate` is a synchronous FFI call that
/// can do blocking JWKS/introspection I/O, and called inline on a Tokio worker inside this middleware
/// a slow admin IdP would park a worker per in-flight admin request until `/healthz` (exempt, but
/// still needing a worker to run) and every other route stall and the node fails its liveness probe.
///
/// So a plugin admin chain is bounded by its OWN [`ADMIN_OFFLOAD_PERMITS`] budget (separate from the
/// data plane's) and run on the blocking pool. An admin-tokens-only chain (no plugin) is
/// microsecond constant-time compares and runs INLINE. FAIL-CLOSED at every failure: a permit that
/// cannot be acquired in time, a chain that does not finish in time, and a panicking plugin (join
/// error) are all `Denied`, never an admit.
async fn run_admin_chain_maybe_offloaded(
    app: &std::sync::Arc<crate::state::App>,
    bearer: Option<String>,
    header: Option<String>,
) -> (ChainVerdict, Option<crate::admin::v1::contract::Scope>) {
    if !app.admin_modules.has_plugin {
        // No blocking admin plugin: run inline (admin-tokens + any compiled-in test stand-in).
        return run_admin_chain(app, bearer.as_deref(), header.as_deref());
    }
    // Warn-once transition latch: a saturated admin offload persists per request until the wedged
    // plugin recovers. Warn on the transition; hold the rest at debug; reset on a fresh permit.
    static ADMIN_OFFLOAD_SATURATED_WARNED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    let permit = match tokio::time::timeout(ADMIN_OFFLOAD_WAIT, ADMIN_OFFLOAD_PERMITS.acquire())
        .await
    {
        Ok(Ok(p)) => {
            ADMIN_OFFLOAD_SATURATED_WARNED.store(false, std::sync::atomic::Ordering::Relaxed);
            p
        }
        _ => {
            if !ADMIN_OFFLOAD_SATURATED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                diag_warn!(
                    ADMIN_OFFLOAD_SATURATED,
                    "admin auth chain offload could not be started within {ADMIN_OFFLOAD_WAIT:?} \
                     ({ADMIN_OFFLOAD_MAX_INFLIGHT} already in flight); an admin auth plugin is not \
                     returning. Denying (fail-closed) rather than admitting unverified."
                );
            } else {
                diag_debug!(
                    ADMIN_OFFLOAD_SATURATED,
                    "admin auth chain offload could not be started within {ADMIN_OFFLOAD_WAIT:?} \
                     ({ADMIN_OFFLOAD_MAX_INFLIGHT} already in flight); an admin auth plugin is not \
                     returning. Denying (fail-closed) rather than admitting unverified."
                );
            }
            return (ChainVerdict::Denied, None);
        }
    };
    let app = app.clone();
    let joined = tokio::task::spawn_blocking(move || {
        let verdict = run_admin_chain(&app, bearer.as_deref(), header.as_deref());
        // Release the permit when the blocking work is DONE, not when the awaiting future is dropped
        // — a request that timed out (below) must not hand its slot to another while the plugin
        // thread it started is still wedged.
        drop(permit);
        verdict
    });
    // Warn-once transition latch: a stalled/panicking admin chain recurs per request until the
    // plugin recovers. Warn on the transition; hold the rest at debug; reset on a clean completion.
    static ADMIN_CHAIN_STALLED_WARNED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    match tokio::time::timeout(ADMIN_OFFLOAD_WAIT, joined).await {
        Ok(Ok(v)) => {
            ADMIN_CHAIN_STALLED_WARNED.store(false, std::sync::atomic::Ordering::Relaxed);
            v
        }
        // Join error (the plugin panicked) or a timeout waiting for it: fail closed. The wedged
        // blocking task keeps its permit until it eventually finishes, bounding the leak.
        _ => {
            if !ADMIN_CHAIN_STALLED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                diag_warn!(
                    ADMIN_CHAIN_STALLED,
                    "admin auth chain did not complete within {ADMIN_OFFLOAD_WAIT:?} (or panicked); \
                 denying (fail-closed)."
                );
            } else {
                diag_debug!(
                    ADMIN_CHAIN_STALLED,
                    "admin auth chain did not complete within {ADMIN_OFFLOAD_WAIT:?} (or panicked); \
                 denying (fail-closed)."
                );
            }
            (ChainVerdict::Denied, None)
        }
    }
}

/// The ADMIN-SCOPE CEILING for an identifying module (`max_admin_scope:`): the built-in
/// `admin-tokens` operator credential is exempt (full by definition — the root credential); every
/// other module is capped at its configured ceiling, DEFAULT `read-only` — `full` through an
/// external chain is an explicit opt-in (boot-warned in config_validate).
fn module_admin_scope_cap(
    app: &crate::state::App,
    module: &str,
) -> Option<crate::admin::v1::contract::Scope> {
    use crate::admin::v1::contract::Scope;
    if module == "admin-tokens" {
        return None;
    }
    Some(
        app.auth_scope_caps
            .get(module)
            .map(String::as_str)
            .and_then(Scope::parse)
            .unwrap_or(Scope::ReadOnly),
    )
}

/// DRY-RUN: evaluate what EFFECTIVE admin scope the presented carriers would earn under
/// `app`'s admin chain (chain verdict → role_bindings resolution → module ceiling), without serving
/// anything. Empty `Grants` = denied / no grant. `PUT /api/v1/admin/auth` runs the CALLER through
/// the CANDIDATE chain with this before committing — a chain that would lock the caller out is
/// rejected instead of applied (restart remains the backstop).
pub(crate) fn dry_run_admin_scope(
    app: &crate::state::App,
    bearer: Option<&str>,
    header: Option<&str>,
) -> crate::admin::v1::contract::Grants {
    let (verdict, cap) = run_admin_chain(app, bearer, header);
    let (module, principal) = match verdict {
        ChainVerdict::Identified {
            module, principal, ..
        } => (Some(module), Some(principal)),
        ChainVerdict::Open => (None, None),
        ChainVerdict::Denied => return crate::admin::v1::contract::Grants::default(),
    };
    let grants = admin_scope_for(module.as_deref(), principal.as_ref(), &app.role_bindings);
    match cap {
        Some(c) => grants.capped_by(c),
        None => grants,
    }
}

/// Resolve a principal's ADMIN SCOPE — the authorization half, operator-owned by construction:
/// the built-in operator token (the `admin-tokens` principal) is FULL by definition (it is the
/// root credential); any other principal gets the UNION of what its bound roles grant in
/// `role_bindings.<identifying module>` (bindings are NESTED BY MODULE - a role asserted by
/// module A never rides module B's binding; an unbound role grants nothing - fail closed). A
/// principal can hold two roles bound to INCOMPARABLE scopes at once (a hooks-register role and a
/// mint role) — `Grants` keeps both rather than collapsing to one (in-tree precedent:
/// `allowed_pools` already unions across a principal's granting roles). No principal = the explicit
/// open admin posture (empty `admin_auth:`) - full, dev-only.
fn admin_scope_for(
    module: Option<&str>,
    principal: Option<&Principal>,
    role_bindings: &crate::config::RoleBindings,
) -> crate::admin::v1::contract::Grants {
    use crate::admin::v1::contract::{Grants, Scope};
    let Some(p) = principal else {
        return Grants::of(Scope::Full);
    };
    // The operator credential. Scope is MODULE-intrinsic, keyed off the fixed principal id the
    // admin-tokens module mints — an external module returning `id: "admin"` cannot reach here
    // with it, because role-carrying principals resolve THROUGH role_bindings below only when they
    // carry roles; a roleless external "admin" id would land Grants::of(Full) - so the id is
    // reserved: config_validate forbids bindings that could shadow it, and external modules are
    // capped by `max_admin_scope` when they land. Until external ADMIN modules exist (none are
    // compiled today), the only producer of a roleless principal on this path is admin-tokens
    // itself.
    if p.roles.is_empty() {
        // Full-by-reserved-id is gated on the identifying MODULE being the built-in `admin-tokens`
        // (the operator credential), NOT merely on the id string: an EXTERNAL admin module returning
        // a roleless principal that happens to carry the reserved id (`"admin"`) must NOT reach
        // `Grants::of(Full)` — it falls to `Grants::default()`. Only admin-tokens itself
        // mints the operator identity, so only it confers operator authority.
        #[cfg(feature = "auth-admin-tokens")]
        if module == Some(crate::config::ADMIN_TOKENS_MODULE)
            && p.id == busbar_auth_admin_tokens::ADMIN_TOKENS_PRINCIPAL_ID
        {
            return Grants::of(Scope::Full);
        }
        return Grants::default();
    }
    let Some(table) = module.and_then(|m| role_bindings.get(m)) else {
        return Grants::default();
    };
    p.roles
        .iter()
        .filter_map(|role| table.get(role))
        .filter_map(|b| b.admin_scope.as_deref())
        .filter_map(Scope::parse)
        .fold(Grants::default(), Grants::with)
}

/// A 403 in the frozen admin error envelope (`{"error":{"code":"forbidden","message":…}}`),
/// naming the scope that WOULD have sufficed — never any other principal's data.
/// A 401 in the frozen admin error envelope — no/invalid admin credential. The admin plane's
/// most-frequent error must carry the SAME `{error:{code,message}}` shape tooling branches on;
/// the data plane keeps vendor-native 401 shaping (`unauthorized_response`).
fn admin_unauthorized_response() -> Response {
    let e = crate::admin::v1::contract::AdminError::Unauthorized;
    let body = serde_json::json!({
        "error": { "code": e.code(), "message": e.message() }
    })
    .to_string();
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static unauthorized response")
}

fn forbidden_response(needed: crate::admin::v1::contract::Scope) -> Response {
    let body = serde_json::json!({
        "error": {
            "code": "forbidden",
            "message": format!(
                "this endpoint requires the `{}` admin scope",
                needed.as_str()
            ),
        }
    })
    .to_string();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static forbidden response")
}

/// A 429 in the frozen admin error envelope — the per-principal mutation budget is spent. Carries
/// `Retry-After: 60` (the fixed window length): a compliant client backs off without guessing.
fn rate_limited_response() -> Response {
    let e = crate::admin::v1::contract::AdminError::RateLimited;
    let body = serde_json::json!({
        "error": { "code": e.code(), "message": e.message() }
    })
    .to_string();
    Response::builder()
        .header(
            axum::http::header::RETRY_AFTER,
            crate::admin::rate::MUTATION_RATE_WINDOW_SECS.to_string(),
        )
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static rate-limited response")
}

/// Fire the synthetic `rejected_by_auth` response taps (fire-and-forget) and return the auth
/// denial — so audit taps see auth denials, not just served traffic. The
/// request body is unparsed at the auth stage, so the shape is the zeroed default bucket with the
/// path-inferred protocol. The tap's `status` MUST be the client-visible HTTP status, which is
/// PROTOCOL-NATIVE for an auth failure — 401 for anthropic/openai/responses/cohere, 403 for Bedrock
/// (SigV4 → AccessDenied), 400 for Gemini (INVALID_ARGUMENT). Hardcoding 401 made a tap watching a
/// gemini/bedrock ingress denial contradict the response the client actually got.
fn unauthorized_with_completion_taps(app: &crate::state::App, path: &str) -> Response {
    // The `ingress_protocol` label is the resolved ingress's own WIRE FORMAT, so a denial on a
    // mounted plane is tapped as that plane's dialect rather than as whichever LLM dialect its path
    // happens to resemble; a residual path that names none is labelled with the dialect its answer
    // is shaped in, so the tap and the response can never disagree.
    let proto = crate::ingress::native::envelope_dialect(ingress_for_path(app, path));
    if !app.tap_hooks_response.is_empty() {
        // An auth denial never reaches `forward_with_pool_parsed` (no `RequestCtx` is ever built for
        // it), so it has no id from that path — stamp a fresh one here from the SAME process-wide
        // counter so this synthetic completion notification still carries a real, unique
        // correlation id rather than a misleading placeholder.
        // The pre-routing auth denial has no resolved operation and no readable body — `operation:
        // None` short-circuits the seam to the zeroed shape before any read (MINOR-8).
        let shape = crate::proxy::capture_stage_shape(
            None,
            &[],
            "",
            "",
            proto,
            None,
            false,
            app.next_request_id(),
        );
        let status = auth_failure_status_and_kind(proto).0.as_u16();
        crate::proxy::fire_stage_taps(
            &app.tap_hooks_response,
            &shape,
            crate::hooks::wire::HookStageProjection {
                at: "response",
                model: None,
                attempt_number: None,
                remaining_candidates: None,
                previous_failure: None,
                outcome: Some("rejected_by_auth"),
                status: Some(status),
            },
            // An auth denial has no authenticated caller, so no group binding: unscoped taps fire,
            // group-scoped taps do not (a groupless caller matches only an unscoped hook).
            None,
            &app.groups_registry,
        );
    }
    unauthorized_response(app, path)
}

/// Axum middleware layer that validates auth before routing.
// Both arms are `Response` (axum requires the Err arm to be an IntoResponse we can return
// directly); `Response` exceeds clippy's result_large_err threshold but boxing it would break the
// middleware signature, so the large-Err is intrinsic here, not a smell.
#[allow(clippy::result_large_err)]
pub(crate) async fn auth_middleware(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::Extension(core_routes): axum::Extension<
        std::sync::Arc<crate::core_routes::CoreRouteTable>,
    >,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // Clone the path so no immutable borrow of `req` is held while we later mutate its extensions.
    // Stage timer for the middleware's OWN work; taken (recording) before every `next.run` below so
    // downstream handler time is never attributed to auth. No-op unless `BUSBAR_PROFILE` is set.
    let mut _mw = crate::profile::start(crate::profile::Stage::MwAuth);
    let path = req.uri().path().to_owned();

    // CORE HTTP ROUTES: every first-party route declared its admission bar at the moment it was
    // mounted (`core_routes`), so this middleware asserts nothing about any particular path. The
    // table is THIS router's, not the process's: `/healthz` is open wherever it is mounted because
    // it declares itself open (a liveness probe must not require a caller token), and
    // `/auth/token` bypasses on the data plane because the handler runs the auth chain ITSELF (it
    // needs the identified principal to self-scope the minted key) — on the admin plane, which does
    // not mount it, there is no declaration and therefore no bypass.
    //
    // EXACT path + method match, never a prefix, so nothing else rides a bypass. `/metrics` is NOT
    // exempted anywhere — Prometheus telemetry (lane/pool topology, per-protocol counters, error
    // rates) is a fingerprinting / information-disclosure surface, so it goes through the same auth
    // check as any other route. Operators scraping from a localhost sidecar use a configured token
    // (or run under `none`/`passthrough` mode, where `validate_token` admits unconditionally).
    let mut declared_admin = false;
    if let Some(auth) = core_routes.declared_auth(&path, req.method()) {
        match auth {
            busbar_plugin_loader::RouteAuth::None => {
                drop(_mw.take());
                return Ok(next.run(req).await);
            }
            busbar_plugin_loader::RouteAuth::Admin => declared_admin = true,
            busbar_plugin_loader::RouteAuth::Key => {}
        }
    }

    // PLUGIN HTTP ROUTES: a registered plugin route carries its OWN declared auth level,
    // enforced through THIS chain. `none` bypasses (like `/healthz`); `admin` is forced down the admin
    // chain below; `key` needs no special handling (it flows through the normal client-token check).
    // Consulted off the LIVE snapshot so a hot-swap that changes a route's auth takes effect at once.
    // `declared_auth` returns `None` for every non-plugin path, so this is a no-op on the hot path.
    if let Some(auth) = app.plugin_routes.declared_auth(&path, req.method()) {
        match auth {
            busbar_plugin_loader::RouteAuth::None => {
                drop(_mw.take());
                return Ok(next.run(req).await);
            }
            busbar_plugin_loader::RouteAuth::Admin => declared_admin = true,
            busbar_plugin_loader::RouteAuth::Key => {}
        }
    }

    // Derive owned values up front so no immutable borrow of `req` is live when we mutate its
    // extensions below.
    //
    // Admin detection must be path-boundary-safe: a bare `starts_with("/api")` also captures
    // sibling paths like `/apix/v1/messages`, which are NOT native-API routes. Such a path would be
    // sent down the admin auth branch and (with a valid admin token) early-return WITHOUT the
    // `CallerToken` extension a non-admin handler requires — yielding a 500 MissingExtension and
    // leaking that the path was treated as admin-protected. Require either the exact `/api` segment
    // or an `/api/` delimiter so only the native-API root (`/api/<version>/<area>/…`) matches.
    let is_admin = path == ADMIN_PATH || path.starts_with(ADMIN_PATH_PREFIX) || declared_admin;
    let admin_header_token = extract_admin_header_token(&req);
    // The busbar client token, taken from whichever carrier the SDK used (Authorization: Bearer,
    // then x-api-key, then x-goog-api-key). This single value drives BOTH the static-allowlist
    // check and the governance virtual-key lookup, so every scheme is validated identically and in
    // constant time. Replaces the previous Bearer-only `bearer_token`.
    let client_token: Option<String> = AuthMiddleware::extract_client_token(&req);

    // Thread the caller's token into request extensions for passthrough forwarding, using the same
    // multi-scheme carrier precedence as auth (Bearer / x-api-key / x-goog-api-key). Inserted BEFORE
    // any early-return below so EVERY request that reaches `next.run(req)` through this middleware
    // carries the extension — the `Extension<CallerToken>` extractor in handlers never sees it
    // absent (which would surface as a 500 MissingExtension). Always inserted (even when `None`).
    req.extensions_mut()
        .insert(CallerToken(client_token.clone()));

    // THE PLANE'S ADMISSION FACTS. `None` for every path on the residual LLM plane, which is every
    // path in a deployment that is not also an MCP server — one `Option` test, then nothing below
    // this point costs anything. `Some` means this path is an OAuth 2.1 protected resource: a token
    // presented here must be bound to this resource's canonical URI, and a refusal owes the caller
    // a machine-readable challenge naming where to go and get one.
    let admission = app.planes.admission_for(&path).cloned();

    // the /admin management API is gated by the ADMIN AUTH CHAIN (`admin_auth:`, default
    // `[admin-tokens]` — the single operator token, Bearer or X-Admin-Token) — NOT a virtual key,
    // and NOT the vendor-SDK carriers (admin is a busbar operator surface, not a native SDK
    // ingress). The chain authenticates (WHO); the principal's admin SCOPE then authorizes against
    // the endpoint's required scope (WHAT) — the matrix, checked here at the one chokepoint
    // every /admin path crosses. Extract the admin Bearer separately so the multi-scheme
    // client-token carriers can't present an operator token via `x-api-key`/`x-goog-api-key`.
    if is_admin {
        let admin_bearer = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(AuthMiddleware::extract_bearer_token);
        let (verdict, scope_cap) =
            run_admin_chain_maybe_offloaded(&app, admin_bearer, admin_header_token.clone()).await;
        let (id_module, principal) = match verdict {
            ChainVerdict::Identified {
                module, principal, ..
            } => (Some(module), Some(principal)),
            // The explicit `admin_auth: []` OPEN posture (dev): anonymous, full authority —
            // symmetric with the data plane's empty chain. The default config never lands here.
            ChainVerdict::Open => (None, None),
            // The ADMIN plane 401 speaks the frozen v1 envelope ({error:{code:"unauthorized"}}) —
            // the most frequent error a tooling consumer hits (setup/rotation) must branch on the
            // SAME `code` seam as every other admin error, never a protocol-shaped body (the
            // vendor-native shaping below is for the DATA plane, whose SDKs must parse it).
            ChainVerdict::Denied => return Err(admin_unauthorized_response()),
        };
        // AUTHORIZATION: resolve the principal's admin scope (module-intrinsic for the operator
        // token; `role_bindings:` for group-carrying principals: the UNION of what its bound roles
        // grant, unmapped groups grant nothing), CAPPED by the identifying module's
        // `max_admin_scope:` ceiling, and check it against the endpoint's required scope. An
        // identified principal with NO grant is 403, never 401 — authenticated but not authorized.
        let scope = admin_scope_for(id_module.as_deref(), principal.as_ref(), &app.role_bindings);
        let scope = match scope_cap {
            Some(cap) => scope.capped_by(cap),
            None => scope,
        };
        let required = crate::admin::v1::contract::required_scope(req.method(), &path);
        if !scope.allows(required) {
            // Denied authorization is AUDITED (a credential probing beyond its scope is exactly what
            // an operator wants to see) — but at most once per (principal, window). The durable
            // write-through is a blocking store round-trip under a process-global lock, and this path
            // returns BEFORE the mutation limiter runs (and a GET never reaches it at all), so an
            // unbounded audit here is an unmetered I/O amplifier on the reactor. Same bound, same
            // reason, as the rate-limited audit below.
            let actor = principal
                .as_ref()
                .map(|p| p.id.as_str())
                .unwrap_or("anonymous");
            if let crate::admin::rate::RateCheck::Denied {
                first_in_window: true,
            } = app.mutation_limiter.check(
                actor,
                crate::admin::rate::MutationClass::Forbidden,
                crate::store::now(),
            ) {
                crate::admin::audit::AUDIT.record_by(
                    "admin.forbidden",
                    &path,
                    crate::admin::audit::OUTCOME_REJECTED,
                    actor,
                );
            } else {
                // Suppressed records still leave a per-request signal, at zero I/O cost.
                diag_debug!(ADMIN_FORBIDDEN_SUPPRESSED, principal = %actor, path = %path, required = %required.as_str(),
                    "admin request forbidden (audit suppressed: already recorded this window)");
            }
            return Err(forbidden_response(required));
        }
        // MUTATION RATE LIMITS: per-principal fixed windows, spent BEFORE the handler so
        // FAILED attempts count too (anti-enumeration). Config-plane mutations (apply/rollback)
        // are the tight class; every other mutation is the CRUD class. Reads are unmetered.
        let method = req.method();
        let is_mutation = method == axum::http::Method::POST
            || method == axum::http::Method::PUT
            || method == axum::http::Method::PATCH
            || method == axum::http::Method::DELETE;
        if is_mutation {
            // The CONFIG class (10/min) is the blast-radius set: whole-config mutations AND the
            // admin auth chain itself. Everything else that mutates (hooks, keys, cache flush) is
            // the CRUD class (60/min). Matched RELATIVE to the one contract prefix so this gate
            // can never drift from the mount grammar. Classification itself lives in
            // `admin::rate::classify_mutation`, driven by a const table rather than an inline
            // predicate, so it can be enumerated and cross-checked against
            // `docs/admin-api.md`'s rate-limit table (see that table's doc comment).
            let rel = path
                .strip_prefix(crate::admin::v1::contract::ADMIN_PREFIX)
                .unwrap_or(&path);
            let class = crate::admin::rate::classify_mutation(rel);
            let actor = principal
                .as_ref()
                .map(|p| p.id.as_str())
                .unwrap_or("anonymous");
            if let crate::admin::rate::RateCheck::Denied { first_in_window } = app
                .mutation_limiter
                .check(actor, class, crate::store::now())
            {
                // Audit the first denial of the window only. The durable audit write-through is a
                // blocking store round-trip, and this is the SHED path — auditing every rejected
                // attempt would let a client that ignores its 429s drive unbounded blocking work
                // through the limiter whose entire purpose is to stop doing work.
                if first_in_window {
                    crate::admin::audit::AUDIT.record_by(
                        "admin.rate_limited",
                        &format!("{}:{path}", class.label()),
                        crate::admin::audit::OUTCOME_REJECTED,
                        actor,
                    );
                }
                return Err(rate_limited_response());
            }
        }
        req.extensions_mut().insert(AuthPrincipal(principal));
        // (1.5.2 scope collapse: the EFFECTIVE-scope extension is no longer threaded to handlers —
        // every mutation now requires `Full` at the route matrix, so the former body-derived
        // refinements a handler applied via `AdminScope` are gone; the `required_scope` check above
        // is the whole authorization decision.)
        // INTENTIONAL governance bypass for the operator admin token. A successful admin auth attaches
        // an EMPTY `GovCtx::default()` (no resolved virtual key) and returns HERE — BEFORE the
        // virtual-key governance resolution below — so per-key controls (`allowed_pools`, budget, RPM/
        // TPM) are deliberately NOT applied to admin requests. This is by design, not an oversight:
        // the admin token is an operator-only credential, and the /admin routes expose ONLY
        // key-management (create / list / disable / usage), never inference. There is no per-key
        // budget or pool to enforce on a key-management call, and holding the admin token already
        // confers full authority over EVERY key by design, so subjecting it to a single key's
        // governance would be meaningless. Inference ingress (every non-/admin path) still falls
        // through to the governance resolution below and is fully governed.
        req.extensions_mut()
            .insert(crate::governance::GovCtx::default());
        drop(_mw.take());
        return Ok(next.run(req).await);
    }

    // ── DATA PLANE ── the ADMIN TOKEN NO LONGER APPEARS HERE. Admission is decided SOLELY by the
    // data-plane chain verdict (fed by the `keys` engine arm, any IdP plugin, or the SigV4 pre-step),
    // NOT by whether an admin token is set. `chain:[]` is a genuine open front door again (admit
    // anonymous); `chain:[keys]` requires and resolves a virtual key; an IdP chain requires the IdP.
    // Enforcement rides whatever principal-with-key the chain resolved, independent of the admin token.

    // keys-in-chain makes every data-plane request present a valid virtual key, which SUPERSEDES
    // `upstream_credentials: passthrough` (there is no caller credential to forward — the vkey is
    // busbar's own). Warn once so an operator who set passthrough expecting caller-credential
    // forwarding sees why a no-vkey request is rejected. (Reframed off the deleted admin-token gate
    // onto the actual axis: keys-in-chain.)
    if app.auth.keys_in_chain && app.upstream_creds() == UpstreamCreds::Passthrough {
        static WARN_ONCE: std::sync::Once = std::sync::Once::new();
        WARN_ONCE.call_once(|| {
            diag_warn!(
                KEYS_IN_CHAIN_PASSTHROUGH_CONFLICT,
                "auth.chain names `keys` with upstream_credentials: passthrough: the keys verifier \
                 requires a valid virtual key on every request and supersedes passthrough's \
                 accept-and-forward-caller-credential intent. Use upstream_credentials: own (or omit \
                 it) alongside `keys`."
            );
        });
    }

    // BEDROCK INGRESS via inbound AWS SigV4 is a real INGRESS-PROTOCOL PRE-STEP (not a fork on the
    // admin token): it needs the BUFFERED BODY to bind the payload hash, which the chain ABI cannot
    // take. It runs ONLY when the running chain names `keys` (a busbar-minted SigV4 credential IS a
    // `keys` credential) AND the ingress protocol authenticates with SigV4 AND the request actually
    // carries an `AWS4-HMAC-SHA256` Authorization header. Gating on `keys_in_chain` keeps an OPEN
    // `chain:[]` open even for a SigV4-shaped request (pure anonymous). On success it yields the same
    // `Identified { resolved: Some(key) }` the bearer keys arm produces, feeding the SINGLE match
    // below. The "which protocol uses SigV4" decision is a DECLARED protocol fact
    // (`ProtocolDecl::ingress_auth`), NOT a `proto == "bedrock"` name-branch — and reading it no
    // longer costs the reader/writer pair the old vtable predicate had to allocate to ask.
    let ingress_uses_sigv4 = crate::proto::decl_for(crate::ingress::native::envelope_dialect(
        ingress_for_path(&app, &path),
    ))
    .is_some_and(|d| d.uses_sigv4_ingress_auth());
    // The SigV4 pre-step is CONFINED TO THE RESIDUAL PLANE (`admission.is_none()`). An
    // audience-bound plane admits bearer tokens only: SigV4 signs a request with a busbar key's
    // secret and produces an identity with no audience anywhere in it, so allowing it here would be
    // a second door into the MCP plane that the RFC 8707 check does not stand behind. MCP has no
    // SigV4 dialect to be compatible with, so nothing is lost by closing it.
    let verdict = if admission.is_none()
        && app.auth.keys_in_chain
        && ingress_uses_sigv4
        && has_sigv4_authorization(&req)
    {
        // STRUCTURAL GATE, before buffering: require the Authorization header to actually parse
        // as SigV4 (`has_sigv4_authorization` only checked the algorithm-token prefix) and the
        // `x-amz-content-sha256`/`x-amz-date` headers to be present. This is a HOIST of work
        // `verify_bedrock_sigv4` already does below (its own parse, and its own presence checks
        // on these same two headers) — a reordering, not a new check — so it removes the trivial
        // `AWS4-HMAC-SHA256 x` attacker (who reaches the buffer today) before a single body byte
        // is read. All three conditions are STRUCTURAL and attacker-known (the attacker can
        // trivially satisfy all three), so this is not an oracle: it never depends on whether an
        // AccessKeyId is valid — gating on that would leak validity through a read/no-read signal
        // and reintroduce the enumeration oracle `verify_bedrock_sigv4` spends a dummy secret to
        // avoid.
        let auth_value = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let structurally_valid = crate::sigv4::parse_authorization_header(auth_value).is_ok()
            && req.headers().contains_key(X_AMZ_CONTENT_SHA256)
            && req.headers().contains_key(X_AMZ_DATE);
        if !structurally_valid {
            return Err(unauthorized_response(&app, &path));
        }
        // BODY INTEGRITY: a SigV4 signature only binds the payload if we re-hash the actual bytes
        // and confirm they match the signed `x-amz-content-sha256` (which the signature covers).
        // Verifying the signature alone leaves a MitM free to tamper the body in transit while the
        // request still authenticates. Buffer the body HERE so the verifier can compare
        // `sha256_hex(body)` to the declared hash, then reconstruct the request from the SAME bytes
        // so the downstream handler receives the payload intact (no consumption bug). A buffering
        // failure (e.g. a truncated/aborted body) is itself a failed request — collapse it to the
        // same opaque auth error so it leaks nothing about why it failed.
        //
        // CAP the buffer at the SAME knob (`limits.request_body_max_bytes`) that drives the inbound
        // `DefaultBodyLimit` layer, rather than `usize::MAX`. This auth middleware runs BEFORE
        // authentication is confirmed and the SigV4 branch is reachable from attacker-controlled
        // headers alone (a fabricated AccessKeyId still reaches here), so relying on the body-limit
        // layer being present and ordered ahead of us is a stack assumption, not enforcement. An
        // in-code cap means a never-terminating / oversized body cannot exhaust the heap even if
        // the layer is absent or misconfigured (defense-in-depth).
        let (parts, body) = req.into_parts();
        let Ok(body_bytes) =
            axum::body::to_bytes(body, crate::limits::translate_body_max_bytes()).await
        else {
            return Err(unauthorized_response(&app, &path));
        };
        req = Request::from_parts(parts, Body::from(body_bytes.clone()));
        // Governance is always constructed (RAM by default); if somehow absent there is no store
        // to resolve the SigV4 credential against → fail closed.
        match app.governance.as_deref() {
            Some(gov) => match verify_bedrock_sigv4(gov, &req, &body_bytes) {
                Ok(key) => ChainVerdict::Identified {
                    module: crate::config::KEYS_MODULE.to_string(),
                    principal: principal_from_vkey(&key),
                    resolved: Some(std::sync::Arc::new(key)),
                },
                // EVERY failure (missing/malformed header, unknown AccessKeyId, expired date,
                // signed-headers mismatch, bad signature, OR a body whose bytes don't match the
                // signed x-amz-content-sha256) maps to the identical native auth error — the
                // distinction is logged inside the verifier, never surfaced, so there is no oracle.
                Err(()) => return Err(unauthorized_response(&app, &path)),
            },
            None => return Err(unauthorized_response(&app, &path)),
        }
    } else {
        // Not `run_chain_cached` directly: a plugin chain does blocking I/O on a Tokio worker. The
        // `keys` engine arm (inside the chain run) needs the governance handle to verify a
        // busbar-signed key; pass `app.governance` in PER-REQUEST (governance is built AFTER
        // `AuthMiddleware::new`, so the arm takes it as a call parameter, never a struct field).
        // THE AUDIENCE PRE-FILTER, for credentials busbar did not mint. The chain's plugin modules
        // verify an operator IdP's signature and cannot be asked about RFC 8707 — the module ABI
        // has no shape for it — so core establishes the binding itself, BEFORE the chain runs, and
        // only ever to refuse. See `auth::audience`: a token that passes here still has to pass the
        // chain, so this can narrow what is admitted and can never widen it.
        if let (Some(adm), Some(tok)) = (admission.as_ref(), client_token.as_deref()) {
            match audience::inspect_bearer(tok, &adm.audience) {
                // A busbar-signed token: the verifier below has the claims and the signature, and
                // does the real check. Pre-judging it here would refuse every valid one.
                audience::Binding::Deferred | audience::Binding::Bound => {}
                audience::Binding::Mismatch => {
                    return Err(challenge::refuse(
                        challenge::ChallengeError::InvalidToken,
                        &adm.resource_metadata,
                        "The access token's audience does not identify this resource. Request a                          token whose `resource` (RFC 8707) is this server's canonical URI.",
                        None,
                    ))
                }
                audience::Binding::Opaque => {
                    return Err(challenge::refuse(
                        challenge::ChallengeError::InvalidToken,
                        &adm.resource_metadata,
                        "This credential carries no readable audience, so it cannot be shown to                          have been issued for this resource. A JWT access token is required here.",
                        None,
                    ))
                }
            }
        }
        AuthMiddleware::run_chain_on_request_path(
            &app.auth,
            &app.credential_cache,
            client_token.clone(),
            app.governance.clone(),
            admission.as_ref().map(|a| a.audience.clone()),
        )
        .await
    };

    // THE SINGLE DATA-PLANE GATE — one resolution of the chain verdict, with NO branch anywhere on
    // admin-token presence. The DECISION lives in [`resolve_data_plane_identity`], shared with the
    // stdio serve mode's boot-time session bind, so "who does this credential make you" cannot be
    // answered differently on the two transports; only the WORDING of a refusal differs here
    // (an RFC 6750 challenge or a native envelope, where the stdio binding words it on stderr).
    match resolve_data_plane_identity(&app, verdict) {
        Ok((principal, gov)) => {
            // ALWAYS inserted — including `AuthPrincipal(None)` + empty `GovCtx` on the open front
            // door — so downstream `Extension` extraction never 500s `MissingExtension`.
            req.extensions_mut().insert(principal);
            req.extensions_mut().insert(gov);
        }
        Err(IdentityRefusal::Denied) => {
            // On an audience-bound plane the refusal is an RFC 6750 challenge, not a vendor-shaped
            // envelope: the caller is an OAuth client, and the `WWW-Authenticate` header is the only
            // place the discovery loop's next step was ever going to come from. `Absent` (no
            // credential at all) and `invalid_token` (one was presented and failed) are different
            // signals and clients branch on the difference, so they are not collapsed.
            if let Some(adm) = admission.as_ref() {
                let kind = if client_token.is_none() {
                    challenge::ChallengeError::Absent
                } else {
                    challenge::ChallengeError::InvalidToken
                };
                return Err(challenge::refuse(
                    kind,
                    &adm.resource_metadata,
                    "Authentication is required for this resource.",
                    None,
                ));
            }
            return Err(unauthorized_with_completion_taps(&app, &path));
        }
        Err(IdentityRefusal::NoGrant) => {
            if let Some(adm) = admission.as_ref() {
                return Err(challenge::refuse(
                    challenge::ChallengeError::InsufficientScope,
                    &adm.resource_metadata,
                    "The authenticated principal carries no grant on this resource.",
                    None,
                ));
            }
            return Err(unauthorized_with_completion_taps(&app, &path));
        }
    }

    drop(_mw.take());
    Ok(next.run(req).await)
}

// IdentityRefusal (WHY a chain verdict did not resolve to an admitted identity) now lives in the
// neutral contracts crate so a plane names it without reaching into busbar-core; re-exported here so
// every crate::auth::IdentityRefusal caller is unchanged.
pub use busbar_api::IdentityRefusal;

/// WHO A CHAIN VERDICT MAKES YOU on the data plane — the one resolution of verdict →
/// (principal, governance context), shared by the HTTP auth middleware and the stdio serve mode's
/// boot-time session bind so the two transports cannot come to different answers.
///
/// - `Open` (`chain: []`, no keys arm) admits ANONYMOUS: `AuthPrincipal(None)` and an empty
///   `GovCtx`, the explicit open-front-door posture the boot banner warns about.
/// - `Identified` rides the RESOLVED key when an engine arm (keys / SigV4) produced one; otherwise
///   a group-carrying principal is re-keyed through `role_bindings` via
///   [`crate::governance::synthesize_principal_key`]. A DISABLED vkey never reaches here as
///   `Identified` (the keys arm denies it), so it can never be re-admitted through synth.
/// - FAIL-CLOSED for a GROUP principal (asserted roles) that earned NO enforcement key WHEN its
///   module HAS a `role_bindings` table (governance is configured for it): its roles were supposed
///   to define its data-plane access and defined none (an unbound role, or an explicit
///   `allowed_pools: []`). Admitting it `key: None` would hand it UNRESTRICTED pool access — the
///   regression `test_role_bound_principal_governed_like_a_virtual_key` pins. With NO bindings
///   table for the module (`bindings.is_none()`), a role principal is admitted UNGOVERNED
///   (`key: None`), exactly as the old static/inert path did
///   (`test_chain_accepts_all_carriers_and_native_401`); a plain vkey (`resolved: Some`) or a
///   ROLELESS principal never trips the guard.
pub(crate) fn resolve_data_plane_identity(
    app: &crate::state::App,
    verdict: ChainVerdict,
) -> Result<(AuthPrincipal, crate::governance::GovCtx), IdentityRefusal> {
    match verdict {
        ChainVerdict::Open => Ok((AuthPrincipal(None), crate::governance::GovCtx::default())),
        ChainVerdict::Denied => Err(IdentityRefusal::Denied),
        ChainVerdict::Identified {
            module,
            principal,
            resolved,
        } => {
            let bindings = app.role_bindings.get(&module);
            let gov_key = resolved
                .or_else(|| crate::governance::synthesize_principal_key(&principal, bindings));
            if gov_key.is_none() && !principal.roles.is_empty() && bindings.is_some() {
                return Err(IdentityRefusal::NoGrant);
            }
            Ok((
                AuthPrincipal(Some(principal)),
                crate::governance::GovCtx { key: gov_key },
            ))
        }
    }
}

/// Does the request carry an inbound AWS SigV4 `Authorization` header (`AWS4-HMAC-SHA256 ...`)? Cheap
/// pre-check so the SigV4 verify path is entered ONLY for genuine SigV4 requests; everything else
/// (bearer, x-api-key, x-goog-api-key, or no Authorization) takes the unchanged token path. The full
/// structural parse/validation happens inside the verifier — this only gates entry.
fn has_sigv4_authorization(req: &Request<Body>) -> bool {
    req.headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim_start().starts_with(SIGV4_ALGORITHM))
        .unwrap_or(false)
}

/// Canonicalize the request query string for SigV4: split into key=value pairs, sort by (encoded)
/// key then (encoded) value, and join with `&`. An empty/absent query yields `""`. A bare key
/// (`?foo`) canonicalizes to `foo=` (AWS signs a missing value as empty).
///
/// Deliberately does NOT run each key/value through an AWS URI-encoder. `query` here is the RAW
/// wire query string — i.e. already percent-encoded exactly once by whatever HTTP client/SDK sent
/// the request, since a compliant SigV4 client uses the SAME single URI-encoding pass to build both
/// the CanonicalQueryString it signs AND the query string it puts on the wire (AWS "Create a
/// canonical request for Signature Version 4": CanonicalQueryString is built by URI-encoding each
/// parameter name/value ONCE — unlike CanonicalURI, which for non-S3 services is deliberately
/// double-encoded; see `uri_encode_path`'s caller in `proxy/egress.rs` and its mirror at the
/// `canonical_uri` line above for that asymmetric, INTENTIONAL case). Running the already
/// once-encoded wire text through an AWS URI-encoder again would double-encode it (e.g. a client's
/// correct `a%2Fb` becomes `a%252Fb`), producing a CanonicalQueryString that diverges from the one
/// the client actually signed — every request with a query parameter needing escaping would fail
/// verification. Sorting is done on the RAW (already-encoded) bytes, which is equivalent to sorting
/// on the encoded key/value per the AWS spec, since the wire bytes ARE the encoded form.
fn canonical_query_string(query: Option<&str>) -> String {
    let Some(q) = query.filter(|q| !q.is_empty()) else {
        return String::new();
    };
    let mut pairs: Vec<(&str, &str)> = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Verify an inbound Bedrock SigV4 request against the governance virtual-key store. On success
/// returns the resolved, ENABLED `VirtualKey` (so the caller attaches its `GovCtx`); on ANY failure
/// returns `Err(())` — the SINGLE opaque failure the caller maps to the native auth error, with no
/// distinction reaching the wire (the specific `VerifyError` is logged here for operators only).
///
/// Indistinguishability / no enumeration oracle: an UNKNOWN AccessKeyId does NOT short-circuit. We
/// still run the full constant-time signature verification against a fixed DUMMY secret, so the
/// unknown-key path and the wrong-signature path do the same work and reject identically. A DISABLED
/// key likewise still verifies before rejecting, so "disabled" is not distinguishable from "bad sig".
fn verify_bedrock_sigv4(
    gov: &crate::governance::GovState,
    req: &Request<Body>,
    body: &[u8],
) -> Result<crate::governance::VirtualKey, ()> {
    use crate::sigv4::{parse_authorization_header, verify_inbound_sigv4, InboundRequest};

    // Parse the Authorization header. (has_sigv4_authorization already confirmed the algorithm token,
    // but re-parse fully here — a malformed-but-AWS4-prefixed header still rejects.)
    let auth_value = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let parsed = match parse_authorization_header(auth_value) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(reason = ?e, "inbound SigV4 rejected: unparseable Authorization");
            return Err(());
        }
    };

    // Gather the signed-header VALUES from the request (every name the client listed in SignedHeaders;
    // the verifier rejects if any is missing). Lowercase the names to match the signer.
    //
    // PREFILTER: `verify_inbound_sigv4` consumes ONLY the headers named in `SignedHeaders` (plus the
    // payload-hash and amzdate it reads from struct fields, both of which are themselves signed
    // headers). Lowercasing + allocating EVERY inbound header — many of them irrelevant — is wasted
    // work on every request. Restrict to the signed subset BEFORE allocating, matching names
    // case-insensitively against the signer's list. Semantics are unchanged: the verifier's signed-set
    // selection (step 3) sees exactly the same {name→value} mapping it would have found in the full
    // list; an unsigned `x-amz-content-sha256`/`x-amz-date` would not have been bound by the signature
    // anyway, so omitting it here is the same fail-closed outcome the verifier already produces.
    let signed_names: std::collections::HashSet<String> = parsed
        .signed_headers
        .split(';')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            let lname = name.as_str().to_ascii_lowercase();
            if !signed_names.contains(&lname) {
                return None;
            }
            value.to_str().ok().map(|v| (lname, v.to_string()))
        })
        .collect();

    // The payload hash the client signed is its `x-amz-content-sha256` header value. We verify the
    // signature against that DECLARED hash (it is itself a signed header, so the signature binds it).
    // A request that omits the header cannot have signed it, so reject — there is nothing to feed the
    // canonical request.
    let Some(payload_hash) = headers
        .iter()
        .find(|(k, _)| k == X_AMZ_CONTENT_SHA256)
        .map(|(_, v)| v.clone())
    else {
        tracing::debug!("inbound SigV4 rejected: missing x-amz-content-sha256");
        return Err(());
    };

    // BODY INTEGRITY (the real bind): the signature only proves the client signed `payload_hash`; it
    // does NOT prove the bytes we actually received hash to that value. Without this check a MitM who
    // cannot forge the signature can still tamper the body in transit and the request authenticates —
    // the signature stops binding the payload. Re-hash the buffered body and require it to equal the
    // signed declared hash (lowercase-hex, constant-time compare to avoid leaking a prefix-match
    // length via timing). `UNSIGNED-PAYLOAD` is the AWS sentinel for "I did not hash my body"; for
    // this governed ingress we REQUIRE a signed payload, so reject it outright (it can never equal a
    // real sha256 digest anyway — the explicit reject documents the decision and avoids a future
    // signer that hashes the literal string "UNSIGNED-PAYLOAD" sneaking past). On ANY mismatch reject
    // with the SAME opaque `Err(())` every other failure returns — the reason is logged here only, so
    // the wire cannot tell "body tampered" from "bad signature".
    const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
    if payload_hash.eq_ignore_ascii_case(UNSIGNED_PAYLOAD) {
        tracing::debug!(
            "inbound SigV4 rejected: UNSIGNED-PAYLOAD not permitted for governed ingress"
        );
        return Err(());
    }
    let actual_body_hash = crate::sigv4::sha256_hex(body);
    if !AuthMiddleware::constant_time_eq(&actual_body_hash, &payload_hash.to_ascii_lowercase()) {
        tracing::debug!(
            "inbound SigV4 rejected: request body does not match signed x-amz-content-sha256"
        );
        return Err(());
    };
    let Some(amzdate) = headers
        .iter()
        .find(|(k, _)| k == X_AMZ_DATE)
        .map(|(_, v)| v.clone())
    else {
        tracing::debug!("inbound SigV4 rejected: missing x-amz-date");
        return Err(());
    };

    let canonical_uri = crate::sigv4::uri_encode_path(req.uri().path());
    let canonical_qs = canonical_query_string(req.uri().query());
    let method = req.method().as_str().to_string();

    let inbound = InboundRequest {
        method: &method,
        canonical_uri: &canonical_uri,
        canonical_querystring: &canonical_qs,
        headers: &headers,
        payload_hash: &payload_hash,
        amzdate: &amzdate,
    };

    // Resolve (kind="sigv4", AccessKeyId) to (key, credential). On an UNKNOWN AccessKeyId, verify
    // against a fixed dummy secret so the work — and the timing/response — is indistinguishable
    // from a wrong-signature rejection (no AccessKeyId-enumeration oracle). The dummy is a
    // constant, never a real secret.
    let now = crate::store::now();
    let (secret, resolved): (String, Option<(crate::governance::VirtualKey, bool)>) =
        match gov.lookup_credential("sigv4", &parsed.access_key_id) {
            Some((key, cred)) => {
                let live = cred.meta.is_live(now);
                // `plaintext()` strips the "v1:plain:" envelope — HMAC verification needs the exact
                // raw bytes the client signed with, never the versioned-envelope string itself. An
                // unrecognized scheme (e.g. a future at-rest-encrypted form reached through the wrong
                // path) falls back to the dummy secret, same treatment as an unknown AccessKeyId — it
                // must never surface as a distinguishable rejection reason.
                let secret = cred
                    .plaintext()
                    .map(str::to_string)
                    .unwrap_or_else(|| DUMMY_SECRET.to_string());
                (secret, Some(((*key).clone(), live)))
            }
            None => (DUMMY_SECRET.to_string(), None),
        };

    let verify = verify_inbound_sigv4(&parsed, &inbound, &secret, now);

    // Decide admission. The signature must verify; the resolved key must exist AND be enabled; the
    // resolved CREDENTIAL itself must be live (not revoked, not expired — independent of the key,
    // per CredentialMeta::is_live: this is what lets a leaked SigV4 secret be killed via
    // revoke_credential without touching the key's bearer token or re-minting anything); AND the
    // subject not on the KEY-level revocation denylist. All conditions are evaluated, and only the
    // combined success admits — a failure in any one rejects with the same opaque `Err(())`. An
    // unknown AccessKeyId has `resolved == None`, so even a (cryptographically impossible)
    // signature match against the dummy secret cannot admit.
    //
    // The denylist clause mirrors the signed-token path (`verify_token`), which consults
    // `denylist.contains(&claims.sub)` before resolving. A dual-credential key (signed token +
    // SigV4) is bound to ONE subject id; `revoke` denylists that id but deliberately preserves
    // `enabled` for history — so WITHOUT this check the SigV4 credential of a revoked key would keep
    // authenticating even though its signed token is rejected. Gating here closes that bypass.
    match (verify, resolved) {
        (Ok(()), Some((key, true))) if key.enabled && !gov.is_revoked(&key.id) => Ok(key),
        (Ok(()), Some((key, true))) if key.enabled => {
            tracing::debug!(id = %key.id, "inbound SigV4 rejected: subject is revoked");
            Err(())
        }
        (Ok(()), Some((_key, true))) => {
            tracing::debug!("inbound SigV4 rejected: virtual key disabled");
            Err(())
        }
        (Ok(()), Some((key, false))) => {
            tracing::debug!(id = %key.id, "inbound SigV4 rejected: this credential is revoked or expired");
            Err(())
        }
        (Ok(()), None) => {
            // Signature "verified" against the dummy secret but the AccessKeyId is unknown — this is
            // not reachable for a real signer (it would need to have signed with the dummy secret) but
            // is handled explicitly so an unknown key can NEVER authenticate.
            tracing::debug!("inbound SigV4 rejected: unknown access key id");
            Err(())
        }
        (Err(e), _) => {
            tracing::debug!(reason = ?e, "inbound SigV4 rejected");
            Err(())
        }
    }
}

#[cfg(test)]
impl AuthMiddleware {
    /// Build an `AuthMiddleware` directly over a chain, declaring whether it should be treated as
    /// containing a PLUGIN module. Tests need this because the real constructor only sets
    /// `has_plugin_module` by actually `dlopen`ing a signed cdylib, and the property under test
    /// (that a blocking module does not run on the reactor) is about ANY blocking module.
    /// `chain` entries are `(provider NAME, module)`: the name is the `identity-providers:` key that
    /// chain position referenced, and is what a successful `Identify` reports as
    /// [`ChainVerdict::Identified::module`].
    pub(crate) fn from_chain_for_test(
        chain: Vec<(String, Box<dyn AuthModule>)>,
        has_plugin_module: bool,
    ) -> Self {
        Self {
            keys_in_chain: false,
            chain,
            has_plugin_module,
        }
    }
}

/// RFC 8707 audience binding for credentials busbar did not mint — the confused-deputy defence for
/// the operator-IdP deployment shape, where an auth plugin verifies the signature and core still has
/// to decide whether the token was minted for THIS resource.
pub mod audience;

/// The RFC 6750 `WWW-Authenticate` challenge, for ingresses that are OAuth 2.1 resource servers.
/// Relocated to the neutral substrate (`busbar_substrate::auth::challenge`) — pure `axum::http` +
/// `serde_json`, no core reach — so a plane crate names it without depending on core; re-exported
/// here so `crate::auth::challenge::{refuse, ChallengeError}` still resolves for its in-core callers.
pub use busbar_substrate::auth::challenge;

/// The self-serve key SEAM (1.5.2 token-exchange): `SelfServeKeys` trait + the deterministic
/// GovState-backed impl, and the verdict→mint decision the `POST /auth/token` handler drives.
pub(crate) mod self_keys;

/// The `POST /auth/token` data-plane exchange handler (identity from the verified chain, mint via
/// the [`self_keys`] seam).
pub(crate) mod exchange;

/// The `GET /auth/token` hosted browser-login page (1.5.2): the chooser / begin / callback
/// sub-states, PKCE + state + nonce, the core-executed token-exchange hop (client_secret injected by
/// the CORE only), and the render of the key-issued page — all issuing through the SAME [`self_keys`]
/// seam as the headless `POST`.
pub(crate) mod token;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/plugin_chain_tests.rs"]
mod plugin_chain_tests;
