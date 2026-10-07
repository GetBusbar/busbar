// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AUTH-CHAIN seam tests over the kernel's own pipeline: `plugins_preflight` + `AuthMiddleware::new`
//! as boot runs them, and the chain's walk, offload and cache admission. They prove:
//!
//! * a role a chain position asserts resolves through `role_bindings.<provider>` to an admin scope,
//!   capped by the provider's `max_admin_scope`;
//! * a MISSING or UNTRUSTED plugin at boot → a LOUD failure (never a silently-open front door);
//! * `plugins.enabled: false` + a configured auth plugin → boot refuses (`plugins_preflight`);
//! * the chain never runs a blocking module on the reactor, and admits nothing to the credential
//!   cache for a chain that did not identify.
//!
//! The kernel's tests name no auth plugin (R-FIX3): a chain position here is an in-process test
//! module (`auth::stand_in`), and an auth row that must not load is a structurally valid tarball whose
//! library bytes are not a library. The FULL-CHAIN proofs over the REAL token-verifying module
//! (GetBusbar/busbar-auth-oidc, R-FIX2: a signed JWT through the dropped-in door, a secret-ref setting
//! delivered to it, the admin chain rebuilt on reload, the login-capability gate) live with the
//! composition root, which links it: `crates/busbar/tests/auth_plugin_chain.rs`.
//!
//! Mirrors the store-plugin end-to-end packed test (`crate::tests`), reusing its plugin-dir /
//! manifest helpers.

use crate::auth::{AuthMiddleware, ChainVerdict};
use crate::config::{AuthCfg, AuthChainEntry, PluginsCfg};
use crate::tests::{plugin_manifest, tmp_plugin_dir, unsigned_tarball};
use std::path::Path;

/// The issuer every token in this file is signed by, and the audience it is bound to.
const ISSUER: &str = "https://issuer.plugin-chain.invalid";
const AUDIENCE: &str = "api://plugin-chain";

/// THE LOCAL ISSUER, one per test process (the loader's `test_issuer`): an ES256 key, its JWKS
/// served only to a need trusting the issuer's certificate (which the module names as its
/// `ca_cert_pem`), and genuinely signed tokens. Starting it also binds the test build's auth axis to
/// a connection table serving that JWKS (`https_conns`): the host fetches it for the module over its
/// declared need, and the module does the whole verification.
fn issuer() -> &'static busbar_plugin_loader::test_issuer::Issuer {
    static ONE: std::sync::OnceLock<busbar_plugin_loader::test_issuer::Issuer> =
        std::sync::OnceLock::new();
    ONE.get_or_init(|| {
        let issuer = busbar_plugin_loader::test_issuer::Issuer::start(ISSUER, "plugin-chain");
        let conns = busbar_plugin_loader::https_conns::HttpsConns::new();
        conns.serve_issuer(&issuer);
        busbar_plugin_loader::auth_axis::stand_in_conns(std::sync::Arc::new(conns));
        issuer
    })
}

/// The module's `settings:` for the local issuer and [`AUDIENCE`].
fn settings() -> serde_json::Map<String, serde_json::Value> {
    issuer().settings(AUDIENCE)
}

/// A `kind: auth` row's manifest for the given name/alias whose library bytes are not a library
/// (the store helper stamps kind=store; we retarget it to auth + the auth ABI so the scan admits
/// its structure). Nothing ever loads it: it is the row a trust or presence refusal judges.
fn auth_row_manifest(
    name: &str,
    alias: &str,
    publisher: &str,
) -> busbar_plugin_loader::sign::Manifest {
    let mut m = plugin_manifest(name, alias, publisher);
    m.kind = "auth".into();
    m.abi_version = *busbar_plugin_loader::supported_abi("auth")
        .iter()
        .max()
        .expect("auth abi");
    m
}

/// The bytes an auth row carries where a library would be.
const NOT_A_LIBRARY: &[u8] = b"an auth row whose library bytes are not a library";

/// An enabled plugins config over `dir` that permits unsigned rows.
fn plugins_cfg_allow_unsigned(dir: &Path) -> PluginsCfg {
    let mut cfg = PluginsCfg {
        enabled: true,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    cfg.trust.allow_unsigned = true;
    cfg
}

/// An `auth.chain` naming exactly the given plugin module (with an optional `settings` map).
fn chain_with(module: &str, settings: serde_json::Map<String, serde_json::Value>) -> AuthCfg {
    let mut entry = AuthChainEntry::bare(module);
    entry.settings = settings;
    AuthCfg {
        chain: vec![entry],
        ..AuthCfg::default_none()
    }
}

/// An in-process chain position that identifies the credential `alice` as `oidc:alice` holding the
/// role `platform` (the shape of a token-verifying module's verdict), and passes anything else.
struct PlatformRole;
impl busbar_contract::auth::AuthModule for PlatformRole {
    fn name(&self) -> &'static str {
        "platform-role-module"
    }
    fn authenticate(&self, candidate: Option<&str>) -> busbar_contract::auth::AuthVerdict {
        match candidate {
            Some("alice") => busbar_contract::auth::AuthVerdict::Identify(crate::auth::Principal {
                id: "oidc:alice".to_string(),
                name: None,
                roles: vec!["platform".to_string()],
                ttl_secs: None,
            }),
            _ => busbar_contract::auth::AuthVerdict::Pass,
        }
    }
}

/// IDENTITY → POLICY hop under a PROVIDER name: a role a chain position asserts resolves through
/// `role_bindings.<provider>` to an admin scope, CAPPED by the provider's `max_admin_scope`. Proves
/// role_bindings resolution + the module ceiling both work when `<module>` is a provider the chain
/// names (the role the REAL token-verifying module asserts from a signed token is proven by
/// `crates/busbar/tests/auth_plugin_chain.rs::auth_plugin_loads_and_identifies_through_middleware`).
#[test]
fn auth_plugin_role_binding_and_scope_cap_apply() {
    use busbar_contract::authz::Scope;

    let mut cfg = chain_with("idp", serde_json::Map::new());
    // The chain entry caps this module at `read-only`, below the `full` the role would otherwise
    // grant (1.5.2 scope collapse retired the intermediate `mint`/`hooks-register` ceilings).
    cfg.chain[0].max_admin_scope = Some("read-only".into());
    // role_bindings NESTED BY THE PROVIDER NAME (`idp`): the `platform` role → full.
    let mut roles = std::collections::BTreeMap::new();
    roles.insert(
        "platform".to_string(),
        crate::config::RoleBindingCfg {
            admin_scope: Some("full".into()),
            ..Default::default()
        },
    );
    cfg.role_bindings.insert("idp".into(), roles);

    // The chain position the provider `idp` names, in process.
    let mw = AuthMiddleware::from_chain_for_test(
        vec![(
            "idp".to_string(),
            Box::new(PlatformRole) as Box<dyn crate::auth::AuthModule>,
        )],
        /* offload = */ false,
    );

    let principal = match mw.run_chain(Some("alice")) {
        ChainVerdict::Identified {
            module, principal, ..
        } => {
            assert_eq!(module, "idp", "role_bindings key = the PROVIDER NAME");
            principal
        }
        other => panic!("expected Identify, got {other:?}"),
    };
    // The role resolves to `full` in role_bindings.idp.platform...
    let bound = crate::auth::admin_scope_for(
        &crate::test_support::TestApp::new()
            .role_bindings(cfg.role_bindings.clone())
            .build(),
        Some("idp"),
        Some(&principal),
    );
    assert_eq!(
        bound,
        busbar_contract::authz::Grants::of(Scope::Full),
        "role binds full under the provider name"
    );
    // ..but the module's `max_admin_scope: read-only` ceiling caps the effective scope. Calling the
    // actual `Grants::capped_by` production method (instead of re-implementing the ceiling with
    // `std::cmp::min`) proves the real ceiling arithmetic under a provider name — a `full`
    // binding capped by a `read-only` ceiling collapses to read-only.
    let capped = bound.capped_by(Scope::ReadOnly);
    assert_eq!(
        capped,
        busbar_contract::authz::Grants::of(Scope::ReadOnly),
        "max_admin_scope caps the plugin module"
    );
}

/// FAIL-CLOSED: a configured auth plugin that is PRESENT but UNTRUSTED (unsigned under the default
/// strict policy) is SKIPPED by the scan; both `plugins_preflight` and `AuthMiddleware::new` must
/// fail LOUD — never silently drop the front-door module and admit everyone.
#[test]
fn untrusted_auth_plugin_fails_closed_not_open() {
    let dir = tmp_plugin_dir("auth-plugin-untrusted");
    let tarball = unsigned_tarball(
        auth_row_manifest("acme-idp", "test-idp-double", "acme"),
        NOT_A_LIBRARY,
    );
    std::fs::write(dir.join("idp.tar.gz"), tarball).unwrap();

    // STRICT default trust: the unsigned auth plugin is skipped.
    let strict = PluginsCfg {
        enabled: true,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cfg = chain_with("test-idp-double", settings());
    // Preflight refuses (names the module + carries the trust opt-in to set).
    let err = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &strict,
        &Default::default(),
    )
    .unwrap_err();
    assert!(
        err.contains("test-idp-double"),
        "names the auth module: {err}"
    );
    assert!(
        err.contains("allow_unsigned"),
        "carries the trust reason: {err}"
    );

    // And the middleware itself fail-closes on the skipped plugin (the runtime load-time gate):
    // the scan succeeds (skips are not fatal) but resolving the referenced module fails loud.
    let registry = busbar_plugin_loader::scan_and_validate(
        Path::new(&strict.dir),
        &crate::test_support::trust_policy(&strict).unwrap(),
    )
    .expect("scan succeeds; the untrusted plugin is merely skipped");
    let registry = std::sync::Arc::new(registry);
    let mw_err = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .unwrap_err();
    assert!(
        mw_err.contains("test-idp-double"),
        "middleware names the module: {mw_err}"
    );
    assert!(
        mw_err.contains("not loaded") || mw_err.contains("was not loaded"),
        "middleware fail-closes with the trust reason: {mw_err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED: a configured auth plugin with NO matching tarball is a loud boot error at both
/// gates — never silently skipped.
#[test]
fn missing_auth_plugin_is_loud_boot_failure() {
    let dir = tmp_plugin_dir("auth-plugin-missing");
    // A DIFFERENT (store) plugin present, so the dir is non-empty but the auth ref is absent.
    let other = unsigned_tarball(plugin_manifest("acme-store-x", "x", "acme"), b"lib");
    std::fs::write(dir.join("x.tar.gz"), other).unwrap();
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let cfg = chain_with("test-idp-double", settings());

    let err = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .unwrap_err();
    assert!(
        err.contains("test-idp-double"),
        "names the missing module: {err}"
    );
    assert!(
        err.contains("no plugin matching") && err.contains("is installed in"),
        "explains it is unresolved: {err}"
    );
    // The two-part diagnosis — subsystem enabled? / tarball in the folder? + the fetch/drop
    // remediation.
    assert!(
        err.contains("enabled") && err.contains("plugins.fetch"),
        "gives the two-part enabled?/in-folder? diagnosis: {err}"
    );

    // The middleware's own resolution is equally loud.
    let registry = busbar_plugin_loader::scan_and_validate(
        Path::new(&plugins.dir),
        &crate::test_support::trust_policy(&plugins).unwrap(),
    )
    .expect("scan");
    let registry = std::sync::Arc::new(registry);
    let mw_err = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .unwrap_err();
    assert!(
        mw_err.contains("test-idp-double"),
        "middleware names it: {mw_err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED: `plugins.enabled: false` with a configured auth plugin refuses boot naming the flag
/// — the plugin subsystem being off must never leave a configured front-door module silently absent.
#[test]
fn auth_plugin_with_plugins_disabled_is_boot_error_naming_the_flag() {
    let dir = tmp_plugin_dir("auth-plugin-disabled");
    let plugins = PluginsCfg {
        enabled: false,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cfg = chain_with("test-idp-double", settings());
    let err = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .unwrap_err();
    assert!(err.contains("plugins.enabled"), "names the flag: {err}");
    assert!(
        err.contains("test-idp-double"),
        "names the auth module: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The builtin `keys` module is engine-handled and never treated as a plugin — a `[keys]` chain
/// needs no plugin subsystem and loads fine with plugins disabled (regression guard for the
/// plugin-ref filter).
#[test]
fn keys_module_is_not_a_plugin_ref() {
    let cfg = AuthCfg {
        chain: vec![AuthChainEntry::bare(crate::config::KEYS_MODULE)],
        ..AuthCfg::default_none()
    };
    // No plugins dir, plugins disabled: keys must not be treated as a plugin ref.
    let plugins = PluginsCfg::default();
    let registry = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("keys needs no plugin");
    let registry = std::sync::Arc::new(registry);
    let mw = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect("keys chain builds");
    assert!(mw.keys_in_chain, "keys sets the engine flag");
    assert!(mw.chain_names().is_empty(), "keys is not a boxed module");
}

// ── THE AUTH CHAIN MUST NOT RUN ON THE REACTOR ───────────────────────────────────
//
// A `kind: auth` plugin's `authenticate` is a synchronous FFI call, and behind it the module does
// whatever it does — the shipped OIDC module fetches JWKS over blocking HTTPS with a 10s timeout.
// `auth_middleware` is an `async fn` on a Tokio worker, so calling the chain inline hands that
// worker to the plugin. A slow identity provider then parks one worker per in-flight request until
// the runtime polls nothing at all: not other requests, not the admin plane, and not `/healthz`
// (exempt from the chain, but it still needs a worker thread to run). The node fails its liveness
// probe and is killed, over an IdP most of the stalled traffic never used.

/// An auth module that blocks — the shape of every plugin that talks to a network identity
/// provider. It signals the moment it is entered, so the test never has to guess at timing.
struct BlockingModule {
    entered: std::sync::mpsc::Sender<()>,
    hold: std::time::Duration,
}
impl busbar_contract::auth::AuthModule for BlockingModule {
    fn name(&self) -> &'static str {
        "blocking-test-module"
    }
    fn authenticate(&self, _candidate: Option<&str>) -> busbar_contract::auth::AuthVerdict {
        let _ = self.entered.send(());
        std::thread::sleep(self.hold);
        busbar_contract::auth::AuthVerdict::Pass
    }
    fn cacheable(&self) -> bool {
        false
    }
}

/// Called INLINE from `auth_middleware`, the probe below is never scheduled, because the single
/// worker is inside the plugin. OFFLOADED to the blocking pool, the worker is free and the probe
/// completes while the plugin is still blocking.
///
/// A one-worker runtime is not a contrived shape — busbar sizes its runtime from
/// `available_parallelism()` and the docs recommend 1-2 workers for sidecar deployments. It is
/// simply the smallest configuration in which "a worker is parked" is decidable.
#[test]
fn a_blocking_auth_plugin_does_not_park_the_reactor() {
    let (tx, entered) = std::sync::mpsc::channel();
    let auth = std::sync::Arc::new(AuthMiddleware::from_chain_for_test(
        vec![(
            "blocking".to_string(),
            Box::new(BlockingModule {
                entered: tx,
                hold: std::time::Duration::from_secs(3),
            }) as Box<dyn crate::auth::AuthModule>,
        )],
        /* offload = */ true,
    ));
    let cache = std::sync::Arc::new(crate::auth_cache::CredentialCache::new());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");

    rt.spawn(async move {
        let _ = AuthMiddleware::run_chain_on_request_path(
            &auth,
            &cache,
            Some("tok".into()),
            crate::auth::ChainHead::default(),
            None,
            None,
        )
        .await;
    });
    entered
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the auth module must actually have been entered");

    // Can the runtime still schedule anything while the module blocks? Signalled over a STD channel
    // with a std timeout deliberately: a dead reactor has a dead timer driver, so a
    // `tokio::time::timeout` would hang instead of failing.
    let (ptx, probe) = std::sync::mpsc::channel();
    rt.spawn(async move {
        let _ = ptx.send("healthz ok");
    });
    let served = probe.recv_timeout(std::time::Duration::from_secs(2));
    assert!(
        matches!(served, Ok("healthz ok")),
        "the runtime must keep serving while an auth module blocks; the worker is parked inside \
         the plugin (got {served:?})"
    );
}

/// The counterpart, so the offload is not applied blindly: an ALL-IN-PROCESS chain is called
/// inline. Those modules are microsecond constant-time compares, and paying a `spawn_blocking` hop
/// per request to protect against work that cannot block would be a pure regression. Asserted by
/// behaviour — the verdict is identical and correct either way — plus the explicit flag.
#[test]
fn an_in_process_chain_is_not_offloaded() {
    let auth = std::sync::Arc::new(AuthMiddleware::from_chain_for_test(
        vec![(
            "test-groups-module".to_string(),
            Box::new(crate::auth::TestGroupsModule) as Box<dyn crate::auth::AuthModule>,
        )],
        /* offload = */ false,
    ));
    let cache = std::sync::Arc::new(crate::auth_cache::CredentialCache::new());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    // A current-thread runtime has NO blocking-pool round-trip to hide behind: if this path tried to
    // offload, the verdict would still arrive, but the point is that it resolves synchronously
    // within one poll of the future.
    let verdict = rt.block_on(async {
        AuthMiddleware::run_chain_on_request_path(
            &auth,
            &cache,
            Some("grp:admins".into()),
            crate::auth::ChainHead::default(),
            None,
            None,
        )
        .await
    });
    assert!(
        matches!(verdict, ChainVerdict::Identified { .. }),
        "an in-process chain must keep identifying exactly as before"
    );
}

// ── PASS ADMISSION IS CHAIN-OUTCOME-CONDITIONED ──────────────────────────────────
//
// `TestGroupsModule` (used above) leaves `cacheable()` at the trait default `false`
// (`api/src/auth.rs:67-69`), so it cannot exercise the cache. These two purpose-built modules are
// `cacheable() -> true`, mirroring `BlockingModule`'s pattern above but for the caching path
// instead of the offload path.

/// Always `Pass`es, and is cacheable — the shape of a `cacheable` introspection/directory module
/// that does not recognize a given credential.
struct CacheablePass;
impl busbar_contract::auth::AuthModule for CacheablePass {
    fn name(&self) -> &'static str {
        "cacheable-pass-module"
    }
    fn authenticate(&self, _candidate: Option<&str>) -> busbar_contract::auth::AuthVerdict {
        busbar_contract::auth::AuthVerdict::Pass
    }
    fn cacheable(&self) -> bool {
        true
    }
}

/// Always `Reject`s, and is cacheable (cacheability is irrelevant to `Reject`, which
/// `auth_cache.rs:104` never caches regardless — included so the chain-position test is honest).
struct CacheableReject;
impl busbar_contract::auth::AuthModule for CacheableReject {
    fn name(&self) -> &'static str {
        "cacheable-reject-module"
    }
    fn authenticate(&self, _candidate: Option<&str>) -> busbar_contract::auth::AuthVerdict {
        busbar_contract::auth::AuthVerdict::Reject
    }
    fn cacheable(&self) -> bool {
        true
    }
}

/// `Identify`s any candidate that equals `"good"`, else `Pass`es. Cacheable.
struct CacheableIdentify;
impl busbar_contract::auth::AuthModule for CacheableIdentify {
    fn name(&self) -> &'static str {
        "cacheable-identify-module"
    }
    fn authenticate(&self, candidate: Option<&str>) -> busbar_contract::auth::AuthVerdict {
        match candidate {
            Some("good") => busbar_contract::auth::AuthVerdict::Identify(crate::auth::Principal {
                id: "test:good".to_string(),
                name: None,
                roles: vec![],
                ttl_secs: None,
            }),
            _ => busbar_contract::auth::AuthVerdict::Pass,
        }
    }
    fn cacheable(&self) -> bool {
        true
    }
}

/// An unauthenticated caller (a chain that never identifies) must leave NO trace in the
/// cache. A `run_chain_cached` that `put`s a fresh `Pass` immediately leaves `flush_all()`
/// observing 1 — and that `Pass` is what displaces a real
/// `Identify` under the oldest-inserted eviction rule (`auth_cache.rs:111-114`).
#[test]
fn an_unauthenticated_chain_admits_nothing_to_the_cache() {
    let auth = AuthMiddleware::from_chain_for_test(
        vec![(
            "cacheable-pass".to_string(),
            Box::new(CacheablePass) as Box<dyn crate::auth::AuthModule>,
        )],
        /* offload = */ false,
    );
    let cache = crate::auth_cache::CredentialCache::new();

    let verdict = auth.run_chain_cached(
        Some("junk-token"),
        Some(&cache),
        None,
        busbar_kernel::store::now(),
        None,
    );

    assert_eq!(verdict, ChainVerdict::Denied);
    assert_eq!(
        cache.flush_all(),
        0,
        "an all-Pass chain must admit nothing to the cache"
    );
}

/// A chain that `Pass`es through a leading module and is then `Reject`ed must also admit
/// nothing — the leading `Pass` must not be committed before the `Reject` short-circuits the
/// chain. This is the case the old `MAX_PASS_ENTRIES` partition design never addressed at all: it
/// still admitted this leading `Pass`.
#[test]
fn a_rejected_chain_admits_nothing_to_the_cache() {
    let auth = AuthMiddleware::from_chain_for_test(
        vec![
            (
                "cacheable-pass".to_string(),
                Box::new(CacheablePass) as Box<dyn crate::auth::AuthModule>,
            ),
            (
                "cacheable-reject".to_string(),
                Box::new(CacheableReject) as Box<dyn crate::auth::AuthModule>,
            ),
        ],
        /* offload = */ false,
    );
    let cache = crate::auth_cache::CredentialCache::new();

    let verdict = auth.run_chain_cached(
        Some("junk-token"),
        Some(&cache),
        None,
        busbar_kernel::store::now(),
        None,
    );

    assert_eq!(verdict, ChainVerdict::Denied);
    assert_eq!(
        cache.flush_all(),
        0,
        "a chain that ends in Reject must admit nothing to the cache, including the leading Pass"
    );
}

/// The end-to-end scenario. A real `Identify` is cached first (the entry the
/// eviction rule must protect); then an unauthenticated caller runs the chain `MAX_ENTRIES` times
/// with distinct junk credentials at the SAME `now`, so `retain`'s expiry sweep reclaims nothing
/// and every `put` must fall through to `min_by_key(inserted_seq)`. An unconditional-`Pass`-put
/// admits each of those, and because the `Identify` was inserted first it has the lowest
/// `inserted_seq` and is evicted FIRST (`auth_cache.rs:111-114`).
#[test]
fn pass_churn_cannot_evict_an_identity() {
    let auth = AuthMiddleware::from_chain_for_test(
        vec![(
            "cacheable-pass".to_string(),
            Box::new(CacheablePass) as Box<dyn crate::auth::AuthModule>,
        )],
        /* offload = */ false,
    );
    let cache = crate::auth_cache::CredentialCache::new();
    let now = 1_000_000u64;

    cache.put(
        "real-identity-module",
        "real-credential",
        &busbar_contract::auth::AuthVerdict::Identify(crate::auth::Principal {
            id: "real:identity".to_string(),
            name: None,
            roles: vec![],
            ttl_secs: Some(3600),
        }),
        now,
        cache.generation(),
    );

    for i in 0..4096u64 {
        let junk = format!("junk-{i}");
        let _ = auth.run_chain_cached(Some(&junk), Some(&cache), None, now, None);
    }

    assert!(
        matches!(
            cache.get("real-identity-module", "real-credential", now),
            Some(busbar_contract::auth::AuthVerdict::Identify(_))
        ),
        "unauthenticated Pass churn must not evict a real identity from the cache"
    );
}

/// REGRESSION PROOF (passes before and after): the buffering must not be over-broad. An
/// authenticated multi-module chain — a leading module that `Pass`es, followed by one that
/// `Identify`s — must keep caching BOTH entries exactly as it does today, so the leading module's
/// round-trip is still saved on the next request. If this goes red, the commit-on-identify path is
/// wrong.
#[test]
fn an_identified_chain_still_caches_the_leading_pass() {
    let auth = AuthMiddleware::from_chain_for_test(
        vec![
            (
                "cacheable-pass".to_string(),
                Box::new(CacheablePass) as Box<dyn crate::auth::AuthModule>,
            ),
            (
                "cacheable-identify".to_string(),
                Box::new(CacheableIdentify) as Box<dyn crate::auth::AuthModule>,
            ),
        ],
        /* offload = */ false,
    );
    let cache = crate::auth_cache::CredentialCache::new();

    let verdict = auth.run_chain_cached(
        Some("good"),
        Some(&cache),
        None,
        busbar_kernel::store::now(),
        None,
    );

    assert!(matches!(verdict, ChainVerdict::Identified { .. }));
    assert_eq!(
        cache.flush_all(),
        2,
        "an identified chain must still cache both the leading Pass and the Identify"
    );
}

/// `Identify`s any candidate that equals `"revocable"` with a module-suggested TTL, else `Pass`es.
/// Cacheable, and COUNTS every `authenticate` call (shared via the `Arc` the test holds onto) so a
/// revocation-bypass regression can prove the module was RE-CONSULTED rather than served from a
/// cache entry whose lifetime a hit silently extended.
struct CountingIdentify {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl busbar_contract::auth::AuthModule for CountingIdentify {
    fn name(&self) -> &'static str {
        "counting-identify-module"
    }
    fn authenticate(&self, candidate: Option<&str>) -> busbar_contract::auth::AuthVerdict {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match candidate {
            Some("revocable") => {
                busbar_contract::auth::AuthVerdict::Identify(crate::auth::Principal {
                    id: "test:revocable".to_string(),
                    name: None,
                    roles: vec![],
                    ttl_secs: Some(10),
                })
            }
            _ => busbar_contract::auth::AuthVerdict::Pass,
        }
    }
    fn cacheable(&self) -> bool {
        true
    }
}

/// AUTH-CACHE REVOCATION BYPASS (RED before the fix). `run_chain_cached` must never refresh a
/// cache entry's TTL just because it was PRESENTED again — the TTL bounds how stale an admission
/// decision may be, and a hit that resets it makes that bound unreachable: a credential presented
/// more often than its own TTL would never be re-verified against the module, so a revocation would
/// never take effect. This proves the opposite: hit the entry repeatedly at an interval SHORTER
/// than its TTL (each hit must be served from cache, module NOT re-consulted), then query PAST the
/// ORIGINAL TTL boundary (not any hit-refreshed one) and prove the chain is RE-RUN.
///
/// The call counter is the oracle: 1 after the first (miss) call, still 1 after every in-window
/// hit, and 2 only once queried past the entry's ORIGINAL expiry. A buggy re-`put`-on-hit would
/// have pushed the entry's expiry out to `last_hit_time + TTL` on each hit, so the exact instant
/// chosen below (`t0 + TTL + 1`) sits PAST the original boundary but still INSIDE that
/// bug-extended one — it would read as a HIT (calls staying at 1) under the bug and only reads as a
/// MISS (calls becoming 2) once the fix lands.
#[test]
fn a_credential_hit_within_ttl_does_not_extend_the_cache_entrys_lifetime() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let auth = AuthMiddleware::from_chain_for_test(
        vec![(
            "counting-identify".to_string(),
            Box::new(CountingIdentify {
                calls: calls.clone(),
            }) as Box<dyn crate::auth::AuthModule>,
        )],
        /* offload = */ false,
    );
    let cache = crate::auth_cache::CredentialCache::new();
    let t0 = 1_000_000u64;
    const TTL: u64 = 10;

    // First call: a cache MISS, so the module runs and the verdict is cached with its 10s TTL
    // (expires_at == t0 + TTL).
    let v0 = auth.run_chain_cached(Some("revocable"), Some(&cache), None, t0, None);
    assert!(matches!(v0, ChainVerdict::Identified { .. }));
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the first presentation must consult the module (cache starts empty)"
    );

    // Hit it repeatedly at an interval SHORTER than the TTL (3s steps, well under 10s), all still
    // inside the ORIGINAL window (t0+3 and t0+6 are both < t0+TTL == t0+10). Every one of these
    // must be served from the cache: the module call count must not move.
    for offset in [3u64, 6] {
        let v = auth.run_chain_cached(Some("revocable"), Some(&cache), None, t0 + offset, None);
        assert!(matches!(v, ChainVerdict::Identified { .. }));
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a hit inside the TTL window must be served from cache, not re-consult the module \
             (offset {offset})"
        );
    }

    // Advance PAST the ORIGINAL TTL boundary (t0 + TTL == t0 + 10), to t0 + 11 — which is still
    // INSIDE a bug-extended window (the last hit was at t0 + 6, so a buggy re-put would have set
    // expires_at = t0 + 6 + TTL == t0 + 16). The chain MUST be re-run here: a revoked credential
    // presented on this steady cadence must be re-checked against the module, not served stale.
    let past_original_ttl = t0 + TTL + 1;
    let v_after = auth.run_chain_cached(
        Some("revocable"),
        Some(&cache),
        None,
        past_original_ttl,
        None,
    );
    assert!(matches!(v_after, ChainVerdict::Identified { .. }));
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "past the ORIGINAL TTL the chain must be RE-RUN — a hit must never have refreshed the \
         entry's expiry, or a revoked credential would silently keep working forever"
    );
}

// ── THE SAME RULE ON THE ADMIN CHAIN ──────────────────────────────────────────────────────────
//
// `run_admin_chain` runs its own copy of the walk above against the SAME `CredentialCache`
// (`state::App::credential_cache`, one 4096-entry instance shared by both planes), and it kept the
// unconditional `Pass` put the data plane gave up. The admin plane is where that costs the most: a
// cacheable admin module is by definition an EXTERNAL `kind: auth` plugin doing a JWKS /
// introspection round-trip, so unauthenticated churn on the admin surface evicted real DATA-PLANE
// identities under the oldest-inserted rule and bought nothing back — the denied request never
// consults the module again.
//
// `test-scope-module` is the compiled-in external-admin stand-in: it `Pass`es any credential that
// is not `grp:<group>`, and it is cacheable for exactly the reason a real one is (it is not the
// operator credential).

/// An unauthenticated ADMIN caller leaves NO trace in the shared credential cache — the rule
/// `an_unauthenticated_chain_admits_nothing_to_the_cache` already pins on the data plane.
#[test]
fn an_unauthenticated_admin_chain_admits_nothing_to_the_cache() {
    let app = crate::test_support::TestApp::new()
        .admin_chain(vec!["test-scope-module".to_string()])
        .build();

    let (verdict, _cap) = crate::auth::tests::run_admin_chain_on(&app, Some("junk-token"), None);

    assert_eq!(verdict, ChainVerdict::Denied);
    assert_eq!(
        app.credential_cache.flush_all(),
        0,
        "an all-Pass admin chain must admit nothing to the cache"
    );
}

/// THE END-TO-END SCENARIO: a real DATA-PLANE identity is cached first, then the cache is filled to
/// its ceiling with unauthenticated ADMIN probes carrying distinct junk credentials, all at the
/// same instant so nothing expires. Under the unconditional put, every probe admitted a `Pass` row
/// and the identity — which holds the lowest `inserted_seq` — is the first thing evicted, forcing
/// the data plane to re-verify against its module.
#[test]
fn admin_pass_churn_cannot_evict_an_identified_data_plane_row() {
    let app = crate::test_support::TestApp::new()
        .admin_chain(vec!["test-scope-module".to_string()])
        .build();
    let now = busbar_kernel::store::now();

    // The data plane's row, put exactly as `run_chain_cached` puts one.
    app.credential_cache.put(
        "data-plane-module",
        "data-plane-credential",
        &busbar_contract::auth::AuthVerdict::Identify(busbar_contract::auth::Principal::from_id(
            "acct:paying-customer",
        )),
        now,
        app.credential_cache.generation(),
    );

    // The cache's own ceiling (`auth_cache::MAX_ENTRIES`) worth of unauthenticated admin probes.
    for i in 0..4096u64 {
        let junk = format!("junk-{i}");
        let (verdict, _cap) = crate::auth::tests::run_admin_chain_on(&app, Some(&junk), None);
        assert_eq!(
            verdict,
            ChainVerdict::Denied,
            "the probe must be denied — this is unauthenticated churn, not a login"
        );
    }

    assert!(
        matches!(
            app.credential_cache
                .get("data-plane-module", "data-plane-credential", now),
            Some(busbar_contract::auth::AuthVerdict::Identify(_))
        ),
        "unauthenticated admin churn must not evict an identified data-plane row from the shared \
         cache"
    );
}

/// REGRESSION PROOF: the buffering is not over-broad. An admin chain that DOES identify still
/// caches what it resolved, so the next request on the same credential skips the module's
/// round-trip — which is the whole reason the admin cache exists.
#[test]
fn an_identified_admin_chain_still_caches_its_identity() {
    let app = crate::test_support::TestApp::new()
        .admin_chain(vec!["test-scope-module".to_string()])
        .build();

    let (verdict, _cap) = crate::auth::tests::run_admin_chain_on(&app, Some("grp:admins"), None);

    assert!(matches!(verdict, ChainVerdict::Identified { .. }));
    assert_eq!(
        app.credential_cache.flush_all(),
        1,
        "an identified admin chain must still cache the identity it resolved"
    );
}
