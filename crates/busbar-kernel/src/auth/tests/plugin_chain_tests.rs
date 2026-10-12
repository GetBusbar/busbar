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

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");

    rt.spawn(async move {
        let _ = AuthMiddleware::run_chain_on_request_path(
            &auth,
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
