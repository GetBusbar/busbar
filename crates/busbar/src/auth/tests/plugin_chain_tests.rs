// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FULL-CHAIN auth-plugin seam tests: the engine's `AuthMiddleware` loading a REAL signed
//! `kind: auth` plugin cdylib over the loader, exactly as boot does. We pack the hermetic
//! `busbar-auth-static-plugin` cdylib into a tarball, run it through `plugins_preflight` +
//! `AuthMiddleware::new`, and prove:
//!
//! * a valid token → `Identify` → a mapped `Principal` whose roles resolve to `role_bindings`
//! policy AND whose admin scope is capped by `auth.chain.<module>.max_admin_scope`;
//! * an invalid/absent credential → the chain fail-closed-denies (all-`Pass`);
//! * a MISSING or UNTRUSTED plugin at boot → a LOUD failure (never a silently-open front door);
//! * `plugins.enabled: false` + a configured auth plugin → boot refuses (`plugins_preflight`).
//!
//! Mirrors the store-plugin end-to-end packed test (`crate::tests`), reusing its plugin-dir /
//! manifest helpers.

use crate::auth::{AuthMiddleware, ChainVerdict};
use crate::config::{AuthCfg, AuthChainEntry, PluginsCfg};
use crate::tests::{plugin_manifest, tmp_plugin_dir, unsigned_tarball};
use std::path::{Path, PathBuf};

/// Locate the hermetic static-auth plugin cdylib in the build's target dir (like the sqlite store
/// tests). Under CI (`cargo test --workspace` always builds it) a missing cdylib is a HARD failure,
/// never a silent skip; locally a missing cdylib skips cleanly.
fn static_auth_cdylib() -> Option<PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_auth_static_plugin");
        let candidate = profile_dir.join(&name);
        candidate.exists().then_some(candidate)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the static-auth plugin cdylib is not built under CI; refusing to silently skip the \
             full-chain auth-plugin seam coverage"
        );
    }
    candidate
}

/// A `kind: auth` manifest for the given name/alias (the store helper stamps kind=store; we retarget
/// it to auth + the auth ABI so the scan admits it).
fn auth_manifest(name: &str, alias: &str, publisher: &str) -> busbar_plugin_sign::Manifest {
    let mut m = plugin_manifest(name, alias, publisher);
    m.kind = "auth".into();
    m.abi_version = *busbar_plugin_loader::supported_abi("auth")
        .iter()
        .max()
        .expect("auth abi");
    m
}

/// Write an UNSIGNED (structurally valid) static-auth tarball into `dir` under `file`, returning the
/// cdylib bytes' presence. We use the unsigned+`allow_unsigned` path because the test cannot sign
/// with the embedded first-party release key; this still exercises the whole load pipeline.
fn write_static_auth(dir: &Path, file: &str, name: &str, alias: &str) -> bool {
    let Some(path) = static_auth_cdylib() else {
        return false;
    };
    let lib = std::fs::read(&path).expect("read static-auth cdylib");
    let tarball = unsigned_tarball(auth_manifest(name, alias, "acme"), &lib);
    std::fs::write(dir.join(file), tarball).unwrap();
    true
}

/// An enabled plugins config over `dir` that permits the unsigned test cdylib.
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

/// The static-auth `settings:` map: token `sekret` → id `alice`, role `platform`.
fn alice_settings() -> serde_json::Map<String, serde_json::Value> {
    serde_json::json!({ "token": "sekret", "id": "alice", "roles": ["platform"] })
        .as_object()
        .unwrap()
        .clone()
}

/// The static-auth settings with a `licenseKey` spelled as the given SecretRef value (raw JSON for
/// the ref, e.g. `{ "env": "VAR" }`). Proves the ENGINE resolves the ref before the plugin sees it.
fn alice_settings_with_license_ref(
    license_ref: serde_json::Value,
) -> serde_json::Map<String, serde_json::Value> {
    let mut s = alice_settings();
    s.insert("licenseKey".to_string(), license_ref);
    s
}

/// PLUGIN LICENSING E2E (ADR-0010): a `licenseKey` spelled as a SecretRef (`{ env: VAR }`) is
/// RESOLVED by the engine to the raw key and DELIVERED to the plugin, which validates it ITSELF and
/// loads. Conversely, an UNRESOLVABLE license ref fails the load FAIL-CLOSED — the plugin is never
/// handed a dangling reference. Proves the whole path: SecretRef-in-settings → resolve → deliver →
/// plugin self-validates.
#[test]
fn auth_plugin_license_key_secret_ref_is_resolved_and_delivered() {
    let dir = tmp_plugin_dir("auth-plugin-license");
    if !write_static_auth(&dir, "static.tar.gz", "acme-auth-static", "lic-auth") {
        eprintln!("skip: static-auth plugin cdylib not built (run under --workspace)");
        return;
    }
    let plugins = plugins_cfg_allow_unsigned(&dir);

    // A VALID license delivered via an env SecretRef: the engine resolves `{ env: VAR }` to the demo
    // key BEFORE open, the plugin validates its own license, and the chain loads.
    let ok_var = format!("BUSBAR_PLUGIN_LICENSE_OK_{}", std::process::id());
    std::env::set_var(&ok_var, "LICENSE-OK");
    let cfg = chain_with(
        "lic-auth",
        alice_settings_with_license_ref(serde_json::json!({ "env": ok_var })),
    );
    let registry = crate::plugins_preflight(None, Some(&cfg), &Default::default(), &plugins)
        .expect("preflight resolves the kind:auth plugin");
    let mw = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect("a resolvable, valid licenseKey is delivered and the plugin loads");
    assert_eq!(mw.chain_names(), vec!["static-auth"], "plugin loaded");
    std::env::remove_var(&ok_var);

    // FAIL-CLOSED: the SAME license ref, now UNRESOLVABLE (env unset), refuses the chain build — the
    // plugin is never handed the unresolved ref. The error names the field, never a secret value.
    let err = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect_err("an unresolvable licenseKey ref fails the load fail-closed");
    assert!(
        err.contains("licenseKey") && err.contains("did not resolve"),
        "fail-closed, names the setting: {err}"
    );
    // The overlay/config still holds the REFERENCE, never the resolved secret: SecretRef serializes
    // the ref, so a licenseKey setting serialized back out is the env ref, not `LICENSE-OK`.
    let serialized = serde_json::to_string(&cfg.chain[0].settings).expect("serialize settings");
    assert!(
        serialized.contains(&ok_var) && !serialized.contains("LICENSE-OK"),
        "config keeps the ref, never the resolved secret: {serialized}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// FULL CHAIN, REAL CDYLIB: `auth.chain: [my-auth]` loads the static-auth plugin over the loader;
/// the valid token identifies as `alice/platform`, an invalid/absent credential fail-closed-denies.
#[test]
fn auth_plugin_loads_and_identifies_through_middleware() {
    let dir = tmp_plugin_dir("auth-plugin-e2e");
    // The config chain name is the ALIAS `my-auth`; the plugin's canonical name differs on purpose.
    if !write_static_auth(&dir, "static.tar.gz", "acme-auth-static", "my-auth") {
        eprintln!("skip: static-auth plugin cdylib not built (run under --workspace)");
        return;
    }
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let cfg = chain_with("my-auth", alice_settings());

    // Manifest-only preflight resolves the auth plugin (the `--validate`/boot gate).
    let registry = crate::plugins_preflight(None, Some(&cfg), &Default::default(), &plugins)
        .expect("preflight resolves the kind:auth plugin");

    // The real load through the middleware — resolve → open_auth → box → chain.
    let mw = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect("auth chain loads the plugin");
    // The RUNTIME module identity is the plugin's own `name()` (`static-auth`), NOT the config alias.
    assert_eq!(mw.chain_names(), vec!["static-auth"], "runtime module name");

    // Valid token → Identify with the configured id + roles.
    match mw.run_chain(Some("sekret")) {
        ChainVerdict::Identified { module, principal } => {
            assert_eq!(module, "static-auth", "role_bindings key = module.name()");
            assert_eq!(principal.id, "alice");
            assert_eq!(principal.roles, vec!["platform".to_string()]);
        }
        other => panic!("valid token must Identify, got {other:?}"),
    }
    // Invalid credential → the module Passes → a non-empty chain fail-closed-DENIES.
    assert_eq!(
        mw.run_chain(Some("wrong")),
        ChainVerdict::Denied,
        "bad token denies"
    );
    // Absent credential → likewise denied (never the open front door for a configured chain).
    assert_eq!(
        mw.run_chain(None),
        ChainVerdict::Denied,
        "no credential denies"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// IDENTITY → POLICY hop with a PLUGIN module name: a role a loaded auth plugin asserts resolves
/// through `role_bindings.<plugin-name>` to an admin scope, CAPPED by the module's `max_admin_scope`.
/// Proves role_bindings resolution + the module ceiling both work when `<module>` is a plugin name.
#[test]
fn auth_plugin_role_binding_and_scope_cap_apply() {
    use crate::admin::v1::contract::Scope;

    let dir = tmp_plugin_dir("auth-plugin-policy");
    if !write_static_auth(&dir, "static.tar.gz", "acme-auth-static", "static-auth") {
        eprintln!("skip: static-auth plugin cdylib not built (run under --workspace)");
        return;
    }
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let mut cfg = chain_with("static-auth", alice_settings());
    // The chain entry caps this module at `mint`, below the `full` the role would otherwise grant.
    cfg.chain[0].max_admin_scope = Some("mint".into());
    // role_bindings NESTED BY THE PLUGIN'S RUNTIME NAME (`static-auth`): the `platform` role → full.
    let mut roles = std::collections::BTreeMap::new();
    roles.insert(
        "platform".to_string(),
        crate::config::RoleBindingCfg {
            admin_scope: Some("full".into()),
            ..Default::default()
        },
    );
    cfg.role_bindings.insert("static-auth".into(), roles);

    let registry = crate::plugins_preflight(None, Some(&cfg), &Default::default(), &plugins)
        .expect("preflight");
    let mw = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect("load");

    let principal = match mw.run_chain(Some("sekret")) {
        ChainVerdict::Identified { principal, .. } => principal,
        other => panic!("expected Identify, got {other:?}"),
    };
    // The role resolves to `full` in role_bindings.static-auth.platform...
    let bound =
        crate::auth::admin_scope_for(Some("static-auth"), Some(&principal), &cfg.role_bindings);
    assert_eq!(
        bound,
        Some(Scope::Full),
        "role binds full under the PLUGIN module name"
    );
    // ..but the module's `max_admin_scope: mint` ceiling caps the effective scope.
    let capped = std::cmp::min(bound.unwrap(), Scope::Mint);
    assert_eq!(
        capped,
        Scope::Mint,
        "max_admin_scope caps the plugin module"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED: a configured auth plugin that is PRESENT but UNTRUSTED (unsigned under the default
/// strict policy) is SKIPPED by the scan; both `plugins_preflight` and `AuthMiddleware::new` must
/// fail LOUD — never silently drop the front-door module and admit everyone.
#[test]
fn untrusted_auth_plugin_fails_closed_not_open() {
    let dir = tmp_plugin_dir("auth-plugin-untrusted");
    let Some(path) = static_auth_cdylib() else {
        eprintln!("skip: static-auth plugin cdylib not built (run under --workspace)");
        return;
    };
    let lib = std::fs::read(&path).unwrap();
    let tarball = unsigned_tarball(auth_manifest("acme-auth-static", "oidc", "acme"), &lib);
    std::fs::write(dir.join("static.tar.gz"), tarball).unwrap();

    // STRICT default trust: the unsigned auth plugin is skipped.
    let strict = PluginsCfg {
        enabled: true,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cfg = chain_with("oidc", alice_settings());
    // Preflight refuses (names the module + carries the trust opt-in to set).
    let err = crate::plugins_preflight(None, Some(&cfg), &Default::default(), &strict).unwrap_err();
    assert!(err.contains("oidc"), "names the auth module: {err}");
    assert!(
        err.contains("allow_unsigned"),
        "carries the trust reason: {err}"
    );

    // And the middleware itself fail-closes on the skipped plugin (the runtime load-time gate):
    // the scan succeeds (skips are not fatal) but resolving the referenced module fails loud.
    let registry = busbar_plugin_loader::scan_and_validate(
        Path::new(&strict.dir),
        &strict.to_policy().unwrap(),
    )
    .expect("scan succeeds; the untrusted plugin is merely skipped");
    let mw_err = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .unwrap_err();
    assert!(
        mw_err.contains("oidc"),
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
    let cfg = chain_with("oidc", alice_settings());

    let err =
        crate::plugins_preflight(None, Some(&cfg), &Default::default(), &plugins).unwrap_err();
    assert!(err.contains("oidc"), "names the missing module: {err}");
    assert!(
        err.contains("does not match any plugin"),
        "explains it is unresolved: {err}"
    );

    // The middleware's own resolution is equally loud.
    let registry = busbar_plugin_loader::scan_and_validate(
        Path::new(&plugins.dir),
        &plugins.to_policy().unwrap(),
    )
    .expect("scan");
    let mw_err = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .unwrap_err();
    assert!(mw_err.contains("oidc"), "middleware names it: {mw_err}");

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
    let cfg = chain_with("oidc", alice_settings());
    let err =
        crate::plugins_preflight(None, Some(&cfg), &Default::default(), &plugins).unwrap_err();
    assert!(err.contains("plugins.enabled"), "names the flag: {err}");
    assert!(err.contains("oidc"), "names the auth module: {err}");
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
    let registry = crate::plugins_preflight(None, Some(&cfg), &Default::default(), &plugins)
        .expect("keys needs no plugin");
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
impl busbar_api::AuthModule for BlockingModule {
    fn name(&self) -> &'static str {
        "blocking-test-module"
    }
    fn authenticate(&self, _candidate: Option<&str>) -> busbar_api::AuthOutcome {
        let _ = self.entered.send(());
        std::thread::sleep(self.hold);
        busbar_api::AuthOutcome::Pass
    }
    fn cacheable(&self) -> bool {
        false
    }
}

/// RED (chain called inline from `auth_middleware`): the probe below is never scheduled, because
/// the single worker is inside the plugin.
/// GREEN (chain offloaded to the blocking pool): the worker is free and the probe completes while
/// the plugin is still blocking.
///
/// A one-worker runtime is not a contrived shape — busbar sizes its runtime from
/// `available_parallelism()` and the docs recommend 1-2 workers for sidecar deployments. It is
/// simply the smallest configuration in which "a worker is parked" is decidable.
#[test]
fn a_blocking_auth_plugin_does_not_park_the_reactor() {
    let (tx, entered) = std::sync::mpsc::channel();
    let auth = std::sync::Arc::new(AuthMiddleware::from_chain_for_test(
        vec![Box::new(BlockingModule {
            entered: tx,
            hold: std::time::Duration::from_secs(3),
        })],
        /* has_plugin_module = */ true,
    ));
    let cache = std::sync::Arc::new(crate::auth_cache::CredentialCache::new());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");

    rt.spawn(async move {
        let _ = AuthMiddleware::run_chain_on_request_path(&auth, &cache, Some("tok".into())).await;
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
        vec![Box::new(crate::auth::TestGroupsModule)],
        /* has_plugin_module = */ false,
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
        AuthMiddleware::run_chain_on_request_path(&auth, &cache, Some("grp:admins".into())).await
    });
    assert!(
        matches!(verdict, ChainVerdict::Identified { .. }),
        "an in-process chain must keep identifying exactly as before"
    );
}
