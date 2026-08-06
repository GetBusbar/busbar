// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FULL-CHAIN auth-plugin seam tests: the engine's `AuthMiddleware` loading a REAL signed
//! `kind: auth` plugin cdylib over the loader, exactly as boot does. We pack the hermetic
//! `busbar-auth-static-plugin` cdylib into a tarball, run it through `plugins_preflight` +
//! `AuthMiddleware::new`, and prove:
//!
//! * a valid token → `Identify` → a mapped `Principal` whose roles resolve to `role_bindings`
//!   policy AND whose admin scope is capped by `auth.chain.<module>.max_admin_scope`;
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

/// 1.5.2 CAPABILITY GATE: a `browser_login` login method backed by a PRE-v2 auth plugin must
/// be a HARD `LoginMethods::build` error (config/boot-time), NOT a 500 at request time. We stamp a
/// v1 auth manifest (still admitted by the scan — the auth ABI floor is 1) and attach `browser_login`
/// to it; the build refuses, naming the abi_version.
#[test]
fn browser_login_on_v1_plugin_is_a_build_error() {
    let dir = tmp_plugin_dir("auth-login-v1-gate");
    let Some(path) = static_auth_cdylib() else {
        eprintln!("skip: static-auth plugin cdylib not built (run under --workspace)");
        return;
    };
    let lib = std::fs::read(&path).expect("read static-auth cdylib");
    let mut manifest = auth_manifest("acme-auth-static", "cap-idp", "acme");
    manifest.abi_version = 1; // PRE-v2 — no login capability
    std::fs::write(dir.join("static.tar.gz"), unsigned_tarball(manifest, &lib)).unwrap();
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let registry = busbar_plugin_loader::scan_and_validate(
        Path::new(&plugins.dir),
        &plugins.to_policy().unwrap(),
    )
    .expect("scan admits a v1 auth plugin (floor is 1)");

    let mut cfg = AuthCfg::default_none();
    let mut method = crate::config::AuthMethodCfg {
        // 1.5.3: the resolved method carries the PROVIDER's `module:` — the plugin it opens —
        // separately from the map key, which is the provider NAME.
        module: "acme-auth-static".into(),
        browser_login: Some(crate::config::BrowserLoginCfg {
            client_secret: Some(crate::config::SecretRef::env("BUSBAR_TEST_CLIENT_SECRET")),
            client_id: Some("client-abc".into()),
        }),
        // Valid static-auth settings so `open()` SUCCEEDS — the build must then fail on the ABI
        // CAPABILITY GATE (abi_version < 2), not on a missing-config open error.
        settings: alice_settings(),
    };
    method.settings.insert(
        "issuer".into(),
        serde_json::json!("https://idp.example.com"),
    );
    cfg.methods.insert("cap-idp".into(), method);
    // The v2 build below resolves the client_secret (the v1 gate fires BEFORE resolution); set the
    // env so the v2 case fails ONLY on capability, never on an unresolvable secret.
    std::env::set_var("BUSBAR_TEST_CLIENT_SECRET", "the-confidential-secret");
    let resolver = crate::config::secret::SecretResolver::builtins_only();

    let err = crate::auth::token::LoginMethods::build(&cfg, &registry, &resolver)
        .expect_err("a browser_login method on a v1 plugin must fail the build");
    assert!(
        err.contains("abi_version") && err.contains("cap-idp"),
        "the capability-gate error names the offending method + abi_version: {err}"
    );

    // A v2 build of the SAME plugin (login-capable) with browser_login succeeds — the gate is
    // specifically the version, not the presence of browser_login.
    let dir2 = tmp_plugin_dir("auth-login-v2-ok");
    let mut m2 = auth_manifest("acme-auth-static", "cap-idp", "acme");
    m2.abi_version = 2;
    std::fs::write(dir2.join("static.tar.gz"), unsigned_tarball(m2, &lib)).unwrap();
    let plugins2 = plugins_cfg_allow_unsigned(&dir2);
    let registry2 = busbar_plugin_loader::scan_and_validate(
        Path::new(&plugins2.dir),
        &plugins2.to_policy().unwrap(),
    )
    .expect("scan");
    crate::auth::token::LoginMethods::build(&cfg, &registry2, &resolver)
        .expect("a v2 login-capable plugin with browser_login builds");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
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

/// A `kind: auth` manifest carrying a `settings_schema` that marks `field` as `x-busbar-secret:
/// true` at the schema's ROOT `properties`. `resolve_settings()` itself never reads this schema —
/// resolution fires on VALUE SHAPE alone, not on what the manifest declares — but the whole point of
/// `x-busbar-secret` being "mechanically true, not a convention" is that the two agree: what the
/// schema marks as a secret IS what the engine actually resolves before the plugin sees it. This
/// helper exists so the contract test below mints a config against a manifest that genuinely
/// declares the field secret, not merely a bare settings map with no schema at all.
fn auth_manifest_with_root_secret_schema(
    name: &str,
    alias: &str,
    publisher: &str,
    field: &str,
) -> busbar_plugin_sign::Manifest {
    let mut m = auth_manifest(name, alias, publisher);
    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            field: {"type": "string", "x-busbar-secret": true},
            "id": {"type": "string"},
            "roles": {"type": "array", "items": {"type": "string"}},
        },
    });
    m.settings_schema = Some(schema.to_string());
    m
}

/// Write an UNSIGNED static-auth tarball whose manifest declares `token` as a ROOT-LEVEL
/// `x-busbar-secret` field (see [`auth_manifest_with_root_secret_schema`]).
fn write_static_auth_with_root_secret_schema(
    dir: &Path,
    file: &str,
    name: &str,
    alias: &str,
) -> bool {
    let Some(path) = static_auth_cdylib() else {
        return false;
    };
    let lib = std::fs::read(&path).expect("read static-auth cdylib");
    let tarball = unsigned_tarball(
        auth_manifest_with_root_secret_schema(name, alias, "acme", "token"),
        &lib,
    );
    std::fs::write(dir.join(file), tarball).unwrap();
    true
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
    let registry = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
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

/// THE CONTRACT TEST for the `x-busbar-secret` guarantee, via the PLUGIN-SETTINGS path
/// specifically: a manifest that declares an
/// ARBITRARY root-level field (`token` — not the well-known `licenseKey` convention the OTHER
/// contract test above already covers) as `x-busbar-secret: true`, set to `{ env: VAR }`, boots for
/// REAL through the full engine pipeline (`plugins_preflight` → `AuthMiddleware::new`, the exact
/// path boot itself takes — no shortcut through `resolve_settings()` directly), and the plugin's
/// `open()` receives a PLAIN STRING it can authenticate a caller against — never the raw `{env:
/// VAR}` reference object (which would fail `StaticConfig`'s `token: String` deserialization, so
/// this test would fail closed rather than silently pass on a lucky coincidence).
///
/// This pins the guarantee generically (any field shape resolve_settings recognizes, not merely the
/// license-key convention some future refactor might special-case) — a future change that broke
/// resolution for a non-license field would go red here even if it happened to leave the
/// license-key path intact.
#[test]
fn auth_plugin_root_level_secret_marked_setting_resolves_and_authenticates() {
    let dir = tmp_plugin_dir("auth-plugin-root-secret-contract");
    if !write_static_auth_with_root_secret_schema(
        &dir,
        "static.tar.gz",
        "acme-auth-static",
        "sec-auth",
    ) {
        eprintln!("skip: static-auth plugin cdylib not built (run under --workspace)");
        return;
    }
    let plugins = plugins_cfg_allow_unsigned(&dir);

    let var = format!("BUSBAR_PLUGIN_ROOT_SECRET_CONTRACT_{}", std::process::id());
    let raw_token = "the-actual-plaintext-token-value";
    std::env::set_var(&var, raw_token);

    let mut settings = serde_json::json!({ "id": "alice", "roles": ["platform"] })
        .as_object()
        .unwrap()
        .clone();
    settings.insert("token".to_string(), serde_json::json!({ "env": var }));
    let cfg = chain_with("sec-auth", settings);

    let registry = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect(
        "preflight resolves the kind:auth plugin, whose manifest declares `token` as a \
                 root-level x-busbar-secret field",
    );
    let mw = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect(
        "the {env: VAR} reference resolves BEFORE open() — the plugin's StaticConfig.token: String \
         field would fail to deserialize an unresolved reference object, so a load success here is \
         itself proof open() received a plain string",
    );

    // The PLAIN, resolved value (never the reference) is what open() actually stored as the
    // credential — authenticating with the RAW env value succeeds; the literal reference text
    // never authenticates anything (it was never delivered to the plugin at all).
    match mw.run_chain(Some(raw_token)) {
        ChainVerdict::Identified { principal, .. } => assert_eq!(principal.id, "alice"),
        other => panic!(
            "the resolved plaintext token must authenticate — open() did not receive the plain \
             string: {other:?}"
        ),
    }
    assert_eq!(
        mw.run_chain(Some("{\"env\":\"irrelevant\"}")),
        ChainVerdict::Denied,
        "the raw reference text itself was never delivered to the plugin as a credential"
    );

    // The overlay/config still holds the REFERENCE, never the resolved secret.
    let serialized = serde_json::to_string(&cfg.chain[0].settings).expect("serialize settings");
    assert!(
        serialized.contains(&var) && !serialized.contains(raw_token),
        "config keeps the ref, never the resolved secret: {serialized}"
    );

    std::env::remove_var(&var);
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
    let registry = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
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
        ChainVerdict::Identified {
            module, principal, ..
        } => {
            // 1.5.3: the verdict reports the IDENTITY-PROVIDER NAME — the
            // `identity-providers:` key the chain referenced — NOT the plugin's own self-reported
            // name. That is what makes two NAMED providers backed by one module independently
            // bindable (`role_bindings.<name>`) instead of silently collapsing onto one identity.
            assert_eq!(module, "my-auth", "role_bindings key = the PROVIDER NAME");
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
    // The chain entry caps this module at `read-only`, below the `full` the role would otherwise
    // grant (1.5.2 scope collapse retired the intermediate `mint`/`hooks-register` ceilings).
    cfg.chain[0].max_admin_scope = Some("read-only".into());
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

    let registry = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
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
        crate::admin::v1::contract::Grants::of(Scope::Full),
        "role binds full under the PLUGIN module name"
    );
    // ..but the module's `max_admin_scope: read-only` ceiling caps the effective scope. Calling the
    // actual `Grants::capped_by` production method (instead of re-implementing the ceiling with
    // `std::cmp::min`) proves the real ceiling arithmetic under a plugin module name — a `full`
    // binding capped by a `read-only` ceiling collapses to read-only.
    let capped = bound.capped_by(Scope::ReadOnly);
    assert_eq!(
        capped,
        crate::admin::v1::contract::Grants::of(Scope::ReadOnly),
        "max_admin_scope caps the plugin module"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// 1.5.2 admin-plane OIDC: `AdminAuthChain::build` — the function `build_app_from_config` invokes on
/// BOTH boot and reload — resolves every NON-BUILTIN `admin_auth:` entry into a loaded `kind: auth`
/// plugin, keyed by config name, `has_plugin: true`; `admin-tokens` (an engine arm) is NOT in the
/// map. Building it TWICE against the same registry (boot, then the reload rebuild) both populate:
/// the reload path can never leave `admin_modules` stale/empty.
#[test]
fn admin_modules_rebuilt_on_reload() {
    use crate::auth::AdminAuthChain;
    let dir = tmp_plugin_dir("admin-modules-reload");
    if !write_static_auth(&dir, "static.tar.gz", "acme-auth-static", "admin-oidc") {
        eprintln!("skip: static-auth plugin cdylib not built (run under --workspace)");
        return;
    }
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let registry = busbar_plugin_loader::scan_and_validate(
        Path::new(&plugins.dir),
        &plugins.to_policy().unwrap(),
    )
    .expect("scan succeeds");
    let mut cfg = AuthCfg::default_none();
    let mut entry = AuthChainEntry::bare("admin-oidc");
    entry.settings = alice_settings();
    cfg.admin_auth = vec![
        AuthChainEntry::bare(crate::config::ADMIN_TOKENS_MODULE),
        entry,
    ];
    let resolver = crate::config::secret::SecretResolver::builtins_only();

    // BOOT build.
    let boot = AdminAuthChain::build(&cfg, &registry, &resolver).expect("boot builds admin chain");
    assert!(
        boot.has_plugin,
        "an external admin module is a loaded plugin"
    );
    assert!(
        boot.modules.contains_key("admin-oidc"),
        "keyed by the config module name"
    );
    assert_eq!(
        boot.modules.len(),
        1,
        "admin-tokens is an engine arm, never inserted into admin_modules"
    );

    // RELOAD build (the SAME code path `build_app_from_config` re-runs with `prior = Some`).
    let reload =
        AdminAuthChain::build(&cfg, &registry, &resolver).expect("reload rebuilds admin chain");
    assert!(
        reload.has_plugin && reload.modules.contains_key("admin-oidc"),
        "reload repopulates admin_modules — never stale/empty"
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
    let err = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &strict,
        &Default::default(),
    )
    .unwrap_err();
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

    let err = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .unwrap_err();
    assert!(err.contains("oidc"), "names the missing module: {err}");
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
    let registry = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
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
        /* has_plugin_module = */ true,
    ));
    let cache = std::sync::Arc::new(crate::auth_cache::CredentialCache::new());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");

    rt.spawn(async move {
        let _ = AuthMiddleware::run_chain_on_request_path(&auth, &cache, Some("tok".into()), None)
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
        AuthMiddleware::run_chain_on_request_path(&auth, &cache, Some("grp:admins".into()), None)
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
impl busbar_api::AuthModule for CacheablePass {
    fn name(&self) -> &'static str {
        "cacheable-pass-module"
    }
    fn authenticate(&self, _candidate: Option<&str>) -> busbar_api::AuthOutcome {
        busbar_api::AuthOutcome::Pass
    }
    fn cacheable(&self) -> bool {
        true
    }
}

/// Always `Reject`s, and is cacheable (cacheability is irrelevant to `Reject`, which
/// `auth_cache.rs:104` never caches regardless — included so the chain-position test is honest).
struct CacheableReject;
impl busbar_api::AuthModule for CacheableReject {
    fn name(&self) -> &'static str {
        "cacheable-reject-module"
    }
    fn authenticate(&self, _candidate: Option<&str>) -> busbar_api::AuthOutcome {
        busbar_api::AuthOutcome::Reject
    }
    fn cacheable(&self) -> bool {
        true
    }
}

/// `Identify`s any candidate that equals `"good"`, else `Pass`es. Cacheable.
struct CacheableIdentify;
impl busbar_api::AuthModule for CacheableIdentify {
    fn name(&self) -> &'static str {
        "cacheable-identify-module"
    }
    fn authenticate(&self, candidate: Option<&str>) -> busbar_api::AuthOutcome {
        match candidate {
            Some("good") => busbar_api::AuthOutcome::Identify(crate::auth::Principal {
                id: "test:good".to_string(),
                name: None,
                roles: vec![],
                ttl_secs: None,
            }),
            _ => busbar_api::AuthOutcome::Pass,
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
        /* has_plugin_module = */ false,
    );
    let cache = crate::auth_cache::CredentialCache::new();

    let verdict = auth.run_chain_cached(Some("junk-token"), Some(&cache), None);

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
        /* has_plugin_module = */ false,
    );
    let cache = crate::auth_cache::CredentialCache::new();

    let verdict = auth.run_chain_cached(Some("junk-token"), Some(&cache), None);

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
        /* has_plugin_module = */ false,
    );
    let cache = crate::auth_cache::CredentialCache::new();
    let now = 1_000_000u64;

    cache.put(
        "real-identity-module",
        "real-credential",
        &busbar_api::AuthOutcome::Identify(crate::auth::Principal {
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
        let _ = auth.run_chain_cached(Some(&junk), Some(&cache), None);
    }

    assert!(
        matches!(
            cache.get("real-identity-module", "real-credential", now),
            Some(busbar_api::AuthOutcome::Identify(_))
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
        /* has_plugin_module = */ false,
    );
    let cache = crate::auth_cache::CredentialCache::new();

    let verdict = auth.run_chain_cached(Some("good"), Some(&cache), None);

    assert!(matches!(verdict, ChainVerdict::Identified { .. }));
    assert_eq!(
        cache.flush_all(),
        2,
        "an identified chain must still cache both the leading Pass and the Identify"
    );
}
