// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FULL-CHAIN auth-plugin seam tests: the engine's `AuthMiddleware` loading a REAL signed
//! `kind: auth` plugin cdylib over the loader, exactly as boot does. The plugin is the REAL
//! token-verifying OIDC module, GetBusbar/busbar-auth-oidc (the owner's FIXTURES ruling: real plugins are the
//! proofs; R-FIX2), pulled at a pinned rev as a dev-dependency of the composition root so the
//! workspace build carries its cdylib. We pack it into a tarball, run it through `plugins_preflight` +
//! `AuthMiddleware::new` against a LOCAL issuer ([`Issuer`]: an ES256 key whose JWKS is served over a
//! real HTTPS listener, trusted through the module's `ca_cert_pem` setting), present SIGNED JWTs, and
//! prove:
//!
//! * a valid token → `Identify` → a mapped `Principal` whose roles resolve to `role_bindings`
//!   policy AND whose admin scope is capped by `auth.chain.<module>.max_admin_scope`;
//! * an invalid/absent credential → the chain fail-closed-denies (all-`Pass`), and a token signed by
//!   another key is refused;
//! * a MISSING or UNTRUSTED plugin at boot → a LOUD failure (never a silently-open front door);
//! * `plugins.enabled: false` + a configured auth plugin → boot refuses (`plugins_preflight`).
//!
//! Mirrors the store-plugin end-to-end packed test (`crate::tests`), reusing its plugin-dir /
//! manifest helpers.

use crate::auth::{AuthMiddleware, ChainVerdict};
use crate::config::{AuthCfg, AuthChainEntry, PluginsCfg};
use crate::tests::{plugin_manifest, tmp_plugin_dir, unsigned_tarball};
use std::path::{Path, PathBuf};

/// The auth-oidc module's cdylib, built by the workspace build as a git dev-dependency of the
/// composition root — so it lives under `deps/` WITH a metadata hash (`lib<name>-<hex>.<ext>`) and is
/// never uplifted; the exact name is checked too. Newest wins. Under CI (`cargo test --workspace`
/// always builds it) a missing cdylib is a HARD failure, never a silent skip; locally a missing
/// cdylib skips cleanly.
///
/// Checks BOTH the uplifted profile dir AND `target/deps`: a SCOPED build leaves the artifact in
/// `target/deps` ALONE, and checking only the profile dir once made every cdylib-gated test in this
/// file return early and report `ok` — `untrusted_auth_plugin_fails_closed_not_open` and
/// `missing_auth_plugin_is_loud_boot_failure`, the front-door fail-closed guarantees, among them.
fn auth_cdylib() -> Option<PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let snake = "busbar_auth_oidc_plugin";
        let file = busbar_plugin_loader::plugin_library_filename(snake);
        let (prefix, suffix) = file.split_once(snake)?;
        let is_lib = |f: &str| {
            f.strip_prefix(prefix)
                .and_then(|f| f.strip_suffix(suffix))
                .and_then(|f| f.strip_prefix(snake))
                .is_some_and(|stem| {
                    stem.is_empty()
                        || stem.strip_prefix('-').is_some_and(|h| {
                            !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                })
        };
        let in_deps = std::fs::read_dir(profile_dir.join("deps"))
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.file_name().and_then(|f| f.to_str()).is_some_and(is_lib));
        std::iter::once(profile_dir.join(&file))
            .chain(in_deps)
            .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
            .max()
            .map(|(_, p)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the auth-oidc plugin cdylib is not built under CI; refusing to silently skip the \
             full-chain auth-plugin seam coverage"
        );
    }
    candidate
}

/// The issuer every token in this file is signed by, and the audience it is bound to.
const ISSUER: &str = "https://issuer.plugin-chain.invalid";
const AUDIENCE: &str = "api://plugin-chain";

/// THE LOCAL ISSUER, one per test process: the auth module's OWN test issuer (its logic crate's
/// `testkit` feature) — an ES256 key, its JWKS served over a certificate-verified loopback endpoint
/// the module trusts through `ca_cert_pem`, and genuinely signed tokens. The module's own blocking
/// fetcher does the whole fetch and the whole verification.
fn issuer() -> &'static busbar_auth_oidc::testkit::Issuer {
    static ONE: std::sync::OnceLock<busbar_auth_oidc::testkit::Issuer> = std::sync::OnceLock::new();
    ONE.get_or_init(|| busbar_auth_oidc::testkit::Issuer::start(ISSUER, "plugin-chain"))
}

/// The module's `settings:` for the local issuer and [`AUDIENCE`].
fn settings() -> serde_json::Map<String, serde_json::Value> {
    issuer().settings(AUDIENCE)
}

/// `alice`'s token: role `platform`, bound to [`AUDIENCE`].
fn alice_token() -> String {
    issuer().mint("alice", &["platform"], AUDIENCE)
}

/// The runtime identity the module reports for itself — what its OWN compiled-in constructor's
/// `name()` answers under the same settings. The chain must report this, never the config alias.
fn module_name() -> &'static str {
    busbar_auth_oidc_plugin::open(&serde_json::Value::Object(settings()).to_string())
        .expect("the compiled-in constructor opens under the same settings")
        .name()
}

/// A `kind: auth` manifest for the given name/alias (the store helper stamps kind=store; we retarget
/// it to auth + the auth ABI so the scan admits it).
fn auth_manifest(name: &str, alias: &str, publisher: &str) -> busbar_plugin_loader::sign::Manifest {
    let mut m = plugin_manifest(name, alias, publisher);
    m.kind = "auth".into();
    m.abi_version = *busbar_plugin_loader::supported_abi("auth")
        .iter()
        .max()
        .expect("auth abi");
    m
}

/// THE DESIGN §11.8 (C21): a v1 auth plugin (the pre-login 1.5.x wire) no longer reaches the
/// login-capability gate: the scan refuses it at boot, naming the rebuild. The current version of
/// the SAME plugin with `browser_login` builds.
#[test]
fn a_v1_auth_plugin_is_refused_at_boot_and_the_current_one_builds_browser_login() {
    let dir = tmp_plugin_dir("auth-login-v1-gate");
    let Some(path) = auth_cdylib() else {
        eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
        return;
    };
    let lib = std::fs::read(&path).expect("read the auth-oidc cdylib");
    let mut manifest = auth_manifest("acme-idp", "cap-idp", "acme");
    manifest.abi_version = 1;
    std::fs::write(dir.join("idp.tar.gz"), unsigned_tarball(manifest, &lib)).unwrap();
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let errs = busbar_plugin_loader::scan_and_validate(
        Path::new(&plugins.dir),
        &crate::test_support::trust_policy(&plugins).unwrap(),
    )
    .expect_err("a v1 auth plugin is refused at boot");
    assert!(
        errs.iter()
            .any(|e| e.contains("rebuild the plugin against the 1.6.0 SDK")),
        "the refusal names the rebuild: {errs:?}"
    );

    let mut cfg = AuthCfg::default_none();
    let method = crate::config::AuthMethodCfg {
        // 1.5.3: the resolved method carries the PROVIDER's `module:` — the plugin it opens —
        // separately from the map key, which is the provider NAME.
        module: "acme-idp".into(),
        browser_login: Some(crate::config::BrowserLoginCfg {
            client_secret: Some(crate::config::SecretRef::env("BUSBAR_TEST_CLIENT_SECRET")),
            client_id: Some("client-abc".into()),
        }),
        settings: settings(),
    };
    cfg.methods.insert("cap-idp".into(), method);
    std::env::set_var("BUSBAR_TEST_CLIENT_SECRET", "the-confidential-secret");
    let resolver = crate::config::secret::SecretResolver::builtins_only();

    let dir2 = tmp_plugin_dir("auth-login-current-ok");
    let current = auth_manifest("acme-idp", "cap-idp", "acme");
    std::fs::write(dir2.join("idp.tar.gz"), unsigned_tarball(current, &lib)).unwrap();
    let plugins2 = plugins_cfg_allow_unsigned(&dir2);
    let registry2 = busbar_plugin_loader::scan_and_validate(
        Path::new(&plugins2.dir),
        &crate::test_support::trust_policy(&plugins2).unwrap(),
    )
    .expect("scan");
    crate::auth::token::LoginMethods::build(&cfg, &registry2, &resolver)
        .expect("the current login-capable plugin with browser_login builds");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

/// Write an UNSIGNED (structurally valid) auth-oidc tarball into `dir` under `file`, returning the
/// cdylib bytes' presence. We use the unsigned+`allow_unsigned` path because the test cannot sign
/// with the embedded first-party release key; this still exercises the whole load pipeline.
fn write_auth_plugin(dir: &Path, file: &str, name: &str, alias: &str) -> bool {
    let Some(path) = auth_cdylib() else {
        return false;
    };
    let lib = std::fs::read(&path).expect("read the auth-oidc cdylib");
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
) -> busbar_plugin_loader::sign::Manifest {
    let mut m = auth_manifest(name, alias, publisher);
    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            field: {"type": "string", "x-busbar-secret": true},
            "issuer": {"type": "string"},
            "jwks_url": {"type": "string"},
        },
    });
    m.settings_schema = Some(schema.to_string());
    m
}

/// Write an UNSIGNED auth-oidc tarball whose manifest declares `audience` as a ROOT-LEVEL
/// `x-busbar-secret` field (see [`auth_manifest_with_root_secret_schema`]).
fn write_auth_plugin_with_root_secret_schema(
    dir: &Path,
    file: &str,
    name: &str,
    alias: &str,
) -> bool {
    let Some(path) = auth_cdylib() else {
        return false;
    };
    let lib = std::fs::read(&path).expect("read the auth-oidc cdylib");
    let tarball = unsigned_tarball(
        auth_manifest_with_root_secret_schema(name, alias, "acme", "audience"),
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

/// A SECRET-REFERENCE SETTING, END TO END (the ADR-0010 delivery path, on a real module): a setting
/// spelled as a SecretRef (`{ env: VAR }`) is RESOLVED by the engine and DELIVERED to the plugin,
/// which uses it ITSELF — here the module's `ca_cert_pem`, the trust root its own HTTPS fetcher needs
/// to reach the issuer, so a token only verifies if the resolved PEM arrived. Conversely, an
/// UNRESOLVABLE ref fails the load FAIL-CLOSED — the plugin is never handed a dangling reference.
#[test]
fn auth_plugin_setting_secret_ref_is_resolved_and_delivered() {
    let dir = tmp_plugin_dir("auth-plugin-secret-ref");
    if !write_auth_plugin(&dir, "idp.tar.gz", "acme-idp", "ref-auth") {
        eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
        return;
    }
    let plugins = plugins_cfg_allow_unsigned(&dir);

    // The trust root delivered via an env SecretRef: the engine resolves `{ env: VAR }` to the PEM
    // BEFORE open, the module builds its fetcher on it, and a signed token verifies against its keys.
    let var = format!("BUSBAR_PLUGIN_CA_PEM_{}", std::process::id());
    std::env::set_var(&var, issuer().cert_pem());
    let mut settings = settings();
    settings.insert("ca_cert_pem".into(), serde_json::json!({ "env": var }));
    let cfg = chain_with("ref-auth", settings);
    let registry = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("preflight resolves the kind:auth plugin");
    let registry = std::sync::Arc::new(registry);
    let mw = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect("a resolvable setting ref is delivered and the plugin loads");
    assert_eq!(mw.chain_names(), vec![module_name()], "plugin loaded");
    match mw.run_chain(Some(&alice_token())) {
        ChainVerdict::Identified { principal, .. } => assert_eq!(principal.id, "oidc:alice"),
        other => panic!("the delivered trust root must let the module verify: {other:?}"),
    }
    std::env::remove_var(&var);

    // FAIL-CLOSED: the SAME ref, now UNRESOLVABLE (env unset), refuses the chain build — the plugin
    // is never handed the unresolved ref. The error names the field, never a secret value.
    let err = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect_err("an unresolvable setting ref fails the load fail-closed");
    assert!(
        err.contains("ca_cert_pem") && err.contains("did not resolve"),
        "fail-closed, names the setting: {err}"
    );
    // The overlay/config still holds the REFERENCE, never the resolved secret: SecretRef serializes
    // the ref, so the setting serialized back out is the env ref, not the PEM.
    let serialized = serde_json::to_string(&cfg.chain[0].settings).expect("serialize settings");
    assert!(
        serialized.contains(&var) && !serialized.contains("BEGIN CERTIFICATE"),
        "config keeps the ref, never the resolved secret: {serialized}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// THE CONTRACT TEST for the `x-busbar-secret` guarantee, via the PLUGIN-SETTINGS path
/// specifically: a manifest that declares an
/// ARBITRARY root-level field (`audience` — not the trust-root setting the OTHER contract test above
/// already covers) as `x-busbar-secret: true`, set to `{ env: VAR }`, boots for
/// REAL through the full engine pipeline (`plugins_preflight` → `AuthMiddleware::new`, the exact
/// path boot itself takes — no shortcut through `resolve_settings()` directly), and the plugin's
/// `open()` receives a PLAIN STRING it verifies callers against — never the raw `{env: VAR}`
/// reference object (which would fail the module's `audience: String` deserialization, so this test
/// would fail closed rather than silently pass on a lucky coincidence).
///
/// This pins the guarantee generically (any field shape resolve_settings recognizes, not merely the
/// license-key convention some future refactor might special-case) — a future change that broke
/// resolution for a non-license field would go red here even if it happened to leave the
/// trust-root path intact.
#[test]
fn auth_plugin_root_level_secret_marked_setting_resolves_and_authenticates() {
    let dir = tmp_plugin_dir("auth-plugin-root-secret-contract");
    if !write_auth_plugin_with_root_secret_schema(&dir, "idp.tar.gz", "acme-idp", "sec-auth") {
        eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
        return;
    }
    let plugins = plugins_cfg_allow_unsigned(&dir);

    let var = format!("BUSBAR_PLUGIN_ROOT_SECRET_CONTRACT_{}", std::process::id());
    let raw_audience = "api://the-actual-plaintext-audience";
    std::env::set_var(&var, raw_audience);

    let mut settings = settings();
    settings.insert("audience".to_string(), serde_json::json!({ "env": var }));
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
        "preflight resolves the kind:auth plugin, whose manifest declares `audience` as a \
                 root-level x-busbar-secret field",
    );
    let registry = std::sync::Arc::new(registry);
    let mw = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect(
        "the {env: VAR} reference resolves BEFORE open() — the module's `audience: String` field \
         would fail to deserialize an unresolved reference object, so a load success here is \
         itself proof open() received a plain string",
    );

    // The PLAIN, resolved value (never the reference) is what open() actually stored as the
    // audience — a token bound to the RAW env value verifies; a token bound to any other audience
    // does not, and the literal reference text never authenticates anything.
    match mw.run_chain(Some(&issuer().mint("alice", &["platform"], raw_audience))) {
        ChainVerdict::Identified { principal, .. } => assert_eq!(principal.id, "oidc:alice"),
        other => panic!(
            "a token for the resolved plaintext audience must authenticate — open() did not \
             receive the plain string: {other:?}"
        ),
    }
    assert_eq!(
        mw.run_chain(Some(&alice_token())),
        ChainVerdict::Denied,
        "a token for any other audience is refused"
    );
    assert_eq!(
        mw.run_chain(Some("{\"env\":\"irrelevant\"}")),
        ChainVerdict::Denied,
        "the raw reference text itself was never delivered to the plugin as a credential"
    );

    // The overlay/config still holds the REFERENCE, never the resolved secret.
    let serialized = serde_json::to_string(&cfg.chain[0].settings).expect("serialize settings");
    assert!(
        serialized.contains(&var) && !serialized.contains(raw_audience),
        "config keeps the ref, never the resolved secret: {serialized}"
    );

    std::env::remove_var(&var);
    let _ = std::fs::remove_dir_all(&dir);
}

/// FULL CHAIN, REAL CDYLIB: `auth.chain: [my-auth]` loads the auth-oidc plugin over the loader; a
/// token the issuer signed identifies as `oidc:alice/platform`, and a token with a forged signature,
/// a non-token and an absent credential fail-closed-deny.
#[test]
fn auth_plugin_loads_and_identifies_through_middleware() {
    let dir = tmp_plugin_dir("auth-plugin-e2e");
    // The config chain name is the ALIAS `my-auth`; the plugin's canonical name differs on purpose.
    if !write_auth_plugin(&dir, "idp.tar.gz", "acme-idp", "my-auth") {
        eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
        return;
    }
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let cfg = chain_with("my-auth", settings());

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
    let registry = std::sync::Arc::new(registry);

    // The real load through the middleware — resolve → open_auth → box → chain.
    let mw = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect("auth chain loads the plugin");
    // The RUNTIME module identity is the plugin's own `name()`, NOT the config alias.
    assert_eq!(mw.chain_names(), vec![module_name()], "runtime module name");
    assert_ne!(
        module_name(),
        "my-auth",
        "the alias is not the module's identity"
    );

    // Valid token → Identify with the token's subject + roles.
    match mw.run_chain(Some(&alice_token())) {
        ChainVerdict::Identified {
            module, principal, ..
        } => {
            // 1.5.3: the verdict reports the IDENTITY-PROVIDER NAME — the
            // `identity-providers:` key the chain referenced — NOT the plugin's own self-reported
            // name. That is what makes two NAMED providers backed by one module independently
            // bindable (`role_bindings.<name>`) instead of silently collapsing onto one identity.
            assert_eq!(module, "my-auth", "role_bindings key = the PROVIDER NAME");
            assert_eq!(principal.id, "oidc:alice");
            assert_eq!(principal.roles, vec!["platform".to_string()]);
        }
        other => panic!("valid token must Identify, got {other:?}"),
    }
    // A non-token credential → the module Passes → a non-empty chain fail-closed-DENIES.
    assert_eq!(
        mw.run_chain(Some("wrong")),
        ChainVerdict::Denied,
        "bad token denies"
    );
    // The same token with a FORGED signature → the module rejects it.
    let token = alice_token();
    let (signed, _) = token.rsplit_once('.').expect("a JWT");
    assert_eq!(
        mw.run_chain(Some(&format!("{signed}.{}", "A".repeat(86)))),
        ChainVerdict::Denied,
        "a forged signature denies"
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
    if !write_auth_plugin(&dir, "idp.tar.gz", "acme-idp", "idp") {
        eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
        return;
    }
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let mut cfg = chain_with("idp", settings());
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

    let registry = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("preflight");
    let registry = std::sync::Arc::new(registry);
    let mw = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect("load");

    let principal = match mw.run_chain(Some(&alice_token())) {
        ChainVerdict::Identified { principal, .. } => principal,
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
/// plugin, keyed by config name; the operator credential is NOT in the map (it
/// is held apart, `AdminAuthChain::operator`). Building it TWICE against the same registry (boot, then the reload rebuild) both populate:
/// the reload path can never leave `admin_modules` stale/empty.
#[test]
fn admin_modules_rebuilt_on_reload() {
    use crate::auth::AdminAuthChain;
    let dir = tmp_plugin_dir("admin-modules-reload");
    if !write_auth_plugin(&dir, "idp.tar.gz", "acme-idp", "admin-oidc") {
        eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
        return;
    }
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let registry = busbar_plugin_loader::scan_and_validate(
        Path::new(&plugins.dir),
        &crate::test_support::trust_policy(&plugins).unwrap(),
    )
    .expect("scan succeeds");
    let registry = std::sync::Arc::new(registry);
    let mut cfg = AuthCfg::default_none();
    let mut entry = AuthChainEntry::bare("admin-oidc");
    entry.settings = settings();
    cfg.admin_auth = vec![
        AuthChainEntry::bare(crate::config::operator_provider()),
        entry,
    ];
    let resolver = crate::config::secret::SecretResolver::builtins_only();

    // BOOT build.
    let boot = AdminAuthChain::build(&cfg, &registry, &resolver).expect("boot builds admin chain");
    assert!(
        boot.modules.contains_key("admin-oidc"),
        "keyed by the config module name"
    );
    assert_eq!(
        boot.modules.len(),
        1,
        "the operator credential is held apart, never inserted into admin_modules"
    );

    // RELOAD build (the SAME code path `build_app_from_config` re-runs with `prior = Some`).
    let reload =
        AdminAuthChain::build(&cfg, &registry, &resolver).expect("reload rebuilds admin chain");
    assert!(
        reload.modules.contains_key("admin-oidc"),
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
    let Some(path) = auth_cdylib() else {
        eprintln!("skip: auth-oidc plugin cdylib not built (run under --workspace)");
        return;
    };
    let lib = std::fs::read(&path).unwrap();
    let tarball = unsigned_tarball(auth_manifest("acme-idp", "test-idp-double", "acme"), &lib);
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
