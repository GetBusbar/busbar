// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FULL-CHAIN auth-plugin seam tests: the engine's `AuthMiddleware` loading a REAL signed
//! `kind: auth` plugin cdylib over the loader, exactly as boot does. The plugin is the REAL
//! token-verifying OIDC module (the owner's FIXTURES ruling: real plugins are the
//! proofs; R-FIX2), pulled at a pinned rev as a dev-dependency of this crate — the composition root,
//! the one crate that may name every kind — so its test build carries the cdylib. (These proofs
//! moved here from busbar-kernel's `auth/tests/plugin_chain_tests.rs`, R-FIX3: the kernel's own
//! tests run on in-crate doubles and name no plugin.) It is on the auth kind's memory ABI: it holds
//! no socket and no TLS, and fetches through the host's connection table over the needs its
//! Statement declares. We pack it into a tarball stating that Statement, run it through
//! `plugins_preflight` + `AuthMiddleware::new` against a LOCAL issuer (the loader's `test_issuer`: an
//! ES256 key whose JWKS is served only to a need trusting the issuer's certificate, the module's
//! `ca_cert_pem` setting) reached through a connection table (the loader's `https_conns`, standing in
//! for the process's connector; the real connector's fetch over real TLS is the served
//! node's proof), present SIGNED JWTs, and prove:
//!
//! * a valid token → `Identify` → a mapped `Principal` under the PROVIDER name, with its roles;
//! * an invalid/absent credential → the chain fail-closed-denies (all-`Pass`), and a token signed by
//!   another key is refused;
//! * a secret-reference setting is resolved by the engine and delivered to the module, and an
//!   unresolvable one fails the load closed;
//! * the admin chain is rebuilt with the module on reload;
//! * a v1 auth plugin is refused at boot, and the current one builds its hosted login.

mod common;

use busbar_contract::secret_ref::SECRET_MODULE_ENV;
use busbar_kernel::auth::{AuthMiddleware, ChainVerdict};
use busbar_kernel::config::{AuthCfg, AuthChainEntry, PluginsCfg};
use std::path::{Path, PathBuf};

/// The token-verifying module's cdylib ([`common::plugins::token_verifier_cdylib_path`]), built by
/// this crate's test build as a git dev-dependency — so it lives under `deps/` WITH a metadata hash.
/// A missing cdylib is a HARD failure in every run, never a skip.
fn auth_cdylib() -> PathBuf {
    common::plugins::token_verifier_cdylib_path().unwrap_or_else(|| {
        panic!(
            "the token-verifying auth plugin's cdylib is not built: run `cargo test -p busbar \
             --no-run` first (its dev-dependency edge builds it; this test never skips)"
        )
    })
}

/// A fresh, empty plugins directory for this process under `tag`.
fn tmp_plugin_dir(tag: &str) -> PathBuf {
    common::plugins::scratch(&format!("auth-chain-{tag}"))
}

/// `lib` packed UNSIGNED under `m` (the hash bound, no signature).
fn unsigned_tarball(m: busbar_plugin_loader::sign::Manifest, lib: &[u8]) -> Vec<u8> {
    common::plugins::seal(m, lib)
}

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

/// `alice`'s token: role `platform`, bound to [`AUDIENCE`].
fn alice_token() -> String {
    issuer().mint("alice", &["platform"], AUDIENCE)
}

/// The runtime identity the module reports for itself — the name its door's Statement states. The
/// chain must report this, never the config alias.
fn module_name() -> &'static str {
    static ONE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ONE.get_or_init(|| {
        let stated = busbar_plugin_loader::dispatch::rendering_of_library(&auth_cdylib())
            .expect("the auth module's cdylib states its door")
            .expect("the auth module's cdylib exports a door");
        busbar_contract::abi::mechanism::rendering::read(&stated)
            .expect("its Statement reads")
            .name
    })
}

/// A `kind: auth` manifest for the given name/alias, stating the door's Statement as the packer
/// renders it from the built library (`busbar-plugin-pack`): a 1.6.0 plugin's manifest states its
/// door, and the engine admits the door against it.
fn auth_manifest(name: &str, alias: &str, publisher: &str) -> busbar_plugin_loader::sign::Manifest {
    let mut m = common::plugins::manifest("auth", name, publisher);
    m.alias = alias.into();
    m.version = "1.5.0".into();
    m.statement = busbar_plugin_loader::dispatch::rendering_of_library(&auth_cdylib())
        .expect("the auth module's cdylib states its door")
        .map(hex::encode);
    m
}

/// Write an UNSIGNED (structurally valid) auth-module tarball into `dir` under `file`. We use the
/// unsigned+`allow_unsigned` path because the test cannot sign with the embedded first-party release
/// key; this still exercises the whole load pipeline.
fn write_auth_plugin(dir: &Path, file: &str, name: &str, alias: &str) {
    let lib = std::fs::read(auth_cdylib()).expect("read the auth module's cdylib");
    let tarball = unsigned_tarball(auth_manifest(name, alias, "acme"), &lib);
    std::fs::write(dir.join(file), tarball).unwrap();
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

/// Write an UNSIGNED auth-module tarball whose manifest declares `audience` as a ROOT-LEVEL
/// `x-busbar-secret` field (see [`auth_manifest_with_root_secret_schema`]).
fn write_auth_plugin_with_root_secret_schema(dir: &Path, file: &str, name: &str, alias: &str) {
    let lib = std::fs::read(auth_cdylib()).expect("read the auth module's cdylib");
    let tarball = unsigned_tarball(
        auth_manifest_with_root_secret_schema(name, alias, "acme", "audience"),
        &lib,
    );
    std::fs::write(dir.join(file), tarball).unwrap();
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
/// which uses it ITSELF — here the module's `ca_cert_pem`, the trust root its need declares for the
/// host to reach the issuer with (`trust_from`), so a token only verifies if the resolved PEM
/// arrived. Conversely, an
/// UNRESOLVABLE ref fails the load FAIL-CLOSED — the plugin is never handed a dangling reference.
#[test]
fn auth_plugin_setting_secret_ref_is_resolved_and_delivered() {
    let dir = tmp_plugin_dir("auth-plugin-secret-ref");
    write_auth_plugin(&dir, "idp.tar.gz", "acme-idp", "ref-auth");
    let plugins = plugins_cfg_allow_unsigned(&dir);

    // The trust root delivered via an env SecretRef: the engine resolves `{ env: VAR }` to the PEM
    // BEFORE open, the module builds its fetcher on it, and a signed token verifies against its keys.
    let var = format!("BUSBAR_PLUGIN_CA_PEM_{}", std::process::id());
    std::env::set_var(&var, issuer().cert_pem());
    let mut settings = settings();
    settings.insert(
        "ca_cert_pem".into(),
        serde_json::json!({ SECRET_MODULE_ENV: var }),
    );
    let cfg = chain_with("ref-auth", settings);
    let registry = busbar_kernel::plugins_preflight(
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
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
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
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
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
    write_auth_plugin_with_root_secret_schema(&dir, "idp.tar.gz", "acme-idp", "sec-auth");
    let plugins = plugins_cfg_allow_unsigned(&dir);

    let var = format!("BUSBAR_PLUGIN_ROOT_SECRET_CONTRACT_{}", std::process::id());
    let raw_audience = "api://the-actual-plaintext-audience";
    std::env::set_var(&var, raw_audience);

    let mut settings = settings();
    settings.insert(
        "audience".to_string(),
        serde_json::json!({ SECRET_MODULE_ENV: var }),
    );
    let cfg = chain_with("sec-auth", settings);

    let registry = busbar_kernel::plugins_preflight(
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
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
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

/// FULL CHAIN, REAL CDYLIB: `auth.chain: [my-auth]` loads the auth module over the loader; a
/// token the issuer signed identifies as `oidc:alice/platform`, and a token with a forged signature,
/// a non-token and an absent credential fail-closed-deny.
#[test]
fn auth_plugin_loads_and_identifies_through_middleware() {
    let dir = tmp_plugin_dir("auth-plugin-e2e");
    // The config chain name is the ALIAS `my-auth`; the plugin's canonical name differs on purpose.
    write_auth_plugin(&dir, "idp.tar.gz", "acme-idp", "my-auth");
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let cfg = chain_with("my-auth", settings());

    // Manifest-only preflight resolves the auth plugin (the `--validate`/boot gate).
    let registry = busbar_kernel::plugins_preflight(
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
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
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

/// 1.5.2 admin-plane OIDC: `AdminAuthChain::build` — the function `build_app_from_config` invokes on
/// BOTH boot and reload — resolves every NON-BUILTIN `admin_auth:` entry into a loaded `kind: auth`
/// plugin, keyed by config name; the operator credential is NOT in the map (it
/// is held apart, `AdminAuthChain::operator`). Building it TWICE against the same registry (boot, then the reload rebuild) both populate:
/// the reload path can never leave `admin_modules` stale/empty.
#[test]
fn admin_modules_rebuilt_on_reload() {
    use busbar_kernel::auth::AdminAuthChain;
    let dir = tmp_plugin_dir("admin-modules-reload");
    write_auth_plugin(&dir, "idp.tar.gz", "acme-idp", "admin-oidc");
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let registry = busbar_plugin_loader::scan_and_validate(
        Path::new(&plugins.dir),
        &busbar_kernel::test_support::trust_policy(&plugins).unwrap(),
    )
    .expect("scan succeeds");
    let registry = std::sync::Arc::new(registry);
    let mut cfg = AuthCfg::default_none();
    let mut entry = AuthChainEntry::bare("admin-oidc");
    entry.settings = settings();
    cfg.admin_auth = vec![
        AuthChainEntry::bare(busbar_kernel::config::operator_provider()),
        entry,
    ];
    let resolver = busbar_kernel::config::secret::SecretResolver::builtins_only();

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

/// THE DESIGN §11.8 (C21): a v1 auth plugin (the pre-login 1.5.x wire) no longer reaches the
/// login-capability gate: the scan refuses it at boot, naming the rebuild. The current version of
/// the SAME plugin with `browser_login` builds — through the one construction path boot and every
/// config apply run (`build_app_from_config`, which builds the hosted-login methods), over a
/// configuration read from disk as boot reads it.
#[test]
fn a_v1_auth_plugin_is_refused_at_boot_and_the_current_one_builds_browser_login() {
    let dir = tmp_plugin_dir("auth-login-v1-gate");
    let lib = std::fs::read(auth_cdylib()).expect("read the auth module's cdylib");
    let mut manifest = auth_manifest("acme-idp", "cap-idp", "acme");
    manifest.abi_version = 1;
    std::fs::write(dir.join("idp.tar.gz"), unsigned_tarball(manifest, &lib)).unwrap();
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let errs = busbar_plugin_loader::scan_and_validate(
        Path::new(&plugins.dir),
        &busbar_kernel::test_support::trust_policy(&plugins).unwrap(),
    )
    .expect_err("a v1 auth plugin is refused at boot");
    assert!(
        errs.iter()
            .any(|e| e.contains("rebuild the plugin against the 1.6.0 SDK")),
        "the refusal names the rebuild: {errs:?}"
    );

    // The current version, configured as a hosted-login provider with `browser_login` (the
    // PROVIDER's `module:` is the plugin it opens; the map key is the provider NAME).
    let dir2 = tmp_plugin_dir("auth-login-current-ok");
    let current = auth_manifest("acme-idp", "cap-idp", "acme");
    std::fs::write(dir2.join("idp.tar.gz"), unsigned_tarball(current, &lib)).unwrap();
    std::env::set_var("BUSBAR_TEST_CLIENT_SECRET", "the-confidential-secret");
    let settings = serde_json::Value::Object(settings()).to_string();
    let config = dir2.join("config.yaml");
    std::fs::write(dir2.join("providers.yaml"), "{}\n").unwrap();
    std::fs::write(
        &config,
        format!(
            "listen: \"127.0.0.1:0\"\npublic_url: \"https://busbar.example.com\"\n\
             store: {{ module: memory }}\nproviders: {{}}\nmodels: {{}}\n\
             plugins: {{ enabled: true, dir: {dir:?}, trust: {{ allow_unsigned: true }} }}\n\
             identity-providers:\n  cap-idp:\n    module: acme-idp\n    browser_login:\n      \
             client_id: client-abc\n      client_secret: {{ env: BUSBAR_TEST_CLIENT_SECRET }}\n    \
             settings: {settings}\n",
            dir = dir2.display().to_string(),
        ),
    )
    .unwrap();
    busbar_kernel::test_support::register_neutral_test_plane();
    let loaded = busbar_kernel::load_config_from_disk(
        &config,
        Some(&dir2.join("providers.yaml")),
        false,
        busbar_kernel::config::EnvSubst::Strict,
    )
    .expect("the configuration reads");
    let cfg = busbar_kernel::config::resolve(&loaded.deploy, &loaded.defs)
        .expect("the configuration resolves");
    let built = busbar_kernel::build_app_from_config(
        cfg,
        loaded.deploy.plugins.clone(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        None,
    );
    let (_app, _rotation, limits) =
        built.expect("the current login-capable plugin with browser_login builds");
    limits.keep();

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}
