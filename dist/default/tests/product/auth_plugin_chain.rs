// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::test_common as common;

use busbar_kernel::auth::{AuthMiddleware, ChainVerdict};
use busbar_kernel::config::{AuthCfg, AuthChainEntry, PluginsCfg};
use std::path::{Path, PathBuf};

fn auth_cdylib() -> PathBuf {
    common::plugins::token_verifier_cdylib_path().unwrap_or_else(|| {
        panic!(
            "the token-verifying auth plugin's cdylib is not built: run `cargo test -p busbar \
             --no-run` first (its dev-dependency edge builds it; this test never skips)"
        )
    })
}

fn tmp_plugin_dir(tag: &str) -> PathBuf {
    common::plugins::scratch(&format!("auth-chain-{tag}"))
}

fn unsigned_tarball(m: busbar_plugin_loader::sign::Manifest, lib: &[u8]) -> Vec<u8> {
    common::plugins::seal(m, lib)
}

const AUDIENCE: &str = "api://plugin-chain";

fn settings() -> serde_json::Map<String, serde_json::Value> {
    common::credentials::settings(AUDIENCE)
}

fn alice_token() -> String {
    common::credentials::token_for("alice", &["platform"], AUDIENCE)
}

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

fn auth_manifest(name: &str, alias: &str, publisher: &str) -> busbar_plugin_loader::sign::Manifest {
    let mut m = common::plugins::manifest("auth", name, publisher);
    m.alias = alias.into();
    m.version = "1.5.0".into();
    m.statement = busbar_plugin_loader::dispatch::rendering_of_library(&auth_cdylib())
        .expect("the auth module's cdylib states its door")
        .map(hex::encode);
    m
}

fn first_party_tarball(mut m: busbar_plugin_loader::sign::Manifest, lib: &[u8]) -> Vec<u8> {
    m.publisher = busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into();
    common::plugins::signed(&crate::dist_root_install::release_key(), m, lib)
}

fn write_auth_plugin(dir: &Path, file: &str, name: &str, alias: &str) {
    let lib = std::fs::read(auth_cdylib()).expect("read the auth module's cdylib");
    let tarball = first_party_tarball(auth_manifest(name, alias, "acme"), &lib);
    std::fs::write(dir.join(file), tarball).unwrap();
}

/// Stage the actual durable Store whose fresh namespace the fixture will initialize.
fn write_application_store(dir: &Path) -> (String, String) {
    let path = common::plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid");
    let mut manifest = common::plugins::manifest("store", &facts.name, "acme");
    manifest.version = facts.version;
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(path).expect("the actual Store image reads");
    std::fs::write(
        dir.join("store.tar.gz"),
        first_party_tarball(manifest, &library),
    )
    .expect("stage the actual Store archive");
    let config = serde_json::json!({
        "module": facts.name,
        "settings": common::plugins::application_store_settings(dir),
    });
    (facts.name, config.to_string())
}

fn plugins_cfg_allow_unsigned(dir: &Path) -> PluginsCfg {
    let mut cfg = PluginsCfg {
        enabled: true,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    cfg.trust.allow_unsigned = true;
    cfg
}

fn pinned_plugins_document(dir: &Path) -> serde_json::Value {
    let mut cfg = plugins_cfg_allow_unsigned(dir);
    // Base configuration must pin the exact staged archives before opening the Store.
    cfg.fetch =
        common::plugins::trusted_config_with_key(dir, &crate::dist_root_install::release_key())
            .fetch;
    common::plugins::config_document(&cfg)
}

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

fn write_auth_plugin_with_root_secret_schema(dir: &Path, file: &str, name: &str, alias: &str) {
    let lib = std::fs::read(auth_cdylib()).expect("read the auth module's cdylib");
    let tarball = first_party_tarball(
        auth_manifest_with_root_secret_schema(name, alias, "acme", "audience"),
        &lib,
    );
    std::fs::write(dir.join(file), tarball).unwrap();
}

fn chain_with(module: &str, settings: serde_json::Map<String, serde_json::Value>) -> AuthCfg {
    let mut entry = AuthChainEntry::bare(module);
    entry.settings = settings.into();
    AuthCfg {
        chain: vec![entry],
        ..AuthCfg::default_none()
    }
}

#[test]
fn auth_plugin_undeclared_setting_is_delivered_as_written_and_a_reference_there_is_refused() {
    crate::dist_root_install::install();
    let dir = tmp_plugin_dir("auth-plugin-secret-ref");
    write_auth_plugin(&dir, "idp.tar.gz", "acme-idp", "ref-auth");
    let plugins = plugins_cfg_allow_unsigned(&dir);

    let mut written = settings();
    written.insert(
        "ca_cert_pem".into(),
        serde_json::json!(common::credentials::cert_pem()),
    );
    let cfg = chain_with("ref-auth", written);
    let registry = busbar_kernel::plugins_preflight(
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
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("a setting written as its value is delivered and the plugin loads");
    assert_eq!(mw.chain_names(), vec![module_name()], "plugin loaded");
    match mw.run_chain(Some(&alice_token())) {
        ChainVerdict::Identified { principal, .. } => {
            assert_eq!(principal.id, common::credentials::principal_id("alice"))
        }
        other => panic!("the delivered trust root must let the module verify: {other:?}"),
    }

    let var = format!("BUSBAR_PLUGIN_CA_PEM_{}", std::process::id());
    std::env::set_var(&var, common::credentials::cert_pem());
    let mut settings = settings();
    settings.insert(
        "ca_cert_pem".into(),
        serde_json::to_value(
            common::plugins::source_reference(
                crate::root::linked::secret_rows(),
                busbar_contract::abi::mechanism::door::SUGAR_ROLE_FILL,
                &var,
            )
            .authoring(&busbar_kernel::seal::acquire()),
        )
        .expect("the admitted source reference serializes"),
    );
    let cfg = chain_with("ref-auth", settings);
    let err = AuthMiddleware::new(
        &cfg,
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect_err("a reference at a field the plugin did not declare secret is refused");
    assert!(
        err.contains("ca_cert_pem")
            && err.contains("did not declare it as a secret")
            && err.contains("write the value itself")
            && !err.contains("BEGIN CERTIFICATE"),
        "refused, names the setting, never the value: {err}"
    );
    std::env::remove_var(&var);

    let serialized = serde_json::to_string(
        &cfg.chain[0]
            .settings
            .authoring(&busbar_kernel::seal::acquire()),
    )
    .expect("serialize settings");
    assert!(
        serialized.contains(&var) && !serialized.contains("BEGIN CERTIFICATE"),
        "config keeps the ref, never the resolved secret: {serialized}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn auth_plugin_schema_marked_setting_is_not_declared_so_a_reference_there_is_refused() {
    crate::dist_root_install::install();
    let dir = tmp_plugin_dir("auth-plugin-root-secret-contract");
    write_auth_plugin_with_root_secret_schema(&dir, "idp.tar.gz", "acme-idp", "sec-auth");
    let plugins = plugins_cfg_allow_unsigned(&dir);

    let raw_audience = "api://the-actual-plaintext-audience";
    let mut written = settings();
    written.insert("audience".to_string(), serde_json::json!(raw_audience));
    let cfg = chain_with("sec-auth", written);
    let registry = busbar_kernel::plugins_preflight(
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
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the audience written as its value is delivered");
    match mw.run_chain(Some(&common::credentials::token_for(
        "alice",
        &["platform"],
        raw_audience,
    ))) {
        ChainVerdict::Identified { principal, .. } => {
            assert_eq!(principal.id, common::credentials::principal_id("alice"))
        }
        other => panic!("a token for the delivered audience must authenticate: {other:?}"),
    }
    assert_eq!(
        mw.run_chain(Some(&alice_token())),
        ChainVerdict::Denied,
        "a token for any other audience is refused"
    );

    let var = format!("BUSBAR_PLUGIN_ROOT_SECRET_CONTRACT_{}", std::process::id());
    std::env::set_var(&var, raw_audience);
    let mut settings = settings();
    settings.insert(
        "audience".to_string(),
        serde_json::to_value(
            common::plugins::source_reference(
                crate::root::linked::secret_rows(),
                busbar_contract::abi::mechanism::door::SUGAR_ROLE_FILL,
                &var,
            )
            .authoring(&busbar_kernel::seal::acquire()),
        )
        .expect("the admitted source reference serializes"),
    );
    let cfg = chain_with("sec-auth", settings);
    let err = AuthMiddleware::new(
        &cfg,
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect_err("a reference at a schema-marked but undeclared field is refused");
    assert!(
        err.contains("audience")
            && err.contains("did not declare it as a secret")
            && !err.contains(raw_audience),
        "refused, names the setting, never the value: {err}"
    );
    std::env::remove_var(&var);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn auth_plugin_loads_and_identifies_through_middleware() {
    crate::dist_root_install::install();
    let dir = tmp_plugin_dir("auth-plugin-e2e");

    write_auth_plugin(&dir, "idp.tar.gz", "acme-idp", "my-auth");
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let cfg = chain_with("my-auth", settings());

    let registry = busbar_kernel::plugins_preflight(
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
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("auth chain loads the plugin");

    assert_eq!(mw.chain_names(), vec![module_name()], "runtime module name");
    assert_ne!(
        module_name(),
        "my-auth",
        "the alias is not the module's identity"
    );

    match mw.run_chain(Some(&alice_token())) {
        ChainVerdict::Identified {
            module, principal, ..
        } => {
            assert_eq!(module, "my-auth", "role_bindings key = the PROVIDER NAME");
            assert_eq!(principal.id, common::credentials::principal_id("alice"));
            assert_eq!(principal.roles, vec!["platform".to_string()]);
        }
        other => panic!("valid token must Identify, got {other:?}"),
    }

    assert_eq!(
        mw.run_chain(Some("wrong")),
        ChainVerdict::Denied,
        "bad token denies"
    );

    let token = alice_token();
    let (signed, _) = token.rsplit_once('.').expect("a JWT");
    assert_eq!(
        mw.run_chain(Some(&format!("{signed}.{}", "A".repeat(86)))),
        ChainVerdict::Denied,
        "a forged signature denies"
    );

    assert_eq!(
        mw.run_chain(None),
        ChainVerdict::Denied,
        "no credential denies"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn admin_modules_rebuilt_on_reload() {
    crate::dist_root_install::install();
    let dir = tmp_plugin_dir("admin-modules-reload");
    let (_, store) = write_application_store(&dir);
    write_auth_plugin(&dir, "idp.tar.gz", "acme-idp", "admin-oidc");
    let plugins = pinned_plugins_document(&dir);
    let config = dir.join("config.yaml");
    let providers = dir.join("providers.yaml");
    std::fs::write(&providers, "{}\n").unwrap();
    let settings = serde_json::Value::Object(settings()).to_string();
    let rules = std::sync::Arc::new(busbar_kernel::appbuild::AcceptAll)
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let build = async |provider: &str, prior: Option<&busbar_kernel::state::App>| {
        std::fs::write(
            &config,
            format!(
                "listen: \"127.0.0.1:0\"\nstore: {store}\nproviders: {{}}\nmodels: {{}}\n\
             plugins: {plugins}\n\
             auth:\n  chain: []\n  admin_auth: [{operator:?}, {provider:?}]\n\
             identity-providers:\n  admin-oidc:\n    module: acme-idp\n    settings: {settings}\n\
             \x20 reloaded-admin:\n    module: acme-idp\n    settings: {settings}\n",
                operator = busbar_kernel::config::operator_provider(),
            ),
        )
        .unwrap();
        let loaded = busbar_kernel::load_config_from_disk(
            &config,
            Some(&providers),
            false,
            busbar_kernel::config::EnvSubst::Strict,
        )
        .expect("the configuration reads");
        let cfg = busbar_kernel::config::resolve(&loaded.deploy, &loaded.defs)
            .expect("the configuration resolves");
        // Initialize only at first construction; reload retains the same baseline and Store.
        let anchor = if prior.is_none() {
            Some(
                common::plugins::bootstrap_fresh_application_store(
                    &cfg,
                    &loaded.deploy.plugins,
                    &dir,
                )
                .await
                .expect("the actual new Store initializes its principal baseline"),
            )
        } else {
            None
        };
        let (app, _rotation, _limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            loaded.deploy.plugins.clone(),
            None,
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
            (Some(config.clone()), Some(providers.clone())),
            prior,
            &rules,
            anchor,
            false,
        )
        .await
        .expect("the real application builds its admin chain");
        app
    };
    // Keep both marked provider definitions stable; reload changes admin-chain membership.
    let boot = build("admin-oidc", None).await;
    assert!(
        boot.admin_modules.modules.contains_key("admin-oidc"),
        "keyed by the config module name"
    );
    assert_eq!(
        boot.admin_modules.modules.len(),
        1,
        "the operator credential is held apart, never inserted into admin_modules"
    );

    let reload = build("reloaded-admin", Some(&boot)).await;
    assert!(
        reload.admin_modules.modules.contains_key("reloaded-admin"),
        "the reload installs its newly configured provider"
    );
    assert!(!reload.admin_modules.modules.contains_key("admin-oidc"));
    assert_eq!(reload.admin_modules.modules.len(), 1);
    assert_eq!(
        reload.admin_chain.last().map(String::as_str),
        Some("reloaded-admin")
    );
    assert!(boot.admin_modules.modules.contains_key("admin-oidc"));
    assert!(!boot.admin_modules.modules.contains_key("reloaded-admin"));
    assert!(
        std::sync::Arc::ptr_eq(
            boot.governance.as_ref().expect("boot store"),
            reload.governance.as_ref().expect("reload store"),
        ),
        "the reload actually uses its prior generation's store"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_v1_auth_plugin_is_refused_at_boot_and_the_current_one_builds_browser_login() {
    crate::dist_root_install::install();
    let dir = tmp_plugin_dir("auth-login-v1-gate");
    let lib = std::fs::read(auth_cdylib()).expect("read the auth module's cdylib");
    let mut manifest = auth_manifest("acme-idp", "cap-idp", "acme");
    manifest.abi_version = 1;
    std::fs::write(dir.join("idp.tar.gz"), unsigned_tarball(manifest, &lib)).unwrap();
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let errs = busbar_plugin_loader::scan_and_validate(
        Path::new(&plugins.dir),
        &crate::dist_root_install::trust_policy(&plugins).unwrap(),
    )
    .expect_err("a v1 auth plugin is refused at boot");
    assert!(
        errs.iter()
            .any(|e| e.contains("rebuild the plugin against the 1.6.0 SDK")),
        "the refusal names the rebuild: {errs:?}"
    );

    let dir2 = tmp_plugin_dir("auth-login-current-ok");
    let (store_module, store) = write_application_store(&dir2);
    let current = auth_manifest("acme-idp", "cap-idp", "acme");
    std::fs::write(dir2.join("idp.tar.gz"), first_party_tarball(current, &lib)).unwrap();
    let plugins = pinned_plugins_document(&dir2);
    std::env::set_var("BUSBAR_TEST_CLIENT_SECRET", "the-confidential-secret");
    let settings = serde_json::Value::Object(settings()).to_string();
    let config = dir2.join("config.yaml");
    std::fs::write(dir2.join("providers.yaml"), "{}\n").unwrap();
    std::fs::write(
        &config,
        format!(
            "listen: \"127.0.0.1:0\"\npublic_url: \"https://busbar.example.com\"\n\
             store: {store}\nproviders: {{}}\nmodels: {{}}\n\
             plugins: {plugins}\n\
             identity-providers:\n  cap-idp:\n    module: acme-idp\n    browser_login:\n      \
             client_id: client-abc\n      client_secret: {{ env: BUSBAR_TEST_CLIENT_SECRET }}\n    \
             settings: {settings}\n",
        ),
    )
    .unwrap();
    let loaded = busbar_kernel::load_config_from_disk(
        &config,
        Some(&dir2.join("providers.yaml")),
        false,
        busbar_kernel::config::EnvSubst::Strict,
    )
    .expect("the configuration reads");
    let cfg = busbar_kernel::config::resolve(&loaded.deploy, &loaded.defs)
        .expect("the configuration resolves");
    let anchor =
        common::plugins::bootstrap_fresh_application_store(&cfg, &loaded.deploy.plugins, &dir2)
            .await
            .expect("the actual new Store initializes its principal baseline");
    let built = busbar_kernel::appbuild::build_app_from_config_with_store(
        cfg,
        loaded.deploy.plugins.clone(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        None,
        &(std::sync::Arc::new(busbar_kernel::appbuild::AcceptAll)
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>),
        Some(anchor),
        true,
    )
    .await;
    let (app, _rotation, limits) =
        built.expect("the current login-capable plugin with browser_login builds");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &store_module)
        .await
        .expect("the real configured Store binds the boot rate authority before activation");
    limits
        .keep()
        .await
        .expect("the login-capable app activates its configuration");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}
