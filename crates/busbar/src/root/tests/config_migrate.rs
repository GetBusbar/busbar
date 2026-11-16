// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_migrations::config::migrate::migrate_config_with;
use busbar_migrations::config::migrate_plugins::MigrateHost;

use super::{Index, IndexPlugin};
use busbar_contract::yaml::ValueExt;

#[test]
fn core_applies_the_real_llm_migrations_private_destination_need() {
    crate::dist_root_install::install();
    let config = "\
store: { module: memory }
providers:
  in-rack:
    base_url: http://\x310.1.2.3:8000/v1
models: {}
pools: {}
";
    let directory = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    let host = super::RootHost::for_document(config, &directory.0.join("config.yaml"));
    let out = migrate_config_with(config, &host).expect("the real linked plane migrates");
    let doc: busbar_contract::yaml::Value =
        busbar_contract::yaml::from_str(&out.yaml).expect("migrated YAML");
    assert_eq!(
        *doc.at("advanced").at("allow_destinations"),
        busbar_contract::yaml::from_str::<busbar_contract::yaml::Value>("['\x310.1.2.3']").unwrap(),
        "the real plane's need is applied to the core-owned allowlist: {}",
        out.yaml
    );
    assert_eq!(
        doc.at("providers").at("in-rack").at("base_url").as_str(),
        Some("http://\x310.1.2.3:8000/v1"),
        "the plane's provider settings remain intact"
    );
}

#[test]
fn direct_models_migrate_the_catalog_destination_without_a_pool_section() {
    crate::dist_root_install::install();
    let config = "\
store: { module: memory }
providers:
  fixture-openai: { api_key: { env: FIXTURE_UPSTREAM_KEY } }
models:
  m-chat: { provider: fixture-openai }
advanced:
  usage_flush_interval_ms: 3600000
";
    let directory = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    let catalog = "fixture-openai:\n  protocol: openai\n  base_url: http://127.0.0.1:35761\n";
    std::fs::write(directory.0.join("providers.yaml"), catalog).unwrap();
    let host = super::RootHost::for_document(config, &directory.0.join("config.yaml"));
    let out = migrate_config_with(config, &host).expect("the selected LLM plane migrates");
    let doc: busbar_contract::yaml::Value = busbar_contract::yaml::from_str(&out.yaml).unwrap();
    assert_eq!(
        *doc.at("advanced").at("allow_destinations"),
        busbar_contract::yaml::from_str::<busbar_contract::yaml::Value>("[127.0.0.1]").unwrap()
    );
    assert!(doc.at("advanced").get("block_private_addresses").is_none());
    assert!(
        doc.get("pools").is_none(),
        "migration must not invent a pool section"
    );
    assert_eq!(
        doc.at("models").at("m-chat").at("provider").as_str(),
        Some("fixture-openai")
    );
    assert_eq!(
        doc.at("providers")
            .at("fixture-openai")
            .at("api_key")
            .at("env")
            .as_str(),
        Some("FIXTURE_UPSTREAM_KEY")
    );
    assert_eq!(
        std::fs::read_to_string(directory.0.join("providers.yaml")).unwrap(),
        catalog
    );
    assert!(out.changes.iter().any(|line| line.contains("127.0.0.1")));
    assert!(out.todos.is_empty(), "{:?}", out.todos);
}

/// WHO: an operator migrating a 1.5.x config that has the shipped catalog beside it, whose model
/// names a private provider that exists only in the catalog (an in-rack upstream).
/// WHY: migrate judges exactly the hosts the deployment dials (a model names it, or the config
/// authors it) and nothing else. A catalog-only provider a model names still gets its
/// allow_destinations entry, or 1.6.0 refuses the dial after the upgrade. A catalog entry no model
/// names and the config does not author is neither resolved nor reported (UPG-A17e).
#[test]
fn migrate_judges_only_the_providers_the_deployment_dials_not_the_whole_catalog() {
    crate::dist_root_install::install();
    // `used` is in the catalog only and is named only by a model: the config does NOT author it,
    // so it is kept only if core hands `models:` to the plane's migrate site. `authored` is kept
    // through the authored-providers provenance. Address literals and one `.invalid` name, so no
    // DNS answer decides the result.
    let config = "\
store: { module: memory }
providers:
  authored: { api_key: { env: FIXTURE_UPSTREAM_KEY } }
models:
  m: { provider: used }
advanced:
  usage_flush_interval_ms: 3600000
";
    let directory = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    let catalog = "\
used:
  protocol: openai
  base_url: http://\x310.20.0.1:8000
authored:
  protocol: openai
  base_url: http://\x310.20.0.2
catalog-only:
  protocol: openai
  base_url: http://\x310.20.0.3
catalog-unresolvable:
  protocol: openai
  base_url: http://never.invalid
";
    std::fs::write(directory.0.join("providers.yaml"), catalog).unwrap();
    let host = super::RootHost::for_document(config, &directory.0.join("config.yaml"));
    let out = migrate_config_with(config, &host).expect("the real linked plane migrates");
    let doc: busbar_contract::yaml::Value =
        busbar_contract::yaml::from_str(&out.yaml).expect("migrated YAML");
    let mut allowed: Vec<String> = doc
        .at("advanced")
        .at("allow_destinations")
        .as_sequence()
        .map(|hosts| {
            hosts
                .iter()
                .filter_map(|h| h.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    allowed.sort();
    assert_eq!(
        allowed,
        ["\x310.20.0.1", "\x310.20.0.2"],
        "exactly the model-named and the authored provider are judged: {}",
        out.yaml
    );
    for line in out.changes.iter().chain(out.todos.iter()) {
        assert!(
            !line.contains("\x310.20.0.3") && !line.contains("never.invalid"),
            "a catalog entry the deployment never dials is reported: {line}"
        );
    }
    assert!(out.todos.is_empty(), "{:?}", out.todos);
}

#[test]
fn the_release_index_picks_the_newest_release_built_for_this_core() {
    let kind = "store";
    let speaks = crate::root::loader::registry::supported_abi(kind).unwrap();
    let index = Index::parse(
        &serde_json::to_vec(&serde_json::json!({
            "plugins": [{
                "repo": "Acme/busbar-store-stub",
                "former_repos": ["Acme/stub-store"],
                "kind": kind,
                "answers_to": ["stub", "busbar-store-stub", "busbar-store-stub-plugin"],
                "releases": [
                    { "tag": "v1.0.6", "abi_version": speaks - 1 },
                    { "tag": "v1.6.1", "abi_version": speaks },
                    { "tag": "v1.6.0", "abi_version": speaks },
                    { "tag": "v2.0.0", "abi_version": speaks + 1 }
                ]
            }]
        }))
        .expect("JSON"),
    )
    .expect("an index");
    let plugin: &IndexPlugin = index
        .by_repo("acme/STUB-store")
        .expect("a former repo resolves");
    assert_eq!(
        plugin.pin_for_this_core().as_deref(),
        Some("Acme/busbar-store-stub@v1.6.1")
    );
    assert!(index.by_module(kind, "busbar-store-stub-plugin").is_some());
    assert!(
        index.by_module("auth", "stub").is_none(),
        "a module is looked up on its own kind"
    );
    assert!(
        Index::parse(br#"{"plugins": [], "extra": 1}"#).is_err(),
        "an index with keys this core does not know is refused"
    );
}

#[test]
fn release_index_orders_prereleases_before_stable_and_numeric_identifiers_numerically() {
    let abi = crate::root::loader::registry::supported_abi("store").unwrap();
    for tags in [
        vec!["v1.6.0", "v1.6.0-rc.10"],
        vec!["v1.6.0-rc.10", "v1.6.0"],
        vec!["v1.6.0-rc.2", "v1.6.0-rc.10"],
    ] {
        let stable = tags.contains(&"v1.6.0");
        let plugin = IndexPlugin {
            repo: "Acme/stub".into(),
            former_repos: vec![],
            kind: "store".into(),
            answers_to: vec!["stub".into()],
            releases: tags
                .into_iter()
                .map(|tag| super::IndexRelease {
                    tag: tag.into(),
                    abi_version: abi,
                })
                .collect(),
        };
        assert_eq!(
            plugin.pin_for_this_core().as_deref(),
            Some(if stable {
                "Acme/stub@v1.6.0"
            } else {
                "Acme/stub@v1.6.0-rc.10"
            })
        );
    }
    assert_eq!(
        super::version_order("v1.6.0+build.2", "v1.6.0+build.9"),
        std::cmp::Ordering::Equal
    );
    assert!(super::version_order("v1.6.0-alpha", "v1.6.0-alpha.1").is_lt());
    assert!(super::version_order("v1.6.0-11", "v1.6.0-alpha").is_lt());
}

#[test]
fn migration_paths_do_not_consume_later_provider_options() {
    for (option, path) in [
        ("--migrate-config", "--config"),
        ("--migrate-config", "--providers"),
        ("--migrate-config", "-c"),
        ("--config", "--migrate-config"),
    ] {
        let args = [option, path, "--providers", "selected-catalog.yaml"];
        assert_eq!(
            crate::root::cli::Argv::parse(args).providers,
            Some("selected-catalog.yaml".to_owned()),
            "the literal migration path {path} is not a providers option"
        );
    }
}

#[test]
fn migration_staging_owns_only_its_fresh_private_directory() {
    let first = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    let second = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    assert_ne!(first.0, second.0);
    std::fs::write(first.0.join("owned"), b"first").unwrap();
    std::fs::write(second.0.join("other"), b"second").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&first.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    let gone = first.0.clone();
    drop(first);
    assert!(!gone.exists());
    assert_eq!(std::fs::read(second.0.join("other")).unwrap(), b"second");
}

#[test]
fn the_root_hands_the_catalog_boot_reads_to_the_plane_migrations() {
    let config = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/migration-corpus/private-destinations/config.yaml");
    let raw = std::fs::read_to_string(&config).expect("the corpus fixture");
    let host = super::RootHost::for_document(&raw, &config);
    let catalog = host
        .providers_catalog()
        .expect("reads")
        .expect("a catalog beside the configuration");
    assert_eq!(
        catalog["in-rack"]["base_url"],
        serde_json::json!("http://\x3192.168.40.12:8000/v1")
    );
    assert_eq!(
        catalog["corp-gateway"]["token_url"],
        serde_json::json!("http://\x310.9.8.7/oauth2/token")
    );
}

#[test]
fn frozen_overlay_host_keeps_coincident_authored_templates_as_literal_data() {
    let raw = "store: {module: memory, settings: {password: '${COINCIDENT}'}}\n";
    let detection = "store: {module: memory, settings: {password: 'environment-value'}}\n";
    let documents =
        std::sync::Arc::new(crate::root::startup_upgrade::documents::Documents::default());
    let authored = super::RootHost::for_startup_document(
        raw,
        detection,
        std::path::Path::new("config.yaml"),
        documents.clone(),
    )
    .unwrap();
    assert_eq!(
        authored.resolved_authored_scalar("${COINCIDENT}").unwrap(),
        Some(serde_json::Value::String("environment-value".into()))
    );
    let frozen = super::RootHost::for_frozen_overlay(
        raw,
        detection,
        std::path::Path::new("config.yaml"),
        documents,
    )
    .unwrap();
    assert_eq!(
        frozen.resolved_authored_scalar("${COINCIDENT}").unwrap(),
        None
    );
}

#[test]
fn current_settings_validation_does_not_read_a_selected_planes_historical_catalog() {
    use std::cell::Cell;

    struct Host {
        catalog_reads: Cell<usize>,
        auth_validations: Cell<usize>,
    }
    impl MigrateHost for Host {
        fn migrate(
            &self,
            _: &str,
            _: &str,
            _: &serde_json::Value,
            _: &str,
        ) -> Result<Option<(String, busbar_contract::abi::sdk::migrate::MigrationAnswer)>, String>
        {
            Ok(None)
        }
        fn repin(&self, _: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn release_for(&self, _: &str, _: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn providers_catalog(
            &self,
        ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
            self.catalog_reads.set(self.catalog_reads.get() + 1);
            Err("historical catalog unavailable".into())
        }
        fn validate_migrated(
            &self,
            kind: &str,
            module: &str,
            settings: &serde_json::Value,
        ) -> Result<(), String> {
            if kind == "auth" {
                assert_eq!(module, "oidc");
                assert_eq!(
                    settings,
                    &serde_json::json!({
                        "issuer": "https://issuer.example", "audience": "witness"
                    })
                );
                self.auth_validations.set(self.auth_validations.get() + 1);
            }
            Ok(())
        }
    }

    crate::dist_root_install::install();
    assert!(
        busbar_kernel::plane_driver::registry::plane_decls()
            .iter()
            .any(|plane| {
                (plane.config_section == "pools" || plane.owned_config_sections.contains(&"pools"))
                    && busbar_kernel::plane_driver::door::consumed_sections(plane)
                        .contains(&"providers")
            }),
        "the actual installed pools plane consumes providers for historical migration"
    );
    let raw = "store: {module: memory}
providers: {}
models: {}
pools: {}
identity-providers: {rig: {module: oidc, settings: {issuer: https://issuer.example, audience: witness}}}
auth: {chain: [keys], admin_auth: [rig], signing_key: {env: UNUSED_CATALOG_WITNESS}, role_bindings: {rig: {reader: {admin_scope: read-only}}}}
";
    let host = Host {
        catalog_reads: Cell::new(0),
        auth_validations: Cell::new(0),
    };
    let current = busbar_migrations::config::normalize_authored(raw, &host).unwrap();
    assert_eq!(host.catalog_reads.get(), 0);
    assert_eq!(host.auth_validations.get(), 1);
    assert!(current.todos.is_empty(), "{:?}", current.todos);
    assert_eq!(current.yaml, raw);

    let historical = migrate_config_with(raw, &host).unwrap();
    assert!(host.catalog_reads.get() > 0);
    assert!(
        historical
            .todos
            .iter()
            .any(|todo| todo.starts_with("providers:")
                && todo.contains("providers catalog could not be read for the plane migrations")
                && todo.contains("historical catalog unavailable")),
        "{:?}",
        historical.todos
    );
}

#[cfg(distribution_root)]
#[test]
fn credential_owner_migration_resolves_outer_source_once_and_keeps_inline_reference() {
    crate::dist_root_install::install();
    let directory = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    let key = directory.0.join(" key.json ");
    let pointer = directory.0.join("old-credential");
    std::fs::write(
        &key,
        br#"{"client_email":"test@example.com","private_key":"SYNTHETIC_KEY"}"#,
    )
    .unwrap();
    std::fs::write(&pointer, format!("{}\r\n", key.display())).unwrap();
    let host = super::RootHost::for_document("{}", &directory.0.join("elsewhere/config.yaml"));
    let sources = host.source_declarations().unwrap();
    let source = |path: &std::path::Path| {
        sources
            .reference_for_role(
                busbar_contract::abi::mechanism::door::SUGAR_ROLE_PATH,
                path.to_str().unwrap(),
            )
            .unwrap()
    };
    let original = source(&pointer);
    let migrated = host
        .migrate_credential("oauth", &original, "1.5.5")
        .unwrap()
        .unwrap();
    assert_eq!(migrated, source(&key));
    assert!(host
        .migrate_credential("oauth", &migrated, "1.5.5")
        .unwrap()
        .is_none());
    let error = host
        .migrate_credential(
            "oauth",
            &source(&directory.0.join("SYNTHETIC_ABSENT")),
            "1.5.5",
        )
        .unwrap_err();
    assert!(!error.contains("SYNTHETIC_ABSENT"));
}

/// The 1.4 `governance.db_path` shape of the `LAW0-MIG-OPERATOR-14X` cell: no `plugins:` section,
/// so the sqlite Store's current plugin can only be fetched.
const GOVERNANCE_14: &str = "governance: {enabled: true, db_path: busbar-governance.db}\n";

/// A downloader that never touches the network and fails the way the connector does, echoing the
/// whole URL it was handed.
fn echo_fail(url: &str) -> Result<Vec<u8>, String> {
    Err(format!("GET {url}: error sending request for url ({url})"))
}

#[test]
fn an_unreachable_credentialed_index_is_shown_without_its_secrets() {
    crate::dist_root_install::install();
    let directory = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    let mut host = super::RootHost::for_document(GOVERNANCE_14, &directory.0.join("config.yaml"));
    host.index_source =
        "https://u:TOKSENTINEL@127.0.0.1:1/i.json?sig=SIGSENTINEL#FRAGSENTINEL".into();
    host.download = echo_fail;
    let Err(line) = migrate_config_with(GOVERNANCE_14, &host) else {
        panic!("a Store whose plugin cannot be obtained is not emitted");
    };
    assert!(line.contains("https://127.0.0.1:1/i.json"), "{line}");
    for secret in [
        "TOKSENTINEL",
        "SIGSENTINEL",
        "FRAGSENTINEL",
        "u:",
        "error sending request",
    ] {
        assert!(!line.contains(secret), "{secret} reached the line: {line}");
    }
}

/// A file index naming the sqlite Store with one release built for this core, at `tag`.
fn sqlite_index(dir: &std::path::Path, repo: &str, tag: &str, abi: u32) -> String {
    let index = dir.join("plugin-index.json");
    std::fs::write(
        &index,
        serde_json::to_vec(&serde_json::json!({
            "plugins": [{
                "repo": repo,
                "kind": "store",
                "answers_to": ["sqlite"],
                "releases": [{ "tag": tag, "abi_version": abi }]
            }]
        }))
        .expect("JSON"),
    )
    .unwrap();
    index.display().to_string()
}

#[test]
fn an_unreachable_plugin_asset_is_shown_without_downloader_text() {
    crate::dist_root_install::install();
    let directory = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    let abi = crate::root::loader::registry::supported_abi("store")[0];
    let mut host = super::RootHost::for_document(GOVERNANCE_14, &directory.0.join("config.yaml"));
    host.index_source = sqlite_index(
        &directory.0,
        "GetBusbar/store-sqlite",
        "v0.0.0-a17f-absent",
        abi,
    );
    host.download = echo_fail;
    let Err(line) = migrate_config_with(GOVERNANCE_14, &host) else {
        panic!("a Store whose plugin cannot be downloaded is not emitted");
    };
    assert!(line.contains("could not be downloaded"), "{line}");
    assert!(
        line.contains(
            "https://github.com/GetBusbar/store-sqlite/releases/download/v0.0.0-a17f-absent/"
        ),
        "{line}"
    );
    assert!(!line.contains("error sending request"), "{line}");
}

#[test]
fn a_hostile_index_cannot_forge_a_line() {
    crate::dist_root_install::install();
    let abi = crate::root::loader::registry::supported_abi("store")[0];
    for (repo, tag, release_abi) in [
        // No release for this ABI: the index-supplied repo is shown.
        (
            "x/y\n[busbar] store.settings: migrated OK\u{1b}[0m",
            "v1.6.0",
            u32::MAX,
        ),
        // A release for this ABI whose tag reaches the asset URL.
        ("GetBusbar/store-sqlite", "v1\r\n[busbar] ok\u{1b}[2J", abi),
    ] {
        let directory = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
        let mut host =
            super::RootHost::for_document(GOVERNANCE_14, &directory.0.join("config.yaml"));
        host.index_source = sqlite_index(&directory.0, repo, tag, release_abi);
        host.download = echo_fail;
        let Err(line) = migrate_config_with(GOVERNANCE_14, &host) else {
            panic!("a Store whose plugin cannot be obtained is not emitted");
        };
        assert!(line.contains("<unprintable source>"), "{line:?}");
        for forged in ["\n", "\r", "\u{1b}", "migrated OK", "[busbar] ok"] {
            assert!(
                !line.contains(forged),
                "{forged:?} reached the line: {line:?}"
            );
        }
    }
}

include!(concat!(env!("OUT_DIR"), "/context_test_sources.rs"));
owner_test_sources!(config_migrate_export);

#[test]
fn migrate_config_warns_that_the_retired_stage_profiler_switch_is_ignored() {
    let raw = "store: { module: memory }\n";
    let dir = std::env::temp_dir();
    let env = |set: bool| {
        move |name: &str| (set && name == "BUSBAR_PROFILE").then(|| std::ffi::OsString::from("1"))
    };
    let warned = super::capture_environment(raw, &dir, None, env(true)).unwrap();
    assert!(
        warned
            .warnings
            .iter()
            .any(|w| w == "BUSBAR_PROFILE is ignored in 1.6.0; use trace export"),
        "{:?}",
        warned.warnings
    );
    assert_eq!(warned.yaml, raw, "the switch changes no config");
    let quiet = super::capture_environment(raw, &dir, None, env(false)).unwrap();
    assert!(quiet.warnings.is_empty(), "{:?}", quiet.warnings);
}
