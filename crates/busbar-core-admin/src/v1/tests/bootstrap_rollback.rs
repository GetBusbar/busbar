// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;

struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn service(
    anchor: &str,
    target: &str,
    alias: &str,
    base_floor: &str,
    store_settings: serde_json::Value,
    kind: &str,
) -> (Scratch, AdminService) {
    let dir = tmp_plugins_dir("bootstrap-rollback");
    let plugins = dir.join("plugins");
    std::fs::create_dir_all(&plugins).unwrap();
    let config = dir.join("config.yaml");
    let providers = dir.join("providers.yaml");
    std::fs::write(&providers, "{}").unwrap();
    let mut live = strict_posture();
    live.enabled = true;
    live.dir = plugins.to_string_lossy().into_owned();

    live.min_versions.insert(target.into(), "1.4.0".into());
    let mut rows = vec![busbar_kernel_testkit::test_support::rows::row(
        "acme-anchor",
        "anchor-alias",
        "store",
    )];
    if target != "acme-anchor" {
        rows.push(busbar_kernel_testkit::test_support::rows::row(
            target, alias, kind,
        ));
    }
    busbar_kernel_testkit::test_support::rows::drop_in(&plugins, rows, Vec::new());
    let mut bytes = fake_tarball(target, alias, "1.4.0", "rollback-only");
    if kind != "store" {
        let mut manifest: serde_json::Value =
            serde_json::from_slice(bytes.strip_prefix(FAKE_HEAD).unwrap()).unwrap();
        manifest["kind"] = serde_json::json!(kind);
        bytes = FAKE_HEAD.to_vec();
        bytes.extend(serde_json::to_vec(&manifest).unwrap());
    }
    let archive_pin = busbar_contract::redacted::sha256_hex(&bytes);
    std::fs::write(plugins.join("target.tar.gz"), &bytes).unwrap();

    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
            "providers": {}, "models": {}, "store": {"module":anchor,"settings":store_settings},
            "plugins": {
                "enabled":true,"dir":plugins,"min_versions":{(target):base_floor},
                "fetch":[{"url":"https://plugins.example/target.tar.gz","sha256":archive_pin}]
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let app = crate::new_test_app()
        .plugins_dir(plugins)
        .plugins_cfg(live)
        .plugin_admission(&DIR_ADMISSION)
        .disk_paths(config, providers)
        .build();
    (Scratch(dir), AdminService::new(app))
}

#[test]
fn rollback_refuses_the_anchor_below_its_operator_bootstrap_floor_before_any_pin_is_returned() {
    let (_dir, service) = service(
        "anchor-alias",
        "acme-anchor",
        "anchor-alias",
        "2.0.0",
        serde_json::json!({}),
        "store",
    );
    let error = service
        .resolve_plugin_rollback("target.tar.gz", &Default::default())
        .unwrap_err();
    assert!(
        matches!(&error, AdminError::Conflict(message) if message.contains("bootstrap dependency") && message.contains("base config.yaml") && message.contains("acme-anchor")),
        "{error:?}"
    );
}

#[test]
fn safe_anchor_and_nonanchor_rollbacks_preserve_the_existing_pin_merge() {
    for (anchor, target, alias, base_floor) in [
        ("anchor-alias", "acme-anchor", "anchor-alias", "1.4.0"),
        ("anchor-alias", "other-store", "other", "2.0.0"),
    ] {
        let (_dir, service) = service(
            anchor,
            target,
            alias,
            base_floor,
            serde_json::json!({}),
            "store",
        );
        let prior = std::collections::BTreeMap::from([("prior-plugin".into(), "3.0.0".into())]);
        let (manifest, pins) = service
            .resolve_plugin_rollback("target.tar.gz", &prior)
            .unwrap();
        assert_eq!(manifest.name, target);
        assert_eq!(pins[target], "1.4.0");
        assert_eq!(pins["prior-plugin"], "3.0.0");
    }
}

#[test]
fn a_secret_plugin_needed_to_open_the_anchor_cannot_rely_on_its_unread_store_pin() {
    let anchor = busbar_kernel_testkit::test_support::stand_in_store().module;
    let (_dir, service) = service(
        &anchor,
        "acme-vault",
        "vault-alias",
        "2.0.0",
        serde_json::json!({"token":{"module":"vault-alias","settings":{}}}),
        "secret",
    );
    let error = service
        .resolve_plugin_rollback("target.tar.gz", &Default::default())
        .unwrap_err();
    assert!(
        matches!(&error, AdminError::Conflict(message) if message.contains("bootstrap dependency") && message.contains("acme-vault")),
        "{error:?}"
    );
}

#[test]
fn an_upload_cannot_replace_the_anchor_with_a_target_only_the_running_pin_admits() {
    let (dir, service) = service(
        "anchor-alias",
        "acme-anchor",
        "anchor-alias",
        "2.0.0",
        serde_json::json!({}),
        "store",
    );
    let file = dir.0.join("plugins/target.tar.gz");
    let original = fake_tarball("acme-anchor", "anchor-alias", "2.0.0", "trusted");
    std::fs::write(&file, &original).unwrap();
    let candidate = fake_tarball("acme-anchor", "anchor-alias", "1.4.0", "rollback-only");
    let error = service
        .install_store_plugin("target.tar.gz", &candidate)
        .unwrap_err();
    assert!(
        matches!(&error, AdminError::Conflict(message) if message.contains("bootstrap dependency") && message.contains("install")),
        "{error:?}"
    );
    assert_eq!(std::fs::read(file).unwrap(), original);
}
