// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::test_common as common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use busbar_contract::plugin_rows::PluginRows;
use busbar_kernel::config::{PluginsCfg, StoreCfg};
use busbar_plugin_loader::sign::Manifest;

fn tmp_plugin_dir(tag: &str) -> PathBuf {
    common::plugins::scratch(&format!("preflight-scan-{tag}"))
}

fn plugin_manifest(name: &str, alias: &str, publisher: &str) -> Manifest {
    let mut m = common::plugins::manifest("store", name, publisher);
    m.alias = alias.into();
    m.version = "1.5.0".into();
    m
}

fn unsigned_tarball(mut m: Manifest, lib: &[u8]) -> Vec<u8> {
    m.sha256 = busbar_plugin_loader::sign::sha256_hex(lib);
    busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap()
}

fn plugins_cfg(dir: &Path, enabled: bool) -> PluginsCfg {
    PluginsCfg {
        enabled,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    }
}

fn gov_with_store(store: &str) -> StoreCfg {
    StoreCfg {
        module: store.to_string(),
        settings: serde_json::Map::new(),
    }
}

fn preflight(
    store: Option<&StoreCfg>,
    plugins: &PluginsCfg,
) -> Result<Arc<dyn PluginRows>, String> {
    crate::dist_root_install::install();
    busbar_kernel::plugins_preflight(
        store,
        None,
        &Default::default(),
        &Default::default(),
        plugins,
        &Default::default(),
    )
}

#[test]
fn disabled_plugins_are_inert_even_when_present() {
    let dir = tmp_plugin_dir("inert");
    let tarball = unsigned_tarball(plugin_manifest("acme-store-x", "x", "acme"), b"lib");
    std::fs::write(dir.join("x.tar.gz"), tarball).unwrap();

    std::fs::write(dir.join("junk.tar.gz"), b"not a tarball").unwrap();
    let reg = preflight(None, &plugins_cfg(&dir, false)).expect("inert");
    assert!(reg.loadable().is_empty() && reg.skipped().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_built_in_stores_dropped_in_copy_is_admitted_once_and_a_rival_is_refused() {
    crate::dist_root_install::install();
    let (name, _, _, canonical) = busbar_kernel::preflight::root_rows()
        .stores
        .first()
        .copied()
        .expect("the build links a store");
    let store = gov_with_store(name);
    let linked = busbar_kernel::preflight::linked().expect("the linked rows register");
    let registry =
        busbar_plugin_loader::rows::registry_of(linked.as_ref()).expect("the loader built it");
    let row = registry.resolve(name).expect("the linked store is a row");
    let version = row.plugin_version().expect("the store states its version");
    let statement = row.statement().expect("the store states itself");

    let dir = tmp_plugin_dir("linked-store");
    let mut m = plugin_manifest(canonical, name, "acme");
    m.version = version.clone();
    m.statement = Some(hex::encode(&statement));
    std::fs::write(dir.join("copy.tar.gz"), unsigned_tarball(m, b"lib")).unwrap();
    let mut cfg = plugins_cfg(&dir, true);
    cfg.trust.allow_unsigned = true;
    let scan = || preflight(Some(&store), &cfg);
    let reg = scan().expect("the directory scans");
    assert!(
        reg.resolve(name).expect("resolves").linked,
        "the linked row serves"
    );
    assert_eq!(reg.loadable().len(), 0, "the copy is no row of its own");
    let scanned = busbar_plugin_loader::rows::registry_of(reg.as_ref()).expect("the loader's");
    assert_eq!(scanned.linked_copies().len(), 1);

    std::fs::remove_file(dir.join("copy.tar.gz")).unwrap();
    let other = unsigned_tarball(plugin_manifest(name, "acme-ram", "acme"), b"lib");
    std::fs::write(dir.join("ram.tar.gz"), other).unwrap();
    let refused = scan().expect_err("two plugins claim the key");
    assert!(
        refused.contains("plugin claim conflict")
            && refused.contains(&format!("'{name}'"))
            && refused.contains("ram.tar.gz"),
        "{refused}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn configured_store_with_untrusted_plugin_fails_boot_with_naming_error() {
    let dir = tmp_plugin_dir("untrusted-store");
    let tarball = unsigned_tarball(
        plugin_manifest("busbar-store-held", "held", "busbar"),
        b"unsigned lib bytes",
    );
    std::fs::write(dir.join("held.tar.gz"), tarball).unwrap();

    let err = preflight(Some(&gov_with_store("held")), &plugins_cfg(&dir, true)).unwrap_err();
    assert!(
        err.contains("busbar-store-held") || err.contains("'held'"),
        "names the plugin: {err}"
    );
    assert!(
        err.contains("allow_unsigned"),
        "carries the exact opt-in flag to set: {err}"
    );

    let mut cfg = plugins_cfg(&dir, true);
    cfg.trust.allow_unsigned = true;
    let reg = preflight(Some(&gov_with_store("held")), &cfg)
        .expect("allow_unsigned permits the unsigned store plugin at boot");
    assert!(reg.resolve("held").is_some(), "alias resolves");
    assert!(
        reg.resolve("busbar-store-held").is_some(),
        "canonical name resolves"
    );
    let reg2 = preflight(Some(&gov_with_store("busbar-store-held")), &cfg)
        .expect("the canonical name is equally valid as governance.store");
    assert!(reg2.resolve("busbar-store-held").is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invalid_manifest_in_enabled_dir_fails_boot() {
    let dir = tmp_plugin_dir("invalid-any");
    std::fs::write(dir.join("junk.tar.gz"), b"not a tarball at all").unwrap();
    let err = preflight(None, &plugins_cfg(&dir, true)).unwrap_err();
    assert!(err.contains("junk.tar.gz"), "names the file: {err}");
    assert!(err.contains("plugin validation failed"), "got {err}");

    std::fs::remove_file(dir.join("junk.tar.gz")).unwrap();
    let mut m = plugin_manifest("acme-store-x", "x", "acme");
    m.sha256 = busbar_plugin_loader::sign::sha256_hex(b"OTHER bytes");
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", b"real bytes").unwrap();
    std::fs::write(dir.join("sha.tar.gz"), tarball).unwrap();
    let err = preflight(None, &plugins_cfg(&dir, true)).unwrap_err();
    assert!(err.contains("integrity"), "names the sha mismatch: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn alias_conflict_fails_boot_naming_both() {
    let dir = tmp_plugin_dir("conflict");
    let mut cfg = plugins_cfg(&dir, true);
    cfg.trust.allow_unsigned = true;
    let a = unsigned_tarball(
        plugin_manifest("busbar-store-kv-plugin", "kv", "busbar"),
        b"a",
    );
    let b = unsigned_tarball(plugin_manifest("acme-store-kv", "kv", "acme"), b"b");
    std::fs::write(dir.join("a.tar.gz"), a).unwrap();
    std::fs::write(dir.join("b.tar.gz"), b).unwrap();
    let err = preflight(None, &cfg).unwrap_err();
    assert!(
        err.contains("busbar-store-kv-plugin") && err.contains("acme-store-kv"),
        "names both plugins: {err}"
    );
    assert!(err.contains("alias conflict"), "got {err}");
    let _ = std::fs::remove_dir_all(&dir);
}
