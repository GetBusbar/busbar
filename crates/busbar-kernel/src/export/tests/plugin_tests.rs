// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the export axis (`export/plugin.rs`). The kernel names no export plugin, so the axis
//! here is a plugin registry scanned out of a temp `plugins/` directory holding NEUTRAL `kind:
//! export` rows whose library bytes are not a library — enough for every question the kernel asks
//! of the axis (does this module resolve, is it an export) and for the open to fail the way a
//! broken plugin fails. The dropped-in plugin that actually SERVES is driven end to end by the
//! composition root (`crates/busbar/tests/export_plugin_dropped_in_serves.rs`).

use super::*;
use crate::config::{resolve_export, ExportDefCfg, ExportDefs};

/// A structurally valid, unsigned `kind: export` tarball named `name`/`alias` over `lib`.
fn write_row(dir: &std::path::Path, name: &str, alias: &str, lib: &[u8]) {
    let m = busbar_plugin_loader::sign::Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "export".into(),
        version: "1.6.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("export")
            .iter()
            .max()
            .expect("an export payload schema"),
        sha256: busbar_plugin_loader::sign::sha256_hex(lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
    };
    let bytes = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).expect("package");
    std::fs::write(dir.join(format!("{name}.tar.gz")), bytes).expect("write the tarball");
}

/// A registry scanned from a fresh directory holding one export row per `(name, alias)`.
fn registry_of(tag: &str, rows: &[(&str, &str)]) -> &'static PluginRegistry {
    let dir = std::env::temp_dir().join(format!("busbar-export-axis-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("plugins dir");
    for (name, alias) in rows {
        write_row(&dir, name, alias, b"not a library");
    }
    let plugins: crate::config::PluginsCfg = serde_json::from_value(serde_json::json!({
        "enabled": true,
        "dir": dir.display().to_string(),
        "trust": { "allow_unsigned": true },
    }))
    .expect("a plugins block");
    let policy = plugins.to_policy().expect("a trust policy");
    let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the scan");
    Box::leak(Box::new(registry))
}

/// The axis this test binary installs — once, as the composition root does.
fn installed_axis() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        install(registry_of("installed", &[("k9-axis-sink", "k9-tail")]));
    });
}

fn def(module: &str) -> ExportDefCfg {
    serde_json::from_value(serde_json::json!({ "module": module })).expect("a minimal definition")
}

/// THE CONTROL OF ITEM 141 at the config layer: a `module:` naming a `kind: export` row on the axis
/// — by its name or its alias — RESOLVES to an instance the boot will open, and one naming nothing
/// on the axis is refused in exactly 1.5.5's words, so a config without plugins reads as it always did.
#[test]
fn a_module_on_the_axis_resolves_and_an_unregistered_one_is_refused_as_before() {
    installed_axis();
    for module in ["k9-axis-sink", "k9-tail"] {
        let mut defs = ExportDefs::new();
        defs.insert("audit-tail".to_string(), def(module));
        let mut errors = Vec::new();
        let cfg = resolve_export(&defs, &mut errors);
        assert!(errors.is_empty(), "{module}: {errors:?}");
        assert_eq!(cfg.plugins.len(), 1, "{module}");
        assert_eq!(cfg.plugins[0].name, "audit-tail");
        // The sink's streams are not known until it is opened, so the compute gate provisionally
        // wants what this release produces — `logs` among them — rather than nothing.
        assert!(cfg.projection_union().wants_stream(ExportStream::Logs));
    }

    let mut defs = ExportDefs::new();
    defs.insert("audit-tail".to_string(), def("k9-never-registered"));
    let mut errors = Vec::new();
    let cfg = resolve_export(&defs, &mut errors);
    assert!(cfg.plugins.is_empty());
    assert_eq!(
        errors,
        vec![
            "export.audit-tail.module: unknown exporter 'k9-never-registered'; the built-in export \
             modules are prometheus | request-log-webhook | request-log-file | otlp"
                .to_string()
        ]
    );
}

/// A sink that will not open refuses the boot, naming the instance and carrying the loader's reason
/// — a configured sink is never silently absent.
#[test]
fn a_sink_that_will_not_open_refuses_naming_the_instance() {
    installed_axis();
    let mut defs = ExportDefs::new();
    defs.insert("tail".to_string(), def("k9-axis-sink"));
    let mut errors = Vec::new();
    let cfg = resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    let refusal = open(&cfg).expect_err("bytes that are not a library do not open");
    assert!(refusal.starts_with("export.tail: "), "{refusal}");
}
