// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT AXIS a test binary resolves `export:` against. The kernel names no export plugin, so
//! the axis here is a plugin registry scanned out of a temp `plugins/` directory holding NEUTRAL
//! `kind: export` rows whose library bytes are not a library.

use busbar_plugin_loader::PluginRegistry;

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
        declares: Default::default(),
    };
    let bytes = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).expect("package");
    std::fs::write(dir.join(format!("{name}.tar.gz")), bytes).expect("write the tarball");
}

/// A registry scanned from a fresh directory holding one export row per `(name, alias)`.
pub fn registry_of(tag: &str, rows: &[(&str, &str)]) -> &'static PluginRegistry {
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

/// The axis every test in this binary resolves `export:` against — installed once, as the
/// composition root does. Besides a neutral row (`k9-axis-sink`, alias `k9-tail`) it holds a row
/// spelling each FIRST-PARTY sink's frozen module name (`request-log-file`, K9b;
/// `request-log-webhook`, K9c): a linked build
/// resolves that module on its axis, so a test configuration naming it resolves here too. The rows'
/// bytes are not a library, so each sink validates nothing and opens nothing — enough for the
/// configuration layer, which is all a kernel test drives.
pub fn install_export_axis() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        crate::export::plugin::install(registry_of(
            "installed",
            &[
                ("k9-axis-sink", "k9-tail"),
                ("k9b-log-file", "request-log-file"),
                ("k9c-webhook", "request-log-webhook"),
            ],
        ));
    });
}
