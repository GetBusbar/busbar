// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT AXIS a test binary resolves `export:` against. The kernel names no export plugin, so
//! the axis here is a plugin registry scanned out of a temp `plugins/` directory holding NEUTRAL
//! `kind: export` rows whose library bytes are not a library.

use busbar_plugin_loader::{
    dispatch::{DispatchConfig, Dispatcher},
    export_axis::ExportRows,
    PluginRegistry,
};

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
        ..Default::default()
    };
    let bytes = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).expect("package");
    std::fs::write(dir.join(format!("{name}.tar.gz")), bytes).expect("write the tarball");
}

/// A registry scanned from a fresh directory holding one export row per `(name, alias)`.
pub fn registry_of(tag: &str, rows: &[(&str, &str)]) -> PluginRegistry {
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
    let policy = crate::test_support::trust_policy(&plugins).expect("a trust policy");
    busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the scan")
}

/// The registry the stand-in axis reads, kept for the test binary's life. Unset = no export module
/// resolves (a test binary that installs none).
static REGISTRY: std::sync::OnceLock<&'static PluginRegistry> = std::sync::OnceLock::new();

/// The registry [`install_export_axis_with`] builds, owned for the test binary's life.
static BUILT: std::sync::OnceLock<PluginRegistry> = std::sync::OnceLock::new();

/// THE STAND-IN EXPORT AXIS: `preflight::RootInstall`'s `export_axis` in a test build (a test build
/// has no root). It answers over the registry installed here, on one test dispatcher, through the
/// export rows the root's axis answers with.
#[derive(Debug)]
pub struct StandIn;

/// The stand-in axis `preflight::RootInstall` holds in a test build.
pub static STAND_IN: StandIn = StandIn;

fn rows() -> Option<ExportRows<'static>> {
    static DISPATCHER: std::sync::OnceLock<std::sync::Arc<Dispatcher>> = std::sync::OnceLock::new();
    let registry = REGISTRY.get()?;
    let dispatcher =
        DISPATCHER.get_or_init(|| std::sync::Arc::new(Dispatcher::new(DispatchConfig::default())));
    Some(ExportRows::new(registry, dispatcher.clone()))
}

impl busbar_contract::export_calls::ExportAxis for StandIn {
    fn probe(
        &self,
        module: &str,
        instance: &str,
        settings: &serde_json::Value,
    ) -> Option<busbar_contract::export_calls::Probed> {
        rows()?.probe(module, instance, settings)
    }

    fn check(
        &self,
        module: &str,
        phase: u32,
        instances: &[(String, serde_json::Value)],
    ) -> Option<Vec<String>> {
        rows()?.check(module, phase, instances)
    }

    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<std::sync::Arc<dyn busbar_contract::export_calls::ExportCalls>, String> {
        let rows =
            rows().ok_or_else(|| format!("no `kind: export` plugin answers to '{module}'"))?;
        rows.open(module, label, settings)
    }

    fn linked(&self, module: &str) -> bool {
        rows().is_some_and(|r| r.linked(module))
    }

    fn first_party(&self, module: &str) -> bool {
        rows().is_some_and(|r| r.first_party(module))
    }
}

/// The axis every test in this binary resolves `export:` against — installed once, as the
/// composition root does. Besides a neutral row (`k9-axis-sink`, alias `k9-tail`) it holds a row
/// spelling each FIRST-PARTY sink's frozen module name (`request-log-file`, K9b;
/// `request-log-webhook`, K9c; `otlp`, K9e-2): a linked build resolves that module on its axis, so a
/// test configuration naming it resolves here too. The rows' bytes are not a library, so each sink
/// validates nothing and opens nothing — enough for the configuration layer, which is all a kernel
/// test drives.
pub fn install_export_axis() {
    install_export_axis_with(Vec::new());
}

/// [`install_export_axis`], with `linked` registered ahead of the neutral rows through the linked
/// door — for a test binary that links a sink of its own. The first install holds.
pub fn install_export_axis_with(linked: Vec<busbar_plugin_loader::LinkedPlugin>) {
    let built = BUILT.get_or_init(|| {
        let rows = [
            ("k9-axis-sink", "k9-tail"),
            ("k9b-log-file", "request-log-file"),
            ("k9c-webhook", "request-log-webhook"),
            ("k9e-otlp", crate::config::EXPORT_MODULE_OTLP),
        ];
        let scanned = registry_of("installed", &rows);
        scanned
            .link(linked)
            .expect("the linked door admits the rows")
    });
    let _ = REGISTRY.set(built);
}

/// A FIRST-PARTY memory-ABI sink linked as the composition root links it, by its `door` (its logic
/// crate's `plugin_door!`), under `name`/`alias` — for a test binary whose axis must know that sink.
pub fn install_first_party_door(
    name: &str,
    alias: &str,
    door: busbar_contract::abi::mechanism::door::DoorFn,
) {
    install_export_axis_with(vec![busbar_plugin_loader::LinkedPlugin::first_party_door(
        "export", name, alias, door,
    )]);
}
