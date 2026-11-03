// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::sign::{sign, Manifest, SigningKey, TrustPolicy};
use crate::PluginRegistry;
use std::path::PathBuf;

// The deleted fixture-crate generator is intentionally not reconstructed. Only
// actual product rows belong here; callers of retired fixture rows must migrate
// to their owning product's ordinary tests rather than silently selecting a fake.
pub(crate) fn door_fixture(
    row: &str,
) -> (&'static str, busbar_contract::abi::mechanism::door::DoorFn) {
    match row {
        "mcp" => ("busbar_plane_mcp", crate::actual_mcp::door),
        _ => panic!("retired both-ways fixture row `{row}` has no actual product binding; migrate the caller to its owning product"),
    }
}

pub(crate) fn statement(kind: &str, name: &str, alias: &str, abi_version: u32) -> Manifest {
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: kind.into(),
        version: "1.6.0".into(),
        publisher: "busbar".into(),
        abi_version,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
        statement: None,
        former_names: Vec::new(),
    }
}

pub(crate) const BUILD_EXAMPLES: &str = "cargo build -p busbar-plugin-loader --examples";

pub(crate) const BUILD_DEPS: &str = "cargo test -p busbar-plugin-loader --no-run";

pub(crate) fn missing(name: &str, command: &str) -> ! {
    panic!("the {name} cdylib is not built: run `{command}` first (a both-ways proof never skips)")
}

pub(crate) fn example_cdylib(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary's path");
    let path = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("the test binary sits in <profile>/deps")
        .join("examples")
        .join(crate::plugin_library_filename(name));
    if !path.exists() {
        missing(name, BUILD_EXAMPLES);
    }
    path
}

pub(crate) fn cdylib(crate_snake: &str) -> PathBuf {
    let found = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile = exe.parent()?.parent()?;
        let name = crate::plugin_library_filename(crate_snake);
        let (prefix, suffix) = name.split_once(crate_snake)?;
        let is_lib = |f: &str| {
            f.strip_prefix(prefix)
                .and_then(|f| f.strip_suffix(suffix))
                .and_then(|f| f.strip_prefix(crate_snake))
                .is_some_and(|stem| {
                    stem.is_empty()
                        || stem.strip_prefix('-').is_some_and(|h| {
                            !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                })
        };
        let in_deps = std::fs::read_dir(profile.join("deps"))
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.file_name().and_then(|f| f.to_str()).is_some_and(is_lib));
        std::iter::once(profile.join(&name))
            .chain(in_deps)
            .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
            .max()
            .map(|(_, p)| p)
    })();
    found.unwrap_or_else(|| missing(crate_snake, BUILD_DEPS))
}

pub(crate) fn dropped(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    dropped_signed(tag, manifest, lib, &SigningKey::from_bytes(&[11u8; 32]))
}

pub(crate) fn dropped_third_party(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    dropped_signed(tag, manifest, lib, &SigningKey::from_bytes(&[22u8; 32]))
}

fn dropped_signed(
    tag: &str,
    manifest: Manifest,
    lib: &[u8],
    signer: &SigningKey,
) -> PluginRegistry {
    static CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "busbar-both-ways-{tag}-{}-{call}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the plugins dir");
    let release = SigningKey::from_bytes(&[11u8; 32]);
    let publisher = (manifest.publisher.clone(), signer.verifying_key());
    let signed = sign(signer, manifest, lib);
    let tarball = crate::tarball::package(&signed, "libplugin.so", lib).expect("package");
    std::fs::write(dir.join(format!("{tag}.tar.gz")), tarball).expect("write the tarball");
    let policy = TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: "1.6.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: std::iter::once(publisher)
            .filter(|(_, key)| *key != release.verifying_key())
            .collect(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
        ..TrustPolicy::default()
    };
    let registry = crate::scan_and_validate(&dir, &policy)
        .unwrap_or_else(|e| panic!("the signed plugin scans: {e:?}"));
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

pub(crate) fn row(registry: &PluginRegistry, name: &str) -> String {
    let Some(p) = registry.resolve(name) else {
        return format!("no row for '{name}'");
    };
    let by_alias = registry
        .resolve(&p.manifest.alias)
        .map(|a| a.manifest.name.clone());
    let stated = Manifest {
        sha256: String::new(),
        signature: String::new(),
        ..p.manifest.clone()
    };
    serde_json::json!({ "manifest": stated, "alias_resolves_to": by_alias }).to_string()
}
