// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE BOTH-WAYS HARNESS** (DECISIONS #2 rule (1): a plugin is compiled in OR dropped in — same
//! contract, same loading path).
//!
//! One plugin is registered TWICE: LINKED (its door, through [`PluginRegistry::link`]) and DROPPED
//! IN (its `cdylib`, signed first-party into a fresh `plugins/` directory and found by
//! [`crate::scan_and_validate`]). Each kind's conformance test then asks both registries for the row
//! the plugin's name resolves to, opens it, runs one script against each opened instance, and
//! requires the two rows and the two transcripts to be byte-identical.
//!
//! Each kind's fixture comes from the tables `build.rs` generates out of `Cargo.toml`'s
//! `[package.metadata.busbar.both-ways]` ([`door_fixture`], [`hot_cdylib`]): the tests reach a
//! fixture by its KIND, and no test source names a plugin instance.
//!
//! What is compared is the plugin's STATEMENT (its manifest, every field but the two that describe
//! a tarball — `sha256` and `signature`) and its BEHAVIOUR. What is not compared is provenance —
//! the tarball's `file` and the trust `verdict` — which belongs to the door, exactly as the export
//! conformance test leaves out the host-assigned display name.

use crate::sign::{sign, Manifest, SigningKey, TrustPolicy};
use crate::PluginRegistry;
use std::path::PathBuf;

include!(concat!(env!("OUT_DIR"), "/both_ways.rs"));

/// The memory-ABI both-ways fixture of `row`: its `cdylib`'s crate name and its linked door.
pub(crate) fn door_fixture(
    row: &str,
) -> (&'static str, busbar_contract::abi::mechanism::door::DoorFn) {
    DOOR_FIXTURES
        .iter()
        .find(|(k, ..)| *k == row)
        .map(|&(_, krate, door)| (krate, door))
        .unwrap_or_else(|| {
            panic!("no `{row}` memory-ABI row in Cargo.toml's [package.metadata.busbar.both-ways]")
        })
}

/// The built `cdylib` of the HOT kind `kind`'s row, by the table's crate name.
pub(crate) fn hot_cdylib(kind: &str) -> PathBuf {
    let (_, krate) = HOT_FIXTURES
        .iter()
        .find(|(k, _)| *k == kind)
        .unwrap_or_else(|| panic!("no hot `{kind}` row in the both-ways table"));
    cdylib(krate)
}

/// The manifest both doors state for the plugin: a first-party `name`/`alias` of `kind` at payload
/// schema `abi_version`, with no artifact.
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

/// The command that builds every example `cdylib` of this crate.
pub(crate) const BUILD_EXAMPLES: &str = "cargo build -p busbar-plugin-loader --examples";

/// The command that builds every pinned plugin's `cdylib` under `deps/` (the dev-dependency edge).
pub(crate) const BUILD_DEPS: &str = "cargo test -p busbar-plugin-loader --no-run";

/// A both-ways proof whose `name` cdylib is absent: a hard failure naming the `command` that builds
/// it, in every run (BUSBAR-1.6.0.md: between a false RED and a false GREEN, a gate takes the RED).
pub(crate) fn missing(name: &str, command: &str) -> ! {
    panic!("the {name} cdylib is not built: run `{command}` first (a both-ways proof never skips)")
}

/// The example `cdylib` `name` in this target dir; absent, the test fails naming the command that
/// builds it — this is a both-ways proof, and it never skips.
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

/// The `cdylib` of `crate_snake` in this target dir, newest wins: uplifted, under `deps` by its
/// exact name, or under `deps` WITH a metadata hash (`lib<snake>-<hex>.<ext>`) — the only place a
/// fixture pulled from its own repo as a git dependency is ever built. Absent, the test fails
/// naming the command that builds it — this is a both-ways proof, and it never skips.
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

/// THE DROPPED-IN DOOR: `lib` signed first-party under `manifest` into a fresh `plugins/` directory,
/// and that directory scanned under the default posture that holds the release key.
pub(crate) fn dropped(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    dropped_signed(tag, manifest, lib, &SigningKey::from_bytes(&[11u8; 32]))
}

/// THE DROPPED-IN DOOR for a THIRD party: `manifest`'s publisher allowlisted under its own key,
/// which signs it — trusted, and not first-party. The RED arm of every grant a first-party plugin
/// earns (K9a).
pub(crate) fn dropped_third_party(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    dropped_signed(tag, manifest, lib, &SigningKey::from_bytes(&[22u8; 32]))
}

/// The dropped-in door with `signer` signing: the release key (`[11; 32]`) is the policy's
/// first-party key, and any other signer is allowlisted as the manifest's own publisher.
fn dropped_signed(
    tag: &str,
    manifest: Manifest,
    lib: &[u8],
    signer: &SigningKey,
) -> PluginRegistry {
    // One directory per call: two tests of one plugin run in parallel in this binary.
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
    };
    let registry = crate::scan_and_validate(&dir, &policy)
        .unwrap_or_else(|e| panic!("the signed plugin scans: {e:?}"));
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

/// THE ROW `registry` resolves `name` to, as JSON: the plugin's statement (its manifest without the
/// artifact's `sha256`/`signature`), and the row its ALIAS resolves to, which must be the same one.
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
