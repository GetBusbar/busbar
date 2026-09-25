// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE BOTH-WAYS HARNESS FOR THE COLD KINDS** (DECISIONS #2 rule (1): a plugin is compiled in OR
//! dropped in — same contract, same loading path).
//!
//! One in-tree SDK plugin is registered TWICE: LINKED (its `rlib`'s `BUSBAR_COLD_ENTRY`, through
//! [`PluginRegistry::link`]) and DROPPED IN (its `cdylib`, signed first-party into a fresh
//! `plugins/` directory and found by [`crate::scan_and_validate`]). Each kind's conformance test then
//! asks both registries for the row the plugin's name resolves to and opens it through the kind's
//! own `open_*`, runs one script against each opened instance, and requires the two rows and the two
//! transcripts to be byte-identical.
//!
//! Each kind's fixture comes from the table `build.rs` generates out of `Cargo.toml`'s
//! `[package.metadata.busbar.both-ways]` ([`fixture`]): the tests reach a fixture by its KIND, and no
//! test source names a plugin instance.
//!
//! What is compared is the plugin's STATEMENT (its manifest, every field but the two that describe
//! a tarball — `sha256` and `signature`) and its BEHAVIOUR. What is not compared is provenance —
//! the tarball's `file` and the trust `verdict` — which belongs to the door, exactly as the export
//! conformance test leaves out the host-assigned display name.

use crate::sign::{sign, Manifest, SigningKey, TrustPolicy};
use crate::{LinkedPlugin, PluginRegistry};
use busbar_plugin::cold::ColdEntry;
use std::path::PathBuf;

include!(concat!(env!("OUT_DIR"), "/both_ways.rs"));

/// The both-ways fixture of `kind`: its `cdylib`'s crate name and its linked entry.
pub(crate) fn fixture(kind: &str) -> (&'static str, &'static ColdEntry) {
    FIXTURES
        .iter()
        .find(|(k, ..)| *k == kind)
        .map(|&(_, krate, entry)| (krate, entry))
        .unwrap_or_else(|| {
            panic!("no `{kind}` row in Cargo.toml's [package.metadata.busbar.both-ways]")
        })
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
    }
}

/// The in-tree `cdylib` of `crate_snake` in this target dir (uplifted or under `deps`, newest wins).
/// Under CI a missing artifact is a failure, never a skip: this is a both-ways proof.
pub(crate) fn cdylib(crate_snake: &str) -> Option<PathBuf> {
    let found = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile = exe.parent()?.parent()?;
        let name = crate::plugin_library_filename(crate_snake);
        [profile.join(&name), profile.join("deps").join(&name)]
            .into_iter()
            .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
            .max()
            .map(|(_, p)| p)
    })();
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the {crate_snake} cdylib is not built under CI; a both-ways proof must not skip"
    );
    found
}

/// THE LINKED DOOR: `manifest` and `entry` registered through [`PluginRegistry::link`].
pub(crate) fn linked(manifest: Manifest, entry: &'static ColdEntry) -> PluginRegistry {
    PluginRegistry::empty()
        .link(vec![LinkedPlugin::boundary(manifest, entry)])
        .expect("the linked door admits the plugin")
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

/// Both doors for the fixture of `manifest.kind`: `(row, transcript)` for the LINKED registration,
/// then for the DROPPED one — each registry's row for `manifest.name`, and `script` run over what
/// `open` makes of it. `None` when the `cdylib` is not built in this (scoped, non-CI) run.
pub(crate) fn both_doors<T>(
    manifest: Manifest,
    open: impl Fn(&PluginRegistry) -> T,
    script: impl Fn(&T) -> String,
) -> Option<[(String, String); 2]> {
    let (crate_snake, entry) = fixture(&manifest.kind);
    let lib = std::fs::read(cdylib(crate_snake)?).expect("read the cdylib");
    let name = manifest.name.clone();
    let doors = [
        linked(manifest.clone(), entry),
        dropped(crate_snake, manifest, &lib),
    ];
    Some(doors.map(|registry| (row(&registry, &name), script(&open(&registry)))))
}
