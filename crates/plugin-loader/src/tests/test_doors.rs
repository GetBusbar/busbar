// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DROPPED-IN DOOR THE LOADER'S OWN TESTS DRIVE: a library signed first-party into a fresh
//! `plugins/` directory and found by [`crate::scan_and_validate`] ([`dropped`]), and the manifest
//! such a test states ([`statement`]).
//!
//! OWNER 2026-10-03 (NO TEST PLUGINS): the cold kinds' both-ways table (`build.rs` over
//! `[package.metadata.busbar.both-ways]`) and the harness that compared a plugin's two doors are
//! gone. A plugin proves itself against the published suite (this crate's `conformance` feature) in
//! its own repo; what stays here is the loader's own path, with no plugin as the subject.

use crate::sign::{sign, Manifest, SigningKey, TrustPolicy};
use crate::PluginRegistry;

/// The manifest a test states for a plugin: a first-party `name`/`alias` of `kind` at payload
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
    }
}

/// THE DROPPED-IN DOOR: `lib` signed first-party under `manifest` with the release key into a fresh
/// `plugins/` directory, and that directory scanned under the default posture that holds the key.
pub(crate) fn dropped(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    // One directory per call: two tests of one plugin run in parallel in this binary.
    static CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "busbar-dropped-{tag}-{}-{call}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the plugins dir");
    let release = SigningKey::from_bytes(&[11u8; 32]);
    let signed = sign(&release, manifest, lib);
    let tarball = crate::tarball::package(&signed, "libplugin.so", lib).expect("package");
    std::fs::write(dir.join(format!("{tag}.tar.gz")), tarball).expect("write the tarball");
    let policy = TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: "1.6.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    let registry = crate::scan_and_validate(&dir, &policy)
        .unwrap_or_else(|e| panic!("the signed plugin scans: {e:?}"));
    let _ = std::fs::remove_dir_all(&dir);
    registry
}
