// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::sign::Manifest;
use std::path::PathBuf;

pub(crate) const BUILD_EXAMPLES: &str = "cargo build -p busbar-plugin-loader --examples";

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

const FIXTURE_ROOT_SEED: u8 = 81;

/// A first-party plugin as busbar ships it (#300/#357): a release seal whose keys document the
/// fixture root signs and whose targets document the plugins signer signs, naming the canonical
/// manifest. Returns the sealed manifest and the embedded root that verifies it.
pub(crate) fn sealed_first_party(
    mut manifest: Manifest,
    lib: &[u8],
) -> (Manifest, Vec<crate::sign::FirstPartyKey>) {
    use crate::release_trust::tests::{
        entry, keys_doc, seal_keys, seal_targets, targets_doc, TestSigner,
    };
    use crate::release_trust::{wire, PLUGIN_TARGET};
    let root = TestSigner::ed25519(FIXTURE_ROOT_SEED);
    let signer = TestSigner::ed25519(82);
    manifest.sha256 = crate::sign::sha256_hex(lib);
    manifest.signature = String::new();
    let canonical = crate::sign::canonical_manifest_bytes(&manifest);
    let mut target = entry(
        &manifest.name,
        &manifest.version,
        PLUGIN_TARGET,
        &crate::sign::sha256_hex(&canonical),
    );
    target.length = canonical.len() as u64;
    let keys = seal_keys(&keys_doc(&[&signer]), &[&root]);
    let targets = seal_targets(&targets_doc(vec![target]), &[&signer]);
    manifest.signature = wire::write_seal(&keys, &targets).expect("the release seal writes");
    (manifest, vec![root.root("fixture-root")])
}
