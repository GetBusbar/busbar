// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::sign::{sign, Manifest, SigningKey, TrustPolicy};
use crate::PluginRegistry;
use std::path::PathBuf;

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

/// The embedded release root that verifies [`sealed_first_party`]'s seals.
pub(crate) fn first_party_roots() -> Vec<crate::sign::FirstPartyKey> {
    vec![crate::release_trust::tests::TestSigner::ed25519(FIXTURE_ROOT_SEED).root("fixture-root")]
}

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
    let publisher = (
        manifest.publisher.clone(),
        crate::sign::PublisherTrust {
            plugins: [manifest.name.clone()].into_iter().collect(),
            keys: vec![crate::sign::PublisherKey {
                key: signer.verifying_key(),
                revoked: false,
            }],
        },
    );
    let first_party = manifest.publisher == crate::sign::FIRST_PARTY_PUBLISHER;
    // Busbar's own artifacts carry a release seal (#300/#357): embedded roots sign keys documents,
    // never artifacts, so a first-party fixture is sealed as busbar ships it.
    let (signed, first_party_keys) = if first_party {
        sealed_first_party(manifest, lib)
    } else {
        (sign(signer, manifest, lib), Vec::new())
    };
    let tarball = crate::tarball::package(&signed, "libplugin.so", lib).expect("package");
    std::fs::write(dir.join(format!("{tag}.tar.gz")), tarball).expect("write the tarball");
    let policy = TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        first_party_keys,
        release_clock: Some(crate::release_trust::tests::NOW),
        binary_version: "1.6.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: std::iter::once(publisher)
            .filter(|_| !first_party)
            .collect(),
        allow_untrusted: false,
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
    busbar_contract::json::json!({ "manifest": stated, "alias_resolves_to": by_alias }).to_string()
}
