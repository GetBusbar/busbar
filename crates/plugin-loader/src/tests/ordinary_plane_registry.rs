// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::sign::{sign, Manifest, SigningKey, TrustPolicy};

fn plane_manifest(name: &str, alias: &str, publisher: &str) -> Manifest {
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "plane".into(),
        version: "1.6.0".into(),
        publisher: publisher.into(),
        abi_version: busbar_contract::abi::plane::ABI_VERSION,
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

fn first_party_only_policy(release: &SigningKey) -> TrustPolicy {
    TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: "1.6.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
        ..TrustPolicy::default()
    }
}

fn plane_tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-plane-trust-{}-{tag}-{}",
        std::process::id(),
        crate::stage::next_seq()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_plane_tarball(dir: &std::path::Path, file: &str, m: &Manifest, lib: &[u8]) {
    let bytes = crate::tarball::package(m, "libplane.so", lib).unwrap();
    std::fs::write(dir.join(file), bytes).unwrap();
}

#[test]
fn a_plane_with_no_door_is_refused() {
    let release = SigningKey::from_bytes(&[1u8; 32]);
    let dir = plane_tmpdir("no-door");
    let m = sign(
        &release,
        plane_manifest("busbar-plane-gamma-plugin", "gamma", "busbar"),
        b"plane lib",
    );
    write_plane_tarball(&dir, "plane.tar.gz", &m, b"plane lib");

    let reg =
        crate::registry::scan_and_validate(&dir, &first_party_only_policy(&release)).expect("scan");
    let err = reg
        .open_planes(&[])
        .map(|_| ())
        .expect_err("a plane with no door is refused");
    assert!(
        err.contains("busbar-plane-gamma-plugin") && err.contains("busbar_plugin_door"),
        "the refusal names the plane and the door it lacks: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plane_supported_abi_is_the_plane_kinds_one_version() {
    let range = crate::registry::supported_abi("plane");
    assert_eq!(range, &[busbar_contract::abi::plane::ABI_VERSION]);

    assert!(!crate::registry::supported_abi("store").is_empty());
    assert!(crate::registry::supported_abi("nonsense").is_empty());
}
