// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::sign::{Manifest, SigningKey, TrustPolicy};

fn plane_manifest(name: &str, alias: &str, publisher: &str) -> Manifest {
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "plane".into(),
        version: "1.6.0".into(),
        publisher: publisher.into(),
        abi_version: busbar_plugin_abi::versions::PLANE,
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
        allow_untrusted: false,
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
fn plane_supported_abi_is_the_plane_kinds_one_version() {
    assert_eq!(
        crate::registry::supported_abi("plane"),
        Some(busbar_plugin_abi::versions::PLANE)
    );
    assert!(crate::registry::supported_abi("store").is_some());
    assert_eq!(crate::registry::supported_abi("nonsense"), None);
}

/// A MIN-3 plane image's bytes: its one stamp names kind PLANE (IF §7.4), with other bytes around it.
fn min3_plane_lib() -> Vec<u8> {
    use busbar_plugin_abi::stamp::{emit, Spec};
    use busbar_plugin_abi::types::KindCode;
    let stamp = emit(&Spec {
        kind: KindCode::Plane,
        kind_abi: 1,
        layout: busbar_plugin_abi::plane::FP,
        out_of_process: false,
        engine_min: None,
        engine_max: None,
        name: "busbar-plane-delta",
        version: "1.6.0",
        build_id: None,
        crypto: "host",
    })
    .0;
    let mut lib = b"\x7fELF min3 plane ".to_vec();
    lib.extend_from_slice(&stamp);
    lib.extend_from_slice(b" tail");
    lib
}
