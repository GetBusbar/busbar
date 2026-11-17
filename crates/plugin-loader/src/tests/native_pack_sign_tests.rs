// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_plugin_abi::stamp::{emit, Spec};
use busbar_plugin_abi::types::KindCode;

fn artifact() -> Vec<u8> {
    emit(&Spec {
        kind: KindCode::Plane,
        kind_abi: busbar_plugin_abi::versions::PLANE,
        layout: busbar_plugin_abi::plane::FP,
        out_of_process: false,
        engine_min: None,
        engine_max: None,
        name: "native-pack-plane",
        version: "1.6.0",
        build_id: None,
        crypto: "host",
    })
    .0
    .to_vec()
}

fn manifest(bytes: &[u8]) -> Manifest {
    sign(
        &SigningKey::from_bytes(&[7; 32]),
        Manifest {
            name: "native-pack-plane".into(),
            alias: "native".into(),
            kind: "plane".into(),
            version: "1.6.0".into(),
            publisher: "example".into(),
            abi_version: busbar_plugin_abi::versions::PLANE,
            former_names: vec!["old-native".into(), "native".into()],
            ..Manifest::default()
        },
        bytes,
    )
}

fn validate(m: &Manifest, bytes: &[u8]) -> Result<(), String> {
    validate_structure(m, bytes, &crate::supported_abi, HOST_IDENTITY)
}

#[test]
fn native_signed_alias_list_is_complete_without_a_legacy_statement() {
    let bytes = artifact();
    let m = manifest(&bytes);
    assert!(m.statement.is_none());
    validate(&m, &bytes).expect("a native manifest signs its alias in the complete header list");
    assert!(
        validate_identity(&m, HOST_IDENTITY).is_err(),
        "legacy identity rules are unchanged"
    );
    let archive = crate::tarball::package(&m, "fixture.so", &bytes).unwrap();
    let unpacked = crate::tarball::unpack(&archive).unwrap();
    assert_eq!(unpacked.manifest, m);
    assert_eq!(unpacked.lib_bytes, bytes);
}

#[test]
fn native_manifest_identity_must_match_the_image_stamp() {
    let bytes = artifact();
    for field in ["name", "version", "kind", "abi"] {
        let mut m = manifest(&bytes);
        match field {
            "name" => m.name = "different-native".into(),
            "version" => m.version = "1.6.1".into(),
            "kind" => m.kind = "transport".into(),
            "abi" => m.abi_version += 1,
            _ => unreachable!(),
        }
        assert!(validate(&m, &bytes).is_err(), "{field}");
    }
}

#[test]
fn native_manifest_cannot_supply_legacy_operational_authority() {
    let bytes = artifact();
    for field in ["statement", "schema", "derived", "declares", "needs"] {
        let mut m = manifest(&bytes);
        match field {
            "statement" => m.statement = Some(String::new()),
            "schema" => m.settings_schema = Some("{}".into()),
            "derived" => m.schema_derived = true,
            "declares" => m.declares.disk = true,
            "needs" => m.needs.prompt = NeedLevel::Ro,
            _ => unreachable!(),
        }
        assert!(validate(&m, &bytes).is_err(), "{field}");
    }
}

#[test]
fn malformed_native_stamp_never_becomes_a_legacy_manifest() {
    let bytes = artifact();
    let mut malformed = bytes.clone();
    malformed[20..24].copy_from_slice(&0u32.to_le_bytes());
    let mut ambiguous = bytes.clone();
    ambiguous.extend_from_slice(&bytes);
    for image in [malformed, ambiguous, bytes[..100].to_vec()] {
        let mut m = manifest(&image);
        m.former_names.clear(); // valid legacy identity: must still refuse the native artifact.
        assert!(validate(&m, &image).is_err());
    }
}
