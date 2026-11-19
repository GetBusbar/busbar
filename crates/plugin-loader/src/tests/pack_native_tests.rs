// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn assertions() -> Manifest {
    Manifest {
        name: "native-pack-fixture".into(),
        alias: "native".into(),
        kind: "secret".into(),
        publisher: crate::test_host::TEST_PUBLISHER.into(),
        ..Manifest::default()
    }
}

fn fixture() -> Vec<u8> {
    read_image(&crate::both_ways::example_cdylib("native_pack_fixture")).unwrap()
}

#[test]
fn the_real_native_image_supplies_signed_metadata_and_closes_on_the_worker() {
    let bytes = fixture();
    let before = crate::UNLOADS_ON_WORKER.with(std::cell::Cell::get);
    let manifest = complete(&bytes, assertions(), None).expect("the native fixture packs");
    assert_eq!(
        crate::UNLOADS_ON_WORKER.with(std::cell::Cell::get),
        before + 1
    );
    assert_eq!(manifest.former_names, ["old-native", "native"]);
    assert_eq!(manifest.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest.abi_version, busbar_plugin_abi::versions::SECRET);
    assert!(manifest.statement.is_none());
    let signed = crate::test_host::test_sign(manifest, &bytes);
    let archive = crate::tarball::package(&signed, "native.so", &bytes).unwrap();
    let unpacked = crate::tarball::unpack(&archive).unwrap();
    assert_eq!(unpacked.manifest, signed);
    assert_eq!(unpacked.lib_bytes, bytes);
    crate::sign::evaluate(
        &unpacked.lib_bytes,
        &unpacked.manifest,
        &crate::test_host::test_trust("native-pack-fixture"),
    )
    .unwrap();
    #[cfg(target_os = "linux")]
    {
        let admitted = crate::admit::admit_bytes(
            &unpacked.lib_bytes,
            &unpacked.manifest,
            &crate::test_host::test_trust("native-pack-fixture"),
        )
        .unwrap();
        assert_eq!(admitted.identity(), "native-pack-fixture");
    }
    let mut forged = signed.clone();
    forged.former_names.reverse();
    assert!(crate::sign::evaluate(
        &bytes,
        &forged,
        &crate::test_host::test_trust("native-pack-fixture")
    )
    .is_err());
    #[cfg(target_os = "linux")]
    {
        let signed_wrong_order = crate::test_host::test_sign(forged, &bytes);
        let refused = crate::admit::admit_bytes(
            &bytes,
            &signed_wrong_order,
            &crate::test_host::test_trust("native-pack-fixture"),
        )
        .unwrap_err();
        assert_eq!(refused.code, crate::refusal::RefusalCode::DoorStampMismatch);
    }
    assert!(crate::sign::evaluate(
        &bytes,
        &signed,
        &crate::test_host::test_trust("different-scope")
    )
    .is_err());
}

#[test]
fn native_identity_assertions_refuse_before_loading_and_alias_errors_close() {
    let bytes = fixture();
    for field in ["name", "kind", "version", "abi"] {
        let before = crate::stage::STAGED_HERE.with(std::cell::Cell::get);
        let mut m = assertions();
        match field {
            "name" => m.name = "wrong".into(),
            "kind" => m.kind = "plane".into(),
            "version" => m.version = "99.0.0".into(),
            "abi" => {}
            _ => unreachable!(),
        }
        assert!(
            complete(&bytes, m, (field == "abi").then_some(999)).is_err(),
            "{field}"
        );
        assert_eq!(crate::stage::STAGED_HERE.with(std::cell::Cell::get), before);
    }
    for words in [vec!["native"], vec!["wrong"], vec!["old-native", "extra"]] {
        let before = crate::UNLOADS_ON_WORKER.with(std::cell::Cell::get);
        let mut m = assertions();
        m.former_names = words.iter().map(|word| (*word).to_owned()).collect();
        assert!(complete(&bytes, m, None).is_err());
        assert_eq!(
            crate::UNLOADS_ON_WORKER.with(std::cell::Cell::get),
            before + 1
        );
    }
    let mut m = assertions();
    m.former_names = vec!["old-native".into()];
    assert_eq!(
        complete(&bytes, m, None).unwrap().former_names,
        ["old-native", "native"]
    );
}

#[test]
fn incompatible_native_stamps_never_reach_staging_or_an_initializer() {
    use busbar_plugin_abi::stamp::{emit, Spec};
    let good = emit(&Spec {
        kind: busbar_plugin_abi::types::KindCode::Secret,
        kind_abi: busbar_plugin_abi::versions::SECRET,
        kind_minor: busbar_plugin_abi::versions::SECRET_MINOR,
        layout: busbar_plugin_abi::secret::FP,
        out_of_process: false,
        engine_min: None,
        engine_max: None,
        name: "native-pack-fixture",
        version: "1.6.0",
        build_id: None,
        crypto: "host",
    })
    .0;
    // Format 3 returned byte 64 (format 2's duplicate semantic word) to reserve: setting it is no
    // longer an incompatible stamp but a malformed one, refused by the scan itself.
    let mut reserved = good;
    reserved[64] ^= 1;
    assert!(matches!(
        crate::scan::stamp(&reserved),
        Err(crate::scan::StampScanErr::Malformed { byte: 64, .. })
    ));
    let before = crate::stage::STAGED_HERE.with(std::cell::Cell::get);
    assert!(complete(&reserved, assertions(), None).is_err(), "offset 64");
    assert_eq!(crate::stage::STAGED_HERE.with(std::cell::Cell::get), before);
    for at in [28usize, 32, 40, 48, 56, 72, 184, 248, 36] {
        let mut bytes = good;
        match at {
            28 | 32 => bytes[at..at + 4].copy_from_slice(&999u32.to_le_bytes()),
            36 => bytes[at..at + 4].copy_from_slice(&9u32.to_le_bytes()),
            72 => {
                bytes[72..74].copy_from_slice(&99u16.to_le_bytes());
                bytes[80..82].copy_from_slice(&99u16.to_le_bytes());
            }
            184 => {
                bytes[184..216].fill(0);
                bytes[184..191].copy_from_slice(b"foreign");
            }
            248 => {
                bytes[248..256].fill(0);
                bytes[248..251].copy_from_slice(b"bad");
            }
            _ => bytes[at] ^= 1,
        }
        crate::scan::stamp(&bytes).expect("negative control is syntactically a valid stamp");
        let before = crate::stage::STAGED_HERE.with(std::cell::Cell::get);
        assert!(complete(&bytes, assertions(), None).is_err(), "offset {at}");
        assert_eq!(crate::stage::STAGED_HERE.with(std::cell::Cell::get), before);
    }
}
