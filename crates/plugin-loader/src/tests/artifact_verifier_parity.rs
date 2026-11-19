// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_artifact_verifier as isolated;
use busbar_contract::json::{self, JsonValueTrait};
use isolated::verification::{
    Authority, Operation, Phase, Unavailable, VerificationError, Verifier,
};
use std::cell::Cell;

fn image() -> Vec<u8> {
    std::fs::read(crate::both_ways::example_cdylib("native_pack_fixture")).unwrap()
}

fn signed(image: &[u8]) -> (crate::sign::Manifest, crate::sign::TrustPolicy) {
    let key = crate::sign::SigningKey::from_bytes(&[71; 32]);
    let manifest = crate::sign::seal_test_artifact(
        &key,
        crate::sign::Manifest {
            name: "native-pack-fixture".into(),
            alias: "native".into(),
            former_names: vec!["old-native".into(), "native".into()],
            kind: "secret".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            publisher: crate::sign::FIRST_PARTY_PUBLISHER.into(),
            abi_version: busbar_plugin_abi::versions::SECRET,
            ..Default::default()
        },
        image,
    );
    let policy = crate::sign::TrustPolicy {
        first_party_keys: vec![crate::sign::FirstPartyKey {
            id: "independent-test-root".into(),
            key: crate::sign::ReleaseKey::Ed25519(key.verifying_key()),
        }],
        release_clock: Some(1_800_000_000),
        release_enforce_expiry: true,
        ..Default::default()
    };
    (manifest, policy)
}

#[test]
fn standalone_verifier_preserves_real_native_chain_bytes_abi_and_trust() {
    let image = image();
    let (manifest, policy) = signed(&image);
    let archive = crate::tarball::package(&manifest, "native.so", &image).unwrap();
    let old = crate::tarball::unpack(&archive).unwrap();
    let moved = isolated::tarball::unpack(&archive).unwrap();
    assert_eq!(old.manifest, moved.manifest);
    assert_eq!(moved.lib_bytes, image);
    assert_eq!(
        crate::sign::canonical_manifest_bytes(&old.manifest),
        isolated::sign::canonical_manifest_bytes(&moved.manifest)
    );
    let verifier = Verifier::unrestricted();
    verifier
        .validate_structure(&manifest, &image, &isolated::supported_abi, "busbar")
        .unwrap();
    let (verdict, evidence) = verifier
        .evaluate_with_verification(&image, &manifest, &policy)
        .unwrap();
    assert!(matches!(
        verdict,
        isolated::sign::Verdict::Trusted {
            first_party: true,
            ..
        }
    ));
    assert!(evidence.root.is_some());
    assert_eq!(evidence.signers.len(), 1);
    assert_eq!(evidence.keys_version, Some(1));
    assert_eq!(
        crate::sign::evaluate_with_verification(&image, &manifest, &policy).unwrap(),
        (verdict, evidence)
    );
    assert!(verifier
        .evaluate(&image, &manifest, &Default::default())
        .is_err());
    let mut wrong_abi = manifest.clone();
    wrong_abi.abi_version += 1;
    assert!(verifier
        .validate_structure(&wrong_abi, &image, &isolated::supported_abi, "busbar")
        .is_err());
    let mut altered = image.clone();
    altered.push(0);
    assert!(verifier.evaluate(&altered, &manifest, &policy).is_err());
    let mut forged = manifest.clone();
    forged.description.push_str("altered signed field");
    assert!(verifier.evaluate(&image, &forged, &policy).is_err());
    let mut rollback = policy.clone();
    rollback.release_keys_floor = 2;
    assert!(verifier.evaluate(&image, &manifest, &rollback).is_err());
}

struct Current {
    calls: Cell<usize>,
    deny: usize,
}
impl Authority for Current {
    fn check(&self, _: Operation, _: Phase) -> Result<(), Unavailable> {
        let next = self.calls.get() + 1;
        self.calls.set(next);
        if next == self.deny {
            Err(Unavailable)
        } else {
            Ok(())
        }
    }
}

#[test]
fn actual_native_proof_refuses_every_lost_authority_checkpoint() {
    let image = image();
    let (manifest, mut policy) = signed(&image);
    policy.allow_untrusted = true;
    let current = Current {
        calls: Cell::new(0),
        deny: usize::MAX,
    };
    Verifier::new(&current)
        .evaluate(&image, &manifest, &policy)
        .unwrap();
    assert!(current.calls.get() > 2);
    for deny in 1..=current.calls.get() {
        let authority = Current {
            calls: Cell::new(0),
            deny,
        };
        assert!(
            matches!(
                Verifier::new(&authority).evaluate(&image, &manifest, &policy),
                Err(VerificationError::Unavailable(_))
            ),
            "checkpoint {deny}"
        );
        assert_eq!(authority.calls.get(), deny);
    }
}

#[test]
fn legacy_value_readers_keep_their_pre_move_depth_and_duplicate_rules() {
    use busbar_artifact_metadata::BLOB_JSON;
    use busbar_contract::rendering::ReadBlob;
    for depth in [127usize, 128, 129] {
        let text = format!(
            "{{\"x\":{}0{}}}",
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        let blob = ReadBlob {
            fmt: BLOB_JSON,
            flags: 0,
            bytes: text.into_bytes(),
        };
        assert_eq!(
            crate::settings_schema::statement_schema(&blob).is_ok(),
            depth == 127
        );
        let declares = format!(
            "{{\"contract_abi\":{}0{}}}",
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        assert_eq!(
            crate::sign::Declares::from_declares_json(declares.as_bytes()).is_ok(),
            depth == 127
        );
    }
    let declares = crate::sign::Declares::from_declares_json(
        br#"{"destinations":["wrong"],"destinations":["path"],"keep":{"path":7,"path":0}}"#,
    )
    .unwrap();
    assert_eq!(declares.destinations, ["path"]);
    assert_eq!(declares.keep["path"], 0);
}

fn archive_with_manifest(raw: &[u8]) -> Vec<u8> {
    let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (name, body) in [("manifest.json", raw), ("fixture.so", b"image".as_slice())] {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, body).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap()
}

#[test]
fn typed_manifest_keeps_deep_ignored_fields_but_refuses_malformed_known_fields() {
    let manifest = crate::sign::Manifest {
        name: "fixture".into(),
        alias: "fixture".into(),
        kind: "secret".into(),
        version: "1.6.0".into(),
        publisher: "fixture".into(),
        abi_version: 1,
        ..Default::default()
    };
    let raw = json::to_string(&manifest).unwrap();
    let deep = format!(
        "{{\"metrics\":[{{\"name\":\"counter\",\"type\":\"counter\",\"extra\":{}0{}}}]}}",
        "[".repeat(256),
        "]".repeat(256)
    );
    let with_deep = raw.replacen(
        "\"description\":",
        &format!("\"declares\":{deep},\"description\":"),
        1,
    );
    assert!(crate::tarball::unpack(&archive_with_manifest(with_deep.as_bytes())).is_ok());
    for invalid in [
        raw.replacen("\"abi_version\":1", "\"abi_version\":1.5", 1),
        raw.replacen(
            "\"abi_version\":1",
            "\"abi_version\":1,\"abi_version\":1",
            1,
        ),
        raw.replacen("\"description\":", "\"unknown\":0,\"description\":", 1),
        format!("{raw} trailing"),
        raw.trim_end_matches('}').to_string(),
    ] {
        assert!(crate::tarball::unpack(&archive_with_manifest(invalid.as_bytes())).is_err());
    }
    assert!(json::parse_value(raw.as_bytes())
        .unwrap()
        .get("name")
        .is_some());
}
