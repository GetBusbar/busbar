// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const LIB: &[u8] = b"scoped publisher artifact";

fn artifact(key: &SigningKey, name: &str) -> Manifest {
    sign(
        key,
        Manifest {
            name: name.into(),
            alias: "fixture".into(),
            kind: "store".into(),
            publisher: "acme".into(),
            version: "1.6.0".into(),
            abi_version: 1,
            ..Manifest::default()
        },
        LIB,
    )
}

fn policy(keys: &[(VerifyingKey, bool)]) -> TrustPolicy {
    TrustPolicy {
        publishers: [(
            "acme".into(),
            PublisherTrust {
                plugins: ["acme-store".into()].into_iter().collect(),
                keys: keys
                    .iter()
                    .map(|(key, revoked)| PublisherKey {
                        key: *key,
                        revoked: *revoked,
                    })
                    .collect(),
            },
        )]
        .into_iter()
        .collect(),
        ..TrustPolicy::default()
    }
}

#[test]
fn publisher_rotation_overlaps_then_revokes_without_an_override_escape() {
    let old = SigningKey::from_bytes(&[71; 32]);
    let new = SigningKey::from_bytes(&[72; 32]);
    let overlap = policy(&[(old.verifying_key(), false), (new.verifying_key(), false)]);
    for key in [&old, &new] {
        assert!(matches!(
            evaluate(LIB, &artifact(key, "acme-store"), &overlap),
            Ok(Verdict::Trusted {
                first_party: false,
                ..
            })
        ));
    }
    for allow_untrusted in [false, true] {
        let mut rotated = policy(&[(old.verifying_key(), true), (new.verifying_key(), false)]);
        rotated.allow_untrusted = allow_untrusted;
        assert_eq!(
            evaluate(LIB, &artifact(&old, "acme-store"), &rotated)
                .unwrap_err()
                .kind,
            RejectKind::Revoked
        );
        assert!(matches!(
            evaluate(LIB, &artifact(&new, "acme-store"), &rotated),
            Ok(Verdict::Trusted { .. })
        ));
    }
}

#[test]
fn a_publisher_key_cannot_sign_outside_its_operator_scope() {
    let key = SigningKey::from_bytes(&[73; 32]);
    let mut trust = policy(&[(key.verifying_key(), false)]);
    trust.allow_untrusted = true;
    assert_eq!(
        evaluate(LIB, &artifact(&key, "another-store"), &trust)
            .unwrap_err()
            .kind,
        RejectKind::PublisherScope
    );
}

#[test]
fn configured_unsigned_and_invalid_signatures_are_hard_refusals() {
    let key = SigningKey::from_bytes(&[74; 32]);
    let wrong = SigningKey::from_bytes(&[75; 32]);
    let mut trust = policy(&[(key.verifying_key(), false)]);
    trust.allow_untrusted = true;
    let mut unsigned = artifact(&key, "acme-store");
    unsigned.signature.clear();
    for m in [unsigned, artifact(&wrong, "acme-store")] {
        assert_eq!(
            evaluate(LIB, &m, &trust).unwrap_err().kind,
            RejectKind::Tampered
        );
    }
}

#[test]
fn unknown_signature_text_is_not_verified_evidence() {
    let key = SigningKey::from_bytes(&[76; 32]);
    let mut m = artifact(&key, "acme-store");
    m.signature = "not-a-signature".into();
    let trust = TrustPolicy {
        allow_untrusted: true,
        ..TrustPolicy::default()
    };
    assert!(matches!(
        evaluate(LIB, &m, &trust),
        Ok(Verdict::Allowed {
            allow: AllowReason::Untrusted,
            ..
        })
    ));
    assert_eq!(
        evaluate(b"altered", &m, &trust).unwrap_err().kind,
        RejectKind::Tampered
    );
}

#[test]
fn publisher_config_rejects_duplicates_weak_keys_and_empty_scope() {
    let key = hex::encode(SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes());
    let names = vec!["acme-store".into()];
    let none = BTreeMap::new();
    let check = |publishers: &[PublisherInput<'_>]| {
        TrustPolicy::from_config(TrustInput {
            publishers,
            allow_untrusted: false,
            min_versions: &none,
            first_party_floors: &none,
            binary_version: "1.6.0",
        })
    };
    assert!(check(&[(
        "acme",
        &names,
        vec![(key.as_str(), false), (key.as_str(), true)]
    )])
    .is_err());
    assert!(check(&[
        ("acme", &names, vec![(key.as_str(), false)]),
        ("other", &names, vec![(key.as_str(), false)])
    ])
    .is_err());
    assert!(check(&[("acme", &[], vec![(key.as_str(), false)])]).is_err());
    assert!(check(&[("acme", &names, vec![])]).is_err());
    let weak = format!("01{}", "00".repeat(31));
    assert!(check(&[("acme", &names, vec![(weak.as_str(), false)])]).is_err());
    assert!(
        check(&[("acme", &names, vec![(key.as_str(), true)])]).is_ok(),
        "all-revoked authority must remain representable"
    );
}

#[test]
fn admission_evidence_distinguishes_roots_signers_and_unverified_claims() {
    let root = SigningKey::from_bytes(&[78; 32]);
    let mut m = artifact(&root, "busbar-store-evidence");
    m.publisher = FIRST_PARTY_PUBLISHER.into();
    let sealed = seal_test_artifact(&root, m, LIB);
    let trust = TrustPolicy {
        first_party_keys: vec![FirstPartyKey::unnamed(root.verifying_key())],
        ..TrustPolicy::default()
    };
    let (_, proof) = evaluate_with_verification(LIB, &sealed, &trust).unwrap();
    let root_id = crate::release_trust::wire::key_id(&ReleaseKey::Ed25519(root.verifying_key()));
    assert_eq!(proof.root.as_deref(), Some(root_id.as_str()));
    assert_eq!(proof.keys_version, Some(1));
    assert_eq!(proof.signers.len(), 1);
    assert_ne!(
        proof.signers[0], root_id,
        "root authority must not be reported as the artifact signer"
    );

    let publisher = SigningKey::from_bytes(&[79; 32]);
    let scoped = policy(&[(publisher.verifying_key(), false)]);
    let (_, proof) =
        evaluate_with_verification(LIB, &artifact(&publisher, "acme-store"), &scoped).unwrap();
    assert_eq!(
        proof.signers,
        [crate::release_trust::wire::key_id(&ReleaseKey::Ed25519(
            publisher.verifying_key()
        ))]
    );
    assert!(proof.root.is_none());
    assert!(proof.keys_version.is_none());

    let untrusted = TrustPolicy {
        allow_untrusted: true,
        ..TrustPolicy::default()
    };
    let (_, proof) =
        evaluate_with_verification(LIB, &artifact(&publisher, "acme-store"), &untrusted).unwrap();
    assert_eq!(proof, Verification::default());
}
