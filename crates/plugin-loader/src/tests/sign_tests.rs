// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::json;

fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[test]
fn known_publisher_invalid_signature_never_uses_the_untrusted_override() {
    let trusted = test_key(91);
    let imposter = test_key(92);
    let bytes = b"known-publisher artifact";
    let m = sign(&imposter, manifest("acme-store", "acme", "acme"), bytes);
    let pol = policy(
        None,
        &[("acme", &trusted.verifying_key(), &["acme-store"])],
        true,
    );
    assert!(evaluate(bytes, &m, &pol).is_err());
}

#[test]
fn untrusted_override_never_accepts_a_library_hash_mismatch() {
    let key = test_key(93);
    let m = sign(
        &key,
        manifest("unknown-store", "unknown", "unknown"),
        b"original",
    );
    let pol = policy(None, &[], true);
    assert!(evaluate(b"altered", &m, &pol).is_err());
}

#[test]
fn busbar_root_cannot_sign_an_artifact_directly_to_bypass_the_keys_floor() {
    let root = test_key(94);
    let bytes = b"bare-root artifact";
    let m = sign(
        &root,
        manifest("busbar-store-test", "test", FIRST_PARTY_PUBLISHER),
        bytes,
    );
    for permissive in [false, true] {
        for floor in [0, 9] {
            let mut pol = policy(Some(&root), &[], permissive);
            pol.release_keys_floor = floor;
            assert!(
                evaluate(bytes, &m, &pol).is_err(),
                "override={permissive}, floor={floor}"
            );
        }
    }
}

fn manifest(name: &str, alias: &str, publisher: &str) -> Manifest {
    Manifest {
        name: name.to_string(),
        alias: alias.to_string(),
        kind: "store".to_string(),
        version: "1.5.0".to_string(),
        publisher: publisher.to_string(),
        abi_version: 1,
        sha256: String::new(),
        signature: String::new(),
        description: "A store plugin".to_string(),
        homepage: "https://example.dev".to_string(),
        license: "Apache-2.0".to_string(),
        needs: HookNeeds::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
        statement: None,
        former_names: Vec::new(),
    }
}

#[test]
fn hook_needs_is_signed_and_defaults_to_none() {
    let n = HookNeeds::default();
    assert!(!n.declares_any());
    assert!(!n.prompt.wants_read());

    let json = r#"{"prompt":"rw","user":"ro"}"#;
    let parsed: HookNeeds = json::parse_str(json).unwrap();
    assert!(parsed.declares_any());
    assert!(parsed.prompt.wants_read() && parsed.prompt.wants_rewrite());
    assert!(parsed.user.wants_read() && !parsed.user.wants_rewrite());

    assert!(
        HookNeeds {
            prompt: NeedLevel::Ro,
            user: NeedLevel::No
        }
        .declares_any(),
        "declaring only the prompt axis is still declaring a need"
    );
    assert!(
        HookNeeds {
            prompt: NeedLevel::No,
            user: NeedLevel::Ro
        }
        .declares_any(),
        "declaring only the user axis is still declaring a need"
    );

    let key = test_key(9);
    let mut m = manifest("busbar-hook-x", "x", "busbar");
    m.kind = "hook".into();
    let signed = sign(&key, m, b"lib");
    let mut tampered = signed.clone();
    tampered.needs = parsed;
    assert!(
        signature_ok_guarded(
            &Verifier::unrestricted(),
            &tampered,
            b"lib",
            &key.verifying_key()
        )
        .is_err(),
        "altering the declared intent after signing must fail verification"
    );
    assert!(signature_ok_guarded(
        &Verifier::unrestricted(),
        &signed,
        b"lib",
        &key.verifying_key()
    )
    .is_ok());
}

fn abi(_kind: &str) -> Option<u32> {
    Some(1)
}

fn policy(
    first_party: Option<&SigningKey>,
    pairs: &[(&str, &VerifyingKey, &[&str])],
    allow_untrusted: bool,
) -> TrustPolicy {
    TrustPolicy {
        first_party_key: first_party.map(|k| k.verifying_key()),
        binary_version: "1.5.0".to_string(),
        first_party_floors: BTreeMap::new(),
        first_party_high_water: BTreeMap::new(),
        publishers: pairs
            .iter()
            .map(|(n, k, scope)| {
                (
                    n.to_string(),
                    PublisherTrust {
                        plugins: scope.iter().map(|name| (*name).to_string()).collect(),
                        keys: vec![PublisherKey {
                            key: **k,
                            revoked: false,
                        }],
                    },
                )
            })
            .collect(),
        allow_untrusted,
        min_versions: BTreeMap::new(),
        ..TrustPolicy::default()
    }
}

#[test]
fn a_first_party_replay_below_the_high_water_mark_is_refused() {
    let release = test_key(1);
    let artifact = b"genuine busbar-signed 1.0.0 with a known fixed defect";
    let mut old = manifest("busbar-store-gamma-plugin", "gamma", FIRST_PARTY_PUBLISHER);
    old.version = "1.0.0".into();
    let old = seal_test_artifact(&release, old, artifact);

    let pol = policy(Some(&release), &[], false);
    assert!(
        matches!(
            evaluate(artifact, &old, &pol),
            Ok(Verdict::Trusted {
                first_party: true,
                ..
            })
        ),
        "a name with no high-water mark carries no floor"
    );

    let mut pol = policy(Some(&release), &[], true);
    pol.first_party_high_water
        .insert("busbar-store-gamma-plugin".to_string(), "1.2.0".to_string());
    let err = evaluate(artifact, &old, &pol).unwrap_err();
    assert_eq!(err.kind, RejectKind::AntiDowngrade);
    assert!(err.reason.contains("1.2.0"), "names the floor: {err:?}");
    assert!(
        err.reason.contains("plugins.rollback") || err.reason.contains("rollback"),
        "names the override: {err:?}"
    );

    for v in ["1.2.0", "1.3.0"] {
        let mut cur = manifest("busbar-store-gamma-plugin", "gamma", FIRST_PARTY_PUBLISHER);
        cur.version = v.into();
        let cur = seal_test_artifact(&release, cur, artifact);
        assert!(
            matches!(
                evaluate(artifact, &cur, &pol),
                Ok(Verdict::Trusted {
                    first_party: true,
                    ..
                })
            ),
            "{v} is at or above the mark and must load"
        );
    }
}

#[test]
fn an_explicit_rollback_pin_overrides_the_high_water_mark() {
    let release = test_key(1);
    let artifact = b"the 1.0.0 an operator deliberately rolled back to";
    let mut old = manifest("busbar-store-gamma-plugin", "gamma", FIRST_PARTY_PUBLISHER);
    old.version = "1.0.0".into();
    let old = seal_test_artifact(&release, old, artifact);

    let mut pol = policy(Some(&release), &[], false);
    pol.first_party_high_water
        .insert("busbar-store-gamma-plugin".to_string(), "1.2.0".to_string());

    assert!(evaluate(artifact, &old, &pol).is_err());

    pol.first_party_floors
        .insert("busbar-store-gamma-plugin".to_string(), "1.0.0".to_string());
    assert!(
        matches!(
            evaluate(artifact, &old, &pol),
            Ok(Verdict::Trusted {
                first_party: true,
                ..
            })
        ),
        "an explicit, audited rollback pin replaces the high-water floor"
    );

    let mut b = manifest("busbar-hook-ranker", "ranker", FIRST_PARTY_PUBLISHER);
    b.version = "1.0.0".into();
    let b = seal_test_artifact(&release, b, artifact);
    pol.first_party_high_water
        .insert("busbar-hook-ranker".to_string(), "1.2.0".to_string());
    assert!(
        evaluate(artifact, &b, &pol).is_err(),
        "pinning A must not lower B's floor"
    );
}

#[test]
fn the_high_water_mark_does_not_floor_a_third_party_plugin() {
    let release = test_key(1);
    let vendor = test_key(2);
    let artifact = b"a third-party artifact";
    let mut m = manifest("acme-store-plugin", "acme", "acme");
    m.version = "1.0.0".into();
    let m = sign(&vendor, m, artifact);

    let mut pol = policy(
        Some(&release),
        &[("acme", &vendor.verifying_key(), &["acme-store-plugin"])],
        false,
    );
    pol.first_party_high_water
        .insert("acme-store-plugin".to_string(), "1.2.0".to_string());
    assert!(
        matches!(
            evaluate(artifact, &m, &pol),
            Ok(Verdict::Trusted {
                first_party: false,
                ..
            })
        ),
        "the first-party mark must not floor a third-party publisher"
    );
}

#[test]
fn first_party_signed_is_trusted_with_zero_config() {
    let release = test_key(1);
    let artifact = b"\x7fELF first-party plugin";
    let m = seal_test_artifact(
        &release,
        manifest("busbar-store-gamma-plugin", "gamma", FIRST_PARTY_PUBLISHER),
        artifact,
    );

    let j = json::to_string(&m).unwrap();
    assert_eq!(json::parse_str::<Manifest>(&j).unwrap(), m);

    let pol = policy(Some(&release), &[], false);
    assert_eq!(
        evaluate(artifact, &m, &pol).unwrap(),
        Verdict::Trusted {
            publisher: FIRST_PARTY_PUBLISHER.into(),
            first_party: true
        }
    );
}

#[test]
fn secret_kind_is_known_and_signs_like_any_plugin() {
    assert!(KNOWN_KINDS.contains(&"secret"));
    let release = test_key(1);
    let artifact = b"\x7fELF secret plugin";
    let mut m0 = manifest("busbar-secret-delta", "delta", FIRST_PARTY_PUBLISHER);
    m0.kind = "secret".to_string();
    let m = seal_test_artifact(&release, m0, artifact);
    validate_structure(&m, artifact, &abi, HOST_IDENTITY)
        .expect("kind secret is structurally valid");
    let pol = policy(Some(&release), &[], false);
    assert_eq!(
        evaluate(artifact, &m, &pol).unwrap(),
        Verdict::Trusted {
            publisher: FIRST_PARTY_PUBLISHER.into(),
            first_party: true
        }
    );

    let mut bad = manifest("busbar-x", "x", FIRST_PARTY_PUBLISHER);
    bad.kind = "gizmo".to_string();
    let bad = seal_test_artifact(&release, bad, artifact);
    let err = validate_structure(&bad, artifact, &abi, HOST_IDENTITY).unwrap_err();
    assert!(err.contains("gizmo"), "got {err}");
}

#[test]
fn export_kind_is_known_and_signs_like_any_plugin() {
    assert!(KNOWN_KINDS.contains(&"export"));
    let release = test_key(1);
    let artifact = b"\x7fELF export plugin";
    let mut m0 = manifest("busbar-export-sink", "sink", FIRST_PARTY_PUBLISHER);
    m0.kind = "export".to_string();
    let m = seal_test_artifact(&release, m0, artifact);
    validate_structure(&m, artifact, &abi, HOST_IDENTITY)
        .expect("kind export is structurally valid");
    let pol = policy(Some(&release), &[], false);
    assert_eq!(
        evaluate(artifact, &m, &pol).unwrap(),
        Verdict::Trusted {
            publisher: FIRST_PARTY_PUBLISHER.into(),
            first_party: true
        }
    );
}

#[test]
fn first_party_version_floats_free_of_the_binary_version() {
    let release = test_key(1);
    let artifact = b"current first-party build on its own version line";
    let mut m = manifest("busbar-store-gamma-plugin", "gamma", FIRST_PARTY_PUBLISHER);
    m.version = "1.0.1".into();
    let m = seal_test_artifact(&release, m, artifact);
    let pol = policy(Some(&release), &[], false);
    assert!(
        matches!(
            evaluate(artifact, &m, &pol),
            Ok(Verdict::Trusted {
                first_party: true,
                ..
            })
        ),
        "a verified first-party plugin with no per-name floor loads regardless of the binary version"
    );

    let mut floored = policy(Some(&release), &[], true);
    floored
        .first_party_floors
        .insert("busbar-store-gamma-plugin".to_string(), "1.0.2".to_string());
    let err = evaluate(artifact, &m, &floored).unwrap_err();
    assert!(
        err.reason.contains("first-party anti-downgrade"),
        "got {err:?}"
    );

    let mut met = policy(Some(&release), &[], true);
    met.first_party_floors
        .insert("busbar-store-gamma-plugin".to_string(), "1.0.0".to_string());
    assert!(
        matches!(
            evaluate(artifact, &m, &met),
            Ok(Verdict::Trusted {
                first_party: true,
                ..
            })
        ),
        "a version at/above its own per-name floor must load, not be rejected"
    );
}

#[test]
fn first_party_floor_override_is_scoped_per_name() {
    let release = test_key(1);
    let artifact_a = b"old first-party A";
    let artifact_b = b"old first-party B";
    let mut a = manifest("busbar-store-gamma-plugin", "gamma", FIRST_PARTY_PUBLISHER);
    a.version = "1.4.0".into();
    let a = seal_test_artifact(&release, a, artifact_a);
    let mut b = manifest("busbar-hook-ranker", "ranker", FIRST_PARTY_PUBLISHER);
    b.version = "1.4.0".into();
    let b = seal_test_artifact(&release, b, artifact_b);

    let mut pol = policy(Some(&release), &[], false);
    pol.first_party_floors
        .insert("busbar-store-gamma-plugin".to_string(), "1.4.1".to_string());

    let err = evaluate(artifact_a, &a, &pol).unwrap_err();
    assert!(
        err.reason.contains("anti-downgrade"),
        "a pinned first-party plugin below its own floor is rejected: {err:?}"
    );

    assert!(
        matches!(
            evaluate(artifact_b, &b, &pol),
            Ok(Verdict::Trusted {
                first_party: true,
                ..
            })
        ),
        "another plugin's floor must not leak onto an unpinned first-party plugin"
    );
}

#[test]
fn first_party_claim_without_embedded_key_is_refused_even_with_override() {
    let release = test_key(1);
    let artifact = b"bytes";
    let m = seal_test_artifact(
        &release,
        manifest("busbar-store-gamma-plugin", "gamma", FIRST_PARTY_PUBLISHER),
        artifact,
    );

    let pol = policy(None, &[], false);
    let err = evaluate(artifact, &m, &pol).unwrap_err();
    assert_eq!(err.kind, RejectKind::Tampered);
    assert!(
        err.reason.contains("Busbar release proof refused"),
        "{err:?}"
    );
    let loose = policy(None, &[], true);
    assert!(
        evaluate(artifact, &m, &loose).is_err(),
        "unknown Busbar authority is a hard refusal"
    );
}

#[test]
fn first_party_publisher_name_cannot_be_forged_with_another_key() {
    let release = test_key(1);
    let attacker = test_key(9);
    let artifact = b"malicious plugin claiming to be busbar";

    let m = sign(
        &attacker,
        manifest("busbar-store-gamma-plugin", "gamma", FIRST_PARTY_PUBLISHER),
        artifact,
    );

    let pol = policy(Some(&release), &[], false);
    let err = evaluate(artifact, &m, &pol).unwrap_err();
    assert!(
        err.reason.contains("Busbar release proof refused"),
        "impersonation must be reported as a first-party signature failure, got {err:?}"
    );

    let third_party_open = policy(Some(&release), &[], true);
    assert!(
        evaluate(artifact, &m, &third_party_open).is_err(),
        "allow_untrusted must NOT permit a forged first-party plugin"
    );

    let mut mislead = policy(Some(&release), &[], false);
    mislead.publishers.insert(
        FIRST_PARTY_PUBLISHER.to_string(),
        PublisherTrust {
            plugins: [m.name.clone()].into_iter().collect(),
            keys: vec![PublisherKey {
                key: attacker.verifying_key(),
                revoked: false,
            }],
        },
    );
    assert!(
        evaluate(artifact, &m, &mislead).is_err(),
        "a 'busbar' entry in publishers must never override the embedded first-party key"
    );
}

#[test]
fn stripped_signature_old_first_party_is_rejected_by_default() {
    let release = test_key(1);
    let artifact = b"old vulnerable first-party build";
    let mut old = manifest("busbar-store-gamma-plugin", "gamma", FIRST_PARTY_PUBLISHER);
    old.version = "1.0.0".into();
    let old = seal_test_artifact(&release, old, artifact);

    let mut stripped = old.clone();
    stripped.signature = String::new();
    let pol = policy(Some(&release), &[], false);
    let err = evaluate(artifact, &stripped, &pol).unwrap_err();
    assert!(
        err.reason.contains("require a release seal"),
        "a stripped-signature old first-party plugin must be rejected as unsigned, got {err:?}"
    );
}

#[test]
fn third_party_allowlisted_publisher_is_trusted() {
    let acme = test_key(2);
    let artifact = b"third-party bytes";
    let m = sign(
        &acme,
        manifest("acme-store-dynamo", "dynamo", "acme"),
        artifact,
    );
    let pol = policy(
        None,
        &[("acme", &acme.verifying_key(), &["acme-store-dynamo"])],
        false,
    );
    assert_eq!(
        evaluate(artifact, &m, &pol).unwrap(),
        Verdict::Trusted {
            publisher: "acme".into(),
            first_party: false
        }
    );
}

#[test]
fn tampering_any_signed_field_fails() {
    let key = test_key(1);
    let artifact = b"bytes";
    let m = sign(&key, manifest("acme-p", "p", "acme"), artifact);
    let pol = policy(None, &[("acme", &key.verifying_key(), &["acme-p"])], false);

    let mut forged = m.clone();
    forged.description = "Busbar Official".into();
    assert!(evaluate(artifact, &forged, &pol).is_err());

    let mut forged = m.clone();
    forged.alias = "gamma".into();
    assert!(evaluate(artifact, &forged, &pol).is_err());

    assert!(evaluate(b"different!", &m, &pol).is_err());
}

#[test]
fn wrong_publisher_key_does_not_verify() {
    let key = test_key(1);
    let attacker = test_key(2);
    let artifact = b"bytes";
    let m = sign(&key, manifest("acme-p", "p", "acme"), artifact);
    let pol = policy(
        None,
        &[("acme", &attacker.verifying_key(), &["acme-p"])],
        false,
    );
    assert!(evaluate(artifact, &m, &pol).is_err());
}

#[test]
fn unknown_publisher_needs_allow_untrusted() {
    let key = test_key(3);
    let artifact = b"third-party bytes";
    let m = sign(&key, manifest("acme-p", "p", "acme"), artifact);

    let err = evaluate(artifact, &m, &policy(None, &[], false)).unwrap_err();
    assert!(err.reason.contains("allow_untrusted"), "got {err:?}");

    assert!(evaluate(artifact, &m, &policy(None, &[], false)).is_err());

    assert!(matches!(
        evaluate(artifact, &m, &policy(None, &[], true)).unwrap(),
        Verdict::Allowed {
            allow: AllowReason::Untrusted,
            ..
        }
    ));
}

#[test]
fn unsigned_needs_allow_untrusted() {
    let artifact = b"unsigned bytes";
    let mut m = manifest("acme-p", "p", "acme");
    m.sha256 = sha256_hex(artifact);

    let pol = policy(None, &[], false);
    let err = evaluate(artifact, &m, &pol).unwrap_err();
    assert!(err.reason.contains("allow_untrusted"), "got {err:?}");
    let loose = policy(None, &[], true);
    assert!(matches!(
        evaluate(artifact, &m, &loose).unwrap(),
        Verdict::Allowed {
            allow: AllowReason::Untrusted,
            ..
        }
    ));
}

#[test]
fn canonical_bytes_are_stable_and_exclude_signature() {
    let key = test_key(1);
    let m = sign(&key, manifest("acme-p", "p", "acme"), b"bytes");
    let a = canonical_manifest_bytes(&m);
    let mut m2 = m.clone();
    m2.signature = "deadbeef".into();
    assert_eq!(a, canonical_manifest_bytes(&m2));

    let s = String::from_utf8(a).unwrap();
    assert!(s.find("\"abi_version\"").unwrap() < s.find("\"alias\"").unwrap());
    assert!(s.find("\"alias\"").unwrap() < s.find("\"name\"").unwrap());
}

#[test]
fn public_key_hex_roundtrip() {
    let key = test_key(1);
    let hex = hex::encode(key.verifying_key().to_bytes());
    assert_eq!(public_key_from_hex(&hex).unwrap(), key.verifying_key());
    assert!(public_key_from_hex("zz").is_err());
}

#[test]
fn version_ordering_is_numeric_not_lexical() {
    assert!(version_at_least("1.10.0", "1.9.0"), "10 > 9 numerically");
    assert!(version_at_least("2.0.0", "1.99.99"));
    assert!(version_at_least("1.4.0", "1.4.0"), "equal clears the floor");
    assert!(!version_at_least("1.3.9", "1.4.0"));
    assert!(version_at_least("1.4.0-rc1", "1.4.0"));
    assert!(!version_at_least("not-a-version", "0.0.1"));
}

#[test]
fn name_and_semver_validators() {
    assert!(valid_name("busbar-store-gamma-plugin"));
    assert!(valid_name("gamma"));
    assert!(!valid_name(""));
    assert!(!valid_name("Gamma"));
    assert!(!valid_name("re dis"));
    assert!(!valid_name("-gamma"));
    assert!(!valid_name("gamma-"));
    assert!(!valid_name("../evil"));
    assert!(valid_semver("1.5.0"));
    assert!(valid_semver("1.5.0-rc1"));
    assert!(!valid_semver("1.5"));
    assert!(!valid_semver("1.5.x"));
    assert!(!valid_semver(""));
}

#[test]
fn structural_validation_names_each_failure() {
    let key = test_key(1);
    let bytes = b"lib bytes";
    let good = sign(&key, manifest("acme-p", "p", "acme"), bytes);
    assert!(validate_structure(&good, bytes, &abi, HOST_IDENTITY).is_ok());

    let mut bad = good.clone();
    bad.name = "Bad Name".into();
    assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
        .unwrap_err()
        .contains("not a valid plugin name"));

    let mut bad = good.clone();
    bad.alias = "UP".into();
    assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
        .unwrap_err()
        .contains("alias"));

    let mut bad = good.clone();
    bad.kind = "widget".into();
    assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
        .unwrap_err()
        .contains("kind"));

    let mut bad = good.clone();
    bad.version = "latest".into();
    assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
        .unwrap_err()
        .contains("semver"));

    let mut bad = good.clone();
    bad.publisher = " ".into();
    assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
        .unwrap_err()
        .contains("publisher"));

    let mut bad = good.clone();
    bad.sha256 = "abc".into();
    assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
        .unwrap_err()
        .contains("64-char hex"));

    let mut bad = good.clone();
    bad.sha256 = sha256_hex(b"other bytes");
    assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
        .unwrap_err()
        .contains("integrity"));

    let mut bad = good.clone();
    bad.abi_version = 99;
    assert!(validate_structure(&bad, bytes, &abi, HOST_IDENTITY)
        .unwrap_err()
        .contains("abi_version"));
}

#[test]
fn unknown_manifest_field_fails_parse() {
    let key = test_key(1);
    let m = sign(&key, manifest("acme-p", "p", "acme"), b"bytes");
    let mut v = json::to_value(&m).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("surprise".into(), json::json!(true));
    assert!(json::from_value::<Manifest>(&v).is_err());
}

#[test]
fn configured_floor_rejects_downgrade_and_is_not_bypassable() {
    let acme = test_key(2);
    let artifact = b"older vulnerable build";
    let mut old = manifest("acme-store-dynamo", "dynamo", "acme");
    old.version = "1.0.0".into();
    let old = sign(&acme, old, artifact);

    let mut pol = policy(
        None,
        &[("acme", &acme.verifying_key(), &["acme-store-dynamo"])],
        false,
    );
    assert!(matches!(
        evaluate(artifact, &old, &pol).unwrap(),
        Verdict::Trusted { .. }
    ));

    pol.min_versions
        .insert("acme-store-dynamo".to_string(), "2.0.0".to_string());
    let err = evaluate(artifact, &old, &pol).unwrap_err();
    assert!(err.reason.contains("anti-downgrade"), "got {err:?}");

    let mut stripped = old.clone();
    stripped.signature = String::new();
    let mut loose = policy(None, &[], true);
    loose
        .min_versions
        .insert("acme-store-dynamo".to_string(), "2.0.0".to_string());
    let err = evaluate(artifact, &stripped, &loose).unwrap_err();
    assert!(err.reason.contains("anti-downgrade"), "got {err:?}");

    let mut cur = manifest("acme-store-dynamo", "dynamo", "acme");
    cur.version = "2.0.0".into();
    let cur = sign(&acme, cur, artifact);
    assert!(matches!(
        evaluate(artifact, &cur, &pol).unwrap(),
        Verdict::Trusted { .. }
    ));
}

#[test]
fn garbage_min_version_floor_is_unsatisfiable_not_void() {
    let acme = test_key(2);
    let artifact = b"older vulnerable build";
    let mut old = manifest("acme-store-dynamo", "dynamo", "acme");
    old.version = "1.0.0".into();
    let old = sign(&acme, old, artifact);

    let mut pol = policy(
        None,
        &[("acme", &acme.verifying_key(), &["acme-store-dynamo"])],
        false,
    );
    pol.min_versions
        .insert("acme-store-dynamo".to_string(), "v2.0.0".to_string());

    let err = evaluate(artifact, &old, &pol).unwrap_err();
    assert_eq!(err.kind, RejectKind::AntiDowngrade);
    assert!(
        err.reason.contains("v2.0.0"),
        "reason must name the malformed floor: {}",
        err.reason
    );
}

#[test]
fn garbage_first_party_floor_does_not_erase_the_binary_floor() {
    let release = test_key(1);
    let artifact = b"old first-party build";
    let mut old = manifest("busbar-store-gamma-plugin", "gamma", FIRST_PARTY_PUBLISHER);
    old.version = "1.0.0".into();
    let old = seal_test_artifact(&release, old, artifact);

    let mut pol = policy(Some(&release), &[], false);
    pol.first_party_floors.insert(
        "busbar-store-gamma-plugin".to_string(),
        "v9.9.9".to_string(),
    );

    let err = evaluate(artifact, &old, &pol).unwrap_err();
    assert_eq!(err.kind, RejectKind::AntiDowngrade);
}

#[test]
fn malformed_floor_reason_says_the_floor_is_malformed() {
    assert_eq!(floor_note("1.6.0"), "");
    assert_eq!(floor_note(""), "");
    let note = floor_note("v1.6.0");
    assert!(!note.is_empty());
    assert!(note.contains("MAJOR.MINOR.PATCH"));
}

#[test]
fn validate_structure_accepts_only_the_one_abi_version_of_the_kind() {
    // LINT-RULES R21: a binary loads exactly one version per kind, never a range.
    fn abi_2(_kind: &str) -> Option<u32> {
        Some(2)
    }
    let release = test_key(1);
    let artifact = b"lib bytes";

    let mut exact = manifest("busbar-store-x", "x", FIRST_PARTY_PUBLISHER);
    exact.abi_version = 2;
    let exact = sign(&release, exact, artifact);
    validate_structure(&exact, artifact, &abi_2, HOST_IDENTITY)
        .expect("the kind's one abi_version is accepted");

    for other in [1, 3] {
        let mut m = manifest("busbar-store-x", "x", FIRST_PARTY_PUBLISHER);
        m.abi_version = other;
        let m = sign(&release, m, artifact);
        let err = validate_structure(&m, artifact, &abi_2, HOST_IDENTITY)
            .expect_err("a neighbouring abi_version is refused");
        assert!(err.contains("it loads v2 only"), "{err}");
    }
}

#[test]
fn embedded_key_mirrors_the_build_env() {
    match option_env!("BUSBAR_RELEASE_PUBKEY") {
        Some(hex) if !hex.trim().is_empty() => {
            let expected = public_key_from_hex(hex)
                .expect("this tree's committed BUSBAR_RELEASE_PUBKEY parses");
            assert_eq!(
                embedded_release_pubkey(),
                Some(expected),
                "a build with the key set must embed exactly that key, not a stand-in"
            );
        }
        _ => assert!(
            embedded_release_pubkey().is_none(),
            "a keyless build must embed nothing"
        ),
    }
}

#[test]
fn kind_restart_default_matches_binding_lifecycle() {
    assert!(kind_restart_default("store"));
    assert!(kind_restart_default("secret"));
    assert!(!kind_restart_default("hook"));
    assert!(!kind_restart_default("auth"));

    assert!(kind_restart_default("widget"));
}

#[test]
fn manifest_with_no_host_field_parses_and_loads() {
    let key = test_key(1);
    let artifact = b"pre-existing manifest bytes";
    let json = r#"{
            "name": "busbar-store-gamma-plugin",
            "alias": "gamma",
            "kind": "store",
            "version": "1.5.0",
            "publisher": "acme",
            "abi_version": 1,
            "sha256": "",
            "signature": "",
            "description": "",
            "homepage": "",
            "license": ""
        }"#;
    let m: Manifest =
        busbar_contract::json::parse_str(json).expect("manifest with no host field parses");
    assert_eq!(m.host, None, "absent host deserializes to None");
    let m = sign(&key, m, artifact);
    validate_structure(&m, artifact, &abi, HOST_IDENTITY)
        .expect("a manifest with no host field must still pass structural validation");
}

#[test]
fn manifest_with_host_busbar_loads() {
    let key = test_key(1);
    let artifact = b"same-host bytes";
    let mut m = manifest("busbar-store-gamma-plugin", "gamma", "acme");
    m.host = Some(HOST_IDENTITY.to_string());
    let m = sign(&key, m, artifact);
    validate_structure(&m, artifact, &abi, HOST_IDENTITY)
        .expect("host: busbar matches this binary's own identity and must load");
}

#[test]
fn manifest_with_foreign_host_is_rejected() {
    let key = test_key(1);
    let artifact = b"foreign-host bytes";
    let mut m = manifest("busbar-ui-store-tenants", "tenants", "acme");
    m.host = Some("busbar-ui".to_string());
    let m = sign(&key, m, artifact);
    let err = validate_structure(&m, artifact, &abi, HOST_IDENTITY).unwrap_err();
    assert!(
        err.contains("busbar-ui") && err.contains("host"),
        "rejection must name both the offending host and the field, got: {err}"
    );

    let pol = policy(Some(&key), &[], true);
    assert!(
        validate_structure(&m, artifact, &abi, HOST_IDENTITY).is_err(),
        "the host gate is structural and does not consult TrustPolicy at all"
    );
    let _ = pol;
}

#[test]
fn manifest_with_garbage_host_is_rejected() {
    let key = test_key(1);
    let artifact = b"garbage-host bytes";
    let mut m = manifest("acme-p", "p", "acme");
    m.host = Some("Busbar".to_string());
    let m = sign(&key, m, artifact);
    assert!(validate_structure(&m, artifact, &abi, HOST_IDENTITY).is_err());
}

#[test]
fn validate_structure_consults_the_host_identity_parameter_not_a_hardcoded_const() {
    let key = test_key(1);
    let artifact = b"sibling-product bytes";
    let mut m = manifest("busbar-ui-store-tenants", "tenants", "acme");
    m.host = Some("busbar-ui".to_string());
    let m = sign(&key, m, artifact);

    validate_structure(&m, artifact, &abi, "busbar-ui").expect(
        "a busbar-ui-hosted manifest must load when the CALLER's own identity is busbar-ui",
    );

    let err = validate_structure(&m, artifact, &abi, HOST_IDENTITY).unwrap_err();
    assert!(
        err.contains("busbar-ui"),
        "the same manifest validated by a busbar-identity caller must still be rejected, got: {err}"
    );
}

#[test]
fn manifest_with_no_host_matches_any_caller_identity() {
    let key = test_key(1);
    let artifact = b"no-host bytes";
    let m = manifest("acme-p", "p", "acme");
    assert_eq!(m.host, None);
    let m = sign(&key, m, artifact);

    validate_structure(&m, artifact, &abi, HOST_IDENTITY)
        .expect("absent host must match this binary's own identity");
    validate_structure(&m, artifact, &abi, "busbar-ui")
        .expect("absent host must ALSO match a sibling product's identity");
    validate_structure(&m, artifact, &abi, "some-third-product")
        .expect("absent host must match ANY caller's identity, not just known ones");
}

const WEAK_PUBLIC_KEY_HEX: &str =
    "0100000000000000000000000000000000000000000000000000000000000000";

#[test]
fn weak_publisher_key_is_refused_at_parse() {
    let err = public_key_from_hex(WEAK_PUBLIC_KEY_HEX)
        .expect_err("the ed25519 identity point must not be accepted as a publisher key");
    assert!(
        err.contains("weak"),
        "the refusal must name WHY the key is unusable, got: {err}"
    );
}

/// `y = 2`, sign bit clear: canonical (`y < p`) and not small-order, but no point on edwards25519 has
/// it. QE: a pinned key like this is refused when the configuration loads (boot, `--validate`), with
/// the INVALID text it had before Q9b, not first at the first verify.
const OFF_CURVE_PUBLIC_KEY_HEX: &str =
    "0200000000000000000000000000000000000000000000000000000000000000";

#[test]
fn off_curve_publisher_key_is_refused_at_config_load() {
    let err = public_key_from_hex(OFF_CURVE_PUBLIC_KEY_HEX)
        .expect_err("a key with no point on the curve must not be pinned");
    assert_eq!(
        err,
        "invalid ed25519 public key: invalid crypto input: Ed25519 public key is not a canonical \
         curve point"
    );
    let none = BTreeMap::new();
    let err = TrustPolicy::from_config(TrustInput {
        publishers: &[(
            "acme",
            &["acme-p".to_string()],
            vec![(OFF_CURVE_PUBLIC_KEY_HEX, false)],
        )],
        allow_untrusted: false,
        min_versions: &none,
        first_party_floors: &none,
        binary_version: "1.6.0",
    })
    .map(drop)
    .unwrap_err();
    assert_eq!(
        err,
        "plugins.trust.publishers['acme']: invalid ed25519 public key: invalid crypto input: \
         Ed25519 public key is not a canonical curve point"
    );
    let err = parse_release_keys(&format!("rk1:ed25519:{OFF_CURVE_PUBLIC_KEY_HEX}"))
        .map(drop)
        .unwrap_err();
    assert!(err.contains("invalid ed25519 public key"), "{err}");
}

#[test]
fn signature_does_not_verify_under_a_weak_key() {
    let mut weak = [0u8; 32];
    weak[0] = 1;

    let key = VerifyingKey::from_bytes(&weak)
        .expect("the identity point decompresses; only a weakness check refuses it");
    let artifact = b"attacker-supplied library bytes";
    let mut m = manifest("acme-p", "p", "acme");
    m.sha256 = sha256_hex(artifact);

    let mut forged = [0u8; 64];
    forged[0] = 1;
    m.signature = hex::encode(forged);
    assert!(
        signature_ok_guarded(&Verifier::unrestricted(), &m, artifact, &key).is_err(),
        "a weak-key universal forgery must not verify"
    );
}

#[test]
fn a_contract_abi_range_is_never_carried_and_a_signed_manifest_stating_one_is_refused() {
    let d = Declares::from_declares_json(br#"{"contract_abi": {"min": 3, "max": 4}}"#)
        .expect("a declares file's stale range is read and dropped");
    assert_eq!(d, Declares::default());
    assert!(d.is_empty());
    assert_eq!(json::to_value(&d).unwrap(), json::json!({}));

    let m = manifest("busbar-store-ranged", "ranged", FIRST_PARTY_PUBLISHER);
    let mut wire = json::to_value(&m).expect("encodes");
    wire["declares"] = json::json!({ "contract_abi": { "min": 3, "max": 4 } });
    assert!(
        json::from_value::<Manifest>(&wire).is_err(),
        "a signed manifest stating a contract-ABI range is refused"
    );
}

#[test]
fn a_declared_breaker_fact_round_trips_and_a_manifest_without_one_keeps_its_bytes() {
    let key = test_key(12);
    let mut quiet = manifest("busbar-plane-quiet", "quiet", FIRST_PARTY_PUBLISHER);
    quiet.kind = "plane".to_string();
    let quiet = sign(&key, quiet, b"door");
    let wire = json::to_vec(&quiet).expect("encodes");
    assert!(
        !String::from_utf8_lossy(&wire).contains("breaker"),
        "an absent fact is left off the wire"
    );
    assert!(!String::from_utf8_lossy(&canonical_manifest_bytes(&quiet)).contains("breaker"));
    let read: Manifest = json::parse(&wire).expect("reads");
    assert_eq!(read.declares.breaker, None);
    assert_eq!(
        json::to_vec(&read).expect("encodes"),
        wire,
        "a manifest that states no breaker fact keeps its exact bytes"
    );
    assert_eq!(
        canonical_manifest_bytes(&read),
        canonical_manifest_bytes(&quiet),
        "and the bytes its signature covers"
    );
    assert!(Declares::default().is_empty());

    let stated = r#"{"breaker":{"bench_below_trip_threshold":false}}"#;
    let d = Declares::from_declares_json(stated.as_bytes()).expect("parses");
    assert_eq!(
        d.breaker,
        Some(BreakerDecl {
            bench_below_trip_threshold: false
        })
    );
    assert!(!d.is_empty(), "a stated fact is a declaration");
    assert_eq!(json::to_string(&d).expect("encodes"), stated);
    assert!(Declares::from_declares_json(
        br#"{"breaker":{"bench_below_trip_threshold":false,"x":1}}"#
    )
    .is_err());
    assert!(Declares::from_declares_json(br#"{"breaker":{}}"#).is_err());

    let mut m = quiet.clone();
    m.declares.breaker = d.breaker;
    let m = sign(&key, m, b"door");
    let back: Manifest = json::parse(&json::to_vec(&m).expect("encodes")).expect("reads");
    assert_eq!(back, m, "a stated fact round-trips whole");
    let mut flipped = m.clone();
    flipped.declares.breaker = Some(BreakerDecl {
        bench_below_trip_threshold: true,
    });
    assert_ne!(
        canonical_manifest_bytes(&m),
        canonical_manifest_bytes(&flipped),
        "the fact is covered by the signature"
    );
    assert_ne!(
        canonical_manifest_bytes(&m),
        canonical_manifest_bytes(&quiet),
        "stating it changes the signed bytes"
    );
}

#[test]
fn red_the_stated_statement_is_signed_and_must_be_one_whole_rendering() {
    use busbar_contract::abi::mechanism::rendering::render;
    use busbar_contract::abi::sdk::door::statement;
    let st = statement("busbar-store-x", "1.5.0", 4);
    // SAFETY: the SDK's Statement names only `'static` strings and no list.
    let rendering = unsafe { render(&st) }.unwrap();
    let key = test_key(11);
    let mut m = manifest("busbar-store-x", "x", "busbar");
    m.statement = Some(hex::encode(&rendering));
    let signed = sign(&key, m, b"lib");
    assert!(signature_ok_guarded(
        &Verifier::unrestricted(),
        &signed,
        b"lib",
        &key.verifying_key()
    )
    .is_ok());
    assert_eq!(signed.stated_rendering().unwrap(), Some(rendering.clone()));
    assert_eq!(signed.stated().unwrap().unwrap().name, "busbar-store-x");
    assert!(validate_identity(&signed, HOST_IDENTITY).is_ok());

    let mut tampered = signed.clone();
    let mut other = rendering.clone();
    let last = other.len() - 1;
    other[last] ^= 1;
    tampered.statement = Some(hex::encode(&other));
    assert!(
        signature_ok_guarded(
            &Verifier::unrestricted(),
            &tampered,
            b"lib",
            &key.verifying_key()
        )
        .is_err(),
        "a statement changed after signing fails verification"
    );

    for bad in ["zz", "ABCD", "00"] {
        let mut m = signed.clone();
        m.statement = Some(bad.into());
        assert!(
            validate_identity(&m, HOST_IDENTITY).is_err(),
            "{bad} is not a whole rendering"
        );
    }

    let none = manifest("busbar-store-x", "x", "busbar");
    let canonical = String::from_utf8(canonical_manifest_bytes(&none)).unwrap();
    assert!(
        !canonical.contains("statement"),
        "an absent statement is not in the signed bytes: {canonical}"
    );
}

#[test]
fn statement_schema_is_authoritative_and_malformed_material_is_rejected() {
    use busbar_contract::abi::mechanism::call::{Blob, BLOB_JSON};
    use busbar_contract::abi::mechanism::rendering::render;
    use busbar_contract::abi::sdk::door::statement;
    let make = |bytes: &'static [u8]| {
        let mut st = statement("busbar-store-x", "1.5.0", 4);
        st.settings_schema = Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: BLOB_JSON,
            flags: 0,
        };
        // SAFETY: every byte and all Statement fields have static storage.
        let rendering = unsafe { render(&st) }.unwrap();
        let mut m = manifest("busbar-store-x", "x", "busbar");
        m.statement = Some(hex::encode(rendering));
        m.settings_schema = Some("{ invalid legacy schema".into());
        m
    };
    let good = make(br#"{"type":"object","required":["url"]}"#);
    let original = canonical_manifest_bytes(&good);
    let schema = good.settings_schema_text().unwrap().unwrap();
    assert_eq!(
        json::parse_str::<json::Value>(&schema).unwrap()["required"][0],
        "url"
    );
    assert!(validate_identity(&good, HOST_IDENTITY).is_ok());
    assert_eq!(
        canonical_manifest_bytes(&good),
        original,
        "projection must not mutate signed bytes"
    );
    let absent = make(b"");
    assert_eq!(
        absent.settings_schema_text().unwrap(),
        absent.settings_schema
    );
    assert!(
        validate_identity(&absent, HOST_IDENTITY).is_ok(),
        "legacy errors remain inspectable"
    );
    for bad in [
        b"\xff".as_slice(),
        b"{ invalid".as_slice(),
        b"null".as_slice(),
    ] {
        let m = make(bad);
        assert!(m.settings_schema_text().is_err());
        assert!(validate_identity(&m, HOST_IDENTITY).is_err());
        assert!(
            crate::dispatch::ManifestFacts::read(&m.stated_rendering().unwrap().unwrap()).is_err()
        );
    }
    let mut none = manifest("busbar-store-x", "x", "busbar");
    assert_eq!(none.settings_schema_text().unwrap(), None);
    none.settings_schema = Some("false".into());
    assert_eq!(
        none.settings_schema_text().unwrap().as_deref(),
        Some("false")
    );
}

#[test]
fn a_signed_need_retention_policy_must_equal_the_actual_modules_policy() {
    use crate::dispatch::{load_linked, Adopter, Bind, ConnTable, LinkedRow, LoadError, NoSink};
    use busbar_contract::abi::host::conn::connector::{Need, KEEP_ALL_EXCEPT_DENIED, KEEP_NAMED};
    use busbar_contract::abi::mechanism::door::{Door, Statement};
    use busbar_contract::abi::mechanism::rendering::render;
    use busbar_contract::abi::sdk::door::abi_str;
    use std::sync::atomic::{AtomicPtr, Ordering};
    use std::sync::Arc;

    static ACTUAL: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
    extern "C" fn actual() -> *const Door {
        ACTUAL.load(Ordering::SeqCst)
    }
    const HEADERS: &[busbar_contract::abi::mechanism::call::AbiStr] =
        &[abi_str("x-retention-first"), abi_str("x-retention-second")];
    const REVERSED: &[busbar_contract::abi::mechanism::call::AbiStr] =
        &[abi_str("x-retention-second"), abi_str("x-retention-first")];
    const RENAMED: &[busbar_contract::abi::mechanism::call::AbiStr] =
        &[abi_str("x-retention-third"), abi_str("x-retention-second")];
    const ARTIFACT: &[u8] = b"signed-retention-test-module";
    let key = test_key(11);
    let binding = || Bind {
        instance: "retention-policy".into(),
        max_inflight_cap: 1,
        sink: Arc::new(NoSink),
        dispatcher: Adopter::unwatched(),
        conns: ConnTable::Probe,
    };
    for mode in [KEEP_NAMED, KEEP_ALL_EXCEPT_DENIED] {
        let policy = |names| {
            let need = Need {
                keep_mode: mode,
                ..crate::needs_restated::need(abi_str("tcp"))
            };
            if mode == KEEP_NAMED {
                need.with_keep_response_headers(names)
            } else {
                need.with_deny_response_headers(names)
            }
        };
        let actual_need = Box::leak(Box::new([policy(HEADERS)]));
        let mut parts = crate::dispatch_test_plugin::door().parts();
        // SAFETY: the real fixture's door holds a complete static Statement.
        let base = unsafe { parts.statement.read_unaligned() };
        let st = Box::leak(Box::new(Statement {
            needs: actual_need.as_ptr(),
            needs_len: actual_need.len(),
            ..base
        }));
        parts.statement = st;
        // SAFETY: all copied fixture data and the replacement Need/Statement live for the process.
        ACTUAL.store(
            Box::into_raw(Box::new(unsafe { Door::__from_parts(parts) })),
            Ordering::SeqCst,
        );
        // SAFETY: all Statement backing is static or leaked above.
        let own = unsafe { render(st) }.unwrap();
        let facts = busbar_contract::abi::mechanism::rendering::read(&own).unwrap();
        let mut m = manifest(&facts.name, "retention", "busbar");
        m.kind = crate::dispatch_test_plugin::KIND.word().into();
        m.version = facts.version;
        m.abi_version = crate::dispatch_test_plugin::KIND.abi_version();
        m.statement = Some(hex::encode(&own));
        let signed = sign(&key, m, ARTIFACT);
        assert!(signature_ok_guarded(
            &Verifier::unrestricted(),
            &signed,
            ARTIFACT,
            &key.verifying_key()
        )
        .is_ok());
        let control = LinkedRow {
            statement: signed.stated_rendering().unwrap().unwrap(),
            door: actual,
        };
        assert!(load_linked::<crate::dispatch_tests::TestKind>(&control, binding()).is_ok());
        let other_mode = Need {
            keep_mode: if mode == KEEP_NAMED {
                KEEP_ALL_EXCEPT_DENIED
            } else {
                KEEP_NAMED
            },
            ..crate::needs_restated::need(abi_str("tcp"))
        };
        for need in [
            policy(&[]),
            policy(&HEADERS[..1]),
            policy(REVERSED),
            policy(RENAMED),
            other_mode,
        ] {
            let changed = Statement {
                needs: &need,
                ..*st
            };
            // SAFETY: replacement Need lives through rendering and its names are static.
            let changed = unsafe { render(&changed) }.unwrap();
            assert_ne!(changed, own);
            let mut tampered = signed.clone();
            tampered.statement = Some(hex::encode(&changed));
            assert!(signature_ok_guarded(
                &Verifier::unrestricted(),
                &tampered,
                ARTIFACT,
                &key.verifying_key()
            )
            .is_err());
            let restated = sign(&key, tampered, ARTIFACT);
            assert!(signature_ok_guarded(
                &Verifier::unrestricted(),
                &restated,
                ARTIFACT,
                &key.verifying_key()
            )
            .is_ok());
            let row = LinkedRow {
                statement: restated.stated_rendering().unwrap().unwrap(),
                door: actual,
            };
            assert_eq!(
                load_linked::<crate::dispatch_tests::TestKind>(&row, binding()).err(),
                Some(LoadError::StatementMismatch)
            );
        }
    }
}

#[test]
fn from_config_keeps_its_refusal_bytes_and_carries_every_floor_exactly() {
    let none = BTreeMap::new();
    let input = TrustInput {
        publishers: &[],
        allow_untrusted: false,
        min_versions: &none,
        first_party_floors: &none,
        binary_version: "1.6.0",
    };
    assert_eq!(
        TrustPolicy::from_config(TrustInput {
            publishers: &[("busbar", &["acme-p".to_string()], vec![("00", false)])],
            ..input
        })
        .map(drop)
        .unwrap_err(),
        "plugins.trust.publishers['busbar']: the publisher name 'busbar' is reserved for busbar's \
         embedded release key and cannot be configured"
    );
    assert_eq!(
        TrustPolicy::from_config(TrustInput {
            publishers: &[("acme", &["acme-p".to_string()], vec![("zz", false)])],
            ..input
        })
        .map(drop)
        .unwrap_err(),
        "plugins.trust.publishers['acme']: public key not valid hex: Invalid character 'z' at \
         position 0"
    );
    assert_eq!(
        TrustPolicy::from_config(TrustInput {
            publishers: &[("acme", &["acme-p".to_string()], vec![("00", false)])],
            ..input
        })
        .map(drop)
        .unwrap_err(),
        "plugins.trust.publishers['acme']: public key must be 32 bytes, got 1"
    );

    let mut floors = BTreeMap::new();
    floors.insert("busbar-store-kv-plugin".to_string(), "0.9.0".to_string());
    let mut mins = BTreeMap::new();
    mins.insert("acme-hook".to_string(), "2.1.0".to_string());
    let key = hex::encode(test_key(3).verifying_key().to_bytes());
    let p = TrustPolicy::from_config(TrustInput {
        publishers: &[("acme", &["acme-p".to_string()], vec![(key.as_str(), false)])],
        allow_untrusted: true,
        min_versions: &mins,
        first_party_floors: &floors,
        binary_version: "1.6.0",
    })
    .unwrap();
    assert_eq!(p.first_party_floors, floors);
    assert_eq!(p.min_versions, mins);
    assert!(
        p.first_party_high_water.is_empty(),
        "the registry build arms the automatic floor"
    );
    assert_eq!(p.binary_version, "1.6.0");
    assert!(p.allow_untrusted);
    assert_eq!(
        p.publishers.get("acme").map(|p| p.keys[0].key.to_bytes()),
        Some(test_key(3).verifying_key().to_bytes())
    );
    assert_eq!(p.first_party_key, embedded_release_pubkey());
}

const RELEASE_PUBKEY_1_5: &str = "b18395a332803151b9cd40a71489a86a96d8bea3ee6a37a45f59dec197bacba7";

#[test]
fn the_default_release_key_input_is_not_a_retired_key() {
    let cfg = include_str!("../../../../.cargo/config.toml");
    assert!(
        !cfg.contains(RELEASE_PUBKEY_1_5),
        "the committed build input must not carry the retired 1.5 release key"
    );
    let committed: Vec<&str> = cfg
        .lines()
        .filter_map(|l| l.trim().strip_prefix("BUSBAR_RELEASE_PUBKEY"))
        .filter_map(|rest| rest.trim().strip_prefix('='))
        .map(|v| v.trim().trim_matches('"'))
        .collect();
    for value in committed {
        assert!(
            !RETIRED_RELEASE_KEYS
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(value)),
            "the committed build input {value} is a retired release key"
        );
    }
}

fn stand_in_retired(artifact: &[u8]) -> (SigningKey, String, Manifest) {
    let key = test_key(0x15);
    let hex = hex::encode(key.verifying_key().as_bytes());
    let signed = sign(
        &key,
        manifest("busbar-store-retired", "retired", FIRST_PARTY_PUBLISHER),
        artifact,
    );
    (key, hex, signed)
}

#[test]
fn a_manifest_signed_by_a_retired_key_is_refused() {
    let artifact = b"\x7fELF signed by a retired key";
    let (key, hex, signed) = stand_in_retired(artifact);
    let retired = [(hex.as_str(), "a stand-in retired key")];
    let pol = policy(Some(&key), &[], false);
    let r = evaluate_against(artifact, &signed, &pol, &retired).unwrap_err();
    assert_eq!(r.kind, RejectKind::RetiredKey, "got {r:?}");
    assert!(r.reason.contains(&hex) && r.reason.contains("a stand-in retired key"));
    assert!(
        evaluate_against(artifact, &signed, &pol, &[]).is_err(),
        "a bare root signature is not a release seal even without retirement"
    );
}

#[test]
fn a_retired_busbar_key_cannot_be_reallowed_under_another_publisher() {
    let artifact = b"\x7fELF signed by a retired key";
    let (key, hex, signed) = stand_in_retired(artifact);
    let retired = [(hex.as_str(), "a stand-in retired key")];
    for allow_untrusted in [false, true] {
        let pol = policy(
            None,
            &[(
                "busbar-1-5-retired",
                &key.verifying_key(),
                &["busbar-store-retired"],
            )],
            allow_untrusted,
        );
        let refusal = evaluate_against(artifact, &signed, &pol, &retired).unwrap_err();
        assert_eq!(refusal.kind, RejectKind::RetiredKey);
        assert!(refusal.reason.contains(&hex));
        assert!(refusal.reason.contains("a stand-in retired key"));
        assert_eq!(
            evaluate_against(b"altered", &signed, &pol, &retired)
                .unwrap_err()
                .kind,
            RejectKind::Tampered
        );
    }
    let known_retired = RETIRED_RELEASE_KEYS[0].0;
    let none = BTreeMap::new();
    assert!(TrustPolicy::from_config(TrustInput {
        publishers: &[(
            "retired-fixture",
            &["busbar-store-retired".to_string()],
            vec![(known_retired, false)]
        )],
        allow_untrusted: true,
        min_versions: &none,
        first_party_floors: &none,
        binary_version: "1.6.0",
    })
    .is_err());
}

#[test]
fn an_empty_former_name_list_preserves_neutral_signed_manifest_bytes() {
    let key = test_key(0x55);
    let signed = sign(
        &key,
        manifest("busbar-hook-fixture", "fixture", "busbar"),
        b"fixture library",
    );
    let text = json::to_string(&signed).unwrap();
    let parsed: Manifest = json::parse_str(&text).unwrap();
    assert!(parsed.former_names.is_empty());
    let canonical = canonical_manifest_bytes(&parsed);
    assert!(!String::from_utf8_lossy(&canonical).contains("former_names"));
    signature_ok_guarded(
        &Verifier::unrestricted(),
        &parsed,
        b"fixture library",
        &key.verifying_key(),
    )
    .unwrap();
    assert_eq!(
        json::to_value(&parsed).unwrap(),
        json::to_value(&signed).unwrap()
    );
}

#[test]
fn former_names_are_covered_by_the_signature() {
    let key = test_key(9);
    let lib = b"lib";
    let mut m = manifest("busbar-store-alpha", "alpha", "busbar");
    m.former_names = vec!["busbar-store-alpha-plugin".into()];
    let signed = sign(&key, m, lib);
    assert!(String::from_utf8_lossy(&canonical_manifest_bytes(&signed))
        .contains("\"former_names\":[\"busbar-store-alpha-plugin\"]"));
    signature_ok_guarded(
        &Verifier::unrestricted(),
        &signed,
        lib,
        &key.verifying_key(),
    )
    .expect("the signed list verifies");
    for tamper in [
        vec![],
        vec![
            "busbar-store-alpha-plugin".to_string(),
            "alpha-x".to_string(),
        ],
        vec!["busbar-store-beta-plugin".to_string()],
    ] {
        let mut t = signed.clone();
        t.former_names = tamper.clone();
        assert!(
            signature_ok_guarded(&Verifier::unrestricted(), &t, lib, &key.verifying_key()).is_err(),
            "a tampered former-name list {tamper:?} must not verify"
        );
    }
}

#[test]
fn a_malformed_or_repeated_former_name_fails_structure() {
    let ok = |former: &[&str]| {
        let mut m = manifest("busbar-hook-fixture", "fixture", "busbar");
        m.former_names = former.iter().map(|s| s.to_string()).collect();
        validate_identity(&m, HOST_IDENTITY)
    };
    ok(&["busbar-fixture"]).expect("a well-formed former name");
    ok(&[]).expect("none");
    for bad in [
        &["Busbar-Fixture"][..],
        &["busbar_fixture"],
        &["-busbar"],
        &[""],
        &["busbar-hook-fixture"],
        &["fixture"],
        &["busbar-fixture", "busbar-fixture"],
    ] {
        let e = ok(bad).expect_err("refused");
        assert!(e.contains("former name"), "{bad:?}: {e}");
    }
}

#[test]
fn only_a_secret_source_may_declare_a_disk_need() {
    let mut store = manifest("busbar-store-disk", "disk", "acme");
    store.declares.disk = true;
    let err = validate_identity(&store, HOST_IDENTITY).unwrap_err();
    assert!(
        err.contains("'store'") && err.contains("disk"),
        "the refusal names the kind and the need: {err}"
    );

    let mut secret = manifest("busbar-secret-disk", "disk", "acme");
    secret.kind = "secret".to_string();
    secret.declares.disk = true;
    validate_identity(&secret, HOST_IDENTITY).expect("a secret source may read the disk");

    assert_eq!(
        json::to_value(Declares::default()).expect("encode"),
        json::json!({}),
        "no disk need is left off the wire"
    );
    assert_eq!(
        Declares::from_declares_json(br#"{"disk": true}"#).map(|d| d.disk),
        Ok(true)
    );
}

#[test]
fn overflowing_min_version_components_refuse_a_real_signed_artifact() {
    let acme = test_key(2);
    let artifact = b"older vulnerable build";
    let mut old = manifest("acme-store-dynamo", "dynamo", "acme");
    old.version = "1.0.0".into();
    let old = sign(&acme, old, artifact);
    for floor in [
        "18446744073709551616.0.0",
        "1.18446744073709551616.0",
        "1.0.18446744073709551616",
    ] {
        let mut pol = policy(
            None,
            &[("acme", &acme.verifying_key(), &["acme-store-dynamo"])],
            false,
        );
        pol.min_versions
            .insert("acme-store-dynamo".into(), floor.into());
        let err = evaluate(artifact, &old, &pol).unwrap_err();
        assert_eq!(err.kind, RejectKind::AntiDowngrade, "{floor}");
        assert!(err.reason.contains(floor), "{}", err.reason);
        assert!(!version_at_least("1.0.0", floor), "{floor}");
        assert!(version_at_least(floor, floor), "{floor}");
    }
    assert!(version_at_least(
        "18446744073709551616.0.0",
        "18446744073709551615.0.0"
    ));
    assert!(!version_at_least(
        "18446744073709551615.0.0",
        "18446744073709551616.0.0"
    ));
    assert!(version_at_least("1.0.0", "0.18446744073709551616.0"));
    assert!(version_at_least("0001.0000.0000-rc1+build", "1.0.0"));
    assert!(version_at_least(
        "00000000000000000000000000000000000000000000001.0.0",
        "1.0.0"
    ));
    assert!(!version_at_least("not-a-version", "0.0.0"));
    assert!(
        version_at_least("not-a-version", ""),
        "empty means no floor"
    );
}

#[test]
fn release_root_lists_are_complete_unique_and_never_restore_retired_keys() {
    let a = test_key(71).verifying_key();
    let b = test_key(72).verifying_key();
    let a_hex = hex::encode(a.as_bytes());
    let b_hex = hex::encode(b.as_bytes());
    let roots = parse_release_keys(&format!("current:ed25519:{a_hex}, next:{b_hex}")).unwrap();
    assert_eq!(roots.len(), 2);
    assert_eq!(roots[0].id, "current");
    assert_eq!(roots[0].key, ReleaseKey::Ed25519(a));
    assert_eq!(roots[1].id, "next");
    assert_eq!(roots[1].key, ReleaseKey::Ed25519(b));
    assert_eq!(
        parse_release_keys(&a_hex).unwrap(),
        vec![FirstPartyKey::unnamed(a)]
    );
    for invalid in [
        String::new(),
        format!("current:{a_hex},"),
        format!("same:{a_hex},same:{b_hex}"),
        format!("one:{a_hex},two:{a_hex}"),
        format!("UPPER:{a_hex}"),
        format!("root:unknown:{a_hex}"),
        "root:p256:04".into(),
    ] {
        assert!(
            parse_release_keys(&invalid).is_err(),
            "invalid root list accepted"
        );
    }
    let retired = RETIRED_RELEASE_KEYS[0].0;
    for spec in [
        retired.to_owned(),
        format!("old:{retired}"),
        format!("old:ed25519:{retired}"),
    ] {
        assert!(parse_release_keys(&spec).unwrap_err().contains("retired"));
    }
    assert!(
        FirstPartyKey::unnamed(public_key_from_hex(retired).unwrap())
            .retired_reason()
            .is_some()
    );
}

#[test]
fn nested_manifest_canonical_bytes_match_original_oidc_signer() {
    let manifest: Manifest = json::parse(include_bytes!(
        "fixtures/oidc-original-signed-manifest.json"
    ))
    .unwrap();
    let signer_bytes = include_bytes!("fixtures/oidc-original-signer-canonical.json");
    let canonical = canonical_manifest_bytes(&manifest);
    assert_eq!(
        sha256_hex(&canonical),
        "9ad24692a54c63d010b652ac34ba5c9da3e5b3d755c76e780dd8c06de6c764fb",
        "nested declarations must have the same bytes in ordinary and preserve_order builds"
    );
    assert_eq!(canonical.as_slice(), signer_bytes);
    let public: [u8; 32] =
        hex::decode("e990bbd9ce59115f6951f4490c0cba9fde5699a3eef90f407411346898b4272f")
            .unwrap()
            .try_into()
            .unwrap();
    let public = VerifyingKey::from_bytes(&public).unwrap();
    let signature = Signature::from_slice(&hex::decode(&manifest.signature).unwrap()).unwrap();
    public.verify_strict(signer_bytes, &signature).unwrap();
    public.verify_strict(&canonical, &signature).unwrap();

    let mut tampered = manifest.clone();
    tampered.declares.diagnostics[0].summary.push('!');
    assert!(public
        .verify_strict(&canonical_manifest_bytes(&tampered), &signature)
        .is_err());

    // Native causal runs additionally exercise the unchanged original archive through
    // the production tar reader, image binding and signature checker. The small golden
    // manifest above remains sufficient for ordinary unit runs without an ELF fixture.
    if let Some(path) = std::env::var_os("BUSBAR_CANONICAL_OIDC_ARCHIVE") {
        let archive = std::fs::read(path).unwrap();
        assert_eq!(
            sha256_hex(&archive),
            "8fa5eb41ac0fb764ce096586eea70d74b672621893e4d7deb052e1696b712e43"
        );
        let unpacked = crate::tarball::unpack(&archive).unwrap();
        assert_eq!(unpacked.manifest, manifest);
        signature_ok_guarded(
            &Verifier::unrestricted(),
            &unpacked.manifest,
            &unpacked.lib_bytes,
            &public,
        )
        .unwrap();
        assert!(signature_ok_guarded(
            &Verifier::unrestricted(),
            &tampered,
            &unpacked.lib_bytes,
            &public
        )
        .is_err());
        println!("original_oidc_archive_verified: unchanged signer, archive and library");
    }
}

/// RFC 8032 §7.1 TEST 1 and TEST 2: the plugin-facing `SigningKey`/`VerifyingKey` derive the same
/// public key and the same deterministic signature from a fixed seed on every ed25519-dalek major
/// this crate has shipped on, so keys and signatures made before an upgrade stay byte-identical.
#[test]
fn signing_from_a_fixed_seed_matches_the_rfc_8032_known_answers() {
    for (seed, public, message, signature) in [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            concat!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f",
                "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ),
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            concat!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            ),
        ),
    ] {
        let seed: [u8; 32] = hex::decode(seed).unwrap().try_into().unwrap();
        let key = SigningKey::from_bytes(&seed);
        assert_eq!(hex::encode(key.verifying_key().as_bytes()), public);
        assert_eq!(key.to_bytes(), seed, "the seed round-trips unchanged");
        let message = hex::decode(message).unwrap();
        let signed = key.sign(&message);
        assert_eq!(hex::encode(signed.to_bytes()), signature);
        let public: [u8; 32] = hex::decode(public).unwrap().try_into().unwrap();
        let public = VerifyingKey::from_bytes(&public).unwrap();
        let wire: [u8; 64] = hex::decode(signature).unwrap().try_into().unwrap();
        public
            .verify_strict(&message, &Signature::from_bytes(&wire))
            .expect("the RFC signature verifies strictly");
    }
}

#[test]
fn every_verification_checkpoint_refuses_revocation_even_with_untrusted_opt_in() {
    use crate::verification::{VerificationError, Verifier};
    use busbar_contract::crypto::verification::{Authority, Operation, Phase, Unavailable};
    use std::cell::Cell;
    struct Admission {
        calls: Cell<usize>,
        deny: usize,
    }
    impl Authority for Admission {
        fn check(&self, _: Operation, _: Phase) -> Result<(), Unavailable> {
            let call = self.calls.get() + 1;
            self.calls.set(call);
            if call == self.deny {
                Err(Unavailable)
            } else {
                Ok(())
            }
        }
    }
    let root = test_key(51);
    let bytes = b"authority-bound artifact";
    let sealed = seal_test_artifact(
        &root,
        manifest("busbar-store-test", "test", FIRST_PARTY_PUBLISHER),
        bytes,
    );
    let publisher = sign(&root, manifest("acme-store", "acme", "acme"), bytes);
    for (manifest, policy) in [
        (sealed, policy(Some(&root), &[], true)),
        (
            publisher,
            policy(
                None,
                &[("acme", &root.verifying_key(), &["acme-store"])],
                true,
            ),
        ),
    ] {
        let baseline = Admission {
            calls: Cell::new(0),
            deny: usize::MAX,
        };
        Verifier::new(&baseline)
            .evaluate(bytes, &manifest, &policy)
            .unwrap();
        let checkpoints = baseline.calls.get();
        assert!(
            checkpoints > 2,
            "verification must cross multiple primitives"
        );
        for deny in 1..=checkpoints {
            let authority = Admission {
                calls: Cell::new(0),
                deny,
            };
            assert!(
                matches!(
                    Verifier::new(&authority).evaluate(bytes, &manifest, &policy),
                    Err(VerificationError::Unavailable(_))
                ),
                "checkpoint {deny}"
            );
            assert_eq!(
                authority.calls.get(),
                deny,
                "refusal must stop the workflow"
            );
        }
    }
}

#[test]
fn root_import_preserves_authority_loss_as_unavailable() {
    use busbar_contract::crypto::verification::{Authority, Operation, Phase, Unavailable};
    struct Revoked;
    impl Authority for Revoked {
        fn check(&self, _: Operation, _: Phase) -> Result<(), Unavailable> {
            Err(Unavailable)
        }
    }
    let root = test_key(52);
    let spec = format!(
        "root:ed25519:{}",
        hex::encode(root.verifying_key().as_bytes())
    );
    assert!(matches!(
        crate::verification::Verifier::new(&Revoked).parse_release_keys(&spec),
        Err(crate::verification::VerificationError::Unavailable(_))
    ));
}

#[test]
fn expired_seal_probe_cannot_hide_lost_signature_authority() {
    use busbar_contract::crypto::verification::{Authority, Operation, Phase, Unavailable};
    struct RefuseSignatures;
    impl Authority for RefuseSignatures {
        fn check(&self, operation: Operation, _: Phase) -> Result<(), Unavailable> {
            if operation == Operation::Ed25519Verify {
                Err(Unavailable)
            } else {
                Ok(())
            }
        }
    }
    let root = test_key(53);
    let bytes = b"expired verification probe";
    let manifest = seal_test_artifact(
        &root,
        manifest("busbar-store-test", "test", FIRST_PARTY_PUBLISHER),
        bytes,
    );
    let mut policy = policy(Some(&root), &[], true);
    policy.release_enforce_expiry = true;
    policy.release_clock =
        Some(crate::release_trust::wire::parse_time("2100-01-01T00:00:00Z").unwrap());
    assert!(matches!(
        crate::verification::Verifier::new(&RefuseSignatures).evaluate(bytes, &manifest, &policy),
        Err(crate::verification::VerificationError::Unavailable(_))
    ));
}
