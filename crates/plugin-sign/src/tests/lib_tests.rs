// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-sign/src/lib.rs`.

use super::*;

/// Deterministic test key from a seed byte (no RNG needed in this crate's tests).
fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A well-formed manifest (sha256/signature set by `sign`).
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
    }
}

/// The advisory `needs:` intent is SIGNED (covered by the canonical bytes) so it cannot be
/// spoofed, and a manifest omitting it parses with the default "asks for nothing". `NeedLevel`
/// exposes the read/rewrite predicates the core compares against the operator grant.
#[test]
fn hook_needs_is_signed_and_defaults_to_none() {
    // Default (absent) needs → declares nothing.
    let n = HookNeeds::default();
    assert!(!n.declares_any());
    assert!(!n.prompt.wants_read());

    // A declared prompt:rw need round-trips through JSON and reads as read+rewrite.
    let json = r#"{"prompt":"rw","user":"ro"}"#;
    let parsed: HookNeeds = serde_json::from_str(json).unwrap();
    assert!(parsed.declares_any());
    assert!(parsed.prompt.wants_read() && parsed.prompt.wants_rewrite());
    assert!(parsed.user.wants_read() && !parsed.user.wants_rewrite());

    // It is covered by the signature: changing `needs` after signing breaks verification.
    let key = test_key(9);
    let mut m = manifest("busbar-hook-x", "x", "busbar");
    m.kind = "hook".into();
    let signed = sign(&key, m, b"lib");
    let mut tampered = signed.clone();
    tampered.needs = parsed;
    assert!(
        signature_ok(&tampered, b"lib", &key.verifying_key()).is_err(),
        "altering the declared intent after signing must fail verification"
    );
    assert!(signature_ok(&signed, b"lib", &key.verifying_key()).is_ok());
}

fn abi(_kind: &str) -> &'static [u32] {
    &[1]
}

/// A policy with the given first-party key, third-party publishers, and opt-in flags.
fn policy(
    first_party: Option<&SigningKey>,
    pairs: &[(&str, &VerifyingKey)],
    allow_unsigned: bool,
    allow_third_party: bool,
) -> TrustPolicy {
    TrustPolicy {
        first_party_key: first_party.map(|k| k.verifying_key()),
        binary_version: "1.5.0".to_string(),
        first_party_floors: BTreeMap::new(),
        publishers: pairs.iter().map(|(n, k)| (n.to_string(), **k)).collect(),
        allow_unsigned,
        allow_third_party,
        min_versions: BTreeMap::new(),
    }
}

#[test]
fn first_party_signed_is_trusted_with_zero_config() {
    let release = test_key(1);
    let artifact = b"\x7fELF first-party plugin";
    let m = sign(
        &release,
        manifest(
            "busbar-store-valkey-plugin",
            "valkey",
            FIRST_PARTY_PUBLISHER,
        ),
        artifact,
    );
    // Manifest round-trips through JSON (it travels inside the tarball).
    let j = serde_json::to_string(&m).unwrap();
    assert_eq!(serde_json::from_str::<Manifest>(&j).unwrap(), m);

    // ZERO configured publishers: the embedded key alone proves first-party.
    let pol = policy(Some(&release), &[], false, false);
    assert_eq!(
        evaluate(artifact, &m, &pol).unwrap(),
        Verdict::Trusted {
            publisher: FIRST_PARTY_PUBLISHER.into(),
            first_party: true
        }
    );
}

/// `kind: secret` is a first-class plugin kind - a signed secret-module manifest passes
/// structural validation and the trust evaluation identically to a store plugin (a plugin is a
/// plugin), while an unknown kind still fails structure.
#[test]
fn secret_kind_is_known_and_signs_like_any_plugin() {
    assert!(KNOWN_KINDS.contains(&"secret"));
    let release = test_key(1);
    let artifact = b"\x7fELF secret plugin";
    let mut m0 = manifest("busbar-secret-vault", "vault", FIRST_PARTY_PUBLISHER);
    m0.kind = "secret".to_string();
    let m = sign(&release, m0, artifact);
    validate_structure(&m, artifact, &abi, HOST_IDENTITY)
        .expect("kind secret is structurally valid");
    let pol = policy(Some(&release), &[], false, false);
    assert_eq!(
        evaluate(artifact, &m, &pol).unwrap(),
        Verdict::Trusted {
            publisher: FIRST_PARTY_PUBLISHER.into(),
            first_party: true
        }
    );
    // A made-up kind still fails structure (the closed KNOWN_KINDS set).
    let mut bad = manifest("busbar-x", "x", FIRST_PARTY_PUBLISHER);
    bad.kind = "gizmo".to_string();
    let bad = sign(&release, bad, artifact);
    let err = validate_structure(&bad, artifact, &abi, HOST_IDENTITY).unwrap_err();
    assert!(err.contains("gizmo"), "got {err}");
}

/// `kind: export` is a first-class plugin kind — a signed export-sink manifest passes structural
/// validation and trust evaluation identically to any other plugin (a plugin is a plugin). Mirrors
/// `secret_kind_is_known_and_signs_like_any_plugin`.
#[test]
fn export_kind_is_known_and_signs_like_any_plugin() {
    assert!(KNOWN_KINDS.contains(&"export"));
    let release = test_key(1);
    let artifact = b"\x7fELF export plugin";
    let mut m0 = manifest("busbar-export-otlp", "otlp", FIRST_PARTY_PUBLISHER);
    m0.kind = "export".to_string();
    let m = sign(&release, m0, artifact);
    validate_structure(&m, artifact, &abi, HOST_IDENTITY)
        .expect("kind export is structurally valid");
    let pol = policy(Some(&release), &[], false, false);
    assert_eq!(
        evaluate(artifact, &m, &pol).unwrap(),
        Verdict::Trusted {
            publisher: FIRST_PARTY_PUBLISHER.into(),
            first_party: true
        }
    );
}

/// First-party plugin versions float FREE of the binary's version: the fleet ships 1.0.x
/// stores/auth/hooks (and 2.x headroom) under a 1.5.0 engine, so a verified first-party
/// plugin below the binary version MUST load when no per-name floor pins it. (The automatic
/// binary-version floor this replaces rejected every correctly-signed current release.)
#[test]
fn first_party_version_floats_free_of_the_binary_version() {
    let release = test_key(1);
    let artifact = b"current first-party build on its own version line";
    let mut m = manifest(
        "busbar-store-valkey-plugin",
        "valkey",
        FIRST_PARTY_PUBLISHER,
    );
    m.version = "1.0.1".into(); // binary is 1.5.0 — and that must not matter
    let m = sign(&release, m, artifact);
    let pol = policy(Some(&release), &[], false, false);
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

    // A per-name floor (rollback pin / registry floor) still hard-rejects below it, and no
    // loose opt-in flag can launder that (verified first-party never consults opt-ins).
    let mut floored = policy(Some(&release), &[], true, true);
    floored.first_party_floors.insert(
        "busbar-store-valkey-plugin".to_string(),
        "1.0.2".to_string(),
    );
    let err = evaluate(artifact, &m, &floored).unwrap_err();
    assert!(
        err.reason.contains("first-party anti-downgrade"),
        "got {err:?}"
    );
}

/// Per-name scoping: a PER-NAME first-party floor binds the pinned name
/// ONLY. Plugin A's floor must never change what plugin B is allowed to be — B is judged
/// solely by its own pin (or, absent one, no floor).
#[test]
fn first_party_floor_override_is_scoped_per_name() {
    let release = test_key(1);
    let artifact_a = b"old first-party A";
    let artifact_b = b"old first-party B";
    let mut a = manifest(
        "busbar-store-valkey-plugin",
        "valkey",
        FIRST_PARTY_PUBLISHER,
    );
    a.version = "1.4.0".into();
    let a = sign(&release, a, artifact_a);
    let mut b = manifest("busbar-hook-ranker", "ranker", FIRST_PARTY_PUBLISHER);
    b.version = "1.4.0".into();
    let b = sign(&release, b, artifact_b);

    // Floor A at 1.4.1 (above what A ships) and leave B unpinned.
    let mut pol = policy(Some(&release), &[], false, false);
    pol.first_party_floors.insert(
        "busbar-store-valkey-plugin".to_string(),
        "1.4.1".to_string(),
    );

    // A is below ITS OWN floor and is rejected.
    let err = evaluate(artifact_a, &a, &pol).unwrap_err();
    assert!(
        err.reason.contains("anti-downgrade"),
        "a pinned first-party plugin below its own floor is rejected: {err:?}"
    );
    // B, unpinned, is untouched by A's floor and loads.
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
fn first_party_claim_without_embedded_key_is_unsigned() {
    let release = test_key(1);
    let artifact = b"bytes";
    let m = sign(
        &release,
        manifest(
            "busbar-store-valkey-plugin",
            "valkey",
            FIRST_PARTY_PUBLISHER,
        ),
        artifact,
    );
    // No embedded key in this build: default posture rejects, naming the situation.
    let pol = policy(None, &[], false, false);
    let err = evaluate(artifact, &m, &pol).unwrap_err();
    assert!(
        err.reason.contains("embeds no busbar release key"),
        "got {err:?}"
    );
    // allow_unsigned permits it (dev builds), as the Unsigned category.
    let loose = policy(None, &[], true, false);
    assert!(matches!(
        evaluate(artifact, &m, &loose).unwrap(),
        Verdict::Allowed {
            allow: AllowReason::Unsigned,
            ..
        }
    ));
}

/// FIRST-PARTY IMPERSONATION is impossible: an attacker signs a plugin with their OWN key and
/// sets `publisher: busbar` to masquerade as first-party. Even with the real release key
/// EMBEDDED, evaluation routes a `publisher: busbar` manifest ONLY to the embedded key, so the
/// attacker's signature fails and the plugin is UNSIGNED (rejected by default; never third-party
/// laundered, and never trusted). Setting the publisher name buys nothing.
#[test]
fn first_party_publisher_name_cannot_be_forged_with_another_key() {
    let release = test_key(1); // the REAL embedded release key
    let attacker = test_key(9); // a key the operator never trusted
    let artifact = b"malicious plugin claiming to be busbar";
    // Attacker signs a busbar-branded manifest with their own key.
    let m = sign(
        &attacker,
        manifest(
            "busbar-store-valkey-plugin",
            "valkey",
            FIRST_PARTY_PUBLISHER,
        ),
        artifact,
    );
    // Embedded key present, attacker NOT in publishers. Default posture: rejected as unsigned
    // (the signature does not verify against the embedded first-party key).
    let pol = policy(Some(&release), &[], false, false);
    let err = evaluate(artifact, &m, &pol).unwrap_err();
    assert!(
        err.reason.contains("first-party signature failed"),
        "impersonation must be reported as a first-party signature failure, got {err:?}"
    );
    // Even allow_third_party cannot launder it: a `busbar` publisher never routes to the
    // third-party path, so the third-party opt-in is irrelevant. It stays UNSIGNED-category,
    // permitted ONLY by allow_unsigned (which is "load anything unsigned" by definition).
    let third_party_open = policy(Some(&release), &[], false, true);
    assert!(
        evaluate(artifact, &m, &third_party_open).is_err(),
        "allow_third_party must NOT permit a forged first-party plugin"
    );
    // And the attacker cannot get themselves allowlisted UNDER the name `busbar` to reach the
    // first-party branch: even if such a policy existed, the `publisher == busbar` branch only
    // consults the embedded key, never `publishers`. Prove the routing directly.
    let mut mislead = policy(Some(&release), &[], false, false);
    mislead
        .publishers
        .insert(FIRST_PARTY_PUBLISHER.to_string(), attacker.verifying_key());
    assert!(
        evaluate(artifact, &m, &mislead).is_err(),
        "a 'busbar' entry in publishers must never override the embedded first-party key"
    );
}

/// STRIPPED-SIGNATURE first-party downgrade: an attacker takes an OLD first-party release,
/// strips its signature, and hopes the automatic first-party anti-downgrade (which only guards
/// VERIFIED first-party manifests) no longer applies. Under the DEFAULT posture it is rejected
/// as unsigned - the downgrade never lands. (Under allow_unsigned the operator has already
/// opted into loading arbitrary unsigned code, so this is out of scope of the anti-downgrade
/// guarantee, which is specifically about REPLAYING a still-VALIDLY-SIGNED old release.)
#[test]
fn stripped_signature_old_first_party_is_rejected_by_default() {
    let release = test_key(1);
    let artifact = b"old vulnerable first-party build";
    let mut old = manifest(
        "busbar-store-valkey-plugin",
        "valkey",
        FIRST_PARTY_PUBLISHER,
    );
    old.version = "1.0.0".into(); // below the 1.5.0 binary
    let old = sign(&release, old, artifact);
    // Strip the (valid) signature: now it is an unsigned artifact claiming to be busbar.
    let mut stripped = old.clone();
    stripped.signature = String::new();
    let pol = policy(Some(&release), &[], false, false);
    let err = evaluate(artifact, &stripped, &pol).unwrap_err();
    assert!(
        err.reason.contains("unsigned") || err.reason.contains("no signature"),
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
    let pol = policy(None, &[("acme", &acme.verifying_key())], false, false);
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
    let pol = policy(None, &[("acme", &key.verifying_key())], false, false);

    // Flip a DISPLAY field: signature must break (the display card cannot be spoofed).
    let mut forged = m.clone();
    forged.description = "Busbar Official".into();
    assert!(evaluate(artifact, &forged, &pol).is_err());
    // Flip the ALIAS (the config-selection identity): signature must break.
    let mut forged = m.clone();
    forged.alias = "valkey".into();
    assert!(evaluate(artifact, &forged, &pol).is_err());
    // Swap the library under a good manifest -> hash mismatch.
    assert!(evaluate(b"different!", &m, &pol).is_err());
}

#[test]
fn wrong_publisher_key_does_not_verify() {
    let key = test_key(1);
    let attacker = test_key(2);
    let artifact = b"bytes";
    let m = sign(&key, manifest("acme-p", "p", "acme"), artifact);
    let pol = policy(None, &[("acme", &attacker.verifying_key())], false, false);
    assert!(evaluate(artifact, &m, &pol).is_err());
}

#[test]
fn unknown_publisher_needs_allow_third_party() {
    let key = test_key(3);
    let artifact = b"third-party bytes";
    let m = sign(&key, manifest("acme-p", "p", "acme"), artifact);

    // Default: refused, naming allow_third_party (NOT allow_unsigned).
    let err = evaluate(artifact, &m, &policy(None, &[], false, false)).unwrap_err();
    assert!(err.reason.contains("allow_third_party"), "got {err:?}");
    // allow_unsigned alone does NOT permit a third-party-signed plugin.
    assert!(evaluate(artifact, &m, &policy(None, &[], true, false)).is_err());
    // allow_third_party permits it.
    assert!(matches!(
        evaluate(artifact, &m, &policy(None, &[], false, true)).unwrap(),
        Verdict::Allowed {
            allow: AllowReason::ThirdParty,
            ..
        }
    ));
}

#[test]
fn unsigned_needs_allow_unsigned() {
    let artifact = b"unsigned bytes";
    let mut m = manifest("acme-p", "p", "acme");
    m.sha256 = sha256_hex(artifact);
    // Publisher IS allowlisted but the signature is empty -> tamper/unsigned category.
    let key = test_key(1);
    let pol = policy(None, &[("acme", &key.verifying_key())], false, false);
    let err = evaluate(artifact, &m, &pol).unwrap_err();
    assert!(err.reason.contains("allow_unsigned"), "got {err:?}");
    let loose = policy(None, &[("acme", &key.verifying_key())], true, false);
    assert!(matches!(
        evaluate(artifact, &m, &loose).unwrap(),
        Verdict::Allowed {
            allow: AllowReason::Unsigned,
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
    // Sorted-key JSON: abi_version sorts before alias before name.
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
    assert!(valid_name("busbar-store-valkey-plugin"));
    assert!(valid_name("valkey"));
    assert!(!valid_name(""));
    assert!(!valid_name("Valkey"));
    assert!(!valid_name("re dis"));
    assert!(!valid_name("-valkey"));
    assert!(!valid_name("valkey-"));
    assert!(!valid_name("../evil"));
    assert!(valid_semver("1.5.0"));
    assert!(valid_semver("1.5.0-rc1"));
    assert!(!valid_semver("1.5"));
    assert!(!valid_semver("1.5.x"));
    assert!(!valid_semver(""));
}

/// Phase-1 structural validation catches each malformation with a specific reason, independent
/// of trust (a validly-signed malformed manifest still fails).
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

    // Integrity: right shape, wrong digest.
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

/// A manifest with an UNKNOWN field fails to parse at all (deny_unknown_fields): fail-closed
/// against content this binary does not understand.
#[test]
fn unknown_manifest_field_fails_parse() {
    let key = test_key(1);
    let m = sign(&key, manifest("acme-p", "p", "acme"), b"bytes");
    let mut v = serde_json::to_value(&m).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("surprise".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<Manifest>(v).is_err());
}

/// Configured floor: a validly-signed-but-old third-party release is rejected once floored, and
/// a stripped-signature copy cannot be laundered past the floor by a loose posture.
#[test]
fn configured_floor_rejects_downgrade_and_is_not_bypassable() {
    let acme = test_key(2);
    let artifact = b"older vulnerable build";
    let mut old = manifest("acme-store-dynamo", "dynamo", "acme");
    old.version = "1.0.0".into();
    let old = sign(&acme, old, artifact);

    // No floor: trusted (baseline).
    let mut pol = policy(None, &[("acme", &acme.verifying_key())], false, false);
    assert!(matches!(
        evaluate(artifact, &old, &pol).unwrap(),
        Verdict::Trusted { .. }
    ));

    // Floor pinned: the old validly-signed release is rejected.
    pol.min_versions
        .insert("acme-store-dynamo".to_string(), "2.0.0".to_string());
    let err = evaluate(artifact, &old, &pol).unwrap_err();
    assert!(err.reason.contains("anti-downgrade"), "got {err:?}");

    // Stripped signature + both opt-ins: STILL rejected (the floor requires trusted proof).
    let mut stripped = old.clone();
    stripped.signature = String::new();
    let mut loose = policy(None, &[], true, true);
    loose
        .min_versions
        .insert("acme-store-dynamo".to_string(), "2.0.0".to_string());
    let err = evaluate(artifact, &stripped, &loose).unwrap_err();
    assert!(err.reason.contains("anti-downgrade"), "got {err:?}");

    // A current signed release at the floor still passes.
    let mut cur = manifest("acme-store-dynamo", "dynamo", "acme");
    cur.version = "2.0.0".into();
    let cur = sign(&acme, cur, artifact);
    assert!(matches!(
        evaluate(artifact, &cur, &pol).unwrap(),
        Verdict::Trusted { .. }
    ));
}

/// A MALFORMED `min_versions` floor (no leading `v`, so it fails [`valid_semver`]) must be
/// UNSATISFIABLE, not silently void. `version_components("v2.0.0")` truncates to `[0,0,0]`, so
/// without the [`valid_semver`] guard `version_at_least("1.0.0", "v2.0.0")` would be `true` and
/// the old artifact would evaluate `Verdict::Trusted` — a silent admission past a floor the
/// operator believed was armed.
#[test]
fn garbage_min_version_floor_is_unsatisfiable_not_void() {
    let acme = test_key(2);
    let artifact = b"older vulnerable build";
    let mut old = manifest("acme-store-dynamo", "dynamo", "acme");
    old.version = "1.0.0".into();
    let old = sign(&acme, old, artifact);

    let mut pol = policy(None, &[("acme", &acme.verifying_key())], false, false);
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

/// A malformed `first_party_floors` override must NOT erase the automatic `binary_version`
/// floor it REPLACES — the sharpest case, because the override would make a plugin the
/// automatic floor alone would have refused instead get ADMITTED, i.e. strictly LESS
/// protection than configuring nothing at all. Unguarded, the override reads as `[0,0,0]`,
/// which every version satisfies.
#[test]
fn garbage_first_party_floor_does_not_erase_the_binary_floor() {
    let release = test_key(1);
    let artifact = b"old first-party build";
    let mut old = manifest(
        "busbar-store-valkey-plugin",
        "valkey",
        FIRST_PARTY_PUBLISHER,
    );
    old.version = "1.0.0".into(); // below `binary_version` ("1.5.0", set by `policy()`)
    let old = sign(&release, old, artifact);

    let mut pol = policy(Some(&release), &[], false, false);
    pol.first_party_floors.insert(
        "busbar-store-valkey-plugin".to_string(),
        "v9.9.9".to_string(),
    );

    let err = evaluate(artifact, &old, &pol).unwrap_err();
    assert_eq!(err.kind, RejectKind::AntiDowngrade);
}

/// `floor_note`'s operator-facing wording, pinned by a test rather than by review.
#[test]
fn malformed_floor_reason_says_the_floor_is_malformed() {
    assert_eq!(floor_note("1.6.0"), "");
    assert_eq!(floor_note(""), "");
    let note = floor_note("v1.6.0");
    assert!(!note.is_empty());
    assert!(note.contains("MAJOR.MINOR.PATCH"));
}

/// The embedded-release-key accessor mirrors the build-time env exactly: a build that carried
/// BUSBAR_RELEASE_PUBKEY (CI, and every build in this tree through .cargo/config.toml) embeds a key
/// that parses; a build without it embeds none. Neither state is assumed, so the test is honest in
/// both.
#[test]
fn embedded_key_mirrors_the_build_env() {
    match option_env!("BUSBAR_RELEASE_PUBKEY") {
        Some(hex) if !hex.trim().is_empty() => {
            assert!(embedded_release_pubkey().is_some(), "a build with the key set must embed it");
        }
        _ => assert!(embedded_release_pubkey().is_none(), "a keyless build must embed nothing"),
    }
}

/// `store`/`secret` default to restart-required; `hook`/`auth` default to hot-appliable —
/// derived from `kind`, never plugin-declared.
#[test]
fn kind_restart_default_matches_binding_lifecycle() {
    assert!(kind_restart_default("store"));
    assert!(kind_restart_default("secret"));
    assert!(!kind_restart_default("hook"));
    assert!(!kind_restart_default("auth"));
    // An unrecognized kind fails to the SAFE direction (restart-required), never the
    // hot-appliable one.
    assert!(kind_restart_default("widget"));
}

fn trusted_first_party() -> Verdict {
    Verdict::Trusted {
        publisher: FIRST_PARTY_PUBLISHER.to_string(),
        first_party: true,
    }
}

fn trusted_third_party() -> Verdict {
    Verdict::Trusted {
        publisher: "acme".to_string(),
        first_party: false,
    }
}

fn allowed_unsigned() -> Verdict {
    Verdict::Allowed {
        reason: "dev opt-in".to_string(),
        allow: AllowReason::Unsigned,
    }
}

/// The override direction that INCREASES caution (`true` against a `false` kind default) is
/// ALWAYS honored, regardless of trust — the safe direction to be wrong in.
#[test]
fn restart_override_to_true_is_always_honored() {
    for verdict in [
        trusted_first_party(),
        trusted_third_party(),
        allowed_unsigned(),
    ] {
        assert!(effective_restart_required("hook", Some(true), &verdict));
        assert!(effective_restart_required("auth", Some(true), &verdict));
    }
}

/// The override direction that DECREASES caution (`false` against a `true` kind default) is
/// honored ONLY for a trusted, first-party (`publisher == "busbar"`) manifest — the exact same
/// trust+publisher gate `schema_derived`'s load-bearing rule uses. A
/// trusted THIRD-PARTY publisher, or an unsigned/allowed artifact, does NOT clear the gate —
/// `publisher` alone is never sufficient; only `Verdict::Trusted { first_party: true, .. }` does.
#[test]
fn restart_override_to_false_requires_trusted_first_party() {
    assert!(
        !effective_restart_required("store", Some(false), &trusted_first_party()),
        "trusted first-party clears the gate: the false override is honored"
    );
    assert!(
        effective_restart_required("store", Some(false), &trusted_third_party()),
        "trusted THIRD-PARTY does not clear the gate: kind default (true) is enforced"
    );
    assert!(
        effective_restart_required("secret", Some(false), &allowed_unsigned()),
        "an unsigned/allowed artifact does not clear the gate: kind default enforced"
    );
}

/// With no per-field override, the kind default applies unconditionally (trust is irrelevant
/// when there is nothing to override).
#[test]
fn restart_no_override_uses_kind_default_regardless_of_trust() {
    assert!(effective_restart_required(
        "store",
        None,
        &allowed_unsigned()
    ));
    assert!(!effective_restart_required(
        "hook",
        None,
        &allowed_unsigned()
    ));
}

/// A `false` override against an ALREADY hot-appliable kind default changes nothing observable
/// (there is no restart-required claim being weakened), so it is honored regardless of trust —
/// this is not the silent-data-loss direction the asymmetry guards against.
#[test]
fn restart_override_to_false_against_hot_default_is_a_no_op_honored_unconditionally() {
    assert!(!effective_restart_required(
        "hook",
        Some(false),
        &allowed_unsigned()
    ));
}

// ── manifest `host` disambiguates sibling products that share this exact plugin ABI ─────────

/// BACKWARD COMPAT: a manifest with no `host` field at all (every manifest packed before this
/// field existed — real packed tarballs, not just an in-memory struct) still parses AND still
/// passes structural validation. Deserializes from raw JSON (not `Manifest { .. }` literal
/// syntax) so this actually proves the wire format, not just that the Rust default exists.
#[test]
fn manifest_with_no_host_field_parses_and_loads() {
    let key = test_key(1);
    let artifact = b"pre-existing manifest bytes";
    let json = r#"{
            "name": "busbar-store-valkey-plugin",
            "alias": "valkey",
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
    let m: Manifest = serde_json::from_str(json).expect("manifest with no host field parses");
    assert_eq!(m.host, None, "absent host deserializes to None");
    let m = sign(&key, m, artifact);
    validate_structure(&m, artifact, &abi, HOST_IDENTITY)
        .expect("a manifest with no host field must still pass structural validation");
}

/// A manifest that EXPLICITLY declares `host: busbar` (this binary's own identity) loads
/// exactly like an absent `host` — the field is additive, not merely tolerated when omitted.
#[test]
fn manifest_with_host_busbar_loads() {
    let key = test_key(1);
    let artifact = b"same-host bytes";
    let mut m = manifest("busbar-store-valkey-plugin", "valkey", "acme");
    m.host = Some(HOST_IDENTITY.to_string());
    let m = sign(&key, m, artifact);
    validate_structure(&m, artifact, &abi, HOST_IDENTITY)
        .expect("host: busbar matches this binary's own identity and must load");
}

/// THE ACTUAL SAFETY PROPERTY: a manifest declaring a DIFFERENT host (e.g. `busbar-ui`, the
/// sibling product that reuses this identical six-symbol ABI and signed-manifest shape) is
/// REJECTED at structural validation — not silently ignored. This is what stops a busbar-ui
/// `store` plugin (tenants/deployments) from `dlopen`ing into the engine and answering `store`
/// calls with the wrong payload contract (keys/denylists) after passing the ABI handshake.
/// Runs even on a VALIDLY SIGNED manifest, proving this is a structural (phase 1) gate that
/// trust cannot override.
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

    // Not just structural: even a manifest that WOULD verify as trusted first-party never
    // reaches `evaluate` in the real pipeline, because `registry.rs::examine` runs
    // `validate_structure` (phase 1) before `evaluate` (phase 2, trust) — a foreign host never
    // gets a chance to be laundered through a loose trust posture.
    let pol = policy(Some(&key), &[], true, true);
    assert!(
        validate_structure(&m, artifact, &abi, HOST_IDENTITY).is_err(),
        "the host gate is structural and does not consult TrustPolicy at all"
    );
    let _ = pol; // constructed only to make the "trust cannot help" point explicit above
}

/// A `host` value that is neither absent, `busbar`, nor a recognizable other product string
/// (garbage / typo) is rejected the same way as a deliberately foreign host — there is no
/// third "unknown, so allow" outcome.
#[test]
fn manifest_with_garbage_host_is_rejected() {
    let key = test_key(1);
    let artifact = b"garbage-host bytes";
    let mut m = manifest("acme-p", "p", "acme");
    m.host = Some("Busbar".to_string()); // case mismatch is still not an exact match
    let m = sign(&key, m, artifact);
    assert!(validate_structure(&m, artifact, &abi, HOST_IDENTITY).is_err());
}

/// REGRESSION GUARD: `host_identity` must be the parameter `validate_structure` actually
/// consults, not a decorative signature widening that still checks against a hardcoded
/// `HOST_IDENTITY` const internally. Every OTHER test in this file passes `HOST_IDENTITY`
/// verbatim, so none of them can tell the difference between "the parameter is load-bearing"
/// and "the parameter is ignored" — a manifest whose `host` is `busbar-ui`, validated by a
/// caller whose own identity IS `busbar-ui`, must load; the identical manifest validated by a
/// caller whose identity is `busbar` (this binary's own `HOST_IDENTITY`) must not. If a future
/// change reverted the body to compare against `HOST_IDENTITY` instead of the parameter, this
/// test is the one that would catch it — every other host test in this file would still pass.
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

/// An ABSENT `host` matches ANY caller's identity (the field is additive/backward-compatible —
/// see `manifest_with_no_host_field_parses_and_loads`), regardless of which host_identity is
/// passed. Proves the "absent means match" branch doesn't secretly special-case `HOST_IDENTITY`.
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
