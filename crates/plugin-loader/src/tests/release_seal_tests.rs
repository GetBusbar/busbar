// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::release_trust::tests::{
    checks, entry, keys_doc, seal_keys, seal_targets, targets_doc, TestSigner, NOW,
};
use crate::release_trust::{wire, PLUGIN_TARGET};

const LIB: &[u8] = b"\x7fELF the plugin library";

fn unsealed() -> Manifest {
    Manifest {
        name: "busbar-store-alpha".into(),
        alias: "alpha".into(),
        kind: "store".into(),
        version: "1.6.0".into(),
        publisher: FIRST_PARTY_PUBLISHER.into(),
        abi_version: 1,
        sha256: sha256_hex(LIB),
        ..Manifest::default()
    }
}

fn listed(m: &Manifest) -> String {
    sha256_hex(&canonical_manifest_bytes(m))
}

struct Release {
    kms: TestSigner,
    piv: TestSigner,
    signer: TestSigner,
}

impl Release {
    fn new() -> Self {
        Release {
            kms: TestSigner::p256(),
            piv: TestSigner::p256(),
            signer: TestSigner::p256(),
        }
    }

    fn policy(&self) -> TrustPolicy {
        TrustPolicy {
            first_party_keys: vec![
                self.kms.root("busbar-plugins-root"),
                self.piv.root("busbar-plugins-2026a"),
            ],
            release_clock: Some(checks().now),
            ..TrustPolicy::default()
        }
    }

    fn seal(
        &self,
        m: Manifest,
        keys: &crate::release_trust::KeysDoc,
        root: &TestSigner,
        entries: Vec<crate::release_trust::Target>,
        by: &TestSigner,
    ) -> Manifest {
        let keys = seal_keys(keys, &[root]);
        let targets = seal_targets(&targets_doc(entries), &[by]);
        Manifest {
            signature: wire::write_seal(&keys, &targets).unwrap(),
            ..m
        }
    }

    fn good(&self, m: Manifest, root: &TestSigner) -> Manifest {
        let e = entry(&m.name, &m.version, PLUGIN_TARGET, &listed(&m));
        self.seal(m, &keys_doc(&[&self.signer]), root, vec![e], &self.signer)
    }
}

fn first_party() -> Verdict {
    Verdict::Trusted {
        publisher: FIRST_PARTY_PUBLISHER.into(),
        first_party: true,
    }
}

#[track_caller]
fn refused(r: Result<Verdict, Rejected>, kind: RejectKind, code: &str) -> Rejected {
    let e = r.expect_err("refused");
    assert_eq!(e.kind, kind, "{}", e.reason);
    assert!(
        e.reason.contains(&format!("({code})")),
        "the reason names the audit code {code}: {}",
        e.reason
    );
    e
}

#[test]
fn a_plugin_sealed_under_the_kms_root_loads_as_first_party() {
    let r = Release::new();
    let m = r.good(unsealed(), &r.kms);
    assert_eq!(evaluate(LIB, &m, &r.policy()), Ok(first_party()));
}

#[test]
fn a_plugin_sealed_under_the_piv_root_loads_as_first_party() {
    let r = Release::new();
    let m = r.good(unsealed(), &r.piv);
    assert_eq!(evaluate(LIB, &m, &r.policy()), Ok(first_party()));
}

#[test]
fn a_tampered_plugin_byte_is_refused() {
    let r = Release::new();
    let m = r.good(unsealed(), &r.kms);

    let mut lib = LIB.to_vec();
    lib[5] ^= 1;
    let e = evaluate(&lib, &m, &r.policy()).expect_err("refused");
    assert_eq!(e.kind, RejectKind::Tampered, "{}", e.reason);

    let repinned = Manifest {
        sha256: sha256_hex(&lib),
        ..m
    };
    refused(
        evaluate(&lib, &repinned, &r.policy()),
        RejectKind::Tampered,
        "hash-mismatch",
    );
}

#[test]
fn a_plugin_the_release_does_not_list_is_refused() {
    let r = Release::new();
    let other = Manifest {
        name: "busbar-store-beta".into(),
        alias: "beta".into(),
        ..unsealed()
    };
    let e = entry(&other.name, &other.version, PLUGIN_TARGET, &listed(&other));
    let m = r.seal(
        unsealed(),
        &keys_doc(&[&r.signer]),
        &r.kms,
        vec![e],
        &r.signer,
    );
    let e = refused(
        evaluate(LIB, &m, &r.policy()),
        RejectKind::Tampered,
        "not-in-release",
    );
    assert!(
        e.reason
            .contains("does not list 'busbar-store-alpha' version 1.6.0"),
        "{}",
        e.reason
    );
}

#[test]
fn a_release_signed_by_an_unlisted_key_is_refused() {
    let r = Release::new();
    let stranger = TestSigner::p256();

    let m = unsealed();
    let e = entry(&m.name, &m.version, PLUGIN_TARGET, &listed(&m));
    let m = r.seal(
        m,
        &keys_doc(&[&r.signer]),
        &r.kms,
        vec![e.clone()],
        &stranger,
    );
    refused(
        evaluate(LIB, &m, &r.policy()),
        RejectKind::Tampered,
        "release-signature",
    );

    let m = r.seal(
        unsealed(),
        &keys_doc(&[&stranger]),
        &stranger,
        vec![e],
        &stranger,
    );
    let e = refused(
        evaluate(LIB, &m, &r.policy()),
        RejectKind::Tampered,
        "keys-signature",
    );
    assert_eq!(
        e.trusted_keys,
        ["busbar-plugins-root", "busbar-plugins-2026a"]
    );
}

#[test]
fn a_plugin_listed_for_another_target_is_refused() {
    let r = Release::new();
    let m = unsealed();
    let e = entry(
        &m.name,
        &m.version,
        "riscv64gc-unknown-linux-gnu",
        &listed(&m),
    );
    let m = r.seal(m, &keys_doc(&[&r.signer]), &r.kms, vec![e], &r.signer);
    let e = refused(
        evaluate(LIB, &m, &r.policy()),
        RejectKind::Tampered,
        "wrong-target",
    );
    assert!(e.reason.contains(PLUGIN_TARGET), "{}", e.reason);
}

#[test]
fn installing_a_plugin_whose_keys_document_has_expired_is_refused() {
    for allow_untrusted in [false, true] {
        let r = Release::new();
        let m = r.good(unsealed(), &r.kms);
        let install = TrustPolicy {
            release_clock: Some(NOW + 91 * 86_400),
            release_enforce_expiry: true,
            allow_untrusted,
            ..r.policy()
        };
        refused(
            evaluate(LIB, &m, &install),
            RejectKind::Tampered,
            "keys-expired",
        );
    }
}

#[test]
fn an_installed_plugin_whose_documents_have_since_expired_still_loads_at_boot() {
    for allow_untrusted in [false, true] {
        let r = Release::new();
        let m = r.good(unsealed(), &r.kms);
        let boot = TrustPolicy {
            release_clock: Some(NOW + 2 * 365 * 86_400),
            allow_untrusted,
            ..r.policy()
        };
        assert!(!boot.release_enforce_expiry, "boot is the default posture");
        assert_eq!(evaluate(LIB, &m, &boot), Ok(first_party()));
    }
}

#[test]
fn a_revocation_is_refused_at_boot_though_the_keys_document_has_expired() {
    for allow_untrusted in [false, true] {
        let r = Release::new();
        let boot = TrustPolicy {
            release_clock: Some(NOW + 365 * 86_400),
            allow_untrusted,
            ..r.policy()
        };
        let m = unsealed();
        let e = entry(&m.name, &m.version, PLUGIN_TARGET, &listed(&m));
        let mut keys = keys_doc(&[&r.signer]);
        keys.revoked_digests.insert(listed(&m), "pulled".into());
        let sealed = r.seal(m.clone(), &keys, &r.kms, vec![e.clone()], &r.signer);
        refused(
            evaluate(LIB, &sealed, &boot),
            RejectKind::Revoked,
            "digest-revoked",
        );
        let mut keys = keys_doc(&[&r.signer]);
        keys.revoked_keyids.insert(r.signer.id());
        let sealed = r.seal(m, &keys, &r.kms, vec![e], &r.signer);
        refused(
            evaluate(LIB, &sealed, &boot),
            RejectKind::Revoked,
            "signer-revoked",
        );
    }
}

#[test]
fn a_revoked_artefact_is_refused_whatever_the_operator_opted_in_to() {
    let r = Release::new();
    let m = unsealed();
    let mut keys = keys_doc(&[&r.signer]);
    keys.revoked_digests
        .insert(listed(&m), "pulled for a defect".into());
    let e = entry(&m.name, &m.version, PLUGIN_TARGET, &listed(&m));
    let m = r.seal(m, &keys, &r.kms, vec![e], &r.signer);
    let open = TrustPolicy {
        allow_untrusted: true,
        ..r.policy()
    };
    refused(
        evaluate(LIB, &m, &open),
        RejectKind::Revoked,
        "digest-revoked",
    );
}

#[test]
fn a_revoked_signer_is_refused_whatever_the_operator_opted_in_to() {
    let r = Release::new();
    let m = unsealed();
    let mut keys = keys_doc(&[&r.signer]);
    keys.revoked_keyids.insert(r.signer.id());
    let e = entry(&m.name, &m.version, PLUGIN_TARGET, &listed(&m));
    let m = r.seal(m, &keys, &r.kms, vec![e], &r.signer);
    let open = TrustPolicy {
        allow_untrusted: true,
        ..r.policy()
    };
    refused(
        evaluate(LIB, &m, &open),
        RejectKind::Revoked,
        "signer-revoked",
    );
}

#[test]
fn a_rolled_back_keys_document_is_refused_whatever_the_operator_opted_in_to() {
    let r = Release::new();
    let m = r.good(unsealed(), &r.kms);
    let floored = TrustPolicy {
        release_keys_floor: 2,
        allow_untrusted: true,
        ..r.policy()
    };
    refused(
        evaluate(LIB, &m, &floored),
        RejectKind::AntiDowngrade,
        "keys-rollback",
    );
}

#[test]
fn a_seal_is_read_back_from_the_manifest_signature() {
    let r = Release::new();
    let m = r.good(unsealed(), &r.kms);
    assert!(m.signature.starts_with(wire::SEAL_PREFIX));
    assert_eq!(wire::sealed_keys_version(&m.signature), Some(1));
    assert_eq!(
        canonical_manifest_bytes(&m),
        canonical_manifest_bytes(&unsealed()),
        "sealing never changes the bytes the release lists"
    );
    assert!(
        wire::read_seal("ab".repeat(64).as_str()).is_none(),
        "a per-plugin signature is not a seal"
    );
}

#[test]
fn only_an_authenticated_trusted_seal_returns_store_floor_evidence() {
    let r = Release::new();
    let sealed = r.good(unsealed(), &r.kms);
    let (verdict, version) = evaluate_with_evidence(LIB, &sealed, &r.policy()).unwrap();
    assert_eq!(verdict, first_party());
    assert_eq!(version, Some(keys_doc(&[&r.signer]).version));

    let mut malformed = sealed;
    malformed.signature.push('!');
    let allowed = TrustPolicy {
        allow_untrusted: true,
        ..r.policy()
    };
    assert!(
        evaluate_with_evidence(LIB, &malformed, &allowed).is_err(),
        "malformed Busbar seals never use the override"
    );
    let key = SigningKey::from_bytes(&[83; 32]);
    let raw = sign(&key, unsealed(), LIB);
    for allow_untrusted in [false, true] {
        let legacy = TrustPolicy {
            first_party_key: Some(key.verifying_key()),
            allow_untrusted,
            ..TrustPolicy::default()
        };
        assert!(
            evaluate_with_evidence(LIB, &raw, &legacy).is_err(),
            "bare Busbar root signatures produce no admission or floor evidence"
        );
    }
}

#[test]
fn expired_install_checks_cannot_mask_hard_revocation_or_rollback_vetoes() {
    for allow_untrusted in [false, true] {
        for release_enforce_expiry in [false, true] {
            let r = Release::new();
            let m = unsealed();
            let e = entry(&m.name, &m.version, PLUGIN_TARGET, &listed(&m));
            let expired = TrustPolicy {
                release_clock: Some(NOW + 365 * 86_400),
                release_enforce_expiry,
                allow_untrusted,
                ..r.policy()
            };

            let mut keys = keys_doc(&[&r.signer]);
            keys.revoked_digests.insert(listed(&m), "pulled".into());
            let sealed = r.seal(m.clone(), &keys, &r.kms, vec![e.clone()], &r.signer);
            refused(
                evaluate(LIB, &sealed, &expired),
                RejectKind::Revoked,
                "digest-revoked",
            );

            let mut keys = keys_doc(&[&r.signer]);
            keys.revoked_keyids.insert(r.signer.id());
            let sealed = r.seal(m.clone(), &keys, &r.kms, vec![e], &r.signer);
            refused(
                evaluate(LIB, &sealed, &expired),
                RejectKind::Revoked,
                "signer-revoked",
            );

            let sealed = r.good(m, &r.kms);
            let floored = TrustPolicy {
                release_keys_floor: 2,
                ..expired.clone()
            };
            refused(
                evaluate(LIB, &sealed, &floored),
                RejectKind::AntiDowngrade,
                "keys-rollback",
            );
            if release_enforce_expiry {
                assert!(
                    evaluate_with_evidence(LIB, &sealed, &expired).is_err(),
                    "an expired prospective Busbar seal never uses the override"
                );
            } else {
                assert_eq!(
                    evaluate_with_evidence(LIB, &sealed, &expired),
                    Ok((first_party(), Some(1))),
                    "installed boot still authenticates the expired seal"
                );
            }
        }
    }
}

#[test]
fn retired_root_refusals_remain_hard_policy_vetoes() {
    let refusal = crate::release_trust::SealRefusal::RetiredRoot {
        id: "retired".into(),
        why: "permanently retired signing material".into(),
    };
    assert_eq!(hard_seal_refusal(&refusal), Some(RejectKind::RetiredKey));
}

#[test]
fn permanently_retired_delegated_signers_remain_hard_policy_vetoes() {
    let refusal = crate::release_trust::SealRefusal::RetiredSigner {
        id: "retired-delegate".into(),
        why: "permanently retired signing material".into(),
    };
    assert_eq!(hard_seal_refusal(&refusal), Some(RejectKind::RetiredKey));
}

#[test]
fn malformed_release_key_spec_surfaces_its_parse_error_p29_craft_0() {
    assert!(release_key_parse_error(None).is_none());
    let msg = release_key_parse_error(Some("not-a-key")).expect("bad spec yields its error");
    assert!(!msg.is_empty());
}

/// Live release-crypto behaviour, driven through the one Standard path only (ported from the
/// provider-seam suite so the cases outlive the seam).
mod standard_crypto {
    use crate::release_trust::tests::{
        checks, entry, keys_doc, seal_keys, seal_targets, targets_doc, TestSigner, NOW,
    };
    use crate::release_trust::{
        self, wire, KeysDoc, ReleaseKey, Seal, Subject, TargetsDoc, PLUGINS_ROLE, PLUGIN_TARGET,
    };
    use crate::sign::{self, FirstPartyKey, Manifest, RejectKind, TrustPolicy, Verdict};

    const LIB: &[u8] = b"exact library bytes signed by a release";

    fn manifest() -> Manifest {
        Manifest {
            name: "busbar-store-provider".into(),
            alias: "provider".into(),
            kind: "store".into(),
            publisher: sign::FIRST_PARTY_PUBLISHER.into(),
            version: "1.6.0".into(),
            abi_version: 1,
            sha256: sign::sha256_hex(LIB),
            ..Manifest::default()
        }
    }

    struct Chain {
        roots: Vec<TestSigner>,
        signers: Vec<TestSigner>,
        keys: KeysDoc,
        targets: TargetsDoc,
    }

    impl Chain {
        fn new(p256: bool) -> Self {
            let make = |seed| {
                if p256 {
                    TestSigner::p256()
                } else {
                    TestSigner::ed25519(seed)
                }
            };
            let roots = vec![make(31), make(32)];
            let signers = vec![make(33), make(34)];
            let mut keys = keys_doc(&signers.iter().collect::<Vec<_>>());
            keys.roles.get_mut(PLUGINS_ROLE).unwrap().threshold = 2;
            let m = manifest();
            let targets = targets_doc(vec![entry(
                &m.name,
                &m.version,
                PLUGIN_TARGET,
                &sign::sha256_hex(&sign::canonical_manifest_bytes(&m)),
            )]);
            Self {
                roots,
                signers,
                keys,
                targets,
            }
        }
        fn roots(&self) -> Vec<FirstPartyKey> {
            self.roots
                .iter()
                .enumerate()
                .map(|(i, s)| s.root(&format!("root-{i}")))
                .collect()
        }
        fn policy(&self) -> TrustPolicy {
            TrustPolicy {
                first_party_keys: self.roots(),
                release_clock: Some(NOW),
                release_enforce_expiry: true,
                ..TrustPolicy::default()
            }
        }
        fn documents(&self) -> (Vec<u8>, Vec<u8>) {
            (
                seal_keys(&self.keys, &self.roots.iter().collect::<Vec<_>>()),
                seal_targets(&self.targets, &self.signers.iter().collect::<Vec<_>>()),
            )
        }
        fn manifest(&self) -> Manifest {
            let (keys, targets) = self.documents();
            Manifest {
                signature: wire::write_seal(&keys, &targets).unwrap(),
                ..manifest()
            }
        }
        fn subject<'a>(&self, m: &'a Manifest, digest: &'a str) -> Subject<'a> {
            Subject {
                name: &m.name,
                version: &m.version,
                target: PLUGIN_TARGET,
                sha256: digest,
                lib_sha256: &m.sha256,
            }
        }
    }

    fn bytes<const N: usize>(value: &str) -> [u8; N] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    fn ed25519(value: &str) -> Option<ReleaseKey> {
        crate::sign::VerifyingKey::from_bytes(&bytes(value))
            .ok()
            .map(ReleaseKey::Ed25519)
    }

    #[test]
    fn ed25519_and_p256_chains_keep_evidence_and_signer() {
        for p256 in [false, true] {
            let c = Chain::new(p256);
            let m = c.manifest();
            let (verdict, version) = sign::evaluate_with_evidence(LIB, &m, &c.policy()).unwrap();
            assert!(matches!(
                verdict,
                Verdict::Trusted {
                    first_party: true,
                    ..
                }
            ));
            assert_eq!(version, Some(c.keys.version));
            let roots = c.roots();
            let (keys, targets) = c.documents();
            let seal = Seal {
                keys: &keys,
                targets: &targets,
            };
            let digest = sign::sha256_hex(&sign::canonical_manifest_bytes(&m));
            let verified =
                release_trust::verify_release(&roots, seal, c.subject(&m, &digest), checks());
            assert!(verified.is_ok(), "{verified:?}");
            let signer =
                sign::first_party_signer_for(&m, LIB, &roots, checks(), PLUGIN_TARGET).unwrap();
            assert!(roots.iter().any(|r| r.id == signer.id));
        }
    }

    #[test]
    fn expiry_rollback_revocation_and_tampering_are_refused() {
        for p256 in [false, true] {
            for case in 0..11 {
                let mut c = Chain::new(p256);
                let mut policy = c.policy();
                match case {
                    0 => c.keys.expires = NOW,
                    1 => c.targets.expires = NOW,
                    2 => policy.release_keys_floor = c.keys.version + 1,
                    3 => {
                        c.keys
                            .revoked_digests
                            .insert(manifest().sha256, "revoked library".into());
                    }
                    4 => {
                        c.keys.revoked_digests.insert(
                            c.targets.targets[0].sha256.clone(),
                            "revoked manifest".into(),
                        );
                    }
                    5 => {
                        c.keys.revoked_keyids.insert(c.signers[0].id());
                    }
                    6 => c.keys.roles.get_mut(PLUGINS_ROLE).unwrap().threshold = 0,
                    7 => c.targets.role = "another-role".into(),
                    8 => c.targets.targets[0].target = "another-target".into(),
                    9 => {
                        policy
                            .first_party_high_water
                            .insert(manifest().name, "1.7.0".into());
                    }
                    10 => {
                        policy.min_versions.insert(manifest().name, "1.7.0".into());
                    }
                    _ => unreachable!(),
                }
                let m = c.manifest();
                assert!(
                    sign::evaluate_with_evidence(LIB, &m, &policy).is_err(),
                    "case {case}"
                );
            }
            let c = Chain::new(p256);
            let m = c.manifest();
            for (bytes, altered) in [
                (&b"other library"[..], m.clone()),
                (
                    LIB,
                    Manifest {
                        version: "9.0.0".into(),
                        ..m.clone()
                    },
                ),
                (
                    &b"other library"[..],
                    Manifest {
                        sha256: sign::sha256_hex(b"other library"),
                        ..m
                    },
                ),
            ] {
                assert!(sign::evaluate_with_evidence(bytes, &altered, &c.policy()).is_err());
            }
        }
    }

    #[test]
    fn invalid_and_duplicate_signatures_earn_no_threshold_credit() {
        let c = Chain::new(false);
        let (keys, targets) = c.documents();
        let mut doc: serde_json::Value = serde_json::from_slice(&targets).unwrap();
        let mut policy = c.policy();
        for duplicate in [false, true] {
            if duplicate {
                doc["signatures"][1] = doc["signatures"][0].clone();
            } else {
                doc["signatures"][1]["sig"] = serde_json::json!("00".repeat(64));
            }
            let targets = serde_json::to_vec(&doc).unwrap();
            let m = Manifest {
                signature: wire::write_seal(&keys, &targets).unwrap(),
                ..manifest()
            };
            let result = sign::evaluate_with_evidence(LIB, &m, &policy);
            assert!(matches!(result, Err(ref e) if e.kind == RejectKind::Tampered));
            policy.allow_untrusted = true;
            let result = sign::evaluate_with_evidence(LIB, &m, &policy);
            assert!(matches!(result, Err(ref e) if e.kind == RejectKind::Tampered));
            policy.allow_untrusted = false;
        }
    }

    #[test]
    fn expired_chains_do_not_hide_hard_refusals() {
        let mut c = Chain::new(false);
        c.keys.expires = NOW;
        c.keys
            .revoked_digests
            .insert(manifest().sha256, "revoked".into());
        let m = c.manifest();
        let mut policy = c.policy();
        policy.allow_untrusted = true;
        assert!(matches!(
            sign::evaluate_with_evidence(LIB, &m, &policy),
            Err(e) if e.kind == RejectKind::Revoked
        ));
    }

    #[test]
    fn weak_keys_and_malleable_signatures_are_refused() {
        let mut forged = [0; 64];
        forged[0] = 1;
        for encoded in [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "0200000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert!(sign::public_key_from_hex(encoded).is_err(), "{encoded}");
        }
        for encoded in [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            if let Some(key) = ed25519(encoded) {
                assert!(
                    !wire::verify(&key, b"any message", &forged).unwrap(),
                    "{encoded}"
                );
            }
        }
        let key =
            ed25519("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
        let signature = bytes::<64>(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f",
            "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ));
        assert!(wire::verify(&key, b"", &signature).unwrap());
        for scalar in [
            bytes::<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"),
            bytes("4c8c7872aa064e049dbb3013fbf29380d25bf5f0595bbe24655141438e7a101b"),
            [255; 32],
        ] {
            let mut bad = signature;
            bad[32..].copy_from_slice(&scalar);
            assert!(!wire::verify(&key, b"", &bad).unwrap());
        }
        let small_r = bytes::<64>(concat!(
            "0100000000000000000000000000000000000000000000000000000000000000",
            "be6ea3b30c95cf09aa095e2bbdd3d0ba5277670ebfab1b959653b0d80a614f0c"
        ));
        assert!(!wire::verify(&key, b"low-order-r-canary", &small_r).unwrap());
        for sig in [
            vec![],
            signature[..63].to_vec(),
            [signature.as_slice(), &[0]].concat(),
        ] {
            assert!(!wire::verify(&key, b"", &sig).unwrap());
        }
    }

    // Fixed independent fixtures: for each nonzero torsion T_i, A=B+T_i and R=2B+T_i are
    // nonweak, non-prime-subgroup points with [S]B-[k]A=R.
    const MIXED: [(&str, &str, &str); 7] = [("98519eadf35b995233b51b5cd23e9cc5a28b639b5a4af0ec903cb960d81b7819", "mixed-order-1-9", "e6ff0e4955925b2100e8ceebbd4ffe93e6fdfc71c226b33409a570d916254f7229ecba287ba75e7be6c01c4f5187891b1fbc30e1e682a3a89f0d58c33c1b800f"),
    ("9bad33f580df7ecc49df5342bac8145d5bedc40f573d1b067f3c4ce449689a15", "mixed-order-2-4", "e4dd22778010b28a10d0ddcf35d7a144216299cbe36ba86b31952ef0a294176ed9309aa49fd75c9c08d6ea572db496514a78f947f4e219437bf269312abc0b06"),
    ("da99e28ba529cdde35a25fba9059e78ecaee239f99755b9b1aa4f65df00803e2", "mixed-order-3-4", "543ac908ca97124ab06caab11552257e53aba22a4e66b769175823a19a0452e0017d382a709cb9fd31c0587a0b76adf39f9197418b97d6e9c6261e664fb3610a"),
    ("9599999999999999999999999999999999999999999999999999999999999999", "mixed-order-4-2", "245c079551b9a0f1a9aec79baef0c668a9e05d3617a15de23dd6dcf60c329fdd0f53f4592c59c427204fc14726dee3f05774824c2572c57d581600f8162a6a03"),
    ("55ae61520ca466adcc4ae4a32dc1633a5d749c64a5b50f136fc3469f27e487e6", "mixed-order-5-5", "0700f1b6aa6da4deff17311442b0016c1902038e3dd94ccbf65a8f26e9dab08d993acf5badc0e3760db163f57c028444fc6ee7f3a37189091318a14b49785508"),
    ("5252cc0a7f208133b620acbd4537eba2a4123bf0a8c2e4f980c3b31bb69765ea", "mixed-order-6-2", "0922dd887fef4d75ef2f2230ca285ebbde9d66341c945794ce6ad10f5d6be8911154329328422afe11aaa0c57beaf6f456ff26904ba8e8208ecfb53539df2e0c"),
    ("13661d745ad63221ca5da0456fa618713511dc60668aa464e55b09a20ff7fc1d", "mixed-order-7-21", "99c536f73568edb54f93554eeaadda81ac545dd5b1994896e8a7dc5e65fbad1fa9005cb81af44ea4baf80bdcab2be2990fcd5aca99b3c393918649fde850610f")];

    #[test]
    fn strict_mixed_order_nonweak_keys_and_r_stay_accepted() {
        for (public, message, sig) in MIXED {
            let key = ed25519(public).unwrap();
            let signature = bytes::<64>(sig);
            assert!(wire::verify(&key, message.as_bytes(), &signature).unwrap());
            assert!(!wire::verify(&key, b"wrong message", &signature).unwrap());
        }
    }

    #[test]
    fn retired_roots_are_never_vouching_roots() {
        let c = Chain::new(false);
        let retired = sign::public_key_from_hex(sign::RETIRED_RELEASE_KEYS[0].0).unwrap();
        let retired_key = ReleaseKey::Ed25519(retired);
        assert!(retired_key.retired_reason().is_some());
        let retired_id = wire::key_id(&retired_key);
        let (keys, targets) = c.documents();
        let mut doc: serde_json::Value = serde_json::from_slice(&keys).unwrap();
        doc["signatures"] = serde_json::json!([{"keyid": retired_id, "sig": "00".repeat(64)}]);
        let retired_keys = serde_json::to_vec(&doc).unwrap();
        let m = manifest();
        let digest = sign::sha256_hex(&sign::canonical_manifest_bytes(&m));
        let roots = [FirstPartyKey {
            id: "retired".into(),
            key: retired_key,
        }];
        assert!(release_trust::verify_release(
            &roots,
            Seal {
                keys: &retired_keys,
                targets: &targets
            },
            c.subject(&m, &digest),
            checks(),
        )
        .is_err());
    }

    #[test]
    fn p256_keeps_der_signatures_and_hashes_the_original_message_once() {
        let signer = TestSigner::p256();
        let key = signer.key();
        let message = b"P-256 signed original message";
        let sig = signer.sign(message);
        assert!(wire::verify(&key, message, &sig).unwrap());
        let digest = busbar_contract::abi::sdk::digest::sha256(message);
        assert!(!wire::verify(&key, &digest, &sig).unwrap());
        for malformed in [
            vec![],
            vec![0; 64],
            sig[..sig.len() - 1].to_vec(),
            [sig.as_slice(), &[0]].concat(),
        ] {
            assert!(!wire::verify(&key, message, &malformed).unwrap());
        }
    }

    #[test]
    fn structure_validation_hashes_the_exact_library() {
        let m = manifest();
        let abi = |_: &str| Some(1);
        assert_eq!(sign::validate_structure(&m, LIB, &abi, "busbar"), Ok(()));
        assert!(sign::validate_structure(&m, b"wrong library", &abi, "busbar").is_err());
    }

    #[test]
    fn concrete_public_types_build_without_annotations() {
        let p = TrustPolicy {
            allow_untrusted: true,
            ..Default::default()
        };
        assert!(p.allow_untrusted);
        assert!(!TrustPolicy::default().allow_untrusted);
        let d = KeysDoc {
            version: 7,
            ..Default::default()
        };
        assert_eq!(d.version, 7);
        assert_eq!(KeysDoc::default().version, 0);
        let r = FirstPartyKey {
            id: "test".into(),
            key: TestSigner::ed25519(89).key(),
        };
        assert_eq!(r.id, "test");
    }
}
