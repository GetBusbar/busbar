// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::release_trust::tests::{
    checks, entry, keys_doc, seal_keys, seal_targets, targets_doc, TestSigner, NOW,
};
use crate::release_trust::{
    self, wire, KeysDoc, Seal, SealRefusal, Subject, TargetsDoc, PLUGINS_ROLE, PLUGIN_TARGET,
};
use crate::sign::{self, FirstPartyKey, Manifest, RejectKind, TrustPolicy, Verdict};
use std::cell::RefCell;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Hash(Vec<u8>),
    Validate(Vec<u8>),
    Ed25519(Vec<u8>, Vec<u8>),
    P256(Vec<u8>, Vec<u8>),
}

/// A test provider, not a native-module qualification. Valid primitives delegate to the current
/// implementation, with Console's canonical/nonweak public-key floor. Every service is observable
/// and can fail independently, including a service invoked after a threshold was already met.
#[derive(Default)]
struct TraceCrypto {
    calls: RefCell<Vec<Call>>,
    fail_at: Option<usize>,
    accept_signatures: bool,
}
impl TraceCrypto {
    fn call(&self, call: Call) -> Result<(), CryptoUnavailable> {
        let mut calls = self.calls.borrow_mut();
        let index = calls.len();
        calls.push(call);
        if self.fail_at == Some(index) {
            Err(CryptoUnavailable)
        } else {
            Ok(())
        }
    }
}
impl ReleaseCrypto for TraceCrypto {
    fn sha256(&self, bytes: &[u8]) -> Result<[u8; 32], CryptoUnavailable> {
        self.call(Call::Hash(bytes.to_vec()))?;
        StandardCrypto.sha256(bytes)
    }
    fn validate_public_key(&self, key: PublicKey<'_>) -> Result<bool, CryptoUnavailable> {
        self.call(Call::Validate(match key {
            PublicKey::Ed25519(k) => k.to_vec(),
            PublicKey::P256(k) => k.to_vec(),
        }))?;
        Ok(match key {
            PublicKey::Ed25519(k) => ed25519_dalek::VerifyingKey::from_bytes(k)
                .is_ok_and(|v| !v.is_weak() && v.to_edwards().compress().to_bytes() == *k),
            PublicKey::P256(k) => {
                // Validate the curve point independently of whether a particular signature is
                // valid. ring's agreement service performs the complete P-256 point check.
                let private = ring::agreement::EphemeralPrivateKey::generate(
                    &ring::agreement::ECDH_P256,
                    &ring::rand::SystemRandom::new(),
                )
                .unwrap();
                ring::agreement::agree_ephemeral(
                    private,
                    &ring::agreement::UnparsedPublicKey::new(&ring::agreement::ECDH_P256, k),
                    |_| (),
                )
                .is_ok()
            }
        })
    }
    fn verify_ed25519_strict(
        &self,
        key: &[u8; 32],
        msg: &[u8],
        sig: &[u8; 64],
    ) -> Result<bool, CryptoUnavailable> {
        self.call(Call::Ed25519(key.to_vec(), msg.to_vec()))?;
        if self.accept_signatures {
            Ok(true)
        } else {
            StandardCrypto.verify_ed25519_strict(key, msg, sig)
        }
    }
    fn verify_p256_sha256_asn1(
        &self,
        key: &[u8; 65],
        msg: &[u8],
        sig: &[u8],
    ) -> Result<bool, CryptoUnavailable> {
        self.call(Call::P256(key.to_vec(), msg.to_vec()))?;
        if self.accept_signatures {
            Ok(true)
        } else {
            StandardCrypto.verify_p256_sha256_asn1(key, msg, sig)
        }
    }
}

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
    fn standard_roots(&self) -> Vec<FirstPartyKey> {
        self.roots
            .iter()
            .enumerate()
            .map(|(i, s)| s.root(&format!("root-{i}")))
            .collect()
    }
    fn policy(&self) -> TrustPolicy {
        TrustPolicy {
            first_party_keys: self.standard_roots(),
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

#[test]
fn valid_ed25519_and_p256_chains_preserve_evidence_and_all_hash_domains() {
    for p256 in [false, true] {
        let c = Chain::new(p256);
        let m = c.manifest();
        let policy = c.policy();
        let native = TraceCrypto::default();
        let expected = sign::evaluate_with_evidence(LIB, &m, &policy).unwrap();
        assert_eq!(expected.1, Some(c.keys.version));
        assert_eq!(
            sign::evaluate_with_evidence_with_crypto(LIB, &m, &policy.to_raw(), &native),
            Ok(expected)
        );
        let calls = native.calls.borrow();
        assert!(calls.contains(&Call::Hash(LIB.to_vec())));
        assert!(calls.contains(&Call::Hash(sign::canonical_manifest_bytes(&m))));
        for key in c.roots.iter().chain(&c.signers) {
            assert!(calls.contains(&Call::Hash(
                wire::canonical(&wire::key_object(&key.key())).unwrap()
            )));
        }
        drop(calls);
        let roots = c.standard_roots();
        let raw: Vec<_> = roots.iter().map(FirstPartyKey::to_raw).collect();
        let (keys, targets) = c.documents();
        let seal = Seal {
            keys: &keys,
            targets: &targets,
        };
        let digest = sign::sha256_hex(&sign::canonical_manifest_bytes(&m));
        assert_eq!(
            release_trust::verify_release_with_crypto(
                &raw,
                seal,
                c.subject(&m, &digest),
                checks(),
                &native
            ),
            release_trust::verify_release(&roots, seal, c.subject(&m, &digest), checks())
                .map_err(WithCryptoError::Rejected)
        );
        assert_eq!(
            sign::first_party_signer_for_with_crypto(
                &m,
                LIB,
                &raw,
                checks(),
                PLUGIN_TARGET,
                &native
            )
            .unwrap()
            .id,
            sign::first_party_signer_for(&m, LIB, &roots, checks(), PLUGIN_TARGET)
                .unwrap()
                .id
        );
    }
}

#[test]
fn every_provider_failure_aborts_before_next_root_threshold_or_opt_in() {
    for p256 in [false, true] {
        let c = Chain::new(p256);
        let m = c.manifest();
        let mut policy = c.policy().to_raw();
        policy.allow_unsigned = true;
        policy.allow_third_party = true;
        let baseline = TraceCrypto::default();
        assert!(matches!(
            sign::evaluate_with_evidence_with_crypto(LIB, &m, &policy, &baseline),
            Ok((
                Verdict::Trusted {
                    first_party: true,
                    ..
                },
                Some(1)
            ))
        ));
        let calls = baseline.calls.into_inner();
        // This fails each library/canonical/key-ID hash, every document/root key validation and
        // every root->keys / keys->targets signature. All later roots/signers are valid fallback
        // candidates. An unavailable callback must still stop at the exact failing prefix.
        for index in 0..calls.len() {
            let provider = TraceCrypto {
                fail_at: Some(index),
                ..TraceCrypto::default()
            };
            assert_eq!(
                sign::evaluate_with_evidence_with_crypto(LIB, &m, &policy, &provider),
                Err(WithCryptoError::Unavailable(CryptoUnavailable)),
                "failure {index}: {:?}",
                calls[index]
            );
            assert_eq!(*provider.calls.borrow(), calls[..=index]);
        }
    }
}

#[test]
fn final_signer_recheck_and_freshness_propagate_provider_failure() {
    let c = Chain::new(true);
    let m = c.manifest();
    let roots = c.policy().to_raw().first_party_keys;
    let baseline = TraceCrypto::default();
    sign::first_party_signer_for_with_crypto(&m, LIB, &roots, checks(), PLUGIN_TARGET, &baseline)
        .unwrap();
    let calls = baseline.calls.into_inner();
    for index in 0..calls.len() {
        let provider = TraceCrypto {
            fail_at: Some(index),
            ..TraceCrypto::default()
        };
        assert!(matches!(
            sign::first_party_signer_for_with_crypto(
                &m,
                LIB,
                &roots,
                checks(),
                PLUGIN_TARGET,
                &provider
            ),
            Err(WithCryptoError::Unavailable(_))
        ));
        assert_eq!(*provider.calls.borrow(), calls[..=index]);
    }
    let (keys, targets) = c.documents();
    let provider = TraceCrypto {
        fail_at: Some(0),
        ..TraceCrypto::default()
    };
    assert_eq!(
        release_trust::check_fresh_with_crypto(
            Seal {
                keys: &keys,
                targets: &targets
            },
            NOW,
            &provider
        ),
        Err(WithCryptoError::Unavailable(CryptoUnavailable))
    );
}

#[test]
fn policy_refusals_match_standard_for_expiry_rollback_revocation_and_tampering() {
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
            let standard = sign::evaluate_with_evidence(LIB, &m, &policy);
            assert!(standard.is_err(), "case {case}");
            assert_eq!(
                sign::evaluate_with_evidence_with_crypto(
                    LIB,
                    &m,
                    &policy.to_raw(),
                    &TraceCrypto::default()
                ),
                standard.map_err(WithCryptoError::Rejected),
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
            let standard = sign::evaluate_with_evidence(bytes, &altered, &c.policy());
            assert!(standard.is_err());
            assert_eq!(
                sign::evaluate_with_evidence_with_crypto(
                    bytes,
                    &altered,
                    &c.policy().to_raw(),
                    &TraceCrypto::default()
                ),
                standard.map_err(WithCryptoError::Rejected)
            );
        }
    }
}

#[test]
fn invalid_signatures_and_duplicate_signatures_do_not_gain_threshold_credit() {
    let c = Chain::new(false);
    let (keys, targets) = c.documents();
    let mut doc: serde_json::Value = serde_json::from_slice(&targets).unwrap();
    let mut policy = c.policy().to_raw();
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
        let result =
            sign::evaluate_with_evidence_with_crypto(LIB, &m, &policy, &TraceCrypto::default());
        assert!(
            matches!(result, Err(WithCryptoError::Rejected(ref e)) if e.kind == RejectKind::Tampered)
        );
        policy.allow_unsigned = true;
        let result =
            sign::evaluate_with_evidence_with_crypto(LIB, &m, &policy, &TraceCrypto::default());
        assert!(matches!(result, Ok((Verdict::Allowed { .. }, None))));
        policy.allow_unsigned = false;
    }
}

#[test]
fn expired_chains_do_not_hide_hard_refusals_or_provider_failure() {
    let mut c = Chain::new(false);
    c.keys.expires = NOW;
    c.keys
        .revoked_digests
        .insert(manifest().sha256, "revoked".into());
    let m = c.manifest();
    let mut policy = c.policy().to_raw();
    policy.allow_unsigned = true;
    let baseline = TraceCrypto::default();
    assert!(
        matches!(sign::evaluate_with_evidence_with_crypto(LIB, &m, &policy, &baseline),
        Err(WithCryptoError::Rejected(e)) if e.kind == RejectKind::Revoked)
    );
    let calls = baseline.calls.into_inner();
    for index in 0..calls.len() {
        let provider = TraceCrypto {
            fail_at: Some(index),
            ..TraceCrypto::default()
        };
        assert_eq!(
            sign::evaluate_with_evidence_with_crypto(LIB, &m, &policy, &provider),
            Err(WithCryptoError::Unavailable(CryptoUnavailable))
        );
        assert_eq!(*provider.calls.borrow(), calls[..=index]);
    }
}

#[test]
fn legacy_first_party_and_allowlisted_signatures_use_the_same_provider() {
    let signing = sign::SigningKey::from_bytes(&[35; 32]);
    for publisher in [sign::FIRST_PARTY_PUBLISHER, "third-party"] {
        let m = sign::sign(
            &signing,
            Manifest {
                publisher: publisher.into(),
                ..manifest()
            },
            LIB,
        );
        let policy = TrustPolicy {
            first_party_key: Some(signing.verifying_key()),
            publishers: [(publisher.into(), signing.verifying_key())].into(),
            allow_unsigned: true,
            allow_third_party: true,
            ..TrustPolicy::default()
        };
        let baseline = TraceCrypto::default();
        assert_eq!(
            sign::evaluate_with_evidence_with_crypto(LIB, &m, &policy.to_raw(), &baseline),
            sign::evaluate_with_evidence(LIB, &m, &policy).map_err(WithCryptoError::Rejected)
        );
        let calls = baseline.calls.into_inner();
        for index in 0..calls.len() {
            let provider = TraceCrypto {
                fail_at: Some(index),
                ..TraceCrypto::default()
            };
            assert_eq!(
                sign::evaluate_with_evidence_with_crypto(LIB, &m, &policy.to_raw(), &provider),
                Err(WithCryptoError::Unavailable(CryptoUnavailable))
            );
            assert_eq!(*provider.calls.borrow(), calls[..=index]);
        }
    }
}

#[test]
fn native_key_decoders_do_not_construct_dalek_keys_or_hash_outside_provider() {
    struct RawOnly;
    impl ReleaseCrypto for RawOnly {
        fn sha256(&self, _: &[u8]) -> Result<[u8; 32], CryptoUnavailable> {
            Ok([42; 32])
        }
        fn validate_public_key(&self, _: PublicKey<'_>) -> Result<bool, CryptoUnavailable> {
            Ok(true)
        }
        fn verify_ed25519_strict(
            &self,
            _: &[u8; 32],
            _: &[u8],
            _: &[u8; 64],
        ) -> Result<bool, CryptoUnavailable> {
            panic!("decode only")
        }
        fn verify_p256_sha256_asn1(
            &self,
            _: &[u8; 65],
            _: &[u8],
            _: &[u8],
        ) -> Result<bool, CryptoUnavailable> {
            panic!("decode only")
        }
    }
    let mut invalid = [0; 32];
    invalid[0] = 2;
    assert!(ed25519_dalek::VerifyingKey::from_bytes(&invalid).is_err());
    let raw = RawReleaseKey::Ed25519(invalid);
    let roots =
        sign::parse_release_keys_with_crypto(&format!("raw:{}", hex::encode(invalid)), &RawOnly)
            .unwrap();
    assert_eq!(roots[0].key, raw);
    assert_eq!(
        wire::read_key_object_with_crypto(&wire::raw_key_object(&raw), &RawOnly),
        Ok(raw.clone())
    );
    let id = hex::encode([42; 32]);
    assert_eq!(wire::key_id_with_crypto(&raw, &RawOnly), Ok(id.clone()));
    let doc = serde_json::json!({"_type": wire::KEYS_TYPE, "spec_version": wire::SPEC_VERSION,
        "version": 1, "expires": wire::format_time(NOW + 1),
        "keys": {id.clone(): wire::raw_key_object(&raw)}, "roles": {}});
    let bytes = wire::write_envelope(&doc, &[]).unwrap();
    let parsed = wire::read_keys_with_crypto(&bytes, &RawOnly).unwrap();
    assert_eq!(parsed.doc.keys[&id], raw);
    assert!(wire::read_keys(&bytes).is_err());
    let fail = TraceCrypto {
        fail_at: Some(0),
        ..TraceCrypto::default()
    };
    assert_eq!(
        sign::parse_release_keys_with_crypto(&format!("raw:{}", hex::encode(invalid)), &fail),
        Err(WithCryptoError::Unavailable(CryptoUnavailable))
    );
}

#[test]
fn structure_validation_hashes_exact_library_with_selected_provider() {
    let m = manifest();
    let provider = TraceCrypto::default();
    let abi = |_: &str| &([1][..]);
    assert_eq!(
        sign::validate_structure_with_crypto(&m, LIB, &abi, "busbar", &provider),
        Ok(())
    );
    assert_eq!(*provider.calls.borrow(), vec![Call::Hash(LIB.to_vec())]);
    let fail = TraceCrypto {
        fail_at: Some(0),
        ..TraceCrypto::default()
    };
    assert_eq!(
        sign::validate_structure_with_crypto(&m, LIB, &abi, "busbar", &fail),
        Err(WithCryptoError::Unavailable(CryptoUnavailable))
    );
    assert!(
        sign::validate_structure_with_crypto(&m, b"wrong library", &abi, "busbar", &provider)
            .is_err()
    );
}

fn bytes<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value).unwrap().try_into().unwrap()
}

#[test]
fn native_strict_floor_rejects_weak_noncanonical_keys_and_malleable_signatures() {
    let native = TraceCrypto::default();
    for encoded in [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "0200000000000000000000000000000000000000000000000000000000000000",
    ] {
        assert!(sign::public_key_from_hex_with_crypto(encoded, &native).is_err());
        let raw = RawReleaseKey::Ed25519(bytes(encoded));
        let mut forged = [0; 64];
        forged[0] = 1;
        assert_eq!(
            wire::verify_with_crypto(&raw, b"any message", &forged, &native),
            Ok(false)
        );
    }
    // Standard's existing ZIP-215 public-key parser is intentionally unchanged.
    assert!(sign::public_key_from_hex(&"ff".repeat(32)).is_ok());
    assert!(sign::parse_release_keys(&"ff".repeat(32)).is_ok());
    let raw = RawReleaseKey::Ed25519(bytes(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    ));
    let signature = bytes::<64>(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f",
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ));
    assert_eq!(
        wire::verify_with_crypto(&raw, b"", &signature, &native),
        Ok(true)
    );
    for scalar in [
        bytes::<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"),
        bytes("4c8c7872aa064e049dbb3013fbf29380d25bf5f0595bbe24655141438e7a101b"),
        [255; 32],
    ] {
        let mut bad = signature;
        bad[32..].copy_from_slice(&scalar);
        assert_eq!(
            wire::verify_with_crypto(&raw, b"", &bad, &native),
            Ok(false)
        );
    }
    let small_r = bytes::<64>(concat!(
        "0100000000000000000000000000000000000000000000000000000000000000",
        "be6ea3b30c95cf09aa095e2bbdd3d0ba5277670ebfab1b959653b0d80a614f0c"
    ));
    assert_eq!(
        wire::verify_with_crypto(&raw, b"low-order-r-canary", &small_r, &native),
        Ok(false)
    );
    for sig in [
        vec![],
        signature[..63].to_vec(),
        [signature.as_slice(), &[0]].concat(),
    ] {
        assert_eq!(
            wire::verify_with_crypto(&raw, b"", &sig, &native),
            Ok(false)
        );
    }
}

// Fixed independent test fixtures generated with curve25519-dalek 4.1.3 and
// ring SHA-512. For each nonzero torsion T_i: A=B+T_i, R=2B+T_i;
// search message until (k+1)*i == 0 mod 8, k=SHA512(R||A||M) mod L;
// S=2+k mod L. Thus both A and R are nonweak, non-prime-subgroup points.
// The generator asserted !is_small_order(), !is_torsion_free() for BOTH points
// and [S]B-[k]A=R. No alternate crypto implementation enters the candidate.
const MIXED: [(&str, &str, &str); 7] = [("98519eadf35b995233b51b5cd23e9cc5a28b639b5a4af0ec903cb960d81b7819", "mixed-order-1-9", "e6ff0e4955925b2100e8ceebbd4ffe93e6fdfc71c226b33409a570d916254f7229ecba287ba75e7be6c01c4f5187891b1fbc30e1e682a3a89f0d58c33c1b800f"),
("9bad33f580df7ecc49df5342bac8145d5bedc40f573d1b067f3c4ce449689a15", "mixed-order-2-4", "e4dd22778010b28a10d0ddcf35d7a144216299cbe36ba86b31952ef0a294176ed9309aa49fd75c9c08d6ea572db496514a78f947f4e219437bf269312abc0b06"),
("da99e28ba529cdde35a25fba9059e78ecaee239f99755b9b1aa4f65df00803e2", "mixed-order-3-4", "543ac908ca97124ab06caab11552257e53aba22a4e66b769175823a19a0452e0017d382a709cb9fd31c0587a0b76adf39f9197418b97d6e9c6261e664fb3610a"),
("9599999999999999999999999999999999999999999999999999999999999999", "mixed-order-4-2", "245c079551b9a0f1a9aec79baef0c668a9e05d3617a15de23dd6dcf60c329fdd0f53f4592c59c427204fc14726dee3f05774824c2572c57d581600f8162a6a03"),
("55ae61520ca466adcc4ae4a32dc1633a5d749c64a5b50f136fc3469f27e487e6", "mixed-order-5-5", "0700f1b6aa6da4deff17311442b0016c1902038e3dd94ccbf65a8f26e9dab08d993acf5badc0e3760db163f57c028444fc6ee7f3a37189091318a14b49785508"),
("5252cc0a7f208133b620acbd4537eba2a4123bf0a8c2e4f980c3b31bb69765ea", "mixed-order-6-2", "0922dd887fef4d75ef2f2230ca285ebbde9d66341c945794ce6ad10f5d6be8911154329328422afe11aaa0c57beaf6f456ff26904ba8e8208ecfb53539df2e0c"),
("13661d745ad63221ca5da0456fa618713511dc60668aa464e55b09a20ff7fc1d", "mixed-order-7-21", "99c536f73568edb54f93554eeaadda81ac545dd5b1994896e8a7dc5e65fbad1fa9005cb81af44ea4baf80bdcab2be2990fcd5aca99b3c393918649fde850610f")];

#[test]
fn strict_mixed_order_nonweak_keys_and_r_remain_accepted() {
    let native = TraceCrypto::default();
    for (public, message, sig) in MIXED {
        let raw = RawReleaseKey::Ed25519(bytes(public));
        let signature = bytes::<64>(sig);
        assert_eq!(
            wire::verify_with_crypto(&raw, message.as_bytes(), &signature, &native),
            Ok(true)
        );
        assert_eq!(
            wire::verify_with_crypto(&raw, b"wrong message", &signature, &native),
            Ok(false)
        );
        assert_eq!(
            wire::verify_with_crypto(&raw, message.as_bytes(), &signature, &StandardCrypto),
            Ok(true)
        );
    }
}

#[test]
fn unused_supplied_keys_are_validated_before_native_policy_admission() {
    let c = Chain::new(false);
    let m = c.manifest();
    let mut policy = c.policy().to_raw();
    policy.publishers.insert("unused".into(), [255; 32]);
    policy.allow_unsigned = true;
    assert!(matches!(
        sign::evaluate_with_crypto(LIB, &m, &policy, &TraceCrypto::default()),
        Err(WithCryptoError::Rejected(_))
    ));
    let mut policy = c.policy().to_raw();
    policy.first_party_keys.push(sign::RawFirstPartyKey {
        id: "unused".into(),
        key: RawReleaseKey::Ed25519([255; 32]),
    });
    assert!(matches!(
        sign::first_party_signer_for_with_crypto(
            &m,
            LIB,
            &policy.first_party_keys,
            checks(),
            PLUGIN_TARGET,
            &TraceCrypto::default()
        ),
        Err(WithCryptoError::Rejected(_))
    ));
    let fail = TraceCrypto {
        fail_at: Some(2),
        ..TraceCrypto::default()
    };
    let (keys, targets) = c.documents();
    let digest = sign::sha256_hex(&sign::canonical_manifest_bytes(&m));
    assert_eq!(
        release_trust::verify_release_with_crypto(
            &policy.first_party_keys,
            Seal {
                keys: &keys,
                targets: &targets
            },
            c.subject(&m, &digest),
            checks(),
            &fail
        ),
        Err(WithCryptoError::Unavailable(CryptoUnavailable))
    );
    assert_eq!(fail.calls.borrow().len(), 3);
    // The legacy Standard policy still ignores an unrelated publisher key, preserving its
    // existing behavior; canonicality is the opt-in provider's stronger key-construction floor.
    let mut standard = c.policy();
    standard.publishers.insert(
        "unused".into(),
        sign::public_key_from_hex(&"ff".repeat(32)).unwrap(),
    );
    assert!(matches!(
        sign::evaluate(LIB, &m, &standard),
        Ok(Verdict::Trusted { .. })
    ));
}

#[test]
fn successful_provider_callbacks_cannot_override_retired_roots_or_signers() {
    let c = Chain::new(false);
    let retired = sign::public_key_from_hex(sign::RETIRED_RELEASE_KEYS[0].0).unwrap();
    let retired_key = release_trust::ReleaseKey::Ed25519(retired);
    let retired_id = wire::key_id(&retired_key);
    let (keys, targets) = c.documents();
    let provider = TraceCrypto {
        accept_signatures: true,
        ..TraceCrypto::default()
    };
    let mut doc: serde_json::Value = serde_json::from_slice(&keys).unwrap();
    doc["signatures"] = serde_json::json!([{"keyid": retired_id, "sig": "00".repeat(64)}]);
    let retired_keys = serde_json::to_vec(&doc).unwrap();
    let m = manifest();
    let digest = sign::sha256_hex(&sign::canonical_manifest_bytes(&m));
    let roots = [sign::RawFirstPartyKey {
        id: "retired".into(),
        key: RawReleaseKey::from(&retired_key),
    }];
    assert!(matches!(
        release_trust::verify_release_with_crypto(
            &roots,
            Seal {
                keys: &retired_keys,
                targets: &targets
            },
            c.subject(&m, &digest),
            checks(),
            &provider
        ),
        Err(WithCryptoError::Rejected(SealRefusal::RetiredRoot { .. }))
    ));
    let mut kd = c.keys.clone();
    kd.keys.insert(retired_id.clone(), retired_key);
    kd.roles.get_mut(PLUGINS_ROLE).unwrap().keyids = vec![retired_id.clone()];
    kd.roles.get_mut(PLUGINS_ROLE).unwrap().threshold = 1;
    let keys = seal_keys(&kd, &[&c.roots[0]]);
    let mut td: serde_json::Value = serde_json::from_slice(&targets).unwrap();
    td["signatures"] = serde_json::json!([{"keyid": retired_id, "sig": "00".repeat(64)}]);
    let targets = serde_json::to_vec(&td).unwrap();
    let roots = c.policy().to_raw().first_party_keys;
    assert!(matches!(
        release_trust::verify_release_with_crypto(
            &roots,
            Seal {
                keys: &keys,
                targets: &targets
            },
            c.subject(&m, &digest),
            checks(),
            &provider
        ),
        Err(WithCryptoError::Rejected(SealRefusal::RetiredSigner { .. }))
    ));
}

#[test]
fn p256_keeps_der_signatures_and_hashes_the_original_message_once() {
    let signer = TestSigner::p256();
    let raw = RawReleaseKey::from(&signer.key());
    let message = b"P-256 signed original message";
    let sig = signer.sign(message);
    let native = TraceCrypto::default();
    assert_eq!(
        wire::verify_with_crypto(&raw, message, &sig, &native),
        Ok(true)
    );
    let digest = StandardCrypto.sha256(message).unwrap();
    assert_eq!(
        wire::verify_with_crypto(&raw, &digest, &sig, &native),
        Ok(false)
    );
    for malformed in [
        vec![],
        vec![0; 64],
        sig[..sig.len() - 1].to_vec(),
        [sig.as_slice(), &[0]].concat(),
    ] {
        assert_eq!(
            wire::verify_with_crypto(&raw, message, &malformed, &native),
            Ok(false)
        );
    }
    let mut invalid = [0; 65];
    invalid[0] = 4;
    assert!(sign::parse_release_keys_with_crypto(
        &format!("bad:p256:{}", hex::encode(invalid)),
        &native
    )
    .is_err());
    // The Standard constructor still performs its historical syntax check only.
    assert!(sign::parse_release_keys(&format!("bad:p256:{}", hex::encode(invalid))).is_ok());
}

#[test]
fn concrete_public_type_aliases_preserve_uncontextualized_source_constructors() {
    // Deliberately no downstream function/type annotations to drive generic inference.
    let p = TrustPolicy {
        allow_unsigned: true,
        ..Default::default()
    };
    assert!(p.allow_unsigned);
    let p = TrustPolicy::default();
    assert!(!p.allow_unsigned);
    let d = KeysDoc::default();
    assert_eq!(d.version, 0);
    let d = KeysDoc {
        version: 7,
        ..Default::default()
    };
    assert_eq!(d.version, 7);
    let r = FirstPartyKey {
        id: "test".into(),
        key: TestSigner::ed25519(89).key(),
    };
    assert_eq!(r.id, "test");
    let raw = sign::RawTrustPolicy::default();
    assert!(!raw.allow_unsigned);
}
