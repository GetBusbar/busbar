// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RELEASE TRUST CHAIN: root -> keys document -> release manifest -> artefact. Each link is
//! proven to hold for a good release and to refuse, explained, for every way it can break.

use super::*;
use crate::sign::{parse_release_keys, sha256_hex, FirstPartyKey};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_ASN1_SIGNING};

/// A signer the tests hold the private half of.
pub(crate) enum TestSigner {
    P256(EcdsaKeyPair),
    Ed25519(ed25519_dalek::SigningKey),
}

impl TestSigner {
    pub(crate) fn p256() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        TestSigner::P256(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap(),
        )
    }

    pub(crate) fn ed25519(seed: u8) -> Self {
        TestSigner::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }

    pub(crate) fn key(&self) -> ReleaseKey {
        match self {
            TestSigner::P256(p) => ReleaseKey::P256(p.public_key().as_ref().try_into().unwrap()),
            TestSigner::Ed25519(k) => ReleaseKey::Ed25519(k.verifying_key()),
        }
    }

    pub(crate) fn id(&self) -> String {
        wire::key_id(&self.key())
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            TestSigner::P256(p) => p.sign(&SystemRandom::new(), msg).unwrap().as_ref().to_vec(),
            TestSigner::Ed25519(k) => {
                use ed25519_dalek::Signer as _;
                k.sign(msg).to_bytes().to_vec()
            }
        }
    }

    pub(crate) fn root(&self, id: &str) -> FirstPartyKey {
        FirstPartyKey {
            id: id.to_string(),
            key: self.key(),
        }
    }
}

/// 2027-01-15T08:00:00Z.
pub(crate) const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

pub(crate) fn checks() -> Checks {
    Checks {
        now: NOW,
        keys_floor: 0,
    }
}

/// A keys document naming `signers` for the plugins role (threshold 1), expiring in 90 days.
pub(crate) fn keys_doc(signers: &[&TestSigner]) -> KeysDoc {
    KeysDoc {
        version: 1,
        expires: NOW + 90 * DAY,
        keys: signers.iter().map(|s| (s.id(), s.key())).collect(),
        roles: [(
            PLUGINS_ROLE.to_string(),
            Role {
                keyids: signers.iter().map(|s| s.id()).collect(),
                threshold: 1,
            },
        )]
        .into(),
        ..KeysDoc::default()
    }
}

/// `doc`'s envelope, signed by `by`.
pub(crate) fn seal_keys(doc: &KeysDoc, by: &[&TestSigner]) -> Vec<u8> {
    let signed = wire::keys_signed(doc);
    let bytes = wire::canonical(&signed).unwrap();
    let sigs: Vec<(String, Vec<u8>)> = by.iter().map(|s| (s.id(), s.sign(&bytes))).collect();
    wire::write_envelope(&signed, &sigs).unwrap()
}

/// A release manifest listing `entries`, expiring in a year.
pub(crate) fn targets_doc(entries: Vec<Target>) -> TargetsDoc {
    TargetsDoc {
        role: PLUGINS_ROLE.to_string(),
        version: 1,
        expires: NOW + 365 * DAY,
        targets: entries,
    }
}

pub(crate) fn seal_targets(doc: &TargetsDoc, by: &[&TestSigner]) -> Vec<u8> {
    let signed = wire::targets_signed(doc);
    let bytes = wire::canonical(&signed).unwrap();
    let sigs: Vec<(String, Vec<u8>)> = by.iter().map(|s| (s.id(), s.sign(&bytes))).collect();
    wire::write_envelope(&signed, &sigs).unwrap()
}

pub(crate) fn entry(name: &str, version: &str, target: &str, sha256: &str) -> Target {
    Target {
        name: name.into(),
        version: version.into(),
        target: target.into(),
        sha256: sha256.into(),
        length: 7,
    }
}

const NAME: &str = "busbar-store-alpha";
const VERSION: &str = "1.6.0";

fn artefact() -> String {
    sha256_hex(b"canonical manifest bytes")
}

fn subject(sha: &str) -> Subject<'_> {
    Subject {
        name: NAME,
        version: VERSION,
        target: PLUGIN_TARGET,
        sha256: sha,
        lib_sha256: "00",
    }
}

/// The two roots (KMS and PIV, both P-256) and the interim release signer.
struct World {
    kms: TestSigner,
    piv: TestSigner,
    signer: TestSigner,
}

impl World {
    fn new() -> Self {
        World {
            kms: TestSigner::p256(),
            piv: TestSigner::p256(),
            signer: TestSigner::p256(),
        }
    }

    fn roots(&self) -> Vec<FirstPartyKey> {
        vec![
            self.kms.root("busbar-plugins-root"),
            self.piv.root("busbar-plugins-2026a"),
        ]
    }

    /// A good release: keys document by `root`, release manifest by the signer, listing the artefact.
    fn release(&self, root: &TestSigner) -> (Vec<u8>, Vec<u8>) {
        let keys = seal_keys(&keys_doc(&[&self.signer]), &[root]);
        let targets = seal_targets(
            &targets_doc(vec![entry(NAME, VERSION, PLUGIN_TARGET, &artefact())]),
            &[&self.signer],
        );
        (keys, targets)
    }

    fn verify(
        &self,
        keys: &[u8],
        targets: &[u8],
        sha: &str,
        checks: Checks,
    ) -> Result<Verified, SealRefusal> {
        verify_release(&self.roots(), Seal { keys, targets }, subject(sha), checks)
    }
}

#[test]
fn a_release_vouched_for_by_the_kms_root_loads() {
    let w = World::new();
    let (keys, targets) = w.release(&w.kms);
    let v = w
        .verify(&keys, &targets, &artefact(), checks())
        .expect("the chain holds");
    assert_eq!(v.root, "busbar-plugins-root");
    assert_eq!(v.signers, vec![w.signer.id()]);
    assert_eq!((v.keys_version, v.targets_version), (1, 1));
}

#[test]
fn the_same_release_vouched_for_by_the_piv_root_loads() {
    let w = World::new();
    let (keys, targets) = w.release(&w.piv);
    let v = w
        .verify(&keys, &targets, &artefact(), checks())
        .expect("the chain holds");
    assert_eq!(v.root, "busbar-plugins-2026a");
}

#[test]
fn a_root_key_may_also_be_the_release_signer() {
    let w = World::new();
    let keys = seal_keys(&keys_doc(&[&w.piv]), &[&w.piv]);
    let targets = seal_targets(
        &targets_doc(vec![entry(NAME, VERSION, PLUGIN_TARGET, &artefact())]),
        &[&w.piv],
    );
    w.verify(&keys, &targets, &artefact(), checks())
        .expect("the PIV root signs both documents");
}

#[test]
fn an_ed25519_root_and_signer_still_verify() {
    let (root, signer) = (TestSigner::ed25519(7), TestSigner::ed25519(8));
    let keys = seal_keys(&keys_doc(&[&signer]), &[&root]);
    let targets = seal_targets(
        &targets_doc(vec![entry(NAME, VERSION, PLUGIN_TARGET, &artefact())]),
        &[&signer],
    );
    verify_release(
        &[root.root("run-key")],
        Seal {
            keys: &keys,
            targets: &targets,
        },
        subject(&artefact()),
        checks(),
    )
    .expect("ed25519 is kept beside P-256");
}

#[test]
fn an_altered_artefact_is_refused() {
    let w = World::new();
    let (keys, targets) = w.release(&w.kms);
    let altered = sha256_hex(b"canonical manifest bytes, one byte changed");
    let e = w.verify(&keys, &targets, &altered, checks()).unwrap_err();
    assert!(matches!(e, SealRefusal::HashMismatch { .. }), "{e:?}");
    assert_eq!(e.code(), "hash-mismatch");
}

#[test]
fn an_artefact_the_release_does_not_list_is_refused() {
    let w = World::new();
    let keys = seal_keys(&keys_doc(&[&w.signer]), &[&w.kms]);
    let targets = seal_targets(
        &targets_doc(vec![entry(
            "busbar-store-beta",
            VERSION,
            PLUGIN_TARGET,
            &artefact(),
        )]),
        &[&w.signer],
    );
    let e = w
        .verify(&keys, &targets, &artefact(), checks())
        .unwrap_err();
    assert_eq!(
        e,
        SealRefusal::Unlisted {
            name: NAME.into(),
            version: VERSION.into()
        }
    );
}

#[test]
fn an_artefact_listed_only_for_another_target_is_refused() {
    let w = World::new();
    let keys = seal_keys(&keys_doc(&[&w.signer]), &[&w.kms]);
    let targets = seal_targets(
        &targets_doc(vec![entry(
            NAME,
            VERSION,
            "riscv64gc-unknown-linux-gnu",
            &artefact(),
        )]),
        &[&w.signer],
    );
    let e = w
        .verify(&keys, &targets, &artefact(), checks())
        .unwrap_err();
    assert!(
        matches!(&e, SealRefusal::WrongTarget { listed, target, .. }
            if listed == &["riscv64gc-unknown-linux-gnu".to_string()] && target == PLUGIN_TARGET),
        "{e:?}"
    );
}

#[test]
fn a_release_signed_by_a_key_the_keys_document_does_not_name_is_refused() {
    let w = World::new();
    let stranger = TestSigner::p256();
    let keys = seal_keys(&keys_doc(&[&w.signer]), &[&w.kms]);
    let targets = seal_targets(
        &targets_doc(vec![entry(NAME, VERSION, PLUGIN_TARGET, &artefact())]),
        &[&stranger],
    );
    let e = w
        .verify(&keys, &targets, &artefact(), checks())
        .unwrap_err();
    assert!(
        matches!(
            e,
            SealRefusal::TargetsSignature {
                valid: 0,
                threshold: 1,
                ..
            }
        ),
        "{e:?}"
    );
}

#[test]
fn a_keys_document_signed_by_a_key_that_is_not_a_root_is_refused() {
    let w = World::new();
    let keys = seal_keys(&keys_doc(&[&w.signer]), &[&w.signer]);
    let (_, targets) = w.release(&w.kms);
    let e = w
        .verify(&keys, &targets, &artefact(), checks())
        .unwrap_err();
    assert_eq!(
        e,
        SealRefusal::KeysSignature {
            roots: vec!["busbar-plugins-root".into(), "busbar-plugins-2026a".into()]
        }
    );
}

#[test]
fn a_keys_document_altered_after_the_root_signed_it_is_refused() {
    let w = World::new();
    let stranger = TestSigner::p256();
    let honest = seal_keys(&keys_doc(&[&w.signer]), &[&w.kms]);
    // Swap the stranger in under the root's signature.
    let mut env: serde_json::Value = serde_json::from_slice(&honest).unwrap();
    env["signed"] = wire::keys_signed(&keys_doc(&[&stranger]));
    let forged = serde_json::to_vec(&env).unwrap();
    let targets = seal_targets(
        &targets_doc(vec![entry(NAME, VERSION, PLUGIN_TARGET, &artefact())]),
        &[&stranger],
    );
    let e = w
        .verify(&forged, &targets, &artefact(), checks())
        .unwrap_err();
    assert!(matches!(e, SealRefusal::KeysSignature { .. }), "{e:?}");
}

#[test]
fn an_expired_keys_document_is_refused() {
    let w = World::new();
    let (keys, targets) = w.release(&w.kms);
    let later = Checks {
        now: NOW + 90 * DAY,
        ..checks()
    };
    let e = w.verify(&keys, &targets, &artefact(), later).unwrap_err();
    assert!(matches!(e, SealRefusal::KeysExpired { .. }), "{e:?}");
}

#[test]
fn an_expired_release_manifest_is_refused() {
    let w = World::new();
    let keys = seal_keys(&keys_doc(&[&w.signer]), &[&w.kms]);
    let mut doc = targets_doc(vec![entry(NAME, VERSION, PLUGIN_TARGET, &artefact())]);
    doc.expires = NOW;
    let targets = seal_targets(&doc, &[&w.signer]);
    let e = w
        .verify(&keys, &targets, &artefact(), checks())
        .unwrap_err();
    assert!(matches!(e, SealRefusal::TargetsExpired { .. }), "{e:?}");
}

#[test]
fn a_keys_document_older_than_one_already_accepted_is_refused() {
    let w = World::new();
    let (keys, targets) = w.release(&w.kms);
    let floored = Checks {
        keys_floor: 2,
        ..checks()
    };
    let e = w.verify(&keys, &targets, &artefact(), floored).unwrap_err();
    assert_eq!(
        e,
        SealRefusal::KeysRollback {
            version: 1,
            floor: 2
        }
    );
    let same = Checks {
        keys_floor: 1,
        ..checks()
    };
    w.verify(&keys, &targets, &artefact(), same)
        .expect("the version already accepted still loads");
}

#[test]
fn a_release_signed_by_a_revoked_signer_is_refused() {
    let w = World::new();
    let mut doc = keys_doc(&[&w.signer]);
    doc.revoked_keyids.insert(w.signer.id());
    let keys = seal_keys(&doc, &[&w.kms]);
    let (_, targets) = w.release(&w.kms);
    let e = w
        .verify(&keys, &targets, &artefact(), checks())
        .unwrap_err();
    assert_eq!(
        e,
        SealRefusal::SignerRevoked {
            keyids: vec![w.signer.id()]
        }
    );
}

#[test]
fn a_revoked_digest_is_refused_though_the_release_lists_it() {
    let w = World::new();
    let mut doc = keys_doc(&[&w.signer]);
    doc.revoked_digests
        .insert(artefact(), "pulled for a defect".into());
    let keys = seal_keys(&doc, &[&w.kms]);
    let (_, targets) = w.release(&w.kms);
    let e = w
        .verify(&keys, &targets, &artefact(), checks())
        .unwrap_err();
    assert!(
        matches!(&e, SealRefusal::DigestRevoked { why, .. } if why == "pulled for a defect"),
        "{e:?}"
    );
}

#[test]
fn a_role_with_a_zero_threshold_or_no_signers_trusts_nothing() {
    let w = World::new();
    let (_, targets) = w.release(&w.kms);
    for broken in [0u64, 1] {
        let mut doc = keys_doc(&[&w.signer]);
        let role = doc.roles.get_mut(PLUGINS_ROLE).unwrap();
        if broken == 0 {
            role.threshold = 0;
        } else {
            role.keyids.clear();
        }
        let keys = seal_keys(&doc, &[&w.kms]);
        let e = w
            .verify(&keys, &targets, &artefact(), checks())
            .unwrap_err();
        assert!(matches!(e, SealRefusal::NoRole { .. }), "{e:?}");
    }
}

#[test]
fn every_refusal_is_explained_and_coded() {
    let all = [
        SealRefusal::Malformed {
            doc: "keys document",
            why: "x".into(),
        },
        SealRefusal::KeysSignature {
            roots: vec!["r".into()],
        },
        SealRefusal::KeysExpired {
            version: 1,
            expires: NOW,
            now: NOW,
        },
        SealRefusal::KeysRollback {
            version: 1,
            floor: 2,
        },
        SealRefusal::NoRole {
            role: PLUGINS_ROLE.into(),
        },
        SealRefusal::TargetsSignature {
            role: PLUGINS_ROLE.into(),
            threshold: 1,
            valid: 0,
        },
        SealRefusal::SignerRevoked {
            keyids: vec!["k".into()],
        },
        SealRefusal::TargetsExpired {
            version: 1,
            expires: NOW,
            now: NOW,
        },
        SealRefusal::DigestRevoked {
            digest: "d".into(),
            why: "w".into(),
        },
        SealRefusal::Unlisted {
            name: NAME.into(),
            version: VERSION.into(),
        },
        SealRefusal::WrongTarget {
            name: NAME.into(),
            version: VERSION.into(),
            target: "t".into(),
            listed: vec![],
        },
        SealRefusal::HashMismatch {
            name: NAME.into(),
            version: VERSION.into(),
            target: "t".into(),
            listed: "a".into(),
            actual: "b".into(),
        },
    ];
    let codes: std::collections::BTreeSet<&str> = all.iter().map(SealRefusal::code).collect();
    assert_eq!(
        codes.len(),
        all.len(),
        "every refusal has its own audit code"
    );
    for r in &all {
        assert!(r.to_string().len() > 60, "{r:?} explains itself: {r}");
    }
}

// ── the wire encoding (provisional) ─────────────────────────────────────────────────────────────

#[test]
fn canonical_json_is_sorted_compact_and_matches_python() {
    let v = serde_json::json!({"b": [1, "x\"y\\z"], "a": {"d": true, "c": null}});
    // python3 -c 'import json;print(json.dumps(v, sort_keys=True, separators=(",",":")))'
    assert_eq!(
        String::from_utf8(wire::canonical(&v).unwrap()).unwrap(),
        r#"{"a":{"c":null,"d":true},"b":[1,"x\"y\\z"]}"#
    );
    assert!(
        wire::canonical(&serde_json::json!(1.5)).is_err(),
        "no floats"
    );
    assert!(
        wire::canonical(&serde_json::json!(-1)).is_err(),
        "no negatives"
    );
    assert!(
        wire::canonical(&serde_json::json!("caf\u{e9}")).is_err(),
        "ASCII only"
    );
    assert!(
        wire::canonical(&serde_json::json!("a\nb")).is_err(),
        "no control characters"
    );
}

#[test]
fn times_are_utc_seconds_both_ways() {
    assert_eq!(wire::parse_time("1970-01-01T00:00:00Z"), Ok(0));
    assert_eq!(wire::parse_time("2027-01-15T08:00:00Z"), Ok(NOW));
    assert_eq!(wire::format_time(NOW), "2027-01-15T08:00:00Z");
    assert_eq!(
        wire::parse_time("2028-02-29T23:59:59Z").map(wire::format_time),
        Ok("2028-02-29T23:59:59Z".into())
    );
    for bad in [
        "2027-02-29T00:00:00Z",
        "2027-01-15 08:00:00Z",
        "2027-01-15T08:00:00+00:00",
        "2027-13-01T00:00:00Z",
    ] {
        assert!(wire::parse_time(bad).is_err(), "{bad}");
    }
}

#[test]
fn a_key_id_is_the_sha256_of_its_canonical_key_object() {
    let k = TestSigner::ed25519(3).key();
    let obj = format!(
        r#"{{"keytype":"ed25519","keyval":{{"public":"{}"}},"scheme":"ed25519"}}"#,
        k.public_hex()
    );
    assert_eq!(wire::key_id(&k), sha256_hex(obj.as_bytes()));
}

#[test]
fn a_document_with_an_unknown_field_or_spec_version_is_refused() {
    let w = World::new();
    let mut signed = wire::keys_signed(&keys_doc(&[&w.signer]));
    signed["extra"] = serde_json::json!(1);
    let env = wire::write_envelope(&signed, &[]).unwrap();
    assert!(wire::read_keys(&env)
        .unwrap_err()
        .contains("unknown field 'extra'"));
    let mut signed = wire::keys_signed(&keys_doc(&[&w.signer]));
    signed["spec_version"] = serde_json::json!("9");
    let env = wire::write_envelope(&signed, &[]).unwrap();
    assert!(wire::read_keys(&env).unwrap_err().contains("spec_version"));
}

// ── the root key list ───────────────────────────────────────────────────────────────────────────

#[test]
fn the_root_key_list_names_its_algorithm_per_key() {
    let p = TestSigner::p256().key();
    let e = TestSigner::ed25519(4).key();
    let spec = format!(
        "busbar-plugins-root:p256:{},busbar-plugins-2026a:ed25519:{},legacy:{}",
        p.public_hex(),
        e.public_hex(),
        TestSigner::ed25519(5).key().public_hex()
    );
    let keys = parse_release_keys(&spec).expect("parses");
    assert_eq!(keys[0].id, "busbar-plugins-root");
    assert_eq!(keys[0].key, p);
    assert_eq!(keys[1].key, e);
    assert_eq!(keys[2].key.algorithm(), "ed25519");
    for bad in [
        format!("r:p256:{}", &p.public_hex()[2..]),
        format!("r:rsa:{}", p.public_hex()),
        format!("p256:{}", p.public_hex()),
        format!("r:p256:{}", "02".to_string() + &p.public_hex()[2..66]),
    ] {
        assert!(parse_release_keys(&bad).is_err(), "{bad}");
    }
}
