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
        enforce_expiry: true,
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
fn a_forged_retired_root_keyid_is_not_authenticated_as_a_retired_signature() {
    let w = World::new();
    let retired = FirstPartyKey {
        id: "retired-root".into(),
        key: ReleaseKey::Ed25519(
            crate::sign::public_key_from_hex(crate::sign::RETIRED_RELEASE_KEYS[0].0).unwrap(),
        ),
    };
    assert!(retired.retired_reason().is_some());
    let (keys, targets) = w.release(&w.kms);
    let mut envelope: serde_json::Value = serde_json::from_slice(&keys).unwrap();
    envelope["signatures"][0]["keyid"] = serde_json::json!(wire::key_id(&retired.key));
    let forged = serde_json::to_vec(&envelope).unwrap();
    assert!(matches!(
        verify_release(
            std::slice::from_ref(&retired),
            Seal {
                keys: &forged,
                targets: &targets
            },
            subject(&artefact()),
            checks(),
        ),
        Err(SealRefusal::KeysSignature { .. })
    ));

    // The unauthenticated retired-key label also cannot poison a valid current root signature.
    let mut valid: serde_json::Value = serde_json::from_slice(&keys).unwrap();
    valid["signatures"]
        .as_array_mut()
        .unwrap()
        .push(envelope["signatures"][0].clone());
    let valid = serde_json::to_vec(&valid).unwrap();
    let mut roots = w.roots();
    roots.push(retired);
    verify_release(
        &roots,
        Seal {
            keys: &valid,
            targets: &targets,
        },
        subject(&artefact()),
        checks(),
    )
    .expect("a forged retired-root key id does not override a valid current root");
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

/// AT BOOT (TUF's semantics): an installed plugin's expired keys document and release manifest are
/// not judged, so it never stops loading because time passed; everything else still is.
#[test]
fn at_boot_expired_documents_are_not_judged() {
    let w = World::new();
    let keys = seal_keys(&keys_doc(&[&w.signer]), &[&w.kms]);
    let mut doc = targets_doc(vec![entry(NAME, VERSION, PLUGIN_TARGET, &artefact())]);
    doc.expires = NOW + 30 * DAY;
    let targets = seal_targets(&doc, &[&w.signer]);
    let boot = Checks {
        now: NOW + 400 * DAY,
        enforce_expiry: false,
        ..checks()
    };
    w.verify(&keys, &targets, &artefact(), boot)
        .expect("an installed plugin keeps loading after its documents expire");
    let install = Checks {
        enforce_expiry: true,
        ..boot
    };
    assert!(matches!(
        w.verify(&keys, &targets, &artefact(), install),
        Err(SealRefusal::KeysExpired { .. })
    ));
}

/// AT BOOT a revocation in an expired keys document is still honoured, digest and signer alike.
#[test]
fn at_boot_a_revocation_is_refused_though_the_keys_document_has_expired() {
    let w = World::new();
    let boot = Checks {
        now: NOW + 400 * DAY,
        enforce_expiry: false,
        ..checks()
    };
    let (_, targets) = w.release(&w.kms);
    let mut doc = keys_doc(&[&w.signer]);
    doc.revoked_digests.insert(artefact(), "pulled".into());
    let keys = seal_keys(&doc, &[&w.kms]);
    assert!(matches!(
        w.verify(&keys, &targets, &artefact(), boot),
        Err(SealRefusal::DigestRevoked { .. })
    ));
    let mut doc = keys_doc(&[&w.signer]);
    doc.revoked_keyids.insert(w.signer.id());
    let keys = seal_keys(&doc, &[&w.kms]);
    assert!(matches!(
        w.verify(&keys, &targets, &artefact(), boot),
        Err(SealRefusal::SignerRevoked { .. })
    ));
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
fn the_permanently_retired_public_key_stays_retired_when_delegated() {
    let w = World::new();
    let (retired_hex, why) = crate::sign::RETIRED_RELEASE_KEYS[0];
    let retired_key = ReleaseKey::Ed25519(crate::sign::public_key_from_hex(retired_hex).unwrap());
    let retired_id = wire::key_id(&retired_key);
    let mut doc = keys_doc(&[&w.signer]);
    doc.keys.insert(retired_id.clone(), retired_key.clone());
    doc.roles
        .get_mut(PLUGINS_ROLE)
        .unwrap()
        .keyids
        .push(retired_id.clone());
    let keys = seal_keys(&doc, &[&w.kms]);
    let decoded = wire::read_keys(&keys).unwrap().doc;
    assert!(!decoded.revoked_keyids.contains(&retired_id));
    assert_eq!(decoded.keys[&retired_id].retired_reason(), Some(why));
    assert_eq!(w.signer.key().retired_reason(), None);

    // No retired private material is available. A forged key id must not authenticate retirement.
    let targets = seal_targets(
        &targets_doc(vec![entry(NAME, VERSION, PLUGIN_TARGET, &artefact())]),
        &[&w.signer],
    );
    let mut forged: serde_json::Value = serde_json::from_slice(&targets).unwrap();
    forged["signatures"][0]["keyid"] = serde_json::json!(retired_id);
    let forged_bytes = serde_json::to_vec(&forged).unwrap();
    assert!(matches!(
        w.verify(&keys, &forged_bytes, &artefact(), checks()),
        Err(SealRefusal::TargetsSignature { valid: 0, .. })
    ));

    let mut valid: serde_json::Value = serde_json::from_slice(&targets).unwrap();
    valid["signatures"]
        .as_array_mut()
        .unwrap()
        .push(forged["signatures"][0].clone());
    w.verify(
        &keys,
        &serde_json::to_vec(&valid).unwrap(),
        &artefact(),
        checks(),
    )
    .expect("a forged retired signer id cannot poison a valid current signer");
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
fn a_revoked_library_digest_is_refused_even_when_the_manifest_digest_is_current() {
    let w = World::new();
    let library_digest = sha256_hex(b"revoked library bytes");
    let mut doc = keys_doc(&[&w.signer]);
    doc.revoked_digests
        .insert(library_digest.clone(), "library pulled".into());
    let keys = seal_keys(&doc, &[&w.kms]);
    let (_, targets) = w.release(&w.kms);
    let manifest_digest = artefact();
    let mut plugin = subject(&manifest_digest);
    plugin.lib_sha256 = &library_digest;
    assert_eq!(
        verify_release(
            &w.roots(),
            Seal {
                keys: &keys,
                targets: &targets
            },
            plugin,
            checks()
        ),
        Err(SealRefusal::DigestRevoked {
            digest: library_digest,
            why: "library pulled".into(),
        })
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
        SealRefusal::RetiredRoot {
            id: "retired-root".into(),
            why: "compromised release key".into(),
        },
        SealRefusal::RetiredSigner {
            id: "retired-signer".into(),
            why: "compromised release key".into(),
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
        "2027-\u{e9}1-15T08:00:00Z",
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

#[test]
fn unknown_fields_in_keys_signatures_and_target_details_are_refused() {
    let signer = TestSigner::ed25519(8);
    for nested in [false, true] {
        let mut key = wire::key_object(&signer.key());
        if nested {
            key["keyval"]["extra"] = serde_json::json!("unsupported");
        } else {
            key["extra"] = serde_json::json!("unsupported");
        }
        assert!(wire::read_key_object(&key)
            .unwrap_err()
            .contains("unknown field 'extra'"));
    }

    let keys = seal_keys(&keys_doc(&[&signer]), &[&signer]);
    let mut envelope: serde_json::Value = serde_json::from_slice(&keys).unwrap();
    envelope["signatures"][0]["extra"] = serde_json::json!("unsupported");
    assert!(wire::read_keys(&serde_json::to_vec(&envelope).unwrap())
        .unwrap_err()
        .contains("unknown field 'extra'"));

    for nested in ["custom", "hashes"] {
        let mut signed = wire::targets_signed(&targets_doc(vec![entry(
            NAME,
            VERSION,
            PLUGIN_TARGET,
            &artefact(),
        )]));
        let path = format!("{NAME}/{VERSION}/{PLUGIN_TARGET}");
        signed["targets"][&path][nested]["extra"] = serde_json::json!("unsupported");
        let envelope = wire::write_envelope(&signed, &[]).unwrap();
        assert!(wire::read_targets(&envelope)
            .unwrap_err()
            .contains("unknown field 'extra'"));
    }
}

#[test]
fn malformed_revocation_lists_are_refused_instead_of_ignored() {
    let signer = TestSigner::ed25519(8);
    for (field, value) in [
        ("keyids", serde_json::json!("revoked-key")),
        ("keyids", serde_json::Value::Null),
        ("digests", serde_json::json!(["revoked-digest"])),
        ("digests", serde_json::Value::Null),
    ] {
        let mut signed = wire::keys_signed(&keys_doc(&[&signer]));
        signed["revocations"][field] = value;
        let envelope = wire::write_envelope(&signed, &[]).unwrap();
        assert!(
            wire::read_keys(&envelope).is_err(),
            "malformed revocations.{field} must not become an empty revocation set"
        );
    }
}

#[test]
fn repeating_a_signature_does_not_satisfy_a_two_signer_threshold() {
    let root = TestSigner::ed25519(7);
    let signer = TestSigner::ed25519(8);
    let other = TestSigner::ed25519(9);
    let mut doc = keys_doc(&[&signer, &other]);
    doc.roles.get_mut(PLUGINS_ROLE).unwrap().threshold = 2;
    let keys = seal_keys(&doc, &[&root]);
    let targets = seal_targets(
        &targets_doc(vec![entry(NAME, VERSION, PLUGIN_TARGET, &artefact())]),
        &[&signer, &signer],
    );
    assert!(matches!(
        verify_release(
            &[root.root("test-root")],
            Seal {
                keys: &keys,
                targets: &targets
            },
            subject(&artefact()),
            checks()
        ),
        Err(SealRefusal::TargetsSignature {
            threshold: 2,
            valid: 1,
            ..
        })
    ));
}

#[test]
fn distinct_signers_of_different_algorithms_satisfy_the_role_threshold() {
    let root = TestSigner::ed25519(7);
    let first = TestSigner::p256();
    let second = TestSigner::ed25519(9);
    let mut doc = keys_doc(&[&first, &second]);
    doc.roles.get_mut(PLUGINS_ROLE).unwrap().threshold = 2;
    let keys = seal_keys(&doc, &[&root]);
    let targets = seal_targets(
        &targets_doc(vec![entry(NAME, VERSION, PLUGIN_TARGET, &artefact())]),
        &[&first, &second],
    );
    let verified = verify_release(
        &[root.root("test-root")],
        Seal {
            keys: &keys,
            targets: &targets,
        },
        subject(&artefact()),
        checks(),
    )
    .expect("two distinct authorized signers satisfy a threshold of two");
    assert_eq!(verified.signers, vec![first.id(), second.id()]);
}

#[test]
fn a_seal_round_trip_preserves_the_verified_chain_and_expiry_boundary() {
    let w = World::new();
    let (keys, targets) = w.release(&w.kms);
    let signature = wire::write_seal(&keys, &targets).unwrap();
    let (keys, targets) = wire::read_seal(&signature).unwrap().unwrap();
    let seal = Seal {
        keys: &keys,
        targets: &targets,
    };
    w.verify(&keys, &targets, &artefact(), checks()).unwrap();
    assert_eq!(wire::sealed_keys_version(&signature), Some(1));
    assert_eq!(check_fresh(seal, NOW + 90 * DAY - 1), Ok(()));
    assert!(matches!(
        check_fresh(seal, NOW + 90 * DAY),
        Err(SealRefusal::KeysExpired { .. })
    ));
    assert!(wire::read_seal(&"00".repeat(64)).is_none());
    assert!(wire::read_seal("seal:{}").unwrap().is_err());
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
