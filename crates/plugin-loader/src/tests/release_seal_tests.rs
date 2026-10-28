// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SEALED FIRST-PARTY PLUGIN through the loader's own trust evaluation ([`evaluate`]): it loads as
//! first-party when its release seal's chain holds, and every broken link is refused by default
//! with a reason that names the audit code and says what to do. A revoked artefact or signer and a
//! rolled-back keys document are refused whatever the operator opted in to.

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

/// The artefact digest a release lists for `m`.
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

    /// `m` sealed: a keys document `root` signed naming the signer, a release manifest listing
    /// `entries` (each `(name, version, target, sha256)`) that `by` signed.
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

    /// `m` sealed by a good release vouched for by `root`.
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

/// A default-posture refusal: `kind`, and a reason naming `code`.
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
    // The library alone changed: its manifest no longer binds it.
    let mut lib = LIB.to_vec();
    lib[5] ^= 1;
    let e = evaluate(&lib, &m, &r.policy()).expect_err("refused");
    assert_eq!(e.kind, RejectKind::Tampered, "{}", e.reason);
    // The library changed and the manifest re-pinned to it: not the artefact the release lists.
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
    // The release manifest signed by a key the keys document does not name.
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
    // A keys document vouched for by a key that is not a root of this build.
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

/// INSTALL (an upload, its preview, a fetch, an update) judges expiry: a plugin whose keys document
/// has expired is refused.
#[test]
fn installing_a_plugin_whose_keys_document_has_expired_is_refused() {
    let r = Release::new();
    let m = r.good(unsealed(), &r.kms);
    let install = TrustPolicy {
        release_clock: Some(NOW + 91 * 86_400),
        release_enforce_expiry: true,
        ..r.policy()
    };
    refused(
        evaluate(LIB, &m, &install),
        RejectKind::Tampered,
        "keys-expired",
    );
}

/// BOOT does not: a plugin already installed whose keys document (90 days) and release manifest have
/// since expired still loads as first-party.
#[test]
fn an_installed_plugin_whose_documents_have_since_expired_still_loads_at_boot() {
    let r = Release::new();
    let m = r.good(unsealed(), &r.kms);
    let boot = TrustPolicy {
        release_clock: Some(NOW + 2 * 365 * 86_400),
        ..r.policy()
    };
    assert!(!boot.release_enforce_expiry, "boot is the default posture");
    assert_eq!(evaluate(LIB, &m, &boot), Ok(first_party()));
}

/// BOOT still honours a revocation, digest or signer, in a keys document that has expired.
#[test]
fn a_revocation_is_refused_at_boot_though_the_keys_document_has_expired() {
    let r = Release::new();
    let boot = TrustPolicy {
        release_clock: Some(NOW + 365 * 86_400),
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
        allow_unsigned: true,
        allow_third_party: true,
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
        allow_unsigned: true,
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
        allow_unsigned: true,
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
