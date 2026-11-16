// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALING-FIX r20 MR-4 (kernel-audit half): the page stamp (`audit.stamp.v1`), the break notice
//! (`audit.break.v1`) and the two signing capabilities the deployment key is consumed into.

use busbar_contract::caps::MeterClassId;
use busbar_kernel_audit::record::{AuditBreak, AuditBreakKind, AuditChain, AuditRecord};
use busbar_kernel_audit::sign::{AuditKeySet, AuditSigningKey, AuditVerifyingKey, KeyError};
use busbar_kernel_audit::{
    break_body, break_from_journal_body, from_journal_body, stamp_body, stamp_from_journal_body,
    BootstrapSigner, BreakNotice, BreakReason, CoverError, Fingerprint, LiveSigner, Notary, Recipe,
    Stamp, StampError, StampKind, StampSignError,
};

use super::link_tests::{linked, NODE};

const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn key() -> AuditSigningKey {
    AuditSigningKey::from_hex_seed(SEED).expect("the test seed is 64 lowercase hex")
}

fn public() -> AuditVerifyingKey {
    AuditVerifyingKey::from_hex(&key().public_key_hex()).expect("a public key")
}

fn signers() -> (Notary, BootstrapSigner) {
    let (notary, bootstrap) = key()
        .into_grants(LiveSigner::SameAsBootstrap)
        .expect("the software backend approves a local signer");
    (Notary::new(notary), BootstrapSigner::new(bootstrap))
}

fn declared(name: &str) -> Option<MeterClassId> {
    ["tokens_in", "tokens_out"]
        .into_iter()
        .find(|c| *c == name)
        .map(MeterClassId::new)
}

/// An unsigned page of `kind` over `lines` (oldest first) of [`NODE`].
fn page(lines: &[AuditRecord], kind: StampKind) -> Stamp {
    let last = lines.last().expect("a page has lines");
    Stamp {
        node: NODE,
        from: lines[0].seq,
        to: last.seq,
        fingerprint: Fingerprint::from_hex(&last.hash).expect("a link line's hash"),
        kind,
        sealer: NODE,
        host: "host-a".into(),
        every: 1,
        stamped_ms: last.linked_ms + 1,
        down_from_ms: 0,
        down_to_ms: 0,
        crypto: String::new(),
        sig_alg: String::new(),
        key_id: String::new(),
        key_cert: 0,
        signature: Vec::new(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// SEALING-FIX tests 25(a) and (f), 7 ("relabelled kind; altered sealer, crypto or sig_alg"): the
/// signature binds every field, `crypto`, `sig_alg`, `host` and `every` come before `key_id` in the
/// preimage, and `key_cert` is in it.
#[test]
fn a_stamp_signature_binds_every_field() {
    let (_, lines) = linked(3);
    let (notary, _) = signers();
    let stamp = notary
        .sign_stamp(page(&lines, StampKind::Live))
        .expect("the notary signs a live page");
    assert_eq!(stamp.crypto, busbar_contract::crypto::BACKEND);
    assert_eq!(stamp.sig_alg, "ed25519");
    assert_eq!(stamp.key_id, key().key_id());
    assert_eq!(stamp.signature.len(), 64);
    assert_eq!(stamp.verify(&public()), Ok(()));

    let edits: [(&str, fn(&mut Stamp)); 13] = [
        ("node", |s| s.node += 1),
        ("from", |s| s.from += 1),
        ("to", |s| s.to += 1),
        ("fingerprint", |s| s.fingerprint.0[0] ^= 1),
        ("kind", |s| s.kind = StampKind::Final),
        ("sealer", |s| s.sealer += 1),
        ("host", |s| s.host.push('b')),
        ("every", |s| s.every += 1),
        ("stamped_ms", |s| s.stamped_ms += 1),
        ("down_from_ms", |s| s.down_from_ms += 1),
        ("down_to_ms", |s| s.down_to_ms += 1),
        ("crypto", |s| s.crypto.push('x')),
        ("key_cert", |s| s.key_cert = 9),
    ];
    for (field, edit) in edits {
        let mut forged = stamp.clone();
        edit(&mut forged);
        assert_eq!(
            forged.verify(&public()),
            Err(StampError::BadSignature),
            "{field}"
        );
    }
    let mut forged = stamp.clone();
    forged.sig_alg = "ecdsa-p256-sha256".into();
    assert!(forged.verify(&public()).is_err(), "sig_alg");
    let mut forged = stamp.clone();
    forged.key_id = "0000000000000000".into();
    assert_eq!(forged.verify(&public()), Err(StampError::WrongKey));

    let preimage = stamp.preimage();
    assert!(preimage.starts_with(b"busbar.audit.stamp.v1\0"));
    let at = |needle: &[u8]| {
        preimage
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("the field is in the preimage")
    };
    let key_id_at = at(stamp.key_id.as_bytes());
    assert!(at(b"host-a") < key_id_at, "host before key_id");
    assert!(
        at(stamp.crypto.as_bytes()) < key_id_at,
        "crypto before key_id"
    );
    assert!(at(b"ed25519") < key_id_at, "sig_alg before key_id");
}

/// SEALING-FIX test 7 ("stamp domain used as a record signature"): a stamp signature is never a
/// per-line record signature, and a record signature is never a stamp's.
#[test]
fn the_stamp_domain_is_never_a_record_signature() {
    let (_, lines) = linked(2);
    let (notary, _) = signers();
    let stamp = notary
        .sign_stamp(page(&lines, StampKind::Live))
        .expect("the notary signs a live page");
    let digest = stamp.fingerprint.to_string();
    assert_eq!(
        public().verify_digest(&digest, &hex(&stamp.signature)),
        Err(KeyError::BadSignature)
    );
    let mut forged = stamp.clone();
    forged.signature = unhex(&key().sign_digest(&digest));
    assert_eq!(forged.verify(&public()), Err(StampError::BadSignature));
}

/// CRYPTO-SEAM §2.5 key map: only the Bootstrap key signs an `after_restart` page (with `key_cert`
/// 0), and the Bootstrap capability signs no `live` or `final` page.
#[test]
fn only_the_bootstrap_key_signs_a_restart_page() {
    let (_, lines) = linked(2);
    let (notary, bootstrap) = signers();
    assert_eq!(
        notary.sign_stamp(page(&lines, StampKind::AfterRestart)),
        Err(StampSignError::WrongKind(StampKind::AfterRestart))
    );
    for kind in [StampKind::Live, StampKind::Final] {
        assert_eq!(
            bootstrap.sign_restart_page(page(&lines, kind)),
            Err(StampSignError::WrongKind(kind))
        );
    }
    let mut draft = page(&lines, StampKind::AfterRestart);
    draft.key_cert = 5;
    draft.down_from_ms = lines[1].linked_ms;
    draft.down_to_ms = lines[1].linked_ms + 9_000;
    let restart = bootstrap
        .sign_restart_page(draft)
        .expect("the Bootstrap key signs a restart page");
    assert_eq!(restart.key_cert, 0, "a restart page names no certificate");
    assert_eq!(restart.verify(&public()), Ok(()));
    let last = notary
        .sign_stamp(page(&lines, StampKind::Final))
        .expect("the notary signs the final page");
    assert_eq!(last.verify(&public()), Ok(()));
}

/// SEALING-FIX §3.5 "Covering stamp" and test 14's shape: a stamp vouches for a line only through
/// the walk from that line to its `to`, whose last hash must be its fingerprint.
#[test]
fn a_stamp_covers_its_page_only_through_the_walk() {
    let (_, lines) = linked(4);
    let (notary, _) = signers();
    let stamp = notary
        .sign_stamp(page(&lines, StampKind::Live))
        .expect("the notary signs a live page");
    assert_eq!(stamp.covers(&lines), Ok(()));
    assert_eq!(stamp.covers(&lines[1..]), Ok(()));
    assert_eq!(stamp.covers(&lines[3..]), Ok(()));
    assert_eq!(
        stamp.covers(&lines[1..3]),
        Err(CoverError::OutOfRange),
        "a walk that stops short of `to` proves nothing"
    );
    assert_eq!(stamp.covers(&[]), Err(CoverError::OutOfRange));

    let mut rewritten = lines.clone();
    rewritten[2].wall += 1;
    rewritten[2].hash = AuditChain::digest_of(&rewritten[2]);
    assert_eq!(
        stamp.covers(&rewritten[1..]),
        Err(CoverError::Walk(AuditBreak {
            at_index: 3,
            kind: AuditBreakKind::LinkMismatch,
        })),
        "a rewritten line no longer links to the next"
    );
    rewritten[3].prev_hash = rewritten[2].hash.clone();
    rewritten[3].hash = AuditChain::digest_of(&rewritten[3]);
    assert_eq!(
        stamp.covers(&rewritten[1..]),
        Err(CoverError::Fingerprint),
        "a re-linked tail no longer ends at the stamped fingerprint"
    );

    let mut other = stamp.clone();
    other.node += 1;
    assert_eq!(other.covers(&lines), Err(CoverError::WrongNode));
    let mut legacy = lines.clone();
    legacy[3].recipe = Recipe::V7;
    assert_eq!(stamp.covers(&legacy), Err(CoverError::NotALinkLine));
}

/// Stamps and break notices have their own bodies and decoders; neither reads as an audit record,
/// and a relabelled break reason fails its signature.
#[test]
fn stamp_and_break_bodies_round_trip_and_are_not_records() {
    let (_, lines) = linked(2);
    let (notary, bootstrap) = signers();
    let stamp = notary
        .sign_stamp(page(&lines, StampKind::Live))
        .expect("the notary signs a live page");
    let body = stamp_body(&stamp).expect("the body fits");
    assert_eq!(stamp_from_journal_body(&body), Ok(Some(stamp.clone())));
    assert_eq!(from_journal_body(&body, &declared), Ok(None));
    assert_eq!(break_from_journal_body(&body), Ok(None));
    assert!(stamp_from_journal_body(&body[..body.len() - 1]).is_err());

    let notice = bootstrap
        .sign_break(BreakNotice {
            node: NODE,
            sealer: NODE + 1,
            last_good: 1,
            unsealed_from: 2,
            unsealed_to: 2,
            journal_from: 40,
            journal_to: 40,
            reason: BreakReason::Unanchored,
            detected_ms: lines[1].linked_ms + 9_000,
            host: "host-a".into(),
            crypto: String::new(),
            sig_alg: String::new(),
            key_id: String::new(),
            signature: Vec::new(),
        })
        .expect("the Bootstrap key signs a break notice");
    assert_eq!(notice.key_id, key().key_id());
    assert_eq!(notice.verify(&public()), Ok(()));
    let body = break_body(&notice).expect("the body fits");
    assert_eq!(break_from_journal_body(&body), Ok(Some(notice.clone())));
    assert_eq!(stamp_from_journal_body(&body), Ok(None));
    assert_eq!(from_journal_body(&body, &declared), Ok(None));
    let mut forged = notice.clone();
    forged.reason = BreakReason::Span;
    assert_eq!(forged.verify(&public()), Err(StampError::BadSignature));
}

/// The Bootstrap capability signs a batch of unit checkpoint bodies with the same bytes the
/// deployment key's checkpoint signature has today, so the key set verifies them unchanged.
#[test]
fn the_bootstrap_signer_signs_checkpoints_the_key_set_verifies() {
    let (_, bootstrap) = signers();
    let bodies: [&[u8]; 2] = [b"unit checkpoint 1", b"unit checkpoint 2"];
    let signatures = bootstrap
        .sign_checkpoint(&bodies)
        .expect("the Bootstrap key signs checkpoints");
    assert_eq!(signatures.len(), 2);
    let mut keys = AuditKeySet::new();
    keys.insert(public());
    for (body, signature) in bodies.iter().zip(&signatures) {
        assert_eq!(keys.verify_checkpoint_body(body, signature), Ok(()));
        assert_eq!(signature, &key().sign_checkpoint_body(body));
    }
    assert_eq!(
        keys.verify_checkpoint_body(bodies[0], &signatures[1]),
        Err(KeyError::BadSignature)
    );
}

/// `into_grants` consumes the key into one shared local signer by default; a delegated notary key
/// signs live pages under its own identifier while the Bootstrap capability keeps the deployment key.
#[test]
fn grants_route_live_pages_to_the_notary_key() {
    let (notary, bootstrap) = signers();
    assert_eq!(notary.key_id(), key().key_id());
    assert_eq!(bootstrap.key_id(), key().key_id());

    let delegated = busbar_contract::crypto::LocalSigner::from_seed(&[7; 32])
        .expect("the software backend builds a local signer");
    let (notary, bootstrap) = key()
        .into_grants(LiveSigner::Delegated(Box::new(delegated)))
        .expect("the software backend approves both signers");
    let (notary, bootstrap) = (Notary::new(notary), BootstrapSigner::new(bootstrap));
    let notary_key = AuditSigningKey::from_seed(&[7; 32]);
    assert_eq!(notary.key_id(), notary_key.key_id());
    assert_eq!(bootstrap.key_id(), key().key_id());

    let (_, lines) = linked(2);
    let stamp = notary
        .sign_stamp(page(&lines, StampKind::Live))
        .expect("the notary key signs a live page");
    assert_eq!(stamp.key_id, notary_key.key_id());
    assert_eq!(stamp.verify(&public()), Err(StampError::WrongKey));
    let notary_public =
        AuditVerifyingKey::from_hex(&notary_key.public_key_hex()).expect("a public key");
    assert_eq!(stamp.verify(&notary_public), Ok(()));
}
