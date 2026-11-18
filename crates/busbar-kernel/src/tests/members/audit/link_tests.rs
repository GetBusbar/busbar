// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALING-FIX r20 MR-4 (kernel-audit half): the link-only line, recipe `busbar.audit.link.v1`,
//! journal tag `audit.v8`. Its content is hashed before the chain is read, it carries no per-line
//! signature, and the chain it builds still walks and still catches an edit.

use busbar_contract::caps::{Audit as AuditStep, MeterClassId, Pass};
use busbar_kernel_audit::digest::{Digest, Framing};
use busbar_kernel_audit::journal::{from_journal_body, head_from_journal_body, journal_body};
use busbar_kernel_audit::recipe::DigestValue;
use busbar_kernel_audit::record::{AuditBreak, AuditBreakKind, AuditChain, AuditRecord};
use busbar_kernel_audit::{line_fingerprint, line_hasher, Fingerprint, Recipe, LINK_RECIPE};

/// The node every line here names.
pub(super) const NODE: u64 = 21;

/// The wall clock (ms) line `seq` is linked at.
const LINKED_AT: u64 = 1_700_000_000_000;

fn declared(name: &str) -> Option<MeterClassId> {
    ["tokens_in", "tokens_out"]
        .into_iter()
        .find(|c| *c == name)
        .map(MeterClassId::new)
}

fn pass() -> Pass<AuditStep> {
    Pass::<AuditStep>::mint(&crate::seal::acquire())
}

/// `n` lines prepared, linked and advanced on a fresh chain of [`NODE`], line `k` linked at
/// `LINKED_AT + k`.
pub(super) fn linked(n: u64) -> (AuditChain, Vec<AuditRecord>) {
    let mut chain = AuditChain::new().sealing_as(NODE);
    let mut lines = Vec::new();
    for unit in 1..=n {
        let mut inputs = super::sign_tests::rich_inputs(unit);
        inputs.what.incarnation = 3;
        let line = chain.link(AuditChain::prepare(inputs, NODE), LINKED_AT + unit, &pass());
        chain.advance(&line);
        lines.push(line.into_record());
    }
    (chain, lines)
}

#[test]
fn certificate_shares_unit_chain_and_refuses_stale_signing_position() {
    use busbar_contract::crypto::{LocalSigner, Signer};
    use busbar_kernel_audit::linked_record::{verify_linked_chain, AuditLinkedRecord};
    use busbar_kernel_audit::{AuditSigningKey, BootstrapSigner, LiveSigner};
    let (mut chain, units) = linked(1);
    let (_, grant) = AuditSigningKey::from_seed(&[7; 32])
        .into_grants(LiveSigner::SameAsBootstrap)
        .unwrap();
    let bootstrap = BootstrapSigner::new(grant);
    let live = LocalSigner::from_seed(&[9; 32]).unwrap();
    let previous = Fingerprint::from_hex(chain.head()).unwrap();
    let certificate = bootstrap
        .sign_notary_key(NODE, chain.next_seq(), previous, live.public_key())
        .unwrap();
    let prepare = || AuditChain::prepare_notary_key(NODE, 2, previous, certificate.clone());
    let linked = chain
        .link_notary_key(prepare(), LINKED_AT + 2, &pass())
        .unwrap();
    assert_eq!(chain.next_seq(), 2, "link without stage does not advance");
    chain.advance_notary_key(&linked).unwrap();
    assert_eq!(chain.next_seq(), 3);
    assert_eq!(chain.head(), linked.record().fingerprint.to_string());
    assert_eq!(chain.heads().tip().unwrap().seq, 2);
    assert!(chain
        .link_notary_key(prepare(), LINKED_AT + 3, &pass())
        .is_err());
    assert!(
        chain.advance_notary_key(&linked).is_err(),
        "no repeated advance"
    );
    let next = chain.link(
        AuditChain::prepare(super::sign_tests::rich_inputs(3), NODE),
        LINKED_AT + 3,
        &pass(),
    );
    chain.advance(&next);
    let rows = vec![
        AuditLinkedRecord::Unit(Box::new(units[0].clone())),
        AuditLinkedRecord::NotaryKey(Box::new(linked.into_record())),
        AuditLinkedRecord::Unit(Box::new(next.into_record())),
    ];
    verify_linked_chain(&rows).unwrap();
    let resumed = AuditChain::resume_linked(&rows).unwrap();
    assert_eq!(resumed.next_seq(), 4);
    assert_eq!(resumed.head(), chain.head());
}

/// SEALING-FIX test 25(b): a link line names `busbar.audit.link.v1`, signs nothing, and its hash is
/// SHA-256 over its content fields first, then `linked_ms`, `seq` and the predecessor's 32 raw
/// bytes, each framed by its big-endian eight-byte length.
#[test]
fn a_link_line_is_sha256_over_its_content_then_its_position() {
    assert_eq!(LINK_RECIPE, "busbar.audit.link.v1");
    let (_, lines) = linked(2);
    assert_eq!(
        lines[0].prev_hash, "",
        "the first line links to the genesis"
    );
    assert_eq!(lines[1].prev_hash, lines[0].hash);
    for (i, line) in lines.iter().enumerate() {
        let seq = i as u64 + 1;
        assert_eq!(line.recipe, Recipe::V8);
        assert_eq!(line.recipe.name(), "busbar.audit.link.v1");
        assert_eq!((line.seq, line.linked_ms), (seq, LINKED_AT + seq));
        assert_eq!(line.signature, None, "a link line is signed by no one");
        assert_eq!(line.key_id, None);

        let fields = super::digest_fields(line);
        assert_eq!(fields[0].name, "subject_tag", "the content comes first");
        let names: Vec<&str> = fields[fields.len() - 3..].iter().map(|f| f.name).collect();
        assert_eq!(
            names,
            ["linked_ms", "seq", "prev_hash"],
            "the position comes last"
        );

        let mut framed = Digest::new(Framing::LengthPrefixed);
        for field in &fields[..fields.len() - 1] {
            match &field.value {
                DigestValue::Text(text) => framed.text(text),
                DigestValue::Num(n) => framed.num(*n),
            };
        }
        let prev = Fingerprint::from_hex(&line.prev_hash).expect("a fingerprint or the genesis");
        framed.raw(&32u64.to_be_bytes()).raw(&prev.0);
        let expected = Fingerprint(busbar_contract::crypto::sha256(&framed.into_framed()));
        assert_eq!(line.hash, expected.to_string(), "line {seq}");
    }
}

/// A chain of link lines walks like any other, and an edit of any field, the date included, is a
/// digest mismatch; a renumbered line is a sequence mismatch.
#[test]
fn a_link_chain_walks_and_catches_an_edit() {
    let (chain, lines) = linked(3);
    assert_eq!(AuditChain::verify_chain(&lines), Ok(()));
    assert_eq!((chain.next_seq(), chain.sealed()), (4, 3));
    assert_eq!(chain.head(), lines[2].hash);
    for line in &lines {
        assert_eq!(AuditChain::digest_of(line), line.hash);
        assert_eq!(line_fingerprint(line).to_string(), line.hash);
    }
    let digest_mismatch = Err(AuditBreak {
        at_index: 2,
        kind: AuditBreakKind::DigestMismatch,
    });
    let mut edited = lines.clone();
    edited[1].linked_ms += 1;
    assert_eq!(AuditChain::verify_chain(&edited), digest_mismatch, "date");
    let mut edited = lines.clone();
    edited[1].wall += 1;
    assert_eq!(
        AuditChain::verify_chain(&edited),
        digest_mismatch,
        "content"
    );
    let mut edited = lines.clone();
    edited[1].unit.status = 503;
    assert_eq!(
        AuditChain::verify_chain(&edited),
        digest_mismatch,
        "unit facts"
    );
    let mut edited = lines.clone();
    edited[1].seq = 7;
    assert_eq!(
        AuditChain::verify_chain(&edited),
        Err(AuditBreak {
            at_index: 2,
            kind: AuditBreakKind::SequenceMismatch {
                expected: 2,
                found: 7
            },
        })
    );
}

/// `link` places a line at the next position without moving the chain, so a line whose stage is
/// refused leaves no hole; only `advance` moves it.
#[test]
fn link_takes_a_position_and_only_advance_moves_the_chain() {
    let mut chain = AuditChain::new().sealing_as(NODE);
    let refused = chain.link(
        AuditChain::prepare(super::sign_tests::rich_inputs(1), NODE),
        5,
        &pass(),
    );
    let staged = chain.link(
        AuditChain::prepare(super::sign_tests::rich_inputs(2), NODE),
        6,
        &pass(),
    );
    assert_eq!((refused.record().seq, staged.record().seq), (1, 1));
    assert_eq!(refused.record().prev_hash, "");
    assert_eq!((chain.next_seq(), chain.sealed(), chain.head()), (1, 0, ""));
    assert_eq!(refused.fingerprint().to_string(), refused.record().hash);

    chain.advance(&staged);
    assert_eq!((chain.next_seq(), chain.sealed()), (2, 1));
    assert_eq!(chain.head(), staged.record().hash);
    let next = chain.link(
        AuditChain::prepare(super::sign_tests::rich_inputs(3), NODE),
        7,
        &pass(),
    );
    assert_eq!(next.record().seq, 2);
    assert_eq!(next.record().prev_hash, staged.record().hash);
}

/// A link line's journal body (`audit.v8`) round-trips, carries both fingerprints as 32 raw bytes
/// and no signature, and its head prefix reads back without the meter vocabulary.
#[test]
fn a_link_line_round_trips_through_its_journal_body() {
    let (_, lines) = linked(2);
    for line in &lines {
        let body = journal_body(line).expect("the body fits");
        assert_eq!(&body[..4], &8u32.to_be_bytes());
        assert_eq!(&body[4..12], b"audit.v8");
        assert_eq!(from_journal_body(&body, &declared), Ok(Some(line.clone())));
        let head = match head_from_journal_body(&body) {
            Ok(Some(head)) => head,
            Ok(None) => panic!("a link line is an audit body"),
            Err(why) => panic!("the head prefix decodes: {why}"),
        };
        assert_eq!((head.head.seq, head.node), (line.seq, NODE));
        assert_eq!(head.head.hash, line.hash);
        assert_eq!(head.prev_hash, line.prev_hash);
        assert_eq!((head.head.signature, head.head.key_id), (None, None));
    }
    let body = journal_body(&lines[1]).expect("the body fits");
    let hash = Fingerprint::from_hex(&lines[1].hash).expect("a fingerprint");
    assert!(body.windows(32).any(|w| w == hash.0), "raw bytes");
    assert!(
        !body.windows(64).any(|w| w == lines[1].hash.as_bytes()),
        "never the hex text"
    );
}

/// SEALING-FIX test 25(c), decode half: a line naming a link recipe this build cannot recompute is
/// refused as `AUDIT_RECIPE_UNSUPPORTED`, never read as verified.
#[test]
fn a_line_under_an_unknown_link_recipe_is_refused_as_unsupported() {
    assert!(line_hasher(LINK_RECIPE).is_ok());
    assert!(line_hasher("busbar.audit.link.v2-test").is_err());

    let (_, lines) = linked(1);
    let body = journal_body(&lines[0]).expect("the body fits");
    let tag = u32::from_be_bytes(body[..4].try_into().expect("a length")) as usize;
    let at = 4 + tag;
    let len = u32::from_be_bytes(body[at..at + 4].try_into().expect("a length")) as usize;
    assert_eq!(&body[at + 4..at + 4 + len], LINK_RECIPE.as_bytes());
    let other = b"busbar.audit.link.v2-test";
    let mut forged = body[..at].to_vec();
    forged.extend_from_slice(&(other.len() as u32).to_be_bytes());
    forged.extend_from_slice(other);
    forged.extend_from_slice(&body[at + 4 + len..]);

    let refused = from_journal_body(&forged, &declared).expect_err("an unknown recipe is refused");
    assert!(refused.starts_with("AUDIT_RECIPE_UNSUPPORTED"), "{refused}");
    match head_from_journal_body(&forged) {
        Err(why) => assert!(why.starts_with("AUDIT_RECIPE_UNSUPPORTED"), "{why}"),
        Ok(_) => panic!("the head prefix of an unknown recipe is refused too"),
    }
}

/// PM ruling D-AUDIT (2026-11-17): every tampering case is detected on a V8 chain as `link` seals it.
/// An edited line or count is a digest mismatch; an edited, dropped or reordered link breaks the
/// walk; a truncated tail walks (a prefix is a chain) but no longer ends at the chain's head.
#[test]
fn every_tampering_of_a_v8_chain_is_detected() {
    let (chain, lines) = linked(4);
    assert!(lines.iter().all(|l| l.recipe == Recipe::V8));
    assert_eq!(AuditChain::verify_chain(&lines), Ok(()));
    let kind = |chain: &[AuditRecord]| AuditChain::verify_chain(chain).map_err(|b| b.kind);

    let mut edited = lines.clone();
    edited[1].mono += 1;
    assert_eq!(
        kind(&edited),
        Err(AuditBreakKind::DigestMismatch),
        "edit a line"
    );
    let mut edited = lines.clone();
    edited[2].usage.fee_count += 1;
    assert_eq!(
        kind(&edited),
        Err(AuditBreakKind::DigestMismatch),
        "change a count"
    );
    let mut edited = lines.clone();
    edited[2].usage.lines.pop();
    assert_eq!(
        kind(&edited),
        Err(AuditBreakKind::DigestMismatch),
        "drop a usage line"
    );

    let mut edited = lines.clone();
    edited[2].prev_hash = lines[0].hash.clone();
    assert!(
        kind(&edited).is_err(),
        "edit a prev link to another real line"
    );
    edited[2].hash = AuditChain::digest_of(&edited[2]);
    assert!(
        kind(&edited).is_err(),
        "an edited prev link stays detected even when its line is rehashed"
    );

    let mut dropped = lines.clone();
    dropped.remove(1);
    assert!(
        matches!(
            kind(&dropped),
            Err(AuditBreakKind::LinkMismatch | AuditBreakKind::SequenceMismatch { .. })
        ),
        "drop a line: {:?}",
        kind(&dropped)
    );
    let mut reordered = lines.clone();
    reordered.swap(1, 2);
    assert!(
        matches!(
            kind(&reordered),
            Err(AuditBreakKind::LinkMismatch | AuditBreakKind::SequenceMismatch { .. })
        ),
        "reorder two lines: {:?}",
        kind(&reordered)
    );

    let truncated = &lines[..3];
    assert_eq!(kind(truncated), Ok(()), "a prefix walks");
    assert_eq!(chain.head(), lines[3].hash);
    assert_ne!(
        truncated.last().unwrap().hash,
        chain.head(),
        "a truncated tail no longer ends at the chain's head"
    );
}
