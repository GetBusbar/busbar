// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two amendment classes.

use busbar_caps::{Audit as AuditStep, KernelSeal, UnitToken};

use crate::amend::{content_access, correction, AmendBody, AmendChain, AmendClass, Reader};
use crate::record::{AuditBreakKind, OpClassId, Subject};

fn token() -> UnitToken<AuditStep> {
    UnitToken::mint(&KernelSeal::acquire_for_kernel())
}

/// The two constructors are pinned against each other, as the previous release's chain already pins
/// its own: a DERIVED default gives a next position of zero, which is not a position a chain has —
/// the first entry is one — and the position is DIGESTED, so a chain that quietly started at zero
/// would seal entries a verifier walking from one rejects.
#[test]
fn the_default_amend_chain_is_the_new_one_because_a_derived_default_starts_at_zero() {
    let made = AmendChain::new();
    let defaulted = AmendChain::default();
    assert_eq!(made.next_seq(), 1);
    assert_eq!(defaulted.next_seq(), made.next_seq());
    assert_eq!(defaulted.head(), made.head());
}

/// The same pinning for the fixed record's chain, which digests its position too.
#[test]
fn the_default_audit_chain_is_the_new_one() {
    let made = crate::record::AuditChain::new();
    let defaulted = crate::record::AuditChain::default();
    assert_eq!(made.next_seq(), 1);
    assert_eq!(defaulted.next_seq(), made.next_seq());
    assert_eq!(defaulted.head(), made.head());
}

fn an_access() -> AmendBody {
    content_access(
        Reader::Hook,
        "compress",
        Subject::PrincipalId("pseudonym-1".into()),
        OpClassId::new("chat.completion"),
        vec!["messages".into(), "system".into()],
        1_700_000_000,
    )
}

fn a_correction() -> AmendBody {
    correction(
        "the-entry-being-amended",
        Subject::PrincipalId("pseudonym-1".into()),
        1_000,
        800,
        "operator",
        "duplicate charge on a retried request",
        1_700_000_100,
    )
}

#[test]
fn an_access_records_who_read_what_and_never_what_they_read() {
    let mut chain = AmendChain::new();
    let amendment = chain.append(an_access(), &token());
    assert_eq!(amendment.class(), AmendClass::Access);
    match &amendment.body {
        AmendBody::Access(a) => {
            assert_eq!(a.reader, Reader::Hook);
            assert_eq!(a.name, "compress");
            // FIELD NAMES, not values. An amendment that carried the content would put content on a
            // chain that cannot be erased, which is the one thing the design forbids outright.
            assert_eq!(a.fields, vec!["messages".to_string(), "system".to_string()]);
        }
        other => panic!("expected an access, got {other:?}"),
    }
}

#[test]
fn an_export_access_is_recorded_the_same_way_a_hook_access_is() {
    let mut chain = AmendChain::new();
    let export = content_access(
        Reader::Export,
        "siem",
        Subject::Arrival,
        OpClassId::new("chat.completion"),
        vec!["response".into()],
        1,
    );
    let amendment = chain.append(export, &token());
    assert_eq!(amendment.class(), AmendClass::Access);
    assert!(amendment.hash.len() == 64);
}

#[test]
fn a_correction_names_what_it_amends_and_why() {
    let mut chain = AmendChain::new();
    let amendment = chain.append(a_correction(), &token());
    assert_eq!(amendment.class(), AmendClass::Adjust);
    match &amendment.body {
        AmendBody::Adjust(a) => {
            assert_eq!(a.amends_hash, "the-entry-being-amended");
            assert_eq!(a.delta(), -200);
            assert!(
                !a.reason.is_empty(),
                "a correction nobody can question is not one to trust"
            );
            assert_eq!(a.authorised_by, "operator");
        }
        other => panic!("expected a correction, got {other:?}"),
    }
}

#[test]
fn the_original_figure_survives_the_correction() {
    // The point of an amendment being a new entry: there is no state in which the original amount
    // has quietly become something else.
    let mut chain = AmendChain::new();
    let amendment = chain.append(a_correction(), &token());
    match &amendment.body {
        AmendBody::Adjust(a) => {
            assert_eq!(a.was, 1_000);
            assert_eq!(a.now, 800);
        }
        other => panic!("expected a correction, got {other:?}"),
    }
}

#[test]
fn accesses_and_corrections_share_one_chain_so_their_order_survives() {
    let mut chain = AmendChain::new();
    let first = chain.append(an_access(), &token());
    let second = chain.append(a_correction(), &token());
    let third = chain.append(an_access(), &token());

    assert_eq!(first.seq, 1);
    assert_eq!(second.seq, 2);
    assert_eq!(third.seq, 3);
    assert_eq!(second.prev_hash, first.hash);
    assert_eq!(third.prev_hash, second.hash);
    assert!(AmendChain::verify(&[first, second, third]).is_ok());
}

#[test]
fn editing_an_amendment_is_caught() {
    let mut chain = AmendChain::new();
    let mut run = vec![
        chain.append(an_access(), &token()),
        chain.append(a_correction(), &token()),
        chain.append(an_access(), &token()),
    ];
    assert!(AmendChain::verify(&run).is_ok());

    match &mut run[1].body {
        AmendBody::Adjust(a) => a.now += 1,
        other => panic!("expected a correction, got {other:?}"),
    }
    let brk = AmendChain::verify(&run).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::DigestMismatch);
    assert_eq!(brk.at_index, 2);
}

#[test]
fn removing_an_amendment_from_the_middle_is_caught() {
    let mut chain = AmendChain::new();
    let mut run = vec![
        chain.append(an_access(), &token()),
        chain.append(a_correction(), &token()),
        chain.append(an_access(), &token()),
    ];
    run.remove(1);
    let brk = AmendChain::verify(&run).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
}

/// A DELTA THAT WOULD OVERRUN THE SIGNED RANGE PINS AT THE EXTREME, rather than panicking in a
/// debug build or wrapping — into a correction in the opposite direction — in a release one.
///
/// The two figures themselves are what the chain digests and what a reader answers questions from;
/// this is a convenience over them, so saturating costs nothing and wrapping would mislead.
#[test]
fn a_delta_too_large_for_the_range_saturates_instead_of_wrapping() {
    let far_apart = correction(
        "e",
        Subject::Aggregate,
        i128::MIN,
        i128::MAX,
        "operator",
        "a pair no meter could report",
        1,
    );
    match &far_apart {
        AmendBody::Adjust(a) => assert_eq!(a.delta(), i128::MAX),
        other => panic!("expected a correction, got {other:?}"),
    }
    // And the other way round, which is the one that would have read as an INCREASE.
    match &correction(
        "e",
        Subject::Aggregate,
        i128::MAX,
        i128::MIN,
        "operator",
        "the same pair, reversed",
        1,
    ) {
        AmendBody::Adjust(a) => assert_eq!(a.delta(), i128::MIN),
        other => panic!("expected a correction, got {other:?}"),
    }
}

/// A correction DOWNWARD is the commonest one there is, so `was` exceeding `now` is an ordinary
/// amendment and not something to refuse.
#[test]
fn a_correction_downward_is_an_ordinary_amendment() {
    match &a_correction() {
        AmendBody::Adjust(a) => {
            assert!(a.was > a.now);
            assert_eq!(a.delta(), -200);
        }
        other => panic!("expected a correction, got {other:?}"),
    }
}

/// CUTTING THE HEAD OFF A CORRECTION HISTORY IS CAUGHT.
///
/// The survivors link perfectly to each other — every one still names the amendment before it — so
/// the only thing that says entries are missing is that the run does not begin where the chain
/// does. The earliest amendments are the ones somebody covering a correction would drop first.
#[test]
fn truncating_the_head_of_an_amendment_run_is_caught() {
    let mut chain = AmendChain::new();
    let mut run = vec![
        chain.append(an_access(), &token()),
        chain.append(a_correction(), &token()),
        chain.append(an_access(), &token()),
    ];
    assert!(AmendChain::verify(&run).is_ok());

    run.remove(0);
    let brk = AmendChain::verify(&run).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
    assert_eq!(brk.at_index, 1, "the cut is reported at the run's start");
}

/// CUTTING THE TAIL OFF takes the chain's own head to notice, exactly as it does for records.
#[test]
fn truncating_the_tail_of_an_amendment_run_is_caught_against_the_chain_head() {
    let mut chain = AmendChain::new();
    let mut run = vec![
        chain.append(an_access(), &token()),
        chain.append(a_correction(), &token()),
        chain.append(an_access(), &token()),
    ];
    assert!(chain.verify_to_head(&run).is_ok());

    run.pop();
    // The survivors still walk from the genesis, which is precisely why the walk alone cannot see
    // this and the head check must.
    assert!(AmendChain::verify(&run).is_ok());
    let brk = chain.verify_to_head(&run).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
}

/// An EMPTY run verifies against itself and fails against a chain that sealed something: the two
/// readings of "no amendments" are only distinguishable with the chain on hand.
#[test]
fn an_empty_run_verifies_alone_and_fails_against_a_chain_that_sealed_one() {
    assert!(AmendChain::verify(&[]).is_ok());
    let mut chain = AmendChain::new();
    let _ = chain.append(a_correction(), &token());
    assert!(chain.verify_to_head(&[]).is_err());
}

#[test]
fn a_chain_resumed_from_a_persisted_tail_continues_it() {
    let mut chain = AmendChain::new();
    let first = chain.append(an_access(), &token());
    let mut resumed = AmendChain::resume(chain.head().to_string(), chain.next_seq());
    let second = resumed.append(a_correction(), &token());
    assert_eq!(second.seq, 2);
    assert_eq!(second.prev_hash, first.hash);
    assert!(AmendChain::verify(&[first, second]).is_ok());
}

/// EVERY SUBJECT TAG THE AMENDMENT DIGEST SEALS IS SPELLED OUT, not derived.
///
/// The digested text for the subject used to be whatever the derived `Debug` printed, which made
/// every sealed amendment hostage to a rename: an amendment is a correction to money, and a
/// correction that reports itself tampered because somebody renamed a variant is worse than no
/// correction at all. The spellings live in the production file now; this pins each one, so a
/// rename shows up here — as a difference somebody has to look at — instead of in the hash.
#[test]
fn the_frozen_subject_tags_are_the_ones_the_amendment_digest_seals() {
    use crate::record::{subject_tag, subject_value};

    assert_eq!(
        subject_tag(&Subject::PrincipalId("pseudonym-1".into())),
        "principal"
    );
    assert_eq!(subject_tag(&Subject::Arrival), "arrival");
    assert_eq!(subject_tag(&Subject::Node(7)), "node");
    assert_eq!(subject_tag(&Subject::Aggregate), "aggregate");

    // The value is the second half of the pair, and it is what stops a principal whose pseudonym
    // reads as another subject's tag from digesting as that subject.
    assert_eq!(
        subject_value(&Subject::PrincipalId("pseudonym-1".into())),
        "pseudonym-1"
    );
    assert_eq!(subject_value(&Subject::Arrival), "");
    assert_eq!(subject_value(&Subject::Node(7)), "7");
    assert_eq!(subject_value(&Subject::Aggregate), "");
}

/// A PRINCIPAL NAMED AFTER ANOTHER SUBJECT'S TAG STILL DIGESTS AS A PRINCIPAL.
///
/// The tag and the value are two digested fields rather than one joined string, which is the whole
/// reason this cannot collide.
#[test]
fn a_principal_pseudonym_that_reads_as_a_node_does_not_digest_as_one() {
    let mut one = AmendChain::new();
    let mut other = AmendChain::new();
    let as_principal = one.append(
        correction(
            "e",
            Subject::PrincipalId("7".into()),
            10,
            5,
            "operator",
            "why",
            1,
        ),
        &token(),
    );
    let as_node = other.append(
        correction("e", Subject::Node(7), 10, 5, "operator", "why", 1),
        &token(),
    );
    assert_ne!(as_principal.hash, as_node.hash);
}

/// THE SEALED AMENDMENT DIGEST IS A FROZEN VALUE, not whatever today's encoder happens to produce.
///
/// Every amendment a deployment has written is verified by recomputing this digest, so a change
/// that moves it makes a stored correction report itself TAMPERED. The hex below was produced by an
/// earlier build over the fixture in this test; it is a value to preserve, never one to re-capture
/// from a failing run. Moving it needs a migration for anything already on disk, not an edit here.
#[test]
fn the_sealed_digest_of_an_amendment_is_the_frozen_hex() {
    let mut chain = AmendChain::new();
    let access = chain.append(an_access(), &token());
    let adjust = chain.append(a_correction(), &token());
    assert_eq!(
        access.hash, "2a9ac567b083d3fc25768d98445737fb2aee7a20db291930467a7abbfa83944b",
        "the amendment digest MOVED. Every stored correction now reports itself tampered. Restore \
         the encoding; do not re-capture this constant."
    );
    assert_eq!(
        adjust.hash, "56addfe3f65d8c5fa750b61cbec3fc0fb987c6510238246757660b4638d0a2bc",
        "the amendment digest MOVED. Every stored correction now reports itself tampered. Restore \
         the encoding; do not re-capture this constant."
    );
}

#[test]
fn the_two_class_names_are_the_two_the_journal_knows() {
    assert_eq!(AmendClass::Access.as_str(), "access");
    assert_eq!(AmendClass::Adjust.as_str(), "adjust");
    assert_eq!(AmendClass::Access.to_string(), "access");
}

#[test]
fn an_amendment_names_the_audit_record_it_amends() {
    // The one place the two chains touch: an amendment carries the digest of the entry it concerns,
    // so a reader can go from one to the other without the two chains sharing a buffer.
    use crate::amend::amends;
    use crate::record::{
        Amount, Audit, AuditChain, AuditInputs, Controls, FinishClass, OutcomeFacts, What,
    };
    use busbar_caps::{Origin, OriginKind, Outcome, UnitKey};

    let mut audit = AuditChain::new();
    let record = audit.seal(
        AuditInputs {
            subject: Subject::PrincipalId("p".into()),
            what: What {
                unit_key: UnitKey::new(1),
                op_class: OpClassId::new("chat.completion"),
                destination: None,
                parent: None,
                pre_hook_head: None,
                post_hook_head: None,
            },
            wall: 1,
            mono: 1,
            origin: Origin::seal(&KernelSeal::acquire_for_kernel(), OriginKind::Client),
            outcome: OutcomeFacts {
                unit_end: Outcome::Completed,
                step: None,
                finish: FinishClass::Complete,
                hook_failed: false,
                emission_delta: 0,
                stale_policy: false,
            },
            amount: Amount {
                lines: Vec::new(),
                pre_tier: 100,
                priced: 100,
                tier_bp: 10_000,
                fee_count: 0,
                currency: "USD".into(),
                rate_card_version: 1,
                bucket_chain_ref: String::new(),
            },
            controls: Controls::default(),
            correlation_label: None,
        },
        &token(),
    );

    let mut chain = AmendChain::new();
    let amendment = chain.append(
        correction(
            &amends(&record),
            Subject::PrincipalId("p".into()),
            100,
            0,
            "operator",
            "refunded in full",
            2,
        ),
        &token(),
    );
    match &amendment.body {
        AmendBody::Adjust(a) => assert_eq!(a.amends_hash, record.hash),
        other => panic!("expected a correction, got {other:?}"),
    }
}
