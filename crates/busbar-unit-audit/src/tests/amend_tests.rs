// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two amendment classes.

use busbar_caps::{Audit as AuditStep, KernelSeal, UnitToken};

use crate::amend::{content_access, correction, AmendBody, AmendChain, AmendClass, Reader};
use crate::record::{AuditBreakKind, OpClassId, Subject};

fn token() -> UnitToken<AuditStep> {
    UnitToken::mint(&KernelSeal::acquire_for_kernel())
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
