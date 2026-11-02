// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::inputs;
use busbar_contract::caps::Pass;
use busbar_contract::count::Count;
use busbar_kernel_audit::amend::{
    content_access, Adjust, AmendBody, AmendChain, Amendment, Reader,
};
use busbar_kernel_audit::record::{
    Audit, AuditBreak, AuditBreakKind, AuditChain, AuditRecord, OpClassId, Subject,
};

fn three_amendments() -> (AmendChain, Vec<Amendment>) {
    let mut chain = AmendChain::new();
    let t = Pass::<busbar_contract::caps::Audit>::mint(&crate::seal::acquire());
    let a = chain.append(
        content_access(
            Reader::Hook,
            "compress",
            Subject::PrincipalId("alice".into()),
            OpClassId::new("chat"),
            vec!["prompt".into()],
            10,
        ),
        &t,
    );
    let b = chain.append(
        content_access(
            Reader::Export,
            "s3",
            Subject::PrincipalId("alice".into()),
            OpClassId::new("chat"),
            vec!["completion".into()],
            20,
        ),
        &t,
    );
    let c = chain.append(
        legacy_correction(
            &b.hash,
            Subject::PrincipalId("alice".into()),
            "lane",
            1,
            [(
                "input_tokens".to_string(),
                Count::from_integer(100).unwrap(),
            )]
            .into(),
            [("input_tokens".to_string(), Count::from_integer(90).unwrap())].into(),
            "carol",
            "overbilled",
            30,
        ),
        &t,
    );
    (chain, vec![a, b, c])
}

#[test]
fn a_truncated_amendment_run_relinked_to_look_like_a_genesis_is_refused_for_its_position() {
    let (_chain, amendments) = three_amendments();
    let mut forged = amendments[1..].to_vec();
    forged[0].prev_hash = String::new();

    forged[0].hash = AmendChain::digest_of(&forged[0]);
    forged[1].prev_hash = forged[0].hash.clone();
    forged[1].hash = AmendChain::digest_of(&forged[1]);

    assert_eq!(forged[0].prev_hash, "");
    assert_eq!(forged[1].prev_hash, forged[0].hash);

    assert_eq!(forged[0].seq, 2);

    let err = AmendChain::verify(&forged)
        .expect_err("a run that does not start at the genesis is missing amendments");
    assert_eq!(err.at_index, 1);

    assert_eq!(
        err.kind,
        AuditBreakKind::SequenceMismatch {
            expected: 1,
            found: 2
        }
    );
}

#[test]
fn an_amendment_run_at_the_right_positions_pointing_at_the_wrong_predecessor_is_refused() {
    let (_chain, mut amendments) = three_amendments();
    amendments[1].prev_hash = "not-the-predecessors-hash".to_string();
    amendments[1].hash = AmendChain::digest_of(&amendments[1]);

    assert_eq!(amendments[1].seq, 2, "the position is untouched");
    let err = AmendChain::verify(&amendments)
        .expect_err("an amendment pointing at the wrong predecessor is a break");
    assert_eq!(err.at_index, 2);
    assert_eq!(err.kind, AuditBreakKind::LinkMismatch);
}

#[test]
fn a_run_that_matches_the_chains_head_on_only_one_of_the_two_counts_is_refused() {
    let (chain, amendments) = three_amendments();
    chain
        .verify_to_head(&amendments)
        .expect("the whole run against its own chain is whole");

    let ahead = AmendChain::resume(chain.head().to_string(), chain.next_seq() + 1);
    let err = ahead
        .verify_to_head(&amendments)
        .expect_err("a chain that has sealed an amendment this run does not carry is a break");
    assert_eq!(err.kind, AuditBreakKind::LinkMismatch);
    assert_eq!(err.at_index, amendments.len());

    let substituted = AmendChain::resume("a-different-head".to_string(), chain.next_seq());
    let err = substituted
        .verify_to_head(&amendments)
        .expect_err("a run ending on an amendment the chain did not seal is a break");
    assert_eq!(err.kind, AuditBreakKind::LinkMismatch);
}

#[test]
fn an_empty_amendment_run_against_a_chain_that_has_sealed_amendments_is_refused() {
    let (chain, _amendments) = three_amendments();
    AmendChain::verify(&[]).expect("the walk alone cannot know an empty run is wrong");
    chain
        .verify_to_head(&[])
        .expect_err("every amendment was deleted and the chain's own head says so");

    AmendChain::new()
        .verify_to_head(&[])
        .expect("a chain with no amendments is whole");
}

fn three_records() -> (AuditChain, Vec<AuditRecord>) {
    let mut chain = AuditChain::new();
    let t = Pass::<busbar_contract::caps::Audit>::mint(&crate::seal::acquire());
    let records = (1..=3).map(|i| chain.seal(inputs(i), &t)).collect();
    (chain, records)
}

#[test]
fn a_renumbered_record_run_with_every_link_intact_is_reported_as_renumbered() {
    let (_chain, records) = three_records();
    let mut forged = records.clone();
    forged[1].seq = 3;
    forged[1].hash = AuditChain::digest_of(&forged[1]);
    forged[2].seq = 4;
    forged[2].prev_hash = forged[1].hash.clone();
    forged[2].hash = AuditChain::digest_of(&forged[2]);
    assert_eq!(forged[1].prev_hash, forged[0].hash, "the link is intact");

    let brk = AuditChain::verify_chain(&forged).expect_err("a renumbered run is a break");
    assert_eq!(brk.at_index, 2);
    assert_eq!(
        brk.kind,
        AuditBreakKind::SequenceMismatch {
            expected: 2,
            found: 3
        }
    );
    let said = brk.to_string();
    assert!(
        said.contains("RENUMBERED") && !said.contains("does not point at its predecessor"),
        "a renumbering was reported as a splice: {said:?}"
    );

    let spliced = vec![records[0].clone(), records[2].clone()];
    assert_eq!(
        AuditChain::verify_chain(&spliced).unwrap_err().kind,
        AuditBreakKind::LinkMismatch
    );
}

#[test]
fn an_audit_break_says_where_it_is_and_which_tamper_it_was() {
    let edited = AuditBreak {
        at_index: 3,
        kind: AuditBreakKind::DigestMismatch,
    }
    .to_string();
    assert!(
        edited.contains('3'),
        "the break did not say where it is: {edited:?}"
    );
    assert!(
        edited.contains("EDITED"),
        "a digest mismatch did not name an edit: {edited:?}"
    );

    let spliced = AuditBreak {
        at_index: 7,
        kind: AuditBreakKind::LinkMismatch,
    }
    .to_string();
    assert!(
        spliced.contains('7'),
        "the break did not say where it is: {spliced:?}"
    );
    assert!(
        spliced.contains("INSERTED")
            && spliced.contains("REMOVED")
            && spliced.contains("REORDERED"),
        "a link mismatch did not name what could have happened: {spliced:?}"
    );

    assert_ne!(edited, spliced);
    assert!(!edited.is_empty() && !spliced.is_empty());

    assert_ne!(
        edited,
        AuditBreak {
            at_index: 4,
            kind: AuditBreakKind::DigestMismatch
        }
        .to_string()
    );
}

#[allow(clippy::too_many_arguments)]
fn legacy_correction(
    amends: &str,
    subject: busbar_kernel_audit::record::Subject,
    lane: &str,
    card_epoch_ms: u64,
    was: busbar_kernel_audit::amend::ClassCounts,
    now: busbar_kernel_audit::amend::ClassCounts,
    authorised_by: &str,
    reason: &str,
    wall: u64,
) -> AmendBody {
    AmendBody::Adjust(Adjust {
        amends_hash: amends.to_string(),
        subject,
        lane: lane.to_string(),
        card_epoch_ms,
        was,
        now,
        authorised_by: authorised_by.to_string(),
        reason: reason.to_string(),
        wall,
        pool: None,
    })
}
