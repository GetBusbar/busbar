// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT A BROKEN CHAIN SAYS, AND THE TWO HALVES OF A LINK CHECK.
//!
//! Two families of property that the existing batteries walk past, for the same underlying reason:
//! they check that a tamper is REFUSED, and stop there.
//!
//! **The two halves.** Three verifiers ask one question with two clauses in it — "does this record
//! point at its predecessor OR is it in the wrong position", "is this run's tail the chain's head OR
//! is its position the chain's next". Each clause catches a tamper the other cannot: re-linking a
//! truncated run satisfies the link and not the position; a run stopping one short of the head
//! satisfies both among themselves and neither against the chain. A battery that only ever presents
//! a run failing BOTH clauses proves nothing about either, and collapsing the two into one is a
//! single character.
//!
//! **What it says.** A break is reported to an operator who then has to go and find the log. A
//! report that names no log, no position and no kind of tamper is one that gets read once and
//! ignored — which is the practical difference between a chain that is verified and one that only
//! computes a digest. Nothing asserted these strings, so nothing noticed when they became empty.

// The record-side harness (`token`, `inputs`) is the parent module's; the amendment surface is
// reached through the crate's public paths.
use super::{inputs, token};
use busbar_contract::count::Count;
use busbar_kernel_audit::amend::{content_access, correction, AmendChain, Amendment, Reader};
use busbar_kernel_audit::record::{
    Audit, AuditBreak, AuditBreakKind, AuditChain, AuditRecord, OpClassId, Subject,
};

// ── THE AMENDMENT CHAIN'S TWO HALVES ─────────────────────────────────────────────────────────────

/// Three amendments, sealed in order, and the chain that sealed them.
fn three_amendments() -> (AmendChain, Vec<Amendment>) {
    let mut chain = AmendChain::new();
    let t = token();
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
        correction(
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
        )
        .unwrap(),
        &t,
    );
    (chain, vec![a, b, c])
}

/// A HEAD TRUNCATION THAT RE-LINKS ITSELF IS STILL REFUSED — for its POSITION.
///
/// Drop the genesis amendment and re-point the new first one at nothing. The run now links
/// perfectly to itself: every amendment names the one before it, and the first names no
/// predecessor, exactly as a genesis does. The only thing left that says amendments are missing is
/// that this run does not begin where the chain does. If the verifier asked for the link AND the
/// position rather than the link OR the position, this forgery would verify clean — and the
/// amendments most worth removing are the early ones a later correction was written to cover.
#[test]
fn a_truncated_amendment_run_relinked_to_look_like_a_genesis_is_refused_for_its_position() {
    let (_chain, amendments) = three_amendments();
    let mut forged = amendments[1..].to_vec();
    forged[0].prev_hash = String::new();
    // Re-seal so that ONLY the position is wrong -- otherwise the digest check would catch it and
    // this would say nothing about the position clause.
    forged[0].hash = AmendChain::digest_of(&forged[0]);
    forged[1].prev_hash = forged[0].hash.clone();
    forged[1].hash = AmendChain::digest_of(&forged[1]);

    // The link clause is SATISFIED: the run is internally consistent from an empty predecessor.
    assert_eq!(forged[0].prev_hash, "");
    assert_eq!(forged[1].prev_hash, forged[0].hash);
    // The position clause is not: this run starts at two.
    assert_eq!(forged[0].seq, 2);

    let err = AmendChain::verify(&forged)
        .expect_err("a run that does not start at the genesis is missing amendments");
    assert_eq!(err.at_index, 1);
    // The link is satisfied, so the break is the POSITION's, and it says so (item 405).
    assert_eq!(
        err.kind,
        AuditBreakKind::SequenceMismatch {
            expected: 1,
            found: 2
        }
    );
}

/// AND THE OTHER HALF: A RUN AT THE RIGHT POSITIONS THAT POINTS AT THE WRONG THING.
///
/// The control for the test above. Here the sequence numbers are untouched and only the link is
/// broken, so a verifier that checked the position alone would pass it.
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

/// A TAIL TRUNCATION IS INVISIBLE TO THE RUN AND VISIBLE TO THE CHAIN — ON EITHER HALF.
///
/// `verify_to_head` adds the check the walk cannot make on its own, and it too is two clauses. Each
/// is presented alone: a chain whose head hash agrees but whose next position does not, and a chain
/// whose next position agrees but whose head hash does not. Both are breaks. Collapsed into an AND,
/// neither is.
#[test]
fn a_run_that_matches_the_chains_head_on_only_one_of_the_two_counts_is_refused() {
    let (chain, amendments) = three_amendments();
    chain
        .verify_to_head(&amendments)
        .expect("the whole run against its own chain is whole");

    // HASH AGREES, POSITION DOES NOT: the chain believes it has sealed a fourth amendment.
    let ahead = AmendChain::resume(chain.head().to_string(), chain.next_seq() + 1);
    let err = ahead
        .verify_to_head(&amendments)
        .expect_err("a chain that has sealed an amendment this run does not carry is a break");
    assert_eq!(err.kind, AuditBreakKind::LinkMismatch);
    assert_eq!(err.at_index, amendments.len());

    // POSITION AGREES, HASH DOES NOT: the chain's head is some other amendment at the same
    // position -- a tail amendment substituted rather than removed.
    let substituted = AmendChain::resume("a-different-head".to_string(), chain.next_seq());
    let err = substituted
        .verify_to_head(&amendments)
        .expect_err("a run ending on an amendment the chain did not seal is a break");
    assert_eq!(err.kind, AuditBreakKind::LinkMismatch);
}

/// AN EMPTY RUN AGAINST A CHAIN THAT HAS SEALED SOMETHING IS A BREAK.
///
/// The walk alone passes an empty run, deliberately: "no amendments" and "every amendment deleted"
/// are indistinguishable from the amendments alone. The chain is the thing that can tell them
/// apart, and this is the case it exists for.
#[test]
fn an_empty_amendment_run_against_a_chain_that_has_sealed_amendments_is_refused() {
    let (chain, _amendments) = three_amendments();
    AmendChain::verify(&[]).expect("the walk alone cannot know an empty run is wrong");
    chain
        .verify_to_head(&[])
        .expect_err("every amendment was deleted and the chain's own head says so");

    // And an empty run against an empty chain is whole -- the head and the position both agree.
    AmendChain::new()
        .verify_to_head(&[])
        .expect("a chain with no amendments is whole");
}

// ── THE RECORD CHAIN'S RUNS ──────────────────────────────────────────────────────────────────────

/// Three sealed audit records and the chain that sealed them.
fn three_records() -> (AuditChain, Vec<AuditRecord>) {
    let mut chain = AuditChain::new();
    let t = token();
    let records = (1..=3).map(|i| chain.seal(inputs(i), &t)).collect();
    (chain, records)
}

// ── A RENUMBERING IS NOT A SPLICE (item 405) ─────────────────────────────────────────────────────

/// A RUN RENUMBERED WITH EVERY LINK INTACT IS REPORTED AS A RENUMBERING, NOT AS A SPLICE.
///
/// The sequence item 405 names: `[seq=1 prev=""]`, `[seq=3 prev=hash(#1)]`, `[seq=4 prev=hash(#2)]`,
/// each re-sealed so that only the positions are wrong. Every record points at the one before it,
/// so a report that one "does not point at its predecessor" is false — and the operator's response
/// to a renumbering (who rewrote positions) is not the response to an insertion or a removal (what
/// is missing). The walk used to say LinkMismatch here; it now says the positions were renumbered.
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

    // And a real splice — the middle record removed — is still the LINK's, not the position's.
    let spliced = vec![records[0].clone(), records[2].clone()];
    assert_eq!(
        AuditChain::verify_chain(&spliced).unwrap_err().kind,
        AuditBreakKind::LinkMismatch
    );
}

// ── WHAT A BREAK SAYS ────────────────────────────────────────────────────────────────────────────

/// AN AUDIT BREAK NAMES THE POSITION AND THE KIND OF TAMPER.
///
/// This is what an operator reads. "Something is wrong with the audit log" is a sentence that gets
/// a verifier switched off; "the record at index 3 does not hash to its own fields — it was EDITED"
/// is one somebody can act on. The two kinds must not render as each other, and neither may render
/// as nothing at all.
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

    // The two kinds are distinguishable, and neither is empty.
    assert_ne!(edited, spliced);
    assert!(!edited.is_empty() && !spliced.is_empty());
    // The index really is read from the break rather than baked in.
    assert_ne!(
        edited,
        AuditBreak {
            at_index: 4,
            kind: AuditBreakKind::DigestMismatch
        }
        .to_string()
    );
}
