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

// The record-side harness (`token`, `inputs`) is the parent module's; the amendment and legacy
// surfaces are reached through the crate's public paths.
use super::{inputs, token};
use crate::amend::{content_access, correction, AmendChain, Amendment, Reader};
use crate::legacy::chain::{verify_chain, Chain, ChainBreakKind};
use crate::legacy::entry::ADMIN_LOG;
use crate::legacy::{AuditEntry, AuditInput, OUTCOME_APPLIED};
use crate::record::{
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
            100,
            90,
            "carol",
            "overbilled",
            30,
        ),
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
    assert_eq!(err.kind, AuditBreakKind::LinkMismatch);
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

// ── THE RECORD CHAIN'S TAIL CHECK ────────────────────────────────────────────────────────────────

/// Three sealed audit records and the chain that sealed them.
fn three_records() -> (AuditChain, Vec<AuditRecord>) {
    let mut chain = AuditChain::new();
    let t = token();
    let records = (1..=3).map(|i| chain.seal(inputs(i), &t)).collect();
    (chain, records)
}

/// THE SAME TWO CLAUSES, ON THE FIXED RECORD CHAIN.
///
/// A tail truncation of an audit chain removes the most recent evidence — which is the evidence
/// somebody would most want gone. The run that is left links and numbers correctly among itself, so
/// only the chain's own head notices, and only if BOTH of the head's two clauses are checked.
#[test]
fn a_record_run_matching_the_chains_head_on_only_one_count_is_refused() {
    let (chain, records) = three_records();
    chain
        .verify_to_head(&records)
        .expect("the whole run against its own chain is whole");

    let ahead = AuditChain::resume(chain.head().to_string(), chain.next_seq() + 1);
    assert_eq!(
        ahead
            .verify_to_head(&records)
            .expect_err("a sealed record is missing from this run")
            .kind,
        AuditBreakKind::LinkMismatch
    );

    let substituted = AuditChain::resume("a-different-head".to_string(), chain.next_seq());
    assert_eq!(
        substituted
            .verify_to_head(&records)
            .expect_err("this run does not end on the record the chain sealed")
            .kind,
        AuditBreakKind::LinkMismatch
    );

    // And a truncated run fails both clauses at once, which is the ordinary case.
    assert!(chain.verify_to_head(&records[..2]).is_err());
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

/// A CHAIN BREAK NAMES THE LOG THE OPERATOR HAS TO GO AND LOOK AT.
///
/// The scope is read off the record, not off the chain type, and it is what tells an operator WHICH
/// log broke on a node running several. The admin chain has exactly one scope, so the foreign-scope
/// check can never fire on it and the scope's only remaining job is to be in this message — which
/// means nothing else in the crate notices if the record stops naming it.
#[test]
fn a_broken_admin_chain_names_the_admin_log_in_its_report() {
    let mut entry = AuditEntry {
        seq: 1,
        ts: 1_700_000_000,
        action: "hook.register".to_string(),
        resource: "hook:x".to_string(),
        outcome: OUTCOME_APPLIED.to_string(),
        principal: "alice".to_string(),
        prev_hash: String::new(),
        hash: String::new(),
        recorded_here: false,
    };
    entry.hash = crate::legacy::chain::digest(&entry);
    // Now edit it, so the walk reports a digest mismatch and we can read what it says.
    entry.principal = "mallory".to_string();

    let brk =
        verify_chain(std::slice::from_ref(&entry)).expect_err("an edited entry must not verify");
    assert_eq!(
        brk.scope, ADMIN_LOG,
        "the break did not name the log it belongs to"
    );
    assert_eq!(brk.labels.chain, "the admin audit chain");
    assert_eq!(brk.labels.scope, "log");
    assert!(matches!(brk.kind, ChainBreakKind::DigestMismatch { .. }));

    let rendered = brk.to_string();
    assert!(
        rendered.contains("the admin audit chain") && rendered.contains(ADMIN_LOG),
        "the report does not name the log to go and look at: {rendered:?}"
    );
    assert!(
        rendered.contains("EDITED"),
        "the report does not name the tamper: {rendered:?}"
    );
}

// ── THE CHAIN POSITION'S HAND-WRITTEN IMPLEMENTATIONS ────────────────────────────────────────────

/// A chain position advanced onto a real record, for the implementations below to have something
/// other than the default to be.
fn advanced_position() -> Chain<AuditEntry> {
    let mut chain: Chain<AuditEntry> = Chain::new();
    chain.append(
        ADMIN_LOG,
        AuditInput {
            ts: 1_700_000_000,
            action: "hook.register".to_string(),
            resource: "hook:x".to_string(),
            outcome: OUTCOME_APPLIED.to_string(),
            principal: "alice".to_string(),
        },
    );
    chain
}

/// CLONING A CHAIN POSITION COPIES THE POSITION.
///
/// The `Clone` is hand-written because a derive would demand `Clone` of the RECORD type, which the
/// position does not hold. Hand-written means unchecked: a clone that quietly handed back a FRESH
/// chain would restart at sequence one with an empty tail, and the next record appended through it
/// would re-issue a number the log already holds and link to nothing.
#[test]
fn cloning_a_chain_position_copies_the_position_rather_than_starting_a_new_chain() {
    let chain = advanced_position();
    let copy = chain.clone();
    assert_eq!(copy.next_seq(), chain.next_seq());
    assert_eq!(copy, chain);
    // And it is genuinely advanced, so "equal to a default" is not what is being asserted.
    assert_ne!(chain.next_seq(), Chain::<AuditEntry>::new().next_seq());
    assert_ne!(copy, Chain::<AuditEntry>::new());
}

/// TWO CHAIN POSITIONS ARE EQUAL ONLY WHEN BOTH HALVES AGREE.
///
/// The equality is hand-written for the same reason the clone is, and it is a conjunction: a
/// position is a tail hash AND a next sequence. An equality that answered true regardless, or that
/// accepted either half alone, would make every restore witness that compares a rebuilt position
/// against the expected one pass without looking.
#[test]
fn chain_positions_differing_in_either_half_are_not_equal() {
    let chain = advanced_position();
    let same = chain.clone();
    assert_eq!(chain, same);

    // Advancing moves BOTH halves: the ordinary case, and the one that says nothing about which
    // half the equality reads.
    let mut advanced = chain.clone();
    advanced.append(
        ADMIN_LOG,
        AuditInput {
            ts: 1_700_000_001,
            action: "hook.register".to_string(),
            resource: "hook:y".to_string(),
            outcome: OUTCOME_APPLIED.to_string(),
            principal: "alice".to_string(),
        },
    );
    assert_ne!(chain, advanced, "two different positions compared equal");
    assert_ne!(chain.next_seq(), advanced.next_seq());

    // ONE HALF AT A TIME. A position is rebuilt from a persisted tail, so the two halves can be
    // moved independently by moving the record the rebuild reads -- which is precisely what a
    // tampered store hands a booting node.
    let entry = sealed_entry("hook:x", 1);
    let base = Chain::<AuditEntry>::from_persisted_unverified(std::slice::from_ref(&entry));

    // SAME TAIL, DIFFERENT POSITION: the same record claiming a different place in the log.
    let mut renumbered = entry.clone();
    renumbered.seq = 9;
    let same_tail =
        Chain::<AuditEntry>::from_persisted_unverified(std::slice::from_ref(&renumbered));
    // Both were rebuilt from the same sealed record, so both carry that record's hash as their
    // tail -- read back off the position's own rendering, which is the only thing that publishes
    // it. Only the position differs.
    assert_eq!(
        tail_in(&base),
        tail_in(&same_tail),
        "the two positions must share a tail for this to test the other half"
    );
    assert_ne!(base.next_seq(), same_tail.next_seq());
    assert_ne!(
        base, same_tail,
        "two positions agreeing only on their tail compared equal"
    );

    // DIFFERENT TAIL, SAME POSITION: a different record substituted at the same place.
    let substituted = sealed_entry("hook:substituted", 1);
    let same_seq =
        Chain::<AuditEntry>::from_persisted_unverified(std::slice::from_ref(&substituted));
    assert_eq!(base.next_seq(), same_seq.next_seq());
    assert_ne!(tail_in(&base), tail_in(&same_seq));
    assert_ne!(
        base, same_seq,
        "two positions agreeing only on their next position compared equal"
    );

    // A fresh chain and an advanced one differ in BOTH halves.
    assert_ne!(chain, Chain::<AuditEntry>::new());
}

/// The tail hash a chain position is standing on, read off the rendering that publishes it. There
/// is no accessor for it, and adding one to production so that a test can look would be the test
/// changing the thing it is checking.
fn tail_in(chain: &Chain<AuditEntry>) -> String {
    let rendered = format!("{chain:?}");
    let (_, after) = rendered
        .split_once("tail_hash: ")
        .expect("the position's rendering names its tail");
    after
        .split(',')
        .next()
        .expect("the tail is a field of the rendering")
        .to_string()
}

/// One sealed admin entry at a given position, for building chain positions from.
fn sealed_entry(resource: &str, seq: u64) -> AuditEntry {
    crate::legacy::chain::seal(
        ADMIN_LOG,
        seq,
        String::new(),
        AuditInput {
            ts: 1_700_000_000,
            action: "hook.register".to_string(),
            resource: resource.to_string(),
            outcome: OUTCOME_APPLIED.to_string(),
            principal: "alice".to_string(),
        },
    )
}

/// THE NEXT POSITION IS THE CHAIN'S, NOT A CONSTANT.
///
/// `next_seq` is what an appending caller and every restore witness read to say where the chain is
/// up to. Answering one always would report an advanced chain as empty, and a caller acting on that
/// re-issues a number the log already holds.
#[test]
fn a_chains_next_position_advances_with_every_record_it_seals() {
    let mut chain: Chain<AuditEntry> = Chain::new();
    assert_eq!(chain.next_seq(), 1, "a fresh chain's first record is one");
    for expected in 2..=4u64 {
        chain.append(
            ADMIN_LOG,
            AuditInput {
                ts: 1_700_000_000 + expected,
                action: "hook.register".to_string(),
                resource: "hook:x".to_string(),
                outcome: OUTCOME_APPLIED.to_string(),
                principal: "alice".to_string(),
            },
        );
        assert_eq!(
            chain.next_seq(),
            expected,
            "the chain did not advance past the record it just sealed"
        );
    }
}

/// A CHAIN POSITION PRINTS THE TWO THINGS IT IS.
///
/// The position is what an operator or a log line reports when a restore is being diagnosed. The
/// `Debug` is hand-written (a derive would demand it of the record type), so it is unchecked, and a
/// position that printed nothing would make every such line say nothing.
#[test]
fn a_chain_position_prints_its_tail_and_its_next_position() {
    let chain = advanced_position();
    let rendered = format!("{chain:?}");
    assert!(rendered.contains("Chain"), "{rendered:?}");
    assert!(rendered.contains("tail_hash"), "{rendered:?}");
    assert!(rendered.contains("next_seq"), "{rendered:?}");
    assert!(
        rendered.contains(&chain.next_seq().to_string()),
        "the rendering does not carry the position: {rendered:?}"
    );
    assert_ne!(
        rendered,
        format!("{:?}", Chain::<AuditEntry>::new()),
        "an advanced chain printed the same as an empty one"
    );
}

/// A RING THAT SAYS HOW MUCH OF THE TAIL IT IS HOLDING.
///
/// The `Debug` is hand-written because the ring holds a boxed clock and a boxed seam that have no
/// `Debug` of their own, and what it prints is the one number an operator diagnosing a restore
/// wants: how many entries this ring is actually retaining. A rendering that said nothing would
/// make every such line say nothing, and a hand-written implementation is exactly the kind nothing
/// else checks.
#[test]
fn an_audit_ring_prints_how_many_entries_it_is_retaining() {
    struct FixedClock;
    impl crate::legacy::entry::Clock for FixedClock {
        fn now(&self) -> u64 {
            1_700_000_000
        }
    }

    let log =
        crate::legacy::AuditLog::with(Box::new(FixedClock), Box::new(crate::legacy::entry::NoSeam));
    let empty = format!("{log:?}");
    assert!(empty.contains("AuditLog"), "{empty:?}");
    assert!(empty.contains("retained"), "{empty:?}");
    assert!(
        empty.contains('0'),
        "an empty ring did not say it holds nothing: {empty:?}"
    );

    for i in 0..3 {
        log.record_by(
            "hook.register",
            &format!("hook:{i}"),
            OUTCOME_APPLIED,
            "alice",
        );
    }
    let filled = format!("{log:?}");
    assert!(
        filled.contains('3'),
        "the ring did not say how many entries it retains: {filled:?}"
    );
    assert_ne!(
        empty, filled,
        "a ring holding three entries printed the same as an empty one"
    );
}
