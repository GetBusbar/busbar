// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/a2a/provenance.rs`.
//!
//! The point of every test below: a hash chain whose links are never recomputed proves nothing,
//! because nobody ever finds out that it does not. So each of the four ways a chain can be broken is
//! produced HERE, by actually breaking one, and the verifier is required to name it.

use super::*;

const T: &str = "task-1";

fn input(kind: &'static str, state: &str, ts: u64) -> EventInput {
    EventInput {
        kind,
        context_id: "ctx-1".to_string(),
        principal: "key-abc".to_string(),
        agent_id: "planner".to_string(),
        state: state.to_string(),
        request_id: "req-1".to_string(),
        ts,
    }
}

/// A three-event chain: submitted, working, completed.
fn a_chain() -> Vec<TaskEventRow> {
    let mut chain = TaskChain::new();
    vec![
        chain.append(T, input(EV_SUBMITTED, "submitted", 100)),
        chain.append(T, input(EV_WORKING, "working", 101)),
        chain.append(T, input(EV_TERMINAL, "completed", 102)),
    ]
}

/// The links are real links, the sequence starts at 1, and the whole thing verifies.
#[test]
fn an_untouched_chain_verifies_and_its_links_are_actual_links() {
    let events = a_chain();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].seq, 1);
    assert_eq!(events[1].seq, 2);
    assert_eq!(events[2].seq, 3);
    assert_eq!(
        events[0].prev_hash, "",
        "the first event has no predecessor"
    );
    assert_eq!(events[1].prev_hash, events[0].hash);
    assert_eq!(events[2].prev_hash, events[1].hash);
    assert!(
        events.iter().all(|e| e.hash.len() == 64),
        "every digest is a full sha256 hex string"
    );
    assert_eq!(verify_chain(&events), Ok(()));
}

/// TAMPER 1 — EDIT AN EVENT IN PLACE. The single most important assertion in this file: a chain that
/// does not detect this is decoration.
#[test]
fn editing_one_events_fields_is_detected_and_located() {
    let mut events = a_chain();
    let original_hash = events[1].hash.clone();
    // Rewrite history: claim the middle event was a DIFFERENT agent's.
    events[1].agent_id = "attacker-agent".to_string();

    let brk = verify_chain(&events).expect_err("an edited event must break the chain");
    assert_eq!(brk.at_index, 2, "the break is located at the edited event");
    assert_eq!(brk.seq, 2);
    assert_eq!(brk.task_id, T);
    match &brk.kind {
        ChainBreakKind::DigestMismatch { stored, recomputed } => {
            assert_eq!(stored, &original_hash, "the stored digest is the old one");
            assert_ne!(
                recomputed, stored,
                "the recomputed digest reflects the edit"
            );
        }
        other => panic!("expected a digest mismatch, got {other:?}"),
    }
    assert!(
        brk.to_string().contains("EDITED"),
        "the operator-facing message names what happened: {brk}"
    );
}

/// TAMPER 2 — DELETE AN EVENT FROM THE MIDDLE. Reported as a SEQUENCE break, because the sequence is
/// the first thing that stops being contiguous and it names the real defect ("something is missing")
/// rather than blaming the innocent successor.
#[test]
fn deleting_an_event_from_the_middle_is_detected() {
    let mut events = a_chain();
    events.remove(1);
    let brk = verify_chain(&events).expect_err("a deletion must break the chain");
    assert_eq!(brk.at_index, 2);
    assert_eq!(
        brk.kind,
        ChainBreakKind::SequenceBreak {
            expected: 2,
            found: 3
        }
    );
    assert!(brk.to_string().contains("REMOVED"), "{brk}");
}

/// TAMPER 3 — REORDER. Swapping two events keeps every digest individually valid, which is exactly
/// why the LINK has to be checked and not just the digests.
#[test]
fn reordering_two_events_is_detected() {
    let mut events = a_chain();
    events.swap(1, 2);
    let brk = verify_chain(&events).expect_err("a reorder must break the chain");
    // Each event's own digest is still self-consistent; it is the sequence/link that gives it away.
    assert_eq!(
        brk.kind,
        ChainBreakKind::SequenceBreak {
            expected: 2,
            found: 3
        }
    );
}

/// TAMPER 4 — SPLICE IN A FORGED EVENT that carries a correct sequence number and a correct digest
/// over its OWN fields. The forger controls everything except the predecessor's hash, and that is
/// what the link check catches.
#[test]
fn a_forged_event_with_a_self_consistent_digest_is_detected_by_its_link() {
    let events = a_chain();
    // Build the forgery on a chain of its own so its digest is internally valid. The rogue chain's
    // seed differs from the real one (a different timestamp), which models the forger's actual
    // position: it can produce a self-consistent event, but it does not hold the real predecessor's
    // digest. Where it DOES — a host compromised deeply enough to replay the whole chain — this
    // verifies, and that limit is stated in the module doc rather than tested around.
    let mut rogue_chain = TaskChain::new();
    let _ = rogue_chain.append(T, input(EV_SUBMITTED, "submitted", 999));
    let forged = rogue_chain.append(T, input(EV_TERMINAL, "completed", 500));
    assert_eq!(forged.seq, 2, "the forgery claims the right sequence");

    let spliced = vec![events[0].clone(), forged.clone(), events[2].clone()];
    let brk = verify_chain(&spliced).expect_err("a spliced event must break the chain");
    assert_eq!(brk.at_index, 2);
    match &brk.kind {
        ChainBreakKind::LinkMismatch { expected, found } => {
            assert_eq!(expected, &events[0].hash);
            assert_eq!(found, &forged.prev_hash);
        }
        other => panic!("expected a link mismatch, got {other:?}"),
    }
    assert!(brk.to_string().contains("INSERTED"), "{brk}");
}

/// A chain is scoped to ONE task. Another task's event appearing in it is refused, so one caller's
/// provenance can never be made to depend on another caller's rows.
#[test]
fn another_tasks_event_cannot_hide_inside_this_tasks_chain() {
    let mut events = a_chain();
    events[1].task_id = "task-2".to_string();
    let brk = verify_chain(&events).expect_err("a foreign task's event must be refused");
    assert_eq!(
        brk.kind,
        ChainBreakKind::ForeignTask {
            expected: T.to_string(),
            found: "task-2".to_string()
        }
    );
}

/// TRUNCATING THE TAIL is the one tamper a naive link-only walk misses entirely: every remaining
/// link is still correct. It is caught here because the caller holds the task row too — the registry
/// knows the task reached `completed`, and the persisted chain's last event does not say so.
#[test]
fn truncating_the_tail_leaves_a_chain_that_verifies_which_is_why_the_task_row_is_the_other_half() {
    let mut events = a_chain();
    events.pop();
    assert_eq!(
        verify_chain(&events),
        Ok(()),
        "a truncated chain is internally consistent — this is a real limit of chaining alone, \
         stated rather than papered over"
    );
    // What actually catches it: the surviving chain no longer reaches the task's terminal state.
    assert_eq!(events.last().unwrap().state, "working");
}

/// An EMPTY chain verifies, and that is a stated limit rather than a loophole: "no events" and
/// "every event deleted" are indistinguishable from the events alone.
#[test]
fn an_empty_chain_verifies_and_the_limit_is_deliberate() {
    assert_eq!(verify_chain(&[]), Ok(()));
}

/// RESUME across a restart continues the SAME chain: the next sequence follows the persisted tail
/// and the next event links to it. A resume that restarted at seq 1 would open a second chain under
/// one task id — two chains that each verify and together describe nothing.
#[test]
fn resume_continues_the_persisted_chain_rather_than_starting_a_second_one() {
    let persisted = a_chain();
    let mut resumed = TaskChain::from_persisted(&persisted).expect("an intact chain resumes");
    assert_eq!(resumed.next_seq(), 4);
    let next = resumed.append(T, input(EV_REHYDRATED, "working", 200));
    assert_eq!(next.seq, 4);
    assert_eq!(next.prev_hash, persisted[2].hash);

    let mut whole = persisted;
    whole.push(next);
    assert_eq!(
        verify_chain(&whole),
        Ok(()),
        "the chain still verifies across the restart boundary"
    );
}

/// RESUME REFUSES A BROKEN CHAIN rather than appending onto it. Appending a valid link onto a forged
/// one launders the forgery: every later verification passes and the break sits permanently behind
/// the point anybody looks.
#[test]
fn resume_refuses_to_launder_a_broken_chain() {
    let mut events = a_chain();
    events[0].principal = "someone-else".to_string();
    let brk = TaskChain::from_persisted(&events).expect_err("resume must verify before it trusts");
    assert_eq!(brk.at_index, 1);
    // The unverified variant exists for the tamper-detected path, and it positions on the tail so
    // provenance CONTINUES rather than silently stopping the moment somebody corrupts one row.
    let forced = TaskChain::from_persisted_unverified(&events);
    assert_eq!(forced.next_seq(), 4);
}

/// The digest covers what it claims to cover. Each chained field is perturbed one at a time and the
/// digest must move; `request_id` is perturbed and must NOT, because it is a join key that is
/// legitimately absent on the paths with no inbound request.
#[test]
fn the_digest_covers_every_chained_field_and_deliberately_excludes_the_join_key() {
    let base = a_chain();
    let ev = base[1].clone();

    /// One named edit to a single field of an event. Aliased because the tuple of a label and a
    /// boxed mutator is otherwise an unreadable signature for what is simply "a table of edits".
    type Perturbation = (&'static str, Box<dyn Fn(&mut TaskEventRow)>);
    let perturbations: Vec<Perturbation> = vec![
        (
            "prev_hash",
            Box::new(|e: &mut TaskEventRow| e.prev_hash.push('x')),
        ),
        (
            "task_id",
            Box::new(|e: &mut TaskEventRow| e.task_id.push('x')),
        ),
        ("seq", Box::new(|e: &mut TaskEventRow| e.seq += 1)),
        ("ts", Box::new(|e: &mut TaskEventRow| e.ts += 1)),
        ("kind", Box::new(|e: &mut TaskEventRow| e.kind.push('x'))),
        (
            "context_id",
            Box::new(|e: &mut TaskEventRow| e.context_id.push('x')),
        ),
        (
            "principal",
            Box::new(|e: &mut TaskEventRow| e.principal.push('x')),
        ),
        (
            "agent_id",
            Box::new(|e: &mut TaskEventRow| e.agent_id.push('x')),
        ),
        ("state", Box::new(|e: &mut TaskEventRow| e.state.push('x'))),
    ];
    let mut covered = 0usize;
    for (field, perturb) in &perturbations {
        let mut m = ev.clone();
        perturb(&mut m);
        assert_ne!(
            compute_hash(&m),
            ev.hash,
            "`{field}` is a chained field: changing it must change the digest"
        );
        covered += 1;
    }
    assert_eq!(covered, 9, "every chained field was actually perturbed");

    let mut join_only = ev.clone();
    join_only.request_id = "a-completely-different-request".to_string();
    assert_eq!(
        compute_hash(&join_only),
        ev.hash,
        "`request_id` is a join key, not a chained field: a missing one must not make an intact \
         chain unverifiable"
    );
}
