// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A FRONT DOOR'S AUDIT CHAIN, DRIVEN — a real inbound task, through the real router,
//! leaving real hash-chained events in a real sink, read back and RECOMPUTED.
//!
//! ## What this file replaces, and why the cell it closes had to be re-pointed
//!
//! `audit-chain x a2a-server` was GREEN on
//! `provenance_tests::an_untouched_chain_verifies_and_its_links_are_actual_links`, which builds a
//! `TaskChain` IN PROCESS and appends to it directly. That is a fine test OF THE MECHANISM and it is
//! not evidence about the plane: **it would pass, unchanged, if the A2A front door chained
//! nothing at all**. A cell that closes on a test the plane never touches is exactly the failure
//! mode the per-call record's own dlopen battery was written about — a complete, verified, tested
//! subsystem with no production call site.
//!
//! So nothing here constructs a chain, a record or a registry. A caller POSTs `message/send` at a
//! real listener; busbar admits it, opens a task, relays the hop and records the outcome; and only
//! then does this file look — at the SINK, not at the engine's own memory.
//!
//! ## The read-back is the assertion, and it cannot be skipped
//!
//! `busbar_api::Store`'s task methods are DEFAULTED to accept-and-keep-nothing, so a write's
//! `Ok(())` is worthless as evidence and the shipped memory store answers every read with an empty
//! list. Every chain battery therefore attaches `EventLedger` as the registry's sink for the
//! duration (`relay_harness::with_ledger`), so an empty read-back is a FAILURE and is asserted as
//! one. There is no arm here that can be silently satisfied by nothing having happened.

use super::relay_harness::*;
use crate::taskstore::TASKS;
use busbar_substrate::audit::vocab as provenance;

/// THE FRONT DOOR CHAINS THE TASK IT OPENED, and the chain RECOMPUTES from the persisted rows.
///
/// This is the `audit-chain x a2a-server` cell, re-pointed off a synthetic chain and onto the plane.
/// Every event asserted here was written by production code on the inbound path: `task.submitted` by
/// the admission that opened the task, `task.delegated` by the hop that chose the backend agent.
///
/// A chain nothing ever recomputes proves nothing, so this recomputes it — over the rows a store
/// gave back, which is the only place a tamper could ever have been made.
#[tokio::test]
async fn an_inbound_task_leaves_a_verifying_chain_in_the_store_the_front_door_wrote_it_to() {
    crate::testkit::install_test_seams();
    let (ledger, _guard) = with_ledger().await;

    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");
    let task_id = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .expect("the answer names the task busbar opened")
        .to_string();

    // The wait is bounded and ends in a panic: an empty (or never-settling) read-back is the answer
    // this battery exists to FAIL on, because it is indistinguishable from a plane that chains
    // nothing. The delegation record rides detached work, hence the wait rather than a bare read.
    let events = await_chain_with(&ledger, &task_id, provenance::EV_DELEGATED).await;
    TASKS.clear_sink_for_test();

    crate::taskstore::verify_chain(&events)
        .expect("the per-task chain must recompute from the store");

    let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        kinds.first().copied(),
        Some(provenance::EV_SUBMITTED),
        "the first event of an inbound task's chain is the submission that opened it: {kinds:?}"
    );
    assert!(
        kinds.contains(&provenance::EV_DELEGATED),
        "the delegating side's one indispensable provenance fact — who was delegated to — must be \
         on the chain: {kinds:?}"
    );
    assert_eq!(
        events[0].seq, 1,
        "the chain the front door opened starts at seq 1"
    );
    assert!(
        events[0].prev_hash.is_empty(),
        "a genesis event has no predecessor to link to"
    );
    assert!(
        events.iter().all(|e| e.task_id == task_id),
        "every event is scoped to the task the front door opened; a foreign scope would make one \
         caller's evidence depend on another's rows"
    );
}

/// A TAMPER IN THE STORE IS DETECTED ON THE ROWS THE FRONT DOOR WROTE.
///
/// The tamper-evidence claim is only worth anything over records a REAL request produced: verifying a
/// chain the test built itself proves the walk works, which nobody doubted. This edits a persisted
/// event the same way an operator with database access — or an attacker who got there — would, and
/// requires the verifier to say so.
#[tokio::test]
async fn editing_a_persisted_event_breaks_the_chain_the_front_door_wrote() {
    crate::testkit::install_test_seams();
    let (ledger, _guard) = with_ledger().await;

    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");
    let task_id = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .expect("the answer names the task busbar opened")
        .to_string();

    let mut events = await_chain_with(&ledger, &task_id, provenance::EV_DELEGATED).await;
    TASKS.clear_sink_for_test();
    crate::taskstore::verify_chain(&events).expect("the untampered rows verify first");

    // The agent a task was delegated to is the fact a delegation record exists to carry, and
    // therefore the one worth rewriting after the fact.
    events[0].agent_id = format!("{}-rewritten", events[0].agent_id);
    let brk = crate::taskstore::verify_chain(&events)
        .expect_err("an edited event must not still verify against its own chain");
    assert_eq!(
        brk.scope, task_id,
        "the break names the task whose chain it is, so an operator knows where to look: {brk}"
    );
}
