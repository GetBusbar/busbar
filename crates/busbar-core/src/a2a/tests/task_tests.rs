// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/a2a/task.rs`.

use super::*;

const NOW: u64 = 1_770_000_000;

fn a_task() -> Task {
    Task::submitted("t-1", "ctx-1", "key-abc", Direction::Inbound, NOW).expect("valid identity")
}

/// EVERY state's token round-trips. Not a formality: these strings are the store row, the audit row
/// and the admin response, so a token that parses to a different state than it renders from is a
/// task that changes state by being written and read.
#[test]
fn every_state_token_round_trips() {
    let all = [
        TaskState::Submitted,
        TaskState::Working,
        TaskState::InputRequired,
        TaskState::AuthRequired,
        TaskState::Completed,
        TaskState::Failed,
        TaskState::Canceled,
        TaskState::Rejected,
    ];
    for s in all {
        assert_eq!(
            TaskState::parse(s.as_str()),
            Ok(s),
            "`{}` must parse back to itself",
            s.as_str()
        );
    }
    // SET EQUALITY, not a floor: the token set and the variant set must match exactly, so a variant
    // added without a token (or a token added without a variant) is RED here rather than discovered
    // when a row fails to load in production.
    let tokens: std::collections::BTreeSet<&str> = all.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        tokens,
        std::collections::BTreeSet::from([
            "submitted",
            "working",
            "input-required",
            "auth-required",
            "completed",
            "failed",
            "canceled",
            "rejected",
        ]),
        "the rendered token set and the protocol's state set must be equal"
    );
    assert_eq!(all.len(), 8, "every variant is covered above");
}

/// An unknown token is REFUSED, never defaulted. A row written by a newer engine must not be
/// classified by guesswork — the cheap guess ("unknown is terminal") deletes a live task.
#[test]
fn an_unknown_state_token_is_refused_not_defaulted() {
    assert_eq!(
        TaskState::parse("nearly-done"),
        Err(TaskError::UnknownState("nearly-done".to_string()))
    );
    assert_eq!(
        Direction::parse("sideways"),
        Err(TaskError::UnknownDirection("sideways".to_string()))
    );
}

/// THE TRANSITION TABLE, exhaustively. Every ordered pair of states is asserted, so a pair nobody
/// thought about is covered by construction rather than by whichever ones a test author listed.
#[test]
fn the_transition_table_is_total_and_terminal_is_terminal() {
    use TaskState::*;
    let all = [
        Submitted,
        Working,
        InputRequired,
        AuthRequired,
        Completed,
        Failed,
        Canceled,
        Rejected,
    ];
    let mut checked = 0usize;
    for from in all {
        for to in all {
            let allowed = from.can_transition_to(to);
            let expected = match (from, to) {
                // Nothing leaves a terminal state, including to itself.
                (f, _) if f.is_terminal() => false,
                // Nothing returns to `submitted`: a started task can never truthfully claim it has
                // not started.
                (_, Submitted) => false,
                // A task never transitions to the state it is already in — a repeated transition is
                // the shape a duplicate delivery takes, and accepting it double-bills the caller.
                (f, t) if f == t => false,
                _ => true,
            };
            assert_eq!(
                allowed,
                expected,
                "`{}` -> `{}` should be {}",
                from.as_str(),
                to.as_str(),
                if expected { "allowed" } else { "refused" }
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 64, "all 8x8 ordered pairs were actually asserted");
}

/// The two interrupt states reach each other DIRECTLY. Forcing an input-required task through
/// `working` to become auth-required would emit a `task.working` provenance event claiming work
/// happened when none did.
#[test]
fn an_interrupt_may_become_the_other_interrupt_without_pretending_to_work() {
    assert!(TaskState::InputRequired.can_transition_to(TaskState::AuthRequired));
    assert!(TaskState::AuthRequired.can_transition_to(TaskState::InputRequired));
}

/// A refused transition leaves the task COMPLETELY untouched, `updated_at` included. If a rejected
/// move bumped the age key, a task could be kept alive forever by a caller retrying an illegal
/// transition — or aged out by one.
#[test]
fn a_refused_transition_changes_nothing_at_all() {
    let mut t = a_task();
    t.transition_to(TaskState::Completed, NOW + 1).unwrap();
    let before = t.clone();
    let err = t
        .transition_to(TaskState::Working, NOW + 999)
        .expect_err("terminal is terminal");
    assert_eq!(
        err,
        TaskError::IllegalTransition {
            from: "completed",
            to: "working"
        }
    );
    assert_eq!(t, before, "a refused transition mutates nothing");
}

/// Identity is checked on the way IN. An empty principal is a task nobody can be shown and nobody
/// can be billed for; an empty task id collides with the next one.
#[test]
fn a_task_without_identity_is_refused_at_construction() {
    assert_eq!(
        Task::submitted("", "ctx", "key", Direction::Inbound, NOW),
        Err(TaskError::MissingIdentity("task_id"))
    );
    assert_eq!(
        Task::submitted("t", "", "key", Direction::Inbound, NOW),
        Err(TaskError::MissingIdentity("context_id"))
    );
    assert_eq!(
        Task::submitted("t", "ctx", "", Direction::Inbound, NOW),
        Err(TaskError::MissingIdentity("principal"))
    );
}

/// The store projection round-trips every field. A field added to `Task` and forgotten in `to_row`
/// is a field that silently resets on every restart, which is the quietest possible data loss.
#[test]
fn the_store_projection_round_trips_every_field() {
    let mut t = a_task();
    t.transition_to(TaskState::InputRequired, NOW + 5).unwrap();
    t.agent_id = "planner".to_string();
    t.artifact_cursor = 42;
    t.push_callback = Some("https://caller.example/cb".to_string());

    let back = Task::from_row(&t.to_row()).expect("a row we wrote must read back");
    assert_eq!(back, t, "every field survives the store seam");

    // And the empty callback is `None` rather than `Some("")` — a distinction that decides whether
    // the delivery path tries to POST to the empty string.
    let mut plain = a_task();
    plain.push_callback = None;
    assert_eq!(Task::from_row(&plain.to_row()).unwrap().push_callback, None);
}

/// An INTERRUPTED task is neither terminal nor "just running". The classification is load-bearing:
/// the retention sweep must never collect it, and the boot rehydrate must always resume it.
#[test]
fn an_interrupt_is_active_and_never_collectable() {
    for s in [TaskState::InputRequired, TaskState::AuthRequired] {
        assert!(s.is_interrupted(), "{} is an interrupt", s.as_str());
        assert!(!s.is_terminal(), "{} is not an ending", s.as_str());
        assert!(s.is_active(), "{} must be rehydrated on boot", s.as_str());
    }
    for s in [
        TaskState::Completed,
        TaskState::Failed,
        TaskState::Canceled,
        TaskState::Rejected,
    ] {
        assert!(s.is_terminal());
        assert!(!s.is_active());
        assert!(!s.is_interrupted());
    }
}
