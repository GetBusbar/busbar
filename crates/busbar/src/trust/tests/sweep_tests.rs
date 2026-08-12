// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROOF THAT THE SWEEP JOB IS ONE JOB.
//!
//! The plane-specific behaviour is proven where it lives — `mcp/tests/timer_dispatch_tests.rs` runs
//! a real schema change through the MCP sweep, and `a2a/tests/scheduler_tests.rs` runs the
//! re-verification asymmetry through the A2A one. What those cannot prove is the thing this file
//! exists for: that there is only ONE job above them, that it names no plane, and that the reporting
//! an operator reads is single.
//!
//! The ratchet here is the same one choke point F uses on the lifecycle, for the same reason: the
//! way this file stops being shared is a plane noun leaking into it, after which the sibling plane
//! can no longer parameterise it and writes a parallel copy instead.

use super::*;
use crate::plane::Plane;
use crate::trust::reverify::Due;
use crate::trust::Drift;

/// A plane's pass type, stood in for. Deliberately carries nothing real: the shared job must be
/// drivable by a detail it has never heard of, which is what makes it a parameter rather than a
/// union of the two planes it happens to have today.
struct FakePass(Vec<SweepEvent>);

impl SweepDetail for FakePass {
    fn events(&self) -> Vec<SweepEvent> {
        self.0.clone()
    }
}

fn outcome(subject: &str, due: Due, events: Vec<SweepEvent>) -> SweepOutcome<FakePass> {
    SweepOutcome {
        subject: subject.to_string(),
        due,
        detail: FakePass(events),
    }
}

fn every_event_shape() -> Vec<SweepEvent> {
    vec![
        SweepEvent::NotAttempted {
            reason: "an unroutable id".to_string(),
        },
        SweepEvent::ContactFailed {
            reason: "connection refused".to_string(),
        },
        SweepEvent::Drifted {
            state: "quarantined",
            drift: Drift {
                pin_changed: true,
                added: vec!["b".to_string()],
                changed: vec!["a".to_string()],
                removed: vec!["c".to_string()],
            },
        },
        SweepEvent::RecoveryHeld,
        SweepEvent::Suspended {
            reason: "too many failed contacts".to_string(),
        },
    ]
}

/// THE RATCHET. This module is shared because it names no plane; the moment it does, the sibling
/// plane stops being able to parameterise it and grows a copy instead — which is the shape that
/// produced this release's plane-local drift.
///
/// Comments are stripped before the check, exactly as the lifecycle's own ratchet strips them: the
/// header of this module has to be able to EXPLAIN which planes it serves and how their fetches
/// differ, and prose that explains a boundary is not the same as code that crosses it.
#[test]
fn the_sweep_job_names_no_plane_in_its_code() {
    // The plane NOUNS only. `reverify` is deliberately absent: `trust::reverify` is the shared
    // cadence both planes already drive, so naming it here is the opposite of a plane leak.
    const BANNED: &[&str] = &[
        "mcp", "Mcp", "MCP", "a2a", "A2a", "A2A", "tool", "Tool", "agent", "Agent", "skill",
        "Skill", "card", "Card", "server", "Server",
    ];
    let source = include_str!("../sweep.rs");
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in BANNED {
        assert!(
            !code.contains(needle),
            "the plane-neutral sweep job names `{needle}` in its CODE. A job that knows one plane's \
             vocabulary is not a job the other plane can parameterise: keep the noun in the \
             plane's own `Sweeper::sweep`, which is the one seam that is allowed to have one."
        );
    }
}

/// THE ACCEPTANCE TEST, mechanically. The plane is a LABEL that travels through the job; it is never
/// a branch. A `match` on it here would mean the job had been re-forked inside one file, which reads
/// as unified and is not.
#[test]
fn the_plane_is_a_label_and_never_a_branch() {
    let source = include_str!("../sweep.rs");
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in ["match plane", "match self.plane", "if plane ==", "Plane::"] {
        assert!(
            !code.contains(needle),
            "the shared sweep job contains `{needle}`. Parameterising over the plane means the \
             plane is data: one job, one report, one clock, and the only per-plane code is the \
             `Sweeper::sweep` a plane supplies."
        );
    }
}

/// THE ONE RENDERER TOLERATES EVERY OUTCOME SHAPE. `report` is the one line in the job that no
/// per-plane test ever runs, so it is exercised here over every event a plane can produce, plus the
/// two boundary shapes (nothing due, nothing to say).
#[test]
fn the_one_renderer_tolerates_every_outcome_shape() {
    for plane in [Plane::Llm, Plane::Mcp, Plane::A2a] {
        report(
            plane,
            &[
                outcome("everything", Due::TtlExpired, every_event_shape()),
                outcome("never-checked", Due::NeverChecked, every_event_shape()),
                outcome("clock-went-backwards", Due::ClockWentBackwards, vec![]),
                outcome(
                    "operator",
                    Due::OperatorSync,
                    vec![SweepEvent::RecoveryHeld],
                ),
                // NOT DUE, and therefore silent even though it carries events. A plane that
                // returned events for a registration it never looked at must not be able to make
                // the log claim a contact happened.
                outcome("fresh", Due::No, every_event_shape()),
            ],
        );
    }
}

/// A REGISTRATION THAT WAS NOT DUE IS SILENT, and that is a property of the shared renderer rather
/// than of either plane remembering to check. Asserted on the decision rather than on a subscriber:
/// the events of a not-due outcome are never asked for at all.
#[test]
fn a_registration_that_was_not_due_is_never_reported() {
    struct Counting(std::cell::Cell<u32>);
    impl SweepDetail for Counting {
        fn events(&self) -> Vec<SweepEvent> {
            self.0.set(self.0.get() + 1);
            vec![SweepEvent::RecoveryHeld]
        }
    }
    let not_due = SweepOutcome {
        subject: "fresh".to_string(),
        due: Due::No,
        detail: Counting(std::cell::Cell::new(0)),
    };
    let due = SweepOutcome {
        subject: "stale".to_string(),
        due: Due::TtlExpired,
        detail: Counting(std::cell::Cell::new(0)),
    };
    report(Plane::Mcp, std::slice::from_ref(&not_due));
    report(Plane::Mcp, std::slice::from_ref(&due));
    assert_eq!(
        not_due.detail.0.get(),
        0,
        "a registration the sweep decided was fresh must not have its pass projected for the log: \
         a line about a contact that never happened is a line an operator would act on"
    );
    assert_eq!(due.detail.0.get(), 1);
}

/// THE JOB STOPS ON THE SHUTDOWN BROADCAST, and it is JOINED rather than waited on, so this proves
/// termination instead of guessing a wall-clock duration.
#[tokio::test]
async fn the_job_exits_its_loop_on_the_shutdown_broadcast() {
    struct NeverDue;
    impl Sweeper for NeverDue {
        type Detail = FakePass;
        fn plane(&self) -> Plane {
            Plane::A2a
        }
        async fn sweep(&self, _now_ms: u64) -> Vec<SweepOutcome<FakePass>> {
            Vec::new()
        }
    }
    let (tx, rx) = tokio::sync::broadcast::channel(1);
    let job = spawn(NeverDue, rx);
    tx.send(()).expect("the job is subscribed");
    tokio::time::timeout(std::time::Duration::from_secs(5), job)
        .await
        .expect("the job must exit on the shutdown broadcast rather than run to the next tick")
        .expect("the job must not panic on shutdown");
}

/// THE CADENCE IS ONE VALUE. Two planes running one defence on two heartbeats is a difference with
/// no reason behind it, and it used to be held only by prose in two files asking each other to stay
/// in step.
#[test]
fn there_is_exactly_one_cadence_and_it_is_not_config() {
    assert!(SWEEP_TICK.as_secs() > 0);
    assert!(
        SWEEP_TICK.as_secs() <= 60,
        "the tick bounds how finely a lapsed TTL is noticed; coarsening it can only make detection \
         later"
    );
}
