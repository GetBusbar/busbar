// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE UNIT-ENDING TO FINISH-CLASS MAPPING, checked here rather than five times over in the

use busbar_contract::unit::{
    finish_class_of, AbortBy, FailureReason, FinishClass, Refusal, RefusalReason, Step, UnitEnd,
};

fn refusal() -> UnitEnd<'static> {
    UnitEnd::Refused(Refusal {
        step: Step::Admit,
        reason: RefusalReason::Revoked,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    })
}

/// The whole mapping, stated as a table. Only the completed ending varies by plane, and it varies

#[test]
fn every_ending_has_one_answer_and_only_completion_varies() {
    let failed = UnitEnd::Failed {
        step: Step::Route,
        reason: FailureReason::Transport,
    };
    let table: [(UnitEnd<'static>, FinishClass); 5] = [
        (refusal(), FinishClass::Error),
        (failed, FinishClass::Error),
        (UnitEnd::Aborted(AbortBy::Client), FinishClass::Partial),
        (
            UnitEnd::Aborted(AbortBy::Kernel {
                reason: RefusalReason::Revoked,
            }),
            FinishClass::Partial,
        ),
        (UnitEnd::Stalled, FinishClass::Partial),
    ];
    for (end, expected) in &table {
        for completed in [FinishClass::Complete, FinishClass::TurnComplete] {
            assert_eq!(
                finish_class_of(end, completed),
                *expected,
                "{end:?} must not depend on what a completed unit is called"
            );
        }
    }
    assert_eq!(
        finish_class_of(&UnitEnd::Completed, FinishClass::Complete),
        FinishClass::Complete
    );
    assert_eq!(
        finish_class_of(&UnitEnd::Completed, FinishClass::TurnComplete),
        FinishClass::TurnComplete
    );
}

/// An abort is `Partial` whoever performed it. `Error` is reserved for an upstream that reported

#[test]
fn a_kernel_abort_is_partial_like_any_other_abort() {
    let kernel = finish_class_of(
        &UnitEnd::Aborted(AbortBy::Kernel {
            reason: RefusalReason::SessionBudget,
        }),
        FinishClass::Complete,
    );
    let client = finish_class_of(&UnitEnd::Aborted(AbortBy::Client), FinishClass::Complete);

    assert_eq!(kernel, client, "who performed the abort changed the class");
    assert_eq!(kernel, FinishClass::Partial);
}
