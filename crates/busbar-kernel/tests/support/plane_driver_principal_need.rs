// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! GetBusbar/busbar#116 (Aikido 1074606943): `arrive`'s `principal_need` is enforced. A plane that
//! states `PRINCIPAL_REQUIRED` never sees an anonymous caller: the unit is refused at Authenticate
//! (`Unauthenticated`, audited), before any piece reaches the far end. `PRINCIPAL_NONE` and
//! `PRINCIPAL_OPTIONAL` admit the anonymous caller exactly as before.

use super::*;
use busbar_contract::caps::{Outcome as UnitOutcome, ReasonCode, StepName};

fn anonymous() -> common::TestUnits {
    common::TestUnits {
        anonymous: true,
        ..common::TestUnits::passing()
    }
}

#[tokio::test]
async fn principal_required_refuses_an_anonymous_caller_audited() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), cases::Book::default());
        let (steps, far, caller) = (
            anonymous(),
            cases::Far::new(&["ok"], cases::CHUNKS),
            cases::Caller::default(),
        );
        let units = r.driver.unit(
            &steps,
            &far,
            &caller,
            cases::arrival("/principal-required", b"x"),
            0,
        );
        let outcome = cases::drive(&units).await;
        assert!(
            matches!(
                outcome,
                UnitOutcome::Refused(StepName::Authenticate, ReasonCode::Unauthenticated)
            ),
            "{outcome:?}"
        );
        assert!(far.sent().is_empty(), "no piece reaches the far end");
        assert!(!steps.called().contains(&StepName::Verify));
        assert!(!steps.called().contains(&StepName::Admit));
        assert!(
            steps.refused_door.load(Ordering::Acquire),
            "the refusal is audited"
        );
    }
}

#[tokio::test]
async fn principal_required_admits_a_verified_principal() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), cases::Book::default());
        let (steps, far, caller) = (
            common::TestUnits::passing(),
            cases::Far::new(&["ok"], cases::CHUNKS),
            cases::Caller::default(),
        );
        let units = r.driver.unit(
            &steps,
            &far,
            &caller,
            cases::arrival("/principal-required", b"x"),
            0,
        );
        let outcome = cases::drive(&units).await;
        assert!(matches!(outcome, UnitOutcome::Completed), "{outcome:?}");
        assert_eq!(far.sent().len(), 1);
    }
}

#[tokio::test]
async fn principal_none_and_optional_admit_an_anonymous_caller() {
    for target in ["/principal-none", "/principal-optional"] {
        for way in ways() {
            let r = rig(way, BufferCaps::default(), cases::Book::default());
            let (steps, far, caller) = (
                anonymous(),
                cases::Far::new(&["ok"], cases::CHUNKS),
                cases::Caller::default(),
            );
            let units = r
                .driver
                .unit(&steps, &far, &caller, cases::arrival(target, b"x"), 0);
            let outcome = cases::drive(&units).await;
            assert!(
                matches!(outcome, UnitOutcome::Completed),
                "{target}: {outcome:?}"
            );
            assert_eq!(far.sent().len(), 1, "{target}");
        }
    }
}
