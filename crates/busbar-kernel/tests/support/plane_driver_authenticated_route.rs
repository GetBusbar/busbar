// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::plane::{AuthenticatedRouteOut, ROUTE_DIRECT};
use busbar_contract::caps::{ReasonCode, StepName};
use busbar_contract::plane_calls::AuthenticatedRouteInFlight;

pub(super) struct Flight {
    pub pending: bool,
    pub refused: bool,
    pub settled: bool,
}

impl Future for Flight {
    type Output = Answered;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Answered> {
        if self.pending {
            return Poll::Pending;
        }
        self.settled = true;
        Poll::Ready(Answered {
            outcome: if self.refused {
                Outcome::Refused
            } else {
                Outcome::Ready
            },
            short: false,
            disposition: None,
        })
    }
}

impl AuthenticatedRouteInFlight for Flight {
    fn out(&self) -> Option<AuthenticatedRouteOut> {
        self.settled.then(|| AuthenticatedRouteOut {
            entry_written: if self.refused {
                0
            } else {
                b"stored-entry".len() as u32
            },
            route: if self.refused { 0 } else { ROUTE_DIRECT },
            refusal: u32::from(self.refused),
            refusal_status: if self.refused { 404 } else { 0 },
            ..busbar_contract::abi::sdk::door::blank_out()
        })
    }
}

fn rig_with_lookup(enabled: bool, caller_key: bool) -> Rig {
    let plane = Arc::new(Double {
        declared: InstanceDecl {
            authenticated_route: enabled,
            ..InstanceDecl::default()
        },
        ..Double::default()
    });
    let book = Arc::new(cases::Book::default());
    let caller_refs = caller_key.then(|| {
        Arc::new(std::sync::RwLock::new(Some(Arc::new(
            busbar_kernel::auth::CallerRefKey::derive(&[7; 32]),
        ))))
    });
    let driver = PlaneDriver::new(
        plane.clone(),
        DriverConfig {
            caps: BufferCaps::default(),
            op_classes: vec![OpClassId::new("call")],
            status_of: refusal_status,
            refusal_statuses: cases::statuses(),
            caller_refs,
        },
        book.clone(),
        services(),
        ("test_plane", &serde_yaml::Value::Null),
    )
    .now_or_never()
    .unwrap()
    .unwrap();
    Rig {
        plane,
        driver,
        book,
    }
}

#[tokio::test]
async fn authenticated_route_preserves_request_and_runs_normal_verification() {
    let r = rig_with_lookup(true, true);
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["ok"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = r.driver.unit(
        &steps,
        &far,
        &caller,
        cases::arrival("/authenticated", b"unchanged"),
        0,
    );
    let outcome = cases::drive(&units).await;
    assert!(
        matches!(outcome, busbar_contract::caps::Outcome::Completed),
        "{outcome:?}"
    );
    let decoded = units.decoded().unwrap();
    assert_eq!(decoded.route, ROUTE_DIRECT);
    assert_eq!(decoded.pool.as_deref(), Some(b"stored-entry".as_slice()));
    assert_eq!(decoded.expected[0].amount, 9);
    assert!(steps.called().contains(&StepName::Verify));
    assert!(steps.called().contains(&StepName::Admit));
    assert_eq!(far.sent().len(), 1);
    let calls = r.plane.authenticated_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_ne!(calls[0].0, 0);
    assert_eq!(
        calls[0].1,
        busbar_kernel::auth::CallerRefKey::derive(&[7; 32])
            .caller_ref(common::principal().as_str())
            .as_bytes()
    );
}

#[tokio::test]
async fn authenticated_route_requires_authentication_declaration_and_caller_reference() {
    for (enabled, caller_key, refuse_auth) in [
        (true, true, true),
        (false, true, false),
        (true, false, false),
    ] {
        let r = rig_with_lookup(enabled, caller_key);
        let steps = if refuse_auth {
            common::TestUnits::refusing(StepName::Authenticate, ReasonCode::Unauthenticated)
        } else {
            common::TestUnits::passing()
        };
        let (far, caller) = (
            cases::Far::new(&["ok"], cases::CHUNKS),
            cases::Caller::default(),
        );
        let units = r.driver.unit(
            &steps,
            &far,
            &caller,
            cases::arrival("/authenticated", b"x"),
            0,
        );
        assert!(matches!(
            cases::drive(&units).await,
            busbar_contract::caps::Outcome::Refused(..)
        ));
        assert!(r.plane.authenticated_calls.lock().unwrap().is_empty());
        assert!(far.sent().is_empty());
        assert!(!steps.called().contains(&StepName::Admit));
    }
}

#[tokio::test]
async fn authenticated_route_cannot_bypass_revoked_destination_grant() {
    let r = rig_with_lookup(true, true);
    let steps = common::TestUnits::refusing(StepName::Verify, ReasonCode::ScopeDenied);
    let (far, caller) = (
        cases::Far::new(&["ok"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = r.driver.unit(
        &steps,
        &far,
        &caller,
        cases::arrival("/authenticated", b"x"),
        0,
    );
    assert!(matches!(
        cases::drive(&units).await,
        busbar_contract::caps::Outcome::Refused(StepName::Verify, ReasonCode::ScopeDenied)
    ));
    assert_eq!(r.plane.authenticated_calls.lock().unwrap().len(), 1);
    assert!(far.sent().is_empty());
    assert!(!steps.called().contains(&StepName::Admit));
}

#[tokio::test]
async fn authenticated_route_missing_record_refuses_without_default_scope() {
    let r = rig_with_lookup(true, true);
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["ok"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = r.driver.unit(
        &steps,
        &far,
        &caller,
        cases::arrival("/authenticated-refused", b"x"),
        0,
    );
    assert!(matches!(
        cases::drive(&units).await,
        busbar_contract::caps::Outcome::Refused(..)
    ));
    assert!(!steps.called().contains(&StepName::Verify));
    assert!(far.sent().is_empty());
}

#[tokio::test]
async fn authenticated_route_pending_is_bounded_by_request_deadline_and_cleans_once() {
    let r = rig_with_lookup(true, true);
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["ok"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = r.driver.unit(
        &steps,
        &far,
        &caller,
        cases::arrival("/authenticated-pending", b"x"),
        now_ns() + 10_000_000,
    );
    assert!(matches!(
        cases::drive(&units).await,
        busbar_contract::caps::Outcome::Refused(StepName::Verify, ReasonCode::DeadlineExceeded)
    ));
    assert_eq!(r.plane.authenticated_calls.lock().unwrap().len(), 1);
    assert!(far.sent().is_empty());
    drop(units);
    r.driver.sweep();
    let closes = r.plane.closes.lock().unwrap();
    assert_eq!(closes.len(), 1);
    assert_eq!(closes.values().copied().collect::<Vec<_>>(), vec![1]);
    assert_eq!(r.stats()[stat::CANCELS], 1);
}

#[tokio::test]
async fn authenticated_route_caller_stop_reload_and_future_drop_cancel_before_admission() {
    for mode in 0..3 {
        let r = rig_with_lookup(true, true);
        let (steps, far) = (
            common::TestUnits::passing(),
            cases::Far::new(&["ok"], cases::CHUNKS),
        );
        let mut caller = cases::Caller::default();
        caller.stop_after = (mode == 0).then_some(Duration::from_millis(5));
        let units = r.driver.unit(
            &steps,
            &far,
            &caller,
            cases::arrival("/authenticated-pending", b"x"),
            0,
        );
        if mode == 2 {
            let mut running = Box::pin(cases::drive(&units));
            assert!(futures::poll!(&mut running).is_pending());
            drop(running);
        } else {
            let reload = async {
                if mode == 1 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    r.driver.reload();
                }
            };
            let (outcome, ()) = tokio::join!(cases::drive(&units), reload);
            assert!(matches!(
                outcome,
                busbar_contract::caps::Outcome::Refused(StepName::Verify, _)
            ));
        }
        assert_eq!(r.plane.authenticated_calls.lock().unwrap().len(), 1);
        assert_eq!(r.stats()[stat::CANCELS], 1);
        assert!(!steps.called().contains(&StepName::Admit));
        assert!(far.sent().is_empty());
        drop(units);
        r.driver.sweep();
        assert_eq!(r.stats()[stat::CANCELS], 1);
    }
}
