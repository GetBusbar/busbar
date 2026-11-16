// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-K3: the `RetryPolicy` schedules (IF §12.3; C-FAIL-FACTS retry arm, C-EXPORT-DELIVERY (e), C-CRED-CACHE (c)).

use super::*;
use busbar_plugin_abi::fail::failed::{F_BUSY, F_LIMIT, F_UNAVAILABLE};

fn failed_with(code: u32, retry_after_s: Option<u64>) -> PortError {
    PortError::Failed {
        code,
        text: "t".into(),
        retry_after_s,
        backend_status: None,
        error: None,
    }
}

fn refused() -> PortError {
    PortError::Refused {
        code: 1,
        text: "t".into(),
        error: None,
    }
}

fn low() -> Policy {
    Policy::with_draw(|| 0.0)
}
fn high() -> Policy {
    Policy::with_draw(|| 1.0)
}

fn secs(n: u64) -> Retry {
    Retry::After(Duration::from_secs(n))
}

#[test]
fn a_script_is_a_pure_function_of_site_attempt_and_error() {
    let e = failed_with(F_UNAVAILABLE, None);
    for site in [RetrySite::StoreRead, RetrySite::ExportDeliver(1)] {
        assert_eq!(low().next(site, 1, &e), low().next(site, 1, &e));
    }
}

#[test]
fn retry_policy_honours_retry_after() {
    let e = failed_with(F_UNAVAILABLE, Some(30));
    let Retry::After(d) = low().next(RetrySite::ExportDeliver(1), 1, &e) else {
        panic!("a Failed export delivery waits");
    };
    assert!(
        d >= Duration::from_secs(30),
        "never shorter than the backend asked"
    );
    // a store call too
    let Retry::After(d) = low().next(RetrySite::StoreRead, 1, &e) else {
        panic!("a Failed store read waits");
    };
    assert!(d >= Duration::from_secs(30));
}

#[test]
fn a_retry_after_above_the_ceiling_is_clamped_to_it() {
    let e = failed_with(F_UNAVAILABLE, Some(900));
    assert_eq!(low().next(RetrySite::ExportDeliver(1), 1, &e), secs(300));
    assert_eq!(low().next(RetrySite::AuthOutbound, 1, &e), secs(300));
}

#[test]
fn export_waits_lie_in_the_backoff_range() {
    let e = failed_with(F_UNAVAILABLE, None);
    let b = Backoff::new(Duration::from_millis(250), Duration::from_secs(60));
    for attempt in 1..=2 {
        let Retry::After(lo) = low().next(RetrySite::ExportDeliver(2), attempt, &e) else {
            panic!("waits");
        };
        let Retry::After(hi) = high().next(RetrySite::ExportDeliver(2), attempt, &e) else {
            panic!("waits");
        };
        assert_eq!(lo, FLOOR);
        assert_eq!(hi, b.ceiling(attempt));
    }
}

#[test]
fn export_stops_on_refused_limit_and_after_attempt_three() {
    let site = RetrySite::ExportDeliver(2);
    assert_eq!(low().next(site, 1, &refused()), Retry::Stop);
    assert_eq!(
        low().next(site, 1, &failed_with(F_LIMIT, None)),
        Retry::Stop
    );
    assert_eq!(
        low().next(site, 1, &PortError::Call(CallError::Quarantined)),
        Retry::Stop
    );
    let e = failed_with(F_UNAVAILABLE, None);
    assert!(matches!(low().next(site, 2, &e), Retry::After(_)));
    assert_eq!(low().next(site, 3, &e), Retry::Stop);
    // a deadline is retried
    assert!(matches!(
        low().next(site, 1, &PortError::Call(CallError::Deadline)),
        Retry::After(_)
    ));
}

#[test]
fn content_deliveries_are_not_bounded_by_a_count() {
    let e = failed_with(F_BUSY, None);
    assert!(matches!(
        low().next(RetrySite::ExportDeliver(9), 500, &e),
        Retry::After(_)
    ));
    assert_eq!(
        low().next(RetrySite::ExportDeliver(9), 1, &failed_with(F_LIMIT, None)),
        Retry::Stop
    );
}

#[test]
fn auth_outbound_window_doubles_from_thirty_to_three_hundred() {
    let e = failed_with(F_UNAVAILABLE, None);
    let got: Vec<Retry> = (1..=6)
        .map(|n| low().next(RetrySite::AuthOutbound, n, &e))
        .collect();
    assert_eq!(
        got,
        [
            secs(30),
            secs(60),
            secs(120),
            secs(240),
            secs(300),
            secs(300)
        ]
    );
    assert_eq!(low().next(RetrySite::AuthOutbound, u32::MAX, &e), secs(300));
}

#[test]
fn auth_outbound_honours_retry_after_and_retries_every_failed() {
    let e = failed_with(F_UNAVAILABLE, Some(45));
    assert_eq!(low().next(RetrySite::AuthOutbound, 1, &e), secs(45));
    assert_eq!(
        low().next(RetrySite::AuthOutbound, 1, &failed_with(F_LIMIT, None)),
        secs(30)
    );
    assert_eq!(
        low().next(
            RetrySite::AuthOutbound,
            1,
            &PortError::Call(CallError::Deadline)
        ),
        secs(30)
    );
    assert_eq!(
        low().next(RetrySite::AuthOutbound, 1, &refused()),
        Retry::Stop
    );
    assert_eq!(
        low().next(
            RetrySite::AuthOutbound,
            1,
            &PortError::Call(CallError::Cancelled)
        ),
        Retry::Stop
    );
}

#[test]
fn store_secret_and_admin_calls_get_three_attempts() {
    let e = failed_with(F_UNAVAILABLE, None);
    for site in [
        RetrySite::StoreRead,
        RetrySite::StoreScan,
        RetrySite::StoreCommit,
        RetrySite::StoreClock,
        RetrySite::SecretResolve,
        RetrySite::AuthRefresh,
        RetrySite::PlaneAdmin,
    ] {
        assert!(
            matches!(low().next(site, 1, &e), Retry::After(_)),
            "{site:?}"
        );
        assert_eq!(low().next(site, 3, &e), Retry::Stop, "{site:?}");
        assert_eq!(low().next(site, 1, &refused()), Retry::Stop, "{site:?}");
    }
}

#[test]
fn push_is_bounded_and_a_probe_keeps_trying() {
    let e = failed_with(F_UNAVAILABLE, None);
    assert!(matches!(
        low().next(RetrySite::PlanePush, 7, &e),
        Retry::After(_)
    ));
    assert_eq!(low().next(RetrySite::PlanePush, 8, &e), Retry::Stop);
    assert!(matches!(
        low().next(RetrySite::PlaneProbe, 1_000, &e),
        Retry::After(_)
    ));
    assert_eq!(
        low().next(RetrySite::PlaneProbe, 1, &refused()),
        Retry::Stop
    );
}
