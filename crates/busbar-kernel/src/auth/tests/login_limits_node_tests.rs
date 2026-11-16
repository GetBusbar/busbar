// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

const T0: u64 = 1_800_000_000;

#[test]
fn one_source_spraying_many_accounts_is_refused_after_twenty() {
    let policy = LoginLimitsPolicy::default();
    let mut t = SourceTable::default();
    for i in 0..20 {
        // 20 failures spread over 20 minutes would roll; keep them inside one window.
        t.reserve(ip("203.0.113.1"), &policy, false, T0 + i * 40)
            .expect("under the source ceiling");
    }
    assert_eq!(
        t.reserve(ip("203.0.113.1"), &policy, false, T0 + 800),
        Err(SourceRefusal::Failures(SourceBucket::V4(
            "203.0.113.1".parse().unwrap()
        )))
    );
    assert!(
        t.reserve(ip("203.0.113.2"), &policy, false, T0 + 800)
            .is_ok(),
        "another address is its own source"
    );
    assert!(
        t.reserve(ip("203.0.113.1"), &policy, false, T0 + 900 + 1)
            .is_ok(),
        "the window slides: the oldest failure aged out"
    );
}

#[test]
fn a_refunded_reservation_is_not_a_failure() {
    let policy = LoginLimitsPolicy::default();
    let mut t = SourceTable::default();
    for i in 0..40 {
        let ticket = t
            .reserve(ip("198.51.100.4"), &policy, false, T0 + i * 3)
            .expect("refunded attempts never accumulate");
        t.refund(&ticket);
    }
}

#[test]
fn the_submission_rate_is_capped_whatever_the_outcome() {
    let policy = LoginLimitsPolicy::default();
    let mut t = SourceTable::default();
    for _ in 0..30 {
        let ticket = t.reserve(ip("192.0.2.9"), &policy, false, T0).unwrap();
        t.refund(&ticket);
    }
    assert!(matches!(
        t.reserve(ip("192.0.2.9"), &policy, false, T0 + 30),
        Err(SourceRefusal::Submissions(_))
    ));
    assert!(t.reserve(ip("192.0.2.9"), &policy, false, T0 + 60).is_ok());
}

#[test]
fn ipv6_aggregates_cap_a_48_spread_over_many_64s() {
    let policy = LoginLimitsPolicy::default();
    let mut t = SourceTable::default();
    // 100 failures across 100 distinct /64s inside one /48: each /64 is far under 20.
    for i in 0..100u32 {
        let a = format!("2001:db8:1:{:x}::1", i);
        t.reserve(ip(&a), &policy, false, T0 + u64::from(i))
            .expect("under the /48 aggregate");
    }
    assert!(matches!(
        t.reserve(ip("2001:db8:1:ffff::1"), &policy, false, T0 + 200),
        Err(SourceRefusal::Failures(SourceBucket::V6(48, _)))
    ));
    assert!(
        t.reserve(ip("2001:db8:2::1"), &policy, false, T0 + 200)
            .is_ok(),
        "another /48 in the same /32 is still under the /32 aggregate"
    );
}

#[test]
fn the_tripped_alarm_tightens_source_limits() {
    let policy = LoginLimitsPolicy::default();
    let mut t = SourceTable::default();
    for _ in 0..5 {
        t.reserve(ip("203.0.113.50"), &policy, true, T0).unwrap();
    }
    assert!(
        matches!(
            t.reserve(ip("203.0.113.50"), &policy, true, T0),
            Err(SourceRefusal::Failures(_))
        ),
        "a quarter of 20 while the global alarm is tripped"
    );
    let mut s = SourceTable::default();
    for _ in 0..10 {
        let ticket = s.reserve(ip("203.0.113.51"), &policy, true, T0).unwrap();
        s.refund(&ticket);
    }
    assert!(
        matches!(
            s.reserve(ip("203.0.113.51"), &policy, true, T0),
            Err(SourceRefusal::Submissions(_))
        ),
        "a third of 30 submissions per minute"
    );
}

#[test]
fn key_table_is_bounded_and_never_evicts_a_throttled_key_first() {
    let policy = LoginLimitsPolicy::default();
    let mut t = SourceTable::default();
    for _ in 0..20 {
        t.reserve(ip("\x310.0.0.1"), &policy, false, T0).unwrap();
    }
    for i in 0..(MAX_TRACKED as u32 + 10) {
        let a = std::net::Ipv4Addr::from(0x0b00_0000 + i);
        let ticket = t
            .reserve(IpAddr::V4(a), &policy, false, T0 + 1)
            .unwrap_or_else(|e| panic!("{a}: {e:?}"));
        t.refund(&ticket);
    }
    assert!(t.tracked() <= MAX_TRACKED);
    assert!(
        t.reserve(ip("\x310.0.0.1"), &policy, false, T0 + 2)
            .is_err(),
        "the throttled source survived the eviction"
    );
}

#[test]
fn the_global_alarm_trips_once_and_clears() {
    let mut g = GlobalAlarm::default();
    let mut changes = Vec::new();
    for i in 0..700 {
        if let Some(c) = g.failure(600, T0 + i / 20) {
            changes.push(c);
        }
    }
    assert_eq!(
        changes.len(),
        1,
        "one trip, not one per failure: {changes:?}"
    );
    assert!(matches!(changes[0], AlarmChange::Tripped(n) if n >= 600));
    assert_eq!(g.poll(600, T0 + 36), (true, None));
    assert_eq!(
        g.poll(600, T0 + 200),
        (false, Some(AlarmChange::Cleared)),
        "a quiet minute clears it"
    );
    assert_eq!(g.poll(600, T0 + 201), (false, None));
}

#[test]
fn the_outage_breaker_opens_after_five_outages_in_a_minute_for_thirty_seconds() {
    let mut b = Breaker::default();
    for i in 0..4 {
        assert!(!b.outage(T0 + i));
    }
    assert!(!b.open(T0 + 4));
    assert!(b.outage(T0 + 4), "the fifth outage opens it");
    assert!(b.open(T0 + 4 + 29));
    assert!(!b.open(T0 + 4 + 30));
    let mut slow = Breaker::default();
    for i in 0..10 {
        assert!(
            !slow.outage(T0 + i * 20),
            "spread over minutes it never opens"
        );
    }
}

#[test]
fn admin_door_counts_per_source_and_reports_the_real_retry_after() {
    let limit = LoginLimitsPolicy::default().admin;
    let mut a = AdminTable::default();
    let mut firsts = 0;
    for i in 0..50 {
        assert_eq!(a.throttled(ip("203.0.113.8"), limit, T0 + i), None);
        if a.refused(ip("203.0.113.8"), limit, T0 + i) {
            firsts += 1;
        }
    }
    assert_eq!(
        firsts, 1,
        "the refusal that spent the budget is reported once"
    );
    assert_eq!(
        a.throttled(ip("203.0.113.8"), limit, T0 + 100),
        Some(300 - 100),
        "Retry-After is when the oldest refusal leaves the window, not a fixed constant"
    );
    assert_eq!(a.throttled(ip("203.0.113.9"), limit, T0 + 100), None);
    assert_eq!(a.throttled(ip("203.0.113.8"), limit, T0 + 300), None);
}

#[test]
fn audit_is_first_in_window_within_a_budget_and_summarises_what_it_suppressed() {
    let mut g = AuditGate::default();
    let now = T0 - T0 % 60;
    assert!(g.admit("auth.login_throttled", "fp1", 900, now).record);
    assert!(
        !g.admit("auth.login_throttled", "fp1", 900, now + 1).record,
        "latched for the window"
    );
    for i in 0..59 {
        assert!(
            g.admit("auth.login_throttled", &format!("k{i}"), 900, now + 2)
                .record
        );
    }
    let over = g.admit("auth.login_throttled", "fresh", 900, now + 3);
    assert!(!over.record, "the per-node budget is spent");
    let next = g.admit("auth.login_failed", "fresh", 900, now + 61);
    assert!(next.record);
    assert_eq!(
        next.summary,
        Some(2),
        "nothing goes silent: the suppressed count is written"
    );
}

#[test]
fn an_account_throttled_for_more_than_four_consecutive_windows_is_sustained() {
    let mut s = Sustained::default();
    let w = 900;
    let mut fired = Vec::new();
    for window in 0..7u64 {
        for _ in 0..3 {
            if s.throttled("fp", w, T0 + window * w) {
                fired.push(window);
            }
        }
    }
    assert_eq!(fired.len(), 3, "once per window from the fifth: {fired:?}");
    let mut gap = Sustained::default();
    for window in [0u64, 1, 2, 4, 5, 6] {
        assert!(
            !gap.throttled("fp", w, T0 + window * w),
            "a gap resets the run"
        );
    }
}

#[test]
fn retry_after_is_the_method_window_in_whole_minutes_whichever_limiter_tripped() {
    let mut p = LoginLimitsPolicy::default();
    assert_eq!(p.retry_after_secs("any"), 900);
    p.per_method.insert(
        "short".into(),
        Limit {
            max: 2,
            window_secs: 61,
        },
    );
    p.per_method.insert(
        "long".into(),
        Limit {
            max: 2,
            window_secs: 86_400,
        },
    );
    assert_eq!(p.retry_after_secs("short"), 120);
    assert_eq!(p.retry_after_secs("long"), 900);
}
