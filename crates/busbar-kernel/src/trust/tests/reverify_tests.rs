// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The re-verification cadence ([`super::due`]), driven the way a hostile upstream would drive it:
//! stop the clock, or wait out a window it earned earlier.

use super::*;

fn policy() -> Policy {
    Policy {
        ttl_ms: 6 * 60 * 60 * 1000,
        recovery_backoff_ms: 30 * 60 * 1000,
    }
}

/// A registration approved from a declarative pin has legitimately never been contacted, and that is
/// due rather than fresh. Treating "no observation" as "nothing has changed" would mean an upstream
/// nobody ever looked at is the one thing nobody ever looks at.
#[test]
fn never_contacted_is_due() {
    assert_eq!(
        due(&Ledger::default(), &policy(), 0, false),
        Due::NeverChecked
    );
    assert!(due(&Ledger::default(), &policy(), 0, false).should_check());
}

/// Reaching the TTL is due, both sides of the boundary pinned. The operator wrote the longest
/// staleness they will accept, so treating it as still acceptable makes the setting mean something
/// other than what it says.
#[test]
fn reaching_the_ttl_is_due_and_one_tick_short_is_not() {
    let ledger = Ledger {
        last_checked_ms: Some(1_000),
        ..Ledger::default()
    };
    let p = policy();
    assert_eq!(due(&ledger, &p, 1_000 + p.ttl_ms - 1, false), Due::No);
    assert_eq!(due(&ledger, &p, 1_000 + p.ttl_ms, false), Due::TtlExpired);
    assert_eq!(
        due(&ledger, &p, 1_000 + p.ttl_ms * 9, false),
        Due::TtlExpired
    );
}

/// THE CLOCK GOING BACKWARDS. An NTP correction, a restored snapshot, or a tampered host clock makes
/// the elapsed time uncomputable. The fail-closed answer is to check; the naive one saturates the
/// subtraction to zero, reports fresh, and hands the upstream permanent freshness. An upstream that
/// is never checked again can change whatever it likes.
#[test]
fn a_clock_that_went_backwards_is_due_rather_than_permanently_fresh() {
    let ledger = Ledger {
        last_checked_ms: Some(1_000_000),
        ..Ledger::default()
    };
    assert_eq!(
        due(&ledger, &policy(), 999_999, false),
        Due::ClockWentBackwards
    );
    assert_eq!(due(&ledger, &policy(), 0, false), Due::ClockWentBackwards);
    assert!(due(&ledger, &policy(), 0, false).should_check());
}

/// An operator sync outranks the timer. Someone with out-of-band reason to suspect an upstream, or
/// handling a scheduled vendor key rotation, does not wait for it.
#[test]
fn an_operator_sync_outranks_a_fresh_window() {
    let ledger = Ledger {
        last_checked_ms: Some(1_000),
        ..Ledger::default()
    };
    assert_eq!(due(&ledger, &policy(), 1_001, false), Due::No);
    assert_eq!(due(&ledger, &policy(), 1_001, true), Due::OperatorSync);
}
