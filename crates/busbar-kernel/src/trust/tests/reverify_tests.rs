// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn policy() -> Policy {
    Policy {
        ttl_ms: 6 * 60 * 60 * 1000,
        recovery_backoff_ms: 30 * 60 * 1000,
    }
}

#[test]
fn never_contacted_is_due() {
    assert_eq!(
        due(&Ledger::default(), &policy(), 0, false),
        Due::NeverChecked
    );
    assert!(due(&Ledger::default(), &policy(), 0, false).should_check());
}

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

#[test]
fn an_operator_sync_outranks_a_fresh_window() {
    let ledger = Ledger {
        last_checked_ms: Some(1_000),
        ..Ledger::default()
    };
    assert_eq!(due(&ledger, &policy(), 1_001, false), Due::No);
    assert_eq!(due(&ledger, &policy(), 1_001, true), Due::OperatorSync);
}
