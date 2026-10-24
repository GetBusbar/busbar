// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn attempt(member: &str, handle: u64) -> AttemptAuth {
    AttemptAuth {
        member: member.to_owned(),
        handle,
        extensions: Vec::new(),
        caller_credential: None,
        waived: false,
        secret: [0, 0],
        outcome: None,
    }
}

#[test]
fn a_units_record_is_its_last_attempts_and_is_gone_once_forgotten() {
    let unit = 0x5eed_0001;
    record(unit, attempt("a", 1));
    record(unit, attempt("b", 2));
    let live = of(unit).expect("recorded");
    assert_eq!((live.member.as_str(), live.handle), ("b", 2));
    assert_ne!(
        live.secret,
        [0, 0],
        "the unit's secret is drawn, never the caller's"
    );
    forget(unit);
    assert!(of(unit).is_none());
}

#[test]
fn unit_zero_records_nothing() {
    record(0, attempt("a", 1));
    assert!(of(0).is_none());
}

#[test]
fn a_record_debug_prints_no_credential_bytes() {
    let mut a = attempt("m", 7);
    a.caller_credential = Some(Secret::new(b"sk-caller-secret".to_vec()));
    let printed = format!("{a:?}");
    assert!(!printed.contains("sk-caller-secret"), "{printed}");
}

#[test]
fn a_units_secret_is_kept_across_its_attempts_and_is_its_own() {
    let (one, two) = (0x5eed_0002, 0x5eed_0003);
    record(one, attempt("a", 1));
    let first = of(one).expect("recorded").secret;
    record(one, attempt("b", 2));
    assert_eq!(
        of(one).expect("recorded").secret,
        first,
        "one unit, one secret"
    );
    record(two, attempt("a", 1));
    assert_ne!(
        of(two).expect("recorded").secret,
        first,
        "another unit's is its own"
    );
    forget(one);
    forget(two);
}

#[test]
fn an_auth_outcome_is_the_live_attempts_and_a_new_attempt_clears_it() {
    let unit = 0x5eed_0004;
    record(unit, attempt("a", 1));
    mark(unit, AuthOutcome::Refused);
    assert_eq!(
        of(unit).expect("recorded").outcome,
        Some(AuthOutcome::Refused)
    );
    record(unit, attempt("b", 2));
    assert_eq!(
        of(unit).expect("recorded").outcome,
        None,
        "a new attempt starts clean"
    );
    mark(0x5eed_0005, AuthOutcome::Failed);
    assert!(of(0x5eed_0005).is_none(), "no live attempt, nothing marked");
    forget(unit);
}
