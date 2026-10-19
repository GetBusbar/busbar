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
    }
}

#[test]
fn a_units_record_is_its_last_attempts_and_is_gone_once_forgotten() {
    let unit = 0x5eed_0001;
    record(unit, attempt("a", 1));
    record(unit, attempt("b", 2));
    let live = of(unit).expect("recorded");
    assert_eq!((live.member.as_str(), live.handle), ("b", 2));
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
