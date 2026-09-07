// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Direct unit tests for [`Hold`]'s read accessors.
//!
//! `crates/busbar-substrate/src/teller/tests.rs` exercises `Hold` only through
//! `run_gauntlet`/`into_parts`, and every call site of `into_parts` discards its own read with
//! `let (_admit, _downgraded, _charged) = ...`. That leaves `Hold::downgraded()` and `Hold::admit()`
//! — both `pub` and part of the crate's external surface — with no caller anywhere in the crate and
//! no assertion anywhere on the values they read. A mutant that makes either always return `None`,
//! or that swaps which field each one reads, changes no test's outcome. These tests build a `Hold`
//! directly (reachable here because this module is a descendant of `teller`, same as `tokens::Hold`'s
//! `pub(super)` constructor) and assert on the exact values each accessor reports, independent of
//! `charged()` and `into_parts()`.

use super::tokens::UnitToken;
use super::Admit;
use crate::plane_host::AdmitHandle;
use std::sync::Arc;

#[test]
fn downgraded_reports_the_pool_the_hold_was_opened_with() {
    let token = UnitToken::<Admit>::mint();
    let hold = token.hold(None, Some("overflow".to_string()), false);
    assert_eq!(hold.downgraded(), Some("overflow"));
}

#[test]
fn downgraded_is_none_when_the_hold_was_not_downgraded() {
    let token = UnitToken::<Admit>::mint();
    let hold = token.hold(None, None, false);
    assert_eq!(hold.downgraded(), None);
}

#[test]
fn admit_reports_the_grant_the_hold_was_opened_with() {
    let token = UnitToken::<Admit>::mint();
    let handle = AdmitHandle(Arc::new(42_u32));
    let hold = token.hold(Some(handle), None, false);

    let admit = hold.admit().expect("a grant was opened");
    let value = admit.0.downcast_ref::<u32>().expect("the same grant type");
    assert_eq!(*value, 42);
}

#[test]
fn admit_is_none_when_no_grant_was_opened() {
    let token = UnitToken::<Admit>::mint();
    let hold = token.hold(None, None, true);
    assert!(hold.admit().is_none());
}

#[test]
fn downgraded_and_admit_read_independently_of_charged_and_of_each_other() {
    // Every field set to a distinct, checkable value: a mutant that reads the wrong field, or
    // that couples one accessor's answer to another field, is caught here.
    let token = UnitToken::<Admit>::mint();
    let handle = AdmitHandle(Arc::new(7_u32));
    let hold = token.hold(Some(handle), Some("small".to_string()), true);

    assert!(hold.charged());
    assert_eq!(hold.downgraded(), Some("small"));
    assert_eq!(
        *hold.admit().unwrap().0.downcast_ref::<u32>().unwrap(),
        7_u32
    );
}
