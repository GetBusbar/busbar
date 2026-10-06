// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIAL'S OPENING (`conformance/transport.rs`, `begin_dial_want`): the declared bytes pass,
//! a silent dial passes, and undeclared or other bytes are refused.

use super::{begin_dial_want, contract, yielded_line, Want};
use crate::conformance::Step;

fn begun(wire: &[u8]) -> Vec<Step> {
    vec![Step {
        label: "begin dial".into(),
        answer: yielded_line(wire, &[], &[], 0, true),
        crossed: 1,
        pinned: 1,
    }]
}

fn judged(inputs: &str, wire: &[u8]) {
    let dial: serde_json::Value = serde_json::from_str(inputs).expect("inputs");
    let want: Vec<(String, Want)> = vec![("begin dial".into(), begin_dial_want(&dial, 0))];
    contract(&begun(wire), &want);
}

/// GREEN: the declared opening, exactly; and nothing where none is declared.
#[test]
fn a_declared_opening_and_a_silent_dial_both_pass() {
    judged(r#"{ "opening": { "hex": "00010203" } }"#, &[0, 1, 2, 3]);
    judged(r#"{}"#, &[]);
}

/// RED: a door that writes bytes its inputs do not declare is refused.
#[test]
#[should_panic(expected = "begin dial")]
fn an_undeclared_opening_is_refused() {
    judged(r#"{}"#, b"speaks first");
}

/// RED: a door that writes other bytes than the ones declared is refused.
#[test]
#[should_panic(expected = "begin dial")]
fn an_opening_other_than_the_declared_one_is_refused() {
    judged(r#"{ "opening": "hello" }"#, b"hullo");
}
