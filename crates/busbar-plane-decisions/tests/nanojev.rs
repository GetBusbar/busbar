// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECOND DIALECT, `nanojev`, DRIVEN OVER THE DOOR'S ABI (THE DESIGN section 2, the decisions
//! bullet): "NanoJev is the one, dialect `nanojev`: `/api/evaluate` is its second exact claim; a
//! model's dialect is its override or its provider's protocol; a model of the wrong dialect gets
//! that dialect's existing unknown-model refusal; it meters the upstream's own billing unit,
//! counted from the answer already read (`execution.states`; an answer with no count refuses
//! loudly ...), with no extra egress".

#![allow(unsafe_code)]

mod door_harness;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::plane::{ROUTE_DIRECT, UNITS_REPORTED};
use door_harness::{open, open_with, validate, Bufs, Given};

const SYSTEMONE: (&str, &str) = ("POST", "/v1/systemone");
const EVALUATE: (&str, &str) = ("POST", "/api/evaluate");

/// One model of each dialect: `nano` by its own `protocol`, `jev` by its provider's.
const BOTH: &str =
    r#"{"models":{"nano":{"provider":"np","protocol":"nanojev"},"jev":{"provider":"typesafe"}}}"#;

fn claims(c: &[(&str, &str)]) -> Vec<(String, String)> {
    c.iter()
        .map(|(v, t)| ((*v).to_string(), (*t).to_string()))
        .collect()
}

/// RED (audit plane-decisions#3): `/api/evaluate` is claimed when a `nanojev` model is configured,
/// by its own `protocol` or its provider's as the host stated it at `open`, and only then.
#[test]
fn evaluate_is_claimed_with_a_nanojev_model() {
    assert_eq!(open(BOTH).claims, claims(&[SYSTEMONE, EVALUATE]));
    let by_provider = open_with(
        r#"{"models":{"n":{"provider":"np"}}}"#,
        &[("np", "nanojev")],
    );
    assert_eq!(by_provider.claims, claims(&[EVALUATE]));
    let jev_only = open_with(
        r#"{"models":{"j":{"provider":"typesafe"}}}"#,
        &[("typesafe", "jev")],
    );
    assert_eq!(jev_only.claims, claims(&[SYSTEMONE]));
    // A refresh keeps the provider facts `open` was handed.
    assert_eq!(
        by_provider.refresh(r#"{"models":{"n2":{"provider":"np"}}}"#, 2),
        claims(&[EVALUATE])
    );
}

/// RED (audit plane-decisions#3): a request routes among its claim's dialect's models; a model of
/// the other dialect is that dialect's unknown model (404).
#[test]
fn a_model_of_the_wrong_dialect_is_an_unknown_model() {
    let door = open(BOTH);
    let nano = door.arrive_on(1, EVALUATE.0, EVALUATE.1, br#"{"input":{}}"#, &[]);
    assert_eq!(
        (nano.outcome, nano.route, nano.entry.as_str()),
        (Outcome::Ready, ROUTE_DIRECT, "nano"),
        "{nano:?}"
    );
    let wrong = door.arrive_on(2, EVALUATE.0, EVALUATE.1, br#"{"model":"jev"}"#, &[]);
    assert_eq!(
        (wrong.outcome, wrong.status),
        (Outcome::Refused, 404),
        "{wrong:?}"
    );
    let wrong = door.arrive_on(3, SYSTEMONE.0, SYSTEMONE.1, br#"{"model":"nano"}"#, &[]);
    assert_eq!(
        (wrong.outcome, wrong.status),
        (Outcome::Refused, 404),
        "{wrong:?}"
    );
    let jev = door.arrive(4, br#"{"state":{}}"#);
    assert_eq!(
        (jev.outcome, jev.entry.as_str()),
        (Outcome::Ready, "jev"),
        "{jev:?}"
    );
}

/// A `nanojev` unit served: its ATTEMPT, its body, and the far end's whole answer.
fn served(answer: &[u8]) -> (door_harness::Answered, door_harness::Answered) {
    let door = open(BOTH);
    let arrived = door.arrive_on(1, EVALUATE.0, EVALUATE.1, br#"{"input":{}}"#, &[]);
    assert_eq!(arrived.outcome, Outcome::Ready);
    let mut bufs = Bufs::new(1 << 16);
    let mut attempt = Given::attempt(1);
    attempt.dialect = 1;
    let request = door.piece(1, attempt, &mut bufs);
    let mut body = Given::caller(br#"{"input":{}}"#);
    body.dialect = 1;
    assert!(door.piece(1, body, &mut bufs).far);
    let mut far = Given::whole(200, answer);
    far.dialect = 1;
    (request, door.piece(1, far, &mut bufs))
}

/// RED (audit plane-decisions#3): the far end is asked at the dialect's own path, and the answer's
/// `execution.states` is the decision count; an answer with none fails loudly.
#[test]
fn a_nanojev_unit_is_sent_to_evaluate_and_bills_its_states() {
    let (request, answer) = served(br#"{"execution":{"states":3},"result":{}}"#);
    assert_eq!(request.request, "POST /api/evaluate");
    assert_eq!(answer.outcome, Some(Outcome::Ready), "{answer:?}");
    assert_eq!(answer.units[0], (0, UNITS_REPORTED, 3), "{answer:?}");
    let (_, none) = served(br#"{"result":{}}"#);
    assert_eq!(
        (none.outcome, none.short),
        (Some(Outcome::Failed), false),
        "{none:?}"
    );
    assert!(none.units.is_empty() && none.bytes.is_empty(), "{none:?}");
}

/// A model's own `protocol` that names no dialect the plane speaks is refused at validate (#51:
/// fail closed), naming the dialects it does.
#[test]
fn an_unspoken_protocol_is_refused_at_validate() {
    let (outcome, words) = validate(r#"{"models":{"m":{"provider":"p","protocol":"bogus"}}}"#);
    assert_eq!(outcome, Outcome::Refused, "{words}");
    assert!(
        words.contains("bogus") && words.contains("jev, nanojev"),
        "{words}"
    );
    assert_eq!(validate(BOTH).0, Outcome::Ready);
}
