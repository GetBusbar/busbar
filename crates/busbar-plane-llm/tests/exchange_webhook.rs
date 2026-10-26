// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The OpenAI Responses webhook receiver, ported from the retiring engine crate's
//! `openai_responses_webhook.rs` onto this plane (ARCHITECT 2026-10-14, option A): the plane's own
//! `webhooks:` section switches it on, the auth kind verifies the sender, and the plane reads the
//! delivery and acknowledges it.
//!
//! RED: before the port this plane had no receiver, no `webhooks:` section and no claim on the
//! receiver's path, so every test here failed to build. The off-by-default half is the parity
//! guard: a document that does not write the section claims exactly what it claimed before.

// A list read is `unsafe` while its pointer and length fields are pub (status row 194), and
// safe once #1471 makes them private: the same `unsafe { x.list() }` compiles on both.
#![allow(unused_unsafe)]

use busbar_contract::abi::mechanism::door::{SECTION_CONSUMED, SECTION_DECLARING};
use busbar_contract::abi::plane::CLAIM_EXACT;
use busbar_plane_llm::exchange::webhook::{
    ack, from_owned, is_receiver, read_event, Event, Webhooks, MALFORMED, PATH, SECTION,
};
use busbar_plane_llm::plane_door::{claims, webhook_claims, STATEMENT};

const ON: &[u8] = br#"{"webhooks":{"openai_responses":true}}"#;

#[test]
fn the_receiver_is_off_unless_its_section_switches_it_on() {
    assert_eq!(from_owned(b""), Ok(Webhooks::default()));
    assert_eq!(from_owned(b"{}"), Ok(Webhooks::default()));
    assert_eq!(
        from_owned(br#"{"webhooks":{}}"#),
        Ok(Webhooks::default()),
        "a section that names no receiver switches none on"
    );
    assert_eq!(
        from_owned(br#"{"webhooks":{"openai_responses":false}}"#),
        Ok(Webhooks::default())
    );
    assert!(
        webhook_claims(Webhooks::default()).is_empty(),
        "off: no claim beyond the plane's own, so the path answers what the previous release did"
    );
    assert!(
        claims().iter().all(|c| c.target != PATH),
        "the plane's own claims never name the receiver's path"
    );
}

#[test]
fn switched_on_the_receiver_is_one_exact_post_claim_wearing_the_responses_dialect() {
    let on = from_owned(ON).expect("the section reads");
    assert!(on.openai_responses);
    let claimed = webhook_claims(on);
    assert_eq!(claimed.len(), 1);
    let claim = &claimed[0];
    assert_eq!((claim.verb.as_str(), claim.target.as_str()), ("POST", PATH));
    assert_eq!(
        claim.flags & CLAIM_EXACT,
        CLAIM_EXACT,
        "exact: it ranks above the fallback"
    );
    let responses = busbar_plane_llm::dialect::DIALECTS
        .iter()
        .position(|d| d.name == "responses")
        .expect("the plane serves the Responses dialect");
    assert_eq!(usize::from(claim.refusal_dialect), responses);
}

#[test]
fn a_section_that_does_not_read_is_refused_naming_it() {
    let err = from_owned(br#"{"webhooks":{"openai_respones":true}}"#)
        .expect_err("a misspelt receiver is refused, never silently off");
    assert!(err.starts_with("`webhooks`: "), "{err}");
    assert!(err.contains("unknown field `openai_respones`"), "{err}");
    let err = from_owned(br#"{"webhooks":{"openai_responses":"yes"}}"#)
        .expect_err("a wrong-typed switch is refused");
    assert!(err.starts_with("`webhooks`: "), "{err}");
}

#[test]
fn the_statement_owns_the_section_neither_declaring_nor_consumed() {
    let statement = STATEMENT;
    let sections = unsafe { statement.sections() };
    let owned: Vec<&[u8]> = sections
        .iter()
        .filter(|s| s.flags & (SECTION_DECLARING | SECTION_CONSUMED) == 0)
        // SAFETY: each `AbiStr` names a `'static` string of `len` bytes.
        .map(|s| unsafe { std::slice::from_raw_parts(s.name.ptr(), s.name.len()) })
        .collect();
    assert_eq!(owned, [SECTION.as_bytes()]);
}

#[test]
fn only_a_post_on_the_exact_path_is_a_delivery() {
    assert!(is_receiver("POST", PATH));
    assert!(!is_receiver("GET", PATH));
    assert!(!is_receiver("POST", "/v1/llm/webhooks/openai/x"));
    assert!(!is_receiver("POST", "/v1/responses"));
}

#[test]
fn a_delivery_is_read_and_acknowledged_with_its_correlation_id() {
    let body = br#"{"id":"evt_1","type":"response.completed","created_at":1719000000,
        "data":{"id":"resp_abc","extra":1},"unknown":true}"#;
    let event = read_event(body).expect("a well-formed delivery reads");
    assert_eq!(
        event,
        Event {
            event_type: "response.completed".to_string(),
            response_id: "resp_abc".to_string(),
        }
    );
    assert_eq!(
        ack(&event),
        br#"{"received":true,"response_id":"resp_abc","type":"response.completed"}"#.to_vec(),
        "the acknowledgement the receiver this ports answered"
    );
}

#[test]
fn a_delivery_missing_or_mistyping_what_it_must_carry_is_refused() {
    for body in [
        &b"not json"[..],
        b"[]",
        br#"{"data":{"id":"resp_1"}}"#,
        br#"{"type":"","data":{"id":"resp_1"}}"#,
        br#"{"type":"response.completed"}"#,
        br#"{"type":"response.completed","data":"resp_1"}"#,
        br#"{"type":"response.completed","data":{"id":""}}"#,
        br#"{"type":"response.completed","data":{"id":7}}"#,
        br#"{"id":7,"type":"response.completed","data":{"id":"resp_1"}}"#,
        br#"{"created_at":"soon","type":"response.completed","data":{"id":"resp_1"}}"#,
    ] {
        assert_eq!(
            read_event(body),
            Err(MALFORMED),
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

/// LEGACY `crates/busbar-llm/src/tests/webhook_tests.rs::body_tolerates_absent_and_unknown_fields`
/// and `::body_rejects_present_but_wrong_typed_modeled_fields`. A delivery that leaves out the
/// optional `id` and `created_at` and carries keys this receiver does not model still reads, while
/// a `type` that is present but not text is refused like any other mistyped field.
///
/// RED: a receiver that requires the optional fields refuses a lenient delivery, or one that
/// stringifies a numeric `type` acknowledges it.
#[test]
fn a_delivery_without_its_optional_fields_reads_and_a_numeric_type_does_not() {
    let lenient = br#"{"type":"response.failed","data":{"id":"resp_1","status":"failed"},
        "some_future_field":{"nested":true}}"#;
    assert_eq!(
        read_event(lenient),
        Ok(Event {
            event_type: "response.failed".to_string(),
            response_id: "resp_1".to_string(),
        })
    );
    assert_eq!(
        read_event(br#"{"type":5,"data":{"id":"resp_1"}}"#),
        Err(MALFORMED)
    );
}
