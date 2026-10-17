// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-streaming/src/ticket.rs`.

use super::*;

#[test]
fn a_mint_asks_for_the_requested_lifetime_held_inside_its_bounds() {
    assert_eq!(clamped_ttl_secs(None), 600);
    assert_eq!(clamped_ttl_secs(Some(1)), 10);
    assert_eq!(clamped_ttl_secs(Some(99_999)), 7200);
    assert_eq!(clamped_ttl_secs(Some(300)), 300);
}

/// The mint door's answer is the OpenAI-compatible shape SDKs read, and nothing else.
#[test]
fn the_caller_is_answered_the_ticket_and_its_expiry_only() {
    let read: serde_json::Value =
        serde_json::from_slice(&minted_answer("ek_abc", 1_700_000_600)).expect("json");
    assert_eq!(
        read,
        serde_json::json!({"value": "ek_abc", "expires_at_unix": 1_700_000_600})
    );
    assert!(TICKET_PREFIX == "ek_", "SDKs pass the ek_ prefix through");
}

#[test]
fn a_tickets_record_locks_its_session_and_reads_back() {
    let locked = SessionConfig {
        instructions: Some("locked".into()),
        ..SessionConfig::default()
    };
    let record = ticket_record(&locked).expect("serializes");
    assert_eq!(locked_by(&record).expect("reads"), locked);
    // RED: a record that is not a session config.
    assert!(locked_by(b"not json").is_err());
    assert!(locked_by(b"[1,2]").is_err());
}

/// The upstream form: the locked session first, then the opened part the description fills.
#[test]
fn the_upstream_form_carries_the_session_and_opens_the_description_part() {
    let locked = SessionConfig {
        instructions: Some("be brief".into()),
        ..SessionConfig::default()
    };
    let (content_type, lead) = call_form(&locked).expect("serializes");
    assert_eq!(
        content_type,
        "multipart/form-data; boundary=busbar-call-form"
    );
    let lead = String::from_utf8(lead).expect("utf-8");
    let session = String::from_utf8(ticket_record(&locked).expect("serializes")).expect("utf-8");
    assert_eq!(
        lead,
        format!(
            "--busbar-call-form\r\nContent-Disposition: form-data; name=\"session\"\r\n\
             Content-Type: application/json\r\n\r\n{session}\r\n--busbar-call-form\r\n\
             Content-Disposition: form-data; name=\"sdp\"\r\nContent-Type: application/sdp\r\n\r\n"
        )
    );
}

#[test]
fn busbars_call_id_is_opaque_and_named_by_its_location() {
    let id = call_id(&[0xab; 16]);
    assert_eq!(id, format!("rtc_{}", "ab".repeat(16)));
    assert_ne!(call_id(&[0; 16]), call_id(&[1; 16]));
    assert_eq!(call_location(&id), format!("/v1/realtime/calls/{id}"));
    assert_eq!(call_id_of(&call_location(&id)), Some(id));
}

#[test]
fn the_providers_call_id_is_the_call_segment_of_its_location() {
    assert_eq!(
        call_id_of("/v1/realtime/calls/rtc_abc?x=1"),
        Some("rtc_abc".into())
    );
    assert_eq!(
        call_id_of("https://p.example/v1/realtime/calls/rtc_z#f"),
        Some("rtc_z".into())
    );
    // RED: no call segment.
    assert_eq!(call_id_of("/v1/realtime/calls/abc"), None);
    assert_eq!(call_id_of("/v1/realtime/calls/rtc_"), None);
}
