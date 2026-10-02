// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-streaming/src/broker.rs`.

use super::*;

#[test]
fn a_mint_asks_for_the_requested_lifetime_held_inside_its_bounds() {
    assert_eq!(clamped_ttl_secs(None), 600);
    assert_eq!(clamped_ttl_secs(Some(1)), 10);
    assert_eq!(clamped_ttl_secs(Some(99_999)), 7200);
    assert_eq!(clamped_ttl_secs(Some(300)), 300);
}

#[test]
fn the_mint_body_anchors_the_lifetime_and_carries_the_locked_session() {
    let cfg = SessionConfig {
        instructions: Some("be brief".into()),
        ..SessionConfig::default()
    };
    let body: serde_json::Value =
        serde_json::from_slice(&mint_request_body(600, &cfg).expect("serializes")).expect("json");
    assert_eq!(
        body["expires_after"],
        serde_json::json!({"anchor": "created_at", "seconds": 600})
    );
    assert_eq!(body["session"]["instructions"], "be brief");
}

#[test]
fn a_minted_answer_reads_the_ek_secret_and_its_expiry() {
    let m = read_minted(br#"{"value":"ek_live","expires_at":1700000600}"#).expect("reads");
    assert_eq!(
        m,
        Minted {
            value: "ek_live".into(),
            expires_at_unix: 1_700_000_600
        }
    );
    assert_eq!(
        read_minted(br#"{"value":"ek_x"}"#)
            .expect("reads")
            .expires_at_unix,
        0
    );
}

#[test]
fn a_mint_answer_that_is_not_an_ephemeral_secret_is_refused() {
    assert_eq!(
        read_minted(br#"{"value":"sk-real"}"#),
        Err("client-secret response value is not an ek_ ephemeral secret".to_string())
    );
    let err = read_minted(b"not json").expect_err("refused");
    assert!(err.starts_with("client-secret response did not parse: "), "{err}");
}

#[test]
fn the_browser_is_answered_the_secret_and_its_expiry_only() {
    let body = minted_answer(&Minted {
        value: "ek_1".into(),
        expires_at_unix: 5,
    });
    let read: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(read, serde_json::json!({"value": "ek_1", "expires_at_unix": 5}));
}

#[test]
fn the_call_id_is_the_rtc_segment_of_the_location() {
    assert_eq!(
        rtc_call_id_of("/v1/realtime/calls/rtc_abc?x=1"),
        Some("rtc_abc".into())
    );
    assert_eq!(
        rtc_call_id_of("https://p.example/v1/realtime/calls/rtc_z#f"),
        Some("rtc_z".into())
    );
    assert_eq!(rtc_call_id_of("/v1/realtime/calls/abc"), None);
}
