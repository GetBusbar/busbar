// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-streaming/src/driven.rs`.

use super::*;

#[test]
fn every_published_claim_arrives_at_its_door_in_its_dialect() {
    let doors: Vec<_> = (0..5)
        .map(|c| arrive(c).map(|a| (a.door, a.dialect, a.op_class)))
        .collect();
    assert_eq!(
        doors,
        [
            Some((Door::Mint, 0, 0)),
            Some((Door::Sdp, 0, 0)),
            Some((Door::Sideband, 0, 0)),
            Some((Door::Gemini, 1, 0)),
            Some((Door::Twilio, 2, 0)),
        ]
    );
    assert_eq!(
        arrive(5),
        None,
        "a claim the plane never published arrives nowhere (the metadata path is no claim)"
    );
    assert_eq!(crate::door::ROUTES.len(), 5, "one door per published claim");
}

#[test]
fn the_mint_attempt_names_the_caller_and_carries_the_locked_session() {
    let cfg = SessionConfig {
        instructions: Some("locked".into()),
        ..SessionConfig::default()
    };
    let a = mint_attempt(&cfg, Some("vk-1"), None).expect("serializes");
    assert_eq!((a.verb, a.target), ("POST", "/v1/realtime/client_secrets"));
    assert_eq!(
        a.fields,
        vec![
            ("content-type", "application/json".to_string()),
            ("OpenAI-Safety-Identifier", "vk-1".to_string()),
        ]
    );
    let body: serde_json::Value = serde_json::from_slice(&a.body).expect("json");
    assert_eq!(body["expires_after"]["seconds"], 600);
    assert_eq!(body["session"]["instructions"], "locked");
    assert!(
        a.fields
            .iter()
            .all(|(n, _)| !n.eq_ignore_ascii_case("authorization")),
        "the plane never writes the credential; the kernel adds it"
    );
    let anonymous = mint_attempt(&cfg, None, None).expect("serializes");
    assert_eq!(
        anonymous.fields,
        vec![("content-type", "application/json".to_string())],
        "no reference lent, no caller named"
    );
}

#[test]
fn a_minted_secret_is_answered_and_a_failure_keeps_the_served_text() {
    let ok = mint_reply(200, br#"{"value":"ek_1","expires_at":9}"#);
    assert_eq!(ok.status, 200);
    let v: serde_json::Value = serde_json::from_slice(&ok.body).expect("json");
    assert_eq!(
        v,
        serde_json::json!({"value": "ek_1", "expires_at_unix": 9})
    );

    let refused = mint_reply(400, b"{}");
    assert_eq!(refused.status, 502);
    assert_eq!(
        String::from_utf8(refused.body).expect("utf-8"),
        "streaming ephemeral-secret mint failed: ephemeral token mint failed: client-secret \
         endpoint returned 400 Bad Request"
    );
    let not_ek = mint_reply(200, br#"{"value":"sk-real"}"#);
    assert_eq!(not_ek.status, 502);
    assert!(!String::from_utf8(not_ek.body)
        .expect("utf-8")
        .contains("sk-real"));
}

#[test]
fn the_sdp_offer_is_relayed_and_its_answer_names_the_call() {
    let a = sdp_attempt(b"v=0\r\n");
    assert_eq!((a.verb, a.target), ("POST", "/v1/realtime/calls"));
    assert_eq!(
        a.fields,
        vec![("content-type", "application/sdp".to_string())]
    );
    assert_eq!(a.body, b"v=0\r\n");

    let r = sdp_reply(201, Some("/v1/realtime/calls/rtc_abc"), b"v=0 answer");
    assert_eq!(r.status, 201);
    assert_eq!(r.rtc_call_id.as_deref(), Some("rtc_abc"));
    assert_eq!(
        r.fields,
        vec![
            ("content-type", "application/sdp".to_string()),
            ("location", "/v1/realtime/calls/rtc_abc".to_string()),
        ]
    );
    assert_eq!(sdp_reply(400, None, b"no").rtc_call_id, None);
}

#[test]
fn a_status_prints_with_its_reason_phrase_when_it_has_one() {
    assert_eq!(status_text(502), "502 Bad Gateway");
    assert_eq!(status_text(299), "299");
}

#[test]
fn each_loop_step_has_the_planes_answer() {
    use busbar_contract::abi::plane::PRINCIPAL_REQUIRED;
    assert_eq!(Door::Mint.authenticate(), PRINCIPAL_REQUIRED);
    assert_eq!(Door::Twilio.authenticate(), PRINCIPAL_REQUIRED);
    assert_eq!(Door::Sideband.verify(), "session.model");
    assert_eq!(Door::Sideband.approve(), ("session", "streaming-server"));
    assert!(
        Door::Sideband.admit().is_empty(),
        "a session pays for what the far end reports"
    );
    let cfg = SessionConfig::default();
    let sock = Door::Gemini
        .route(&cfg, None, b"")
        .expect("routes")
        .expect("a session dials");
    assert_eq!(sock.verb, "GET");
    assert!(
        !sock.target.contains("key="),
        "the credential is never in the target"
    );
    assert_eq!(
        Door::Sdp.route(&cfg, None, b"v=0").expect("routes"),
        Some(sdp_attempt(b"v=0"))
    );
    let mut units = crate::session_unit::CumulativeUnits::default();
    units.0[1] = 20;
    units.0[4] = 2;
    assert_eq!(Door::Sideband.meter(&units), vec![(1, 20), (4, 2)]);
    assert_eq!(Door::Mint.audit(), "streaming.session.open");
}
