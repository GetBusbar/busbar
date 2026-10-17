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

/// Busbar terminates the browser's media (row 132): the mint door dials nothing; the SDP door is a
/// session whose far end is busbar's own call, one form carrying the locked session.
#[test]
fn the_mint_door_dials_nothing_and_the_sdp_door_places_busbars_own_call() {
    let cfg = SessionConfig {
        instructions: Some("locked".into()),
        ..SessionConfig::default()
    };
    assert_eq!(Door::Mint.route(&cfg, None), Ok(None));
    assert!(!Door::Mint.is_session());
    assert!(Door::Sdp.is_session());
    let call = Door::Sdp
        .route(&cfg, None)
        .expect("routes")
        .expect("a call");
    assert_eq!(
        (call.verb, call.target.as_str()),
        ("POST", "/v1/realtime/calls")
    );
    assert_eq!(
        call.fields,
        vec![(
            "content-type",
            "multipart/form-data; boundary=busbar-call-form".to_string()
        )]
    );
    let (_, lead) = crate::ticket::call_form(&cfg).expect("serializes");
    assert_eq!(call.body, lead);
    assert_eq!(call, call_attempt(&cfg).expect("serializes"));
    assert!(
        call.fields
            .iter()
            .all(|(n, _)| !n.eq_ignore_ascii_case("authorization")),
        "the plane never writes the credential; the kernel adds it"
    );
}

/// The sideband door controls the provider's call its busbar call id resolved to.
#[test]
fn a_sideband_session_dials_the_providers_call() {
    let cfg = SessionConfig::default();
    let sock = Door::Sideband
        .route(&cfg, Some("rtc_upstream"))
        .expect("routes")
        .expect("dials");
    assert_eq!(sock.target, "/v1/realtime?call_id=rtc_upstream");
    let bare = Door::Sideband
        .route(&cfg, None)
        .expect("routes")
        .expect("dials");
    assert_eq!(bare.target, "/v1/realtime");
}

/// A ticket's answer and a refused mint, in the served plane's shapes.
#[test]
fn a_minted_ticket_is_answered_and_a_failure_keeps_the_served_text() {
    let ok = minted("ek_1", 9);
    assert_eq!(ok.status, 200);
    let v: serde_json::Value = serde_json::from_slice(&ok.body).expect("json");
    assert_eq!(
        v,
        serde_json::json!({"value": "ek_1", "expires_at_unix": 9})
    );
    let refused = mint_failed("no ticket is minted: the principal's key does not stand");
    assert_eq!(refused.status, 502);
    assert_eq!(
        String::from_utf8(refused.body).expect("utf-8"),
        "streaming ephemeral-secret mint failed: ephemeral token mint failed: no ticket is \
         minted: the principal's key does not stand"
    );
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
        .route(&cfg, None)
        .expect("routes")
        .expect("a session dials");
    assert_eq!(sock.verb, "GET");
    assert!(
        !sock.target.contains("key="),
        "the credential is never in the target"
    );
    assert_eq!(
        Door::Sdp.route(&cfg, None).expect("routes"),
        Some(call_attempt(&cfg).expect("serializes"))
    );
    let mut units = crate::session_unit::CumulativeUnits::default();
    units.0[1] = 20;
    units.0[4] = 2;
    assert_eq!(Door::Sideband.meter(&units), vec![(1, 20), (4, 2)]);
    assert_eq!(Door::Mint.audit(), "streaming.session.open");
}
