// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-streaming/src/sessions.rs`.

use super::*;

fn json(v: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&v).expect("json")
}

/// The telephony door opens the one Twilio reader's session. RED arm: a telephony session opened
/// without the envelope reads a Twilio frame as nothing, so the caller's audio reaches no one.
#[test]
fn the_telephony_door_opens_a_session_behind_the_twilio_envelope() {
    let locked = SessionConfig::default();
    let mut s = open(Door::Twilio, &locked, 0, None, "call-1", "ref").expect("a session door");
    let start = json(
        serde_json::json!({"event":"start","start":{"streamSid":"MZ1",
        "callSid":"CA1","mediaFormat":{"encoding":"audio/x-mulaw","sampleRate":8000,"channels":1}}}),
    );
    let _ = s.from_caller(&start);
    let media = json(serde_json::json!({"event":"media","streamSid":"MZ1",
        "media":{"payload": busbar_contract::media::base64_encode(&[0x7f; 80])}}));
    let plan = s.from_caller(&media);
    assert_eq!(
        plan.to_far_end.len(),
        1,
        "the caller's audio reaches the far end"
    );
    assert!(String::from_utf8_lossy(&plan.to_far_end[0]).contains("input_audio_buffer.append"));

    // The RED arm: the same frames on the browser sideband, where no envelope is expected.
    let mut bare = open(Door::Sideband, &locked, 0, None, "call-2", "ref").expect("a session");
    let _ = bare.from_caller(&start);
    assert!(bare.from_caller(&media).to_far_end.is_empty());
}

#[test]
fn a_one_request_door_opens_no_session() {
    let locked = SessionConfig::default();
    for door in [Door::Mint, Door::Sdp, Door::Metadata] {
        assert!(
            open(door, &locked, 0, None, "x", "ref").is_none(),
            "{door:?}"
        );
    }
    assert!(matches!(
        open(Door::Gemini, &locked, 0, None, "g", "ref"),
        Some(Session::Gemini(_))
    ));
}
