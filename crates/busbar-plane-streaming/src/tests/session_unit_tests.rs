// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-streaming/src/session_unit.rs`.

use super::*;
use crate::codec::ir::codec::OpenAiRealtimeCodec;
use crate::session_params::g711_config;

fn json(v: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&v).expect("json")
}

fn text(frames: &[Vec<u8>]) -> String {
    frames
        .iter()
        .map(|f| String::from_utf8_lossy(f).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

fn start(encoding: &str) -> Vec<u8> {
    json(
        serde_json::json!({"event":"start","start":{"streamSid":"MZ1","callSid":"CA1",
        "mediaFormat":{"encoding":encoding,"sampleRate":8000,"channels":1}}}),
    )
}

fn media(sid: &str, bytes: &[u8]) -> Vec<u8> {
    json(serde_json::json!({"event":"media","streamSid":sid,
        "media":{"payload": busbar_contract::media::base64_encode(bytes)}}))
}

fn telephony() -> SessionUnit<OpenAiRealtimeCodec> {
    SessionUnit::open(OpenAiRealtimeCodec, g711_config(), true, 0, None)
}

#[test]
fn the_callers_audio_on_the_telephony_door_reaches_the_far_end() {
    // The served telephony leg handed Twilio's `event`-tagged frames to the realtime reader, which
    // reads only `type`-tagged ones: the caller's audio reached no one.
    let mut s = telephony();
    assert_eq!(s.from_caller(&start("audio/x-mulaw")), Plan::default());
    let plan = s.from_caller(&media("MZ1", &[0x7f; 160]));
    let up = text(&plan.to_far_end);
    assert!(up.contains("input_audio_buffer.append"), "{up}");
    assert!(
        up.contains(&busbar_contract::media::base64_encode(&[0x7f; 160])),
        "the caller's audio passes through unchanged: {up}"
    );
}

#[test]
fn media_for_another_stream_and_unmodelled_events_reach_no_one() {
    let mut s = telephony();
    let _ = s.from_caller(&start("audio/x-mulaw"));
    assert_eq!(s.from_caller(&media("MZ-forged", &[1; 8])), Plan::default());
    assert_eq!(
        s.from_caller(&json(serde_json::json!({"event":"something-new"}))),
        Plan::default(),
        "an event this reader does not model is dropped, not a session end"
    );
    assert!(!s.ended());
}

#[test]
fn a_call_in_another_media_format_ends_the_session() {
    let mut s = telephony();
    assert!(s.from_caller(&start("audio/l16")).end);
    assert!(s.ended());
}

#[test]
fn model_audio_and_a_barge_in_reach_the_caller_in_the_carriers_envelope() {
    let mut s = telephony();
    let _ = s.from_caller(&start("audio/x-mulaw"));
    let delta = json(serde_json::json!({"type":"response.output_audio.delta",
        "delta": busbar_contract::media::base64_encode(&[9; 16]),
        "item_id":"it1","output_index":0,"content_index":0}));
    let plan = s.from_far_end(&delta, 0);
    let down = text(&plan.to_caller);
    assert!(
        down.contains("\"event\":\"media\"") && down.contains("MZ1"),
        "{down}"
    );
    let barge = json(
        serde_json::json!({"type":"input_audio_buffer.speech_started",
        "audio_start_ms":0,"item_id":"it1"}),
    );
    let plan = s.from_far_end(&barge, 0);
    assert!(text(&plan.to_caller).contains("\"event\":\"clear\""));
    assert!(text(&plan.to_far_end).contains("response.cancel"));
}

#[test]
fn a_stop_settles_the_open_turns_counters_once() {
    let mut s = telephony();
    let _ = s.from_caller(&start("audio/x-mulaw"));
    // Two seconds of 8 kHz mu-law: 8 bytes a millisecond.
    let _ = s.from_caller(&media("MZ1", &[0; 16_000]));
    assert_eq!(s.units(), CumulativeUnits::default(), "no turn closed yet");
    assert!(
        s.from_caller(&json(serde_json::json!({"event":"stop"})))
            .end
    );
    let seconds = CLASSES
        .iter()
        .position(|c| *c == meta::CLASS_AUDIO_SECONDS_IN)
        .expect("declared");
    assert_eq!(s.units().0[seconds], 2);
    let _ = s.end();
    assert_eq!(s.units().0[seconds], 2, "a second end settles nothing");
}

#[test]
fn usage_reports_accumulate_across_turns() {
    let mut s = SessionUnit::open(
        OpenAiRealtimeCodec,
        SessionConfig::default(),
        false,
        0,
        None,
    );
    let done = json(
        serde_json::json!({"type":"response.done","response":{"usage":{
        "input_token_details":{"audio_tokens":10,"text_tokens":3,"cached_tokens":2},
        "output_token_details":{"audio_tokens":20,"text_tokens":4}}}}),
    );
    let _ = s.from_far_end(&done, 0);
    let _ = s.from_far_end(&done, 0);
    assert_eq!(
        s.units().0,
        [20, 40, 6, 8, 0, 0],
        "cached tokens are attribution, never billed"
    );
}

#[test]
fn a_session_past_its_ceiling_is_told_why_and_ends() {
    let mut s = SessionUnit::open(
        OpenAiRealtimeCodec,
        SessionConfig::default(),
        false,
        1_000,
        Some(2),
    );
    assert_eq!(s.tick(1_000 + 1_999_999_999, 0), Plan::default());
    let plan = s.tick(1_000 + 2_000_000_000, 0);
    assert!(plan.end);
    assert!(text(&plan.to_caller).contains(crate::session_pump::SESSION_CEILING_REASON));
    assert!(s.ended());
}

#[test]
fn the_sessions_record_is_written_at_open_on_its_call_id_and_at_its_end() {
    let mut s = SessionUnit::open_as(
        OpenAiRealtimeCodec,
        SessionConfig::default(),
        false,
        5_000_000_000,
        None,
        "call-1",
        "ref-abc",
    );
    let opened = s.take_writes();
    assert_eq!(opened.len(), 1);
    assert_eq!(
        (
            opened[0].id.as_str(),
            opened[0].owner.as_str(),
            opened[0].updated_at,
            opened[0].terminal
        ),
        ("call-1", "ref-abc", 5, false)
    );
    s.set_rtc_call_id("rtc_9", 6);
    let _ = s.end();
    let _ = s.end();
    let later = s.take_writes();
    assert_eq!(later.len(), 2, "the call id once, the end once");
    assert_eq!(later[0].rtc_call_id.as_deref(), Some("rtc_9"));
    assert!(later[1].terminal && later[1].rtc_call_id.as_deref() == Some("rtc_9"));
    assert!(s.take_writes().is_empty());
}

#[test]
fn admitted_milliseconds_meter_as_whole_seconds_rounded_up() {
    assert_eq!(meta::audio_seconds_in(0), 0);
    assert_eq!(meta::audio_seconds_in(1), 1);
    assert_eq!(meta::audio_seconds_in(1_500), 2);
    assert_eq!(meta::audio_seconds_in(3_000), 3);
}

#[test]
fn a_stop_settles_the_open_turns_tool_calls_too() {
    let mut s = telephony();
    let _ = s.from_caller(&start("audio/x-mulaw"));
    let _ = s.from_caller(&media("MZ1", &[0; 8_000]));
    let open = json(serde_json::json!({"type":"response.output_item.added",
        "item":{"type":"function_call","call_id":"c1","name":"lookup"}}));
    let _ = s.from_far_end(&open, 0);
    assert!(
        s.from_caller(&json(serde_json::json!({"event":"stop"})))
            .end
    );
    assert_eq!(s.units().0, [0, 0, 0, 0, 1, 1]);
}

#[test]
fn one_full_turn_reports_the_six_classes_the_served_plane_metered() {
    let mut s = SessionUnit::open(
        OpenAiRealtimeCodec,
        SessionConfig::default(),
        false,
        0,
        None,
    );
    let pcm = busbar_contract::media::base64_encode(&vec![0u8; 48_000]);
    let _ = s.from_caller(&json(
        serde_json::json!({"type":"input_audio_buffer.append","audio":pcm}),
    ));
    let open = json(serde_json::json!({"type":"response.output_item.added",
        "item":{"type":"function_call","call_id":"c1","name":"lookup"}}));
    let _ = s.from_far_end(&open, 0);
    let done = json(
        serde_json::json!({"type":"response.done","response":{"usage":{
        "input_token_details":{"audio_tokens":10,"text_tokens":3,"cached_tokens":1},
        "output_token_details":{"audio_tokens":20,"text_tokens":4}}}}),
    );
    let _ = s.from_far_end(&done, 0);
    assert_eq!(s.units().0, [10, 20, 3, 4, 1, 1]);
}

#[test]
fn a_start_with_no_stream_id_refuses_the_call() {
    let mut s = telephony();
    let empty = json(
        serde_json::json!({"event":"start","start":{"streamSid":"","callSid":"CA1",
        "mediaFormat":{"encoding":"audio/x-mulaw","sampleRate":8000,"channels":1}}}),
    );
    assert!(s.from_caller(&empty).end);
    assert!(s.ended());
    assert_eq!(
        s.from_caller(&media("", &[1; 80])),
        Plan::default(),
        "no binding was opened for an empty stream id"
    );
}

#[test]
fn a_media_payload_resuming_after_padding_is_refused_and_never_billed() {
    for payload in ["QQ==QQ==".to_string(), "QQ==".repeat(2_000)] {
        let mut s = telephony();
        let _ = s.from_caller(&start("audio/x-mulaw"));
        let frame = json(serde_json::json!({"event":"media","streamSid":"MZ1",
            "media":{"payload": payload}}));
        let plan = s.from_caller(&frame);
        assert!(plan.end && plan.to_far_end.is_empty());
        assert_eq!(s.units(), CumulativeUnits::default(), "nothing is billed");
    }
}
