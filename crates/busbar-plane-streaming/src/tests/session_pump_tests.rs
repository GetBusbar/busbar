// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-streaming/src/session_pump.rs`.

use bytes::Bytes;

use super::*;
use crate::codec::ir::codec::OpenAiRealtimeCodec;

fn wire(v: serde_json::Value) -> WireEvent {
    WireEvent(Bytes::from(serde_json::to_vec(&v).expect("json")))
}

fn texts(frames: &[WireEvent]) -> String {
    frames
        .iter()
        .map(|w| String::from_utf8_lossy(&w.0).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

fn pump() -> SessionPump<OpenAiRealtimeCodec> {
    SessionPump::new(OpenAiRealtimeCodec, None)
}

/// Every closed turn, and the answer the next one gets.
#[derive(Default)]
struct Turns {
    closed: Vec<(Option<IrDuplexUsage>, TurnCounters)>,
    refuse: bool,
}

impl TurnSink for Turns {
    fn turn_closed(&mut self, usage: Option<&IrDuplexUsage>, counters: TurnCounters) -> bool {
        self.closed.push((usage.copied(), counters));
        !self.refuse
    }
}

fn usage_done() -> WireEvent {
    wire(serde_json::json!({
        "type": "response.done",
        "response": {"usage": {
            "input_token_details": {"audio_tokens": 10, "text_tokens": 3},
            "output_token_details": {"audio_tokens": 20, "text_tokens": 4},
        }}
    }))
}

fn call_frames(id: &str, name: &str, args: &str) -> [WireEvent; 3] {
    [
        wire(serde_json::json!({"type":"response.output_item.added",
            "item":{"type":"function_call","call_id":id,"name":name}})),
        wire(
            serde_json::json!({"type":"response.function_call_arguments.delta",
            "call_id":id,"delta":args}),
        ),
        wire(serde_json::json!({"type":"response.function_call_arguments.done","call_id":id})),
    ]
}

#[test]
fn a_usage_report_closes_the_turn_with_its_counters_and_the_session_continues() {
    let mut p = pump();
    let mut sink = Turns::default();
    let b64 = busbar_contract::media::base64_encode(&[0u8; 48_000]);
    let up = p.on_client_frame(wire(serde_json::json!({
        "type":"input_audio_buffer.append","audio": b64
    })));
    assert_eq!(up.upstream.len(), 1, "uplink audio is written through");
    let out = p.on_server_frame(usage_done(), 0, &mut sink);
    assert!(!out.close);
    assert_eq!(sink.closed.len(), 1);
    let (usage, counters) = sink.closed[0];
    let usage = usage.expect("the turn carries its usage");
    assert_eq!((usage.audio_in, usage.audio_out), (10, 20));
    assert_eq!(
        counters.audio_ms_in, 1000,
        "48 000 bytes of pcm16 is one second"
    );
}

#[test]
fn a_sink_that_refuses_closes_the_session_and_authors_nothing_upstream() {
    let mut p = pump();
    let mut sink = Turns {
        refuse: true,
        ..Turns::default()
    };
    let out = p.on_server_frame(usage_done(), 0, &mut sink);
    assert!(out.close);
    assert!(out.upstream.is_empty(), "{}", texts(&out.upstream));
}

/// LAW 11 (QUESTIONS Q98): a tool call is part of the model's response. Every frame of it is relayed
/// to the caller as the model streamed it, its arguments verbatim, and nothing the gateway writes
/// upstream answers it: no `function_call_output`, no `response.create`. RED: the pump handed a
/// closed call to a server-side executor and wrote the executor's output upstream itself.
#[test]
fn a_tool_call_is_relayed_to_the_caller_as_is_and_the_gateway_answers_nothing() {
    let mut p = pump();
    let mut sink = Turns::default();
    let (mut down, mut up) = (Vec::new(), Vec::new());
    for f in call_frames("ca", "alpha", "{\"x\":1}") {
        let out = p.on_server_frame(f, 0, &mut sink);
        down.extend(out.downlink);
        up.extend(out.upstream);
    }
    let down = texts(&down);
    assert!(
        down.contains("\"name\":\"alpha\"")
            && down.contains("\"call_id\":\"ca\"")
            && down.contains("{\\\"x\\\":1}")
            && down.contains("function_call_arguments.done"),
        "the call's open, its arguments and its close reach the caller: {down}"
    );
    assert!(
        up.is_empty(),
        "the gateway writes nothing upstream for a call: {}",
        texts(&up)
    );
    p.settle_open_turn(&mut sink);
    assert_eq!(sink.closed.len(), 1);
    assert_eq!(
        sink.closed[0].1.tool_calls, 1,
        "the opened call is counted once"
    );
}

/// P-ITEM: VOICE TOOL-ARGS (spec DONE item 2, "All P-item behaviours match 1.5.5"; the drive log's
/// P5, commit 470351a480: "streamed tool-call arguments are discarded"). The model streams a call's
/// arguments as several partial-JSON fragments; none of them is lost, and they reach the caller
/// whole, in order, as one call, counted once.
///
/// Voice is new in 1.6.0; the 1.5.5 behaviour it matches is the llm surface's own streamed tool
/// call (owner correction 2026-09-28): 1.5.5 accumulated every `InputJsonDelta` fragment of an open
/// tool block and emitted the call ONCE on its block stop with the fully reassembled arguments,
/// because parsing each fragment alone lost the arguments and split one call into many (v1.5.5
/// `crates/busbar/src/proto/gemini/writer.rs:734-780`). The streaming plane holds no tool executor
/// (LAW 11, QUESTIONS Q98): the caller runs the call, so the pin is on what the caller receives,
/// and the gateway answers nothing upstream on any fragment or on the close.
#[test]
fn p_item_voice_tool_args_streamed_fragments_reach_the_caller_whole_and_once() {
    let mut p = pump();
    let mut sink = Turns::default();
    let mut down = Vec::new();
    let open = wire(serde_json::json!({"type":"response.output_item.added",
        "item":{"type":"function_call","call_id":"cw","name":"weather"}}));
    let out = p.on_server_frame(open, 0, &mut sink);
    assert!(out.upstream.is_empty(), "an announced call is not answered");
    down.extend(out.downlink);
    for fragment in ["{\"lo", "c\":\"S", "F\"}"] {
        let delta = wire(
            serde_json::json!({"type":"response.function_call_arguments.delta",
            "call_id":"cw","delta":fragment}),
        );
        let out = p.on_server_frame(delta, 0, &mut sink);
        assert!(
            out.upstream.is_empty(),
            "a fragment of a call's arguments is not answered"
        );
        down.extend(out.downlink);
    }
    let done = wire(
        serde_json::json!({"type":"response.function_call_arguments.done",
        "call_id":"cw"}),
    );
    let out = p.on_server_frame(done, 0, &mut sink);
    assert!(out.upstream.is_empty(), "a closed call is not answered");
    down.extend(out.downlink);
    let frames: Vec<serde_json::Value> = down
        .iter()
        .map(|w| serde_json::from_slice(&w.0).expect("a downlink frame is json"))
        .collect();
    let args: String = frames
        .iter()
        .filter(|f| f["type"] == "response.function_call_arguments.delta")
        .map(|f| f["delta"].as_str().expect("a delta carries its fragment"))
        .collect();
    assert_eq!(
        args,
        "{\"loc\":\"SF\"}",
        "the fragments reach the caller whole, in order: {}",
        texts(&down)
    );
    assert_eq!(
        frames
            .iter()
            .filter(|f| f["type"] == "response.function_call_arguments.done")
            .count(),
        1,
        "one call, closed once: {}",
        texts(&down)
    );
    p.settle_open_turn(&mut sink);
    assert_eq!(sink.closed.len(), 1);
    assert_eq!(sink.closed[0].1.tool_calls, 1, "one call, counted once");
}

#[test]
fn a_callers_session_update_is_replaced_by_the_locked_config() {
    let locked = SessionConfig {
        instructions: Some("locked".into()),
        ..SessionConfig::default()
    };
    let mut p = SessionPump::new(OpenAiRealtimeCodec, Some(locked));
    let out = p.on_client_frame(wire(serde_json::json!({
        "type":"session.update","session":{"type":"realtime","instructions":"override"}
    })));
    let up = texts(&out.upstream);
    assert!(up.contains("locked") && !up.contains("override"), "{up}");
}

#[test]
fn a_session_past_its_ceiling_is_told_why_in_its_dialect() {
    let mut p = pump();
    let told = p
        .ceiling_error(1800)
        .expect("the dialect carries an error frame");
    let text = String::from_utf8_lossy(&told.0).into_owned();
    assert!(
        text.contains(SESSION_CEILING_REASON) && text.contains("1800 s"),
        "{text}"
    );
}

#[test]
fn an_error_closes_the_open_turn_before_it_is_relayed() {
    let mut p = pump();
    let mut sink = Turns::default();
    let out = p.on_server_frame(
        wire(serde_json::json!({"type":"error","error":{"code":"x","message":"y"}})),
        0,
        &mut sink,
    );
    assert_eq!(sink.closed.len(), 1);
    assert!(sink.closed[0].0.is_none());
    assert!(texts(&out.downlink).contains("error"));
}

#[test]
fn an_ungoverned_session_relays_a_call_and_never_answers_it() {
    // No open-call table bound (an ungoverned node): the call reaches the caller, and nothing the
    // gateway writes answers it.
    let mut p = pump();
    let mut sink = Turns::default();
    let (mut down, mut up) = (Vec::new(), Vec::new());
    for f in call_frames("cu", "unknown_tool", "{\"q\":1}") {
        let out = p.on_server_frame(f, 0, &mut sink);
        down.extend(out.downlink);
        up.extend(out.upstream);
    }
    let down = texts(&down);
    assert!(
        down.contains("unknown_tool") && down.contains("\"call_id\":\"cu\""),
        "the call is relayed to the caller: {down}"
    );
    assert!(
        !texts(&up).contains("function_call_output"),
        "no result is authored upstream by the gateway"
    );
}

fn uplink_ms(ms: usize) -> WireEvent {
    wire(serde_json::json!({"type":"input_audio_buffer.append",
        "audio": busbar_contract::media::base64_encode(&vec![0u8; ms * 48])}))
}

#[test]
fn an_upstream_error_still_meters_the_turn_it_ended() {
    let mut p = pump();
    let mut sink = Turns::default();
    let _ = p.on_client_frame(uplink_ms(40_000));
    for id in ["e1", "e2"] {
        let open = call_frames(id, "t", "{}");
        let [first, ..] = open;
        let _ = p.on_server_frame(first, 0, &mut sink);
    }
    let _ = p.on_server_frame(
        wire(serde_json::json!({"type":"error","error":{"code":"x","message":"y"}})),
        0,
        &mut sink,
    );
    assert_eq!(sink.closed.len(), 1);
    let closed = sink.closed[0].1;
    assert_eq!((closed.audio_ms_in, closed.tool_calls), (40_000, 2));
}

#[test]
fn a_barge_in_bills_what_the_interrupted_turn_served_on_the_turn_that_takes_over() {
    let mut p = pump();
    let mut sink = Turns::default();
    let _ = p.on_client_frame(uplink_ms(1_000));
    let [open, ..] = call_frames("b1", "t", "{}");
    let _ = p.on_server_frame(open, 0, &mut sink);
    let _ = p.on_server_frame(
        wire(
            serde_json::json!({"type":"input_audio_buffer.speech_started",
            "audio_start_ms":0,"item_id":"it"}),
        ),
        0,
        &mut sink,
    );
    assert!(
        sink.closed.is_empty(),
        "a barge-in closes no turn and drops no counter"
    );
    let _ = p.on_server_frame(usage_done(), 0, &mut sink);
    assert_eq!(sink.closed.len(), 1);
    let closed = sink.closed[0].1;
    assert_eq!((closed.audio_ms_in, closed.tool_calls), (1_000, 1));
}

/// A caller frame that is not JSON goes nowhere and counts nothing: the lock is judged on what the
/// reader reads, and bytes it cannot read never reach a far end that might read them otherwise.
#[test]
fn a_caller_frame_that_is_not_json_goes_nowhere_and_counts_nothing() {
    let mut p = pump();
    let mut sink = Turns::default();
    let bad = p.on_client_frame(WireEvent(Bytes::from_static(&[0xff, 0xfe, 0x00])));
    assert!(bad.upstream.is_empty() && bad.downlink.is_empty() && !bad.close);
    let unclosed = p.on_client_frame(WireEvent(Bytes::from_static(
        br#"{"type":"session.update","session":{"instructions":"x"},}"#,
    )));
    assert!(
        unclosed.upstream.is_empty(),
        "a near-JSON update is not passed"
    );
    p.settle_open_turn(&mut sink);
    assert!(sink.closed.is_empty(), "nothing was counted");
}

/// The `audio_seconds_in` every closed turn bills, summed over the session.
fn billed_audio_seconds(sink: &Turns) -> u64 {
    sink.closed
        .iter()
        .flat_map(|(usage, counters)| crate::session::class_counts(usage.as_ref(), *counters))
        .filter(|(class, _)| *class == crate::meta::CLASS_AUDIO_SECONDS_IN)
        .map(|(_, n)| n)
        .sum()
}

/// RED-BEFORE-GREEN (MONEY-AUDIT STR-2): a session is one unit, so its uplink audio converts to
/// seconds ONCE. Rounding each turn's milliseconds up on its own billed 20 turns of 1050 ms as 40 s;
/// the session spoke 21 000 ms, which is 21 s.
#[test]
fn twenty_turns_of_1050_ms_bill_21_audio_seconds_not_40() {
    let mut p = pump();
    let mut sink = Turns::default();
    // 1050 ms of pcm16 (48 bytes per ms).
    let b64 = busbar_contract::media::base64_encode(&[0u8; 1050 * 48]);
    for _ in 0..20 {
        let _ = p.on_client_frame(wire(serde_json::json!({
            "type":"input_audio_buffer.append","audio": b64
        })));
        let _ = p.on_server_frame(usage_done(), 0, &mut sink);
    }
    assert_eq!(sink.closed.len(), 20);
    assert_eq!(billed_audio_seconds(&sink), 21);
}

/// RED-BEFORE-GREEN (MONEY-AUDIT STR-2): a frame's bytes need not divide into whole milliseconds,
/// and the part left over is audio too. 960 frames of 50 bytes of pcm16 are 48 000 bytes, one second;
/// flooring each frame to 1 ms counted 960 ms.
#[test]
fn the_part_of_a_millisecond_a_frame_leaves_over_is_carried_not_floored() {
    let mut p = pump();
    let mut sink = Turns::default();
    let b64 = busbar_contract::media::base64_encode(&[0u8; 50]);
    for _ in 0..960 {
        let _ = p.on_client_frame(wire(serde_json::json!({
            "type":"input_audio_buffer.append","audio": b64
        })));
    }
    let _ = p.on_server_frame(usage_done(), 0, &mut sink);
    assert_eq!(sink.closed.len(), 1);
    assert_eq!(sink.closed[0].1.audio_ms_in, 1000);
    assert_eq!(billed_audio_seconds(&sink), 1);
}

/// A Gemini Live uplink blob of `bytes` zero bytes, its mime stating `rate`.
fn gemini_uplink(rate: u32, bytes: usize) -> WireEvent {
    wire(serde_json::json!({"realtimeInput":{"audio":{
        "mimeType": format!("audio/pcm;rate={rate}"),
        "data": busbar_contract::media::base64_encode(&vec![0u8; bytes])
    }}}))
}

/// RED-BEFORE-GREEN (plane-streaming audit HIGH 9; THE DESIGN section 7, "a plane that
/// under-reports is that plugin's bug"): Gemini Live's uplink is 16 kHz PCM, 32 bytes a
/// millisecond. Counted at the 24 kHz rate (48 bytes a millisecond), one second of it was 666 ms.
#[test]
fn a_second_of_gemini_16k_uplink_counts_one_second_not_two_thirds() {
    let mut p = SessionPump::new(crate::codec::ir::GeminiLiveCodec, None);
    let mut sink = Turns::default();
    let _ = p.on_client_frame(gemini_uplink(16_000, 32_000));
    p.settle_open_turn(&mut sink);
    assert_eq!(sink.closed.len(), 1);
    assert_eq!(sink.closed[0].1.audio_ms_in, 1000);
}

/// RED-BEFORE-GREEN (audit HIGH 9): each frame is counted at the rate its own wire states, and the
/// part of a millisecond one frame leaves over carries exactly onto a frame at another rate. Half a
/// millisecond at 16 kHz (16 bytes) and half at 24 kHz (24 bytes), a thousand times each, is one
/// second.
#[test]
fn gemini_uplink_frames_at_two_rates_each_count_at_their_own() {
    let mut p = SessionPump::new(crate::codec::ir::GeminiLiveCodec, None);
    let mut sink = Turns::default();
    for _ in 0..1000 {
        let _ = p.on_client_frame(gemini_uplink(16_000, 16));
        let _ = p.on_client_frame(gemini_uplink(24_000, 24));
    }
    p.settle_open_turn(&mut sink);
    assert_eq!(sink.closed.len(), 1);
    assert_eq!(sink.closed[0].1.audio_ms_in, 1000);
}

// ── THE SAME-DIALECT RELAY (Law 5; Law 11; Part 2 #45) ─────────────────────────────────────────

/// The bytes of `v`, exactly as a peer sent them.
fn raw(v: &str) -> WireEvent {
    WireEvent(Bytes::from(v.as_bytes().to_vec()))
}

fn locked_pump() -> SessionPump<OpenAiRealtimeCodec> {
    SessionPump::new(
        OpenAiRealtimeCodec,
        Some(SessionConfig {
            instructions: Some("locked".into()),
            ..SessionConfig::default()
        }),
    )
}

/// RED-BEFORE-GREEN (Law 11, "content never triggers an action ... answers nothing on the
/// caller's behalf"): the far end's speech-start is the caller's to act on. Nothing goes upstream,
/// and the event reaches the caller as the far end sent it. RED: the pump wrote `response.cancel`
/// and `conversation.item.truncate` upstream itself and rewrote `audio_start_ms` to 0.
#[test]
fn a_barge_in_is_relayed_unchanged_and_nothing_goes_upstream() {
    let mut p = locked_pump();
    let mut sink = Turns::default();
    let _ = p.on_server_frame(
        wire(serde_json::json!({"type":"response.output_audio.delta",
            "delta": busbar_contract::media::base64_encode(&[0u8; 96]),"item_id":"i1"})),
        0,
        &mut sink,
    );
    let frame = r#"{"type":"input_audio_buffer.speech_started","item_id":"i1","audio_start_ms":1234,"event_id":"ev_9"}"#;
    let out = p.on_server_frame(raw(frame), 0, &mut sink);
    assert!(
        out.upstream.is_empty(),
        "busbar authors nothing upstream on a barge-in: {}",
        texts(&out.upstream)
    );
    assert_eq!(
        texts(&out.downlink),
        frame,
        "the event reaches the caller unchanged"
    );
}

/// RED-BEFORE-GREEN (Law 5, "A RELAY (same dialect) runs the reader only as that read-only tap
/// and sends the client's bytes"): every far-end frame reaches the caller byte for byte, the
/// events the IR does not model and the usage report included, while the usage still meters.
/// RED: `response.done` was consumed, `rate_limits.updated` dropped, a transcript delta dropped and
/// an audio delta re-serialised without its `event_id`.
#[test]
fn a_same_dialect_far_end_frame_reaches_the_caller_byte_for_byte() {
    let mut p = locked_pump();
    let mut sink = Turns::default();
    let b64 = busbar_contract::media::base64_encode(&[1u8; 96]);
    let frames = [
        format!(r#"{{"type":"response.output_audio.delta","event_id":"ev_1","response_id":"r1","item_id":"i1","output_index":0,"content_index":0,"delta":"{b64}"}}"#),
        r#"{"type":"response.output_audio_transcript.delta","event_id":"ev_2","delta":"hel"}"#.to_string(),
        r#"{"type":"rate_limits.updated","event_id":"ev_3","rate_limits":[{"name":"tokens","limit":100,"remaining":90,"reset_seconds":1.5}]}"#.to_string(),
        r#"{"type":"response.done","event_id":"ev_4","response":{"id":"r1","status":"completed","usage":{"total_tokens":7,"input_tokens":3,"output_tokens":4,"input_token_details":{"audio_tokens":1,"text_tokens":2},"output_token_details":{"audio_tokens":3,"text_tokens":1}}}}"#.to_string(),
    ];
    for f in &frames {
        let out = p.on_server_frame(raw(f), 0, &mut sink);
        assert!(out.upstream.is_empty(), "{f}");
        assert_eq!(&texts(&out.downlink), f, "relayed byte for byte");
    }
    assert_eq!(
        sink.closed.len(),
        1,
        "the usage report still closes the turn"
    );
    let usage = sink.closed[0].0.expect("its usage");
    assert_eq!(
        (
            usage.audio_in,
            usage.text_in,
            usage.audio_out,
            usage.text_out
        ),
        (1, 2, 3, 1)
    );
}

/// RED-BEFORE-GREEN (Law 5 governed splice; Part 2 #45 "cannot override the session's locked
/// instructions"): a caller's `session.update` keeps every field it set, unmodelled ones included,
/// and only the locked keys are spliced in. RED: the whole update was replaced by the locked config,
/// so the caller's voice and noise-reduction setting never reached the far end.
#[test]
fn a_callers_session_update_keeps_its_fields_and_takes_the_locked_keys() {
    let mut p = locked_pump();
    let out = p.on_client_frame(raw(
        r#"{"type":"session.update","event_id":"c1","session":{"type":"realtime","voice":"verse","instructions":"override","tools":[{"type":"function","name":"evil"}],"input_audio_noise_reduction":{"type":"near_field"}}}"#,
    ));
    assert_eq!(out.upstream.len(), 1);
    let v: serde_json::Value = serde_json::from_slice(&out.upstream[0].0).expect("json");
    assert_eq!(v["type"], "session.update");
    assert_eq!(v["event_id"], "c1");
    assert_eq!(v["session"]["type"], "realtime");
    assert_eq!(v["session"]["voice"], "verse");
    assert_eq!(
        v["session"]["input_audio_noise_reduction"]["type"],
        "near_field"
    );
    assert_eq!(v["session"]["instructions"], "locked");
    assert!(
        v["session"].get("tools").is_none(),
        "a caller-authored tool set never reaches the far end: {v}"
    );
}

/// RED-BEFORE-GREEN (Part 2 #45, "the browser ... never authors tools or instructions, and cannot
/// override the session's locked instructions"): a per-response override of the instructions or
/// the tool set is spliced out of a caller's `response.create`; every other field passes. RED: the
/// response object went upstream verbatim.
#[test]
fn a_callers_response_create_cannot_override_the_locked_instructions_or_tools() {
    let mut p = locked_pump();
    let out = p.on_client_frame(raw(
        r#"{"type":"response.create","response":{"instructions":"evil","tools":[{"type":"function","name":"x"}],"output_modalities":["text"],"metadata":{"k":"v"}}}"#,
    ));
    assert_eq!(out.upstream.len(), 1);
    let v: serde_json::Value = serde_json::from_slice(&out.upstream[0].0).expect("json");
    assert_eq!(v["type"], "response.create");
    assert!(v["response"].get("instructions").is_none(), "{v}");
    assert!(v["response"].get("tools").is_none(), "{v}");
    assert_eq!(v["response"]["output_modalities"][0], "text");
    assert_eq!(v["response"]["metadata"]["k"], "v");
}

/// RED-BEFORE-GREEN (Law 5): a caller frame the IR does not model is the caller's to send; the
/// far end answers it. RED: it went nowhere.
#[test]
fn an_unmodelled_caller_frame_reaches_the_far_end_unchanged() {
    let mut p = locked_pump();
    let frame = r#"{"type":"output_audio_buffer.clear","event_id":"c9"}"#;
    let out = p.on_client_frame(raw(frame));
    assert_eq!(texts(&out.upstream), frame);
}

fn gemini_locked_pump() -> SessionPump<crate::codec::ir::GeminiLiveCodec> {
    SessionPump::new(
        crate::codec::ir::GeminiLiveCodec,
        Some(SessionConfig {
            instructions: Some("locked".into()),
            ..SessionConfig::default()
        }),
    )
}

/// RED-BEFORE-GREEN (Law 5; Law 11 "a tool call ... goes back to the caller unchanged"): a
/// Gemini Live caller receives the far end's tool call as one frame, both calls in it, arguments
/// and all, and a text part and a `goAway` reach it too. RED: the call was re-framed as one frame
/// per call announcing it WITHOUT arguments and a second one with them, and the text part and the
/// `goAway` were dropped.
#[test]
fn a_gemini_far_end_frame_reaches_the_caller_byte_for_byte() {
    let mut p = gemini_locked_pump();
    let mut sink = Turns::default();
    let frames = [
        r#"{"toolCall":{"functionCalls":[{"id":"f1","name":"a","args":{"x":1}},{"id":"f2","name":"b","args":{"y":2}}]}}"#,
        r#"{"serverContent":{"modelTurn":{"parts":[{"text":"hello"}]}}}"#,
        r#"{"goAway":{"timeLeft":"10s"}}"#,
    ];
    for f in frames {
        let out = p.on_server_frame(raw(f), 0, &mut sink);
        assert!(out.upstream.is_empty(), "{f}");
        assert_eq!(texts(&out.downlink), f, "relayed byte for byte");
    }
    p.settle_open_turn(&mut sink);
    assert_eq!(sink.closed.len(), 1);
    assert_eq!(sink.closed[0].1.tool_calls, 2, "both calls are counted");
}

/// RED-BEFORE-GREEN (Law 5 governed splice; Part 2 #45): a Gemini caller's `setup` keeps what it
/// set, and the locked system instruction is spliced in over the caller's. RED: the whole setup was
/// replaced, so the caller's model and generation settings never reached the far end.
#[test]
fn a_gemini_callers_setup_keeps_its_fields_and_takes_the_locked_instruction() {
    let mut p = gemini_locked_pump();
    let out = p.on_client_frame(raw(
        r#"{"setup":{"model":"models/gemini-live","generationConfig":{"temperature":0.3,"responseModalities":["AUDIO"]},"systemInstruction":{"parts":[{"text":"override"}]},"tools":[{"functionDeclarations":[{"name":"evil"}]}]}}"#,
    ));
    assert_eq!(out.upstream.len(), 1);
    let v: serde_json::Value = serde_json::from_slice(&out.upstream[0].0).expect("json");
    assert_eq!(v["setup"]["model"], "models/gemini-live");
    assert_eq!(v["setup"]["generationConfig"]["temperature"], 0.3);
    assert_eq!(
        v["setup"]["generationConfig"]["responseModalities"][0],
        "AUDIO"
    );
    assert_eq!(
        v["setup"]["systemInstruction"]["parts"][0]["text"],
        "locked"
    );
    assert!(v["setup"].get("tools").is_none(), "{v}");
}
