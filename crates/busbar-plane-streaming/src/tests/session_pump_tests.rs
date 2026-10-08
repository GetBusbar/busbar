// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-streaming/src/session_pump.rs`.

use std::sync::{Arc, Mutex};

use super::*;
use crate::codec::ir::codec::OpenAiRealtimeCodec;
use crate::governed::{GovernedCalls, ReplyRefusal};

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

fn serves_all(_: &str) -> bool {
    true
}

fn serves_none(_: &str) -> bool {
    false
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
    let (out, runs) = p.on_server_frame(usage_done(), 0, &mut sink, &serves_all);
    assert!(!out.close && runs.is_empty());
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
fn a_sink_that_refuses_cuts_the_session_and_tells_the_far_end_to_stop() {
    let mut p = pump();
    let mut sink = Turns {
        refuse: true,
        ..Turns::default()
    };
    let (out, _) = p.on_server_frame(usage_done(), 0, &mut sink, &serves_all);
    assert!(out.close);
    assert!(texts(&out.upstream).contains("response.cancel"));
}

#[test]
fn a_barge_in_cancels_and_truncates_at_what_was_heard() {
    let mut p = pump();
    let mut sink = Turns::default();
    let b64 = busbar_contract::media::base64_encode(&[0u8; 96]);
    let _ = p.on_server_frame(
        wire(
            serde_json::json!({"type":"response.output_audio.delta","delta":b64,
            "item_id":"it7","output_index":0,"content_index":0}),
        ),
        0,
        &mut sink,
        &serves_all,
    );
    let (out, _) = p.on_server_frame(
        wire(
            serde_json::json!({"type":"input_audio_buffer.speech_started",
            "audio_start_ms":0,"item_id":"it7"}),
        ),
        0,
        &mut sink,
        &serves_all,
    );
    let up = texts(&out.upstream);
    assert!(up.contains("response.cancel"), "{up}");
    assert!(
        up.contains("conversation.item.truncate") && up.contains("\"audio_end_ms\":2"),
        "{up}"
    );
    assert!(texts(&out.downlink).contains("speech_started"));
}

#[test]
fn a_tool_call_is_run_once_on_its_close_with_its_accumulated_arguments() {
    let mut p = pump();
    let mut sink = Turns::default();
    let mut runs = Vec::new();
    for f in call_frames("ca", "alpha", "{\"x\":1}") {
        let (_, r) = p.on_server_frame(f, 0, &mut sink, &serves_all);
        runs.extend(r);
    }
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].name, "alpha");
    assert_eq!(runs[0].call_id, "ca");
    assert_eq!(runs[0].args, b"{\"x\":1}");
    let mut out = Outbound::default();
    p.tool_executed(runs.remove(0), b"{\"ok\":true}".to_vec(), &mut out);
    let up = texts(&out.upstream);
    assert!(up.contains("function_call_output") && up.contains("\"call_id\":\"ca\""));
    assert!(up.contains("response.create"));
    p.settle_open_turn(&mut sink);
    assert_eq!(sink.closed.len(), 1);
    assert_eq!(
        sink.closed[0].1.tool_calls, 1,
        "the opened call is counted once"
    );
}

/// P-ITEM: VOICE TOOL-ARGS (spec DONE item 2, "All P-item behaviours match 1.5.5"; the drive log's
/// P5, commit 470351a480: "streamed tool-call arguments are discarded"). The model streams a call's
/// arguments as several partial-JSON fragments; they reach the executor CONCATENATED, as one call,
/// run once, on the call's close and not before.
///
/// Voice is new in 1.6.0; the 1.5.5 behaviour it matches is the llm surface's own streamed tool
/// call (owner correction 2026-09-28): 1.5.5 accumulated every `InputJsonDelta` fragment of an open
/// tool block and emitted the call ONCE on its block stop with the fully reassembled arguments,
/// because parsing each fragment alone lost the arguments and split one call into many (v1.5.5
/// `crates/busbar/src/proto/gemini/writer.rs:734-780`).
#[test]
fn p_item_voice_tool_args_streamed_fragments_reach_the_executor_whole_and_once() {
    let mut p = pump();
    let mut sink = Turns::default();
    let mut runs = Vec::new();
    let open = wire(serde_json::json!({"type":"response.output_item.added",
        "item":{"type":"function_call","call_id":"cw","name":"weather"}}));
    let (_, r) = p.on_server_frame(open, 0, &mut sink, &serves_all);
    assert!(r.is_empty(), "an announced call is not run");
    for fragment in ["{\"lo", "c\":\"S", "F\"}"] {
        let delta = wire(
            serde_json::json!({"type":"response.function_call_arguments.delta",
            "call_id":"cw","delta":fragment}),
        );
        let (_, r) = p.on_server_frame(delta, 0, &mut sink, &serves_all);
        assert!(
            r.is_empty(),
            "a call is not run on a fragment of its arguments"
        );
    }
    let done = wire(
        serde_json::json!({"type":"response.function_call_arguments.done",
        "call_id":"cw"}),
    );
    let (_, r) = p.on_server_frame(done, 0, &mut sink, &serves_all);
    runs.extend(r);
    assert_eq!(runs.len(), 1, "one call, run once on its close");
    assert_eq!(runs[0].name, "weather");
    assert_eq!(runs[0].call_id, "cw");
    assert_eq!(
        runs[0].args, b"{\"loc\":\"SF\"}",
        "the fragments reach the executor whole, in order"
    );
}

/// A table that records what the pump asked of it.
#[derive(Default)]
struct Table {
    planned: Mutex<Vec<(u64, String, u64)>>,
    open: Mutex<Vec<String>>,
    closed: Mutex<Vec<u64>>,
}

impl GovernedCalls for Table {
    fn planned(&self, session: u64, call_id: &str, now_ms: u64) -> bool {
        self.planned
            .lock()
            .expect("lock")
            .push((session, call_id.to_string(), now_ms));
        self.open.lock().expect("lock").push(call_id.to_string());
        true
    }
    fn replied(&self, _session: u64, call_id: &str) -> Result<(), ReplyRefusal> {
        let mut open = self.open.lock().expect("lock");
        match open.iter().position(|c| c == call_id) {
            Some(i) => {
                open.remove(i);
                Ok(())
            }
            None => Err(ReplyRefusal::UnknownCall),
        }
    }
    fn expired(&self, _now_ms: u64) -> usize {
        0
    }
    fn closed(&self, session: u64) {
        self.closed.lock().expect("lock").push(session);
    }
}

#[test]
fn a_call_the_session_does_not_serve_waits_for_the_callers_reply() {
    let table = Arc::new(Table::default());
    let mut p = pump();
    p.bind_governed(GovernedSession {
        session: 7,
        calls: table.clone(),
    });
    let mut sink = Turns::default();
    for f in call_frames("cc", "lookup", "{}") {
        let (_, runs) = p.on_server_frame(f, 42, &mut sink, &serves_none);
        assert!(
            runs.is_empty(),
            "the gateway never answers a call it does not serve"
        );
    }
    assert_eq!(
        *table.planned.lock().expect("lock"),
        vec![(7, "cc".to_string(), 42)]
    );
    let reply = |id: &str| {
        wire(
            serde_json::json!({"type":"conversation.item.create","item":{
            "type":"function_call_output","call_id":id,"output":"{}"}}),
        )
    };
    let forged = p.on_client_frame(reply("nope"));
    assert!(forged.refused_reply && forged.upstream.is_empty());
    let real = p.on_client_frame(reply("cc"));
    assert!(!real.refused_reply);
    let up = texts(&real.upstream);
    assert!(up.contains("function_call_output") && up.contains("response.create"));
    p.forget_governed_calls();
    assert_eq!(*table.closed.lock().expect("lock"), vec![7]);
    assert_eq!(p.governed_session(), Some(7));
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
    let (out, _) = p.on_server_frame(
        wire(serde_json::json!({"type":"error","error":{"code":"x","message":"y"}})),
        0,
        &mut sink,
        &serves_all,
    );
    assert_eq!(sink.closed.len(), 1);
    assert!(sink.closed[0].0.is_none());
    assert!(texts(&out.downlink).contains("error"));
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
        let _ = p.on_server_frame(usage_done(), 0, &mut sink, &serves_all);
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
    let _ = p.on_server_frame(usage_done(), 0, &mut sink, &serves_all);
    assert_eq!(sink.closed.len(), 1);
    assert_eq!(sink.closed[0].1.audio_ms_in, 1000);
    assert_eq!(billed_audio_seconds(&sink), 1);
}
