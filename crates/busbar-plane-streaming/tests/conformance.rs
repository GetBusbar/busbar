//! The streaming-plane conformance rig: one live realtime-voice session, end to end.
//!
//! This drives [`busbar_plane_streaming::StreamingPlane`] — the STREAMING plane, registered under its
//! own key — through the whole shape a governed streaming turn takes: RESERVE (a session opens, a turn
//! is drafted, the plane names what the admit step reserves a hold against), TURNS (audio relays under
//! the open turn's hold; a barge-in supersedes it; a provider tool call opens a sub-unit), and SETTLE
//! (the turn's `response.done` carries usage, and the plane's meter names every per-turn class and the
//! quantity the money-book settles END-OF-TURN against).
//!
//! The dialect exercised is `openai-realtime` — the live realtime VOICE dialect, which is ONE dialect of
//! the streaming plane, not the plane's name. The wire fixtures are the same ones the underlying voice
//! codec proves; the point of this rig is that the STREAMING plane attributes and meters them, so a
//! deployment that registers `"streaming"` gets a byte-identical duplex session to the one the voice
//! adapter proves — the reframe changes the plane, not the bytes.

mod harness;

use busbar_contract::bounded::{FactValue, Facts, Labels};
use busbar_contract::ids::{LaneId, OpClassId};
use busbar_contract::plane::{Ingress, Plane, PlaneMeta, Progress, SessionPlane};
use busbar_contract::wire::FrameCursor;
use serde_json::json;

use busbar_plane_streaming::{Dialect, StreamingPlane, Upstream};
use harness::{ctx, destination, frame, EmptyConfig, LeakArena, WsStack};

/// A streaming plane configured with one openai-realtime (voice-dialect) upstream.
fn streaming_plane() -> StreamingPlane {
    static UPSTREAMS: &[Upstream] = &[Upstream {
        lane: LaneId::new("realtime"),
        host: "api.openai.com",
        dialect: Dialect::OpenaiRealtime,
    }];
    StreamingPlane::new(UPSTREAMS)
}

fn session_update_fixture() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "type": "session.update",
        "session": {
            "modalities": ["audio", "text"],
            "instructions": "You are a helpful voice agent.",
            "voice": "marin",
            "input_audio_format": "pcm16",
            "output_audio_format": "g711_ulaw",
            "turn_detection": {
                "type": "server_vad",
                "threshold": 0.5,
                "prefix_padding_ms": 300,
                "silence_duration_ms": 200,
                "create_response": true,
                "interrupt_response": true
            },
            "tools": [{ "type": "function", "name": "lookup", "parameters": { "type": "object" } }],
            "tool_choice": "auto",
            "max_output_tokens": 4096
        }
    }))
    .expect("fixture serializes")
}

/// THE WHOLE SHAPE, in one session: reserve, turns (relay + barge-in + tool call), settle.
#[test]
fn a_realtime_voice_session_reserves_takes_turns_and_settles() {
    let plane = streaming_plane();

    // The plane is STREAMING, and the realtime voice dialect is one of its dialects — asserted at the
    // identity level so the reframe is a fact the rig checks, not a comment.
    assert_eq!(
        <StreamingPlane as PlaneMeta>::KEY,
        "streaming",
        "the plane registers under its own streaming key, never 'voice'"
    );
    assert_eq!(Dialect::OpenaiRealtime.name(), "openai-realtime");

    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);

    // ── RESERVE ────────────────────────────────────────────────────────────────────────────────
    // The client half of the session's codec state is opened by the plane, as the kernel opens it at
    // session admit; the first client frame drafts the turn the hold is reserved against.
    let mut state = SessionPlane::open_session(&plane, &c);
    let open_bytes = session_update_fixture();
    let open_frames = [frame(&open_bytes)];
    let mut open_cursor = FrameCursor::new(&open_frames);
    let ingress = plane
        .decode_ingress(&mut open_cursor, Some(&mut state), &c)
        .expect("session.update decodes");
    let Ingress::Open(draft) = ingress else {
        panic!("expected Ingress::Open (a turn opens), got {ingress:?}");
    };
    assert_eq!(draft.op.as_str(), "duplex_turn");
    assert_eq!(
        draft.facts.get(busbar_plane_streaming::meta::FACT_DIALECT),
        Some(FactValue::Str("openai-realtime")),
        "the opened turn names the realtime voice dialect"
    );
    assert!(
        draft.correlation_out.is_some(),
        "the turn carries the correlation an answer rides back on"
    );

    // The admit step is where the money-book (S2) reserves a hold: the plane's `admit` names the lane,
    // the response ceiling and the priced input span the reservation is sized against. Proven to
    // answer here; the reservation itself is the cost unit's, on the far side of the kernel.
    let opened_unit = harness::unit(OpClassId::new("duplex_turn"), draft.body_ir, draft.facts);
    let admit = plane.admit(&opened_unit, &c);
    assert!(
        !format!("{admit:?}").is_empty(),
        "admit answers with the facts the hold is reserved against"
    );

    // ── TURNS ─────────────────────────────────────────────────────────────────────────────────
    // (1) Audio relays UNDER the open turn's hold — a second frame does not reopen a turn.
    let audio = serde_json::to_vec(&json!({
        "type": "input_audio_buffer.append",
        "audio": "AAAA",
    }))
    .expect("audio fixture serializes");
    let audio_frames = [frame(&audio)];
    let mut audio_cursor = FrameCursor::new(&audio_frames);
    let relayed = plane
        .decode_ingress(&mut audio_cursor, Some(&mut state), &c)
        .expect("audio frame decodes");
    let Ingress::Frame { for_, .. } = relayed else {
        panic!("expected Ingress::Frame (audio relays under the turn), got {relayed:?}");
    };
    assert!(
        for_.is_some(),
        "the relay frame carries the turn's correlation"
    );

    // (2) BARGE-IN: a client truncation supersedes the open turn, and the plane writes the declared
    // interrupt fact carrying the playback position — the kernel's teller loop reads this to truncate.
    let truncate = serde_json::to_vec(&json!({
        "type": "conversation.item.truncate",
        "item_id": "item_1",
        "content_index": 0,
        "audio_end_ms": 640,
    }))
    .expect("truncate fixture serializes");
    let truncate_frames = [frame(&truncate)];
    let mut truncate_cursor = FrameCursor::new(&truncate_frames);
    let barge_in = plane
        .decode_ingress(&mut truncate_cursor, Some(&mut state), &c)
        .expect("truncate decodes");
    let Ingress::Open(bi_draft) = barge_in else {
        panic!("expected Ingress::Open (barge-in opens the superseding turn), got {barge_in:?}");
    };
    let interrupt_fact = <StreamingPlane as PlaneMeta>::INTERRUPT_FACT
        .expect("the streaming plane declares an interrupt fact");
    assert_eq!(
        bi_draft.facts.get(interrupt_fact),
        Some(FactValue::Int(640)),
        "barge-in carries the playback position the truncation is established at"
    );

    // (3) TOOL LOOP: a provider tool call arrives on the upstream half and surfaces as a one-shot
    // sub-unit the kernel drives the tool loop over — priced as its own `tool_call` op class.
    let mut upstream_state = SessionPlane::open_upstream(
        &plane,
        &destination("api.openai.com", LaneId::new("realtime")),
        &c,
    );
    let tool_open = serde_json::to_vec(&json!({
        "type": "response.output_item.added",
        "item": { "type": "function_call", "call_id": "call_1", "name": "lookup" },
    }))
    .expect("tool-call fixture serializes");
    let tool_frames = [frame(&tool_open)];
    let mut tool_cursor = FrameCursor::new(&tool_frames);
    let tool = plane
        .decode_response(
            &mut tool_cursor,
            &destination("api.openai.com", LaneId::new("realtime")),
            Some(&mut upstream_state),
            &c,
        )
        .expect("tool-call open decodes");
    let Progress::OneShot(tool_draft) = tool else {
        panic!("expected Progress::OneShot (a tool call opens), got {tool:?}");
    };
    assert_eq!(tool_draft.op.as_str(), "tool_call");
    assert_eq!(
        tool_draft
            .facts
            .get(busbar_plane_streaming::meta::FACT_TOOL_NAME),
        Some(FactValue::Str("lookup")),
        "the tool-call sub-unit names the tool the loop invokes"
    );

    // ── SETTLE (END-OF-TURN) ────────────────────────────────────────────────────────────────────
    // The turn's `response.done` carries usage; the plane decodes it as the terminal frame and the
    // meter names every per-turn class with the reported quantity. This is the evidence the money-book
    // (S2) settles the reserved hold against, once per completed turn (#23).
    let done = serde_json::to_vec(&json!({
        "type": "response.done",
        "response": {
            "usage": {
                "input_token_details": { "audio_tokens": 10, "text_tokens": 3, "cached_tokens": 1 },
                "output_token_details": { "audio_tokens": 20, "text_tokens": 4 },
            }
        }
    }))
    .expect("usage fixture serializes");
    let done_frames = [frame(&done)];
    let mut done_cursor = FrameCursor::new(&done_frames);
    let settle_dest = destination("api.openai.com", LaneId::new("realtime"));
    let progress = plane
        .decode_response(
            &mut done_cursor,
            &settle_dest,
            Some(&mut upstream_state),
            &c,
        )
        .expect("response.done decodes");
    let Progress::Terminal { r, .. } = progress else {
        panic!("expected Progress::Terminal (the turn completes), got {progress:?}");
    };
    assert_eq!(r.finish, busbar_contract::unit::FinishClass::TurnComplete);

    let settled_unit = harness::unit(OpClassId::new("duplex_turn"), r.ir, Facts::new());
    let locators = plane.meter(&settled_unit, &r, &c);
    let quantity = |class: &str| {
        locators
            .lines
            .as_slice()
            .iter()
            .find(|l| l.class.as_str() == class)
            .and_then(|l| l.quantity)
    };
    // Every class the money-book settles the turn against, at the quantity the usage reports. The
    // in/out split is the money-relevant part: swapping a direction reprices the turn.
    assert_eq!(quantity("audio_tokens_in"), Some(10));
    assert_eq!(quantity("audio_tokens_out"), Some(20));
    assert_eq!(quantity("text_tokens_in"), Some(3));
    assert_eq!(quantity("text_tokens_out"), Some(4));
    assert_eq!(quantity("cached_tokens"), Some(1));
    // The duration class the architecture's own inventory names for this plane is present too.
    assert!(
        locators
            .lines
            .as_slice()
            .iter()
            .any(|l| l.class.as_str() == "audio_seconds_in"),
        "the per-turn meter names the audio-seconds class the money-book settles duration against"
    );
}

/// The streaming plane speaks exactly the dialect roster the proven voice adapter does — the reframe
/// changes the plane's identity, never the claims the boot's overlap check reads.
#[test]
fn the_streaming_plane_declares_its_full_dialect_and_meter_roster() {
    // Two WS duplex claims (openai-realtime + gemini-live) and two one-shot HTTP claims (transcribe +
    // tts); twilio's claim is dropped until its transport lands (see `claims`).
    assert_eq!(
        <StreamingPlane as PlaneMeta>::CLAIMS.len(),
        4,
        "streaming claims its four live dialect surfaces"
    );
    // The seven per-turn meter classes the architecture's inventory row names for this plane.
    assert_eq!(
        <StreamingPlane as PlaneMeta>::METER_CLASSES.len(),
        7,
        "streaming meters its seven per-turn classes"
    );
    // The two duplex dialects a streaming session may DIAL, with voice among them.
    let plane = streaming_plane();
    assert!(plane
        .upstream_for_dialect(Dialect::OpenaiRealtime)
        .is_some());
    assert!(plane.upstream_for_dialect(Dialect::GeminiLive).is_none());
}
