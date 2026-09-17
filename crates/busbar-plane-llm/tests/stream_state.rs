//! A stream is read against the state the frames before it left behind.
//!
//! The plane holds nothing across calls; the kernel holds one codec state per connection half and
//! hands it in. What matters is that the plane hands it BACK. `StreamDecodeState` is almost entirely
//! latches — which content block is open, whether the opening frame has been seen, the stop reason
//! one dialect buffers between its penultimate and final frames — and a latch read from a copy that
//! is then dropped is a latch that resets on every chunk.
//!
//! Both cases below are written against the dialect whose stream splits ONE fact across TWO frames,
//! because that is where a forgotten latch is not a subtle difference but a lost answer: the reason
//! the model stopped, and the model's text.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::ids::LaneId;
use busbar_contract::plane::{Plane, PlaneSessionState, Progress};
use busbar_contract::unit::FinishClass;
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::codec::LlmSessionState;
use busbar_plane_llm::{LlmPlane, Upstream};

/// One configured upstream, speaking the dialect whose stream carries state between frames.
const UPSTREAMS: &[Upstream] = &[Upstream {
    lane: LaneId::new("lane-bedrock"),
    host: "bedrock.invalid",
    dialect: "bedrock",
    model: "claude",
}];

/// The lane the answers below arrive on.
const LANE: LaneId = LaneId::new("lane-bedrock");

/// The kernel's own half of the codec state, as the kernel opens it.
fn session() -> PlaneSessionState {
    PlaneSessionState::new(LlmSessionState::default())
}

/// One streamed frame, in the transport's own event framing.
fn event(name: &str, data: &str) -> Vec<u8> {
    format!("event: {name}\ndata: {data}\n\n").into_bytes()
}

/// The reason the model stopped survives the frame boundary the dialect splits it across.
///
/// This dialect states the stop reason on one frame and the usage on the NEXT one, and its reader
/// buffers the first until the second arrives. Read against a copy of the state, the buffered reason
/// is dropped with the copy: the closing frame reports no reason at all, and an answer that ended
/// naturally settles as a partial one.
#[test]
fn a_stop_reason_buffered_on_one_frame_is_read_on_the_next() {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("bedrock"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("bedrock.invalid", LANE);
    let mut st = session();

    let stop = event(
        "messageStop",
        r#"{"type":"messageStop","stopReason":"end_turn"}"#,
    );
    let frames = vec![harness::frame(&stop)];
    let mut answers = FrameCursor::new(&frames);
    let first = plane
        .decode_response(&mut answers, &dest, Some(&mut st), &ctx)
        .expect("the stop frame is read");
    assert!(
        matches!(first, Progress::Frame { .. }),
        "the stop frame states no usage yet, so it does not end the answer: {first:?}"
    );

    let meta = event(
        "metadata",
        r#"{"type":"metadata","usage":{"inputTokens":10,"outputTokens":5}}"#,
    );
    let frames = vec![harness::frame(&meta)];
    let mut answers = FrameCursor::new(&frames);
    let second = plane
        .decode_response(&mut answers, &dest, Some(&mut st), &ctx)
        .expect("the usage frame is read");
    let Progress::Terminal { r, .. } = second else {
        panic!("the usage frame ends the answer: {second:?}");
    };
    assert_eq!(
        r.finish,
        FinishClass::Complete,
        "the reason buffered by the previous frame is what says the answer completed"
    );
}

/// The text of a stream reaches the client, frame after frame.
///
/// This dialect implies its text block from the first text delta and reads every later delta against
/// the open-block latch that implied it — and it opens nothing at all until the stream's own opening
/// frame has been seen. Read against a copy, every frame after the first arrives at a state that has
/// seen no opening frame, so each delta is dropped as an orphan and the client is written nothing.
#[test]
fn the_deltas_after_the_opening_frame_are_written_to_the_client() {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    // The client speaks a different dialect from the upstream, so the frames are rewritten rather
    // than relayed and the bytes below are the bytes the client reads.
    let transport = harness::HttpStack::new(harness::path_for("anthropic"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("bedrock.invalid", LANE);
    // Two halves, as the kernel opens two: one for the connection the frames arrive on and one for
    // the connection they are written to. Reading the upstream's grammar and writing the client's
    // are two positions in two streams, and one value cannot be both.
    let mut upstream = session();
    let mut client = session();

    let written = |frame: &[u8],
                   upstream: &mut PlaneSessionState,
                   client: &mut PlaneSessionState|
     -> String {
        let frames = vec![harness::frame(frame)];
        let mut answers = FrameCursor::new(&frames);
        let progress = plane
            .decode_response(&mut answers, &dest, Some(upstream), &ctx)
            .expect("the frame is read");
        let (Progress::Frame { r, .. } | Progress::Terminal { r, .. }) = progress else {
            panic!("a streamed frame carries a response: {progress:?}");
        };
        let bytes = plane
            .encode_response(&r, Some(client), &ctx)
            .expect("the frame is written");
        String::from_utf8(bytes.as_slice().to_vec()).expect("the client's bytes are text")
    };

    let _ = written(
        &event(
            "messageStart",
            r#"{"type":"messageStart","role":"assistant"}"#,
        ),
        &mut upstream,
        &mut client,
    );
    let first_delta = written(
        &event(
            "contentBlockDelta",
            r#"{"type":"contentBlockDelta","contentBlockIndex":0,"delta":{"text":"Hel"}}"#,
        ),
        &mut upstream,
        &mut client,
    );
    assert!(
        first_delta.contains("content_block_start") && first_delta.contains("Hel"),
        "the first delta opens the block and carries its text: {first_delta}"
    );

    let second_delta = written(
        &event(
            "contentBlockDelta",
            r#"{"type":"contentBlockDelta","contentBlockIndex":0,"delta":{"text":"lo"}}"#,
        ),
        &mut upstream,
        &mut client,
    );
    assert!(
        second_delta.contains("lo"),
        "the second delta's text reaches the client: {second_delta}"
    );
    assert!(
        !second_delta.contains("content_block_start"),
        "and it does not re-open a block the first delta already opened: {second_delta}"
    );
}

/// An SSE comment/keepalive frame keeps the stream open rather than aborting it.
///
/// A `: ping` line is neither `event:` nor `data:` and is not JSON. Read as a whole body it would
/// fail to parse and abort the stream as `Malformed`; it is the transport holding the connection
/// open, so the plane must report `NeedMore`, the way the A2A and MCP planes do.
#[test]
fn an_sse_comment_keepalive_is_needmore_not_malformed() {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("bedrock"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("bedrock.invalid", LANE);
    let mut st = session();

    let comment = b": ping\n\n".to_vec();
    let frames = vec![harness::frame(&comment)];
    let mut answers = FrameCursor::new(&frames);
    let progress = plane
        .decode_response(&mut answers, &dest, Some(&mut st), &ctx)
        .expect("a keepalive comment must not error the stream");
    assert!(
        matches!(progress, Progress::NeedMore),
        "an SSE comment is a keepalive, not a document: {progress:?}"
    );
}

/// An SSE event whose JSON payload is split across MULTIPLE `data:` lines is joined per the SSE
/// grammar before it is read. Keeping only the last line would hand a truncated, invalid document to
/// the reader and abort the stream.
#[test]
fn a_payload_split_across_two_data_lines_is_joined() {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("bedrock"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("bedrock.invalid", LANE);
    let mut st = session();

    // One valid document, its bytes split across two `data:` lines. Joined with a newline (legal
    // JSON whitespace between tokens) it parses; the last line alone does not.
    let split =
        b"event: contentBlockDelta\ndata: {\"type\":\"contentBlockDelta\",\ndata: \"contentBlockIndex\":0,\"delta\":{\"text\":\"Hi\"}}\n\n"
            .to_vec();
    let frames = vec![harness::frame(&split)];
    let mut answers = FrameCursor::new(&frames);
    let progress = plane
        .decode_response(&mut answers, &dest, Some(&mut st), &ctx)
        .expect("the joined payload is valid and must decode, not abort as Malformed");
    assert!(
        matches!(progress, Progress::Frame { .. } | Progress::Terminal { .. }),
        "the two data lines join into one valid document: {progress:?}"
    );
}

/// A terminal `message_stop` that carries no stop reason settles the answer as COMPLETE, not
/// PARTIAL. The `message_delta` that states the reason and the `message_stop` that ends the stream
/// can arrive as SEPARATE transport frames, so the frame that ends the stream may carry no reason of
/// its own — a naturally completed answer must not be recorded as cut short.
#[test]
fn a_terminal_stop_without_a_reason_settles_complete() {
    const ANTHROPIC: &[Upstream] = &[Upstream {
        lane: LaneId::new("lane-anthropic"),
        host: "anthropic.invalid",
        dialect: "anthropic",
        model: "claude",
    }];
    const A_LANE: LaneId = LaneId::new("lane-anthropic");
    let plane = LlmPlane::new(ANTHROPIC);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("anthropic"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("anthropic.invalid", A_LANE);
    let mut st = session();

    let stop = event("message_stop", r#"{"type":"message_stop"}"#);
    let frames = vec![harness::frame(&stop)];
    let mut answers = FrameCursor::new(&frames);
    let progress = plane
        .decode_response(&mut answers, &dest, Some(&mut st), &ctx)
        .expect("the stop frame is read");
    let Progress::Terminal { r, .. } = progress else {
        panic!("message_stop ends the answer: {progress:?}");
    };
    assert_eq!(
        r.finish,
        FinishClass::Complete,
        "a terminal stop with no reason is a completed answer, not a partial one"
    );
}
