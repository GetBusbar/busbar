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
