//! A streamed answer is read against the state the frame before it left behind.
//!
//! The plane holds nothing between calls; the connection's own codec state is the kernel's, handed
//! in on each frame and taken back. The property that matters is that what the reader ADVANCED on
//! one frame is what the next frame is read against — because the readers of the dialects whose
//! events must balance gate the stream's opening event on "have I started", and a reader handed a
//! fresh state on every chunk starts the stream again on every chunk.
//!
//! The two halves are separate values, as the kernel keeps them: the half the answer is decoded
//! against and the half the answer is written to the client against. Each is threaded through its
//! own call, frame after frame.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::ids::LaneId;
use busbar_contract::plane::{Plane, PlaneSessionState, Progress};
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::codec::LlmSessionState;
use busbar_plane_llm::{LlmPlane, Upstream};

/// One upstream, speaking a dialect whose streaming reader gates the opening event on its state.
const UPSTREAMS: &[Upstream] = &[Upstream {
    lane: LaneId::new("lane-gemini"),
    host: "gemini.invalid",
    dialect: "gemini",
    model: "gemini-2.0-flash",
}];

/// Two chunks of one streamed answer, in the upstream's dialect.
const CHUNKS: [&str; 2] = [
    "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hello\"}]}}]}\n\n",
    "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\" there\"}]}}]}\n\n",
];

/// The stream's opening event, as the client's dialect names it on the wire.
const OPENING_EVENT: &str = "message_start";

/// The second chunk of a stream does not open the stream a second time.
///
/// A client of a dialect whose events balance reads one opening event per answer. Two of them is
/// not a cosmetic difference: the blocks the first opening event announced are never the blocks the
/// second one's closes refer to, so the answer the client assembles is an answer neither the
/// upstream nor this node ever produced.
#[test]
fn the_second_frame_of_a_stream_is_read_against_the_first_frames_state() {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    // The client speaks the dialect whose streaming envelope has an explicit opening event.
    let transport = harness::HttpStack::new(harness::path_for("anthropic"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("gemini.invalid", LaneId::new("lane-gemini"));

    // The two halves the kernel keeps: one per direction of the one connection.
    let mut upstream_half = PlaneSessionState::new(LlmSessionState::default());
    let mut client_half = PlaneSessionState::new(LlmSessionState::default());

    let mut written: Vec<String> = Vec::new();
    for chunk in CHUNKS {
        let frames = vec![harness::frame(chunk.as_bytes())];
        let mut cursor = FrameCursor::new(&frames);
        let response = match plane
            .decode_response(&mut cursor, &dest, Some(&mut upstream_half), &ctx)
            .expect("the chunk is this dialect's shape")
        {
            Progress::Frame { r, .. } | Progress::Terminal { r, .. } => r,
            other => panic!("a streamed chunk carries a response, got {other:?}"),
        };
        let bytes = plane
            .encode_response(&response, Some(&mut client_half), &ctx)
            .expect("the chunk is expressible to the client");
        written.push(String::from_utf8_lossy(bytes.as_slice()).into_owned());
    }

    assert!(
        written[0].contains(OPENING_EVENT),
        "the first chunk of a stream must open it: {:?}",
        written[0]
    );
    assert!(
        !written[1].contains(OPENING_EVENT),
        "the second chunk opened the stream again, so the frame before it left nothing behind: {:?}",
        written[1]
    );
}

/// What the reader advanced is still there when the call returns.
///
/// The assertion above is about what a client reads; this one is about the seam itself, so a change
/// that made the bytes right by some other route would still have to keep the state.
#[test]
fn the_reader_leaves_its_state_in_the_half_it_was_handed() {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("anthropic"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("gemini.invalid", LaneId::new("lane-gemini"));

    let mut half = PlaneSessionState::new(LlmSessionState::default());
    let frames = vec![harness::frame(CHUNKS[0].as_bytes())];
    let mut cursor = FrameCursor::new(&frames);
    let _ = plane
        .decode_response(&mut cursor, &dest, Some(&mut half), &ctx)
        .expect("the chunk is this dialect's shape");

    assert!(
        half.get::<LlmSessionState>()
            .expect("the half still holds this plane's own state")
            .decode
            .started,
        "the reader started the stream and the half was handed back as if it had not"
    );
}

/// A half the kernel is not holding is still a frame this plane can read.
///
/// The one-shot transports hand no state at all, and a plane that required one would refuse an
/// answer it can read perfectly well.
#[test]
fn a_frame_with_no_half_still_reads() {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("anthropic"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("gemini.invalid", LaneId::new("lane-gemini"));

    let frames = vec![harness::frame(CHUNKS[0].as_bytes())];
    let mut cursor = FrameCursor::new(&frames);
    assert!(plane
        .decode_response(&mut cursor, &dest, None, &ctx)
        .is_ok());
}
