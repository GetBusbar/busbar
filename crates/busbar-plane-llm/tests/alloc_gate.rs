//! What the same-dialect relay is allowed to allocate.
//!
//! A request whose dialect the lane already speaks, and whose model the lane already names, is
//! relayed byte-for-byte: the bytes the client sent are the bytes the upstream gets. A relay that
//! parses a second copy of that document on its way out is doing work whose only effect is to be
//! thrown away, and no wall-clock test catches it reliably on a shared runner. An allocation COUNT
//! does — it is the same number on every machine, so it can be pinned.
//!
//! The instrument is a counting wrapper around the system allocator, counting per thread so a
//! concurrently-running test never inflates the measured count. The bound is exact, not an upper
//! bound: the measured call is a pure synchronous function over bytes, with no I/O and no clock, so
//! its count does not vary run to run. If an intentional change moves it, run with `--nocapture`,
//! read the printed count, and move the constant in the same commit — a raise IS the regression
//! unless the commit says in words why the extra allocation is the cheaper of two evils.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::ids::LaneId;
use busbar_contract::plane::{Ingress, Plane};
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::{LlmPlane, Upstream};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Allocations made by THIS thread since the counter was last read.
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

/// The system allocator, counting.
struct Counting;

// SAFETY: every call is forwarded verbatim to the system allocator; the counter is a thread-local
// `Cell` of a plain integer, touched only on the allocating thread, and never reads or writes the
// memory being handed out.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// How many allocations one call made on this thread.
fn allocations_of(f: impl FnOnce()) -> u64 {
    let before = ALLOCS.with(Cell::get);
    f();
    ALLOCS.with(Cell::get) - before
}

/// The model the lane names, and the model the request already names.
const MODEL: &str = "gpt-4o";

/// One upstream, speaking the dialect its clients speak.
const UPSTREAMS: &[Upstream] = &[Upstream {
    lane: LaneId::new("lane-openai"),
    host: "openai.invalid",
    dialect: "openai",
    model: MODEL,
}];

/// A request the lane relays unchanged: its dialect and its model are both the lane's own.
const BODY: &str = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello there"}],"max_tokens":64,"stream":false}"#;

/// COMMITTED BASELINE — the exact allocation count of ONE same-dialect, same-model
/// `encode_egress`.
///
/// Five, and every one of the five belongs to the hop ENVELOPE: the three fields it carries
/// (method, request target, content type), each copied once by the test arena, the request target
/// the dialect's writer builds as a string, and the field list's own buffer, which starts empty and
/// grows as the fields go in. The BODY is not among them, and that is the whole point of the
/// number: the relayed document is neither parsed nor copied, because it is already sitting in the
/// unit's arena exactly as it arrived. Before this gate the same call allocated nineteen times — a
/// full `serde_json::Value` of the request plus two further copies of its bytes — for no difference
/// at all in what went on the wire.
///
/// A SIXTH nearly joined them and is not here: asking the dialect's writer for the request target
/// used to mean resolving a whole codec first, and a resolved codec boxes a writer that carries
/// per-stream state this arm never touches. The box was the one allocation on this arm that bought
/// nothing. The question is now asked of a writer built on the stack, so the count is what the
/// envelope costs and nothing else.
const PASSTHROUGH_ALLOCS: u64 = 5;

/// An ANSWER in the same dialect the client speaks, which the plane hands back unchanged.
const ANSWER: &str = r#"{"id":"chatcmpl-1","object":"chat.completion","created":1752000000,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"hello there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":4,"total_tokens":16}}"#;

/// COMMITTED BASELINE — the exact allocation count of ONE same-dialect `encode_response`.
///
/// ONE, and it is the copy into the unit's arena that the method's own signature promises: the
/// answer leaves in the arena because that is where an answer the loop can hold lives. The answer
/// DOCUMENT is not among them, and that is the point of the number — the upstream's own bytes are
/// already what the client reads, so nothing about them has to be read a second time to say so.
///
/// The request direction has had this gate since the same-dialect relay was made a borrow; the
/// answer direction had none, and it parsed a whole `serde_json::Value` of the upstream's answer
/// before deciding it had nothing to do with it. Answers are the larger of the two documents on
/// every request this plane serves, so it was the more expensive of the two copies.
const ANSWER_PASSTHROUGH_ALLOCS: u64 = 1;

/// COMMITTED BASELINE — the exact allocation count of ONE streamed frame written back to a client
/// that speaks the dialect the frame arrived in.
///
/// A stream is many frames, so anything a frame costs is paid once per chunk rather than once per
/// request, and a codec CONSTRUCTED per frame is the worst shape that cost can take: the writer a
/// streamed answer is written by carries the stream's own state — which blocks it has opened, which
/// identity it minted — so it has to be the same writer on every frame anyway. It is built once, at
/// the first frame of the stream, and kept in the state the kernel already hands in for the reader's
/// half; a later frame builds no codec at all.
///
/// What the number is made of, for the one-text-delta chunk this test feeds. Every remaining
/// allocation belongs to the frame's own CONTENT, and none of them to a codec:
///   * the frame's own `data:` document, parsed into a `serde_json::Value` — seventeen of them, one
///     per node and owned key of the chunk, and the largest single share of the count;
///   * the IR events the upstream's reader fans that document out to, which are owned values;
///   * the wire documents the client's writer builds from those events, and the owned strings it
///     stamps on them (the replayed stream identity, each event's name, the delta's text);
///   * one serialization per written frame;
///   * the buffer the framed bytes are assembled in, and the growths it takes; and
///   * the one copy into the unit's arena the method's signature promises.
///
/// What is NOT among them is the point of the gate: the codec. This call used to resolve a whole
/// `Protocol` per frame to get the writer — one heap allocation per chunk of every streamed answer
/// the node serves, for a value the stream has to keep anyway. The writer now lives in the stream's
/// state, so the first frame builds one and every frame after it builds nothing. The count fell by
/// exactly that one, and by one rather than two only because the reader the `Protocol` boxed
/// alongside it is a unit struct and a box of a zero-sized value allocates nothing.
///
/// A raise IS the regression unless the commit says in words why the extra allocation is the
/// cheaper of two evils.
const STREAM_FRAME_SAME_DIALECT_ALLOCS: u64 = 42;

/// COMMITTED BASELINE — the same measurement for a frame that CROSSES dialects.
///
/// The client speaks one dialect and the upstream answered in another, so the frame is read in one
/// grammar and written in the other — which is the same work in the same order as the sibling above,
/// over a smaller upstream document (eight allocations for its parse rather than seventeen) and a
/// client dialect that frames a text delta in more events. The codec construction is gone from this
/// arm for the same reason and by the same means, and the same reading of a raise applies.
const STREAM_FRAME_CROSS_DIALECT_ALLOCS: u64 = 30;

/// One openai upstream, for a stream whose client speaks the same dialect.
const STREAM_SAME_UPSTREAMS: &[Upstream] = &[Upstream {
    lane: LaneId::new("lane-openai"),
    host: "openai.invalid",
    dialect: "openai",
    model: MODEL,
}];

/// One bedrock upstream, for a stream whose client speaks anthropic.
const STREAM_CROSS_UPSTREAMS: &[Upstream] = &[Upstream {
    lane: LaneId::new("lane-bedrock"),
    host: "bedrock.invalid",
    dialect: "bedrock",
    model: "claude",
}];

/// One streamed frame, in the transport's own event framing.
fn event(name: &str, data: &str) -> Vec<u8> {
    if name.is_empty() {
        format!("data: {data}\n\n").into_bytes()
    } else {
        format!("event: {name}\ndata: {data}\n\n").into_bytes()
    }
}

/// A streamed answer's frames does not build a codec per frame.
///
/// Both directions of one frame are driven — the upstream's frame is read against the kernel's
/// reader state, and the client's bytes are written against the kernel's writer state — and the
/// WRITE is what is measured, because that is the half that used to resolve a whole `Protocol`.
/// Several frames are fed before the window opens, so what is measured is a frame of a stream
/// already running, which is what all but one frame of a stream is.
fn stream_frame_allocations(
    upstreams: &'static [Upstream],
    client_dialect: &str,
    lane: LaneId,
    host: &'static str,
    frames: &[Vec<u8>],
    warm: usize,
) -> u64 {
    use busbar_contract::plane::{PlaneSessionState, Progress};
    use busbar_plane_llm::codec::LlmSessionState;

    let plane = LlmPlane::new(upstreams);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for(client_dialect), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination(host, lane);
    // Two halves, as the kernel opens two: the connection the frames arrive on and the connection
    // they are written to.
    let mut upstream = PlaneSessionState::new(LlmSessionState::default());
    let mut client = PlaneSessionState::new(LlmSessionState::default());

    let mut count = 0;
    for (n, bytes) in frames.iter().enumerate() {
        let wire = vec![harness::frame(bytes)];
        let mut answers = FrameCursor::new(&wire);
        let progress = plane
            .decode_response(&mut answers, &dest, Some(&mut upstream), &ctx)
            .expect("the frame is this dialect's shape");
        let (Progress::Frame { r, .. } | Progress::Terminal { r, .. }) = progress else {
            panic!("a streamed frame carries a response: {progress:?}");
        };
        let measured = allocations_of(|| {
            let _ = plane
                .encode_response(&r, Some(&mut client), &ctx)
                .expect("the client speaks a dialect this frame can be written in");
        });
        if n >= warm {
            count = measured;
        }
    }
    count
}

#[test]
fn a_streamed_frame_builds_no_codec_when_the_client_speaks_the_answer_s_dialect() {
    let chunk = |text: &str| {
        event(
            "",
            &format!(
                r#"{{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1752000000,"model":"gpt-4o","choices":[{{"index":0,"delta":{{"content":"{text}"}},"finish_reason":null}}]}}"#
            ),
        )
    };
    let frames = vec![chunk("He"), chunk("ll"), chunk("o"), chunk("!")];
    let count = stream_frame_allocations(
        STREAM_SAME_UPSTREAMS,
        "openai",
        LaneId::new("lane-openai"),
        "openai.invalid",
        &frames,
        3,
    );
    println!("same-dialect streamed frame allocations: {count}");
    assert_eq!(
        count, STREAM_FRAME_SAME_DIALECT_ALLOCS,
        "one streamed frame allocated {count} times, not \
         {STREAM_FRAME_SAME_DIALECT_ALLOCS}: a stream is many frames, and a codec built per frame \
         is a malloc per chunk for a value the stream already holds"
    );
}

#[test]
fn a_streamed_frame_builds_no_codec_when_the_client_speaks_another_dialect() {
    let delta = |text: &str| {
        event(
            "contentBlockDelta",
            &format!(
                r#"{{"type":"contentBlockDelta","contentBlockIndex":0,"delta":{{"text":"{text}"}}}}"#
            ),
        )
    };
    let frames = vec![
        event(
            "messageStart",
            r#"{"type":"messageStart","role":"assistant"}"#,
        ),
        delta("He"),
        delta("ll"),
        delta("o"),
        delta("!"),
    ];
    let count = stream_frame_allocations(
        STREAM_CROSS_UPSTREAMS,
        "anthropic",
        LaneId::new("lane-bedrock"),
        "bedrock.invalid",
        &frames,
        4,
    );
    println!("cross-dialect streamed frame allocations: {count}");
    assert_eq!(
        count, STREAM_FRAME_CROSS_DIALECT_ALLOCS,
        "one streamed frame allocated {count} times, not \
         {STREAM_FRAME_CROSS_DIALECT_ALLOCS}: the crossing reads one grammar and writes another, \
         and neither of those is a reason to build a codec per frame"
    );
}

#[test]
fn same_dialect_relay_does_not_reparse_the_request() {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("openai"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);

    let frames = vec![harness::frame(BODY.as_bytes())];
    let mut cursor = FrameCursor::new(&frames);
    let draft = match plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("the body is this dialect's shape")
    {
        Ingress::OneShot(draft) => draft,
        other => panic!("a whole request body decodes as one complete unit, got {other:?}"),
    };
    let unit = harness::unit(draft.op, draft.body_ir, draft.facts);
    let dest = harness::destination("openai.invalid", LaneId::new("lane-openai"));

    // One warm call outside the window, so nothing a first call sets up for the process is charged
    // to the measured one.
    let warm = plane
        .encode_egress(&unit, &dest, None, &ctx)
        .expect("the lane speaks this dialect");
    assert_eq!(
        warm.body.as_slice(),
        BODY.as_bytes(),
        "a same-dialect, same-model relay sends the bytes the client sent"
    );

    let mut measured = None;
    let count = allocations_of(|| {
        measured = Some(
            plane
                .encode_egress(&unit, &dest, None, &ctx)
                .expect("the lane speaks this dialect"),
        );
    });
    println!("same-dialect relay allocations: {count}");
    assert_eq!(
        measured.expect("the call ran").body.as_slice(),
        BODY.as_bytes(),
        "a same-dialect, same-model relay sends the bytes the client sent"
    );
    assert_eq!(
        count, PASSTHROUGH_ALLOCS,
        "the same-dialect relay allocated {count} times, not {PASSTHROUGH_ALLOCS}: it is doing \
         work on a document it is about to send back unchanged"
    );
}

/// The same-dialect ANSWER relay does not read the answer it is handing straight back.
///
/// The upstream speaks the dialect the client speaks, so the bytes the upstream sent are the bytes
/// the client reads, and the method says so in one line. What it must not do first is build a
/// document out of them: that document is discarded on the very next line, and building it costs a
/// full parse of the largest body on the request.
#[test]
fn same_dialect_answer_relay_does_not_reparse_the_answer() {
    use busbar_contract::plane::Progress;

    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("openai"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination("openai.invalid", LaneId::new("lane-openai"));

    let frames = vec![harness::frame(ANSWER.as_bytes())];
    let mut cursor = FrameCursor::new(&frames);
    let response = match plane
        .decode_response(&mut cursor, &dest, None, &ctx)
        .expect("the answer is this dialect's shape")
    {
        Progress::Terminal { r, .. } => r,
        other => panic!("a whole answer body is terminal, got {other:?}"),
    };

    // One warm call outside the window, for the same reason the request gate warms one.
    let warm = plane
        .encode_response(&response, None, &ctx)
        .expect("the client speaks the dialect the answer arrived in");
    assert_eq!(
        warm.as_slice(),
        ANSWER.as_bytes(),
        "a same-dialect answer relay gives the client the bytes the upstream sent"
    );

    let mut measured = None;
    let count = allocations_of(|| {
        measured = Some(
            plane
                .encode_response(&response, None, &ctx)
                .expect("the client speaks the dialect the answer arrived in"),
        );
    });
    println!("same-dialect answer relay allocations: {count}");
    assert_eq!(
        measured.expect("the call ran").as_slice(),
        ANSWER.as_bytes(),
        "a same-dialect answer relay gives the client the bytes the upstream sent"
    );
    assert_eq!(
        count, ANSWER_PASSTHROUGH_ALLOCS,
        "the same-dialect answer relay allocated {count} times, not \
         {ANSWER_PASSTHROUGH_ALLOCS}: it is reading a document it is about to send back unchanged"
    );
}
