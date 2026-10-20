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
    caps: busbar_contract::ir::egress_prep::LaneCaps::NONE,
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

#[test]
fn same_dialect_relay_does_not_reparse_the_request() {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakPlaneAlloc;
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

// ── F25 REHOME: the whole forward the served door runs, bounded (coverage map v2) ─────────────────

/// The generation the served door holds: one openai far end, under a pool that names it.
fn served_generation() -> busbar_plane_llm::exchange::shaping::Shaping {
    busbar_plane_llm::exchange::shaping::Shaping::from_settings(&serde_json::json!({
        "providers": { "oai": { "protocol": "openai", "base_url": "https://openai.invalid" } },
        "models": { "gpt-4o": { "provider": "oai" } },
        "pools": { "p": { "members": ["gpt-4o"] } }
    }))
    .expect("a well-formed generation reads")
}

/// The host the gated forward is handed: no entropy and no clock (a passthrough forward mints no
/// id and stamps no time), so the gate counts the plane's allocations and nothing of a host's.
struct GateHost;

impl busbar_contract::codec::CodecHost for GateHost {
    fn fill_entropy(&self, _out: &mut [u8]) -> bool {
        false
    }

    fn wall_clock_now(&self) -> Option<u64> {
        None
    }
}

const HOST: &dyn busbar_contract::codec::CodecHost = &GateHost;

/// A canned far-end chat completion (the 1.5.5 gate's upstream answer).
const FAR_OK: &[u8] = br#"{"id":"chatcmpl-gate","object":"chat.completion","created":0,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

/// ONE served forward, as the plane's door runs it for a unit: the arrival read off the caller's
/// head and body, the far-end request the attempt writes for the member, and the far end's whole
/// answer relayed back to the caller. Answers the caller's status.
fn one_forward(shaping: &busbar_plane_llm::exchange::shaping::Shaping, body: &[u8]) -> u16 {
    use busbar_plane_llm::exchange::attempt::{build, stream_intent};
    use busbar_plane_llm::exchange::reply::{At, Reply, ReplyCtx};
    use busbar_plane_llm::exchange::{arrive::arrive, handler_of};
    let caller: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];
    let arrived = arrive("POST", "/v1/chat/completions", caller, body, shaping)
        .expect("the caller's request arrives");
    let far =
        build(HOST, &arrived, caller, shaping, "p", "gpt-4o").expect("the attempt is written");
    assert!(!far.body.is_empty(), "the far end is sent a body");
    let lane = shaping.lane("gpt-4o").expect("the member's lane");
    let ctx = ReplyCtx {
        arrived: &arrived,
        lane,
        intent: handler_of(&arrived)
            .map(|h| stream_intent(h, arrived.parsed.as_ref()))
            .unwrap_or_default(),
        passthrough: false,
        translate_cap: busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
    };
    let head: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];
    let mut reply = Reply::new(HOST, &ctx, 200, head);
    let at = At {
        now_s: 1_752_000_000,
        elapsed_ms: Some(1),
    };
    let piece = reply.feed(HOST, &ctx, FAR_OK, true, at);
    assert!(piece.done, "a whole answer ends on its last piece");
    piece.head.map_or(0, |h| h.status)
}

/// COMMITTED BOUND (1.5.5's `FORWARD_PASSTHROUGH_MAX_ALLOCS`): the most allocations ONE warmed
/// openai>openai passthrough forward may make, measured as the minimum over several iterations.
const FORWARD_PASSTHROUGH_MAX_ALLOCS: u64 = 107;

/// LEGACY `crates/busbar-llm/src/engine/tests/alloc_gate_tests.rs::alloc_gate_openai_passthrough_forward`
/// (coverage map v2 row 39). 1.5.5: one warmed, steady-state openai->openai chat forward through the
/// served path (the arrival, the far-end exchange and the relay of the answer, 200 each) allocates
/// at most 107 times, the minimum over the measured iterations.
///
/// RED: a new per-request allocation on the served forward (a builder per send, a codec boxed per
/// call, a scaling allocation) pushes the warmed minimum over 107.
#[test]
fn alloc_gate_openai_passthrough_forward() {
    let shaping = served_generation();
    let body = br#"{"model":"p","messages":[{"role":"user","content":"hi"}],"max_tokens":16}"#;
    // WARM UP: first-touch statics are per process, not per request.
    assert_eq!(one_forward(&shaping, body), 200, "passthrough must be 200");
    let mut min_allocs = u64::MAX;
    for _ in 0..4 {
        let mut status = 0;
        let count = allocations_of(|| status = one_forward(&shaping, body));
        assert_eq!(status, 200, "passthrough must be 200");
        min_allocs = min_allocs.min(count);
    }
    println!("served forward openai>openai steady-state min allocations = {min_allocs}");
    assert!(
        min_allocs <= FORWARD_PASSTHROUGH_MAX_ALLOCS,
        "OPENAI>OPENAI FORWARD-PATH ALLOCATION COUNT REGRESSED: measured {min_allocs} > committed \
         bound {FORWARD_PASSTHROUGH_MAX_ALLOCS}. A new per-request allocation on the forward path \
         (or a scaling one) pushed it over."
    );
}

/// How many `messages` entries the large body carries (1.5.5's `ECHO_SCALING_MESSAGES`).
const ECHO_SCALING_MESSAGES: usize = 4_000;

/// COMMITTED BOUND (1.5.5's `ECHO_BODY_SCALING_MAX_ALLOCS`): how many more allocations a request of
/// [`ECHO_SCALING_MESSAGES`] messages may cost than the same request with one, on the buffered
/// delivery arm (the caller asked to stream, the far end answered one body).
const ECHO_BODY_SCALING_MAX_ALLOCS: u64 = 92_000;

/// An openai chat request with `n` messages, asking to STREAM.
fn openai_stream_body(n: usize) -> Vec<u8> {
    let messages: Vec<serde_json::Value> = (0..n)
        .map(|i| serde_json::json!({ "role": "user", "content": format!("message {i}") }))
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "model": "p",
        "messages": messages,
        "max_tokens": 16,
        "stream": true,
    }))
    .expect("serializes")
}

/// LEGACY `crates/busbar-llm/src/engine/tests/alloc_gate_tests.rs::alloc_gate_request_echo_body_materialized_once`
/// (coverage map v2 row 40). 1.5.5: on the buffered delivery arm (an openai caller asking to
/// stream, answered one JSON body, 200 each), a body of 4000 messages costs at most 92000
/// allocations more than the same body with one: the client-chosen node count multiplies no added
/// per-node wave (the deep clone of the parsed request it once paid).
///
/// RED: the served forward gains a whole-body materialization (a second parse, a deep clone of the
/// request) whose cost scales with the caller's message count past the 92000 delta.
#[test]
fn alloc_gate_request_echo_body_materialized_once() {
    let shaping = served_generation();
    let small_body = openai_stream_body(1);
    let large_body = openai_stream_body(ECHO_SCALING_MESSAGES);
    // WARM both shapes outside the measured window.
    assert_eq!(one_forward(&shaping, &small_body), 200);
    assert_eq!(one_forward(&shaping, &large_body), 200);
    let mut status = (0, 0);
    let small = allocations_of(|| status.0 = one_forward(&shaping, &small_body));
    let large = allocations_of(|| status.1 = one_forward(&shaping, &large_body));
    assert_eq!(status, (200, 200), "the arm under test must be 200");
    let delta = large.saturating_sub(small);
    println!(
        "buffered delivery arm: small={small} large={large} delta={delta} over \
         {ECHO_SCALING_MESSAGES} messages"
    );
    assert!(
        delta <= ECHO_BODY_SCALING_MAX_ALLOCS,
        "THE BUFFERED DELIVERY ARM GAINED A PER-NODE ALLOCATION WAVE: a body with \
         {ECHO_SCALING_MESSAGES} messages cost {delta} allocations more than a one-message body, \
         over the committed bound {ECHO_BODY_SCALING_MAX_ALLOCS}."
    );
}

/// LEGACY `crates/busbar-llm/src/engine/tests/alloc_gate_tests.rs::alloc_gate_dialect_seam_resolution_is_free_for_every_dialect`
/// (coordinator ruling 2026-10-18: no-alloc is a Law). RESOLVING A DIALECT BY NAME COSTS NOTHING,
/// for all six: the same stateless question (`requested_candidate_count`) asked through this plane's
/// own resolution (`codec::decl_of(name)` then its codec) and on the dialect's writer directly
/// allocates the same number of times. The difference is the resolution's own per-call cost, and
/// it must be none: `decl_of` reads a `'static` table and the codec is a `&'static` borrow.
///
/// RED: a resolution that builds or boxes a codec per call allocates on every request of that
/// dialect, and its count runs ahead of the writer's.
#[test]
fn resolving_every_dialect_by_name_allocates_nothing() {
    use busbar_plane_llm::codec::proto_codec::{self as p, ProtocolWriter};
    use busbar_plane_llm::codec::{
        anthropic, bedrock, cohere, decl_of, gemini, openai_chat, openai_responses,
    };

    fn resolution_costs_what_the_writer_costs(
        name: &'static str,
        writer: &dyn ProtocolWriter,
        body: &serde_json::Value,
    ) {
        let codec = decl_of(name)
            .and_then(busbar_contract::protocol::ProtocolDecl::dialect)
            .unwrap_or_else(|| panic!("{name} declares a codec"));
        // Warm both sides outside the measured windows: a first touch of a lazy static a writer
        // reads is a per-process cost, not a per-request one.
        let _ = codec.requested_candidate_count(body);
        let _ = writer.requested_candidate_count(body);
        let direct = allocations_of(|| {
            let _ = writer.requested_candidate_count(body);
        });
        let resolved = allocations_of(|| {
            let codec = decl_of(name)
                .and_then(busbar_contract::protocol::ProtocolDecl::dialect)
                .expect("declared");
            let _ = codec.requested_candidate_count(body);
        });
        assert_eq!(
            resolved, direct,
            "asking the `{name}` dialect one stateless question cost {resolved} allocation(s) \
             through its resolution but {direct} on the writer itself"
        );
    }

    let body = serde_json::json!({ "model": "m", "messages": [] });
    // Each writer is bound to a local before it is borrowed: the writers are constants with
    // interior mutability, and a borrow of the constant itself would be a fresh copy per use.
    let anthropic = anthropic::AnthropicWriter;
    let bedrock = bedrock::BedrockWriter;
    let cohere = cohere::CohereWriter;
    let gemini = gemini::GeminiWriter;
    let openai = openai_chat::OpenAiWriter;
    let responses = openai_responses::ResponsesWriter;
    resolution_costs_what_the_writer_costs(p::PROTO_ANTHROPIC, &anthropic, &body);
    resolution_costs_what_the_writer_costs(p::PROTO_BEDROCK, &bedrock, &body);
    resolution_costs_what_the_writer_costs(p::PROTO_COHERE, &cohere, &body);
    resolution_costs_what_the_writer_costs(p::PROTO_GEMINI, &gemini, &body);
    resolution_costs_what_the_writer_costs(p::PROTO_OPENAI, &openai, &body);
    resolution_costs_what_the_writer_costs(p::PROTO_RESPONSES, &responses, &body);
}
