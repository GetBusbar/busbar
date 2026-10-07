// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The allocation gates the retired engine crate's tests pinned, ported onto the plane's own seams.
//!
//! The instrument is the one `alloc_gate.rs` uses: a counting wrapper around the system allocator,
//! counting per thread so a concurrently running test never inflates the measured count. Each test
//! cites the legacy test it ports.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use serde_json::{json, Value};

use busbar_plane_llm::codec::proto_codec::ProtocolWriter;
use busbar_plane_llm::exchange::arrive::arrive;
use busbar_plane_llm::exchange::attempt::{build, stream_intent};
use busbar_plane_llm::exchange::reply::{At, Reply, ReplyCtx};
use busbar_plane_llm::exchange::shaping::Shaping;

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

/// Ask one dialect one stateless question twice, once through the neutral seam (its declaration's
/// codec) and once of a writer built directly, and require the two to allocate alike: the
/// difference is what resolving the dialect costs, and it must be nothing.
fn seam_costs_what_the_writer_costs<W: ProtocolWriter>(
    name: &'static str,
    mint: impl Fn() -> W,
    body: &Value,
) {
    let dialect = busbar_plane_llm::codec::decl_of(name)
        .and_then(|d| d.dialect())
        .unwrap_or_else(|| panic!("{name} declares a codec"));
    // Warm both sides outside the measured windows.
    let _ = dialect.requested_candidate_count(body);
    let _ = mint().requested_candidate_count(body);
    let direct = allocations_of(|| {
        let w = mint();
        let _ = w.requested_candidate_count(body);
    });
    let seam = allocations_of(|| {
        let _ = dialect.requested_candidate_count(body);
    });
    println!("{name}: seam allocations = {seam}, direct = {direct}");
    assert_eq!(
        seam, direct,
        "asking the {name} dialect one stateless question cost {seam} allocation(s) through the \
         neutral seam but {direct} on the writer itself: something behind the seam boxes a codec \
         per call"
    );
}

/// Resolving each of the six dialects through the neutral seam allocates no more than asking its
/// writer directly.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/alloc_gate_tests.rs::alloc_gate_dialect_seam_resolution_is_free_for_every_dialect`.
#[test]
fn resolving_a_dialect_through_the_seam_is_free_for_every_dialect() {
    use busbar_plane_llm::codec::{
        anthropic::AnthropicWriter, bedrock::BedrockWriter, cohere::CohereWriter,
        gemini::GeminiWriter, openai_chat::OpenAiWriter, openai_responses::ResponsesWriter,
    };
    let body = json!({ "model": "m", "messages": [] });
    seam_costs_what_the_writer_costs("anthropic", || AnthropicWriter, &body);
    seam_costs_what_the_writer_costs("bedrock", || BedrockWriter, &body);
    seam_costs_what_the_writer_costs("cohere", || CohereWriter, &body);
    seam_costs_what_the_writer_costs("gemini", || GeminiWriter, &body);
    seam_costs_what_the_writer_costs("openai", || OpenAiWriter, &body);
    seam_costs_what_the_writer_costs("responses", || ResponsesWriter, &body);
}

/// How many messages the scaling gate's large request carries.
const ECHO_SCALING_MESSAGES: usize = 4_000;

/// COMMITTED BOUND, carried over unchanged from the legacy gate: the most allocations by which a
/// request carrying [`ECHO_SCALING_MESSAGES`] messages may exceed the same request carrying one, on
/// the arm where the caller asked to stream and the far end answered one JSON body. A per-message
/// wave added to the exchange is work a caller-sized body multiplies; this catches one being added.
const ECHO_BODY_SCALING_MAX_ALLOCS: u64 = 92_000;

/// An openai chat request with `n` messages, asking to stream.
fn streamed_request(n: usize) -> Vec<u8> {
    let messages: Vec<Value> = (0..n)
        .map(|i| json!({ "role": "user", "content": format!("message {i}") }))
        .collect();
    serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "messages": messages,
        "max_tokens": 16,
        "stream": true,
    }))
    .expect("serializes")
}

/// The far end's one JSON answer.
const ANSWER: &[u8] = br#"{"id":"chatcmpl-gate","object":"chat.completion","created":0,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

/// One whole exchange on the buffered arm: the arrival, the attempt, and the far end's JSON answer
/// relayed to a caller that asked to stream.
fn one_exchange(shaping: &Shaping, body: &[u8]) {
    let h: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];
    let arrived = arrive("POST", "/v1/chat/completions", h, body, &()).expect("arrives");
    let far = build(&arrived, h, shaping, "p", "gpt-4o").expect("built");
    assert!(!far.body.is_empty());
    let handler = busbar_plane_llm::exchange::handler_of(&arrived).expect("a handler");
    let lane = shaping.lane("gpt-4o").expect("the lane");
    let ctx = ReplyCtx {
        arrived: &arrived,
        lane,
        intent: stream_intent(handler, arrived.parsed.as_ref()),
        passthrough: false,
    };
    let head: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];
    let mut reply = Reply::new(&ctx, 200, head);
    let piece = reply.feed(&ctx, ANSWER, true, At::default());
    assert!(piece.done, "the answer completes");
    assert_eq!(piece.head.map(|h| h.status), Some(200));
}

/// A 4000-message streamed request answered by one JSON body costs at most the committed number of
/// extra allocations over a one-message one: no whole-body wave per message is added.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/alloc_gate_tests.rs::alloc_gate_request_echo_body_materialized_once`.
#[test]
fn a_large_streamed_request_answered_whole_adds_no_per_message_wave() {
    let shaping = Shaping::from_settings(&json!({
        "providers": { "oai": { "protocol": "openai" } },
        "models": { "gpt-4o": { "provider": "oai" } },
        "pools": { "p": { "members": ["gpt-4o"] } }
    }))
    .expect("reads");
    let (one, many) = (streamed_request(1), streamed_request(ECHO_SCALING_MESSAGES));
    one_exchange(&shaping, &one);
    one_exchange(&shaping, &many);
    let small = allocations_of(|| one_exchange(&shaping, &one));
    let large = allocations_of(|| one_exchange(&shaping, &many));
    let delta = large.saturating_sub(small);
    println!(
        "buffered arm: small={small} large={large} delta={delta} over {ECHO_SCALING_MESSAGES} messages"
    );
    assert!(
        delta <= ECHO_BODY_SCALING_MAX_ALLOCS,
        "a body with {ECHO_SCALING_MESSAGES} messages cost {delta} allocations more than a \
         one-message body, over the committed bound {ECHO_BODY_SCALING_MAX_ALLOCS}"
    );
}
