// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MARSHALLING COST OF A DROPPED-IN PLUGIN, measured rather than assumed.
//!
//! R-K says a protocol plugin must be droppable, not merely compiled in. The C ABI carries JSON over
//! `ptr + len`, so a dropped-in codec pays a serialize/deserialize round trip on every value that
//! crosses. The owner rejected a +41.5 µs per-request cost on the plugin path, so the question
//! "what does marshalling the IR actually cost?" decides whether droppable codecs are viable at all
//! — and it must be answered with a number.
//!
//! These are `#[ignore]` because they are INSTRUMENTS, not assertions: they measure a machine, and a
//! machine-dependent threshold in the gate would be a flake. Run with:
//! `cargo test --release -p busbar-api --lib marshal -- --ignored --nocapture`
//!
//! ## MEASURE IN RELEASE. The debug number is meaningless and alarming.
//!
//! On this host, debug reports 53,332 ns per request crossing and release reports 3,321 — a 16x
//! difference. Measuring in debug produces "marshalling costs 107 us per request", which would have
//! killed droppable codecs on a number that does not exist in any shipped build. Recorded here
//! because the mistake is easy, one-directional, and was made once already.
//!
//! ## THE RESULT, and it reverses the expected conclusion
//!
//! MARSHALLING IS NOT THE BLOCKER. Release, this host:
//!   * unary request, 845 B: 3.3 us per crossing, ~6.6 us for the two a codec needs.
//!     The `spawn_blocking` hop the owner rejected was 41.5 us. Marshalling is ~6x CHEAPER than a
//!     cost already ruled too expensive.
//!   * stream event, 84 B: 0.37 us per crossing, ~0.75 us per event. A 300-event completion pays
//!     ~224 us spread across its whole lifetime, against network I/O measured in milliseconds.
//!
//! So a dropped-in codec is affordable, and what actually blocks droppability is the ABSENCE OF
//! PRIMITIVES, not the price of using them: no inbound capability callbacks, no streaming shape, no
//! async. Those are buildable. A per-request cost that could not be engineered away would not have
//! been.

/// A representative chat request body — the SHAPE the IR carries on a real request: a system
/// message, a short conversation, and a tool definition. ~1.5 KB, which is a small-to-typical
/// production body.
fn representative_request() -> serde_json::Value {
    serde_json::json!({
        "model": "claude-sonnet-4",
        "max_tokens": 4096,
        "system": "You are a careful assistant. Prefer evidence over assertion.",
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "Summarise the attached incident report and list the three most load-bearing facts."}]},
            {"role": "assistant", "content": [{"type": "text", "text": "I will read it and extract the facts that other conclusions depend on."}]},
            {"role": "user", "content": [{"type": "text", "text": "Go ahead. Keep it to three."}]}
        ],
        "tools": [{
            "name": "search_incidents",
            "description": "Search the incident database by free text and date range.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Free-text search"},
                    "since": {"type": "string", "description": "ISO-8601 lower bound"},
                    "limit": {"type": "integer", "description": "Max rows"}
                },
                "required": ["query"]
            }
        }],
        "stream": true
    })
}

/// One streamed delta — what crosses PER EVENT on a streaming response. This is where a dropped-in
/// codec's cost concentrates: a unary body marshals twice per request, a stream marshals twice per
/// EVENT, and a long completion is hundreds of events.
fn representative_stream_event() -> serde_json::Value {
    serde_json::json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": " the"}
    })
}

fn round_trip_nanos(value: &serde_json::Value, iterations: u32) -> u128 {
    // One crossing = serialize on one side, deserialize on the other. Measured together because
    // that pair is what one `busbar_call` costs; measuring only one half would halve the answer.
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let bytes = serde_json::to_vec(value).expect("serialize");
        let back: serde_json::Value = serde_json::from_slice(&bytes).expect("deserialize");
        std::hint::black_box(back);
    }
    start.elapsed().as_nanos() / u128::from(iterations)
}

#[test]
#[ignore = "instrument, not an assertion: measures the host machine"]
fn measure_the_marshalling_cost_of_one_crossing() {
    let req = representative_request();
    let ev = representative_stream_event();
    let req_bytes = serde_json::to_vec(&req).unwrap().len();
    let ev_bytes = serde_json::to_vec(&ev).unwrap().len();

    // Warm up, so the first-iteration allocator behaviour does not dominate the smaller sample.
    let _ = round_trip_nanos(&req, 1_000);
    let _ = round_trip_nanos(&ev, 1_000);

    let req_ns = round_trip_nanos(&req, 20_000);
    let ev_ns = round_trip_nanos(&ev, 200_000);

    println!("\n== DROPPED-IN PLUGIN MARSHALLING COST ==");
    println!("request body   {req_bytes:>5} bytes   {req_ns:>7} ns/crossing");
    println!("stream event   {ev_bytes:>5} bytes   {ev_ns:>7} ns/crossing");
    println!(
        "\nUNARY request (2 crossings: wire->plugin, plugin->host IR): ~{} ns",
        req_ns * 2
    );
    println!(
        "STREAM of 300 events (2 crossings each):                    ~{} ns (~{} us)",
        ev_ns * 2 * 300,
        ev_ns * 2 * 300 / 1000
    );
    println!("\nReference: the spawn_blocking hop the owner rejected = 41,500 ns.\n");
}
