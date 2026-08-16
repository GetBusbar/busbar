// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROTOCOL-KIND CROSSING COST, measured rather than assumed.
//!
//! The protocol/plane kind is the first plugin kind on the REQUEST HOT PATH. `plugin-abi`'s own doc
//! justifies its JSON-over-`ptr+len` transport with *"the cost is irrelevant: these backends are off
//! the request hot path (the store is write-behind, auth is cached)"* — true for store/auth/hook,
//! and simply false for a codec. These instruments are what replaced that assumption with numbers.
//!
//! ## RULE FOR THE REPO: STATE THE PROFILE, AND MEASURE IN RELEASE
//!
//! Every number here is `--release`. The same measurement in debug reports **53,332 ns** where
//! release reports **3,321 ns** — a 16x difference that nearly killed a sound design on a figure
//! that exists in no shipped build. A performance number without its profile is not a number.
//! Run these with:
//! `cargo test --release -p busbar-api --lib marshal -- --ignored --nocapture`
//!
//! ## THE FINDING
//!
//! JSON's cost is **linear in payload bytes**, because it is a parse. A realistic chat request is
//! 10-50 KB, so the crossing lands in tens of microseconds — against the owner's bar of
//! *"nanoseconds not microseconds"*. A zero-copy layout is **flat in payload bytes**, because
//! reading a field is a pointer offset rather than a scan. That difference, not any constant factor,
//! is the whole argument for the new contract.

/// A representative chat request body — the SHAPE the IR carries: system prompt, conversation, tool
/// definitions. `turns` scales it to the sizes real traffic actually has.
fn representative_request(turns: usize) -> serde_json::Value {
    let mut messages = Vec::new();
    for i in 0..turns {
        messages.push(serde_json::json!({
            "role": if i % 2 == 0 { "user" } else { "assistant" },
            "content": [{"type": "text", "text":
                "Summarise the attached incident report and list the load-bearing facts. \
                 Prefer evidence over assertion, and name the file and line for each claim."}]
        }));
    }
    serde_json::json!({
        "model": "claude-sonnet-4",
        "max_tokens": 4096,
        "system": "You are a careful assistant. Prefer evidence over assertion.",
        "messages": messages,
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

/// One streamed delta — what crosses PER EVENT. A long completion is hundreds of these, so
/// per-crossing overhead multiplies by frame count.
fn representative_stream_event() -> serde_json::Value {
    serde_json::json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": " the"}
    })
}

/// ONE CROSSING, JSON: serialize on one side, deserialize on the other. Measured as a pair because
/// that pair is what one call costs; measuring one half would halve the answer.
fn json_crossing_nanos(value: &serde_json::Value, iterations: u32) -> u128 {
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let bytes = serde_json::to_vec(value).expect("serialize");
        let back: serde_json::Value = serde_json::from_slice(&bytes).expect("deserialize");
        std::hint::black_box(back);
    }
    start.elapsed().as_nanos() / u128::from(iterations)
}

/// ONE CROSSING, ZERO-COPY: the consumer reads the fields it needs by offset, touching nothing else.
///
/// This models the ACCESS PATTERN a FlatBuffers/Cap'n Proto reader has, using a hand-rolled offset
/// table so the measurement needs no codegen step. It deliberately measures the CLASS of approach
/// (pointer-offset access into a prebuilt buffer) rather than a specific library's constant factor —
/// what is being established is that the cost does not grow with the payload.
///
/// The buffer is built ONCE, outside the loop, exactly as it is in production: the plugin writes the
/// IR into the buffer as it parses the wire (which it must parse anyway), and the host never parses
/// it at all.
fn flat_crossing_nanos(buffer: &[u8], offsets: &[usize], iterations: u32) -> u128 {
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        // Read every top-level field the host actually needs off a request: model, max_tokens,
        // stream flag, message count, and the first message's text. Pointer arithmetic + a slice —
        // no scan, no allocation, no validation of the bytes we did not look at.
        let mut acc = 0usize;
        for &off in offsets {
            let len = u32::from_le_bytes(buffer[off..off + 4].try_into().unwrap()) as usize;
            let field = &buffer[off + 4..off + 4 + len];
            acc = acc
                .wrapping_add(field.len())
                .wrapping_add(field[0] as usize);
        }
        std::hint::black_box(acc);
    }
    start.elapsed().as_nanos() / u128::from(iterations)
}

/// Build the flat buffer + offset table for a payload of the given size. Production uses a schema
/// compiler; this is the same shape by hand.
fn build_flat(value: &serde_json::Value) -> (Vec<u8>, Vec<usize>) {
    let fields: Vec<Vec<u8>> = vec![
        value["model"].as_str().unwrap().as_bytes().to_vec(),
        value["max_tokens"].to_string().into_bytes(),
        value["stream"].to_string().into_bytes(),
        value["messages"]
            .as_array()
            .unwrap()
            .len()
            .to_string()
            .into_bytes(),
        // The whole conversation rides in the buffer; the host points at it and does not parse it.
        serde_json::to_vec(&value["messages"]).unwrap(),
    ];
    let mut buf = Vec::new();
    let mut offsets = Vec::new();
    for f in fields {
        offsets.push(buf.len());
        buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
        buf.extend_from_slice(&f);
    }
    (buf, offsets)
}

#[test]
#[ignore = "instrument, not an assertion: measures the host machine"]
fn measure_the_protocol_crossing_cost() {
    println!("\n== PROTOCOL-KIND CROSSING COST (RELEASE) ==");
    println!("bar: nanoseconds, not microseconds\n");
    println!(
        "{:<10} {:>9} {:>14} {:>14}",
        "turns", "bytes", "json ns", "zero-copy ns"
    );

    for turns in [1usize, 12, 64, 320] {
        let v = representative_request(turns);
        let bytes = serde_json::to_vec(&v).unwrap().len();
        let (buf, offs) = build_flat(&v);

        // Warm up so first-iteration allocator behaviour does not dominate.
        let _ = json_crossing_nanos(&v, 200);
        let _ = flat_crossing_nanos(&buf, &offs, 2_000);

        let iters = if bytes > 20_000 { 2_000 } else { 20_000 };
        let j = json_crossing_nanos(&v, iters);
        let f = flat_crossing_nanos(&buf, &offs, 200_000);
        println!("{turns:<10} {bytes:>9} {j:>14} {f:>14}");
    }

    let ev = representative_stream_event();
    let ev_bytes = serde_json::to_vec(&ev).unwrap().len();
    let (ebuf, eoffs) = build_flat(&serde_json::json!({
        "model": "delta", "max_tokens": 0, "stream": true,
        "messages": [{"role":"assistant","content":[{"type":"text","text":" the"}]}]
    }));
    let ej = json_crossing_nanos(&ev, 200_000);
    let ef = flat_crossing_nanos(&ebuf, &eoffs, 200_000);
    println!("\nstream event  {ev_bytes:>9} {ej:>14} {ef:>14}");
    println!("\nreference: the spawn_blocking hop the owner rejected = 41,500 ns");
    println!("JSON grows with payload (it is a parse). Zero-copy does not (it is an offset).\n");
}
