// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MEASUREMENT-ONLY. The shared half of the plugin-ABI marshalling instrument: the IR wire schema
//! ([`wire`]), the payload corpus, the one unit of "work" every arm performs, and the opcode byte
//! that selects an arm inside the bench plugin.
//!
//! Nothing here ships. It exists so `abi-bench` (the host harness) and `abi-bench-plugin` (the
//! cdylib on the far side of `dlopen`) agree on a schema without either depending on the other's
//! internals.

pub mod wire;

use wire::*;

/// The request-buffer HEADER length. Byte 0 is the opcode; bytes 1..16 are padding.
///
/// SIXTEEN, not one, and this is a finding rather than a detail: an rkyv/FlatBuffers/Cap'n Proto
/// archive can only be read IN PLACE if it is correctly aligned (16 bytes for rkyv's default). A
/// one-byte opcode prefix would put every archive at an odd address and force the plugin to copy the
/// whole payload into aligned storage before reading it — which is exactly the copy zero-copy exists
/// to remove. The current `ptr + len` transport says NOTHING about alignment, so any zero-copy
/// payload schema has to add an alignment guarantee to the contract.
pub const HDR: usize = 16;

/// Byte 0 of every `busbar_call` request buffer selects the arm; the payload starts at [`HDR`]. A
/// raw opcode byte (rather than a serialized envelope enum, which is what the real ABI uses) keeps
/// the arm SELECTION out of the number: an envelope parse is itself one of the costs under test, so
/// it must not be charged to every arm equally.
pub mod op {
    /// Ignore the payload, return a zero-length buffer. The pure transport floor.
    pub const NOOP: u8 = 0;
    /// Payload is a `u32` LE count; return that many bytes. Isolates the payload-proportional part
    /// of the transport (plugin allocates, host copies out, host calls back to free).
    pub const ECHO_N: u8 = 1;
    /// JSON in, work, JSON out. Today's ABI.
    pub const JSON: u8 = 2;
    /// Postcard (compact binary, still a parse) in, work, postcard out.
    pub const POSTCARD: u8 = 3;
    /// rkyv archive in, VALIDATED access in place, work, freshly-built archive out.
    pub const RKYV_CHECKED: u8 = 4;
    /// rkyv archive in, UNVALIDATED access in place, work, freshly-built archive out.
    pub const RKYV_UNCHECKED: u8 = 5;
    /// rkyv archive in, unvalidated access in place, work, return a PRE-BUILT archive the plugin
    /// serialized once at open. This is the "the serialize step disappeared" arm — the floor a
    /// zero-copy design reaches ONLY if the producer emits the archive as its native output instead
    /// of building Rust structs and then encoding them.
    pub const RKYV_PREBUILT: u8 = 6;
    /// JSON in, work, JSON out — but on the tiny streaming-frame schema.
    pub const JSON_FRAME: u8 = 7;
    /// rkyv in/out on the tiny streaming-frame schema, unvalidated access, fresh archive out.
    pub const RKYV_FRAME: u8 = 8;
    /// rkyv in on the streaming-frame schema, unvalidated access, PRE-BUILT archive out.
    pub const RKYV_FRAME_PREBUILT: u8 = 9;
    /// Raw wire bytes in (the caller's HTTP body, unparsed), work = a `serde_json::Value` parse plus
    /// a field walk, rkyv archive out. The "hand the codec raw bytes" design: the plugin was going
    /// to parse anyway, so the marginal cost over compiled-in is the IR encode alone.
    pub const RAW_BYTES_TO_RKYV: u8 = 10;
}

// ── THE WORK ────────────────────────────────────────────────────────────────────────────────────
// Every arm runs the SAME semantic work so the arms differ only in how the payload got there. The
// work touches EVERY text-bearing field, which is the honest shape for a codec (a dialect writer
// reads essentially the whole IR); a work function that touched one field would flatter zero-copy,
// whose whole claim is that untouched fields are free.

/// Sum every text byte reachable from an owned request, and count the blocks.
pub fn work_owned(req: &WireRequest) -> u64 {
    let mut acc = 0u64;
    for b in &req.system {
        acc = acc.wrapping_add(block_owned(b));
    }
    for m in &req.messages {
        acc = acc.wrapping_add(m.content.iter().map(block_owned).sum::<u64>());
    }
    for t in &req.tools {
        acc = acc
            .wrapping_add(t.name.len() as u64)
            .wrapping_add(t.input_schema_json.len() as u64)
            .wrapping_add(t.description.as_ref().map_or(0, |d| d.len() as u64));
    }
    acc.wrapping_add(req.extra_json.len() as u64)
        .wrapping_add(req.max_tokens.unwrap_or(0) as u64)
        .wrapping_add(req.stream as u64)
}

fn block_owned(b: &WireBlock) -> u64 {
    match b {
        WireBlock::Text { text, citations, .. } => {
            text.len() as u64 + citations.len() as u64
        }
        WireBlock::Thinking { text, signature, .. } => {
            text.len() as u64 + signature.as_ref().map_or(0, |s| s.len() as u64)
        }
        WireBlock::ToolUse {
            id,
            name,
            input_json,
            ..
        } => (id.len() + name.len() + input_json.len()) as u64,
        WireBlock::ToolResult {
            tool_use_id,
            content,
            ..
        } => tool_use_id.len() as u64 + content.iter().map(block_owned).sum::<u64>(),
        WireBlock::Image { source, .. } => src_owned(source),
        WireBlock::Media { source, name, .. } => {
            src_owned(source) + name.as_ref().map_or(0, |n| n.len() as u64)
        }
        WireBlock::Json(s) => s.len() as u64,
    }
}

fn src_owned(s: &WireImageSource) -> u64 {
    match s {
        WireImageSource::Base64 { media_type, data } => (media_type.len() + data.len()) as u64,
        WireImageSource::Url(u) => u.len() as u64,
        WireImageSource::Vendor { vendor, value_json } => (vendor.len() + value_json.len()) as u64,
    }
}

/// The same work, read straight out of an rkyv archive with no deserialize step.
pub fn work_archived(req: &ArchivedWireRequest) -> u64 {
    let mut acc = 0u64;
    for b in req.system.iter() {
        acc = acc.wrapping_add(block_archived(b));
    }
    for m in req.messages.iter() {
        acc = acc.wrapping_add(m.content.iter().map(block_archived).sum::<u64>());
    }
    for t in req.tools.iter() {
        acc = acc
            .wrapping_add(t.name.len() as u64)
            .wrapping_add(t.input_schema_json.len() as u64)
            .wrapping_add(t.description.as_ref().map_or(0, |d| d.len() as u64));
    }
    acc.wrapping_add(req.extra_json.len() as u64)
        .wrapping_add(req.max_tokens.as_ref().map_or(0, |v| v.to_native() as u64))
        .wrapping_add(req.stream as u64)
}

fn block_archived(b: &ArchivedWireBlock) -> u64 {
    match b {
        ArchivedWireBlock::Text { text, citations, .. } => {
            text.len() as u64 + citations.len() as u64
        }
        ArchivedWireBlock::Thinking { text, signature, .. } => {
            text.len() as u64 + signature.as_ref().map_or(0, |s| s.len() as u64)
        }
        ArchivedWireBlock::ToolUse {
            id,
            name,
            input_json,
            ..
        } => (id.len() + name.len() + input_json.len()) as u64,
        ArchivedWireBlock::ToolResult {
            tool_use_id,
            content,
            ..
        } => tool_use_id.len() as u64 + content.iter().map(block_archived).sum::<u64>(),
        ArchivedWireBlock::Image { source, .. } => src_archived(source),
        ArchivedWireBlock::Media { source, name, .. } => {
            src_archived(source) + name.as_ref().map_or(0, |n| n.len() as u64)
        }
        ArchivedWireBlock::Json(s) => s.len() as u64,
    }
}

fn src_archived(s: &ArchivedWireImageSource) -> u64 {
    match s {
        ArchivedWireImageSource::Base64 { media_type, data } => {
            (media_type.len() + data.len()) as u64
        }
        ArchivedWireImageSource::Url(u) => u.len() as u64,
        ArchivedWireImageSource::Vendor { vendor, value_json } => {
            (vendor.len() + value_json.len()) as u64
        }
    }
}

/// The streaming-frame work: touch the delta text and the index.
pub fn frame_work_owned(ev: &WireStreamEvent) -> u64 {
    match ev {
        WireStreamEvent::BlockDelta { index, delta } => {
            *index as u64
                + match delta {
                    WireDelta::TextDelta(s)
                    | WireDelta::ThinkingDelta(s)
                    | WireDelta::InputJsonDelta(s)
                    | WireDelta::SignatureDelta(s)
                    | WireDelta::RedactedReasoningDelta(s) => s.len() as u64,
                }
        }
        WireStreamEvent::BlockStart { index, .. } | WireStreamEvent::BlockStop { index } => {
            *index as u64
        }
        WireStreamEvent::MessageStart { usage, .. }
        | WireStreamEvent::MessageDelta { usage, .. } => usage.output_tokens,
        WireStreamEvent::MessageStop => 0,
    }
}

/// The same, read out of an archive.
pub fn frame_work_archived(ev: &ArchivedWireStreamEvent) -> u64 {
    match ev {
        ArchivedWireStreamEvent::BlockDelta { index, delta } => {
            index.to_native() as u64
                + match delta {
                    ArchivedWireDelta::TextDelta(s)
                    | ArchivedWireDelta::ThinkingDelta(s)
                    | ArchivedWireDelta::InputJsonDelta(s)
                    | ArchivedWireDelta::SignatureDelta(s)
                    | ArchivedWireDelta::RedactedReasoningDelta(s) => s.len() as u64,
                }
        }
        ArchivedWireStreamEvent::BlockStart { index, .. }
        | ArchivedWireStreamEvent::BlockStop { index } => index.to_native() as u64,
        ArchivedWireStreamEvent::MessageStart { usage, .. }
        | ArchivedWireStreamEvent::MessageDelta { usage, .. } => usage.output_tokens.to_native(),
        ArchivedWireStreamEvent::MessageStop => 0,
    }
}

// ── THE CORPUS ──────────────────────────────────────────────────────────────────────────────────

/// A realistic system prompt fragment, repeated to reach a target size.
const LOREM: &str = "You are a careful assistant operating inside an enterprise gateway. Prefer \
precise answers, cite the tool you used, and never invent an identifier you were not given. ";

/// A realistic JSON-Schema tool definition, as a string (an IR `input_schema` is a `Value`).
const TOOL_SCHEMA: &str = r#"{"type":"object","properties":{"query":{"type":"string","description":"The search query"},"limit":{"type":"integer","minimum":1,"maximum":100},"filters":{"type":"object","properties":{"since":{"type":"string","format":"date-time"},"tags":{"type":"array","items":{"type":"string"}}}}},"required":["query"]}"#;

/// Build a chat request whose serialized size lands near `target_bytes`, shaped like a real one:
/// a system prompt, an alternating user/assistant history with a tool call and a tool result in it,
/// and three tool definitions.
pub fn build_request(target_bytes: usize) -> WireRequest {
    let mut req = WireRequest {
        max_tokens: Some(4096),
        temperature: Some(0.7),
        top_p: Some(0.95),
        stream: true,
        stop: vec!["\n\nHuman:".to_string()],
        tool_choice: Some(WireToolChoice::Auto),
        user: Some("user_01HQ8XKPZJ2M4N6R8T0V".to_string()),
        parallel_tool_calls: Some(true),
        extra_json: "{}".to_string(),
        ..Default::default()
    };

    for i in 0..3 {
        req.tools.push(WireTool {
            name: format!("search_corpus_{i}"),
            description: Some("Search the enterprise corpus for matching documents.".to_string()),
            input_schema_json: TOOL_SCHEMA.to_string(),
            cache_control: None,
            hosted_json: None,
            strict: Some(true),
        });
    }

    req.system.push(WireBlock::Text {
        text: LOREM.repeat(3),
        cache_control: Some(WireCacheControl { ephemeral: true }),
        citations: Vec::new(),
    });

    // A tool call + tool result turn, so the history is not just prose.
    req.messages.push(WireMessage {
        role: WireRole::User,
        content: vec![WireBlock::Text {
            text: "Find every incident report that mentions the ingress breaker.".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
    });
    req.messages.push(WireMessage {
        role: WireRole::Assistant,
        content: vec![WireBlock::ToolUse {
            id: "toolu_01A09q90qw90lq917835lq9".to_string(),
            name: "search_corpus_0".to_string(),
            input_json: r#"{"query":"ingress breaker","limit":25}"#.to_string(),
            cache_control: None,
            thought_signature: None,
        }],
    });
    req.messages.push(WireMessage {
        role: WireRole::Tool,
        content: vec![WireBlock::ToolResult {
            tool_use_id: "toolu_01A09q90qw90lq917835lq9".to_string(),
            content: vec![WireBlock::Text {
                text: LOREM.to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            is_error: false,
            cache_control: None,
        }],
    });

    // Grow the history until the JSON encoding lands at/above the target.
    let mut turn = 0usize;
    while serde_json::to_vec(&req).unwrap().len() < target_bytes {
        let remaining = target_bytes.saturating_sub(serde_json::to_vec(&req).unwrap().len());
        // Chunk the growth so the loop terminates in a handful of iterations even at 500 KB.
        let chunk = remaining.clamp(200, 64 * 1024);
        req.messages.push(WireMessage {
            role: if turn % 2 == 0 {
                WireRole::User
            } else {
                WireRole::Assistant
            },
            content: vec![WireBlock::Text {
                text: LOREM.repeat(chunk / LOREM.len() + 1),
                cache_control: None,
                citations: Vec::new(),
            }],
        });
        turn += 1;
    }
    req
}

/// The SAME byte budget as [`build_request`], but spread across `n_blocks` message blocks instead of
/// a few long ones.
///
/// This exists to DISENTANGLE two variables that [`build_request`]'s sweep confounds. Growing a
/// request by lengthening its strings and growing it by adding more fields both grow "payload
/// bytes", but a JSON parser's cost tracks the number of VALUES it must tokenize, allocate and
/// dispatch on far more than the number of bytes it must scan — long string bodies are memcpy, and
/// memcpy is nearly free next to a `Value` allocation. If the two sweeps have different slopes, then
/// "cost is proportional to payload bytes" is the wrong model and the right one is "cost is
/// proportional to structural density", which changes what the redesign should optimize.
pub fn build_request_dense(target_bytes: usize, n_blocks: usize) -> WireRequest {
    let mut req = WireRequest {
        max_tokens: Some(4096),
        stream: true,
        extra_json: "{}".to_string(),
        ..Default::default()
    };
    let per = target_bytes / n_blocks.max(1);
    for i in 0..n_blocks {
        req.messages.push(WireMessage {
            role: if i % 2 == 0 {
                WireRole::User
            } else {
                WireRole::Assistant
            },
            content: vec![WireBlock::Text {
                text: LOREM.repeat((per / LOREM.len()).max(1)),
                cache_control: None,
                citations: Vec::new(),
            }],
        });
    }
    req
}

/// Count every JSON value (scalar, array, object and each member) in an encoding of `req`. The
/// structural-density metric the density experiment reports its slope against.
pub fn value_count(req: &WireRequest) -> u64 {
    fn walk(v: &serde_json::Value) -> u64 {
        1 + match v {
            serde_json::Value::Array(a) => a.iter().map(walk).sum::<u64>(),
            serde_json::Value::Object(o) => o.values().map(walk).sum::<u64>(),
            _ => 0,
        }
    }
    walk(&serde_json::to_value(req).unwrap())
}

/// The decisive payload: one SSE text delta, the size a real one is.
pub fn build_frame() -> WireStreamEvent {
    WireStreamEvent::BlockDelta {
        index: 0,
        delta: WireDelta::TextDelta(" the ingress breaker trips".to_string()),
    }
}
