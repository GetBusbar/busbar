// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/transport.rs` — the third axis.
//!
//! These are axis tests, not cell tests: what is being asserted is that the axis is a bounded label
//! and that framing a codec is genuinely inert, because the whole claim of this step is that the
//! seam costs nothing before anything depends on it.

use super::*;
use crate::handlers::request_handler;

#[test]
fn names_are_stable_and_distinct() {
    let all = [Transport::Http];
    let names: Vec<_> = all.iter().map(|t| t.name()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "transport names must be unique");
    assert_eq!(Transport::Http.name(), "http");
}

/// FRAMING IS IDENTITY ON `Http`, AND THE CODEC IS UNTOUCHED. The framed cell hands back the very
/// codec it was given — same operation, same vtable — so nothing a codec does can depend on having
/// been framed. That is what makes "the codec never learns the transport" a fact rather than a
/// convention.
#[test]
fn framing_carries_the_codec_through_unchanged() {
    let rh = request_handler("openai").expect("openai is registered");
    let codec = rh
        .operation_handler(Operation::Chat)
        .expect("openai serves chat");
    let framed = Transport::Http.frame(Operation::Chat, codec);

    assert_eq!(framed.operation, Operation::Chat);
    assert_eq!(framed.transport(), Transport::Http);
    assert_eq!(framed.name(), Operation::Chat.name());
    assert_eq!(framed.transport().name(), "http");
    // The codec is the SAME object, not a wrapper around it.
    assert!(std::ptr::eq(
        std::ptr::from_ref::<dyn crate::handlers::OperationHandler>(framed.op_handler).cast::<u8>(),
        std::ptr::from_ref::<dyn crate::handlers::OperationHandler>(codec).cast::<u8>(),
    ));
    // And every capability the engine reads off the cell still answers exactly as the bare codec
    // does: framing added no behaviour.
    assert_eq!(framed.streaming(), codec.streaming());
    assert_eq!(framed.taps_nonstream_usage(), codec.taps_usage());
}

/// EVERY PROTOCOL IN THE MATRIX FRAMES ON THE ONE VARIANT. Six LLM dialects plus MCP, each framed
/// through its own registered codec — the acceptance condition for landing the axis with one
/// variant. When a second variant arms, this test is where its row goes.
#[test]
fn all_seven_protocols_frame_over_http() {
    let cells = [
        ("openai", Operation::Chat),
        ("anthropic", Operation::Chat),
        ("gemini", Operation::Chat),
        ("bedrock", Operation::Chat),
        ("cohere", Operation::Chat),
        ("responses", Operation::Chat),
        ("mcp", Operation::ToolCall),
    ];
    for (protocol, operation) in cells {
        let rh = request_handler(protocol).unwrap_or_else(|| panic!("{protocol} is registered"));
        let codec = rh
            .operation_handler(operation)
            .unwrap_or_else(|| panic!("{protocol} serves {}", operation.name()));
        let framed = Transport::Http.frame(operation, codec);
        assert_eq!(framed.transport(), Transport::Http, "{protocol}");
        assert_eq!(framed.operation, operation, "{protocol}");
    }
}
