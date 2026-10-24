// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE USAGE-TAP FAULT PIN (#83a SD-3, architect ruling R-USAGE; row 155): every way a same-protocol
//! usage tap can fail to read a 2xx body is RETURNED as its fault, under the reason that says which
//! way, whether the tap is the chat cell's own (unknown protocol / bad JSON / a body its reader
//! refuses) or a leaf cell's default (a decode failure). The door carries the fault out on its
//! answer and the kernel counts it, one increment of
//! `busbar_billing_tap_decode_fail_total{protocol,reason}`: the kernel's suite pins that step. The
//! codec names no metrics crate, reaches no host and holds no latch: this suite reads what the tap
//! returns.

use busbar_contract::codec::{OperationHandler, UsageTapFault};
use busbar_contract::operation::OpVerb;

fn cell(op: OpVerb) -> &'static dyn OperationHandler {
    crate::codec::bedrock::DECL
        .handler
        .and_then(|h| h.operation_handler(op))
        .expect("the signing dialect serves the operation")
}

/// A JSON body the signing dialect's chat reader refuses (it is not a Converse document).
const UNREADABLE: &[u8] = b"[1,2,3]";
const NOT_JSON: &[u8] = b"{not json";

#[test]
fn the_chat_cells_three_fault_paths_each_return_their_reason() {
    let chat = crate::codec::chat_handle::ChatOperation("bedrock");
    let unknown = crate::codec::chat_handle::ChatOperation("no-such-dialect");
    let faults = [
        chat.extract_usage(crate::codec::test_host::HOST, "bedrock", UNREADABLE),
        chat.extract_usage(crate::codec::test_host::HOST, "bedrock", NOT_JSON),
        unknown.extract_usage(crate::codec::test_host::HOST, "no-such-dialect", b"{}"),
    ];
    assert_eq!(
        faults,
        [
            Err(UsageTapFault::Decode),
            Err(UsageTapFault::BadJson),
            Err(UsageTapFault::UnknownProtocol),
        ]
    );
    let reasons: Vec<&str> = faults
        .iter()
        .filter_map(|f| f.as_ref().err().map(|f| f.reason()))
        .collect();
    assert_eq!(reasons, ["decode", "bad_json", "unknown_protocol"]);
}

#[test]
fn a_leaf_cells_default_tap_returns_a_refused_body_as_a_decode_fault() {
    for op in [OpVerb::EMBEDDINGS, OpVerb::IMAGE] {
        assert_eq!(
            cell(op).extract_usage(crate::codec::test_host::HOST, "bedrock", NOT_JSON),
            Err(UsageTapFault::Decode),
            "{op:?}"
        );
    }
}

/// A body the tap reads is no fault, whatever usage it states.
#[test]
fn a_readable_body_is_no_fault() {
    let chat = crate::codec::chat_handle::ChatOperation("bedrock");
    let body = br#"{"output":{"message":{"role":"assistant","content":[{"text":"hi"}]}},"stopReason":"end_turn","usage":{"inputTokens":3,"outputTokens":2,"totalTokens":5}}"#;
    assert!(chat
        .extract_usage(crate::codec::test_host::HOST, "bedrock", body)
        .is_ok());
}
