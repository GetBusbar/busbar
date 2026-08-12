// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the plane's JSON-RPC error envelope.
//!
//! These assert the shape the official A2A TCK reads, in the TCK's own words: an INTEGER `code`, a
//! `message`, the caller's `id` echoed, `jsonrpc: "2.0"`, and — for the A2A-specific errors — a
//! `data` ARRAY carrying a `google.rpc.ErrorInfo` whose `domain` is `a2a-protocol.org`.

use super::*;
use serde_json::json;

#[test]
fn every_error_is_a_json_rpc_2_0_envelope_with_an_integer_code() {
    for err in [
        A2aError::TaskNotFound,
        A2aError::TaskNotCancelable,
        A2aError::UnsupportedOperation,
        A2aError::InvalidAgentResponse,
        A2aError::Parse,
        A2aError::InvalidRequest,
        A2aError::MethodNotFound,
        A2aError::InvalidParams,
        A2aError::Internal,
    ] {
        let doc = body(&json!(7), err, "because");
        assert_eq!(doc["jsonrpc"], "2.0", "{err:?}");
        assert_eq!(doc["id"], json!(7), "the caller's id must be echoed: {err:?}");
        assert!(
            doc["error"]["code"].is_i64(),
            "the code must be an INTEGER, not a name: {doc}"
        );
        assert_eq!(doc["error"]["message"], "because", "{err:?}");
        // The JSON-RPC error object admits `code`, `message` and `data` and nothing else. busbar's
        // ordinary gateway body carries `param` and `type`, which is what the TCK rejected.
        let members: Vec<&String> = doc["error"].as_object().expect("object").keys().collect();
        for m in &members {
            assert!(
                matches!(m.as_str(), "code" | "message" | "data"),
                "unexpected member `{m}` in the error object: {doc}"
            );
        }
    }
}

#[test]
fn an_a2a_specific_error_carries_error_info_in_a_data_array() {
    let doc = body(&json!("abc"), A2aError::TaskNotFound, "no such task");
    assert_eq!(doc["error"]["code"], -32001, "A2A §5.4 binds TaskNotFound");
    let data = doc["error"]["data"]
        .as_array()
        .expect("`data` must be an ARRAY, not an object");
    let info = data
        .iter()
        .find(|i| i["@type"] == "type.googleapis.com/google.rpc.ErrorInfo")
        .expect("a google.rpc.ErrorInfo entry");
    assert_eq!(info["domain"], "a2a-protocol.org");
    assert_eq!(info["reason"], "TASK_NOT_FOUND");
}

#[test]
fn a_standard_json_rpc_error_carries_no_invented_reason() {
    // The specification's table leaves `reason` unset for the JSON-RPC errors. Inventing one would
    // put a string in `data` that no conformant client knows how to read.
    for err in [
        A2aError::Parse,
        A2aError::InvalidRequest,
        A2aError::MethodNotFound,
        A2aError::InvalidParams,
        A2aError::Internal,
    ] {
        let doc = body(&Value::Null, err, "x");
        assert!(doc["error"].get("data").is_none(), "{err:?}: {doc}");
    }
}

#[test]
fn the_codes_and_statuses_are_the_specifications_own() {
    // Transcribed from A2A §5.4. Written out rather than derived, so a future edit that changes a
    // code has to change this table too.
    for (err, code, status) in [
        (A2aError::TaskNotFound, -32001, 404),
        (A2aError::TaskNotCancelable, -32002, 409),
        (A2aError::UnsupportedOperation, -32004, 400),
        (A2aError::InvalidAgentResponse, -32006, 502),
        (A2aError::InvalidRequest, -32600, 400),
        (A2aError::MethodNotFound, -32601, 404),
        (A2aError::InvalidParams, -32602, 400),
        (A2aError::Internal, -32603, 500),
        (A2aError::Parse, -32700, 400),
    ] {
        assert_eq!(err.code(), code, "{err:?}");
        assert_eq!(err.http_status(), status, "{err:?}");
    }
}

#[test]
fn an_id_that_was_never_sent_is_null_rather_than_absent() {
    // JSON-RPC 2.0 §5: a response to a request whose id could not be determined carries `id: null`.
    assert_eq!(id_of(&json!({ "method": "x" })), Value::Null);
    assert_eq!(id_of(&json!("not even an object")), Value::Null);
    assert_eq!(id_of(&json!({ "id": 4 })), json!(4));
    assert_eq!(body(&Value::Null, A2aError::Parse, "x")["id"], Value::Null);
}
