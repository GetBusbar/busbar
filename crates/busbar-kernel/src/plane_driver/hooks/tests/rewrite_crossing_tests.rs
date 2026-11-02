// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::call::BLOB_OCTETS;
use busbar_contract::hooks::RewriteReply;

use super::*;

#[test]
fn a_committed_rewrite_crosses_to_the_plane_as_one_and_never_as_absent() {
    let carried = RewriteReply {
        messages: vec![serde_json::json!({ "role": "user", "content": "[redacted]" })],
        tools: Vec::new(),
    };
    let empty = RewriteReply {
        messages: Vec::new(),
        tools: Vec::new(),
    };
    for (what, rw, expected) in [
        (
            "a rewrite carrying messages",
            &carried,
            serde_json::json!({
                "messages": [{ "role": "user", "content": "[redacted]" }],
                "tools": [],
            }),
        ),
        (
            "a rewrite naming no messages",
            &empty,
            serde_json::json!({ "messages": [], "tools": [] }),
        ),
    ] {
        let bytes = rewrite_bytes(rw);
        assert!(
            !bytes.is_empty(),
            "{what}: a committed rewrite that serialized to nothing would cross as ABSENT and the \
             plane would relay the caller's original body"
        );
        let crossed = blob(&bytes);
        assert!(
            !crossed.ptr.is_null() && crossed.len == bytes.len() && crossed.fmt == BLOB_OCTETS,
            "{what}: the plane is handed the rewrite, never the absent blob"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("JSON"),
            expected,
            "{what}: the plane reads the reply the hook committed, `messages` and all"
        );
    }

    assert!(blob(&[]).ptr.is_null(), "empty bytes cross as ABSENT");
}

#[test]
fn the_crossing_is_byte_identical_to_the_object_it_replaced() {
    let replies = [
        RewriteReply {
            messages: Vec::new(),
            tools: Vec::new(),
        },
        RewriteReply {
            messages: vec![
                serde_json::json!({ "role": "system", "content": "be \"brief\"\n" }),
                serde_json::json!({
                    "role": "user",
                    "content": [{ "type": "text", "text": "é ✓" }, { "z": 1, "a": [1.5, -2, null] }],
                }),
            ],
            tools: vec![serde_json::json!({ "name": "t", "parameters": { "b": true, "a": {} } })],
        },
    ];
    for rw in &replies {
        let tree = serde_json::to_vec(&serde_json::json!({
            "messages": rw.messages,
            "tools": rw.tools,
        }))
        .expect("the object serializes");
        assert_eq!(
            String::from_utf8(rewrite_bytes(rw)).expect("utf-8"),
            String::from_utf8(tree).expect("utf-8")
        );
    }
}
