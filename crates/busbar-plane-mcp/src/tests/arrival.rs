// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One arrival decided as the served engine decides it.

use serde_json::json;

use super::*;
use crate::codec::{
    H_MCP_METHOD, H_PROTOCOL_VERSION, META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
};

fn meta() -> serde_json::Value {
    json!({ META_PROTOCOL_VERSION: PROTOCOL_VERSION, META_CLIENT_CAPABILITIES: {} })
}

fn body(v: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&v).expect("a document")
}

/// The head fields of a well-formed stateless request for `method`.
fn fields(method: &str) -> impl Fn(&str) -> Option<&'static str> + '_ {
    move |n| {
        if n == H_PROTOCOL_VERSION {
            Some(PROTOCOL_VERSION)
        } else if n == H_MCP_METHOD {
            // A leaked `'static` for the test's one method name.
            Some(Box::leak(method.to_string().into_boxed_str()))
        } else {
            None
        }
    }
}

fn no_fields(_: &str) -> Option<&'static str> {
    None
}

#[test]
fn a_body_that_is_not_json_is_a_parse_error_with_a_null_id() {
    match decide(b"{not json", no_fields) {
        Decision::Refused(r) => {
            assert_eq!((r.status, r.code, r.id), (400, -32700, None));
            assert_eq!(r.message, NOT_JSON);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_batch_is_refused_by_the_contracts_reader() {
    match decide(b"[]", no_fields) {
        Decision::Refused(r) => assert_eq!((r.status, r.code), (400, -32600)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_well_formed_stateless_request_is_its_row() {
    let b = body(
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta()}}),
    );
    match decide(&b, fields("tools/list")) {
        Decision::Request { row, id } => {
            assert_eq!(row.method, "tools/list");
            assert_eq!(id, json!(1));
        }
        other => panic!("{other:?}"),
    }
}

/// An unknown method, and a method only an upstream sends, are `404` + `-32601` naming the method.
#[test]
fn an_uncarried_method_is_404_method_not_found() {
    for method in ["tools/nope", "sampling/createMessage"] {
        let b =
            body(json!({"jsonrpc": "2.0", "id": 5, "method": method, "params": {"_meta": meta()}}));
        match decide(&b, fields(method)) {
            Decision::Refused(r) => {
                assert_eq!((r.status, r.code, r.id), (404, -32601, Some(json!(5))));
                assert_eq!(
                    r.message,
                    format!("Method `{method}` is not implemented by this server.")
                );
            }
            other => panic!("{method}: {other:?}"),
        }
    }
}

/// The envelope checks run before the vocabulary: an unknown method with no `_meta` is `-32602`.
#[test]
fn the_envelope_checks_precede_the_vocabulary() {
    let b = body(json!({"jsonrpc": "2.0", "id": 5, "method": "tools/nope", "params": {}}));
    match decide(&b, fields("tools/nope")) {
        Decision::Refused(r) => assert_eq!((r.status, r.code), (400, -32602)),
        other => panic!("{other:?}"),
    }
}

/// A notification is acknowledged and never answered, a cancel included.
#[test]
fn a_notification_is_acknowledged() {
    let cancel = "notifications/cancelled";
    let b = body(json!({"jsonrpc": "2.0", "method": cancel, "params": {"requestId": 7}}));
    assert_eq!(
        decide(&b, no_fields),
        Decision::Notice {
            method: cancel.to_string()
        }
    );
}

#[test]
fn a_refusal_body_echoes_its_id() {
    let r = Refusal {
        status: 404,
        id: Some(json!(3)),
        code: -32601,
        message: "m".into(),
        data: None,
    };
    let v: serde_json::Value = serde_json::from_slice(&r.body()).expect("a document");
    assert_eq!(
        v,
        json!({"jsonrpc": "2.0", "id": 3, "error": {"code": -32601, "message": "m"}})
    );
}
