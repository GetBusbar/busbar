// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One arrival decided as the served engine decides it, over both carriers.

use serde_json::json;

use super::*;
use crate::codec::{META_CLIENT_CAPABILITIES, PROTOCOL_VERSION};

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
    match decide(false, b"{not json", no_fields) {
        Decision::Refused(r) => {
            assert_eq!((r.status, r.code, r.id), (400, -32700, None));
            assert_eq!(r.message, NOT_JSON);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_batch_is_refused_by_the_contracts_reader() {
    match decide(false, b"[]", no_fields) {
        Decision::Refused(r) => assert_eq!((r.status, r.code), (400, -32600)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_well_formed_stateless_request_is_its_row_with_no_correlation() {
    let b = body(
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta()}}),
    );
    match decide(false, &b, fields("tools/list")) {
        Decision::Request {
            row,
            id,
            correlation,
        } => {
            assert_eq!(row.method, "tools/list");
            assert_eq!(id, json!(1));
            assert_eq!(
                correlation, 0,
                "the stateless carrier does not cancel by name"
            );
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
        match decide(false, &b, fields(method)) {
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
    match decide(false, &b, fields("tools/nope")) {
        Decision::Refused(r) => assert_eq!((r.status, r.code), (400, -32602)),
        other => panic!("{other:?}"),
    }
}

/// A stateless notification is acknowledged and cancels nothing, even a cancel.
#[test]
fn a_stateless_notification_cancels_nothing() {
    let b = body(json!({"jsonrpc": "2.0", "method": METHOD_CANCELLED, "params": {"requestId": 7}}));
    assert_eq!(
        decide(false, &b, no_fields),
        Decision::Notice {
            method: METHOD_CANCELLED.to_string(),
            cancels: 0
        }
    );
}

/// On the child-process carrier a cancel names the request by the key its arrival carried.
#[test]
fn a_child_process_cancel_names_the_request_it_cancels() {
    let req = body(
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {"_meta": meta()}}),
    );
    let Decision::Request { correlation, .. } = decide(true, &req, no_fields) else {
        panic!("the request decodes");
    };
    assert_ne!(correlation, 0);
    let cancel =
        body(json!({"jsonrpc": "2.0", "method": METHOD_CANCELLED, "params": {"requestId": 7}}));
    assert_eq!(
        decide(true, &cancel, no_fields),
        Decision::Notice {
            method: METHOD_CANCELLED.to_string(),
            cancels: correlation
        }
    );
    // The string "7" is a different request.
    assert_ne!(correlation_of(&json!("7")), correlation);
}

/// The child-process carrier answers its session verbs before the envelope checks: a legacy
/// `initialize` with no `_meta` is a session verb, not a `-32602`.
#[test]
fn a_child_process_session_verb_precedes_the_envelope_checks() {
    for method in SESSION_VERBS {
        let b = body(json!({"jsonrpc": "2.0", "id": "i", "method": method}));
        match decide(true, &b, no_fields) {
            Decision::Session { method: m, id, .. } => {
                assert_eq!((m.as_str(), id), (*method, json!("i")));
            }
            other => panic!("{method}: {other:?}"),
        }
        // On the stateless carrier the same message is an envelope defect.
        match decide(false, &b, no_fields) {
            Decision::Refused(r) => assert_eq!(r.code, -32602, "{method}"),
            other => panic!("{method}: {other:?}"),
        }
    }
}

/// On the child-process carrier the mirror is the body's own, so a well-formed request passes
/// with no head fields at all.
#[test]
fn a_child_process_request_mirrors_its_own_body() {
    let b = body(json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"_meta": meta(), "name": "fs_read_file"}
    }));
    assert!(matches!(
        decide(true, &b, no_fields),
        Decision::Request { .. }
    ));
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
