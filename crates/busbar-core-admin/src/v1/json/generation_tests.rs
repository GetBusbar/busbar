// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use axum::http::HeaderMap;
use busbar_contract::json::{JsonContainerTrait as _, JsonValueTrait as _};

#[cfg(feature = "openapi-schema")]
#[test]
fn settings_openapi_declares_the_actual_instance_edit_idempotency_header() {
    let doc = crate::v1::json::openapi_doc();
    let operation = &doc["paths"]["/api/v1/admin/config/settings"]["put"];
    let headers: Vec<_> = operation["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|parameter| parameter["in"] == "header" && parameter["name"] == "Idempotency-Key")
        .collect();
    assert_eq!(headers.len(), 1);
    let header = headers[0];
    assert_eq!(
        header["required"], false,
        "other settings modes retain optional replay"
    );
    assert_eq!(header["schema"]["minLength"], 1);
    assert_eq!(header["schema"]["maxLength"], 128);
    assert_eq!(header["schema"]["pattern"], "^[A-Za-z0-9._:-]+$");
    assert!(header["description"]
        .as_str()
        .unwrap()
        .contains("instance_edit"));
    assert_eq!(
        operation["x-busbar-instance-edit"]["idempotency"],
        "required_exact_method_path_query_body"
    );
    for valid in ["a", "Aa09._:-", &"a".repeat(128)] {
        assert!(valid_idempotency_key(valid));
    }
    for invalid in ["", "two words", "slash/value", "é", &"a".repeat(129)] {
        assert!(!valid_idempotency_key(invalid));
    }
}

#[test]
fn original_precondition_clone_retains_first_backing_and_all_duplicate_counts() {
    let mut headers = HeaderMap::new();
    let value = HeaderValue::from_str(&format!("\"{}\"", "original".repeat(32))).unwrap();
    let pointer = value.as_bytes().as_ptr();
    headers.append(header::IF_MATCH, value);
    for count in 1..=12 {
        let retained = OriginalConfigPrecondition::capture(&headers).clone();
        assert_eq!(retained.count, count);
        assert_eq!(
            retained.first.as_ref().unwrap().as_bytes().as_ptr(),
            pointer
        );
        if count == 1 {
            assert!(retained.require_strong().is_ok());
        } else {
            assert_eq!(
                retained.require_strong().unwrap_err().status(),
                StatusCode::BAD_REQUEST
            );
        }
        headers.append(header::IF_MATCH, HeaderValue::from_static("\"another\""));
    }
}

#[test]
fn conditional_read_keeps_first_field_and_existing_weak_comparison() {
    for (field, expected) in [
        ("*", true),
        (" \"tag\" ", true),
        ("W/\"tag\"", true),
        ("\"other\", W/\"tag\"", true),
        ("\"other\"", false),
        ("", false),
    ] {
        let mut headers = HeaderMap::new();
        headers.append(header::IF_NONE_MATCH, HeaderValue::from_str(field).unwrap());
        headers.append(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        let first = headers.get(header::IF_NONE_MATCH).cloned();
        drop(headers);
        assert_eq!(
            if_none_match(first.as_ref(), "W/\"tag\""),
            expected,
            "{field}"
        );
    }
    assert!(!if_none_match(None, "\"tag\""));
    let invalid = HeaderValue::from_bytes(b"\xff").unwrap();
    assert!(!if_none_match(Some(&invalid), "\"tag\""));
}

#[test]
fn original_precondition_keeps_multiplicity_and_bytes_before_translation() {
    let mut headers = HeaderMap::new();
    assert_eq!(
        OriginalConfigPrecondition::capture(&headers)
            .require_strong()
            .unwrap_err()
            .status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    let wire = HeaderValue::from_static("\"dep_original.7\"");
    headers.insert(header::IF_MATCH, wire.clone());
    let original = OriginalConfigPrecondition::capture(&headers);
    headers.insert(header::IF_MATCH, HeaderValue::from_static("\"12\""));
    assert_eq!(original.require_strong().unwrap(), &wire);
    for malformed in [
        "*",
        "W/\"dep_original.7\"",
        "\"one\", \"two\"",
        " \"one\"",
        "\"one two\"",
        "7",
    ] {
        headers.insert(header::IF_MATCH, HeaderValue::from_str(malformed).unwrap());
        assert_eq!(
            OriginalConfigPrecondition::capture(&headers)
                .require_strong()
                .unwrap_err()
                .status(),
            StatusCode::BAD_REQUEST,
            "{malformed}"
        );
    }
    headers.insert(header::IF_MATCH, wire.clone());
    headers.append(header::IF_MATCH, wire);
    assert_eq!(
        OriginalConfigPrecondition::capture(&headers)
            .require_strong()
            .unwrap_err()
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn answer_round_trip_retains_exact_long_header_and_original_etag() {
    let content_type = format!("application/json; profile=\"{}\"", "x".repeat(300));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type).unwrap(),
    );
    headers.insert(header::ETAG, HeaderValue::from_static("\"dep_original.7\""));
    let bytes = encode_answer(201, 10, 7, &[9; 32], &headers, b"original reply").unwrap();
    let decoded = decode_answer(&bytes).unwrap();
    assert_eq!(decoded.status, 201);
    assert_eq!(decoded.received_at, 10);
    assert_eq!(decoded.generation, 7);
    assert_eq!(decoded.body, b"original reply");
    let replay = replay(&bytes, &[9; 32]);
    assert_eq!(
        replay.headers()[header::CONTENT_TYPE],
        headers[header::CONTENT_TYPE]
    );
    assert_eq!(replay.headers()[header::ETAG], headers[header::ETAG]);
    assert_eq!(replay.headers()[REPLAYED], "true");
    assert_eq!(
        super::replay(&bytes, &[8; 32]).status(),
        StatusCode::CONFLICT
    );
}

#[test]
fn answer_distinguishes_absent_and_empty_header() {
    let empty = HeaderMap::new();
    let bytes = encode_answer(200, 10, 7, &[9; 32], &empty, b"reply").unwrap();
    assert!(replay(&bytes, &[9; 32])
        .headers()
        .get(header::CONTENT_TYPE)
        .is_none());
    let mut present = empty;
    present.insert(header::CONTENT_TYPE, HeaderValue::from_static(""));
    let bytes = encode_answer(200, 10, 7, &[9; 32], &present, b"reply").unwrap();
    assert_eq!(replay(&bytes, &[9; 32]).headers()[header::CONTENT_TYPE], "");
}

#[test]
fn legacy_answer_has_no_invented_generation_etag() {
    // Exact prior layout 2: status, time, generation, framed digest, u8 type length, type, body.
    let mut bytes = vec![2];
    bytes.extend_from_slice(&200u16.to_be_bytes());
    bytes.extend_from_slice(&10u64.to_be_bytes());
    bytes.extend_from_slice(&7u64.to_be_bytes());
    bytes.extend_from_slice(&[9; 32]);
    bytes.push(16);
    bytes.extend_from_slice(b"application/json");
    bytes.extend_from_slice(b"{}");
    assert_eq!(decode_answer(&bytes).unwrap().body, b"{}");
    let response = replay(&bytes, &[9; 32]);
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::ETAG).is_none());
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    bytes[0] = 1;
    assert_eq!(
        replay(&bytes, &[9; 32]).status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn malformed_header_layout_is_not_replayed() {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("x"));
    let valid = encode_answer(200, 10, 7, &[9; 32], &headers, b"reply").unwrap();
    for end in 0..58 {
        assert!(decode_answer(&valid[..end]).is_none(), "truncated at {end}");
    }
    let mut bad_marker = valid.clone();
    bad_marker[51] = 2;
    assert!(decode_answer(&bad_marker).is_none());
    let mut bad_length = valid.clone();
    bad_length[52..56].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(decode_answer(&bad_length).is_none());
    let mut bad_value = valid;
    bad_value[56] = b'\n';
    assert!(decode_answer(&bad_value).is_none());
}

/// The record `GET /operations/{key}` sends for a stored operation, as the client sees it.
#[cfg(feature = "openapi-schema")]
fn operation_reply(looked: Looked) -> busbar_contract::json::Value {
    let body = operation_body("key-1", "alice", looked)
        .unwrap_or_else(|_| panic!("the stored operation reads"));
    busbar_contract::json::parse_value(body.to_string().as_bytes()).unwrap()
}

/// The served admin API document, as a tree.
#[cfg(feature = "openapi-schema")]
fn served_document() -> busbar_contract::json::Value {
    busbar_contract::json::parse_value(crate::v1::json::openapi_json().as_bytes()).unwrap()
}

/// The `components.schemas` entry the served document has under `name`.
#[cfg(feature = "openapi-schema")]
fn served_schema(name: &str) -> busbar_contract::json::Value {
    let document = served_document();
    document
        .get("components")
        .and_then(|components| components.get("schemas"))
        .and_then(|schemas| schemas.get(name))
        .unwrap_or_else(|| panic!("the served document has a schema {name}"))
        .clone()
}

/// The strings of the `enum` of the served schema `name`.
#[cfg(feature = "openapi-schema")]
fn documented_enum(name: &str) -> Vec<String> {
    let schema = served_schema(name);
    let values = schema
        .get("enum")
        .and_then(|values| values.as_array())
        .unwrap_or_else(|| panic!("{name} documents an enum"));
    values
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect()
}

/// Every state the engine reports for a stored operation, each produced by the reply code from
/// what the idempotency store holds: in flight (claimed, and bound but unsettled), applied and
/// rejected.
#[cfg(feature = "openapi-schema")]
fn operation_replies() -> [(&'static str, busbar_contract::json::Value); 4] {
    let settled = |status| {
        let answer = encode_answer(
            status,
            10,
            7,
            &[9; 32],
            &HeaderMap::new(),
            br#"{"applied":true}"#,
        )
        .unwrap();
        Looked::Done {
            answer,
            completed_at: 11,
        }
    };
    [
        (
            "in_flight",
            operation_reply(Looked::Retained {
                receipt: encode_intent(10, 7, &[9; 32]),
            }),
        ),
        (
            "in_flight",
            operation_reply(Looked::InFlight {
                request_sha256: [9; 32],
                received_at: 10,
            }),
        ),
        ("applied", operation_reply(settled(200))),
        ("rejected", operation_reply(settled(409))),
    ]
}

#[cfg(feature = "openapi-schema")]
#[test]
fn every_operation_reply_state_is_one_the_served_document_lists() {
    let documented = documented_enum("OperationState");
    for (state, reply) in operation_replies() {
        let sent = reply.get("state").and_then(|value| value.as_str());
        assert_eq!(sent, Some(state), "the reply names its state");
        assert!(
            documented.iter().any(|listed| listed == state),
            "the served document lists {documented:?}, and the engine's own {state} reply says {state}"
        );
    }
}

#[cfg(feature = "openapi-schema")]
#[test]
fn every_operation_reply_member_is_one_the_served_document_names() {
    let view = served_schema("OperationView");
    let properties = view.get("properties").expect("OperationView has members");
    for (state, reply) in operation_replies() {
        let members = reply.as_object().expect("the reply is an object");
        assert_eq!(
            members.len(),
            properties.as_object().unwrap().len(),
            "the {state} reply and the document name the same number of members"
        );
        for (name, _) in members.iter() {
            assert!(
                properties.get(name).is_some(),
                "the {state} reply sends {name}, which the document does not name"
            );
        }
    }
}

#[cfg(feature = "openapi-schema")]
#[test]
fn the_documented_operation_states_are_the_ones_the_reply_sends() {
    let mut named = documented_enum("OperationState");
    assert_eq!(named, ["applied", "rejected", "in_flight"]);
    let mut sent: Vec<_> = operation_replies()
        .into_iter()
        .map(|(state, _)| state.to_string())
        .collect();
    sent.sort();
    sent.dedup();
    named.sort();
    assert_eq!(
        sent, named,
        "the states sent are exactly the states documented"
    );
}
