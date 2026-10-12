// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stateless revision's envelope checks answer as the served engine does: the same order, the
//! same codes and the same sentences.

use serde_json::{json, Value};

use super::*;

/// A well-formed request for `method`, its body and its mirrored fields.
fn well_formed(method: &str) -> (Value, Vec<(&'static str, String)>) {
    let mut params = json!({
        "_meta": {
            META_PROTOCOL_VERSION: PROTOCOL_VERSION,
            META_CLIENT_CAPABILITIES: {},
        }
    });
    let mut fields = vec![
        (H_PROTOCOL_VERSION, PROTOCOL_VERSION.to_string()),
        (H_MCP_METHOD, method.to_string()),
    ];
    if let Some(source) = name_source_of(method) {
        params[source] = json!("read_file");
        fields.push((H_MCP_NAME, "read_file".to_string()));
    }
    (
        json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
        fields,
    )
}

fn check(value: &Value, method: &str, fields: &[(&'static str, String)]) -> Result<(), Refused> {
    check_request(value, method, |name| {
        fields
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    })
}

fn without(fields: &[(&'static str, String)], name: &str) -> Vec<(&'static str, String)> {
    fields.iter().filter(|(n, _)| *n != name).cloned().collect()
}

fn with(
    fields: &[(&'static str, String)],
    name: &'static str,
    v: &str,
) -> Vec<(&'static str, String)> {
    let mut out = without(fields, name);
    out.push((name, v.to_string()));
    out
}

#[test]
fn a_well_formed_request_passes_every_check() {
    for method in ["tools/list", "tools/call", "prompts/get", "resources/read"] {
        let (v, f) = well_formed(method);
        assert_eq!(check(&v, method, &f), Ok(()), "{method}");
    }
}

#[test]
fn a_missing_meta_or_member_is_a_400_invalid_params_in_the_served_words() {
    let (mut v, f) = well_formed("tools/list");
    v["params"].as_object_mut().unwrap().remove("_meta");
    let r = check(&v, "tools/list", &f).unwrap_err();
    assert_eq!(r.code, -32602);
    assert!(r
        .message
        .starts_with("`params._meta` is required on every request."));

    let (mut v, f) = well_formed("tools/list");
    v["params"]["_meta"]
        .as_object_mut()
        .unwrap()
        .remove(META_PROTOCOL_VERSION);
    let r = check(&v, "tools/list", &f).unwrap_err();
    assert_eq!(r.code, -32602);
    assert!(r
        .message
        .contains("must carry `io.modelcontextprotocol/protocolVersion`"));

    let (mut v, f) = well_formed("tools/list");
    v["params"]["_meta"]
        .as_object_mut()
        .unwrap()
        .remove(META_CLIENT_CAPABILITIES);
    let r = check(&v, "tools/list", &f).unwrap_err();
    assert_eq!(r.code, -32602);
    assert!(r
        .message
        .contains("must carry `io.modelcontextprotocol/clientCapabilities`"));
}

/// Every mirror/body disagreement is one class: `-32020`.
#[test]
fn every_field_body_disagreement_is_a_header_mismatch() {
    let (v, f) = well_formed("tools/call");
    let cases = [
        without(&f, H_PROTOCOL_VERSION),
        with(&f, H_PROTOCOL_VERSION, "2025-06-18"),
        without(&f, H_MCP_METHOD),
        with(&f, H_MCP_METHOD, "tools/list"),
        with(&f, H_MCP_METHOD, "TOOLS/CALL"),
        without(&f, H_MCP_NAME),
        with(&f, H_MCP_NAME, "write_file"),
        with(&f, H_MCP_NAME, "=?base64?not base64?="),
    ];
    for (i, fields) in cases.iter().enumerate() {
        let r = check(&v, "tools/call", fields).unwrap_err();
        assert_eq!(r.code, -32020, "case {i}: {}", r.message);
    }
}

/// The sentinel is decoded before comparison.
#[test]
fn an_encoded_name_matches_its_decoded_body_name() {
    let (v, f) = well_formed("tools/call");
    let encoded = format!("=?base64?{}?=", "cmVhZF9maWxl");
    assert_eq!(
        check(&v, "tools/call", &with(&f, H_MCP_NAME, &encoded)),
        Ok(())
    );
}

/// An unsupported revision is judged last and names what is supported.
#[test]
fn an_unsupported_revision_is_a_400_naming_the_supported() {
    let (mut v, f) = well_formed("tools/list");
    v["params"]["_meta"][META_PROTOCOL_VERSION] = json!("2025-06-18");
    let f = with(&f, H_PROTOCOL_VERSION, "2025-06-18");
    let r = check(&v, "tools/list", &f).unwrap_err();
    assert_eq!(r.code, -32022);
    let data = r.data.expect("data names the revisions");
    assert_eq!(data["requested"], "2025-06-18");
    assert_eq!(data["supported"], json!([PROTOCOL_VERSION]));
}

/// A malformed request is refused for its malformation before its revision is judged.
#[test]
fn a_malformed_request_is_refused_before_the_revision_is_judged() {
    let (mut v, f) = well_formed("tools/list");
    v["params"]["_meta"][META_PROTOCOL_VERSION] = json!("2025-06-18");
    let r = check(&v, "tools/list", &without(&f, H_MCP_METHOD)).unwrap_err();
    assert_eq!(r.code, -32020);
}

/// The body is the one JSON-RPC error envelope (the contract's builder, the one the served engine
/// renders through), with the id echoed or `null`. Compared as a document: member order is the
/// JSON library's, and it is the same library in both.
#[test]
fn a_refusal_body_is_the_one_error_envelope() {
    let r = Refused {
        code: -32020,
        message: "m",
        data: None,
    };
    let read = |b: Vec<u8>| serde_json::from_slice::<Value>(&b).expect("a document");
    assert_eq!(
        read(r.body(Some(&json!(7)))),
        json!({"jsonrpc": "2.0", "id": 7, "error": {"code": -32020, "message": "m"}})
    );
    assert_eq!(
        read(r.body(None)),
        json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32020, "message": "m"}})
    );
    assert_eq!(STATUS, 400);
}
