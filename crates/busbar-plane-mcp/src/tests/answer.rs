// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Each arrival is answered here or sent on, and what is answered here is the served engine's.

use serde_json::{json, Value};

use super::*;
use crate::arrival::decide;

const SECTION: &[u8] = br#"{
  "fs": {
    "url": "https://mcp.example/fs",
    "pin": {"mechanism": "unpinned"},
    "tools_allow": {"read_file": {"schema_hash": "sha256:aa"}},
    "prompts_allow": {
      "greet": {"template": "Hello"},
      "confirm": {"template": "Sure?", "ask_caller": [{"ok": {"method": "elicitation/create"}}]}
    },
    "resources_allow": {"file:///readme": {"text": "hi"}}
  }
}"#;

fn catalogue() -> Catalogue {
    Catalogue::build(
        1,
        &crate::door::read_settings(SECTION).expect("the section reads"),
    )
}

fn everyone(_: &str, _: &str) -> bool {
    true
}

/// A stateless-revision request for `method`, decided as an arrival.
fn request(method: &str, params: Value) -> (Decision, Value) {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    let body = json!({"jsonrpc": "2.0", "id": 9, "method": method, "params": params});
    let bytes = serde_json::to_vec(&body).expect("bytes");
    let name = params
        .get("name")
        .or_else(|| params.get("uri"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let method_owned = method.to_string();
    let d = decide(&bytes, |f| match f {
        "mcp-protocol-version" => Some(PROTOCOL_VERSION),
        "mcp-method" => Some(method_owned.as_str()),
        "mcp-name" => name.as_deref(),
        _ => None,
    });
    (d, params)
}

fn run(method: &str, params: Value) -> Answer {
    let (d, params) = request(method, params);
    answer(&d, Some(&params), &catalogue(), &everyone, |_| false)
}

fn body(a: &Answer) -> Value {
    match a {
        Answer::Here { body, .. } => serde_json::from_slice(body).expect("a document"),
        Answer::Far => panic!("answered elsewhere"),
    }
}

#[test]
fn the_catalogue_reads_are_answered_here() {
    for (method, member) in [
        ("tools/list", "tools"),
        ("prompts/list", "prompts"),
        ("resources/list", "resources"),
        ("resources/templates/list", "resourceTemplates"),
    ] {
        let a = run(method, json!({}));
        assert!(matches!(a, Answer::Here { status: 200, .. }), "{method}");
        assert!(body(&a)["result"][member].is_array(), "{method}");
        assert_eq!(body(&a)["id"], 9);
    }
    let read = run("resources/read", json!({"uri": "file:///readme"}));
    assert_eq!(body(&read)["result"]["contents"][0]["text"], "hi");
    let get = run("prompts/get", json!({"name": "fs_greet"}));
    assert_eq!(
        body(&get)["result"]["messages"][0]["content"]["text"],
        "Hello"
    );
    let done = run("completion/complete", json!({}));
    assert_eq!(body(&done)["result"]["completion"]["total"], 0);
}

#[test]
fn discover_counts_what_the_caller_reaches_and_names_the_revisions() {
    let a = run("server/discover", json!({}));
    let v = body(&a);
    assert_eq!(v["result"]["supportedVersions"], json!([PROTOCOL_VERSION]));
    assert_eq!(v["result"]["servers"], json!(["fs"]));
    assert_eq!(
        v["result"]["counts"],
        json!({"tools": 1, "prompts": 2, "resources": 1})
    );
    assert_eq!(v["result"]["registryEmpty"], false);
    assert_eq!(v["result"]["resultType"], "complete");
    assert_eq!(
        v["result"]["capabilities"]["extensions"],
        json!({ TASKS_EXTENSION_ID: {} })
    );
    let (d, params) = request("server/discover", json!({}));
    let none = answer(
        &d,
        Some(&params),
        &catalogue(),
        &|_: &str, _: &str| false,
        |_| false,
    );
    assert_eq!(body(&none)["result"]["servers"], json!([]));
}

/// A call, and a prompt that asks its caller first, are not answered here.
#[test]
fn a_call_and_an_asking_prompt_go_on() {
    assert_eq!(
        run("tools/call", json!({"name": "fs_read_file"})),
        Answer::Far
    );
    assert_eq!(
        run("prompts/get", json!({"name": "fs_confirm"})),
        Answer::Far
    );
}

/// A local refusal is answered with its own status and body.
#[test]
fn a_local_refusal_answers_its_own_status() {
    let a = run("resources/read", json!({"uri": "file:///nope"}));
    let Answer::Here { status, .. } = &a else {
        panic!("answered here")
    };
    assert_eq!(*status, 404);
    assert_eq!(body(&a)["error"]["code"], -32000);
}

/// A notification is acknowledged with no body; a refused arrival answers its refusal.
#[test]
fn a_notice_is_acknowledged_and_a_refusal_answered() {
    let d = decide(br#"{"jsonrpc":"2.0","method":"notifications/x"}"#, |_| None);
    let a = answer(&d, None, &catalogue(), &everyone, |_| false);
    assert_eq!(
        a,
        Answer::Here {
            status: STATUS_ACCEPTED,
            body: Vec::new()
        }
    );
    let d = decide(b"not json", |_| None);
    let a = answer(&d, None, &catalogue(), &everyone, |_| false);
    assert!(matches!(a, Answer::Here { status: 400, .. }));
    assert_eq!(body(&a)["error"]["code"], -32700);
}
