// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `prompts/get` and `resources/read` answer from the section as the served engine does.

use serde_json::{json, Value};

use super::*;

const SECTION: &[u8] = br#"{
  "fs": {
    "url": "https://mcp.example/fs",
    "pin": {"mechanism": "unpinned"},
    "prompts_allow": {
      "greet": {"description": "Greets.", "template": "Hello {who}<script>x</script> {missing}"},
      "typed": {"messages": [
        {"role": "assistant", "content": {"type": "text", "text": "Hi {who}"}},
        {"content": {"type": "image", "data": "aGk=", "mime_type": "image/png"}}
      ]}
    },
    "resources_allow": {"file:///shared": {"text": "fs copy"}},
    "resource_templates_allow": {"file:///logs/{date}": {"text": "log for {date}", "mime_type": "text/plain"}}
  },
  "db": {
    "url": "https://mcp.example/db",
    "pin": {"mechanism": "unpinned"},
    "resources_allow": {"file:///shared": {"blob": "YmluYXJ5"}},
    "resource_templates_allow": {"file:///logs/{day}": {"text": "db log {day}"}}
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

fn only_fs(kind: &str, name: &str) -> bool {
    (kind == "mcp_server" && name == "fs") || (kind == "mcp_tool" && name.starts_with("fs_"))
}

fn read(bytes: Vec<u8>) -> Value {
    serde_json::from_slice(&bytes).expect("a document")
}

#[test]
fn a_template_substitutes_once_then_normalises_and_keeps_unknown_placeholders() {
    let c = catalogue();
    let params = json!({"name": "fs_greet", "arguments": {"who": "{missing}"}});
    let prompt = prompt_named(&c, &json!(1), Some(&params), &everyone).expect("found");
    let v = read(prompts_get(prompt, &json!(1), Some(&params)));
    assert_eq!(v["result"]["resultType"], "complete");
    assert_eq!(v["result"]["description"], "Greets.");
    let text = v["result"]["messages"][0]["content"]["text"]
        .as_str()
        .expect("text");
    assert!(text.starts_with("Hello {missing}"), "{text}");
    assert!(!text.contains("<script>"), "{text}");
    assert_eq!(v["result"]["messages"][0]["role"], "user");
}

#[test]
fn a_typed_prompt_renders_each_message_and_leaves_media_untouched() {
    let c = catalogue();
    let params = json!({"name": "fs_typed", "arguments": {"who": "Ann"}});
    let prompt = prompt_named(&c, &json!(1), Some(&params), &everyone).expect("found");
    let v = read(prompts_get(prompt, &json!(1), Some(&params)));
    assert_eq!(
        v["result"]["messages"],
        json!([
            {"role": "assistant", "content": {"type": "text", "text": "Hi Ann"}},
            {"role": "user", "content": {"type": "image", "data": "aGk=", "mimeType": "image/png"}}
        ])
    );
    assert_eq!(v["result"]["description"], Value::Null);
}

#[test]
fn an_ungranted_prompt_answers_exactly_like_a_nonexistent_one() {
    let c = catalogue();
    let none = |_: &str, _: &str| false;
    let hidden =
        prompt_named(&c, &json!(1), Some(&json!({"name": "fs_greet"})), &none).expect_err("hidden");
    let absent = prompt_named(&c, &json!(1), Some(&json!({"name": "fs_nope"})), &everyone)
        .expect_err("absent");
    assert_eq!((hidden.status, hidden.code), (404, -32000));
    assert_eq!((absent.status, absent.code), (404, -32000));
    assert_eq!(
        hidden.message,
        "`fs_greet` is not a prompt this server exposes."
    );
    let missing = prompt_named(&c, &json!(1), Some(&json!({})), &everyone).expect_err("missing");
    assert_eq!((missing.status, missing.code), (400, -32602));
}

#[test]
fn a_resource_is_read_by_its_own_uri_and_two_reachable_approvals_are_named() {
    let c = catalogue();
    let params = json!({"uri": "file:///shared"});
    let fs = read(resources_read(&c, &json!(1), Some(&params), &only_fs).expect("one"));
    assert_eq!(
        fs["result"]["contents"],
        json!([{"uri": "file:///shared", "text": "fs copy"}])
    );
    assert_eq!(fs["result"]["cacheScope"], "private");
    let both = resources_read(&c, &json!(1), Some(&params), &everyone).expect_err("two");
    assert_eq!((both.status, both.code), (409, -32000));
    assert_eq!(
        both.data,
        Some(json!({"reason": "resource_ambiguous", "candidates": ["db", "fs"]}))
    );
}

#[test]
fn a_template_answers_after_the_concrete_approvals_and_contends_like_one() {
    let c = catalogue();
    let params = json!({"uri": "file:///logs/2026-09-30"});
    let fs = read(resources_read(&c, &json!(1), Some(&params), &only_fs).expect("one"));
    assert_eq!(
        fs["result"]["contents"],
        json!([{"uri": "file:///logs/2026-09-30", "mimeType": "text/plain", "text": "log for 2026-09-30"}])
    );
    let both = resources_read(&c, &json!(1), Some(&params), &everyone).expect_err("two");
    assert_eq!(both.status, 409);
    assert_eq!(
        both.data.expect("data")["candidates"],
        json!(["db_file:///logs/{day}", "fs_file:///logs/{date}"])
    );
}

#[test]
fn nothing_reachable_is_not_found_and_a_missing_uri_is_invalid() {
    let c = catalogue();
    let none = |_: &str, _: &str| false;
    let r = resources_read(
        &c,
        &json!(1),
        Some(&json!({"uri": "file:///shared"})),
        &none,
    )
    .expect_err("hidden");
    assert_eq!((r.status, r.code), (404, -32000));
    assert_eq!(
        r.message,
        "`file:///shared` is not a resource this server exposes."
    );
    let r = resources_read(&c, &json!(1), None, &everyone).expect_err("missing");
    assert_eq!((r.status, r.code), (400, -32602));
}

/// A binding is non-empty and holds no `/`: one template approves one shape, never a subtree.
#[test]
fn a_template_binds_one_segment_and_never_a_subtree() {
    let t = "file:///t/{id}/data";
    assert_eq!(
        crate::catalogue::match_uri_template(t, "file:///t/7/data").map(|b| b["id"].clone()),
        Some("7".to_string())
    );
    assert_eq!(
        crate::catalogue::match_uri_template(t, "file:///t//data"),
        None
    );
    assert_eq!(
        crate::catalogue::match_uri_template(t, "file:///t/a/b/data"),
        None
    );
    assert_eq!(
        crate::catalogue::match_uri_template(t, "file:///t/7/data/x"),
        None
    );
}
