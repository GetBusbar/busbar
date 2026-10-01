// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use serde_json::json;

fn paths(lock: &Lock, dir: &str) -> Vec<String> {
    lock.dirs[dir].keys().cloned().collect()
}

fn planted_openapi() -> Value {
    json!({
        "openapi": "3.1.0",
        "components": {"schemas": {
            "Req": {"type": "object", "properties": {
                "model": {"type": "string"},
                "tier": {"type": ["string", "null"], "enum": ["auto", "standard_only", null]},
                "metadata": {"type": "object", "additionalProperties": {"type": "string"}},
                "messages": {"type": "array", "items": {"$ref": "#/components/schemas/Msg"}},
                "node": {"$ref": "#/components/schemas/Node"}
            }},
            "Msg": {"type": "object", "properties": {
                "role": {"type": "string", "enum": ["user", "assistant"]},
                "content": {"anyOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"$ref": "#/components/schemas/Block"}}
                ]}
            }},
            "Block": {
                "discriminator": {"propertyName": "type", "mapping": {
                    "text": "#/components/schemas/Text",
                    "image": "#/components/schemas/Image"
                }},
                "oneOf": [{"$ref": "#/components/schemas/Text"}, {"$ref": "#/components/schemas/Image"}]
            },
            "Text": {"type": "object", "properties": {
                "type": {"const": "text"}, "text": {"type": "string"}
            }},
            "Image": {"allOf": [
                {"type": "object", "properties": {"type": {"const": "image"}}},
                {"type": "object", "properties": {"data": {"type": "string"}}}
            ]},
            "Node": {"type": "object", "properties": {
                "child": {"$ref": "#/components/schemas/Node"}
            }},
            "Resp": {"type": "object", "properties": {"id": {"type": "string"}}},
            "Event": {"oneOf": [
                {"type": "object", "properties": {"type": {"const": "start"}, "message": {"$ref": "#/components/schemas/Resp"}}},
                {"type": "object", "properties": {"type": {"const": "stop"}}}
            ]}
        }}
    })
}

const PLANTED_OAS: Dialect = Dialect {
    name: "planted",
    spec: "planted",
    format: Format::OpenApi,
    roots: [
        Some("#/components/schemas/Req"),
        Some("#/components/schemas/Resp"),
        Some("#/components/schemas/Event"),
    ],
};

#[test]
fn openapi_paths_follow_notation_a() {
    let lock = lock_of(&PLANTED_OAS, &planted_openapi(), "0").expect("lock");
    assert_eq!(
        paths(&lock, "request"),
        [
            "messages",
            "messages[].content",
            "messages[].content[].type=image",
            "messages[].content[].type=image.data",
            "messages[].content[].type=text",
            "messages[].content[].type=text.text",
            "messages[].role",
            "metadata",
            "model",
            "node",
            "node.child",
            "tier",
        ]
    );
    let req = &lock.dirs["request"];
    assert_eq!(req["messages"].ty, "array<object>");
    assert_eq!(req["messages[].content"].ty, "array<object>|string");
    assert_eq!(req["messages[].content"].tags, ["image", "text"]);
    assert_eq!(req["messages[].content"].tag.as_deref(), Some("type"));
    assert!(req["messages[].content[].type=text"].arm);
    assert_eq!(req["metadata"].ty, "map<string>");
    assert_eq!(req["node.child"].ty, "ref:Node");
    assert_eq!(req["tier"].ty, "null|string");
    assert_eq!(req["tier"].enums, [json!("auto"), json!("standard_only")]);
    // The stream walk is cut at the response schema; event names are arm paths.
    assert_eq!(
        paths(&lock, "stream"),
        ["type=start", "type=start.message", "type=stop"]
    );
    assert_eq!(lock.dirs["stream"]["type=start.message"].ty, "ref:Resp");
}

#[test]
fn botocore_unions_are_member_presence_and_uri_members_are_not_body() {
    let doc = json!({"shapes": {
        "Req": {"type": "structure", "members": {
            "modelId": {"shape": "S", "location": "uri"},
            "messages": {"shape": "Msgs"},
            "fields": {"shape": "M"}
        }},
        "Msgs": {"type": "list", "member": {"shape": "Block"}},
        "Block": {"type": "structure", "union": true, "members": {
            "text": {"shape": "S"}, "image": {"shape": "Img"}
        }},
        "Img": {"type": "structure", "members": {"format": {"shape": "Fmt"}, "size": {"shape": "L"}}},
        "Fmt": {"type": "string", "enum": ["png", "jpeg"]},
        "L": {"type": "long"},
        "S": {"type": "string"},
        "M": {"type": "map", "key": {"shape": "S"}, "value": {"shape": "S"}},
        "Resp": {"type": "structure", "members": {"stopReason": {"shape": "S"}}},
        "Out": {"type": "structure", "eventstream": true, "members": {"messageStop": {"shape": "Resp"}, "metadata": {"shape": "Img"}}}
    }});
    let d = Dialect {
        name: "b",
        spec: "b",
        format: Format::Botocore,
        roots: [Some("Req"), Some("Resp"), Some("Out")],
    };
    let lock = lock_of(&d, &doc, "0").expect("lock");
    assert_eq!(
        paths(&lock, "request"),
        [
            "fields",
            "messages",
            "messages[].image",
            "messages[].image.format",
            "messages[].image.size",
            "messages[].text",
        ]
    );
    let req = &lock.dirs["request"];
    assert_eq!(req["messages"].tags, ["image", "text"]);
    assert_eq!(req["messages"].tag, None);
    assert!(req["messages[].image"].arm);
    assert_eq!(req["messages[].image.size"].ty, "integer");
    assert_eq!(req["fields"].ty, "map<string>");
    assert_eq!(
        paths(&lock, "stream"),
        [
            "messageStop",
            "metadata",
            "metadata.format",
            "metadata.size"
        ]
    );
    assert_eq!(lock.dirs["stream"]["messageStop"].ty, "ref:Resp");
}

#[test]
fn discovery_refs_are_schema_names() {
    let doc = json!({"schemas": {
        "Req": {"type": "object", "properties": {
            "contents": {"type": "array", "items": {"$ref": "Content"}},
            "labels": {"type": "object", "additionalProperties": {"type": "string"}}
        }},
        "Content": {"type": "object", "properties": {
            "role": {"type": "string"},
            "parts": {"type": "array", "items": {"$ref": "Part"}}
        }},
        "Part": {"type": "object", "properties": {
            "text": {"type": "string"},
            "mode": {"type": "string", "enum": ["A", "B"]}
        }},
        "Resp": {"type": "object", "properties": {"modelVersion": {"type": "string"}}}
    }});
    let d = Dialect {
        name: "g",
        spec: "g",
        format: Format::Discovery,
        roots: [Some("Req"), Some("Resp"), None],
    };
    let lock = lock_of(&d, &doc, "0").expect("lock");
    assert_eq!(
        paths(&lock, "request"),
        [
            "contents",
            "contents[].parts",
            "contents[].parts[].mode",
            "contents[].parts[].text",
            "contents[].role",
            "labels",
        ]
    );
    assert!(!lock.dirs.contains_key("stream"));
    assert!(!lock.streams());
}

/// DETERMINISM: two generations of the same document are byte-identical, and the committed form
/// reads back to the same lock.
#[test]
fn generation_is_deterministic_and_round_trips() {
    let a = lock_of(&PLANTED_OAS, &planted_openapi(), "abc").expect("lock");
    let b = lock_of(&PLANTED_OAS, &planted_openapi(), "abc").expect("lock");
    assert_eq!(a.render(), b.render());
    let back = Lock::parse(&a.render()).expect("parse");
    assert_eq!(back, a);
    assert_eq!(back.render(), a.render());
}

#[test]
fn the_inventory_marks_only_streaming_dialects() {
    let locks = committed(&Ctx::workspace().expect("workspace")).expect("the committed locks");
    let inv: Value = serde_json::from_str(&render_inventory(&locks)).expect("json");
    assert_eq!(
        inv["dialects"],
        json!([
            "anthropic",
            "openai",
            "responses",
            "gemini",
            "bedrock",
            "cohere"
        ])
    );
    let streaming: Vec<&str> = inv["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .filter_map(|f| f["dialect"].as_str())
        .collect();
    assert_eq!(
        streaming,
        ["anthropic", "openai", "responses", "bedrock", "cohere"]
    );
}

// ── THE DIFF SELFTESTS, planted into the committed anthropic lock ────────────────────────────────

fn anthropic() -> Lock {
    let cx = Ctx::workspace().expect("workspace");
    Lock::parse(
        &cx.read(lock_path("anthropic"))
            .expect("the committed anthropic lock"),
    )
    .expect("parse")
}

#[test]
fn selftest_a_planted_rename_is_a_probable_rename() {
    let old = anthropic();
    let mut new = old.clone();
    let req = new.dirs.get_mut("request").expect("request");
    let e = req
        .remove("stop_sequences")
        .expect("stop_sequences is in the lock");
    req.insert("stop".to_string(), e.clone());
    let changes = diff::diff(&old, &new);
    assert_eq!(
        changes,
        [Change::Rename {
            id: "anthropic/request/stop_sequences".into(),
            to: "stop".into(),
            ty: e.ty,
            children: 0,
        }]
    );
    assert!(changes[0].to_string().starts_with("RENAME?"));
}

#[test]
fn selftest_a_renamed_parent_carries_its_children() {
    let old = anthropic();
    let mut new = old.clone();
    let req = new.dirs.get_mut("request").expect("request");
    let moved: Vec<String> = req
        .keys()
        .filter(|k| k.starts_with("metadata."))
        .cloned()
        .collect();
    assert!(!moved.is_empty(), "metadata has members in the lock");
    let parent = req.remove("metadata").expect("metadata");
    req.insert("meta".into(), parent);
    for k in &moved {
        let e = req.remove(k).expect("child");
        req.insert(format!("meta{}", &k["metadata".len()..]), e);
    }
    let changes = diff::diff(&old, &new);
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert!(
        matches!(&changes[0], Change::Rename { to, children, .. } if to == "meta" && *children == moved.len())
    );
}

#[test]
fn selftest_a_planted_removed_field_is_removed() {
    let old = anthropic();
    let mut new = old.clone();
    let e = new
        .dirs
        .get_mut("request")
        .expect("request")
        .remove("inference_geo")
        .expect("inference_geo is in the lock");
    assert_eq!(
        diff::diff(&old, &new),
        [Change::Removed {
            id: "anthropic/request/inference_geo".into(),
            ty: e.ty,
        }]
    );
}

#[test]
fn selftest_a_planted_new_enum_value_is_gained() {
    let old = anthropic();
    let mut new = old.clone();
    let (path, e) = new
        .dirs
        .get_mut("response")
        .expect("response")
        .iter_mut()
        .find(|(p, e)| p.as_str() == "stop_reason" && !e.enums.is_empty())
        .expect("stop_reason carries enum values");
    e.enums.push(json!("planted_reason"));
    let id = format!("anthropic/response/{path}");
    assert_eq!(
        diff::diff(&old, &new),
        [Change::Values {
            id,
            what: "enum",
            gained: true,
            values: vec!["\"planted_reason\"".into()],
        }]
    );
}

#[test]
fn an_unchanged_lock_diffs_to_nothing() {
    let old = anthropic();
    assert!(diff::diff(&old, &old.clone()).is_empty());
}

/// An integer outside i64/u64 in a YAML spec keeps its exact digits (OpenAI writes
/// `seed.minimum: -9223372036854776000`); it is never rounded to a float.
#[test]
fn a_yaml_integer_beyond_i64_keeps_its_exact_digits() {
    let doc = spec::parse(
        "spec.yaml",
        "seed:\n  minimum: -9223372036854776000\n  maximum: 18446744073709551616\n  small: -5\n",
    )
    .expect("parses");
    assert_eq!(doc["seed"]["minimum"], json!("-9223372036854776000"));
    assert_eq!(doc["seed"]["maximum"], json!("18446744073709551616"));
    assert_eq!(doc["seed"]["small"], json!(-5));
}
