// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `ADMIN_API_REVISION` moves with the shape of the committed admin API document, and only with it.

use busbar_contract::json::{JsonContainerTrait as _, JsonValueTrait as _, Value};

/// Every admin API revision and the structure digest of the committed `openapi.json` at it, oldest
/// first. When `api_revision_moves_with_the_document_shape` fails because the document changed
/// shape, raise `ADMIN_API_REVISION` by one and append one row with the digest the failure prints.
/// Never edit or remove a row: an old row is what an older engine reported.
const API_REVISION_DIGESTS: &[(u32, &str)] = &[
    (
        1,
        "1056059904688f1624efd1f074355e51a5d2c63c89d15e32feb2cc4ab9d25800",
    ),
    (
        2,
        "80315de24685e1fa65363fc5f0a77d48145c733bf83bd4d30de0be50e3719366",
    ),
];

const COMMITTED_OPENAPI: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/v1/json/openapi.json");

/// Members that are prose wherever they are a schema or operation keyword. Inside a
/// `properties` map the same words are member names, which are shape.
fn prose(key: &str, value: &Value) -> bool {
    match key {
        "description" | "summary" | "title" => value.as_str().is_some(),
        "example" | "examples" => true,
        _ => false,
    }
}

/// The document's structure as one canonical text: object members in sorted order, prose
/// dropped, the `info` block (the release version and the document's own blurb) left out.
fn shape(value: &Value, parent: Option<&str>, out: &mut String) {
    if let Some(members) = value.as_object() {
        let names_members = matches!(parent, Some("properties" | "patternProperties"));
        let mut sorted: Vec<(&str, &Value)> = members
            .iter()
            .filter(|(key, member)| {
                !(parent == Some("") && *key == "info") && (names_members || !prose(key, member))
            })
            .collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        out.push('{');
        for (key, member) in sorted {
            out.push_str(&format!("{key:?}:"));
            shape(member, Some(key), out);
            out.push(',');
        }
        out.push('}');
    } else if let Some(items) = value.as_array() {
        out.push('[');
        for item in items.iter() {
            shape(item, None, out);
            out.push(',');
        }
        out.push(']');
    } else {
        out.push_str(&busbar_contract::json::to_string(value).unwrap_or_else(|_| "?".into()));
    }
}

fn committed_shape_digest() -> String {
    let bytes = std::fs::read(COMMITTED_OPENAPI).expect("read the committed openapi.json");
    let tree = busbar_contract::json::parse_value(&bytes).expect("the committed document parses");
    let mut canonical = String::new();
    shape(&tree, Some(""), &mut canonical);
    busbar_contract::redacted::sha256_hex(canonical.as_bytes())
}

#[test]
fn api_revision_moves_with_the_document_shape() {
    for (index, (revision, _)) in API_REVISION_DIGESTS.iter().enumerate() {
        assert_eq!(
            *revision as usize,
            index + 1,
            "revisions are consecutive from 1, one row each"
        );
    }
    for (index, (_, digest)) in API_REVISION_DIGESTS.iter().enumerate() {
        assert!(
            API_REVISION_DIGESTS[..index]
                .iter()
                .all(|(_, earlier)| earlier != digest),
            "two revisions cannot share one document shape ({digest})"
        );
    }
    let (revision, pinned) = API_REVISION_DIGESTS
        .last()
        .expect("at least revision 1 is pinned");
    assert_eq!(
        *revision,
        super::ADMIN_API_REVISION,
        "ADMIN_API_REVISION is the newest pinned revision"
    );
    let digest = committed_shape_digest();
    assert_eq!(
        digest,
        *pinned,
        "API_REVISION_DIGESTS: the committed openapi.json changed shape since revision {revision}. \
         Raise ADMIN_API_REVISION to {next} and append ({next}, \"{digest}\") to \
         API_REVISION_DIGESTS (description-only changes never land here)",
        next = revision + 1,
    );
}

#[test]
fn prose_does_not_move_the_revision_but_shape_does() {
    let base = busbar_contract::json::parse_value(
        br#"{"info":{"version":"1"},"paths":{"/a":{"get":{"summary":"s","description":"d","parameters":[{"name":"x","description":"p"}]}}},"components":{"schemas":{"A":{"title":"A","description":"a","properties":{"description":{"type":"string","description":"m"}},"example":{"description":"e"}}}}}"#,
    )
    .unwrap();
    let reworded = busbar_contract::json::parse_value(
        br#"{"info":{"version":"2","description":"new"},"paths":{"/a":{"get":{"summary":"S2","description":"D2","parameters":[{"name":"x","description":"P2"}]}}},"components":{"schemas":{"A":{"title":"A2","description":"a2","properties":{"description":{"type":"string","description":"m2"}},"example":{"other":1}}}}}"#,
    )
    .unwrap();
    let grown = busbar_contract::json::parse_value(
        br#"{"info":{"version":"1"},"paths":{"/a":{"get":{"summary":"s","description":"d","parameters":[{"name":"x","description":"p"}]}}},"components":{"schemas":{"A":{"title":"A","description":"a","properties":{"description":{"type":"string","description":"m"},"added":{"type":"integer"}},"example":{"description":"e"}}}}}"#,
    )
    .unwrap();
    let renamed_member = busbar_contract::json::parse_value(
        br#"{"info":{"version":"1"},"paths":{"/a":{"get":{"summary":"s","description":"d","parameters":[{"name":"x","description":"p"}]}}},"components":{"schemas":{"A":{"title":"A","description":"a","properties":{"summary":{"type":"string","description":"m"}},"example":{"description":"e"}}}}}"#,
    )
    .unwrap();
    let of = |tree: &Value| {
        let mut out = String::new();
        shape(tree, Some(""), &mut out);
        out
    };
    assert_eq!(of(&base), of(&reworded), "prose and info never move it");
    assert_ne!(of(&base), of(&grown), "an added member moves it");
    assert_ne!(
        of(&base),
        of(&renamed_member),
        "a member named like a prose keyword is shape"
    );
}
