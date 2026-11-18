// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `openapi-diff`: each breaking change is found, each additive change passes, and the committed
//! admin document differs from itself by nothing.

use busbar_contract::json;

use crate::diff::breaking_changes;

fn doc(text: &str) -> json::Value {
    json::parse_str(text).expect("a fixture document")
}

fn changes(old: &str, new: &str) -> Vec<String> {
    breaking_changes(&doc(old), &doc(new))
}

const BASE: &str = r##"{"paths":{"/a":{"get":{"operationId":"GetA","x-busbar-required-scope":"read-only",
"parameters":[{"name":"limit","in":"query","required":false,"schema":{"type":"integer"}}],
"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/A"}}}},
"401":{"description":"no"}}},
"post":{"operationId":"PostA","x-busbar-required-scope":"full",
"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/In"}}}},
"responses":{"200":{"description":"ok"}}}}},
"components":{"schemas":{
"A":{"type":"object","required":["id"],"properties":{"id":{"type":"string"},"kind":{"type":"string","enum":["x","y"]}}},
"In":{"type":"object","required":["name"],"properties":{"name":{"type":"string"},"note":{"type":"string"}}}}}}"##;

#[test]
fn a_document_differs_from_itself_by_nothing() {
    assert_eq!(changes(BASE, BASE), Vec::<String>::new());
}

#[test]
fn a_removed_operation_is_found() {
    let new = BASE.replace(
        r#""post":{"operationId":"PostA""#,
        r#""x-gone":{"operationId":"PostA""#,
    );
    let found = changes(BASE, &new);
    assert!(
        found
            .iter()
            .any(|c| c.contains("post /a") && c.contains("removed")),
        "{found:?}"
    );
}

#[test]
fn a_removed_path_is_found() {
    let new = BASE.replace(r#""/a":"#, r#""/b":"#);
    let found = changes(BASE, &new);
    assert!(
        found
            .iter()
            .any(|c| c.contains("/a") && c.contains("removed")),
        "{found:?}"
    );
}

#[test]
fn a_changed_operation_id_is_found() {
    let found = changes(BASE, &BASE.replace("GetA", "GetAgain"));
    assert!(found.iter().any(|c| c.contains("operationId")), "{found:?}");
}

#[test]
fn a_removed_response_status_is_found() {
    // BASE breaks its line before `"401"` (1316ef513a), so the removal names that line break too.
    let found = changes(
        BASE,
        &BASE.replace(",\n\"401\":{\"description\":\"no\"}", ""),
    );
    assert!(
        found
            .iter()
            .any(|c| c.contains("401") && c.contains("removed")),
        "{found:?}"
    );
}

#[test]
fn a_raised_required_scope_is_found() {
    let new = BASE.replacen(
        r#""x-busbar-required-scope":"read-only""#,
        r#""x-busbar-required-scope":"full""#,
        1,
    );
    let found = changes(BASE, &new);
    assert!(found.iter().any(|c| c.contains("scope")), "{found:?}");
}

#[test]
fn a_newly_required_request_property_is_found() {
    let new = BASE.replace(r#""required":["name"]"#, r#""required":["name","note"]"#);
    let found = changes(BASE, &new);
    assert!(
        found
            .iter()
            .any(|c| c.contains("note") && c.contains("required")),
        "{found:?}"
    );
}

#[test]
fn a_removed_response_property_is_found() {
    let new = BASE.replace(r#","kind":{"type":"string","enum":["x","y"]}"#, "");
    let found = changes(BASE, &new);
    assert!(
        found
            .iter()
            .any(|c| c.contains("kind") && c.contains("removed")),
        "{found:?}"
    );
}

#[test]
fn a_removed_enum_value_is_found() {
    let found = changes(BASE, &BASE.replace(r#"["x","y"]"#, r#"["x"]"#));
    assert!(
        found
            .iter()
            .any(|c| c.contains("enum") && c.contains("\"y\"")),
        "{found:?}"
    );
}

#[test]
fn a_narrowed_type_is_found() {
    let new = BASE.replace(
        r#""name":{"type":"string"}"#,
        r#""name":{"type":"integer"}"#,
    );
    let found = changes(BASE, &new);
    assert!(
        found
            .iter()
            .any(|c| c.contains("name") && c.contains("type")),
        "{found:?}"
    );
}

#[test]
fn a_new_required_parameter_is_found() {
    let new = BASE.replace(r#""required":false"#, r#""required":true"#);
    let found = changes(BASE, &new);
    assert!(
        found
            .iter()
            .any(|c| c.contains("limit") && c.contains("required")),
        "{found:?}"
    );
}

#[test]
fn a_removed_parameter_is_found() {
    let new = BASE.replace(r#""parameters":[{"name":"limit","in":"query","required":false,"schema":{"type":"integer"}}],"#, "");
    let found = changes(BASE, &new);
    assert!(
        found
            .iter()
            .any(|c| c.contains("limit") && c.contains("removed")),
        "{found:?}"
    );
}

#[test]
fn additive_changes_pass() {
    let new = BASE
        .replace(r#"["x","y"]"#, r#"["x","y","z"]"#)
        .replace(r#""note":{"type":"string"}"#, r#""note":{"type":"string"},"extra":{"type":"string"}"#)
        .replace(r#""id":{"type":"string"},"#, r#""id":{"type":"string"},"more":{"type":"string"},"#)
        .replace(r#""401":{"description":"no"}"#, r#""401":{"description":"no"},"429":{"description":"slow"}"#)
        .replace(r#""/a":"#, r#""/new":{"get":{"operationId":"GetNew","responses":{"200":{"description":"ok"}}}},"/a":"#);
    assert_eq!(changes(BASE, &new), Vec::<String>::new());
}

#[test]
fn a_recursive_schema_terminates() {
    let recursive = r##"{"paths":{"/t":{"get":{"operationId":"T","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/N"}}}}}}}},
"components":{"schemas":{"N":{"type":"object","properties":{"next":{"$ref":"#/components/schemas/N"},"v":{"type":"string"}}}}}}"##;
    assert_eq!(changes(recursive, recursive), Vec::<String>::new());
    let narrowed = recursive.replace(r#""v":{"type":"string"}"#, r#""v":{"type":"integer"}"#);
    assert!(!changes(recursive, &narrowed).is_empty());
}

#[test]
fn the_committed_admin_document_differs_from_itself_by_nothing() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/busbar-core-admin/src/v1/json/openapi.json");
    let text = std::fs::read(&path).expect("the committed document");
    let document = json::parse_value(&text).expect("it parses");
    assert_eq!(breaking_changes(&document, &document), Vec::<String>::new());
}
