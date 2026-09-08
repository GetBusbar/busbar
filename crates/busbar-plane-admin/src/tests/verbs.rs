//! Tests for `verbs.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// The root's view of a row and the plane's own view of it are the same row. If they ever
/// disagreed, a root would be binding a verb the codec never decodes to.
#[test]
fn the_public_table_is_the_same_table_the_codec_decodes_against() {
    let public = table();
    assert_eq!(public.len(), VERB_COUNT);
    for (row, entry) in public.iter().zip(all_verbs().iter()) {
        assert_eq!(row.verb, entry.verb);
        assert_eq!(row.method, entry.method);
        assert_eq!(row.template, entry.path);
        assert_eq!(row.read_only, entry.read_only);
        assert_eq!(
            row.op_class(),
            if entry.read_only { OP_READ } else { OP_WRITE }
        );
    }
}

/// A query string names arguments to an operation, not a different operation. The row a caller
/// resolves has to be the same one either way, or an admin request with a `?limit=` would be
/// an unsupported operation on a surface that has supported it since 1.5.5.
#[test]
fn resolve_reads_through_a_query_string_to_the_same_row() {
    let bare = resolve("GET", "/api/v1/admin/audit").expect("audit is in the table");
    let with_query =
        resolve("GET", "/api/v1/admin/audit?limit=4").expect("a query names arguments");
    assert_eq!(bare, with_query);
    assert_eq!(bare.verb, "get_audit");
    assert!(bare.read_only);
}

/// A pair the table does not declare has no answer. The point of a closed table is that its
/// silence is a refusal rather than a default.
#[test]
fn resolve_refuses_a_pair_the_table_does_not_declare() {
    assert!(resolve("GET", "/api/v1/admin/not-a-verb").is_none());
    assert!(resolve("TRACE", "/api/v1/admin/audit").is_none());
}

#[test]
fn table_has_exactly_the_rows_the_count_declares() {
    assert_eq!(all_verbs().len(), VERB_COUNT);
}

/// The amendment's wire shape, as the design names it: a `POST`, under the `/ledger/`
/// sub-prefix, on the full-scope side of the split.
///
/// The method is the load-bearing half. Every other row under `/ledger/` is a `GET`, and this
/// plane decides scope and rate class off the `read_only` column that the method decides — so a
/// row that reprices an already-invoiced window bound as a read would be reachable by a
/// credential that may only look, and would spend no mutation budget doing it.
#[test]
fn the_amendment_is_a_full_scope_post_under_the_ledger_prefix() {
    let row = resolve("POST", "/api/v1/admin/ledger/amend-rate-history")
        .expect("the design names this path");
    assert_eq!(row.verb, "amend_rate_history");
    assert!(!row.read_only, "an amendment is not a read");
    assert_eq!(row.op_class(), OP_WRITE);
    assert!(row.template.starts_with("/api/v1/admin/ledger/"));
    // The same path under a read method is not this operation, and the table invents nothing
    // for it.
    assert!(resolve("GET", "/api/v1/admin/ledger/amend-rate-history").is_none());
}

/// The five reads under the prefix are still five, and are still reads. The amendment joined
/// their prefix and not their rung.
#[test]
fn the_amendment_did_not_change_what_a_ledger_read_is() {
    assert_eq!(LEDGER_VERBS_1_6_0.len(), 5);
    for entry in LEDGER_VERBS_1_6_0 {
        assert_eq!(entry.method, "GET");
        assert!(entry.read_only);
        let row = resolve("GET", entry.path).expect("a declared read resolves");
        assert_eq!(row.op_class(), OP_READ);
        // A query string names arguments to a read, never a different one — the shape
        // `?as_of=` and `?currency=` will arrive as.
        assert_eq!(
            resolve("GET", &format!("{}?as_of=7", entry.path)),
            Some(row)
        );
    }
}

/// The additive rows never touch the pinned 66. The `/ledger/` prefix is 1.6.0-only surface, so
/// no row this change adds may carry a path the 1.5.5 document declares — otherwise a client
/// that fetched the pinned document before the upgrade would find an operation on a path it
/// believes it already knows.
#[test]
fn no_new_row_lands_on_a_path_the_pinned_document_declares() {
    let doc = fixture();
    let pinned: Vec<&str> = doc["paths"]
        .as_object()
        .expect("paths is an object")
        .keys()
        .map(String::as_str)
        .collect();
    for entry in NEW_VERBS_1_6_0.iter().chain(LEDGER_VERBS_1_6_0.iter()) {
        assert!(
            !pinned.contains(&entry.path),
            "{} lands on a path the pinned 1.5.5 document already declares",
            entry.path
        );
    }
    // and the pinned document declares no `/ledger/` path at all.
    assert!(
        !pinned.iter().any(|p| p.contains("/ledger/")),
        "the 1.5.5 document must carry no /ledger/ path"
    );
}

#[test]
fn matches_a_templated_path_and_captures_the_param() {
    let params = match_path("/api/v1/admin/keys/{id}", "/api/v1/admin/keys/abc123").unwrap();
    assert_eq!(params, vec![("id", "abc123")]);
}

#[test]
fn rejects_a_wrong_segment_count() {
    assert!(match_path("/api/v1/admin/keys/{id}", "/api/v1/admin/keys").is_none());
}

/// An empty segment is a segment. A trailing slash, a doubled slash and a bare `{id}` position
/// with nothing in it are three paths the mounted router does not carry, and the table may not
/// normalise any of them onto a row it does — a `DELETE` that revoked on `/keys/abc/` would be
/// a mutation on a request the previous release answers with its router's own 404.
#[test]
fn an_empty_segment_never_normalises_onto_a_row() {
    assert!(resolve("DELETE", "/api/v1/admin/keys/abc/").is_none());
    assert!(resolve("DELETE", "/api/v1/admin/keys/").is_none());
    assert!(resolve("DELETE", "/api/v1//admin/keys/abc").is_none());
    assert!(resolve("GET", "/api/v1/admin/audit/").is_none());
    // and the paths the table DOES declare still resolve, so the check above is a filter and
    // not a wall.
    assert!(resolve("DELETE", "/api/v1/admin/keys/abc").is_some());
    assert!(resolve("GET", "/api/v1/admin/audit").is_some());
    assert!(resolve("GET", "/api/v1/admin/audit?limit=4").is_some());
}

#[test]
fn find_verb_resolves_a_concrete_request() {
    let (entry, params) = find_verb("GET", "/api/v1/admin/keys/xyz").expect("matches");
    assert_eq!(entry.verb, "get_keys_id");
    assert_eq!(params, vec![("id", "xyz")]);
}

/// The pinned fixture, parsed once per test that reads it.
fn fixture() -> serde_json::Value {
    let text = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testing/shadow-oracle/fixtures/openapi-1.5.5.json"
    ));
    serde_json::from_str(text).expect("fixture is valid JSON")
}

/// Follow a document-local `$ref` chain to the schema it names.
fn deref<'d>(doc: &'d serde_json::Value, mut node: &'d serde_json::Value) -> &'d serde_json::Value {
    while let Some(pointer) = node.get("$ref").and_then(serde_json::Value::as_str) {
        node = doc
            .pointer(pointer.trim_start_matches('#'))
            .expect("a document-local $ref resolves");
    }
    node
}

/// Every representative body field this plane extracts is a member the pinned schema declares.
///
/// The extraction writes a decode-time fact under the field's own name, so a field the schema
/// has no member for is a fact key that can never be set — a documented promise the wire cannot
/// keep, and one nobody would notice, because an absent fact and an unpopulated one look the
/// same downstream. This reads the fixture rather than a second transcription of it.
#[test]
fn every_documented_body_field_is_a_member_the_pinned_schema_declares() {
    let doc = fixture();
    let mut checked = 0usize;
    for (path, item) in doc["paths"].as_object().expect("paths is an object") {
        for (method, op) in item.as_object().expect("path item is an object") {
            let verb = snake_case(op["operationId"].as_str().expect("an operationId"));
            let Some(field) = documented_body_field(&verb) else {
                continue;
            };
            let body = op.get("requestBody").unwrap_or_else(|| {
                panic!("{verb}: a documented body field on an operation with no request body")
            });
            let schema = deref(&doc, body)["content"]["application/json"]["schema"].clone();
            let properties = deref(&doc, &schema)
                .get("properties")
                .and_then(serde_json::Value::as_object)
                .unwrap_or_else(|| {
                    panic!("{verb}: {} {path} takes a body with no named members, so no field of it can be documented", method.to_uppercase())
                });
            assert!(
                properties.contains_key(field),
                "{verb}: the documented field `{field}` is not a member of the pinned schema (it declares {:?})",
                properties.keys().collect::<Vec<_>>()
            );
            checked += 1;
        }
    }
    assert_eq!(
        checked, 15,
        "every documented body field belongs to a 1.5.5 operation the fixture declares"
    );
}

/// Mechanically converts a `PascalCase` `operationId` (`GetKeysIdUsage`) to this crate's own
/// `snake_case` verb name (`get_keys_id_usage`), so the fixture test below can compute the
/// expected verb name rather than hand-transcribing a second copy of the 66-row mapping.
fn snake_case(operation_id: &str) -> String {
    let mut out = String::new();
    for (i, c) in operation_id.chars().enumerate() {
        if c.is_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The table test required by the crate's design brief: for every one of the 66 operations the
/// pinned `testing/shadow-oracle/fixtures/openapi-1.5.5.json` fixture declares, `find_verb`
/// resolves the right verb name and the right (`read_only`) scope. This is the boundary check
/// that the closed table in this module (transcribed by hand from the same fixture) has not
/// drifted from it.
///
/// The scope comes off the fixture's own `x-busbar-required-scope` column, which is the pinned
/// tag's answer. It used to be RE-DERIVED here from the method plus two hand-listed path
/// exceptions — a rule that happens to agree with the column today and is not the column: a
/// seventh read-only `POST` added to the tag would have been checked against this file's
/// reading of 1.5.5 rather than against 1.5.5.
#[test]
fn every_1_5_5_fixture_operation_resolves_to_the_right_verb_and_scope() {
    let doc = fixture();
    let paths = doc["paths"].as_object().expect("paths is an object");

    let mut checked = 0usize;
    let mut read_only_rows = 0usize;
    for (path, methods) in paths {
        let methods = methods.as_object().expect("path item is an object");
        for (method, op) in methods {
            let method = method.to_uppercase();
            let operation_id = op["operationId"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} has no operationId"));
            let expected_verb = snake_case(operation_id);
            let expected_read_only = match op["x-busbar-required-scope"].as_str() {
                Some("read-only") => true,
                Some("full") => false,
                other => {
                    panic!("{method} {path} declares no scope this plane knows: {other:?}")
                }
            };
            read_only_rows += usize::from(expected_read_only);

            let (entry, _) = find_verb(&method, path).unwrap_or_else(|| {
                panic!("no table row matches fixture operation {method} {path}")
            });
            assert_eq!(
                entry.verb, expected_verb,
                "{method} {path}: table verb does not match the fixture's operationId"
            );
            assert_eq!(
                entry.read_only, expected_read_only,
                "{method} {path}: table scope does not match the fixture's pinned x-busbar-required-scope"
            );
            checked += 1;
        }
    }
    assert_eq!(
        checked, 66,
        "the pinned fixture must declare exactly 66 operations"
    );
    assert_eq!(
        read_only_rows, 34,
        "the pinned tag's own column splits the 66 as 34 read-only / 32 full"
    );
}
