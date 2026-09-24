//! Tests for `verbs.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// The root's view of a row and this module's own view of it are the same row. If they ever
/// disagreed, a root would be binding a verb the table does not hold.
#[test]
fn the_public_table_is_the_same_table_the_lookup_runs_against() {
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
                    panic!("{method} {path} declares no scope this table knows: {other:?}")
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

/// ITEM 149 — THE GATE AND THE VERB TABLE AGREE ON EVERY ADMIN ROUTE.
///
/// Three answers exist for "what scope does this admin operation need": the live gate's (method,
/// path) matrix (`busbar_kernel::admin::v1::contract::required_scope`, the 1.5.5 rule the auth
/// middleware and the admin units' approve step enforce), this table's per-row `read_only`, and the
/// verbs unit's `verbs::required_scope(verb)`. For every row the closed table declares, all three
/// must name the same rung. `POST /api/v1/admin/verify` was the one row where they did not: the gate
/// demanded `full` of a verb the unit answers `read-only` for, refusing a read-only operator.
#[test]
fn the_live_gate_and_the_verb_table_agree_on_every_admin_route() {
    use crate::verb::{verb_name, AUDIT_VERBS, LEDGER_VERBS, LEGACY_VERBS, NEW_VERBS};
    let kernel_verb = |entry: &VerbEntry| {
        LEGACY_VERBS
            .iter()
            .find(|r| r.method == entry.method && r.path == entry.path)
            .map(|r| r.verb)
            .or_else(|| {
                NEW_VERBS
                    .iter()
                    .chain(LEDGER_VERBS)
                    .chain(AUDIT_VERBS)
                    .copied()
                    .find(|v| verb_name(*v) == Some(entry.verb))
            })
            .unwrap_or_else(|| panic!("{} {}: no kernel verb", entry.method, entry.path))
    };
    let mut checked = 0usize;
    let mut disagreements = Vec::new();
    for entry in all_verbs() {
        let method = axum::http::Method::from_bytes(entry.method.as_bytes()).expect("a method");
        let gate = busbar_kernel::admin::v1::contract::required_scope(&method, entry.path);
        let gate_read_only = gate == busbar_kernel::admin::v1::contract::Scope::ReadOnly;
        let unit_read_only =
            crate::verbs::required_scope(kernel_verb(entry)) == crate::verb::VerbScope::ReadOnly;
        if gate_read_only != entry.read_only || gate_read_only != unit_read_only {
            disagreements.push(format!(
                "{} {}: gate read_only={gate_read_only}, table read_only={}, verbs unit read_only={unit_read_only}",
                entry.method, entry.path, entry.read_only
            ));
        }
        checked += 1;
    }
    assert_eq!(checked, VERB_COUNT, "every declared admin route is checked");
    assert!(
        disagreements.is_empty(),
        "the live admin gate and the verb table disagree:\n{}",
        disagreements.join("\n")
    );
    // The row this item moved: `verify` is the architecture's `GET`, and no `POST` row names it.
    assert_eq!(
        resolve("GET", "/api/v1/admin/verify").map(|r| r.verb),
        Some("verify")
    );
    assert!(resolve("POST", "/api/v1/admin/verify").is_none());
}
