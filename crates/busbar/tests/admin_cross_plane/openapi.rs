// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The OpenAPI document's tests that read the plane operations it documents (moved from
//! busbar-core-admin's `src/v1/json/tests/tests.rs`, assertions unchanged).

use busbar_core_admin::test_support::openapi_doc;

/// Every operation carries a stable `operationId`,
/// PascalCase METHOD+path (`GetKeysId`, `PostKeysIdRotate`, …), so third-party generators (Go/TS)
/// get a method name that does not churn when a path is touched. Locks presence, uniqueness, and
/// the exact naming scheme busbar-ui's own `scripts/openapi-prep.py::op_id` synthesizes — so a spec
/// generated here and one synthesized client-side always agree.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_operations_carry_stable_operation_ids() {
    use std::collections::HashMap;
    let doc = openapi_doc_seamed();
    let paths = doc["paths"].as_object().expect("paths object");
    let mut seen: HashMap<String, (String, String)> = HashMap::new();
    let mut checked = 0usize;
    for (path, methods) in paths {
        for (method, op) in methods.as_object().expect("methods") {
            if !matches!(method.as_str(), "get" | "post" | "put" | "patch" | "delete") {
                continue;
            }
            let oid = op["operationId"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} missing operationId"));
            assert!(!oid.is_empty(), "{method} {path} has an empty operationId");
            if let Some((prev_method, prev_path)) =
                seen.insert(oid.to_string(), (method.clone(), path.clone()))
            {
                panic!("operationId {oid} collides: {prev_method} {prev_path} vs {method} {path}");
            }
            checked += 1;
        }
    }
    // 81 = 66 + the five generic named-map routes EACH of the two compiled-in plane sections adds
    // (`tools:` and `agents:`) + the plane-specific trust verbs each section layers on top of the
    // generic named-map shape: three trust verbs on one section (`POST .../connect`,
    // `GET .../changes`, `GET .../health`) and two on the other (`POST .../connect`,
    // `POST .../approve`), which are specific to their section rather than part of the generic
    // named-map shape. The count is a FLOOR-and-CEILING on purpose: a route added without a stable
    // `operationId`, and a route silently removed, both land here.
    //
    // This assertion is why the two plane sections could not land on `dev` independently without
    // one of them noticing the other: 76 was correct for either section alone and wrong for both
    // together.
    //
    // 101 = those 81 + the 20 operations the 1.6.0 closed verb table adds, every one with its
    // effect bound since owner answer Q71(2) (9 money-governance verbs, 5 ledger views, 3
    // audit-chain reads) and the ARCHITECT's 2026-10-06 trust verbs (`GET /trust`,
    // `POST /trust/approve`, `POST /trust/revoke`), which the node's administrative loop answers
    // and which the one document describes (items 45/46: no side-car document).
    assert_eq!(checked, 101, "expected exactly 101 admin operations");
    // Spot-check the exact naming scheme against a few representative paths.
    assert_eq!(
        doc["paths"]["/api/v1/admin/keys"]["get"]["operationId"],
        "GetKeys"
    );
    assert_eq!(
        doc["paths"]["/api/v1/admin/keys/{id}/rotate"]["post"]["operationId"],
        "PostKeysIdRotate"
    );
    assert_eq!(
        doc["paths"]["/api/v1/admin/plugins/{file}/schema"]["get"]["operationId"],
        "GetPluginsFileSchema"
    );
    assert_eq!(
        doc["paths"]["/api/v1/admin/admin-auth"]["put"]["operationId"],
        "PutAdminAuth"
    );
}

/// The committed static OpenAPI document the LIVE handler serves (via `include_str!`). The release
/// binary can't regenerate it (schemars is CI-only), so this path is what every build ships.
#[cfg(feature = "openapi-schema")]
const COMMITTED_OPENAPI_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../busbar-core-admin/src/v1/json/openapi.json"
);

/// Serialize the doc the way it is committed: pretty-printed + a trailing newline (POSIX text file).
#[cfg(feature = "openapi-schema")]
fn render_committed_openapi() -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(&openapi_doc_seamed()).expect("serialize openapi doc")
    )
}

/// SEAM PRECONDITION for every openapi test: `openapi_doc()` reads the process-global plane registry,
/// which is populated by `crate::ensure_seam()` (the LLM/MCP/A2A plane decls that contribute the
/// `tools:`/`agents:` admin trust-verb operations). Only `openapi_json_matches_committed_file` used to
/// install it, so any OTHER openapi test that read the document before that test's `ensure_seam()`
/// happened to run first saw a PLANE-LESS document (5 operations short) — deterministic single-threaded
/// (definition order), but a race under `--test-threads > 1`. `ensure_seam()` is `Once`-guarded and
/// idempotent, so routing every read through this helper makes the document plane-complete regardless
/// of harness thread count or test order. (Test-harness setup, not a production ordering bug — the
/// composition root installs the planes before the binary ever serves the document.)
#[cfg(feature = "openapi-schema")]
pub(crate) fn openapi_doc_seamed() -> serde_json::Value {
    crate::ensure_seam();
    openapi_doc()
}

/// GOLDEN + DRIFT GUARD: the committed `openapi.json` (served live via `include_str!`) MUST equal the
/// document `openapi_doc()` generates right now. Run with `UPDATE_OPENAPI=1` to REGENERATE the file
/// (after an intentional contract change); otherwise this asserts byte-equality, so the static file
/// the release binary serves can never silently drift from the typed route contract in code.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_json_matches_committed_file() {
    // Register the plane decls so `openapi_doc()` includes each plane's admin trust-verb operations
    // and `openapi_schemas` — busbar-core's own `cfg(test)` binary had them as builtins; a
    // test-support consumer must install the plane testkits first, or the generated document drops
    // the `tools:`/`agents:` operations the committed file has.
    crate::ensure_seam();
    let fresh = render_committed_openapi();
    if std::env::var("UPDATE_OPENAPI").is_ok_and(|v| v == "1") {
        std::fs::write(COMMITTED_OPENAPI_PATH, &fresh)
            .unwrap_or_else(|e| panic!("write {COMMITTED_OPENAPI_PATH}: {e}"));
        // The gz twin the binary embeds, DETERMINISTIC (mtime 0, fixed level) so the same
        // contract always produces the same committed bytes.
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        std::io::Write::write_all(&mut enc, fresh.as_bytes()).expect("gz write");
        let gz = enc.finish().expect("gz finish");
        std::fs::write(format!("{COMMITTED_OPENAPI_PATH}.gz"), gz)
            .unwrap_or_else(|e| panic!("write {COMMITTED_OPENAPI_PATH}.gz: {e}"));
        return;
    }
    let committed = std::fs::read_to_string(COMMITTED_OPENAPI_PATH)
        .unwrap_or_else(|e| panic!("read {COMMITTED_OPENAPI_PATH}: {e}"));
    assert_eq!(
        committed, fresh,
        "committed openapi.json is stale — regenerate with `UPDATE_OPENAPI=1 cargo test -p busbar \
         --features openapi-schema openapi_json_matches_committed_file`"
    );
}

/// The mirror of the response drift test, for REQUEST bodies. Every mutating operation must either
/// declare a `requestBody` whose schema resolves, or be named in `BODYLESS` — so an operation can
/// never escape coverage by being silently omitted, which is exactly how all 26 came to document
/// no body at all.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_every_mutating_operation_declares_a_request_body() {
    /// Operations that take NO body. Each is a pure command: the target rides the path, and
    /// optimistic concurrency rides `If-Match`.
    const BODYLESS: &[(&str, &str)] = &[
        ("post", "/api/v1/admin/config/reload"),
        ("post", "/api/v1/admin/plugins/reload"),
        ("post", "/api/v1/admin/signing-key/rotate"),
        ("post", "/api/v1/admin/keys/{id}/revoke"),
        ("post", "/api/v1/admin/keys/{id}/rotate"),
        ("delete", "/api/v1/admin/groups/{name}"),
        ("delete", "/api/v1/admin/hooks/{name}"),
        ("delete", "/api/v1/admin/keys/{id}"),
        ("delete", "/api/v1/admin/overlay/{section}"),
        ("delete", "/api/v1/admin/plugins/{file}"),
        // The generic named-DEFINITION map deletes: the target rides the path, the guard rides
        // `If-Match`. Enumerated per section so a new section shows up here as a deliberate edit.
        ("delete", "/api/v1/admin/identity-providers/{name}"),
        ("delete", "/api/v1/admin/export/{name}"),
        ("delete", "/api/v1/admin/tools/{name}"),
        ("delete", "/api/v1/admin/agents/{name}"),
        // The `tools:` section's connect trust verb. It is a pure command in the same sense as the
        // deletes above: the entry to re-observe rides the path, and the handler takes `State`,
        // `Extension` and `Path` — no body extractor. There is nothing a caller could put in a body
        // that would change what it does, so documenting one would describe a parameter that does
        // not exist.
        ("post", "/api/v1/admin/tools/{name}/connect"),
        // The `agents:` section's PREVIEW trust verb, bodyless for the same reason: the entry to
        // look at rides the path, and there is nothing a caller could put in a body that would
        // change what it does. Its sibling `POST /agents/{name}/approve` is NOT here — that one
        // carries the fingerprint the operator is attesting they saw, which is the whole trust root.
        ("post", "/api/v1/admin/agents/{name}/connect"),
        // The 1.6.0 kernel verbs whose body the node's administrative loop never reads: the two
        // recovery verbs are pure commands (the effect is the store's; the verb IS the argument).
        // Their siblings that DO take one — `store-restore` (`backup_ref`), `adjust` (the count
        // correction) and `ledger/amend-rate-history` (the signed correction) — are not here; the
        // verbs with no effect bound are not served, so not documented at all.
        ("post", "/api/v1/admin/chain-break"),
        ("post", "/api/v1/admin/reseal-epoch-floor"),
    ];

    let doc = openapi_doc_seamed();
    let schemas = doc["components"]["schemas"].as_object().expect("schemas");
    let paths = doc["paths"].as_object().expect("paths");
    let mut declared = 0usize;
    let mut bodyless_seen = Vec::new();

    for (path, methods) in paths {
        for (method, op) in methods.as_object().expect("methods") {
            if method.starts_with("x-") || method == "get" {
                continue;
            }
            let listed = BODYLESS.contains(&(method.as_str(), path.as_str()));
            let body = op.get("requestBody");
            if listed {
                assert!(
                    body.is_none(),
                    "{method} {path} is declared bodyless but documents a requestBody"
                );
                bodyless_seen.push((method.clone(), path.clone()));
                continue;
            }
            let body = body.unwrap_or_else(|| {
                panic!(
                    "{method} {path} documents no requestBody and is not declared bodyless — a \
                     client cannot construct a call to it"
                )
            });
            let schema = &body["content"]["application/json"]["schema"];
            // Either a component `$ref` (derived from the request struct) or an inline object
            // schema (the config-carrying bodies, which are declared by hand on purpose).
            if let Some(reference) = schema["$ref"].as_str() {
                let name = reference
                    .strip_prefix("#/components/schemas/")
                    .unwrap_or_else(|| {
                        panic!("{method} {path} $ref is not a component: {reference}")
                    });
                assert!(
                    schemas.contains_key(name),
                    "{method} {path} references undefined component {name}"
                );
            } else {
                assert_eq!(
                    schema["type"], "object",
                    "{method} {path} requestBody must be a $ref or an object schema"
                );
            }
            declared += 1;
        }
    }

    assert_eq!(
        bodyless_seen.len(),
        BODYLESS.len(),
        "every BODYLESS entry must name a real operation; saw {bodyless_seen:?}"
    );
    assert_eq!(
        declared, 34,
        "34 mutating operations take a body; a change here is a deliberate API change. 34 = 22 \
         + each plane section's PUT and PATCH-settings (both DELETEs are bodyless, above) + the \
         agents plane's approve verb, whose body carries the fingerprint the \
         operator is attesting they read + the seven 1.6.0 kernel verbs that read one \
         (`store-restore`, `adjust`, `ledger/amend-rate-history`, since owner answer Q71(2) \
         `plane-record-write` and `commit-upgrade`, and the ARCHITECT's 2026-10-06 \
         `trust/approve` and `trust/revoke`, whose body names the trust key)"
    );
}
