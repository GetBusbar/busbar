use super::*;

/// Collect an axum Response into (status, content-type, parsed JSON body) for the wire-helper
/// micro-tests below.
async fn parts(resp: Response) -> (StatusCode, String, serde_json::Value) {
    let status = resp.status();
    let ct = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    use http_body_util::BodyExt;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).expect("body is JSON");
    (status, ct, body)
}

/// The error envelope projection is `{"error":{"code","message"}}` with the error's status — the
/// shape v1 tooling parses — served as application/json.
#[tokio::test]
async fn err_json_uses_stable_envelope() {
    let (status, ct, body) = parts(err_json(&AdminError::not_found("hook"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(ct, crate::proxy::APPLICATION_JSON);
    assert_eq!(body["error"]["code"], "not_found");
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|m| !m.is_empty()),
        "message is human text, never empty"
    );
    assert_eq!(
        body["error"].as_object().unwrap().len(),
        2,
        "the envelope is exactly code+message (additive changes go OUTSIDE error)"
    );
}

/// `ok_json` serializes the view verbatim with the GIVEN status and application/json.
#[tokio::test]
async fn ok_json_serializes_view_with_given_status() {
    #[derive(Serialize)]
    struct View {
        name: &'static str,
        n: u32,
    }
    let (status, ct, body) = parts(ok_json(StatusCode::CREATED, &View { name: "x", n: 7 })).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(ct, crate::proxy::APPLICATION_JSON);
    assert_eq!(body, json!({"name": "x", "n": 7}));
}

/// `respond` — the single seam every v1 handler funnels through — maps Ok to the given status
/// and Err to the error's own status + envelope (the Ok-status never leaks onto an error).
#[tokio::test]
async fn respond_maps_ok_and_err() {
    let ok: Result<serde_json::Value, AdminError> = Ok(json!({"ok": true}));
    let (status, _, body) = parts(respond(StatusCode::OK, ok)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);

    let err: Result<serde_json::Value, AdminError> = Err(AdminError::RateLimited);
    let (status, _, body) = parts(respond(StatusCode::OK, err)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "rate_limited");
}

/// Structural lock on the discovery doc: OpenAPI 3.1, an info.version that matches the crate,
/// and every path under the ONE contract prefix (whose literal value is pinned by the golden
/// test in contract.rs) — the doc never mixes prefixes.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_doc_is_31_and_v1_prefixed() {
    let doc = openapi_doc();
    assert!(
        doc["openapi"].as_str().unwrap().starts_with("3.1"),
        "discovery doc is OpenAPI 3.1"
    );
    assert_eq!(doc["info"]["version"], env!("CARGO_PKG_VERSION"));
    let prefix = format!("{}/", crate::admin::v1::contract::ADMIN_PREFIX);
    for path in doc["paths"].as_object().unwrap().keys() {
        assert!(
            path.starts_with(&prefix),
            "{path} escaped the frozen {prefix} prefix"
        );
    }
}

/// Release tooling, not a behavioral assertion. Publishing the OpenAPI schema is a release chore
/// WE do — an operator gets the doc from the live `GET /openapi.json` endpoint or the release
/// asset, so it earns no user-facing CLI surface. This test is the build-time handle CI uses to
/// capture the artifact straight from the same `openapi_doc()` the gateway serves, guaranteeing the
/// published file matches the shipped binary. A normal `cargo test` (no env var) just re-asserts
/// the doc is well-formed; the release workflow sets `BUSBAR_EMIT_OPENAPI=<path>` to also write the
/// pretty-printed document there, then uploads it to the GitHub Release.
#[cfg(feature = "openapi-schema")]
#[test]
fn emit_openapi_artifact() {
    let doc = openapi_doc();
    assert!(
        doc["openapi"]
            .as_str()
            .unwrap_or_default()
            .starts_with("3.1"),
        "OpenAPI document must be 3.1"
    );
    if let Ok(path) = std::env::var("BUSBAR_EMIT_OPENAPI") {
        let json = serde_json::to_string_pretty(&doc).expect("serialize OpenAPI document");
        std::fs::write(&path, json).unwrap_or_else(|e| panic!("write {path}: {e}"));
    }
}

/// CONTRACT LOCK: every openapi path+method is annotated with `x-busbar-required-scope`, and
/// the annotation matches the enforced `required_scope` matrix exactly (one source of truth —
/// this test guards against a future hand-written path entry forgetting or contradicting it).
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_paths_annotate_required_scope() {
    // Re-derives `required_scope`'s decision INDEPENDENTLY (not by calling it) so a change to the
    // production matrix moves only the annotation side, not this expectation — `required_scope` is
    // the single producer that stamps BOTH the OpenAPI annotation (`handlers.rs`'s stamping loop)
    // and enforces the auth middleware, so comparing the annotation against a call to that same
    // function is a tautology: editing the matrix moves both sides together and can never fail.
    fn expected_scope(method: &str, path: &str) -> &'static str {
        use crate::admin::v1::contract::{
            ADMIN_PREFIX, PATH_CONFIG_VALIDATE, PATH_HOOKS, PATH_KEYS,
        };
        if method == "get" || method == "head" {
            return "read-only";
        }
        let is_mutation = matches!(method, "post" | "put" | "patch" | "delete");
        let rel = path.strip_prefix(ADMIN_PREFIX).unwrap_or(path);
        if rel == PATH_CONFIG_VALIDATE {
            return "read-only";
        }
        if is_mutation && (rel == PATH_HOOKS || rel.starts_with("/hooks/")) {
            return "hooks-register";
        }
        if method == "post" && rel == PATH_KEYS {
            return "mint";
        }
        "full"
    }

    let doc = openapi_doc();
    let paths = doc["paths"].as_object().expect("paths object");
    assert!(!paths.is_empty());
    let mut checked = 0usize;
    for (path, methods) in paths {
        for (method, op) in methods.as_object().expect("methods") {
            match method.as_str() {
                "get" | "post" | "put" | "patch" | "delete" => {}
                // Path-item `x-*` specification extensions (e.g. `x-busbar-error-envelope`) are
                // valid OpenAPI and are not operations — they carry no scope annotation.
                ext if ext.starts_with("x-") => continue,
                other => panic!("unexpected method {other} on {path}"),
            };
            let annotated = op["x-busbar-required-scope"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} missing scope annotation"));
            let golden = expected_scope(method, path);
            assert_eq!(
                annotated, golden,
                "{method} {path} annotation drifted from the independently-derived golden scope"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no operations were checked");
}

/// E-004 item 1 (busbar-ui/docs/ENGINE-BUGS.md): every operation carries a stable `operationId`,
/// PascalCase METHOD+path (`GetKeysId`, `PostKeysIdRotate`, …), so third-party generators (Go/TS)
/// get a method name that does not churn when a path is touched. Locks presence, uniqueness, and
/// the exact naming scheme busbar-ui's own `scripts/openapi-prep.py::op_id` synthesizes — so a spec
/// generated here and one synthesized client-side always agree.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_operations_carry_stable_operation_ids() {
    use std::collections::HashMap;
    let doc = openapi_doc();
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
    assert_eq!(checked, 55, "expected exactly 55 admin operations");
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

/// CONTRACT LOCK: the openapi Error-schema `code` enum must EXACTLY match the frozen `AdminError`
/// codes — no drift between the discovery doc and the taxonomy tooling actually receives. Every
/// variant's `code()` must appear in the enum, and the enum must list nothing else.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_error_enum_matches_admin_error_codes() {
    use std::collections::BTreeSet;
    let doc = openapi_doc();
    let enum_codes: BTreeSet<String> = doc["components"]["schemas"]["Error"]["properties"]["error"]
        ["properties"]["code"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    // The exhaustive set of AdminError codes — kept in lock-step with `AdminError::code`.
    let actual_codes: BTreeSet<String> = [
        AdminError::not_found(""),
        AdminError::Unauthorized,
        AdminError::Forbidden {
            needed: crate::admin::v1::contract::Scope::Full,
        },
        AdminError::MethodNotAllowed,
        AdminError::Validation(String::new()),
        AdminError::VersionConflict(String::new()),
        AdminError::Conflict(String::new()),
        AdminError::RateLimited,
        AdminError::Internal,
    ]
    .iter()
    .map(|e| e.code().to_string())
    .collect();
    assert_eq!(
        enum_codes, actual_codes,
        "openapi error-code enum drifted from AdminError::code"
    );
}

/// The escalation 403 fires on PUT `/hooks/{name}` and PATCH
/// `/hooks/{name}/settings` (a `hooks-register` principal touching a content-seeing / global
/// hook), exactly as it does on POST `/hooks` — so all three must DOCUMENT the 403.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_hook_escalation_endpoints_document_403() {
    let doc = openapi_doc();
    let cases = [
        ("/api/v1/admin/hooks", "post"),
        ("/api/v1/admin/hooks/{name}", "put"),
        ("/api/v1/admin/hooks/{name}", "delete"),
        ("/api/v1/admin/hooks/{name}/settings", "patch"),
    ];
    for (path, method) in cases {
        assert!(
            doc["paths"][path][method]["responses"]["403"].is_object(),
            "{method} {path} can 403 on escalation but its openapi omits it"
        );
    }
}

/// The committed static OpenAPI document the LIVE handler serves (via `include_str!`). The release
/// binary can't regenerate it (schemars is CI-only), so this path is what every build ships.
#[cfg(feature = "openapi-schema")]
const COMMITTED_OPENAPI_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/admin/v1/json/openapi.json"
);

/// Serialize the doc the way it is committed: pretty-printed + a trailing newline (POSIX text file).
#[cfg(feature = "openapi-schema")]
fn render_committed_openapi() -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(&openapi_doc()).expect("serialize openapi doc")
    )
}

/// GOLDEN + DRIFT GUARD: the committed `openapi.json` (served live via `include_str!`) MUST equal the
/// document `openapi_doc()` generates right now. Run with `UPDATE_OPENAPI=1` to REGENERATE the file
/// (after an intentional contract change); otherwise this asserts byte-equality, so the static file
/// the release binary serves can never silently drift from the typed route contract in code.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_json_matches_committed_file() {
    let fresh = render_committed_openapi();
    if std::env::var("UPDATE_OPENAPI").is_ok_and(|v| v == "1") {
        std::fs::write(COMMITTED_OPENAPI_PATH, &fresh)
            .unwrap_or_else(|e| panic!("write {COMMITTED_OPENAPI_PATH}: {e}"));
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

/// The static string the live handler serves must be BYTE-IDENTICAL to the committed file — i.e.
/// `include_str!` compiled in the same bytes the drift test checks. (Guards against, e.g., a stale
/// build cache serving an old embed.)
#[cfg(feature = "openapi-schema")]
#[test]
fn served_openapi_equals_committed_file() {
    let committed =
        std::fs::read_to_string(COMMITTED_OPENAPI_PATH).expect("read committed openapi");
    assert_eq!(super::OPENAPI_JSON, committed);
}

/// class-13/14 R2: `POST /restart`'s handler explicitly treats an absent body as `RestartReq::default()`
/// (`handlers.rs`'s own doc comment on `restart()` — "Absent is the same as `{}`"), but `body_raw!`
/// hardcodes `"required": true` on every attached request body, so the openapi contract asserts the
/// no-body call (the common one — an operator with a supervisor never needs `confirm`) is invalid. A
/// generated client honouring `required: true` would refuse to emit the call the server supports.
#[cfg(feature = "openapi-schema")]
#[test]
fn restart_request_body_is_documented_optional() {
    let doc = openapi_doc();
    let required = &doc["paths"]["/api/v1/admin/restart"]["post"]["requestBody"]["required"];
    assert_eq!(
        required.as_bool(),
        Some(false),
        "POST /restart's body must be documented optional, matching the handler's \
         absent-body-is-default() behavior; got: {required:?}"
    );
}

/// COVERAGE LOCK: 100% of operations carry a typed success-response BODY schema. Every operation
/// (each method under each path, excluding `x-*` path-item extensions) must have — for its success
/// status (204 No Content excepted — it has no body) — a `content.application/json.schema` that is a
/// `$ref` into `components.schemas`, and every referenced component must be defined. This is the
/// machine proof that no operation regressed to a bodyless `{"description":"OK"}`.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_every_operation_has_a_typed_response_schema() {
    let doc = openapi_doc();
    let schemas = doc["components"]["schemas"].as_object().expect("schemas");
    let paths = doc["paths"].as_object().expect("paths");
    let mut op_count = 0usize;
    let mut with_body = 0usize;
    for (path, methods) in paths {
        for (method, op) in methods.as_object().expect("methods") {
            if method.starts_with("x-") {
                continue;
            }
            op_count += 1;
            let responses = op["responses"].as_object().expect("responses");
            // The success response: the single 2xx entry (200/201). 204 (No Content) has no body.
            let success = responses
                .keys()
                .find(|s| s.starts_with('2') && s.as_str() != "204");
            let Some(status) = success else {
                // A 204-only op (DELETE) legitimately has no success body.
                assert!(
                    responses.contains_key("204"),
                    "{method} {path} has no 2xx success response"
                );
                continue;
            };
            with_body += 1;
            let schema = &responses[status]["content"]["application/json"]["schema"];
            // The discovery endpoint (`GET /openapi.json`) returns an OpenAPI document — described by
            // an inline object schema, not a component `$ref` (no named struct, and modeling the
            // OpenAPI meta-schema would be circular). Every OTHER operation must be a `$ref`.
            if path.ends_with("/openapi.json") {
                assert_eq!(
                    schema["type"], "object",
                    "{method} {path} must at least declare an object body"
                );
                continue;
            }
            let reference = schema["$ref"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} {status} has no $ref response schema"));
            let name = reference
                .strip_prefix("#/components/schemas/")
                .unwrap_or_else(|| {
                    panic!("{method} {path} $ref is not a component ref: {reference}")
                });
            assert!(
                schemas.contains_key(name),
                "{method} {path} references undefined schema {name}"
            );
        }
    }
    // Sanity: the surface is ~34 operations; every non-204 op carries a body.
    assert!(op_count >= 30, "unexpectedly few operations: {op_count}");
    assert!(
        with_body >= 28,
        "too few operations with a response body: {with_body}/{op_count}"
    );
}

/// EXHAUSTIVENESS BRIDGE: every `AdminError` variant is classified — either as a
/// per-endpoint-declarable `ErrKind` or as ALGORITHMIC (`None`, stamped on every operation). The
/// bridge itself is `err_kind_of`'s `match`, which will not COMPILE once a new variant exists; this
/// test locks the other half: that the declarable kinds round-trip to the same frozen code + status
/// the taxonomy already froze, and that the algorithmic bucket is exactly the universal errors.
///
/// Together with the golden, this subsumes `openapi_error_enum_matches_admin_error_codes`: the code
/// enum can no longer be right while a per-endpoint response set is wrong.
#[test]
fn err_kind_bridges_every_admin_error_variant() {
    use crate::admin::v1::contract::taxonomy::{err_kind_of, ErrKind};
    let declarable = [
        (AdminError::not_found(""), ErrKind::NotFound),
        (AdminError::Validation(String::new()), ErrKind::Validation),
        (
            AdminError::VersionConflict(String::new()),
            ErrKind::VersionConflict,
        ),
        (AdminError::Conflict(String::new()), ErrKind::Conflict),
        (
            AdminError::Forbidden {
                needed: crate::admin::v1::contract::Scope::Full,
            },
            ErrKind::Forbidden,
        ),
    ];
    for (e, kind) in declarable {
        assert_eq!(err_kind_of(&e), Some(kind), "{e:?} lost its ErrKind");
        assert_eq!(
            kind.code(),
            e.code(),
            "{kind:?} code drifted from AdminError"
        );
        assert_eq!(
            kind.status(),
            e.http_status(),
            "{kind:?} status drifted from AdminError"
        );
    }
    // The universal half: emitted for EVERY operation, so never declarable per endpoint.
    for e in [
        AdminError::Unauthorized,
        AdminError::MethodNotAllowed,
        AdminError::RateLimited,
        AdminError::Internal,
    ] {
        assert_eq!(
            err_kind_of(&e),
            None,
            "{e:?} is algorithmic — declaring it per endpoint would be noise AND a drift vector"
        );
    }
}

/// TOTALITY of the declaration itself: every entry resolves to a real 4xx with a non-empty phrase,
/// and no operation names the same condition twice (which would render a duplicated clause). Cheap,
/// always-on, and it makes a typo'd table entry impossible rather than merely unlikely.
#[cfg(feature = "openapi-schema")]
#[test]
fn declared_errors_is_total_and_well_formed() {
    use crate::admin::v1::contract::taxonomy::{declared_errors, declared_responses, MethodTag};
    let doc = openapi_doc();
    let prefix = crate::admin::v1::contract::ADMIN_PREFIX;
    for (path, methods) in doc["paths"].as_object().expect("paths") {
        let rel = path.strip_prefix(prefix).unwrap_or(path);
        for (key, op) in methods.as_object().expect("methods") {
            let Some(method) = MethodTag::from_op_key(key) else {
                continue;
            };
            let declared = declared_errors(method, rel);
            let mut seen = std::collections::BTreeSet::new();
            for de in declared {
                assert!(
                    (400..500).contains(&de.kind.status()),
                    "{key} {rel} declares {:?}, whose status {} is not a 4xx — only client-visible \
                     failures are per-endpoint declarable",
                    de.kind,
                    de.kind.status()
                );
                assert!(
                    !de.cond.phrase().is_empty(),
                    "{key} {rel}: {:?} has no phrase",
                    de.cond
                );
                assert!(
                    seen.insert((de.kind, de.cond)),
                    "{key} {rel} declares {:?}/{:?} twice",
                    de.kind,
                    de.cond
                );
            }
            // The document IS the projection: every status the declaration produces is present in
            // the generated operation, with exactly the projected description.
            let responses = op["responses"].as_object().expect("responses");
            for (status, description) in declared_responses(method, rel) {
                assert_eq!(
                    responses[&status]["description"].as_str(),
                    Some(description.as_str()),
                    "{key} {rel} {status} is not the projection of its declaration — someone \
                     hand-wrote a response body again"
                );
            }
        }
    }
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
    ];

    let doc = openapi_doc();
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
        declared, 17,
        "17 mutating operations take a body; a change here is a deliberate API change"
    );
}

/// An operation summary must not advertise a body field the request schema forbids. The keys PATCH
/// summary listed `allowed_pools` and `labels`, which are mint-only — `UpdateKeyReq` is
/// `deny_unknown_fields` over `{enabled, group}`, so a client following the document got a 400.
/// Now that the operation also publishes a schema, the two would contradict each other in one file.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_summaries_do_not_advertise_forbidden_body_fields() {
    let doc = openapi_doc();
    let schemas = doc["components"]["schemas"].as_object().expect("schemas");
    let paths = doc["paths"].as_object().expect("paths");

    // Every field name declared by any closed request schema. A name in this set means something
    // specific to a client, so naming it in a summary is a promise the schema must keep.
    let mut known: Vec<String> = Vec::new();
    for schema in schemas.values() {
        if schema["additionalProperties"] != serde_json::Value::Bool(false) {
            continue;
        }
        if let Some(props) = schema["properties"].as_object() {
            known.extend(props.keys().cloned());
        }
    }
    known.sort();
    known.dedup();

    for (path, methods) in paths {
        for (method, op) in methods.as_object().expect("methods") {
            if method.starts_with("x-") {
                continue;
            }
            let Some(reference) = op["requestBody"]["content"]["application/json"]["schema"]
                ["$ref"]
                .as_str()
                .and_then(|r| r.strip_prefix("#/components/schemas/"))
            else {
                continue;
            };
            let schema = &schemas[reference];
            if schema["additionalProperties"] != serde_json::Value::Bool(false) {
                continue;
            }
            let declared: Vec<&str> = schema["properties"]
                .as_object()
                .map(|p| p.keys().map(String::as_str).collect())
                .unwrap_or_default();
            let summary = op["summary"].as_str().unwrap_or("");
            for name in &known {
                if declared.contains(&name.as_str()) {
                    continue;
                }
                // Only a word-boundary hit counts, so a summary mentioning `group` does not trip on
                // a schema that declares `groups`.
                let named = summary
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .any(|w| w == name);
                assert!(
                    !named,
                    "{method} {path} summary advertises `{name}`, which {reference} forbids: {summary}"
                );
            }
        }
    }
}
