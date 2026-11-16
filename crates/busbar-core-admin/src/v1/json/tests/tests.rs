// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[cfg(feature = "openapi-schema")]
const OAS_OPERATION_STATUSES: &str =
    include_str!("../../../../tests/fixtures/openapi_operation_statuses_key.txt").trim_ascii();

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

#[tokio::test]
async fn err_json_uses_stable_envelope() {
    let (status, ct, body) = parts(err_json(&AdminError::not_found("hook"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(ct, busbar_contract::protocol::APPLICATION_JSON);
    assert_eq!(body["error"]["code"], "not_found");
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|m| !m.is_empty()),
        "message is human text, never empty"
    );
    assert_eq!(
        body["error"].as_object().unwrap().len(),
        6,
        "the envelope is code, reason, message, request_id, retryable and details (ADMIN-API-1.6 section 1.2)"
    );
}

#[tokio::test]
async fn ok_json_serializes_view_with_given_status() {
    #[derive(Serialize)]
    struct View {
        name: &'static str,
        n: u32,
    }
    let (status, ct, body) = parts(ok_json(StatusCode::CREATED, &View { name: "x", n: 7 })).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(ct, busbar_contract::protocol::APPLICATION_JSON);
    assert_eq!(body, json!({"name": "x", "n": 7}));
}

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

#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_doc_is_31_and_v1_prefixed() {
    let doc = openapi_doc();
    assert!(
        doc["openapi"].as_str().unwrap().starts_with("3.1"),
        "discovery doc is OpenAPI 3.1"
    );
    assert_eq!(doc["info"]["version"], env!("CARGO_PKG_VERSION"));
    let prefix = format!("{}/", crate::v1::contract::ADMIN_PREFIX);
    for path in doc["paths"].as_object().unwrap().keys() {
        assert!(
            path.starts_with(&prefix),
            "{path} escaped the frozen {prefix} prefix"
        );
    }
}

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

#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_paths_annotate_required_scope() {
    fn expected_scope(method: &str, path: &str) -> &'static str {
        use crate::v1::contract::{ADMIN_PREFIX, PATH_CONFIG_VALIDATE, PATH_PLUGINS_INSPECT};
        if method == "get" || method == "head" {
            return "read-only";
        }
        let rel = path.strip_prefix(ADMIN_PREFIX).unwrap_or(path);
        if rel == PATH_CONFIG_VALIDATE || rel == PATH_PLUGINS_INSPECT {
            return "read-only";
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

#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_never_emits_a_boolean_items_subschema() {
    fn walk(v: &serde_json::Value, path: &str, offenders: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(map) => {
                if let Some(items) = map.get("items") {
                    if items.is_boolean() {
                        offenders.push(format!("{path}/items = {items}"));
                    }
                }
                for (k, vv) in map {
                    walk(vv, &format!("{path}/{k}"), offenders);
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, vv) in arr.iter().enumerate() {
                    walk(vv, &format!("{path}[{i}]"), offenders);
                }
            }
            _ => {}
        }
    }
    let doc = openapi_doc();
    let mut offenders = Vec::new();
    walk(&doc, "", &mut offenders);
    assert!(
        offenders.is_empty(),
        "boolean `items` sub-schema(s) found — fatal to kin-openapi/oapi-codegen: {offenders:?}"
    );
}

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

    let actual_codes: BTreeSet<String> = [
        AdminError::not_found(""),
        AdminError::Unauthorized,
        AdminError::Forbidden {
            needed: crate::v1::contract::Scope::Full,
        },
        AdminError::MethodNotAllowed,
        AdminError::Validation(String::new()),
        AdminError::VersionConflict(String::new()),
        AdminError::Conflict(String::new()),
        AdminError::RateLimited,
        AdminError::Internal,
        AdminError::UnpricedClass {
            lane: String::new(),
            class: None,
        },
    ]
    .iter()
    .map(|e| e.code().to_string())
    .chain([
        "unavailable".to_string(),
        busbar_contract::protocol::ERR_TYPE_REQUEST_TOO_LARGE.to_string(),
        "idempotency_mismatch".to_string(),
        "mutation_applied".to_string(),
        "action_in_flight".to_string(),
    ])
    .collect();
    assert_eq!(
        enum_codes, actual_codes,
        "openapi error-code enum drifted from AdminError::code"
    );
}

#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_documents_the_loops_503_on_every_operation_it_walks() {
    let doc = openapi_doc();
    let codes =
        &doc["components"]["schemas"]["Error"]["properties"]["error"]["properties"]["code"]["enum"];
    assert!(
        codes
            .as_array()
            .is_some_and(|c| c.iter().any(|v| v == "unavailable")),
        "the Error code enum must name `unavailable`: {codes}"
    );
    let mut walked = 0usize;
    for (path, item) in doc["paths"].as_object().expect("paths") {
        for (method, op) in item.as_object().expect("path item") {
            if method.starts_with("x-") {
                continue;
            }
            let loop_walks =
                crate::admin_codec::verbs::resolve(&method.to_ascii_uppercase(), path).is_some();
            let documented = &op[OAS_OPERATION_STATUSES]["503"];
            if loop_walks || op.get("x-busbar-plane").is_some() {
                walked += 1;
                let expected_schema = if method == "post"
                    && path == &format!("{}/adjust", crate::v1::contract::ADMIN_PREFIX)
                {
                    // The durable adjustment profile also returns a typed action outcome.
                    // Its pre-admission refusal still uses the ordinary Error envelope.
                    json!({"anyOf": [
                        {"$ref": "#/components/schemas/Error"},
                        {"$ref": "#/components/schemas/AdjustmentActionView"},
                        {"$ref": "#/components/schemas/AdjustmentActionInFlightError"}
                    ]})
                } else {
                    json!({"$ref": "#/components/schemas/Error"})
                };
                assert_eq!(
                    documented["content"]["application/json"]["schema"], expected_schema,
                    "{method} {path}: the loop can answer `503 unavailable`, so the operation \
                     documents the Error envelope alongside any durable action outcomes"
                );
            } else {
                assert!(
                    documented.is_null(),
                    "{method} {path} is neither loop-walked nor a plane operation but documents a 503"
                );
            }
        }
    }
    assert!(
        walked >= 66,
        "only {walked} loop-walked operations were checked"
    );
}

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
            doc["paths"][path][method][OAS_OPERATION_STATUSES]["403"].is_object(),
            "{method} {path} can 403 on escalation but its openapi omits it"
        );
    }
}

#[cfg(feature = "openapi-schema")]
const COMMITTED_OPENAPI_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/src/v1/json/openapi.json");

/// Flattens a JSON tree to `JSON-pointer -> leaf text`, keys visited in sorted order, so two trees
/// are equal exactly when they hold the same members whatever order their objects were written in.
/// Empty containers are leaves (`{}` / `[]`) so an emptied object is not mistaken for a missing one.
#[cfg(feature = "openapi-schema")]
fn flatten_openapi(
    value: &busbar_contract::json::Value,
    pointer: String,
    out: &mut std::collections::BTreeMap<String, String>,
) {
    use busbar_contract::json::JsonContainerTrait;
    if let Some(members) = value.as_object() {
        if members.is_empty() {
            out.insert(pointer, "{}".to_string());
            return;
        }
        let mut sorted: Vec<(&str, &busbar_contract::json::Value)> = members.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        for (key, member) in sorted {
            let escaped = key.replace('~', "~0").replace('/', "~1");
            flatten_openapi(member, format!("{pointer}/{escaped}"), out);
        }
    } else if let Some(items) = value.as_array() {
        if items.is_empty() {
            out.insert(pointer, "[]".to_string());
            return;
        }
        for (index, item) in items.iter().enumerate() {
            flatten_openapi(item, format!("{pointer}/{index}"), out);
        }
    } else {
        let text = busbar_contract::json::to_string(value).unwrap_or_else(|_| "?".to_string());
        out.insert(pointer, text);
    }
}

/// The OpenAPI document as sorted `pointer -> leaf` pairs, read through the JSON facade (DEP-3).
#[cfg(feature = "openapi-schema")]
fn openapi_leaves(bytes: &[u8]) -> std::collections::BTreeMap<String, String> {
    let tree = busbar_contract::json::parse_value(bytes).expect("OpenAPI document parses");
    let mut out = std::collections::BTreeMap::new();
    flatten_openapi(&tree, String::new(), &mut out);
    out
}

/// `committed` is what the generator `openapi_doc()` produces, member for member. On a mismatch the
/// generated document is written to `target/openapi.generated.json` (CI keeps it as an artifact: it
/// is the exact file to commit) and the failure lists what differs.
#[cfg(feature = "openapi-schema")]
#[test]
fn served_openapi_equals_committed_file() {
    let committed_text =
        std::fs::read_to_string(COMMITTED_OPENAPI_PATH).expect("read committed openapi");
    let generated = openapi_doc();
    // serde_json writes its exact numbers as plain JSON numbers; the facade (sonic-rs) would write
    // them as the `$serde_json::private::Number` wrapper, which no committed file carries.
    let generated_bytes = serde_json::to_vec(&generated).expect("serialize generated openapi");

    let want = openapi_leaves(&generated_bytes);
    let have = openapi_leaves(committed_text.as_bytes());
    if want == have {
        return;
    }

    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let artifact = target.join("openapi.generated.json");
    // The facade has no pretty printer, so the artifact is written as the emit path writes the
    // committed file (`emit_openapi_artifact`, `openapi_for_configured_planes`: serde_json's pretty
    // form), byte for byte what to copy over it. Those two paths name serde_json directly (DEP-3);
    // this line follows them and moves with them when the facade grows a pretty writer.
    let pretty = serde_json::to_string_pretty(&generated).expect("pretty openapi");
    let written = std::fs::create_dir_all(&target)
        .and_then(|()| std::fs::write(&artifact, format!("{pretty}\n")))
        .map(|()| artifact.display().to_string())
        .unwrap_or_else(|e| format!("(could not write {}: {e})", artifact.display()));

    let missing: Vec<&String> = want.keys().filter(|k| !have.contains_key(*k)).collect();
    let extra: Vec<&String> = have.keys().filter(|k| !want.contains_key(*k)).collect();
    let changed: Vec<&String> = want
        .iter()
        .filter(|(k, v)| have.get(*k).is_some_and(|h| h != *v))
        .map(|(k, _)| k)
        .collect();
    let show = |label: &str, items: &[&String]| {
        let mut text = format!("  {label}: {}\n", items.len());
        for item in items.iter().take(25) {
            text.push_str(&format!("    {item}\n"));
        }
        if items.len() > 25 {
            text.push_str(&format!("    ... and {} more\n", items.len() - 25));
        }
        text
    };
    panic!(
        "committed openapi.json differs from openapi_doc() (compared as parsed JSON, keys sorted).\n\
         {}{}{}generated document written to {written}; copy it over {COMMITTED_OPENAPI_PATH} to fix.",
        show("in the generated document but not the committed file", &missing),
        show("in the committed file but not the generated document", &extra),
        show("present in both with different values", &changed),
    );
}

#[cfg(feature = "openapi-schema")]
#[test]
fn restart_unreachable_is_documented_on_every_restart_scoped_route() {
    let doc = openapi_doc();
    // The `/export/{name}` writes left with `/export` (ADMIN-API-1.6 §0.2, CON-6): an export section
    // is written through `/config/settings`, which carries the refusal.
    for (path, method) in [("/api/v1/admin/config/settings", "put")] {
        let description = doc["paths"][path][method]["responses"]["409"]["description"]
            .as_str()
            .unwrap_or_else(|| panic!("{method} {path} documents a 409"));
        assert!(
            description.contains("restart-only change on an in-memory Store"),
            "{method} {path} 409 names the in-memory Store refusal: {description}"
        );
    }
}

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
            let by_status = op[OAS_OPERATION_STATUSES]
                .as_object()
                .expect("documented statuses");

            let success = by_status
                .keys()
                .find(|s| s.starts_with('2') && s.as_str() != "204");
            let Some(status) = success else {
                assert!(
                    by_status.contains_key("204"),
                    "{method} {path} has no 2xx success response"
                );
                continue;
            };
            with_body += 1;
            let schema = &by_status[status]["content"]["application/json"]["schema"];

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

    assert!(op_count >= 30, "unexpectedly few operations: {op_count}");
    assert!(
        with_body >= 28,
        "too few operations with a response body: {with_body}/{op_count}"
    );
}

#[test]
fn err_kind_bridges_every_admin_error_variant() {
    use crate::v1::contract::taxonomy::{err_kind_of, ErrKind};
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
                needed: crate::v1::contract::Scope::Full,
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

#[cfg(feature = "openapi-schema")]
#[test]
fn declared_errors_is_total_and_well_formed() {
    use crate::v1::contract::taxonomy::{declared_errors, declared_responses, MethodTag};
    let doc = openapi_doc();
    let prefix = crate::v1::contract::ADMIN_PREFIX;
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

            let by_status = op[OAS_OPERATION_STATUSES]
                .as_object()
                .expect("documented statuses");
            for (status, description) in declared_responses(method, rel) {
                assert_eq!(
                    by_status[&status]["description"].as_str(),
                    Some(description.as_str()),
                    "{key} {rel} {status} is not the projection of its declaration — a response \
                     body was hand-written instead of projected"
                );
            }
        }
    }
}

#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_summaries_do_not_advertise_forbidden_body_fields() {
    let doc = openapi_doc();
    let schemas = doc["components"]["schemas"].as_object().expect("schemas");
    let paths = doc["paths"].as_object().expect("paths");

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
    let mut advertised: Vec<String> = Vec::new();

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
            // Restart applies these already-stored config fields; they are not body keys.
            // Exclude only that exact lifecycle clause, retaining every other field check.
            let summary = if reference == "RestartReq" {
                summary.replace(
                    "restart-scoped settings (listen, admin_listen, tls, admin_tls, admin_require_mtls, store)",
                    "",
                )
            } else if reference == "PutAuthBody" {
                // "at runtime" is the lifecycle clause (live now, not at the next boot); `runtime` is also
                // a field of an unrelated config form. Exclude only that exact clause.
                summary.replace("admin_auth chain at runtime,", "admin_auth chain,")
            } else {
                summary.to_owned()
            };
            for name in &known {
                if declared.contains(&name.as_str()) {
                    continue;
                }

                let named = summary
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .any(|w| w == name);
                if named {
                    advertised.push(format!(
                        "{method} {path} summary advertises `{name}`, which {reference} forbids: {summary}"
                    ));
                }
            }
        }
    }
    assert!(advertised.is_empty(), "{}", advertised.join("\n"));
}

#[test]
fn the_restart_note_keeps_the_route_sentence_and_names_a_pending_plane() {
    let routes = vec!["/metrics".to_string()];
    let planes = vec!["pending-red".to_string()];
    assert_eq!(named_map::restart_note(&[], &[]), None);
    let route_only = named_map::restart_note(&routes, &[]).expect("a route is pending");
    assert_eq!(
        route_only,
        "stored and applied, EXCEPT the newly declared route(s) /metrics — each plugin route path \
         is registered on the HTTP router once, at process start, and a config apply swaps only \
         the config snapshot, so a route that did not exist at boot keeps answering 404 until the \
         next RESTART (removing one, by contrast, takes effect immediately)"
    );
    let plane_only = named_map::restart_note(&[], &planes).expect("a plane is pending");
    assert!(plane_only.contains("pending-red") && plane_only.contains("RESTART"));
    assert!(!plane_only.contains("/metrics"));
    assert_eq!(
        named_map::restart_note(&routes, &planes),
        Some(format!("{route_only}; {plane_only}"))
    );
}

async fn worker_was_free_during<Fut: std::future::Future<Output = Response>>(
    served: Fut,
) -> (bool, Response) {
    let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ran_during = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sibling = {
        let finished = Arc::clone(&finished);
        let ran_during = Arc::clone(&ran_during);
        tokio::spawn(async move {
            let during = !finished.load(std::sync::atomic::Ordering::SeqCst);
            ran_during.store(during, std::sync::atomic::Ordering::SeqCst);
        })
    };
    let resp = served.await;
    finished.store(true, std::sync::atomic::Ordering::SeqCst);
    sibling.await.expect("the sibling task runs");
    (ran_during.load(std::sync::atomic::Ordering::SeqCst), resp)
}

#[tokio::test(flavor = "current_thread")]
async fn openapi_builds_the_served_document_off_the_async_worker() {
    let (free, resp) = worker_was_free_during(super::handlers::render_openapi(|_| false)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        free,
        "GET openapi.json built the document on the async worker"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn openapi_still_serves_the_document_filtered_to_the_configured_planes() {
    // The generating test binary installs no plane, so the committed document marks none; mark one
    // operation as a plane's, exactly as the generator marks an installed plane's operations.
    fn marked() -> String {
        let mut doc: serde_json::Value =
            serde_json::from_str(&super::handlers::openapi_json()).unwrap();
        doc["paths"]["/api/v1/admin/info"]["get"]["x-busbar-plane"] = json!("examples");
        serde_json::to_string_pretty(&doc).unwrap()
    }
    let expected = super::handlers::openapi_for_configured_planes(&marked(), |_| false)
        .expect("a document that marks a plane operation is filtered");
    let doc: serde_json::Value = serde_json::from_str(&expected).unwrap();
    assert!(doc["paths"].get("/api/v1/admin/keys").is_some());
    assert!(doc["paths"].get("/api/v1/admin/info").is_none());
    assert!(
        super::handlers::openapi_for_configured_planes(&marked(), |section| section == "examples")
            .is_none(),
        "a configured plane keeps its operations"
    );
    let resp = super::handlers::render_openapi_of(marked, |_| false).await;
    assert_eq!(resp.status(), StatusCode::OK);
    use http_body_util::BodyExt;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected.as_str());
}

#[tokio::test(flavor = "current_thread")]
async fn openapi_is_answered_with_1_5_5s_head() {
    let resp = super::handlers::openapi_document_response(super::handlers::openapi_json());
    assert_eq!(resp.status(), StatusCode::OK);
    let names: Vec<&str> = resp.headers().keys().map(|k| k.as_str()).collect();
    assert_eq!(names, ["content-type"], "{:?}", resp.headers());
    assert_eq!(
        resp.headers()[axum::http::header::CONTENT_TYPE],
        busbar_contract::protocol::APPLICATION_JSON
    );
}

thread_local! {
    /// Set on whichever thread resolved the trust policy for the inspect below.
    static TRUST_RESOLVED_HERE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[tokio::test(flavor = "current_thread")]
async fn inspect_plugin_unpacks_the_candidate_off_the_async_worker() {
    TRUST_RESOLVED_HERE.with(|here| here.set(false));
    let resp = super::handlers::inspect_candidate(|| {
        TRUST_RESOLVED_HERE.with(|here| here.set(true));
        Err(AdminError::Validation("the marking root refuses".into()))
    })
    .await;
    let (status, _, body) = parts(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["message"], "the marking root refuses");
    assert!(
        !TRUST_RESOLVED_HERE.with(std::cell::Cell::get),
        "the plugin inspect ran on the async worker"
    );
}

/// The two named-definition view schemas as the document generator emits them (same generator
/// settings). `openapi_doc()` only carries them when a plane with a named-definition list is
/// installed, and the generating test binary installs none.
#[cfg(feature = "openapi-schema")]
fn named_view_schemas() -> serde_json::Value {
    let mut generator = schemars::generate::SchemaSettings::draft2020_12()
        .with(|s| {
            s.definitions_path = "/components/schemas".into();
            s.meta_schema = None;
        })
        .for_serialize()
        .into_generator();
    generator.subschema_for::<crate::v1::contract::NamedDefView>();
    generator.subschema_for::<named_map::MutatedDefView>();
    serde_json::Value::Object(generator.definitions().clone())
}

#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_existing_sdk_routes_named_mutations_include_restart_metadata() {
    let doc = openapi_doc();
    let schemas = &named_view_schemas();
    // The per-kind admin routes of identity-providers and export are gone (ADMIN-API-1.6: /kinds);
    // the sections that still route are the planes'.
    for section in named_map::routed_sections() {
        let root = section.path_root();
        for (suffix, method, expected) in [
            // GET reports the same installed definition/restart metadata as mutations.
            ("/{name}", "get", "MutatedDefView"),
            ("/{name}", "put", "MutatedDefView"),
            ("/{name}/settings", "patch", "MutatedDefView"),
        ] {
            let path = format!("/api/v1/admin{root}{suffix}");
            assert_eq!(
                doc["paths"][&path][method][OAS_OPERATION_STATUSES]["200"]["content"]
                    ["application/json"]["schema"]["$ref"],
                format!("#/components/schemas/{expected}"),
                "{method} {path}"
            );
        }
    }
    let mutation = &schemas["MutatedDefView"];
    for field in ["reload_to_apply", "note"] {
        assert!(mutation["properties"].get(field).is_some(), "{field}");
        assert!(!mutation["required"]
            .as_array()
            .unwrap()
            .contains(&json!(field)));
    }
    // Flattened post-state still includes every definition field.
    for field in schemas["NamedDefView"]["properties"]
        .as_object()
        .unwrap()
        .keys()
    {
        assert!(mutation["properties"].get(field).is_some(), "{field}");
    }
}

#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_existing_sdk_routes_cache_flush_accepts_absent_body() {
    let doc = openapi_doc();
    let body = &doc["paths"]["/api/v1/admin/auth/cache/flush"]["post"]["requestBody"];
    assert_eq!(body["required"], false);
    assert_eq!(
        body["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/FlushCacheReq"
    );
    let request = &doc["components"]["schemas"]["FlushCacheReq"];
    assert!(request["properties"].get("module").is_some());
    assert!(request["required"]
        .as_array()
        .is_none_or(|fields| fields.is_empty()));
    // The neighboring body-taking endpoint still requires its configuration.
    assert_eq!(
        doc["paths"]["/api/v1/admin/admin-auth"]["put"]["requestBody"]["required"],
        true
    );
}

#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_existing_sdk_routes_money_describes_each_wire_representation() {
    let doc = openapi_doc();
    let schemas = &doc["components"]["schemas"];
    assert_eq!(
        schemas["KeyMeteringView"]["properties"]["spend_cents"]["type"],
        "integer"
    );
    assert_eq!(
        schemas["UsageBreakdown"]["properties"]["spend_micros"]["type"],
        "integer"
    );
    assert_eq!(schemas["Amount"]["type"], "string");
    let money = doc["info"]["x-busbar-marks"]["money"].as_str().unwrap();
    assert!(money.contains("Amount values are decimal-integer JSON strings"));
    assert!(money.contains("spend_micros are JSON integers"));
}

/// The message of a refused admin body decode, after checking it is the 400 `invalid_request`
/// envelope.
async fn bad_body_message<T: serde::de::DeserializeOwned>(body: &[u8], what: &str) -> String {
    let Err(err) = json_body::<T>(body, what) else {
        panic!("a malformed {what} body must be refused");
    };
    let (status, _, body) = parts(*err).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");
    body["error"]["message"]
        .as_str()
        .expect("the refusal carries a message")
        .to_string()
}

#[tokio::test]
async fn bad_body_refusal_names_the_missing_field_and_position() {
    let message =
        bad_body_message::<super::handlers::RegisterGroupReq>(br#"{"name":"oracle-bad"}"#, "group")
            .await;
    assert_eq!(
        message,
        "malformed group body: missing field `config` at line 1 column 21"
    );
}

#[tokio::test]
async fn bad_body_refusal_keeps_the_type_and_drops_the_value() {
    let message =
        bad_body_message::<super::handlers::RollbackReq>(br#"{"version":"zero"}"#, "rollback")
            .await;
    assert_eq!(
        message,
        "malformed rollback body: invalid type: string (values not echoed), expected u64 at line 1 \
         column 17"
    );
    assert!(
        !message.contains("zero"),
        "the value is not echoed: {message}"
    );
}

/// A data error built the way a `Deserialize` impl raises it (no position: line 0).
fn custom_error(message: &str) -> serde_json::Error {
    <serde_json::Error as serde::de::Error>::custom(message)
}

#[test]
fn describe_body_error_renders_every_serde_form() {
    use serde::de::{Error as _, Unexpected};

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Need {
        a: u64,
    }
    #[derive(Debug, PartialEq, serde::Deserialize)]
    enum Mode {
        Own,
        Passthrough,
    }
    let long = "k".repeat(100);
    let over_cap = "k".repeat(65);
    let at_cap = "k".repeat(64);
    // The well-formed bodies decode: the shapes the error forms below are rendered against.
    assert_eq!(serde_json::from_slice::<Need>(br#"{"a":7}"#).unwrap().a, 7);
    assert_eq!(
        serde_json::from_slice::<Mode>(br#""Own""#).unwrap(),
        Mode::Own
    );
    assert_eq!(
        serde_json::from_slice::<Mode>(br#""Passthrough""#).unwrap(),
        Mode::Passthrough
    );

    // Kept verbatim, with the position: missing field, duplicate field, short unknown field,
    // invalid length, syntax and EOF.
    for (body, head) in [
        (r#"{}"#.to_string(), "missing field `a`"),
        (r#"{"a":1,"a":2}"#.to_string(), "duplicate field `a`"),
        (
            r#"{"zz":1}"#.to_string(),
            "unknown field `zz`, expected `a`",
        ),
        (r#"{"a":1"#.to_string(), "EOF while parsing an object"),
        (r#"{"a":1}x"#.to_string(), "trailing characters"),
        (r#"{"a":}"#.to_string(), "expected value"),
    ] {
        let e = serde_json::from_slice::<Need>(body.as_bytes()).unwrap_err();
        assert!(e.to_string().starts_with(head), "{body}: {e}");
        assert!(e.to_string().contains(" at line 1 column "), "{body}: {e}");
        assert_eq!(describe_body_error(&e), e.to_string(), "{body}");
    }
    let e = serde_json::from_slice::<(u8, u8)>(b"[1]").unwrap_err();
    assert!(
        e.to_string().starts_with("invalid length 1, expected"),
        "{e}"
    );
    assert_eq!(describe_body_error(&e), e.to_string());

    // Unknown field over 64 bytes: the name is dropped, the expected list and position kept.
    let body = format!(r#"{{"{long}":1}}"#);
    let e = serde_json::from_slice::<Need>(body.as_bytes()).unwrap_err();
    let rendered = describe_body_error(&e);
    assert!(
        rendered.starts_with(
            "unknown field (name over 64 bytes, not echoed), expected `a` at line 1 column "
        ),
        "{rendered}"
    );
    assert!(!rendered.contains(&over_cap), "{rendered}");

    // Key-name forms at and over the cap, from the authored copies (no position).
    for (message, want) in [
        (
            format!("unknown field `{long}`, there are no fields"),
            "unknown field (name over 64 bytes, not echoed), there are no fields".to_string(),
        ),
        (
            format!("unknown field `{at_cap}`, there are no fields"),
            format!("unknown field `{at_cap}`, there are no fields"),
        ),
        (
            format!("duplicate field `{long}`"),
            "duplicate field (name over 64 bytes, not echoed)".to_string(),
        ),
        (
            format!("duplicate field `{at_cap}`"),
            format!("duplicate field `{at_cap}`"),
        ),
        (
            format!("duplicate entry with key \"{long}\""),
            "duplicate entry with key (name over 64 bytes, not echoed)".to_string(),
        ),
        (
            format!("duplicate entry with key \"{at_cap}\""),
            format!("duplicate entry with key \"{at_cap}\""),
        ),
    ] {
        assert_eq!(describe_body_error(&custom_error(&message)), want);
    }

    // Unknown variant: the variant is a value.
    let e = serde_json::from_slice::<Mode>(br#""sk-secret""#).unwrap_err();
    let rendered = describe_body_error(&e);
    assert!(
        rendered.starts_with(
            "unknown variant (values not echoed), expected `Own` or `Passthrough` at line 1 column "
        ),
        "{rendered}"
    );
    assert!(!rendered.contains("sk-secret"), "{rendered}");
    assert_eq!(
        describe_body_error(&serde_json::Error::unknown_variant("sk-x", &[])),
        "unknown variant (values not echoed), there are no variants"
    );

    // Invalid type and invalid value: every value kind keeps only its kind word, every value-free
    // kind is kept, anything else is fully redacted.
    let value_kinds = [
        (
            Unexpected::Str("sk-x, expected y"),
            "string (values not echoed)",
        ),
        (Unexpected::Unsigned(7), "integer (values not echoed)"),
        (Unexpected::Signed(-7), "integer (values not echoed)"),
        (Unexpected::Float(1.5), "floating point (values not echoed)"),
        (Unexpected::Bool(true), "boolean (values not echoed)"),
        (Unexpected::Char('q'), "character (values not echoed)"),
        (Unexpected::Other("sk-other"), "(values not echoed)"),
        (Unexpected::Bytes(b"sk"), "byte array"),
        // serde_json renders `Unexpected::Unit` as JSON's own word, `null`, not serde's `unit value`.
        (Unexpected::Unit, "null"),
        (Unexpected::Option, "Option value"),
        (Unexpected::NewtypeStruct, "newtype struct"),
        (Unexpected::Seq, "sequence"),
        (Unexpected::Map, "map"),
        (Unexpected::Enum, "enum"),
        (Unexpected::UnitVariant, "unit variant"),
        (Unexpected::NewtypeVariant, "newtype variant"),
        (Unexpected::TupleVariant, "tuple variant"),
        (Unexpected::StructVariant, "struct variant"),
        (Unexpected::Other("null"), "null"),
    ];
    for (unexpected, want) in value_kinds {
        let e = serde_json::Error::invalid_type(unexpected, &"a map");
        assert_eq!(
            describe_body_error(&e),
            format!("invalid type: {want}, expected a map")
        );
        let e = serde_json::Error::invalid_value(unexpected, &"a map");
        assert_eq!(
            describe_body_error(&e),
            format!("invalid value: {want}, expected a map")
        );
    }
    // No `, expected ` after the marker: the whole rest is dropped.
    assert_eq!(
        describe_body_error(&custom_error("invalid type: sk-secret")),
        "invalid type: (values not echoed)"
    );

    // Real admin bodies at the formerly raw sites: the value goes, the type and position stay.
    for (e, expected, value) in [
        (
            serde_json::from_slice::<super::handlers::RestartReq>(br#"{"confirm":"yes"}"#)
                .err()
                .expect("a string confirm is refused"),
            "expected a boolean",
            "yes",
        ),
        (
            serde_json::from_slice::<super::handlers::PutAuthBody>(
                br#"{"admin_auth":"admin-tokens"}"#,
            )
            .err()
            .expect("a string admin_auth is refused"),
            "expected a sequence",
            "admin-tokens",
        ),
    ] {
        let rendered = describe_body_error(&e);
        assert!(
            rendered.starts_with("invalid type: string (values not echoed), "),
            "{rendered}"
        );
        assert!(rendered.contains(expected), "{rendered}");
        assert!(rendered.contains(" at line 1 column "), "{rendered}");
        assert!(!rendered.contains(value), "{rendered}");
    }

    // Authored custom text passes as written.
    let authored = "plugin settings must be an object (values not echoed)";
    assert_eq!(describe_body_error(&custom_error(authored)), authored);

    // Trust boundary (i): a nested serde error behind an authored `<path>: ` prefix keeps the
    // prefix and drops the value, even when the value contains `, expected `.
    let rendered = describe_body_error(&custom_error(
        "plane.rate_card: invalid type: string \"sk-x, expected y\", expected a map",
    ));
    assert_eq!(
        rendered,
        "plane.rate_card: invalid type: string (values not echoed), expected a map"
    );
    assert!(!rendered.contains("sk-x"), "{rendered}");
    let rendered = describe_body_error(&custom_error(
        "the reserved `x.hooks:` all-x attach must be a list of hook names: invalid type: string \
         \"sk-x\", expected a sequence",
    ));
    assert_eq!(
        rendered,
        "the reserved `x.hooks:` all-x attach must be a list of hook names: invalid type: string \
         (values not echoed), expected a sequence"
    );
    assert!(!rendered.contains("sk-x"), "{rendered}");

    // Trust boundary (ii): authored text that names a caller word passes byte for byte.
    let e = custom_error(
        "on_error keyword 'zzz-word' is not one of the reserved terminals (nothing | weighted | \
         reject | first)",
    );
    assert_eq!(describe_body_error(&e), e.to_string());

    // Trust boundary (iii): the real config-apply decode of a named hook leaves today's text.
    let e = serde_json::from_value::<busbar_kernel::config::HookDefCfg>(
        serde_json::json!({"module":"m","on_error":"zzz-word"}),
    )
    .unwrap_err();
    assert_eq!(describe_body_error(&e), e.to_string());
    assert!(
        e.to_string()
            .starts_with("on_error keyword 'zzz-word' is not one of the reserved terminals"),
        "{e}"
    );
}

#[tokio::test]
async fn admin_body_refusals_from_hooks_and_groups_do_not_reach_keyword_deserializers() {
    assert!(
        json_body::<super::handlers::RegisterHookReq>(
            br#"{"name":"h","config":{"kind":"gate","module":"m","on_error":"zzz-word"}}"#,
            "hook",
        )
        .is_ok(),
        "a hook's on_error is a plain name at this site; validation checks it later"
    );
    let message = bad_body_message::<super::handlers::RegisterGroupReq>(
        br#"{"name":"g","config":{"on_exhausted":"zzz-word"}}"#,
        "group",
    )
    .await;
    assert!(
        message.starts_with("malformed group body: unknown field `on_exhausted`, expected"),
        "{message}"
    );
    assert!(!message.contains("zzz-word"), "{message}");
}

#[tokio::test]
async fn config_body_provider_key_echoes_are_capped() {
    let p = r#"{"protocol":"openai","base_url":"https://x"}"#;
    let long = "k".repeat(100);
    let over_cap = "k".repeat(65);
    for (body, head, capped) in [
        (
            format!(r#"{{"config":{{}},"providers":{{"k1":{p},"k1":{p}}}}}"#),
            "malformed config body: duplicate entry with key \"k1\" at line 1 column ",
            false,
        ),
        (
            format!(r#"{{"config":{{}},"providers":{{"{long}":{p},"{long}":{p}}}}}"#),
            "malformed config body: duplicate entry with key (name over 64 bytes, not echoed) at \
             line 1 column ",
            true,
        ),
        (
            r#"{"config":{},"providers":{"p":{"k1":1,"k1":2}}}"#.to_string(),
            "malformed config body: duplicate field `k1` at line 1 column ",
            false,
        ),
        (
            format!(r#"{{"config":{{}},"providers":{{"p":{{"{long}":1,"{long}":2}}}}}}"#),
            "malformed config body: duplicate field (name over 64 bytes, not echoed) at line 1 \
             column ",
            true,
        ),
    ] {
        let message =
            bad_body_message::<super::handlers::ValidateConfigReq>(body.as_bytes(), "config").await;
        assert!(message.starts_with(head), "{body}: {message}");
        if capped {
            assert!(!message.contains(&over_cap), "{message}");
        }
    }
}

#[test]
fn admin_decode_errors_go_through_the_renderer() {
    const RAW_FORMS: &[&str] = &[
        "body: {e}",
        "patch: {e}",
        "invalid body: {e}",
        "definition body: {e}",
    ];
    for (file, text) in [
        ("handlers.rs", include_str!("../handlers.rs")),
        ("named_map.rs", include_str!("../named_map.rs")),
        ("mod.rs", include_str!("../mod.rs")),
    ] {
        for (n, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for form in RAW_FORMS {
                assert!(
                    !line.contains(form),
                    "{file}:{}: a decode refusal formats the raw serde error; route it through \
                     describe_body_error: {line}",
                    n + 1
                );
            }
        }
    }
    let mod_rs = include_str!("../mod.rs");
    let start = mod_rs
        .find("fn json_body<")
        .expect("json_body is defined in json/mod.rs");
    let end = mod_rs[start..]
        .find("\n}\n")
        .map(|i| start + i)
        .expect("json_body has a body");
    assert!(
        mod_rs[start..end].contains("describe_body_error(&e)"),
        "json_body must render its decode error through describe_body_error"
    );
}
