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
        2,
        "the envelope is exactly code+message (additive changes go OUTSIDE error)"
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
    let doc = openapi_doc_seamed();
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
    let doc = openapi_doc_seamed();
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

    let doc = openapi_doc_seamed();
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
    let doc = openapi_doc_seamed();
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
    let doc = openapi_doc_seamed();
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
    .chain(std::iter::once("unavailable".to_string()))
    .collect();
    assert_eq!(
        enum_codes, actual_codes,
        "openapi error-code enum drifted from AdminError::code"
    );
}

#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_documents_the_loops_503_on_every_operation_it_walks() {
    let doc = openapi_doc_seamed();
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
            if loop_walks {
                walked += 1;
                assert_eq!(
                    documented["content"]["application/json"]["schema"]["$ref"],
                    "#/components/schemas/Error",
                    "{method} {path}: the loop can answer `503 unavailable`, so the operation \
                     documents it in the one Error envelope"
                );
            } else {
                assert!(
                    documented.is_null(),
                    "{method} {path} is not walked through the loop but documents a 503"
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
    let doc = openapi_doc_seamed();
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

#[cfg(feature = "openapi-schema")]
fn openapi_doc_seamed() -> serde_json::Value {
    crate::ensure_seam();
    openapi_doc()
}

#[cfg(feature = "openapi-schema")]
#[test]
fn served_openapi_equals_committed_file() {
    let committed =
        std::fs::read_to_string(COMMITTED_OPENAPI_PATH).expect("read committed openapi");
    assert_eq!(super::handlers::openapi_json(), committed);
}

#[cfg(feature = "openapi-schema")]
#[test]
fn restart_request_body_is_documented_optional() {
    let doc = openapi_doc_seamed();
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
    let doc = openapi_doc_seamed();
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
    let doc = openapi_doc_seamed();
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
    let doc = openapi_doc_seamed();
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
    let handle = Arc::new(AppHandle::new(crate::new_test_app().build()));
    let (free, resp) =
        worker_was_free_during(super::handlers::openapi(State(Arc::clone(&handle)))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        free,
        "GET openapi.json built the document on the async worker"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn openapi_still_serves_the_document_filtered_to_the_configured_planes() {
    let expected =
        super::handlers::openapi_for_configured_planes(&super::handlers::openapi_json(), |_| false)
            .expect("the committed document marks plane operations");
    let doc: serde_json::Value = serde_json::from_str(&expected).unwrap();
    assert!(doc["paths"].get("/api/v1/admin/keys").is_some());
    let handle = Arc::new(AppHandle::new(crate::new_test_app().build()));
    let resp = super::handlers::openapi(State(Arc::clone(&handle))).await;
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

struct MarkingAdmission;

impl busbar_kernel::admission::PluginAdmission for MarkingAdmission {
    fn is_tarball(&self, file: &str) -> bool {
        busbar_kernel_testkit::test_support::AdmissionStandIn.is_tarball(file)
    }
    fn max_tarball_bytes(&self) -> u64 {
        busbar_kernel_testkit::test_support::AdmissionStandIn.max_tarball_bytes()
    }
    fn restart_default(&self, kind: &str) -> bool {
        busbar_kernel_testkit::test_support::AdmissionStandIn.restart_default(kind)
    }
    fn policy_resolves(&self, cfg: &busbar_kernel::config::PluginsCfg) -> Result<(), String> {
        busbar_kernel_testkit::test_support::AdmissionStandIn.policy_resolves(cfg)
    }
    fn inventory(
        &self,
        dir: &std::path::Path,
        cfg: &busbar_kernel::config::PluginsCfg,
    ) -> Result<Vec<busbar_kernel::admission::Inventoried>, String> {
        busbar_kernel_testkit::test_support::AdmissionStandIn.inventory(dir, cfg)
    }
    fn admit_upload(
        &self,
        dir: &std::path::Path,
        file: &str,
        tarball: &[u8],
        cfg: &busbar_kernel::config::PluginsCfg,
    ) -> Result<busbar_kernel::admission::Admitted, busbar_kernel::admission::Refusal> {
        busbar_kernel_testkit::test_support::AdmissionStandIn.admit_upload(dir, file, tarball, cfg)
    }
    fn inspect(
        &self,
        _: &[u8],
        _: &busbar_kernel::config::PluginsCfg,
    ) -> Result<
        (
            busbar_kernel::admission::Stated,
            busbar_kernel::admission::Judged,
        ),
        busbar_kernel::admission::Refusal,
    > {
        TRUST_RESOLVED_HERE.with(|here| here.set(true));
        Err(busbar_kernel::admission::Refusal::Validation(
            "the marking root refuses".into(),
        ))
    }
    fn rollback_target(
        &self,
        file: &str,
        bytes: &[u8],
        cfg: &busbar_kernel::config::PluginsCfg,
    ) -> Result<busbar_kernel::admission::Stated, busbar_kernel::admission::Refusal> {
        busbar_kernel_testkit::test_support::AdmissionStandIn.rollback_target(file, bytes, cfg)
    }
}

fn inspect_body(tarball: &[u8]) -> axum::body::Bytes {
    use base64::Engine as _;
    axum::body::Bytes::from(format!(
        r#"{{"file":"candidate.tar.gz","tarball_b64":"{}"}}"#,
        base64::engine::general_purpose::STANDARD.encode(tarball)
    ))
}

#[tokio::test(flavor = "current_thread")]
async fn inspect_plugin_unpacks_the_candidate_off_the_async_worker() {
    let app = crate::new_test_app()
        .plugin_admission(&MarkingAdmission)
        .build();
    let handle = Arc::new(AppHandle::new(app));
    TRUST_RESOLVED_HERE.with(|here| here.set(false));
    let resp = super::handlers::inspect_plugin(State(handle), inspect_body(b"candidate")).await;
    let (status, _, body) = parts(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["message"], "the marking root refuses");
    assert!(
        !TRUST_RESOLVED_HERE.with(std::cell::Cell::get),
        "the plugin inspect ran on the async worker"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn inspect_plugin_still_refuses_a_bad_candidate_in_the_envelope() {
    let handle = Arc::new(AppHandle::new(crate::new_test_app().build()));
    let resp = super::handlers::inspect_plugin(
        State(Arc::clone(&handle)),
        inspect_body(b"not a tarball at all"),
    )
    .await;
    let (status, ct, body) = parts(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(ct.starts_with("application/json"), "{ct}");
    assert_eq!(body["error"]["code"], "invalid_request");

    assert_eq!(
        body["error"]["message"],
        "a test build has no plugin admission: the composition root's tests prove it",
        "{body}"
    );
    let resp = super::handlers::inspect_plugin(
        State(handle),
        axum::body::Bytes::from(r#"{"file":"x.tar.gz","tarball_b64":"%%%"}"#),
    )
    .await;
    let (status, _, body) = parts(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");
}
