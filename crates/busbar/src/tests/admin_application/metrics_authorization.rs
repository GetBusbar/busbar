// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use busbar_contract::abi::mechanism::endpoint::{EndpointRequest, EndpointResponse};
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use busbar_contract::json::{self, JsonValueTrait as _};
use busbar_kernel::plugin_routes::{build_route_table, PluginHttpDispatch, RouteDecl, RouteKind};
use tower::ServiceExt as _;

const PATHS: [(&str, &str); 2] = [
    ("/metrics", "get_metrics"),
    ("/metrics/hooks", "get_metrics_hooks"),
];

async fn ask(
    router: &Router,
    method: Method,
    path: &str,
    token: Option<&str>,
    accept: &str,
    body: Option<json::Value>,
) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("accept", accept);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let body = match body {
        Some(body) => {
            request = request.header("content-type", "application/json");
            Body::from(json::to_vec(&body).unwrap())
        }
        None => Body::empty(),
    };
    let response = router
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 22)
        .await
        .unwrap();
    (status, body.to_vec())
}

async fn mint(router: &Router, name: &str, verbs: Option<&[&str]>) -> String {
    let mut body = json::json!({"name":name});
    if let Some(verbs) = verbs {
        body["admin"] = json::json!({"scope":"read-only", "verbs":verbs});
    }
    let (status, bytes) = ask(
        router,
        Method::POST,
        "/api/v1/admin/keys",
        Some(super::TOKEN),
        "application/json",
        Some(body),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "native mint {name}: {}",
        String::from_utf8_lossy(&bytes)
    );
    let created = json::parse_value(&bytes).unwrap();
    let token = created["token"]
        .as_str()
        .expect("mint returns the credential once");
    assert!(token.starts_with("bbk_"));
    token.to_owned()
}

struct Keys {
    all: String,
    metrics: String,
    hooks: String,
    both: String,
    unrelated: String,
    data: String,
}

impl Keys {
    async fn mint(router: &Router) -> Self {
        Self {
            all: mint(router, "all-reads", Some(&[])).await,
            metrics: mint(router, "metrics-only", Some(&["get_metrics"])).await,
            hooks: mint(router, "hooks-only", Some(&["get_metrics_hooks"])).await,
            both: mint(
                router,
                "both-metrics",
                Some(&["get_metrics", "get_metrics_hooks"]),
            )
            .await,
            unrelated: mint(router, "unrelated-read", Some(&["get_info"])).await,
            data: mint(router, "data-only", None).await,
        }
    }
}

async fn assert_discovery(router: &Router, keys: &Keys) {
    for (token, names, all) in [
        (&keys.metrics, vec!["get_metrics", "get_whoami"], false),
        (&keys.hooks, vec!["get_metrics_hooks", "get_whoami"], false),
        (
            &keys.both,
            vec!["get_metrics", "get_metrics_hooks", "get_whoami"],
            false,
        ),
        (&keys.unrelated, vec!["get_info", "get_whoami"], false),
        (&keys.all, vec![], true),
    ] {
        let (status, body) = ask(
            router,
            Method::GET,
            "/api/v1/admin/whoami",
            Some(token),
            "application/json",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let who = json::parse_value(&body).unwrap();
        assert_eq!(who["scope"], "read-only");
        assert_eq!(who["verbs_all"].as_bool(), Some(all));
        assert_eq!(who["credential"]["kind"], "key");
        let verbs: Vec<_> = who["verbs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(
            verbs.windows(2).all(|pair| pair[0] < pair[1]),
            "sorted, unique effective verbs"
        );
        if all {
            assert!(verbs.contains(&"get_metrics") && verbs.contains(&"get_metrics_hooks"));
            assert!(!verbs.contains(&"post_keys"));
        } else {
            assert_eq!(
                verbs.into_iter().collect::<BTreeSet<_>>(),
                names.into_iter().collect::<BTreeSet<_>>()
            );
        }
    }
}

async fn assert_access(router: &Router, keys: &Keys, telemetry_off: bool) {
    for (path, name) in PATHS {
        for (token, permitted) in [
            (&keys.all, true),
            (&keys.metrics, name == "get_metrics"),
            (&keys.hooks, name == "get_metrics_hooks"),
            (&keys.both, true),
            (&keys.unrelated, false),
        ] {
            let (status, body) = ask(
                router,
                Method::GET,
                path,
                Some(token),
                "application/json",
                None,
            )
            .await;
            let doc = json::parse_value(&body).unwrap();
            if !permitted {
                assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
                assert_eq!(doc["error"]["reason"], "scope_insufficient");
            } else if telemetry_off && path == "/metrics" {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(doc["error"]["reason"], "telemetry_disabled");
            } else {
                assert_eq!(status, StatusCode::OK, "{path}: {doc}");
                let families = doc["families"].as_array().unwrap();
                if path == "/metrics" {
                    assert!(families.iter().any(|f| f["name"] == "busbar_build_info"));
                }
            }
        }
        for token in [None, Some("invalid-admin-token"), Some(keys.data.as_str())] {
            let (status, _) = ask(router, Method::GET, path, token, "application/json", None).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{path} never uses the data/open door"
            );
        }
        // Real HEAD requests: the exact-method named grant rule is deliberately unchanged.
        for (token, expected) in [
            (None, StatusCode::UNAUTHORIZED),
            (Some(keys.both.as_str()), StatusCode::FORBIDDEN),
            (
                Some(keys.all.as_str()),
                if telemetry_off && path == "/metrics" {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::OK
                },
            ),
        ] {
            let (status, body) =
                ask(router, Method::HEAD, path, token, "application/json", None).await;
            assert_eq!(status, expected, "HEAD {path}");
            if token == Some(keys.all.as_str()) {
                assert!(
                    body.is_empty(),
                    "the authorized GET handler's HEAD body is empty"
                );
            }
        }
    }
    for token in [&keys.all, &keys.metrics, &keys.hooks, &keys.both] {
        let (status, body) = ask(
            router,
            Method::POST,
            "/api/v1/admin/keys",
            Some(token),
            "application/json",
            Some(json::json!({"name":"must-not-mint"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            json::parse_value(&body).unwrap()["error"]["reason"],
            "scope_insufficient"
        );
    }
}

struct UncalledPlugin(AtomicUsize);

impl PluginHttpDispatch for UncalledPlugin {
    fn handle_http(&self, _: &EndpointRequest) -> EndpointResponse {
        self.0.fetch_add(1, Ordering::SeqCst);
        EndpointResponse {
            status: 418,
            headers: Vec::new(),
            body: b"wrong handler".to_vec(),
        }
    }
}

#[tokio::test]
async fn metrics_named_admin_contract() {
    if super::isolated() {
        return;
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(60));
    let (app, _scratch) = super::application_with_native_keys(true).await;
    assert!(busbar_kernel::base_data_core_lines(&app)
        .iter()
        .all(|(path, _, _)| !PATHS.iter().any(|(metrics, _)| path.as_str() == *metrics)));
    let (data, admin, handle) =
        busbar_core_admin::build_split_routers_with_limits(app.clone(), 64 * 1024, 16, false);
    for (path, _) in PATHS {
        let (status, _) = ask(
            &data,
            Method::GET,
            path,
            Some(super::TOKEN),
            "application/json",
            None,
        )
        .await;
        assert!(
            !status.is_success(),
            "the data listener must not acquire core {path}"
        );
    }
    let keys = Keys::mint(&admin).await;
    assert_discovery(&admin, &keys).await;
    assert_access(&admin, &keys, false).await;
    for (path, _) in PATHS {
        for accept in ["text/plain", "application/openmetrics-text"] {
            let (status, body) =
                ask(&admin, Method::GET, path, Some(&keys.both), accept, None).await;
            assert_eq!(status, StatusCode::OK);
            if accept == "application/openmetrics-text" {
                assert!(body.ends_with(b"# EOF\n"));
            }
            if path == "/metrics" {
                assert!(String::from_utf8(body)
                    .unwrap()
                    .contains("busbar_build_info"));
            }
        }
    }

    let combined = busbar_core_admin::build_router(app.clone());
    assert_discovery(&combined, &keys).await;
    assert_access(&combined, &keys, false).await;

    let plugin = Arc::new(UncalledPlugin(AtomicUsize::new(0)));
    for auth in [RouteAuth::None, RouteAuth::Key, RouteAuth::Admin] {
        let mut candidate = (*app).clone();
        candidate.plugin_routes = Arc::new(
            build_route_table(
                PATHS
                    .iter()
                    .map(|(path, _)| RouteDecl {
                        owner: "metrics-declaration-probe".into(),
                        source_instance: "metrics-declaration-probe".into(),
                        dispatch_available: true,
                        kind: RouteKind::Export,
                        route: Route {
                            path: (*path).into(),
                            method: RouteMethod::Get,
                            auth,
                        },
                        scrape: true,
                        persistent: false,
                        dispatch: plugin.clone(),
                    })
                    .collect(),
            )
            .unwrap(),
        );
        handle.swap(Arc::new(candidate)).await;
        let admin = busbar_kernel::router::build_admin_router_on(&handle, 64 * 1024, false);
        assert_access(&admin, &keys, false).await;
        assert_eq!(
            plugin.0.load(Ordering::SeqCst),
            0,
            "the core handler owns the admin metrics paths"
        );
    }
}

#[tokio::test]
async fn metrics_disabled_is_still_authorized_and_hooks_render_independently() {
    if super::isolated() {
        return;
    }
    let (app, _scratch) = super::application_with_native_keys(true).await;
    let (_, admin, _) =
        busbar_core_admin::build_split_routers_with_limits(app, 64 * 1024, 16, false);
    let keys = Keys::mint(&admin).await;
    let telemetry = busbar_kernel::config::TelemetryCfg {
        enabled: false,
        ..Default::default()
    };
    busbar_kernel::snapshot::configure_telemetry(&telemetry, None);
    assert_access(&admin, &keys, true).await;
}
