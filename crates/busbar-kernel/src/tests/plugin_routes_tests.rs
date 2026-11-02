// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::endpoint::{EndpointRequest, EndpointResponse};
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use std::sync::Arc;

struct FakeDispatch {
    label: &'static str,
}
impl PluginHttpDispatch for FakeDispatch {
    fn handle_http(&self, req: &EndpointRequest) -> EndpointResponse {
        EndpointResponse {
            status: 200,
            headers: vec![("x-served-by".into(), self.label.into())],
            body: format!("{} {} {}", self.label, req.method, req.path).into_bytes(),
        }
    }
}

fn expect_err(r: Result<PluginRouteTable, String>) -> String {
    match r {
        Err(e) => e,
        Ok(_) => panic!("expected the registration to be REFUSED, but it succeeded"),
    }
}

fn decl(
    owner: &str,
    kind: RouteKind,
    path: &str,
    method: RouteMethod,
    auth: RouteAuth,
    label: &'static str,
) -> RouteDecl {
    RouteDecl {
        owner: owner.to_string(),
        source_instance: owner.to_string(),
        dispatch_available: true,
        kind,
        route: Route {
            path: path.to_string(),
            method,
            auth,
        },
        scrape: false,
        persistent: false,
        dispatch: Arc::new(FakeDispatch { label }),
    }
}

#[test]
fn collision_is_a_loud_failure_naming_the_owner() {
    let mut decls = vec![
        decl(
            "prometheus",
            RouteKind::Export,
            "/metrics",
            RouteMethod::Get,
            RouteAuth::None,
            "prom",
        ),
        decl(
            "datadog",
            RouteKind::Export,
            "/metrics",
            RouteMethod::Get,
            RouteAuth::None,
            "dd",
        ),
    ];
    for route in &mut decls {
        route.scrape = true;
    }
    let err = expect_err(build_route_table(decls));
    assert_eq!(
        err,
        "plugin \"datadog\" cannot register GET /metrics — already registered by \"prometheus\""
    );
}

#[test]
fn granted_public_route_is_not_hardcoded_to_an_exporter_path() {
    let granted = |path| RouteDecl {
        scrape: true,
        ..decl(
            "neutral",
            RouteKind::Export,
            path,
            RouteMethod::Get,
            RouteAuth::Key,
            "ok",
        )
    };
    let table = build_route_table(vec![granted("/observations")])
        .expect("the trusted consumer declares its own public path");
    assert_eq!(
        table.declared_auth("/observations", &http::Method::GET),
        Some(RouteAuth::Key)
    );
    assert!(build_route_table(vec![granted("/api/admin")]).is_err());
    assert!(build_route_table(vec![granted("/healthz")]).is_err());
    assert!(build_route_table(vec![decl(
        "neutral",
        RouteKind::Export,
        "/observations",
        RouteMethod::Get,
        RouteAuth::Key,
        "refused"
    )])
    .is_err());
}

#[test]
fn same_path_different_method_is_not_a_collision() {
    let decls = vec![
        decl(
            "sr",
            RouteKind::Hook,
            "/hooks/sr/feedback",
            RouteMethod::Get,
            RouteAuth::Key,
            "g",
        ),
        decl(
            "sr",
            RouteKind::Hook,
            "/hooks/sr/feedback",
            RouteMethod::Post,
            RouteAuth::Key,
            "p",
        ),
    ];
    assert!(build_route_table(decls).is_ok());
}

#[test]
fn confinement_rejects_hook_out_of_namespace() {
    assert!(build_route_table(vec![decl(
        "sr",
        RouteKind::Hook,
        "/hooks/sr/feedback",
        RouteMethod::Post,
        RouteAuth::Key,
        "ok",
    )])
    .is_ok());

    assert!(expect_err(build_route_table(vec![decl(
        "sr",
        RouteKind::Hook,
        "/api/v1/admin/keys",
        RouteMethod::Get,
        RouteAuth::Admin,
        "x",
    )]))
    .contains("/api/* admin surface is reserved"));

    assert!(expect_err(build_route_table(vec![decl(
        "sr",
        RouteKind::Hook,
        "/metrics",
        RouteMethod::Get,
        RouteAuth::None,
        "x",
    )]))
    .contains("/hooks/sr/*"));

    assert!(expect_err(build_route_table(vec![decl(
        "sr",
        RouteKind::Hook,
        "/feedback",
        RouteMethod::Post,
        RouteAuth::Key,
        "x",
    )]))
    .contains("/hooks/sr/*"));
}

#[test]
fn confinement_export_metrics_exception_and_reserved_routes() {
    assert!(build_route_table(vec![RouteDecl {
        scrape: true,
        ..decl(
            "prometheus",
            RouteKind::Export,
            "/metrics",
            RouteMethod::Get,
            RouteAuth::None,
            "ok",
        )
    }])
    .is_ok());

    assert!(build_route_table(vec![decl(
        "datadog",
        RouteKind::Export,
        "/exports/datadog/push",
        RouteMethod::Post,
        RouteAuth::Key,
        "ok",
    )])
    .is_ok());

    assert!(expect_err(build_route_table(vec![decl(
        "prometheus",
        RouteKind::Export,
        "/stats",
        RouteMethod::Get,
        RouteAuth::None,
        "x",
    )]))
    .contains("reserved core route"));

    assert!(expect_err(build_route_table(vec![decl(
        "datadog",
        RouteKind::Export,
        "/anywhere",
        RouteMethod::Get,
        RouteAuth::None,
        "x",
    )]))
    .contains("/exports/datadog/*"));
}

#[test]
fn only_the_scrape_sink_claims_metrics_hooks() {
    let hooks = |owner: &str, kind: RouteKind, scrape: bool| RouteDecl {
        scrape,
        ..decl(
            owner,
            kind,
            "/metrics/hooks",
            RouteMethod::Get,
            RouteAuth::Key,
            "x",
        )
    };
    assert!(build_route_table(vec![hooks("prometheus", RouteKind::Export, true)]).is_ok());
    for refused in [
        hooks("datadog", RouteKind::Export, false),
        hooks("sr", RouteKind::Hook, false),
    ] {
        assert!(expect_err(build_route_table(vec![refused])).contains("routes are confined"));
    }
}

// Actual export dispatch, same-listener generation swaps and GET/HEAD crossings live in
// busbar/src/tests/kernel_application/plugin_routes_actual.rs, where a real root and
// a real dropped Prometheus owner replace the former label-echo application fixture.

#[test]
fn admin_auth_route_is_classified_to_the_admin_plane_only() {
    let table = build_route_table(vec![decl(
        "audit-sink",
        RouteKind::Export,
        "/exports/audit-sink/admin-op",
        RouteMethod::Get,
        RouteAuth::Admin,
        "audit",
    )])
    .unwrap();
    assert!(
        table.mounts_for_plane(false).is_empty(),
        "an auth:admin route is absent from the data plane"
    );
    assert_eq!(
        table.mounts_for_plane(true).len(),
        1,
        "an auth:admin route is on the admin plane"
    );
}

// The former injected audit-sink response only proved its own fake body. The actual
// core-admin info owner now witnesses physical listener isolation (404 data / 200
// authenticated admin) in plugin_routes_actual.rs. The policy test above separately
// retains plugin auth:admin -> admin-plane classification; it does not claim a real
// plugin auth:admin wire crossing.

#[test]
fn head_is_looked_up_as_the_declared_get_route() {
    let table = build_route_table(vec![decl(
        "prometheus",
        RouteKind::Export,
        "/exports/prometheus/scrape",
        RouteMethod::Get,
        RouteAuth::None,
        "prom",
    )])
    .unwrap();
    assert_eq!(
        table.declared_auth("/exports/prometheus/scrape", &axum::http::Method::HEAD),
        Some(RouteAuth::None),
        "a HEAD to a declared GET plugin route must resolve to that route's declared auth"
    );
    assert_eq!(
        route_method_of(&axum::http::Method::HEAD),
        Some(RouteMethod::Get),
        "HEAD maps onto the declared GET route (axum already routes HEAD to the GET handler)"
    );

    assert_eq!(route_method_of(&axum::http::Method::OPTIONS), None);
    assert_eq!(route_method_of(&axum::http::Method::TRACE), None);
}

#[tokio::test]
async fn head_dispatches_to_the_declared_get_route() {
    const P: &str = "/exports/prometheus/scrape";
    let table = Arc::new(
        build_route_table(vec![decl(
            "prometheus",
            RouteKind::Export,
            P,
            RouteMethod::Get,
            RouteAuth::None,
            "prom",
        )])
        .unwrap(),
    );
    let (data_router, _admin_router, _handle) = crate::build_split_routers_with_limits(
        app_with_table(table),
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, data_router).await.unwrap() });
    let resp = reqwest::Client::new()
        .head(format!("http://{addr}{P}"))
        .send()
        .await
        .unwrap();
    let code = resp.status().as_u16();
    let served_by = resp
        .headers()
        .get("x-served-by")
        .map(|v| v.to_str().unwrap().to_string());
    server.abort();
    assert_eq!(
        code, 200,
        "HEAD on a declared GET plugin route is served, not 405'd"
    );
    assert_eq!(
        served_by.as_deref(),
        Some("prom"),
        "the owning plugin served the HEAD"
    );
}

#[test]
fn over_cap_request_headers_are_marked_not_silently_cut() {
    let mut headers = HeaderMap::new();
    for i in 0..100 {
        headers.insert(
            axum::http::HeaderName::try_from(format!("x-custom-{i}")).unwrap(),
            axum::http::HeaderValue::from_static("v"),
        );
    }
    let projected = project_request_headers(&headers);

    assert!(
        projected.len() <= MAX_PLUGIN_HEADERS,
        "the projection stays bounded"
    );
    assert!(
        projected
            .iter()
            .any(|(k, v)| k == PLUGIN_REQUEST_HEADERS_TRUNCATED_MARKER && v == "true"),
        "an over-cap request header set MUST carry the truncation marker, never a silent cut \
         (got: {projected:?})"
    );
}

#[test]
fn under_cap_request_headers_carry_no_marker() {
    let mut headers = HeaderMap::new();
    headers.insert("x-one", axum::http::HeaderValue::from_static("v1"));
    headers.insert("x-two", axum::http::HeaderValue::from_static("v2"));
    let projected = project_request_headers(&headers);

    assert_eq!(projected.len(), 2);
    assert!(
        !projected
            .iter()
            .any(|(k, _)| k == PLUGIN_REQUEST_HEADERS_TRUNCATED_MARKER),
        "no marker when nothing was truncated"
    );
}

#[test]
fn non_text_request_headers_mark_the_projection_incomplete() {
    let mut headers = HeaderMap::new();
    headers.insert("x-readable", axum::http::HeaderValue::from_static("kept"));
    headers.insert(
        "x-unreadable",
        axum::http::HeaderValue::from_bytes(&[0xff]).unwrap(),
    );
    let projected = project_request_headers(&headers);
    assert!(projected
        .iter()
        .any(|(k, v)| k == "x-readable" && v == "kept"));
    assert!(!projected.iter().any(|(k, _)| k == "x-unreadable"));
    assert!(projected
        .iter()
        .any(|(k, v)| { k == PLUGIN_REQUEST_HEADERS_TRUNCATED_MARKER && v == "true" }));

    headers.remove("x-unreadable");
    headers.insert(
        "authorization",
        axum::http::HeaderValue::from_bytes(&[0xff]).unwrap(),
    );
    assert_eq!(
        project_request_headers(&headers),
        vec![("x-readable".to_string(), "kept".to_string())]
    );
}

#[test]
fn over_cap_response_headers_are_rejected_not_silently_truncated() {
    let headers: Vec<(String, String)> = (0..100)
        .map(|i| (format!("x-resp-{i}"), "v".to_string()))
        .collect();
    let resp = EndpointResponse {
        status: 200,
        headers,
        body: b"hello".to_vec(),
    };
    let out = relay_response("some-plugin", "/exports/some-plugin/x", resp);
    assert_eq!(
        out.status(),
        StatusCode::BAD_GATEWAY,
        "an over-cap plugin response must be REJECTED (502), never relayed with a silently \
         truncated header set"
    );
}

#[test]
fn under_cap_response_headers_relay_unchanged() {
    let resp = EndpointResponse {
        status: 201,
        headers: vec![("x-a".into(), "1".into()), ("x-b".into(), "2".into())],
        body: b"ok".to_vec(),
    };
    let out = relay_response("some-plugin", "/exports/some-plugin/x", resp);
    assert_eq!(out.status(), StatusCode::CREATED);
    assert_eq!(out.headers().get("x-a").unwrap(), "1");
    assert_eq!(out.headers().get("x-b").unwrap(), "2");
}

#[test]
fn paths_awaiting_restart_flags_only_newly_declared_unmounted_paths() {
    fn table(paths: &[&str]) -> PluginRouteTable {
        build_route_table(
            paths
                .iter()
                .map(|p| RouteDecl {
                    scrape: true,
                    ..decl(
                        "prometheus",
                        RouteKind::Export,
                        p,
                        RouteMethod::Get,
                        RouteAuth::Key,
                        "x",
                    )
                })
                .collect(),
        )
        .expect("the fixture declares no colliding route")
    }
    fn boot(paths: &[&str]) -> std::collections::HashSet<String> {
        paths.iter().map(|p| p.to_string()).collect()
    }
    let empty = table(&[]);
    let metrics = table(&["/metrics"]);

    assert_eq!(
        paths_awaiting_restart(&metrics, &empty, &boot(&[])),
        vec!["/metrics".to_string()],
    );

    assert!(paths_awaiting_restart(&metrics, &empty, &boot(&["/metrics"])).is_empty());

    assert!(paths_awaiting_restart(&empty, &metrics, &boot(&["/metrics"])).is_empty());

    assert!(paths_awaiting_restart(&metrics, &metrics, &boot(&[])).is_empty());
}

#[tokio::test]
async fn response_body_wipes_when_the_last_http_chunk_retires_or_is_abandoned() {
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicBool, Ordering};

    for consume in [false, true] {
        let payload = b"private-outbound-metric-label".to_vec();
        let at = payload.as_ptr();
        let retired = Arc::new(AtomicBool::new(false));
        let mut owner = ResponseBytes::new(payload);
        owner.retired = Some(retired.clone());
        let mut body = Body::from(Bytes::from_owner(owner));
        if consume {
            let frame = body.frame().await.unwrap().unwrap();
            let chunk = frame.into_data().unwrap();
            assert_eq!(chunk.as_ptr(), at, "relay preserves the guarded allocation");
            assert_eq!(&chunk[..], b"private-outbound-metric-label");
            let last = chunk.clone();
            drop(chunk);
            drop(body);
            assert!(!retired.load(Ordering::SeqCst));
            drop(last);
        } else {
            drop(body);
        }
        assert!(retired.load(Ordering::SeqCst), "live body retired unwiped");
    }
}
