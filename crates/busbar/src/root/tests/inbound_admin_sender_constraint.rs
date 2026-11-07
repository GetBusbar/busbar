// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::auth::POINT_HEAD;
use busbar_contract::abi::host::service::{FLOW_CONTINUE, FLOW_STOP};
use busbar_contract::abi::transport::route::{METHOD_GET, METHOD_POST, PATH_EXACT};
use busbar_kernel::auth::{admin_door_admits, AdminDoor};
use busbar_kernel::guest::{Claimant, Line, LineAuth, Route};
use busbar_kernel::inbound::{Call, HandIn, Head};
use tower::ServiceExt as _;

const PATH: &str = "/api/v1/admin/keys";
const AUDIENCE: &str = "api://inbound-body-cap";
const LISTENER: u64 = 91;
const FRAMING: u64 = 92;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_admin_doors_refuse_sender_downgrade_and_preserve_service_and_scoped_credentials() {
    let (app, _config, _book) = app_with_admin_reader(false, true).await;
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::clone(&app)));
    let router = busbar_kernel::router::build_admin_router_on(&handle, 32 * 1024 * 1024, false);
    // Seal a neutral line over the same actual opened auth products. The admin HTTP adapter
    // below covers both admin carriers; the generic neutral listener uses the default inbound
    // carriers and separately covers the receipt projection boundary with Authorization.
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer carrier-probe"),
    );
    assert_eq!(
        app.auth.extract_client_token(&headers).as_deref(),
        Some("carrier-probe")
    );
    headers.clear();
    headers.insert(
        "x-admin-token",
        http::HeaderValue::from_static("carrier-probe"),
    );
    assert_eq!(app.auth.extract_client_token(&headers), None);
    let line = |methods| Line {
        route: Route {
            methods,
            path_form: PATH_EXACT,
            path: PATH.into(),
            fields: vec![],
            rung: 0,
        },
        claimant: Claimant::Clean("admin-sender-constraint-test".into()),
        dialect: 0,
        auth: LineAuth::Chain(
            app.admin_chain.clone(),
            busbar_contract::abi::auth::AuthPoints::HEAD,
        ),
        upgrade: None,
        offered: crate::root::doors::offers_unstated(),
    };
    let mut auths: std::collections::HashMap<_, _> = app
        .admin_modules
        .modules
        .iter()
        .map(|(provider, module)| (provider.clone(), module.calls.clone()))
        .collect();
    if let busbar_kernel::auth::OperatorCredential::Module(calls) = &*app.admin_modules.operator {
        auths.insert(
            busbar_kernel::config::operator_provider().to_owned(),
            calls.clone(),
        );
    }
    let listener = kin::Listener {
        guests: GuestList::seal(vec![line(METHOD_GET), line(METHOD_POST)]).unwrap(),
        auths,
        body_limit: 1024,
        app: Arc::clone(&app),
        door_refusals: vec![],
        ids: vec![1, 2],
        signed_ingress: Arc::new(|_, _| false),
        scope: None,
    };
    let guests = listener.guests.clone();
    let next = Arc::new(AtomicU64::new(1));
    let inbound = Inbound::new(
        kin::Seals {
            mint: Arc::new(move || next.fetch_add(1, Ordering::SeqCst)),
            mac: Arc::new(|tag| {
                auth_handle::mint_unit_ref(
                    tag.secret,
                    tag.generation,
                    tag.owner,
                    tag.line,
                    tag.unit,
                )
                .map(|unit| unit.mac)
            }),
        },
        Arc::new(|future| {
            tokio::spawn(future);
        }),
        Arc::new(|_| {}),
    );
    inbound.install_at(OWNER, LISTENER, GEN, listener).unwrap();
    inbound
        .framing_started(OWNER, LISTENER, FRAMING, GEN)
        .unwrap();
    let specs = inbound.specs_at(OWNER, LISTENER, GEN).unwrap();
    let bound = crate::test_common::credentials::token_with_claims(
        "bound-reader",
        &["readers"],
        AUDIENCE,
        serde_json::json!({"cnf": {"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}}),
    );
    let ordinary = crate::test_common::credentials::token_for("reader", &["readers"], AUDIENCE);
    let wrong_audience =
        crate::test_common::credentials::token_for("reader", &["readers"], "api://other");
    let expired = crate::test_common::credentials::token_with_claims(
        "expired-reader",
        &["readers"],
        AUDIENCE,
        serde_json::json!({"exp": 1}),
    );
    let no_grant = crate::test_common::credentials::token_for("unprivileged", &[], AUDIENCE);
    let cases = [
        ("GET", ordinary.as_str(), 200, false),
        ("POST", ordinary.as_str(), 403, false),
        ("GET", no_grant.as_str(), 403, false),
        ("GET", wrong_audience.as_str(), 401, false),
        ("GET", expired.as_str(), 401, false),
        ("GET", bound.as_str(), 401, false),
        ("GET", bound.as_str(), 401, true),
        // A second presentation remains refused; rejection cannot populate a usable verdict.
        ("GET", bound.as_str(), 401, true),
        ("GET", "actual-inbound-operator", 200, false),
        ("GET", ordinary.as_str(), 200, false),
    ];
    let mut stream = 0;
    for carrier in ["authorization", "x-admin-token"] {
        for (case, (method, token, expected, proof)) in cases.into_iter().enumerate() {
            stream += 1;
            let value = if carrier == "authorization" {
                format!("Bearer {token}")
            } else {
                token.to_owned()
            };
            let mut head = Head {
                method: method.into(),
                target: PATH.into(),
                authority: "admin.test".into(),
                query: None,
                fields: vec![(carrier.into(), value.as_bytes().to_vec())],
            };
            if proof {
                head.fields.push((
                    "dpop".into(),
                    b"an-unverified-proof-is-not-authority".to_vec(),
                ));
            }

            // Legacy/admin HTTP admission performs real signature, issuer, audience and expiry
            // verification through the loaded OIDC product, then applies the sender guard.
            let mut request = axum::http::Request::builder()
                .method(method)
                .uri(PATH)
                .header(carrier, &value);
            if proof {
                request = request.header("dpop", "an-unverified-proof-is-not-authority");
            }
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                router
                    .clone()
                    .oneshot(request.body(axum::body::Body::empty()).unwrap()),
            )
            .await
            .expect("the actual admin request is bounded")
            .unwrap();
            assert_eq!(
                response.status().as_u16(),
                expected,
                "HTTP: case={case}, {method} {carrier}, proof={proof}"
            );
            axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();

            // x-admin-token belongs to the HTTP admin adapter, not the generic listener's
            // declared inbound carriers. Its HTTP assertion above is still required.
            if carrier == "x-admin-token" {
                continue;
            }

            // The neutral transport has its own verified receipt projection. Exercise that real
            // path with the same loaded auth products and the sealed listener's lines.
            inbound.grant_stream(OWNER, FRAMING, stream, GEN).unwrap();
            let selected = selected_line(&guests, &head);
            assert_ne!(selected, LINE_NONE, "the actual admin route is present");
            let line = specs.iter().find(|spec| spec.line == selected).unwrap();
            assert_ne!(line.points & POINT_HEAD, 0);
            let (done, waited) = tokio::sync::oneshot::channel();
            let immediate = inbound.auth_call(
                Call {
                    owner: OWNER,
                    generation: GEN,
                    auth: line.auth,
                    unit: UnitRef::NONE,
                    point: POINT_HEAD,
                    conn: FRAMING,
                    stream,
                    framing: FRAMING,
                    head: head.clone(),
                    body: None,
                    deadline: None,
                },
                Box::new(move |answer| {
                    let _ = done.send(answer);
                }),
            );
            let answer = match immediate {
                Some(answer) => answer,
                None => tokio::time::timeout(std::time::Duration::from_secs(10), waited)
                    .await
                    .expect("the actual neutral verifier is bounded")
                    .unwrap(),
            }
            .unwrap();
            if answer.flow == FLOW_STOP {
                assert_eq!(
                    expected, 401,
                    "only invalid credentials stop before admin projection: case={case}, {method} {carrier}, proof={proof}"
                );
            } else {
                assert_eq!(answer.flow, FLOW_CONTINUE);
                let mut sanitized = head;
                sanitized.fields.retain(|(name, _)| {
                    !answer.strips.iter().any(|strip| {
                        strip.place == busbar_contract::auth_calls::StripPlace::Field
                            && strip.name.eq_ignore_ascii_case(name)
                    })
                });
                let handed = inbound
                    .hand_in(HandIn {
                        owner: OWNER,
                        generation: GEN,
                        auth: line.auth,
                        unit: answer.unit,
                        line: selected,
                        conn: FRAMING,
                        stream,
                        framing: Some(FRAMING),
                        head: sanitized.clone(),
                    })
                    .unwrap();
                assert_eq!(handed.0, FLOW_CONTINUE);
                let receipt = inbound
                    .claim_request(OWNER, FRAMING, stream, &sanitized)
                    .unwrap();
                let verdict = receipt.admin_verdict();
                let status = if matches!(verdict.door, AdminDoor::Denied) {
                    401
                } else if admin_door_admits(&verdict.door, method, PATH) {
                    200
                } else {
                    403
                };
                assert_eq!(
                    status, expected,
                    "neutral receipt: case={case}, {method} {carrier}, proof={proof}"
                );
            }
            inbound.stream_ended(OWNER, FRAMING, stream);
        }
    }
    inbound.framing_ended(FRAMING);
}
