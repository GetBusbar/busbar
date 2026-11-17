// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::inbound::request_snapshot::SnapshotInput;
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
use axum::extract::FromRequestParts;

fn snapshot(budget: &Arc<ProcessAdmission>, duplicates: usize) -> Arc<ChargedRequestSnapshot> {
    let lease = budget.try_enter(AdmissionClass::Operator).unwrap();
    let fields = vec![("if-match", b"\"original\"".as_slice()); duplicates];
    ChargedRequestSnapshot::capture(
        SnapshotInput {
            method: "PUT",
            path: "/api/v1/admin/config/settings",
            query: "",
            query_present: false,
            authority: "",
            headers: fields.iter().copied(),
            peer: "",
            tls_peer_cert: &[],
            body: &[],
            now_s: 1,
        },
        &lease,
    )
    .unwrap()
}

#[tokio::test]
async fn moved_extractor_retains_original_map_and_credit_through_last_owner() {
    let budget = ProcessAdmission::with_limits(1, 65536, 65536);
    let snapshot = snapshot(&budget, 3);
    let base = budget.used().0;
    let projection = HttpProjection::from_snapshot(snapshot.clone()).unwrap();
    let pointer = projection.headers()[header::IF_MATCH].as_bytes().as_ptr();
    let funded = budget.used().0;
    assert!(funded > base);
    let (parts, ()) = projection.into_request(()).into_parts();
    let projection = HttpProjection::from_parts(parts).unwrap();
    assert_eq!(
        projection.headers()[header::IF_MATCH].as_bytes().as_ptr(),
        pointer
    );
    let (mut parts, ()) = projection.into_request(()).into_parts();
    let headers = AdminHeaders::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert_eq!(headers.get_all(header::IF_MATCH).iter().count(), 3);
    assert_eq!(headers[header::IF_MATCH].as_bytes().as_ptr(), pointer);
    assert!(parts.headers.is_empty());
    assert!(parts
        .extensions
        .get::<Arc<ChargedRequestSnapshot>>()
        .is_some());
    drop(parts);
    drop(snapshot);
    assert_eq!(budget.used().0, funded);
    drop(headers);
    assert_eq!(budget.used().0, 0);
    assert!(budget.try_enter(AdmissionClass::Operator).is_ok());
}

#[test]
fn saturated_numeric_rewrite_leaves_original_map_untouched() {
    let budget = ProcessAdmission::with_limits(1, 65536, 65536);
    let snapshot = snapshot(&budget, 3);
    let mut request = HttpProjection::from_snapshot(snapshot.clone())
        .unwrap()
        .into_request(());
    let pointer = request.headers()[header::IF_MATCH].as_bytes().as_ptr();
    let remaining = 65536 - budget.used().0;
    let full = snapshot.request().try_reserve(remaining).unwrap();
    assert!(replace_if_match(&mut request, b"\"7\"").is_err());
    assert_eq!(
        request.headers().get_all(header::IF_MATCH).iter().count(),
        3
    );
    assert_eq!(
        request.headers()[header::IF_MATCH].as_bytes().as_ptr(),
        pointer
    );
    drop(full);
    let used = budget.used().0;
    replace_if_match(&mut request, b"\"7\"").unwrap();
    assert_eq!(
        request.headers().get_all(header::IF_MATCH).iter().count(),
        1
    );
    assert_eq!(budget.used().0, used + 3);
    let replacement = request.headers()[header::IF_MATCH].clone();
    drop(request);
    drop(snapshot);
    assert_eq!(budget.used().0, 3);
    drop(replacement);
    assert_eq!(budget.used().0, 0);
}

#[test]
fn shared_name_and_method_projections_keep_original_snapshot_backing() {
    let budget = ProcessAdmission::with_limits(1, 65536, 65536);
    let lease = budget.try_enter(AdmissionClass::Operator).unwrap();
    let fields = [("x-original-name", b"original value".as_slice())];
    let snapshot = ChargedRequestSnapshot::capture(
        SnapshotInput {
            method: "LONG-EXTENSION-METHOD",
            path: "/",
            query: "",
            query_present: false,
            authority: "",
            headers: fields.iter().copied(),
            peer: "",
            tls_peer_cert: &[],
            body: &[],
            now_s: 1,
        },
        &lease,
    )
    .unwrap();
    let projection = HttpProjection::from_snapshot(snapshot.clone()).unwrap();
    let request = projection.into_request(());
    let name = request.headers().keys().next().unwrap().clone();
    let method = request.method().clone();
    assert_eq!(
        name.as_str().as_ptr(),
        snapshot.headers().next().unwrap().0.as_ptr()
    );
    assert_eq!(method.as_str().as_ptr(), snapshot.method().as_ptr());
    let original = Arc::downgrade(&snapshot);
    drop(snapshot);
    drop(request);
    drop(lease);
    assert!(original.upgrade().is_some());
    drop(name);
    assert!(original.upgrade().is_some());
    drop(method);
    assert!(original.upgrade().is_none());
    assert_eq!(budget.used().0, 0);
}

#[tokio::test]
async fn extractor_refuses_snapshot_without_original_map_carrier() {
    let budget = ProcessAdmission::with_limits(1, 65536, 65536);
    let snapshot = snapshot(&budget, 1);
    let (mut parts, ()) = Request::new(()).into_parts();
    parts.extensions.insert(snapshot);
    assert!(AdminHeaders::from_request_parts(&mut parts, &())
        .await
        .is_err());
}

#[derive(serde::Deserialize)]
struct FormValue {
    field: String,
}

fn form_request(
    budget: &Arc<ProcessAdmission>,
    content_type: Option<&str>,
    body: &[u8],
) -> axum::extract::Request {
    let lease = budget.try_enter(AdmissionClass::Operator).unwrap();
    let fields: Vec<_> = content_type
        .into_iter()
        .map(|value| ("content-type", value.as_bytes()))
        .collect();
    let snapshot = ChargedRequestSnapshot::capture(
        SnapshotInput {
            method: "POST",
            path: "/",
            query: "",
            query_present: false,
            authority: "",
            headers: fields.iter().copied(),
            peer: "",
            tls_peer_cert: &[],
            body,
            now_s: 1,
        },
        &lease,
    )
    .unwrap();
    HttpProjection::from_snapshot(snapshot.clone())
        .unwrap()
        .into_request(axum::body::Body::from(snapshot.body_bytes()))
}

#[tokio::test]
async fn combined_form_preserves_axum_content_type_and_body_limit_outcomes() {
    use axum::{extract::DefaultBodyLimit, routing::post, Form, Router};
    use tower::ServiceExt;
    let baseline = Router::new().route(
        "/",
        post(|Form(value): Form<FormValue>| async move { value.field }),
    );
    let combined = Router::new().route(
        "/",
        post(
            |ProjectedForm { value, headers }: ProjectedForm<FormValue>| async move {
                assert!(headers.contains_key(header::CONTENT_TYPE));
                value.field
            },
        ),
    );
    for (content_type, body, limit) in [
        (None, b"field=ok".as_slice(), 1024),
        (Some("application/json"), b"field=ok".as_slice(), 1024),
        (
            Some("application/x-www-form-urlencoded"),
            b"field=ok".as_slice(),
            1024,
        ),
        (
            Some("application/x-www-form-urlencoded"),
            b"wrong=ok".as_slice(),
            1024,
        ),
        (
            Some("application/x-www-form-urlencoded"),
            b"field=ok".as_slice(),
            2,
        ),
    ] {
        let budget = ProcessAdmission::with_limits(1, 65536, 65536);
        let expected = baseline
            .clone()
            .layer(DefaultBodyLimit::max(limit))
            .oneshot(form_request(&budget, content_type, body))
            .await
            .unwrap();
        let status = expected.status();
        let expected = axum::body::to_bytes(expected.into_body(), 65536)
            .await
            .unwrap();
        assert_eq!(budget.used().0, 0);
        let actual = combined
            .clone()
            .layer(DefaultBodyLimit::max(limit))
            .oneshot(form_request(&budget, content_type, body))
            .await
            .unwrap();
        assert_eq!(actual.status(), status);
        assert_eq!(
            axum::body::to_bytes(actual.into_body(), 65536)
                .await
                .unwrap(),
            expected
        );
        assert_eq!(budget.used().0, 0);
    }
}

#[tokio::test]
async fn combined_form_capacity_and_cancellation_retire_both_maps() {
    use axum::extract::FromRequest;
    let budget = ProcessAdmission::with_limits(1, 65536, 65536);
    let request = form_request(
        &budget,
        Some("application/x-www-form-urlencoded"),
        b"field=ok",
    );
    let lease = request.extensions().get::<RequestLease>().unwrap().clone();
    let full = lease.try_reserve(65536 - budget.used().0).unwrap();
    let reply = ProjectedForm::<FormValue>::from_request(request, &()).await;
    assert!(matches!(reply, Err(response) if response.status() == 503));
    drop(full);
    drop(lease);
    assert_eq!(budget.used().0, 0);

    let mut request = form_request(&budget, Some("application/x-www-form-urlencoded"), b"");
    *request.body_mut() = axum::body::Body::from_stream(futures::stream::pending::<
        Result<bytes::Bytes, std::io::Error>,
    >());
    let original = budget.used().0;
    let mut operation = Box::pin(ProjectedForm::<FormValue>::from_request(request, &()));
    assert!(futures::poll!(operation.as_mut()).is_pending());
    assert!(
        budget.used().0 > original,
        "Form has an independent map reservation"
    );
    drop(operation);
    assert_eq!(budget.used().0, 0);
    assert!(budget.try_enter(AdmissionClass::Operator).is_ok());
}

#[tokio::test]
async fn combined_form_keeps_get_query_semantics_without_content_type() {
    use axum::extract::FromRequest;
    let budget = ProcessAdmission::with_limits(1, 65536, 65536);
    let lease = budget.try_enter(AdmissionClass::Operator).unwrap();
    let fields: [(&str, &[u8]); 0] = [];
    let snapshot = ChargedRequestSnapshot::capture(
        SnapshotInput {
            method: "GET",
            path: "/",
            query: "field=query",
            query_present: true,
            authority: "",
            headers: fields.iter().copied(),
            peer: "",
            tls_peer_cert: &[],
            body: b"field=body",
            now_s: 1,
        },
        &lease,
    )
    .unwrap();
    let request = HttpProjection::from_snapshot(snapshot.clone())
        .unwrap()
        .into_request(axum::body::Body::from(snapshot.body_bytes()));
    let form = ProjectedForm::<FormValue>::from_request(request, &())
        .await
        .unwrap();
    assert_eq!(form.value.field, "query");
    assert!(form.headers.is_empty());
    drop(snapshot);
    drop(lease);
    drop(form);
    assert_eq!(budget.used().0, 0);
}
