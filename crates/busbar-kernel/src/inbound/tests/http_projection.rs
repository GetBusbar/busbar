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
