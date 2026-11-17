// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[tokio::test]
async fn an_unresolved_consent_grant_cannot_offer_an_approval_form_or_be_cached() {
    let response = unresolved_grant(&oauth_as::store::StorageError(
        "client lookup unavailable".into(),
    ));
    assert_eq!(
        response.status(),
        503,
        "an unresolved grant cannot be approved"
    );
    assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let page = std::str::from_utf8(&body).unwrap();
    assert!(
        !page.contains("<form"),
        "no approval form on lookup failure: {page}"
    );
}

/// #359 SEC-L8: the consent pages refuse to render inside another origin's frame.
#[tokio::test]
async fn a_consent_page_refuses_framing() {
    let response = unresolved_grant(&oauth_as::store::StorageError(
        "client lookup unavailable".into(),
    ));
    assert_eq!(response.headers()[http::header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(
        response.headers()[http::header::CONTENT_SECURITY_POLICY],
        "frame-ancestors 'none'"
    );
}
