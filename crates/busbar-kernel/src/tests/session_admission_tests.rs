// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{FramedSession, SessionAdmission};
use axum::extract::FromRequestParts;

#[tokio::test]
async fn a_default_or_disconnected_slot_has_no_admission_authority() {
    assert!(!FramedSession::default().admit().await);
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel::<SessionAdmission>();
    drop(receiver);
    assert!(!FramedSession::with_admission(sender, 17).admit().await);
}

#[tokio::test]
async fn admission_names_the_request_and_is_consumed_once_across_clones() {
    let (sender, mut requests) = tokio::sync::mpsc::unbounded_channel::<SessionAdmission>();
    let slot = FramedSession::with_admission(sender, 29);
    let copy = slot.clone();
    let admit = slot.admit();
    tokio::pin!(admit);
    let answer = async {
        let request = requests.recv().await.expect("one admission request");
        assert_eq!(request.stream, 29);
        assert!(!copy.admit().await, "in-flight authority cannot be reused");
        request.reply.send(true).unwrap();
    };
    let (accepted, ()) = tokio::join!(admit, answer);
    assert!(accepted);
    assert!(!copy.admit().await, "accepted authority cannot be reused");
    assert!(requests.try_recv().is_err(), "only one request was sent");
}

#[tokio::test]
async fn a_refused_or_abandoned_admission_stays_refused() {
    for abandoned in [false, true] {
        let (sender, mut requests) = tokio::sync::mpsc::unbounded_channel::<SessionAdmission>();
        let slot = FramedSession::with_admission(sender, 31);
        let admit = slot.admit();
        let answer = async {
            let request = requests.recv().await.unwrap();
            if !abandoned {
                request.reply.send(false).unwrap();
            }
        };
        let (accepted, ()) = tokio::join!(admit, answer);
        assert!(!accepted);
        assert!(!slot.admit().await);
    }
}

#[tokio::test]
async fn raw_upgrade_headers_cannot_turn_an_empty_extension_into_admission() {
    let request = axum::http::Request::builder()
        .method("GET")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-version", "13")
        .extension(FramedSession::default())
        .body(())
        .unwrap();
    let (mut parts, ()) = request.into_parts();
    assert!(matches!(
        crate::ingress::session::SessionUpgrade::from_request_parts(&mut parts, &()).await,
        Err(axum::http::StatusCode::FORBIDDEN)
    ));
}

#[tokio::test]
async fn a_forged_extension_cannot_enter_the_session_handler() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tower::ServiceExt;
    let entered = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&entered);
    let router = axum::Router::new().route(
        "/session",
        axum::routing::get(
            move |_: crate::ingress::session::SessionUpgrade| async move {
                seen.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::NO_CONTENT
            },
        ),
    );
    let request = axum::http::Request::builder()
        .uri("/session")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-version", "13")
        .extension(FramedSession::default())
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(entered.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_typed_admission_completes_before_the_handler_without_wire_header_checks() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tower::ServiceExt;
    let entered = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&entered);
    let router = axum::Router::new().route(
        "/session",
        axum::routing::get(
            move |_: crate::ingress::session::SessionUpgrade| async move {
                seen.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::NO_CONTENT
            },
        ),
    );
    let (sender, mut admissions) = tokio::sync::mpsc::unbounded_channel::<SessionAdmission>();
    let request = axum::http::Request::builder()
        .uri("/session")
        .extension(FramedSession::with_admission(sender, 71))
        .body(axum::body::Body::empty())
        .unwrap();
    let answer = async {
        let admission = admissions.recv().await.unwrap();
        assert_eq!(admission.stream, 71);
        assert_eq!(entered.load(Ordering::SeqCst), 0);
        admission.reply.send(true).unwrap();
    };
    let (response, ()) = tokio::join!(router.oneshot(request), answer);
    assert_eq!(
        response.unwrap().status(),
        axum::http::StatusCode::NO_CONTENT
    );
    assert_eq!(entered.load(Ordering::SeqCst), 1);
}
