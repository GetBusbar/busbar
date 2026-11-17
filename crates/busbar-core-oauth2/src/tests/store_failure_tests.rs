// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A consent session or answer the store did not keep is refused, never answered as kept.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::testkit::MemoryBackend;

async fn plane_over(backend: &Arc<MemoryBackend>) -> crate::plane::AsPlane {
    let store = crate::testkit::memory_store_on(Arc::clone(backend)).await;
    let identity = crate::config::AsIdentity::from_cfg(&crate::config::OauthAsCfg {
        issuer: "https://as.example".to_string(),
        ..Default::default()
    })
    .expect("a valid oauth_as block");
    crate::plane::AsPlane::build_carrying(
        identity,
        crate::testkit::ADMIN_ORIGIN.to_string(),
        None,
        Vec::new(),
        crate::cimd::unconnected(),
        Arc::new(crate::plane::Carried::over(store).expect("the store opens")),
    )
    .await
    .expect("the plane builds")
}

#[tokio::test]
async fn a_consent_session_the_store_refused_is_not_opened() {
    let backend = Arc::new(MemoryBackend::default());
    let plane = plane_over(&backend).await;
    backend.refuse_commits.store(true, Ordering::SeqCst);
    let opened = plane
        .open_session("busbar-operator", "session-refused".to_string())
        .await;
    assert!(opened.is_err(), "a session the store refused is an error");
    assert!(
        plane.sessions().subject("session-refused").is_none(),
        "a session the store refused was opened in memory anyway: {opened:?}"
    );
}

#[tokio::test]
async fn a_consent_answer_the_store_refused_is_an_error_and_not_staked() {
    let backend = Arc::new(MemoryBackend::default());
    let plane = plane_over(&backend).await;
    let session = plane
        .open_session("busbar-operator", "session-kept".to_string())
        .await
        .expect("the store keeps the session");
    backend.refuse_commits.store(true, Ordering::SeqCst);
    assert!(
        plane
            .stake(&session, "request-1".to_string(), true)
            .await
            .is_err(),
        "an answer the store refused must not read as kept"
    );
    backend.refuse_commits.store(false, Ordering::SeqCst);
    assert!(
        !plane.is_staked(&session, "request-1").await,
        "the refused answer is not staked"
    );
}
