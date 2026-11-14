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
        None,
        Vec::new(),
        crate::cimd::unconnected(),
        Arc::new(crate::plane::Carried::over(Some(store)).expect("the store opens")),
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
    assert!(
        plane.sessions().subject("session-refused").is_none(),
        "a session the store refused was opened in memory anyway: {opened:?}"
    );
}
