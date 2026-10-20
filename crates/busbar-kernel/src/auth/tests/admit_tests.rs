// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/auth/admit.rs`.

use std::sync::Arc;

/// An OPEN chain (`chain: []`, no keys arm) admits ANONYMOUS: the session gets the same chain and
/// resolution the in-process door runs — `AuthPrincipal(None)` and an ungoverned context.
#[tokio::test]
async fn an_open_chain_admits_a_session_anonymous_and_ungoverned() {
    let auth = Arc::new(crate::auth::AuthMiddleware::new_builtin(
        &crate::config::AuthCfg::default_none(),
    ));
    let app = crate::test_support::TestApp::new().auth(auth).build();
    let (principal, gov) = super::admit_session(app, None, "urn:aud".to_string())
        .await
        .expect("an open chain admits");
    assert_eq!(
        principal.actor_id(),
        "anonymous",
        "the open front door admits the anonymous principal"
    );
    assert!(
        !gov.is_governed(),
        "the open front door carries an ungoverned (key: None) context"
    );
}

/// A CONFIGURED chain refuses an unauthenticated session with the SAME `IdentityRefusal::Denied`
/// the in-process resolution returns, so the session renders its unauthenticated sentence unchanged.
#[tokio::test]
async fn a_configured_chain_denies_a_session_with_no_credential() {
    let app = crate::test_support::TestApp::new().keys_chain().build();
    let refusal = super::admit_session(app, None, "urn:aud".to_string())
        .await
        .expect_err("a configured chain refuses an unauthenticated session");
    assert_eq!(refusal, crate::auth::IdentityRefusal::Denied);
}
