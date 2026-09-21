// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/identity_admit.rs`.

use std::sync::Arc;

/// An OPEN chain (`chain: []`, no keys arm) admits ANONYMOUS through the seam: the host runs the
/// same chain + resolution the in-process door runs, and the plane recovers the EXACT resolved
/// identity through the opaque handle — `AuthPrincipal(None)` + an ungoverned context. Proves the
/// async→sync bridge, the POD marshalling, and the handle round-trip end to end.
#[tokio::test]
async fn identity_admit_over_open_chain_admits_anonymous_ungoverned() {
    let auth = Arc::new(crate::auth::AuthMiddleware::new_builtin(
        &crate::config::AuthCfg::default_none(),
    ));
    let app = crate::test_support::TestApp::new().auth(auth).build();
    let (principal, gov) =
        super::super::identity_admit_over(app, None, "urn:aud".to_string(), "urn:aud".to_string())
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

/// A CONFIGURED chain refuses an unauthenticated session through the seam with the SAME
/// `IdentityRefusal::Denied` the in-process resolution returns — the plane then renders its own
/// unauthenticated sentence unchanged (byte-identical refusal variant).
#[tokio::test]
async fn identity_admit_over_configured_chain_denies_missing_credential() {
    let app = crate::test_support::TestApp::new().keys_chain().build();
    let refusal =
        super::super::identity_admit_over(app, None, "urn:aud".to_string(), "urn:aud".to_string())
            .await
            .expect_err("a configured chain refuses an unauthenticated session");
    assert_eq!(refusal, crate::auth::IdentityRefusal::Denied);
}
