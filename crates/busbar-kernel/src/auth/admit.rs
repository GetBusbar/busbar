// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

/// A line session's admission. The session's credential is moved in, in its wiping holder, and is
/// wiped when the admission task ends: the chain borrows it, nothing copies it.
pub async fn admit_session(
    app: Arc<crate::state::App>,
    token: Option<busbar_contract::secure::SecureString>,
    audience: String,
) -> Result<(super::AuthPrincipal, crate::governance::PlaneRequestCtx), super::IdentityRefusal> {
    tokio::spawn(async move {
        let expected_aud = (!audience.is_empty()).then_some(audience.as_str());
        let (verdict, _, claim) = super::AuthMiddleware::judge_chain_on_request_path_naming(
            &app.auth,
            token.as_deref(),
            &super::ChainHead::default(),
            app.governance.clone(),
            expected_aud,
        )
        .await;
        super::admit_verified_session(
            &app.role_bindings,
            verdict.unwrap_or(super::ChainVerdict::Denied),
            claim.as_ref(),
        )
        .await
    })
    .await
    .unwrap_or(Err(super::IdentityRefusal::Denied))
}
