// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

pub async fn admit_session(
    app: Arc<crate::state::App>,
    token: Option<String>,
    audience: String,
) -> Result<(super::AuthPrincipal, crate::governance::PlaneRequestCtx), super::IdentityRefusal> {
    tokio::spawn(async move {
        let expected_aud = (!audience.is_empty()).then_some(audience);
        let (verdict, _, claim) = super::AuthMiddleware::judge_chain_on_request_path_naming(
            &app.auth,
            token,
            super::ChainHead::default(),
            app.governance.clone(),
            expected_aud,
        )
        .await;
        let admitted = super::resolve_data_plane_identity(
            &app,
            verdict.unwrap_or(super::ChainVerdict::Denied),
        )?;

        match claim {
            Some(claim) if !claim.win().await => Err(super::IdentityRefusal::Denied),
            _ => Ok(admitted),
        }
    })
    .await
    .unwrap_or(Err(super::IdentityRefusal::Denied))
}

#[cfg(test)]
#[path = "tests/admit_tests.rs"]
mod tests;
