// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SESSION'S ADMISSION: the configured auth chain run over a caller's own credential, then the one
//! verdict resolution the HTTP middleware uses ([`super::resolve_data_plane_identity`]).
//!
//! A carrier that admits a session outside an HTTP request (the stdio session's environment
//! credential) calls this directly. It runs the same chain with the same expected audience and
//! answers the same refusal variants, so the session renders the same sentence for each.

use std::sync::Arc;

/// Admit one session: run the configured chain over `token` (the caller's own credential; `None` is
/// no candidate, distinct from an empty one) against the expected `audience` (empty ⇒ no audience
/// expectation), then resolve the verdict to a principal and a governance context.
///
/// The chain runs on its own task, so a panic inside it refuses (`Denied`) rather than unwinding
/// into the caller; a chain that could not run denies, exactly as a refused one does.
///
/// # Errors
/// [`super::IdentityRefusal::Denied`] for a refused or failed chain, and
/// [`super::IdentityRefusal::NoGrant`] for a principal holding no grant.
pub async fn admit_session(
    app: Arc<crate::state::App>,
    token: Option<String>,
    audience: String,
) -> Result<(super::AuthPrincipal, crate::governance::PlaneRequestCtx), super::IdentityRefusal> {
    tokio::spawn(async move {
        let expected_aud = (!audience.is_empty()).then_some(audience);
        let verdict = super::AuthMiddleware::run_chain_on_request_path(
            &app.auth,
            token,
            // The session carries the caller's credential and no request head.
            super::ChainHead::default(),
            app.governance.clone(),
            expected_aud,
        )
        .await;
        super::resolve_data_plane_identity(&app, verdict)
    })
    .await
    .unwrap_or(Err(super::IdentityRefusal::Denied))
}

#[cfg(test)]
#[path = "tests/admit_tests.rs"]
mod tests;
