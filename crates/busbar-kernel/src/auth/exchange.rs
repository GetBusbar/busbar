// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};

use super::self_keys::{
    admit_self_mint, issue_key, DeterministicEd25519Keys, ExchangeError, HandleProvisioner,
    IssuedKey, SelfMint,
};
use super::AuthMiddleware;
use crate::diagnostics::{diag_error, TOKEN_EXCHANGE_MINT_FAILED};

pub(crate) const AUTH_TOKEN_PATH: &str = "/auth/token";

pub(crate) async fn exchange(
    State(handle): State<Arc<crate::state::AppHandle>>,
    req: Request<Body>,
) -> Response {
    let app = handle.load();

    let req = match crate::auth::login::seam::credential_form(handle.clone(), req).await {
        Ok(answered) => return answered,
        Err(req) => *req,
    };

    let candidate = app.auth.extract_client_token(req.headers());

    let judged = if app.oauth_as.is_some() {
        crate::auth::dpop::judge(
            &app,
            req.method(),
            req.uri().path(),
            req.headers(),
            candidate.as_deref(),
            &mut None,
        )
        .await
    } else {
        crate::auth::dpop::SenderConstraint::Unconstrained
    };
    let candidate = match judged {
        crate::auth::dpop::SenderConstraint::Unconstrained => candidate,
        crate::auth::dpop::SenderConstraint::Proven(token) => Some(token),
        crate::auth::dpop::SenderConstraint::Refused => {
            return refusal(ExchangeError::Unauthorized)
        }
    };
    let (judged, _, claim) = AuthMiddleware::judge_chain_on_request_path_naming(
        &app.auth,
        candidate,
        crate::auth::ChainHead::of(&req),
        app.governance.clone(),
        None,
    )
    .await;
    let verdict = match exchange_verdict_result(judged) {
        Ok(verdict) => verdict,
        Err(response) => return response,
    };

    let (
        SelfMint {
            principal,
            team,
            granted_scopes: pools,
            ttl,
        },
        provider,
        gov,
    ) = match admit_exchange_mint(
        &verdict,
        &app.role_bindings,
        &app.mint_policy,
        app.self_key_ttl_secs,
        app.governance.as_ref(),
        claim,
    )
    .await
    {
        Ok(admitted) => admitted,
        Err(error) => return refusal(error),
    };

    let provisioner = Arc::new(HandleProvisioner::new(handle.clone(), principal.id.clone()));
    let keys = DeterministicEd25519Keys::new(gov, provider.to_string(), team, pools, provisioner);
    match issue_key(&keys, principal, ttl, false).await {
        Ok(issued) => {
            let base_url = app.public_url.as_deref().unwrap_or("");
            (
                StatusCode::OK,
                axum::Json(exchange_ok_body(&issued, base_url)),
            )
                .into_response()
        }
        Err(e) => refusal(e),
    }
}

fn exchange_verdict_result(
    judged: Result<super::ChainVerdict, super::VerifierUnavailable>,
) -> Result<super::ChainVerdict, Response> {
    match judged {
        Ok(verdict) => Ok(verdict),
        Err(super::VerifierUnavailable::NoVerdict) => {
            Err(crate::limits::admission::inbound_overloaded_response())
        }
        Err(super::VerifierUnavailable::Overloaded) => Ok(super::ChainVerdict::Denied),
    }
}

// The post-verification admission continuation. A rejected policy/provider/governance decision
// must return before the verified identity's replay claim can be consumed.
async fn admit_exchange_mint<'a>(
    verdict: &'a super::ChainVerdict,
    bindings: &crate::config::RoleBindings,
    policy: &crate::governance::mint_policy::MintPolicy,
    default_ttl: u64,
    governance: Option<&Arc<crate::governance::GovState>>,
    claim: Option<super::PendingClaim>,
) -> Result<(SelfMint<'a>, &'a str, Arc<crate::governance::GovState>), ExchangeError> {
    let admitted = admit_self_mint(verdict, bindings, policy, default_ttl)?;
    let super::ChainVerdict::Identified {
        module: provider, ..
    } = verdict
    else {
        return Err(ExchangeError::Unauthorized);
    };
    let Some(gov) = governance.cloned() else {
        return Err(ExchangeError::MintFailed(
            "governance is disabled: cannot mint keys".to_string(),
        ));
    };
    if let Some(claim) = claim {
        if !claim.win().await {
            return Err(ExchangeError::Unauthorized);
        }
    }
    Ok((admitted, provider.as_str(), gov))
}

fn exchange_ok_body(issued: &IssuedKey, base_url: &str) -> serde_json::Value {
    serde_json::json!({
        // `.expose(&crate::seal::lend())`: the once-shown mint response is the intended, documented plaintext
        // egress of the issued token (Secret has no Serialize, so json! cannot embed it directly).
        "api_key": issued.secret.expose(&crate::seal::lend()),
        "key_id": issued.key_id,
        "group": issued.group,
        "exp": issued.exp,
        "base_url": base_url,
    })
}

fn refusal(e: ExchangeError) -> Response {
    let (status, msg) = match e {
        ExchangeError::StaticKeyPresented => (
            StatusCode::BAD_REQUEST,
            "present an IdP identity, not a busbar key",
        ),
        ExchangeError::Unauthorized => (StatusCode::UNAUTHORIZED, "not authenticated"),
        ExchangeError::SelfMintDisabled => (
            StatusCode::FORBIDDEN,
            "self-serve minting is disabled by policy",
        ),
        ExchangeError::Unbound => (
            StatusCode::FORBIDDEN,
            "no self-serve grant for this identity",
        ),
        ExchangeError::BadSubject => (StatusCode::FORBIDDEN, "identity is not a valid subject"),
        ExchangeError::OverCeiling(_) => (
            StatusCode::FORBIDDEN,
            "the key this identity would mint is over the mint ceiling (auth.policy)",
        ),
        ExchangeError::MintFailed(ref detail) => {
            diag_error!(TOKEN_EXCHANGE_MINT_FAILED, error = %detail, "token-exchange mint failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "could not issue a key")
        }
    };
    (status, axum::Json(serde_json::json!({ "error": msg }))).into_response()
}

#[cfg(test)]
#[path = "tests/exchange_tests.rs"]
mod tests;
