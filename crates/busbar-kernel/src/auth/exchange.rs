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

    let candidate = app.auth.exchange_token(req.headers());

    // Always judged: a bound token must never be swapped for an unbound key, AS or not.
    let judged = crate::auth::dpop::judge(
        &app,
        req.method(),
        req.uri().path(),
        req.headers(),
        crate::auth::dpop::Surface::Exchange,
    )
    .await;
    // A proven token is read in place off the request's head; the chain below only reads it.
    let candidate: Option<std::borrow::Cow<'_, str>> = match judged {
        crate::auth::dpop::SenderConstraint::Unconstrained => {
            candidate.map(std::borrow::Cow::Owned)
        }
        crate::auth::dpop::SenderConstraint::Proven(token) => {
            Some(std::borrow::Cow::Borrowed(token))
        }
        crate::auth::dpop::SenderConstraint::Refused(reason) => {
            if let Some(admission) = req.extensions().get::<crate::inbound::RequestAdmission>() {
                admission.refuse(
                    busbar_contract::caps::StepName::Authenticate,
                    busbar_contract::caps::ReasonCode::Unauthenticated,
                );
            }
            // With no authorization server no proof can help, so the caller is told so.
            let reason = if app.oauth_as.is_none() {
                crate::auth::dpop::Refusal::Unverifiable
            } else {
                reason
            };
            return refusal(&ExchangeError::SenderConstraint(reason));
        }
    };
    let (judged, _, claim) = AuthMiddleware::judge_chain_on_request_path_naming(
        &app.auth,
        candidate.as_deref(),
        &crate::auth::ChainHead::of(&req),
        app.governance.clone(),
        None,
    )
    .await;
    let verdict = match exchange_verdict_result(judged) {
        Ok(verdict) => verdict,
        Err(response) => return *response,
    };

    // CA-5 (IF §12.29): a principal whose linked subject is INACTIVE in a provisioning instance that links this
    // inbound instance is refused before any mint; no plugin is asked. No probe when nothing links it.
    if let super::ChainVerdict::Identified {
        module, principal, ..
    } = &verdict
    {
        if crate::holds::held_now(module, &principal.id) {
            crate::cold::auth::keys::exchange_principal_held(module);
            return held_refusal();
        }
    }

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
        Err(error) => return refusal(&error),
    };

    let provisioner = Arc::new(HandleProvisioner::new(handle.clone(), principal.id.clone()));
    // The provider's name is read off the verdict for the length of this exchange: no copy.
    let keys = DeterministicEd25519Keys::new(gov, provider, team, pools, provisioner);
    match issue_key(&keys, principal, ttl, false).await {
        Ok(issued) => {
            let base_url = app.public_url.as_deref().unwrap_or("");
            (
                StatusCode::OK,
                axum::Json(exchange_ok_body(&issued, base_url)),
            )
                .into_response()
        }
        Err(e) => refusal(&e),
    }
}

fn exchange_verdict_result(
    judged: Result<super::ChainVerdict, super::VerifierUnavailable>,
) -> Result<super::ChainVerdict, Box<Response>> {
    match judged {
        Ok(verdict) => Ok(verdict),
        Err(super::VerifierUnavailable::NoVerdict) => Err(Box::new(
            crate::limits::admission::inbound_overloaded_response(),
        )),
        Err(super::VerifierUnavailable::Overloaded) => Ok(super::ChainVerdict::Denied),
    }
}

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
        return Err(ExchangeError::MintFailed(std::borrow::Cow::Borrowed(
            "governance is disabled: cannot mint keys",
        )));
    };
    if let Some(claim) = claim {
        if !claim.win().await {
            return Err(ExchangeError::Unauthorized);
        }
    }
    Ok((admitted, provider.as_str(), gov))
}

/// The once-shown mint response, borrowed from the issued key, in member order. The key stays
/// sealed in the body; it is exposed only as the response is written.
#[derive(serde::Serialize)]
struct ExchangeOk<'a> {
    #[serde(serialize_with = "shown_once")]
    api_key: &'a busbar_contract::redacted::Secret<String>,
    base_url: &'a str,
    exp: u64,
    group: &'a str,
    key_id: &'a str,
}

/// The issued key written into the once-shown mint response: the intended, documented plaintext
/// egress of the issued token (`Secret` has no `Serialize`).
fn shown_once<S: serde::Serializer>(
    secret: &&busbar_contract::redacted::Secret<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret.expose(&crate::seal::lend()))
}

fn exchange_ok_body<'a>(issued: &'a IssuedKey, base_url: &'a str) -> ExchangeOk<'a> {
    ExchangeOk {
        api_key: &issued.secret,
        base_url,
        exp: issued.exp,
        group: &issued.group,
        key_id: &issued.key_id,
    }
}

/// An exchange refusal's body, `{"error":..}`.
#[derive(serde::Serialize)]
struct ExchangeRefused {
    error: std::borrow::Cow<'static, str>,
}

/// A sender-constraint refusal's body (RFC 9449), `{"error":"sender_constrained",..}`.
#[derive(serde::Serialize)]
struct SenderConstrained {
    error: &'static str,
    error_description: &'static str,
}

/// CA-5: the verified principal is held (R_DENIED). Audited `principal_held` at the call.
fn held_refusal() -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(ExchangeRefused {
            error: "identity is deactivated by its provisioning directory".into(),
        }),
    )
        .into_response()
}

fn refusal(e: &ExchangeError) -> Response {
    let (status, msg): (StatusCode, std::borrow::Cow<'static, str>) = match e {
        ExchangeError::SenderConstraint(reason) => {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(SenderConstrained {
                    error: "sender_constrained",
                    error_description: reason.description(false),
                }),
            )
                .into_response();
        }
        ExchangeError::StaticKeyPresented => (
            StatusCode::BAD_REQUEST,
            "present an IdP identity, not a busbar key".into(),
        ),
        ExchangeError::Unauthorized => (StatusCode::UNAUTHORIZED, "not authenticated".into()),
        ExchangeError::SelfMintDisabled => (
            StatusCode::FORBIDDEN,
            "self-serve minting is disabled by policy".into(),
        ),
        ExchangeError::Unbound => (
            StatusCode::FORBIDDEN,
            "no self-serve grant for this identity".into(),
        ),
        // The flat data-plane envelope, carrying the coded reason (no new top-level field).
        ExchangeError::Held(reason) => (StatusCode::FORBIDDEN, reason.message().into()),
        ExchangeError::BadSubject => (
            StatusCode::FORBIDDEN,
            "identity is not a valid subject".into(),
        ),
        ExchangeError::OverCeiling(_) => (
            StatusCode::FORBIDDEN,
            "the key this identity would mint is over the mint ceiling (auth.policy)".into(),
        ),
        ExchangeError::MintFailed(detail) => {
            diag_error!(TOKEN_EXCHANGE_MINT_FAILED, error = %detail, "token-exchange mint failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not issue a key".into(),
            )
        }
    };
    (status, axum::Json(ExchangeRefused { error: msg })).into_response()
}

#[cfg(test)]
#[path = "tests/exchange_tests.rs"]
mod tests;
