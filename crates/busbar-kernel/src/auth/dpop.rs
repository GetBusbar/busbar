// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RFC 9449 DPoP AT THE RESOURCE: sender-constrained tokens on busbar's own data plane.
//!
//! Under `oauth_as.fapi2: true` every token the authorization server mints is DPoP-bound (its
//! `cnf.jkt` names the client's key), and a bound token is presented as `Authorization: DPoP
//! <token>` with a `DPoP` proof header (s7.1). The door decides three things, before the chain runs:
//!
//! 1. **A DPoP presentation, with an authorization server configured:** exactly one proof, verified
//!    by the plane through the seam (`oauth_as::seam::AsPlaneSeam::verify_dpop`: signature, `htm`,
//!    `htu`, `iat` window, `ath`, single-use `jti`, and the proof key's thumbprint equal to the
//!    token's `cnf.jkt`). Proven, the token goes to the chain exactly as a bearer would, so the
//!    chain still verifies its signature, issuer and audience. Anything else is refused.
//! 2. **A DPoP-bound token presented as a bearer** (any carrier) is refused: s7.1, a bound token
//!    without its proof is a stolen token.
//! 3. **Everything else is untouched**, and that is most requests: a token that was never bound
//!    takes the bearer path it always took, and with no authorization server configured an
//!    `Authorization: DPoP` header is what it was in 1.5.5 — not a credential carrier.
//!
//! Reading `cnf` off an unverified payload is sound for the reason `auth::audience` gives: here it
//! only ever REFUSES. A proven presentation still has to pass the chain's real signature check.

use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderName, Method};
use base64::Engine as _;

/// RFC 9449 s4.1: the proof header.
pub(crate) const DPOP_HEADER: HeaderName = HeaderName::from_static("dpop");
/// RFC 9449 s7.1: the authorization scheme (matched case-insensitively, RFC 9110 s11.1).
const DPOP_SCHEME: &str = "DPoP";

/// What the door decided about sender constraint.
pub(crate) enum SenderConstraint {
    /// Not a DPoP presentation and not a bound bearer: the path every request took before.
    Unconstrained,
    /// A DPoP-bound token with a verified proof: the credential the chain judges.
    Proven(String),
    /// Refuse the request.
    Refused,
}

/// The `<token>` of `Authorization: DPoP <token>`.
fn dpop_credential(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case(DPOP_SCHEME) && !token.is_empty()).then(|| token.to_string())
}

/// Judge a request's sender constraint from its method, path and headers (the parts, not the
/// request: the body is not `Sync`, and this is awaited). `bearer` is the credential the bearer
/// carriers yielded.
pub(crate) async fn judge(
    app: &crate::state::App,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    bearer: Option<&str>,
) -> SenderConstraint {
    if let Some(token) = dpop_credential(headers) {
        let (Some(plane), Some(seam)) = (app.oauth_as.as_ref(), crate::oauth_as::seam::seam())
        else {
            return SenderConstraint::Unconstrained;
        };
        // s4.3 (1): exactly one proof.
        let mut proofs = headers.get_all(DPOP_HEADER).iter();
        let proof = match (proofs.next(), proofs.next()) {
            (Some(proof), None) => proof.to_str().ok(),
            _ => None,
        };
        let Some(proof) = proof else {
            return SenderConstraint::Refused;
        };
        let presented = crate::oauth_as::seam::DpopPresentation {
            method: method.as_str().to_string(),
            path: path.to_string(),
            token: token.clone(),
            proof: proof.to_string(),
        };
        return if (seam.verify_dpop)(plane, presented).await {
            SenderConstraint::Proven(token)
        } else {
            SenderConstraint::Refused
        };
    }
    if bearer.is_some_and(is_dpop_bound) {
        return SenderConstraint::Refused;
    }
    SenderConstraint::Unconstrained
}

/// Whether `token` is bound to a DPoP key (RFC 9449 s6: a string `cnf.jkt`). busbar's own signed
/// keys and anything that is not a three-segment JWS are never bound, and are not parsed.
pub fn is_dpop_bound(token: &str) -> bool {
    if token.starts_with(crate::governance::signing::TOKEN_PREFIX) {
        return false;
    }
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .is_some_and(|claims| claims["cnf"]["jkt"].is_string())
}

#[cfg(test)]
#[path = "tests/dpop_tests.rs"]
mod dpop_tests;
