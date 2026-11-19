// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RFC 9449 DPoP AT THE RESOURCE: sender-constrained tokens on busbar's own data plane.
//!
//! Under `oauth_as.fapi2: true` every token the authorization server mints is DPoP-bound (its
//! `cnf.jkt` names the client's key), and a bound token is presented as `Authorization: DPoP
//! <token>` with a `DPoP` proof header (s7.1). Busbar reads `cnf.jkt`, so it is a resource that
//! knows DPoP, and the door decides three things before the chain runs:
//!
//! 1. **A DPoP presentation.** With an authorization server configured: exactly one proof,
//!    verified by the plane through the seam (`oauth_as::seam::AsPlaneSeam::verify_dpop`:
//!    signature, `htm`, `htu`, `iat` window, `ath`, single-use `jti`, and the proof key's
//!    thumbprint equal to the token's `cnf.jkt`). Proven, the token goes to the chain exactly as a
//!    bearer would, so the chain still verifies its signature, issuer and audience. Anything else
//!    is refused. With none, the presentation cannot be verified, so it is refused: it never
//!    falls through to another carrier.
//! 2. **A DPoP-bound token presented as a bearer**, on any occurrence of any carrier, is refused
//!    whether or not an authorization server is configured (s7.2). Any `cnf.jkt`, whatever its
//!    type, makes a token bound.
//! 3. **Everything else is untouched**, and that is most requests: a token that was never bound
//!    takes the bearer path it always took.
//!
//! Every refusal is recorded as BUSBAR-4032 (never the token) and explained to the caller.
//! Reading `cnf` off an unverified payload is sound for the reason `auth::audience` gives: here it
//! only ever REFUSES. A proven presentation still has to pass the chain's real signature check.

use super::audience::Bearer;
use crate::diagnostics::{diag_warn, AUTH_SENDER_CONSTRAINT_REFUSED};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderName, Method};

pub(crate) const DPOP_HEADER: HeaderName = HeaderName::from_static("dpop");

const DPOP_SCHEME: &str = "DPoP";

pub(crate) const PROOF_FAILED_DESCRIPTION: &str =
    "A DPoP-bound access token needs its DPoP proof (RFC 9449), and this one did not verify.";

pub(crate) const BOUND_BEARER_DESCRIPTION: &str =
    "This access token is DPoP-bound (cnf.jkt) and cannot be presented as a bearer token \
     (RFC 9449 section 7.2). Present it with the DPoP scheme and a DPoP proof.";

pub(crate) const UNVERIFIABLE_DESCRIPTION: &str =
    "This deployment does not verify DPoP proofs, so a DPoP-bound or DPoP-scheme presentation \
     cannot be accepted (RFC 9449). Present an unbound bearer token.";

/// A request's sender constraint, judged. A proven token is lent from the request's own head
/// (`'h`): a holder that keeps it past the request makes its own copy.
pub(crate) enum SenderConstraint<'h> {
    Unconstrained,

    Proven(&'h str),

    Refused(Refusal),
}

/// Why a sender-constrained presentation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A DPoP presentation whose proof is missing, duplicated or did not verify.
    ProofFailed,
    /// A DPoP-bound token presented as a bearer, on any carrier.
    BoundBearer,
    /// A DPoP presentation this deployment cannot verify (no authorization server).
    Unverifiable,
}

impl Refusal {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProofFailed => "proof_failed",
            Self::BoundBearer => "bound_bearer",
            Self::Unverifiable => "unverifiable",
        }
    }

    /// What the caller is told. With no authorization server a bound bearer cannot be fixed by
    /// adding a proof, so it is told what it can do: present an unbound token.
    #[must_use]
    pub fn description(self, no_authorization_server: bool) -> &'static str {
        match self {
            Self::ProofFailed => PROOF_FAILED_DESCRIPTION,
            Self::BoundBearer if !no_authorization_server => BOUND_BEARER_DESCRIPTION,
            Self::BoundBearer | Self::Unverifiable => UNVERIFIABLE_DESCRIPTION,
        }
    }
}

/// The surface a sender-constraint refusal happened on, as BUSBAR-4032 names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Surface {
    Door,
    Plane,
    Exchange,
    Session,
}

impl std::fmt::Display for Surface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Door => "door",
            Self::Plane => "plane",
            Self::Exchange => "exchange",
            Self::Session => "session",
        })
    }
}

/// The one way a sender-constraint refusal is made: recorded (never the token), then returned.
fn refused(
    reason: Refusal,
    surface: Surface,
    no_authorization_server: bool,
) -> SenderConstraint<'static> {
    diag_warn!(
        AUTH_SENDER_CONSTRAINT_REFUSED,
        surface = %surface,
        reason = %reason.as_str(),
        no_authorization_server,
        "sender-constrained credential refused"
    );
    SenderConstraint::Refused(reason)
}

/// The DPoP-scheme token the request's `Authorization` carries, read in place.
pub(crate) fn dpop_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case(DPOP_SCHEME) && !token.is_empty()).then_some(token)
}

/// The DPoP-scheme token as the candidate's custody keeps it past the request: the one owned copy,
/// moved at once into a `Secret`.
pub(crate) fn dpop_credential(headers: &HeaderMap) -> Option<String> {
    dpop_token(headers).map(|token| token.to_string())
}

pub(crate) async fn judge<'h>(
    app: &crate::state::App,
    method: &Method,
    path: &str,
    headers: &'h HeaderMap,
    surface: Surface,
) -> SenderConstraint<'h> {
    judge_method(app, method.as_str(), path, headers, surface).await
}

pub(crate) async fn judge_method<'h>(
    app: &crate::state::App,
    method: &str,
    path: &str,
    headers: &'h HeaderMap,
    surface: Surface,
) -> SenderConstraint<'h> {
    let no_authorization_server = app.oauth_as.is_none();
    if let Some(token) = dpop_token(headers) {
        let (Some(plane), Some(seam)) = (app.oauth_as.as_ref(), crate::oauth_as::seam::seam())
        else {
            return refused(Refusal::Unverifiable, surface, no_authorization_server);
        };

        let mut proofs = headers.get_all(DPOP_HEADER).iter();
        let proof = match (proofs.next(), proofs.next()) {
            (Some(proof), None) => proof.to_str().ok(),
            _ => None,
        };
        let Some(proof) = proof else {
            return refused(Refusal::ProofFailed, surface, no_authorization_server);
        };
        let presented = crate::oauth_as::seam::DpopPresentation {
            method,
            path,
            token,
            proof,
        };
        return if (seam.verify_dpop)(plane, presented).await {
            SenderConstraint::Proven(token)
        } else {
            refused(Refusal::ProofFailed, surface, no_authorization_server)
        };
    }

    match bearer_constraint(headers, app.auth.carriers()) {
        SenderConstraint::Refused(reason) => refused(reason, surface, no_authorization_server),
        unconstrained => unconstrained,
    }
}

/// A bound token on any occurrence of any configured carrier, or of `Authorization` as a bearer,
/// is refused: duplicate or secondary carriers cannot hide it behind an unbound candidate.
fn bearer_constraint(headers: &HeaderMap, carriers: &[HeaderName]) -> SenderConstraint<'static> {
    if carries_bound(headers, carriers)
        || (!carriers.contains(&AUTHORIZATION) && carries_bound(headers, &[AUTHORIZATION]))
    {
        return SenderConstraint::Refused(Refusal::BoundBearer);
    }
    SenderConstraint::Unconstrained
}

/// Whether any occurrence of any of `carriers` holds a DPoP-bound token (`Authorization` read
/// as a bearer).
pub(crate) fn carries_bound(headers: &HeaderMap, carriers: &[HeaderName]) -> bool {
    carriers.iter().any(|name| carrier_bound(headers, name))
}

/// Whether any occurrence of the one carrier `name` holds a DPoP-bound token (`Authorization`
/// read as a bearer).
pub(crate) fn carrier_bound(headers: &HeaderMap, name: &HeaderName) -> bool {
    // Inspect every occurrence: choosing only the first lets duplicate carriers hide a bound
    // credential while another reader takes a different occurrence.
    headers.get_all(name).iter().any(|value| {
        let Ok(value) = value.to_str() else {
            return false;
        };
        if *name == AUTHORIZATION {
            super::AuthMiddleware::extract_bearer_token(value).is_some_and(is_dpop_bound)
        } else {
            is_dpop_bound(value)
        }
    })
}

pub fn is_dpop_bound(token: &str) -> bool {
    Bearer::read(token).dpop_bound()
}

/// A line session presents one credential for its whole life and can never carry a per-request
/// DPoP proof, so a bound credential is always refused there (RFC 9449 s7.1). Records
/// BUSBAR-4032 and answers `true` when it refuses.
pub fn refuse_bound_session(token: &str, no_authorization_server: bool) -> bool {
    if !is_dpop_bound(token) {
        return false;
    }
    let _ = refused(
        Refusal::Unverifiable,
        Surface::Session,
        no_authorization_server,
    );
    true
}

#[cfg(test)]
#[path = "tests/dpop_tests.rs"]
mod dpop_tests;
