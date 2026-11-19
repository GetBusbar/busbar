// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RFC 9449 DPoP on the native DATA path: a token bound to a key (`cnf.jkt`, every token of
//! `oauth_as.fapi2: true`) is admitted only with a proof of possession of that key.
//!
//! [`judge`] runs in `NativeDataRoute::prepare` before any verifier, on the frozen head:
//!
//! 1. **A token that is not bound, presented as it always was, is untouched**
//!    ([`Sender::Unconstrained`]): the route's own scans and its chain judge it as before.
//! 2. **A bound token presented as a bearer**, on any occurrence of any carrier the route reads,
//!    is refused (s7.2).
//! 3. **A DPoP presentation** (`Authorization: DPoP <token>`) must be the head's ONE credential
//!    and carry exactly ONE `DPoP` proof header. The proof is judged by this deployment's own
//!    authorization server through its seam (`oauth_as::seam::AsPlaneSeam::prove_dpop`), the one
//!    implementation the door has always used: the JWT's signature under its embedded public
//!    key, `typ` `dpop+jwt`, an asymmetric algorithm, `htm` the request's method, `htu` the URL
//!    the request was received at ([`received_at`]), `iat` inside the window, `ath` the hash of
//!    the presented token, the proof key's thumbprint equal to the token's `cnf.jkt`, the token
//!    held by its issuer, and the `jti` claimed once. No server nonce is issued or expected:
//!    this deployment has never issued one.
//! 4. **Proven**, the token goes on to the route's chain exactly as a bearer would
//!    ([`Sender::Proven`], [`as_bearer`]): the chain still verifies its signature, issuer and
//!    expiry, and the route still judges its audience and its standing. A proof admits nothing
//!    by itself.
//!
//! Every refusal is the route's one 401 (`DataRefused::Credential`), with the route's own
//! challenge; the reason is recorded as BUSBAR-4032 (never the token, never the proof) and is not
//! told to the caller. A store that cannot answer is 503, never an admission. With no
//! authorization server no proof can be judged, so a DPoP presentation is refused.
//!
//! Reading `cnf` off an unverified payload is sound here for the reason `auth::dpop` gives: by
//! itself it only ever refuses.

use std::sync::Arc;

use busbar_contract::secure::SecureString;

use super::native_chain::NativeChain;
use super::native_data::DataRefused;
use crate::diagnostics::{diag_warn, AUTH_SENDER_CONSTRAINT_REFUSED};
use crate::inbound::request_snapshot::ChargedRequestSnapshot;
use crate::oauth_as::seam::{DpopAtResource, DpopVerdict};
use crate::state::App;

const AUTHORIZATION: &str = "authorization";
const DPOP: &str = "dpop";
const BEARER: &str = "Bearer";

/// Why a head's sender-constrained presentation was refused before any proof was judged. For the
/// log only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    /// A bound token presented as a bearer, on some occurrence of some carrier.
    BoundBearer,
    /// A DPoP presentation that is not the head's one credential: a second `authorization`
    /// line, a credential on another carrier the route reads, or no token after the scheme.
    NotOneCredential,
    /// A DPoP presentation with no `DPoP` proof header, more than one, or one that is not text.
    NotOneProof,
    /// This deployment has no authorization server: no proof can be judged.
    Unverifiable,
    /// The route states no public URL, so the URL its proof must name cannot be stated.
    NoPublicUrl,
}

impl Reason {
    fn as_str(self) -> &'static str {
        match self {
            Self::BoundBearer => "bound_bearer",
            Self::NotOneCredential => "not_one_credential",
            Self::NotOneProof => "not_one_proof",
            Self::Unverifiable => "unverifiable",
            Self::NoPublicUrl => "no_public_url",
        }
    }
}

/// What a head presents, as far as its sender constraint goes.
#[derive(PartialEq, Eq)]
pub(crate) enum Presentation<'h> {
    /// No DPoP presentation and no bound token on any carrier.
    Unbound,
    /// The head's one credential is `Authorization: DPoP <token>`, with its one proof.
    Dpop {
        token: &'h str,
        proof: &'h str,
    },
    Refused(Reason),
}

impl std::fmt::Debug for Presentation<'_> {
    /// The variant and the refusal reason only: the token and its proof are credentials and are
    /// never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unbound => f.write_str("Unbound"),
            Self::Dpop { .. } => f.debug_struct("Dpop").finish_non_exhaustive(),
            Self::Refused(reason) => f.debug_tuple("Refused").field(reason).finish(),
        }
    }
}

/// Read a head's sender constraint. `reads`: whether the route reads a credential from the named
/// header (its chain's declared carriers and its own credential header); `authorization` is
/// always read. Every occurrence of every carrier is read, not a decoy first one.
pub(crate) fn read<'h>(
    headers: impl Iterator<Item = (&'h str, &'h [u8])>,
    reads: impl Fn(&str) -> bool,
) -> Presentation<'h> {
    // The DPoP-scheme token, and how many `authorization` lines carried that scheme.
    let mut dpop: Option<&'h str> = None;
    let mut dpop_lines = 0usize;
    // Every other credential line the route would read.
    let mut other_lines = 0usize;
    let mut bound_bearer = false;
    let mut proof: Option<&'h str> = None;
    let mut proof_lines = 0usize;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case(DPOP) {
            proof_lines += 1;
            proof = std::str::from_utf8(value).ok();
            continue;
        }
        let authorization = name.eq_ignore_ascii_case(AUTHORIZATION);
        if !authorization && !reads(name) {
            continue;
        }
        let Ok(value) = std::str::from_utf8(value) else {
            // A credential line that is not text is still a credential line.
            other_lines += 1;
            continue;
        };
        if !authorization {
            other_lines += 1;
            bound_bearer |= super::dpop::is_dpop_bound(value.trim());
            continue;
        }
        match value.split_once(' ') {
            Some((scheme, token)) if scheme.eq_ignore_ascii_case("DPoP") => {
                dpop_lines += 1;
                dpop = Some(token.trim());
            }
            Some((scheme, token)) if scheme.eq_ignore_ascii_case(BEARER) => {
                other_lines += 1;
                bound_bearer |= super::dpop::is_dpop_bound(token.trim());
            }
            // Another scheme, or no scheme at all: a credential this path does not read as a
            // token, and still a credential beside a DPoP presentation.
            _ => other_lines += 1,
        }
    }
    if dpop_lines == 0 {
        return if bound_bearer {
            Presentation::Refused(Reason::BoundBearer)
        } else {
            Presentation::Unbound
        };
    }
    let token = match dpop {
        Some(token) if dpop_lines == 1 && other_lines == 0 && !token.is_empty() => token,
        _ => return Presentation::Refused(Reason::NotOneCredential),
    };
    match proof {
        Some(proof) if proof_lines == 1 => Presentation::Dpop { token, proof },
        _ => Presentation::Refused(Reason::NotOneProof),
    }
}

/// The URL a request was received at, as its proof's `htu` must name it (RFC 9449 s4.3 (9)): the
/// origin of the route's public URL and the path as received, with no query and no fragment.
/// `None` where that URL cannot be stated: `public` is not an `http(s)` URL with a host and no
/// userinfo, or `path` is not an origin-form path.
pub(crate) fn received_at(public: &str, path: &str) -> Option<String> {
    let end = public.find(['?', '#']).unwrap_or(public.len());
    let (scheme, rest) = public[..end].split_once("://")?;
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
        return None;
    }
    let authority = &rest[..rest.find('/').unwrap_or(rest.len())];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    if !path.starts_with('/') || path.contains(['?', '#']) {
        return None;
    }
    let mut url = String::with_capacity(scheme.len() + 3 + authority.len() + path.len());
    url.push_str(scheme);
    url.push_str("://");
    url.push_str(authority);
    url.push_str(path);
    Some(url)
}

/// What the authorization server's verdict means to admission: only `Proven` goes on; a refused
/// proof is the one 401 (its reason recorded here); a store that cannot answer is 503.
pub(crate) fn verdict(verdict: DpopVerdict) -> Result<(), DataRefused> {
    match verdict {
        DpopVerdict::Proven => Ok(()),
        DpopVerdict::Refused(reason) => {
            refused(reason.as_str());
            Err(DataRefused::Credential)
        }
        DpopVerdict::Unavailable => Err(DataRefused::Unavailable),
    }
}

/// The one way a sender-constraint refusal is recorded on this path: the reason, never the token
/// or the proof.
fn refused(reason: &'static str) {
    diag_warn!(
        AUTH_SENDER_CONSTRAINT_REFUSED,
        surface = "native",
        reason,
        "sender-constrained credential refused"
    );
}

/// The head a proven presentation is judged by from here on: the request exactly as received,
/// its `Authorization: DPoP <token>` restated as `Bearer <token>` (the chain's members and the
/// route's audience and standing checks read a bearer) and its spent `DPoP` proof left out (no
/// member and no plane is handed it). Only its restated head is a new copy, charged to the same
/// request as the original; its method, target, peer and body are the original's own bytes,
/// charged once ([`ChargedRequestSnapshot::restate_headers`]). A request that cannot pay for the
/// restated head is refused.
pub(crate) fn as_bearer(
    original: &Arc<ChargedRequestSnapshot>,
    token: &str,
) -> Result<Arc<ChargedRequestSnapshot>, DataRefused> {
    // The one new copy of the credential: wiped when this returns, like the view's own bytes
    // when the view is dropped.
    let mut bearer = SecureString::with_capacity(BEARER.len() + 1 + token.len());
    bearer.push_str(BEARER);
    bearer.push(' ');
    bearer.push_str(token);
    let mut fields: Vec<(&str, &[u8])> = Vec::new();
    fields
        .try_reserve_exact(original.headers().len())
        .map_err(|_| DataRefused::Capacity)?;
    for (name, value) in original.headers() {
        if name.eq_ignore_ascii_case(DPOP) {
            continue;
        }
        if name.eq_ignore_ascii_case(AUTHORIZATION) {
            fields.push((name, bearer.as_str().as_bytes()));
        } else {
            fields.push((name, value));
        }
    }
    ChargedRequestSnapshot::restate_headers(original, fields.iter().copied())
        .map_err(|_| DataRefused::Capacity)
}

/// A request's sender constraint, judged.
pub(crate) enum Sender {
    /// No DPoP presentation and no bound token: the head as received, for the route's own scans
    /// and its chain.
    Unconstrained(Arc<ChargedRequestSnapshot>),
    /// A bound token whose proof of possession was proven for this request: the head restated
    /// for the chain ([`as_bearer`]). Its one credential is that token, so the route's refusal
    /// of bound and core-signed carriers has nothing left to read on it.
    Proven(Arc<ChargedRequestSnapshot>),
}

/// Judge the sender constraint of one request on a native DATA route, before any verifier.
/// `cred_header`: the route's own credential header. `public_url`: the public URL the route's
/// plane states (the audience it is bound to), whose origin the proof's `htu` must name.
pub(crate) async fn judge(
    app: &App,
    snapshot: Arc<ChargedRequestSnapshot>,
    chain: &NativeChain,
    cred_header: Option<&str>,
    public_url: Option<&str>,
) -> Result<Sender, DataRefused> {
    // The open relay (`anonymous` alone) reads no credential, so none is judged.
    if chain.is_open() {
        return Ok(Sender::Unconstrained(snapshot));
    }
    let presented = read(snapshot.headers(), |name| {
        chain.reads_header(name)
            || cred_header.is_some_and(|header| header.eq_ignore_ascii_case(name))
    });
    let (token, proof) = match presented {
        Presentation::Unbound => return Ok(Sender::Unconstrained(snapshot)),
        Presentation::Refused(reason) => return Err(refuse(reason)),
        Presentation::Dpop { token, proof } => (token, proof),
    };
    let (Some(plane), Some(seam)) = (app.oauth_as.as_ref(), crate::oauth_as::seam::seam()) else {
        return Err(refuse(Reason::Unverifiable));
    };
    let Some(htu) = public_url.and_then(|public| received_at(public, snapshot.path())) else {
        return Err(refuse(Reason::NoPublicUrl));
    };
    let presentation = DpopAtResource {
        method: snapshot.method(),
        htu: &htu,
        token,
        proof,
    };
    verdict((seam.prove_dpop)(plane, presentation).await)?;
    let view = as_bearer(&snapshot, token)?;
    Ok(Sender::Proven(view))
}

fn refuse(reason: Reason) -> DataRefused {
    refused(reason.as_str());
    DataRefused::Credential
}

#[cfg(test)]
#[path = "tests/native_dpop_tests.rs"]
mod tests;
