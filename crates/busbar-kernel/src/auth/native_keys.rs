// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The engine's own credentials on the native path: a token core signed (`bbk_`) and an access
//! token this deployment's authorization server (`oauth_as`) minted.
//!
//! **A core-signed token** is judged by the data chain's built-in member `keys`, and by nothing
//! else: no plugin instance is ever handed one. It is admitted on a route only when
//!
//! 1. the route's chain names `keys` (the operator chain never does, so the admin listener never
//!    judges one);
//! 2. the head presents exactly one, and no other credential on a carrier the route reads;
//! 3. it verifies under this engine's own signing key, is unexpired, and its audience claim is
//!    the route's audience EXACTLY: the plane's `canonical_uri` (RFC 8707) on an audience-bound
//!    plane, and no audience at all on a route bound to none
//!    (`GovState::verify_token_authority`, the verification 1.5.5's `keys` arm ran);
//! 4. its key stands: not revoked, not held, not expired, enabled, not rotated since the mint;
//! 5. at the publication gate all of 3 and 4 still hold ([`CoreKey::standing`]);
//! 6. on an audience-bound plane, a restricted key holds a grant of a kind the route's record
//!    names ([`holds_record_scope`]); the exact names are judged where they always were (the
//!    request walk and the plane's selection).
//!
//! No proof of possession is asked: a core-signed token carries no confirmation claim, and 1.5.5
//! asked none.
//!
//! **An access token of this deployment's authorization server** is a JWT a chain instance
//! verifies (signature, issuer, expiry), after core judged its `aud` for equality. Here it is
//! also asked of its own issuer's store ([`as_standing`]): revoked, expired, never issued, or
//! granted for another resource, it is refused before any verifier runs. That question only ever
//! refuses.

use std::sync::Arc;

use busbar_contract::records::VirtualKey;

use super::native_chain::NativeChain;
use super::native_data::DataRefused;
use super::route_record::RouteRecord;
use crate::governance::current_credential::{CurrentCredentialRefusal, VerifiedKeyAuthority};
use crate::governance::signing::TOKEN_PREFIX;
use crate::governance::GovState;
use crate::inbound::request_snapshot::ChargedRequestSnapshot;
use crate::oauth_as::seam::AccessStanding;
use crate::state::App;

/// A core-signed token that verified on a route, and the audience it was verified against. Made
/// only by [`admit`]; holds the signature's evidence, never the token.
pub struct CoreKey {
    authority: VerifiedKeyAuthority,
    audience: Option<Arc<str>>,
}

impl std::fmt::Debug for CoreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreKey")
            .field("subject", &self.subject())
            .field("audience", &self.audience)
            .finish()
    }
}

impl CoreKey {
    /// The key's stable id: the subject the request is served as.
    pub fn subject(&self) -> &str {
        &self.authority.original_key().id
    }

    /// The key as it stands now, re-judged with no verifier call: the token unexpired, its
    /// audience still the route's, its signer still this engine's, the key not revoked, not held,
    /// not expired, not rotated and not deleted. Disabled is a verified caller whose key the
    /// operator switched off (403); every other refusal is the one 401.
    pub(crate) fn standing(
        &self,
        gov: Option<&GovState>,
        now: u64,
    ) -> Result<Arc<VirtualKey>, DataRefused> {
        let gov = gov.ok_or(DataRefused::Policy)?;
        self.authority
            .current_key(gov, now, self.audience.as_deref())
            .map_err(|refused| match refused {
                CurrentCredentialRefusal::DisabledKey => DataRefused::Disabled,
                // Verified under one governance and judged under another: the engine's own
                // fault, never an answer about the credential.
                CurrentCredentialRefusal::ForeignAuthority => DataRefused::Binding,
                CurrentCredentialRefusal::SigningUnavailable
                | CurrentCredentialRefusal::Expired
                | CurrentCredentialRefusal::AudienceMismatch
                | CurrentCredentialRefusal::UntrustedSigner
                | CurrentCredentialRefusal::Revoked
                | CurrentCredentialRefusal::SubjectHeld
                | CurrentCredentialRefusal::MissingKey
                | CurrentCredentialRefusal::KeyExpired
                | CurrentCredentialRefusal::RotatedKey
                | CurrentCredentialRefusal::DeletedKey => DataRefused::Policy,
            })
    }

    /// [`Self::standing`] under the generation the gate admitted.
    pub(crate) fn standing_in(&self, app: &App, now: u64) -> Result<Arc<VirtualKey>, DataRefused> {
        self.standing(app.governance.as_deref(), now)
    }
}

/// What a head presents on the carriers a route reads, as far as core's own tokens go.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Presented<'h> {
    /// The first core-signed token found.
    core: Option<&'h str>,
    /// How many carrier lines hold a core-signed token.
    core_lines: usize,
    /// How many carrier lines hold anything else.
    other_lines: usize,
}

impl<'h> Presented<'h> {
    /// Read every occurrence of every carrier: `authorization` (as a bearer) and each header
    /// `reads` names (its whole value). A line that is not a carrier is not read.
    pub(crate) fn scan(
        fields: impl IntoIterator<Item = (&'h str, &'h [u8])>,
        reads: impl Fn(&str) -> bool,
    ) -> Self {
        let mut presented = Self::default();
        for (name, value) in fields {
            let authorization = name.eq_ignore_ascii_case("authorization");
            if !authorization && !reads(name) {
                continue;
            }
            let credential = std::str::from_utf8(value).ok().and_then(|value| {
                if !authorization {
                    return Some(value.trim());
                }
                let (scheme, token) = value.split_once(' ')?;
                scheme.eq_ignore_ascii_case("Bearer").then(|| token.trim())
            });
            match credential {
                Some(token) if token.starts_with(TOKEN_PREFIX) => {
                    presented.core_lines += 1;
                    if presented.core.is_none() {
                        presented.core = Some(token);
                    }
                }
                // Another credential, another scheme, or bytes that are not text: not core's,
                // and beside a core token it makes the head ambiguous.
                _ => presented.other_lines += 1,
            }
        }
        presented
    }

    /// Whether any carrier line holds a core-signed token.
    pub(crate) fn core_presented(&self) -> bool {
        self.core_lines != 0
    }
}

/// The built-in member `keys`, judging what a head presented. `Ok(None)`: no core token, so the
/// chain's other members judge the head. `Ok(Some)`: the one core token, verified for
/// `audience`. Every refusal is the one 401; the reason is logged by the verifier at debug and
/// never told to the caller.
pub(crate) fn admit(
    gov: Option<&GovState>,
    presented: &Presented<'_>,
    keys_member: bool,
    audience: Option<&str>,
    now: u64,
) -> Result<Option<CoreKey>, DataRefused> {
    let Some(token) = presented.core else {
        return Ok(None);
    };
    // A chain that does not name `keys` never judges a core token, and no other member is
    // handed one. Two of them, or one beside another credential, is not one caller's credential.
    if !keys_member || presented.core_lines != 1 || presented.other_lines != 0 {
        return Err(DataRefused::Credential);
    }
    let authority = gov
        .and_then(|gov| gov.verify_token_authority(token, now, audience))
        .ok_or(DataRefused::Credential)?;
    Ok(Some(CoreKey {
        authority,
        audience: audience.map(Arc::from),
    }))
}

/// [`admit`] over a request's frozen head. `cred_header`: the route's own credential header.
pub(crate) fn judge(
    snapshot: &ChargedRequestSnapshot,
    chain: &NativeChain,
    cred_header: Option<&str>,
    gov: Option<&GovState>,
    audience: Option<&str>,
    now: u64,
) -> Result<Option<CoreKey>, DataRefused> {
    // The open relay reads no credential.
    if chain.is_open() {
        return Ok(None);
    }
    snapshot
        .with_auth_input(|request| {
            let presented = Presented::scan(
                request
                    .headers
                    .iter()
                    .map(|field| (field.name.get(), field.value.get())),
                |name| {
                    chain.reads_header(name)
                        || cred_header.is_some_and(|header| header.eq_ignore_ascii_case(name))
                },
            );
            admit(gov, &presented, chain.admits_keys(), audience, now)
        })
        .map_err(|_| DataRefused::Capacity)?
}

/// Whether `key` carries the scope `record` requires at all: an unrestricted key does; a route
/// whose record states scope none requires none; otherwise a restricted key must hold at least
/// one grant of a kind the record names (its walk kind or a selected kind). Necessary, never
/// sufficient: which names the key may use is judged by the walk and the selection.
pub(crate) fn holds_record_scope(record: &RouteRecord, key: &VirtualKey) -> bool {
    let Some(granted) = &key.allowed_scopes else {
        return true;
    };
    record.scope.is_none()
        || record
            .scope
            .kinds()
            .any(|kind| granted.iter().any(|grant| grant.kind == kind))
}

/// What the authorization server's standing means to admission: `Ok(true)` the token is this
/// deployment's own and live; `Ok(false)` it is not this deployment's (the chain judges it as
/// any other issuer's); a dead one is the one 401; a store that cannot answer is 503.
pub(crate) fn as_standing_of(standing: AccessStanding) -> Result<bool, DataRefused> {
    match standing {
        AccessStanding::NotMine => Ok(false),
        AccessStanding::Live => Ok(true),
        AccessStanding::Dead => Err(DataRefused::Credential),
        AccessStanding::Unavailable => Err(DataRefused::Unavailable),
    }
}

/// On an audience-bound plane of a deployment that is its own authorization server: ask that
/// server whether each bearer JWT on the head is one it issued, still holds, and granted for
/// `audience`. `Ok(true)`: one of them is. A deployment that is not an authorization server is
/// asked nothing and copies nothing.
///
/// The token is copied once to cross the store read (a head is lent only for a synchronous
/// reading) and wiped when the answer is in.
pub(crate) async fn as_standing(
    app: &App,
    snapshot: &ChargedRequestSnapshot,
    chain: &NativeChain,
    audience: &str,
) -> Result<bool, DataRefused> {
    let (Some(plane), Some(seam)) = (app.oauth_as.as_ref(), crate::oauth_as::seam::seam()) else {
        return Ok(false);
    };
    if chain.is_open() {
        return Ok(false);
    }
    let bearers: Vec<busbar_contract::secure::SecureString> = snapshot
        .with_auth_input(|request| {
            request
                .headers
                .iter()
                .filter(|field| field.name.get().eq_ignore_ascii_case("authorization"))
                .filter_map(|field| {
                    let value = std::str::from_utf8(field.value.get()).ok()?;
                    let (scheme, token) = value.split_once(' ')?;
                    let token = token.trim();
                    (scheme.eq_ignore_ascii_case("Bearer")
                        && !token.is_empty()
                        && !token.starts_with(TOKEN_PREFIX))
                    .then(|| busbar_contract::secure::SecureString::from(token))
                })
                .collect()
        })
        .map_err(|_| DataRefused::Capacity)?;
    let mut live = false;
    for bearer in &bearers {
        live |= as_standing_of((seam.access_standing)(plane, bearer.as_str(), audience).await)?;
    }
    Ok(live)
}

#[cfg(test)]
#[path = "tests/native_keys_tests.rs"]
mod tests;
