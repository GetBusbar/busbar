// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT THE AUTH GATE TOOK FROM THE CALLER, AND WHAT A PLANE MAY HOLD OF IT (#65 zero trust, #40(b):
//! no raw secret to any plugin; the 2026-09-20 ruling "a plane passes a credential REF, never
//! plaintext"). A plane — linked or dropped in, identically — never sees the caller's credential:
//!
//! - [`ConsumedCredentials`] is every header the configured gate reads as a credential carrier —
//!   taken from the gate's own carrier declarations, never a list of its own — whichever one carried
//!   THIS request's credential: a second carrier the gate did not need is still a credential. The
//!   host strips all of them from every request it hands a plane: the plane-route context (and so
//!   the HOT request head built from it) and the protocol arrival.
//! - [`CallerCredential`] is the caller's verified credential as a REF: it has no byte accessor
//!   outside this module. A `passthrough` pool's upstream still receives the caller's credential
//!   byte for byte, because the HOST presents it at egress ([`present_caller`]) — the plane passes
//!   the ref and never holds the plaintext.

use super::{HeaderMap, HeaderName, HeaderValue};
use crate::bound_credential::CredentialProvider;
use busbar_contract::protocol::SigningContext;

/// What the auth gate holds of one request's credentials (request extension): the header names the
/// configured gate reads a credential from, and the credential it extracted, as a ref. Inserted by the gate on every request it judged;
/// absent on a route that bypassed it (a `RouteAuth::None` route consumed nothing, so a plane there
/// reads its own headers whole).
#[derive(Clone, Debug, Default)]
pub struct ConsumedCredentials {
    names: Vec<HeaderName>,
    /// The caller's credential the gate extracted, as a ref (`None`: the caller presented none).
    pub caller: Option<CallerCredential>,
    /// The record of the TICKET the gate spent admitting the caller (row 132); `None` when a key
    /// (or nothing) admitted it. Handed to the unit once, for `ticket.take`.
    pub ticket: Option<Vec<u8>>,
}

impl ConsumedCredentials {
    /// The set over `carriers`, with no credential extracted yet.
    pub(crate) fn carrying(carriers: &[HeaderName]) -> Self {
        let mut set = Self::default();
        set.carry(carriers);
        set
    }

    /// Add `carriers` to the set (a repeat is harmless: stripping is idempotent).
    pub(crate) fn carry(&mut self, carriers: &[HeaderName]) {
        self.names.extend_from_slice(carriers);
    }

    /// Remove every consumed credential header from `headers` — every value under each name.
    pub fn strip(&self, headers: &mut HeaderMap) {
        for name in &self.names {
            headers.remove(name);
        }
    }

    /// The consumed fields `headers` carries, each by its lower-case name with its value's scheme
    /// word (the value up to its first space; empty when it has none): what an entry fact may read
    /// of a field the gate consumed, never the credential itself.
    pub(crate) fn fields_of(consumed: Option<&Self>, headers: &HeaderMap) -> Vec<(String, String)> {
        let Some(consumed) = consumed else {
            return Vec::new();
        };
        consumed
            .names
            .iter()
            .filter_map(|name| {
                let value = headers.get(name)?;
                let scheme = value
                    .to_str()
                    .ok()
                    .and_then(|v| v.split_once(' '))
                    .map(|(word, _)| word.to_owned())
                    .unwrap_or_default();
                Some((name.as_str().to_owned(), scheme))
            })
            .collect()
    }

    /// Strip the credentials the gate consumed (an absent extension consumed nothing).
    pub(crate) fn strip_from(consumed: Option<&Self>, headers: &mut HeaderMap) {
        if let Some(consumed) = consumed {
            consumed.strip(headers);
        }
    }
}

/// The caller's verified credential, as a REF a plane carries and cannot read: no byte accessor
/// leaves the auth gate, and its `Debug` prints presence only. The host resolves it at egress
/// ([`present_caller`]).
///
/// ZEROISED AT EXIT (THE DESIGN §6: the kernel "holds it on the unit, zeroised at exit, for the
/// caller-credential style"; "auth material is zeroised"): the bytes live in ONE zeroising buffer,
/// and a clone shares it, so the plaintext is wiped when the last holder drops, never left behind in
/// a copy a clone made.
#[derive(Clone)]
pub struct CallerCredential(std::sync::Arc<zeroize::Zeroizing<Vec<u8>>>);

impl CallerCredential {
    /// A ref over the credential the gate verified: its bytes are copied once into the zeroising
    /// buffer every clone shares.
    pub(super) fn verified(token: &str) -> Self {
        Self(std::sync::Arc::new(zeroize::Zeroizing::new(
            token.as_bytes().to_vec(),
        )))
    }

    /// The credential as text, borrowed from the shared buffer (it was text when the gate took it).
    fn text(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or_default()
    }

    /// THE CREDENTIAL LENT TO THE HOST'S EGRESS (L2 credential lending): the bytes, zeroised on
    /// drop and printed as presence only, for the one outbound auth call of a passthrough member
    /// (`FieldsRequest::caller_credential`). Never handed to a plane.
    #[must_use]
    pub fn lend(&self) -> busbar_contract::redacted::Secret<Vec<u8>> {
        busbar_contract::redacted::Secret::new(self.0.to_vec())
    }
}

impl std::fmt::Debug for CallerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallerCredential(<present>)")
    }
}

/// PRESENT THE CALLER'S CREDENTIAL UPSTREAM (a `passthrough` pool), host-side: `credential`'s
/// scheme over the caller's own bytes. No caller credential presents nothing — never the operator's
/// key — unless the scheme ignores the key (a self-minting credential presents its own token).
pub fn present_caller(
    credential: &dyn CredentialProvider,
    caller: Option<&CallerCredential>,
    ctx: &SigningContext,
) -> Vec<(HeaderName, HeaderValue)> {
    let key = caller.map_or("", CallerCredential::text);
    if key.is_empty() && credential.uses_key() {
        return Vec::new();
    }
    credential.headers_for(key, ctx)
}

#[cfg(test)]
#[path = "tests/caller_credential_tests.rs"]
mod caller_credential_tests;
