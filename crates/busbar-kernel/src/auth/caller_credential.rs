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
use crate::{egress_auth::CredentialProvider, proto::SigningContext};

/// What the auth gate holds of one request's credentials (request extension): the header names the
/// configured gate reads a credential from, and the credential it extracted, as a ref. Inserted by the gate on every request it judged;
/// absent on a route that bypassed it (a `RouteAuth::None` route consumed nothing, so a plane there
/// reads its own headers whole).
#[derive(Clone, Debug, Default)]
pub struct ConsumedCredentials {
    names: Vec<HeaderName>,
    /// The caller's credential the gate extracted, as a ref (`None`: the caller presented none).
    pub caller: Option<CallerCredential>,
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
#[derive(Clone)]
pub struct CallerCredential(pub(super) String);

impl CallerCredential {
    /// A ref over `token`, for a test that stands in for the gate.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(token: &str) -> Self {
        Self(token.to_string())
    }

    /// The credential, for the host's test-only verifier seam (`EngineHost::verify_token_test`) —
    /// compiled only into a test build, never into a served binary.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reveal_for_test(&self) -> &str {
        &self.0
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
    let key = caller.map_or("", |c| c.0.as_str());
    if key.is_empty() && credential.uses_key() {
        return Vec::new();
    }
    credential.headers_for(key, ctx)
}
