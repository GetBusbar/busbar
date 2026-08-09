// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RFC 8707 AUDIENCE BINDING for credentials busbar did not mint.
//!
//! ## The hole this closes, stated plainly
//!
//! busbar's own signed tokens carry an audience claim and the verifier enforces it
//! (`governance::signing`, the 1.5.5 plane boundary). That covers exactly one credential shape. The
//! deployment shape this release actually ships is the OTHER one: the operator's IdP — Okta, Entra,
//! Auth0 — mints the token, an auth PLUGIN in the chain verifies its signature, and busbar core
//! never sees a claim.
//!
//! On an audience-bound plane that is not good enough, and the reason is the whole point of the
//! plane. RFC 8707 exists so a resource server can refuse a token that some authorization server
//! legitimately issued FOR SOMEBODY ELSE. If busbar delegates that judgement to a plugin, then any
//! token from a configured IdP — a token minted for the operator's wiki, their CI, their internal
//! API — is spendable against busbar's MCP plane, its pools, its budget and its upstream
//! credentials. That is the confused-deputy attack, and it is not hypothetical: it is the default
//! outcome of a correctly-implemented OIDC plugin doing exactly its job, which is to say "yes, our
//! IdP signed this".
//!
//! So core makes its own, independent determination, and it is the LAST word, never the first.
//!
//! ## Why an unverified claim read is sound HERE and nowhere else
//!
//! This module decodes a JWT payload WITHOUT verifying its signature, which is normally the classic
//! JWT mistake. It is sound here because of an asymmetry: the result is only ever used to REFUSE.
//!
//! - A token whose unverified `aud` does not match is refused. An attacker gains nothing by forging
//!   an unsigned token that claims the right audience — it still has to pass the plugin's real
//!   signature check afterwards, which is untouched.
//! - A token whose unverified `aud` DOES match is not admitted by this module. It proceeds to the
//!   chain exactly as before.
//!
//! In other words this is a fail-closed pre-filter that can only ever narrow what is admitted. It
//! cannot widen it, because it never returns "admit".
//!
//! ## The opaque-token limitation, stated rather than hidden
//!
//! An IdP that issues opaque reference tokens (verified by RFC 7662 introspection rather than by
//! signature) presents a credential with no readable claims at all. There is no way for busbar to
//! establish that such a token was minted for busbar, and the honest answer to "I cannot tell" on a
//! confused-deputy defence is refusal, not admission. So an opaque bearer is [`Binding::Opaque`] and
//! an audience-bound plane refuses it. Supporting those IdPs needs token introspection, which is a
//! separate unit; until it exists, an operator whose IdP issues opaque tokens cannot serve the MCP
//! plane, and finds that out from a clear refusal rather than from an audience check that silently
//! was not happening.

use base64::Engine as _;

/// What could be established about a presented bearer's audience binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Binding {
    /// A busbar-signed token. The real audience check happens in the verifier, which has the
    /// signature and the claims; this module must not pre-judge it, because a busbar token is not a
    /// JWT and reading it as one would refuse every valid one.
    Deferred,
    /// A JWT whose `aud` includes the expected value. Not an admission — the chain still has to
    /// verify it.
    Bound,
    /// A JWT whose `aud` does not include the expected value, or which carries no `aud` at all. A
    /// token minted for someone else, or a token minted for nobody in particular; both are refused
    /// for the same reason.
    Mismatch,
    /// Not a JWT and not a busbar token: nothing to read. Refused, per the module header.
    Opaque,
}

/// Establish what can be established about `token`'s binding to `expected_aud`.
///
/// `expected_aud` is compared for EQUALITY against each entry of the `aud` claim. RFC 7519 allows
/// `aud` to be a single string or an array of them, and both forms are accepted — but neither is
/// matched as a prefix, a suffix, or case-insensitively. A resource indicator is an opaque
/// identifier; treating it as a namespace is how `https://gw.example.com/mcp` begins admitting
/// tokens minted for `https://gw.example.com/mcp-staging`.
pub(crate) fn inspect_bearer(token: &str, expected_aud: &str) -> Binding {
    if token.starts_with(crate::governance::signing::TOKEN_PREFIX) {
        return Binding::Deferred;
    }
    // A JWS compact serialization is exactly three `.`-separated segments. Anything else is not a
    // JWT, and guessing at a fourth shape is how a parser starts accepting things.
    let mut parts = token.split('.');
    let (Some(_header), Some(payload), Some(_sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Binding::Opaque;
    };
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return Binding::Opaque;
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Binding::Opaque;
    };
    match claims.get("aud") {
        Some(serde_json::Value::String(s)) if s == expected_aud => Binding::Bound,
        Some(serde_json::Value::Array(vs)) => {
            if vs.iter().any(|v| v.as_str() == Some(expected_aud)) {
                Binding::Bound
            } else {
                Binding::Mismatch
            }
        }
        // A JWT with a present-but-wrong `aud`, an `aud` of some other JSON type, or no `aud` at
        // all. All three are "this was not minted for us", which is the only question being asked.
        _ => Binding::Mismatch,
    }
}

#[cfg(test)]
#[path = "tests/audience_tests.rs"]
mod audience_tests;
