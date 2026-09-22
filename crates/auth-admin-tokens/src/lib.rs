// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in `admin-tokens` ADMIN auth PLUGIN.
//!
//! A default-included, compile-removable module for the `admin_auth:` chain (the parallel chain
//! gating `/admin/v1/*`): the single operator admin token, presented as `Authorization: Bearer` or
//! `X-Admin-Token`. Architecturally a peer of any external admin module (AD/OIDC);
//! this one is credential-compare only, so it takes the pre-computed token hash and the extracted
//! carriers rather than the `AuthModule` single-candidate shape (an admin credential legitimately
//! arrives on two carriers, and the constant-time both-carriers fold must live INSIDE the module —
//! selecting a carrier before the compare would reintroduce the timing observable the fold kills).

use busbar_api::{constant_time_eq, sha256_hex, AuthOutcome, Principal};

/// The fixed principal id the operator admin token identifies as. The built-in operator credential
/// carries FULL admin scope by definition (it is the root credential the deployment was born with);
/// group-mapped external principals get their scope from `group_map:` instead.
pub const ADMIN_TOKENS_PRINCIPAL_ID: &str = "admin";

/// Judge the presented admin credential carriers against the configured admin token hash
/// (SHA-256 hex, pre-computed at engine construction).
///
/// Timing stance (unchanged from the pre-plugin inline check): BOTH carrier comparisons run
/// UNCONDITIONALLY and fold with bitwise-OR — a request presenting both a Bearer and an
/// `X-Admin-Token` never skips the second compare, so "Bearer matched" and "Bearer missed, header
/// matched" are indistinguishable. Both candidates are SHA-256-hashed before the constant-time
/// compare, so candidate length leaks nothing. A missing carrier contributes 0.
///
/// `None` hash (no admin token configured) ⇒ `Pass` — this module has nothing to judge; a chain
/// that ends all-`Pass` is denied (fail-closed), preserving "admin API disabled without a token".
///
/// SHAPE PRE-CHECK — THE CHAIN HAS TO COMPOSE. A candidate shaped like a JWS/JWT compact
/// serialization (three non-empty dot-separated segments) is never this module's credential
/// grammar: admin-tokens compares an opaque token HASH, it does not parse structured tokens. Such a
/// candidate belongs to a different scheme — typically an OIDC/AD admin module configured later in
/// the same `admin_auth:` chain, which legitimately shares the `Authorization: Bearer` carrier.
/// `Reject` is TERMINAL in `run_admin_chain`, so rejecting it here denied the request before that
/// arm ever ran, which is a chain that cannot be composed rather than a door that is shut.
///
/// Fail-closed but NON-TERMINAL: this module still never `Identify`s such a candidate; what changes
/// is that a carrier which is absent, or present but JWS-shaped, does not count as "this module was
/// addressed", so a JWS-shaped mismatch alone DEFERS (`Pass`) and keeps the next arm reachable. A
/// carrier that is present and NOT JWS-shaped is a genuine wrong-credential attempt against this
/// module and still `Reject`s. The timing stance is unchanged: the shape test reads only the PUBLIC
/// candidate string and never the compare result, and both constant-time hash compares still run
/// unconditionally on every presented carrier regardless of shape.
pub fn authenticate_admin_tokens(
    configured_hash: Option<&str>,
    bearer: Option<&str>,
    header: Option<&str>,
) -> AuthOutcome {
    let Some(configured_hash) = configured_hash else {
        return AuthOutcome::Pass;
    };
    if bearer.is_none() && header.is_none() {
        // No credential presented for this module — defer (the chain's all-Pass denies).
        return AuthOutcome::Pass;
    }
    // Read off the PUBLIC candidate strings only, BEFORE either compare, so no branch below can
    // depend on a compare result: the constant-time fold is untouched.
    let bearer_is_jws = bearer.is_some_and(is_jws_shaped);
    let header_is_jws = header.is_some_and(is_jws_shaped);
    let bearer_match = u8::from(
        bearer
            .map(|b| constant_time_eq(&sha256_hex(b.as_bytes()), configured_hash))
            .unwrap_or(false),
    );
    let header_match = u8::from(
        header
            .map(|h| constant_time_eq(&sha256_hex(h.as_bytes()), configured_hash))
            .unwrap_or(false),
    );
    if std::hint::black_box(bearer_match | header_match) != 0 {
        return AuthOutcome::Identify(Principal::from_id(ADMIN_TOKENS_PRINCIPAL_ID));
    }
    // Only a carrier that was actually presented AND is not JWS-shaped counts as "addressed to this
    // module, and wrong" — that still terminally denies. A carrier that is absent, or present but
    // carrying some other scheme's grammar, defers instead of short-circuiting the chain.
    let bearer_addressed_me = bearer.is_some() && !bearer_is_jws;
    let header_addressed_me = header.is_some() && !header_is_jws;
    if bearer_addressed_me || header_addressed_me {
        AuthOutcome::Reject
    } else {
        AuthOutcome::Pass
    }
}

/// Whether `candidate` is shaped like a JWS/JWT compact serialization: exactly three dot-separated
/// segments, none of them empty (`header.payload.signature`).
///
/// A pure SHAPE test — it says nothing about validity, signature or issuer, and is never used to
/// admit anything. Its only job is to recognise "this is not admin-tokens' grammar" so the chain
/// can carry the candidate on to the arm whose grammar it IS.
fn is_jws_shaped(candidate: &str) -> bool {
    let mut segments = candidate.split('.');
    let (Some(a), Some(b), Some(c), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    !a.is_empty() && !b.is_empty() && !c.is_empty()
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
