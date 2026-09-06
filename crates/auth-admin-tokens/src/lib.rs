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
/// THREE ANSWERS, not two. A chain arm owes the chain three: `Identify` (mine and valid), `Reject`
/// (mine and wrong — stop, nobody else was asked for this), and `Pass` (NOT MINE — ask the next
/// arm). This module used to collapse the last two, answering a terminal `Reject` for any credential
/// that did not match. With `admin_auth: [admin-tokens, corp-oidc]` that made the second arm
/// unreachable: an OIDC bearer JWT was refused here before `corp-oidc` was ever asked, and the arm
/// was silently dead. The miss path now splits on [`is_foreign_credential_form`].
///
/// ORDER MATTERS, and it is validation FIRST: an operator token that matches identifies whatever it
/// looks like. The form test only ever runs on the miss path, so no shape rule can turn a valid
/// operator credential away.
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
    // A miss. Was this credential ever MINE to refuse? Every carrier actually presented has to be
    // attributable to another issuer before this arm steps aside; one unattributable carrier keeps
    // the whole presentation mine, and mine-and-wrong is terminal.
    let presented_is_all_foreign = [bearer, header]
        .into_iter()
        .flatten()
        .all(is_foreign_credential_form);
    if presented_is_all_foreign {
        AuthOutcome::Pass
    } else {
        AuthOutcome::Reject
    }
}

/// Is this candidate PROVABLY another issuer's credential, and therefore not an operator admin
/// token this arm should refuse on behalf of the whole chain?
///
/// The test has to run in this direction, because the other direction has no answer. There is no
/// minted admin-token form to match against: the operator admin token is an opaque secret the
/// DEPLOYMENT supplies through a `token:` secret ref, and the only thing the boot path ever asserts
/// about its value is that it is not blank (`resolve_admin_token`). Nothing in the binary generates
/// one, so it has no prefix, no length and no charset — the shipped configs and docs carry only
/// `{ env: BUSBAR_ADMIN_TOKEN }` and placeholders like `your-admin-token`. This module also
/// deliberately declines to look at an admin candidate's length or charset at all (see the timing
/// stance above). So "is this an admin token by shape" is a question no code here could answer
/// honestly, and answering it by guess would refuse real operator credentials.
///
/// What DOES have an answer is "does this candidate carry a form some other issuer mints". The one
/// such form this chain actually meets is the JWS Compact Serialization an OIDC / AD arm is handed
/// (RFC 7515 §7.1): three `.`-separated non-empty segments drawn entirely from the base64url
/// alphabet. That is the same class of structural pre-check busbar's own minted key uses to say "not
/// mine" before spending any crypto — `TokenVerifier::verify` reads the `bbk_` prefix and the
/// segment grammar straight off its mint site — so the rule here is read off a mint site rather than
/// guessed at, and it is a grammar walk rather than a pattern someone wrote out by hand.
///
/// FAIL-CLOSED DIRECTION. Anything this cannot positively attribute elsewhere stays MINE, so a wrong
/// credential is still the terminal `Reject` it was in 1.5.5 and only a provably-foreign one defers.
/// An operator who chose a JWT-shaped admin secret loses nothing either: it still matches and still
/// identifies (validation runs first), and if it is presented WRONG the chain refuses anyway — later
/// instead of here.
///
/// TIMING. This runs only after the constant-time fold has already missed, and it reads only the
/// candidate's own public structure. The configured secret is not an input, so neither its length
/// nor its charset becomes observable.
fn is_foreign_credential_form(candidate: &str) -> bool {
    let mut segments = candidate.split('.');
    let (Some(header), Some(payload), Some(signature)) =
        (segments.next(), segments.next(), segments.next())
    else {
        return false;
    };
    if segments.next().is_some() {
        // More than three segments: not the compact serialization, so not attributable.
        return false;
    }
    [header, payload, signature]
        .iter()
        .all(|seg| !seg.is_empty() && seg.bytes().all(is_base64url_byte))
}

/// The base64url alphabet (RFC 4648 §5), unpadded — the character set every JWS compact segment is
/// drawn from. `=` is excluded: JWS forbids the padding.
fn is_base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
