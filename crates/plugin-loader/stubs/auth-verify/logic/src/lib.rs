// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in `admin-tokens` ADMIN auth PLUGIN.
//!
//! A default-included, compile-removable module for the `admin_auth:` chain (the parallel chain
//! gating `/admin/v1/*`): the single operator admin token, presented as `Authorization: Bearer` or
//! `X-Admin-Token`. Architecturally a peer of any external admin module (AD/OIDC); this one is
//! credential-compare only. An admin credential legitimately arrives on two carriers, and the
//! constant-time both-carriers fold lives INSIDE the module: selecting a carrier before the compare
//! would reintroduce the timing observable the fold kills.
//!
//! ## One door, on the auth kind's memory ABI (THE DESIGN §11.4, §11.6)
//!
//! [`door::door`] is the plugin's `plugin_door!` door, built by the SDK's `auth_verify_door!` over
//! [`AdminTokens`]: a `kind: auth` plugin that states `CAP_INBOUND` only, reads its two credential
//! lines (`authorization` for the Bearer, and `x-admin-token`), names both for the transport to strip
//! whatever its verdict, and judges on the spot. A build that LINKS this crate
//! registers that door as its `admin-tokens` row; the dropped-in build
//! (`busbar-auth-admin-tokens-plugin`) exports the SAME door as `busbar_plugin_door`. Every verdict
//! either way is [`authenticate_admin_tokens`]'s.
//!
//! THE TEMPLATE for porting a `kind: auth` plugin onto the memory ABI: implement
//! `abi::sdk::auth_door::VerifyPlugin` (open from the settings document, verify over the
//! `VerifyView`), state the tail with `verify_tail`, and let `auth_verify_door!` write the door. The
//! crate holds no `unsafe`.

#![forbid(unsafe_code)]

use busbar_contract::abi::auth::{AuthPoints, AuthTail};
use busbar_contract::abi::mechanism::door::{MarkWord, Statement};
use busbar_contract::abi::sdk::auth_door::{
    carrier, verify_tail, with_operator, with_tail, Answer, Strip, Verdict, VerifiedIdentity,
    VerifyPlugin, VerifyView,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::{constant_time_eq, sha256_hex};

/// The fixed principal id the operator admin token identifies as. The built-in operator credential
/// carries FULL admin scope by definition (it is the root credential the deployment was born with);
/// group-mapped external principals get their scope from `group_map:` instead.
pub const ADMIN_TOKENS_PRINCIPAL_ID: &str = "admin";

/// The module name: the `admin_auth:` chain entry this module answers.
pub const ADMIN_TOKENS_MODULE_NAME: &str = "admin-tokens";

/// The second carrier the operator token may arrive on (lower-case); the first is the Bearer.
pub const ADMIN_TOKEN_HEADER: &str = "x-admin-token";

/// The line the Bearer arrives on (lower-case), as `Bearer <token>`.
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// A field value as header text, as 1.5.5 read it (`HeaderValue::to_str`): visible ASCII, space or
/// tab; any other byte makes the value no text at all.
fn header_text(value: &[u8]) -> Option<&str> {
    if !value
        .iter()
        .all(|&b| b == b'\t' || (0x20..0x7f).contains(&b))
    {
        return None;
    }
    std::str::from_utf8(value).ok()
}

/// The token of an `Authorization` value in the Bearer scheme: the value header text, the scheme
/// matched case-insensitively, the token non-empty. Any other value (another scheme, not header
/// text, no token) presents no Bearer (1.5.5's `to_str` then `extract_bearer_token`).
#[must_use]
pub fn bearer_token(value: &[u8]) -> Option<&str> {
    let (scheme, token) = header_text(value)?.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// The operator identity.
fn operator() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: ADMIN_TOKENS_PRINCIPAL_ID.to_string(),
        ..VerifiedIdentity::default()
    }
}

/// Judge the presented admin credential carriers against the configured admin token hash
/// (SHA-256 hex, pre-computed by the host).
///
/// Timing stance: BOTH carrier comparisons run UNCONDITIONALLY and fold with bitwise-OR — a request
/// presenting both a Bearer and an `X-Admin-Token` never skips the second compare, so "Bearer
/// matched" and "Bearer missed, header matched" are indistinguishable. Both candidates are
/// SHA-256-hashed before the constant-time compare, so candidate length leaks nothing. A missing
/// carrier contributes 0.
///
/// `None` hash (no admin token configured) ⇒ `Pass` — this module has nothing to judge; a chain
/// that ends all-`Pass` is denied (fail-closed), preserving "admin API disabled without a token".
///
/// A credential presented and not matching is a wrong credential, whatever its shape: `Reject`,
/// terminal in the admin chain, exactly as 1.5.5 ended every mismatch. A JWS/JWT-shaped wrong token
/// is not passed on to the next `admin_auth:` module.
#[must_use]
pub fn authenticate_admin_tokens(
    configured_hash: Option<&str>,
    bearer: Option<&str>,
    header: Option<&str>,
) -> Verdict {
    let Some(configured_hash) = configured_hash else {
        return Verdict::Pass;
    };
    if bearer.is_none() && header.is_none() {
        // No credential presented for this module: Pass (the chain's all-Pass denies).
        return Verdict::Pass;
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
        return Verdict::Identity(operator());
    }
    // A credential was presented (at least one carrier is `Some`) and neither matched.
    Verdict::reject(NO_MATCH)
}

/// Why a presented admin token is rejected: the operator's log only, never the client's answer.
/// It never echoes what was presented.
pub const NO_MATCH: &str =
    "the presented admin token does not match the configured digest (the token is not echoed)";

/// The refusal of settings that are not a digest. It never echoes what it was given.
pub const NOT_A_DIGEST: &str =
    "admin-tokens plugin config must be the admin token's SHA-256 digest \
                                as 64 hex characters (the value is not echoed)";

/// The refusal of the digest of an empty token: a blank admin token is refused, as the linked path
/// refuses it. It never echoes what it was given.
pub const EMPTY_TOKEN: &str =
    "admin-tokens plugin config is the SHA-256 digest of an empty token, \
                               which is refused (the value is not echoed)";

/// SHA-256 of the empty string: the digest of a blank admin token.
const EMPTY_TOKEN_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The configured digest out of the settings document: a JSON string holding the admin token's
/// SHA-256 digest as 64 hex characters (surrounding whitespace ignored), lower-cased. Fail-closed:
/// anything else is refused, and the raw token is never accepted, so no configuration has to hold
/// it.
///
/// # Errors
/// [`NOT_A_DIGEST`]; [`EMPTY_TOKEN`] for the digest of an empty token.
pub fn digest_of(settings: &[u8]) -> Result<String, &'static str> {
    let text: String = serde_json::from_slice(settings).map_err(|_| NOT_A_DIGEST)?;
    let digest = text.trim();
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NOT_A_DIGEST);
    }
    let digest = digest.to_ascii_lowercase();
    if digest == EMPTY_TOKEN_SHA256 {
        return Err(EMPTY_TOKEN);
    }
    Ok(digest)
}

/// The `X-Admin-Token` line as 1.5.5 read it (`extract_admin_header_token`: `to_str().ok()` then
/// `.filter(|t| !t.is_empty())`): a value that is not header text, or is blank, is ABSENT, never a
/// presented wrong credential.
fn header_token(value: &[u8]) -> Option<&str> {
    header_text(value).filter(|t| !t.is_empty())
}

/// THE PLUGIN: the configured admin token's SHA-256 hex digest (never the raw token).
#[derive(Debug)]
pub struct AdminTokens {
    configured_hash: String,
}

impl VerifyPlugin for AdminTokens {
    fn validate(settings: &[u8]) -> Result<(), busbar_contract::abi::sdk::life::Refusal> {
        busbar_contract::abi::sdk::auth_door::validate_by_opening::<Self>(settings)
    }

    fn open(settings: &[u8], _secrets: &[&[u8]]) -> Result<Self, Refusal> {
        Ok(Self {
            configured_hash: digest_of(settings).map_err(Refusal::failed)?,
        })
    }

    /// The Bearer (off the `authorization` line) and the `X-Admin-Token` line are put to
    /// [`authenticate_admin_tokens`] in one call, so the fold is the module's own. Whatever the
    /// verdict, both lines are named for the transport to strip: they are this module's credential
    /// lines.
    fn verify(&self, request: &VerifyView<'_>) -> Answer {
        let verdict = authenticate_admin_tokens(
            Some(&self.configured_hash),
            request.line(AUTHORIZATION_HEADER).and_then(bearer_token),
            request.line(ADMIN_TOKEN_HEADER).and_then(header_token),
        );
        Answer {
            strips: vec![
                Strip::field(AUTHORIZATION_HEADER),
                Strip::field(ADMIN_TOKEN_HEADER),
            ],
            ..verdict.into()
        }
    }
}

/// The credential lines `verify` reads, the Statement's carrier word marks: the host lends exactly
/// these.
const CARRIERS: &[MarkWord] = &[carrier(AUTHORIZATION_HEADER), carrier(ADMIN_TOKEN_HEADER)];

/// The auth tail: inbound only, judged on the spot, nothing cached (a compare against a value the
/// operator can rotate is never worth caching), reading its two credential lines. It states that it
/// IS the operator credential, and the principal id its identity carries: the host finds the
/// operator credential's row by this fact, never by its name.
const TAIL: &AuthTail = &with_operator(verify_tail(0, AuthPoints::HEAD), ADMIN_TOKENS_PRINCIPAL_ID);

/// What the plugin states: its name, version, the concurrency it serves and its two carriers.
pub const STATEMENT: Statement = with_tail(
    Statement {
        mark_words: CARRIERS.as_ptr(),
        mark_words_len: CARRIERS.len(),
        ..statement(ADMIN_TOKENS_MODULE_NAME, env!("CARGO_PKG_VERSION"), 64)
    },
    TAIL,
);

/// THE DOOR: `door::door`, the plugin's `DoorFn`. A build that links this crate registers it as the
/// `admin-tokens` row; `busbar-auth-admin-tokens-plugin` exports it as `busbar_plugin_door`.
pub mod door {
    busbar_contract::auth_verify_door!(super::AdminTokens, super::STATEMENT);
}
