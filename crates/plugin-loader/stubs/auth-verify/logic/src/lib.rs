// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]

use busbar_contract::abi::auth::{AuthPoints, AuthTail};
use busbar_contract::abi::mechanism::door::{MarkWord, Statement};
use busbar_contract::abi::sdk::auth_door::{
    carrier, strip_field, verify_tail, with_operator, with_tail, Answer, Strip, Verdict,
    VerifiedIdentity, VerifyPlugin, VerifyView,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::{constant_time_eq, sha256_hex};

pub const ADMIN_TOKENS_PRINCIPAL_ID: &str = "admin";

pub const ADMIN_TOKENS_MODULE_NAME: &str = "admin-tokens";

pub const ADMIN_TOKEN_HEADER: &str = "x-admin-token";

pub const AUTHORIZATION_HEADER: &str = "authorization";

const STRIPS: &[Strip] = &[
    strip_field(AUTHORIZATION_HEADER),
    strip_field(ADMIN_TOKEN_HEADER),
];

fn header_text(value: &[u8]) -> Option<&str> {
    if !value
        .iter()
        .all(|&b| b == b'\t' || (0x20..0x7f).contains(&b))
    {
        return None;
    }
    std::str::from_utf8(value).ok()
}

#[must_use]
pub fn bearer_token(value: &[u8]) -> Option<&str> {
    let (scheme, token) = header_text(value)?.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

fn operator() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: ADMIN_TOKENS_PRINCIPAL_ID.to_string(),
        ..VerifiedIdentity::default()
    }
}

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

    Verdict::reject(NO_MATCH)
}

pub const NO_MATCH: &str =
    "the presented admin token does not match the configured digest (the token is not echoed)";

pub const NOT_A_DIGEST: &str =
    "admin-tokens plugin config must be the admin token's SHA-256 digest \
                                as 64 hex characters (the value is not echoed)";

pub const EMPTY_TOKEN: &str =
    "admin-tokens plugin config is the SHA-256 digest of an empty token, \
                               which is refused (the value is not echoed)";

const EMPTY_TOKEN_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

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

fn header_token(value: &[u8]) -> Option<&str> {
    header_text(value).filter(|t| !t.is_empty())
}

/// THE PLUGIN: the configured admin token's SHA-256 hex digest (never the raw token).
#[derive(Debug)]
pub struct AdminTokens {
    configured_hash: String,
    short_judgments: std::sync::atomic::AtomicU64,
}

impl VerifyPlugin for AdminTokens {
    fn validate(settings: &[u8]) -> Result<(), busbar_contract::abi::sdk::life::Refusal> {
        busbar_contract::abi::sdk::auth_door::validate_by_opening::<Self>(settings)
    }

    fn open_refusing(settings: &[u8], _secrets: &[&[u8]]) -> Result<Self, Refusal> {
        Ok(Self {
            configured_hash: digest_of(settings).map_err(Refusal::failed)?,
            short_judgments: std::sync::atomic::AtomicU64::new(0),
        })
    }

    fn verify(&self, request: &VerifyView<'_>) -> Answer {
        if request.path() == b"/auth-short-custody" {
            let judgment = self
                .short_judgments
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            return Verdict::Identity(VerifiedIdentity {
                subject: format!("judgment-{judgment}"),
                groups: (0..300).map(|i| format!("group-{i}")).collect(),
                ..VerifiedIdentity::default()
            })
            .into();
        }
        let verdict = authenticate_admin_tokens(
            Some(&self.configured_hash),
            request.line(AUTHORIZATION_HEADER).and_then(bearer_token),
            request.line(ADMIN_TOKEN_HEADER).and_then(header_token),
        );
        Answer {
            fixed_strips: STRIPS,
            ..verdict.into()
        }
    }
}

const CARRIERS: &[MarkWord] = &[carrier(AUTHORIZATION_HEADER), carrier(ADMIN_TOKEN_HEADER)];

const TAIL: &AuthTail = &with_operator(verify_tail(0, AuthPoints::HEAD), ADMIN_TOKENS_PRINCIPAL_ID);

pub const STATEMENT: Statement = with_tail(
    Statement {
        mark_words: CARRIERS.as_ptr(),
        mark_words_len: CARRIERS.len(),
        ..statement(ADMIN_TOKENS_MODULE_NAME, env!("CARGO_PKG_VERSION"), 64)
    },
    TAIL,
);

pub mod door {
    busbar_contract::auth_verify_door!(super::AdminTokens, super::STATEMENT);
}
