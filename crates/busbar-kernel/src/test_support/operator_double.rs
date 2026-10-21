// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPERATOR-CREDENTIAL DOUBLE: the `kind: auth` door a test binary links onto the auth axis in
//! place of whichever operator-credential plugin the composition root links (BUSBAR-1.6.0.md
//! l.179-181: "Kernel tests use kind-neutral doubles ... The cleanliness crates (§8) obey the same
//! rule").
//!
//! It states itself under the stand-in operator words (`busbar_kernel_identity::operator::STAND_IN`)
//! and answers the operator credential's contract, nothing more: opened with the configured token's
//! SHA-256 digest (64 hex characters, as the operator `token:` resolves), it identifies the
//! operator principal when a bearer or an `x-admin-token` line hashes to that digest, refuses a
//! credential addressed to it that does not, and passes one shaped like a JWS (another verifier's).
//! The carriers are stripped whatever the verdict. Its Statement name is its own, never a plugin's.
//!
//! [`install`] links it as the operator credential's test registry row; the first install stands.

use busbar_contract::abi::auth::{AuthPoints, AuthTail};
use busbar_contract::abi::mechanism::door::{MarkWord, Statement};
use busbar_contract::abi::sdk::auth_door::{
    carrier, verify_tail, with_operator, with_tail, Answer, Strip, Verdict, VerifiedIdentity,
    VerifyPlugin, VerifyView,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::redacted::{constant_time_eq, sha256_hex};

/// The stand-in operator words the double answers to.
const WORDS: busbar_kernel_identity::operator::OperatorWords =
    busbar_kernel_identity::operator::STAND_IN;

/// The bearer carrier.
const AUTHORIZATION: &str = "authorization";
/// The operator's own header carrier (1.5.5's admin header).
const OPERATOR_HEADER: &str = "x-admin-token";

/// A line's value as the admin door reads it (`HeaderValue::to_str`: visible ASCII and tab), or
/// `None` for one that does not read as text, which the door treats as absent.
fn text(value: &[u8]) -> Option<&str> {
    value
        .iter()
        .all(|&b| b == b'\t' || (32..127).contains(&b))
        .then(|| std::str::from_utf8(value).ok())
        .flatten()
}

/// The token of a `Bearer <token>` line, or `None` for any other scheme or an empty token
/// (`admin_carriers`' bearer reading).
fn bearer_token(value: &[u8]) -> Option<&str> {
    let (scheme, token) = text(value)?.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// Three non-empty dot-separated segments: a signed token another verifier owns.
fn jws_shaped(candidate: &str) -> bool {
    let mut segments = candidate.split('.');
    matches!(
        (segments.next(), segments.next(), segments.next(), segments.next()),
        (Some(a), Some(b), Some(c), None) if !a.is_empty() && !b.is_empty() && !c.is_empty()
    )
}

/// The verdict over the two carriers: both compared (no short-circuit), the operator on a match, a
/// refusal for a non-JWS credential that missed, a pass otherwise.
fn judge(digest: &str, bearer: Option<&str>, header: Option<&str>) -> Verdict {
    if bearer.is_none() && header.is_none() {
        return Verdict::Pass;
    }
    let matches =
        |c: Option<&str>| c.is_some_and(|c| constant_time_eq(&sha256_hex(c.as_bytes()), digest));
    if u8::from(matches(bearer)) | u8::from(matches(header)) != 0 {
        return Verdict::Identity(VerifiedIdentity {
            subject: WORDS.principal_id.to_string(),
            ..VerifiedIdentity::default()
        });
    }
    let addressed = |c: Option<&str>| c.is_some_and(|c| !jws_shaped(c));
    if addressed(bearer) || addressed(header) {
        Verdict::Reject
    } else {
        Verdict::Pass
    }
}

/// One opened instance: the configured token's digest.
#[derive(Debug)]
pub struct OperatorDouble {
    digest: String,
}

impl VerifyPlugin for OperatorDouble {
    fn open(settings: &[u8], _secrets: &[&[u8]]) -> Result<Self, &'static str> {
        const NOT_A_DIGEST: &str = "the operator double's settings are the token's SHA-256 digest";
        let text: String = serde_json::from_slice(settings).map_err(|_| NOT_A_DIGEST)?;
        let digest = text.trim();
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(NOT_A_DIGEST);
        }
        Ok(Self {
            digest: digest.to_ascii_lowercase(),
        })
    }

    fn verify(&self, request: &VerifyView<'_>) -> Answer {
        // `admin_carriers`' reading: a present-but-blank (or non-text) `x-admin-token` is absent.
        let header = request
            .line(OPERATOR_HEADER)
            .and_then(text)
            .filter(|t| !t.is_empty());
        let verdict = judge(
            &self.digest,
            request.line(AUTHORIZATION).and_then(bearer_token),
            header,
        );
        Answer {
            strips: vec![Strip::field(AUTHORIZATION), Strip::field(OPERATOR_HEADER)],
            ..verdict.into()
        }
    }
}

const CARRIERS: &[MarkWord] = &[carrier(AUTHORIZATION), carrier(OPERATOR_HEADER)];

const TAIL: &AuthTail = &with_operator(verify_tail(0, AuthPoints::HEAD), WORDS.principal_id);

/// The double's Statement: the stand-in provider's name, its two carriers, the operator tail.
const STATEMENT: Statement = with_tail(
    Statement {
        mark_words: CARRIERS.as_ptr(),
        mark_words_len: CARRIERS.len(),
        ..statement(WORDS.provider, env!("CARGO_PKG_VERSION"), 64)
    },
    TAIL,
);

busbar_contract::auth_verify_door!(OperatorDouble, STATEMENT);

/// Link the double as the operator credential's test registry row, under the stand-in words. The
/// first install stands (the axis is process-wide).
pub fn install() {
    crate::test_support::install_operator_auth_row_as(WORDS, door);
}
