// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::auth::FACT_OPERATOR;
use busbar_contract::abi::auth::{AuthPoints, AuthTail};
use busbar_contract::abi::mechanism::door::{MarkWord, Statement};
use busbar_contract::abi::sdk::auth_door::{
    carrier, strip_field, verify_tail, with_operator, with_tail, Answer, Strip, Verdict,
    VerifiedIdentity, VerifyPlugin, VerifyView,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::auth_calls::{AuthCalls, Verified, VerifyAnswer, VerifyRequest, Verifying};
use busbar_contract::redacted::{constant_time_eq, sha256_hex};

const WORDS: busbar_kernel_identity::operator::OperatorWords =
    busbar_kernel_identity::operator::OperatorWords {
        provider: "test-operator-double",
        principal_id: "admin",
    };

pub(crate) fn words() -> busbar_kernel_identity::operator::OperatorWords {
    WORDS
}

const AUTHORIZATION: &str = "authorization";

const OPERATOR_HEADER: &str = "x-admin-token";

const STRIPS: &[Strip] = &[strip_field(AUTHORIZATION), strip_field(OPERATOR_HEADER)];

fn text(value: &[u8]) -> Option<&str> {
    value
        .iter()
        .all(|&b| b == b'\t' || (32..127).contains(&b))
        .then(|| std::str::from_utf8(value).ok())
        .flatten()
}

fn bearer_token(value: &[u8]) -> Option<&str> {
    let (scheme, token) = text(value)?.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

fn jws_shaped(candidate: &str) -> bool {
    let mut segments = candidate.split('.');
    matches!(
        (segments.next(), segments.next(), segments.next(), segments.next()),
        (Some(a), Some(b), Some(c), None) if !a.is_empty() && !b.is_empty() && !c.is_empty()
    )
}

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
        Verdict::reject("the presented operator token does not match the configured digest")
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
    fn validate(settings: &[u8]) -> Result<(), busbar_contract::abi::sdk::life::Refusal> {
        busbar_contract::abi::sdk::auth_door::validate_by_opening::<Self>(settings)
    }

    fn open_refusing(settings: &[u8], _secrets: &[&[u8]]) -> Result<Self, Refusal> {
        const NOT_A_DIGEST: &str = "the operator double's settings are the token's SHA-256 digest";
        let text: String =
            serde_json::from_slice(settings).map_err(|_| Refusal::failed(NOT_A_DIGEST))?;
        let digest = text.trim();
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Refusal::failed(NOT_A_DIGEST));
        }
        Ok(Self {
            digest: digest.to_ascii_lowercase(),
        })
    }

    fn verify(&self, request: &VerifyView<'_>) -> Answer {
        self.answer(|name| request.line(name))
    }
}

impl OperatorDouble {
    fn answer<'a>(&self, line: impl Fn(&str) -> Option<&'a [u8]>) -> Answer {
        let header = line(OPERATOR_HEADER)
            .and_then(text)
            .filter(|t| !t.is_empty());
        let verdict = judge(
            &self.digest,
            line(AUTHORIZATION).and_then(bearer_token),
            header,
        );
        Answer {
            fixed_strips: STRIPS,
            ..verdict.into()
        }
    }
}

const CARRIERS: &[MarkWord] = &[carrier(AUTHORIZATION), carrier(OPERATOR_HEADER)];

const TAIL: &AuthTail = &with_operator(verify_tail(0, AuthPoints::HEAD), WORDS.principal_id);

const STATEMENT: Statement = with_tail(
    Statement {
        mark_words: CARRIERS.as_ptr(),
        mark_words_len: CARRIERS.len(),
        ..statement(WORDS.provider, env!("CARGO_PKG_VERSION"), 64)
    },
    TAIL,
);

busbar_contract::auth_verify_door!(OperatorDouble, STATEMENT);

pub fn install() {
    crate::test_support::install_operator_auth_row_as(WORDS, door);
}

#[must_use]
pub(crate) fn carriers() -> Vec<String> {
    vec![AUTHORIZATION.to_string(), OPERATOR_HEADER.to_string()]
}

#[must_use]
pub(crate) fn principal() -> &'static str {
    WORDS.principal_id
}

#[must_use]
pub(crate) fn is_door(candidate: busbar_contract::abi::mechanism::door::DoorFn) -> bool {
    std::ptr::fn_addr_eq(
        candidate,
        door as busbar_contract::abi::mechanism::door::DoorFn,
    )
}

pub(crate) fn open_in_process(
    module: &str,
    settings: &serde_json::Value,
) -> Result<std::sync::Arc<dyn AuthCalls>, String> {
    let text = settings.to_string();
    <OperatorDouble as VerifyPlugin>::open_refusing(text.as_bytes(), &[])
        .map(|double| std::sync::Arc::new(OperatorCalls(double)) as std::sync::Arc<dyn AuthCalls>)
        .map_err(|e| format!("auth plugin '{module}': {e}"))
}

/// One in-process instance of the double (see the module doc).
#[derive(Debug)]
pub(crate) struct OperatorCalls(OperatorDouble);

impl OperatorCalls {
    fn answer(&self, request: &VerifyRequest) -> VerifyAnswer {
        let seal = crate::seal::lend();
        let Answer {
            verdict,
            mut strips,
            fixed_strips,
            ..
        } = self.0.answer(|name| {
            request
                .lines
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.expose(&seal).as_slice())
        });
        let (verified, reason) = match verdict {
            Verdict::Identity(id) => (Verified::Identity(id), None),
            Verdict::Reject => (Verified::Reject, None),
            Verdict::RejectBecause(why) => (Verified::Reject, Some(why.text().to_string())),
            Verdict::Pass => (Verified::Pass, None),
        };
        VerifyAnswer {
            strips: {
                strips.extend_from_slice(fixed_strips);
                strips
            },
            reason,
            ..VerifyAnswer::from(verified)
        }
    }
}

impl AuthCalls for OperatorCalls {
    fn name(&self) -> &str {
        WORDS.provider
    }

    fn facts(&self) -> u32 {
        FACT_OPERATOR
    }

    fn inbound_points(&self) -> AuthPoints {
        AuthPoints::HEAD
    }

    fn carriers(&self) -> Vec<String> {
        carriers()
    }

    fn verify_now(&self, request: &VerifyRequest) -> Option<VerifyAnswer> {
        Some(self.answer(request))
    }

    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        Box::new(Settled(Some(self.answer(&request))))
    }

    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

struct Settled(Option<VerifyAnswer>);

impl std::future::Future for Settled {
    type Output = VerifyAnswer;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<VerifyAnswer> {
        std::task::Poll::Ready(self.0.take().unwrap_or_else(|| Verified::Failed.into()))
    }
}

impl Verifying for Settled {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        self.0.take()
    }
}
