// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The operator credential on the auth kind's memory ABI: the request's lines handed through as
//! presented, the answer read as the admin chain reads it — an overloaded verifier and an outage
//! kept apart from a bad credential.

use crate::operator::{Judgement, OperatorCredential};
use busbar_contract::auth::AuthVerdict;
use busbar_contract::auth_calls::{
    AuthCalls, Verified, VerifiedIdentity, VerifyAnswer, VerifyRequest, Verifying,
};
use busbar_contract::redacted::Secret;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// The lines each crossing was handed, in order, still sealed (compared in constant time, never
/// revealed: a test double holds no seal).
type Seen = Mutex<Vec<Vec<(String, Secret<Vec<u8>>)>>>;

/// Answers `verified` on every call and records the lines it was handed.
struct Double {
    verified: Verified,
    now: bool,
    seen: Seen,
}

impl Double {
    fn new(verified: Verified, now: bool) -> Arc<Self> {
        Arc::new(Self {
            verified,
            now,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn record(&self, request: &VerifyRequest) {
        let lines = request
            .lines
            .iter()
            .map(|(n, v)| (n.clone(), v.clone()))
            .collect();
        self.seen.lock().unwrap().push(lines);
    }
}

struct Answered(Option<VerifyAnswer>);

impl Future for Answered {
    type Output = VerifyAnswer;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<VerifyAnswer> {
        Poll::Ready(self.0.take().expect("polled once"))
    }
}

impl Verifying for Answered {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        self.0.take()
    }
}

impl AuthCalls for Double {
    fn name(&self) -> &str {
        "double"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(&self, request: &VerifyRequest) -> Option<VerifyAnswer> {
        self.record(request);
        self.now.then(|| self.verified.clone().into())
    }
    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        self.record(&request);
        Box::new(Answered(Some(self.verified.clone().into())))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

/// Drive a future that never waits.
fn ready<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("the double never waits"),
    }
}

fn request() -> VerifyRequest {
    VerifyRequest {
        lines: vec![
            ("line-a".into(), Secret::new(b"one".to_vec())),
            ("line-b".into(), Secret::new(b"two".to_vec())),
        ],
        ..VerifyRequest::default()
    }
}

fn kind(j: Option<Judgement>) -> &'static str {
    match j.map(|j| j.verdict) {
        None => "unanswered",
        Some(AuthVerdict::Identify(_)) => "identify",
        Some(AuthVerdict::Reject) => "reject",
        Some(AuthVerdict::Pass) => "pass",
    }
}

#[test]
fn every_answer_is_read_as_the_admin_chain_reads_it() {
    let identity = Verified::Identity(VerifiedIdentity {
        subject: "op".into(),
        groups: vec!["g".into()],
        ..VerifiedIdentity::default()
    });
    for (verified, want) in [
        (identity, "identify"),
        (Verified::Reject, "reject"),
        (Verified::Pass, "pass"),
        (Verified::Overloaded, "reject"),
        (Verified::Failed, "reject"),
    ] {
        let double = Double::new(verified, true);
        let credential = OperatorCredential::Module(double.clone());
        assert_eq!(kind(ready(credential.judge(request()))), want, "awaited");
        assert_eq!(kind(credential.probe(&request())), want, "probed");
        let seen = double.seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "one crossing per judgement");
        for lines in seen.iter() {
            assert_eq!(
                lines,
                &vec![
                    ("line-a".to_string(), Secret::new(b"one".to_vec())),
                    ("line-b".to_string(), Secret::new(b"two".to_vec()))
                ],
                "the request's lines reach the plugin as presented"
            );
        }
    }
}

/// SIGN-auth-kind 2026-10-30 (lead-signed under owner delegation, extending the owner-signed
/// 2026-10-30 rule "an IdP outage answers 503, never 401"): a verifier that answered NO VERDICT is
/// still refused (a `Reject`, fail-closed) and is marked `no_verdict`, so the door answers it 503
/// rather than the bad credential's 401. An overloaded verifier and a bad credential are not
/// marked. RED before the decision: nothing told the verdict-less refusal apart.
#[test]
fn a_verdict_less_answer_is_refused_and_marked() {
    for (verified, no_verdict) in [
        (Verified::Failed, true),
        (Verified::Reject, false),
        (Verified::Overloaded, false),
        (Verified::Pass, false),
    ] {
        let credential = OperatorCredential::Module(Double::new(verified.clone(), true));
        let judged = ready(credential.judge(request())).expect("a row answers");
        assert_eq!(judged.no_verdict, no_verdict, "{verified:?}");
        if no_verdict {
            assert_eq!(judged.verdict, AuthVerdict::Reject, "refused, fail-closed");
        }
        assert_eq!(
            Judgement::answered(verified.clone().into()).no_verdict,
            no_verdict
        );
    }
    assert!(!Judgement::of(AuthVerdict::Reject).no_verdict);
}

#[test]
fn the_identity_becomes_the_principal() {
    let double = Double::new(
        Verified::Identity(VerifiedIdentity {
            subject: "admin".into(),
            name: Some("Op".into()),
            groups: vec!["ops".into()],
            ttl_secs: Some(7),
            ..VerifiedIdentity::default()
        }),
        true,
    );
    let credential = OperatorCredential::Module(double);
    let Some(Judgement {
        verdict: AuthVerdict::Identify(p),
        ..
    }) = ready(credential.judge(request()))
    else {
        panic!("identifies");
    };
    assert_eq!(p.id, "admin");
    assert_eq!(p.name.as_deref(), Some("Op"));
    assert_eq!(p.roles, vec!["ops".to_string()]);
    assert_eq!(p.ttl_secs, Some(7));
}

#[test]
fn a_probe_the_plugin_cannot_answer_on_the_spot_is_a_refusal() {
    let credential = OperatorCredential::Module(Double::new(Verified::Pass, false));
    assert_eq!(kind(credential.probe(&request())), "reject");
}

#[test]
fn no_row_is_unanswered_and_no_token_passes() {
    assert_eq!(
        kind(ready(OperatorCredential::Unanswered.judge(request()))),
        "unanswered"
    );
    assert_eq!(
        kind(OperatorCredential::Unanswered.probe(&request())),
        "unanswered"
    );
    assert_eq!(
        kind(ready(OperatorCredential::Unset.judge(request()))),
        "pass"
    );
    assert_eq!(kind(OperatorCredential::Unset.probe(&request())), "pass");
}
