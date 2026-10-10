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
use busbar_contract::redacted::Redacted;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// The lines each crossing was handed, in order.
type Seen = Mutex<Vec<Vec<(String, Vec<u8>)>>>;

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
            .map(|(n, v)| (n.clone(), v.expose_secret().clone()))
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
            ("line-a".into(), Redacted::new(b"one".to_vec())),
            ("line-b".into(), Redacted::new(b"two".to_vec())),
        ],
        ..VerifyRequest::default()
    }
}

fn kind(j: Option<Judgement>) -> &'static str {
    match j {
        None => "unanswered",
        Some(Judgement::Verdict(AuthVerdict::Identify(_))) => "identify",
        Some(Judgement::Verdict(AuthVerdict::Reject)) => "reject",
        Some(Judgement::Verdict(AuthVerdict::Pass)) => "pass",
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
                    ("line-a".to_string(), b"one".to_vec()),
                    ("line-b".to_string(), b"two".to_vec())
                ],
                "the request's lines reach the plugin as presented"
            );
        }
    }
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
    let Some(Judgement::Verdict(AuthVerdict::Identify(p))) = ready(credential.judge(request()))
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

/// THE ADMIN VERDICT MAPPING (Q134: no admin 503 ships): a verdict is a verdict, and an overloaded
/// verifier or one that answered no verdict is 1.5.5's refusal, awaited and probed alike. RED: an
/// unjudged row read as anything but `reject` (the retired 503's `Err`).
#[test]
fn an_unjudged_admin_verdict_is_the_1_5_5_refusal() {
    for (verified, want) in [
        (Verified::Reject, "reject"),
        (Verified::Pass, "pass"),
        (Verified::Overloaded, "reject"),
        (Verified::Failed, "reject"),
    ] {
        let credential = OperatorCredential::Module(Double::new(verified, true));
        let judged = [
            ready(credential.judge(request())),
            credential.probe(&request()),
        ];
        for (judged, how) in judged.into_iter().zip(["awaited", "probed"]) {
            let got = judged.expect("a row answers").verdict();
            assert_eq!(kind(Some(Judgement::Verdict(got))), want, "{how}");
        }
    }
}
