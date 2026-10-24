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
            assert!(judged.is_some(), "a row answers");
            assert_eq!(kind(judged), want, "{how}");
        }
    }
}

/// A door no test opens: the rows below are read for their names alone.
extern "C" fn no_door() -> &'static busbar_contract::abi::mechanism::door::Door {
    unreachable!("the rows are read for their names; no test opens a door")
}

/// The rows a build links are an ARGUMENT: a row answers the operator provider by its key or by its
/// canonical name, and `names` judges a module by the row's identity rather than one spelling.
#[test]
fn the_linked_rows_are_read_from_what_the_caller_hands_in() {
    let rows: [crate::operator::LinkedAuth; 2] = [
        ("op-key", "op-canonical", no_door),
        ("other", "other", no_door),
    ];
    assert!(crate::operator::answered(&rows, "op-key"));
    assert!(crate::operator::answered(&rows, "op-canonical"));
    assert!(!crate::operator::answered(&rows, "absent"));
    assert!(
        !crate::operator::answered(&[], "op-key"),
        "no rows answer nothing"
    );
    assert!(crate::operator::names(&rows, "op-key", "op-key"));
    assert!(crate::operator::names(&rows, "op-key", "op-canonical"));
    assert!(!crate::operator::names(&rows, "op-key", "other"));
    assert!(
        crate::operator::names(&[], "op-key", "op-key"),
        "the bare key is always its own"
    );
}

/// NO WORDS IS NO OPERATOR. A record that lends no operator words (`RootInstall::default()`, a
/// build no root lent its record) reads its provider and principal id as the empty string; the
/// operator credential built over that answers for no provider and mints nobody, so an admin chain
/// position named `""` that identified `""` is not the operator. RED before: `Operator::new("")`
/// answered for `""` and minted `""`.
#[test]
fn no_words_make_no_operator() {
    let none = crate::operator::Operator::new("");
    assert!(
        !none.is(""),
        "an empty provider is not the operator credential"
    );
    assert!(
        !none.mints(Some(""), "", ""),
        "with no words lent, nothing is minted as the operator"
    );
    let op = crate::operator::Operator::new("op");
    assert!(op.is("op"));
    assert!(op.mints(Some("op"), "root", "root"));
    assert!(
        !op.mints(Some("op"), "", ""),
        "an empty principal id is minted by nobody, even by the operator credential"
    );
    let opened = crate::operator::Operator::open(
        "",
        [("", "")].into_iter(),
        &|_: &str| true,
        false,
        None,
        |_: &str| Err("not opened".to_string()),
    )
    .expect("an unanswered credential opens");
    assert!(
        !opened.is(""),
        "an opened credential with no words answers for nothing"
    );
}
