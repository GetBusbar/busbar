// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-VERDICT-CACHE (ABI-MIN3-INTERFACE §14): Verdict cache rules 1-6 and single-flight (K2 + K8).
//!
//! W1-K8B's arms drive the chain walk with the verdict cache wired in (`busbar_kernel::auth::chain_run`) over a
//! fake `AuthPort` with a verify counter: the outcomes a lead shares (NotMine, Rejected), rule 1's bypass, the
//! per-instance key and the key derivation. The arms that need a filled entry need W1-L5's `Identity` (its
//! accessors are W0 stubs); K2's own tests cover the fill and TTL rules over stand-in values.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use busbar_kernel::auth::chain_run::{credential_hash, run_chain, verify_cached, ChainEnd, ChainInstance};
use busbar_kernel::auth::verdicts::{VerdictPolicy, Verdicts};
use busbar_plugin_abi::auth::{BAD_CREDENTIAL, FB_NEEDS_BODY};
use busbar_plugin_abi::fail::refused::R_UNSUPPORTED;
use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack};
use busbar_plugin_abi::types::{Bytes, Pair, Str};
use busbar_plugin_loader::ports::auth::{
    AuthIn, AuthPort, LoginAnswer, LoginIn, OutboundAnswer, ServeIn, ServeOut, UpstreamIn, Verdict,
    Verify,
};
use busbar_plugin_loader::ports::{CallCx, PortError};

/// What the fake answers on every verify.
#[derive(Clone)]
enum Answer {
    NotMine,
    Rejected,
}

struct Fake {
    facts: u64,
    cred_headers: Vec<Box<str>>,
    answer: Answer,
    verifies: Arc<AtomicUsize>,
}

impl Fake {
    fn new(facts: u64, answer: Answer) -> Self {
        Self {
            facts,
            cred_headers: vec!["authorization".into()],
            answer,
            verifies: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn verifies(&self) -> usize {
        self.verifies.load(Ordering::SeqCst)
    }
}

fn unsupported<'a, T: Send + 'a>() -> BoxFut<'a, Result<T, PortError>> {
    Box::pin(async {
        Err(PortError::Refused {
            code: R_UNSUPPORTED,
            text: "not offered".into(),
            error: None,
        })
    })
}

impl AuthPort for Fake {
    fn facts(&self) -> u64 {
        self.facts
    }

    fn cred_headers(&self) -> &[Box<str>] {
        &self.cred_headers
    }

    fn issued_kind(&self) -> Option<&str> {
        None
    }

    fn verify<'a>(&'a self, _cx: CallCx, _req: &'a AuthIn<'a>) -> Verify<'a> {
        let verifies = Arc::clone(&self.verifies);
        let answer = self.answer.clone();
        // A verify_io-style answer: it yields before it answers, so a burst overlaps one standing lead.
        Verify::Io(Box::pin(async move {
            verifies.fetch_add(1, Ordering::SeqCst);
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            Ok(match answer {
                Answer::NotMine => Verdict::NotMine,
                Answer::Rejected => Verdict::Rejected {
                    code: BAD_CREDENTIAL,
                    text: "wrong password".into(),
                },
            })
        }))
    }

    fn login<'a>(&'a self, _cx: CallCx, _step: LoginIn<'a>) -> BoxFut<'a, Result<LoginAnswer, PortError>> {
        unsupported()
    }

    fn outbound<'a>(
        &'a self,
        _cx: CallCx,
        _req: &'a UpstreamIn<'a>,
    ) -> BoxFut<'a, Result<OutboundAnswer, PortError>> {
        unsupported()
    }

    fn refresh<'a>(&'a self, _cx: CallCx) -> BoxFut<'a, Result<Option<u32>, PortError>> {
        unsupported()
    }

    fn serve<'a>(&'a self, _cx: CallCx, _req: &'a ServeIn<'a>) -> BoxFut<'a, Result<ServeOut, PortError>> {
        unsupported()
    }
}

fn cx() -> CallCx {
    CallCx {
        deadline: Instant::now() + Duration::from_secs(5),
        request_id: 1,
        stack: CallStack::default(),
    }
}

fn pair<'a>(name: &'a str, value: &'a str) -> Pair<'a> {
    Pair {
        name: Str::new(name),
        value: Bytes::new(value.as_bytes()),
    }
}

fn request<'a>(headers: &'a [Pair<'a>]) -> AuthIn<'a> {
    AuthIn {
        method: "GET",
        path: "/v1/models",
        query: "",
        authority: "gateway.example",
        headers,
        peer: "203.0.113.7",
        tls_peer_cert: &[],
        body: &[],
        now_s: 1_000,
    }
}

/// Polls every future to completion on this task, so they overlap like concurrent requests.
async fn join_all<F: Future>(futures: Vec<F>) -> Vec<F::Output> {
    let mut futures: Vec<Pin<Box<F>>> = futures.into_iter().map(Box::pin).collect();
    let mut done: Vec<Option<F::Output>> = futures.iter().map(|_| None).collect();
    std::future::poll_fn(move |cx| {
        let mut pending = false;
        for (future, out) in futures.iter_mut().zip(done.iter_mut()) {
            if out.is_none() {
                match future.as_mut().poll(cx) {
                    Poll::Ready(v) => *out = Some(v),
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(done.iter_mut().filter_map(Option::take).collect())
        }
    })
    .await
}

fn cache() -> Verdicts {
    Verdicts::new(VerdictPolicy::default())
}

#[tokio::test(flavor = "current_thread")]
async fn a_wrong_password_burst_of_64_makes_one_verify_and_64_rejections() {
    let cache = cache();
    let port = Fake::new(0, Answer::Rejected);
    let headers = [pair("authorization", "Basic YWxpY2U6d3Jvbmc=")];
    let req = request(&headers);
    let instance = ChainInstance { id: 7, port: &port };
    let outcomes = join_all((0..64).map(|_| verify_cached(&cache, instance, cx(), &req)).collect()).await;
    assert_eq!(port.verifies(), 1, "one leader verifies; 63 followers share its outcome");
    assert_eq!(outcomes.len(), 64);
    for outcome in outcomes {
        assert!(matches!(outcome, Ok(Verdict::Rejected { code, .. }) if code == BAD_CREDENTIAL));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_leader_dropped_mid_verify_hands_the_lead_to_the_first_follower_at_once() {
    let cache = cache();
    let port = Fake::new(0, Answer::Rejected);
    let headers = [pair("authorization", "Bearer cold")];
    let req = request(&headers);
    let instance = ChainInstance { id: 7, port: &port };
    let mut leader = Box::pin(verify_cached(&cache, instance, cx(), &req));
    let mut follower = Box::pin(verify_cached(&cache, instance, cx(), &req));
    let mut noop = Context::from_waker(Waker::noop());
    assert!(leader.as_mut().poll(&mut noop).is_pending(), "the leader is mid-verify");
    assert!(follower.as_mut().poll(&mut noop).is_pending(), "the follower waits on the lead");
    drop(leader);
    let outcome = follower.await;
    assert!(matches!(outcome, Ok(Verdict::Rejected { .. })));
    assert_eq!(port.verifies(), 2, "the follower led at once and verified; not after LEAD_MS");
}

#[tokio::test(flavor = "current_thread")]
async fn not_mine_is_never_cached() {
    let cache = cache();
    let port = Fake::new(0, Answer::NotMine);
    let headers = [pair("authorization", "Bearer someone-elses")];
    let req = request(&headers);
    let instance = ChainInstance { id: 3, port: &port };
    for _ in 0..2 {
        assert!(matches!(verify_cached(&cache, instance, cx(), &req).await, Ok(Verdict::NotMine)));
    }
    assert_eq!(port.verifies(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn a_body_bound_instance_bypasses_the_cache_and_its_leads() {
    let cache = cache();
    let port = Fake::new(FB_NEEDS_BODY, Answer::Rejected);
    let headers = [pair("authorization", "Bearer signed")];
    let req = request(&headers);
    let instance = ChainInstance { id: 4, port: &port };
    join_all((0..16).map(|_| verify_cached(&cache, instance, cx(), &req)).collect()).await;
    assert_eq!(port.verifies(), 16, "rule 1: an FB_NEEDS_BODY instance verifies every request unshared");
    assert_eq!(cache.keys(4), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn two_instances_given_the_same_credential_never_share() {
    let cache = cache();
    let port = Fake::new(0, Answer::Rejected);
    let headers = [pair("authorization", "Bearer same-bytes")];
    let req = request(&headers);
    let a = ChainInstance { id: 1, port: &port };
    let b = ChainInstance { id: 2, port: &port };
    join_all(vec![verify_cached(&cache, a, cx(), &req), verify_cached(&cache, b, cx(), &req)]).await;
    assert_eq!(port.verifies(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn the_chain_moves_past_not_mine_and_stops_at_a_rejection() {
    let cache = cache();
    let first = Fake::new(0, Answer::NotMine);
    let second = Fake::new(0, Answer::Rejected);
    let third = Fake::new(0, Answer::NotMine);
    let headers = [pair("authorization", "Bearer x")];
    let req = request(&headers);
    let chain = [
        ChainInstance { id: 1, port: &first },
        ChainInstance { id: 2, port: &second },
        ChainInstance { id: 3, port: &third },
    ];
    let end = run_chain(&cache, &chain, cx(), &req).await;
    assert!(matches!(end, ChainEnd::Rejected { instance: 2, code, .. } if code == BAD_CREDENTIAL));
    assert_eq!((first.verifies(), second.verifies(), third.verifies()), (1, 1, 0));
    let none = run_chain(&cache, &chain[..1], cx(), &req).await;
    assert!(matches!(none, ChainEnd::NoIdentity), "all NOT_MINE is R_AUTH_REQUIRED");
    assert!(matches!(run_chain(&cache, &[], cx(), &req).await, ChainEnd::NoIdentity));
}

#[test]
fn the_key_reads_only_the_declared_credential_headers() {
    let declared: [Box<str>; 1] = ["authorization".into()];
    let base = credential_hash(&declared, &[pair("authorization", "Bearer a")]);
    let noise = credential_hash(&declared, &[pair("accept", "*/*"), pair("authorization", "Bearer a")]);
    assert_eq!(base, noise, "an undeclared header does not change the key");
    assert_ne!(base, credential_hash(&declared, &[pair("authorization", "Bearer b")]));
    assert_ne!(
        base,
        credential_hash(&declared, &[pair("authorization", "Bearer a"), pair("authorization", "Bearer a")]),
        "the value count is part of the key"
    );
    assert_ne!(base, credential_hash(&declared, &[]), "no credential is its own key");
    let split = credential_hash(&declared, &[pair("authorization", "ab"), pair("authorization", "c")]);
    let joined = credential_hash(&declared, &[pair("authorization", "a"), pair("authorization", "bc")]);
    assert_ne!(split, joined, "values are length-prefixed");
}

#[test]
#[ignore = "owner: W1-K8B (needs W1-L5's Identity: arms (a), (b), (d), (e) fill and serve an entry)"]
fn identity_arms() {
    todo!("owner: W1-K8B (C-VERDICT-CACHE (a), (b), (d), (e); W1-L5's Identity accessors)")
}

#[test]
#[ignore = "owner: W1-K8B (arm (i): host_verify.rs stays until the service ABI is deleted, busbar#268)"]
fn one_verdict_cache_in_the_kernel() {
    todo!("owner: W1-K8B (C-VERDICT-CACHE (i), busbar#268)")
}
