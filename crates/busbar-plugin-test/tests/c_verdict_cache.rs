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

use busbar_kernel::auth::chain_run::{
    credential_hash, refreshed, AuthServices, ChainEnd, ChainInstance, IdentityPolicy, Verdict,
};
use busbar_kernel::auth::verdicts::{VerdictPolicy, Verdicts};
use busbar_plugin_abi::auth::{BAD_CREDENTIAL, FB_NEEDS_BODY};
use busbar_plugin_abi::fail::refused::R_UNSUPPORTED;
use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack};
use busbar_plugin_abi::types::{Bytes, Pair, Str};
use busbar_ports::auth::{
    AuthIn, AuthPort, Identity, LoginAnswer, LoginIn, OutboundAnswer, ServeIn, ServeOut,
    UpstreamIn, Verify, VerifyAnswer,
};
use busbar_ports::{CallCx, PortError};

// This cache fixture supplies complete host policy explicitly. Live serving constructs these services
// from its actual issued grants, replay store and route policy; this fixture accepts identities.
struct Checks;
impl IdentityPolicy for Checks {
    fn epoch(&self) -> u64 {
        1
    }
    fn authorize(&self, _: u64, _: &Identity, _: &AuthIn<'_>) -> Result<(), u32> {
        Ok(())
    }
}
impl busbar_kernel::issued::IssuedCredentials for Checks {
    fn lookup<'a>(
        &'a self,
        _: u64,
        _: &'a str,
        _: &'a str,
    ) -> BoxFut<'a, busbar_contract::secure::SecureVec> {
        Box::pin(async { busbar_contract::secure::SecureVec::new() })
    }
}
impl busbar_kernel::plane_grants::ReplayGuard for Checks {
    fn claim<'a>(
        &'a self,
        _: &'a busbar_plugin_abi::host_side::caller::Caller<'_>,
        _: &'a [u8],
        _: u64,
    ) -> BoxFut<'a, Result<bool, busbar_kernel::plugin_records::RecordsDenied>> {
        Box::pin(async { Ok(true) })
    }
}
static CHECKS: Checks = Checks;
static SERVICES: AuthServices<'static> = AuthServices {
    issued: &CHECKS,
    replay: &CHECKS,
    policy: &CHECKS,
};
fn instance(id: u64, port: &dyn AuthPort) -> ChainInstance<'_> {
    let caller = Box::leak(Box::new(busbar_plugin_abi::host_side::caller::Caller {
        plugin: "fixture",
        kind: busbar_plugin_abi::types::KindCode::Auth,
        name: "auth",
        instance: id,
        slot: 0,
        chain: 0,
        deadline: cx().deadline,
        stack: CallStack::default(),
        out_of_process: false,
        limits: Default::default(),
    }));
    let keys = Box::leak(Box::new(busbar_kernel::plane_grants::KeyRefresh::new(
        Duration::from_secs(30),
    )));
    ChainInstance {
        id,
        port,
        caller,
        keys,
        holds: &[],
    }
}
async fn verify_cached(
    cache: &dyn busbar_kernel::auth::verdicts::VerdictCache,
    instance: ChainInstance<'_>,
    cx: CallCx,
    req: &AuthIn<'_>,
) -> Result<Verdict, PortError> {
    busbar_kernel::auth::chain_run::verify_cached(&SERVICES, cache, instance, cx, req).await
}
async fn run_chain(
    cache: &dyn busbar_kernel::auth::verdicts::VerdictCache,
    chain: &[ChainInstance<'_>],
    cx: CallCx,
    req: &AuthIn<'_>,
) -> ChainEnd {
    busbar_kernel::auth::chain_run::run_chain(&SERVICES, cache, chain, cx, req).await
}

/// What the fake answers on every verify.
#[derive(Clone)]
pub(super) enum Answer {
    NotMine,
    Rejected,
    /// An identity for this subject (`Identity::from_ticket`: core-built, no F_CACHE_S, no F_EXPIRES_AT_S).
    Admit(String),
    /// The KEYS_STALE refusal.
    KeysStale,
}

pub(super) struct Fake {
    facts: u64,
    cred_headers: Vec<Box<str>>,
    answer: Answer,
    verifies: Arc<AtomicUsize>,
    refreshes: AtomicUsize,
}

impl Fake {
    pub(super) fn new(facts: u64, answer: Answer) -> Self {
        Self {
            facts,
            cred_headers: vec!["authorization".into()],
            answer,
            verifies: Arc::new(AtomicUsize::new(0)),
            refreshes: AtomicUsize::new(0),
        }
    }

    fn verifies(&self) -> usize {
        self.verifies.load(Ordering::SeqCst)
    }

    pub(super) fn refreshes(&self) -> usize {
        self.refreshes.load(Ordering::SeqCst)
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

    fn verify<'a>(&'a self, _cx: CallCx, _req: &AuthIn<'_>, _issued: Option<&[u8]>) -> Verify<'a> {
        let verifies = Arc::clone(&self.verifies);
        let answer = self.answer.clone();
        // A verify_io-style answer: it yields before it answers, so a burst overlaps one standing lead.
        Verify::Io(Box::pin(async move {
            verifies.fetch_add(1, Ordering::SeqCst);
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            Ok(match answer {
                Answer::NotMine => VerifyAnswer::NotMine,
                Answer::Rejected => VerifyAnswer::Refused {
                    code: BAD_CREDENTIAL,
                    text: "wrong password".into(),
                },
                Answer::Admit(subject) => {
                    VerifyAnswer::Identity(Identity::from_ticket(&subject, "chat"))
                }
                Answer::KeysStale => VerifyAnswer::KeysStale,
            })
        }))
    }

    fn login<'a>(
        &'a self,
        _cx: CallCx,
        _step: LoginIn<'a>,
    ) -> BoxFut<'a, Result<LoginAnswer, PortError>> {
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
        Box::pin(async {
            self.refreshes.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        })
    }

    fn serve<'a>(
        &'a self,
        _cx: CallCx,
        _req: &'a ServeIn<'a>,
    ) -> BoxFut<'a, Result<ServeOut, PortError>> {
        unsupported()
    }
}

pub(super) fn cx() -> CallCx {
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
    request_at(headers, 1_000)
}

fn request_at<'a>(headers: &'a [Pair<'a>], now_s: u64) -> AuthIn<'a> {
    AuthIn {
        method: "GET",
        path: "/v1/models",
        query: "",
        authority: "gateway.example",
        headers,
        peer: "203.0.113.7",
        tls_peer_cert: &[],
        body: &[],
        now_s,
    }
}

/// Polls every future to completion on this task, so they overlap like concurrent requests.
pub(super) async fn join_all<F: Future>(futures: Vec<F>) -> Vec<F::Output> {
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
    let instance = instance(7, &port);
    let outcomes = join_all(
        (0..64)
            .map(|_| verify_cached(&cache, instance, cx(), &req))
            .collect(),
    )
    .await;
    assert_eq!(
        port.verifies(),
        1,
        "one leader verifies; 63 followers share its outcome"
    );
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
    let instance = instance(7, &port);
    let mut leader = Box::pin(verify_cached(&cache, instance, cx(), &req));
    let mut follower = Box::pin(verify_cached(&cache, instance, cx(), &req));
    let mut noop = Context::from_waker(Waker::noop());
    assert!(
        leader.as_mut().poll(&mut noop).is_pending(),
        "the leader is mid-verify"
    );
    assert!(
        follower.as_mut().poll(&mut noop).is_pending(),
        "the follower waits on the lead"
    );
    drop(leader);
    let outcome = follower.await;
    assert!(matches!(outcome, Ok(Verdict::Rejected { .. })));
    assert_eq!(
        port.verifies(),
        2,
        "the follower led at once and verified; not after LEAD_MS"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn not_mine_is_never_cached() {
    let cache = cache();
    let port = Fake::new(0, Answer::NotMine);
    let headers = [pair("authorization", "Bearer someone-elses")];
    let req = request(&headers);
    let instance = instance(3, &port);
    for _ in 0..2 {
        assert!(matches!(
            verify_cached(&cache, instance, cx(), &req).await,
            Ok(Verdict::NotMine)
        ));
    }
    assert_eq!(port.verifies(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn a_body_bound_instance_bypasses_the_cache_and_its_leads() {
    let cache = cache();
    let port = Fake::new(FB_NEEDS_BODY, Answer::Rejected);
    let headers = [pair("authorization", "Bearer signed")];
    let req = request(&headers);
    let instance = instance(4, &port);
    join_all(
        (0..16)
            .map(|_| verify_cached(&cache, instance, cx(), &req))
            .collect(),
    )
    .await;
    assert_eq!(
        port.verifies(),
        16,
        "rule 1: an FB_NEEDS_BODY instance verifies every request unshared"
    );
    assert_eq!(cache.keys(4), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn two_instances_given_the_same_credential_never_share() {
    let cache = cache();
    let port = Fake::new(0, Answer::Rejected);
    let headers = [pair("authorization", "Bearer same-bytes")];
    let req = request(&headers);
    let a = instance(1, &port);
    let b = instance(2, &port);
    join_all(vec![
        verify_cached(&cache, a, cx(), &req),
        verify_cached(&cache, b, cx(), &req),
    ])
    .await;
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
        instance(1, &first),
        instance(2, &second),
        instance(3, &third),
    ];
    let end = run_chain(&cache, &chain, cx(), &req).await;
    assert!(matches!(end, ChainEnd::Rejected { instance: 2, code, .. } if code == BAD_CREDENTIAL));
    assert_eq!(
        (first.verifies(), second.verifies(), third.verifies()),
        (1, 1, 0)
    );
    let none = run_chain(&cache, &chain[..1], cx(), &req).await;
    assert!(
        matches!(none, ChainEnd::NoIdentity),
        "all NOT_MINE is R_AUTH_REQUIRED"
    );
    assert!(matches!(
        run_chain(&cache, &[], cx(), &req).await,
        ChainEnd::NoIdentity
    ));
}

#[test]
fn the_key_reads_only_the_declared_credential_headers() {
    let declared: [Box<str>; 1] = ["authorization".into()];
    let base = credential_hash(&declared, &[pair("authorization", "Bearer a")]);
    let noise = credential_hash(
        &declared,
        &[pair("accept", "*/*"), pair("authorization", "Bearer a")],
    );
    assert_eq!(base, noise, "an undeclared header does not change the key");
    assert_ne!(
        base,
        credential_hash(&declared, &[pair("authorization", "Bearer b")])
    );
    assert_ne!(
        base,
        credential_hash(
            &declared,
            &[
                pair("authorization", "Bearer a"),
                pair("authorization", "Bearer a")
            ]
        ),
        "the value count is part of the key"
    );
    assert_ne!(
        base,
        credential_hash(&declared, &[]),
        "no credential is its own key"
    );
    let split = credential_hash(
        &declared,
        &[pair("authorization", "ab"), pair("authorization", "c")],
    );
    let joined = credential_hash(
        &declared,
        &[pair("authorization", "a"), pair("authorization", "bc")],
    );
    assert_ne!(split, joined, "values are length-prefixed");
}

#[test]
#[ignore = "owner: W1-K8B; re-checked 2026-11-16: Identity is real now (plugin-loader ports/auth.rs:39), so arm (a) second request served from the cache, (b) the default 300 s TTL, (d) capacity, eviction order and the 8 KiB identity cap, and (e) flush on refresh, on KEYS_STALE and against an in-flight lead run as the sibling tests below; still missing here: the 0-allocation hit (counting allocator), F_CACHE_S 60/99,999/0 and F_EXPIRES_AT_S (an Identity carries them only from the adapter decode, ports/auth.rs decode_verify_ok is crate-private and no auth fixture image exists), and the flush on reconfigure and close (the instance lifecycle is W2-SW-AUTH: the cache is not on the live request path, which is AuthMiddleware::run_chain_on_request_path, busbar-kernel auth/mod.rs:784; draft MR !2481)"]
fn identity_arms() {
    todo!("owner: W1-K8B (C-VERDICT-CACHE (a), (b), (d), (e); W1-L5's Identity accessors)")
}

#[test]
#[ignore = "owner: W1-K8B; re-checked 2026-11-16: arm (i) needs crates/busbar-kernel/src/host_verify.rs gone, and it still exists (lib.rs:336, VerifyBook, used by crates/busbar/src/root/serve.rs); it goes with the service ABI deletion (busbar#268) and the auth switch-over (draft MR !2481, W2-SW-AUTH)"]
fn one_verdict_cache_in_the_kernel() {
    todo!("owner: W1-K8B (C-VERDICT-CACHE (i), busbar#268)")
}

// Sibling arms: the parts of (a), (b), (d) and (e) that run over a core-built `Identity`
// (`Identity::from_ticket`), through the same chain walk and cache production uses.

fn subject_of(outcome: &Result<Verdict, PortError>) -> Option<String> {
    match outcome {
        Ok(Verdict::Identity(identity)) => Some(identity.subject().to_owned()),
        _ => None,
    }
}

fn admit(subject: &str) -> Fake {
    Fake::new(0, Answer::Admit(subject.to_owned()))
}

fn sized(max_entries: u32) -> Verdicts {
    Verdicts::new(VerdictPolicy {
        max_entries,
        ..VerdictPolicy::default()
    })
}

#[tokio::test(flavor = "current_thread")]
async fn the_same_bearer_twice_verifies_once_and_the_entry_lives_300_s_by_default() {
    let cache = cache();
    let port = admit("alice");
    let headers = [pair("authorization", "Bearer cold")];
    let instance = instance(7, &port);
    let first = verify_cached(&cache, instance, cx(), &request_at(&headers, 1_000)).await;
    let second = verify_cached(&cache, instance, cx(), &request_at(&headers, 1_100)).await;
    assert_eq!(
        port.verifies(),
        1,
        "(a) one plugin verify for the same bearer"
    );
    assert_eq!(subject_of(&first).as_deref(), Some("alice"));
    assert_eq!(
        subject_of(&second).as_deref(),
        Some("alice"),
        "(a) the second request is admitted with the same identity"
    );
    // (b) no F_CACHE_S: the entry lives the 300 s default.
    let last = verify_cached(&cache, instance, cx(), &request_at(&headers, 1_299)).await;
    assert_eq!(subject_of(&last).as_deref(), Some("alice"));
    assert_eq!(port.verifies(), 1, "still fresh at 299 s");
    let after = verify_cached(&cache, instance, cx(), &request_at(&headers, 1_300)).await;
    assert_eq!(subject_of(&after).as_deref(), Some("alice"));
    assert_eq!(port.verifies(), 2, "re-verified once the 300 s are up");
}

#[tokio::test(flavor = "current_thread")]
async fn at_capacity_the_idle_entry_with_the_soonest_expiry_goes_first() {
    let cache = sized(2);
    let port = admit("alice");
    let (a, b, c) = (
        [pair("authorization", "Bearer a")],
        [pair("authorization", "Bearer b")],
        [pair("authorization", "Bearer c")],
    );
    let instance = instance(7, &port);
    for (headers, at) in [(&a, 1_000), (&b, 1_010), (&c, 1_020)] {
        let outcome = verify_cached(&cache, instance, cx(), &request_at(headers, at)).await;
        assert_eq!(subject_of(&outcome).as_deref(), Some("alice"));
    }
    assert_eq!(port.verifies(), 3);
    assert_eq!(cache.keys(7), 2, "(d) never above max_entries");
    verify_cached(&cache, instance, cx(), &request_at(&b, 1_030))
        .await
        .ok();
    assert_eq!(port.verifies(), 3, "b outlived a: the soonest expiry went");
    verify_cached(&cache, instance, cx(), &request_at(&a, 1_030))
        .await
        .ok();
    assert_eq!(port.verifies(), 4, "a was the entry evicted for c");
}

#[tokio::test(flavor = "current_thread")]
async fn with_every_entry_leading_the_next_request_bypasses_and_is_never_refused() {
    let cache = sized(2);
    let port = admit("alice");
    let (a, b, c) = (
        [pair("authorization", "Bearer a")],
        [pair("authorization", "Bearer b")],
        [pair("authorization", "Bearer c")],
    );
    let instance = instance(7, &port);
    let (req_a, req_b, req_c) = (
        request_at(&a, 1_000),
        request_at(&b, 1_000),
        request_at(&c, 1_000),
    );
    let mut lead_a = Box::pin(verify_cached(&cache, instance, cx(), &req_a));
    let mut lead_b = Box::pin(verify_cached(&cache, instance, cx(), &req_b));
    let mut noop = Context::from_waker(Waker::noop());
    assert!(lead_a.as_mut().poll(&mut noop).is_pending());
    assert!(lead_b.as_mut().poll(&mut noop).is_pending());
    let bypassed = verify_cached(&cache, instance, cx(), &req_c).await;
    assert_eq!(
        subject_of(&bypassed).as_deref(),
        Some("alice"),
        "(d) verified and admitted, never refused"
    );
    assert_eq!(port.verifies(), 3);
    assert_eq!(cache.keys(7), 2, "and not filled");
}

#[tokio::test(flavor = "current_thread")]
async fn an_identity_over_8_kib_is_verified_afresh_every_time() {
    let cache = cache();
    let port = admit(&"x".repeat(9_000));
    let headers = [pair("authorization", "Bearer big")];
    let instance = instance(7, &port);
    for _ in 0..2 {
        let outcome = verify_cached(&cache, instance, cx(), &request_at(&headers, 1_000)).await;
        assert!(matches!(outcome, Ok(Verdict::Identity(_))));
    }
    assert_eq!(
        port.verifies(),
        2,
        "(d) over max_identity_bytes is never filled"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_completed_refresh_flushes_the_instance_and_a_failed_one_does_not() {
    let cache = cache();
    let port = admit("alice");
    let headers = [pair("authorization", "Bearer cold")];
    let instance = instance(7, &port);
    let req = request_at(&headers, 1_000);
    verify_cached(&cache, instance, cx(), &req).await.ok();
    let failed: Result<Option<u32>, PortError> = Err(PortError::Refused {
        code: R_UNSUPPORTED,
        text: "not offered".into(),
        error: None,
    });
    refreshed(&cache, 7, &failed);
    verify_cached(&cache, instance, cx(), &req).await.ok();
    assert_eq!(port.verifies(), 1, "(e) a failed refresh keeps the entries");
    refreshed(&cache, 7, &Ok(None));
    verify_cached(&cache, instance, cx(), &req).await.ok();
    assert_eq!(
        port.verifies(),
        2,
        "(e) the next request re-verifies after a refresh"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_keys_stale_answer_flushes_the_instance() {
    let cache = cache();
    let good = admit("alice");
    let stale = Fake::new(0, Answer::KeysStale);
    let known = [pair("authorization", "Bearer known")];
    let unknown_key = [pair("authorization", "Bearer unknown-kid")];
    let id = 7;
    verify_cached(
        &cache,
        instance(id, &good),
        cx(),
        &request_at(&known, 1_000),
    )
    .await
    .ok();
    let refused = verify_cached(
        &cache,
        instance(id, &stale),
        cx(),
        &request_at(&unknown_key, 1_001),
    )
    .await;
    assert!(matches!(refused, Ok(Verdict::Rejected { code, .. }) if code == BAD_CREDENTIAL));
    verify_cached(
        &cache,
        instance(id, &good),
        cx(),
        &request_at(&known, 1_002),
    )
    .await
    .ok();
    assert_eq!(
        good.verifies(),
        2,
        "(e) KEYS_STALE dropped the instance's entries"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_verify_that_began_before_a_flush_does_not_fill() {
    let cache = cache();
    let port = admit("alice");
    let headers = [pair("authorization", "Bearer racing")];
    let instance = instance(7, &port);
    let req = request_at(&headers, 1_000);
    let mut leader = Box::pin(verify_cached(&cache, instance, cx(), &req));
    let mut noop = Context::from_waker(Waker::noop());
    assert!(leader.as_mut().poll(&mut noop).is_pending(), "mid-verify");
    refreshed(&cache, 7, &Ok(None));
    let outcome = leader.await;
    assert_eq!(
        subject_of(&outcome).as_deref(),
        Some("alice"),
        "the leader still gets its own answer"
    );
    verify_cached(&cache, instance, cx(), &req).await.ok();
    assert_eq!(port.verifies(), 2, "(e) the stale-epoch fill was discarded");
}
