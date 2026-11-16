// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The outbound-credential cache (IF §12.2 rules 1-7) against a scripted token endpoint, on a paused clock.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::fail::failed::{F_BUSY, F_UNAVAILABLE};
use busbar_plugin_abi::fail::refused::R_DENIED;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_loader::ports::auth::OutboundAnswer;
use busbar_plugin_loader::ports::PortError;

use super::{CredCache, CredEvent, CredGet, CredKey, CredPolicy, CredentialCache};
use crate::retry::Retry;

type Minted = Result<OutboundAnswer, PortError>;

#[derive(Clone, Copy)]
enum Reply {
    /// A token and the lifetime its issuer stated.
    Token(&'static str, u32),
    /// 503 with a Retry-After.
    Down(u64),
    Refuse,
}

/// The token endpoint: each FETCH takes the next scripted reply (the last one repeats) after `delay`.
struct Endpoint {
    replies: Mutex<VecDeque<Reply>>,
    delay: Duration,
    /// `mint`/`detach` calls (closure invocations).
    minted: AtomicUsize,
    /// FETCHes that reached the endpoint.
    fetches: AtomicUsize,
}

impl Endpoint {
    fn new(replies: &[Reply], delay: Duration) -> Arc<Self> {
        Arc::new(Endpoint {
            replies: Mutex::new(replies.iter().copied().collect()),
            delay,
            minted: AtomicUsize::new(0),
            fetches: AtomicUsize::new(0),
        })
    }

    async fn fetch(&self) -> Minted {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        let reply = {
            let mut replies = self.replies.lock().expect("replies");
            if replies.len() > 1 {
                replies.pop_front()
            } else {
                replies.front().copied()
            }
        };
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        match reply.expect("a scripted reply") {
            Reply::Token(token, cache_s) => Ok(OutboundAnswer {
                headers: vec![(
                    Box::from("authorization"),
                    SecureVec::from(token.as_bytes()),
                )],
                query: Vec::new(),
                cache_s,
                grant_update: None,
            }),
            Reply::Down(retry_after_s) => Err(PortError::Failed {
                code: F_UNAVAILABLE,
                text: Box::from("token endpoint answered 503"),
                retry_after_s: Some(retry_after_s),
                backend_status: Some(503),
                error: None,
            }),
            Reply::Refuse => Err(PortError::Refused {
                code: R_DENIED,
                text: Box::from("invalid_client"),
                error: None,
            }),
        }
    }

    fn minted(&self) -> usize {
        self.minted.load(Ordering::SeqCst)
    }

    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

async fn owned(endpoint: Arc<Endpoint>) -> Minted {
    endpoint.fetch().await
}

fn minter<'e>(endpoint: &'e Endpoint) -> impl Fn() -> BoxFut<'e, Minted> + Send + Sync + 'e {
    move || -> BoxFut<'e, Minted> {
        endpoint.minted.fetch_add(1, Ordering::SeqCst);
        Box::pin(endpoint.fetch())
    }
}

/// The detached builder, counting its calls.
fn detacher(
    endpoint: &Arc<Endpoint>,
    calls: &Arc<AtomicUsize>,
) -> impl Fn() -> BoxFut<'static, Minted> {
    let endpoint = Arc::clone(endpoint);
    let calls = Arc::clone(calls);
    move || -> BoxFut<'static, Minted> {
        calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(owned(Arc::clone(&endpoint)))
    }
}

/// K3's AuthOutbound schedule (§12.3): After(min(300 s, max(30 s × 2^(streak − 1), retry_after_s))).
fn window(streak: u32, error: &PortError) -> Retry {
    let doubled = 30_u64.saturating_mul(1_u64 << streak.saturating_sub(1).min(16));
    let stated = match error {
        PortError::Failed {
            retry_after_s: Some(after),
            ..
        } => *after,
        _ => 0,
    };
    Retry::After(Duration::from_secs(doubled.max(stated).min(300)))
}

struct Fixture {
    cache: CredCache,
    audits: Arc<Mutex<Vec<CredEvent>>>,
}

impl Fixture {
    fn new(policy: CredPolicy) -> Self {
        let audits = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&audits);
        let cache = CredCache::new(policy, window, move |_, event| {
            sink.lock().expect("audits").push(event);
        });
        Fixture { cache, audits }
    }

    fn audits(&self, event: CredEvent) -> usize {
        let audits = self.audits.lock().expect("audits");
        audits.iter().filter(|seen| **seen == event).count()
    }
}

fn key(scope: u8) -> CredKey {
    CredKey {
        auth_instance: 7,
        upstream: 1,
        scope: [scope; 32],
        caller: [0; 32],
    }
}

fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

fn token(answer: &OutboundAnswer) -> &[u8] {
    answer.headers[0].1.as_slice()
}

async fn settled(get: CredGet<'_>) -> Result<Arc<OutboundAnswer>, PortError> {
    match get {
        CredGet::Ready(ready) => ready,
        CredGet::Wait(waiting) => waiting.await,
        CredGet::Direct(_) => panic!("a shared binding never answers Direct"),
    }
}

fn ready(get: CredGet<'_>) -> Result<Arc<OutboundAnswer>, PortError> {
    match get {
        CredGet::Ready(ready) => ready,
        CredGet::Wait(_) => panic!("Wait where Ready was due"),
        CredGet::Direct(_) => panic!("Direct where Ready was due"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_hit_calls_neither_closure_and_serves_the_published_arc() {
    let fx = Fixture::new(CredPolicy::DEFAULT);
    let endpoint = Endpoint::new(&[Reply::Token("tok-1", 600)], Duration::ZERO);
    let detached = Arc::new(AtomicUsize::new(0));
    let detach = detacher(&endpoint, &detached);
    let first = settled(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
    )
    .await
    .expect("minted");
    for _ in 0..10_000 {
        let hit = ready(
            fx.cache
                .get(key(1), false, now(), minter(&endpoint), &detach),
        )
        .expect("a hit");
        assert!(Arc::ptr_eq(&first, &hit));
    }
    assert_eq!(endpoint.minted(), 1);
    assert_eq!(detached.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn sixty_four_requests_on_a_cold_key_make_one_fetch() {
    let fx = Fixture::new(CredPolicy::DEFAULT);
    let endpoint = Endpoint::new(&[Reply::Token("tok-1", 600)], Duration::from_millis(50));
    let detached = Arc::new(AtomicUsize::new(0));
    let detach = detacher(&endpoint, &detached);
    let gets: Vec<_> = (0..64)
        .map(|_| {
            settled(
                fx.cache
                    .get(key(1), false, now(), minter(&endpoint), &detach),
            )
        })
        .collect();
    for answer in futures::future::join_all(gets).await {
        assert_eq!(
            token(&answer.expect("every request carries the token")),
            b"tok-1"
        );
    }
    assert_eq!(endpoint.fetches(), 1);
    assert_eq!(endpoint.minted(), 1);
}

#[tokio::test(start_paused = true)]
async fn refresh_ahead_serves_the_old_token_and_starts_one_detached_mint() {
    let fx = Fixture::new(CredPolicy::DEFAULT);
    let endpoint = Endpoint::new(
        &[Reply::Token("tok-1", 600), Reply::Token("tok-2", 600)],
        Duration::ZERO,
    );
    let detached = Arc::new(AtomicUsize::new(0));
    let detach = detacher(&endpoint, &detached);
    settled(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
    )
    .await
    .expect("minted");
    tokio::time::advance(Duration::from_secs(301)).await;
    for _ in 0..64 {
        let old = ready(
            fx.cache
                .get(key(1), false, now(), minter(&endpoint), &detach),
        )
        .expect("the old token, at once");
        assert_eq!(token(&old), b"tok-1");
    }
    assert_eq!(
        detached.load(Ordering::SeqCst),
        1,
        "one detached mint for 64 callers"
    );
    assert_eq!(endpoint.minted(), 1, "no request minted");
    tokio::time::sleep(Duration::from_millis(1)).await;
    let fresh = ready(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
    )
    .expect("the refreshed token");
    assert_eq!(token(&fresh), b"tok-2");
    assert_eq!(endpoint.fetches(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_down_endpoint_is_called_once_per_window_and_the_window_doubles() {
    let fx = Fixture::new(CredPolicy::DEFAULT);
    let endpoint = Endpoint::new(
        &[Reply::Down(45), Reply::Down(45), Reply::Token("tok-1", 600)],
        Duration::ZERO,
    );
    let detached = Arc::new(AtomicUsize::new(0));
    let detach = detacher(&endpoint, &detached);
    let failed = settled(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
    )
    .await;
    assert!(matches!(failed, Err(PortError::Failed { .. })));
    for _ in 0..100 {
        match ready(
            fx.cache
                .get(key(1), false, now(), minter(&endpoint), &detach),
        ) {
            Err(PortError::Failed {
                retry_after_s: Some(left),
                ..
            }) => assert!(left <= 45, "{left}"),
            _ => panic!("inside the window: the stored failure, no fetch"),
        }
    }
    assert_eq!(endpoint.fetches(), 1);
    assert_eq!(fx.audits(CredEvent::Backoff), 1);
    tokio::time::advance(Duration::from_secs(45)).await;
    let again = settled(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
    )
    .await;
    assert!(again.is_err());
    tokio::time::advance(Duration::from_secs(59)).await;
    assert!(
        ready(
            fx.cache
                .get(key(1), false, now(), minter(&endpoint), &detach)
        )
        .is_err(),
        "the second window is 60 s"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let ok = settled(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
    )
    .await;
    assert_eq!(token(&ok.expect("recovered")), b"tok-1");
    assert_eq!(endpoint.fetches(), 3);
    assert_eq!(fx.audits(CredEvent::Backoff), 2);
}

#[tokio::test(start_paused = true)]
async fn per_request_bindings_answer_direct_and_cache_nothing() {
    let fx = Fixture::new(CredPolicy::DEFAULT);
    let endpoint = Endpoint::new(&[Reply::Token("sig", 600)], Duration::ZERO);
    let detached = Arc::new(AtomicUsize::new(0));
    let detach = detacher(&endpoint, &detached);
    for _ in 0..8 {
        match fx
            .cache
            .get(key(1), true, now(), minter(&endpoint), &detach)
        {
            CredGet::Direct(direct) => {
                assert_eq!(direct.await.expect("signed").cache_s, 600);
            }
            _ => panic!("a per-request binding answers Direct"),
        }
    }
    assert_eq!(endpoint.minted(), 8);
    assert_eq!(detached.load(Ordering::SeqCst), 0);
    assert!(
        matches!(
            fx.cache
                .get(key(1), false, now(), minter(&endpoint), &detach),
            CredGet::Wait(_)
        ),
        "nothing was published"
    );
}

#[tokio::test(start_paused = true)]
async fn an_answer_with_no_lifetime_is_shared_never_published_and_rate_floored() {
    let fx = Fixture::new(CredPolicy::DEFAULT);
    let endpoint = Endpoint::new(&[Reply::Token("tok-0", 0)], Duration::ZERO);
    let detached = Arc::new(AtomicUsize::new(0));
    let detach = detacher(&endpoint, &detached);
    let started = now();
    for _ in 0..3 {
        let answer = settled(
            fx.cache
                .get(key(1), false, now(), minter(&endpoint), &detach),
        )
        .await;
        assert_eq!(token(&answer.expect("a token")), b"tok-0");
    }
    assert_eq!(endpoint.fetches(), 3);
    assert!(
        now().duration_since(started) >= Duration::from_secs(10),
        "each later mint waited out min_mint_interval_s"
    );
    assert_eq!(fx.audits(CredEvent::NoLifetime), 1);
}

#[tokio::test(start_paused = true)]
async fn the_cap_evicts_the_least_recent_idle_key_and_refuses_busy_when_all_mint() {
    let policy = CredPolicy {
        max_keys_per_instance: 4,
        ..CredPolicy::DEFAULT
    };
    let fx = Fixture::new(policy);
    let endpoint = Endpoint::new(&[Reply::Token("tok", 600)], Duration::ZERO);
    let detached = Arc::new(AtomicUsize::new(0));
    let detach = detacher(&endpoint, &detached);
    for scope in 1..=4 {
        settled(
            fx.cache
                .get(key(scope), false, now(), minter(&endpoint), &detach),
        )
        .await
        .expect("minted");
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    for scope in 2..=4 {
        ready(
            fx.cache
                .get(key(scope), false, now(), minter(&endpoint), &detach),
        )
        .expect("hit");
    }
    settled(
        fx.cache
            .get(key(5), false, now(), minter(&endpoint), &detach),
    )
    .await
    .expect("a fifth scope fits");
    assert!(
        matches!(
            fx.cache
                .get(key(1), false, now(), minter(&endpoint), &detach),
            CredGet::Wait(_)
        ),
        "scope 1 was the least recently used"
    );

    let busy = Fixture::new(policy);
    let hung = Endpoint::new(&[Reply::Token("tok", 600)], Duration::from_secs(3_600));
    let minting: Vec<_> = (1..=4)
        .map(|scope| {
            busy.cache
                .get(key(scope), false, now(), minter(&hung), &detach)
        })
        .collect();
    match busy.cache.get(key(5), false, now(), minter(&hung), &detach) {
        CredGet::Ready(Err(PortError::Failed { code, text, .. })) => {
            assert_eq!(code, F_BUSY);
            assert_eq!(&*text, "outbound credential cache full for this binding");
        }
        _ => panic!("every key minting: F_BUSY"),
    }
    drop(minting);
}

#[tokio::test(start_paused = true)]
async fn a_dropped_leader_hands_the_mint_to_a_waiter() {
    let fx = Fixture::new(CredPolicy::DEFAULT);
    let endpoint = Endpoint::new(&[Reply::Token("tok-1", 600)], Duration::ZERO);
    let detached = Arc::new(AtomicUsize::new(0));
    let detach = detacher(&endpoint, &detached);
    let leader = fx
        .cache
        .get(key(1), false, now(), minter(&endpoint), &detach);
    let waiter = fx
        .cache
        .get(key(1), false, now(), minter(&endpoint), &detach);
    drop(leader);
    let answer = settled(waiter).await.expect("the waiter led");
    assert_eq!(token(&answer), b"tok-1");
    assert_eq!(endpoint.fetches(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_refusal_reaches_the_waiters_and_opens_no_window() {
    let fx = Fixture::new(CredPolicy::DEFAULT);
    let endpoint = Endpoint::new(
        &[Reply::Refuse, Reply::Token("tok-1", 600)],
        Duration::from_millis(5),
    );
    let detached = Arc::new(AtomicUsize::new(0));
    let detach = detacher(&endpoint, &detached);
    let leader = settled(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
    );
    let waiter = settled(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
    );
    let (led, waited) = futures::join!(leader, waiter);
    assert!(matches!(led, Err(PortError::Refused { .. })));
    assert!(matches!(waited, Err(PortError::Refused { .. })));
    assert_eq!(endpoint.fetches(), 1);
    assert_eq!(fx.audits(CredEvent::Backoff), 0);
    let next = settled(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
    )
    .await;
    assert_eq!(token(&next.expect("minted after the floor")), b"tok-1");
}

#[tokio::test(start_paused = true)]
async fn evicting_the_instance_aborts_its_detached_mint_and_publishes_nothing() {
    let fx = Fixture::new(CredPolicy::DEFAULT);
    let endpoint = Endpoint::new(
        &[Reply::Token("tok-1", 600), Reply::Token("tok-2", 600)],
        Duration::from_secs(25),
    );
    let detached = Arc::new(AtomicUsize::new(0));
    let detach = detacher(&endpoint, &detached);
    settled(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
    )
    .await
    .expect("minted");
    tokio::time::advance(Duration::from_secs(301)).await;
    ready(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
    )
    .expect("old token");
    assert_eq!(detached.load(Ordering::SeqCst), 1);
    fx.cache.evict_instance(7);
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(matches!(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
        CredGet::Wait(_)
    ));
}

#[tokio::test(start_paused = true)]
async fn no_value_is_held_past_max_hold_s() {
    let fx = Fixture::new(CredPolicy::DEFAULT);
    let endpoint = Endpoint::new(
        &[
            Reply::Token("tok-1", 315_360_000),
            Reply::Token("tok-2", 315_360_000),
        ],
        Duration::ZERO,
    );
    let detached = Arc::new(AtomicUsize::new(0));
    let detach = detacher(&endpoint, &detached);
    settled(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
    )
    .await
    .expect("minted");
    tokio::time::advance(Duration::from_secs(86_400 - 301)).await;
    ready(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
    )
    .expect("fresh");
    assert_eq!(detached.load(Ordering::SeqCst), 0);
    tokio::time::advance(Duration::from_secs(2)).await;
    ready(
        fx.cache
            .get(key(1), false, now(), minter(&endpoint), &detach),
    )
    .expect("old, refreshing");
    assert_eq!(
        detached.load(Ordering::SeqCst),
        1,
        "re-minted at max_hold_s - refresh_ahead_s"
    );
}

#[test]
fn the_policy_ranges_are_core_text_refusals() {
    assert_eq!(CredPolicy::DEFAULT.checked(), Ok(CredPolicy::DEFAULT));
    assert_eq!(CredPolicy::default(), CredPolicy::DEFAULT);
    for bad in [
        CredPolicy {
            refresh_ahead_s: 3_601,
            ..CredPolicy::DEFAULT
        },
        CredPolicy {
            min_mint_interval_s: 0,
            ..CredPolicy::DEFAULT
        },
        CredPolicy {
            mint_deadline_s: 121,
            ..CredPolicy::DEFAULT
        },
        CredPolicy {
            max_keys_per_instance: 0,
            ..CredPolicy::DEFAULT
        },
        CredPolicy {
            max_hold_s: 59,
            ..CredPolicy::DEFAULT
        },
    ] {
        assert!(bad.checked().is_err(), "{bad:?}");
    }
}
