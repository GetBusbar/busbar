// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/egress_auth/bearer_token.rs`.

use super::*;

impl BearerToken {
    pub(crate) fn with_token_for_test(token: &str) -> Self {
        BearerToken {
            token: RwLock::new(Arc::new(CachedToken::new(token.to_string(), 0))),
            _alive: None,
        }
    }
}

fn ctx() -> SigningContext<'static> {
    SigningContext {
        host: "example.com",
        canonical_uri: "/x",
        body: b"{}",
        timestamp_epoch: 0,
        upstream_creds: busbar_api::UpstreamCreds::Own,
    }
}

/// The minted bearer is held `Redacted`, so a `{:?}` of the token field shows
/// `[REDACTED]`, never the token bytes — even though the pre-built header still carries them.
#[test]
fn cached_token_field_is_redacted_in_debug() {
    let c = CachedToken::new("tok-super-secret-abc".to_string(), 0);
    let dbg = format!("{:?}", c.token);
    assert_eq!(dbg, "[REDACTED]");
    assert!(!dbg.contains("tok-super-secret-abc"));
}

#[test]
fn headers_for_emits_bearer_and_ignores_key() {
    let c = BearerToken::with_token_for_test("tok-abc");
    let h = c.headers_for("ignored", &ctx());
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].0.as_str(), "authorization");
    assert_eq!(h[0].1.to_str().unwrap(), "Bearer tok-abc");
}

// The `Authorization` header value is built ONCE by `CachedToken::new` (mint time) rather than
// re-`format!`+re-validated on every `headers_for` call. Simulate the background refresh loop's
// store step directly (swap in a fresh `CachedToken`, as `refresh_loop` does via
// `*p.token.write()... = Arc::new(fresh)`) and assert
// `headers_for` picks up the newly pre-built header — proving the cache-once, clone-on-read path
// stays correct across a refresh, not just at construction.
#[test]
fn headers_for_reflects_prebuilt_header_after_a_refresh() {
    let c = BearerToken::with_token_for_test("tok-old");
    assert_eq!(
        c.headers_for("k", &ctx())[0].1.to_str().unwrap(),
        "Bearer tok-old"
    );

    *c.token.write().unwrap() = Arc::new(CachedToken::new("tok-new".to_string(), 0));

    let h = c.headers_for("k", &ctx());
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].1.to_str().unwrap(), "Bearer tok-new");
}

// `CachedToken::new` must reject-to-`None` the same bytes `HeaderValue::from_str` always rejected
// (e.g. a raw newline), so a token endpoint returning header-invalid bytes still degrades to "no
// auth header" (fail-closed, same as before this change) rather than panicking or emitting a
// malformed header.
#[test]
fn cached_token_new_omits_header_for_bytes_invalid_in_a_header_value() {
    let bad = BearerToken {
        token: RwLock::new(Arc::new(CachedToken::new(
            "tok\nwith-newline".to_string(),
            0,
        ))),
        _alive: None,
    };
    assert!(bad.headers_for("k", &ctx()).is_empty());
}

#[test]
fn headers_for_emits_nothing_before_first_mint() {
    assert!(BearerToken::with_token_for_test("")
        .headers_for("k", &ctx())
        .is_empty());
}

// The prober consults `is_ready` to SKIP an OAuth lane whose first token has not
// minted (empty token) — probing it would send no auth header and the guaranteed 401 could
// HardDown-park a healthy lane. Ready only once a non-empty token is present.
#[test]
fn is_ready_false_before_first_mint_true_after() {
    assert!(!BearerToken::with_token_for_test("").is_ready());
    assert!(BearerToken::with_token_for_test("tok").is_ready());
}

// A short-TTL token must be re-minted BEFORE it expires — the old
// `(ttl - SKEW).max(MIN_SLEEP)` floored the sleep to 30s even for a 10s token, serving it expired.
#[test]
fn next_refresh_never_sleeps_past_a_live_token_expiry() {
    let now = 1_000_000;
    // Long TTL: refresh REFRESH_SKEW early, floored at MIN_SLEEP.
    assert_eq!(next_refresh_secs(now + 3600, now), 3600 - REFRESH_SKEW_SECS);
    // Short TTL (< skew): refresh at ~half-life — strictly before expiry, NOT floored to 30s.
    assert_eq!(next_refresh_secs(now + 10, now), 5);
    assert!(
        next_refresh_secs(now + 10, now) < 10,
        "must land before the 10s expiry"
    );
    assert_eq!(next_refresh_secs(now + 60, now), 30);
    assert_eq!(next_refresh_secs(now + 1, now), 1);
    // Already-expired / garbage (ttl==0): back off MIN_SLEEP so the mint loop can't spin hot.
    assert_eq!(next_refresh_secs(now, now), MIN_SLEEP_SECS);
    assert_eq!(next_refresh_secs(now - 100, now), MIN_SLEEP_SECS);
}

/// `headers_for` runs inline on the request hot path, so a POISONED lock must be recovered,
/// not panicked over (a panic there would 500 a request because some other thread poisoned the
/// lock). Poison the RwLock by panicking while holding the write guard, then assert `headers_for`
/// still returns the Bearer (via `into_inner`). With `.expect(...)` instead of
/// `.unwrap_or_else(|e| e.into_inner())` this call panics on the poisoned lock.
#[test]
fn headers_for_recovers_from_poisoned_lock() {
    let c = Arc::new(BearerToken::with_token_for_test("tok-poison"));
    let c2 = c.clone();
    let _ = std::thread::spawn(move || {
        let _g = c2.token.write().unwrap();
        panic!("poison the lock");
    })
    .join();
    assert!(
        c.token.read().is_err(),
        "precondition: the write-guard panic must have poisoned the lock"
    );
    let h = c.headers_for("k", &ctx());
    assert_eq!(h.len(), 1, "poisoned lock must still yield the auth header");
    assert_eq!(h[0].1.to_str().unwrap(), "Bearer tok-poison");
}

/// `now_epoch()` returns the REAL current unix time, not a stub. A mutant collapsing the body
/// to `0` would silently make `next_refresh_secs`'s "how long until expiry" math always see
/// 1970, i.e. every token permanently "already expired" — bracket against a wall-clock read
/// taken immediately before/after the call so this stays robust to real (sub-second) timing.
#[test]
fn now_epoch_returns_the_real_current_time() {
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let got = now_epoch();
    let after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        got >= before && got <= after,
        "now_epoch() = {got}, expected within [{before}, {after}]"
    );
}

/// A LANE THAT IS RELOADED AWAY TAKES ITS REFRESHER WITH IT. The wait between mints is most of a
/// token lifetime, and the provider check used to happen only after it — so a dropped lane kept a
/// task alive for the rest of that lifetime and then minted one more token, a real request to the
/// operator's token endpoint on behalf of a lane that no longer exists. The refresher holds the only
/// other reference to the minter, so its own death is what this reads.
#[tokio::test]
async fn dropping_the_provider_ends_its_refresher() {
    let minter: Minter = Arc::new(|| {
        // A long-lived token: the refresher settles into a wait measured in most of an hour.
        Box::pin(async { Ok(CachedToken::new("tok-live".to_string(), now_epoch() + 3600)) })
            as MintFuture
    });
    let refresher_holds = Arc::downgrade(&minter);
    let provider = spawn(minter);

    // Let the first mint land, so the task is in its wait and not mid-request.
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if provider.is_ready() {
            break;
        }
    }
    assert!(provider.is_ready(), "the refresher minted its first token");

    drop(provider);
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if refresher_holds.upgrade().is_none() {
            break;
        }
    }
    assert!(
        refresher_holds.upgrade().is_none(),
        "the refresher ended with the lane instead of waiting out the token lifetime"
    );
}
