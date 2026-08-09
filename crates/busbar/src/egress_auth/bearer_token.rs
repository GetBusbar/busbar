// SPDX-License-Identifier: Apache-2.0
//! Shared machinery for self-minting, auto-refreshing **bearer-token** egress credentials.
//!
//! Both OAuth mechanisms busbar ships — `jwt-bearer` (RFC 7523) and `oauth-client-credentials`
//! (RFC 6749 §4.4) — obtain a short-lived bearer from a token endpoint and attach it as
//! `Authorization: Bearer <token>`. They differ ONLY in how a token is minted (sign a JWT vs. POST
//! client credentials). This module owns everything else: the cached token, the `headers_for`
//! read, and the background refresh loop. A mechanism supplies a [`Minter`] closure and gets a ready
//! [`CredentialProvider`] back.
//!
//! [`CredentialProvider::headers_for`] is SYNCHRONOUS and runs inline on the hot path, so minting (an
//! async round-trip) happens in a background task, not there. The task holds a `Weak` to the provider,
//! so a config reload that drops the lane also stops its refresher (no task leak).

use super::CredentialProvider;
use crate::proto::SigningContext;
use axum::http::{HeaderName, HeaderValue};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Refresh this many seconds BEFORE the token's stated expiry, so a request never races an expired
/// token across the refresh boundary.
const REFRESH_SKEW_SECS: u64 = 300;
/// Floor on the refresh sleep so a short-lived / already-near-expiry token can't spin the loop hot,
/// and the retry delay after a mint failure.
const MIN_SLEEP_SECS: u64 = 30;

/// A minted access token and the wall-clock epoch second it expires at.
pub(crate) struct CachedToken {
    /// The minted bearer, held [`busbar_api::Redacted`] so it never leaks via `Debug`/logs and
    /// zeroizes on drop. The pre-built `header` below carries the same bytes for the hot path.
    pub(crate) token: busbar_api::Redacted<String>,
    pub(crate) expires_at: u64,
    /// The `Authorization: Bearer <token>` header value, pre-built ONCE here (at mint time) rather
    /// than on every `headers_for` call — `headers_for` runs inline on the egress hot path for every
    /// outbound request, while a token only changes on the background refresh loop (roughly hourly),
    /// so re-`format!`ing and re-validating the same bytes per request was pure waste. `None` when
    /// `token` is empty (the pre-first-mint sentinel) or contains bytes invalid for an HTTP header
    /// value — both cases mean "emit no auth header",
    /// exactly as before.
    header: Option<HeaderValue>,
}

impl CachedToken {
    /// Construct a `CachedToken`, building its `header` once here so no caller has to remember to.
    pub(crate) fn new(token: String, expires_at: u64) -> Self {
        let header = if token.is_empty() {
            None
        } else {
            match HeaderValue::from_str(&format!("Bearer {token}")) {
                Ok(v) => Some(v),
                Err(_) => {
                    tracing::warn!(
                        "minted an OAuth token with bytes invalid for an HTTP header value; omitting \
                         the auth header — upstream will reject with 401"
                    );
                    None
                }
            }
        };
        Self {
            token: busbar_api::Redacted::new(token),
            expires_at,
            header,
        }
    }
}

/// The future a [`Minter`] returns — a fresh token or a human-readable error.
pub(crate) type MintFuture = Pin<Box<dyn Future<Output = Result<CachedToken, String>> + Send>>;
/// A mechanism's "get me a fresh token" hook. Called on entry and before each expiry.
pub(crate) type Minter = Arc<dyn Fn() -> MintFuture + Send + Sync>;
/// The boot-path return shape shared by the OAuth `build` functions and `egress_auth::resolve`.
pub(crate) type CredentialProviderArc = Arc<dyn CredentialProvider>;

/// A bearer credential backed by a background-refreshed cached token.
pub(crate) struct BearerToken {
    token: RwLock<Arc<CachedToken>>,
}

impl CredentialProvider for BearerToken {
    fn headers_for(&self, _key: &str, _ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        // A self-minting credential ignores the per-request `key`. Read the current cached token; if
        // it is empty (the boot window before the first mint) or un-encodable, emit NO auth header
        // (upstream 401 — the same fail-closed shape as an un-encodable static key). The header value
        // was already built once, at mint time, by `CachedToken::new` — clone it (cheap: `HeaderValue`
        // wraps refcounted bytes) rather than re-`format!`+re-validate on every request.
        // Recover from a poisoned lock rather than panic: the guarded value is always a valid
        // `Arc<CachedToken>`, and this runs inline on the request hot path — a panic here would 500 a
        // request over a lock another thread poisoned. (The critical sections are a trivial Arc clone
        // and an Arc assignment, neither of which can panic, so poisoning is effectively unreachable.)
        let cached = self.token.read().unwrap_or_else(|e| e.into_inner()).clone();
        match &cached.header {
            Some(v) => vec![(HeaderName::from_static("authorization"), v.clone())],
            None => Vec::new(),
        }
    }

    /// Ready once the first mint has populated a non-empty token. Before that (the boot/reload window)
    /// `headers_for` emits no auth header, so the prober skips this lane rather than 401-parking it.
    fn is_ready(&self) -> bool {
        !self
            .token
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .token
            .expose_secret()
            .is_empty()
    }
}

/// Build a bearer credential from a [`Minter`]: start with an empty token and spawn the background
/// refresher (which mints immediately and re-mints before expiry). When no tokio runtime is present
/// (e.g. a sync construction test) the refresher is skipped and the credential simply holds no token.
pub(crate) fn spawn(minter: Minter) -> CredentialProviderArc {
    let provider = Arc::new(BearerToken {
        token: RwLock::new(Arc::new(CachedToken::new(String::new(), 0))),
    });
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let weak = Arc::downgrade(&provider);
        handle.spawn(async move { refresh_loop(minter, weak).await });
    }
    provider
}

/// Seconds to sleep before the next re-mint, given a token that expires at `expires_at` (epoch secs).
///
/// Refresh `REFRESH_SKEW_SECS` BEFORE expiry for a normally-lived token so a request never races the
/// expiry boundary. But that skew cannot be honored for a SHORT-TTL token: the old
/// `(ttl - SKEW).max(MIN_SLEEP)` floored the sleep back up to `MIN_SLEEP_SECS` (30s) even for a token
/// that expired in, say, 10s — so `headers_for` served an EXPIRED bearer for ~20s and the upstream 401'd.
/// Instead:
///   - `ttl == 0` (already expired / garbage `expires_in ≈ 0`): back off `MIN_SLEEP_SECS` so the mint
///     loop cannot spin hot — nothing useful to serve, fail safe.
///   - `ttl <= REFRESH_SKEW_SECS` (too short to refresh a full skew early): re-mint at ~half the
///     remaining life, so the refresh always lands BEFORE expiry (never past `ttl`), and never below 1s.
///   - otherwise: the normal `ttl - REFRESH_SKEW_SECS`, with `MIN_SLEEP_SECS` as a hot-loop floor near
///     the skew boundary.
///
/// Guarantees: for any `ttl > 0` the next mint is scheduled strictly before expiry (no expired token is
/// served); for `ttl == 0` the loop is rate-limited to `MIN_SLEEP_SECS`.
fn next_refresh_secs(expires_at: u64, now: u64) -> u64 {
    let ttl = expires_at.saturating_sub(now);
    if ttl == 0 {
        MIN_SLEEP_SECS
    } else if ttl <= REFRESH_SKEW_SECS {
        (ttl / 2).max(1)
    } else {
        (ttl - REFRESH_SKEW_SECS).max(MIN_SLEEP_SECS)
    }
}

/// Mint (immediately on entry), store, then sleep until shortly before expiry and repeat. Exits when
/// the provider is dropped (config reload) so the task never outlives its lane.
async fn refresh_loop(minter: Minter, weak: Weak<BearerToken>) {
    loop {
        match minter().await {
            // A 200 with an EMPTY access_token must be treated as a (retryable) failure, not stored:
            // an empty token collides with the pre-first-mint sentinel, so `is_ready()` would stay false
            // forever (the prober skips the lane permanently) AND `headers_for` would emit no auth header
            // (organic traffic 401s forever) — a permanent wedge with no self-healing. Retry at
            // MIN_SLEEP instead, exactly like a mint error.
            Ok(fresh) if fresh.token.expose_secret().is_empty() => {
                tracing::warn!(
                    "OAuth token endpoint returned a 200 with an empty access_token; treating as a \
                     mint failure and will retry"
                );
                if weak.upgrade().is_none() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(MIN_SLEEP_SECS)).await;
            }
            Ok(fresh) => {
                let expires_at = fresh.expires_at;
                match weak.upgrade() {
                    Some(p) => {
                        *p.token.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(fresh)
                    }
                    None => return, // provider dropped — stop refreshing
                }
                let sleep_secs = next_refresh_secs(expires_at, now_epoch());
                tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
            }
            Err(e) => {
                // Keep serving whatever token is current; retry soon. If retries keep failing past
                // expiry, `headers_for` emits a stale/empty token → upstream 401, classified like any
                // auth failure by the breaker.
                tracing::warn!(error = %e, "OAuth token mint failed; will retry");
                if weak.upgrade().is_none() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(MIN_SLEEP_SECS)).await;
            }
        }
    }
}

pub(crate) fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "tests/bearer_token_tests.rs"]
mod tests;
