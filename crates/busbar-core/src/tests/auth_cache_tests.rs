// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/auth_cache.rs`.

use super::*;

fn ident(ttl: Option<u64>) -> AuthOutcome {
    let mut p = Principal::from_id("u1");
    p.ttl_secs = ttl;
    AuthOutcome::Identify(p)
}

/// The verdict rules: Identify cached (module TTL clamped), Pass cached short,
/// Reject NEVER cached; expiry is a miss.
#[test]
fn verdict_rules_and_expiry() {
    let c = CredentialCache::new();
    let t = 1_000_000;

    c.put("m", "cred-a", &ident(None), t, c.generation());
    assert!(matches!(
        c.get("m", "cred-a", t + DEFAULT_IDENTIFY_TTL_SECS - 1),
        Some(AuthOutcome::Identify(_))
    ));
    assert!(
        c.get("m", "cred-a", t + DEFAULT_IDENTIFY_TTL_SECS + 1)
            .is_none(),
        "expired Identify is a miss"
    );

    // Module-suggested TTL is CLAMPED to the hard cap.
    c.put("m", "cred-b", &ident(Some(999_999)), t, c.generation());
    assert!(
        c.get("m", "cred-b", t + MAX_IDENTIFY_TTL_SECS + 1)
            .is_none(),
        "a module cannot exceed the hard TTL cap"
    );

    // Pass cached briefly (base + ≤2s jitter)…
    c.put("m", "cred-c", &AuthOutcome::Pass, t, c.generation());
    assert!(matches!(
        c.get("m", "cred-c", t + 1),
        Some(AuthOutcome::Pass)
    ));
    assert!(c.get("m", "cred-c", t + PASS_TTL_SECS + 3).is_none());

    // …and Reject NEVER lands.
    c.put("m", "cred-d", &AuthOutcome::Reject, t, c.generation());
    assert!(
        c.get("m", "cred-d", t + 1).is_none(),
        "Reject is never cached"
    );
}

/// Partitions are per-module: same credential under two modules is two entries, and a module
/// flush drops exactly its own.
#[test]
fn module_partitions_and_flush() {
    let c = CredentialCache::new();
    let t = 1_000_000;
    c.put("m1", "cred", &ident(None), t, c.generation());
    c.put("m2", "cred", &ident(None), t, c.generation());
    assert_eq!(c.flush_module("m1"), 1);
    assert!(c.get("m1", "cred", t + 1).is_none());
    assert!(
        c.get("m2", "cred", t + 1).is_some(),
        "other partitions untouched"
    );
    assert_eq!(c.flush_all(), 1);
    assert!(c.get("m2", "cred", t + 1).is_none());
}

/// The bound holds: at capacity the oldest-inserted live entry is evicted, never unbounded
/// growth.
#[test]
fn bounded_eviction() {
    let c = CredentialCache::new();
    let t = 1_000_000;
    for i in 0..MAX_ENTRIES {
        c.put(
            "m",
            &format!("cred-{i}"),
            &ident(Some(3600)),
            t,
            c.generation(),
        );
    }
    c.put("m", "one-more", &ident(Some(3600)), t, c.generation());
    let guard = c.lock();
    assert!(
        guard.entries.len() <= MAX_ENTRIES,
        "cap held: {}",
        guard.entries.len()
    );
    drop(guard);
    assert!(
        c.get("m", "cred-0", t + 1).is_none(),
        "the oldest-inserted entry was the eviction victim"
    );
    assert!(c.get("m", "one-more", t + 1).is_some());
}

/// An authentication IN FLIGHT across a flush cannot re-insert its PRE-flush allow verdict.
///
/// This is the exact interleaving `POST /api/v1/admin/auth/cache/flush` promised to close and
/// did not: the module is consulted (a JWKS round-trip — seconds, not microseconds), the
/// operator flushes, the flush returns `200 {"flushed": N}` — and then the in-flight request's
/// `put` lands, restoring the allow for up to `MAX_IDENTIFY_TTL_SECS` (an hour). The endpoint
/// reported a revocation that had not happened.
#[test]
fn a_flush_cannot_be_undone_by_an_authentication_already_in_flight() {
    let c = CredentialCache::new();
    let t = 1_000_000;

    // A request begins: capture the generation, THEN consult the (slow) module.
    let in_flight = c.generation();
    // Meanwhile the operator revokes: flush_all clears everything and closes the window.
    c.put("oidc", "seed", &ident(Some(3600)), t, c.generation());
    assert_eq!(c.flush_all(), 1, "the flush reports what it dropped");
    // …and only NOW does the in-flight authentication come back with its stale allow verdict.
    c.put("oidc", "victim", &ident(Some(3600)), t, in_flight);

    assert!(
        c.get("oidc", "victim", t + 1).is_none(),
        "a verdict computed BEFORE the flush must not land AFTER it — that is the entire \
             cached-allow window the flush endpoint exists to close"
    );

    // A FRESH authentication (generation captured after the flush) caches normally: the guard
    // closes the revocation window, it does not disable the cache.
    let fresh = c.generation();
    c.put("oidc", "victim", &ident(Some(3600)), t, fresh);
    assert!(
        c.get("oidc", "victim", t + 1).is_some(),
        "post-flush authentications must still populate the cache"
    );

    // A per-MODULE flush closes the same window (the generation is global on purpose).
    let in_flight2 = c.generation();
    c.flush_module("oidc");
    c.put("oidc", "victim2", &ident(Some(3600)), t, in_flight2);
    assert!(
        c.get("oidc", "victim2", t + 1).is_none(),
        "flush_module must also invalidate in-flight verdicts"
    );
}
