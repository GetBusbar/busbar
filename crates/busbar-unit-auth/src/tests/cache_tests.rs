// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The credential cache's rules, and the ones about what must NOT be admitted to it.

use super::{entry, test_digest, Canned};
use crate::cache::CredentialCache;
use crate::chain::{AuthChain, ChainVerdict};
use crate::module::AuthOutcome;
use crate::principal::Principal;

#[test]
fn a_rejected_chain_admits_nothing_to_the_cache() {
    let cache = CredentialCache::new(test_digest);
    let c = AuthChain::new(
        vec![
            entry(
                "passer",
                Box::new(Canned::cacheable("p", AuthOutcome::Pass)),
            ),
            entry(
                "rejecter",
                Box::new(Canned::cacheable("r", AuthOutcome::Reject)),
            ),
        ],
        false,
    );
    assert_eq!(
        c.run_chain_cached(Some("cred"), Some(&cache), None, 1000, None),
        ChainVerdict::Denied
    );
    assert!(
        cache.is_empty(),
        "a chain that ends in a rejection commits neither the rejection nor the leading pass"
    );
}

#[test]
fn an_unauthenticated_chain_admits_nothing_to_the_cache() {
    let cache = CredentialCache::new(test_digest);
    let c = AuthChain::new(
        vec![
            entry("a", Box::new(Canned::cacheable("a", AuthOutcome::Pass))),
            entry("b", Box::new(Canned::cacheable("b", AuthOutcome::Pass))),
        ],
        false,
    );
    assert_eq!(
        c.run_chain_cached(Some("cred"), Some(&cache), None, 1000, None),
        ChainVerdict::Denied
    );
    assert!(
        cache.is_empty(),
        "an all-pass chain ends denied, so its buffered passes are never committed"
    );
}

#[test]
fn an_identified_chain_still_caches_the_leading_pass() {
    let cache = CredentialCache::new(test_digest);
    let c = AuthChain::new(
        vec![
            entry(
                "leader",
                Box::new(Canned::cacheable("a", AuthOutcome::Pass)),
            ),
            entry(
                "identifier",
                Box::new(Canned::cacheable(
                    "b",
                    AuthOutcome::Identify(Principal::from_id("alice")),
                )),
            ),
        ],
        false,
    );
    assert!(matches!(
        c.run_chain_cached(Some("cred"), Some(&cache), None, 1000, None),
        ChainVerdict::Identified { .. }
    ));
    assert_eq!(
        cache.get("leader", "cred", 1000),
        Some(AuthOutcome::Pass),
        "the leading pass is committed once the chain actually identifies"
    );
    assert!(matches!(
        cache.get("identifier", "cred", 1000),
        Some(AuthOutcome::Identify(_))
    ));
}

#[test]
fn a_cache_hit_does_not_re_consult_the_module() {
    let cache = CredentialCache::new(test_digest);
    let module = Canned::cacheable("a", AuthOutcome::Identify(Principal::from_id("alice")));
    let calls = std::sync::Arc::clone(&module.calls);
    let c = AuthChain::new(vec![entry("prov", Box::new(module))], false);
    for _ in 0..5 {
        let _ = c.run_chain_cached(Some("cred"), Some(&cache), None, 1000, None);
    }
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the module is consulted once per credential per lifetime"
    );
}

#[test]
fn identify_lifetime_is_clamped_and_defaulted() {
    let cache = CredentialCache::new(test_digest);
    let g = cache.generation();
    // No suggestion: five minutes.
    cache.put(
        "m",
        "cred-a",
        &AuthOutcome::Identify(Principal::from_id("a")),
        1000,
        g,
    );
    assert!(cache.get("m", "cred-a", 1000 + 299).is_some());
    assert!(cache.get("m", "cred-a", 1000 + 300).is_none());

    // A greedy suggestion is clamped to an hour.
    let mut greedy = Principal::from_id("b");
    greedy.ttl_secs = Some(86_400);
    let g = cache.generation();
    cache.put("m", "cred-b", &AuthOutcome::Identify(greedy), 1000, g);
    assert!(cache.get("m", "cred-b", 1000 + 3599).is_some());
    assert!(cache.get("m", "cred-b", 1000 + 3600).is_none());
}

/// The jitter is `digest(credential)[0] % 3`, so it only ever takes the values 0, 1 or 2. A test
/// that only checks a point well inside the base lifetime and a point well past the maximum jitter
/// never actually exercises the jitter arithmetic — it would pass identically whether the jitter
/// were `% 3`, always zero, or always the max. Proving it requires landing exactly on the boundary
/// FOR A CREDENTIAL WHOSE JITTER IS KNOWN, on both ends of the range: `test_digest` hex-encodes the
/// raw bytes verbatim, so `"cred"` (first byte `0x63` -> hex digit `'6'`) gives jitter 0 and a
/// credential whose first byte is `0x20` (hex digit `'2'`) gives jitter 2 — the two ends of the
/// range a flat constant or an off-by-one would get wrong in opposite directions.
#[test]
fn a_pass_lives_five_seconds_plus_a_deterministic_jitter() {
    let cache = CredentialCache::new(test_digest);

    // Zero jitter: expires at exactly base (1000 + 5 = 1005).
    let g = cache.generation();
    cache.put("m", "cred", &AuthOutcome::Pass, 1000, g);
    assert!(
        cache.get("m", "cred", 1004).is_some(),
        "still alive one second before the boundary"
    );
    assert!(
        cache.get("m", "cred", 1005).is_none(),
        "expired exactly at the base lifetime when the jitter is zero"
    );

    // Maximum jitter (2): expires at base + 2 (1000 + 7 = 1007), not at the base and not a second
    // early or late either.
    let max_jitter_credential = "\u{20}";
    let g = cache.generation();
    cache.put("m", max_jitter_credential, &AuthOutcome::Pass, 1000, g);
    assert!(
        cache.get("m", max_jitter_credential, 1006).is_some(),
        "still alive one second before the jittered boundary — the base lifetime alone would have \
         expired this two seconds early"
    );
    assert!(
        cache.get("m", max_jitter_credential, 1007).is_none(),
        "expired exactly at base plus the maximum jitter, not a second later"
    );
}

#[test]
fn a_reject_is_never_cached() {
    let cache = CredentialCache::new(test_digest);
    let g = cache.generation();
    cache.put("m", "cred", &AuthOutcome::Reject, 1000, g);
    assert!(cache.is_empty());
}

#[test]
fn a_flush_landing_mid_authentication_drops_the_insert() {
    let cache = CredentialCache::new(test_digest);
    // Captured before the module is consulted.
    let g = cache.generation();
    // The operator flushes while the verification is in flight.
    cache.flush_all();
    cache.put(
        "m",
        "cred",
        &AuthOutcome::Identify(Principal::from_id("a")),
        1000,
        g,
    );
    assert!(
        cache.is_empty(),
        "a verdict that predates a flush must not be re-inserted after it"
    );
}

#[test]
fn flush_module_counts_only_its_own_rows() {
    let cache = CredentialCache::new(test_digest);
    let g = cache.generation();
    cache.put("m1", "a", &AuthOutcome::Pass, 1000, g);
    let g = cache.generation();
    cache.put("m2", "b", &AuthOutcome::Pass, 1000, g);
    assert_eq!(cache.flush_module("m1"), 1);
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.flush_all(), 1);
    assert!(cache.is_empty());
}

/// CG-45a: the pass-TTL jitter is `digest[0] % 3`, derived from whatever digest the cache was built
/// over. This pins that the production `Sha256Digest` — 1.5.5's hex SHA-256 — produces the SAME
/// jitter `busbar_api::sha256_hex` would for a fixed credential, so swapping in the real digest
/// changes nothing about the cache's timing behaviour beyond the digest itself.
#[cfg(feature = "sha256")]
#[test]
fn sha256_digest_jitter_matches_1_5_5s_hex_sha256() {
    use crate::cache::{CredentialDigest, Sha256Digest};

    let credential = b"a-fixed-credential-for-the-jitter-pin";
    let ours = Sha256Digest.digest(credential);
    let reference = busbar_api::sha256_hex(credential);
    assert_eq!(
        ours, reference,
        "Sha256Digest must be byte-for-byte busbar_api::sha256_hex"
    );

    let jitter_from_ours = u64::from(ours.as_bytes().first().copied().unwrap_or(0) % 3);
    let jitter_from_reference = u64::from(reference.as_bytes().first().copied().unwrap_or(0) % 3);
    assert_eq!(
        jitter_from_ours, jitter_from_reference,
        "the pass-TTL jitter derived from the production digest must match 1.5.5's"
    );

    // And the cache actually observes that jitter end to end.
    let cache = CredentialCache::new(Sha256Digest);
    let g = cache.generation();
    cache.put(
        "m",
        "a-fixed-credential-for-the-jitter-pin",
        &AuthOutcome::Pass,
        1000,
        g,
    );
    let expected_ttl = 5 + jitter_from_reference;
    assert!(cache
        .get(
            "m",
            "a-fixed-credential-for-the-jitter-pin",
            1000 + expected_ttl - 1
        )
        .is_some());
    assert!(cache
        .get(
            "m",
            "a-fixed-credential-for-the-jitter-pin",
            1000 + expected_ttl
        )
        .is_none());
}

/// A cache HIT does not refresh the row's lifetime, so a credential in continuous use is still
/// re-verified against its module when its TTL runs out.
///
/// The Identify arm re-inserted on every request, hit or miss, which reset `expires_at` each time.
/// A credential used more often than its own TTL therefore never expired and never went back to
/// the module — a revocation the operator performed upstream would have been honoured only for
/// traffic that paused for longer than the TTL, which is exactly the traffic that does not matter.
/// The Pass arm alongside already only committed on a miss.
#[test]
fn a_hit_does_not_extend_the_row_and_the_module_is_consulted_again_after_the_ttl() {
    let cache = CredentialCache::new(test_digest);
    let module = Canned::cacheable(
        "idp",
        AuthOutcome::Identify(Principal {
            ttl_secs: Some(300),
            ..Principal::from_id("alice")
        }),
    );
    let calls = module.calls.clone();
    let c = AuthChain::new(vec![entry("idp", Box::new(module))], false);
    let consulted = || calls.load(std::sync::atomic::Ordering::Relaxed);

    // The miss that admits the row.
    assert!(matches!(
        c.run_chain_cached(Some("cred"), Some(&cache), None, 1_000, None),
        ChainVerdict::Identified { .. }
    ));
    assert_eq!(consulted(), 1);

    // A hit a third of the way through the row's life. The module is not consulted...
    assert!(matches!(
        c.run_chain_cached(Some("cred"), Some(&cache), None, 1_100, None),
        ChainVerdict::Identified { .. }
    ));
    assert_eq!(consulted(), 1, "a hit does not consult the module");

    // ...and the row still expires when it was always going to, not 300 seconds after the hit.
    assert!(
        cache.get("idp", "cred", 1_301).is_none(),
        "a hit must not have pushed the expiry out"
    );

    // So the credential is verified against its module again, which is what makes an upstream
    // revocation take effect within one TTL of continuous use.
    assert!(matches!(
        c.run_chain_cached(Some("cred"), Some(&cache), None, 1_400, None),
        ChainVerdict::Identified { .. }
    ));
    assert_eq!(
        consulted(),
        2,
        "the expired row sent the credential back to the module"
    );
}

#[test]
fn pass_churn_cannot_evict_an_identity() {
    let cache = CredentialCache::new(test_digest);
    // One real identity, admitted through a chain that identifies.
    let c = AuthChain::new(
        vec![entry(
            "idp",
            Box::new(Canned::cacheable(
                "idp",
                AuthOutcome::Identify(Principal::from_id("alice")),
            )),
        )],
        false,
    );
    assert!(matches!(
        c.run_chain_cached(Some("alice-cred"), Some(&cache), None, 1000, None),
        ChainVerdict::Identified { .. }
    ));
    // Now an unauthenticated prober drives thousands of distinct credentials through an all-pass
    // chain. None of them is committed, so none of them can evict the identity above.
    let passing = AuthChain::new(
        vec![entry(
            "idp",
            Box::new(Canned::cacheable("idp", AuthOutcome::Pass)),
        )],
        false,
    );
    for i in 0..6000u32 {
        let cred = format!("probe-{i}");
        assert_eq!(
            passing.run_chain_cached(Some(&cred), Some(&cache), None, 1000, None),
            ChainVerdict::Denied
        );
    }
    assert!(
        matches!(
            cache.get("idp", "alice-cred", 1000),
            Some(AuthOutcome::Identify(_))
        ),
        "unauthenticated churn admits nothing, so it can evict nothing"
    );
}
