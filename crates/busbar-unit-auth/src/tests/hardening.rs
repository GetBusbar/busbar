// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The parts of the unit the ported suite never watched.
//!
//! Every test here was written because a deliberate change to production code — the wrong
//! comparison in the cache's bound, a boolean accessor pinned to `true`, a conjunction turned into a
//! disjunction — left the existing suite entirely green. Each one names the specific change it
//! refuses, so the property is on record rather than left to be inferred from a passing run.

use super::{entry, test_digest, Canned, Headers};
use crate::cache::CredentialCache;
use crate::chain::{AuthChain, ChainVerdict};
use crate::challenge::{Challenge, ChallengeBounds};
use crate::module::AuthOutcome;
use crate::principal::Principal;

/// `CredentialCache::MAX_ENTRIES`. Private to the cache module, so it is spelled here; the tests
/// below assert against the bound rather than merely against "some" bound, so a change to the
/// constant that is not mirrored here fails loudly instead of silently weakening the test.
const MAX_ENTRIES: usize = 4096;

/// A principal whose cached identification lives `ttl` seconds.
fn ttl_principal(id: &str, ttl: u64) -> AuthOutcome {
    AuthOutcome::Identify(Principal {
        id: id.to_string(),
        name: None,
        roles: Vec::new(),
        ttl_secs: Some(ttl),
    })
}

// ---------------------------------------------------------------------------------------------
// The cache bound.
// ---------------------------------------------------------------------------------------------

/// The cache is BOUNDED, and when it is full of live rows the row that leaves is the oldest
/// INSERTED — not an arbitrary one.
///
/// The bound and the ordering are two separate facts and the suite watched neither. A cache whose
/// bound never fires is an unbounded map an unauthenticated caller drives the size of; a cache whose
/// eviction order is arbitrary because every row shares one sequence number evicts a real identity
/// while a row inserted a moment ago survives, which is the same denial-of-identity the buffered-pass
/// rule exists to prevent.
#[test]
fn a_full_cache_evicts_the_oldest_inserted_row_and_never_grows_past_its_bound() {
    let cache = CredentialCache::new(test_digest);
    let now = 1000u64;
    let live = ttl_principal("alice", 300);

    for i in 0..MAX_ENTRIES {
        cache.put("m", &format!("c{i}"), &live, now, cache.generation());
    }
    assert_eq!(cache.len(), MAX_ENTRIES, "the cache filled to its bound");

    // Eight more, each of which must displace exactly one row.
    const EXTRA: usize = 8;
    for i in MAX_ENTRIES..MAX_ENTRIES + EXTRA {
        cache.put("m", &format!("c{i}"), &live, now, cache.generation());
    }
    assert_eq!(
        cache.len(),
        MAX_ENTRIES,
        "the cache is bounded: inserting past the bound displaces, it does not grow"
    );

    for i in 0..EXTRA {
        assert!(
            cache.get("m", &format!("c{i}"), now).is_none(),
            "c{i} was among the oldest inserted and must have been the row evicted"
        );
    }
    for i in EXTRA..MAX_ENTRIES + EXTRA {
        assert!(
            cache.get("m", &format!("c{i}"), now).is_some(),
            "c{i} was inserted after the evicted rows and must have survived"
        );
    }
}

/// At capacity the cache SWEEPS EXPIRED ROWS FIRST, and a row is expired the moment its own expiry
/// is reached — not one second later.
///
/// The sweep predicate is the same `expires_at > now` liveness test `get` uses, and the two must
/// agree: a row `get` already refuses to serve must not be a row the sweep keeps and then evicts a
/// LIVE row to make room for. An off-by-one in the wrong direction here turns "the cache drops what
/// has expired" into "the cache drops what has not", which is the eviction of a valid identity in
/// favour of a dead one.
#[test]
fn a_full_cache_sweeps_every_row_whose_expiry_has_been_reached_before_it_evicts_a_live_one() {
    let now = 1000u64;
    // Zero-second lifetimes: `expires_at == now` exactly. First, that this is what `get` already
    // calls expired — the fact the sweep below has to agree with. On its own cache, because a `get`
    // that misses removes the row it looked at, and the cache under test must stay exactly full.
    let instant = ttl_principal("alice", 0);
    let probe = CredentialCache::new(test_digest);
    probe.put("m", "c", &instant, now, probe.generation());
    assert!(
        probe.get("m", "c", now).is_none(),
        "a row whose expiry has been reached is not served"
    );

    let cache = CredentialCache::new(test_digest);
    for i in 0..MAX_ENTRIES {
        cache.put("m", &format!("c{i}"), &instant, now, cache.generation());
    }
    assert_eq!(cache.len(), MAX_ENTRIES, "the cache filled to its bound");

    // One more insert at the same instant. Every existing row has reached its expiry, so the sweep
    // clears all of them and nothing live is evicted to make room.
    let live = ttl_principal("bob", 300);
    cache.put("m", "fresh", &live, now, cache.generation());
    assert_eq!(
        cache.len(),
        1,
        "the sweep drops every row already past its expiry, leaving only the new one"
    );
    assert!(cache.get("m", "fresh", now).is_some());
}

// ---------------------------------------------------------------------------------------------
// The flush generation, on the per-module flush.
// ---------------------------------------------------------------------------------------------

/// A PER-MODULE flush bumps the generation too, so an authentication already in flight when the
/// operator flushed cannot re-insert its pre-flush verdict.
///
/// The suite pinned this for `flush_all` only. The two flushes are separate lines of code and the
/// per-module one is the one an operator reaches for first — "revoke this provider's cached
/// verdicts" — so a bump missing from it is the revocation an operator most expects to work
/// silently failing for up to a full identification lifetime.
#[test]
fn a_per_module_flush_also_drops_an_insert_that_predates_it() {
    let cache = CredentialCache::new(test_digest);
    let g = cache.generation();
    cache.flush_module("m");
    cache.put(
        "m",
        "cred",
        &AuthOutcome::Identify(Principal::from_id("a")),
        1000,
        g,
    );
    assert!(
        cache.is_empty(),
        "a verdict computed before a per-module flush must not be inserted after it"
    );
}

/// `flush_module` drops ITS OWN module's rows and keeps every other module's.
///
/// The existing count assertions are symmetric — one row each way, so dropping exactly the wrong set
/// produces exactly the same counts. What survives has to be named.
#[test]
fn flush_module_drops_its_own_rows_and_the_survivor_is_the_other_modules() {
    let cache = CredentialCache::new(test_digest);
    cache.put("m1", "a", &AuthOutcome::Pass, 1000, cache.generation());
    cache.put("m2", "b", &AuthOutcome::Pass, 1000, cache.generation());

    assert_eq!(cache.flush_module("m1"), 1);
    assert!(
        cache.get("m1", "a", 1000).is_none(),
        "the flushed module's row is gone"
    );
    assert!(
        cache.get("m2", "b", 1000).is_some(),
        "another module's row is untouched by a flush that did not name it"
    );
}

// ---------------------------------------------------------------------------------------------
// The chain's own accessors and its cacheability gate.
// ---------------------------------------------------------------------------------------------

/// The two chain-shape accessors answer about the chain they were built over, in BOTH directions.
///
/// Read only in the affirmative, each is satisfied by a constant `true`; a caller deciding whether
/// to run the keys arm, or an operator report saying whether a chain has modules, would then get the
/// same answer for every chain that was ever configured.
#[test]
fn the_chain_shape_accessors_answer_in_both_directions() {
    let with_module = AuthChain::new(
        vec![entry("m", Box::new(Canned::new("m", AuthOutcome::Pass)))],
        false,
    );
    assert!(
        !with_module.has_no_modules(),
        "a chain with a module does not report an empty module list"
    );
    assert!(
        !with_module.keys_in_chain(),
        "a chain that did not name the keys arm does not report it"
    );
    assert!(!with_module.is_open(), "a chain with a module is not open");

    let keys_only = AuthChain::new(Vec::new(), true);
    assert!(
        keys_only.has_no_modules(),
        "the keys arm is not a boxed module, so a keys-only chain has none"
    );
    assert!(keys_only.keys_in_chain());
    assert!(
        !keys_only.is_open(),
        "the arm keeps the door shut even with an empty module list"
    );

    let empty = AuthChain::new(Vec::new(), false);
    assert!(empty.has_no_modules());
    assert!(!empty.keys_in_chain());
    assert!(empty.is_open());
}

/// The chain's `Debug` reports the two facts it says it reports, and never the modules themselves.
///
/// It is hand-written precisely so a boxed module cannot print whatever it likes into an operator's
/// log; a rendering that quietly produced nothing would take the two facts with it.
#[test]
fn the_chains_debug_rendering_carries_the_shape_it_promises() {
    let c = AuthChain::new(
        vec![
            entry("m1", Box::new(Canned::new("m1", AuthOutcome::Pass))),
            entry("m2", Box::new(Canned::new("m2", AuthOutcome::Pass))),
        ],
        true,
    );
    let rendered = format!("{c:?}");
    assert!(rendered.contains("AuthChain"), "{rendered}");
    assert!(rendered.contains("keys_in_chain"), "{rendered}");
    assert!(rendered.contains("true"), "{rendered}");
    assert!(rendered.contains("chain_len"), "{rendered}");
    assert!(rendered.contains('2'), "{rendered}");
}

/// A module that is NOT cacheable has no verdict written to the cache — not even the buffered `Pass`
/// a later identification commits.
///
/// `cacheable` defaults to false because a verifier whose revocation posture nobody in this crate
/// knows must be re-consulted every request. Buffering that module's `Pass` anyway and committing it
/// when a LATER module identifies would cache exactly the verdict the module refused to have cached,
/// and the next request would skip it for as long as the row lived.
#[test]
fn a_non_cacheable_modules_pass_is_never_committed_even_when_the_chain_identifies() {
    let cache = CredentialCache::new(test_digest);
    let opaque = Canned::new("opaque", AuthOutcome::Pass); // cacheable == false
    let calls = opaque.calls.clone();
    let c = AuthChain::new(
        vec![
            entry("opaque", Box::new(opaque)),
            entry(
                "idp",
                Box::new(Canned::cacheable(
                    "idp",
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
    assert!(
        cache.get("opaque", "cred", 1000).is_none(),
        "a module that declined caching has no row, however the chain ended"
    );
    assert!(
        cache.get("idp", "cred", 1000).is_some(),
        "the cacheable module that identified does have one"
    );

    // And the proof that matters to the module: it is consulted again on the next request.
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    let _ = c.run_chain_cached(Some("cred"), Some(&cache), None, 1000, None);
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "a non-cacheable module is re-consulted on every request"
    );
}

// ---------------------------------------------------------------------------------------------
// The challenge budget.
// ---------------------------------------------------------------------------------------------

/// Each round of an exchange spends exactly the bytes it carried, and exactly one round.
///
/// The byte budget is the bound on how much an unauthenticated party may be talked to. The suite
/// watched the refusals at the edges — no rounds left, a round too large — but never that a round
/// that IS accepted debits the budget by what it actually cost, so any accounting that leaves more
/// budget than it should went unnoticed, and with it the unbounded conversation the bound exists to
/// prevent.
#[test]
fn every_accepted_round_spends_its_own_bytes_and_one_round() {
    let bounds = ChallengeBounds {
        max_rounds: 4,
        max_bytes: 100,
    };
    let c = Challenge::open(vec![0u8; 10], bounds);
    assert_eq!(c.rounds_left, 3, "opening spent one round");
    assert_eq!(c.bytes_left, 90, "opening spent its own ten bytes");

    let c = c.advance(vec![0u8; 30]).expect("within budget");
    assert_eq!(c.rounds_left, 2);
    assert_eq!(c.bytes_left, 60, "90 - 30, not 90 divided by anything");
    assert_eq!(c.bytes.len(), 30, "the round's bytes are what is carried");

    let c = c.advance(vec![0u8; 55]).expect("within budget");
    assert_eq!(c.rounds_left, 1);
    assert_eq!(c.bytes_left, 5);
    assert!(!c.exhausted(), "one round and five bytes still left");

    // The next round is refused on BYTES with a round still in hand, which is only reachable
    // because the byte budget was debited honestly above.
    assert!(
        c.clone().advance(vec![0u8; 6]).is_none(),
        "six bytes do not fit in five"
    );
    let c = c.advance(vec![0u8; 5]).expect("five exactly fit");
    assert_eq!(c.bytes_left, 0);
    assert!(c.exhausted(), "the byte budget is spent");
}

// ---------------------------------------------------------------------------------------------
// The protocol ladder.
// ---------------------------------------------------------------------------------------------

/// The Bedrock invoke rung needs BOTH halves of its path shape, and a request matching only one half
/// claims no dialect at all.
///
/// The rung is the pair `/model/…` + `…/invoke`. Loosened to either half, a path that merely ends in
/// `/invoke` — an arbitrary upstream's own route — is claimed as Bedrock, and the request is then
/// parsed and billed as a dialect it never spoke.
#[test]
fn the_bedrock_invoke_rung_requires_both_halves_of_its_path() {
    let none = Headers(Vec::new());
    assert_eq!(
        crate::detect::protocol_id("/model/anthropic.claude/invoke", &none),
        Some(crate::detect::protocol::BEDROCK),
        "both halves present is the rung"
    );
    assert_eq!(
        crate::detect::protocol_id("/some/other/invoke", &none),
        None,
        "the suffix alone is not the Bedrock invoke rung"
    );
    assert_eq!(
        crate::detect::protocol_id("/model/anthropic.claude/stream", &none),
        None,
        "the prefix alone is not the Bedrock invoke rung"
    );
}
