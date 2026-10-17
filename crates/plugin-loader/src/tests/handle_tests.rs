// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The instance handle's own arithmetic and its one check (#74), each judged against a latch of the
//! test's own so no case here moves the process's. The forged context refused at the host's
//! entries is `host_services_tests::a_forged_context_is_refused_before_it_names_an_instance`; the
//! quarantine, the FAULT of the forging op and the entropy refusal at boot are `dispatch_tests`'.

use super::*;

/// The SipHash-2-4 reference vectors (Aumasson and Bernstein, `vectors.h`): key `00..0f`, message
/// `00..len-1`, for the empty, 8-byte and 16-byte messages.
#[test]
fn siphash24_is_the_reference_function() {
    let k = (0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908);
    assert_eq!(siphash24(k, &[]), 0x726f_db47_dd0e_0e31);
    assert_eq!(
        siphash24(k, &[0x0706_0504_0302_0100]),
        0x93f5_f579_9a93_2462
    );
    assert_eq!(
        siphash24(k, &[0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908]),
        0x3f2a_cc7f_57c2_9bdb
    );
}

fn leaked() -> &'static InstanceWake {
    Box::leak(Box::default())
}

/// A minted handle names its instance and no address; every handle the host did not mint names
/// none and is counted; no context is no context, and is not counted.
#[test]
fn only_a_minted_handle_names_an_instance() {
    let latch = Latch::new();
    let wake = leaked();
    let ctx = mint(wake).expect("the host mints a handle");
    assert!(std::ptr::eq(
        resolve_in(ctx, &latch, None).expect("its own instance"),
        wake
    ));
    assert_ne!(
        ctx.handle,
        std::ptr::from_ref(wake) as usize as u64,
        "the handle is not the instance's address"
    );

    assert!(resolve_in(HostCtx::NONE, &latch, None).is_none());
    assert_eq!(latch.forged(), 0, "no context is not a forgery");

    let id = ctx.handle & ID_MASK;
    let unminted = (1u64 << HANDLE_ID_BITS) - 2;
    let key = key().expect("the key");
    for (why, handle) in [
        ("one tag bit off", ctx.handle ^ (1 << HANDLE_ID_BITS)),
        ("the top tag bit off", ctx.handle ^ (1 << 63)),
        ("an id with no tag", id),
        ("a tag with no id", ctx.handle & !ID_MASK),
        (
            "a correctly tagged id the host never minted",
            (tag_of(key, unminted) << HANDLE_ID_BITS) | unminted,
        ),
        (
            "the leaked entry's own address",
            std::ptr::from_ref(wake) as usize as u64,
        ),
    ] {
        let at = latch.forged();
        assert!(
            resolve_in(HostCtx { handle }, &latch, None).is_none(),
            "{why}"
        );
        assert_eq!(latch.forged(), at + 1, "{why} was not counted");
    }
}

/// A REVOKED handle (its instance quarantined, faulted, closed or let go) names nothing, and is not
/// a forgery: its tag is the host's own.
#[test]
fn a_revoked_handle_names_nothing_and_is_no_forgery() {
    let latch = Latch::new();
    let wake = leaked();
    let ctx = mint(wake).expect("the host mints a handle");
    assert!(resolve_in(ctx, &latch, None).is_some());
    wake.revoked.store(true, Ordering::Release);
    assert!(
        resolve_in(ctx, &latch, None).is_none(),
        "a revoked handle resolved"
    );
    assert_eq!(
        latch.forged(),
        0,
        "a revoked handle was counted as a forgery"
    );
}

/// THE LATCH: off-crossing forgeries name no instance to quarantine, so they count; at
/// `LATCH_AT` every resolve outside a crossing is refused, the honest one included, while a
/// crossing's own still resolves.
#[test]
fn the_latch_trips_at_k_and_refuses_every_off_crossing_resolve() {
    let latch = Latch::new();
    let wake = leaked();
    let ctx = mint(wake).unwrap();
    let forged_ctx = HostCtx {
        handle: ctx.handle ^ (1 << HANDLE_ID_BITS),
    };
    for _ in 0..LATCH_AT - 1 {
        assert!(resolve_in(forged_ctx, &latch, None).is_none());
    }
    assert!(!latch.tripped(), "tripped before K");
    assert!(
        resolve_in(ctx, &latch, None).is_some(),
        "below K the honest handle resolves"
    );
    assert!(resolve_in(forged_ctx, &latch, None).is_none());
    assert!(latch.tripped(), "K forgeries did not trip the latch");
    assert!(
        resolve_in(ctx, &latch, None).is_none(),
        "a tripped latch let an off-crossing resolve through"
    );
    assert!(
        resolve_in(ctx, &latch, Some(wake)).is_some(),
        "a crossing's own handle is refused by the latch"
    );
}

/// The key comes from the OS random source or not at all: a source that cannot answer is a
/// refusal ([`LoadError::Entropy`]), never a fallback key.
#[test]
fn a_failing_entropy_source_is_a_refusal_not_a_weaker_key() {
    let refused = draw(|_| Err("no entropy".to_string()));
    assert!(matches!(refused, Err(LoadError::Entropy(why)) if why == "no entropy"));
    let drawn = draw(|b| {
        b.copy_from_slice(&[1; 16]);
        Ok(())
    });
    assert_eq!(
        drawn.ok(),
        Some((0x0101_0101_0101_0101, 0x0101_0101_0101_0101))
    );
}

/// THE TICKET PERMUTATION IS A BIJECTION, exhausted at a reduced width (8-bit domain, 4-bit
/// halves): every nonzero value maps to a distinct nonzero value and back, so uniqueness per slot
/// is exact, as the counter's was, under every key and tweak tried.
#[test]
fn the_ticket_permutation_is_a_bijection_of_the_nonzero_values() {
    for (key, tweak) in [
        ((1, 2), (0, 0)),
        ((0xdead_beef, 7), (3, 9)),
        ((0, 0), (1, 1)),
    ] {
        let mut seen = std::collections::BTreeSet::new();
        for x in 1u64..256 {
            let y = nonzero_permutation(key, tweak, 4, x, false);
            assert!(y != 0 && y < 256, "{x} -> {y} left the nonzero domain");
            assert!(seen.insert(y), "{x} -> {y} collides");
            assert_eq!(
                nonzero_permutation(key, tweak, 4, y, true),
                x,
                "the inverse of {y}"
            );
        }
        assert_eq!(seen.len(), 255);
    }
}

/// The dispatcher's ticket key, as a dispatcher draws it at boot.
fn tkey() -> TicketKey {
    ticket_key().expect("the OS random source answers")
}

/// UNPREDICTABLE: consecutive mints of one slot do not show their counter (no run of +1 steps, no
/// constant stride), while the inverse names each count exactly.
#[test]
fn consecutive_ticket_generations_hide_their_counter() {
    let k = tkey();
    let gens: Vec<u32> = (1..=64).map(|c| ticket_generation(k, 0, 0, c)).collect();
    for (c, g) in (1..=64).zip(&gens) {
        assert_ne!(*g, 0);
        assert_eq!(ticket_count(k, 0, 0, *g), c, "the inverse of mint {c}");
    }
    let steps: std::collections::BTreeSet<i64> = gens
        .windows(2)
        .map(|w| i64::from(w[1]) - i64::from(w[0]))
        .collect();
    assert!(
        steps.len() > 32,
        "the generations step by a few strides: {steps:?}"
    );
    assert!(!steps.contains(&1) || steps.len() > 1);
    assert_ne!(
        ticket_generation(k, 0, 0, 1),
        ticket_generation(k, 0, 1, 1),
        "two slots share a sequence"
    );
}

/// RED (#74, WORKER-TWEAK SEPARATION): the same slot index on two workers runs two unrelated
/// sequences, and a generation one worker minted inverts, on the other, to no count it reached. A
/// tweak that left the worker out would give every worker's slot `idx` one sequence: a ticket a
/// plugin held on worker 0, re-addressed to worker 1's slot, would pass there as a stale wake.
#[test]
fn red_two_workers_share_no_ticket_sequence() {
    let k = tkey();
    let w0: Vec<u32> = (1..=64).map(|c| ticket_generation(k, 0, 5, c)).collect();
    let w1: Vec<u32> = (1..=64).map(|c| ticket_generation(k, 1, 5, c)).collect();
    let same = w0.iter().zip(&w1).filter(|(a, b)| a == b).count();
    assert!(
        same <= 1,
        "worker 0 and worker 1 share slot 5's sequence at {same} of 64 mints"
    );
    // Worker 0's first 64 generations, judged on worker 1's slot 5 having reached count 64: each
    // inverts past 64 (a forgery there), but for a 64-in-2^32 chance per generation.
    let passed = w0
        .iter()
        .filter(|g| (1..=64).contains(&ticket_count(k, 1, 5, **g)))
        .count();
    assert!(
        passed <= 1,
        "{passed} of worker 0's generations pass as minted on worker 1"
    );
}

/// RED (#74, NO SUPPLIER): a forged ticket generation the host itself woke (a connector's
/// readiness: no instance supplied it) counts toward the latch; one an instance supplied
/// quarantines that instance and does NOT count toward it. Judged against this test's own latch.
#[test]
fn red_a_forged_ticket_with_no_supplier_counts_toward_the_latch() {
    let latch = Latch::new();
    forged_ticket(None, &latch);
    assert_eq!(
        (latch.forged(), latch.unattributed()),
        (1, 1),
        "a supplier-less forged ticket was not counted toward the latch"
    );
    let wake: &'static InstanceWake = Box::leak(Box::default());
    forged_ticket(Some(wake), &latch);
    assert_eq!(
        (latch.forged(), latch.unattributed()),
        (2, 1),
        "a supplied forged ticket was counted as unattributed"
    );
    // The supplied forgery above counts nothing toward the trip, so the supplier-less count is
    // still 1 here: LATCH_AT - 2 more leave it one short, and the LATCH_AT-th trips it.
    for _ in 1..LATCH_AT - 1 {
        forged_ticket(None, &latch);
    }
    assert_eq!(latch.unattributed(), LATCH_AT - 1);
    assert!(
        !latch.tripped(),
        "{} supplier-less forged tickets tripped the latch",
        LATCH_AT - 1
    );
    forged_ticket(None, &latch);
    assert!(
        latch.tripped(),
        "{LATCH_AT} supplier-less forged tickets did not trip the latch"
    );
}
