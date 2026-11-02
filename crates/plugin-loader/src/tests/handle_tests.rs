// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

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

fn tkey() -> TicketKey {
    ticket_key().expect("the OS random source answers")
}

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
    assert_ne!(
        ticket_generation(k, 0, 0, 1),
        ticket_generation(k, 0, 1, 1),
        "two slots share a sequence"
    );
}

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

    let passed = w0
        .iter()
        .filter(|g| (1..=64).contains(&ticket_count(k, 1, 5, **g)))
        .count();
    assert!(
        passed <= 1,
        "{passed} of worker 0's generations pass as minted on worker 1"
    );
}

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
