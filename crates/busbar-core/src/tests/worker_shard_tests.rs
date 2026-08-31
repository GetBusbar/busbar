// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The worker-id → client-shard seam: a data worker indexes its OWN shard (so its pool lock is
//! never crossed by another worker), and a thread with no id keeps the round-robin fallback.
//! Tests run on plain spawned threads so each gets a fresh thread-local id slot.

#[test]
fn worker_ids_index_distinct_shards_and_unset_falls_back() {
    let clients = super::UpstreamClients::build(3, || {
        crate::proxy::build_egress_client(&crate::proxy::EgressClientSpec::llm_lane(
            1, 1, false, false,
        ))
    });
    let addr_of = |c: &crate::proxy::EgressClient| c as *const _ as usize;
    let shard_for = |id: Option<usize>| {
        let clients = clients.clone();
        std::thread::spawn(move || {
            if let Some(i) = id {
                super::set_worker_id(i);
            }
            addr_of(clients.get())
        })
        .join()
        .unwrap()
    };
    let s0 = shard_for(Some(0));
    let s1 = shard_for(Some(1));
    let s2 = shard_for(Some(2));
    assert_ne!(s0, s1, "workers 0 and 1 must not share a client shard");
    assert_ne!(s1, s2, "workers 1 and 2 must not share a client shard");
    assert_ne!(s0, s2, "workers 0 and 2 must not share a client shard");
    // Same worker id on another thread → the same shard (identity is the id, not the thread).
    assert_eq!(
        s1,
        shard_for(Some(1)),
        "a worker id must map to one stable shard"
    );
    // Out-of-range id clamps (defensive; the composition root sizes shards to the count).
    assert_eq!(
        s2,
        shard_for(Some(9)),
        "an out-of-range id clamps to the last shard"
    );
    // No id → the round-robin fallback still hands out a valid shard.
    let fallback = shard_for(None);
    assert!(
        [s0, s1, s2].contains(&fallback),
        "fallback must be one of the shards"
    );
}

/// CROSS-CRATE TOPOLOGY EQUALITY PIN: when the shard
/// count resolves through its machine-derived fallback (no composition root published a worker
/// count — this test binary's situation), the fallback arm PUBLISHES the value it computed to
/// the engine's establishment topology, so the connect gate's divisor and the pool's dial bound
/// see the same shard count core's clients use. One derivation function, no cross-crate
/// duplicate of the `min(16, next_pow2(cores))` formula — this test is the drift tripwire.
#[test]
fn shard_count_fallback_publishes_the_establishment_shard_count() {
    let shards = super::UpstreamClients::shard_count();
    assert_eq!(
        busbar_substrate::egress::engine::establishment_shards_or_one(),
        shards,
        "the engine's establishment-shard count must equal the client shard count after a \
         fallback resolution — a divergence re-opens the unpublished-topology 16x dial overrun"
    );
}
