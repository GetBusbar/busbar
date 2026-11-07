// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::facade::CoreStore;
use busbar_contract::records::UsageDelta;
fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
    futures::executor::block_on(future)
}

fn cells() -> [(&'static str, u64, UsageDelta); 1] {
    [(
        "k",
        60,
        UsageDelta {
            requests: 1,
            billable_requests: 1,
            models: Vec::new(),
        },
    )]
}

fn write(store: &CoreStore, op: busbar_contract::records::OpId, why: &str) {
    ready(store.ledger().add_usage_batch_deduped(op, &cells())).expect(why);
}

#[test]
fn two_boots_never_mint_an_equal_op_id_even_at_counter_one() {
    let (before, after) = (OpIds::boot(boot_node()), OpIds::boot(boot_node()));
    let (a, b) = (before.mint(), after.mint());
    assert_ne!(a, b, "counter 1 of two boots is two ids");
    for _ in 0..1000 {
        assert_ne!(before.mint(), after.mint());
    }
}

#[test]
fn the_process_mint_is_one_counter() {
    let (a, b) = (op_id(), op_id());
    assert_ne!(a, b);
    assert_eq!(a.0[..8], b.0[..8], "one node half per process");
}

#[test]
fn exhausted_identity_counters_never_wrap_or_resume_after_a_caught_panic() {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

    let ops = OpIds {
        node: 7,
        counter: AtomicU64::new(u64::MAX - 1),
    };
    assert_eq!(
        ops.mint(),
        busbar_contract::records::OpId::from_parts(7, u64::MAX)
    );
    for _ in 0..2 {
        assert!(std::panic::catch_unwind(|| ops.mint()).is_err());
        assert_eq!(ops.counter.load(Relaxed), u64::MAX);
    }

    let units = UnitKeyMint(AtomicU64::new(u64::MAX - 1));
    assert_eq!(units.mint(), busbar_contract::ids::UnitKey::new(u64::MAX));
    for _ in 0..2 {
        assert!(std::panic::catch_unwind(|| units.mint()).is_err());
        assert_eq!(units.0.load(Relaxed), u64::MAX);
    }
}

#[test]
fn a_new_boots_write_is_not_deduped_against_an_earlier_boots() {
    let store = ready(crate::real_store::core());
    let previous = OpIds::boot(boot_node());
    write(&store, previous.mint(), "the earlier boot's write");
    let restarted = OpIds::boot(boot_node());
    write(&store, restarted.mint(), "the new boot's write");
    assert_eq!(
        ready(store.ledger().get_usage("k", 60))
            .expect("usage")
            .requests,
        2,
        "the new boot's write applied"
    );
}

#[test]
fn a_restarted_counter_under_one_node_half_is_answered_as_a_replay() {
    let store = ready(crate::real_store::core());
    write(&store, OpIds::boot(7).mint(), "the earlier boot's write");
    write(&store, OpIds::boot(7).mint(), "answered as the replay");
    assert_eq!(
        ready(store.ledger().get_usage("k", 60))
            .expect("usage")
            .requests,
        1,
        "the second write was deduped: why the node half is drawn per boot"
    );
}
