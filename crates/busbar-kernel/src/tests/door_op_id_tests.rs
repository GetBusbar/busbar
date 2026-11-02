// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::{RecordStore, UsageDelta};

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

fn write(
    store: &busbar_plugin_loader::store_v3::LoadedStore,
    op: busbar_contract::abi::store::OpId,
    why: &str,
) {
    RecordStore::add_usage_batch_deduped(store, op, &cells()).expect(why);
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
fn a_new_boots_write_is_not_deduped_against_an_earlier_boots() {
    let store = crate::real_store::store();
    let previous = OpIds::boot(boot_node());
    write(&store, previous.mint(), "the earlier boot's write");
    let restarted = OpIds::boot(boot_node());
    write(&store, restarted.mint(), "the new boot's write");
    assert_eq!(
        RecordStore::get_usage(&*store, "k", 60)
            .expect("usage")
            .requests,
        2,
        "the new boot's write applied"
    );
}

#[test]
fn a_restarted_counter_under_one_node_half_is_answered_as_a_replay() {
    let store = crate::real_store::store();
    write(&store, OpIds::boot(7).mint(), "the earlier boot's write");
    write(&store, OpIds::boot(7).mint(), "answered as the replay");
    assert_eq!(
        RecordStore::get_usage(&*store, "k", 60)
            .expect("usage")
            .requests,
        1,
        "the second write was deduped: why the node half is drawn per boot"
    );
}
