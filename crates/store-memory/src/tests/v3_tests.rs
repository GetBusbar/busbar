// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/store-memory/src/v3.rs`: the store v3 slots' dedupe (S1-S4), the reserve
//! grant rule pinned to 1.5.5, slice release clamping, window caps, batches, the ledger
//! streams and the session directory.

use super::*;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, OpRefused, ReserveRefused, StoreSlots,
};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{AuditRecord, ModelTokensDelta, UsageDelta};

fn op(n: u64) -> OpId {
    OpId::from_parts(7, n)
}

fn key(dimension: Dimension<'static>) -> CellKey<'static> {
    CellKey {
        bucket: "b",
        pool: None,
        dimension,
        window_start: 1_000,
    }
}

fn cap(dimension: Dimension<'static>, cap: u64, config_gen: u64) -> Cap<'static> {
    Cap {
        key: key(dimension),
        cap,
        config_gen,
    }
}

fn cell(dimension: Dimension<'static>, amount: u64) -> Cell<'static> {
    Cell {
        key: key(dimension),
        amount,
    }
}

fn capped(dimension: Dimension<'static>, c: u64) -> MemoryStore {
    let s = MemoryStore::new();
    s.window_caps(op(1_000_000), &[cap(dimension, c, 1)])
        .expect("caps");
    s
}

fn delta(requests: i64, input: i64) -> UsageDelta {
    UsageDelta {
        requests,
        billable_requests: requests,
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            usage_units: [("input".to_string(), input)].into_iter().collect(),
        }],
    }
}

fn audit(seq: u64, action: &str) -> AuditRecord {
    AuditRecord {
        seq,
        ts: 1,
        action: action.to_string(),
        resource: "r".to_string(),
        outcome: "ok".to_string(),
        principal: "p".to_string(),
        prev_hash: String::new(),
        hash: format!("h{seq}{action}"),
    }
}

#[test]
fn the_memory_store_states_it_is_ephemeral_and_refuses_forks() {
    assert_eq!(
        <MemoryStore as StoreSlots>::TAIL,
        busbar_contract::abi::sdk::store::Tail {
            ephemeral: true,
            durable_plane: false,
            fork_refusal: true,
        }
    );
}

#[test]
fn a_replayed_usage_batch_applies_once() {
    let s = MemoryStore::new();
    let cells = [("k", 60, delta(1, 10))];
    s.add_usage_batch(op(1), &cells).expect("first");
    s.add_usage_batch(op(1), &cells)
        .expect("replay answers the original");
    assert_eq!(s.get_usage("k", 60).expect("read").requests, 1);
}

#[test]
fn equal_bodies_under_distinct_op_ids_both_apply() {
    let s = MemoryStore::new();
    let cells = [("k", 60, delta(2, 4))];
    s.add_usage_batch(op(1), &cells).expect("a");
    s.add_usage_batch(op(2), &cells).expect("b");
    assert_eq!(s.get_usage("k", 60).expect("read").requests, 4);
}

#[test]
fn a_reused_op_id_with_a_different_body_is_a_conflict_and_applies_nothing() {
    let s = MemoryStore::new();
    s.add_usage_batch(op(1), &[("k", 60, delta(1, 1))])
        .expect("first");
    assert_eq!(
        s.add_usage_batch(op(1), &[("k", 60, delta(5, 5))]),
        Err(OpRefused::Conflict)
    );
    assert_eq!(s.get_usage("k", 60).expect("read").requests, 1);
}

#[test]
fn an_op_id_reused_across_slots_is_a_conflict() {
    let s = MemoryStore::new();
    s.add_usage_op(op(1), "k", 60, &delta(1, 1)).expect("usage");
    assert_eq!(
        s.append_audit_op(op(1), &audit(1, "a")),
        Err(OpRefused::Conflict)
    );
    assert!(s.list_audit().expect("list").is_empty());
}

#[test]
fn a_failed_write_is_not_recorded_so_a_retry_is_evaluated_afresh() {
    let s = MemoryStore::new();
    s.append_audit(&audit(1, "a")).expect("seed");
    // A fork FAILS and is not recorded under the op_id ...
    assert!(matches!(
        s.append_audit_op(op(9), &audit(1, "forked")),
        Err(OpRefused::Failed(_))
    ));
    // ... so the same op_id with a different, applicable body is new, not a conflict.
    s.append_audit_op(op(9), &audit(2, "b")).expect("fresh");
    assert_eq!(s.list_audit().expect("list").len(), 2);
}

#[test]
fn an_audit_batch_with_one_fork_applies_none_of_it() {
    let s = MemoryStore::new();
    s.append_audit(&audit(2, "a")).expect("seed");
    let batch = [audit(1, "x"), audit(2, "forked")];
    assert!(matches!(
        s.append_audit_batch(op(1), &batch),
        Err(OpRefused::Failed(_))
    ));
    assert_eq!(s.list_audit().expect("list").len(), 1);
    // Two different records at one seq INSIDE the batch are a fork too.
    let inner = [audit(5, "x"), audit(5, "y")];
    assert!(s.append_audit_batch(op(2), &inner).is_err());
    assert_eq!(s.list_audit().expect("list").len(), 1);
}

#[test]
fn a_usage_batch_applies_its_cells_in_order() {
    let s = MemoryStore::new();
    let neg = UsageDelta {
        requests: 0,
        billable_requests: -1,
        models: vec![],
    };
    let pos = UsageDelta {
        requests: 0,
        billable_requests: 1,
        models: vec![],
    };
    s.add_usage_batch(op(1), &[("k", 60, neg), ("k", 60, pos)])
        .expect("batch");
    // The floor at zero makes order matter: -1 then +1 is 1, not 0.
    assert_eq!(s.get_usage("k", 60).expect("read").billable_requests, 1);
}

#[test]
fn a_metering_batch_replay_applies_once() {
    let s = MemoryStore::new();
    let d = MeteringDelta {
        key_id: "k".into(),
        bucket: 86_400,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 3,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 2,
        billable_requests: 2,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    };
    s.add_metering_batch(op(1), std::slice::from_ref(&d))
        .expect("a");
    s.add_metering_batch(op(1), std::slice::from_ref(&d))
        .expect("replay");
    let rows = s.list_metering(86_400).expect("list");
    assert_eq!(rows.iter().map(|r| r.requests).sum::<u64>(), 2);
}

#[test]
fn a_reserve_with_no_cap_pushed_is_refused_naming_the_cell() {
    let s = MemoryStore::new();
    assert_eq!(
        s.reserve(op(1), 0, &[cell(Dimension::Requests, 1)]),
        Err(ReserveRefused::NoCap { cell: 0 })
    );
}

#[test]
fn a_grant_is_always_the_whole_amount() {
    let s = capped(Dimension::NanoUnits, 100);
    let g = s
        .reserve(op(1), 0, &[cell(Dimension::NanoUnits, 60)])
        .expect("grant");
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].granted, 60);
}

#[test]
fn requests_refuse_when_used_plus_amount_passes_the_cap() {
    let s = capped(Dimension::Requests, 2);
    s.reserve(op(1), 0, &[cell(Dimension::Requests, 2)])
        .expect("at the cap");
    assert_eq!(
        s.reserve(op(2), 0, &[cell(Dimension::Requests, 1)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
}

#[test]
fn a_class_meter_grants_the_draw_that_crosses_the_cap_and_refuses_at_it() {
    let s = capped(Dimension::Class("tokens"), 10);
    s.reserve(op(1), 0, &[cell(Dimension::Class("tokens"), 9)])
        .expect("under");
    s.reserve(op(2), 0, &[cell(Dimension::Class("tokens"), 50)])
        .expect("crossing is granted whole (1.5.5 `tokens >= cap`)");
    assert_eq!(
        s.reserve(op(3), 0, &[cell(Dimension::Class("tokens"), 1)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
}

#[test]
fn money_refuses_a_draw_that_would_pass_the_cap() {
    let s = capped(Dimension::NanoUnits, 100);
    assert_eq!(
        s.reserve(op(1), 0, &[cell(Dimension::NanoUnits, 101)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    s.reserve(op(2), 0, &[cell(Dimension::NanoUnits, 100)])
        .expect("exactly the cap");
}

#[test]
fn an_overflowing_draw_is_exhausted_not_wrapped() {
    let s = capped(Dimension::Requests, u64::MAX);
    s.reserve(op(1), 0, &[cell(Dimension::Requests, u64::MAX - 1)])
        .expect("near max");
    assert_eq!(
        s.reserve(op(2), 0, &[cell(Dimension::Requests, 5)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
}

#[test]
fn a_chain_draw_is_all_or_nothing() {
    let s = MemoryStore::new();
    s.window_caps(
        op(100),
        &[
            cap(Dimension::Requests, 10, 1),
            cap(Dimension::NanoUnits, 5, 1),
        ],
    )
    .expect("caps");
    // The second cell fails, so the first draws nothing either.
    assert_eq!(
        s.reserve(
            op(1),
            0,
            &[cell(Dimension::Requests, 10), cell(Dimension::NanoUnits, 6)]
        ),
        Err(ReserveRefused::Exhausted { cell: 1 })
    );
    s.reserve(op(2), 0, &[cell(Dimension::Requests, 10)])
        .expect("the first cell's headroom is untouched");
}

#[test]
fn two_cells_on_one_slot_count_against_each_other() {
    let s = capped(Dimension::Requests, 3);
    assert_eq!(
        s.reserve(
            op(1),
            0,
            &[cell(Dimension::Requests, 2), cell(Dimension::Requests, 2)]
        ),
        Err(ReserveRefused::Exhausted { cell: 1 })
    );
}

#[test]
fn a_replayed_reserve_answers_the_same_grants_and_draws_nothing_more() {
    let s = capped(Dimension::Requests, 10);
    let a = s
        .reserve(op(1), 0, &[cell(Dimension::Requests, 6)])
        .expect("a");
    let b = s
        .reserve(op(1), 0, &[cell(Dimension::Requests, 6)])
        .expect("replay");
    assert_eq!(a, b);
    // Only 6 are drawn: 4 more fit, 5 do not.
    assert_eq!(
        s.reserve(op(2), 0, &[cell(Dimension::Requests, 5)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    s.reserve(op(3), 0, &[cell(Dimension::Requests, 4)])
        .expect("the rest");
}

#[test]
fn a_reserve_op_id_reused_with_another_body_is_a_conflict() {
    let s = capped(Dimension::Requests, 10);
    s.reserve(op(1), 0, &[cell(Dimension::Requests, 1)])
        .expect("a");
    assert_eq!(
        s.reserve(op(1), 0, &[cell(Dimension::Requests, 2)]),
        Err(ReserveRefused::Conflict)
    );
}

#[test]
fn a_refused_reserve_is_not_recorded() {
    let s = capped(Dimension::Requests, 1);
    s.reserve(op(1), 0, &[cell(Dimension::Requests, 1)])
        .expect("fill");
    assert_eq!(
        s.reserve(op(2), 0, &[cell(Dimension::Requests, 1)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    s.window_caps(op(3), &[cap(Dimension::Requests, 2, 2)])
        .expect("raise");
    // The same op_id is evaluated afresh and now fits.
    s.reserve(op(2), 0, &[cell(Dimension::Requests, 1)])
        .expect("afresh");
}

#[test]
fn the_memory_store_never_answers_a_stale_epoch() {
    let s = capped(Dimension::Requests, 10);
    s.reserve(op(1), 9, &[cell(Dimension::Requests, 1)])
        .expect("epoch 9");
    s.reserve(op(2), 1, &[cell(Dimension::Requests, 1)])
        .expect("an older epoch is not stale on a node-local store");
}

#[test]
fn slice_release_is_clamped_deduped_and_frees_headroom() {
    let s = capped(Dimension::Requests, 10);
    let g = s
        .reserve(op(1), 0, &[cell(Dimension::Requests, 10)])
        .expect("draw all");
    let id = g[0].slice_id;
    assert_eq!(s.slice_release(op(2), 0, &[(id, 4)]), Ok(vec![4]));
    assert_eq!(
        s.slice_release(op(2), 0, &[(id, 4)]),
        Ok(vec![4]),
        "a replay answers the original and takes nothing more back"
    );
    // Clamped to what the slice has left (6), never more.
    assert_eq!(s.slice_release(op(3), 0, &[(id, u64::MAX)]), Ok(vec![6]));
    // All 10 are free again.
    s.reserve(op(4), 0, &[cell(Dimension::Requests, 10)])
        .expect("headroom back");
}

#[test]
fn releasing_an_unknown_slice_fails_and_applies_nothing() {
    let s = capped(Dimension::Requests, 10);
    let g = s
        .reserve(op(1), 0, &[cell(Dimension::Requests, 10)])
        .expect("draw");
    assert!(matches!(
        s.slice_release(op(2), 0, &[(g[0].slice_id, 3), (999, 1)]),
        Err(OpRefused::Failed(_))
    ));
    // The known item was not applied either: still exhausted.
    assert_eq!(
        s.reserve(op(3), 0, &[cell(Dimension::Requests, 1)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
}

#[test]
fn window_caps_newest_generation_wins_and_equal_generation_conflicts() {
    let s = MemoryStore::new();
    s.window_caps(op(1), &[cap(Dimension::Requests, 1, 5)])
        .expect("gen 5");
    s.window_caps(op(2), &[cap(Dimension::Requests, 99, 4)])
        .expect("an older generation is ignored");
    assert_eq!(
        s.reserve(op(3), 0, &[cell(Dimension::Requests, 2)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    assert_eq!(
        s.window_caps(
            op(4),
            &[
                cap(Dimension::Requests, 3, 6),
                cap(Dimension::Requests, 7, 6)
            ]
        ),
        Err(CapsRefused::CapConflict { index: 1 }),
        "equal gen with a different cap refuses the WHOLE push"
    );
    // Nothing of the refused push applied: the cap is still 1.
    assert_eq!(
        s.reserve(op(5), 0, &[cell(Dimension::Requests, 2)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    s.window_caps(op(6), &[cap(Dimension::Requests, 3, 6)])
        .expect("gen 6");
    s.reserve(op(7), 0, &[cell(Dimension::Requests, 2)])
        .expect("cap 3");
}

#[test]
fn an_op_id_is_forgotten_after_its_retention() {
    let s = MemoryStore::new();
    s.pin_clock(1_000);
    s.add_usage_batch(op(1), &[("k", 60, delta(1, 1))])
        .expect("a");
    s.pin_clock(1_000 + OP_ID_RETENTION_SECS);
    // Recording another op sweeps the expired one; the old op_id then reads as new.
    s.add_usage_batch(op(2), &[("j", 60, delta(1, 1))])
        .expect("b");
    s.add_usage_batch(op(1), &[("k", 60, delta(1, 1))])
        .expect("new again");
    assert_eq!(s.get_usage("k", 60).expect("read").requests, 2);
}

#[test]
fn append_batch_advances_the_stream_head_once_per_op() {
    let s = MemoryStore::new();
    let r = |b: u8| RecordBytes::new(vec![b]).expect("record");
    assert_eq!(
        s.append_batch(op(1), "journal", &[r(1), r(2)])
            .expect("a")
            .seq,
        2
    );
    assert_eq!(
        s.append_batch(op(1), "journal", &[r(1), r(2)])
            .expect("replay")
            .seq,
        2
    );
    assert_eq!(s.append_batch(op(2), "journal", &[r(3)]).expect("b").seq, 3);
    let heads = s.heads().expect("heads");
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].0, "journal");
    assert_eq!(heads[0].1.seq, 3);
}

#[test]
fn sessions_are_listed_per_principal_and_removed() {
    let s = MemoryStore::new();
    s.session_put(1, "n1", "alice").expect("put");
    s.session_put(2, "n2", "alice").expect("put");
    s.session_put(3, "n1", "bob").expect("put");
    assert_eq!(
        s.sessions_for("alice").expect("list"),
        vec![(1, "n1".to_string()), (2, "n2".to_string())]
    );
    s.session_remove(1).expect("remove");
    s.session_remove(1).expect("absent is Ok");
    assert_eq!(
        s.sessions_for("alice").expect("list"),
        vec![(2, "n2".to_string())]
    );
}
