// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `op_id` dedupe every store runs: a replayed batch applies once, a reused `op_id` with a

use std::collections::{BTreeMap, HashMap};

use super::*;
use crate::abi::store::OpId;
use crate::records::{
    MeteringDelta, ModelTokensDelta, PlaneDisposition, PlaneRecordRef, UsageDelta,
};

/// A store's dedupe log and what it applied: `op_id` -> the recorded body.
#[derive(Default)]
struct Log {
    ops: HashMap<OpId, Vec<u8>>,
    applied: u32,
}

impl Log {
    /// One op through [`Dedupe::run`], recording the body as the bytes `store` makes of it.
    fn op(&mut self, op: OpId, d: &Dedupe, store: fn(&Body) -> Vec<u8>) -> OpResult<()> {
        d.run(
            self,
            |log| Ok(log.ops.get(&op).cloned()),
            |log, body| {
                log.applied += 1;
                log.ops.insert(op, store(body));
                Ok(())
            },
        )
    }

    fn raw(&mut self, op: OpId, d: &Dedupe) -> OpResult<()> {
        self.op(op, d, |b| b.to_vec())
    }
}

fn id(n: u8) -> OpId {
    OpId([n; 16])
}

fn delta(requests: i64) -> UsageDelta {
    UsageDelta {
        requests,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
            scale: 0,
            model: "m".into(),
            usage_units: BTreeMap::from([("input".to_owned(), 7)]),
        }],
    }
}

#[test]
fn count_scale_is_part_of_operation_identity_and_never_matches_a_legacy_receipt() {
    let whole = [("b", 60, delta(1))];
    let mut scaled = whole.clone();
    scaled[0].2.models[0].scale = 6;
    let legacy = Dedupe::usage(&whole);
    let exact = Dedupe::usage(&scaled);
    assert_ne!(legacy.body(), exact.body());
    assert_eq!(exact.seen(Some(legacy.body())), Seen::Conflict);
    let older = br#"add_usage_batch:[("b", 60, UsageDelta { requests: 1, billable_requests: 1, models: [ModelTokensDelta { model: "m", usage_units: {"input": 7} }] })]"#;
    assert_eq!(exact.seen(Some(older)), Seen::Conflict);
    assert_eq!(legacy.seen(Some(older)), Seen::Conflict);
}

fn metering(tokens_input: u64) -> MeteringDelta {
    MeteringDelta {
        scale: 0,
        key_id: "k".into(),
        bucket: 20_000,
        model: "m".into(),
        provider: "p".into(),
        tokens_input,
        tokens_output: 2,
        tokens_cache_read: 3,
        tokens_cache_write: 4,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
        usage_units: BTreeMap::new(),
    }
}

fn record(body: &[u8]) -> PlaneRecordRef<'_> {
    PlaneRecordRef {
        kind: "task_event",
        id: "e-1",
        parent: Some("t-1"),
        seq: 3,
        ts: 1_700_000_000,
        disposition: PlaneDisposition::Active,
        body,
    }
}

#[test]
fn a_replayed_usage_batch_applies_once() {
    let cells = [("b", 60, delta(1))];
    let mut log = Log::default();
    assert_eq!(log.raw(id(1), &Dedupe::usage(&cells)), Ok(()));
    assert_eq!(log.raw(id(1), &Dedupe::usage(&cells)), Ok(()));
    assert_eq!(log.applied, 1);
}

#[test]
fn equal_bodies_under_distinct_op_ids_both_apply() {
    let cells = [("b", 60, delta(1))];
    let mut log = Log::default();
    assert_eq!(log.raw(id(1), &Dedupe::usage(&cells)), Ok(()));
    assert_eq!(log.raw(id(2), &Dedupe::usage(&cells)), Ok(()));
    assert_eq!(log.applied, 2);
}

#[test]
fn a_reused_op_id_with_a_different_body_is_a_conflict_and_applies_nothing() {
    let mut log = Log::default();
    assert_eq!(
        log.raw(id(1), &Dedupe::usage(&[("b", 60, delta(1))])),
        Ok(())
    );
    assert_eq!(
        log.raw(id(1), &Dedupe::usage(&[("b", 60, delta(2))])),
        Err(OpRefused::Conflict)
    );
    assert_eq!(log.applied, 1);
}

#[test]
fn an_op_id_reused_across_slots_is_a_conflict() {
    let mut log = Log::default();
    assert_eq!(log.raw(id(1), &Dedupe::usage(&[])), Ok(()));
    assert_eq!(
        log.raw(id(1), &Dedupe::metering(&[])),
        Err(OpRefused::Conflict)
    );
    assert_eq!(
        log.raw(id(1), &Dedupe::append(record(b"x"))),
        Err(OpRefused::Conflict)
    );
    assert_eq!(log.applied, 1);
}

#[test]
fn a_metering_batch_replay_applies_once() {
    let deltas = [metering(10), metering(11)];
    let mut log = Log::default();
    assert_eq!(log.raw(id(1), &Dedupe::metering(&deltas)), Ok(()));
    assert_eq!(log.raw(id(1), &Dedupe::metering(&deltas)), Ok(()));
    assert_eq!(
        log.raw(id(1), &Dedupe::metering(&[metering(10)])),
        Err(OpRefused::Conflict)
    );
    assert_eq!(log.applied, 1);
}

#[test]
fn a_replayed_plane_append_applies_once_and_a_different_record_conflicts() {
    let mut log = Log::default();
    assert_eq!(log.raw(id(1), &Dedupe::append(record(b"x"))), Ok(()));
    assert_eq!(log.raw(id(1), &Dedupe::append(record(b"x"))), Ok(()));
    assert_eq!(
        log.raw(id(1), &Dedupe::append(record(b"y"))),
        Err(OpRefused::Conflict)
    );
    assert_eq!(log.applied, 1);
}

#[test]
fn a_refused_op_records_nothing_and_its_retry_applies() {
    let cells = [("b", 60, delta(1))];
    let d = Dedupe::usage(&cells);
    let mut log = Log::default();
    let refused = d.run(
        &mut log,
        |log| Ok(log.ops.get(&id(1)).cloned()),
        |_, _| Err(OpRefused::Refused("too big".into())),
    );
    assert_eq!(refused, Err(OpRefused::Refused("too big".into())));
    assert!(log.ops.is_empty());
    assert_eq!(log.raw(id(1), &d), Ok(()));
    assert_eq!(log.applied, 1);
}

#[test]
fn a_failed_read_of_the_log_applies_nothing() {
    let cells = [("b", 60, delta(1))];
    let mut log = Log::default();
    let failed = Dedupe::usage(&cells).run(
        &mut log,
        |_| Err::<Option<Vec<u8>>, _>(OpRefused::Failed("gone".into())),
        |log, _| {
            log.applied += 1;
            Ok(())
        },
    );
    assert_eq!(failed, Err(OpRefused::Failed("gone".into())));
    assert_eq!(log.applied, 0);
}

#[test]
fn the_dedupe_log_keeps_a_fixed_size_record_per_op() {
    let small = [("b", 60, delta(1))];
    let large: Vec<(&str, u64, UsageDelta)> = (0..500).map(|w| ("b", w, delta(1))).collect();
    assert_eq!(Dedupe::usage(&small).body().len(), 32);
    assert_eq!(Dedupe::usage(&large).body().len(), 32);
    assert_eq!(Dedupe::usage(&large).body_hex().len(), 64);
}

#[test]
fn a_body_kept_as_hex_text_replays_and_conflicts_as_the_raw_one() {
    let cells = [("b", 60, delta(1))];
    let mut log = Log::default();
    let text = |b: &Body| hex::encode(b).into_bytes();
    assert_eq!(log.op(id(1), &Dedupe::usage(&cells), text), Ok(()));
    assert_eq!(log.op(id(1), &Dedupe::usage(&cells), text), Ok(()));
    assert_eq!(
        log.op(id(1), &Dedupe::usage(&[("b", 61, delta(1))]), text),
        Err(OpRefused::Conflict)
    );
    assert_eq!(log.applied, 1);
}

#[test]
fn development_debug_usage_receipts_conflict_without_applying() {
    let cells = [("b", 60, delta(1))];
    let older = r#"add_usage_batch:[("b", 60, UsageDelta { requests: 1, billable_requests: 1, models: [ModelTokensDelta { model: "m", usage_units: {"input": 7} }] })]"#;
    let mut log = Log::default();
    log.ops.insert(id(1), older.as_bytes().to_vec());
    assert_eq!(
        log.raw(id(1), &Dedupe::usage(&cells)),
        Err(OpRefused::Conflict)
    );
    assert_eq!(
        log.raw(id(1), &Dedupe::usage(&[("b", 60, delta(2))])),
        Err(OpRefused::Conflict)
    );
    assert_eq!(log.applied, 0);
}

#[test]
fn development_debug_metering_receipts_conflict_without_applying() {
    let deltas = vec![metering(10)];
    let mut log = Log::default();
    log.ops
        .insert(id(1), r#"add_metering_batch:[MeteringDelta { key_id: "k", bucket: 20000, model: "m", provider: "p", tokens_input: 10, tokens_output: 2, tokens_cache_read: 3, tokens_cache_write: 4, requests: 1, billable_requests: 1, key_group_at_use: "", pricing_version: "", priced_from_ms: 0, usage_units: {} }]"#.as_bytes().to_vec());
    assert_eq!(
        log.raw(id(1), &Dedupe::metering(&deltas)),
        Err(OpRefused::Conflict)
    );
    assert_eq!(
        log.raw(id(1), &Dedupe::metering(&[metering(11)])),
        Err(OpRefused::Conflict)
    );
    assert_eq!(log.applied, 0);
}

#[test]
fn development_debug_append_receipts_conflict_in_both_forms() {
    let r = record(b"x");
    for older in [
        r#"append_plane_record:PlaneRecordRef { kind: "task_event", id: "e-1", parent: Some("t-1"), seq: 3, ts: 1700000000, disposition: Active, body: [120] }"#,
        r#"append_plane_record:PlaneRecord { kind: "task_event", id: "e-1", parent: Some("t-1"), seq: 3, ts: 1700000000, disposition: Active, body: [120] }"#,
    ] {
        let mut log = Log::default();
        log.ops.insert(id(1), older.as_bytes().to_vec());
        assert_eq!(log.raw(id(1), &Dedupe::append(r)), Err(OpRefused::Conflict));
        assert_eq!(
            log.raw(id(1), &Dedupe::append(record(b"y"))),
            Err(OpRefused::Conflict)
        );
        assert_eq!(log.applied, 0);
    }
}

#[test]
fn an_async_bodys_answer_is_done_replay_or_conflict() {
    let cells = [("b", 60, delta(1))];
    let d = Dedupe::usage(&cells);
    let other = Dedupe::usage(&[]);
    assert_eq!(d.answer(Ok(None::<Vec<u8>>)), Ok(()));
    assert_eq!(d.answer(Ok(Some(d.body().to_vec()))), Ok(()));
    assert_eq!(d.answer(Ok(Some(d.body_hex()))), Ok(()));
    assert_eq!(
        d.answer(Ok(Some(r#"add_usage_batch:[("b", 60, UsageDelta { requests: 1, billable_requests: 1, models: [ModelTokensDelta { model: "m", usage_units: {"input": 7} }] })]"#))),
        Err(OpRefused::Conflict)
    );
    assert_eq!(
        d.answer(Ok(Some(other.body().to_vec()))),
        Err(OpRefused::Conflict)
    );
    assert_eq!(
        d.answer(Err::<Option<Vec<u8>>, _>(OpRefused::Failed("x".into()))),
        Err(OpRefused::Failed("x".into()))
    );
}

#[test]
fn the_body_is_the_documented_encoding() {
    fn text(h: &mut Sha256, s: &str) {
        h.update((s.len() as u64).to_le_bytes());
        h.update(s.as_bytes());
    }

    let mut h = Sha256::new();
    text(&mut h, "busbar.store.op/1");
    text(&mut h, "add_usage_batch");
    h.update(1_u64.to_le_bytes());
    text(&mut h, "b");
    h.update(60_u64.to_le_bytes());
    h.update(1_i64.to_le_bytes());
    h.update(1_i64.to_le_bytes());
    h.update(1_u64.to_le_bytes());
    text(&mut h, "m");
    h.update(1_u64.to_le_bytes());
    text(&mut h, "input");
    h.update(7_i64.to_le_bytes());
    let want: [u8; 32] = h.finalize().into();
    assert_eq!(Dedupe::usage(&[("b", 60, delta(1))]).body(), &want);

    let mut h = Sha256::new();
    text(&mut h, "busbar.store.op/1");
    text(&mut h, "append_plane_record");
    text(&mut h, "task_event");
    text(&mut h, "e-1");
    h.update([1]);
    text(&mut h, "t-1");
    h.update(3_u64.to_le_bytes());
    h.update(1_700_000_000_u64.to_le_bytes());
    h.update([0]);
    h.update(1_u64.to_le_bytes());
    h.update(b"x");
    let want: [u8; 32] = h.finalize().into();
    assert_eq!(Dedupe::append(record(b"x")).body(), &want);
}

#[test]
fn length_prefixes_keep_neighbouring_fields_apart() {
    let a = [("ab", 1, UsageDelta::default())];
    let b = [("a", 1, UsageDelta::default())];
    assert_ne!(Dedupe::usage(&a).body(), Dedupe::usage(&b).body());
    let mut r = record(b"x");
    r.parent = None;
    assert_ne!(
        Dedupe::append(r).body(),
        Dedupe::append(record(b"x")).body()
    );
}

#[test]
fn development_debug_receipts_cannot_prove_signed_or_terminal_operations() {
    let cells = [(
        "b\n\"",
        u64::MAX,
        UsageDelta {
            requests: i64::MIN,
            billable_requests: 0,
            models: vec![ModelTokensDelta {
                scale: 0,
                model: "\tπ".into(),
                usage_units: BTreeMap::from([("z".into(), -1), ("a".into(), 0)]),
            }],
        },
    )];
    let legacy = r#"add_usage_batch:[("b\n\"", 18446744073709551615, UsageDelta { requests: -9223372036854775808, billable_requests: 0, models: [ModelTokensDelta { model: "\tπ", usage_units: {"a": 0, "z": -1} }] })]"#;
    assert_eq!(
        Dedupe::usage(&cells).seen(Some(legacy.as_bytes())),
        Seen::Conflict
    );
    assert_eq!(
        Dedupe::usage(&[]).seen(Some(legacy.as_bytes())),
        Seen::Conflict
    );
    let bytes = [0, 255, 10];
    let row = PlaneRecordRef {
        parent: None,
        disposition: PlaneDisposition::Terminal,
        ..record(&bytes)
    };
    let legacy = r#"append_plane_record:PlaneRecordRef { kind: "task_event", id: "e-1", parent: None, seq: 3, ts: 1700000000, disposition: Terminal, body: [0, 255, 10] }"#;
    assert_eq!(
        Dedupe::append(row).seen(Some(legacy.as_bytes())),
        Seen::Conflict
    );
    let changed = PlaneRecordRef {
        parent: Some(""),
        ..row
    };
    assert_eq!(
        Dedupe::append(changed).seen(Some(legacy.as_bytes())),
        Seen::Conflict
    );
}
