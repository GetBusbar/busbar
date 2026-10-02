// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `LoadedStore`: the build's store loaded through its COMPILED-IN door
//! and reached only through the store v3 table, on both surfaces — the synchronous `RecordStore`
//! bridge and the typed, awaited `StoreCalls`.

use std::sync::Arc;

use busbar_contract::abi::sdk::store::{Cap, Cell, CellKey, Dimension, ReserveRefused};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, ModelTokensDelta, PlaneDisposition, PlaneRecord,
    PlaneSelector, RecordStore, SecretForm, UsageDelta, VirtualKey,
};
use busbar_contract::store_calls::{StoreCalls, StoreFailure};

use super::LoadedStore;
use crate::dispatch::kinds::store::{Store, StoreFacts};
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink};

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig::default()))
}

fn open() -> LoadedStore {
    let d = dispatcher();
    let row = LinkedRow::of(crate::both_ways::store_fixture::door)
        .expect("the memory store states its Statement");
    let plugin = load_linked::<Store>(
        &row,
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 1024,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: None,
        },
    )
    .expect("the memory store's door loads");
    LoadedStore::open(plugin, d, b"{}", 7).expect("the memory store opens")
}

fn run<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

fn op(n: u64) -> OpId {
    OpId::from_parts(9, n)
}

fn key(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: format!("h_{id}"),
        name: "t".to_string(),
        enabled: true,
        ..Default::default()
    }
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

fn record(kind: &str, id: &str, parent: Option<&str>, seq: u64, body: Vec<u8>) -> PlaneRecord {
    PlaneRecord {
        kind: kind.to_string(),
        id: id.to_string(),
        parent: parent.map(str::to_string),
        seq,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body,
    }
}

fn requests_key(window_start: u64) -> CellKey<'static> {
    CellKey {
        bucket: "b",
        pool: None,
        dimension: Dimension::Requests,
        window_start,
    }
}

#[test]
fn the_memory_store_states_its_facts_in_its_tail() {
    let s = open();
    assert_eq!(
        s.facts(),
        StoreFacts {
            ephemeral: true,
            durable_plane: false,
            fork_refusal: true,
        }
    );
    assert!(!s.name().is_empty(), "the store states its name");
}

#[test]
fn keys_round_trip_through_the_table() {
    let s = open();
    s.put_key(&key("a")).expect("put");
    s.put_key(&key("b")).expect("put");
    assert_eq!(s.get_key("a").expect("get").map(|k| k.id), Some("a".into()));
    assert_eq!(s.get_key("zz").expect("absent"), None);
    let mut ids: Vec<String> = s
        .list_keys()
        .expect("list")
        .into_iter()
        .map(|k| k.id)
        .collect();
    ids.sort();
    assert_eq!(ids, ["a", "b"]);
    s.delete_key("a").expect("delete");
    assert!(s
        .get_key("a")
        .expect("get")
        .expect("tombstone")
        .deleted_at
        .is_some());
    assert!(s.delete_key("nope").is_err(), "an unknown id is FAILED");
}

#[test]
fn the_tombstone_precondition_crosses_as_a_failure() {
    let s = open();
    s.put_key(&key("a")).expect("put");
    s.delete_key("a").expect("delete");
    let err = s
        .put_key(&key("a"))
        .expect_err("a live write over a tombstone");
    assert!(!err.0.is_empty());
}

#[test]
fn usage_adds_through_the_bridge_mint_distinct_op_ids() {
    let s = open();
    s.add_usage("k", 60, &delta(1, 10)).expect("a");
    s.add_usage("k", 60, &delta(1, 10))
        .expect("b: a fresh op_id, not a replay");
    assert_eq!(s.get_usage("k", 60).expect("read").requests, 2);
    assert_eq!(s.get_usage("untouched", 60).expect("read").requests, 0);
}

#[test]
fn credentials_cross_as_secret_blobs_and_read_back() {
    let s = open();
    s.put_key(&key("k1")).expect("key");
    let secret = CredentialSecret {
        meta: CredentialMeta {
            id: "c1".into(),
            key_id: "k1".into(),
            kind: "generic".into(),
            slot: 0,
            public_id: "pub".into(),
            secret_form: SecretForm::Recoverable,
            created_at: 0,
            updated_at: 0,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: "s3cret".into(),
    };
    s.put_credential(&secret).expect("put");
    let got = s
        .lookup_credential_secret("generic", "pub")
        .expect("lookup")
        .expect("found");
    assert_eq!(got.meta.id, "c1");
    assert_eq!(
        s.lookup_credential_secret("generic", "pub-absent")
            .expect("lookup"),
        None
    );
    assert_eq!(s.list_credentials("k1").expect("list").len(), 1);
}

#[test]
fn audit_appends_and_a_fork_fails() {
    let s = open();
    let a = AuditRecord {
        seq: 1,
        ts: 1,
        action: "a".into(),
        resource: "r".into(),
        outcome: "ok".into(),
        principal: "p".into(),
        prev_hash: String::new(),
        hash: "h".into(),
    };
    s.append_audit(&a).expect("append");
    s.append_audit(&a).expect("a byte-identical retry is Ok");
    let fork = AuditRecord {
        action: "b".into(),
        ..a.clone()
    };
    assert!(s.append_audit(&fork).is_err());
    assert_eq!(s.list_audit().expect("list"), vec![a]);
}

#[test]
fn plane_records_and_tokens_cross_the_request_path_slots() {
    let store = open();
    let s: &dyn RecordStore = &store;
    s.upsert_plane_record(record("task", "t1", None, 0, b"body".to_vec()).view())
        .expect("upsert");
    assert_eq!(
        s.get_plane_record("task", "t1").expect("get"),
        Some(b"body".to_vec())
    );
    assert_eq!(s.get_plane_record("task", "t-absent").expect("get"), None);
    s.append_plane_record(record("event", "e", Some("t1"), 1, b"one".to_vec()).view())
        .expect("append");
    s.append_plane_record(record("event", "e", Some("t1"), 2, b"two".to_vec()).view())
        .expect("append");
    assert_eq!(
        s.list_plane_records("event", &PlaneSelector::Parent("t1".into()))
            .expect("list"),
        vec![b"one".to_vec(), b"two".to_vec()]
    );
    assert_eq!(
        s.list_plane_record_parents("event").expect("parents"),
        vec!["t1".to_string()]
    );
    assert!(s.redeem_plane_token("tok", "x", 100, 1).expect("first"));
    assert!(!s.redeem_plane_token("tok", "x", 100, 1).expect("second"));
    s.delete_plane_record("task", "t1").expect("delete");
    assert_eq!(s.get_plane_record("task", "t1").expect("get"), None);
}

#[test]
fn a_body_over_the_first_buffer_is_re_asked_once_at_its_size() {
    let store = open();
    let s: &dyn RecordStore = &store;
    let big = vec![7u8; 100 * 1024];
    s.upsert_plane_record(record("task", "big", None, 0, big.clone()).view())
        .expect("upsert");
    assert_eq!(
        s.get_plane_record("task", "big").expect("get"),
        Some(big.clone())
    );
    let got = run(StoreCalls::get_plane_record(&store, "task", "big")).expect("typed get");
    assert_eq!(got, Some(big));
}

#[test]
fn a_list_over_the_first_buffers_is_re_asked_once() {
    let store = open();
    let s: &dyn RecordStore = &store;
    for i in 0..400u64 {
        s.append_plane_record(record("event", "e", Some("p"), i + 1, vec![1; 100]).view())
            .expect("append");
    }
    let rows = s
        .list_plane_records("event", &PlaneSelector::Parent("p".into()))
        .expect("list");
    assert_eq!(rows.len(), 400);
    let typed = run(StoreCalls::list_plane_records(
        &store,
        "event",
        &PlaneSelector::Parent("p".into()),
    ))
    .expect("typed list");
    assert_eq!(typed, rows);
}

#[test]
fn records_put_get_and_scan_through_the_typed_surface() {
    let s = open();
    let v = |b: &[u8]| RecordBytes::new(b.to_vec()).expect("record");
    run(async {
        s.record_put("sch", b"a/1", &v(b"one")).await.expect("put");
        s.record_put("sch", b"a/2", &v(b"two")).await.expect("put");
        s.record_put("sch", b"b/1", &v(b"other"))
            .await
            .expect("put");
        assert_eq!(
            StoreCalls::record_get(&s, "sch", b"a/2")
                .await
                .expect("get"),
            Some(v(b"two"))
        );
        assert_eq!(
            StoreCalls::record_get(&s, "sch", b"zz").await.expect("get"),
            None
        );
        let rows = s.record_scan("sch", b"a/", 10).await.expect("scan");
        assert_eq!(
            rows,
            vec![(b"a/1".to_vec(), v(b"one")), (b"a/2".to_vec(), v(b"two"))]
        );
        assert_eq!(s.record_scan("sch", b"a/", 1).await.expect("scan").len(), 1);
        assert!(s
            .record_scan("sch", b"a/", 0)
            .await
            .expect("scan")
            .is_empty());
    });
}

#[test]
fn a_usage_batch_replays_once_and_a_reused_op_id_is_a_conflict() {
    let s = open();
    run(async {
        let cells = [("k", 60, delta(1, 10))];
        s.add_usage_batch(op(1), &cells).await.expect("a");
        s.add_usage_batch(op(1), &cells).await.expect("replay");
        let other = [("k", 60, delta(5, 5))];
        assert_eq!(
            s.add_usage_batch(op(1), &other).await,
            Err(StoreFailure::Conflict)
        );
    });
    assert_eq!(s.get_usage("k", 60).expect("read").requests, 1);
}

#[test]
fn reserve_needs_a_cap_draws_whole_and_releases_clamped() {
    let s = open();
    run(async {
        let cells = [Cell {
            key: requests_key(1_000),
            amount: 3,
        }];
        assert_eq!(
            s.reserve(op(1), 0, &cells).await,
            Err(StoreFailure::Reserve(ReserveRefused::NoCap { cell: 0 }))
        );
        s.window_caps(
            op(2),
            &[Cap {
                key: requests_key(1_000),
                cap: 4,
                config_gen: 1,
            }],
        )
        .await
        .expect("caps");
        let g = s.reserve(op(3), 0, &cells).await.expect("grant");
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].granted, 3);
        assert_eq!(
            s.reserve(op(3), 0, &cells).await.expect("replay"),
            g,
            "a replay answers the original grants"
        );
        assert_eq!(
            s.reserve(op(4), 0, &cells).await,
            Err(StoreFailure::Reserve(ReserveRefused::Exhausted { cell: 0 }))
        );
        assert_eq!(
            s.slice_release(op(5), 0, &[(g[0].slice_id, u64::MAX)])
                .await
                .expect("release"),
            vec![3],
            "clamped to the grant"
        );
        s.reserve(op(6), 0, &cells).await.expect("headroom back");
    });
}

#[test]
fn a_cap_conflict_names_its_index() {
    let s = open();
    run(async {
        let cap = |c, g| Cap {
            key: requests_key(1_000),
            cap: c,
            config_gen: g,
        };
        s.window_caps(op(1), &[cap(4, 1)]).await.expect("caps");
        assert_eq!(
            s.window_caps(op(2), &[cap(9, 2), cap(5, 2)]).await,
            Err(StoreFailure::CapConflict(1))
        );
    });
}

#[test]
fn metering_and_audit_batches_apply_through_the_typed_surface() {
    let s = open();
    let m = busbar_contract::records::MeteringDelta {
        key_id: "k".into(),
        bucket: 86_400,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 1,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    };
    let a = AuditRecord {
        seq: 1,
        ts: 1,
        action: "a".into(),
        resource: "r".into(),
        outcome: "ok".into(),
        principal: "p".into(),
        prev_hash: String::new(),
        hash: "h".into(),
    };
    run(async {
        s.add_metering_batch(op(1), std::slice::from_ref(&m))
            .await
            .expect("metering");
        s.append_audit_batch(op(2), std::slice::from_ref(&a))
            .await
            .expect("audit");
    });
    assert_eq!(s.list_metering(86_400).expect("list").len(), 1);
    assert_eq!(s.list_audit().expect("list"), vec![a]);
}

#[test]
fn the_ledger_ops_and_sessions_cross_the_typed_surface() {
    let s = open();
    let r = |b: u8| RecordBytes::new(vec![b]).expect("record");
    run(async {
        let h = s
            .append_batch(op(1), "journal", &[r(1), r(2)])
            .await
            .expect("append");
        assert_eq!(h.seq, 2);
        let heads = StoreCalls::heads(&s).await.expect("heads");
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].0, "journal");
        s.session_put(1, "n1", "alice").await.expect("put");
        s.session_put(2, "n2", "alice").await.expect("put");
        assert_eq!(
            s.sessions_for("alice").await.expect("list"),
            vec![(1, "n1".to_string()), (2, "n2".to_string())]
        );
        s.session_remove(1).await.expect("remove");
        assert_eq!(s.sessions_for("alice").await.expect("list").len(), 1);
    });
}

/// One Statement: the memory store's `ephemeral` is the Statement mark `MARK_EPHEMERAL`, carried
/// by the rendering the row states; the store tail it states is the tail without it.
#[test]
fn the_ephemeral_store_states_mark_ephemeral_on_its_statement_not_its_tail() {
    use busbar_contract::abi::mechanism::door::MARK_EPHEMERAL;
    use busbar_contract::abi::mechanism::rendering::read;
    use busbar_contract::abi::store::StoreTail;

    let row = LinkedRow::of(crate::both_ways::store_fixture::door)
        .expect("the memory store states its Statement");
    let st = read(&row.statement).expect("the rendering reads back");
    assert_eq!(st.marks & MARK_EPHEMERAL, MARK_EPHEMERAL);
    assert_eq!(st.kind_tail_size as usize, std::mem::size_of::<StoreTail>());
}
