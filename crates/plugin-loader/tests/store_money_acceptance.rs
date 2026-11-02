// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::records::{
    AuditRecord, MeteringDelta, MeteringRow, ModelTokensDelta, RecordStore, UsageDelta,
    UsageLedger, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};

use busbar_plugin_loader::store_adapter::StoreAdapter;
use std::collections::BTreeMap;
use std::sync::Arc;

include!(concat!(env!("OUT_DIR"), "/store_fixture.rs"));

fn fresh() -> Arc<dyn RecordStore> {
    Arc::from(store_fixture::open("{}").expect("the store opens"))
}

struct Subject {
    door: &'static str,
    store: Arc<dyn RecordStore>,
}

fn subjects() -> Vec<Subject> {
    vec![
        Subject {
            door: "rust type",
            store: fresh(),
        },
        Subject {
            door: "compiled-in table",
            store: Arc::new(v3::compiled_in()),
        },
        Subject {
            door: "adapter",
            store: StoreAdapter::native(Arc::new(v3::compiled_in())).store(),
        },
        Subject {
            door: "dropped-in table",
            store: Arc::new(v3::dropped_in()),
        },
    ]
}

fn delta(requests: i64, billable: i64, model: &str, units: &[(&str, i64)]) -> UsageDelta {
    UsageDelta {
        requests,
        billable_requests: billable,
        models: if units.is_empty() {
            Vec::new()
        } else {
            vec![ModelTokensDelta {
                model: model.to_string(),
                usage_units: units.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            }]
        },
    }
}

fn meter(
    key: &str,
    bucket: u64,
    model: &str,
    provider: &str,
    input: u64,
    reqs: u64,
) -> MeteringDelta {
    MeteringDelta {
        key_id: key.to_string(),
        bucket,
        model: model.to_string(),
        provider: provider.to_string(),
        tokens_input: input,
        tokens_output: input.saturating_mul(2),
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: reqs,
        billable_requests: reqs,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
        usage_units: BTreeMap::new(),
    }
}

fn tier(ledger: &UsageLedger, model: &str, unit: &str) -> u64 {
    ledger
        .models
        .iter()
        .find(|m| m.model == model)
        .map_or(0, |m| m.tier(unit))
}

fn sorted(mut rows: Vec<MeteringRow>) -> Vec<MeteringRow> {
    rows.sort_by(|a, b| {
        (&a.key_id, &a.model, &a.provider, a.priced_from_ms).cmp(&(
            &b.key_id,
            &b.model,
            &b.provider,
            b.priced_from_ms,
        ))
    });
    rows
}

const DAY: u64 = 1_790_000_000 - (1_790_000_000 % 86_400);

#[test]
fn an_untouched_cell_reads_the_empty_ledger() {
    for s in subjects() {
        let got = s.store.get_usage("k-none", DAY).expect("read");
        assert_eq!(got, UsageLedger::default(), "{}", s.door);
    }
}

#[test]
fn add_usage_is_additive_across_flushes() {
    for s in subjects() {
        s.store
            .add_usage("k1", DAY, &delta(2, 2, "m", &[(UNIT_INPUT, 10)]))
            .expect("flush 1");
        s.store
            .add_usage(
                "k1",
                DAY,
                &delta(3, 3, "m", &[(UNIT_INPUT, 5), (UNIT_OUTPUT, 7)]),
            )
            .expect("flush 2");
        let got = s.store.get_usage("k1", DAY).expect("read");
        assert_eq!((got.requests, got.billable_requests), (5, 5), "{}", s.door);
        assert_eq!(tier(&got, "m", UNIT_INPUT), 15, "{}", s.door);
        assert_eq!(tier(&got, "m", UNIT_OUTPUT), 7, "{}", s.door);
    }
}

#[test]
fn nodes_flushing_one_cell_sum_to_the_fleet_total() {
    for s in subjects() {
        for node in 0..3i64 {
            for _ in 0..4 {
                s.store
                    .add_usage("team", DAY, &delta(1, 1, "m", &[(UNIT_OUTPUT, node + 1)]))
                    .expect("flush");
            }
        }
        let got = s.store.get_usage("team", DAY).expect("read");
        assert_eq!(got.requests, 12, "{}", s.door);
        assert_eq!(tier(&got, "m", UNIT_OUTPUT), 4 * (1 + 2 + 3), "{}", s.door);
    }
}

#[test]
fn a_refund_moves_billable_requests_only() {
    for s in subjects() {
        s.store
            .add_usage("k", DAY, &delta(1, 1, "m", &[]))
            .expect("admit");
        s.store
            .add_usage("k", DAY, &delta(0, -1, "m", &[]))
            .expect("refund");
        let got = s.store.get_usage("k", DAY).expect("read");
        assert_eq!((got.requests, got.billable_requests), (1, 0), "{}", s.door);
        assert_eq!(got.total_tokens(), 0, "{} bills no tokens", s.door);
    }
}

#[test]
fn settle_accrues_per_model_and_per_unit() {
    for s in subjects() {
        s.store
            .add_usage(
                "k",
                DAY,
                &delta(
                    1,
                    1,
                    "m-a",
                    &[
                        (UNIT_INPUT, 3),
                        (UNIT_OUTPUT, 4),
                        (UNIT_CACHE_READ, 5),
                        (UNIT_CACHE_WRITE, 6),
                    ],
                ),
            )
            .expect("settle a");
        s.store
            .add_usage(
                "k",
                DAY,
                &delta(1, 1, "m-b", &[(UNIT_INPUT, 100), ("tool_calls", 2)]),
            )
            .expect("settle b");
        let got = s.store.get_usage("k", DAY).expect("read");
        assert_eq!(tier(&got, "m-a", UNIT_CACHE_WRITE), 6, "{}", s.door);
        assert_eq!(tier(&got, "m-b", UNIT_INPUT), 100, "{}", s.door);
        assert_eq!(
            tier(&got, "m-b", "tool_calls"),
            2,
            "{} open class kept",
            s.door
        );
        assert_eq!(got.total_input(), 103, "{}", s.door);
        assert_eq!(
            got.total_tokens(),
            118,
            "{} open class is not a token",
            s.door
        );
    }
}

#[test]
fn a_refund_larger_than_the_balance_floors_at_zero() {
    for s in subjects() {
        s.store
            .add_usage("k", DAY, &delta(1, 1, "m", &[(UNIT_INPUT, 5)]))
            .expect("charge");
        s.store
            .add_usage("k", DAY, &delta(-9, -9, "m", &[(UNIT_INPUT, -50)]))
            .expect("over-refund");
        let got = s.store.get_usage("k", DAY).expect("read");
        assert_eq!((got.requests, got.billable_requests), (0, 0), "{}", s.door);
        assert_eq!(tier(&got, "m", UNIT_INPUT), 0, "{}", s.door);
    }
}

#[test]
fn the_floor_makes_arrival_order_matter() {
    for s in subjects() {
        s.store
            .add_usage("charge-first", DAY, &delta(0, 1, "m", &[]))
            .expect("the charge");
        s.store
            .add_usage("charge-first", DAY, &delta(0, -1, "m", &[]))
            .expect("the refund");
        s.store
            .add_usage("refund-first", DAY, &delta(0, -1, "m", &[]))
            .expect("the refund");
        s.store
            .add_usage("refund-first", DAY, &delta(0, 1, "m", &[]))
            .expect("the charge");
        let a = s.store.get_usage("charge-first", DAY).expect("read");
        let b = s.store.get_usage("refund-first", DAY).expect("read");
        assert_eq!(a.billable_requests, 0, "{}", s.door);
        assert_eq!(b.billable_requests, 1, "{}", s.door);
    }
}

#[test]
fn models_read_back_in_first_seen_order() {
    for s in subjects() {
        for m in ["zeta", "alpha", "mid", "alpha"] {
            s.store
                .add_usage("k", DAY, &delta(0, 0, m, &[(UNIT_INPUT, 1)]))
                .expect("accrue");
        }
        let got = s.store.get_usage("k", DAY).expect("read");
        let order: Vec<&str> = got.models.iter().map(|m| m.model.as_str()).collect();
        assert_eq!(order, ["zeta", "alpha", "mid"], "{}", s.door);
    }
}

#[test]
fn cells_are_independent_per_bucket_and_window() {
    for s in subjects() {
        s.store
            .add_usage("k", DAY, &delta(1, 1, "m", &[]))
            .expect("a");
        s.store
            .add_usage("k", DAY + 86_400, &delta(2, 2, "m", &[]))
            .expect("b");
        s.store
            .add_usage("group:g", DAY, &delta(4, 4, "m", &[]))
            .expect("c");
        let r = |b: &str, w: u64| s.store.get_usage(b, w).expect("read").requests;
        assert_eq!(
            (r("k", DAY), r("k", DAY + 86_400), r("group:g", DAY)),
            (1, 2, 4),
            "{}",
            s.door
        );
    }
}

#[test]
fn put_usage_sets_absolutely_and_add_usage_adds_on_top() {
    for s in subjects() {
        s.store
            .add_usage("k", DAY, &delta(7, 7, "m", &[(UNIT_INPUT, 70)]))
            .expect("a");
        let mut set = UsageLedger::default();
        set.apply_delta(&delta(2, 1, "m", &[(UNIT_INPUT, 20)]));
        s.store.put_usage("k", DAY, &set).expect("set");
        assert_eq!(
            s.store.get_usage("k", DAY).expect("read"),
            set,
            "{}",
            s.door
        );
        s.store
            .add_usage("k", DAY, &delta(1, 1, "m", &[(UNIT_INPUT, 1)]))
            .expect("b");
        let got = s.store.get_usage("k", DAY).expect("read");
        assert_eq!((got.requests, got.billable_requests), (3, 2), "{}", s.door);
        assert_eq!(tier(&got, "m", UNIT_INPUT), 21, "{}", s.door);
    }
}

#[test]
fn one_coalesced_usage_delta_equals_its_singles() {
    for s in subjects() {
        for _ in 0..5 {
            s.store
                .add_usage(
                    "singles",
                    DAY,
                    &delta(1, 1, "m", &[(UNIT_INPUT, 3), (UNIT_OUTPUT, 1)]),
                )
                .expect("single");
        }
        s.store
            .add_usage(
                "coalesced",
                DAY,
                &delta(5, 5, "m", &[(UNIT_INPUT, 15), (UNIT_OUTPUT, 5)]),
            )
            .expect("coalesced");
        assert_eq!(
            s.store.get_usage("singles", DAY).expect("read"),
            s.store.get_usage("coalesced", DAY).expect("read"),
            "{}",
            s.door
        );
    }
}

#[test]
fn usage_counters_saturate_not_wrap() {
    for s in subjects() {
        s.store
            .add_usage(
                "k",
                DAY,
                &delta(i64::MAX, 0, "m", &[(UNIT_INPUT, i64::MAX)]),
            )
            .expect("a");
        s.store
            .add_usage(
                "k",
                DAY,
                &delta(i64::MAX, 0, "m", &[(UNIT_INPUT, i64::MAX)]),
            )
            .expect("b");
        s.store
            .add_usage(
                "k",
                DAY,
                &delta(i64::MAX, 0, "m", &[(UNIT_INPUT, i64::MAX)]),
            )
            .expect("c");
        let got = s.store.get_usage("k", DAY).expect("read");
        assert_eq!(got.requests, u64::MAX, "{}", s.door);
        assert_eq!(tier(&got, "m", UNIT_INPUT), u64::MAX, "{}", s.door);
    }
}

#[test]
fn a_coalesced_metering_delta_counts_every_response() {
    for s in subjects() {
        s.store
            .add_metering(&meter("k", DAY, "m", "p", 30, 3))
            .expect("coalesced");
        s.store
            .add_metering(&meter("k", DAY, "m", "p", 10, 1))
            .expect("single");
        let rows = s.store.list_metering(DAY).expect("list");
        assert_eq!(rows.len(), 1, "{}", s.door);
        let r = &rows[0];
        assert_eq!((r.requests, r.billable_requests), (4, 4), "{}", s.door);
        assert_eq!((r.tokens_input, r.tokens_output), (40, 80), "{}", s.door);
    }
}

#[test]
fn the_metering_cell_is_key_bucket_model_provider() {
    for s in subjects() {
        for d in [
            meter("k", DAY, "m", "p", 1, 1),
            meter("k2", DAY, "m", "p", 1, 1),
            meter("k", DAY, "m2", "p", 1, 1),
            meter("k", DAY, "m", "p2", 1, 1),
            meter("k", DAY, "m", "p", 1, 1),
        ] {
            s.store.add_metering(&d).expect("meter");
        }
        let rows = sorted(s.store.list_metering(DAY).expect("list"));
        let reqs: Vec<(String, String, String, u64)> = rows
            .iter()
            .map(|r| {
                (
                    r.key_id.clone(),
                    r.model.clone(),
                    r.provider.clone(),
                    r.requests,
                )
            })
            .collect();
        let want = |k: &str, m: &str, p: &str, n| (k.to_string(), m.to_string(), p.to_string(), n);
        assert_eq!(
            reqs,
            vec![
                want("k", "m", "p", 2),
                want("k", "m", "p2", 1),
                want("k", "m2", "p", 1),
                want("k2", "m", "p", 1)
            ],
            "{}",
            s.door
        );
    }
}

#[test]
fn a_rate_card_edit_splits_the_metering_day() {
    for s in subjects() {
        let mut after = meter("k", DAY, "m", "p", 5, 1);
        after.priced_from_ms = 1_790_040_000_000;
        s.store
            .add_metering(&meter("k", DAY, "m", "p", 5, 1))
            .expect("before");
        s.store.add_metering(&after).expect("after");
        s.store.add_metering(&after).expect("after again");
        let rows = sorted(s.store.list_metering(DAY).expect("list"));
        let got: Vec<(u64, u64)> = rows
            .iter()
            .map(|r| (r.priced_from_ms, r.requests))
            .collect();
        assert_eq!(got, vec![(0, 1), (1_790_040_000_000, 2)], "{}", s.door);
    }
}

#[test]
fn metering_rows_keep_each_groups_and_versions_counts() {
    for s in subjects() {
        let mut first = meter("k", DAY, "m", "p", 1, 1);
        first.key_group_at_use = "g-old".into();
        first.pricing_version = "v1".into();
        first.usage_units.insert("audio".into(), 2);
        let mut regrouped = first.clone();
        regrouped.key_group_at_use = "g-new".into();
        let mut versioned = first.clone();
        versioned.pricing_version = "v2".into();
        let mut unknown = first.clone();
        unknown.key_group_at_use.clear();
        unknown.pricing_version.clear();
        for delta in [&first, &regrouped, &versioned, &unknown, &first] {
            s.store.add_metering(delta).expect("metering");
        }
        let rows = s.store.list_metering(DAY).expect("list");
        assert_eq!(rows.len(), 4, "{}", s.door);
        let counts: std::collections::BTreeMap<_, _> = rows
            .into_iter()
            .map(|row| {
                (
                    (row.key_group_at_use, row.pricing_version),
                    (row.requests, row.usage_units["audio"]),
                )
            })
            .collect();
        assert_eq!(
            counts,
            [
                (("g-old".into(), "v1".into()), (2, 4)),
                (("g-new".into(), "v1".into()), (1, 2)),
                (("g-old".into(), "v2".into()), (1, 2)),
                ((String::new(), String::new()), (1, 2)),
            ]
            .into(),
            "{}",
            s.door
        );
    }
}

#[test]
fn list_metering_answers_only_the_bucket_asked() {
    for s in subjects() {
        s.store
            .add_metering(&meter("k", DAY, "m", "p", 1, 1))
            .expect("today");
        s.store
            .add_metering(&meter("k", DAY + 86_400, "m", "p", 1, 1))
            .expect("tomorrow");
        assert_eq!(
            s.store.list_metering(DAY).expect("list").len(),
            1,
            "{}",
            s.door
        );
        assert_eq!(
            s.store.list_metering(DAY + 1).expect("list").len(),
            0,
            "{}",
            s.door
        );
    }
}

#[test]
fn metering_counters_add_and_saturate() {
    for s in subjects() {
        let mut big = meter("k", DAY, "m", "p", u64::MAX, 1);
        big.usage_units.insert("tool_calls".into(), u64::MAX - 1);
        let mut small = meter("k", DAY, "m", "p", 1, 1);
        small.usage_units.insert("tool_calls".into(), 5);
        s.store.add_metering(&big).expect("big");
        s.store.add_metering(&small).expect("small");
        let r = &s.store.list_metering(DAY).expect("list")[0];
        assert_eq!(r.tokens_input, u64::MAX, "{}", s.door);
        assert_eq!(
            r.usage_units.get("tool_calls"),
            Some(&u64::MAX),
            "{}",
            s.door
        );
        assert_eq!(r.requests, 2, "{}", s.door);
    }
}

#[test]
fn a_1_5_5_metering_row_reads_the_same_counts() {
    let v155 = r#"{"key_id":"k","model":"m","provider":"p","tokens_input":1,"tokens_output":2,"tokens_cache_read":3,"tokens_cache_write":4,"requests":5,"billable_requests":4,"key_group_at_use":"g","pricing_version":"v"}"#;
    let r: MeteringRow = serde_json::from_str(v155).expect("a 1.5.5 row decodes");
    assert_eq!(
        (
            r.tokens_input,
            r.tokens_output,
            r.tokens_cache_read,
            r.tokens_cache_write,
            r.requests,
            r.billable_requests
        ),
        (1, 2, 3, 4, 5, 4)
    );
    assert_eq!((r.priced_from_ms, r.usage_units.len()), (0, 0));
}

#[test]
fn an_audit_record_round_trips_byte_identical_to_1_5_5() {
    let v155 = r#"{"seq":1,"ts":1790000000,"action":"key.create","resource":"key:k","outcome":"applied","principal":"admin","prev_hash":"","hash":"ab12"}"#;
    let rec: AuditRecord = serde_json::from_str(v155).expect("a 1.5.5 record decodes");
    assert_eq!(serde_json::to_string(&rec).expect("encode"), v155);
}

fn field_names(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, child) in m {
                out.push(k.clone());
                if k != "usage_units" {
                    field_names(child, out);
                }
            }
        }
        serde_json::Value::Array(a) => a.iter().for_each(|c| field_names(c, out)),
        _ => {}
    }
}

fn money_record_fields() -> Vec<String> {
    let mut ledger = UsageLedger::default();
    ledger.apply_delta(&delta(1, 1, "m", &[(UNIT_INPUT, 1), ("tool_calls", 1)]));
    let mut md = meter("k", DAY, "m", "p", 1, 1);
    md.usage_units.insert("tool_calls".into(), 1);
    md.key_group_at_use = "g".into();
    md.pricing_version = "v".into();
    let row: MeteringRow =
        serde_json::from_value(serde_json::to_value(&md).expect("enc")).expect("dec");
    let mut out = Vec::new();
    for v in [
        serde_json::to_value(&ledger),
        serde_json::to_value(delta(1, 1, "m", &[(UNIT_INPUT, 1)])),
        serde_json::to_value(&md),
        serde_json::to_value(&row),
    ] {
        field_names(&v.expect("encode"), &mut out);
    }
    out
}

#[test]
fn money_records_carry_counts_never_a_price() {
    const PRICE: &[&str] = &[
        "spend", "price", "priced", "amount", "cents", "nanos", "micros", "dollar", "usd", "cost",
        "fee",
    ];
    const ALLOW: &[&str] = &["pricing_version", "priced_from_ms", "fee_count"];
    let bad: Vec<String> = money_record_fields()
        .into_iter()
        .filter(|f| !ALLOW.contains(&f.as_str()) && PRICE.iter().any(|t| f.contains(t)))
        .collect();
    assert!(bad.is_empty(), "stored price field(s): {bad:?}");
}

#[test]
fn money_records_name_no_plugin_or_plane() {
    let bad: Vec<String> = money_record_fields()
        .into_iter()
        .filter(|f| f.contains("plugin") || f.contains("plane"))
        .collect();
    assert!(bad.is_empty(), "plugin-keyed money field(s): {bad:?}");
}

#[test]
fn the_adapter_passes_money_through_to_the_loaded_store() {
    let inner = fresh();
    let a = StoreAdapter::native(inner.clone());
    a.store()
        .add_usage("k", DAY, &delta(2, 1, "m", &[(UNIT_OUTPUT, 9)]))
        .expect("usage");
    a.store()
        .add_metering(&meter("k", DAY, "m", "p", 4, 2))
        .expect("meter");
    let got = inner.get_usage("k", DAY).expect("read");
    assert_eq!(
        (
            got.requests,
            got.billable_requests,
            tier(&got, "m", UNIT_OUTPUT)
        ),
        (2, 1, 9)
    );
    assert_eq!(inner.list_metering(DAY).expect("list")[0].requests, 2);
}

mod v3 {
    use std::sync::Arc;

    use super::store_fixture;
    use busbar_contract::records::{
        MeteringDelta, MeteringRow, RecordStore, UsageDelta, UsageLedger,
    };
    use busbar_contract::store_calls::{StoreCalls, StoreFailure};
    use busbar_plugin_loader::dispatch::kinds::store::{Store, StoreFacts};
    use busbar_plugin_loader::dispatch::{
        load_dropped, load_linked, rendering_of, Bind, DispatchConfig, Dispatcher, LinkedRow,
        NoSink,
    };
    use busbar_plugin_loader::store_v3::LoadedStore;

    pub use busbar_contract::abi::store::OpId;

    fn mint() -> OpId {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        OpId::from_parts(
            0x3a11,
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
        )
    }

    fn bind_to(d: &Dispatcher) -> Bind {
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 1024,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
        }
    }

    pub fn compiled_in() -> LoadedStore {
        let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let row = LinkedRow::of(store_fixture::door).expect("the store states its Statement");
        let p = load_linked::<Store>(&row, bind_to(&d)).expect("door");
        LoadedStore::open(p, d, b"{}", mint).expect("open")
    }

    pub fn dropped_in() -> LoadedStore {
        let exe = std::env::current_exe().expect("the test binary's path");
        let name = format!(
            "{}store_v3_door{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        );
        let path = exe
            .parent()
            .and_then(|deps| deps.parent())
            .expect("the test binary sits in <profile>/deps")
            .join("examples")
            .join(name);
        if !path.exists() {
            panic!(
                "the store_v3_door cdylib is not built: run \
                 `cargo build -p busbar-plugin-loader --examples` first (a both-ways proof never skips)"
            );
        }
        let d = Arc::new(Dispatcher::new(DispatchConfig::default()));

        let stated = rendering_of(store_fixture::door).expect("the store renders its Statement");
        let p = load_dropped::<Store>(&path, &stated, bind_to(&d)).expect("dropped door");
        LoadedStore::open(p, d, b"{}", mint).expect("open")
    }

    pub struct Bound {
        pub store: LoadedStore,
        rt: tokio::runtime::Runtime,
    }

    pub fn bind() -> Bound {
        Bound {
            store: compiled_in(),
            rt: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime"),
        }
    }

    impl Bound {
        pub fn facts(&self) -> StoreFacts {
            self.store.facts()
        }
        pub fn add_usage_batch(
            &self,
            op: OpId,
            cells: &[(&str, u64, UsageDelta)],
        ) -> Result<(), StoreFailure> {
            self.rt.block_on(self.store.add_usage_batch(op, cells))
        }
        pub fn add_metering_batch(
            &self,
            op: OpId,
            rows: &[MeteringDelta],
        ) -> Result<(), StoreFailure> {
            self.rt.block_on(self.store.add_metering_batch(op, rows))
        }
        pub fn get_usage(&self, bucket: &str, window: u64) -> UsageLedger {
            RecordStore::get_usage(&self.store, bucket, window).expect("get_usage")
        }
        pub fn list_metering(&self, bucket: u64) -> Vec<MeteringRow> {
            RecordStore::list_metering(&self.store, bucket).expect("list_metering")
        }

        pub fn restart(self) -> Bound {
            assert!(
                self.facts().ephemeral,
                "a durable store restarts onto its own rows"
            );
            bind()
        }
    }
}

use busbar_contract::store_calls::StoreFailure;

fn op(n: u8) -> v3::OpId {
    v3::OpId([n; 16])
}

#[test]
fn v3_a_duplicate_usage_batch_applies_once() {
    let s = v3::bind();
    let batch = [
        ("k", DAY, delta(1, 1, "m", &[(UNIT_INPUT, 10)])),
        ("g", DAY, delta(1, 1, "m", &[])),
    ];
    assert_eq!(s.add_usage_batch(op(1), &batch), Ok(()));
    assert_eq!(
        s.add_usage_batch(op(1), &batch),
        Ok(()),
        "the original answer"
    );
    assert_eq!(s.get_usage("k", DAY).requests, 1);
    assert_eq!(tier(&s.get_usage("k", DAY), "m", UNIT_INPUT), 10);
    assert_eq!(s.get_usage("g", DAY).requests, 1);
}

#[test]
fn v3_a_duplicate_usage_batch_applies_once_after_restart() {
    let s = v3::bind();
    assert!(
        s.facts().ephemeral,
        "the fixture store states it keeps nothing across a restart"
    );
    let batch = [("k", DAY, delta(1, 1, "m", &[(UNIT_OUTPUT, 3)]))];
    assert_eq!(s.add_usage_batch(op(2), &batch), Ok(()));
    assert_eq!(s.add_usage_batch(op(2), &batch), Ok(()));
    assert_eq!(s.get_usage("k", DAY).requests, 1);
    let s = s.restart();
    assert_eq!(
        s.get_usage("k", DAY).requests,
        0,
        "ephemeral: nothing survives"
    );
    assert_eq!(s.add_usage_batch(op(2), &batch), Ok(()));
    assert_eq!(s.add_usage_batch(op(2), &batch), Ok(()));
    assert_eq!(s.get_usage("k", DAY).requests, 1);
}

#[test]
fn v3_equal_bodies_under_distinct_op_ids_both_apply() {
    let s = v3::bind();
    let batch = [("k", DAY, delta(2, 2, "m", &[(UNIT_INPUT, 4)]))];
    assert_eq!(s.add_usage_batch(op(3), &batch), Ok(()));
    assert_eq!(s.add_usage_batch(op(4), &batch), Ok(()));
    assert_eq!(s.get_usage("k", DAY).requests, 4);
}

#[test]
fn v3_a_reused_op_id_with_another_body_is_refused() {
    let s = v3::bind();
    let a = [("k", DAY, delta(1, 1, "m", &[]))];
    let b = [("k", DAY, delta(7, 7, "m", &[]))];
    assert_eq!(s.add_usage_batch(op(20), &a), Ok(()));
    assert_eq!(s.add_usage_batch(op(20), &b), Err(StoreFailure::Conflict));
    assert_eq!(s.get_usage("k", DAY).requests, 1);
}

#[test]
fn v3_a_batch_applies_its_cells_in_order() {
    let s = v3::bind();
    let batch = [
        ("k", DAY, delta(0, -1, "m", &[])),
        ("k", DAY, delta(0, 1, "m", &[])),
    ];
    s.add_usage_batch(op(5), &batch).expect("batch");
    assert_eq!(s.get_usage("k", DAY).billable_requests, 1);
}

#[test]
fn v3_a_duplicate_metering_batch_applies_once_after_restart() {
    let s = v3::bind();
    let rows = [
        meter("k", DAY, "m", "p", 30, 3),
        meter("k", DAY, "m", "p2", 1, 1),
    ];
    assert_eq!(s.add_metering_batch(op(6), &rows), Ok(()));
    assert_eq!(s.add_metering_batch(op(6), &rows), Ok(()));
    let total = |s: &v3::Bound| -> u64 { s.list_metering(DAY).iter().map(|r| r.requests).sum() };
    assert_eq!(total(&s), 4);
    let s = s.restart();
    assert_eq!(s.add_metering_batch(op(6), &rows), Ok(()));
    assert_eq!(s.add_metering_batch(op(6), &rows), Ok(()));
    assert_eq!(total(&s), 4);
}
