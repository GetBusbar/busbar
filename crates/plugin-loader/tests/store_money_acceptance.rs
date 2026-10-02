// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE MONEY ACCEPTANCE SUITE: the store kind's money contract.
//!
//! Written BEFORE the store v3 table exists, as the contract its implementer must meet. Every
//! money-relevant store behaviour has a test here:
//!
//! - **Runs today** against the build's store on every door it has — the
//!   LINKED row, the DROPPED-IN cdylib over the C ABI, and the store adapter the root binds — and
//!   against the adapter's node-local slice shim. These pin what 1.5.5 did and 1.6.0 must keep.
//! - **The store v3 money slots** (`v3_*`), through the store v3 table on the build's store's
//!   compiled-in door ([`v3::bind`]): `op_id` dedupe on the coalesced batches, `reserve` with its
//!   fixed cells (`UnitCell`, the ruled `bb_units[]`), the window caps, `slice_release` and the
//!   epoch. The wire has no "duplicate" answer (a replay answers the ORIGINAL answer), so a
//!   replay is asserted as the same answer with the counts unchanged; what a slice still holds is
//!   read through `reserve` against the window's cap; the memory store is EPHEMERAL (its tail says
//!   so), so the restart and stale-epoch arms assert that statement, and the durable arm is the
//!   store conformance suite's, run by the durable siblings (ARCHITECT rulings Q4 and M4c,
//!   2026-09-29).
//!
//! The 1.5.5 source these pin is cited per test (`v1.5.5:crates/busbar/src/governance/state.rs`
//! `flush_metering`/`record_metering`, `v1.5.5:crates/api/src/store.rs`, `v1.5.5:crates/store-memory`).
//! The money invariants are the `money-invariants` gate rows (`xtask/src/gates/money_invariants.rs`):
//! `:no-stored-price` (#77(3)), `:no-plugin-keyed-money` (#77(1)); `:single-seal-site` (#77(2)) is a
//! kernel-crate rule the store has no surface for, so it is not restated here.

use busbar_contract::records::{
    AuditRecord, MeteringDelta, MeteringRow, ModelTokensDelta, RecordStore, UsageDelta,
    UsageLedger, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};
// The build's store, named once: every subject below reaches it through this alias.
use busbar_contract::slice::{bucket_all, CapDimension, Epoch, SliceId, SliceRequest, SliceStore};
use busbar_plugin_loader::store_adapter::StoreAdapter;
use fixture::store_fixture;
use std::collections::BTreeMap;
use std::sync::Arc;
use store_fixture::MemoryStore;

/// The build's store, reached by KIND: `Cargo.toml`'s `[package.metadata.busbar.both-ways]` row
/// `store`, alone (`build.rs` writes `fixture_store.rs`). No source here names the instance.
mod fixture {
    include!(concat!(env!("OUT_DIR"), "/fixture_store.rs"));
}

// ── subjects: every door the build's store has ─────────────────────────────────────────────────

/// One store under test, named for the door it was reached through.
struct Subject {
    door: &'static str,
    store: Arc<dyn RecordStore>,
}

/// The dropped-in cdylib of the build's store, if built (a scoped `cargo test -p` builds it as this
/// crate's dev-dependency). Under CI a missing artifact is a failure, never a silent skip.
fn dropped_in() -> Option<Arc<dyn RecordStore>> {
    let exe = std::env::current_exe().ok()?;
    let profile_dir = exe.parent()?.parent()?;
    let name = format!(
        "{}{}{}",
        std::env::consts::DLL_PREFIX,
        fixture::STORE_FIXTURE_CDYLIB,
        std::env::consts::DLL_SUFFIX
    );
    let found = [
        profile_dir.join(&name),
        profile_dir.join("deps").join(&name),
    ]
    .into_iter()
    .filter(|p| p.exists())
    .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
    let Some(path) = found else {
        assert!(
            std::env::var_os("CI").is_none(),
            "the store's dropped-in cdylib ({name}) is not built under CI; refusing to skip the \
             over-the-ABI leg of the money suite"
        );
        return None;
    };
    let bytes = std::fs::read(&path).expect("read the store's cdylib");
    let store = busbar_plugin_loader::load_store_from_bytes_at_abi(
        &bytes,
        "{}",
        "money-acceptance",
        "store",
        busbar_contract::abi::cold::ABI_VERSION,
    )
    .expect("load the store's dropped-in door");
    Some(Arc::from(store))
}

/// A FRESH store on every door: its Rust type, the compiled-in door through the store v3 table,
/// the root's adapter over that, the dropped-in door through the same table, and (until M6: the cold ABI's deletion) the legacy
/// cold dropped-in door.
fn subjects() -> Vec<Subject> {
    let mut all = vec![
        Subject {
            door: "rust type",
            store: Arc::new(MemoryStore::new()),
        },
        Subject {
            door: "compiled-in table",
            store: Arc::new(v3::compiled_in()),
        },
        Subject {
            door: "adapter",
            store: StoreAdapter::native(Arc::new(v3::compiled_in())).store(),
        },
    ];
    if let Some(store) = v3::dropped_in() {
        all.push(Subject {
            door: "dropped-in table",
            store: Arc::new(store),
        });
    }
    if let Some(store) = dropped_in() {
        all.push(Subject {
            door: "cold dropped-in, legacy",
            store,
        });
    }
    all
}

// ── builders ───────────────────────────────────────────────────────────────────────────────────

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

// ── usage ledger: reserve (admission) / settle (accrual) / refund, per cell ────────────────────

/// 1.5.5 `Store::get_usage`: an untouched (bucket, window) reads as the empty ledger, not an error.
#[test]
fn an_untouched_cell_reads_the_empty_ledger() {
    for s in subjects() {
        let got = s.store.get_usage("k-none", DAY).expect("read");
        assert_eq!(got, UsageLedger::default(), "{}", s.door);
    }
}

/// 1.5.5 `flush_budgets`: each flush sends only the delta since the acked baseline, so two flushes
/// of one cell must SUM on the store.
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

/// `RecordStore::add_usage` doc: the FLEET-HONEST primitive — N nodes flushing interleaved deltas
/// into one cell read back the fleet total, never last-writer-wins.
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

/// 1.5.5 `BudgetCell`: admission charges `requests` AND `billable_requests`; a non-2xx refund
/// decrements ONLY `billable_requests` (`refund_bucket`). The store must carry the two counters
/// independently — `requests` is never refunded (the requests-cap truth). abi-brief M3: a
/// translate-abort is never billed and the budget unit refunds separately; at the store that is
/// exactly this admit-then-refund pair with no token accrual.
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

/// Settle: provider-reported usage accrues per (model, unit), each tier separately, open classes
/// beside the reserved four, and models never merge.
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

/// 1.5.5 `apply_delta` (`saturating_add_signed`): a refund can never drive a durable counter
/// negative — every counter floors at 0, independently.
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

/// ORDERING (1.5.5): because the floor clips at apply time, deltas do NOT commute across it. A
/// refund that lands before its charge is eaten by the floor; the charge then stands. The store
/// applies in arrival order and must not reorder or net deltas itself.
#[test]
fn the_floor_makes_arrival_order_matter() {
    for s in subjects() {
        s.store
            .add_usage("charge-first", DAY, &delta(0, 1, "m", &[]))
            .expect("c");
        s.store
            .add_usage("charge-first", DAY, &delta(0, -1, "m", &[]))
            .expect("r");
        s.store
            .add_usage("refund-first", DAY, &delta(0, -1, "m", &[]))
            .expect("r");
        s.store
            .add_usage("refund-first", DAY, &delta(0, 1, "m", &[]))
            .expect("c");
        let a = s.store.get_usage("charge-first", DAY).expect("read");
        let b = s.store.get_usage("refund-first", DAY).expect("read");
        assert_eq!(a.billable_requests, 0, "{}", s.door);
        assert_eq!(b.billable_requests, 1, "{}", s.door);
    }
}

/// 1.5.5 `apply_model_delta`: a model is appended on first sight, so `models` reads back in
/// first-seen order (the ledger is a Vec, and consumers iterate it).
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

/// The cell is (bucket, window): neither axis bleeds into another cell.
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

/// `put_usage` is the absolute single-writer set; `add_usage` after it accumulates on top.
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

/// COALESCING (1.5.5 `flush_budgets`): a busy cell's many responses leave the node as ONE delta per
/// flush. One coalesced delta must land exactly as the N single deltas it stands for.
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

/// Counters saturate at `u64::MAX`; they never wrap to a small balance.
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

// ── metering: the billing ledger, coalesced per cell ───────────────────────────────────────────

/// 1.5.5 `record_metering` + `flush_metering`: responses coalesce per (key, day-bucket, model,
/// provider) and leave as ONE `MeteringDelta` whose `requests` is the response count. The store
/// adds it whole: the row counts every response, not one per delta.
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

/// The metering cell key is (key, bucket, model, provider): any one differing opens its own row.
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

/// DECISION #79 (1.6.0, signed): a rate-card edit inside a day SPLITS the day's cell at the edit.
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

/// 1.5.5 `MemoryStore::add_metering` (`or_insert_with`): the row's `key_group_at_use` and
/// `pricing_version` are the FIRST delta's; later deltas add counts and never rewrite them.
#[test]
fn a_metering_row_keeps_its_first_group_and_pricing_version() {
    for s in subjects() {
        let mut first = meter("k", DAY, "m", "p", 1, 1);
        first.key_group_at_use = "g-old".into();
        first.pricing_version = "v1".into();
        let mut later = first.clone();
        later.key_group_at_use = "g-new".into();
        later.pricing_version = "v2".into();
        s.store.add_metering(&first).expect("first");
        s.store.add_metering(&later).expect("later");
        let rows = s.store.list_metering(DAY).expect("list");
        assert_eq!(rows.len(), 1, "{}", s.door);
        assert_eq!(
            (
                rows[0].key_group_at_use.as_str(),
                rows[0].pricing_version.as_str()
            ),
            ("g-old", "v1"),
            "{}",
            s.door
        );
        assert_eq!(rows[0].requests, 2, "{}", s.door);
    }
}

/// `list_metering(bucket)` answers exactly that day and nothing adjacent.
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

/// Every metering counter, open classes included, is additive and saturates rather than wraps.
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

// ── 1.5.5 records ──────────────────────────────────────────────────────────────────────────────

/// A metering row exactly as 1.5.5 persisted it decodes with the same counts, dated at the opening
/// card (`priced_from_ms` 0) and with no open classes.
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

/// The audit record shape is unchanged since 1.5.5: bytes in are bytes out, on every door, so a
/// hash chain written by 1.5.5 verifies after the upgrade.
#[test]
fn an_audit_record_round_trips_byte_identical_to_1_5_5() {
    let v155 = r#"{"seq":1,"ts":1790000000,"action":"key.create","resource":"key:k","outcome":"applied","principal":"admin","prev_hash":"","hash":"ab12"}"#;
    let rec: AuditRecord = serde_json::from_str(v155).expect("a 1.5.5 record decodes");
    for s in subjects() {
        s.store.append_audit(&rec).expect("append");
        let back = s.store.list_audit().expect("list");
        assert_eq!(back.len(), 1, "{}", s.door);
        assert_eq!(
            serde_json::to_string(&back[0]).expect("encode"),
            v155,
            "{}",
            s.door
        );
    }
}

// ── money invariants (money-invariants gate rows, held at runtime over what the store carries) ──

/// The JSON field names a record serializes to, recursively (map KEYS under `usage_units` are data,
/// not fields, so maps are not descended).
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

/// Every money record the store carries, fully populated.
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

/// `money-invariants:no-stored-price` (#77(3)): the store carries RAW COUNTS only; no money record
/// field is a price/spend/amount figure. Token and allow lists are the gate's own.
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

/// `money-invariants:no-plugin-keyed-money` (#77(1)): no money record field names a plugin or plane.
#[test]
fn money_records_name_no_plugin_or_plane() {
    let bad: Vec<String> = money_record_fields()
        .into_iter()
        .filter(|f| f.contains("plugin") || f.contains("plane"))
        .collect();
    assert!(bad.is_empty(), "plugin-keyed money field(s): {bad:?}");
}

// ── slices through the adapter the root binds (today: the node-local shim) ────────────────────

fn slice(wanted: u64, epoch: u64) -> SliceRequest {
    SliceRequest {
        bucket: bucket_all("team-a"),
        dimension: CapDimension::Requests,
        wanted,
        epoch: Epoch(epoch),
    }
}

/// Reserve grants at most what was wanted; `release` gives back the unspent part, and the adapter's
/// net holding is granted minus what came back.
#[test]
fn reserve_grants_at_most_wanted_and_release_returns_the_unspent() {
    let a = StoreAdapter::native(Arc::new(MemoryStore::new()));
    let g1 = a.reserve(&slice(100, 0)).expect("reserve");
    let g2 = a.reserve(&slice(50, 0)).expect("reserve");
    assert!(g1.granted <= 100 && g2.granted <= 50);
    assert_ne!(g1.id, g2.id, "each reservation is its own slice");
    assert_eq!(a.shim_state().slices_granted, g1.granted + g2.granted);
    a.release(g1.id, 40).expect("release");
    assert_eq!(a.shim_state().slices_outstanding, 1);
    assert_eq!(a.shim_state().slices_granted, g1.granted + g2.granted - 40);
}

/// Money invariant: a release can never hand back more than its slice was granted, and a second
/// release of the same slice moves nothing (it is already closed).
#[test]
fn release_is_clamped_to_the_grant_and_closes_the_slice() {
    let a = StoreAdapter::native(Arc::new(MemoryStore::new()));
    let keep = a.reserve(&slice(30, 0)).expect("reserve");
    let g = a.reserve(&slice(10, 0)).expect("reserve");
    a.release(g.id, 1_000).expect("over-release");
    assert_eq!(a.shim_state().slices_granted, keep.granted);
    a.release(g.id, 5).expect("second release");
    assert_eq!(a.shim_state().slices_granted, keep.granted);
}

/// A release naming a slice this adapter never granted is accepted and moves nothing.
#[test]
fn releasing_an_unknown_slice_moves_nothing() {
    let a = StoreAdapter::native(Arc::new(MemoryStore::new()));
    let g = a.reserve(&slice(7, 0)).expect("reserve");
    a.release(SliceId(g.id.0 + 999), 7)
        .expect("unknown release");
    assert_eq!(a.shim_state().slices_granted, g.granted);
    assert_eq!(a.shim_state().slices_outstanding, 1);
}

/// The adapter's published money ops reach the ONE loaded store: a flush through the adapter is
/// read back from the store itself, figure for figure.
#[test]
fn the_adapter_passes_money_through_to_the_loaded_store() {
    let inner = Arc::new(MemoryStore::new());
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

/// Record blobs are opaque to the store (unit-map shapes plus the scale marker are
/// the KERNEL's encoding): whatever bytes go in come back exactly, by key and by prefix scan.
#[test]
fn a_record_blob_comes_back_byte_exact() {
    use busbar_contract::ids::RecordSchemaId;
    use busbar_contract::kinds::RecordBytes;
    const SCHEMA: RecordSchemaId = RecordSchemaId::new("money_acceptance");
    let blob = br#"{"scale":6,"units":{"input":27500000,"output":1}}"#.to_vec();
    let s = MemoryStore::new();
    let body = RecordBytes::new(blob.clone()).expect("inside the record ceiling");
    s.record_put(SCHEMA, b"cell/k/1", &body).expect("put");
    let got = s
        .record_get(SCHEMA, b"cell/k/1")
        .expect("get")
        .expect("present");
    assert_eq!(got.as_slice(), blob.as_slice());
    let scan = s.record_scan(SCHEMA, b"cell/k/", 10).expect("scan");
    assert_eq!(scan.len(), 1);
    assert_eq!(scan[0].1.as_slice(), blob.as_slice());
}

// ── store v3: the money slots through the table ────────────────────────────────────────────────

/// The store v3 money slots, bound to the build's store through the ONE loader and the store v3
/// table (M3 store table; m3-inputs "store v3 money slots").
mod v3 {
    use std::sync::Arc;

    use super::store_fixture;
    use busbar_contract::abi::sdk::store::{Cap, Cell, CellKey, Dimension, Grant};
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

    /// This test process's `op_id` allocator: one counter, as the kernel's `door::op_id` is.
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
            conns: None,
        }
    }

    /// The build's store through its compiled-in door.
    pub fn compiled_in() -> LoadedStore {
        let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let row = LinkedRow::of(store_fixture::door).expect("the store states its Statement");
        let p = load_linked::<Store>(&row, bind_to(&d)).expect("door");
        LoadedStore::open(p, d, b"{}", mint).expect("open")
    }

    /// The same door dropped in (the `store_v3_door` example cdylib) through the same table;
    /// `None` in a scoped non-CI run without it.
    pub fn dropped_in() -> Option<LoadedStore> {
        let exe = std::env::current_exe().ok()?;
        let name = format!(
            "{}store_v3_door{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        );
        let path = exe.parent()?.parent()?.join("examples").join(name);
        if !path.exists() {
            assert!(
                std::env::var_os("CI").is_none(),
                "the store's door cdylib is not built under CI; refusing to skip the dropped-in table"
            );
            return None;
        }
        let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
        // The signed manifest's rendering: the linked rlib's door, the same crate the cdylib is.
        let stated = rendering_of(store_fixture::door).expect("the store renders its Statement");
        let p = load_dropped::<Store>(&path, &stated, bind_to(&d)).expect("dropped door");
        Some(LoadedStore::open(p, d, b"{}", mint).expect("open"))
    }

    /// The window every `v3_*` test draws in (ms), and its bucket.
    pub const WINDOW: u64 = 1_790_000_000_000;

    /// A requests cell of `bucket` in [`WINDOW`].
    pub fn requests(bucket: &'static str) -> CellKey<'static> {
        CellKey {
            bucket,
            pool: None,
            dimension: Dimension::Requests,
            window_start: WINDOW,
        }
    }

    /// One store, bound, with a runtime to await its calls on.
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
        pub fn cap(&self, op: OpId, key: CellKey<'_>, cap: u64) {
            self.rt
                .block_on(self.store.window_caps(
                    op,
                    &[Cap {
                        key,
                        cap,
                        config_gen: 1,
                    }],
                ))
                .expect("window_caps");
        }
        pub fn reserve(
            &self,
            op: OpId,
            epoch: u64,
            cells: &[Cell<'_>],
        ) -> Result<Vec<Grant>, StoreFailure> {
            self.rt.block_on(self.store.reserve(op, epoch, cells))
        }
        pub fn slice_release(
            &self,
            op: OpId,
            items: &[(u64, u64)],
        ) -> Result<Vec<u64>, StoreFailure> {
            self.rt.block_on(self.store.slice_release(op, 0, items))
        }
        /// Close and reopen: a process restart. The memory store states it is ephemeral, so the
        /// reopened store holds nothing, its dedupe log included.
        pub fn restart(self) -> Bound {
            assert!(
                self.facts().ephemeral,
                "a durable store restarts onto its own rows"
            );
            bind()
        }
    }
}

use busbar_contract::abi::sdk::store::{Cell, ReserveRefused};
use busbar_contract::store_calls::StoreFailure;

fn op(n: u8) -> v3::OpId {
    v3::OpId([n; 16])
}

fn draw(bucket: &'static str, amount: u64) -> [Cell<'static>; 1] {
    [Cell {
        key: v3::requests(bucket),
        amount,
    }]
}

/// A duplicate batch (a flush retried after a lost ack) applies ONCE — every cell in it. 1.5.5 was
/// at-least-once here (`BudgetCell.flushed_requests` doc: a lost ack double-counts one interval);
/// the op_id makes it exactly-once. The replay answers what the first call answered.
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

/// Dedupe is DURABLE on a durable store. The memory store states it is EPHEMERAL: a restart loses
/// every row and the dedupe log together, so a replay after it applies onto the empty store it
/// left, once. (The durable arm is the store conformance suite's, per durable sibling.)
#[test]
fn v3_a_duplicate_usage_batch_applies_once_after_restart() {
    let s = v3::bind();
    assert!(
        s.facts().ephemeral,
        "the memory store states it keeps nothing across a restart"
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

/// Dedupe keys on the op_id, never the body: two flushes that happen to carry identical coalesced
/// deltas are two flushes, and both count.
#[test]
fn v3_equal_bodies_under_distinct_op_ids_both_apply() {
    let s = v3::bind();
    let batch = [("k", DAY, delta(2, 2, "m", &[(UNIT_INPUT, 4)]))];
    assert_eq!(s.add_usage_batch(op(3), &batch), Ok(()));
    assert_eq!(s.add_usage_batch(op(4), &batch), Ok(()));
    assert_eq!(s.get_usage("k", DAY).requests, 4);
}

/// The same op_id with a DIFFERENT body is never applied: REFUSED with `STORE_OPID_CONFLICT`.
#[test]
fn v3_a_reused_op_id_with_another_body_is_refused() {
    let s = v3::bind();
    let a = [("k", DAY, delta(1, 1, "m", &[]))];
    let b = [("k", DAY, delta(7, 7, "m", &[]))];
    assert_eq!(s.add_usage_batch(op(20), &a), Ok(()));
    assert_eq!(s.add_usage_batch(op(20), &b), Err(StoreFailure::Conflict));
    assert_eq!(s.get_usage("k", DAY).requests, 1);
}

/// Cells inside one batch apply in batch order, so the 1.5.5 floor behaves exactly as it does for
/// single deltas (see `the_floor_makes_arrival_order_matter`).
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

/// Metering batches dedupe the same way, and a coalesced row still counts every response it
/// carries. Ephemeral: after a restart the replay applies onto the empty store, once.
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

/// Reserve carries fixed cells (`UnitCell`, the ruled `bb_units[]`) and grants each cell's WHOLE
/// amount (S5, 1.5.5 never granted part of a draw); what is drawn holds the window's headroom.
#[test]
fn v3_reserve_grants_at_most_wanted_per_unit() {
    let s = v3::bind();
    s.cap(op(100), v3::requests("k"), 10);
    let g = s.reserve(op(7), 0, &draw("k", 6)).expect("reserve");
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].granted, 6, "the whole amount, never part of it");
    assert_eq!(
        s.reserve(op(8), 0, &draw("k", 5)),
        Err(StoreFailure::Reserve(ReserveRefused::Exhausted { cell: 0 })),
        "6 are held: 5 more do not fit a cap of 10"
    );
    s.reserve(op(9), 0, &draw("k", 4)).expect("4 do");
}

/// A reserve replayed under its op_id returns the SAME grants and draws nothing more.
#[test]
fn v3_a_replayed_reserve_does_not_draw_twice() {
    let s = v3::bind();
    s.cap(op(100), v3::requests("k"), 10);
    let a = s.reserve(op(8), 0, &draw("k", 10)).expect("reserve");
    let b = s.reserve(op(8), 0, &draw("k", 10)).expect("replay");
    assert_eq!(a, b);
    assert_eq!(
        s.reserve(op(9), 0, &draw("k", 1)),
        Err(StoreFailure::Reserve(ReserveRefused::Exhausted { cell: 0 })),
        "only the first draw holds the window"
    );
}

/// A node fenced out by a newer epoch cannot draw on a store that holds a fleet epoch. The memory
/// store is node-local (ephemeral): it holds one constant epoch and never answers a stale one
/// (`ReserveIn`, "A node-local store"), so an older epoch still draws.
#[test]
fn v3_a_stale_epoch_reserve_is_refused() {
    let s = v3::bind();
    assert!(s.facts().ephemeral, "the memory store is node-local");
    s.cap(op(100), v3::requests("k"), 10);
    s.reserve(op(9), 3, &draw("k", 1)).expect("epoch 3");
    s.reserve(op(10), 2, &draw("k", 1))
        .expect("a node-local store never answers a stale epoch");
}

/// `slice_release` returns the unspent part once, is deduped on its op_id, and never hands back
/// more than the slice was granted.
#[test]
fn v3_slice_release_returns_the_unspent_once_and_never_more() {
    let s = v3::bind();
    s.cap(op(100), v3::requests("k"), 10);
    let g = s.reserve(op(10), 0, &draw("k", 10)).expect("reserve");
    let id = g[0].slice_id;
    assert_eq!(s.slice_release(op(11), &[(id, 4)]), Ok(vec![4]));
    assert_eq!(
        s.slice_release(op(11), &[(id, 4)]),
        Ok(vec![4]),
        "the original answer"
    );
    s.reserve(op(12), 0, &draw("k", 4))
        .expect("4 came back, once");
    assert_eq!(
        s.reserve(op(13), 0, &draw("k", 1)),
        Err(StoreFailure::Reserve(ReserveRefused::Exhausted { cell: 0 }))
    );
    assert_eq!(
        s.slice_release(op(14), &[(id, u64::MAX)]),
        Ok(vec![6]),
        "clamped to what the slice has left, never more"
    );
}

/// Reserve → settle (usage batch of what was spent) → release of the rest: the ledger holds the
/// spend and the window's headroom is whole again.
#[test]
fn v3_reserve_settle_release_leaves_only_the_spend() {
    let s = v3::bind();
    s.cap(op(100), v3::requests("k"), 100);
    let g = s.reserve(op(13), 0, &draw("k", 100)).expect("reserve");
    s.add_usage_batch(op(14), &[("k", DAY, delta(1, 1, "m", &[(UNIT_INPUT, 60)]))])
        .expect("settle");
    s.slice_release(op(15), &[(g[0].slice_id, g[0].granted)])
        .expect("release");
    assert_eq!(tier(&s.get_usage("k", DAY), "m", UNIT_INPUT), 60);
    s.reserve(op(16), 0, &draw("k", 100))
        .expect("nothing stays drawn");
}
