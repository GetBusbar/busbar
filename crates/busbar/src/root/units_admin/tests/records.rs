// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 §3.3 (MR3): `GET /records`, the per-unit records feed.

use std::sync::{Arc, Mutex};

use busbar_contract::plane::PlaneDeclaration;
use busbar_kernel_audit::{
    attribution, Audit, AuditChain, AuditInputs, AuditKeySet, AuditRecord, Recipe, UnitFacts,
};
use serde_json::Value;

use crate::root::durability::tests::{audit_inputs, audit_pass, NativeFixture};
use crate::root::durability::{Durability, AUDIT_RING};
use crate::root::units_admin::records::{project, records_answer};
use crate::root::units_admin::{AuditView, NodeAudit};

const NODE: u64 = 0x0123_4567_89ab_cdef;

fn no_plane(_: &str) -> Option<PlaneDeclaration> {
    None
}

/// One unit sealed at `wall_ms`, under recipe v7's facts.
fn inputs_at(unit: u64, wall_ms: u64) -> AuditInputs {
    let mut inputs = audit_inputs(unit);
    inputs.wall = wall_ms / 1_000;
    inputs.unit = UnitFacts {
        wall_ms,
        attribution: attribution("team-a", "default", "acme"),
        boot_nonce: [0x5f; 16],
        ..UnitFacts::default()
    };
    inputs
}

/// A chain held in memory, read the way the node reads its own: windows of at most the ring.
struct Memory(Mutex<(AuditChain, Vec<AuditRecord>)>);

impl Memory {
    fn sealed(arrivals: impl IntoIterator<Item = u64>) -> Self {
        let memory = Memory(Mutex::new((AuditChain::new().sealing_as(NODE), Vec::new())));
        for wall_ms in arrivals {
            memory.seal(wall_ms);
        }
        memory
    }

    fn seal(&self, wall_ms: u64) -> AuditRecord {
        let mut held = self.0.lock().unwrap();
        let unit = held.0.next_seq();
        let record = held.0.seal(inputs_at(unit, wall_ms), &audit_pass());
        held.1.push(record.clone());
        record
    }
}

#[async_trait::async_trait]
impl AuditView for Memory {
    fn read(&self, take: &mut dyn FnMut(&AuditChain, Option<&[AuditRecord]>)) {
        let held = self.0.lock().unwrap();
        take(&held.0, Some(&held.1));
    }

    async fn read_window(
        &self,
        from: u64,
        to: u64,
        take: &mut (dyn for<'chain, 'records> FnMut(&'chain AuditChain, Option<&'records [AuditRecord]>)
                  + Send),
    ) {
        let held = self.0.lock().unwrap();
        let window: Vec<AuditRecord> = held
            .1
            .iter()
            .filter(|r| r.seq >= from && r.seq <= to)
            .take(AUDIT_RING)
            .cloned()
            .collect();
        take(&held.0, Some(&window));
    }

    fn keys(&self) -> AuditKeySet {
        AuditKeySet::new()
    }
}

async fn page(view: &dyn AuditView, query: &str) -> (u16, Value) {
    let answer = records_answer(view, &no_plane, &format!("/api/v1/admin/records{query}")).await;
    let body = serde_json::from_slice(&answer.body).expect("the answer is JSON");
    (answer.status, body)
}

fn seqs(body: &Value) -> Vec<u64> {
    body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["seq"].as_str().unwrap().parse().unwrap())
        .collect()
}

/// Read the whole feed from `query`, following `next_cursor` until caught up.
async fn drain(view: &dyn AuditView, query: &str) -> Vec<u64> {
    let (status, mut body) = page(view, query).await;
    assert_eq!(status, 200, "{body}");
    let mut all = seqs(&body);
    for _ in 0..1_000 {
        if body["complete"] == true {
            return all;
        }
        let cursor = body["next_cursor"].as_str().expect("a cursor").to_string();
        let (status, next) = page(view, &format!("?limit=1000&cursor={cursor}")).await;
        assert_eq!(status, 200, "{next}");
        all.extend(seqs(&next));
        body = next;
    }
    panic!("the feed did not catch up");
}

#[tokio::test]
async fn records_no_cursor_starts_oldest() {
    let view = Memory::sealed((1..=5).map(|n| n * 1_000));
    let (status, body) = page(&view, "?limit=2").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        seqs(&body),
        vec![1, 2],
        "with no cursor the feed starts at the oldest"
    );
    assert_eq!(body["complete"], false);
    let cursor = body["next_cursor"].as_str().unwrap();
    assert_eq!(cursor, format!("rc1.{NODE:016x}.3"));
    let (_, body) = page(&view, &format!("?limit=2&cursor={cursor}")).await;
    assert_eq!(seqs(&body), vec![3, 4]);
    let cursor = body["next_cursor"].as_str().unwrap().to_string();
    let (_, body) = page(&view, &format!("?cursor={cursor}")).await;
    assert_eq!(seqs(&body), vec![5]);
    assert_eq!(body["complete"], true);
    assert_eq!(body["source"]["node_id"], format!("node_{NODE:016x}"));
}

#[tokio::test]
async fn records_feed_never_null_cursor() {
    let empty = Memory::sealed([]);
    let (status, body) = page(&empty, "").await;
    assert_eq!(status, 200, "{body}");
    assert!(body["items"].as_array().unwrap().is_empty());
    assert_eq!(body["complete"], true, "an empty chain is caught up");
    assert_eq!(body["next_cursor"], format!("rc1.{NODE:016x}.1"));

    let view = Memory::sealed([1_000, 2_000]);
    let (_, body) = page(&view, "").await;
    assert_eq!(body["complete"], true);
    let cursor = body["next_cursor"]
        .as_str()
        .expect("a string when caught up");
    view.seal(3_000);
    let (_, body) = page(&view, &format!("?cursor={cursor}")).await;
    assert_eq!(
        seqs(&body),
        vec![3],
        "the caught-up cursor resumes at the next record"
    );
}

#[tokio::test]
async fn records_cursor_foreign_node() {
    let view = Memory::sealed([1_000]);
    let (status, body) = page(&view, "?cursor=rc1.00000000000000aa.1").await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["code"], "invalid_request");
    assert_eq!(body["error"]["reason"], "cursor_mismatch");
    assert_eq!(
        body["error"]["details"]["cursor_node_id"],
        "node_00000000000000aa"
    );
    let (status, body) = page(&view, "?cursor=rc1.nonsense").await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn records_filters_exact() {
    let view = Memory::sealed((1..=6).map(|n| n * 1_000));
    let (_, body) = page(&view, "?key=pseudonym-3").await;
    assert_eq!(seqs(&body), vec![3], "key is exact");
    let (_, body) = page(&view, "?key=pseudonym").await;
    assert!(seqs(&body).is_empty(), "never a prefix match");
    let (_, body) = page(&view, "?outcome=completed&group=team-a&provider=acme&pool=").await;
    assert_eq!(
        body["error"]["code"], "invalid_request",
        "`pool` is not a filter"
    );
    let (_, body) = page(&view, "?outcome=completed&group=team-a&provider=acme").await;
    assert_eq!(seqs(&body), vec![1, 2, 3, 4, 5, 6]);
    let (_, body) = page(&view, "?outcome=refused").await;
    assert!(seqs(&body).is_empty());
    let (_, body) = page(&view, "?to_ms=3000").await;
    assert_eq!(seqs(&body), vec![1, 2], "to_ms bounds arrivals before it");
    let (_, body) = page(&view, "?target=upstream-a&model=upstream-a&instance=pools").await;
    assert_eq!(
        seqs(&body).len(),
        6,
        "target, model and instance from the sealed lane"
    );
    let (status, _) = page(&view, "?modle=upstream-a").await;
    assert_eq!(status, 400, "a mistyped filter never widens a read");
    let (status, _) = page(&view, "?limit=1001").await;
    assert_eq!(status, 400, "limit is at most 1000");
}

#[tokio::test]
async fn records_scan_bounded() {
    let bound = busbar_core_admin::v1::records::RECORDS_SCAN_BOUND;
    let view = Memory::sealed((1..=bound + 50).map(|n| n * 1_000));
    let wanted = format!("pseudonym-{}", bound + 20);
    let (status, body) = page(&view, &format!("?key={wanted}")).await;
    assert_eq!(status, 200, "{body}");
    assert!(seqs(&body).is_empty(), "nothing matched in the bound");
    assert_eq!(body["complete"], false);
    let cursor = body["next_cursor"].as_str().unwrap().to_string();
    assert_eq!(
        cursor,
        format!("rc1.{NODE:016x}.{}", bound + 1),
        "a short page continues"
    );
    let (_, body) = page(&view, &format!("?key={wanted}&cursor={cursor}")).await;
    assert_eq!(seqs(&body), vec![bound + 20]);
    assert_eq!(body["complete"], true);
}

#[tokio::test]
async fn records_from_ms_seeks() {
    let bound = busbar_core_admin::v1::records::RECORDS_SCAN_BOUND;
    let view = Memory::sealed((1..=bound + 100).map(|n| n * 1_000));
    let from = (bound + 20) * 1_000;
    let (status, body) = page(&view, &format!("?from_ms={from}&limit=10")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        seqs(&body),
        ((bound + 20)..(bound + 30)).collect::<Vec<_>>(),
        "past more than the scan bound of older records, the first page is full"
    );
    let (_, body) = page(&view, &format!("?from_ms={}", from - 1)).await;
    assert_eq!(
        seqs(&body).first(),
        Some(&(bound + 20)),
        "the first arrival at or after"
    );
}

#[tokio::test]
async fn records_from_ms_seek_clock_step() {
    // A backward clock step at the sixth unit.
    let arrivals = [1, 2, 3, 4, 5, 3, 4, 6, 7, 8].map(|s| s * 1_000);
    let view = Memory::sealed(arrivals);
    let (status, body) = page(&view, "?from_ms=4000").await;
    assert_eq!(status, 200, "{body}");
    let got = seqs(&body);
    let first = *got.first().expect("a page");
    assert!(
        arrivals[(first - 1) as usize] >= 4_000,
        "the page starts at a boundary"
    );
    assert!(
        arrivals[(first - 2) as usize] < 4_000,
        "the record before it is earlier"
    );
    assert_eq!(
        got,
        (first..=10).collect::<Vec<_>>(),
        "nothing after it is dropped"
    );
}

#[tokio::test]
async fn records_wait_wakes() {
    let view = Arc::new(Memory::sealed([1_000]));
    let (_, body) = page(&*view, "").await;
    let cursor = body["next_cursor"].as_str().unwrap().to_string();
    let waiting = Arc::clone(&view);
    let started = std::time::Instant::now();
    let read =
        tokio::spawn(async move { page(&*waiting, &format!("?wait=20&cursor={cursor}")).await });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    view.seal(2_000);
    crate::root::durability::records_pulse().notify_waiters();
    let (status, body) = read.await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(seqs(&body), vec![2], "the confirmed record wakes the wait");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

#[test]
fn pre_v7_records_never_resolve_from_config() {
    let view = Memory::sealed([1_700_000_000_250]);
    let v7 = view.0.lock().unwrap().1[0].clone();
    let known = |key: &str| {
        busbar_kernel::plane_driver::registry::plane_decls()
            .iter()
            .map(|decl| decl.declaration)
            .find(|decl| decl.key == key)
    };
    let (record, priceable) = project(&v7, &no_plane);
    assert_eq!(record.schema, "busbar.unit_record.v1");
    assert_eq!(record.arrived_at_ms, 1_700_000_000_250);
    assert_eq!(record.arrived_at_precision, "ms");
    assert_eq!(record.group.as_deref(), Some("team-a"));
    assert_eq!(record.pool.as_deref(), Some("default"));
    assert_eq!(record.provider.as_deref(), Some("acme"));
    assert_eq!(
        record.unit,
        Some(format!("node_{NODE:016x}.{}.1", "5f".repeat(16)))
    );
    assert_eq!(record.key.as_deref(), Some("pseudonym-1"));
    assert_eq!(record.target.as_deref(), Some("upstream-a"));
    assert_eq!(record.model.as_deref(), Some("upstream-a"));
    assert_eq!(record.instance.as_deref(), Some("pools"));
    assert_eq!(
        record.kind, None,
        "an instance this node does not know has no kind"
    );
    assert!(record.timing.is_some());
    assert!(priceable.is_some(), "a keyed v7 record can be priced");
    let _ = project(&v7, &known);

    let mut old = v7.clone();
    old.recipe = Recipe::V6;
    old.unit = UnitFacts::default();
    let (record, _) = project(&old, &no_plane);
    assert_eq!(record.arrived_at_ms, old.wall * 1_000);
    assert_eq!(record.arrived_at_precision, "s");
    assert_eq!(
        (record.group, record.pool, record.provider),
        (None, None, None),
        "never resolved from current config"
    );
    assert_eq!(record.unit, None, "no sealed incarnation, no unit id");
    assert_eq!(record.unit_key, "1", "the unit key is still served");
    assert_eq!(
        record.model.as_deref(),
        Some("upstream-a"),
        "the sealed lane"
    );
    assert!(record.timing.is_none());
}

#[tokio::test]
async fn records_survive_ring() {
    let fixture = NativeFixture::new(NODE).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let count = AUDIT_RING as u64 + 50;
    for unit in 1..=count {
        Durability::seal_unit(
            &book,
            inputs_at(unit, unit * 1_000),
            audit_pass(),
            &crate::root::durability::tests::token(),
        )
        .await
        .unwrap();
    }
    fixture.journal.flush().await.unwrap();
    let view = NodeAudit::new(Arc::clone(&book));
    let all = drain(&view, "?limit=1000").await;
    assert_eq!(
        all,
        (1..=count).collect::<Vec<_>>(),
        "older than the ring is read from the Store"
    );
}

fn card(output: f64) -> busbar_kernel_ledger::cost::RateCard {
    use busbar_kernel_ledger::cost::representable_nano_rate;
    crate::root::kernel::card_from_config(
        [(
            "lane",
            busbar_contract::billing::RawTierRates {
                input: representable_nano_rate(0.0),
                output: representable_nano_rate(output),
                cache_read: representable_nano_rate(0.0),
                cache_write: representable_nano_rate(0.0),
            },
        )],
        0,
        true,
    )
}

/// A RECORD PRICES BY THE RULE `/usage` PRICES ITS ROW BY (ADMIN-API-1.6 §3.2, through the one
/// `price_era`): its sealed entry, voided or not, with a later amendment that prices the day's
/// instant applied; voiding the amendment reverts it, and voiding the original changes nothing.
#[test]
fn records_price_through_amendments_and_voids() {
    use busbar_core_admin::v1::records::UnitRecord;
    use busbar_kernel_ledger::cost::{Author, CardEntryDraft, History};
    let mut history = History::new();
    history.append(CardEntryDraft {
        effective_from: 0,
        effective_until: None,
        card: card(1.0),
        appended_at: 0,
        author: Author::Config { policy_epoch: 0 },
    });
    let original = history.entries()[0].key();
    let arrived = 1_700_000_005_000;
    let mut inputs = inputs_at(1, arrived);
    inputs.what.destination = Some("lane".into());
    inputs.usage.rate_card_version = Some(original.0);
    inputs.usage.fee_count = 0;
    inputs.usage.lines = vec![busbar_kernel_audit::UsageLine {
        class: busbar_contract::MeterClassId::new(busbar_contract::records::UNIT_OUTPUT),
        quantity: 1_000u64.into(),
        source: busbar_contract::caps::QuantitySource::Count,
        estimated: false,
    }];
    let record = AuditChain::new()
        .sealing_as(NODE)
        .seal(inputs, &audit_pass());
    let priced = |history: &History| -> UnitRecord {
        let (mut unit, input) = project(&record, &no_plane);
        crate::root::units_admin::records::price(
            &mut unit,
            input.expect("a keyed record"),
            &history.current(),
        );
        unit
    };
    let spend = |unit: &UnitRecord| -> f64 {
        unit.spend_micros
            .as_deref()
            .expect("priced")
            .parse()
            .unwrap()
    };
    let before = priced(&history);
    assert!(before.priced);
    assert_eq!(before.priced_by, Some(original.hex()));
    assert!(spend(&before) > 0.0);

    history.append(CardEntryDraft {
        effective_from: arrived / 86_400_000 * 86_400_000,
        effective_until: None,
        card: card(2.0),
        appended_at: arrived + 60_000,
        author: Author::Amend {
            reason_hash: [7; 32],
        },
    });
    let amendment = history
        .entries()
        .iter()
        .find(|entry| matches!(entry.author(), Author::Amend { .. }))
        .expect("the amendment")
        .key();
    let amended = priced(&history);
    assert_eq!(
        amended.priced_by,
        Some(amendment.hex()),
        "the back-dated amendment prices it"
    );
    assert_eq!(spend(&amended), 2.0 * spend(&before));

    let _ = history.void(&amendment);
    assert_eq!(priced(&history), before, "voiding the amendment reverts it");
    let _ = history.void(&original);
    assert_eq!(
        priced(&history).spend_micros,
        before.spend_micros,
        "a voided original still prices the units sealed against it"
    );
}
