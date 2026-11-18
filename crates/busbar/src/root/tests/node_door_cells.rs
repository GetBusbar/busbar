// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NODE'S CELLS ON THE DOOR PATH: what the deleted plane node cells asserted of a unit the
//! node walked by hand, asserted of a unit a client sends through the router to the linked door.
//! The audit chain a served and a refused unit seal, the subject a sealed record names, the fee a
//! caller that hung up keeps paying, the metering row billing on or off writes,
//! and a rerank's search units on both books.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;

use super::node_rig::{far_end, node_rig, reply, word, NodeRig, NodeRigOpts, LANE, POOL};

const FEE_CENTS: i64 = 1;

const INPUT: u64 = 11;
const OUTPUT: u64 = 7;

const CHAT_PATH: &str = "/v1/chat/completions";

const SEARCH_UNITS: &str = "search_units";

const RERANK_UNITS: u64 = 50;

fn now() -> u64 {
    busbar_kernel::store::now()
}

fn chat() -> serde_json::Value {
    serde_json::json!({
        "model": POOL,
        "messages": [{"role": "user", "content": "hi"}],
    })
}

fn answer() -> String {
    reply(
        "application/json",
        &serde_json::json!({
            "id": "chatcmpl-root", "object": "chat.completion", "created": 0,
            "model": LANE,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "hello"}}],
            "usage": {"prompt_tokens": INPUT, "completion_tokens": OUTPUT,
                      "total_tokens": INPUT + OUTPUT}
        })
        .to_string(),
    )
}

fn card_of(entry: &str) -> BTreeMap<String, busbar_kernel::config::RateEntryCfg> {
    busbar_contract::yaml::from_str(&format!("{LANE}: {entry}\n")).expect("the card parses")
}

async fn drained(response: axum::response::Response) -> (StatusCode, Vec<u8>) {
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body drains")
        .to_vec();
    (status, body)
}

/// The key's admitted requests, its spend in cents and its billable requests.
async fn ledger(rig: &NodeRig) -> (u64, i64, u64) {
    let usage = rig
        .gov
        .usage_for_async(&rig.app.cost, &rig.key.id, now())
        .await
        .expect("usage read")
        .expect("the key exists");
    rig.gov.flush_budgets().await;
    let row = rig
        .gov
        .core_store_handle()
        .expect("native Store")
        .ledger()
        .get_usage(&rig.key.id, 0)
        .await
        .expect("ledger row");
    (usage.requests, usage.spend_cents, row.billable_requests)
}

/// The ledger once `billable` requests have settled, or as it stands after two seconds.
async fn ledger_after(rig: &NodeRig, billable: u64) -> (u64, i64, u64) {
    let mut read = ledger(rig).await;
    for _ in 0..200 {
        if read.2 >= billable {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        read = ledger(rig).await;
    }
    read
}

async fn metering_rows(rig: &NodeRig, at: u64) -> Vec<String> {
    rig.gov.flush_metering().await;
    let bucket = busbar_kernel::governance::metering_bucket(at);
    let mut rows = rig
        .gov
        .metering_for_async(bucket)
        .await
        .expect("metering read");
    let later = busbar_kernel::governance::metering_bucket(now());
    if later != bucket {
        rows.extend(
            rig.gov
                .metering_for_async(later)
                .await
                .expect("metering read"),
        );
    }
    rows.into_iter()
        .filter(|row| row.key_id == rig.key.id)
        .map(|row| {
            format!(
                "{}/{} in={} out={} cr={} cw={} req={} billable={}",
                row.model,
                row.provider,
                busbar_contract::Count::from_stored(row.tokens_input, row.scale).unwrap(),
                busbar_contract::Count::from_stored(row.tokens_output, row.scale).unwrap(),
                busbar_contract::Count::from_stored(row.tokens_cache_read, row.scale).unwrap(),
                busbar_contract::Count::from_stored(row.tokens_cache_write, row.scale).unwrap(),
                row.requests,
                row.billable_requests
            )
        })
        .collect()
}

/// The metering rows once the unit's row has landed, or none after five seconds.
async fn settled_rows(rig: &NodeRig, at: u64) -> Vec<String> {
    for _ in 0..500 {
        let rows = metering_rows(rig, at).await;
        if !rows.is_empty() {
            return rows;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    metering_rows(rig, at).await
}

/// The node's audit records once `count` of them are sealed, or as they stand after five seconds.
async fn records_after(rig: &NodeRig, count: usize) -> Vec<busbar_kernel_audit::AuditRecord> {
    let read = || {
        rig.book
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .audit_records()
            .to_vec()
    };
    for _ in 0..500 {
        if read().len() >= count {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    read()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_unit_the_door_answers_served_or_refused_seals_one_record_on_one_tamper_evident_chain(
) {
    let _one = crate::root::PUBLISHING.lock().await;
    let rig = node_rig(
        "door-cells-chain",
        far_end(answer()).await,
        NodeRigOpts {
            fee_cents: FEE_CENTS,
            ..Default::default()
        },
    )
    .await;

    let served = rig.open(CHAT_PATH, &chat()).await;
    assert_eq!(served.status(), StatusCode::OK, "the completion is served");
    let _ = axum::body::to_bytes(served.into_body(), usize::MAX)
        .await
        .expect("the served body drains");
    let _ = records_after(&rig, 1).await;
    let refused = rig.open_raw(CHAT_PATH, "{not json".to_string(), true).await;
    assert!(
        refused.status().is_client_error(),
        "the unreadable body is refused: {}",
        refused.status()
    );
    let _ = axum::body::to_bytes(refused.into_body(), usize::MAX)
        .await
        .expect("the refusal drains");
    let _ = records_after(&rig, 2).await;

    let durability = rig.book.lock().expect("unpoisoned");
    let records = durability.audit_records().to_vec();
    assert_eq!(records.len(), 2, "one record per unit: {records:?}");
    let (served, refused) = (&records[0], &records[1]);
    assert_eq!(
        served.outcome.unit_end,
        busbar_contract::caps::Outcome::Completed,
        "the dispatch is chained as served"
    );
    assert!(
        matches!(
            refused.outcome.unit_end,
            busbar_contract::caps::Outcome::Refused(..)
        ),
        "the refusal is chained as one: {:?}",
        refused.outcome
    );
    assert_eq!(refused.seq, served.seq + 1, "contiguous");
    assert_eq!(
        refused.prev_hash, served.hash,
        "linked to the record before"
    );
    assert!(busbar_kernel_audit::AuditChain::verify_window(&records).is_ok());
    assert!(
        durability.retained_audit_findings().is_empty(),
        "the node's own verify finds nothing"
    );

    let mut forged = records.clone();
    forged[0].outcome.unit_end = refused.outcome.unit_end;
    assert!(
        busbar_kernel_audit::AuditChain::verify_window(&forged).is_err(),
        "a record altered after its seal breaks the chain"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_caller_that_hangs_up_mid_dispatch_keeps_its_flat_fee_charged() {
    let _one = crate::root::PUBLISHING.lock().await;
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("its address").port();
    let (announced, allowed) = (Arc::clone(&started), Arc::clone(&release));
    let endpoint = axum::Router::new().fallback(axum::routing::post(move || {
        let (announced, allowed) = (Arc::clone(&announced), Arc::clone(&allowed));
        async move {
            announced.notify_one();
            allowed.notified().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "error": {"message": "still answering", "type": "server_error"}
                })),
            )
        }
    }));
    let server = tokio::spawn(async move {
        axum::serve(listener, endpoint)
            .await
            .expect("the far end serves");
    });
    let rig = node_rig(
        "door-cells-hang-up",
        port,
        NodeRigOpts {
            rate_card: Some(card_of("{ input_utok: 1, output_utok: 1 }")),
            fee_cents: FEE_CENTS,
            ..Default::default()
        },
    )
    .await;
    let body = chat();
    tokio::select! {
        _ = rig.open(CHAT_PATH, &body) => {
            panic!("the far end holds its body, so the unit cannot have answered");
        }
        // The unit is reading the held body: the caller goes away here, and its request future is
        // dropped with the unit inside it.
        () = started.notified() => {}
    }
    release.notify_one();

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let (requests, spend, _) = ledger_after(&rig, 1).await;
    assert_eq!(requests, 1, "the door drew the admission slot");
    assert_eq!(
        spend, FEE_CENTS,
        "a caller that went away mid-dispatch is refunded nothing: the flat fee stays charged"
    );
    server.abort();
    let _ = server.await;
}

async fn served_buffered(
    instance: &'static str,
    rate_card: Option<BTreeMap<String, busbar_kernel::config::RateEntryCfg>>,
) -> (StatusCode, Vec<String>) {
    let rig = node_rig(
        instance,
        far_end(answer()).await,
        NodeRigOpts {
            rate_card,
            fee_cents: FEE_CENTS,
            ..Default::default()
        },
    )
    .await;
    let charged_at = now();
    let (status, _) = drained(rig.open(CHAT_PATH, &chat()).await).await;
    (status, settled_rows(&rig, charged_at).await)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn billing_off_serves_free_writes_its_metering_row_reading_zero_yet_still_governs() {
    let _one = crate::root::PUBLISHING.lock().await;
    let row = vec![format!(
        "{LANE}/oai0 in={INPUT} out={OUTPUT} cr=0 cw=0 req=1 billable=1"
    )];

    let (status, free) = served_buffered("door-cells-billing-off", None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "billing off still serves the request (a free failover/routing proxy)"
    );
    assert_eq!(
        free, row,
        "billing off (no rate_card) still writes the plane's counts: the ledger is what the plane did (#43)"
    );

    let (status, billed) = served_buffered(
        "door-cells-billing-on",
        Some(card_of("{ input_utok: 1, output_utok: 1 }")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        billed, free,
        "the same request on a billed plane writes exactly the same metering row"
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Credential {
    /// The deployment's own bearer.
    Good,
    /// No bearer, at a door that asks none.
    Unbound,
}

fn sealed_subject(records: &[busbar_kernel_audit::AuditRecord]) -> busbar_kernel_audit::Subject {
    records
        .last()
        .expect("the served unit sealed its record")
        .subject
        .clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_loop_attributes_the_identity_the_door_resolved_and_invents_none() {
    let _one = crate::root::PUBLISHING.lock().await;
    let cred = Credential::Good;
    let keyed = node_rig(
        "door-cells-identity-keyed",
        far_end(answer()).await,
        NodeRigOpts {
            fee_cents: FEE_CENTS,
            ..Default::default()
        },
    )
    .await;
    let (status, _) = drained(keyed.open(CHAT_PATH, &chat()).await).await;
    assert_eq!(status, StatusCode::OK, "the deployment's own bearer");
    let settled = sealed_subject(&records_after(&keyed, 1).await);
    assert_eq!(
        settled,
        busbar_kernel_audit::Subject::principal(&keyed.key.id),
        "{cred:?}: the loop settled on principal {settled:?}, not the key the door resolved"
    );

    let cred = Credential::Unbound;
    let open = node_rig(
        "door-cells-identity-open",
        far_end(answer()).await,
        NodeRigOpts {
            fee_cents: FEE_CENTS,
            open_door: true,
            ..Default::default()
        },
    )
    .await;
    let (status, _) = drained(open.open_raw(CHAT_PATH, chat().to_string(), false).await).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the open door serves a bare request"
    );
    let anonymous = busbar_contract::auth::AuthPrincipal(None)
        .actor_id()
        .to_string();
    let settled = sealed_subject(&records_after(&open, 1).await);
    assert_eq!(
        settled,
        busbar_kernel_audit::Subject::principal(&anonymous),
        "{cred:?}: an unbound request is not attributed to the anonymous actor"
    );
    assert_ne!(
        settled,
        busbar_kernel_audit::Subject::principal(&open.key.id),
        "{cred:?}: the loop settled on principal {settled:?} for a request the door bound no key to"
    );
}

/// A card history holding one entry for the member: tokens at 3 and 16 micro-units, the flat `fee`,
/// and `search_units` at that many nano-units each, or silent about them.
fn rerank_card(fee: i64, search_units: Option<u64>) -> crate::root::kernel::RootHistory {
    use busbar_kernel_ledger::cost::{LaneClass, RateCard};
    let holder = crate::root::kernel::RootHistory::default();
    holder.apply(
        RateCard::from_micro_rates(
            [
                (
                    LaneClass::new(LANE, busbar_contract::records::UNIT_INPUT),
                    3.0,
                ),
                (
                    LaneClass::new(LANE, busbar_contract::records::UNIT_OUTPUT),
                    16.0,
                ),
            ],
            fee,
        )
        .with_unit_rates(search_units.map(|nanos| (LaneClass::new(LANE, SEARCH_UNITS), nanos))),
        1_000,
    );
    holder
}

static PRICED: std::sync::LazyLock<crate::root::kernel::RootHistory> =
    std::sync::LazyLock::new(|| rerank_card(0, Some(2_000_000)));
static PRICED_WITH_FEE: std::sync::LazyLock<crate::root::kernel::RootHistory> =
    std::sync::LazyLock::new(|| rerank_card(3, Some(2_000_000)));
static SILENT: std::sync::LazyLock<crate::root::kernel::RootHistory> =
    std::sync::LazyLock::new(|| rerank_card(0, None));
static ABSENT: std::sync::LazyLock<crate::root::kernel::RootHistory> =
    std::sync::LazyLock::new(|| {
        let holder = crate::root::kernel::RootHistory::default();
        holder.apply(
            crate::root::kernel::card_from_config(
                std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
                0,
                false,
            ),
            1_000,
        );
        holder
    });

fn priced_pin() -> Option<crate::root::kernel::PinnedHistory> {
    PRICED.pin()
}
fn priced_with_fee_pin() -> Option<crate::root::kernel::PinnedHistory> {
    PRICED_WITH_FEE.pin()
}
fn silent_pin() -> Option<crate::root::kernel::PinnedHistory> {
    SILENT.pin()
}
fn absent_pin() -> Option<crate::root::kernel::PinnedHistory> {
    ABSENT.pin()
}

fn declare_test_classes() {
    let mut registration = crate::root::kernel::new_registration();
    for class in busbar_contract::records::RESERVED_UNITS {
        let _ = registration.key(class);
    }
    let _ = registration.key(SEARCH_UNITS);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedCounts {
    lane: String,
    fee_count: u64,
    classes: BTreeMap<String, u64>,
}

impl RecordedCounts {
    fn entry(&self, at: u64) -> busbar_kernel_ledger::cost::LedgerEntry {
        self.classes.iter().fold(
            busbar_kernel_ledger::cost::LedgerEntry::new(&self.lane, at)
                .with_fee_count(self.fee_count),
            |entry, (class, count)| entry.with_whole(class, *count),
        )
    }

    fn of(row: &busbar_contract::records::UsageLedger) -> Self {
        RecordedCounts {
            lane: LANE.to_string(),
            fee_count: row.billable_requests,
            classes: row
                .models
                .iter()
                .filter(|model| model.model == LANE)
                .flat_map(|model| {
                    model
                        .usage_units
                        .iter()
                        .filter(|(_, count)| **count > 0)
                        .map(|(class, count)| {
                            (
                                class.clone(),
                                busbar_contract::Count::from_stored(*count, model.scale)
                                    .expect("stored exact scale")
                                    .whole_u64()
                                    .expect("whole fixture count"),
                            )
                        })
                })
                .collect(),
        }
    }
}

/// The durable book's row for the key: its counts, and their price under the unit's pin.
#[derive(Debug, Clone)]
struct DurableRow {
    counts: RecordedCounts,
    nanos: Result<u128, String>,
}

fn priced(
    counts: &RecordedCounts,
    history: &crate::root::kernel::PinnedHistory,
    at: u64,
) -> Result<u128, String> {
    busbar_kernel_ledger::cost::price_exact(&[counts.entry(at)], &history.view())
        .and_then(busbar_kernel_ledger::cost::nanos_of_exact)
        .map_err(|error| format!("{error:?}"))
}

fn every_cell_agrees(
    label: &str,
    row: &DurableRow,
    expected: &RecordedCounts,
    history: &crate::root::kernel::PinnedHistory,
    at: u64,
) -> Result<(), String> {
    let counts = &row.counts;
    for class in counts.classes.keys().chain(expected.classes.keys()) {
        if counts.classes.get(class) != expected.classes.get(class) {
            return Err(format!(
                "{label}: class {class}: {:?} vs {:?}",
                counts.classes.get(class),
                expected.classes.get(class)
            ));
        }
    }
    if counts.lane != expected.lane || counts.fee_count != expected.fee_count {
        return Err(format!("{label}: lane or fee count differs"));
    }
    let invoice = priced(expected, history, at);
    if row.nanos != invoice {
        return Err(format!("{label}: money: {:?} vs {invoice:?}", row.nanos));
    }
    Ok(())
}

struct RerankBooks {
    rig: NodeRig,
    status: StatusCode,
    governance: RecordedCounts,
    spend: Result<i64, String>,
    row: DurableRow,
    history: crate::root::kernel::PinnedHistory,
    at: u64,
}

impl RerankBooks {
    fn durable_units(&self) -> Option<u64> {
        self.row.counts.classes.get(SEARCH_UNITS).copied()
    }
}

/// One rerank in the door words' rerank dialect, answered by `answer`, through a rig over `opts`
/// (its member speaking that dialect), read back from both books once its metered request lands.
async fn serve_rerank(
    instance: &'static str,
    answer: &'static str,
    opts: NodeRigOpts,
) -> RerankBooks {
    declare_test_classes();
    let pin = opts.pin.expect("a rerank cell pins its card");
    let rig = node_rig(
        instance,
        far_end(reply("application/json", answer)).await,
        NodeRigOpts {
            dialect: Some(word("rerank_dialect")),
            ..opts
        },
    )
    .await;
    let body: serde_json::Value =
        serde_json::from_str(word("rerank_body")).expect("the rerank body is JSON");
    let at = busbar_kernel::store::now_ms();
    let history = pin().expect("the pinned card has an entry");
    let (status, _) = drained(rig.open(word("rerank_path"), &body).await).await;
    let _ = settled_rows(&rig, at / 1_000).await;

    let spend = rig
        .gov
        .usage_for_async(&rig.app.cost, &rig.key.id, now())
        .await
        .map(|usage| usage.expect("the key exists").spend_cents)
        .map_err(|refusal| format!("{refusal:?}"));
    rig.gov.flush_budgets().await;
    let core = rig.gov.core_store_handle().expect("native Store");
    let governance = RecordedCounts::of(
        &core
            .ledger()
            .get_usage(
                &rig.key.id,
                busbar_kernel::governance::budget_window(
                    busbar_kernel::governance::WINDOW_TOTAL,
                    now(),
                ),
            )
            .await
            .expect("the governance ledger reads"),
    );
    let counts = RecordedCounts::of(
        &core
            .ledger()
            .get_usage(&rig.key.id, 0)
            .await
            .expect("canonical usage reads"),
    );
    let nanos = priced(&counts, &history, at);
    RerankBooks {
        rig,
        status,
        governance,
        spend,
        row: DurableRow { counts, nanos },
        history,
        at,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_served_rerank_puts_identical_search_units_on_both_books() {
    let _one = crate::root::PUBLISHING.lock().await;
    let books = serve_rerank(
        "door-cells-rerank-served",
        word("rerank_answer_50"),
        NodeRigOpts {
            fee_cents: FEE_CENTS,
            pin: Some(priced_with_fee_pin),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(books.status, StatusCode::OK, "the rerank was served");
    let classes = &books.governance.classes;
    assert_eq!(
        classes.get(SEARCH_UNITS),
        Some(&RERANK_UNITS),
        "the governance ledger accrued the rerank's search units: {classes:?}"
    );

    let _ = records_after(&books.rig, 1).await;
    {
        let durability = books.rig.book.lock().expect("unpoisoned");
        assert_eq!(
            durability.audit_records().len(),
            1,
            "one record per unit: {:?}",
            durability.audit_records()
        );
        let record = &durability.audit_records()[0];
        assert_eq!(record.what.incarnation, durability.incarnation);
        assert_eq!(
            record.outcome.unit_end,
            busbar_contract::caps::Outcome::Completed
        );
        assert!(
            record
                .usage
                .lines
                .iter()
                .any(|l| l.class.as_str() == SEARCH_UNITS && l.quantity == RERANK_UNITS),
            "the record's amount is the line's counts: {:?}",
            record.usage.lines
        );
        assert!(durability.retained_audit_findings().is_empty());
    }

    let row = &books.row;
    assert_eq!(
        books.durable_units(),
        Some(RERANK_UNITS),
        "the durable book's row carries the rerank's search units: {row:?}"
    );
    every_cell_agrees(
        "served rerank",
        row,
        &books.governance,
        &books.history,
        books.at,
    )
    .expect("both books hold the same search units and the same figure");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reranks_search_units_reach_the_price_on_both_books() {
    let _one = crate::root::PUBLISHING.lock().await;
    let priced_card = card_of(&format!("{{ units: {{ {SEARCH_UNITS}: 2000 }} }}"));
    for (instance, answer, units, cents) in [
        (
            "door-cells-rerank-priced-50",
            word("rerank_answer_50"),
            50_u64,
            10_i64,
        ),
        ("door-cells-rerank-priced-1", word("rerank_answer_1"), 1, 0),
    ] {
        let books = serve_rerank(
            instance,
            answer,
            NodeRigOpts {
                rate_card: Some(priced_card.clone()),
                pin: Some(priced_pin),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(books.status, StatusCode::OK, "{units} units: served");
        assert_eq!(books.spend, Ok(cents), "{units} search units at 0.2 cents");
        assert_eq!(
            books.row.nanos.clone().ok(),
            Some(u128::from(units) * 2_000_000),
            "{units} units: the durable book settles them at the card"
        );
        every_cell_agrees(
            "rerank, priced",
            &books.row,
            &books.governance,
            &books.history,
            books.at,
        )
        .expect("both books price the rerank alike");
    }

    let silent = serve_rerank(
        "door-cells-rerank-silent",
        word("rerank_answer_50"),
        NodeRigOpts {
            rate_card: Some(card_of("{ input_utok: 1 }")),
            card_as_written: true,
            pin: Some(silent_pin),
            ..Default::default()
        },
    )
    .await;
    assert!(
        silent.spend.is_err(),
        "a present card silent about search_units REFUSES (#42), never a silent 0: {:?}",
        silent.spend
    );
    assert!(
        silent
            .row
            .nanos
            .as_ref()
            .err()
            .is_some_and(|why| why.contains(SEARCH_UNITS)),
        "the durable book refuses the same class: {:?}",
        silent.row
    );

    let off = serve_rerank(
        "door-cells-rerank-billing-off",
        word("rerank_answer_50"),
        NodeRigOpts {
            pin: Some(absent_pin),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(off.spend, Ok(0), "no card: billing off reads 0");
    assert_eq!(
        off.durable_units(),
        Some(50),
        "billing off still keeps the counts"
    );
    every_cell_agrees(
        "rerank, billing off",
        &off.row,
        &off.governance,
        &off.history,
        off.at,
    )
    .expect("both books read the rerank at nothing with billing off");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_same_dialect_rerank_puts_identical_search_units_on_both_books() {
    let _one = crate::root::PUBLISHING.lock().await;
    let dialect = word("rerank_dialect");
    let opts = || NodeRigOpts {
        fee_cents: FEE_CENTS,
        pin: Some(priced_with_fee_pin),
        ..Default::default()
    };
    let billed = serve_rerank(
        "door-cells-rerank-same-billed",
        word("rerank_answer_50"),
        opts(),
    )
    .await;
    assert_eq!(billed.status, StatusCode::OK, "{dialect}: served");
    assert_eq!(
        billed.governance.classes.get(SEARCH_UNITS),
        Some(&RERANK_UNITS),
        "{dialect} -> {dialect}: the governance ledger holds the rerank's search units"
    );
    assert_eq!(
        billed.durable_units(),
        Some(RERANK_UNITS),
        "{dialect} -> {dialect}: the durable book holds the rerank's search units"
    );

    let unbilled = serve_rerank(
        "door-cells-rerank-same-unbilled",
        word("rerank_answer_unbilled"),
        opts(),
    )
    .await;
    assert_eq!(
        (
            unbilled.governance.classes.get(SEARCH_UNITS).copied(),
            unbilled.durable_units()
        ),
        (None, None),
        "{dialect}: no units, none booked"
    );
}
