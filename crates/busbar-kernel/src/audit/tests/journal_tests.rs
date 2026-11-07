// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral chain assertions through the actual native host owner. Journal itself
//! only caches verified positions; no alternate synchronous persistence sink exists.
use super::Journal;
use crate::audit::stream_registry::{StreamInput, StreamRecord};
use crate::audit::{verify_chain, Chain, ChainedRecord, Framing};
use crate::host_chains::{self, ChainBook, ChainFraming, OrdinaryChain, CHAIN_LIFE_SCHEMA};
use crate::host_records::record_key;
use crate::host_records_async::{
    AsyncHistory, AsyncRecords, HistoryCollection, HistoryMode, HistoryOutcome,
};
use crate::persistence::host_records::Outcome;
use busbar_contract::host_records::conditional::{Decision, Expected, Predicate};
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector, Retention};
use std::sync::{Arc, Mutex};

pub(super) const SCHEMA: RecordSchemaId = RecordSchemaId::new("neutral-test");
pub(super) const INSTANCE: &str = "native-neutral-journal";
pub(super) const FRAMING: ChainFraming = ChainFraming {
    framing: Framing::LengthPrefixed,
    digests_scope: true,
};

#[derive(Clone, Default)]
struct AuditDiagnosticCodes(Arc<Mutex<Vec<String>>>);
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for AuditDiagnosticCodes {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if *event.metadata().level() != tracing::Level::ERROR {
            return;
        }
        struct Codes<'a>(&'a mut Vec<String>);
        impl tracing::field::Visit for Codes<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "diag" {
                    self.0.push(format!("{value:?}"));
                }
            }
        }
        event.record(&mut Codes(&mut self.0.lock().unwrap()));
    }
}
pub(super) async fn fixture() -> (Arc<crate::persistence::facade::CoreStore>, AsyncRecords) {
    let store = crate::real_store::core().await;
    let rows = AsyncRecords::authorized(
        store.clone(),
        INSTANCE,
        [SCHEMA.as_str().into(), CHAIN_LIFE_SCHEMA.as_str().into()],
    )
    .unwrap();
    (store, rows)
}
// This is the same prepare/conditional/settle boundary used by the host. It
// submits one immutable request and never turns an unresolved outcome into Applied.
pub(super) async fn append(
    book: &ChainBook,
    rows: &AsyncRecords,
    scope: &str,
    content: &[u8],
) -> Outcome {
    let mut operation = [0; 16];
    getrandom::fill(&mut operation).unwrap();
    let (request, position) = book
        .prepare_ordinary_async(
            rows,
            OrdinaryChain {
                instance: INSTANCE,
                schema: SCHEMA,
                scope,
                content,
                framing: FRAMING,
            },
            operation,
        )
        .await
        .unwrap();
    let outcome = rows.conditional(&request).await.unwrap();
    match outcome {
        Outcome::Applied => book.conditional_settled(&position, Decision::Applied),
        Outcome::ConditionConflict => {
            book.conditional_settled(&position, Decision::ConditionConflict)
        }
        _ => {}
    }
    outcome
}
pub(super) async fn stored(rows: &AsyncRecords, scope: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let prefix = record_key(INSTANCE, format!("{scope}/").as_bytes());
    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let page = rows
            .page(SCHEMA.as_str(), &prefix, cursor.as_ref())
            .await
            .unwrap();
        for (key, value) in page.rows {
            out.push((key, value.expose(&crate::seal::lend()).clone()));
        }
        cursor = page.next;
        if cursor.is_none() {
            return out;
        }
    }
}
pub(super) async fn records(rows: &AsyncRecords, scope: &str) -> Vec<StreamRecord> {
    stored(rows, scope)
        .await
        .iter()
        .filter_map(|(_, body)| host_chains::decode(scope, body, FRAMING))
        .collect()
}
async fn raw_put(rows: &AsyncRecords, scope: &str, seq: u64, body: Vec<u8>) {
    let key = record_key(
        INSTANCE,
        &busbar_contract::services::chain_key(scope.as_bytes(), seq),
    );
    assert_eq!(
        rows.put(SCHEMA.as_str(), &key, busbar_contract::Secret::new(body))
            .await
            .unwrap(),
        Outcome::Applied
    );
}
async fn tamper_first(rows: &AsyncRecords, scope: &str) {
    let first = records(rows, scope).await.remove(0);
    let changed = StreamRecord::from_parts(
        scope.into(),
        first.seq(),
        first.prev_hash().into(),
        first.hash().into(),
        b"|TAMPERED".to_vec(),
        Framing::LengthPrefixed,
        true,
    );
    raw_put(
        rows,
        scope,
        first.seq(),
        host_chains::encode(&changed).unwrap(),
    )
    .await;
}
fn verified(scope: &str, stored: &[(Vec<u8>, Vec<u8>)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let prefix = record_key(INSTANCE, &[]).len();
    let raw = stored
        .iter()
        .map(|(key, body)| (key[prefix..].to_vec(), body.clone()))
        .collect();
    let _ = scope;
    host_chains::verified(INSTANCE, SCHEMA, raw, FRAMING)
}

#[tokio::test]
async fn neutral_records_survive_a_restart_and_the_chain_verifies() {
    let (store, rows) = fixture().await;
    let first = ChainBook::default();
    assert_eq!(
        append(&first, &rows, "acme", b"|first").await,
        Outcome::Applied
    );
    assert_eq!(
        append(&first, &rows, "acme", b"|second").await,
        Outcome::Applied
    );
    drop(first);
    drop(rows);
    let rows = AsyncRecords::authorized(
        store,
        INSTANCE,
        [SCHEMA.as_str().into(), CHAIN_LIFE_SCHEMA.as_str().into()],
    )
    .unwrap();
    let recovered = records(&rows, "acme").await;
    assert_eq!(recovered.len(), 2);
    assert!(verify_chain(&recovered).is_ok());
    let cache = Journal::new(1024);
    assert!(cache.seed_position("acme", &recovered).is_none());
    assert_eq!(cache.next_seq("acme"), 3);
    assert_eq!(
        append(&ChainBook::default(), &rows, "acme", b"|third").await,
        Outcome::Applied
    );
    assert_eq!(records(&rows, "acme").await.last().unwrap().seq(), 3);
}
#[tokio::test]
async fn restore_skips_one_undecodable_record_and_keeps_the_rest() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let (_, rows) = fixture().await;
    let book = ChainBook::default();
    append(&book, &rows, "acme", b"|first").await;
    append(&book, &rows, "acme", b"|second").await;
    raw_put(&rows, "acme", 3, b"{ not a chain body".to_vec()).await;
    let raw = stored(&rows, "acme").await;
    let cap = AuditDiagnosticCodes::default();
    let result = {
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(cap.clone()));
        verified("acme", &raw)
    };
    assert_eq!(
        result.len(),
        2,
        "the good payloads remain readable beside a damaged row"
    );
    assert_eq!(raw.len(), 3, "unreadable evidence is retained");
    assert!(cap
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|line| line.contains("BUSBAR-2046")));
}
#[tokio::test]
async fn a_scope_with_only_undecodable_rows_is_unreadable_not_empty() {
    let (_, rows) = fixture().await;
    for seq in 1..=2 {
        raw_put(&rows, "acme", seq, b"{ not a chain body".to_vec()).await;
    }
    let raw = stored(&rows, "acme").await;
    assert_eq!(raw.len(), 2, "the actual native scope is not empty");
    assert!(
        verified("acme", &raw).is_empty(),
        "unreadable bodies are never invented payloads"
    );
    assert_eq!(
        stored(&rows, "acme").await,
        raw,
        "verification does not repair or delete evidence"
    );
}
#[tokio::test]
async fn neutral_failed_write_does_not_burn_a_sequence() {
    let (_, rows) = fixture().await;
    let book = ChainBook::default();
    append(&book, &rows, "acme", b"|one").await;
    let (mut request, position) = book
        .prepare_ordinary_async(
            &rows,
            OrdinaryChain {
                instance: INSTANCE,
                schema: SCHEMA,
                scope: "acme",
                content: b"|two",
                framing: FRAMING,
            },
            [7; 16],
        )
        .await
        .unwrap();
    request.predicates.push(Predicate {
        schema: SCHEMA.as_str().into(),
        key: record_key(INSTANCE, b"deliberate-refusal"),
        expected: Expected::Bytes(b"absent".to_vec()),
    });
    assert_eq!(
        rows.conditional(&request).await.unwrap(),
        Outcome::ConditionConflict
    );
    book.conditional_settled(&position, Decision::ConditionConflict);
    assert_eq!(records(&rows, "acme").await.len(), 1);
    assert_eq!(
        append(&book, &rows, "acme", b"|two").await,
        Outcome::Applied
    );
    assert_eq!(
        records(&rows, "acme").await.last().unwrap().seq(),
        2,
        "definitive refusal consumes no sequence"
    );
}
#[tokio::test]
async fn a_tampered_row_is_reported_and_still_restored() {
    let (_, rows) = fixture().await;
    let book = ChainBook::default();
    append(&book, &rows, "acme", b"|first").await;
    append(&book, &rows, "acme", b"|second").await;
    tamper_first(&rows, "acme").await;
    let restored = records(&rows, "acme").await;
    let cache = Journal::new(1024);
    assert!(cache.seed_position("acme", &restored).is_some());
    assert_eq!(restored.len(), 2);
    assert_eq!(cache.next_seq("acme"), 3);
    assert_eq!(
        stored(&rows, "acme").await.len(),
        2,
        "tamper evidence is not deleted"
    );
}
#[test]
fn a_pure_chain_without_a_sink_has_no_durability_claim() {
    let mut chain = Chain::<StreamRecord>::new();
    let record = chain.append(
        "acme",
        StreamInput::new(b"|one".to_vec(), Framing::LengthPrefixed, true),
    );
    assert_eq!(record.seq(), 1);
    assert_eq!(chain.next_seq(), 2);
    let cache = Journal::new(1024);
    cache.seed_position("acme", &[record]);
    assert_eq!(cache.len(), 1);
}
#[tokio::test]
async fn an_evicted_scope_resumes_from_the_store_not_from_seq_one() {
    let (_, rows) = fixture().await;
    let book = ChainBook::default();
    let cache = Journal::new(2);
    for scope in ["a", "a", "b", "c"] {
        append(&book, &rows, scope, b"|one").await;
        cache.seed_position(scope, &records(&rows, scope).await);
    }
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.next_seq("a"), 1, "the oldest cache entry was evicted");
    let cold = ChainBook::default();
    append(&cold, &rows, "a", b"|late").await;
    let recovered = records(&rows, "a").await;
    assert_eq!(recovered.last().unwrap().seq(), 3);
    assert!(verify_chain(&recovered).is_ok());
    cache.seed_position("a", &recovered);
    assert_eq!(cache.next_seq("a"), 4);
}
#[tokio::test]
async fn an_evicted_neutral_scopes_tampered_tail_surfaces_a_break_on_resume() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let (_, rows) = fixture().await;
    append(&ChainBook::default(), &rows, "acme", b"|first").await;
    tamper_first(&rows, "acme").await;
    let cap = AuditDiagnosticCodes::default();
    {
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(cap.clone()));
        assert_eq!(
            append(&ChainBook::default(), &rows, "acme", b"|second").await,
            Outcome::Applied
        );
    }
    assert_eq!(records(&rows, "acme").await.last().unwrap().seq(), 2);
    assert!(
        cap.0
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.contains("BUSBAR-2048")),
        "native cold resume reports its chain break"
    );
}
#[tokio::test]
async fn a_fresh_native_history_row_survives_retention() {
    let (core, _) = fixture().await;
    let history = AsyncHistory::authorized(
        core,
        INSTANCE,
        [HistoryCollection {
            kind: SCHEMA.as_str(),
            mode: HistoryMode::Append,
            retention: Retention::Age,
            parent: None,
        }],
    )
    .unwrap();
    let now = crate::store::now();
    let mut chain = Chain::<StreamRecord>::new();
    let record = chain.append(
        "acme",
        StreamInput::new(b"|fresh".to_vec(), Framing::LengthPrefixed, true),
    );
    let body = crate::store::plane_view::encode(&super::NeutralBody {
        seq: record.seq(),
        prev_hash: record.prev_hash().into(),
        hash: record.hash().into(),
        content: record.content.clone(),
    })
    .unwrap();
    let envelope = PlaneRecord {
        kind: SCHEMA.as_str().into(),
        id: "acme".into(),
        parent: Some("acme".into()),
        seq: record.seq(),
        ts: now,
        disposition: PlaneDisposition::Active,
        body,
    };
    assert_eq!(
        history.append(envelope.view()).await.unwrap(),
        HistoryOutcome::Applied
    );
    assert_eq!(
        history
            .purge(SCHEMA.as_str(), now.saturating_sub(3600))
            .await
            .unwrap()
            .1,
        0
    );
    assert_eq!(
        history
            .list(SCHEMA.as_str(), &PlaneSelector::Parent("acme".into()))
            .await
            .unwrap()
            .len(),
        1
    );
}
#[tokio::test]
async fn a_forgotten_scope_on_an_uncapped_stream_resumes_from_the_store_not_seq_one() {
    let (_, rows) = fixture().await;
    let book = ChainBook::default();
    append(&book, &rows, "acme", b"|one").await;
    append(&book, &rows, "acme", b"|two").await;
    let cache = Journal::new(usize::MAX);
    cache.seed_position("acme", &records(&rows, "acme").await);
    cache.forget("acme");
    assert_eq!(cache.len(), 0);
    append(&ChainBook::default(), &rows, "acme", b"|late").await;
    assert_eq!(records(&rows, "acme").await.last().unwrap().seq(), 3);
}
#[tokio::test]
async fn a_chain_another_node_advanced_is_continued_after_a_refused_write() {
    let (_, rows) = fixture().await;
    let a = ChainBook::default();
    let b = ChainBook::default();
    append(&a, &rows, "acme", b"|one").await;
    append(&b, &rows, "acme", b"|two").await;
    assert_eq!(
        append(&a, &rows, "acme", b"|three").await,
        Outcome::ConditionConflict,
        "a stale cached tail is refused atomically"
    );
    assert_eq!(append(&a, &rows, "acme", b"|three").await, Outcome::Applied);
    let recovered = records(&rows, "acme").await;
    assert_eq!(recovered.last().unwrap().seq(), 3);
    assert!(verify_chain(&recovered).is_ok());
}
#[tokio::test]
async fn a_failed_append_resumes_past_a_row_boot_already_reported_unreadable() {
    let (_, rows) = fixture().await;
    let book = ChainBook::default();
    append(&book, &rows, "acme", b"|one").await;
    append(&book, &rows, "acme", b"|two").await;
    raw_put(&rows, "acme", 99, b"{ not a chain body".to_vec()).await;
    let before = stored(&rows, "acme").await;
    assert_eq!(verified("acme", &before).len(), 2);
    assert_eq!(
        append(&ChainBook::default(), &rows, "acme", b"|later").await,
        Outcome::Applied
    );
    assert_eq!(
        records(&rows, "acme").await.last().unwrap().seq(),
        100,
        "native owner does not overwrite occupied unreadable positions or invent seq one"
    );
    assert!(stored(&rows, "acme").await.contains(&before[2]));
}
#[tokio::test]
async fn unreadable_resume_rows_do_not_hide_a_decodable_chain_break() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let (_, rows) = fixture().await;
    let book = ChainBook::default();
    append(&book, &rows, "acme", b"|one").await;
    append(&book, &rows, "acme", b"|two").await;
    tamper_first(&rows, "acme").await;
    raw_put(&rows, "acme", 99, b"{ not a chain body".to_vec()).await;
    let cap = AuditDiagnosticCodes::default();
    {
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(cap.clone()));
        append(&ChainBook::default(), &rows, "acme", b"|later").await;
    }
    let codes = cap.0.lock().unwrap();
    assert!(codes.iter().any(|line| line.contains("BUSBAR-2046")));
    assert!(codes.iter().any(|line| line.contains("BUSBAR-2048")));
    assert_eq!(records(&rows, "acme").await.last().unwrap().seq(), 100);
}
#[tokio::test]
async fn an_entirely_unreadable_resume_never_invents_a_new_chain_at_seq_one() {
    let (_, rows) = fixture().await;
    raw_put(&rows, "acme", 99, b"{ not a chain body".to_vec()).await;
    let original = stored(&rows, "acme").await;
    append(&ChainBook::default(), &rows, "acme", b"|replacement").await;
    let after = stored(&rows, "acme").await;
    assert_eq!(after.len(), 2);
    assert!(after.contains(&original[0]));
    assert_eq!(
        records(&rows, "acme").await[0].seq(),
        100,
        "occupied evidence is never replaced by a fabricated genesis"
    );
}
