// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use busbar_contract::caps::AdminVerb;
use busbar_kernel::host_records_async::{
    AsyncHistory, HistoryCollection, HistoryMode, HistoryOutcome,
};
use busbar_kernel::persistence::facade::CoreStore;
use busbar_kernel::persistence::journal::{BufferBudget, RuntimeJournal};
use busbar_kernel::persistence::recovery_api::{Store as VerbStore, StoreError as VerbStoreError};

const STORE: &str = "configured";
const NODE: u64 = 31;
const BUDGET: BufferBudget = BufferBudget {
    records: 128,
    bytes: 1024 * 1024,
};

#[tokio::test]
async fn native_key_credential_and_denylist_operations_preserve_identity_state() {
    use busbar_contract::records::VirtualKey;
    let core = crate::root::real_store::core().await;
    let identity = core.identity();
    let key = |id: &str| VirtualKey {
        id: id.into(),
        generation_hash: format!("binding:{id}:1"),
        enabled: true,
        ..Default::default()
    };
    identity
        .put_key(&key("k1"))
        .await
        .expect("first key commits");
    identity
        .put_key(&key("k2"))
        .await
        .expect("second key commits");
    assert_eq!(
        identity.get_key("k2").await.unwrap().map(|key| key.id),
        Some("k2".into())
    );
    let mut keys: Vec<_> = identity
        .list_keys()
        .await
        .unwrap()
        .into_iter()
        .map(|key| key.id)
        .collect();
    keys.sort();
    assert_eq!(keys, ["k1", "k2"]);
    assert!(identity.list_credentials("k1").await.unwrap().is_empty());
    assert!(identity.list_credentials_since(0).await.unwrap().is_empty());
    identity.add_denylist("sub-1", "revoked").await.unwrap();
    assert_eq!(identity.list_denylist().await.unwrap(), ["sub-1"]);
    identity.delete_key("k1").await.unwrap();
    assert!(identity
        .get_key("k1")
        .await
        .unwrap()
        .unwrap()
        .deleted_at
        .is_some());
    assert!(core.ledger().list_metering(0).await.unwrap().is_empty());
}

fn admin() -> Grant<AdminVerb> {
    crate::root::kernel::new_kernel().admin_token()
}

async fn boot(core: Arc<CoreStore>) -> (Arc<Mutex<Durability>>, Arc<dyn VerbStore + Send + Sync>) {
    let journal = RuntimeJournal::open(core, NODE, BUDGET)
        .await
        .expect("native journal opens");
    let book = crate::root::durability::node_book(journal, BUDGET)
        .await
        .unwrap()
        .durability;
    let verbs = node_verb_store(
        book.clone(),
        crate::root::kernel::new_kernel().durability_token(),
        STORE,
    )
    .expect("configured native recovery binds");
    (book, verbs)
}
async fn stop(book: &Arc<Mutex<Durability>>) {
    let journal = book.lock().unwrap().runtime_journal();
    journal
        .flush()
        .await
        .expect("the Store confirms all original journal frames");
}
async fn verified_chain(book: &Arc<Mutex<Durability>>) -> Vec<JournalRecord> {
    let selected = book.lock().unwrap().chain_at();
    selected
        .read()
        .await
        .expect("native chain reads")
        .expect("native chain verifies")
}
fn breaks(records: &[JournalRecord]) -> usize {
    records
        .iter()
        .filter(|record| record.class == busbar_kernel_wal::RecordClass::ChainBreak)
        .count()
}

#[tokio::test]
async fn a_chain_break_is_on_the_chain_after_a_restart_over_the_same_store() {
    let core = crate::root::real_store::core().await;
    {
        let (book, verbs) = boot(core.clone()).await;
        verbs
            .chain_break(&admin())
            .await
            .expect("operator break commits natively");
        stop(&book).await;
    }
    let (book, _) = boot(core).await;
    assert_eq!(
        breaks(&verified_chain(&book).await),
        1,
        "restart recovers exactly one deliberate operator break without corruption"
    );
}

async fn events_of<F: std::future::Future>(run: F) -> (F::Output, Vec<String>) {
    #[derive(Clone, Default)]
    struct EventLog(Arc<Mutex<Vec<String>>>);
    impl tracing::Subscriber for EventLog {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Render(String);
            impl tracing::field::Visit for Render {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0.push_str(&format!(" {}={:?}", field.name(), value));
                }
            }
            let mut line = Render(event.metadata().level().to_string());
            event.record(&mut line);
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(line.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    let log = EventLog::default();
    use tracing::instrument::WithSubscriber;
    let answer = run.with_subscriber(log.clone()).await;
    let lines = log.0.lock().unwrap_or_else(|p| p.into_inner()).clone();
    (answer, lines)
}

#[tokio::test]
async fn a_store_restore_is_refused_and_changes_nothing_across_a_restart() {
    let core = crate::root::real_store::core().await;
    {
        let (book, verbs) = boot(core.clone()).await;
        let before = verified_chain(&book).await.len();
        let grant = admin();
        let (answer, lines) = events_of(verbs.store_restore(&grant, "nightly-2026-10-20")).await;
        assert!(
            matches!(answer, Err(VerbStoreError::Failed)),
            "unsupported restore is never acknowledged: {answer:?}"
        );
        let errors: Vec<_> = lines
            .iter()
            .filter(|line| line.starts_with("ERROR"))
            .collect();
        assert_eq!(errors.len(), 1, "one error line: {lines:?}");
        assert!(errors[0].contains("store_restore"));
        assert_eq!(
            verified_chain(&book).await.len(),
            before,
            "refused restore appends nothing"
        );
        stop(&book).await;
    }
    let (book, _) = boot(core).await;
    assert_eq!(
        breaks(&verified_chain(&book).await),
        0,
        "refused restore breaks nothing across restart"
    );
}

#[tokio::test]
async fn native_plane_parent_inventory_and_terminal_purge_preserve_rows() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord, Retention};
    const KIND: &str = "c6-probe";
    let core = crate::root::real_store::core().await;
    let history = AsyncHistory::authorized(
        core,
        "durability-recovery",
        [HistoryCollection {
            kind: KIND,
            mode: HistoryMode::Upsert,
            retention: Retention::TerminalOnly,
            parent: None,
        }],
    )
    .unwrap();
    let row = |id: &str, parent: &str, seq, ts| PlaneRecord {
        kind: KIND.into(),
        id: id.into(),
        parent: Some(parent.into()),
        seq,
        ts,
        disposition: PlaneDisposition::Terminal,
        body: b"{}".to_vec(),
    };
    for row in [
        row("a", "p1", 0, 10),
        row("b", "p2", 0, 20),
        row("c", "p2", 1, 30),
    ] {
        assert!(matches!(
            history.upsert(row.view()).await.unwrap(),
            HistoryOutcome::Applied
        ));
    }
    let mut parents = history.parents(KIND).await.unwrap();
    parents.sort();
    assert_eq!(parents, ["p1", "p2"]);
    let (outcome, count) = history.purge(KIND, 25).await.unwrap();
    assert_eq!(outcome, HistoryOutcome::Applied);
    assert_eq!(count, 2, "two terminal rows older than 25 go");
    let (_, count) = history.purge(KIND, 25).await.unwrap();
    assert_eq!(count, 0, "no old row remains");
    assert_eq!(history.parents(KIND).await.unwrap(), ["p2"]);
}
