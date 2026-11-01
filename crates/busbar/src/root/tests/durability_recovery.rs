// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO DISASTER-RECOVERY VERBS, PROVEN ACROSS A RESTART OVER A REAL STORE. Each cell boots a node's book over the build's linked ephemeral
//! store, opened through its door on the store axis exactly as boot opens the configured store,
//! runs one verb through the verb store the boot binds ([`node_verb_store`]), boots a SECOND book
//! over the SAME store, and reads the effect back from the store and the chain — never from the
//! first node's memory.
//!
//! RED before the fix: the verbs answered `Ok` from the loader adapter's node-memory `Recovery`
//! counters, so the restarted node found no operator break on its chain, and a restore that
//! restored nothing was acknowledged.

use super::*;
use crate::root::durability::{build_on_store, wait_for, DurabilityConfig, JournalLane};
use busbar_contract::caps::AdminVerb;
use busbar_contract::store_calls::{StoreAxis as _, StoreDoor};
use busbar_kernel_seams::verb_store::{Store as VerbStore, StoreError as VerbStoreError};

/// The store's label, as the configuration names it.
const STORE: &str = "configured";

/// This node's id on the store: the same across the restart, as the store's node registry gives
/// a host back its id.
const NODE: u64 = 31;

/// One opened store: the 1.5.5 op set and the v3 slots of ONE instance.
struct Opened {
    records: Arc<dyn busbar_contract::records::RecordStore>,
    calls: Arc<dyn busbar_contract::store_calls::StoreCalls>,
}

/// The build's linked ephemeral store, opened through its door on the store axis, as boot opens it.
fn ephemeral_store() -> Opened {
    let axis = crate::root::loader::store_v3::DoorStoreAxis {
        dispatcher: {
            let d = Arc::new(crate::root::loader::dispatch::Dispatcher::new(
                crate::root::loader::dispatch::DispatchConfig::default(),
            ));
            // The host lends the dispatcher its seal (Part 2 #54), as the root does at boot.
            let _ = d.lend_seal(busbar_kernel::seal::lend());
            d
        },
        logs: crate::root::boot::plugin_logs().clone(),
        // The build's ephemeral store declares no need: it serves with no connection table.
        conns: crate::root::loader::dispatch::ConnTable::NoNeeds,
        mint: busbar_kernel::door::op_id,
    };
    let opened = axis
        .open(
            StoreDoor::Linked(
                crate::LINKED
                    .stores
                    .iter()
                    .find(|s| s.1)
                    .expect("the build links an ephemeral store")
                    .2,
            ),
            STORE,
            b"{}",
        )
        .expect("the ephemeral store opens through its door");
    Opened {
        records: opened.records,
        calls: opened.calls.expect("a door-opened store has its v3 slots"),
    }
}

/// C6: THE STORE'S V3 CALLS SERVE THE KEY, CREDENTIAL, DENYLIST AND LEGACY-READ OPS AS THE 1.5.5
/// OP SET DID, over one door-opened store: what one surface writes the other reads back the same,
/// so a caller moved off the synchronous bridge reads and writes what it did before.
#[test]
fn the_v3_key_credential_and_denylist_ops_answer_as_the_op_set_did() {
    use busbar_contract::records::VirtualKey;
    let store = ephemeral_store();
    let key = |id: &str| VirtualKey {
        id: id.to_string(),
        generation_hash: format!("binding:{id}:1"),
        enabled: true,
        ..VirtualKey::default()
    };
    wait_for(store.calls.put_key(&key("k1"))).expect("v3 put_key");
    store.records.put_key(&key("k2")).expect("op-set put_key");
    let got = wait_for(store.calls.get_key("k2")).expect("v3 get_key");
    assert_eq!(got.map(|k| k.id), Some("k2".to_string()));
    let mut v3: Vec<String> = (wait_for(store.calls.list_keys()).expect("v3 list_keys"))
        .into_iter()
        .map(|k| k.id)
        .collect();
    let mut op_set: Vec<String> = (store.records.list_keys().expect("op-set list_keys"))
        .into_iter()
        .map(|k| k.id)
        .collect();
    v3.sort();
    op_set.sort();
    assert_eq!(v3, vec!["k1".to_string(), "k2".to_string()]);
    assert_eq!(v3, op_set);

    assert_eq!(
        wait_for(store.calls.list_credentials("k1"))
            .expect("v3 list_credentials")
            .len(),
        store
            .records
            .list_credentials("k1")
            .expect("op-set list_credentials")
            .len()
    );
    assert_eq!(
        wait_for(store.calls.list_credentials_since(0))
            .expect("v3 list_credentials_since")
            .len(),
        store
            .records
            .list_credentials_since(0)
            .expect("op-set list_credentials_since")
            .len()
    );

    wait_for(store.calls.add_denylist("sub-1", "revoked")).expect("v3 add_denylist");
    assert_eq!(
        wait_for(store.calls.list_denylist()).expect("v3 list_denylist"),
        store.records.list_denylist().expect("op-set list_denylist")
    );
    assert!(store
        .records
        .list_denylist()
        .expect("op-set list_denylist")
        .contains(&"sub-1".to_string()));

    wait_for(store.calls.delete_key("k1")).expect("v3 delete_key");
    assert_eq!(
        wait_for(store.calls.get_key("k1"))
            .expect("v3 get_key")
            .map(|k| k.deleted_at.is_some()),
        store
            .records
            .get_key("k1")
            .expect("op-set get_key")
            .map(|k| k.deleted_at.is_some())
    );
    assert_eq!(
        wait_for(store.calls.list_audit())
            .expect("v3 list_audit")
            .len(),
        store.records.list_audit().expect("op-set list_audit").len()
    );
    assert_eq!(
        wait_for(store.calls.list_audit_tail(1))
            .expect("v3 list_audit_tail")
            .len(),
        store
            .records
            .list_audit_tail(1)
            .expect("op-set list_audit_tail")
            .len()
    );
    assert_eq!(
        wait_for(store.calls.list_metering(0))
            .expect("v3 list_metering")
            .len(),
        store
            .records
            .list_metering(0)
            .expect("op-set list_metering")
            .len()
    );
}

/// The verbs unit's admin token, as the kernel mints one for the length of an admin verb.
fn admin() -> Grant<AdminVerb> {
    busbar_kernel::test_support::tokens::grant::<AdminVerb>()
}

/// One boot of node [`NODE`] over `store`: its book, resumed from the chain the store kept, and the
/// verb store the boot binds over that book and that store.
fn boot(store: &Opened) -> (Arc<Mutex<Durability>>, Arc<dyn VerbStore + Send + Sync>) {
    let lane = JournalLane::start(Arc::clone(&store.calls), STORE).expect("the lane starts");
    let book = Arc::new(Mutex::new(
        build_on_store(&DurabilityConfig { data_dir: None }, NODE, lane, None)
            .expect("the store reads the chain back"),
    ));
    let verbs = node_verb_store(
        Arc::clone(&book),
        busbar_kernel::test_support::tokens::grant::<DurableWrite>(),
        STORE,
    )
    .expect("a node over a configured store binds the verb store");
    (book, verbs)
}

/// Wait until the store took everything the book's lane holds, then stop the node.
fn stop(book: Arc<Mutex<Durability>>) {
    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    assert!(
        durability
            .lane()
            .expect("a book over the store")
            .drain(std::time::Duration::from_secs(5)),
        "the store takes the journal's records"
    );
}

/// The chain the book holds, read and verified.
fn verified_chain(book: &Arc<Mutex<Durability>>) -> Vec<JournalRecord> {
    book.lock()
        .unwrap_or_else(|p| p.into_inner())
        .chain()
        .expect("the chain reads back")
        .expect("the chain verifies")
}

/// **`chain_break` IS A FACT IN THE CHAIN, AND SURVIVES A RESTART.** The verb seals an operator
/// break on the node's journal; a node booted again over the same store walks a chain that still
/// verifies and carries exactly one deliberate operator break.
#[test]
fn a_chain_break_is_on_the_chain_after_a_restart_over_the_same_store() {
    let store = ephemeral_store();
    {
        let (book, verbs) = boot(&store);
        verbs
            .chain_break(&admin())
            .expect("the chain break is sealed and kept by the store");
        stop(book);
    }

    let (book, _verbs) = boot(&store);
    verified_chain(&book);
    let breaks = book
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .operator_breaks()
        .expect("the chain reads back")
        .expect("the chain verifies: a deliberate break is not corruption");
    assert_eq!(
        breaks.len(),
        1,
        "the restarted node reads exactly one operator break off the chain the store kept"
    );
}

/// The `tracing` events one closure fires on this thread, rendered `LEVEL message field=value ...`.
fn events_of(run: impl FnOnce()) -> Vec<String> {
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
    tracing::subscriber::with_default(log.clone(), run);
    let lines = log.0.lock().unwrap_or_else(|p| p.into_inner()).clone();
    lines
}

/// **`store_restore` REFUSES, AND NOTHING CHANGES ACROSS A RESTART.** The configured store has no
/// restore operation, so the verb answers a store failure — never `Ok` — with one error line naming
/// it and nothing put on the chain; a node booted again over the same store finds no operator break
/// and no floor.
#[test]
fn a_store_restore_is_refused_and_changes_nothing_across_a_restart() {
    let store = ephemeral_store();
    {
        let (book, verbs) = boot(&store);
        let before = verified_chain(&book).len();
        let mut answer = None;
        let lines =
            events_of(|| answer = Some(verbs.store_restore(&admin(), "nightly-2026-10-20")));
        assert!(
            matches!(answer, Some(Err(VerbStoreError::Failed))),
            "a restore that restores nothing is refused, never acknowledged: {answer:?}"
        );
        let errors: Vec<&String> = lines.iter().filter(|l| l.starts_with("ERROR")).collect();
        assert_eq!(errors.len(), 1, "one error line: {lines:?}");
        assert!(
            errors[0].contains("store_restore"),
            "the line names the verb: {}",
            errors[0]
        );
        assert_eq!(
            verified_chain(&book).len(),
            before,
            "the refused restore put nothing on the chain"
        );
        stop(book);
    }

    let (book, _verbs) = boot(&store);
    assert!(
        book.lock()
            .unwrap_or_else(|p| p.into_inner())
            .operator_breaks()
            .expect("the chain reads back")
            .expect("the chain verifies")
            .is_empty(),
        "and broke nothing"
    );
}

/// C6: THE STORE'S V3 CALLS ANSWER THE PLANE PARENTS AND THE RETENTION PURGE AS THE 1.5.5 OP SET
/// DID, over one door-opened store: the same parents, then the same records purged, so a caller
/// moved off the synchronous bridge reads and purges what it read and purged before.
#[test]
fn the_v3_plane_parents_and_purge_answer_as_the_op_set_did() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord};
    const KIND: &str = "c6-probe";
    let store = ephemeral_store();
    // A parented row is placed by `(parent, seq)`, so two rows under one parent take two seqs: at
    // one seq the second would be the first rewritten, and the store would hold two rows, not three.
    let row = |id: &str, parent: &str, seq: u64, ts: u64| PlaneRecord {
        kind: KIND.to_string(),
        id: id.to_string(),
        parent: Some(parent.to_string()),
        seq,
        ts,
        disposition: PlaneDisposition::Terminal,
        body: b"{}".to_vec(),
    };
    for r in [
        row("a", "p1", 0, 10),
        row("b", "p2", 0, 20),
        row("c", "p2", 1, 30),
    ] {
        wait_for(store.calls.upsert_plane_record(r.view())).expect("the store takes the row");
    }
    let mut v3 = wait_for(store.calls.list_plane_record_parents(KIND)).expect("v3 parents");
    let mut op_set = store
        .records
        .list_plane_record_parents(KIND)
        .expect("op-set parents");
    v3.sort();
    op_set.sort();
    assert_eq!(v3, vec!["p1".to_string(), "p2".to_string()]);
    assert_eq!(v3, op_set);
    assert_eq!(
        wait_for(store.calls.purge_plane_records_before(KIND, 25)).expect("v3 purge"),
        2,
        "the two terminal rows older than 25 go"
    );
    assert_eq!(
        store
            .records
            .purge_plane_records_before(KIND, 25)
            .expect("op-set purge"),
        0,
        "nothing older is left for the op set to purge"
    );
    assert_eq!(
        wait_for(store.calls.list_plane_record_parents(KIND)).expect("v3 parents"),
        vec!["p2".to_string()]
    );
}
