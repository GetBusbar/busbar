// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FLEET-SHARED RATE-CARD HISTORY, against a store the test holds (MONEY-DESIGN section 3a, PR-B1):
//! the card in force and every instant's card survive a restart and a new node id (T1-card), a
//! doubtful write is pending, re-put to READY and closes admissions meanwhile (T8), two nodes
//! editing at once converge with an alarm naming the lost fields (T13), a joining node's stale
//! file never moves the card (T19), the skew refusal is cleared by `card void` (T22), and the
//! journal's cards migrate under time keys.

use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use busbar_kernel::config::card::{CardFields, CardSet};
use busbar_kernel::config::RateEntryCfg;
use busbar_kernel::rate_apply::CardPut;
use busbar_kernel_ledger::cost::EntryKey;

use super::{CardStore, Seed};
use crate::root::card_store::{EntryAuthor, StoredEntry, CARD_SCHEMA, SKEW_MS};
use crate::root::store_double::RecordSlots;

fn card(input: f64, fee: i64) -> CardFields {
    CardFields {
        rate_card: Some(BTreeMap::from([(
            "m".to_string(),
            RateEntryCfg {
                input_utok: input,
                output_utok: input * 2.0,
                ..RateEntryCfg::default()
            },
        )])),
        per_request_fee: fee,
        ..CardFields::default()
    }
}

fn seed(card: &CardFields) -> Seed {
    Seed {
        merged: Some(card.clone()),
        file: Some(card.clone()),
    }
}

fn now_ms() -> u64 {
    busbar_kernel::store::now_ms()
}

fn booted(store: &RecordSlots, node: u64, seed: Seed) -> Arc<CardStore> {
    let cs = CardStore::new(store.calls(), node, None);
    cs.boot(seed, Vec::new()).expect("the history boots");
    cs
}

fn fee(n: i64) -> CardSet {
    CardSet {
        per_request_fee: Some(n),
        ..CardSet::default()
    }
}

fn put(cs: &Arc<CardStore>, set: &CardSet) -> Result<CardPut, String> {
    cs.put(set, "test", &mut |_| Ok(()))
}

/// The id and card resolved at each instant.
fn resolved(cs: &CardStore, at: &[u64]) -> Vec<(String, Option<CardFields>)> {
    let history = cs.history().expect("a history");
    at.iter()
        .map(|t| {
            let view = history.current();
            let entry = view.entry_at(*t).expect("covered");
            (
                entry.id().hex(),
                cs.entries()
                    .into_iter()
                    .find(|e| e.key == entry.key())
                    .map(|e| e.card),
            )
        })
        .collect()
}

fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ok() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// **T1-card.** Spend, a mid-window card edit, spend, restart — and restart under a NEW node id.
/// The card in force and the card of every priced instant (each segment's entry) are identical.
#[test]
fn t1_card_the_card_in_force_and_every_instants_card_survive_a_restart_and_a_new_node() {
    let store = RecordSlots::new();
    let boot = card(1.0, 0);
    let first = booted(&store, 1, seed(&boot));
    let spend_a = now_ms();
    std::thread::sleep(Duration::from_millis(5));
    assert!(matches!(put(&first, &fee(3)), Ok(CardPut::Ready { .. })));
    std::thread::sleep(Duration::from_millis(5));
    let spend_b = now_ms();
    let before = resolved(&first, &[spend_a, spend_b]);
    assert_eq!(
        before[0].1.as_ref(),
        Some(&boot),
        "the first spend keeps the boot card"
    );
    assert_eq!(before[1].1.as_ref().map(|c| c.per_request_fee), Some(3));
    let in_force = first.in_force();

    let again = booted(&store, 1, seed(&boot));
    assert_eq!(resolved(&again, &[spend_a, spend_b]), before);
    assert_eq!(
        again.in_force(),
        in_force,
        "the card in force survives the restart"
    );

    let elsewhere = booted(&store, 77, seed(&boot));
    assert_eq!(resolved(&elsewhere, &[spend_a, spend_b]), before);
    assert_eq!(
        elsewhere.in_force(),
        in_force,
        "and a new node id reads the same card"
    );
}

/// **T8.** A doubtful put (the store kept it and lost the ack) is applied as PENDING: this node
/// refuses admissions and further card changes, re-puts the same bytes until READY, and reopens.
/// With a data directory the pending entry survives a restart and is re-put before admissions open.
#[test]
fn t8_a_doubtful_put_is_pending_closes_admissions_and_is_reput_to_ready() {
    let store = RecordSlots::new();
    let dir = std::env::temp_dir().join(format!("card-t8-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cs = CardStore::new(store.calls(), 1, Some(dir.clone()));
    cs.boot(seed(&card(1.0, 0)), Vec::new()).unwrap();
    assert!(cs.admission_refusal().is_none());

    store.lose_acks(true);
    let answer = put(&cs, &fee(9)).expect("a doubtful write is never refused");
    let CardPut::Pending { key } = answer else {
        panic!("a doubtful write answers pending, not {answer:?}");
    };
    assert_eq!(
        cs.in_force().map(|c| c.per_request_fee),
        Some(9),
        "in force on this node"
    );
    assert!(cs.admission_refusal().is_some_and(|why| why.contains(&key)));
    let spooled = crate::root::card_store::Spool::load(&dir).unwrap();
    assert_eq!(
        spooled.pending.as_ref().map(|p| p.key.as_str()),
        Some(key.as_str())
    );
    let refused = put(&cs, &fee(10)).expect_err("no further card change while pending");
    assert!(refused.contains(&key), "{refused}");

    store.lose_acks(false);
    wait_until("the re-put to land", || cs.pending().is_none());
    assert!(
        cs.admission_refusal().is_none(),
        "admissions reopen at READY"
    );
    assert!(crate::root::card_store::Spool::load(&dir)
        .unwrap()
        .pending
        .is_none());
    let read = crate::root::card_store::scan(store.calls().as_ref(), None).unwrap();
    assert!(
        read.entries.iter().any(|e| e.key.hex() == key),
        "READY in the store"
    );

    // A pending entry the restart finds in the spool is re-put BEFORE admissions open.
    store.lose_acks(true);
    let CardPut::Pending { key } = put(&cs, &fee(11)).unwrap() else {
        panic!("pending");
    };
    store.lose_acks(false);
    drop(cs);
    let restarted = CardStore::new(store.calls(), 1, Some(dir.clone()));
    restarted.boot(seed(&card(1.0, 0)), Vec::new()).unwrap();
    assert!(restarted.pending().is_none());
    assert!(restarted.entries().iter().any(|e| e.key.hex() == key));
    assert_eq!(restarted.in_force().map(|c| c.per_request_fee), Some(11));
    let _ = std::fs::remove_dir_all(&dir);
}

/// **T13.** Two nodes PUT within one scan interval: both extend the same head. They converge on the
/// same history, the higher key is in force, every node alarms naming the LOST fields, and no
/// instant before the edits is repriced.
#[test]
fn t13_two_nodes_editing_at_once_converge_on_the_higher_key_and_alarm_the_lost_fields() {
    let store = RecordSlots::new();
    let boot = card(1.0, 0);
    let a = booted(&store, 1, seed(&boot));
    let b = booted(&store, 2, seed(&boot));
    let before = now_ms();
    std::thread::sleep(Duration::from_millis(5));
    // Both rescans happen before either write: the two edits cannot see each other.
    let gate = Arc::new(Barrier::new(2));
    let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let (gate, seen) = (Arc::clone(&gate), Arc::clone(&seen));
        store.on_scan(move || {
            if seen.fetch_add(1, std::sync::atomic::Ordering::AcqRel) < 2 {
                gate.wait();
            }
        });
    }
    let ta = {
        let a = Arc::clone(&a);
        std::thread::spawn(move || put(&a, &fee(5)))
    };
    let tb = {
        let b = Arc::clone(&b);
        std::thread::spawn(move || {
            put(
                &b,
                &CardSet {
                    rate_card: card(7.0, 0).rate_card,
                    ..CardSet::default()
                },
            )
        })
    };
    assert!(matches!(ta.join().unwrap(), Ok(CardPut::Ready { .. })));
    assert!(matches!(tb.join().unwrap(), Ok(CardPut::Ready { .. })));
    store.on_scan(|| {});
    a.rescan(None).unwrap();
    b.rescan(None).unwrap();

    let keys = |cs: &CardStore| cs.entries().iter().map(|e| e.key).collect::<Vec<_>>();
    assert_eq!(
        keys(&a),
        keys(&b),
        "both nodes hold the same ordered history"
    );
    assert_eq!(a.in_force(), b.in_force(), "and the same card in force");
    let puts: Vec<StoredEntry> = a
        .entries()
        .into_iter()
        .filter(|e| matches!(e.author, EntryAuthor::Put))
        .collect();
    let (lower, higher) = (&puts[0], &puts[1]);
    assert_eq!(lower.base, higher.base, "both extended one head");
    assert_eq!(
        a.in_force().as_ref(),
        Some(&higher.card),
        "the higher key is in force"
    );
    for node in [&a, &b] {
        let alarm = node
            .alarms()
            .into_iter()
            .find(|m| m.contains("concurrent rate card edits"))
            .expect("every node alarms");
        let lost = &lower.set_fields[0];
        assert!(alarm.contains(&format!("[{lost}]")), "{alarm}");
    }
    assert_eq!(
        resolved(&a, &[before])[0].1.as_ref(),
        Some(&boot),
        "nothing before the edits is repriced"
    );
}

/// **T19.** A node joining with a STALE file card (the seed, from before a PUT) does not change the
/// card in force; a node joining with an EDITED file card does not either, and says so.
#[test]
fn t19_a_node_with_a_stale_or_edited_file_joining_does_not_change_the_card() {
    let store = RecordSlots::new();
    let boot = card(1.0, 0);
    let first = booted(&store, 1, seed(&boot));
    put(&first, &fee(4)).unwrap();
    let in_force = first.in_force();

    let stale = booted(&store, 2, seed(&boot));
    assert_eq!(stale.in_force(), in_force);
    assert!(stale
        .alarms()
        .iter()
        .all(|m| !m.contains("card edit refused")));

    let edited = booted(&store, 3, seed(&card(50.0, 0)));
    assert_eq!(
        edited.in_force(),
        in_force,
        "an edited file card is never applied"
    );
    assert!(
        edited
            .alarms()
            .iter()
            .any(|m| m.contains("card edit refused")),
        "the boot alarms the edit: {:?}",
        edited.alarms()
    );
}

/// **T22.** An entry beyond now+SKEW refuses every card change, naming the entry and its writer,
/// and the node alarms; after `card void` the next change succeeds.
#[test]
fn t22_a_far_future_head_refuses_card_changes_until_card_void() {
    let store = RecordSlots::new();
    let boot = card(1.0, 0);
    let cs = booted(&store, 1, seed(&boot));
    let ahead = now_ms() + SKEW_MS + 60_000;
    let far = StoredEntry {
        key: EntryKey::new(ahead, [7; 8], 0),
        effective_from: ahead,
        effective_until: None,
        appended_at: ahead,
        author: EntryAuthor::Put,
        actor: "fast clock".to_string(),
        base: None,
        writer: 99,
        set_fields: vec!["per_request_fee".to_string()],
        card: card(1.0, 8),
        correction: None,
    };
    for (key, value) in far.records().unwrap() {
        store.put_row(CARD_SCHEMA, &key, value.as_slice());
    }
    let refused = put(&cs, &fee(2)).expect_err("the skew refusal");
    assert!(
        refused.contains(&far.key.hex()) && refused.contains("node 99"),
        "{refused}"
    );
    assert!(cs.alarms().iter().any(|m| m.contains(&far.key.hex())));
    assert_eq!(
        cs.in_force().map(|c| c.per_request_fee),
        Some(0),
        "it prices nothing yet"
    );

    cs.void(far.key, "operator").expect("card void");
    assert!(matches!(put(&cs, &fee(2)), Ok(CardPut::Ready { .. })));
    assert_eq!(cs.in_force().map(|c| c.per_request_fee), Some(2));
    let history = cs.history().unwrap();
    assert!(
        history.card_of(&far.key.id()).is_some(),
        "a voided id stays known"
    );
}

/// A file edit after first boot is judged against the file-only seed and the card in force.
#[test]
fn the_disk_rule_tells_unedited_copied_edited_back_and_edited_apart() {
    let store = RecordSlots::new();
    let boot = card(1.0, 0);
    let cs = booted(&store, 1, seed(&boot));
    use super::DiskVerdict;
    assert_eq!(cs.judge_disk(&boot), DiskVerdict::Accepted, "unedited");
    put(&cs, &fee(6)).unwrap();
    assert_eq!(
        cs.judge_disk(&boot),
        DiskVerdict::Accepted,
        "unedited after a PUT"
    );
    let in_force = cs.in_force().unwrap();
    assert_eq!(
        cs.judge_disk(&in_force),
        DiskVerdict::Accepted,
        "the PUT card copied in"
    );
    assert!(
        matches!(cs.judge_disk(&boot), DiskVerdict::FileDiffers(_)),
        "edited back to the seed after a PUT"
    );
    assert!(matches!(
        cs.judge_disk(&card(3.0, 0)),
        DiskVerdict::Edited(ref e) if e.fields == vec!["rate_card".to_string(), "per_request_fee".to_string()]
    ));
}

/// Two nodes opening an empty history at once: the LOWEST key wins and the other opening is never
/// in force.
#[test]
fn racing_openings_resolve_to_the_lowest_key() {
    let store = RecordSlots::new();
    let a = CardStore::new(store.calls(), 1, None);
    let b = CardStore::new(store.calls(), 2, None);
    let gate = Arc::new(Barrier::new(2));
    let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let (gate, seen) = (Arc::clone(&gate), Arc::clone(&seen));
        store.on_scan(move || {
            if seen.fetch_add(1, std::sync::atomic::Ordering::AcqRel) < 2 {
                gate.wait();
            }
        });
    }
    let ta = {
        let a = Arc::clone(&a);
        std::thread::spawn(move || a.boot(seed(&card(1.0, 0)), Vec::new()))
    };
    let tb = {
        let b = Arc::clone(&b);
        std::thread::spawn(move || b.boot(seed(&card(2.0, 0)), Vec::new()))
    };
    ta.join().unwrap().unwrap();
    tb.join().unwrap().unwrap();
    store.on_scan(|| {});
    a.rescan(None).unwrap();
    b.rescan(None).unwrap();
    let lowest = a
        .entries()
        .into_iter()
        .find(|e| matches!(e.author, EntryAuthor::Opening { .. }))
        .unwrap();
    assert_eq!(a.in_force().as_ref(), Some(&lowest.card));
    assert_eq!(b.in_force().as_ref(), Some(&lowest.card));
}

/// **THE MIGRATION.** Every chain's journalled cards are copied under time keys; a duplicate by
/// (card, `effective_from`) collapses to the lowest key and only the oldest opening is kept; the
/// card at every instant is the card the journal priced it at.
#[test]
fn the_journals_cards_migrate_under_time_keys_and_collapse_duplicates() {
    use crate::root::kernel::{card_from_raw, CardApplied, CardForm};
    let applied = |card: &CardFields, from: u64, at: u64| {
        let rates = card.rates();
        let built = card_from_raw(&rates.raw());
        CardApplied {
            effective_from: from,
            appended_at: at,
            policy_epoch: 0,
            form: CardForm::of(&rates.raw(), &built),
        }
    };
    let record = |node: u64, seq: u64, a: &CardApplied| busbar_kernel_wal::JournalRecord {
        class: busbar_kernel_wal::RecordClass::Policy,
        node,
        node_seq: seq,
        lease_epoch: 0,
        policy_epoch: 0,
        wall: a.appended_at / 1000,
        mono: 0,
        body: a.body(),
        body_hash: [0; 32],
        prev_hash: [0; 32],
        hash: [0; 32],
    };
    let boot = card(1.0, 0);
    let edit = card(1.0, 3);
    let chains = vec![
        (
            1,
            vec![
                record(1, 1, &applied(&boot, 0, 1_000)),
                record(1, 2, &applied(&edit, 5_000, 5_000)),
            ],
        ),
        // Node 2 opened later with the same card and journalled the same edit too.
        (
            2,
            vec![
                record(2, 1, &applied(&boot, 0, 2_000)),
                record(2, 2, &applied(&edit, 5_000, 5_000)),
            ],
        ),
    ];
    let migrated = super::migrated(&chains, 9);
    assert_eq!(migrated.len(), 2, "one opening and one edit: {migrated:#?}");
    assert_eq!(migrated[0].key.t_ms(), 1_000, "the oldest opening is kept");
    assert_eq!(migrated[0].card, boot);
    assert_eq!(migrated[1].card, edit);
    assert_eq!(migrated[1].key, EntryKey::new(5_000, 1u64.to_be_bytes(), 2));

    let store = RecordSlots::new();
    let cs = CardStore::new(store.calls(), 9, None);
    cs.boot(seed(&card(42.0, 0)), migrated.clone()).unwrap();
    assert_eq!(
        cs.entries().len(),
        2,
        "no opening is written over a migrated history"
    );
    assert_eq!(resolved(&cs, &[4_999])[0].1.as_ref(), Some(&boot));
    assert_eq!(resolved(&cs, &[5_000])[0].1.as_ref(), Some(&edit));
    // Idempotent: a second boot copies nothing again.
    let puts = store.puts();
    let again = CardStore::new(store.calls(), 9, None);
    again.boot(seed(&card(42.0, 0)), migrated).unwrap();
    assert_eq!(store.puts(), puts);
}
