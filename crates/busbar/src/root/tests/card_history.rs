// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use busbar_kernel::config::card::CardFields;
use busbar_kernel::config::RateEntryCfg;
use busbar_kernel_ledger::cost::EntryKey;

use super::CardStore;
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

fn now_ms() -> u64 {
    busbar_kernel::store::now_ms()
}

fn booted(store: &RecordSlots, node: u64, card: &CardFields) -> Arc<CardStore> {
    let cs = CardStore::new(store.calls(), node);
    cs.boot(card, &format!("boot of node {node}"), Vec::new())
        .expect("the history boots");
    cs
}

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

fn changes(cs: &CardStore) -> Vec<StoredEntry> {
    cs.entries()
        .into_iter()
        .filter(|e| matches!(e.author, EntryAuthor::Change))
        .collect()
}

fn original(cs: &CardStore, fee: i64, actor: &str) -> StoredEntry {
    let mut entry = cs.entries()[0].clone();
    entry.key = EntryKey::new(now_ms() + 1, [8; 8], fee as u32);
    entry.author = EntryAuthor::Change;
    entry.actor = actor.into();
    entry.base = cs.own().map(|(key, _)| key);
    entry.writer = cs.node();
    entry.set_fields = vec!["per_request_fee".into()];
    entry.correction = Some(b"original-correction-envelope".to_vec());
    entry.effective_from = now_ms();
    entry.appended_at = now_ms();
    entry.card = card(1.0, fee);
    entry
}

fn candidate_confirmed(cs: &CardStore, key: EntryKey) -> bool {
    cs.lock()
        .pending
        .iter()
        .find(|(held, _)| *held == key)
        .is_some_and(|(_, pending)| pending.confirmed.load(std::sync::atomic::Ordering::Acquire))
}

fn root_holder(store: &RecordSlots, card: &CardFields) -> Arc<crate::root::kernel::RootHistory> {
    let holder = Arc::new(crate::root::kernel::RootHistory::default());
    holder.keep_in_store(store.calls(), 1);
    holder.card_applied(card, "boot fixture");
    holder.boot_in_store(None).unwrap();
    holder
}

#[test]
fn actual_root_rate_apply_retains_old_prices_through_refusal_prepare_drop_and_rescan() {
    use busbar_kernel::rate_apply::{RateApply, RateEpoch};
    let slots = RecordSlots::new();
    let boot = card(1.0, 3);
    let edited = card(2.0, 7);
    let holder = root_holder(&slots, &boot);
    let store = holder.card_store().unwrap();
    let old = store.own();
    let pinned = holder.pin().unwrap();
    let epoch = holder.effective_from_at(now_ms());
    slots.refuse(true);
    assert!(holder
        .prepare(&edited, &edited.rates().raw(), "first attempt")
        .is_err());
    let key = store.pending().unwrap();
    let original = (*store.lock().pending[0].1.entry).clone();
    assert_eq!(store.own(), old);
    assert_eq!(holder.effective_from_at(now_ms()), epoch);
    assert!(!store.entries().contains(&original));
    assert!(holder
        .prepare(&card(3.0, 9), &edited.rates().raw(), "different candidate")
        .is_err());
    assert_eq!(store.pending(), Some(key));
    slots.refuse(false);
    let prepared = holder
        .prepare(&edited, &edited.rates().raw(), "exact retry")
        .unwrap();
    store.rescan(None).unwrap();
    assert_eq!(store.own(), old);
    assert!(!store.entries().contains(&original));
    drop(prepared);
    assert_eq!(store.pending(), Some(key));
    let confirmed = holder
        .prepare(&edited, &edited.rates().raw(), "commit exact original")
        .unwrap()
        .confirm_activation()
        .unwrap();
    store.rescan(None).unwrap();
    assert_eq!(
        store.own(),
        old,
        "confirmed activation still belongs to its generation commit"
    );
    confirmed.commit();
    assert_eq!(store.own(), Some((key, edited.clone())));
    assert_eq!(changes(store), vec![original]);
    let writes = slots.puts();
    holder
        .prepare(&edited, &edited.rates().raw(), "unchanged")
        .unwrap()
        .confirm_activation()
        .unwrap()
        .commit();
    assert_eq!(
        slots.puts(),
        writes,
        "unchanged rates are a Store-free no-op"
    );
    assert_eq!(pinned.view().card_at(0).unwrap().1.fee(), 3);
}

#[test]
fn actual_root_rate_apply_pending_and_callback_unwind_retain_the_same_candidate() {
    use busbar_kernel::rate_apply::RateApply;
    use std::sync::atomic::{AtomicBool, Ordering};
    let slots = RecordSlots::new();
    let boot = card(1.0, 3);
    let edited = card(2.0, 7);
    let holder = root_holder(&slots, &boot);
    let old = holder.card_store().unwrap().own();
    let seen = Arc::new(AtomicBool::new(false));
    slots.on_put({
        let holder = Arc::downgrade(&holder);
        let seen = seen.clone();
        let edited = edited.clone();
        move || {
            let holder = holder.upgrade().unwrap();
            assert!(holder.card_store().unwrap().state.try_lock().is_ok());
            assert!(holder
                .prepare(&edited, &edited.rates().raw(), "reentry")
                .is_err());
            if !seen.swap(true, Ordering::AcqRel) {
                panic!("planted Store callback unwind");
            }
            None
        }
    });
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = holder.prepare(
            &edited,
            &edited.rates().raw(),
            "original callback candidate",
        );
    }))
    .is_err());
    let key = holder.card_store().unwrap().pending().unwrap();
    assert_eq!(holder.card_store().unwrap().own(), old);
    slots.on_put(|| None);
    slots.pause(true);
    let preparing = {
        let holder = holder.clone();
        let edited = edited.clone();
        std::thread::spawn(move || {
            holder.prepare(&edited, &edited.rates().raw(), "retry after unwind")
        })
    };
    wait_until("the real Store future to remain Pending", || {
        slots.waiting() != 0
    });
    assert_eq!(holder.card_store().unwrap().own(), old);
    assert_eq!(holder.card_store().unwrap().pending(), Some(key));
    assert!(holder
        .prepare(
            &card(3.0, 9),
            &edited.rates().raw(),
            "concurrent replacement"
        )
        .is_err());
    slots.pause(false);
    let prepared = preparing.join().unwrap().unwrap();
    assert_eq!(holder.card_store().unwrap().own(), old);
    prepared.confirm_activation().unwrap().commit();
    assert_eq!(holder.card_store().unwrap().own(), Some((key, edited)));
}

#[test]
fn saved_candidate_and_activation_intent_survive_restart_without_automatic_activation() {
    let slots = RecordSlots::new();
    let boot = card(1.0, 3);
    let edited = card(2.0, 7);
    let first = booted(&slots, 1, &boot);
    let old = first.own();
    let prepared = first.prepare(&edited, "durable candidate").unwrap();
    let key = first.pending().unwrap();
    slots.take_then_refuse(1);
    assert!(prepared.confirm_activation().is_err());
    assert_eq!(first.own(), old);
    let scan = crate::root::card_store::scan(slots.calls().as_ref(), None).unwrap();
    let intent = scan
        .intents
        .iter()
        .find(|intent| intent.entry.key == key)
        .unwrap();
    let activation = intent.activation.clone().unwrap();
    assert!(!intent.activation_confirmed && !scan.entries.iter().any(|entry| entry.key == key));
    let original = intent.entry.clone();
    drop(first);
    let restarted = CardStore::new(slots.calls(), 1);
    assert!(restarted
        .boot(&boot, "wrong recovery configuration", Vec::new())
        .is_err());
    assert!(!restarted.entries().contains(&original));
    slots.refuse(false);
    restarted
        .boot(&edited, "explicit recovery of exact candidate", Vec::new())
        .unwrap();
    assert_eq!(restarted.own(), Some((key, edited)));
    assert_eq!(restarted.entry(&key), Some(original));
    assert_eq!(restarted.lock().activations.get(&key), Some(&activation));
}

#[test]
fn no_store_or_an_unconfirmed_opening_cannot_activate_initial_prices() {
    use busbar_kernel::rate_apply::RateApply;
    let boot = card(1.0, 3);
    let holder = crate::root::kernel::RootHistory::default();
    assert!(holder
        .prepare(&boot, &boot.rates().raw(), "no Store")
        .is_err());
    assert!(holder.pin().is_none());
    let slots = RecordSlots::new();
    slots.refuse(true);
    let first = CardStore::new(slots.calls(), 1);
    assert!(first.boot(&boot, "initial refusal", Vec::new()).is_err());
    assert!(!first.is_loaded());
    assert!(first.own().is_none() && first.history().is_none());
    assert!(first.entries().is_empty());
}

#[test]
fn reload_retires_a_prepared_only_candidate_and_preserves_its_original_in_the_store() {
    use busbar_kernel::rate_apply::RateApply;
    let slots = RecordSlots::new();
    let boot = card(1.0, 3);
    let edited = card(2.0, 7);
    let holder = root_holder(&slots, &boot);
    let store = holder.card_store().unwrap();
    let old = store.own();
    drop(
        holder
            .prepare(&edited, &edited.rates().raw(), "live-only prepare")
            .unwrap(),
    );
    let key = store.pending().unwrap();
    let original = (*store.lock().pending[0].1.entry).clone();
    holder
        .prepare_recovery(&boot, &boot.rates().raw(), "authoritative config reload")
        .unwrap()
        .confirm_activation()
        .unwrap()
        .commit();
    assert_eq!(store.own(), old);
    assert!(store.pending().is_none());
    let scanned = crate::root::card_store::scan(slots.calls().as_ref(), None).unwrap();
    assert!(scanned
        .intents
        .iter()
        .any(|intent| intent.entry == original && intent.retired));
    assert!(!scanned.entries.iter().any(|entry| entry.key == key));
    let restarted = booted(&slots, 1, &boot);
    assert_eq!(restarted.own(), old);
    assert!(restarted.pending().is_none());
}

#[test]
fn unknown_retirement_retains_its_exact_inert_intent_across_restart() {
    let slots = RecordSlots::new();
    let boot = card(1.0, 3);
    let edited = card(2.0, 7);
    let first = booted(&slots, 1, &boot);
    let old = first.own();
    drop(
        first
            .prepare(&edited, "prepared but never activated")
            .unwrap(),
    );
    let key = first.pending().unwrap();
    slots.take_then_refuse(1);
    assert!(first
        .prepare_recovery(&boot, "retirement with unknown result")
        .is_err());
    let scanned = crate::root::card_store::scan(slots.calls().as_ref(), None).unwrap();
    let intent = scanned
        .intents
        .iter()
        .find(|intent| intent.entry.key == key)
        .unwrap();
    assert!(intent.retiring && !intent.retired);
    let original = intent.entry.clone();
    assert_eq!(first.own(), old);
    drop(first);
    slots.refuse(false);
    let recovered = booted(&slots, 1, &boot);
    assert_eq!(recovered.own(), old);
    assert!(recovered.pending().is_none());
    let scanned = crate::root::card_store::scan(slots.calls().as_ref(), None).unwrap();
    assert!(scanned
        .intents
        .iter()
        .any(|intent| intent.entry == original && intent.retired));
    assert!(!scanned.entries.contains(&original));
}

#[test]
fn reload_resolves_unknown_activation_and_confirms_a_successor_to_the_old_desired_card() {
    use busbar_kernel::rate_apply::RateApply;
    let slots = RecordSlots::new();
    let boot = card(1.0, 3);
    let edited = card(2.0, 7);
    let holder = root_holder(&slots, &boot);
    let store = holder.card_store().unwrap();
    let old = store.own();
    let prepared = holder
        .prepare(&edited, &edited.rates().raw(), "live-only change")
        .unwrap();
    let key = store.pending().unwrap();
    slots.take_then_refuse(1);
    assert!(prepared.confirm_activation().is_err());
    assert!(holder
        .prepare(&boot, &boot.rates().raw(), "ordinary mutation")
        .is_err());
    assert!(holder
        .prepare_recovery(&boot, &boot.rates().raw(), "reload while unknown")
        .is_err());
    assert_eq!(store.own(), old);
    slots.refuse(false);
    let successor = holder
        .prepare_recovery(&boot, &boot.rates().raw(), "authoritative reload")
        .unwrap()
        .confirm_activation()
        .unwrap();
    assert_eq!(
        store.own(),
        old,
        "no predecessor is published while its successor is prepared"
    );
    drop(successor);
    assert_eq!(store.lock().pending.len(), 2);
    holder
        .prepare_recovery(&boot, &boot.rates().raw(), "retry authoritative reload")
        .unwrap()
        .confirm_activation()
        .unwrap()
        .commit();
    let current = store.own().unwrap();
    assert_eq!(current.1, boot);
    assert_ne!(Some(current.0), old.map(|(key, _)| key));
    assert_ne!(current.0, key);
    assert!(store.pending().is_none());
    let entries = changes(store);
    assert_eq!(entries.len(), 2);
    assert!(entries
        .iter()
        .any(|entry| entry.key == key && entry.card == edited));
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry.key == current.0)
            .unwrap()
            .base,
        Some(key)
    );
}

#[test]
fn unknown_activation_commit_requires_positive_confirmation_and_only_then_generation_publish() {
    use busbar_kernel::rate_apply::{RateApply, RateEpoch};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let slots = RecordSlots::new();
    let boot = card(1.0, 3);
    let edited = card(2.0, 7);
    let holder = root_holder(&slots, &boot);
    let store = holder.card_store().unwrap();
    let old = store.own();
    let epoch = holder.effective_from_at(now_ms());
    let prepared = holder
        .prepare(&edited, &edited.rates().raw(), "saved candidate")
        .unwrap();
    let key = store.pending().unwrap();
    slots.on_put({
        let slots = slots.clone();
        let writes = AtomicUsize::new(0);
        move || {
            slots.lose_acks(writes.fetch_add(1, Ordering::AcqRel) != 0);
            None
        }
    });
    assert!(prepared.confirm_activation().is_err());
    slots.on_put(|| None);
    slots.lose_acks(false);
    let scanned = crate::root::card_store::scan(slots.calls().as_ref(), None).unwrap();
    assert!(
        scanned.entries.iter().any(|entry| entry.key == key),
        "the Store saved the activation but lost its reply"
    );
    store.rescan(None).unwrap();
    assert_eq!(store.own(), old);
    assert_eq!(holder.effective_from_at(now_ms()), epoch);
    let writes = slots.puts();
    let confirmed = holder
        .prepare(&edited, &edited.rates().raw(), "readback exact activation")
        .unwrap()
        .confirm_activation()
        .unwrap();
    assert_eq!(
        slots.puts(),
        writes,
        "exact immutable readback confirms without another write identity"
    );
    assert_eq!(store.own(), old);
    confirmed.commit();
    assert_eq!(store.own(), Some((key, edited)));
}

#[test]
fn actual_root_raw_era_keeps_pending_counts_and_scoped_fees_at_old_prices_after_a_day_boundary() {
    use busbar_kernel::rate_apply::{RateApply, RateEpoch};
    use busbar_kernel_ledger::cost::{
        plane_fee_lane, PlaneFees, RawRateEra, PER_REQUEST, PER_SESSION,
    };
    use busbar_kernel_ledger::usage::{price_dated_raw, DatedHistory};
    use std::sync::atomic::{AtomicUsize, Ordering};
    const PLANE: &str = "pending-era-plane";
    const EXPECTED_OLD_MINOR: i64 = 114;
    const EXPECTED_NEW_MINOR: i64 = 232;
    let slots = RecordSlots::new();
    let mut boot = card(1.0, 3);
    boot.plane_fees.insert(
        PLANE.into(),
        PlaneFees {
            per_request: 3,
            per_session: 5,
        },
    );
    let mut edited = card(2.0, 7);
    edited.plane_fees.insert(
        PLANE.into(),
        PlaneFees {
            per_request: 7,
            per_session: 11,
        },
    );
    let holder = root_holder(&slots, &boot);
    let old = holder.era_at(now_ms());
    assert_eq!(old.effective_from, 0);
    assert!(
        old.entry_id.is_some(),
        "known opening zero differs from legacy undated zero"
    );
    let prepared = holder
        .prepare(&edited, &edited.rates().raw(), "real pending era")
        .unwrap();
    slots.on_put({
        let slots = slots.clone();
        let writes = AtomicUsize::new(0);
        move || {
            slots.lose_acks(writes.fetch_add(1, Ordering::AcqRel) != 0);
            None
        }
    });
    assert!(prepared.confirm_activation().is_err());
    slots.on_put(|| None);
    slots.lose_acks(false);
    let captured_while_pending = holder.era_at(now_ms());
    assert_eq!(captured_while_pending, old);
    let day_ms = busbar_kernel::governance::SECS_PER_DAY.saturating_mul(1_000);
    let next_bucket = (now_ms() / day_ms + 1) * day_ms;
    holder
        .prepare(&edited, &edited.rates().raw(), "confirm exact activation")
        .unwrap()
        .confirm_activation()
        .unwrap()
        .commit();
    let history = holder.history().unwrap();
    let live = super::rate_card_of(&edited);
    let input = BTreeMap::from([(busbar_contract::records::UNIT_INPUT.into(), 1_000_000)]);
    let plane_counts = BTreeMap::from([(PER_REQUEST.into(), 2), (PER_SESSION.into(), 1)]);
    let lane = plane_fee_lane(PLANE);
    let price = |era| {
        price_dated_raw(
            [("m", era, &input), (lane.as_str(), era, &plane_counts)],
            [(era, 1)],
            next_bucket,
            &live,
            Some(DatedHistory::of(&history, next_bucket)),
        )
        .unwrap()
        .minor_i64()
    };
    assert_eq!(price(captured_while_pending), Ok(EXPECTED_OLD_MINOR));
    assert_eq!(
        price(RawRateEra::legacy(0)),
        Ok(EXPECTED_NEW_MINOR),
        "the original timestamp-only max(bucket,era) behavior is the distinguishing failure"
    );
}

#[test]
fn a_partial_store_write_retries_the_exact_owner_at_every_record_boundary() {
    let template_store = RecordSlots::new();
    let template = booted(&template_store, 1, &card(1.0, 0));
    let count = original(&template, 7, "private-original-actor")
        .records_for(true)
        .unwrap()
        .len();
    for cut in 0..count {
        let store = RecordSlots::new();
        let cs = booted(&store, 1, &card(1.0, 0));
        let entry = original(&cs, 7, "private-original-actor");
        let key = entry.key;
        let puts = store.puts();
        store.take_then_refuse(cut);
        let old = cs.own();
        assert!(cs.write(entry.clone(), true).is_err());
        assert_eq!(cs.pending(), Some(key));
        assert_eq!(*cs.lock().pending[0].1.entry, entry);
        assert_eq!(
            cs.lock().pending[0]
                .1
                .progress
                .load(std::sync::atomic::Ordering::Acquire),
            cut
        );
        let scan = crate::root::card_store::scan(store.calls().as_ref(), None).unwrap();
        assert!(
            !scan.entries.contains(&entry),
            "no canonical commit acknowledged"
        );
        if cut + 1 == count {
            let intent = scan
                .intents
                .iter()
                .find(|intent| intent.entry.key == key)
                .unwrap();
            assert_eq!(intent.entry, entry);
            assert!(intent.own && !intent.committed);
        }
        store.refuse(false);
        wait_until("the exact original's canonical acknowledgment", || {
            candidate_confirmed(&cs, key)
        });
        assert_eq!(
            cs.own(),
            old,
            "a custody retry cannot activate a generation"
        );
        assert!(!cs.entries().contains(&entry));
        cs.prepare(&entry.card, "exact generation retry")
            .unwrap()
            .confirm_activation()
            .unwrap()
            .commit();
        let scan = crate::root::card_store::scan(store.calls().as_ref(), None).unwrap();
        assert!(scan.entries.contains(&entry));
        assert_eq!(cs.own(), Some((key, entry.card.clone())));
        assert_eq!(
            store.puts(),
            puts + count
                + crate::root::card_store::Activation {
                    effective_from: entry.effective_from
                }
                .records(&entry)
                .unwrap()
                .len(),
            "acknowledged chunks are not restarted from zero"
        );
    }
}

#[test]
fn an_unknown_commit_outcome_keeps_the_same_owner_until_exact_retry_acknowledgments() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let store = RecordSlots::new();
    let cs = booted(&store, 1, &card(1.0, 0));
    let entry = original(&cs, 7, "unknown commit original");
    let count = entry.records_for(true).unwrap().len();
    let calls = AtomicUsize::new(0);
    let released = Arc::new(AtomicBool::new(false));
    store.on_put({
        let store = store.clone();
        let released = released.clone();
        move || {
            if std::thread::current().name() == Some("card-reput") {
                if !released.load(Ordering::Acquire) {
                    return Some(busbar_contract::store_calls::StoreFailure::Refused(
                        "hold retry".into(),
                    ));
                }
                store.lose_acks(false);
            } else {
                store.lose_acks(calls.fetch_add(1, Ordering::AcqRel) + 1 == count);
            }
            None
        }
    });
    assert!(cs.write(entry.clone(), true).is_err());
    assert_eq!(cs.pending(), Some(entry.key));
    let scan = crate::root::card_store::scan(store.calls().as_ref(), None).unwrap();
    assert!(
        scan.intents
            .iter()
            .any(|intent| intent.entry == entry && intent.committed),
        "candidate commit landed but its ack was lost; no activation was authorized"
    );
    assert!(!scan.entries.contains(&entry));
    assert_eq!(*cs.lock().pending[0].1.entry, entry);
    released.store(true, Ordering::Release);
    wait_until("the same commit to be acknowledged on retry", || {
        candidate_confirmed(&cs, entry.key)
    });
    cs.prepare(&entry.card, "exact generation retry")
        .unwrap()
        .confirm_activation()
        .unwrap()
        .commit();
    assert_eq!(changes(&cs), vec![entry]);
}

#[test]
fn a_ready_write_preserves_every_other_store_intent() {
    let store = RecordSlots::new();
    let cs = booted(&store, 1, &card(1.0, 0));
    let mut unrelated = original(&cs, 4, "another node's original");
    unrelated.writer = 99;
    let mut records = unrelated.records_for(true).unwrap();
    records.pop();
    for (key, value) in &records {
        store.put_row(CARD_SCHEMA, key, value.as_slice());
    }
    let key = cs.apply(&card(1.0, 8), "ready successor").unwrap();
    assert!(cs.pending().is_none());
    let scan = crate::root::card_store::scan(store.calls().as_ref(), None).unwrap();
    assert!(scan.entries.iter().any(|entry| entry.key == key));
    assert!(scan
        .intents
        .iter()
        .any(|intent| intent.entry == unrelated && !intent.committed));
    let restarted = booted(&store, 1, &card(1.0, 8));
    assert!(
        !restarted.entries().contains(&unrelated),
        "peer preparation is not activation authority"
    );
    assert_ne!(restarted.own().map(|(key, _)| key), Some(unrelated.key));
}

#[test]
fn corrupt_or_unknown_store_intents_refuse_boot_before_any_put_or_publication() {
    for corruption in [0, 1, 2] {
        let store = RecordSlots::new();
        let first = booted(&store, 1, &card(1.0, 0));
        let entry = original(&first, 7, "private-original-actor");
        let mut records = entry.records_for(true).unwrap();
        records.pop();
        match corruption {
            0 => {
                records.remove(0);
            }
            1 => {
                let last = records.last_mut().unwrap();
                let mut meta = last.1.as_slice().to_vec();
                meta[0] = 99;
                last.1 = busbar_contract::kinds::RecordBytes::new(meta).unwrap();
            }
            _ => {
                let last = records.last_mut().unwrap();
                last.1 = busbar_contract::kinds::RecordBytes::new(vec![2]).unwrap();
            }
        }
        for (key, value) in &records {
            store.put_row(CARD_SCHEMA, key, value.as_slice());
        }
        let puts = store.puts();
        let cs = CardStore::new(store.calls(), 1);
        let error = cs.boot(&card(1.0, 7), "boot", Vec::new()).unwrap_err();
        assert!(!error.contains("private-original-actor"));
        assert!(!cs.is_loaded());
        assert!(cs.history().is_none());
        assert!(cs.entries().is_empty());
        assert_eq!(
            store.puts(),
            puts,
            "validate the whole snapshot before replay"
        );
    }
}

#[test]
fn a_rescan_never_overwrites_corrupt_store_records_or_publishes_a_partial_snapshot() {
    let store = RecordSlots::new();
    let cs = booted(&store, 1, &card(1.0, 0));
    let before = cs.entries();
    let entry = original(&cs, 7, "private-actor");
    let records = entry.records_for(true).unwrap();
    for (key, value) in &records {
        store.put_row(CARD_SCHEMA, key, value.as_slice());
    }
    let corrupt = records.last().unwrap().0.clone();
    store.corrupt(CARD_SCHEMA, &corrupt);
    let puts = store.puts();
    assert!(cs.rescan(None).is_err());
    assert_eq!(cs.entries(), before);
    assert_eq!(store.puts(), puts);
    assert!(!crate::root::card_store::scan(store.calls().as_ref(), None)
        .unwrap()
        .unreadable
        .is_empty());
}

#[test]
fn a_panicking_reput_releases_ownership_for_the_next_pending_write() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let store = RecordSlots::new();
    let cs = booted(&store, 1, &card(1.0, 0));
    let panicked = Arc::new(AtomicBool::new(false));
    store.on_put({
        let panicked = panicked.clone();
        move || {
            if std::thread::current().name() == Some("card-reput")
                && !panicked.swap(true, Ordering::AcqRel)
            {
                panic!("the store callback unwound");
            }
            Some(busbar_contract::store_calls::StoreFailure::Refused(
                "pending".into(),
            ))
        }
    });
    let old = cs.own();
    assert!(cs.apply(&card(1.0, 1), "first").is_none());
    let first = cs.pending().unwrap();
    wait_until(
        "the callback to unwind and release re-put ownership",
        || panicked.load(Ordering::Acquire) && !cs.lock().reputting,
    );
    store.on_put(|| None);
    assert!(cs.apply(&card(1.0, 2), "second").is_none());
    assert_eq!(cs.pending(), Some(first));
    assert_eq!(cs.own(), old);
    assert_eq!(cs.apply(&card(1.0, 1), "retry first"), Some(first));
    let entries = crate::root::card_store::scan(store.calls().as_ref(), None).unwrap();
    assert!(entries.entries.iter().any(|entry| entry.key == first));
}

#[test]
fn t1_card_the_card_in_force_and_every_instants_card_survive_a_restart_and_a_new_node() {
    let store = RecordSlots::new();
    let boot = card(1.0, 0);
    let first = booted(&store, 1, &boot);
    let spend_a = now_ms();
    std::thread::sleep(Duration::from_millis(5));
    let edited = card(1.0, 3);
    let key = first
        .apply(&edited, "config/reload by admin")
        .expect("applied");
    std::thread::sleep(Duration::from_millis(5));
    let spend_b = now_ms();
    let before = resolved(&first, &[spend_a, spend_b]);
    assert_eq!(
        before[0].1.as_ref(),
        Some(&boot),
        "the first spend keeps the boot card"
    );
    assert_eq!(
        before[1].1.as_ref(),
        Some(&edited),
        "the change takes effect at once"
    );
    let change = &changes(&first)[0];
    assert_eq!(change.key, key);
    assert_eq!(
        change.actor, "config/reload by admin",
        "the entry records who changed it"
    );
    assert_eq!(change.set_fields, vec!["per_request_fee".to_string()]);
    assert_eq!(first.own().map(|(k, _)| k), Some(key));

    let rows = store.rows_under(CARD_SCHEMA);
    let again = booted(&store, 1, &edited);
    assert_eq!(resolved(&again, &[spend_a, spend_b]), before);
    assert_eq!(
        store.rows_under(CARD_SCHEMA),
        rows,
        "an unchanged card appends nothing"
    );
    assert_eq!(
        again.own().map(|(k, _)| k),
        Some(key),
        "it adopts the entry in force"
    );

    let elsewhere = booted(&store, 77, &edited);
    assert_eq!(resolved(&elsewhere, &[spend_a, spend_b]), before);
    assert_eq!(elsewhere.own(), Some((key, edited)));
}

#[test]
fn t8_a_doubtful_put_is_pending_and_reput_to_ready_without_a_directory() {
    let store = RecordSlots::new();
    let cs = booted(&store, 1, &card(1.0, 0));
    store.lose_acks(true);
    let old = cs.own();
    assert!(cs.apply(&card(1.0, 9), "config/apply by admin").is_none());
    let key = cs.pending().unwrap();
    assert_eq!(cs.pending(), Some(key));
    assert!(cs
        .pending_refusal()
        .is_some_and(|why| why.contains(&key.hex())));
    assert!(cs.apply(&card(1.0, 10), "config/apply by admin").is_none());
    assert_eq!(cs.pending(), Some(key));
    assert_eq!(cs.own(), old);
    store.lose_acks(false);
    wait_until("the exact writes to be confirmed", || {
        candidate_confirmed(&cs, key)
    });
    assert_eq!(cs.own(), old);
    assert_eq!(cs.apply(&card(1.0, 9), "retry original"), Some(key));
    let next = cs.apply(&card(1.0, 10), "next confirmed change").unwrap();
    let scan = crate::root::card_store::scan(store.calls().as_ref(), None).unwrap();
    assert!(scan.entries.iter().any(|entry| entry.key == key));
    assert!(scan.entries.iter().any(|entry| entry.key == next));
    let restarted = booted(&store, 1, &card(1.0, 10));
    assert_eq!(restarted.own().map(|(key, _)| key), Some(next));
}

#[test]
fn t13_two_nodes_running_different_cards_are_both_recorded_and_each_prices_its_own() {
    let store = RecordSlots::new();
    let boot = card(1.0, 0);
    let a = booted(&store, 1, &boot);
    let b = booted(&store, 2, &boot);
    let before = now_ms();
    std::thread::sleep(Duration::from_millis(5));
    let (card_a, card_b) = (card(1.0, 5), card(7.0, 0));
    let ka = a.apply(&card_a, "config/reload on node 1").unwrap();
    let kb = b.apply(&card_b, "config/reload on node 2").unwrap();
    a.rescan(None).unwrap();
    b.rescan(None).unwrap();

    let keys = |cs: &CardStore| cs.entries().iter().map(|e| e.key).collect::<Vec<_>>();
    assert_eq!(
        keys(&a),
        keys(&b),
        "both nodes hold the same ordered history"
    );
    assert!(
        keys(&a).contains(&ka) && keys(&a).contains(&kb),
        "both changes are recorded"
    );
    assert_eq!(
        a.own().map(|(_, c)| c),
        Some(card_a.clone()),
        "a prices with its own card"
    );
    assert_eq!(
        b.own().map(|(_, c)| c),
        Some(card_b.clone()),
        "and b with its own"
    );
    let later = if ka > kb { &card_a } else { &card_b };
    assert_eq!(
        a.in_force().as_ref(),
        Some(later),
        "a time-based read takes the later"
    );
    assert_eq!(b.in_force().as_ref(), Some(later));
    for node in [&a, &b] {
        let alarm = node
            .alarms()
            .into_iter()
            .find(|m| m.contains("nodes run different rate cards"))
            .expect("every node alarms");
        assert!(
            alarm.contains("rate_card") && alarm.contains("per_request_fee"),
            "{alarm}"
        );
    }
    assert_eq!(
        resolved(&a, &[before])[0].1.as_ref(),
        Some(&boot),
        "nothing before the changes is repriced"
    );
}

#[test]
fn t19_a_joining_node_adopts_the_card_in_force_or_records_its_own() {
    let store = RecordSlots::new();
    let boot = card(1.0, 0);
    let first = booted(&store, 1, &boot);
    let edited = card(1.0, 4);
    let key = first.apply(&edited, "config/reload by admin").unwrap();
    let rows = store.rows_under(CARD_SCHEMA);

    let same = booted(&store, 2, &edited);
    assert_eq!(same.own().map(|(k, _)| k), Some(key));
    assert_eq!(store.rows_under(CARD_SCHEMA), rows, "nothing appended");

    let before = now_ms();
    std::thread::sleep(Duration::from_millis(5));
    let other = card(50.0, 0);
    let joined = booted(&store, 3, &other);
    let (own, own_card) = joined.own().unwrap();
    assert_eq!(own_card, other, "a node's card is its configuration's");
    let entry = changes(&joined).into_iter().find(|e| e.key == own).unwrap();
    assert_eq!(entry.actor, "boot of node 3");
    assert!(entry.effective_from > before);
    assert_eq!(resolved(&joined, &[before])[0].1.as_ref(), Some(&edited));
}

#[test]
fn t22_a_far_future_head_never_delays_a_change_and_card_void_clears_it() {
    let store = RecordSlots::new();
    let cs = booted(&store, 1, &card(1.0, 0));
    let ahead = now_ms() + SKEW_MS + 60_000;
    let far = StoredEntry {
        key: EntryKey::new(ahead, [7; 8], 0),
        effective_from: ahead,
        effective_until: None,
        appended_at: ahead,
        author: EntryAuthor::Change,
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
    cs.rescan(None).unwrap();
    let key = cs.apply(&card(1.0, 2), "config/reload by admin").unwrap();
    assert!(key > far.key, "the change keys above the far head");
    assert_eq!(
        cs.in_force().map(|c| c.per_request_fee),
        Some(2),
        "and takes effect now"
    );
    assert!(cs
        .alarms()
        .iter()
        .any(|m| m.contains(&far.key.hex()) && m.contains("node 99")));

    cs.void(far.key, "operator").expect("card void");
    let history = cs.history().unwrap();
    assert!(
        history.card_of(&far.key.id()).is_some(),
        "a voided id stays known"
    );
    assert_eq!(
        cs.card_at(ahead + 1).map(|(_, c)| c.per_request_fee),
        Some(2)
    );
}

#[test]
fn racing_openings_resolve_to_the_lowest_key() {
    let store = RecordSlots::new();
    let a = CardStore::new(store.calls(), 1);
    let b = CardStore::new(store.calls(), 2);
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
        std::thread::spawn(move || a.boot(&card(1.0, 0), "boot", Vec::new()))
    };
    let tb = {
        let b = Arc::clone(&b);
        std::thread::spawn(move || b.boot(&card(1.0, 0), "boot", Vec::new()))
    };
    ta.join().unwrap().unwrap();
    tb.join().unwrap().unwrap();
    store.on_scan(|| {});
    a.rescan(None).unwrap();
    b.rescan(None).unwrap();
    let openings: Vec<StoredEntry> = a
        .entries()
        .into_iter()
        .filter(|e| matches!(e.author, EntryAuthor::Opening { .. }))
        .collect();
    let history = a.history().unwrap();
    let view = history.current();
    assert_eq!(
        view.entry_at(0).map(|e| e.key()),
        Some(openings[0].key),
        "the lowest-keyed opening prices instant zero"
    );
}

#[test]
fn racing_different_confirmed_openings_keep_each_nodes_pin_era_and_counts_on_its_own_card() {
    use crate::root::kernel::RootHistory;
    use busbar_kernel::rate_apply::RateEpoch;
    use busbar_kernel_ledger::usage::{price_dated_raw, DatedHistory};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let slots = RecordSlots::new();
    let (card_a, card_b) = (card(1.0, 3), card(7.0, 5));
    let holder = |node, card: &CardFields| {
        let holder = Arc::new(RootHistory::default());
        holder.keep_in_store(slots.calls(), node);
        holder.card_applied(card, "racing first boot");
        holder
    };
    let (a, b) = (holder(1, &card_a), holder(2, &card_b));
    let barrier = Arc::new(Barrier::new(2));
    slots.on_put({
        let barrier = barrier.clone();
        let writes = AtomicUsize::new(0);
        move || {
            if writes.fetch_add(1, Ordering::AcqRel) < 2 {
                barrier.wait();
            }
            None
        }
    });
    let boot_a = {
        let a = a.clone();
        std::thread::spawn(move || a.boot_in_store(None))
    };
    let boot_b = {
        let b = b.clone();
        std::thread::spawn(move || b.boot_in_store(None))
    };
    boot_a.join().unwrap().unwrap();
    boot_b.join().unwrap().unwrap();
    slots.on_put(|| None);
    let writes = slots.puts();
    a.card_store().unwrap().rescan(None).unwrap();
    b.card_store().unwrap().rescan(None).unwrap();
    assert_eq!(
        slots.puts(),
        writes,
        "rescan neither writes a replacement nor activates prices"
    );
    let fleet = a.history().unwrap();
    assert_eq!(fleet.entries().len(), 2);
    let winner = a
        .card_store()
        .unwrap()
        .entries()
        .iter()
        .map(|entry| entry.key)
        .min()
        .unwrap();
    assert_eq!(fleet.current().entry_at(0).unwrap().key(), winner);
    let at = now_ms();
    let counts = BTreeMap::from([(busbar_contract::records::UNIT_INPUT.into(), 1_000_000)]);
    for (holder, fields, expected_minor) in [(a, card_a, 103), (b, card_b, 705)] {
        let own = holder.card_store().unwrap().own().unwrap().0;
        let pinned = holder.pin().unwrap();
        let live = super::rate_card_of(&fields);
        assert_eq!(pinned.view().card_at(at).unwrap().1, &live);
        let era = holder.era_at(at);
        assert_eq!(era.entry_id, Some(own.id()));
        assert_eq!(
            price_dated_raw(
                [("m", era, &counts)],
                [(era, 1)],
                0,
                &live,
                Some(DatedHistory::of(&fleet, at))
            )
            .unwrap()
            .minor_i64(),
            Ok(expected_minor)
        );
    }
}

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
    let cs = CardStore::new(store.calls(), 9);
    cs.boot(&edit, "boot", migrated.clone()).unwrap();
    assert_eq!(
        cs.entries().len(),
        2,
        "no opening is written over a migrated history"
    );
    assert_eq!(resolved(&cs, &[4_999])[0].1.as_ref(), Some(&boot));
    assert_eq!(resolved(&cs, &[5_000])[0].1.as_ref(), Some(&edit));

    let puts = store.puts();
    let again = CardStore::new(store.calls(), 9);
    again.boot(&edit, "boot", migrated).unwrap();
    assert_eq!(store.puts(), puts);
}

#[test]
fn t13_each_nodes_pin_prices_with_its_own_card_after_the_other_changes() {
    use crate::root::kernel::RootHistory;
    let store = RecordSlots::new();
    let boot = card(1.0, 0);
    let holder = |node: u64| {
        let h = RootHistory::default();
        h.keep_in_store(store.calls(), node);
        h.card_applied(&boot, "boot");
        h.boot_in_store(None).expect("the store boot");
        h
    };
    let (a, b) = (holder(1), holder(2));
    let (card_a, card_b) = (card(1.0, 5), card(7.0, 0));
    a.card_applied(&card_a, "config/reload on node 1");
    std::thread::sleep(Duration::from_millis(5));
    b.card_applied(&card_b, "config/reload on node 2");
    a.card_store().unwrap().rescan(None).unwrap();
    b.card_store().unwrap().rescan(None).unwrap();
    let now = now_ms() + 1;
    let priced = |h: &RootHistory| {
        let pin = h.pin().expect("a pin");
        let view = pin.view();
        let (_, card) = view.card_at(now).expect("covered");
        card.clone()
    };
    assert_eq!(
        priced(&a),
        super::rate_card_of(&card_a),
        "node 1 prices with its own card"
    );
    assert_eq!(
        priced(&b),
        super::rate_card_of(&card_b),
        "node 2 prices with its own card"
    );
    let fleet = a.history().unwrap();
    let view = fleet.current();
    assert_eq!(
        view.card_at(now).map(|(_, c)| c.clone()),
        Some(super::rate_card_of(&card_b)),
        "the fleet read takes the later change"
    );
}

#[test]
fn a_node_whose_card_differs_from_the_card_in_force_alarms() {
    let store = RecordSlots::new();
    let first = booted(&store, 1, &card(1.0, 0));
    std::thread::sleep(Duration::from_millis(2));
    let other = booted(&store, 2, &card(1.0, 6));
    first.rescan(None).unwrap();
    assert!(first
        .alarms()
        .iter()
        .any(|m| m.contains("this node prices with rate card entry")
            && m.contains("per_request_fee")));
    assert!(other
        .alarms()
        .iter()
        .all(|m| !m.contains("this node prices with rate card entry")));
}

#[cfg(feature = "root-admin")]
#[test]
fn the_migration_prices_every_instant_as_devs_rebuild_did_with_a_refused_correction() {
    for keyed in [false, true] {
        use crate::root::kernel::{
            card_from_raw, CardApplied, CardForm, CorrectionBase, RootHistory,
        };
        use crate::root::units_admin::{amendment_body, AmendmentRecord};
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
        let record = |seq: u64, body: Vec<u8>| busbar_kernel_wal::JournalRecord {
            class: busbar_kernel_wal::RecordClass::Policy,
            node: 1,
            node_seq: seq,
            lease_epoch: 0,
            policy_epoch: 0,
            wall: 0,
            mono: 0,
            body,
            body_hash: [0; 32],
            prev_hash: [0; 32],
            hash: [0; 32],
        };
        let correction = |seq: u64, digest: [u8; 32], at: u64, nanos: u64| AmendmentRecord {
            version: if keyed {
                crate::root::units_admin::AmendmentVersion::V4
            } else {
                crate::root::units_admin::AmendmentVersion::V3
            },
            effective_from: 5_000,
            effective_until: Some(6_000),
            amended_at_ms: at,
            sealed_over: Some(if keyed {
                CorrectionBase::Key {
                    key: EntryKey::new(5_000, [0; 8], 1),
                    card_digest: digest,
                }
            } else {
                CorrectionBase::LegacyOrdinal {
                    seq: busbar_kernel_ledger::cost::HistorySeq(seq),
                    card_digest: digest,
                }
            }),
            sealed_fee: 3,
            rates: vec![("m".to_string(), "input".to_string(), Some(nanos))],
            operator_fingerprint: String::new(),
            reason_hash: [1; 32],
            principal: "op".to_string(),
            dual_control: "single".to_string(),
            signed_payload: Vec::new(),
            signature: String::new(),
        };
        let (boot, edit) = (card(1.0, 0), card(1.0, 3));
        let (a0, a1) = (applied(&boot, 0, 1_000), applied(&edit, 5_000, 5_000));
        let edit_digest = a1.form.card().digest();
        let records = vec![
            record(1, a0.body()),
            record(2, a1.body()),
            // Sealed over entry 1 with the WRONG digest: dev's rebuild refuses it.
            record(
                3,
                amendment_body(&correction(1, [9; 32], 7_000, 50_000))
                    .expect("valid legacy correction"),
            ),
            // Sealed over entry 1 with its own digest: rebuilt.
            record(
                4,
                amendment_body(&correction(1, edit_digest, 8_000, 4_000))
                    .expect("valid legacy correction"),
            ),
        ];
        let dev = RootHistory::restore(crate::root::kernel::journalled_cards(&records), Vec::new());
        assert_eq!(
            dev.history.len(),
            3,
            "dev's rebuild left the refused correction out"
        );

        let migrated = super::migrated(&[(1, records.clone())], 9);
        assert_eq!(
            migrated.len(),
            3,
            "and so does the migration: {migrated:#?}"
        );
        let store = RecordSlots::new();
        let cs = CardStore::new(store.calls(), 9);
        cs.boot(&edit, "boot", migrated).unwrap();
        let ours = cs.history().unwrap();
        for t in [0, 4_999, 5_000, 5_500, 5_999, 6_000, 9_999] {
            let dev_view = dev.history.current();
            let our_view = ours.current();
            let dev_card = dev_view.card_at(t).map(|(_, c)| c.clone());
            let our_card = our_view.card_at(t).map(|(_, c)| c.clone());
            assert_eq!(our_card, dev_card, "the card at {t} is dev's");
        }
    }
}

#[test]
fn oversized_original_changes_and_amendments_recover_exactly_over_the_same_store() {
    use crate::root::card_store::{put_all, PutOutcome, COMMIT_PART};
    for own in [true, false] {
        let store = RecordSlots::new();
        let first = booted(&store, 1, &card(1.0, 0));
        let old_own = first.own();
        let mut entry = original(&first, 8, "oversized");
        entry.actor = "x".repeat(usize::from(COMMIT_PART) * busbar_contract::MAX_RECORD_BYTES + 1);
        if !own {
            entry.author = EntryAuthor::Amend {
                reason: hex::encode([3; 32]),
            };
            entry.effective_from = 0;
            entry.effective_until = Some(1);
        }
        let records = entry
            .records_for(own)
            .expect("u64 chunk indices accept the original");
        assert!(entry.value().len() > usize::from(COMMIT_PART) * busbar_contract::MAX_RECORD_BYTES);

        assert_eq!(
            put_all(
                store.calls().as_ref(),
                &records[..records.len() - 1],
                None,
                true
            ),
            PutOutcome::Ready
        );
        let scan = crate::root::card_store::scan(store.calls().as_ref(), None).unwrap();
        assert!(!scan.entries.contains(&entry));
        let intent = scan
            .intents
            .iter()
            .find(|intent| intent.entry.key == entry.key)
            .unwrap();
        assert_eq!(intent.entry, entry);
        assert_eq!(intent.own, own);
        assert!(!intent.committed);
        drop(first);
        let boot_card = if own {
            entry.card.clone()
        } else {
            old_own.as_ref().unwrap().1.clone()
        };
        let restarted = booted(&store, 1, &boot_card);
        assert!(
            restarted.entries().contains(&entry),
            "all original fields survive restart"
        );
        assert_eq!(
            restarted.own().map(|(key, _)| key),
            if own {
                Some(entry.key)
            } else {
                old_own.map(|(key, _)| key)
            }
        );
        assert!(restarted.pending().is_none());
        let confirmed = crate::root::card_store::scan(store.calls().as_ref(), None).unwrap();
        assert!(confirmed.entries.contains(&entry));
        assert_eq!(
            confirmed
                .intents
                .iter()
                .find(|intent| intent.entry.key == entry.key)
                .unwrap()
                .records
                .as_ref(),
            &records
        );
    }
}

#[test]
fn unavailable_store_retains_ram_ownership_without_claiming_restart_durability() {
    let store = RecordSlots::new();
    let cs = booted(&store, 1, &card(1.0, 0));
    store.refuse(true);
    let entry = original(&cs, 8, "unrecorded original");
    assert!(cs.write(entry.clone(), true).is_err());
    assert_eq!(cs.pending(), Some(entry.key));
    assert_eq!(*cs.lock().pending[0].1.entry, entry);
    let scan = crate::root::card_store::scan(store.calls().as_ref(), None).unwrap();
    assert!(!scan.entries.contains(&entry));
    assert!(!scan
        .intents
        .iter()
        .any(|intent| intent.entry.key == entry.key));
    drop(cs);
    store.refuse(false);
    let restarted = booted(&store, 1, &card(1.0, 0));
    assert!(
        !restarted.entries().contains(&entry),
        "no Store custody was claimed for the RAM-only original"
    );
}

#[test]
fn an_ephemeral_store_fixture_does_not_persist_after_instance_destruction() {
    let first_store = RecordSlots::new();
    let first = booted(&first_store, 1, &card(1.0, 0));
    let key = first.apply(&card(1.0, 8), "same Store instance").unwrap();
    let again = booted(&first_store, 1, &card(1.0, 8));
    assert!(again.entries().iter().any(|entry| entry.key == key));
    drop(first);
    drop(again);
    drop(first_store);
    let new_instance = RecordSlots::new();
    let fresh = booted(&new_instance, 1, &card(1.0, 8));
    assert!(
        !fresh.entries().iter().any(|entry| entry.key == key),
        "new memory instance has no old records"
    );
}

#[test]
fn shared_store_peer_intents_do_not_steal_own_selection_or_refuse_unrelated_admissions() {
    let store = RecordSlots::new();
    let a = booted(&store, 1, &card(1.0, 1));
    let b = booted(&store, 2, &card(1.0, 2));
    let b_own = b.own();
    let mut pending_a = original(&a, 3, "node one pending original");
    pending_a.base = a.own().map(|(key, _)| key);
    let mut records = pending_a.records_for(true).unwrap();
    records.pop();
    for (key, value) in records {
        store.put_row(CARD_SCHEMA, &key, value.as_slice());
    }
    drop(a);
    drop(b);
    store.refuse(true);
    let restarted_b = booted(&store, 2, &card(1.0, 2));
    assert_eq!(restarted_b.own(), b_own);
    assert!(restarted_b.pending().is_none());
    assert!(
        restarted_b.pending_refusal().is_none(),
        "peer custody does not gate this node"
    );
    assert!(
        !restarted_b.entries().contains(&pending_a),
        "intent alone is no confirmed fleet change"
    );
    let restarted_a = CardStore::new(store.calls(), 1);
    assert!(restarted_a
        .boot(&card(1.0, 3), "retry boot", Vec::new())
        .is_err());
    assert!(!restarted_a.is_loaded());
    assert!(!restarted_a.entries().contains(&pending_a));
    assert_eq!(restarted_a.pending(), Some(pending_a.key));
    assert!(restarted_a.pending_refusal().is_some());
    store.refuse(false);
    wait_until("the original writer's confirmation", || {
        candidate_confirmed(&restarted_a, pending_a.key)
    });
    restarted_a
        .boot(&card(1.0, 3), "confirmed boot", Vec::new())
        .unwrap();
    assert_eq!(
        restarted_a.own(),
        Some((pending_a.key, pending_a.card.clone()))
    );
    assert_eq!(
        restarted_b.own(),
        b_own,
        "peer confirmation never moves this node's card"
    );
    assert!(crate::root::card_store::scan(store.calls().as_ref(), None)
        .unwrap()
        .entries
        .contains(&pending_a));
}

#[test]
fn an_uncertain_opening_commit_recovers_the_same_original_in_a_fresh_host() {
    let store = RecordSlots::new();
    let first = CardStore::new(store.calls(), 1);
    let boot = CardFields {
        per_request_fee: 3,
        ..Default::default()
    };

    store.take_then_refuse(2);
    assert!(first.boot(&boot, "first opening", Vec::new()).is_err());
    assert!(!first.is_loaded());
    let scan = crate::root::card_store::scan(store.calls().as_ref(), None).unwrap();
    assert!(scan.entries.is_empty());
    assert_eq!(scan.intents.len(), 1);
    let original = scan.intents[0].entry.clone();
    assert!(scan.intents[0].own && !scan.intents[0].committed);
    assert_eq!(first.pending(), Some(original.key));
    drop(first);
    store.refuse(false);
    let restarted = booted(&store, 1, &boot);
    assert_eq!(restarted.entries(), vec![original.clone()]);
    assert_eq!(restarted.own(), Some((original.key, boot)));
}

#[test]
fn repeated_refusals_after_an_unknown_outcome_alarm_without_dropping_the_owner() {
    let store = RecordSlots::new();
    let cs = booted(&store, 1, &card(1.0, 0));
    store.lose_acks(true);
    let old = cs.own();
    assert!(cs.apply(&card(1.0, 8), "unknown then refused").is_none());
    let key = cs.pending().unwrap();
    let original = (*cs.lock().pending[0].1.entry).clone();
    store.lose_acks(false);
    store.refuse(true);
    wait_until("repeated unconfirmed retries to alarm", || {
        cs.alarms()
            .iter()
            .any(|why| why.contains(&key.hex()) && why.contains("repeated retries"))
    });
    assert_eq!(cs.pending(), Some(key));
    assert_eq!(cs.entry(&key), None);
    assert_eq!(cs.own(), old);
    store.refuse(false);
    wait_until("the same original to be confirmed", || {
        candidate_confirmed(&cs, key)
    });
    assert_eq!(cs.apply(&original.card, "confirmed retry"), Some(key));
    assert!(crate::root::card_store::scan(store.calls().as_ref(), None)
        .unwrap()
        .entries
        .contains(&original));
}
