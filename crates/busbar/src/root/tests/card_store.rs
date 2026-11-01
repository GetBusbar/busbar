// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The versioned Store record formats: an entry round-trips through its parts and commit, an entry
//! with no commit part (or a commit that does not match) is never read, and a VOID is its own record.

use super::*;
use busbar_kernel_ledger::cost::EntryKey;

fn entry(key: EntryKey) -> StoredEntry {
    let mut rate_card = std::collections::BTreeMap::new();
    for i in 0..40 {
        rate_card.insert(
            format!("model-{i:03}-with-a-long-name"),
            busbar_kernel::config::RateEntryCfg {
                input_utok: 1.5,
                output_utok: 3.25,
                ..Default::default()
            },
        );
    }
    StoredEntry {
        key,
        effective_from: key.t_ms(),
        effective_until: None,
        appended_at: key.t_ms(),
        author: EntryAuthor::Change,
        actor: "admin".to_string(),
        base: Some(EntryKey::new(1, [0; 8], 0)),
        writer: 7,
        set_fields: vec!["rate_card".to_string()],
        card: CardFields {
            rate_card: Some(rate_card),
            per_request_fee: 2,
            ..CardFields::default()
        },
        correction: Some(vec![1, 2, 3]),
    }
}

#[test]
fn an_entry_round_trips_through_its_parts_and_its_commit_is_written_last() {
    let e = entry(EntryKey::new(1_000, [1; 8], 2));
    let records = e.records().unwrap();
    assert!(records.len() > 2, "a large card crosses as several parts");
    assert_eq!(
        records.last().unwrap().0,
        tagged_key(e.key, COMMIT_TAG),
        "the commit part is written last"
    );
    let scanned = Scanned::of(records.clone());
    assert_eq!(scanned.entries, vec![e.clone()]);

    // No commit: never read.
    let mut torn = records.clone();
    torn.pop();
    let scanned = Scanned::of(torn);
    assert!(scanned.entries.is_empty());
    assert_eq!(scanned.uncommitted, vec![e.key]);

    // A part missing under a commit: never read.
    let mut holed = records;
    holed.remove(0);
    assert!(Scanned::of(holed).entries.is_empty());
}

#[test]
fn malformed_void_records_are_reported_without_changing_accepted_entries_or_voids() {
    let first = EntryKey::new(5, [2; 8], 0);
    let second = EntryKey::new(6, [2; 8], 0);
    let valid = VoidRecord {
        voided: first.hex(),
        voider: 3,
        at_ms: 9,
        actor: "op".to_string(),
        why: "void".to_string(),
    };
    let mut records = entry(first).records().unwrap();
    records.push(valid.record().unwrap());
    let bad = VoidRecord {
        voider: 4,
        ..valid.clone()
    };
    records.push((
        bad.record_key(),
        RecordBytes::new(b"private-malformed-body".to_vec()).unwrap(),
    ));
    let mismatch = VoidRecord {
        voided: second.hex(),
        voider: 5,
        ..valid.clone()
    };
    let (_, value) = mismatch.record().unwrap();
    let key = VoidRecord {
        voider: 5,
        ..valid.clone()
    }
    .record_key();
    records.push((key, value));
    let scanned = Scanned::of(records);
    assert_eq!(scanned.entries, vec![entry(first)]);
    assert_eq!(scanned.voids, vec![valid]);
    assert_eq!(scanned.unreadable.len(), 2);
    assert!(scanned.unreadable.iter().all(|(key, why)| {
        *key == first && !why.contains("private-malformed-body") && !why.contains(&second.hex())
    }));
}

#[test]
fn a_void_is_its_own_record_under_the_voided_key_and_the_ff_tag() {
    let key = EntryKey::new(5, [2; 8], 0);
    let void = VoidRecord {
        voided: key.hex(),
        voider: 3,
        at_ms: 9,
        actor: "op".to_string(),
        why: "void".to_string(),
    };
    let (rkey, value) = void.record().unwrap();
    assert_eq!(&rkey[..20], key.as_bytes());
    assert_eq!(rkey[20], VOID_TAG);
    assert_eq!(&rkey[21..], &3u64.to_be_bytes());
    let mut records = entry(key).records().unwrap();
    records.push((rkey, value));
    let scanned = Scanned::of(records);
    assert_eq!(scanned.voids, vec![void]);
    assert_eq!(scanned.entries.len(), 1);
}

#[test]
fn a_complete_intent_preserves_the_original_without_confirming_the_entry() {
    let original = entry(EntryKey::new(1_000, [3; 8], 1));
    let mut records = original.records_for(true).unwrap();
    let canonical = records.pop().unwrap();
    let scanned = Scanned::of(records.clone());
    assert!(scanned.entries.is_empty());
    assert_eq!(scanned.intents.len(), 1);
    let intent = &scanned.intents[0];
    assert_eq!(intent.entry, original);
    assert!(intent.own);
    assert!(!intent.committed);
    records.push(canonical);
    assert_eq!(intent.records.as_ref(), &records);
    assert!(Scanned::of(records).intents[0].committed);
}

#[test]
fn chunk_boundaries_and_empty_values_have_unambiguous_metadata() {
    let key = EntryKey::new(1_000, [3; 8], 1);
    for length in [
        0,
        1,
        PART_BYTES - 1,
        PART_BYTES,
        PART_BYTES + 1,
        PART_BYTES * 2,
    ] {
        let value = vec![7; length];
        let records = value_records(key, &value, true).unwrap();
        let parts = records[..records.len() - 2]
            .iter()
            .enumerate()
            .map(|(i, (_, value))| (i as u64, value.as_slice().to_vec()))
            .collect();
        assert_eq!(
            assemble(&parts, records.last().unwrap().1.as_slice()),
            Ok((value, true))
        );
        assert!(
            records.iter().all(|(_, v)| !v.as_slice().is_empty()),
            "memory Store treats empty record values as deletion"
        );
    }
    let high = u64::from(COMMIT_PART) + 1;
    assert_eq!(
        &data_key(key, high)[ENTRY_KEY_LEN + 1..],
        &high.to_be_bytes()
    );
}

#[test]
fn malformed_metadata_chunks_and_conflicting_duplicates_never_publish_an_entry() {
    let original = entry(EntryKey::new(1_000, [3; 8], 1));
    let records = original.records_for(true).unwrap();
    let mut cases = Vec::new();
    let mut missing = records.clone();
    missing.remove(0);
    cases.push(missing);
    let mut extra = records.clone();
    extra.push((
        data_key(original.key, u64::MAX),
        RecordBytes::new(vec![9]).unwrap(),
    ));
    cases.push(extra);
    let mut empty = records.clone();
    empty[0].1 = RecordBytes::new(Vec::new()).unwrap();
    cases.push(empty);
    let mut conflicting = records.clone();
    let mut duplicate = conflicting[0].clone();
    duplicate.1 = RecordBytes::new(vec![9]).unwrap();
    conflicting.push(duplicate);
    cases.push(conflicting);
    let mut conflicting_commit = records.clone();
    let mut duplicate = conflicting_commit.last().unwrap().clone();
    duplicate.1 = RecordBytes::new(vec![9]).unwrap();
    conflicting_commit.push(duplicate);
    cases.push(conflicting_commit);
    for offset in [0, 1, 2, 9, 10, 17, 18, META_BYTES - 1] {
        let mut bad = records.clone();
        for index in [bad.len() - 2, bad.len() - 1] {
            let mut meta = bad[index].1.as_slice().to_vec();
            meta[offset] ^= 0xff;
            bad[index].1 = RecordBytes::new(meta).unwrap();
        }
        cases.push(bad);
    }
    let mut invalid_commit = records.clone();
    invalid_commit.last_mut().unwrap().1 = RecordBytes::new(vec![2; META_BYTES - 1]).unwrap();
    cases.push(invalid_commit);
    for bad in cases {
        let scanned = Scanned::of(bad.clone());
        assert!(scanned.entries.is_empty());
        assert!(scanned.intents.is_empty());
        assert!(!scanned.unreadable.is_empty());
        assert!(scanned
            .unreadable
            .iter()
            .all(|(_, why)| !why.contains("admin")));
        assert!(Scanned::of(bad.into_iter().rev().collect())
            .entries
            .is_empty());
    }
    let mut same_duplicate = records.clone();
    same_duplicate.extend(records);
    assert_eq!(Scanned::of(same_duplicate).entries, vec![original]);
}

#[test]
fn legacy_entries_remain_readable_and_reject_zero_count_extra_or_conflicting_parts() {
    let original = entry(EntryKey::new(1_000, [3; 8], 1));
    let value = original.value();
    let mut records: Records = value
        .chunks(PART_BYTES)
        .enumerate()
        .map(|(i, chunk)| {
            (
                part_key(&original.key, i as u16),
                RecordBytes::new(chunk.to_vec()).unwrap(),
            )
        })
        .collect();
    let mut meta = (records.len() as u16).to_be_bytes().to_vec();
    meta.extend_from_slice(&sha256(&value));
    records.push((
        part_key(&original.key, COMMIT_PART),
        RecordBytes::new(meta).unwrap(),
    ));
    assert_eq!(Scanned::of(records.clone()).entries, vec![original.clone()]);
    let mut extra = records.clone();
    extra.push((
        part_key(&original.key, COMMIT_PART - 1),
        RecordBytes::new(vec![7]).unwrap(),
    ));
    assert!(Scanned::of(extra).entries.is_empty());
    let mut duplicate = records.clone();
    duplicate.push((records[0].0.clone(), RecordBytes::new(vec![7]).unwrap()));
    assert!(!Scanned::of(duplicate).unreadable.is_empty());
    let mut zero = records;
    let mut meta = 0u16.to_be_bytes().to_vec();
    meta.extend_from_slice(&sha256(&[]));
    zero.last_mut().unwrap().1 = RecordBytes::new(meta).unwrap();
    assert!(Scanned::of(zero).entries.is_empty());
}

#[test]
fn unknown_entry_versions_and_overlapping_protocols_are_rejected_before_effects() {
    let original = entry(EntryKey::new(1_000, [3; 8], 1));
    let mut json: serde_json::Value = serde_json::from_slice(&original.value()).unwrap();
    json["v"] = 99.into();
    let records = value_records(original.key, &serde_json::to_vec(&json).unwrap(), true).unwrap();
    assert!(!Scanned::of(records).unreadable.is_empty());
    let mut records = original.records().unwrap();
    records.push((
        part_key(&original.key, 0),
        RecordBytes::new(vec![7]).unwrap(),
    ));
    assert!(!Scanned::of(records).unreadable.is_empty());
}

#[test]
fn genuinely_pending_store_calls_wake_and_timeout_retry_the_same_original() {
    use crate::root::store_double::RecordSlots;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let store = RecordSlots::new();
    let original = entry(EntryKey::new(1_000, [3; 8], 1));
    let records = Arc::new(original.records_for(true).unwrap());
    let progress = Arc::new(AtomicUsize::new(0));
    store.pause(true);
    let writing = std::thread::spawn({
        let store = store.clone();
        let records = records.clone();
        let progress = progress.clone();
        move || {
            put_from(
                store.calls().as_ref(),
                &records,
                &progress,
                Some(Instant::now() + Duration::from_secs(10)),
                true,
            )
        }
    });
    let until = Instant::now() + Duration::from_secs(5);
    while store.waiting() == 0 {
        assert!(Instant::now() < until, "Store future must genuinely pend");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(progress.load(Ordering::Acquire), 0);
    assert_eq!(store.puts(), 0);
    store.pause(false);
    assert_eq!(writing.join().unwrap(), PutOutcome::Ready);
    assert!(scan(store.calls().as_ref(), None)
        .unwrap()
        .entries
        .contains(&original));

    let next = entry(EntryKey::new(2_000, [3; 8], 2));
    let next_records = next.records_for(true).unwrap();
    let next_progress = AtomicUsize::new(0);
    store.pause(true);
    let answer = put_from(
        store.calls().as_ref(),
        &next_records,
        &next_progress,
        Some(Instant::now() + Duration::from_millis(5)),
        true,
    );
    assert!(matches!(answer, PutOutcome::Doubtful(_)));
    assert_eq!(next_progress.load(Ordering::Acquire), 0);
    store.pause(false); // Waking a timed-out/dropped call is harmless.
    assert_eq!(
        put_from(
            store.calls().as_ref(),
            &next_records,
            &next_progress,
            None,
            false
        ),
        PutOutcome::Ready
    );
    assert_eq!(
        scan(store.calls().as_ref(), None).unwrap().entries,
        vec![original, next]
    );
}

#[test]
fn immutable_conflicting_store_bytes_are_never_overwritten_during_retry() {
    use crate::root::store_double::RecordSlots;
    let store = RecordSlots::new();
    let original = entry(EntryKey::new(1_000, [3; 8], 1));
    let records = original.records_for(true).unwrap();
    store.put_row(CARD_SCHEMA, &records[0].0, b"unrelated immutable bytes");
    let puts = store.puts();
    assert!(matches!(
        put_all(store.calls().as_ref(), &records, None, false),
        PutOutcome::Doubtful(_)
    ));
    assert_eq!(store.puts(), puts);
    let held = wait_until(store.calls().record_get(CARD_SCHEMA, &records[0].0), None)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(held.as_slice(), b"unrelated immutable bytes");
}
