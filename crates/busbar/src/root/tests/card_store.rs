// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `busbar.card.v1` record format: an entry round-trips through its parts and commit, an entry
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
        part_key(&e.key, COMMIT_PART),
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
#[cfg(unix)]
fn spool_save_fault_preserves_the_correct_side_of_rename(fault: save_test::Step) {
    use save_test::Step;

    let dir = std::env::temp_dir().join(format!(
        "card-spool-boundary-{}-{}",
        std::process::id(),
        hex::encode(boot_rand())
    ));
    std::fs::create_dir(&dir).unwrap();
    let old_entry = entry(EntryKey::new(5, [2; 8], 0));
    let old = Spool {
        pending: vec![SpooledWrite::of(
            &old_entry.key,
            &old_entry.records().unwrap(),
        )],
    };
    old.save(&dir).unwrap();
    let mut original = entry(EntryKey::new(6, [2; 8], 0));
    original.actor = "private-original-actor".into();
    original.correction = Some(b"private-original-correction".to_vec());
    let mut latest = old.clone();
    latest.pending.push(SpooledWrite::of(
        &original.key,
        &original.records().unwrap(),
    ));
    let guard = save_test::install(&dir, move |step| {
        if step == fault {
            Err(std::io::Error::other("private-filesystem-error-content"))
        } else {
            Ok(())
        }
    });
    let error = latest
        .save(&dir)
        .expect_err("a failed barrier is not durable");
    for private in [
        "private-original-actor",
        "private-original-correction",
        "private-filesystem-error-content",
    ] {
        assert!(
            !error.contains(private),
            "persistence error exposed contents"
        );
    }
    let expected = match fault {
        Step::SyncFile | Step::Rename => &old,
        Step::OpenDirectory | Step::SyncDirectory => &latest,
    };
    assert_eq!(&Spool::load(&dir).unwrap(), expected, "{fault:?}");
    drop(guard);
    latest.save(&dir).unwrap();
    assert_eq!(Spool::load(&dir).unwrap(), latest);
    let writes = Spool::load(&dir).unwrap().pending;
    assert_eq!(
        Scanned::of(writes[1].records().unwrap()).entries,
        vec![original]
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn spool_file_sync_refusal_preserves_the_previous_spool() {
    spool_save_fault_preserves_the_correct_side_of_rename(save_test::Step::SyncFile);
}

#[cfg(unix)]
#[test]
fn spool_rename_refusal_preserves_the_previous_spool() {
    spool_save_fault_preserves_the_correct_side_of_rename(save_test::Step::Rename);
}

#[cfg(unix)]
#[test]
fn spool_directory_open_refusal_reports_uncertain_published_bytes() {
    spool_save_fault_preserves_the_correct_side_of_rename(save_test::Step::OpenDirectory);
}

#[cfg(unix)]
#[test]
fn spool_directory_sync_refusal_reports_uncertain_published_bytes() {
    spool_save_fault_preserves_the_correct_side_of_rename(save_test::Step::SyncDirectory);
}
