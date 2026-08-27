// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/admin/audit.rs`.

use super::*;

#[test]
fn export_load_roundtrip_resumes_chain() {
    let log = AuditLog::new();
    log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
    log.record_by("hook.delete", "hook:a", OUTCOME_REJECTED, "admin");
    let exported = log.export();
    assert_eq!(exported.len(), 2);

    // Restore into a fresh log (a fresh boot): chain intact, sequence resumes AFTER max seq.
    let restored = AuditLog::new();
    restored.load(exported);
    assert!(restored.verify(), "restored chain must verify");
    restored.record_by("hook.register", "hook:b", OUTCOME_APPLIED, "admin");
    let all = restored.list(10);
    assert_eq!(all.len(), 3);
    assert!(
        all[0].seq > all[1].seq,
        "post-restore entries continue the sequence"
    );
    assert!(
        restored.verify(),
        "chain still verifies across the restore boundary"
    );
}

#[test]
fn record_and_list_newest_first() {
    let log = AuditLog::new();
    log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
    log.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");
    let entries = log.list(10);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].action, "hook.delete", "newest first");
    assert!(entries[0].seq > entries[1].seq, "monotonic seq");
}

#[test]
fn hash_chain_links_and_verifies() {
    let log = AuditLog::new();
    log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
    log.record_by("hook.register", "hook:b", OUTCOME_REJECTED, "admin");
    log.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");
    assert!(log.verify(), "an untouched chain verifies");

    // Each entry (oldest→newest) links to its predecessor's hash.
    let q = log.entries.lock().unwrap();
    assert_eq!(q[0].prev_hash, "", "first entry has no predecessor");
    assert_eq!(q[1].prev_hash, q[0].hash);
    assert_eq!(q[2].prev_hash, q[1].hash);
    drop(q);

    // Tamper: mutate a recorded field in place → verification fails.
    {
        let mut q = log.entries.lock().unwrap();
        q[1].resource = "hook:evil".to_string();
    }
    assert!(!log.verify(), "a tampered entry breaks the chain");
}
