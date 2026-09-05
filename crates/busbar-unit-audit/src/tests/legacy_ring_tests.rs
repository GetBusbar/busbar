// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin ring, ported from the previous release.
//!
//! Every one of these is the previous release's own test, brought across so that "moved unchanged"
//! is checked rather than asserted, plus the cap, the restore and the eight-field wire shape, which
//! were properties of the code there and are properties with names here.

use std::sync::{Arc, Mutex};

use crate::legacy::{
    verify_chain, AuditEntry, AuditLog, Clock, DurableSeam, AUDIT_ACTIONS, MAX_AUDIT_ENTRIES,
    OUTCOME_APPLIED, OUTCOME_REJECTED,
};

// ── THE FROZEN PERSISTED BYTES ───────────────────────────────────────────────────────────────────
//
// Two records, verbatim, as a store holds them on disk. Captured from a past build and frozen as
// literals, hashes included. This is a different KIND of check from recomputing the formula in-test:
// a refactor that moved BOTH the production digest and a parallel test formula the same way would
// pass a recompute and still make every deployed store report TAMPERED at its next boot. The
// expected digest here was produced by a build this one has no way to influence.

const AD_1: &[u8] = br#"{"seq":1,"ts":1700000000,"action":"hook.register","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"","hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa"}"#;
const AD_2: &[u8] = br#"{"seq":2,"ts":1700000060,"action":"hook.delete","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa","hash":"33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264"}"#;

#[test]
fn a_chain_persisted_by_an_earlier_build_still_verifies() {
    let persisted: Vec<AuditEntry> = [AD_1, AD_2]
        .into_iter()
        .map(|bytes| serde_json::from_slice(bytes).expect("the persisted shape still decodes"))
        .collect();

    assert!(
        verify_chain(&persisted).is_ok(),
        "bytes an earlier build wrote report themselves as TAMPERED — the digest drifted"
    );

    // And the ring takes them, resumes after them, and keeps chaining.
    let log = AuditLog::new();
    log.restore_from_store(persisted).unwrap();
    log.record_by("hook.register", "hook:compress", OUTCOME_APPLIED, "admin");
    let all = log.export();
    assert_eq!(all.len(), 3);
    assert_eq!(all[2].seq, 3);
    assert_eq!(all[2].prev_hash, all[1].hash);
    assert!(log.verify());
}

#[test]
fn a_persisted_record_decodes_into_every_one_of_its_eight_fields() {
    let entry: AuditEntry = serde_json::from_slice(AD_1).unwrap();
    assert_eq!(entry.seq, 1);
    assert_eq!(entry.ts, 1_700_000_000);
    assert_eq!(entry.action, "hook.register");
    assert_eq!(entry.resource, "hook:compress");
    assert_eq!(entry.outcome, "applied");
    assert_eq!(entry.principal, "admin");
    assert_eq!(entry.prev_hash, "");
    assert_eq!(
        entry.hash,
        "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa"
    );
    assert!(
        !entry.recorded_here,
        "a decoded record is seeded, not live-appended"
    );
}

/// A clock that stands still unless a test moves it, so a record's timestamp is a value rather than
/// a race.
struct FixedClock(Arc<Mutex<u64>>);

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        *self.0.lock().unwrap()
    }
}

/// One emit, as the seam saw it.
type Emitted = (u64, String, String, String, String);

/// A seam that keeps what it was handed, so the "one clock read" rule is observable.
#[derive(Default, Clone)]
struct RecordingSeam(Arc<Mutex<Vec<Emitted>>>);

impl DurableSeam for RecordingSeam {
    fn emit(&self, ts: u64, action: &str, resource: &str, outcome: &str, principal: &str) {
        self.0.lock().unwrap().push((
            ts,
            action.to_string(),
            resource.to_string(),
            outcome.to_string(),
            principal.to_string(),
        ));
    }
}

fn log_at(ts: u64) -> (AuditLog, Arc<Mutex<u64>>, RecordingSeam) {
    let clock = Arc::new(Mutex::new(ts));
    let seam = RecordingSeam::default();
    (
        AuditLog::with(
            Box::new(FixedClock(Arc::clone(&clock))),
            Box::new(seam.clone()),
        ),
        clock,
        seam,
    )
}

#[test]
fn export_load_roundtrip_resumes_chain() {
    let log = AuditLog::new();
    log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
    log.record_by("hook.delete", "hook:a", OUTCOME_REJECTED, "admin");
    let exported = log.export();
    assert_eq!(exported.len(), 2);

    // Restore into a fresh log — a fresh boot. The chain is intact and the sequence resumes AFTER
    // the highest restored one.
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

    let entries = log.export();
    assert_eq!(entries[0].prev_hash, "", "first entry has no predecessor");
    assert_eq!(entries[1].prev_hash, entries[0].hash);
    assert_eq!(entries[2].prev_hash, entries[1].hash);

    // Tamper: change a recorded field in place, and verification fails.
    let mut tampered = entries.clone();
    tampered[1].resource = "hook:elsewhere".to_string();
    let fresh = AuditLog::new();
    fresh.load(tampered);
    assert!(!fresh.verify(), "an edited entry must not verify");
}

#[test]
fn a_rejection_is_recorded_as_faithfully_as_an_application() {
    // Both outcomes are audited. A log that recorded only successes would be silent about exactly
    // the traffic somebody probing the surface generates.
    let log = AuditLog::new();
    log.record_by("key.rotate", "key:abc", OUTCOME_REJECTED, "someone");
    let entries = log.list(1);
    assert_eq!(entries[0].outcome, OUTCOME_REJECTED);
    assert_eq!(entries[0].principal, "someone");
    assert!(log.verify());
}

#[test]
fn the_ring_is_bounded_and_prunes_the_oldest() {
    let log = AuditLog::new();
    for i in 0..MAX_AUDIT_ENTRIES + 50 {
        log.record_by(
            "hook.register",
            &format!("hook:{i}"),
            OUTCOME_APPLIED,
            "admin",
        );
    }
    assert_eq!(log.len(), MAX_AUDIT_ENTRIES);
    let newest = log.list(1);
    assert_eq!(
        newest[0].resource,
        format!("hook:{}", MAX_AUDIT_ENTRIES + 49)
    );
    // The retained window still verifies, because a pruned head is checked as a window rather than
    // as a whole chain.
    assert!(log.verify());
}

#[test]
fn the_cap_is_a_thousand() {
    assert_eq!(MAX_AUDIT_ENTRIES, 1000);
}

#[test]
fn filtering_matches_exactly_and_pages_from_the_newest() {
    let log = AuditLog::new();
    log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
    log.record_by("key.rotate", "key:1", OUTCOME_APPLIED, "admin");
    log.record_by("hook.register", "hook:b", OUTCOME_APPLIED, "admin");

    let hooks = log.list_filtered(0, 10, Some("hook.register"), None);
    assert_eq!(hooks.len(), 2);
    assert_eq!(hooks[0].resource, "hook:b", "newest first");

    let one_resource = log.list_filtered(0, 10, None, Some("key:1"));
    assert_eq!(one_resource.len(), 1);

    let both = log.list_filtered(0, 10, Some("hook.register"), Some("hook:a"));
    assert_eq!(both.len(), 1);

    let skipped = log.list_filtered(1, 10, Some("hook.register"), None);
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0].resource, "hook:a");

    // A near miss matches nothing: the filter is exact, not a prefix.
    assert!(log
        .list_filtered(0, 10, Some("hook.regist"), None)
        .is_empty());
}

#[test]
fn a_restored_entry_is_not_marked_as_recorded_here() {
    let log = AuditLog::new();
    log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
    assert!(log.export()[0].recorded_here, "a live append is marked");

    let restored = AuditLog::new();
    restored.load(log.export());
    assert!(
        !restored.export()[0].recorded_here,
        "a seeded entry is not marked, whatever it was cloned from"
    );
}

#[test]
fn the_provenance_flag_is_not_on_the_wire_and_there_are_eight_fields() {
    let log = AuditLog::new();
    log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
    let entry = &log.export()[0];
    // Serialised as a map, the flag is absent and the eight wire fields are present. Checked by
    // name so that a field renamed silently is red.
    let json = serde_json::to_value(entry).unwrap();
    let map = json.as_object().unwrap();
    assert_eq!(map.len(), 8, "the wire shape is eight fields");
    for field in [
        "seq",
        "ts",
        "action",
        "resource",
        "outcome",
        "principal",
        "prev_hash",
        "hash",
    ] {
        assert!(map.contains_key(field), "the wire lost `{field}`");
    }
    assert!(!map.contains_key("recorded_here"));
}

#[test]
fn a_restore_from_a_store_verifies_before_it_is_trusted_and_seeds_either_way() {
    let log = AuditLog::new();
    log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
    log.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");
    let good = log.export();

    let fresh = AuditLog::new();
    assert!(fresh.restore_from_store(good.clone()).is_ok());
    assert_eq!(fresh.len(), 2);

    let mut broken = good;
    broken[1].action = "hook.something-else".to_string();
    let fresh = AuditLog::new();
    let verdict = fresh.restore_from_store(broken);
    assert!(verdict.is_err(), "a tampered tail is reported");
    assert_eq!(
        fresh.len(),
        2,
        "and the ring is seeded anyway — a detected tamper must not stop further evidence"
    );
}

#[test]
fn one_clock_read_per_mutation_reaches_both_the_ring_and_the_durable_seam() {
    // Reading the clock twice would let one mutation carry two timestamps up to a second apart,
    // which is exactly the divergence that makes two copies of a log impossible to reconcile.
    let (log, clock, seam) = log_at(1_700_000_000);
    log.record_by("config.apply", "config:main", OUTCOME_APPLIED, "admin");
    *clock.lock().unwrap() = 1_700_000_099;
    log.record_by("config.reload", "config:main", OUTCOME_APPLIED, "admin");

    let ring = log.export();
    let emitted = seam.0.lock().unwrap().clone();
    assert_eq!(emitted.len(), 2, "every mutation reaches the durable seam");
    assert_eq!(ring[0].ts, emitted[0].0);
    assert_eq!(ring[1].ts, emitted[1].0);
    assert_eq!(ring[0].ts, 1_700_000_000);
    assert_eq!(ring[1].ts, 1_700_000_099);
}

#[test]
fn the_seam_sees_the_same_action_resource_outcome_and_principal_the_ring_sealed() {
    let (log, _clock, seam) = log_at(5);
    log.record_by("plugin.install", "plugin:x", OUTCOME_REJECTED, "operator");
    let ring = log.export();
    let emitted = seam.0.lock().unwrap().clone();
    assert_eq!(
        (
            emitted[0].1.as_str(),
            emitted[0].2.as_str(),
            emitted[0].3.as_str(),
            emitted[0].4.as_str()
        ),
        (
            ring[0].action.as_str(),
            ring[0].resource.as_str(),
            ring[0].outcome.as_str(),
            ring[0].principal.as_str()
        )
    );
}

#[test]
fn there_are_thirty_three_action_names_and_they_are_all_distinct() {
    assert_eq!(AUDIT_ACTIONS.len(), 33);
    let mut sorted = AUDIT_ACTIONS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 33, "the action set has a duplicate in it");
}

#[test]
fn every_action_name_reads_as_a_noun_and_a_verb() {
    for action in AUDIT_ACTIONS {
        let parts: Vec<&str> = action.split('.').collect();
        assert_eq!(parts.len(), 2, "`{action}` is not a noun and a verb");
        assert!(!parts[0].is_empty() && !parts[1].is_empty());
    }
}

#[test]
fn every_action_name_chains_and_verifies() {
    // The whole vocabulary, through the chain, so a name that somehow broke the digest is caught by
    // the set rather than by whichever call site happened to be exercised.
    let log = AuditLog::new();
    for action in AUDIT_ACTIONS {
        log.record_by(action, "resource:x", OUTCOME_APPLIED, "admin");
    }
    assert_eq!(log.len(), 33);
    assert!(log.verify());
}

#[test]
fn concurrent_recorders_produce_sequences_in_insertion_order() {
    // The position is allocated INSIDE the entries lock. Allocating it outside let two recorders
    // interleave — the one with the higher number taking the lock first — and produce out-of-order
    // sequences in the ring.
    let log = Arc::new(AuditLog::new());
    let mut threads = Vec::new();
    for t in 0..8u64 {
        let log = Arc::clone(&log);
        threads.push(std::thread::spawn(move || {
            for i in 0..50 {
                log.record_by(
                    "hook.register",
                    &format!("hook:{t}-{i}"),
                    OUTCOME_APPLIED,
                    "admin",
                );
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
    let entries = log.export();
    assert_eq!(entries.len(), 400);
    for pair in entries.windows(2) {
        assert!(
            pair[1].seq > pair[0].seq,
            "sequences are out of insertion order in the ring"
        );
    }
    assert!(log.verify(), "the chain links in insertion order too");
}
