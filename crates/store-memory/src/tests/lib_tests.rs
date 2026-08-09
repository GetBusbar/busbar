// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/store-memory/src/lib.rs`.

use super::*;
use busbar_api::SecretForm;

fn key(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: format!("h_{id}"),
        name: "t".to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: None,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
    }
}

fn credential(id: &str, key_id: &str, public_id: &str) -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: id.to_string(),
            key_id: key_id.to_string(),
            kind: "sigv4".to_string(),
            slot: 0,
            public_id: public_id.to_string(),
            secret_form: SecretForm::Recoverable,
            created_at: 0,
            updated_at: 0,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: "v1:plain:sek".to_string(),
    }
}

fn ledger(requests: u64, model: &str, input: u64, output: u64) -> UsageLedger {
    UsageLedger {
        requests,
        billable_requests: requests,
        models: vec![busbar_api::ModelTokens {
            model: model.to_string(),
            tokens: busbar_api::TierTokens {
                input,
                output,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    }
}

#[test]
fn key_crud_and_ledger_roundtrip() {
    let s = MemoryStore::new();
    s.put_key(&key("a")).unwrap();
    assert_eq!(s.get_key("a").unwrap().unwrap().id, "a");
    assert_eq!(s.list_keys().unwrap().len(), 1);
    // absolute put_usage then read back
    s.put_usage("a", 0, &ledger(3, "m", 100, 40)).unwrap();
    let u = s.get_usage("a", 0).unwrap();
    assert_eq!(u.requests, 3);
    assert_eq!(u.tokens_for("m").unwrap().input, 100);
    // absolute overwrite (not additive)
    s.put_usage("a", 0, &ledger(1, "m", 20, 0)).unwrap();
    assert_eq!(
        s.get_usage("a", 0).unwrap().tokens_for("m").unwrap().input,
        20
    );
    // unknown window is default-empty
    assert_eq!(s.get_usage("a", 999).unwrap(), UsageLedger::default());
}

/// Additive per-model delta accumulate: two adds sum, a second model materializes its own row,
/// and negative deltas floor at 0 (parity contract with sqlite/postgres/valkey).
#[test]
fn add_usage_accumulates_per_model() {
    let s = MemoryStore::new();
    let d = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![busbar_api::ModelTokensDelta {
            model: "gpt-5".to_string(),
            tokens: busbar_api::TierTokensDelta {
                input: 10,
                output: 5,
                cache_read: 1,
                cache_write: 0,
            },
        }],
    };
    s.add_usage("bucket", 100, &d).unwrap();
    s.add_usage("bucket", 100, &d).unwrap();
    let u = s.get_usage("bucket", 100).unwrap();
    assert_eq!(u.requests, 2);
    let t = u.tokens_for("gpt-5").unwrap();
    assert_eq!((t.input, t.output, t.cache_read), (20, 10, 2));
    // Refund floors at zero.
    s.add_usage(
        "bucket",
        100,
        &UsageDelta {
            requests: -5,
            billable_requests: -5,
            models: vec![],
        },
    )
    .unwrap();
    assert_eq!(s.get_usage("bucket", 100).unwrap().requests, 0);
}

#[test]
fn delete_key_tombstones_and_cascades_usage_and_creds() {
    let s = MemoryStore::new();
    s.put_key(&key("a")).unwrap();
    s.put_usage("a", 0, &ledger(1, "m", 5, 0)).unwrap();
    s.put_credential(&credential("c1", "a", "AKIA1")).unwrap();
    s.delete_key("a").unwrap();
    // TOMBSTONE, not removed: the row survives, disabled, with deleted_at set.
    let tombstone = s.get_key("a").unwrap().unwrap();
    assert!(!tombstone.enabled);
    assert!(tombstone.deleted_at.is_some());
    assert_eq!(s.get_usage("a", 0).unwrap(), UsageLedger::default());
    assert!(s.list_credentials("a").unwrap().is_empty());
    // Idempotent: a second delete of an already-tombstoned key is a no-op, not an error.
    s.delete_key("a").unwrap();
}

#[test]
fn put_credential_rejects_a_slot_already_holding_a_live_credential() {
    let s = MemoryStore::new();
    s.put_key(&key("a")).unwrap();
    s.put_credential(&credential("c1", "a", "AKIA1")).unwrap();
    // Same (key_id, kind, slot), different id/public_id: must fail, not silently clobber.
    let clobber = credential("c2", "a", "AKIA2");
    assert!(s.put_credential(&clobber).is_err());
    // Revoking the occupant frees the slot for a fresh mint.
    s.revoke_credential("c1", "rotated").unwrap();
    assert!(s.put_credential(&clobber).is_ok());
}

#[test]
fn put_credential_rejects_a_public_id_reused_under_a_different_key() {
    let s = MemoryStore::new();
    s.put_key(&key("a")).unwrap();
    s.put_key(&key("b")).unwrap();
    s.put_credential(&credential("c1", "a", "AKIA1")).unwrap();
    // Different key, different id, SAME (kind, public_id) — the global AccessKeyId->credential
    // lookup handle must resolve to exactly one credential.
    let mut dupe = credential("c2", "b", "AKIA1");
    dupe.meta.slot = 1; // different slot too, so only the public_id clash can reject it
    assert!(s.put_credential(&dupe).is_err());
    // A genuinely distinct public_id under the other key is fine.
    let mut ok = credential("c3", "b", "AKIA2");
    ok.meta.slot = 1;
    assert!(s.put_credential(&ok).is_ok());
}

#[test]
fn put_credential_public_id_check_excludes_its_own_row_on_reput() {
    // The uniqueness scan excludes the row with the SAME id (`c.meta.id != secret.meta.id`) —
    // otherwise a credential could never even be inserted once the id already existed. This
    // only matters once an id can legitimately be re-put; simulate it by inserting once, then
    // putting the identical secret again under the identical id/public_id/kind and confirming
    // it's accepted, not rejected as "colliding with itself".
    let s = MemoryStore::new();
    s.put_key(&key("a")).unwrap();
    let c = credential("c1", "a", "AKIA1");
    s.put_credential(&c).unwrap();
    assert!(
        s.put_credential(&c).is_ok(),
        "a row must not collide with itself"
    );
}

#[test]
fn list_credentials_filters_by_key_id_and_since_boundary_is_exclusive() {
    let s = MemoryStore::new();
    s.put_key(&key("a")).unwrap();
    s.put_key(&key("b")).unwrap();
    s.put_credential(&credential("c1", "a", "AKIA1")).unwrap();
    let mut c2 = credential("c2", "b", "AKIA2");
    c2.meta.slot = 1;
    s.put_credential(&c2).unwrap();

    let for_a = s.list_credentials("a").unwrap();
    assert_eq!(for_a.len(), 1, "must not also return key b's credential");
    assert_eq!(for_a[0].id, "c1");

    // revision boundary: `revision > since` is exclusive of `since` itself. c2 was put after
    // c1, so it holds the higher revision — use IT as the boundary reference, or c1 (the lower
    // revision) would still be `> since` and the assertion below would be vacuous. The store's
    // revision counter is global (shared with `put_key`), so c1's revision is NOT necessarily
    // `newest_rev - 1` — read it directly rather than assuming adjacency.
    let oldest_rev = s.list_credentials("a").unwrap()[0].revision;
    let newest_rev = s.list_credentials("b").unwrap()[0].revision;
    assert!(newest_rev > oldest_rev);
    assert_eq!(
        s.list_credentials_since(newest_rev).unwrap().len(),
        0,
        "since == the newest row's own revision must exclude it"
    );
    assert_eq!(
        s.list_credentials_since(oldest_rev - 1).unwrap().len(),
        2,
        "since one below the lowest revision must include everything"
    );
}

#[test]
fn list_keys_since_boundary_is_exclusive() {
    let s = MemoryStore::new();
    s.put_key(&key("a")).unwrap();
    s.put_key(&key("b")).unwrap();
    let rev_a = s.get_key("a").unwrap().unwrap().revision;
    let rev_b = s.get_key("b").unwrap().unwrap().revision;
    assert!(rev_b > rev_a);
    assert_eq!(
        s.list_keys_since(rev_b).unwrap().len(),
        0,
        "since == the newest row's own revision must exclude it"
    );
    assert_eq!(
        s.list_keys_since(rev_a).unwrap().len(),
        1,
        "must include only b"
    );
    assert_eq!(s.list_keys_since(rev_a - 1).unwrap().len(), 2);
}

#[test]
fn next_revision_is_strictly_monotonic_starting_above_zero() {
    let s = MemoryStore::new();
    s.put_key(&key("a")).unwrap();
    s.put_key(&key("b")).unwrap();
    let rev_a = s.get_key("a").unwrap().unwrap().revision;
    let rev_b = s.get_key("b").unwrap().unwrap().revision;
    assert!(
        rev_a > 0,
        "the counter must not hand out 0 as a real revision"
    );
    assert_eq!(rev_b, rev_a + 1, "each call must advance by exactly 1");
}

#[test]
fn lookup_credential_secret_resolves_by_kind_and_public_id() {
    let s = MemoryStore::new();
    s.put_key(&key("a")).unwrap();
    s.put_credential(&credential("c1", "a", "AKIA1")).unwrap();
    let found = s
        .lookup_credential_secret("sigv4", "AKIA1")
        .unwrap()
        .unwrap();
    assert_eq!(found.meta.key_id, "a");
    assert_eq!(found.secret, "v1:plain:sek");
    assert!(s
        .lookup_credential_secret("sigv4", "unknown")
        .unwrap()
        .is_none());
}

#[test]
fn scrub_key_requires_tombstone_first() {
    let s = MemoryStore::new();
    s.put_key(&key("a")).unwrap();
    // A live key must not be scrubbable — that would be silent, un-auditable data loss on an
    // active principal.
    assert!(s.scrub_key("a").is_err());
    s.delete_key("a").unwrap();
    s.scrub_key("a").unwrap();
    let scrubbed = s.get_key("a").unwrap().unwrap();
    assert!(scrubbed.name.is_empty());
    assert!(scrubbed.labels.is_empty());
}

#[test]
fn metering_accumulates_per_bucket() {
    let s = MemoryStore::new();
    let d = MeteringDelta {
        key_id: "a".to_string(),
        bucket: 7,
        model: "m".to_string(),
        provider: "p".to_string(),
        tokens_input: 10,
        tokens_output: 5,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
    };
    s.add_metering(&d).unwrap();
    s.add_metering(&d).unwrap();
    let rows = s.list_metering(7).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].tokens_input, 20);
    assert_eq!(rows[0].requests, 2);
    assert!(s.list_metering(999).unwrap().is_empty());
}

/// Regression: `usage` must not grow unbounded forever. A window older than the 31-day
/// retention ceiling gets swept once `add_usage` has been called `SWEEP_INTERVAL` times
/// (the amortized sweep cadence), even though nothing ever explicitly deletes it.
#[test]
fn add_usage_sweeps_stale_windows() {
    let s = MemoryStore::new();
    let old_window = now().saturating_sub(40 * 86_400); // 40 days old > 31-day retention
    let d = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![],
    };
    for _ in 0..SWEEP_INTERVAL {
        s.add_usage("old-bucket", old_window, &d).unwrap();
    }
    // The sweep fired on the SWEEP_INTERVAL-th write and evicted the stale row (including the
    // one just written in that same call, since it's aged by its window_start, not by
    // recency-of-write).
    assert_eq!(
        s.get_usage("old-bucket", old_window).unwrap(),
        UsageLedger::default()
    );

    // A fresh window written afterward is unaffected.
    let fresh_window = now();
    s.add_usage("fresh-bucket", fresh_window, &d).unwrap();
    assert_eq!(
        s.get_usage("fresh-bucket", fresh_window).unwrap().requests,
        1
    );
}

/// Regression: the sweep must not over-prune. A window well within the 31-day retention
/// ceiling survives a sweep triggered by writes to an unrelated, genuinely stale window.
#[test]
fn add_usage_sweep_preserves_fresh_windows() {
    let s = MemoryStore::new();
    let young_window = now().saturating_sub(5 * 86_400); // 5 days old, well within retention
    let old_window = now().saturating_sub(40 * 86_400); // 40 days old, past retention
    let d = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![],
    };
    s.add_usage("young-bucket", young_window, &d).unwrap();
    for _ in 0..(SWEEP_INTERVAL - 1) {
        s.add_usage("old-bucket", old_window, &d).unwrap();
    }
    // That's SWEEP_INTERVAL total add_usage calls, so the sweep just fired.
    assert_eq!(
        s.get_usage("young-bucket", young_window).unwrap().requests,
        1
    );
    assert_eq!(
        s.get_usage("old-bucket", old_window).unwrap(),
        UsageLedger::default()
    );
}

/// The sweep boundary itself: a window exactly `MAX_RETENTION_SECS` old sits AT the ceiling
/// (`window_start + MAX_RETENTION_SECS == now`) and must be evicted (`>`, not `>=`, is the
/// retain condition — a row must be STRICTLY inside the window to survive), while one second
/// fresher survives.
#[test]
fn add_usage_sweep_boundary_is_exact() {
    let s = MemoryStore::new();
    let n = now();
    // Pin the sweep's clock to the SAME `n` the test derives its buckets from, so the retention
    // ceiling is exact and a wall-clock tick between here and the sweep can't shift it. Without
    // this, `one_inside` intermittently falls at/below an advanced ceiling and is wrongly evicted.
    s.pin_clock(n);
    let at_ceiling = n.saturating_sub(MAX_RETENTION_SECS);
    let one_inside = at_ceiling + 1;
    let d = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![],
    };
    s.add_usage("at-ceiling", at_ceiling, &d).unwrap();
    s.add_usage("one-inside", one_inside, &d).unwrap();
    for _ in 0..(SWEEP_INTERVAL - 2) {
        s.add_usage("filler", one_inside, &d).unwrap();
    }
    assert_eq!(
        s.get_usage("at-ceiling", at_ceiling).unwrap(),
        UsageLedger::default(),
        "a window exactly at the retention ceiling must be evicted"
    );
    assert_eq!(
        s.get_usage("one-inside", one_inside).unwrap().requests,
        1,
        "a window one second inside the ceiling must survive"
    );
}

/// Regression: `metering` must not grow unbounded forever either — same amortized sweep, keyed
/// by the (day) `bucket` field this time.
#[test]
fn add_metering_sweeps_stale_buckets() {
    let s = MemoryStore::new();
    let old_bucket = now().saturating_sub(40 * 86_400);
    let d = MeteringDelta {
        key_id: "k".to_string(),
        bucket: old_bucket,
        model: "m".to_string(),
        provider: "p".to_string(),
        tokens_input: 1,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
    };
    for _ in 0..SWEEP_INTERVAL {
        s.add_metering(&d).unwrap();
    }
    assert!(s.list_metering(old_bucket).unwrap().is_empty());

    let fresh_bucket = now();
    let fresh = MeteringDelta {
        bucket: fresh_bucket,
        ..d.clone()
    };
    s.add_metering(&fresh).unwrap();
    assert_eq!(s.list_metering(fresh_bucket).unwrap().len(), 1);
}

/// Regression: metering sweep must not over-prune fresh buckets either.
#[test]
fn add_metering_sweep_preserves_fresh_buckets() {
    let s = MemoryStore::new();
    let young_bucket = now().saturating_sub(5 * 86_400);
    let old_bucket = now().saturating_sub(40 * 86_400);
    let young = MeteringDelta {
        key_id: "k".to_string(),
        bucket: young_bucket,
        model: "m".to_string(),
        provider: "p".to_string(),
        tokens_input: 1,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
    };
    let old = MeteringDelta {
        bucket: old_bucket,
        ..young.clone()
    };
    s.add_metering(&young).unwrap();
    for _ in 0..(SWEEP_INTERVAL - 1) {
        s.add_metering(&old).unwrap();
    }
    assert_eq!(s.list_metering(young_bucket).unwrap().len(), 1);
    assert!(s.list_metering(old_bucket).unwrap().is_empty());
}

/// Same exact-boundary case as `add_usage_sweep_boundary_is_exact`, for metering's bucket
/// retention: a bucket exactly `MAX_RETENTION_SECS` old must be evicted, one second fresher
/// must survive.
#[test]
fn add_metering_sweep_boundary_is_exact() {
    let s = MemoryStore::new();
    let n = now();
    // Pin the sweep's clock to the SAME `n` the test derives its buckets from (see the usage
    // boundary test above) so the retention ceiling is exact and race-free.
    s.pin_clock(n);
    let at_ceiling = n.saturating_sub(MAX_RETENTION_SECS);
    let one_inside = at_ceiling + 1;
    let base = MeteringDelta {
        key_id: "k".to_string(),
        bucket: at_ceiling,
        model: "m".to_string(),
        provider: "p".to_string(),
        tokens_input: 1,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
    };
    let inside = MeteringDelta {
        bucket: one_inside,
        ..base.clone()
    };
    s.add_metering(&base).unwrap();
    for _ in 0..(SWEEP_INTERVAL - 1) {
        s.add_metering(&inside).unwrap();
    }
    assert!(
        s.list_metering(at_ceiling).unwrap().is_empty(),
        "a bucket exactly at the retention ceiling must be evicted"
    );
    assert_eq!(
        s.list_metering(one_inside).unwrap().len(),
        1,
        "a bucket one second inside the ceiling must survive"
    );
}

/// `delete_key` tombstones rows (kept forever, by design, for billing/audit attribution), and
/// that growth needs its own bound — unlike `usage` and
/// `metering`, the `keys` map had no retention sweep, so a repeated self-serve refresh loop by
/// one principal grew it without bound. `put_key` (the hot write path for issue/refresh) now
/// runs the SAME amortized sweep, pruning only tombstoned rows past the 31-day ceiling; a live
/// row is NEVER a candidate regardless of age, and a recently-tombstoned row survives.
#[test]
fn put_key_sweeps_stale_tombstones() {
    let s = MemoryStore::new();
    let n = now();
    let old_deleted_at = n.saturating_sub(40 * 86_400); // 40 days old > 31-day retention

    // Tombstone one key far in the past (pin the clock at delete time so its `deleted_at` lands
    // well past the retention ceiling).
    s.put_key(&key("old-tombstone")).unwrap();
    s.pin_clock(old_deleted_at);
    s.delete_key("old-tombstone").unwrap();
    assert_eq!(
        s.get_key("old-tombstone").unwrap().unwrap().deleted_at,
        Some(old_deleted_at)
    );

    // A live key (never tombstoned) and a recently-tombstoned key.
    s.put_key(&key("live")).unwrap();
    s.put_key(&key("recent-tombstone")).unwrap();
    s.pin_clock(n); // back to "now" — governs both the recent tombstone and the sweep's ceiling
    s.delete_key("recent-tombstone").unwrap();

    // Fire the amortized sweep with a batch of unrelated writes (mirrors add_usage/add_metering
    // sweep tests: SWEEP_INTERVAL put_key calls guarantee the sweep fires at least once).
    for i in 0..SWEEP_INTERVAL {
        s.put_key(&key(&format!("filler-{i}"))).unwrap();
    }

    assert!(
        s.get_key("old-tombstone").unwrap().is_none(),
        "a tombstone past the 31-day retention ceiling must be pruned"
    );
    assert!(
        s.get_key("live").unwrap().is_some(),
        "a live (never-deleted) key must never be pruned, regardless of age"
    );
    assert!(
        s.get_key("recent-tombstone").unwrap().is_some(),
        "a tombstone within the retention window must survive"
    );
}

/// Unlike `usage`/`metering`/tombstoned `keys`, the `creds` map had NO
/// retention sweep at all — its only shrink path was `delete_key`'s cascade, which never fires for
/// a credential rotated on a LIVE key. A long-lived key's occupied-slot -> revoke -> re-put
/// rotation cycle (mint into the free slot, revoke the old one) therefore grew `creds` without
/// bound. `put_credential` now runs the same amortized sweep, pruning only REVOKED rows past the
/// 31-day ceiling; a live (never-revoked) credential is NEVER a candidate regardless of age, and a
/// recently-revoked one survives.
#[test]
fn put_credential_sweeps_stale_revoked_creds() {
    let s = MemoryStore::new();
    let n = now();
    let old_revoked_at = n.saturating_sub(40 * 86_400); // 40 days old > 31-day retention

    s.put_key(&key("k-old")).unwrap();
    s.put_credential(&credential("old-revoked", "k-old", "AKIA_OLD"))
        .unwrap();
    // Revoke it far in the past (pin the clock at revoke time so `revoked_at` lands well past
    // the retention ceiling) — `revoke_credential` stamps `revoked_at` from the real wall clock,
    // not the pinned one, so pin first, revoke, then verify the stamped value directly.
    s.pin_clock(old_revoked_at);
    s.revoke_credential("old-revoked", "rotated").unwrap();

    // A live (never-revoked) credential and a recently-revoked one.
    s.put_key(&key("k-live")).unwrap();
    s.put_credential(&credential("live", "k-live", "AKIA_LIVE"))
        .unwrap();
    s.put_key(&key("k-recent")).unwrap();
    s.put_credential(&credential("recent-revoked", "k-recent", "AKIA_RECENT"))
        .unwrap();
    s.pin_clock(n); // back to "now" — governs both the recent revoke and the sweep's ceiling
    s.revoke_credential("recent-revoked", "rotated").unwrap();

    // Fire the amortized sweep with a batch of unrelated put_credential calls (mirrors
    // put_key_sweeps_stale_tombstones): SWEEP_INTERVAL calls guarantee the sweep fires.
    for i in 0..SWEEP_INTERVAL {
        let kid = format!("k-filler-{i}");
        s.put_key(&key(&kid)).unwrap();
        s.put_credential(&credential(
            &format!("filler-{i}"),
            &kid,
            &format!("AKIA_F{i}"),
        ))
        .unwrap();
    }

    assert!(
        s.lookup_credential_secret("sigv4", "AKIA_OLD")
            .unwrap()
            .is_none(),
        "a credential revoked past the 31-day retention ceiling must be pruned"
    );
    assert!(
        s.lookup_credential_secret("sigv4", "AKIA_LIVE")
            .unwrap()
            .is_some(),
        "a live (never-revoked) credential must never be pruned, regardless of age"
    );
    assert!(
        s.lookup_credential_secret("sigv4", "AKIA_RECENT")
            .unwrap()
            .is_some(),
        "a credential revoked within the retention window must survive"
    );
}
