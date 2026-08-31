// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Contract conformance for [`busbar_api::Store`] — the checks every backend must pass identically.
//!
//! These exist because an audit found the fleet disagreeing with itself: the same input produced a
//! different outcome depending on which store an operator had deployed. `revoke_credential` on an
//! unknown id errored on three backends and silently succeeded on two. `delete_key` on an unknown id
//! split the other way. `append_audit` on a duplicate `seq` had three distinct behaviours across four
//! backends. None of that was a defect in any one backend — the trait doc had not settled it, so each
//! implementation settled it alone.
//!
//! The trait doc settles it now, and this module is how that ruling stays settled. A backend calls
//! these from its own test module; a new ruling added here reaches every backend on its next
//! dependency bump, instead of being hand-copied into each repo and drifting again.
//!
//! # Namespacing, and why every helper takes one
//!
//! Two of the backends (store-postgres, store-mysql) run their suites against a SHARED, live
//! database that is not reset between tests, and their CI can run more than one test binary against
//! it at once. A fixture on a fixed id would then make two concurrent runs each other's failure —
//! store-postgres's own audit test already derives its `seq` from the process id for exactly this
//! reason. So every helper takes an `ns` (or an explicit `seq`) and derives its fixtures from it.
//!
//! The caller owns cleanup: **reset [`key_ids`] and [`credential_ids`] for your `ns`, and delete
//! your `seq`, before calling.** An in-memory backend gets this for free by opening a fresh store;
//! a shared-database backend must issue the deletes itself, since this crate has no SQL of its own.
//!
//! Usage, from a store plugin's own tests:
//! ```ignore
//! use busbar_plugin_testkit::store_conformance as conf;
//!
//! #[test]
//! fn put_key_does_not_resurrect_a_tombstone() {
//!     let ns = format!("conf{}", std::process::id());
//!     hard_reset(&store, &conf::key_ids(&ns));   // the backend's own cleanup
//!     conf::assert_put_key_does_not_resurrect_a_tombstone(&open(), &ns);
//! }
//! ```

use busbar_api::{
    AuditRecord, CredentialMeta, CredentialSecret, PlaneDisposition, PlaneRecord, PlaneSelector,
    SecretForm, Store, VirtualKey,
};
use serde::{Deserialize, Serialize};

/// Every `VirtualKey` id the suite writes under `ns`. A shared-database backend must delete these
/// (and their credential rows) before calling, and should clean them up afterwards.
pub fn key_ids(ns: &str) -> Vec<String> {
    vec![
        format!("{ns}_resurrect"),
        format!("{ns}_deltwice"),
        format!("{ns}_credowner"),
    ]
}

/// Every credential id the suite writes under `ns`. See [`key_ids`].
pub fn credential_ids(ns: &str) -> Vec<String> {
    vec![format!("{ns}_cred")]
}

/// A minimal live key. `id` names the row; every other field is a don't-care the checks never read.
pub fn live_key(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: format!("binding:{id}:g1"),
        name: format!("conformance {id}"),
        allowed_scopes: None,
        enabled: true,
        created_at: 1_700_000_000,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
        ..Default::default()
    }
}

/// A minimal `sigv4` credential for `key_id`, in slot 0.
pub fn credential(id: &str, key_id: &str) -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: id.to_string(),
            key_id: key_id.to_string(),
            kind: "sigv4".to_string(),
            slot: 0,
            // Bounded well under the 128-char column every backend uses, and unique per `ns` so two
            // concurrent runs cannot collide on the global `(kind, public_id)` uniqueness rule.
            public_id: format!("AKIA{id}"),
            secret_form: SecretForm::Recoverable,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: "v1:plain:conformance-secret".to_string(),
    }
}

/// A minimal audit record at `seq`, with `action` as the field the duplicate-`seq` check varies.
pub fn audit(seq: u64, action: &str) -> AuditRecord {
    AuditRecord {
        seq,
        ts: 1_700_000_000,
        action: action.to_string(),
        resource: "hook:conformance".to_string(),
        outcome: "applied".to_string(),
        principal: "conformance".to_string(),
        prev_hash: String::new(),
        hash: format!("hash-of-{action}-at-{seq}"),
    }
}

/// **`put_key` must not clear a tombstone.** Writing a LIVE key over a tombstoned row resurrects a
/// key an operator revoked, which is the outcome `delete_key` exists to prevent, reached through the
/// other door. Writing a key that CARRIES a tombstone stays allowed — hydration and fixtures do that
/// legitimately, and neither clears anything.
///
/// Enforced in the store rather than by the caller on purpose: core's callers do check `deleted_at`
/// first, but that is a read-then-write, and a `delete_key` committing in the gap goes straight
/// through it. Only the backend can make the test and the write atomic.
pub fn assert_put_key_does_not_resurrect_a_tombstone(store: &dyn Store, ns: &str) {
    let id = format!("{ns}_resurrect");
    let key = live_key(&id);
    store.put_key(&key).expect("seed the live key");
    store.delete_key(&id).expect("tombstone it");

    let stored = store
        .get_key(&id)
        .expect("read back")
        .expect("the row is kept, only tombstoned");
    assert!(
        stored.deleted_at.is_some(),
        "delete_key must tombstone rather than remove: {stored:?}"
    );

    // The whole point: an ordinary live-shaped put, exactly as a rename or an enable would issue.
    assert!(
        store.put_key(&key).is_err(),
        "put_key with deleted_at: None overwrote a tombstoned row — the key is now live again and \
         nothing said so"
    );

    let after = store
        .get_key(&id)
        .expect("read back")
        .expect("still present");
    assert!(
        after.deleted_at.is_some(),
        "the tombstone must survive the rejected write: {after:?}"
    );

    // The other half, and the reason this is not simply "reject every write to a tombstoned row":
    // writing a row that already carries the tombstone is legitimate and must still work.
    //
    // `enabled` goes false alongside it. `delete_key` sets both together, and a backend is entitled
    // to enforce that pairing (store-sqlite has a `keys_tombstone_off` CHECK constraint that does
    // exactly this) — a row that is simultaneously enabled and deleted is a corrupt half-state, not
    // something a conformance suite should be asking a backend to accept.
    let mut tombstoned = key.clone();
    tombstoned.deleted_at = after.deleted_at;
    tombstoned.enabled = false;
    store
        .put_key(&tombstoned)
        .expect("writing a row that CARRIES a tombstone clears nothing and must be allowed");
}

/// **`delete_key` on an unknown id is an error.** Distinct from the documented idempotent case:
/// "already tombstoned" means the intent is satisfied and the evidence is on disk, while "no such
/// id" means nothing was touched, and `Ok(())` there tells an operator a key was revoked when it was
/// not.
pub fn assert_delete_key_unknown_id_is_an_error(store: &dyn Store, ns: &str) {
    assert!(
        store.delete_key(&format!("{ns}_no_such_key")).is_err(),
        "delete_key on an id that names no row returned Ok — an operator who typo'd an id is told \
         the key is revoked"
    );

    // And the case that IS idempotent, so the check above cannot be satisfied by erroring on both.
    let id = format!("{ns}_deltwice");
    store.put_key(&live_key(&id)).expect("seed");
    store.delete_key(&id).expect("first delete");
    store
        .delete_key(&id)
        .expect("deleting an ALREADY-tombstoned key is idempotent, not an error");
}

/// **`revoke_credential` on an unknown id is an error, on an already-revoked id is `Ok`.** A backend
/// has to read the row count its UPDATE actually affected: a statement that matched nothing looks
/// identical to one that matched, and this is the case where those must not be confused — a silent
/// no-op lets an operator believe a leaked secret was killed when it was not.
///
/// Skip on a backend with no credential support.
pub fn assert_revoke_credential_unknown_id_is_an_error(store: &dyn Store, ns: &str) {
    assert!(
        store
            .revoke_credential(&format!("{ns}_no_such_cred"), "leaked")
            .is_err(),
        "revoke_credential on an id that names no row returned Ok — an operator responding to a \
         leak is told the credential is dead when it is still live"
    );

    let key_id = format!("{ns}_credowner");
    let cred_id = format!("{ns}_cred");
    store.put_key(&live_key(&key_id)).expect("seed the key");
    store
        .put_credential(&credential(&cred_id, &key_id))
        .expect("seed the credential");
    store
        .revoke_credential(&cred_id, "leaked")
        .expect("first revoke");
    store
        .revoke_credential(&cred_id, "leaked again")
        .expect("revoking an ALREADY-revoked credential is idempotent, not an error");
}

/// **`append_audit` on a duplicate `seq`:** identical record → `Ok` (the write-through retrying after
/// a timeout, the common case); DIFFERENT record → error (two records claiming one chain position is
/// a forked or tampered log, and it is the single most important thing an audit store can report).
///
/// Overwriting is never correct — it destroys the second case instead of reporting it. Silently
/// keeping the first is not correct either: it collapses both cases into one and drops a genuinely
/// different record on the floor.
///
/// `seq` must be free before this runs (see the module doc on namespacing). Skip on a backend that
/// does not provide durable audit (the defaulted no-op).
pub fn assert_append_audit_duplicate_seq(store: &dyn Store, seq: u64) {
    let first = audit(seq, "hook.register");
    store.append_audit(&first).expect("first append");
    store
        .append_audit(&first)
        .expect("re-appending the IDENTICAL record is the retry path and must be Ok");

    let forked = audit(seq, "hook.remove");
    assert!(
        store.append_audit(&forked).is_err(),
        "a DIFFERENT record on an already-occupied seq was accepted — the audit chain has forked \
         and the store said nothing"
    );

    // The stored record must still be the original: neither overwritten nor recomputed. Filtered by
    // `seq` rather than read positionally, so a shared `audit_log` carrying other tests' rows (or a
    // concurrent run's) cannot affect the result.
    let entries = store.list_audit().expect("list");
    let at_seq: Vec<_> = entries.iter().filter(|e| e.seq == seq).collect();
    assert_eq!(
        at_seq.len(),
        1,
        "exactly one record may occupy a seq, got {at_seq:?}"
    );
    assert_eq!(
        at_seq[0].action, "hook.register",
        "the rejected append must not have overwritten the stored record"
    );
}

// ── THE NEUTRAL KIND-TAGGED PLANE-RECORD CONTRACT (1.6.0) ────────────────────────────────────────
//
// The eight neutral verbs (`upsert_plane_record`/…/`redeem_plane_token`) are the ONE durable-plane
// surface every backend now shares (the fourteen protocol-named methods were deleted). These checks
// pin the cross-plugin behaviour a plane depends on regardless of which store an operator deployed —
// the `list_task_events`-orders-by-seq / `list_mcp_call_principals`-enumerates / single-use-ask
// rulings that used to live only in each backend's own suite (and, before them, drifted).
//
// The opaque `body` is a serialized row exactly as core sends it (`serde_json`, the same the
// backends decode with), and the `kind` strings match the reference `impl Store` verbatim. Read-back
// is compared as the DECODED row, so a backend that stores typed columns and re-encodes conforms
// without matching byte-for-byte on an incidental field order.
//
// This module is DELIBERATELY OPAQUE over the plane row types: it names none of the protocol row
// structs (`TaskRow`/`TaskEventRow`/`McpCallRecord`/`McpDemotionRow`, relocated out of `busbar-api`
// into the plane crates). The `body` is just serialized JSON with the field NAMES a backend that
// projects a kind into typed columns decodes by — so these throwaway stand-in structs carry exactly
// those fields, and a backend that stores the body verbatim and one that decodes/re-encodes it both
// conform.
//
// SKIP on a backend that provides no durable plane state (the defaulted keep-nothing — e.g. the RAM
// default). Namespacing follows the module doc: derive fixtures from `ns` and reset the plane tables
// for that `ns` before calling on a shared-database backend.

/// A stand-in for the `task`-kind body: the field NAMES a backend decodes by, nothing more. Local to
/// the suite so the conformance checks name no relocated plane row type.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
struct SampleTask {
    task_id: String,
    context_id: String,
    principal: String,
    direction: String,
    state: String,
    agent_id: String,
    artifact_cursor: u64,
    push_callback: String,
    created_at: u64,
    updated_at: u64,
}

/// A stand-in for the `task_event`-kind body.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
struct SampleEvent {
    task_id: String,
    seq: u64,
    ts: u64,
    kind: String,
    context_id: String,
    principal: String,
    agent_id: String,
    state: String,
    request_id: String,
    prev_hash: String,
    hash: String,
}

/// A stand-in for the `call`-kind body.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
struct SampleCall {
    principal: String,
    seq: u64,
    ts: u64,
    server: String,
    tool: String,
    outcome: String,
    reason: String,
    tool_digest: String,
    pin_generation: u64,
    request_id: String,
    prev_hash: String,
    hash: String,
}

/// A stand-in for the `demotion`-kind body.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
struct SampleDemotion {
    server: String,
    reason: String,
    recorded_at: u64,
}

/// A minimal active (non-terminal) task plane record for `ns`, built from a throwaway body.
pub fn plane_task(ns: &str, state: &str) -> PlaneRecord {
    let task = SampleTask {
        task_id: format!("{ns}_ptask_{state}"),
        context_id: format!("{ns}_ctx"),
        principal: format!("{ns}_vk"),
        direction: "inbound".into(),
        state: state.to_string(),
        agent_id: format!("{ns}_agent"),
        artifact_cursor: 0,
        push_callback: String::new(),
        created_at: 1_700_000_000,
        updated_at: 1_700_000_100,
    };
    PlaneRecord {
        kind: "task".into(),
        id: task.task_id.clone(),
        parent: None,
        seq: 0,
        ts: task.updated_at,
        disposition: PlaneDisposition::Active,
        body: body(&task),
    }
}

/// A minimal per-task provenance-event plane record.
pub fn plane_event(task_id: &str, seq: u64) -> PlaneRecord {
    let event = SampleEvent {
        task_id: task_id.to_string(),
        seq,
        ts: 1_700_000_000 + seq,
        kind: "task.working".into(),
        context_id: "ctx".into(),
        principal: "vk".into(),
        agent_id: "agent".into(),
        state: "working".into(),
        request_id: format!("req-{seq}"),
        prev_hash: String::new(),
        hash: format!("h{seq}"),
    };
    PlaneRecord {
        kind: "task_event".into(),
        id: event.task_id.clone(),
        parent: Some(event.task_id.clone()),
        seq: event.seq,
        ts: event.ts,
        disposition: PlaneDisposition::Active,
        body: body(&event),
    }
}

/// A minimal MCP per-call plane record.
pub fn plane_call(principal: &str, seq: u64, ts: u64) -> PlaneRecord {
    let call = SampleCall {
        principal: principal.to_string(),
        seq,
        ts,
        server: "srv".into(),
        tool: "srv_do".into(),
        outcome: "dispatched".into(),
        reason: String::new(),
        tool_digest: "sha256:d".into(),
        pin_generation: 1,
        request_id: format!("req-{seq}"),
        prev_hash: String::new(),
        hash: format!("h{seq}"),
    };
    PlaneRecord {
        kind: "call".into(),
        id: call.principal.clone(),
        parent: Some(call.principal.clone()),
        seq: call.seq,
        ts: call.ts,
        disposition: PlaneDisposition::Active,
        body: body(&call),
    }
}

/// A minimal MCP demotion plane record for `server`.
pub fn plane_demotion(server: &str) -> PlaneRecord {
    let demotion = SampleDemotion {
        server: server.to_string(),
        reason: "drift".into(),
        recorded_at: 1_700_000_000,
    };
    PlaneRecord {
        kind: "demotion".into(),
        id: demotion.server.clone(),
        parent: None,
        seq: 0,
        ts: demotion.recorded_at,
        disposition: PlaneDisposition::Active,
        body: body(&demotion),
    }
}

fn body<T: serde::Serialize>(row: &T) -> Vec<u8> {
    serde_json::to_vec(row).expect("serialize a plane row into an opaque body")
}

/// **`upsert_plane_record`/`get_plane_record` (kind `task`) round-trip.** A task written through the
/// neutral upsert reads back through the neutral point-read as the same row; an unknown id is `None`,
/// not an error; and the row appears in the kind's unfiltered listing.
pub fn assert_plane_task_upsert_get_list(store: &dyn Store, ns: &str) {
    let record = plane_task(ns, "working");
    let task_id = record.id.clone();
    let expected: SampleTask =
        serde_json::from_slice(&record.body).expect("decode the expected task body");
    store
        .upsert_plane_record(&record)
        .expect("upsert the task plane record");

    let got = store
        .get_plane_record("task", &task_id)
        .expect("get the task plane record")
        .expect("the task must be present after an upsert that reported success");
    let decoded: SampleTask = serde_json::from_slice(&got).expect("decode the task body");
    assert_eq!(
        decoded, expected,
        "the round-tripped task row must be identical"
    );

    assert!(
        store
            .get_plane_record("task", &format!("{ns}_no_such_task"))
            .expect("get an unknown task is not an error")
            .is_none(),
        "an unknown id must read back as None, not a fabricated row"
    );

    let listed = store
        .list_plane_records("task", &PlaneSelector::All)
        .expect("list the task plane records");
    assert!(
        listed
            .iter()
            .filter_map(|b| serde_json::from_slice::<SampleTask>(b).ok())
            .any(|t| t.task_id == task_id),
        "the upserted task must appear in the kind's unfiltered listing"
    );
}

/// **`append_plane_record`/`list_plane_records(Parent)` (kind `task_event`) orders by `seq`.** Events
/// appended OUT of order come back oldest-first — the property the engine's chain verifier depends
/// on. This is exactly the cross-backend ruling that used to live only in each backend's own suite.
pub fn assert_plane_event_chain_is_ordered_by_seq(store: &dyn Store, ns: &str) {
    let parent = format!("{ns}_pchain");
    // Append seq 2 BEFORE seq 1: a backend that returns insertion order rather than `seq` order fails.
    for seq in [2u64, 1u64] {
        store
            .append_plane_record(&plane_event(&parent, seq))
            .expect("append a task-event plane record");
    }
    let seqs: Vec<u64> = store
        .list_plane_records("task_event", &PlaneSelector::Parent(parent.clone()))
        .expect("list the task events for the parent")
        .iter()
        .map(|b| {
            serde_json::from_slice::<SampleEvent>(b)
                .expect("decode event")
                .seq
        })
        .collect();
    assert_eq!(seqs, vec![1, 2], "events must list oldest-first by seq");
}

/// **`list_plane_record_parents` (kind `call`) enumerates every parent with a record.** The boot
/// enumeration a restart resumes chains from — it must find a principal this process never saw
/// written.
pub fn assert_plane_call_parents_enumerated(store: &dyn Store, ns: &str) {
    let p1 = format!("{ns}_prinA");
    let p2 = format!("{ns}_prinB");
    for principal in [&p1, &p2] {
        store
            .append_plane_record(&plane_call(principal, 1, 10))
            .expect("append a call plane record");
    }
    let parents = store
        .list_plane_record_parents("call")
        .expect("enumerate the call parents");
    assert!(
        parents.contains(&p1),
        "parent {p1} must be enumerated: {parents:?}"
    );
    assert!(
        parents.contains(&p2),
        "parent {p2} must be enumerated: {parents:?}"
    );
}

/// **`upsert_plane_record`/`list_plane_records(All)`/`delete_plane_record` (kind `demotion`).** A
/// demotion is recorded, listed, then dropped; deleting an ABSENT record is a no-op, not an error.
pub fn assert_plane_demotion_upsert_list_delete(store: &dyn Store, ns: &str) {
    let s1 = format!("{ns}_srvA");
    let s2 = format!("{ns}_srvB");
    for server in [&s1, &s2] {
        store
            .upsert_plane_record(&plane_demotion(server))
            .expect("upsert a demotion plane record");
    }
    let servers = |store: &dyn Store| -> Vec<String> {
        store
            .list_plane_records("demotion", &PlaneSelector::All)
            .expect("list demotions")
            .iter()
            .filter_map(|b| serde_json::from_slice::<SampleDemotion>(b).ok())
            .map(|d| d.server)
            .collect()
    };
    let listed = servers(store);
    assert!(
        listed.contains(&s1) && listed.contains(&s2),
        "both demotions listed: {listed:?}"
    );

    store
        .delete_plane_record("demotion", &s1)
        .expect("delete a demotion plane record");
    let after = servers(store);
    assert!(
        !after.contains(&s1),
        "the deleted demotion is gone: {after:?}"
    );
    assert!(
        after.contains(&s2),
        "the other demotion survives: {after:?}"
    );

    store
        .delete_plane_record("demotion", &format!("{ns}_no_such_server"))
        .expect("deleting an absent demotion is an idempotent no-op, not an error");
}

/// **`redeem_plane_token` (kind `ask`) is a single-use test-and-set.** The FIRST redemption of a
/// nonce is `true`, every later one is `false` — the durable ledger that makes a confirm-once tool
/// execute once across a restart and across two nodes. A different nonce is still redeemable.
pub fn assert_plane_token_is_single_use(store: &dyn Store, ns: &str) {
    let token = format!("{ns}_asknonce");
    let expires_at = 2_000_000_000;
    let now = 1_700_000_000;
    assert!(
        store
            .redeem_plane_token("ask", &token, expires_at, now)
            .expect("first redemption"),
        "the FIRST redemption of a nonce must report true"
    );
    assert!(
        !store
            .redeem_plane_token("ask", &token, expires_at, now)
            .expect("second redemption"),
        "a SECOND redemption of the same nonce must report false — this is the double-spend the \
         ledger exists to refuse"
    );
    assert!(
        store
            .redeem_plane_token("ask", &format!("{ns}_othernonce"), expires_at, now)
            .expect("a different nonce"),
        "a different nonce is still redeemable"
    );
}
