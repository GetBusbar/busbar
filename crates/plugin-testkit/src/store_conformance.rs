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
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, ModelTokens,
    PlaneDisposition, PlaneRecord, PlaneSelector, SecretForm, Store, UsageLedger, VirtualKey,
};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// A per-`ns` `(old_ts, new_ts)` pair for the two `purge_plane_records_before` checks below, straddling
/// a FIXED, SHARED `cutoff`.
///
/// `purge_plane_records_before(kind, before)` takes a `kind` and a cutoff — no namespace — so it is
/// the one verb in this battery the `ns` discipline (module doc above) cannot reach directly: two
/// concurrent runs sharing a live database both write rows and sweep the same kind-wide cutoff, so
/// each run's sweep can catch the other's OLD rows too, and `assert_eq!(purged, 1)` then fails for a
/// perfectly conforming backend.
///
/// The cutoff itself must NOT vary per run: a `before` that grows with `ns` would let whichever run
/// draws the larger cutoff sweep every smaller-cutoff run's rows in full, including their still-live
/// NEWER rows — trading one collision for a worse one. So `cutoff` is the single fixed point every
/// run shares, and only `old_ts`/`new_ts` are salted per `ns`, each confined to its own side of that
/// shared line: `old_ts` always lands strictly below `cutoff`, `new_ts` always strictly above it. That
/// makes the invariant every run's own survivor check depends on — "the old row is gone, the new row
/// reads back" — hold under an arbitrary interleaving of any number of concurrent runs, since no run's
/// sweep (bounded by the same `cutoff`) can ever reach past `cutoff` into another run's `new_ts`.
fn ns_purge_window(ns: &str, cutoff: u64, high_span: u64) -> (u64, u64) {
    let mut hasher = DefaultHasher::new();
    ns.hash(&mut hasher);
    let salt = hasher.finish();
    let old_ts = 1 + (salt % (cutoff - 1));
    let new_ts = cutoff + 1 + (salt % high_span);
    (old_ts, new_ts)
}

/// Every `VirtualKey` id the suite writes under `ns`. A shared-database backend must delete these
/// (and their credential rows) before calling, and should clean them up afterwards.
pub fn key_ids(ns: &str) -> Vec<String> {
    vec![
        format!("{ns}_resurrect"),
        format!("{ns}_deltwice"),
        format!("{ns}_credowner"),
        format!("{ns}_deadowner"),
        format!("{ns}_mintowner"),
        format!("{ns}_minted"),
        format!("{ns}_persist"),
        format!("{ns}_persistdead"),
    ]
}

/// Every credential id the suite writes under `ns`. See [`key_ids`].
pub fn credential_ids(ns: &str) -> Vec<String> {
    vec![
        format!("{ns}_cred"),
        format!("{ns}_orphan"),
        format!("{ns}_deadcred"),
        format!("{ns}_mintcred"),
        format!("{ns}_mintdupe"),
    ]
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

/// **`put_credential` requires a LIVE owning key.** A credential minted onto a key that names no
/// row, or onto a TOMBSTONED one, must be refused: `delete_key` cascades a key's credentials away
/// precisely so the secret material stops resolving, and accepting a write afterwards puts it back
/// under a key an operator just revoked.
///
/// Enforced in the store for the same reason the tombstone rule above is: a caller that checks the
/// key first and writes after is a read-then-write, and a `delete_key` committing in the gap cascades
/// away only the rows that existed at that moment.
///
/// Skip on a backend with no credential support.
pub fn assert_put_credential_requires_a_live_key(store: &dyn Store, ns: &str) {
    let absent = format!("{ns}_no_such_owner");
    assert!(
        store
            .put_credential(&credential(&format!("{ns}_orphan"), &absent))
            .is_err(),
        "a credential whose owning key names no row was accepted — the secret material now hangs \
         off nothing and no cascade will ever reach it"
    );

    let key_id = format!("{ns}_deadowner");
    let cred_id = format!("{ns}_deadcred");
    store.put_key(&live_key(&key_id)).expect("seed the key");
    store.delete_key(&key_id).expect("tombstone it");
    assert!(
        store
            .put_credential(&credential(&cred_id, &key_id))
            .is_err(),
        "a credential minted onto a TOMBSTONED key was accepted — the tombstone cascade is undone \
         through the other door"
    );
    assert!(
        store
            .lookup_credential_secret("sigv4", &format!("AKIA{cred_id}"))
            .expect("lookup is never an error")
            .is_none(),
        "the refused credential still resolves on the verify path"
    );
}

/// **`put_key_with_credential` is ATOMIC.** When the credential leg is refused — a `public_id`
/// already in use is the ordinary way it is — NO key row may survive. The trait's default is the
/// two-call sequence, which commits the key before the credential can fail, leaving a live bearer key
/// with no credential that the caller was told did not get created.
///
/// Skip on a backend with no credential support.
pub fn assert_put_key_with_credential_is_atomic(store: &dyn Store, ns: &str) {
    let incumbent_key = format!("{ns}_mintowner");
    let incumbent_cred = format!("{ns}_mintcred");
    store
        .put_key(&live_key(&incumbent_key))
        .expect("seed the incumbent key");
    store
        .put_credential(&credential(&incumbent_cred, &incumbent_key))
        .expect("seed the credential holding the public_id");

    // The mint the operator asks for, colliding on the global (kind, public_id) lookup handle.
    let minted_key = format!("{ns}_minted");
    let mut minted = credential(&format!("{ns}_mintdupe"), &minted_key);
    minted.meta.public_id = format!("AKIA{incumbent_cred}");
    assert!(
        store
            .put_key_with_credential(&live_key(&minted_key), &minted)
            .is_err(),
        "a mint whose credential collides on (kind, public_id) must fail"
    );
    assert!(
        store.get_key(&minted_key).expect("read back").is_none(),
        "the refused mint committed its key leg anyway — an orphan bearer key is live and the \
         caller was told the mint failed"
    );
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
    // ts is a fixed sentinel far above any `ns_time_band` window the purge checks below can produce
    // (max ~200_000_100), so a purge sweep run concurrently against the same shared database can
    // never reach these rows out from under this assertion.
    const PARENT_ENUM_TS: u64 = 500_000_000_000;
    for principal in [&p1, &p2] {
        store
            .append_plane_record(&plane_call(principal, 1, PARENT_ENUM_TS))
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

/// **`purge_plane_records_before` (kind `call`) HONOURS THE CUTOFF.** The retention sweep drops rows
/// STRICTLY OLDER than `before` and leaves everything at or after it alone, and it reports how many
/// it actually dropped.
///
/// The eighth neutral verb, and the only one whose failure mode is destruction rather than a wrong
/// answer. Both directions are wrong and both are checked here, because a suite that only asked
/// "did anything go?" would accept either:
///
/// - a backend that IGNORES `before` and truncates the kind deletes live plane state on the first
///   sweep an operator ever runs, and nothing downstream can tell it apart from a quiet node;
/// - a backend that returns `Ok(0)` and purges nothing conforms to the trait signature perfectly
///   while the plane log grows without bound.
///
/// The assertions are on the SURVIVORS ONLY, and deliberately not on the returned count. The count
/// is kind-wide (see [`ns_purge_window`]): under a genuinely concurrent sibling run sharing the same
/// live database, whichever of the two sweeps executes SECOND can correctly see `0` — the row was
/// already dropped by the sibling's earlier, same-kind sweep — with neither backend being
/// non-conforming. So a per-call bound on the count (exact OR `>= 1`) cannot be asserted without
/// reintroducing the same flake this fix removes; what stays true under any interleaving is the
/// SURVIVOR evidence below (this run's own older row, addressed by id/parent, is gone; its own newer
/// row is still readable), because `new_ts` never crosses the shared `cutoff` regardless of who
/// dropped what when.
pub fn assert_plane_purge_honours_the_cutoff(store: &dyn Store, ns: &str) {
    let parent = format!("{ns}_purgeprin");
    // `cutoff` is FIXED and shared by every run (see `ns_purge_window`); only `old_ts`/`new_ts` are
    // salted per `ns`, each confined to its own side of `cutoff`, so no run's sweep can ever reach a
    // sibling run's `new_ts` regardless of interleaving.
    const CUTOFF: u64 = 100_000;
    let (old_ts, new_ts) = ns_purge_window(ns, CUTOFF, 100_000);
    let cutoff = CUTOFF;
    // Two rows under one parent, one either side of the cutoff. Appended newest-first so a backend
    // that drops "the first N" rather than "the ones older than `before`" cannot pass by accident.
    for (seq, ts) in [(2u64, new_ts), (1u64, old_ts)] {
        store
            .append_plane_record(&plane_call(&parent, seq, ts))
            .expect("append a call plane record");
    }

    // The count itself is not asserted here — see the module doc above this function for why a
    // per-call bound on a kind-wide count cannot hold under a genuinely concurrent sibling run.
    let _purged = store
        .purge_plane_records_before("call", cutoff)
        .expect("purge the call plane records older than the cutoff");

    // Namespace-scoped evidence: this run's OWN older row must be gone and its OWN newer row must
    // survive, regardless of which sweep (this one, or a concurrent sibling's) actually did the work.
    let survivors: Vec<u64> = store
        .list_plane_records("call", &PlaneSelector::Parent(parent.clone()))
        .expect("list the calls for the parent")
        .iter()
        .map(|b| {
            serde_json::from_slice::<SampleCall>(b)
                .expect("decode call")
                .seq
        })
        .collect();
    assert_eq!(
        survivors,
        vec![2],
        "purge_plane_records_before must drop ONLY the rows older than `before`: seq 1 (ts {old_ts}) \
         had to go and seq 2 (ts {new_ts}) had to stay, got {survivors:?}"
    );

    // A second sweep at the same cutoff: this run's own row is confirmed gone either way, so the
    // only thing left to check is that it STAYS gone and the survivor stays put. The count is, again,
    // not asserted (a concurrent sibling run may still contribute rows to the same kind-wide sweep).
    let _reswept = store
        .purge_plane_records_before("call", cutoff)
        .expect("re-purge at the same cutoff");
    let resurvivors: Vec<u64> = store
        .list_plane_records("call", &PlaneSelector::Parent(parent))
        .expect("list the calls for the parent again")
        .iter()
        .map(|b| {
            serde_json::from_slice::<SampleCall>(b)
                .expect("decode call")
                .seq
        })
        .collect();
    assert_eq!(
        resurvivors,
        vec![2],
        "a repeated sweep at the same cutoff must not touch this run's own surviving row, got \
         {resurvivors:?}"
    );
}

/// **`purge_plane_records_before` (kind `task`) drops only TERMINAL rows.** Age alone is not the
/// task table's retention rule: an interrupted task waiting on a human is exactly the row that sits
/// still longest, and dropping it loses the work. Terminality is the envelope's
/// [`PlaneDisposition`] sidecar — a backend never has to decode the opaque body to honour this.
///
/// The cutoff still applies on top: a TERMINAL row newer than `before` stays. So the three rows
/// below separate the two axes, and a backend that honours only one of them fails.
pub fn assert_plane_purge_task_keeps_active_rows(store: &dyn Store, ns: &str) {
    // See `ns_purge_window`: `cutoff` is fixed and shared by every run; only `old_ts`/`fresh_ts` are
    // salted per `ns`, each confined to its own side of `cutoff`, well under the ~1_700_000_000
    // epoch-second fixtures other helpers in this module use for the same `task` kind.
    const CUTOFF: u64 = 100_000;
    let (old_ts, fresh_ts) = ns_purge_window(ns, CUTOFF, 100_000);
    let cutoff = CUTOFF;

    let mut old_active = plane_task(ns, "input-required");
    old_active.ts = old_ts;
    let mut old_terminal = plane_task(ns, "completed");
    old_terminal.ts = old_ts;
    old_terminal.disposition = PlaneDisposition::Terminal;
    let mut fresh_terminal = plane_task(ns, "canceled");
    fresh_terminal.ts = fresh_ts;
    fresh_terminal.disposition = PlaneDisposition::Terminal;
    for record in [&old_active, &old_terminal, &fresh_terminal] {
        store
            .upsert_plane_record(record)
            .expect("upsert a task plane record");
    }

    // The count itself is not asserted here — same kind-wide-collision reason as
    // `assert_plane_purge_honours_the_cutoff` above: whichever of two concurrent sibling runs' sweeps
    // executes second can correctly see `0` for its own call, without either backend being
    // non-conforming. What holds under any interleaving is the namespace-scoped evidence below.
    let _purged = store
        .purge_plane_records_before("task", cutoff)
        .expect("purge the task plane records older than the cutoff");

    let ids: Vec<String> = store
        .list_plane_records("task", &PlaneSelector::All)
        .expect("list the tasks")
        .iter()
        .filter_map(|b| serde_json::from_slice::<SampleTask>(b).ok())
        .map(|t| t.task_id)
        .collect();
    assert!(
        ids.contains(&old_active.id),
        "an ACTIVE task older than the cutoff was purged — an interrupted task waiting on a human \
         is exactly the row that sits still longest, and the work is now gone: {ids:?}"
    );
    assert!(
        ids.contains(&fresh_terminal.id),
        "a TERMINAL task NEWER than the cutoff was purged — the sweep ignored `before`: {ids:?}"
    );
    assert!(
        !ids.contains(&old_terminal.id),
        "the old terminal task the sweep reported dropping is still readable: {ids:?}"
    );
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

// ── THE PERSISTENCE CLAIM, AT THE SEAM ───────────────────────────────────────────────────────────

/// The model name every reopen fixture below charges under. Shared by the ledger and the metering
/// row on purpose: the two sides of the same spend must read back agreeing after the reopen.
const REOPEN_MODEL: &str = "conformance-model";
/// The provider the reopen metering row is attributed to.
const REOPEN_PROVIDER: &str = "conformance-provider";
/// The `(bucket_id, window_start)` window the reopen ledger is written into.
pub const REOPEN_WINDOW: u64 = 1_700_000_000;
/// The metering day-bucket the reopen row is written into.
pub const REOPEN_BUCKET: u64 = 1_699_920_000;

/// The exact `UsageLedger` [`assert_key_spend_and_metering_survive_a_reopen`] writes — and the exact
/// value it demands back. Public so a backend can pre-clean its own window before calling.
pub fn reopen_ledger() -> UsageLedger {
    UsageLedger {
        requests: 7,
        billable_requests: 5,
        models: vec![ModelTokens {
            model: REOPEN_MODEL.to_string(),
            usage_units: [
                ("input".to_string(), 11u64),
                ("output".to_string(), 13u64),
                ("cache_read".to_string(), 3u64),
            ]
            .into_iter()
            .collect(),
        }],
    }
}

/// The metering delta the reopen check charges, for key id `key_id`.
pub fn reopen_metering(key_id: &str) -> MeteringDelta {
    MeteringDelta {
        key_id: key_id.to_string(),
        bucket: REOPEN_BUCKET,
        model: REOPEN_MODEL.to_string(),
        provider: REOPEN_PROVIDER.to_string(),
        tokens_input: 11,
        tokens_output: 13,
        tokens_cache_read: 3,
        tokens_cache_write: 2,
        requests: 4,
        billable_requests: 3,
        key_group_at_use: "conformance-group".to_string(),
        pricing_version: "pv-1".to_string(),
    }
}

/// An opener over ONE ALREADY-OPEN STORE, for a backend that has no separate backing to reopen.
///
/// [`assert_key_spend_and_metering_survive_a_reopen`] takes an opener because the claim is about a
/// SECOND handle; an in-memory backend cannot give it one, since its backing is the process itself.
/// This is the honest way to say that: every call hands back the same live store, so the assertion
/// degrades from a durability proof to a READ-BACK proof, and it degrades in ONE place that says so
/// rather than at each call site inventing its own cast.
///
/// It also saves an ephemeral backend from having to name the trait's home crate just to annotate a
/// closure's return type — the kind of incidental coupling the isolation ledger counts.
pub fn shared_opener<S: Store + 'static>(store: Arc<S>) -> impl Fn() -> Arc<dyn Store> {
    move || Arc::clone(&store) as Arc<dyn Store>
}

/// **State written through the face — a virtual key, its usage ledger, and a metering row — is
/// readable back, UNCHANGED, through a handle obtained by RE-OPENING the same backing.**
///
/// That single sentence is the whole claim, and it is the same claim the recorded
/// `plugins.store-persist|*` oracle cells make end to end over the wire (mint a key, spend against
/// it, kill the process, boot it again, read the key and its spend back). This is that claim at the
/// SEAM instead: no server, no wire, no operator-facing JSON — just [`Store`] — so a backend that
/// fails it fails here with the verb named rather than as a 404 three layers up. The two are
/// deliberately the same claim stated twice, because the recorded cell can only ever be run against
/// whatever backend the harness happened to deploy, and this one runs against every backend in the
/// fleet.
///
/// # What `open` means, and the one thing a green row here does NOT prove
///
/// `open` is "get me a handle onto this backing" — called TWICE, with the first handle dropped in
/// between. For a file- or database-backed store the second call is a genuine REOPEN and the check
/// is a durability proof: the only possible source of the values it reads back is whatever the first
/// handle committed to the backing.
///
/// For a RAM backend there IS no separate backing, so the opener necessarily hands back a handle
/// onto the SAME LIVE STORE (an `Arc` clone, not a reopen). **A green row from a RAM backend
/// therefore proves READ-BACK, NOT DURABILITY** — the state never left the process, nothing was
/// reconstructed from bytes, and the check cannot distinguish a store that persists from one that
/// merely remembers. Do not read a green RAM row as evidence that a restart would keep anything; it
/// is evidence only that the face's read verbs return what its write verbs were given. The
/// durability half of the claim is earned only by a backend whose second `open` really is a second
/// open — the same reason this takes an opener rather than a `&dyn Store`: a single handle can never
/// state the claim at all.
///
/// `Arc<dyn Store>` rather than `Box<dyn Store>` for exactly that RAM case: only a shared handle can
/// express "another handle onto the same live store". A backend whose real open yields a `Box` (a
/// dlopen'd plugin's, say) converts with `Arc::from(boxed)` and loses nothing.
///
/// # What it asserts
///
/// The READ-BACK VALUES, field by field — never `is_some()`. A backend that answered
/// `Some(VirtualKey::default())`, or an empty `UsageLedger`, or a zeroed `MeteringRow`, would
/// satisfy a presence check while having kept nothing, and that is the exact defect shape here: a
/// write verb that returns `Ok(())` and drops the row. `revision` is the one field excluded — it is
/// a store-global monotonic stamp the BACKEND owns (see [`VirtualKey::revision`]), so
/// its value across a reopen is the backend's business, not the contract's.
///
/// It also covers the TOMBSTONE across the reopen: `delete_key` is a tombstone, not a remove, so the
/// second handle must still find the row, still see `deleted_at`/`enabled` set the way the delete
/// left them, and must still REFUSE a live-shaped `put_key` over it. A backend that persisted keys
/// but not the tombstone would silently resurrect every revoked key at the next restart.
///
/// # Namespacing
///
/// `ns` scopes both key ids ([`key_ids`] lists them) and the usage bucket. The metering BUCKET and
/// the usage WINDOW are fixed (`REOPEN_BUCKET`/`REOPEN_WINDOW`) because `list_metering` selects by
/// bucket alone, so the metering assertion filters the returned rows down to THIS `ns`'s key id
/// rather than demanding an exact vector — two concurrent runs against one shared database both see
/// each other's rows in that bucket and neither is wrong.
pub fn assert_key_spend_and_metering_survive_a_reopen(open: &dyn Fn() -> Arc<dyn Store>, ns: &str) {
    let live = format!("{ns}_persist");
    let dead = format!("{ns}_persistdead");
    let key = live_key(&live);
    let ledger = reopen_ledger();
    let charge = reopen_metering(&live);

    // ── HANDLE ONE: mint, spend, kill. Then let the handle go. ────────────────────────────────
    //
    // Deliberately no read-back in this block: the claim is about the SECOND handle, and an
    // assertion here would fire first and report a same-handle symptom in its place.
    {
        let store = open();
        store
            .put_key(&key)
            .expect("handle one: mint the key that must survive the reopen");
        store
            .put_key(&live_key(&dead))
            .expect("handle one: mint the key that gets revoked");
        store
            .delete_key(&dead)
            .expect("handle one: revoke it — a TOMBSTONE, which must survive the reopen too");
        store
            .put_usage(&live, REOPEN_WINDOW, &ledger)
            .expect("handle one: write the spend ledger");
        store
            .add_metering(&charge)
            .expect("handle one: charge the metering row");
    }

    // ── HANDLE TWO: the reopen. Everything below reads only through this handle. ───────────────
    let store = open();

    let back = store
        .get_key(&live)
        .expect("handle two: get_key must not error")
        .unwrap_or_else(|| {
            panic!(
                "handle two: get_key('{live}') is None — the key written through handle one did \
                 not survive the reopen. `put_key` returned Ok and the row is gone."
            )
        });
    assert_eq!(back.id, key.id, "the reopened key's id");
    assert_eq!(
        back.generation_hash, key.generation_hash,
        "the reopened key's generation_hash — the rotation fingerprint `verify_token` compares a \
         token's `generation` claim against; a backend that dropped it silently invalidates every \
         live token at the next restart"
    );
    assert_eq!(back.name, key.name, "the reopened key's name");
    assert_eq!(
        back.enabled, key.enabled,
        "the reopened key's enabled flag — a key that came back disabled is a key nobody can use"
    );
    assert_eq!(
        back.created_at, key.created_at,
        "the reopened key's created_at"
    );
    assert_eq!(back.group, key.group, "the reopened key's group binding");
    assert_eq!(back.labels, key.labels, "the reopened key's labels");
    assert_eq!(
        back.expires_at, key.expires_at,
        "the reopened key's expires_at"
    );
    assert_eq!(
        back.deleted_at, None,
        "the LIVE key came back carrying a tombstone it was never given: {back:?}"
    );
    assert_eq!(
        back.allowed_scopes, key.allowed_scopes,
        "the reopened key's scope grant — `None` is the omitted-grant wildcard and `Some([])` is \
         the empty set, so a backend that confuses them across a reopen turns a no-scopes key into \
         an all-scopes one"
    );

    assert!(
        store
            .list_keys()
            .expect("handle two: list_keys must not error")
            .iter()
            .any(|k| k.id == live),
        "the reopened key is readable by id but ABSENT from list_keys — hydration at boot walks \
         the listing, so a key only `get_key` can find is a key the engine never loads"
    );

    assert_eq!(
        store
            .get_usage(&live, REOPEN_WINDOW)
            .expect("handle two: get_usage must not error"),
        ledger,
        "the spend ledger did not survive the reopen UNCHANGED. An empty ledger here is the \
         defect: `put_usage` returned Ok, and after the restart the key's budget is spent back to \
         zero — every cap the operator set is silently refunded"
    );

    let rows: Vec<MeteringRow> = store
        .list_metering(REOPEN_BUCKET)
        .expect("handle two: list_metering must not error")
        .into_iter()
        .filter(|r| r.key_id == live)
        .collect();
    let expected = MeteringRow {
        key_id: live.clone(),
        model: charge.model.clone(),
        provider: charge.provider.clone(),
        tokens_input: charge.tokens_input,
        tokens_output: charge.tokens_output,
        tokens_cache_read: charge.tokens_cache_read,
        tokens_cache_write: charge.tokens_cache_write,
        requests: charge.requests,
        billable_requests: charge.billable_requests,
        key_group_at_use: charge.key_group_at_use.clone(),
        pricing_version: charge.pricing_version.clone(),
    };
    assert_eq!(
        rows,
        vec![expected],
        "the metering row did not survive the reopen UNCHANGED. This is the BILLING ledger: an \
         empty vector here means every response served before the restart is unbilled, and a row \
         with zeroed counts means it is billed at nothing"
    );

    // ── THE TOMBSTONE, ACROSS THE REOPEN ──────────────────────────────────────────────────────
    let revoked = store
        .get_key(&dead)
        .expect("handle two: get_key on the revoked id must not error")
        .unwrap_or_else(|| {
            panic!(
                "handle two: get_key('{dead}') is None — `delete_key` is a TOMBSTONE, not a \
                 remove: the row is KEPT so anything attributing by key id (billing, audit) keeps \
                 resolving forever. A backend that persisted the removal instead of the tombstone \
                 has lost the attribution."
            )
        });
    assert!(
        revoked.deleted_at.is_some(),
        "the revoked key came back WITHOUT its tombstone — the reopen resurrected a key an \
         operator killed: {revoked:?}"
    );
    assert!(
        !revoked.enabled,
        "the revoked key came back ENABLED: {revoked:?}"
    );
    assert!(
        store.put_key(&live_key(&dead)).is_err(),
        "after the reopen, a live-shaped put_key over the tombstoned id was ACCEPTED — the \
         tombstone precondition did not survive the reopen, so every revoked key is one ordinary \
         rename away from being live again"
    );
}
