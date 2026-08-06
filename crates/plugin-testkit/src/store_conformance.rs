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
//! Each helper takes an EMPTY, freshly-opened store, and each is independent — a backend runs the
//! ones that apply to it (a store with no credential support skips the credential one) and no helper
//! depends on another having run.
//!
//! Usage, from a store plugin's own tests:
//! ```ignore
//! use busbar_plugin_testkit::store_conformance as conf;
//!
//! #[test]
//! fn put_key_does_not_resurrect_a_tombstone() {
//!     conf::assert_put_key_does_not_resurrect_a_tombstone(&open_fresh());
//! }
//! ```

use busbar_api::{AuditRecord, CredentialMeta, CredentialSecret, SecretForm, Store, VirtualKey};

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
pub fn assert_put_key_does_not_resurrect_a_tombstone(store: &dyn Store) {
    let key = live_key("resurrect-me");
    store.put_key(&key).expect("seed the live key");
    store.delete_key("resurrect-me").expect("tombstone it");

    let stored = store
        .get_key("resurrect-me")
        .expect("read back")
        .expect("the row is kept, only tombstoned");
    assert!(
        stored.deleted_at.is_some(),
        "delete_key must tombstone rather than remove: {stored:?}"
    );

    // The whole point: an ordinary live-shaped put, exactly as a rename or an enable would issue.
    let err = store.put_key(&key);
    assert!(
        err.is_err(),
        "put_key with deleted_at: None overwrote a tombstoned row — the key is now live again and \
         nothing said so"
    );

    let after = store
        .get_key("resurrect-me")
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
pub fn assert_delete_key_unknown_id_is_an_error(store: &dyn Store) {
    assert!(
        store.delete_key("no-such-key-id").is_err(),
        "delete_key on an id that names no row returned Ok — an operator who typo'd an id is told \
         the key is revoked"
    );

    // And the case that IS idempotent, so the check above cannot be satisfied by erroring on both.
    store.put_key(&live_key("delete-twice")).expect("seed");
    store.delete_key("delete-twice").expect("first delete");
    store
        .delete_key("delete-twice")
        .expect("deleting an ALREADY-tombstoned key is idempotent, not an error");
}

/// **`revoke_credential` on an unknown id is an error, on an already-revoked id is `Ok`.** A backend
/// has to read the row count its UPDATE actually affected: a statement that matched nothing looks
/// identical to one that matched, and this is the case where those must not be confused — a silent
/// no-op lets an operator believe a leaked secret was killed when it was not.
///
/// Skip on a backend with no credential support.
pub fn assert_revoke_credential_unknown_id_is_an_error(store: &dyn Store) {
    assert!(
        store
            .revoke_credential("no-such-credential-id", "leaked")
            .is_err(),
        "revoke_credential on an id that names no row returned Ok — an operator responding to a \
         leak is told the credential is dead when it is still live"
    );

    store
        .put_key(&live_key("cred-owner"))
        .expect("seed the key");
    store
        .put_credential(&credential("cred-1", "cred-owner"))
        .expect("seed the credential");
    store
        .revoke_credential("cred-1", "leaked")
        .expect("first revoke");
    store
        .revoke_credential("cred-1", "leaked again")
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
/// Skip on a backend that does not provide durable audit (the defaulted no-op).
pub fn assert_append_audit_duplicate_seq(store: &dyn Store) {
    let first = audit(1, "hook.register");
    store.append_audit(&first).expect("first append");
    store
        .append_audit(&first)
        .expect("re-appending the IDENTICAL record is the retry path and must be Ok");

    let forked = audit(1, "hook.remove");
    assert!(
        store.append_audit(&forked).is_err(),
        "a DIFFERENT record on an already-occupied seq was accepted — the audit chain has forked \
         and the store said nothing"
    );

    // The stored record must still be the original: neither overwritten nor recomputed.
    let entries = store.list_audit().expect("list");
    let at_one: Vec<_> = entries.iter().filter(|e| e.seq == 1).collect();
    assert_eq!(
        at_one.len(),
        1,
        "exactly one record may occupy a seq, got {at_one:?}"
    );
    assert_eq!(
        at_one[0].action, "hook.register",
        "the rejected append must not have overwritten the stored record"
    );
}
