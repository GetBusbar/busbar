// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MUTATION-HARDENING: `busbar_contract::store::Store` contract TOTALITY.
//!
//! Every `Store` method's DEFAULT body carries real logic (an error, an empty list, a no-op, a
//! sequential compose), and none of it was exercised anywhere in the crate before this file: a
//! backend that overrides the method is exercised by that backend's own test suite, but the
//! DEFAULT itself — the fallback every lightweight test double and every backend that hasn't
//! implemented the newer surface actually runs — had no direct test. That is exactly the gap
//! mutation testing finds: a mutant that flips `Err(..)` to `Ok(())`, or `Ok(Vec::new())` to
//! `Ok(vec![...])`, or drops a step out of a sequential default, produces no compile error and no
//! existing test failure.
//!
//! This is an INTEGRATION test (`crates/busbar-contract/tests/`, auto-discovered by Cargo — no
//! `mod` line needs to be added anywhere for this file to run). It exercises only the kind face's
//! public surface (`busbar_contract::store::*`), same as any out-of-tree Store-plugin author would.
//!
//! IT LIVES BESIDE THE FACE IT TESTS. It was written under the retiring 1.5.5 compatibility crate's
//! tests while that crate still re-exported this face; the re-export is deleted, so the file moved
//! to the crate that DECLARES the trait. Byte-identical but for this paragraph and the sentence
//! above it: the assertions, the `Bare` double and every default body exercised are untouched.
//!
//! `Bare` implements ONLY the eight REQUIRED `Store` methods — every other method here is exercised
//! at its DEFAULT, unmodified body.

use busbar_contract::store::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneDisposition,
    PlaneRecord, PlaneRequestCtx, PlaneSelector, SecretForm, Store, StoreError, StoreResult,
    UsageLedger, VirtualKey,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// The minimal `Store`: only the eight methods with NO default body. Every other trait method here
/// runs at its shipped default — this is deliberately the same shape as `store_tests.rs`'s own
/// `PreTaskBackend` (a backend that keeps no durable plane state must still compile), extended to
/// cover the credential/audit/denylist/plane-record defaults that file does not touch.
#[derive(Default)]
struct Bare {
    put_key_calls: AtomicUsize,
    keys: Mutex<Vec<VirtualKey>>,
}

impl Store for Bare {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        self.put_key_calls.fetch_add(1, Ordering::SeqCst);
        self.keys.lock().unwrap().push(key.clone());
        Ok(())
    }
    fn get_key(&self, _id: &str) -> StoreResult<Option<VirtualKey>> {
        Ok(None)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        Ok(Vec::new())
    }
    fn delete_key(&self, _id: &str) -> StoreResult<()> {
        Ok(())
    }
    fn get_usage(&self, _bucket_id: &str, _window_start: u64) -> StoreResult<UsageLedger> {
        Ok(UsageLedger::default())
    }
    fn put_usage(
        &self,
        _bucket_id: &str,
        _window_start: u64,
        _ledger: &UsageLedger,
    ) -> StoreResult<()> {
        Ok(())
    }
    fn add_metering(&self, _delta: &MeteringDelta) -> StoreResult<()> {
        Ok(())
    }
    fn list_metering(&self, _bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        Ok(Vec::new())
    }
}

fn sample_key() -> VirtualKey {
    VirtualKey {
        id: "vk_1".to_string(),
        generation_hash: "h".to_string(),
        name: "n".to_string(),
        enabled: true,
        created_at: 1,
        ..Default::default()
    }
}

fn sample_credential() -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: "cred_1".to_string(),
            key_id: "vk_1".to_string(),
            kind: "sigv4".to_string(),
            slot: 0,
            public_id: "AKIA_TEST".to_string(),
            secret_form: SecretForm::Recoverable,
            created_at: 1,
            updated_at: 1,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: "v1:plain:s3cr3t".to_string(),
    }
}

fn sample_audit(seq: u64) -> AuditRecord {
    AuditRecord {
        seq,
        ts: 0,
        action: "test.action".to_string(),
        resource: "test:res".to_string(),
        outcome: "applied".to_string(),
        principal: "vk_1".to_string(),
        prev_hash: String::new(),
        hash: String::new(),
    }
}

// ── Error-path defaults: a backend that has NOT implemented the surface must fail LOUD ──────────

#[test]
fn scrub_key_default_is_a_loud_error() {
    let s = Bare::default();
    let err = s
        .scrub_key("vk_1")
        .expect_err("default must error, never silently no-op");
    assert!(!err.to_string().is_empty());
}

#[test]
fn put_credential_default_is_a_loud_error() {
    let s = Bare::default();
    s.put_credential(&sample_credential())
        .expect_err("default must error: a silently-dropped credential must not look like success");
}

#[test]
fn revoke_credential_default_is_a_loud_error() {
    let s = Bare::default();
    let err = s.revoke_credential("cred_1", "leaked").expect_err(
        "default must error: an operator must never believe a leaked secret was killed",
    );
    let _ = err;
}

#[test]
fn add_denylist_default_is_a_loud_error() {
    let s = Bare::default();
    let err = s
        .add_denylist("sub_1", "compromised")
        .expect_err("default must error: a silently-accepted revocation would leave a token valid");
    let _ = err;
}

// ── Empty-list defaults: "this store has none to give" ──────────────────────────────────────────

#[test]
fn list_credentials_default_is_empty() {
    let s = Bare::default();
    assert_eq!(s.list_credentials("vk_1").unwrap(), Vec::new());
}

#[test]
fn lookup_credential_secret_default_is_none() {
    let s = Bare::default();
    assert_eq!(
        s.lookup_credential_secret("sigv4", "AKIA_TEST").unwrap(),
        None
    );
}

#[test]
fn list_credentials_since_default_is_empty() {
    let s = Bare::default();
    assert_eq!(s.list_credentials_since(0).unwrap(), Vec::new());
}

#[test]
fn list_denylist_default_is_empty() {
    let s = Bare::default();
    assert_eq!(s.list_denylist().unwrap(), Vec::<String>::new());
}

#[test]
fn list_audit_default_is_empty() {
    let s = Bare::default();
    assert_eq!(s.list_audit().unwrap(), Vec::new());
}

#[test]
fn list_plane_record_parents_default_is_empty() {
    let s = Bare::default();
    assert_eq!(
        s.list_plane_record_parents("task").unwrap(),
        Vec::<String>::new()
    );
}

// ── No-op / zero-count defaults ──────────────────────────────────────────────────────────────────

#[test]
fn purge_windows_before_default_is_zero() {
    let s = Bare::default();
    assert_eq!(s.purge_windows_before(u64::MAX).unwrap(), 0);
}

#[test]
fn purge_metering_before_default_is_zero() {
    let s = Bare::default();
    assert_eq!(s.purge_metering_before("bucket").unwrap(), 0);
}

#[test]
fn append_audit_default_is_ok_and_keeps_nothing() {
    let s = Bare::default();
    // Accepted...
    s.append_audit(&sample_audit(1)).unwrap();
    // ...and, consistently with every other plane/audit default, NOT actually retained: the
    // (unmodified) `list_audit` default still reports empty, so a caller cannot be fooled into
    // thinking this backend now has durable audit just because the write returned `Ok`.
    assert_eq!(s.list_audit().unwrap(), Vec::new());
}

#[test]
fn delete_plane_record_default_is_ok_and_idempotent() {
    let s = Bare::default();
    s.delete_plane_record("task", "t-1").unwrap();
    // Absent is a no-op: calling it again (nothing was ever there) must not error.
    s.delete_plane_record("task", "t-1").unwrap();
}

#[test]
fn redeem_plane_token_default_is_true_every_time() {
    let s = Bare::default();
    // "This store keeps no ledger" — EVERY call is a fresh "first redemption", never test-and-set,
    // which is the honest default for a backend that tracks nothing.
    assert!(s.redeem_plane_token("ask", "tok-1", 100, 50).unwrap());
    assert!(s.redeem_plane_token("ask", "tok-1", 100, 50).unwrap());
}

// ── Composed defaults: sequencing matters, not just the final `Ok`/`Err` ─────────────────────────

/// `put_key_with_credential`'s DEFAULT is sequential (`put_key` THEN `put_credential`), never the
/// reverse and never both-or-neither on a backend that hasn't overridden it for a real transaction.
/// Pins the ORDER (a mutant that swapped the two calls would still return the same `Err` here,
/// since `Bare::put_credential` is the loud-error default — but it would have left `put_key`
/// UNCALLED, which this test also checks) and that a `put_credential` failure surfaces as the
/// whole call's error rather than being swallowed.
#[test]
fn put_key_with_credential_default_calls_put_key_then_surfaces_the_credential_error() {
    let s = Bare::default();
    let key = sample_key();
    let err = s
        .put_key_with_credential(&key, &sample_credential())
        .expect_err(
            "Bare has no credential support: the default must surface put_credential's error",
        );
    let _ = err;
    // put_key ran (and its effect stuck) even though the overall call failed at the credential step.
    assert_eq!(s.put_key_calls.load(Ordering::SeqCst), 1);
    assert_eq!(s.keys.lock().unwrap().len(), 1);
    assert_eq!(s.keys.lock().unwrap()[0].id, "vk_1");
}

// ── StoreError conversions (used by every `?`-based backend at the seam) ─────────────────────────

#[test]
fn store_error_from_string_and_str_preserve_the_message() {
    let from_string: StoreError = "disk full".to_string().into();
    assert_eq!(from_string.to_string(), "store error: disk full");

    let from_str: StoreError = "disk full".into();
    assert_eq!(from_str.to_string(), "store error: disk full");
}

// ── `PlaneRequestCtx` — the request-scoped governance-key carrier ────────────────────────────────

#[test]
fn plane_request_ctx_default_is_ungoverned() {
    let ctx = PlaneRequestCtx::default();
    assert!(!ctx.is_governed());
    assert!(ctx.key().is_none());
}

#[test]
fn plane_request_ctx_with_key_is_governed() {
    let ctx = PlaneRequestCtx {
        key: Some(std::sync::Arc::new(sample_key())),
    };
    assert!(ctx.is_governed());
    assert_eq!(ctx.key().map(|k| k.id.as_str()), Some("vk_1"));
}

// ── The plane-record defaults NOT already covered by `store_tests.rs`'s own coverage test ────────
// (`upsert_plane_record`/`append_plane_record`/`get_plane_record`/`list_plane_records`/
// `purge_plane_records_before` are pinned there; `list_plane_record_parents`,
// `delete_plane_record`, `redeem_plane_token` were not, and are covered above.)

#[test]
fn plane_record_envelope_carries_an_arbitrary_opaque_body_through_upsert_default() {
    let s = Bare::default();
    // The default keeps nothing, but it must ACCEPT any body shape without inspecting it.
    let body = b"not json at all, on purpose".to_vec();
    s.upsert_plane_record(&PlaneRecord {
        kind: "task".into(),
        id: "t-9".into(),
        parent: None,
        seq: 0,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body,
    })
    .unwrap();
    assert_eq!(s.get_plane_record("task", "t-9").unwrap(), None);
    assert!(s
        .list_plane_records("task", &PlaneSelector::All)
        .unwrap()
        .is_empty());
}
