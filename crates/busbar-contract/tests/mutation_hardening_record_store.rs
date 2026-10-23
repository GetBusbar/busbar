// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MUTATION-HARDENING: `busbar_contract::records::RecordStore` contract TOTALITY.
//!
//! The trait has no default bodies (BUSBAR-1.6.0.md Part 2 #38(a)): each method's doc names the
//! answer a store WITHOUT that surface states (an error, an empty list, a no-op, a sequential
//! compose). `Bare` below writes every one of those answers down, explicitly, and this file pins
//! them: flipping `Err(..)` to `Ok(())`, or `Ok(Vec::new())` to `Ok(vec![...])`, or dropping a step
//! out of the sequential compose, produces no compile error and no other test failure.
//!
//! This is an INTEGRATION test (auto-discovered by Cargo — the crate's existing
//! convention of `#[cfg(test)] #[path = "tests/x.rs"] mod tests;` inline unit tests is left
//! untouched; no `mod` line needs to be added anywhere for this file to run). It exercises only the
//! crate's public surface (`busbar_contract::records::*`), same as any out-of-tree Store-plugin
//! author would. Moved here from `busbar-api`'s own suite when that crate retired.
//!
//! `Bare` keeps keys only; every other method states the no-support answer its trait doc names.

use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneDisposition,
    PlaneRecord, PlaneRecordRef, PlaneRequestCtx, PlaneSelector, RecordStore, RecordStoreError,
    RecordStoreResult, Retention, SecretForm, UsageDelta, UsageLedger, VirtualKey,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// The minimal `Store`: eight methods with real bodies, and every other trait method stating the
/// no-support answer its trait doc names — the same shape as `records_tests.rs`'s own
/// `PreTaskBackend` (a backend that keeps no durable plane state), extended to cover the
/// credential/audit/denylist/plane-record answers that file does not touch.
#[derive(Default)]
struct Bare {
    put_key_calls: AtomicUsize,
    keys: Mutex<Vec<VirtualKey>>,
}

impl RecordStore for Bare {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.put_key_calls.fetch_add(1, Ordering::SeqCst);
        self.keys.lock().unwrap().push(key.clone());
        Ok(())
    }
    fn get_key(&self, _id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        Ok(None)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        Ok(Vec::new())
    }
    fn delete_key(&self, _id: &str) -> RecordStoreResult<()> {
        Ok(())
    }
    fn get_usage(&self, _bucket_id: &str, _window_start: u64) -> RecordStoreResult<UsageLedger> {
        Ok(UsageLedger::default())
    }
    fn put_usage(
        &self,
        _bucket_id: &str,
        _window_start: u64,
        _ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        Ok(())
    }
    fn add_metering(&self, _delta: &MeteringDelta) -> RecordStoreResult<()> {
        Ok(())
    }
    fn list_metering(&self, _bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        Ok(Vec::new())
    }
    fn scrub_key(&self, _id: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support scrub_key".to_string(),
        ))
    }
    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        Ok(RecordStore::list_keys(self)?
            .into_iter()
            .filter(|k| k.revision == 0 || k.revision > since)
            .collect())
    }
    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        let mut cur = RecordStore::get_usage(self, bucket_id, window_start)?;
        cur.apply_delta(delta);
        RecordStore::put_usage(self, bucket_id, window_start, &cur)
    }
    fn purge_windows_before(&self, _before: u64) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn purge_metering_before(&self, _bucket: &str) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn put_credential(&self, _secret: &CredentialSecret) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support row-looked-up credentials".to_string(),
        ))
    }
    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        RecordStore::put_key(self, key)?;
        RecordStore::put_credential(self, secret)?;
        Ok(())
    }
    fn list_credentials(&self, _key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        Ok(Vec::new())
    }
    fn lookup_credential_secret(
        &self,
        _kind: &str,
        _public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>> {
        Ok(None)
    }
    fn revoke_credential(&self, _id: &str, _reason: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support credential revocation".to_string(),
        ))
    }
    fn list_credentials_since(&self, _since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        Ok(Vec::new())
    }
    fn append_audit(&self, _entry: &AuditRecord) -> RecordStoreResult<()> {
        Ok(())
    }
    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        Ok(Vec::new())
    }
    fn add_denylist(&self, _sub: &str, _reason: &str) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "this Store does not support the revocation denylist".to_string(),
        ))
    }
    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        let mut all = RecordStore::list_audit(self)?;
        let limit = limit as usize;
        if all.len() > limit {
            all.drain(0..all.len() - limit);
        }
        Ok(all)
    }
    fn upsert_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        Ok(())
    }
    fn get_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        Ok(None)
    }
    fn append_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        Ok(())
    }
    fn list_plane_records(
        &self,
        _kind: &str,
        _selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }
    fn list_plane_record_parents(&self, _kind: &str) -> RecordStoreResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn purge_plane_records_before(&self, _kind: &str, _before: u64) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        match retention {
            Retention::Age => RecordStore::purge_plane_records_before(self, kind, before),
            Retention::TerminalOnly => Ok(0),
        }
    }
    fn delete_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<()> {
        Ok(())
    }
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(false)
    }
    fn plane_token_live(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(false)
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
            kind: "generic".to_string(),
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

// ── Error-path answers: a backend WITHOUT the surface must fail LOUD ─────────────────────────────

#[test]
fn scrub_key_default_is_a_loud_error() {
    let s = Bare::default();
    let err = s
        .scrub_key("vk_1")
        .expect_err("the no-support answer must error, never silently no-op");
    assert!(!err.to_string().is_empty());
}

#[test]
fn put_credential_default_is_a_loud_error() {
    let s = Bare::default();
    s.put_credential(&sample_credential())
        .expect_err("the no-support answer must error: a silently-dropped credential must not look like success");
}

#[test]
fn revoke_credential_default_is_a_loud_error() {
    let s = Bare::default();
    let err = s.revoke_credential("cred_1", "leaked").expect_err(
        "the no-support answer must error: an operator must never believe a leaked secret was killed",
    );
    let _ = err;
}

#[test]
fn add_denylist_default_is_a_loud_error() {
    let s = Bare::default();
    let err = s
        .add_denylist("sub_1", "compromised")
        .expect_err("the no-support answer must error: a silently-accepted revocation would leave a token valid");
    let _ = err;
}

// ── Empty-list answers: "this store has none to give" ───────────────────────────────────────────

#[test]
fn list_credentials_default_is_empty() {
    let s = Bare::default();
    assert_eq!(s.list_credentials("vk_1").unwrap(), Vec::new());
}

#[test]
fn lookup_credential_secret_default_is_none() {
    let s = Bare::default();
    assert_eq!(
        s.lookup_credential_secret("generic", "AKIA_TEST").unwrap(),
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

// ── No-op / zero-count answers ───────────────────────────────────────────────────────────────────

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
    // ...and, consistently with every other plane/audit no-support answer, NOT actually retained:
    // `list_audit` still reports empty, so a caller cannot be fooled into
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
fn redeem_plane_token_default_is_fail_closed() {
    let s = Bare::default();
    // A store that keeps no ledger cannot attest that a call is the first redemption of a
    // single-use token, so it refuses every redemption rather than granting one on
    // every call — the fail-closed posture, not "this store keeps no ledger".
    assert!(!s.redeem_plane_token("ask", "tok-1", 100, 50).unwrap());
    assert!(!s.redeem_plane_token("ask", "tok-1", 100, 50).unwrap());
}

// ── Composed answers: sequencing matters, not just the final `Ok`/`Err` ──────────────────────────

/// `put_key_with_credential`'s no-transaction answer is sequential (`put_key` THEN `put_credential`),
/// never the reverse, on a backend without a real transaction.
/// Pins the ORDER (a mutant that swapped the two calls would still return the same `Err` here,
/// since `Bare::put_credential` is the loud-error answer — but it would have left `put_key`
/// UNCALLED, which this test also checks) and that a `put_credential` failure surfaces as the
/// whole call's error rather than being swallowed.
#[test]
fn put_key_with_credential_default_calls_put_key_then_surfaces_the_credential_error() {
    let s = Bare::default();
    let key = sample_key();
    let err = s
        .put_key_with_credential(&key, &sample_credential())
        .expect_err("Bare has no credential support: the call must surface put_credential's error");
    let _ = err;
    // put_key ran (and its effect stuck) even though the overall call failed at the credential step.
    assert_eq!(s.put_key_calls.load(Ordering::SeqCst), 1);
    assert_eq!(s.keys.lock().unwrap().len(), 1);
    assert_eq!(s.keys.lock().unwrap()[0].id, "vk_1");
}

// ── StoreError conversions (used by every `?`-based backend at the seam) ─────────────────────────

#[test]
fn store_error_from_string_and_str_preserve_the_message() {
    let from_string: RecordStoreError = "disk full".to_string().into();
    assert_eq!(from_string.to_string(), "store error: disk full");

    let from_str: RecordStoreError = "disk full".into();
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

// ── The plane-record answers NOT already covered by `records_tests.rs`'s own coverage test ──────
// (`upsert_plane_record`/`append_plane_record`/`get_plane_record`/`list_plane_records`/
// `purge_plane_records_before` are pinned there; `list_plane_record_parents`,
// `delete_plane_record`, `redeem_plane_token` were not, and are covered above.)

#[test]
fn plane_record_envelope_carries_an_arbitrary_opaque_body_through_upsert_default() {
    let s = Bare::default();
    // The no-support answer keeps nothing, but it must ACCEPT any body shape without inspecting it.
    let body = b"not json at all, on purpose".to_vec();
    s.upsert_plane_record(
        PlaneRecord {
            kind: "task".into(),
            id: "t-9".into(),
            parent: None,
            seq: 0,
            ts: 1,
            disposition: PlaneDisposition::Active,
            body,
        }
        .view(),
    )
    .unwrap();
    assert_eq!(s.get_plane_record("task", "t-9").unwrap(), None);
    assert!(s
        .list_plane_records("task", &PlaneSelector::All)
        .unwrap()
        .is_empty());
}
