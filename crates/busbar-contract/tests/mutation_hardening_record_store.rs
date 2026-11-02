// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MUTATION-HARDENING: `busbar_contract::records::RecordStore` contract TOTALITY.

use busbar_contract::records::{
    CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneDisposition, PlaneRecord,
    PlaneRequestCtx, PlaneSelector, RecordStore, RecordStoreError, RecordStoreResult, SecretForm,
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

#[test]
fn list_credentials_default_is_empty() {
    let s = Bare::default();
    assert_eq!(s.list_credentials("vk_1").unwrap(), Vec::new());
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

#[test]
fn delete_plane_record_default_is_ok_and_idempotent() {
    let s = Bare::default();
    s.delete_plane_record("task", "t-1").unwrap();

    s.delete_plane_record("task", "t-1").unwrap();
}

#[test]
fn redeem_plane_token_default_is_fail_closed() {
    let s = Bare::default();

    assert!(!s.redeem_plane_token("ask", "tok-1", 100, 50).unwrap());
    assert!(!s.redeem_plane_token("ask", "tok-1", 100, 50).unwrap());
}

/// `put_key_with_credential`'s DEFAULT is sequential (`put_key` THEN `put_credential`), never the

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

    assert_eq!(s.put_key_calls.load(Ordering::SeqCst), 1);
    assert_eq!(s.keys.lock().unwrap().len(), 1);
    assert_eq!(s.keys.lock().unwrap()[0].id, "vk_1");
}

#[test]
fn store_error_from_string_and_str_preserve_the_message() {
    let from_string: RecordStoreError = "disk full".to_string().into();
    assert_eq!(from_string.to_string(), "store error: disk full");

    let from_str: RecordStoreError = "disk full".into();
    assert_eq!(from_str.to_string(), "store error: disk full");
}

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

#[test]
fn plane_record_envelope_carries_an_arbitrary_opaque_body_through_upsert_default() {
    let s = Bare::default();

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
