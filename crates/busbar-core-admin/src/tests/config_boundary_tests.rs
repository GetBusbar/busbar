// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use busbar_contract::records::{
    CredentialMeta, CredentialSecret, RecordStore, RecordStoreError, RecordStoreResult, SecretForm,
    VirtualKey,
};
use busbar_kernel::auth::AuthPrincipal;
use busbar_kernel::governance::at_rest::{self, AtRestKeys};
use busbar_kernel::state::AppHandle;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Default)]
struct RewrapStore {
    inner: MemoryStore,
    fail_listing: AtomicBool,
    deny_claim: AtomicBool,
    listings: AtomicUsize,
}
impl busbar_kernel::governance::RecordStore for RewrapStore {
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<bool> {
        if self.deny_claim.load(Ordering::SeqCst) {
            return Ok(false);
        }
        self.inner.redeem_plane_token(kind, token, expires_at, now)
    }
    fn get_plane_record(
        &self,
        kind: &str,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<Vec<u8>>> {
        self.inner.get_plane_record(kind, id)
    }
    fn upsert_plane_record(
        &self,
        record: busbar_contract::records::PlaneRecordRef<'_>,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.upsert_plane_record(record)
    }
    fn purge_plane_records_before(
        &self,
        kind: &str,
        before: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<u64> {
        self.inner.purge_plane_records_before(kind, before)
    }
    fn put_key(
        &self,
        key: &busbar_contract::records::VirtualKey,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<busbar_contract::records::VirtualKey>>
    {
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_contract::records::VirtualKey>>
    {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_kernel::governance::MeteringDelta,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_kernel::governance::MeteringRow>>
    {
        self.inner.list_metering(bucket)
    }
    fn add_denylist(
        &self,
        sub: &str,
        reason: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> busbar_kernel::governance::RecordStoreResult<Vec<String>> {
        self.inner.list_denylist()
    }

    fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        self.listings.fetch_add(1, Ordering::SeqCst);
        if self.fail_listing.load(Ordering::SeqCst) {
            return Err(RecordStoreError("planted credential listing outage".into()));
        }
        self.inner.list_credentials_since(since)
    }
    fn rewrap_credential(
        &self,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> RecordStoreResult<bool> {
        self.inner.rewrap_credential(expected, replacement)
    }
}

/// The actual reload callback owns retries: listing failure and a lost claim both leave a row
/// readable under previous, and an unchanged subsequent reload must finish the maintenance work.
#[tokio::test]
async fn unchanged_admin_reload_retries_at_rest_maintenance_after_store_recovery() {
    busbar_kernel_testkit::test_support::metrics::init();
    let _limits_lock = busbar_kernel::config::limits::LIMITS_TEST_LOCK.lock().await;
    for failure in ["listing", "claim"] {
        let (dir, config_path, providers_path) = write_reset_fixture(&format!("rewrap-{failure}"));
        let old_path = dir.join("old-at-rest.key");
        let new_path = dir.join("new-at-rest.key");
        std::fs::write(&old_path, [3_u8; 32]).unwrap();
        std::fs::write(&new_path, [4_u8; 32]).unwrap();
        let base = std::fs::read_to_string(&config_path).unwrap();
        std::fs::write(&config_path, format!("{base}\ncredentials:\n  at_rest:\n    key: {{file: {new_path:?}}}\n    previous: {{file: {old_path:?}}}\n")).unwrap();
        let store = Arc::new(RewrapStore::default());
        store
            .inner
            .put_key(&VirtualKey {
                id: "rewrap-owner".into(),
                generation_hash: "binding:rewrap-owner:0".into(),
                enabled: true,
                ..Default::default()
            })
            .unwrap();
        let meta = CredentialMeta {
            id: "rewrap-credential".into(),
            key_id: "rewrap-owner".into(),
            kind: "signed-request".into(),
            slot: 0,
            public_id: "rewrap-public".into(),
            secret_form: SecretForm::Recoverable,
            created_at: 0,
            updated_at: 0,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        };
        let old_keys = AtRestKeys::new(&[3_u8; 32], None);
        store
            .inner
            .put_credential(&CredentialSecret {
                secret: old_keys.seal(&meta, b"recoverable-test-secret").unwrap(),
                meta,
            })
            .unwrap();
        let gov = gov_with_signer(store.clone(), None);
        let overlay = TestOverlayStore::new();
        let mut app = crate::new_test_app()
            .governance(gov.clone())
            .overlay_backend(overlay.backend())
            .build();
        {
            let inner = Arc::get_mut(&mut app).unwrap();
            inner.config_path = Some(config_path);
            inner.providers_path = Some(providers_path);
        }
        let handle = Arc::new(AppHandle::new(app));
        store
            .fail_listing
            .store(failure == "listing", Ordering::SeqCst);
        store.deny_claim.store(failure == "claim", Ordering::SeqCst);
        let first = crate::v1::json::reload_config(
            State(handle.clone()),
            axum::Extension(AuthPrincipal(None)),
        )
        .await;
        assert_eq!(
            first.status(),
            StatusCode::OK,
            "{failure}: first reload commits even with maintenance debt"
        );
        let pending = store.inner.list_credentials_since(0).unwrap().remove(0);
        assert_eq!(at_rest::sealed_kid(&pending.secret), Some(old_keys.kid()));
        let current_keys = AtRestKeys::new(&[4_u8; 32], Some(&[3_u8; 32]));
        assert_eq!(
            at_rest::open(Some(&current_keys), &pending.meta, &pending.secret)
                .as_deref()
                .map(String::as_str),
            Some("recoverable-test-secret")
        );
        let calls = store.listings.load(Ordering::SeqCst);
        store.fail_listing.store(false, Ordering::SeqCst);
        store.deny_claim.store(false, Ordering::SeqCst);
        let second = crate::v1::json::reload_config(
            State(handle.clone()),
            axum::Extension(AuthPrincipal(None)),
        )
        .await;
        assert_eq!(second.status(), StatusCode::OK, "{failure}: retry reload");
        assert!(
            store.listings.load(Ordering::SeqCst) > calls,
            "{failure}: unchanged kids must still retry the Store"
        );
        let sealed = store.inner.list_credentials_since(0).unwrap().remove(0);
        assert_eq!(
            at_rest::sealed_kid(&sealed.secret),
            Some(current_keys.kid())
        );
        assert_eq!(
            at_rest::open(Some(&current_keys), &sealed.meta, &sealed.secret)
                .as_deref()
                .map(String::as_str),
            Some("recoverable-test-secret")
        );
        // A failed settings commit cannot fire the deferred maintenance closure either.
        std::fs::write(&new_path, [5_u8; 32]).unwrap();
        overlay.fail_writes(true);
        let before = handle.load();
        let calls = store.listings.load(Ordering::SeqCst);
        let rejected = crate::v1::json::put_config_settings(
            State(handle.clone()),
            axum::Extension(AuthPrincipal(None)),
            HeaderMap::new(),
            serde_json::json!({"limits": {"request_body_max_bytes": 5000123}})
                .to_string()
                .into(),
        )
        .await;
        assert!(!rejected.status().is_success());
        let rejected_body = axum::body::to_bytes(rejected.into_body(), usize::MAX)
            .await
            .unwrap();
        let rejected_text = std::str::from_utf8(&rejected_body).unwrap();
        assert!(
            rejected_text.contains("persistence to the overlay was not confirmed"),
            "{rejected_text}"
        );
        assert!(Arc::ptr_eq(&before, &handle.load()));
        // The existing setter reports whether the installed kids differed, so this checks that
        // the rejected candidate did not install key 5 without adding a key-inspection API.
        assert!(!gov.set_at_rest_keys(Some(AtRestKeys::new(&[4_u8; 32], Some(&[3_u8; 32])))));
        assert_eq!(
            store.listings.load(Ordering::SeqCst),
            calls,
            "rejected commit does not run credential maintenance"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[tokio::test]
async fn hook_register_and_replace_refuse_oversized_timeouts_without_swapping() {
    busbar_kernel_testkit::test_support::metrics::init();
    let hook =
        serde_json::from_value(serde_json::json!({"kind": "gate", "module": "test-hook"})).unwrap();
    let overlay = TestOverlayStore::new();
    let app = crate::new_test_app()
        .overlay_backend(overlay.backend())
        .hook("existing", hook)
        .build();
    let handle = Arc::new(AppHandle::new(app));
    let before = handle.load();
    let cfg = serde_json::json!({"kind": "gate", "module": "test-hook", "timeout_ms": u64::MAX});
    let register = crate::v1::json::register_hook(
        State(handle.clone()),
        axum::Extension(AuthPrincipal(None)),
        HeaderMap::new(),
        serde_json::json!({"name": "new", "config": cfg})
            .to_string()
            .into(),
    )
    .await;
    assert_eq!(register.status(), StatusCode::BAD_REQUEST);
    let put = crate::v1::json::put_hook(
        State(handle.clone()),
        axum::Extension(AuthPrincipal(None)),
        Path("existing".into()),
        HeaderMap::new(),
        serde_json::json!({"config": cfg}).to_string().into(),
    )
    .await;
    assert_eq!(put.status(), StatusCode::BAD_REQUEST);
    for response in [register, put] {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("timeout_ms") && text.contains("30 years"),
            "{text}"
        );
    }
    assert!(Arc::ptr_eq(&before, &handle.load()));
    assert!(!handle.load().hook_registry.contains_key("new"));
    assert!(overlay.backend().read_required().unwrap().is_none());
}

#[tokio::test]
async fn reload_refuses_env_policy_injection_without_publishing() {
    busbar_kernel_testkit::test_support::metrics::init();
    const VAR: &str = "BUSBAR_TEST_KC_ADMIN_POLICY_TTL";
    let _env = busbar_kernel_testkit::test_support::EnvVarGuard::capture(VAR);
    std::env::set_var(VAR, r#"90d"}, policy: {self_mint: true, default_ttl: "90d"#);
    let (dir, config_path, providers_path) = write_reset_fixture("env-policy");
    std::fs::write(&config_path, r#"{providers: {}, models: {}, store: {module: memory}, auth: {policy: {self_mint: false, max_ttl: 7d, default_ttl: "${BUSBAR_TEST_KC_ADMIN_POLICY_TTL}"}}}"#).unwrap();
    let mut app = crate::new_test_app()
        .overlay_backend(TestOverlayStore::new().backend())
        .build();
    {
        let inner = Arc::get_mut(&mut app).unwrap();
        inner.config_path = Some(config_path);
        inner.providers_path = Some(providers_path);
    }
    let handle = Arc::new(AppHandle::new(app));
    let before = handle.load();
    let response =
        crate::v1::json::reload_config(State(handle.clone()), axum::Extension(AuthPrincipal(None)))
            .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains(VAR) && text.contains("refusing to proceed"),
        "{text}"
    );
    assert!(Arc::ptr_eq(&before, &handle.load()));
    let _ = std::fs::remove_dir_all(dir);
}
