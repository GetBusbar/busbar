// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::records::*;
use busbar_kernel::governance::NewKeySpec;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

struct GatedKeyStore {
    inner: Arc<dyn busbar_kernel::governance::RecordStore>,
    entered: tokio::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    landed: tokio::sync::mpsc::Sender<String>,
    fired: std::sync::atomic::AtomicBool,
}
impl busbar_kernel::governance::RecordStore for GatedKeyStore {
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<bool> {
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
        if self.fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return self.inner.put_key(key);
        }

        let _ = self.entered.try_send(());
        if let Some(rx) = self
            .release
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = rx.recv_timeout(std::time::Duration::from_secs(30));
        }
        let out = self.inner.put_key(key);
        if out.is_ok() {
            let _ = self.landed.try_send(key.id.clone());
        }
        out
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
    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        self.inner.list_keys_since(since)
    }
    fn apply_usage_correction(
        &self,
        request: &correction::Request,
    ) -> RecordStoreResult<correction::Decision> {
        self.inner.apply_usage_correction(request)
    }
    fn supports_usage_correction(&self) -> bool {
        self.inner.supports_usage_correction()
    }
    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        self.inner.add_usage(bucket_id, window_start, delta)
    }
    fn add_usage_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> RecordStoreResult<()> {
        self.inner.add_usage_batch_deduped(op, cells)
    }
    fn supports_usage_batch_deduped(&self) -> bool {
        self.inner.supports_usage_batch_deduped()
    }
    fn supports_metering_batch_deduped(&self) -> bool {
        self.inner.supports_metering_batch_deduped()
    }
    fn add_metering_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        deltas: &[MeteringDelta],
    ) -> RecordStoreResult<()> {
        self.inner.add_metering_batch_deduped(op, deltas)
    }
    fn put_credential(&self, secret: &CredentialSecret) -> RecordStoreResult<()> {
        self.inner.put_credential(secret)
    }
    fn rewrap_credential(
        &self,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> RecordStoreResult<bool> {
        self.inner.rewrap_credential(expected, replacement)
    }
    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        self.inner.put_key_with_credential(key, secret)
    }
    fn list_credentials(&self, key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        self.inner.list_credentials(key_id)
    }
    fn revoke_credential(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        self.inner.revoke_credential(id, reason)
    }
    fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        self.inner.list_credentials_since(since)
    }
    fn append_audit(&self, entry: &AuditRecord) -> RecordStoreResult<()> {
        self.inner.append_audit(entry)
    }
    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        self.inner.list_audit()
    }
    fn add_denylist(&self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        self.inner.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        self.inner.list_denylist()
    }
    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        self.inner.list_audit_tail(limit)
    }
    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.inner.append_plane_record(record)
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        self.inner.list_plane_records(kind, selector)
    }
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        self.inner.list_plane_record_parents(kind)
    }
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        self.inner.purge_plane_records(kind, before, retention)
    }
    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        self.inner.delete_plane_record(kind, id)
    }
    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        self.inner.plane_token_live(kind, token, expires_at, now)
    }
}

struct SlowNthPutKeyStore {
    inner: Arc<dyn busbar_kernel::governance::RecordStore>,
    delay: std::time::Duration,
    calls: std::sync::atomic::AtomicUsize,
    slow_on_call: usize,
}
impl busbar_kernel::governance::RecordStore for SlowNthPutKeyStore {
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<bool> {
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
        let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == self.slow_on_call {
            std::thread::sleep(self.delay);
        }
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
    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        self.inner.list_keys_since(since)
    }
    fn apply_usage_correction(
        &self,
        request: &correction::Request,
    ) -> RecordStoreResult<correction::Decision> {
        self.inner.apply_usage_correction(request)
    }
    fn supports_usage_correction(&self) -> bool {
        self.inner.supports_usage_correction()
    }
    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        self.inner.add_usage(bucket_id, window_start, delta)
    }
    fn add_usage_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> RecordStoreResult<()> {
        self.inner.add_usage_batch_deduped(op, cells)
    }
    fn supports_usage_batch_deduped(&self) -> bool {
        self.inner.supports_usage_batch_deduped()
    }
    fn supports_metering_batch_deduped(&self) -> bool {
        self.inner.supports_metering_batch_deduped()
    }
    fn add_metering_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        deltas: &[MeteringDelta],
    ) -> RecordStoreResult<()> {
        self.inner.add_metering_batch_deduped(op, deltas)
    }
    fn put_credential(&self, secret: &CredentialSecret) -> RecordStoreResult<()> {
        self.inner.put_credential(secret)
    }
    fn rewrap_credential(
        &self,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> RecordStoreResult<bool> {
        self.inner.rewrap_credential(expected, replacement)
    }
    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        self.inner.put_key_with_credential(key, secret)
    }
    fn list_credentials(&self, key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        self.inner.list_credentials(key_id)
    }
    fn revoke_credential(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        self.inner.revoke_credential(id, reason)
    }
    fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        self.inner.list_credentials_since(since)
    }
    fn append_audit(&self, entry: &AuditRecord) -> RecordStoreResult<()> {
        self.inner.append_audit(entry)
    }
    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        self.inner.list_audit()
    }
    fn add_denylist(&self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        self.inner.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        self.inner.list_denylist()
    }
    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        self.inner.list_audit_tail(limit)
    }
    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.inner.append_plane_record(record)
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        self.inner.list_plane_records(kind, selector)
    }
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        self.inner.list_plane_record_parents(kind)
    }
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        self.inner.purge_plane_records(kind, before, retention)
    }
    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        self.inner.delete_plane_record(kind, id)
    }
    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        self.inner.plane_token_live(kind, token, expires_at, now)
    }
}

struct BarrierStore {
    inner: Arc<dyn RecordStore>,
    armed: std::sync::atomic::AtomicBool,
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl busbar_kernel::governance::RecordStore for BarrierStore {
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<bool> {
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
        key: &busbar_kernel::governance::VirtualKey,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            let _ = self.entered.send(());

            let _ = self
                .release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the exact parked Store mutation must receive its explicit release");
        }
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<busbar_kernel::governance::VirtualKey>>
    {
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_kernel::governance::VirtualKey>>
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
    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        self.inner.list_keys_since(since)
    }
    fn apply_usage_correction(
        &self,
        request: &correction::Request,
    ) -> RecordStoreResult<correction::Decision> {
        self.inner.apply_usage_correction(request)
    }
    fn supports_usage_correction(&self) -> bool {
        self.inner.supports_usage_correction()
    }
    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        self.inner.add_usage(bucket_id, window_start, delta)
    }
    fn add_usage_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> RecordStoreResult<()> {
        self.inner.add_usage_batch_deduped(op, cells)
    }
    fn supports_usage_batch_deduped(&self) -> bool {
        self.inner.supports_usage_batch_deduped()
    }
    fn supports_metering_batch_deduped(&self) -> bool {
        self.inner.supports_metering_batch_deduped()
    }
    fn add_metering_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        deltas: &[MeteringDelta],
    ) -> RecordStoreResult<()> {
        self.inner.add_metering_batch_deduped(op, deltas)
    }
    fn put_credential(&self, secret: &CredentialSecret) -> RecordStoreResult<()> {
        self.inner.put_credential(secret)
    }
    fn rewrap_credential(
        &self,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> RecordStoreResult<bool> {
        self.inner.rewrap_credential(expected, replacement)
    }
    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        self.inner.put_key_with_credential(key, secret)
    }
    fn list_credentials(&self, key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        self.inner.list_credentials(key_id)
    }
    fn revoke_credential(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        self.inner.revoke_credential(id, reason)
    }
    fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        self.inner.list_credentials_since(since)
    }
    fn append_audit(&self, entry: &AuditRecord) -> RecordStoreResult<()> {
        self.inner.append_audit(entry)
    }
    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        self.inner.list_audit()
    }
    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        self.inner.list_audit_tail(limit)
    }
    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        self.inner.append_plane_record(record)
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        self.inner.list_plane_records(kind, selector)
    }
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        self.inner.list_plane_record_parents(kind)
    }
    fn purge_plane_records(
        &self,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        self.inner.purge_plane_records(kind, before, retention)
    }
    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        self.inner.delete_plane_record(kind, id)
    }
    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        self.inner.plane_token_live(kind, token, expires_at, now)
    }
}

#[tokio::test]
async fn an_idempotency_key_survives_a_client_disconnect_mid_mint() {
    const CHILD: &str = "BUSBAR_ADMIN_GATED_0A341CDC7FBA";
    const WITNESS: &str =
        "actual root case an_idempotency_key_survives_a_client_disconnect_mid_mint completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its exact test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root case"),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root child failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "the actual-root child timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory =
        plugins::scratch("an_idempotency_key_survives_a_client_disconnect_mid_mint-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let at_rest_key = directory.join("at-rest-key");
    std::fs::write(&at_rest_key, hex::encode([3u8; 32])).expect("write original at-rest key input");
    document["credentials"]["at_rest"]["key"]["file"] = serde_json::json!(at_rest_key);
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let inner = anchor.records.clone();
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (landed_tx, mut landed_rx) = tokio::sync::mpsc::channel::<String>(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let gated_store: Arc<dyn busbar_kernel::governance::RecordStore> = Arc::new(GatedKeyStore {
        inner,
        entered: entered_tx,
        release: std::sync::Mutex::new(Some(release_rx)),
        landed: landed_tx,
        fired: std::sync::atomic::AtomicBool::new(false),
    });
    let anchor = busbar_contract::store_calls::OpenedStore {
        records: gated_store.clone(),
        calls: anchor.calls,
    };
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let keys_url = format!("http://{addr}/api/v1/admin/keys");
    let post = |client: &reqwest::Client, url: &str| {
        client
            .post(url)
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .header("idempotency-key", "dc-1")
            .body(r#"{"name": "disconnector"}"#)
            .send()
    };
    let count_disconnector = |v: &serde_json::Value| -> usize {
        v["items"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|k| k["name"].as_str() == Some("disconnector"))
                    .count()
            })
            .unwrap_or(0)
    };

    let doomed_url = keys_url.clone();
    let doomed = tokio::spawn(async move {
        let client = reqwest::Client::new();
        post(&client, &doomed_url).await
    });

    const RENDEZVOUS_BACKSTOP: std::time::Duration = std::time::Duration::from_secs(60);
    tokio::time::timeout(RENDEZVOUS_BACKSTOP, entered_rx.recv())
        .await
        .expect(
            "waited 60s for the mint to enter the store's put_key and it never did. The request \
             did not get as far as the blocking mint, so there is no mid-mint window to disconnect \
             inside and this test would be asserting nothing.",
        )
        .expect("the gated store was dropped before the mint entered put_key");

    doomed.abort();
    let joined = doomed.await;
    assert!(
        joined.as_ref().is_err_and(|e| e.is_cancelled()),
        "the doomed request must have been cancelled mid-flight; it instead completed, which means \
         the store gate did not hold the mint open and there was no mid-mint disconnect: {:?}",
        joined.map(|r| r.map(|resp| resp.status()))
    );

    let probe = reqwest::Client::new();
    let mid: serde_json::Value = probe
        .get(&keys_url)
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        count_disconnector(&mid),
        0,
        "the mint must still be parked in put_key at this point, so no key should exist yet; \
         found one already committed, so the disconnect was not mid-mint: {mid:?}"
    );

    release_tx
        .send(())
        .expect("the parked mint hung up on its release channel");
    let committed_id = tokio::time::timeout(RENDEZVOUS_BACKSTOP, landed_rx.recv())
        .await
        .expect(
            "waited 60s after releasing the parked mint and its write never committed. A mint \
             whose client disconnected must still run to completion on the uncancellable blocking \
             task; observed instead: released, then silence.",
        )
        .expect("the gated store was dropped before the released mint could commit");

    let normal_client = reqwest::Client::new();
    let retry = post(&normal_client, &keys_url).await.unwrap();

    assert!(
        matches!(retry.status().as_u16(), 201 | 409),
        "a retry must replay the first answer or refuse the held claim: {}",
        retry.status()
    );
    if retry.status().as_u16() == 201 {
        let replay: serde_json::Value = retry.json().await.unwrap();
        assert_eq!(
            replay["id"].as_str(),
            Some(committed_id.as_str()),
            "a cached 201 must name the first committed key, never a second mint"
        );
    }

    let keys: serde_json::Value = normal_client
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = keys["items"].as_array().unwrap();
    let disconnector_count = items
        .iter()
        .filter(|k| k["name"].as_str() == Some("disconnector"))
        .count();
    assert_eq!(
        disconnector_count, 1,
        "exactly one key must exist after a client disconnect mid-mint + retry, got: {items:?}"
    );
    assert!(
        items
            .iter()
            .any(|key| key["id"].as_str() == Some(committed_id.as_str())),
        "the one retained key must be the first committed key"
    );

    handle.abort();
    handle.abort();
    let _ = handle.await;
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_rotate_idempotency_in_flight_is_not_replayed_as_complete() {
    const CHILD: &str = "BUSBAR_ADMIN_GATED_4D8BB99A6A3E";
    const WITNESS: &str =
        "actual root case test_admin_v1_rotate_idempotency_in_flight_is_not_replayed_as_complete completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its exact test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root case"),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root child failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "the actual-root child timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch(
        "test_admin_v1_rotate_idempotency_in_flight_is_not_replayed_as_complete-actual-store",
    );
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let at_rest_key = directory.join("at-rest-key");
    std::fs::write(&at_rest_key, hex::encode([3u8; 32])).expect("write original at-rest key input");
    document["credentials"]["at_rest"]["key"]["file"] = serde_json::json!(at_rest_key);
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let inner = anchor.records.clone();

    let slow_store: Arc<dyn busbar_kernel::governance::RecordStore> =
        Arc::new(SlowNthPutKeyStore {
            inner,
            delay: std::time::Duration::from_millis(500),
            calls: std::sync::atomic::AtomicUsize::new(0),
            slow_on_call: 1,
        });
    let anchor = busbar_contract::store_calls::OpenedStore {
        records: slow_store.clone(),
        calls: anchor.calls,
    };
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let keys_url = format!("http://{addr}/api/v1/admin/keys");

    let created: serde_json::Value = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "r"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    let rotate_url = format!("{keys_url}/{id}/rotate");

    let first_client = client.clone();
    let first_url = rotate_url.clone();
    let first = tokio::spawn(async move {
        first_client
            .post(&first_url)
            .header("x-admin-token", "admintok")
            .header("idempotency-key", "rot-inflight")
            .send()
            .await
            .unwrap()
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let second = client
        .post(&rotate_url)
        .header("x-admin-token", "admintok")
        .header("idempotency-key", "rot-inflight")
        .send()
        .await
        .unwrap();
    assert_eq!(
        second.status().as_u16(),
        409,
        "a concurrent same-key rotate while the first is still landing must be refused as \
         already-in-flight, not replayed as a completed response: {}",
        second.text().await.unwrap_or_default()
    );

    let first = first.await.unwrap();
    assert_eq!(
        first.status().as_u16(),
        200,
        "the reserving (first) rotation itself must still succeed"
    );

    handle.abort();
    handle.abort();
    let _ = handle.await;
    println!("{WITNESS}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_patch_interleaved_with_delete_never_resurrects_key() {
    const CHILD: &str = "BUSBAR_ADMIN_GATED_8F35AC2C41FD";
    const WITNESS: &str =
        "actual root case test_patch_interleaved_with_delete_never_resurrects_key completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its exact test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root case"),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root child failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "the actual-root child timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory =
        plugins::scratch("test_patch_interleaved_with_delete_never_resurrects_key-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let at_rest_key = directory.join("at-rest-key");
    std::fs::write(&at_rest_key, hex::encode([3u8; 32])).expect("write original at-rest key input");
    document["credentials"]["at_rest"]["key"]["file"] = serde_json::json!(at_rest_key);
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: anchor.records.clone(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let anchor = busbar_contract::store_calls::OpenedStore {
        records: store.clone(),
        calls: anchor.calls,
    };
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let gov = app
        .governance
        .as_ref()
        .expect("the actual root opened governance")
        .clone();
    let (key, _secret) = gov
        .mint_signed(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            0,
        )
        .unwrap();
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

    let patch_url = key_url.clone();
    let patch_task = tokio::spawn(async move {
        reqwest::Client::new()
            .patch(&patch_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": false}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    tokio::task::spawn_blocking(move || {
        entered_rx.recv_timeout(std::time::Duration::from_secs(30))
    })
    .await
    .unwrap()
    .expect("PATCH must reach the instrumented put_key");

    let delete_url = key_url.clone();
    let delete_task = tokio::spawn(async move {
        reqwest::Client::new()
            .delete(&delete_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    release_tx.send(()).unwrap();
    let _ = patch_task.await.unwrap();
    let _ = delete_task.await.unwrap();

    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        listed["items"].as_array().unwrap().len(),
        0,
        "a PATCH must never resurrect a key a concurrent DELETE revoked: {listed}"
    );
    handle.abort();
    handle.abort();
    let _ = handle.await;
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_rotate_interleaved_with_delete_never_resurrects_key() {
    const CHILD: &str = "BUSBAR_ADMIN_GATED_0DF8FCDDAA76";
    const WITNESS: &str =
        "actual root case test_rotate_interleaved_with_delete_never_resurrects_key completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its exact test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root case"),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root child failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "the actual-root child timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory =
        plugins::scratch("test_rotate_interleaved_with_delete_never_resurrects_key-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let at_rest_key = directory.join("at-rest-key");
    std::fs::write(&at_rest_key, hex::encode([3u8; 32])).expect("write original at-rest key input");
    document["credentials"]["at_rest"]["key"]["file"] = serde_json::json!(at_rest_key);
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: anchor.records.clone(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let anchor = busbar_contract::store_calls::OpenedStore {
        records: store.clone(),
        calls: anchor.calls,
    };
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let gov = app
        .governance
        .as_ref()
        .expect("the actual root opened governance")
        .clone();
    let (key, _secret) = gov
        .mint_signed(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            0,
        )
        .unwrap();
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

    let rotate_url = format!("http://{addr}/api/v1/admin/keys/{}/rotate", key.id);
    let rotate_task = tokio::spawn(async move {
        reqwest::Client::new()
            .post(&rotate_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    tokio::task::spawn_blocking(move || {
        entered_rx.recv_timeout(std::time::Duration::from_secs(30))
    })
    .await
    .unwrap()
    .expect("ROTATE must reach the instrumented put_key");

    let delete_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);
    let delete_task = tokio::spawn(async move {
        reqwest::Client::new()
            .delete(&delete_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    release_tx.send(()).unwrap();
    let _ = rotate_task.await.unwrap();
    let _ = delete_task.await.unwrap();

    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        listed["items"].as_array().unwrap().len(),
        0,
        "rotate must never resurrect a key a concurrent DELETE revoked: {listed}"
    );
    handle.abort();
    handle.abort();
    let _ = handle.await;
    println!("{WITNESS}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cancelled_patch_keeps_gate_held_for_full_store_mutation() {
    const CHILD: &str = "BUSBAR_ADMIN_GATED_BD958E2FBD26";
    const WITNESS: &str =
        "actual root case test_cancelled_patch_keeps_gate_held_for_full_store_mutation completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its exact test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root case"),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root child failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "the actual-root child timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch(
        "test_cancelled_patch_keeps_gate_held_for_full_store_mutation-actual-store",
    );
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let at_rest_key = directory.join("at-rest-key");
    std::fs::write(&at_rest_key, hex::encode([3u8; 32])).expect("write original at-rest key input");
    document["credentials"]["at_rest"]["key"]["file"] = serde_json::json!(at_rest_key);
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: anchor.records.clone(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let anchor = busbar_contract::store_calls::OpenedStore {
        records: store.clone(),
        calls: anchor.calls,
    };
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let gov = app
        .governance
        .as_ref()
        .expect("the actual root opened governance")
        .clone();
    let (key, _secret) = gov
        .mint_signed(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            0,
        )
        .unwrap();
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

    let patch_url = key_url.clone();
    let patch_task = tokio::spawn(async move {
        let _ = reqwest::Client::new()
            .patch(&patch_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": false}))
            .send()
            .await;
    });

    tokio::task::spawn_blocking(move || {
        entered_rx.recv_timeout(std::time::Duration::from_secs(30))
    })
    .await
    .unwrap()
    .expect("PATCH must reach the instrumented put_key");

    patch_task.abort();
    let _ = patch_task.await;

    let delete_url = key_url.clone();
    let delete_task = tokio::spawn(async move {
        reqwest::Client::new()
            .delete(&delete_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
    while std::time::Instant::now() < deadline {
        assert!(
            !delete_task.is_finished(),
            "a cancelled PATCH must keep the EXISTENCE_GATE held for its full blocking mutation; \
             the DELETE must remain blocked on the gate (old async-guard code releases it on \
             cancel)"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    release_tx.send(()).unwrap();
    let del_status = delete_task.await.unwrap();

    assert_eq!(
        del_status, 204,
        "the DELETE runs after the gate frees and revokes the (now-present) key"
    );
    handle.abort();
    handle.abort();
    let _ = handle.await;
    println!("{WITNESS}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delete_of_another_key_is_not_held_behind_a_patch_parked_in_the_store() {
    const CHILD: &str = "BUSBAR_ADMIN_GATED_950ADA274970";
    const WITNESS: &str =
        "actual root case a_delete_of_another_key_is_not_held_behind_a_patch_parked_in_the_store completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its exact test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root case"),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root child failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "the actual-root child timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch(
        "a_delete_of_another_key_is_not_held_behind_a_patch_parked_in_the_store-actual-store",
    );
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let at_rest_key = directory.join("at-rest-key");
    std::fs::write(&at_rest_key, hex::encode([3u8; 32])).expect("write original at-rest key input");
    document["credentials"]["at_rest"]["key"]["file"] = serde_json::json!(at_rest_key);
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: anchor.records.clone(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let anchor = busbar_contract::store_calls::OpenedStore {
        records: store.clone(),
        calls: anchor.calls,
    };
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
    .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let gov = app
        .governance
        .as_ref()
        .expect("the actual root opened governance")
        .clone();
    let mint = |name: &str| {
        gov.mint_signed(
            NewKeySpec {
                name: name.to_string(),
                ..Default::default()
            },
            2_000_000_000,
            0,
        )
        .unwrap()
        .0
    };
    let (parked_key, other_key) = (mint("parked"), mint("other"));
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let url = |id: &str| format!("http://{addr}/api/v1/admin/keys/{id}");

    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let patch_url = url(&parked_key.id);
    let patch_task = tokio::spawn(async move {
        reqwest::Client::new()
            .patch(&patch_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": false}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });
    tokio::task::spawn_blocking(move || {
        entered_rx.recv_timeout(std::time::Duration::from_secs(10))
    })
    .await
    .unwrap()
    .expect("the PATCH reached the instrumented put_key");

    let delete = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        reqwest::Client::new()
            .delete(url(&other_key.id))
            .header("x-admin-token", "admintok")
            .send(),
    )
    .await;
    release_tx.send(()).unwrap();
    let patch_status = patch_task.await.unwrap();
    let delete_status = delete
        .expect("a DELETE of another key waited on a PATCH parked in the store")
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(delete_status, 204);
    assert_eq!(patch_status, 200);
    handle.abort();
    handle.abort();
    let _ = handle.await;
    println!("{WITNESS}");
}
