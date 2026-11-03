use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

use busbar_contract::abi::sdk::store::conditional::{Decision, Mutation, Request};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStore, UsageDelta, VirtualKey,
};
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};

use crate::root::loader::store_v3::LoadedStore;

type ScanProbe = Arc<Mutex<Option<Arc<dyn Fn() + Send + Sync>>>>;
type PutProbe = Arc<Mutex<Option<Arc<dyn Fn() -> Option<StoreFailure> + Send + Sync>>>>;
type TransactionProbe =
    Arc<Mutex<Option<Arc<dyn Fn(&Request) -> Option<StoreFailure> + Send + Sync>>>>;

#[derive(Clone)]
pub(crate) struct RecordSlots {
    inner: Arc<LoadedStore>,
    refusing: Arc<AtomicBool>,
    unreadable: Arc<AtomicBool>,
    budget: Arc<AtomicUsize>,
    puts: Arc<AtomicUsize>,
    observed_transactions: Arc<Mutex<HashSet<[u8; 16]>>>,
    probe: ScanProbe,
    put_probe: PutProbe,
    lost_acks: Arc<AtomicBool>,
    transaction_acks_lost: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    parked: Arc<Mutex<Vec<Waker>>>,
    transaction_probe: TransactionProbe,
}

impl Default for RecordSlots {
    fn default() -> Self {
        Self {
            inner: crate::root::real_store::store(),
            refusing: Arc::default(),
            unreadable: Arc::default(),
            budget: Arc::default(),
            puts: Arc::default(),
            observed_transactions: Arc::default(),
            probe: Arc::default(),
            put_probe: Arc::default(),
            lost_acks: Arc::default(),
            transaction_acks_lost: Arc::default(),
            paused: Arc::default(),
            parked: Arc::default(),
            transaction_probe: Arc::default(),
        }
    }
}

impl RecordSlots {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn calls(&self) -> Arc<dyn StoreCalls> {
        Arc::new(self.clone())
    }

    pub(crate) fn records(&self) -> Arc<dyn RecordStore> {
        self.inner.clone()
    }

    /// Land a transaction through the actual Store from an injected reply-boundary probe.
    pub(crate) fn apply_transaction(&self, request: &Request) -> Decision {
        completed(self.inner.record_transaction(request))
            .expect("the actual Store answers the injected transaction")
    }

    pub(crate) fn on_transaction(
        &self,
        probe: impl Fn(&Request) -> Option<StoreFailure> + Send + Sync + 'static,
    ) {
        *self
            .transaction_probe
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(probe));
    }

    pub(crate) fn pause(&self, paused: bool) {
        self.paused.store(paused, Ordering::Release);
        if !paused {
            let parked =
                std::mem::take(&mut *self.parked.lock().unwrap_or_else(|p| p.into_inner()));
            for waker in parked {
                waker.wake();
            }
        }
    }

    pub(crate) fn waiting(&self) -> usize {
        self.parked.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    async fn ready(&self) {
        std::future::poll_fn(|cx| {
            if !self.paused.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            let waker = cx.waker().clone();
            self.parked
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(waker);
            if self.paused.load(Ordering::Acquire) {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
    }

    pub(crate) fn refuse(&self, refusing: bool) {
        self.budget.store(0, Ordering::Release);
        self.refusing.store(refusing, Ordering::Release);
    }

    pub(crate) fn fail_reads(&self, failing: bool) {
        self.unreadable.store(failing, Ordering::Release);
    }

    pub(crate) fn on_scan(&self, probe: impl Fn() + Send + Sync + 'static) {
        *self.probe.lock().unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(probe));
    }

    pub(crate) fn on_put(&self, probe: impl Fn() -> Option<StoreFailure> + Send + Sync + 'static) {
        *self.put_probe.lock().unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(probe));
    }

    pub(crate) fn take_then_refuse(&self, n: usize) {
        self.budget.store(n.saturating_add(1), Ordering::Release);
    }

    fn refuses_put(&self) -> bool {
        self.refusing.load(Ordering::Acquire)
            || self
                .budget
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |b| match b {
                    0 => None,
                    1 => Some(1),
                    b => Some(b - 1),
                })
                == Ok(1)
    }

    fn before_put(&self, transaction: Option<OpId>) -> Result<(), StoreFailure> {
        let probe = self
            .put_probe
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(why) = probe.and_then(|probe| probe()) {
            return Err(why);
        }
        let replay_observed = transaction.is_some_and(|op| {
            self.observed_transactions
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains(&op.0)
        });
        if !replay_observed && self.refuses_put() {
            return Err(StoreFailure::Refused(
                "the test store refuses writes".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn lose_acks(&self, losing: bool) {
        self.lost_acks.store(losing, Ordering::Release);
    }

    pub(crate) fn lose_transaction_acks(&self, losing: bool) {
        self.transaction_acks_lost.store(losing, Ordering::Release);
    }

    pub(crate) fn puts(&self) -> usize {
        self.puts.load(Ordering::Acquire)
    }

    pub(crate) fn corrupt(&self, schema: &str, key: &[u8]) {
        let mut edited = completed(self.inner.record_get(schema, key))
            .expect("the product store reads the row")
            .expect("the row is there")
            .as_slice()
            .to_vec();
        if let Some(last) = edited.last_mut() {
            *last ^= 0xff;
        }
        self.put_row(schema, key, &edited);
    }

    pub(crate) fn redeem(&self, kind: &str, token: &str, expires_at: u64, now: u64) -> bool {
        completed(StoreCalls::redeem_plane_token(
            self.inner.as_ref(),
            kind,
            token,
            expires_at,
            now,
        ))
        .expect("the product store redeems the token")
    }

    pub(crate) fn put_row(&self, schema: &str, key: &[u8], value: &[u8]) {
        let value = RecordBytes::new(value.to_vec()).expect("a test row fits a slot");
        completed(self.inner.record_put(schema, key, &value))
            .expect("the product store keeps the fixture row");
    }

    pub(crate) fn rows_under(&self, schema: &str) -> usize {
        completed(self.inner.record_scan(schema, b"", u32::MAX))
            .expect("the product store scans the rows")
            .len()
    }
}

fn completed<T>(call: StoreCall<'_, T>) -> Result<T, StoreFailure> {
    crate::root::card_store::wait_until(call, Some(Instant::now() + Duration::from_secs(30)))
        .expect("the product store answers the fixture operation")
}

impl StoreCalls for RecordSlots {
    fn supports_usage_correction(&self) -> bool {
        StoreCalls::supports_usage_correction(self.inner.as_ref())
    }

    fn apply_usage_correction<'a>(
        &'a self,
        request: &'a busbar_contract::records::correction::Request,
    ) -> StoreCall<'a, busbar_contract::records::correction::Decision> {
        StoreCalls::apply_usage_correction(self.inner.as_ref(), request)
    }

    fn supports_record_transaction(&self) -> bool {
        self.inner.supports_record_transaction()
    }

    fn record_transaction<'a>(&'a self, request: &'a Request) -> StoreCall<'a, Decision> {
        Box::pin(async move {
            self.ready().await;
            let probe = self
                .transaction_probe
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if let Some(why) = probe.and_then(|probe| probe(request)) {
                return Err(why);
            }
            self.before_put(Some(request.op_id))?;
            let decision = self.inner.record_transaction(request).await?;
            if decision == Decision::Applied {
                let first_observation = self
                    .observed_transactions
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(request.op_id.0);
                if first_observation {
                    self.puts.fetch_add(
                        request
                            .mutations
                            .iter()
                            .filter(|mutation| matches!(mutation, Mutation::Put { .. }))
                            .count(),
                        Ordering::AcqRel,
                    );
                }
                if (first_observation && self.lost_acks.load(Ordering::Acquire))
                    || self.transaction_acks_lost.load(Ordering::Acquire)
                {
                    return Err(StoreFailure::Failed(
                        "the test store lost the transaction ack".into(),
                    ));
                }
            }
            Ok(decision)
        })
    }

    fn add_usage_batch<'a>(
        &'a self,
        op: OpId,
        cells: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        self.inner.add_usage_batch(op, cells)
    }

    fn add_metering_batch<'a>(
        &'a self,
        op: OpId,
        deltas: &'a [MeteringDelta],
    ) -> StoreCall<'a, ()> {
        self.inner.add_metering_batch(op, deltas)
    }

    fn record_put<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
        value: &'a RecordBytes,
    ) -> StoreCall<'a, ()> {
        Box::pin(async move {
            self.ready().await;
            self.before_put(None)?;
            self.inner.record_put(schema, key, value).await?;
            self.puts.fetch_add(1, Ordering::AcqRel);
            if self.lost_acks.load(Ordering::Acquire) {
                return Err(StoreFailure::Failed("the test store lost the ack".into()));
            }
            Ok(())
        })
    }

    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        Box::pin(async move {
            if self.unreadable.load(Ordering::Acquire) {
                return Err(StoreFailure::Failed("the test store will not read".into()));
            }
            self.inner.record_get(schema, key).await
        })
    }

    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        Box::pin(async move {
            self.ready().await;
            let probe = self.probe.lock().unwrap_or_else(|p| p.into_inner()).clone();
            if let Some(probe) = probe {
                probe();
            }
            if self.unreadable.load(Ordering::Acquire) {
                return Err(StoreFailure::Failed("the test store will not read".into()));
            }
            self.inner.record_scan(schema, prefix, limit).await
        })
    }

    fn put_key<'a>(&'a self, key: &'a VirtualKey) -> StoreCall<'a, ()> {
        StoreCalls::put_key(self.inner.as_ref(), key)
    }

    fn get_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, Option<VirtualKey>> {
        StoreCalls::get_key(self.inner.as_ref(), id)
    }

    fn list_keys(&self) -> StoreCall<'_, Vec<VirtualKey>> {
        StoreCalls::list_keys(self.inner.as_ref())
    }

    fn delete_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, ()> {
        StoreCalls::delete_key(self.inner.as_ref(), id)
    }

    fn put_key_with_credential<'a>(
        &'a self,
        key: &'a VirtualKey,
        secret: &'a CredentialSecret,
    ) -> StoreCall<'a, ()> {
        StoreCalls::put_key_with_credential(self.inner.as_ref(), key, secret)
    }

    fn list_credentials<'a>(&'a self, key_id: &'a str) -> StoreCall<'a, Vec<CredentialMeta>> {
        StoreCalls::list_credentials(self.inner.as_ref(), key_id)
    }

    fn revoke_credential<'a>(&'a self, id: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        StoreCalls::revoke_credential(self.inner.as_ref(), id, reason)
    }

    fn list_credentials_since(&self, since: u64) -> StoreCall<'_, Vec<CredentialSecret>> {
        StoreCalls::list_credentials_since(self.inner.as_ref(), since)
    }

    fn add_denylist<'a>(&'a self, sub: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        StoreCalls::add_denylist(self.inner.as_ref(), sub, reason)
    }

    fn list_denylist(&self) -> StoreCall<'_, Vec<String>> {
        StoreCalls::list_denylist(self.inner.as_ref())
    }

    fn list_metering(&self, bucket: u64) -> StoreCall<'_, Vec<MeteringRow>> {
        StoreCalls::list_metering(self.inner.as_ref(), bucket)
    }

    fn list_audit(&self) -> StoreCall<'_, Vec<AuditRecord>> {
        StoreCalls::list_audit(self.inner.as_ref())
    }

    fn list_audit_tail(&self, limit: u64) -> StoreCall<'_, Vec<AuditRecord>> {
        StoreCalls::list_audit_tail(self.inner.as_ref(), limit)
    }

    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        StoreCalls::upsert_plane_record(self.inner.as_ref(), record)
    }

    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> StoreCall<'a, Option<Vec<u8>>> {
        StoreCalls::get_plane_record(self.inner.as_ref(), kind, id)
    }

    fn append_plane_record<'a>(
        &'a self,
        op: OpId,
        record: PlaneRecordRef<'a>,
    ) -> StoreCall<'a, ()> {
        StoreCalls::append_plane_record(self.inner.as_ref(), op, record)
    }

    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        StoreCalls::list_plane_records(self.inner.as_ref(), kind, selector)
    }

    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
        StoreCalls::delete_plane_record(self.inner.as_ref(), kind, id)
    }

    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        StoreCalls::redeem_plane_token(self.inner.as_ref(), kind, token, expires_at, now)
    }

    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        StoreCalls::plane_token_live(self.inner.as_ref(), kind, token, expires_at, now)
    }

    fn list_plane_record_parents<'a>(&'a self, kind: &'a str) -> StoreCall<'a, Vec<String>> {
        StoreCalls::list_plane_record_parents(self.inner.as_ref(), kind)
    }

    fn purge_plane_records_before<'a>(&'a self, kind: &'a str, before: u64) -> StoreCall<'a, u64> {
        StoreCalls::purge_plane_records_before(self.inner.as_ref(), kind, before)
    }

    fn purge_usage_before(&self, before: u64) -> StoreCall<'_, u64> {
        StoreCalls::purge_usage_before(self.inner.as_ref(), before)
    }
}
