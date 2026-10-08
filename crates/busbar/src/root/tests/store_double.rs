//! A STORE'S RECORD SLOTS, IN THE TEST: the configured store as the root's journal reaches it
//! (`StoreCalls::record_put` / `record_get` / `record_scan`), over a map the test holds, so two books
//! built over one `RecordSlots` are one deployment restarted over one store. It counts the puts it
//! took and can be told to REFUSE them, which is how a store that has the slots but will not take a
//! write is posed. It keeps the single-use claims `redeem_plane_token` takes (the one atomic step a
//! minting boot races on), and a test can redeem one first as another node would. Every other slot
//! answers FAILED: the journal must not reach them.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::sdk::store::{Cap, Cell, Grant};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta,
};
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};

/// The rows the double keeps: `(schema, key)` to the bytes.
type Rows = BTreeMap<(String, Vec<u8>), RecordBytes>;

/// The single-use claims the double has taken: `(kind, token)` to the instant each lapses.
type Claims = BTreeMap<(String, String), u64>;

/// The double. Cheap to clone; every clone is the same store.
#[derive(Clone, Default)]
pub(crate) struct RecordSlots {
    rows: Arc<Mutex<Rows>>,
    claims: Arc<Mutex<Claims>>,
    refusing: Arc<AtomicBool>,
    puts: Arc<AtomicUsize>,
}

impl RecordSlots {
    /// An empty store that takes every put.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The same store as the root's journal reaches it.
    pub(crate) fn calls(&self) -> Arc<dyn StoreCalls> {
        Arc::new(self.clone())
    }

    /// From now on, refuse (`true`) or take (`false`) every put.
    pub(crate) fn refuse(&self, refusing: bool) {
        self.refusing.store(refusing, Ordering::Release);
    }

    /// How many puts the store took.
    pub(crate) fn puts(&self) -> usize {
        self.puts.load(Ordering::Acquire)
    }

    /// Flip the last byte of the row at `(schema, key)`: an edit made to the store behind the node.
    pub(crate) fn corrupt(&self, schema: &str, key: &[u8]) {
        let mut rows = self.rows.lock().unwrap_or_else(|p| p.into_inner());
        let at = (schema.to_string(), key.to_vec());
        let row = rows.get(&at).expect("the row is there").as_slice().to_vec();
        let mut edited = row;
        if let Some(last) = edited.last_mut() {
            *last ^= 0xff;
        }
        rows.insert(at, RecordBytes::new(edited).expect("the same length"));
    }

    /// Redeem the single-use claim `(kind, token)` as another node would, until `expires_at`:
    /// `true` when this was its first redemption.
    pub(crate) fn redeem(&self, kind: &str, token: &str, expires_at: u64, now: u64) -> bool {
        let mut claims = self.claims.lock().unwrap_or_else(|p| p.into_inner());
        claims.retain(|_, lapses| *lapses > now);
        claims
            .insert((kind.to_string(), token.to_string()), expires_at)
            .is_none()
    }

    /// Keep `value` at `(schema, key)` as another node's write would.
    pub(crate) fn put_row(&self, schema: &str, key: &[u8], value: &[u8]) {
        self.rows.lock().unwrap_or_else(|p| p.into_inner()).insert(
            (schema.to_string(), key.to_vec()),
            RecordBytes::new(value.to_vec()).expect("a test row fits a slot"),
        );
    }

    /// How many rows the store holds under `schema`.
    pub(crate) fn rows_under(&self, schema: &str) -> usize {
        self.rows
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .filter(|(s, _)| s == schema)
            .count()
    }
}

/// A slot the journal must not reach.
fn not_this<'a, T: Send + 'a>() -> StoreCall<'a, T> {
    Box::pin(async { Err(StoreFailure::Failed("not a journal slot".to_string())) })
}

impl StoreCalls for RecordSlots {
    fn reserve<'a>(&'a self, _: OpId, _: u64, _: &'a [Cell<'a>]) -> StoreCall<'a, Vec<Grant>> {
        not_this()
    }
    fn slice_release<'a>(
        &'a self,
        _: OpId,
        _: u64,
        _: &'a [(u64, u64)],
    ) -> StoreCall<'a, Vec<u64>> {
        not_this()
    }
    fn add_usage_batch<'a>(
        &'a self,
        _: OpId,
        _: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        not_this()
    }
    fn add_metering_batch<'a>(&'a self, _: OpId, _: &'a [MeteringDelta]) -> StoreCall<'a, ()> {
        not_this()
    }
    fn append_audit_batch<'a>(&'a self, _: OpId, _: &'a [AuditRecord]) -> StoreCall<'a, ()> {
        not_this()
    }
    fn window_caps<'a>(&'a self, _: OpId, _: &'a [Cap<'a>]) -> StoreCall<'a, ()> {
        not_this()
    }
    fn append_batch<'a>(
        &'a self,
        _: OpId,
        _: &'a str,
        _: &'a [RecordBytes],
    ) -> StoreCall<'a, Head> {
        not_this()
    }
    fn heads(&self) -> StoreCall<'_, Vec<(String, Head)>> {
        not_this()
    }
    fn session_put<'a>(&'a self, _: u64, _: &'a str, _: &'a str) -> StoreCall<'a, ()> {
        not_this()
    }
    fn session_remove(&self, _: u64) -> StoreCall<'_, ()> {
        not_this()
    }
    fn sessions_for<'a>(&'a self, _: &'a str) -> StoreCall<'a, Vec<(u64, String)>> {
        not_this()
    }
    fn record_put<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
        value: &'a RecordBytes,
    ) -> StoreCall<'a, ()> {
        let refused = self.refusing.load(Ordering::Acquire);
        if !refused {
            self.rows
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert((schema.to_string(), key.to_vec()), value.clone());
            self.puts.fetch_add(1, Ordering::AcqRel);
        }
        Box::pin(async move {
            if refused {
                Err(StoreFailure::Refused(
                    "the test store refuses writes".to_string(),
                ))
            } else {
                Ok(())
            }
        })
    }
    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        let got = self
            .rows
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(schema.to_string(), key.to_vec()))
            .cloned();
        Box::pin(async move { Ok(got) })
    }
    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        let rows: Vec<(Vec<u8>, RecordBytes)> = self
            .rows
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|((s, k), _)| s == schema && k.starts_with(prefix))
            .take(limit as usize)
            .map(|((_, k), v)| (k.clone(), v.clone()))
            .collect();
        Box::pin(async move { Ok(rows) })
    }
    fn upsert_plane_record<'a>(&'a self, _: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        not_this()
    }
    fn get_plane_record<'a>(&'a self, _: &'a str, _: &'a str) -> StoreCall<'a, Option<Vec<u8>>> {
        not_this()
    }
    fn append_plane_record<'a>(&'a self, _: OpId, _: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        not_this()
    }
    fn list_plane_records<'a>(
        &'a self,
        _: &'a str,
        _: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        not_this()
    }
    fn delete_plane_record<'a>(&'a self, _: &'a str, _: &'a str) -> StoreCall<'a, ()> {
        not_this()
    }
    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        let first = self.redeem(kind, token, expires_at, now);
        Box::pin(async move { Ok(first) })
    }
    fn plane_token_live<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: u64,
        _: u64,
    ) -> StoreCall<'a, bool> {
        not_this()
    }
}
