// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STAND-IN STORE AXIS: `preflight::RootInstall`'s `store_axis` in a test build. A test build
//! has no composition root and no loader (BUSBAR-1.6.0.md THE DESIGN l.322: the kernel never names
//! the loader), so the store boot opens is opened IN PROCESS: the store double's door
//! ([`super::store_double::door`], what [`super::store_double::STORE`] links) opens a fresh
//! [`super::store_double::MemoryStore`], and every call the kernel makes runs that store's
//! [`StoreSlots`] directly ([`SlotStore`]). Any other door is refused, naming why.
//!
//! WHAT IT MIRRORS is the loader's bridge over a store's table (`LoadedStore`,
//! `crates/plugin-loader/src/store_v3.rs`), op for op:
//!
//! * `open` is the store's own [`StoreSlots::open`] over the section's settings, then its connect
//!   step, as the SDK's door runs them; a refusal is the loader's `plugin '<name>' open failed:
//!   <the store's text>` (`status 3` for a fault);
//! * the typed calls ([`StoreCalls`]) and the 1.5.5 op set ([`RecordStore`], the synchronous
//!   bridge) both run the SAME slots, so a call that answers PENDING on no ticket is FAULT on either
//!   surface;
//! * each answer is classed as the loader classes the door's: an `op_id` conflict
//!   [`StoreFailure::Conflict`], a store's text [`StoreFailure::Failed`]; the bridge carries a
//!   FAILED op's text unchanged and every other failure in its typed words (the loader's `bridge`);
//! * the bridge's additive 1.5.5 writes (`add_usage`, `add_metering`, `append_plane_record`) run the store's `op_id`-carrying slots under an `op_id` the kernel's
//!   one allocator mints ([`crate::door::op_id`]).
//!
//! Every call crosses on no ticket ([`Op::detached`]): a store that answers PENDING there is a
//! FAULT, as the SDK's door rules for a call on no ticket. The store double never pends. How a
//! store is loaded, dispatched, bounded by its `max_inflight` and resumed on its wake is the
//! loader's to prove (`crates/plugin-loader/src/tests/store_v3_tests.rs`), and the double's parity
//! with the shipped store the root's (`the_kernel_store_double_states_what_the_linked_store_door_states`).

use std::sync::Arc;

use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::sdk::store::{Op, OpRefused, OpResult, Step, StoreSlots};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStore, RecordStoreError, RecordStoreResult, UsageDelta, UsageLedger,
    VirtualKey,
};
use busbar_contract::store_calls::{
    OpIdMint, OpenedStore, StoreAxis, StoreCall, StoreCalls, StoreDoor, StoreFailure,
};

use super::store_double::{self, MemoryStore as Double};

/// A test build's store axis (it has no composition root): the store double's door, opened in
/// process.
#[must_use]
pub fn store_axis_stand_in() -> Arc<dyn StoreAxis> {
    Arc::new(StandIn)
}

/// THE STAND-IN AXIS (see the module doc).
struct StandIn;

impl StoreAxis for StandIn {
    fn open(&self, door: StoreDoor, label: &str, settings: &[u8]) -> Result<OpenedStore, String> {
        match door {
            StoreDoor::Linked(door) if is_store_double(door) => {
                let store = Arc::new(SlotStore::<Double>::open(
                    store_double::NAME,
                    settings,
                    crate::door::op_id,
                )?);
                Ok(OpenedStore {
                    records: store.clone(),
                    calls: Some(store),
                })
            }
            StoreDoor::Linked(_) => Err(format!(
                "store '{label}': a test build has no loader, and its store axis opens the store \
                 double's door alone; the composition root's tests open any other"
            )),
            StoreDoor::Dropped { file, .. } => Err(format!(
                "store '{label}' ({file}): a test build has no loader to load a dropped-in store; \
                 the composition root's tests load one"
            )),
        }
    }
}

/// Whether `door` is the store double's door (compared by fn address).
fn is_store_double(door: DoorFn) -> bool {
    std::ptr::fn_addr_eq(door, store_double::door as DoorFn)
}

/// ONE STORE INSTANCE, called in process through its [`StoreSlots`]: the store, the Statement name
/// its refusals carry, and the kernel's `op_id` allocator for the bridge's additive writes.
pub(crate) struct SlotStore<S: StoreSlots> {
    store: S,
    name: &'static str,
    mint: OpIdMint,
}

impl<S: StoreSlots> SlotStore<S> {
    /// Open `S` on `settings` and run its connect step, as the SDK's door's `open` does.
    ///
    /// # Errors
    /// The store refused its settings or its connect step (`plugin '<name>' open failed: <text>`),
    /// or faulted (`status 3`).
    pub(crate) fn open(
        name: &'static str,
        settings: &[u8],
        mint: OpIdMint,
    ) -> Result<Self, String> {
        let refused = |reason: &str| format!("plugin '{name}' open failed: {reason}");
        let store = S::open(settings, None).map_err(|e| refused(&e))?;
        match S::connect(&store, &mut Op::detached()) {
            Step::Ready(Ok(())) => Ok(Self { store, name, mint }),
            Step::Ready(Err(e)) => Err(refused(&e)),
            // Pending on no ticket: FAULT.
            Step::Pending { .. } => Err(refused("status 3")),
        }
    }

    /// Run one slot on no ticket: its answer, or FAULT for a PENDING. A store body that panics is
    /// FAULT too, never an unwind into the caller: the SDK's door runs every slot body under
    /// `catch_unwind` and answers a panic as `Outcome::Fault`, which the loader's bridge classes
    /// [`StoreFailure::Fault`] (`crates/plugin-loader/src/store_v3.rs`). The body runs on a scoped
    /// thread of its own and its join answers the panic, so no unwind boundary is asserted here
    /// (`qa/construction.toml` `hold-escapes`: the stand-in holds no hold, and names no escape).
    fn call<T: Send>(
        &self,
        slot: impl FnOnce(&S, &mut Op<'_>) -> Step<T> + Send,
    ) -> Result<T, StoreFailure> {
        let store = &self.store;
        let ran = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    let mut cx = Op::detached();
                    slot(store, &mut cx)
                })
                .join()
        });
        match ran {
            Ok(Step::Ready(answer)) => Ok(answer),
            Ok(Step::Pending { .. }) => Err(StoreFailure::Fault(format!(
                "store '{}' answered PENDING on a call on no ticket",
                self.name
            ))),
            Err(_) => Err(StoreFailure::Fault(format!(
                "store '{}' panicked in its slot body",
                self.name
            ))),
        }
    }

    /// An `op_id`-carrying write: a conflict is [`StoreFailure::Conflict`], a failure's text FAILED,
    /// a refusal's text REFUSED (S5).
    fn op<T: Send>(
        &self,
        slot: impl FnOnce(&S, &mut Op<'_>) -> Step<OpResult<T>> + Send,
    ) -> Result<T, StoreFailure> {
        self.call(slot)?.map_err(|e| match e {
            OpRefused::Conflict => StoreFailure::Conflict,
            OpRefused::Failed(text) => StoreFailure::Failed(text),
            OpRefused::Refused(text) => StoreFailure::Refused(text),
        })
    }

    /// A slot answering the store's own text on failure: FAILED with it.
    fn text<T: Send>(
        &self,
        slot: impl FnOnce(&S, &mut Op<'_>) -> Step<Result<T, String>> + Send,
    ) -> Result<T, StoreFailure> {
        self.call(slot)?.map_err(StoreFailure::Failed)
    }

    /// A 1.5.5 op: FAILED with the store's error text.
    fn record<T: Send>(
        &self,
        slot: impl FnOnce(&S, &mut Op<'_>) -> Step<RecordStoreResult<T>> + Send,
    ) -> Result<T, StoreFailure> {
        self.call(slot)?.map_err(|e| StoreFailure::Failed(e.0))
    }

    /// A fresh `op_id` for one of the bridge's additive writes.
    fn mint(&self) -> OpId {
        (self.mint)()
    }
}

/// One call's answer, already in hand.
fn ready<'a, T: Send + 'a>(answer: Result<T, StoreFailure>) -> StoreCall<'a, T> {
    Box::pin(std::future::ready(answer))
}

impl<S: StoreSlots> StoreCalls for SlotStore<S> {
    fn get_usage<'a>(&'a self, bucket: &'a str, window_start: u64) -> StoreCall<'a, UsageLedger> {
        ready(self.record(|s, cx| S::get_usage(s, cx, bucket, window_start)))
    }

    fn add_usage_batch<'a>(
        &'a self,
        op: OpId,
        cells: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        ready(self.op(|s, cx| S::add_usage_batch(s, cx, op, cells)))
    }

    fn add_metering_batch<'a>(
        &'a self,
        op: OpId,
        deltas: &'a [MeteringDelta],
    ) -> StoreCall<'a, ()> {
        ready(self.op(|s, cx| S::add_metering_batch(s, cx, op, deltas)))
    }

    fn record_put<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
        value: &'a RecordBytes,
    ) -> StoreCall<'a, ()> {
        ready(self.text(|s, cx| S::record_put(s, cx, schema, key, value.as_slice())))
    }

    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        ready(self.text(|s, cx| S::record_get(s, cx, schema, key)))
    }

    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        ready(self.text(|s, cx| S::record_scan(s, cx, schema, prefix, limit)))
    }

    fn put_key<'a>(&'a self, key: &'a VirtualKey) -> StoreCall<'a, ()> {
        ready(self.record(|s, cx| S::put_key(s, cx, key)))
    }

    fn get_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, Option<VirtualKey>> {
        ready(self.record(|s, cx| S::get_key(s, cx, id)))
    }

    fn list_keys(&self) -> StoreCall<'_, Vec<VirtualKey>> {
        ready(self.record(S::list_keys))
    }

    fn delete_key<'a>(&'a self, id: &'a str) -> StoreCall<'a, ()> {
        ready(self.record(|s, cx| S::delete_key(s, cx, id)))
    }

    fn put_key_with_credential<'a>(
        &'a self,
        key: &'a VirtualKey,
        secret: &'a CredentialSecret,
    ) -> StoreCall<'a, ()> {
        ready(self.record(|s, cx| S::put_key_with_credential(s, cx, key, secret)))
    }

    fn list_credentials<'a>(&'a self, key_id: &'a str) -> StoreCall<'a, Vec<CredentialMeta>> {
        ready(self.record(|s, cx| S::list_credentials(s, cx, key_id)))
    }

    fn revoke_credential<'a>(&'a self, id: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        ready(self.record(|s, cx| S::revoke_credential(s, cx, id, reason)))
    }

    fn list_credentials_since(&self, since: u64) -> StoreCall<'_, Vec<CredentialSecret>> {
        ready(self.record(|s, cx| S::list_credentials_since(s, cx, since)))
    }

    fn add_denylist<'a>(&'a self, sub: &'a str, reason: &'a str) -> StoreCall<'a, ()> {
        ready(self.record(|s, cx| S::add_denylist(s, cx, sub, reason)))
    }

    fn list_denylist(&self) -> StoreCall<'_, Vec<String>> {
        ready(self.record(S::list_denylist))
    }

    fn list_metering(&self, bucket: u64) -> StoreCall<'_, Vec<MeteringRow>> {
        ready(self.record(|s, cx| S::list_metering(s, cx, bucket)))
    }

    fn list_audit(&self) -> StoreCall<'_, Vec<AuditRecord>> {
        ready(self.record(S::list_audit))
    }

    fn list_audit_tail(&self, limit: u64) -> StoreCall<'_, Vec<AuditRecord>> {
        ready(self.record(|s, cx| S::list_audit_tail(s, cx, limit)))
    }

    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        ready(self.record(|s, cx| S::upsert_plane_record(s, cx, record)))
    }

    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> StoreCall<'a, Option<Vec<u8>>> {
        ready(self.record(|s, cx| S::get_plane_record(s, cx, kind, id)))
    }

    fn append_plane_record<'a>(
        &'a self,
        op: OpId,
        record: PlaneRecordRef<'a>,
    ) -> StoreCall<'a, ()> {
        ready(self.op(|s, cx| S::append_plane_record_op(s, cx, op, record)))
    }

    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        ready(self.record(|s, cx| S::list_plane_records(s, cx, kind, selector)))
    }

    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
        ready(self.record(|s, cx| S::delete_plane_record(s, cx, kind, id)))
    }

    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        ready(self.record(|s, cx| S::redeem_plane_token(s, cx, kind, token, expires_at, now)))
    }

    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        ready(self.record(|s, cx| S::plane_token_live(s, cx, kind, token, expires_at, now)))
    }

    fn list_plane_record_parents<'a>(&'a self, kind: &'a str) -> StoreCall<'a, Vec<String>> {
        ready(self.record(|s, cx| S::list_plane_record_parents(s, cx, kind)))
    }

    fn purge_plane_records_before<'a>(&'a self, kind: &'a str, before: u64) -> StoreCall<'a, u64> {
        ready(self.record(|s, cx| S::purge_plane_records_before(s, cx, kind, before)))
    }
}

/// The 1.5.5 op set's error for a store call: a FAILED op's own text unchanged, every other failure
/// in its typed words (the loader's `bridge`).
fn bridge<T>(r: Result<T, StoreFailure>) -> RecordStoreResult<T> {
    r.map_err(|f| match f {
        StoreFailure::Failed(text) => RecordStoreError(text),
        other => RecordStoreError(other.to_string()),
    })
}

/// THE SYNCHRONOUS BRIDGE: the 1.5.5 op set over the same slots.
impl<S: StoreSlots> RecordStore for SlotStore<S> {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        bridge(self.record(|s, cx| S::put_key(s, cx, key)))
    }

    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        bridge(self.record(|s, cx| S::get_key(s, cx, id)))
    }

    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        bridge(self.record(S::list_keys))
    }

    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        bridge(self.record(|s, cx| S::delete_key(s, cx, id)))
    }

    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        bridge(self.record(|s, cx| S::list_keys_since(s, cx, since)))
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
        bridge(self.record(|s, cx| S::get_usage(s, cx, bucket_id, window_start)))
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        bridge(self.record(|s, cx| S::put_usage(s, cx, bucket_id, window_start, ledger)))
    }

    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        let op = self.mint();
        let cells = [(bucket_id, window_start, delta.clone())];
        bridge(self.op(|s, cx| S::add_usage_batch(s, cx, op, &cells)))
    }

    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        let op = self.mint();
        bridge(self.op(|s, cx| S::add_metering_batch(s, cx, op, std::slice::from_ref(delta))))
    }

    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        bridge(self.record(|s, cx| S::list_metering(s, cx, bucket)))
    }

    fn put_credential(&self, secret: &CredentialSecret) -> RecordStoreResult<()> {
        bridge(self.record(|s, cx| S::put_credential(s, cx, secret)))
    }

    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        bridge(self.record(|s, cx| S::put_key_with_credential(s, cx, key, secret)))
    }

    fn list_credentials(&self, key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        bridge(self.record(|s, cx| S::list_credentials(s, cx, key_id)))
    }

    fn revoke_credential(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        bridge(self.record(|s, cx| S::revoke_credential(s, cx, id, reason)))
    }

    fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        bridge(self.record(|s, cx| S::list_credentials_since(s, cx, since)))
    }

    /// No store slot carries a 1.5.5 audit append: refused loudly, as the loader refuses it.
    fn append_audit(&self, _entry: &AuditRecord) -> RecordStoreResult<()> {
        Err(RecordStoreError(
            "append_audit is not a store op: 1.6.0 writes its audit as plane records".to_string(),
        ))
    }

    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        bridge(self.record(S::list_audit))
    }

    fn add_denylist(&self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        bridge(self.record(|s, cx| S::add_denylist(s, cx, sub, reason)))
    }

    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        bridge(self.record(S::list_denylist))
    }

    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        bridge(self.record(|s, cx| S::list_audit_tail(s, cx, limit)))
    }

    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        bridge(self.record(|s, cx| S::upsert_plane_record(s, cx, record)))
    }

    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        bridge(self.record(|s, cx| S::get_plane_record(s, cx, kind, id)))
    }

    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        let op = self.mint();
        bridge(self.op(|s, cx| S::append_plane_record_op(s, cx, op, record)))
    }

    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        bridge(self.record(|s, cx| S::list_plane_records(s, cx, kind, selector)))
    }

    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        bridge(self.record(|s, cx| S::list_plane_record_parents(s, cx, kind)))
    }

    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        bridge(self.record(|s, cx| S::purge_plane_records_before(s, cx, kind, before)))
    }

    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        bridge(self.record(|s, cx| S::delete_plane_record(s, cx, kind, id)))
    }

    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        bridge(self.record(|s, cx| S::redeem_plane_token(s, cx, kind, token, expires_at, now)))
    }

    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        bridge(self.record(|s, cx| S::plane_token_live(s, cx, kind, token, expires_at, now)))
    }
}
