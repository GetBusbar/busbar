// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Invariant (a) proof for the plane store seam: `PlaneStore` carries EXACTLY the plane methods and
//! provably NONE of the audit-chain authority `busbar_api::Store` also holds, and `PlaneStoreView`
//! forwards to the real backend.

use super::super::store::{PlaneStore, PlaneStoreView};
use busbar_api::{McpDemotionRow, PlaneRecord, PlaneSelector, StoreResult};
use std::sync::Arc;

// ── THE POSITIVE HALF: every plane method is present, at its `Store`-mirrored signature ──────────
//
// Each binding coerces the trait method to a concrete function pointer. It fails to COMPILE if the
// method is missing or its signature drifts from the one the store plugin ABI froze, so the set
// below is the authoritative statement of what `PlaneStore` carries. Eight neutral kind-tagged
// verbs, and the exact eight a plane needs to persist its own trust state — the 14→8 consolidation
// of the 1.6.0 store genericization, over the `PlaneRecord` envelope.
#[allow(clippy::type_complexity)]
fn plane_method_set_is_exactly_the_plane_methods() {
    let _: fn(&dyn PlaneStore, &PlaneRecord) -> StoreResult<()> =
        <dyn PlaneStore>::upsert_plane_record;
    let _: fn(&dyn PlaneStore, &str, &str) -> StoreResult<Option<Vec<u8>>> =
        <dyn PlaneStore>::get_plane_record;
    let _: fn(&dyn PlaneStore, &PlaneRecord) -> StoreResult<()> =
        <dyn PlaneStore>::append_plane_record;
    let _: fn(&dyn PlaneStore, &str, &PlaneSelector) -> StoreResult<Vec<Vec<u8>>> =
        <dyn PlaneStore>::list_plane_records;
    let _: fn(&dyn PlaneStore, &str) -> StoreResult<Vec<String>> =
        <dyn PlaneStore>::list_plane_record_parents;
    let _: fn(&dyn PlaneStore, &str, u64) -> StoreResult<u64> =
        <dyn PlaneStore>::purge_plane_records_before;
    let _: fn(&dyn PlaneStore, &str, &str) -> StoreResult<()> =
        <dyn PlaneStore>::delete_plane_record;
    let _: fn(&dyn PlaneStore, &str, &str, u64, u64) -> StoreResult<bool> =
        <dyn PlaneStore>::redeem_plane_token;
}

// ── THE NEGATIVE HALF: the audit chain is NOT reachable through `PlaneStore` ──────────────────────
//
// `AuditChainAbsent` is a blanket fallback carrying the three `Store` audit-chain methods a plane
// must never reach, each at `Store`'s own signature. Because it is implemented for EVERY type, the
// calls below on a `&dyn PlaneStore` resolve to it — UNLESS `PlaneStore` itself declares a method of
// the same name and receiver, in which case the call becomes ambiguous (E0034) and this file STOPS
// COMPILING. So a future edit that widens `PlaneStore` with `append_audit` / `list_audit` /
// `list_audit_tail` (the invariant-(a) breach) is caught at compile time. The `Sentinel` return type
// is what proves the fallback — not a real audit method — is the one that resolved.
struct Sentinel;
trait AuditChainAbsent {
    fn append_audit(&self, _entry: &busbar_api::AuditRecord) -> Sentinel {
        Sentinel
    }
    fn list_audit(&self) -> Sentinel {
        Sentinel
    }
    fn list_audit_tail(&self, _limit: u64) -> Sentinel {
        Sentinel
    }
}
impl<T: ?Sized> AuditChainAbsent for T {}

#[allow(clippy::let_unit_value)]
fn plane_store_reaches_no_audit_method(s: &dyn PlaneStore) {
    let rec = busbar_api::AuditRecord {
        seq: 0,
        ts: 0,
        action: String::new(),
        resource: String::new(),
        outcome: String::new(),
        principal: String::new(),
        prev_hash: String::new(),
        hash: String::new(),
    };
    // Each of these MUST resolve to the blanket `AuditChainAbsent` (returning `Sentinel`). If
    // `PlaneStore` grew its own `append_audit`/`list_audit`/`list_audit_tail`, resolution would be
    // ambiguous and the `let _: Sentinel` would fail to typecheck.
    let _: Sentinel = s.append_audit(&rec);
    let _: Sentinel = s.list_audit();
    let _: Sentinel = s.list_audit_tail(0);
}

#[test]
fn compile_time_seam_proof_is_referenced() {
    // The two functions above are the proof; they are compiled because this test names them. It
    // runs them against a real narrowed store so the negative half has a live `&dyn PlaneStore`.
    plane_method_set_is_exactly_the_plane_methods();
    let store = PlaneStoreView::narrow(Arc::new(busbar_store_memory::MemoryStore::new()));
    plane_store_reaches_no_audit_method(store.as_ref());
}

/// A minimal recording backend: it implements the non-defaulted `Store` methods trivially and
/// records the two plane calls the forwarding test exercises, so a call reaching the inner `Store`
/// is observable. The RAM `MemoryStore` implements none of the plane methods (they take the trait
/// defaults), so it cannot witness forwarding; this can.
#[derive(Default)]
struct RecordingStore {
    demotions: std::sync::Mutex<Vec<McpDemotionRow>>,
    redemptions: std::sync::atomic::AtomicUsize,
}

impl busbar_api::Store for RecordingStore {
    fn put_key(&self, _key: &busbar_api::VirtualKey) -> StoreResult<()> {
        Ok(())
    }
    fn get_key(&self, _id: &str) -> StoreResult<Option<busbar_api::VirtualKey>> {
        Ok(None)
    }
    fn list_keys(&self) -> StoreResult<Vec<busbar_api::VirtualKey>> {
        Ok(Vec::new())
    }
    fn delete_key(&self, _id: &str) -> StoreResult<()> {
        Ok(())
    }
    fn get_usage(&self, _bucket: &str, _win: u64) -> StoreResult<busbar_api::UsageLedger> {
        Ok(busbar_api::UsageLedger::default())
    }
    fn put_usage(
        &self,
        _bucket: &str,
        _win: u64,
        _ledger: &busbar_api::UsageLedger,
    ) -> StoreResult<()> {
        Ok(())
    }
    fn add_metering(&self, _delta: &busbar_api::MeteringDelta) -> StoreResult<()> {
        Ok(())
    }
    fn list_metering(&self, _bucket: u64) -> StoreResult<Vec<busbar_api::MeteringRow>> {
        Ok(Vec::new())
    }
    // The neutral plane verbs the forwarding test observes.
    fn upsert_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        if record.kind == crate::plane::store::KIND_DEMOTION {
            self.demotions
                .lock()
                .unwrap()
                .push(crate::plane::store::decode(&record.body)?);
        }
        Ok(())
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> StoreResult<Vec<Vec<u8>>> {
        match (kind, selector) {
            (crate::plane::store::KIND_DEMOTION, PlaneSelector::All) => self
                .demotions
                .lock()
                .unwrap()
                .iter()
                .map(crate::plane::store::encode)
                .collect(),
            _ => Ok(Vec::new()),
        }
    }
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> StoreResult<bool> {
        // First call fresh, later calls spent — proving the SAME inner instance is reached.
        let n = self
            .redemptions
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(n == 0)
    }
}

#[test]
fn plane_store_view_forwards_to_the_real_backend() {
    // Forwarding is observable: the wrapper hands a write and a read to the SAME inner `Store`, so
    // what one plane method persists another reads back. If `PlaneStoreView` did not forward, the
    // demotion would not survive the call and the redemption ledger would not advance.
    let store: Arc<dyn PlaneStore> = PlaneStoreView::narrow(Arc::new(RecordingStore::default()));
    let list_demotions = |s: &Arc<dyn PlaneStore>| -> Vec<McpDemotionRow> {
        s.list_plane_records(crate::plane::store::KIND_DEMOTION, &PlaneSelector::All)
            .unwrap()
            .iter()
            .map(|body| crate::plane::store::decode(body).unwrap())
            .collect()
    };
    assert!(
        list_demotions(&store).is_empty(),
        "a fresh backend holds no demotions"
    );
    store
        .upsert_plane_record(
            &crate::plane::store::demotion_record(&McpDemotionRow {
                server: "srv-1".to_string(),
                reason: "drift".to_string(),
                recorded_at: 100,
            })
            .unwrap(),
        )
        .unwrap();
    let rows = list_demotions(&store);
    assert_eq!(rows.len(), 1, "the write forwarded to the inner backend");
    assert_eq!(rows[0].server, "srv-1");

    // The spent-approval test-and-set forwards too: first redemption is fresh, the second is not,
    // which can only hold if both calls reached the one inner instance.
    assert!(
        store
            .redeem_plane_token(crate::plane::store::KIND_ASK, "nonce-a", 1_000, 10)
            .unwrap(),
        "first redemption is fresh"
    );
    assert!(
        !store
            .redeem_plane_token(crate::plane::store::KIND_ASK, "nonce-a", 1_000, 10)
            .unwrap(),
        "second redemption sees the same inner ledger the wrapper forwarded to"
    );
}
