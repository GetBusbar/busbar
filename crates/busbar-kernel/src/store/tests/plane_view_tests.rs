// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `PlaneStoreView` forwards to the real backend.

use super::{PlaneStore, PlaneStoreView};

/// A single-use token kind, as a spent-approval ledger writes it (no production caller names one).
const KIND_ASK: &str = "ask";
use busbar_contract::records::{
    PlaneDisposition, PlaneRecord, PlaneRecordRef, PlaneSelector, RecordStoreResult,
};
use std::sync::Arc;

/// A throwaway opaque body for the `demotion` kind — this seam names no plane record type, so the
/// forwarding test stands one up locally to prove the wrapper carries an opaque body through.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DemoRow {
    server: String,
    reason: String,
    recorded_at: u64,
}

/// A minimal recording backend: it implements the non-defaulted `Store` methods trivially and
/// records the two plane calls the forwarding test exercises, so a call reaching the inner `Store`
/// is observable. The RAM `MemoryStore` implements none of the plane methods (they take the trait
/// defaults), so it cannot witness forwarding; this can.
#[derive(Default)]
struct RecordingStore {
    demotions: std::sync::Mutex<Vec<DemoRow>>,
    redemptions: std::sync::atomic::AtomicUsize,
}

impl busbar_contract::records::RecordStore for RecordingStore {
    fn put_key(&self, _key: &busbar_contract::records::VirtualKey) -> RecordStoreResult<()> {
        Ok(())
    }
    fn get_key(
        &self,
        _id: &str,
    ) -> RecordStoreResult<Option<busbar_contract::records::VirtualKey>> {
        Ok(None)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<busbar_contract::records::VirtualKey>> {
        Ok(Vec::new())
    }
    fn delete_key(&self, _id: &str) -> RecordStoreResult<()> {
        Ok(())
    }
    fn get_usage(
        &self,
        _bucket: &str,
        _win: u64,
    ) -> RecordStoreResult<busbar_contract::records::UsageLedger> {
        Ok(busbar_contract::records::UsageLedger::default())
    }
    fn put_usage(
        &self,
        _bucket: &str,
        _win: u64,
        _ledger: &busbar_contract::records::UsageLedger,
    ) -> RecordStoreResult<()> {
        Ok(())
    }
    fn add_metering(
        &self,
        _delta: &busbar_contract::records::MeteringDelta,
    ) -> RecordStoreResult<()> {
        Ok(())
    }
    fn list_metering(
        &self,
        _bucket: u64,
    ) -> RecordStoreResult<Vec<busbar_contract::records::MeteringRow>> {
        Ok(Vec::new())
    }
    // The neutral plane verbs the forwarding test observes.
    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        let record = &record.to_record();
        if record.kind == crate::store::plane_view::KIND_DEMOTION {
            self.demotions
                .lock()
                .unwrap()
                .push(crate::store::plane_view::decode(&record.body)?);
        }
        Ok(())
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        match (kind, selector) {
            (crate::store::plane_view::KIND_DEMOTION, PlaneSelector::All) => self
                .demotions
                .lock()
                .unwrap()
                .iter()
                .map(crate::store::plane_view::encode)
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
    ) -> RecordStoreResult<bool> {
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
    let list_demotions = |s: &Arc<dyn PlaneStore>| -> Vec<DemoRow> {
        s.list_plane_records(crate::store::plane_view::KIND_DEMOTION, &PlaneSelector::All)
            .unwrap()
            .iter()
            .map(|body| crate::store::plane_view::decode(body).unwrap())
            .collect()
    };
    assert!(
        list_demotions(&store).is_empty(),
        "a fresh backend holds no demotions"
    );
    store
        .upsert_plane_record(
            PlaneRecord {
                kind: crate::store::plane_view::KIND_DEMOTION.to_string(),
                id: "srv-1".to_string(),
                parent: None,
                seq: 0,
                ts: 100,
                disposition: PlaneDisposition::Active,
                body: crate::store::plane_view::encode(&DemoRow {
                    server: "srv-1".to_string(),
                    reason: "drift".to_string(),
                    recorded_at: 100,
                })
                .unwrap(),
            }
            .view(),
        )
        .unwrap();
    let rows = list_demotions(&store);
    assert_eq!(rows.len(), 1, "the write forwarded to the inner backend");
    assert_eq!(rows[0].server, "srv-1");

    // The spent-approval test-and-set forwards too: first redemption is fresh, the second is not,
    // which can only hold if both calls reached the one inner instance.
    assert!(
        store
            .redeem_plane_token(KIND_ASK, "nonce-a", 1_000, 10)
            .unwrap(),
        "first redemption is fresh"
    );
    assert!(
        !store
            .redeem_plane_token(KIND_ASK, "nonce-a", 1_000, 10)
            .unwrap(),
        "second redemption sees the same inner ledger the wrapper forwarded to"
    );
}
