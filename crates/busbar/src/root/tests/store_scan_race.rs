// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::durability::store_identity::{take_node, HeldLease};
use busbar_contract::abi::sdk::store::conditional::{Decision, Mutation, Predicate};

struct MixedScan {
    node: u64,
    delegate: ScanView,
    slots: RecordSlots,
    append: busbar_contract::abi::sdk::store::conditional::Request,
    triggered: AtomicBool,
    appended: AtomicBool,
    upper_waker: Mutex<Option<std::task::Waker>>,
    stages: Mutex<Vec<&'static str>>,
    lower_snapshot: AtomicBool,
    upper_seen: AtomicBool,
    first_upper: AtomicBool,
}
impl StoreCalls for MixedScan {
    fn add_usage_batch<'a>(
        &'a self,
        op: OpId,
        cells: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        self.delegate.add_usage_batch(op, cells)
    }
    fn add_metering_batch<'a>(
        &'a self,
        op: OpId,
        deltas: &'a [MeteringDelta],
    ) -> StoreCall<'a, ()> {
        self.delegate.add_metering_batch(op, deltas)
    }
    fn record_put<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
        value: &'a RecordBytes,
    ) -> StoreCall<'a, ()> {
        self.delegate.record_put(schema, key, value)
    }
    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        self.delegate.record_get(schema, key)
    }
    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        self.delegate.upsert_plane_record(record)
    }
    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> StoreCall<'a, Option<Vec<u8>>> {
        self.delegate.get_plane_record(kind, id)
    }
    fn append_plane_record<'a>(
        &'a self,
        op: OpId,
        record: PlaneRecordRef<'a>,
    ) -> StoreCall<'a, ()> {
        self.delegate.append_plane_record(op, record)
    }
    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        self.delegate.list_plane_records(kind, selector)
    }
    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
        self.delegate.delete_plane_record(kind, id)
    }
    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.delegate
            .redeem_plane_token(kind, token, expires_at, now)
    }
    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.delegate.plane_token_live(kind, token, expires_at, now)
    }
    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        Box::pin(async move {
            let upper = prefix == &part_key(self.node, 302, 0)[..16]
                && !self.first_upper.swap(true, Ordering::SeqCst);
            if upper {
                // Do not even create the backend future before the append is
                // confirmed. Registration plus a second Acquire check closes
                // the publication/waker-registration race without a thread.
                std::future::poll_fn(|cx| {
                    if self.appended.load(Ordering::Acquire) {
                        return std::task::Poll::Ready(());
                    }
                    let mut waiter = self.upper_waker.lock().unwrap();
                    *waiter = Some(cx.waker().clone());
                    if self.appended.load(Ordering::Acquire) {
                        std::task::Poll::Ready(())
                    } else {
                        std::task::Poll::Pending
                    }
                })
                .await;
                self.stages.lock().unwrap().push("upper_backend_started");
            }
            let rows = self.delegate.record_scan(schema, prefix, limit).await?;
            if prefix == &part_key(self.node, 301, 0)[..16]
                && !self.triggered.swap(true, Ordering::SeqCst)
            {
                assert!(
                    rows.is_empty(),
                    "lower prefix snapshot predates the atomic append"
                );
                self.lower_snapshot.store(true, Ordering::SeqCst);
                self.stages.lock().unwrap().push("lower_snapshot_captured");
                assert_eq!(
                    self.slots.apply_transaction(&self.append),
                    Decision::Applied,
                    "both consecutive sealed records are appended in one real Store transaction"
                );
                self.stages.lock().unwrap().push("atomic_append_applied");
                self.appended.store(true, Ordering::Release);
                let waiter = self.upper_waker.lock().unwrap().take();
                if let Some(waiter) = waiter {
                    waiter.wake();
                }
            }
            if upper {
                assert!(!rows.is_empty());
                self.upper_seen.store(true, Ordering::SeqCst);
                self.stages.lock().unwrap().push("upper_snapshot_observed");
            }
            Ok(rows)
        })
    }
}

fn bulky_audit(sealed: &mut Sealed, wall: u64) -> JournalRecord {
    let mut inputs = crate::root::durability::audit::tests::inputs(sealed.audit.next_seq());
    inputs.wall = wall;
    inputs.what.destination = Some("x".repeat(4_096));
    let audit = sealed.audit.seal(
        inputs,
        &busbar_kernel::teller::verb_audit_pass(&crate::root::kernel::new_kernel()),
    );
    sealed.append(crate::root::durability::audit_entry(&audit).unwrap())
}

#[test]
fn concurrent_atomic_append_can_produce_a_mixed_prefix_view_that_fails_closed() {
    let slots = RecordSlots::new();
    let taken = take_node(&slots, "actual-prefix-race-writer").unwrap();
    let node = taken.id;
    let lease = HeldLease::default();
    lease.hold(taken.lease.unwrap());
    let mut sealed = Sealed::for_node(node);
    for index in 0..300 {
        bulky_audit(&mut sealed, START + index);
    }
    assert_eq!(sealed.records.len(), 300);
    let upper_parts: usize = sealed
        .records
        .iter()
        .filter(|record| record.node_seq >= 256)
        .map(|record| record.encode().chunks(PART_BYTES).count())
        .sum();
    assert!(upper_parts >= 256, "the actual upper sequence prefix must saturate its page before the traversal can reach exact prefixes 301 and 302");
    for record in &sealed.records {
        let bytes = record.encode();
        let chunks: Vec<_> = bytes.chunks(PART_BYTES).collect();
        for (index, chunk) in chunks.iter().enumerate() {
            let mut value = (chunks.len() as u16).to_be_bytes().to_vec();
            value.extend_from_slice(chunk);
            slots.put_row(
                JOURNAL_SCHEMA,
                &part_key(node, record.node_seq, index as u16),
                &value,
            );
        }
    }
    let upper_prefix = part_key(node, 256, 0)[..15].to_vec();
    assert_eq!(
        wait_for(slots.record_scan(JOURNAL_SCHEMA, &upper_prefix, 256))
            .unwrap()
            .len(),
        256,
        "the actual Store returns a saturated upper-prefix page before the mixed traversal starts"
    );
    let next = bulky_audit(&mut sealed, START + 300);
    let last = bulky_audit(&mut sealed, START + 301);
    assert_eq!(next.node_seq, 301);
    assert_eq!(last.node_seq, 302);
    let mut mutations = Vec::new();
    for record in [&next, &last] {
        let encoded = record.encode();
        let chunks: Vec<_> = encoded.chunks(PART_BYTES).collect();
        for (index, chunk) in chunks.iter().enumerate() {
            let mut value = (chunks.len() as u16).to_be_bytes().to_vec();
            value.extend_from_slice(chunk);
            mutations.push(Mutation::Put {
                schema: JOURNAL_SCHEMA.into(),
                key: part_key(node, record.node_seq, index as u16).to_vec(),
                value,
            });
        }
    }
    let append = crate::root::durability::conditional::candidate(
        vec![
            lease.predicate(&slots).unwrap().unwrap(),
            Predicate {
                schema: JOURNAL_SCHEMA.into(),
                key: part_key(node, next.node_seq, 0).to_vec(),
                expected: busbar_contract::abi::sdk::store::conditional::Expected::Absent,
            },
        ],
        mutations,
    );
    let view = MixedScan {
        node,
        delegate: ScanView::new(&slots, ScanMode::Healthy),
        slots: slots.clone(),
        append,
        triggered: AtomicBool::new(false),
        appended: AtomicBool::new(false),
        upper_waker: Mutex::new(None),
        stages: Mutex::new(Vec::new()),
        lower_snapshot: AtomicBool::new(false),
        upper_seen: AtomicBool::new(false),
        first_upper: AtomicBool::new(false),
    };
    let result = verify_stored_chain(&view, node);
    assert!(view.lower_snapshot.load(Ordering::SeqCst));
    assert!(view.upper_seen.load(Ordering::SeqCst));
    assert_eq!(*view.stages.lock().unwrap(), ["lower_snapshot_captured", "atomic_append_applied", "upper_backend_started", "upper_snapshot_observed"],
        "actual read and atomic Store completion order must establish the two distinct snapshot epochs");
    assert!(
        result.unwrap_err().contains("broken hash link or sequence"),
        "the mixed snapshot must fail specifically at the unchanged hash-link/sequence verifier"
    );
    let mut observed = Vec::new();
    fold_stored_records(
        &view.delegate,
        node,
        node.to_be_bytes().to_vec(),
        |record| {
            observed.push(record);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        observed,
        sealed.records.iter().map(raw).collect::<Vec<_>>(),
        "a fresh stopped-writer read sees every atomically appended record, with no actual gap"
    );
    verify_stored_chain(&view.delegate, node).unwrap();
}
