// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::durability::store_chain::{
    fold_stored_records, part_key, verify_stored_chain, JOURNAL_SCHEMA, PART_BYTES,
};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta};
use busbar_contract::store_calls::StoreCall;

#[derive(Clone, Copy)]
enum ScanMode {
    Healthy,
    BudgetOne,
    FaultAndBudget,
    MalformedAndBudget,
    TransientCountAndBudget,
    Refused,
    Failed,
}

// A read-boundary view over the actual opened Store. It changes scheduling or
// injects a named negative read result; all successful rows come from the Store.
struct ScanView {
    inner: Arc<dyn StoreCalls>,
    mode: ScanMode,
    active: AtomicUsize,
    peak: AtomicUsize,
    overloaded: AtomicUsize,
    starts: Mutex<Vec<Vec<u8>>>,
    count_injected: AtomicBool,
    budget_injected: AtomicBool,
}
struct ActiveScan<'a>(&'a AtomicUsize);
impl Drop for ActiveScan<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl ScanView {
    fn new(slots: &RecordSlots, mode: ScanMode) -> Self {
        Self {
            inner: slots.calls(),
            mode,
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            overloaded: AtomicUsize::new(0),
            starts: Mutex::new(Vec::new()),
            count_injected: AtomicBool::new(false),
            budget_injected: AtomicBool::new(false),
        }
    }
    fn starts_for(&self, prefix: &[u8]) -> usize {
        self.starts
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.as_slice() == prefix)
            .count()
    }
}
impl StoreCalls for ScanView {
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
        self.inner.record_put(schema, key, value)
    }
    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        self.inner.record_get(schema, key)
    }
    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        Box::pin(async move {
            self.starts.lock().unwrap().push(prefix.to_vec());
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            let _active = ActiveScan(&self.active);
            if matches!(self.mode, ScanMode::BudgetOne) && active > 1 {
                self.overloaded.fetch_add(1, Ordering::SeqCst);
                return Err(StoreFailure::Overloaded);
            }
            // Yield exactly once, using the caller's executor and waker; no timer
            // or local thread can make serial reads appear concurrent.
            let mut yielded = false;
            std::future::poll_fn(|cx| {
                if yielded {
                    std::task::Poll::Ready(())
                } else {
                    yielded = true;
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            })
            .await;
            let window = prefix.len() == 9;
            let selector = prefix.get(8).copied();
            if window
                && selector == Some(2)
                && matches!(
                    self.mode,
                    ScanMode::FaultAndBudget | ScanMode::MalformedAndBudget
                )
            {
                self.overloaded.fetch_add(1, Ordering::SeqCst);
                return Err(StoreFailure::Overloaded);
            }
            if window && selector == Some(1) {
                match self.mode {
                    ScanMode::FaultAndBudget => {
                        return Err(StoreFailure::Fault("explicit page fault".into()))
                    }
                    ScanMode::Refused => {
                        return Err(StoreFailure::Refused("explicit non-budget refusal".into()))
                    }
                    ScanMode::Failed => {
                        return Err(StoreFailure::Failed("explicit page failure".into()))
                    }
                    _ => {}
                }
            }
            let leaf_sequence =
                (prefix.len() == 16).then(|| u64::from_be_bytes(prefix[8..16].try_into().unwrap()));
            if matches!(self.mode, ScanMode::TransientCountAndBudget)
                && leaf_sequence == Some(2)
                && !self.budget_injected.swap(true, Ordering::SeqCst)
            {
                self.overloaded.fetch_add(1, Ordering::SeqCst);
                return Err(StoreFailure::Overloaded);
            }
            let mut rows = self.inner.record_scan(schema, prefix, limit).await?;
            if matches!(self.mode, ScanMode::TransientCountAndBudget)
                && leaf_sequence == Some(1)
                && !self.count_injected.swap(true, Ordering::SeqCst)
            {
                let mut bytes = rows[0].1.as_slice().to_vec();
                bytes[..2].copy_from_slice(&0u16.to_be_bytes());
                rows[0].1 = RecordBytes::new(bytes).unwrap();
            }
            if window && selector == Some(1) && matches!(self.mode, ScanMode::MalformedAndBudget) {
                rows.push((vec![0], RecordBytes::new(vec![0]).unwrap()));
            }
            Ok(rows)
        })
    }
    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        self.inner.upsert_plane_record(record)
    }
    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> StoreCall<'a, Option<Vec<u8>>> {
        self.inner.get_plane_record(kind, id)
    }
    fn append_plane_record<'a>(
        &'a self,
        op: OpId,
        record: PlaneRecordRef<'a>,
    ) -> StoreCall<'a, ()> {
        self.inner.append_plane_record(op, record)
    }
    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        self.inner.list_plane_records(kind, selector)
    }
    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> StoreCall<'a, ()> {
        self.inner.delete_plane_record(kind, id)
    }
    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.inner.redeem_plane_token(kind, token, expires_at, now)
    }
    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        self.inner.plane_token_live(kind, token, expires_at, now)
    }
}

fn populated() -> (RecordSlots, Vec<JournalRecord>) {
    let slots = RecordSlots::new();
    let mut sealed = Sealed::new();
    for index in 0..300 {
        // Genuine sealed audit payloads saturate the new 4096-row probe as well as
        // the old 256-row descendants; no fabricated journal filler is inserted.
        let mut inputs = crate::root::durability::audit::tests::inputs(sealed.audit.next_seq());
        inputs.wall = START + index;
        inputs.what.destination = Some("x".repeat(8_192));
        let audit = sealed.audit.seal(
            inputs,
            &busbar_kernel::teller::verb_audit_pass(&crate::root::kernel::new_kernel()),
        );
        sealed.append(crate::root::durability::audit_entry(&audit).unwrap());
    }
    for record in &sealed.records {
        let bytes = record.encode();
        let chunks: Vec<_> = bytes.chunks(PART_BYTES).collect();
        for (index, chunk) in chunks.iter().enumerate() {
            let mut value = (chunks.len() as u16).to_be_bytes().to_vec();
            value.extend_from_slice(chunk);
            slots.put_row(
                JOURNAL_SCHEMA,
                &part_key(record.node, record.node_seq, index as u16),
                &value,
            );
        }
    }
    let lower_prefix = part_key(NODE, 1, 0)[..15].to_vec();
    for prefix in [NODE.to_be_bytes().to_vec(), lower_prefix] {
        assert_eq!(
            wait_for(slots.record_scan(JOURNAL_SCHEMA, &prefix, 4096))
                .unwrap()
                .len(),
            4096,
            "the actual Store must saturate even the probe above the targeted window"
        );
    }
    (slots, sealed.records)
}

#[test]
fn prefetched_pages_overlap_within_the_bound_and_preserve_nested_prefix_lexical_records() {
    let (slots, expected) = populated();
    let view = ScanView::new(&slots, ScanMode::Healthy);
    let mut observed = Vec::new();
    fold_stored_records(&view, NODE, NODE.to_be_bytes().to_vec(), |record| {
        observed.push(record);
        Ok(())
    })
    .unwrap();
    assert!(
        view.peak.load(Ordering::SeqCst) > 4,
        "the one-poll boundary exercises overlap beyond the prior four-page window"
    );
    assert!(view.peak.load(Ordering::SeqCst) <= 16);
    assert_eq!(view.active.load(Ordering::SeqCst), 0);
    assert_eq!(
        observed,
        expected.iter().map(raw).collect::<Vec<_>>(),
        "nested saturated prefixes must yield each sealed record once, in key order"
    );
}

#[test]
fn typed_low_read_budget_retries_fresh_serial_before_visiting_window_records() {
    let (slots, expected) = populated();
    let view = ScanView::new(&slots, ScanMode::BudgetOne);
    let mut observed = Vec::new();
    fold_stored_records(&view, NODE, NODE.to_be_bytes().to_vec(), |record| {
        assert_eq!(
            view.active.load(Ordering::SeqCst),
            0,
            "the prefetch window is drained before its serial retry reaches a visitor"
        );
        observed.push(record);
        Ok(())
    })
    .unwrap();
    assert!(view.overloaded.load(Ordering::SeqCst) > 0);
    let first_child = [NODE.to_be_bytes().as_slice(), &[0]].concat();
    let refused_child = [NODE.to_be_bytes().as_slice(), &[1]].concat();
    assert_eq!(
        view.starts_for(&first_child),
        1,
        "the successful answer is retained rather than replaced during budget fallback"
    );
    assert!(
        view.starts_for(&refused_child) >= 2,
        "only the typed-overloaded prefix is retried fresh and serially"
    );
    assert_eq!(observed, expected.iter().map(raw).collect::<Vec<_>>());
}

#[test]
fn faults_malformed_pages_and_nonbudget_refusals_cannot_hide_behind_budget_fallback() {
    let (slots, _) = populated();
    for mode in [
        ScanMode::FaultAndBudget,
        ScanMode::MalformedAndBudget,
        ScanMode::Refused,
        ScanMode::Failed,
    ] {
        let view = ScanView::new(&slots, mode);
        let result = fold_stored_records(&view, NODE, NODE.to_be_bytes().to_vec(), |_| Ok(()));
        assert!(result.is_err());
        let first_child = [NODE.to_be_bytes().as_slice(), &[0]].concat();
        assert_eq!(
            view.starts_for(&first_child),
            1,
            "a faulty window cannot be relabeled as budget-only and restarted"
        );
        if matches!(
            mode,
            ScanMode::FaultAndBudget | ScanMode::MalformedAndBudget
        ) {
            assert!(
                view.overloaded.load(Ordering::SeqCst) > 0,
                "the same window also reports the typed concurrency refusal"
            );
        }
        assert_eq!(view.active.load(Ordering::SeqCst), 0);
    }
    // Begin at the saturated prefix immediately above record sequences 0..255,
    // so one bounded page window contains both the transient invalid successful
    // answer for record 1 and an overloaded answer for record 2.
    let view = ScanView::new(&slots, ScanMode::TransientCountAndBudget);
    let prefix = part_key(NODE, 1, 0)[..15].to_vec();
    assert!(fold_stored_records(&view, NODE, prefix, |_| Ok(())).is_err(),
        "retrying an overloaded peer must not replace and hide the successful page's invalid part count");
    assert!(view.overloaded.load(Ordering::SeqCst) > 0);
    assert_eq!(view.starts_for(&part_key(NODE, 1, 0)[..16]), 1);
}

#[test]
fn prefetched_full_chain_verification_still_checks_the_last_sealed_record() {
    let (slots, expected) = populated();
    let view = ScanView::new(&slots, ScanMode::Healthy);
    verify_stored_chain(&view, NODE).unwrap();
    let tail = expected.last().unwrap();
    slots.corrupt(JOURNAL_SCHEMA, &part_key(NODE, tail.node_seq, 0));
    assert!(
        verify_stored_chain(&view, NODE).is_err(),
        "a previously valid scan cannot hide later tail corruption"
    );
}
