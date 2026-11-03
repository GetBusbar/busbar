use super::*;
use crate::root::store_double::RecordSlots;

const WAIT: Duration = Duration::from_secs(5);

struct ReleaseTransaction(Option<std::sync::mpsc::Sender<()>>);

impl ReleaseTransaction {
    fn release(mut self) {
        if let Some(send) = self.0.take() {
            let _ = send.send(());
        }
    }
}

impl Drop for ReleaseTransaction {
    fn drop(&mut self) {
        if let Some(send) = self.0.take() {
            let _ = send.send(());
        }
    }
}

fn gate_transaction(
    slots: &RecordSlots,
    selected: impl Fn(&busbar_contract::abi::sdk::store::conditional::Request) -> bool
        + Send
        + Sync
        + 'static,
) -> (
    std::sync::mpsc::Receiver<busbar_contract::abi::sdk::store::conditional::Request>,
    ReleaseTransaction,
) {
    let (arrived, receive) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let released = Mutex::new(released);
    let first = AtomicBool::new(true);
    slots.on_transaction(move |request| {
        if selected(request) && first.swap(false, Ordering::AcqRel) {
            arrived
                .send(request.clone())
                .expect("the test receives the crossing");
            released
                .lock()
                .unwrap()
                .recv_timeout(WAIT)
                .expect("the test releases the crossing");
        }
        None
    });
    (receive, ReleaseTransaction(Some(release)))
}

fn record(node: u64, seq: u64, len: usize) -> Record {
    Record::new(
        node,
        seq,
        (0..len).map(|i| (i % 251) as u8).collect::<Vec<u8>>(),
    )
}

#[test]
fn what_the_store_kept_reads_back_whole_and_in_order() {
    let slots = RecordSlots::new();
    let lane = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    let mut shipper = lane.shipper();
    let mine: Vec<Record> = (1..=300)
        .map(|seq| record(9, seq, if seq % 7 == 0 { 3 * PART_BYTES + 5 } else { 40 }))
        .collect();
    shipper.ship(&mine).expect("the lane has room");
    shipper
        .ship(&[record(8, 1, 10)])
        .expect("another node's record");
    assert!(lane.drain(WAIT), "the store took everything");
    assert_eq!(lane.pending(), 0);

    let back = read_chain(slots.calls().as_ref(), 9).expect("the store reads back");
    assert_eq!(
        back, mine,
        "the chain the store kept, whole, in order, this node's only"
    );
}

#[test]
fn a_refused_record_is_retained_and_lands_once_the_store_recovers() {
    let slots = RecordSlots::new();
    slots.refuse(true);
    let lane = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    let mut shipper = lane.shipper();
    shipper
        .ship(&[record(3, 1, 10), record(3, 2, 10)])
        .expect("a refusing store does not refuse the hand-off: the lane has room");

    let refused = lane
        .wait_acked(3, 2, WAIT)
        .expect_err("the store refused, and the waiter is told");
    assert!(
        refused.contains("the test store refuses writes"),
        "the store's own reason: {refused}"
    );
    assert!(lane.healthy().is_err(), "a durable verb refuses meanwhile");
    assert_eq!(lane.pending(), 2, "nothing was dropped");
    assert_eq!(slots.rows_under(JOURNAL_SCHEMA), 0);

    slots.refuse(false);
    lane.wait_acked(3, 2, WAIT)
        .expect("re-offered, and taken once the store recovers");
    assert!(lane.healthy().is_ok());
    assert_eq!(
        read_chain(slots.calls().as_ref(), 3)
            .expect("reads back")
            .len(),
        2,
        "both records are kept, once each"
    );
}

#[test]
fn a_full_lane_refuses_money_with_its_reason_and_drops_nothing() {
    let slots = RecordSlots::new();
    slots.refuse(true);
    let lane = JournalLane::with_capacity(slots.calls(), "test-store", 2).expect("the lane starts");
    let mut shipper = lane.shipper();
    assert!(lane.refuses_money().is_none(), "an empty lane admits");
    shipper
        .ship(&[record(4, 1, 10), record(4, 2, 10)])
        .expect("two fit");
    let why = lane
        .refuses_money()
        .expect("a full lane refuses new money-bearing work");
    assert!(
        why.contains("`test-store`") && why.contains("2 records await"),
        "the reason names the store and what waits: {why}"
    );
    assert!(
        shipper.ship(&[record(4, 3, 10)]).is_err(),
        "the next batch is turned away, to be retained by the journal"
    );
    assert_eq!(lane.pending(), 2, "what the lane holds is never dropped");

    slots.refuse(false);
    assert!(lane.drain(WAIT), "the store takes what waited");
    shipper
        .ship(&[record(4, 3, 10)])
        .expect("the retained batch is taken on its re-offer");
    assert!(lane.drain(WAIT));
    assert!(lane.refuses_money().is_none(), "the node admits again");
    assert_eq!(
        read_chain(slots.calls().as_ref(), 4)
            .expect("reads back")
            .len(),
        3
    );
}

#[test]
fn a_lane_releases_the_lease_it_holds_and_another_lane_keeps_its_own() {
    use super::super::store_identity::{lease_row, set_lease_expiry, LEASE_REFRESH_TICKS};
    use crate::root::durability::take_node;
    let slots = RecordSlots::new();
    let calls = slots.calls();
    let lane = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    let other = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    let (a, b) = ("host-lane-a", "host-lane-b");
    let first = take_node(calls.as_ref(), a).expect("an identity");
    let kept = take_node(calls.as_ref(), b).expect("an identity");
    lane.hold_lease(first.lease.expect("the first boot holds the name's lease"));
    other.hold_lease(kept.lease.expect("the first boot holds the name's lease"));
    let (holder_a, _) = lease_row(calls.as_ref(), a).expect("a's lease is in the store");
    let (holder_b, _) = lease_row(calls.as_ref(), b).expect("b's lease is in the store");

    set_lease_expiry(calls.as_ref(), b, 1);
    for _ in 1..LEASE_REFRESH_TICKS {
        other.refresh_held_lease();
        assert_eq!(
            lease_row(calls.as_ref(), b),
            Some((holder_b, 1)),
            "a tick before the refresh tick wrote the lease"
        );
    }
    other.refresh_held_lease();
    let (holder, expires) = lease_row(calls.as_ref(), b).expect("b's lease is in the store");
    assert_eq!(holder, holder_b, "the refresh keeps the holder");
    assert!(
        expires > 1,
        "the refresh tick wrote the lease a fresh expiry"
    );

    lane.release_held_lease();
    assert_eq!(
        lease_row(calls.as_ref(), a),
        Some((holder_a, 0)),
        "the released lane's lease is released in the store"
    );
    for _ in 0..LEASE_REFRESH_TICKS {
        lane.refresh_held_lease();
    }
    assert_eq!(
        lease_row(calls.as_ref(), a),
        Some((holder_a, 0)),
        "a released lane's tick refreshed a lease it no longer holds"
    );

    assert_eq!(
        lease_row(calls.as_ref(), b),
        Some((holder_b, expires)),
        "the other lane's lease moved with the first lane's release"
    );
    set_lease_expiry(calls.as_ref(), b, 1);
    for _ in 0..LEASE_REFRESH_TICKS {
        other.refresh_held_lease();
    }
    let (holder, again) = lease_row(calls.as_ref(), b).expect("b's lease is in the store");
    assert_eq!(holder, holder_b, "the other lane still holds its lease");
    assert!(again > 1, "the other lane still refreshes its lease");
}

#[test]
fn a_retained_batch_larger_than_the_lane_is_taken_once_the_lane_is_empty() {
    let slots = RecordSlots::new();
    slots.refuse(true);
    let lane = JournalLane::with_capacity(slots.calls(), "test-store", 2).expect("the lane starts");
    let mut shipper = lane.shipper();
    shipper.ship(&[record(5, 1, 10)]).expect("one fits");
    let retained: Vec<Record> = (2..=6).map(|seq| record(5, seq, 10)).collect();
    assert!(
        shipper.ship(&retained).is_err(),
        "beside what waits, a batch over the bound is turned away, to be retained by the journal"
    );
    assert_eq!(lane.pending(), 1, "what the lane holds is never dropped");
    assert!(
        lane.refuses_money().is_some(),
        "the node fails closed meanwhile"
    );

    slots.refuse(false);
    assert!(lane.drain(WAIT), "the store takes what waited");
    shipper
        .ship(&retained)
        .expect("the empty lane takes the retained batch whole, however large");
    assert!(lane.drain(WAIT), "the store takes the retained batch");
    assert!(lane.refuses_money().is_none(), "the node admits again");
    assert_eq!(
        read_chain(slots.calls().as_ref(), 5)
            .expect("reads back")
            .len(),
        6,
        "every record reached the store, once"
    );
}

#[test]
fn a_delayed_old_journal_writer_cannot_overwrite_the_successors_same_position() {
    use super::super::store_identity::{lease_row, set_lease_expiry};
    use crate::root::durability::take_node;

    let slots = RecordSlots::new();
    let calls = slots.calls();
    let host = "fenced-pending-journal";
    let first = take_node(calls.as_ref(), host).expect("A takes the host identity");
    let node = first.id;
    let old_lease = first.lease.expect("A holds the host lease");
    let lane_a = JournalLane::start(slots.calls(), "test-store").unwrap();
    lane_a.hold_lease(old_lease.clone());
    let mut shipper_a = lane_a.shipper();
    let old = record(node, 1, 19);
    let old_part = parts_of(&old).unwrap()[0].as_slice().to_vec();
    let (crossing, release) = gate_transaction(&slots, move |request| {
        request.mutations.iter().any(|mutation| matches!(mutation,
            Mutation::Put { schema, value, .. } if schema == JOURNAL_SCHEMA && value.as_slice() == old_part.as_slice()))
    });
    shipper_a
        .ship(std::slice::from_ref(&old))
        .expect("A hands off its accepted record");
    let held = crossing.recv_timeout(WAIT).expect("A reached its part CAS");
    assert_eq!(
        held.predicates.len(),
        1,
        "ownership and the part share one transaction"
    );
    assert_eq!(lane_a.pending(), 1);

    set_lease_expiry(calls.as_ref(), host, 1);
    let successor = take_node(calls.as_ref(), host).expect("B takes the expired host lease");
    assert_eq!(
        successor.id, node,
        "B resumes this host's stable journal identity"
    );
    let lease_b = successor.lease.expect("B holds the replacement lease");
    let lane_b = JournalLane::start(slots.calls(), "test-store").unwrap();
    lane_b.hold_lease(lease_b);
    let mut shipper_b = lane_b.shipper();
    let replacement = record(node, 1, 37);
    shipper_b
        .ship(std::slice::from_ref(&replacement))
        .expect("B writes the same position");
    lane_b
        .wait_acked(node, 1, WAIT)
        .expect("B's exact replacement is kept");
    let held_b = lease_row(calls.as_ref(), host).expect("B's lease is stored");
    assert_eq!(
        read_chain(calls.as_ref(), node).unwrap(),
        vec![replacement.clone()]
    );

    release.release();
    let refused = lane_a
        .wait_acked(node, 1, WAIT)
        .expect_err("A no longer owns its predicate");
    assert!(
        refused.contains("no longer owns"),
        "the ownership refusal, not a timeout: {refused}"
    );
    assert!(
        lane_a.refuses_money().is_some(),
        "the stale node fails closed"
    );
    assert!(lane_a.healthy().is_err());
    assert_eq!(
        lane_a.pending(),
        1,
        "its accepted record remains owned and retained"
    );
    assert_eq!(
        lane_a.queued(),
        vec![old],
        "the exact accepted bytes stay in custody"
    );
    assert!(
        shipper_a.ship(&[record(node, 2, 1)]).is_err(),
        "a fenced lane accepts no new batch"
    );
    assert_eq!(read_chain(calls.as_ref(), node).unwrap(), vec![replacement]);
    assert!(!old_lease.refresh(calls.as_ref()).unwrap());
    old_lease.release(calls.as_ref()).unwrap();
    assert_eq!(
        lease_row(calls.as_ref(), host),
        Some(held_b),
        "old lease methods cannot alter B"
    );
    lane_a.release_held_lease();
    assert_eq!(
        lease_row(calls.as_ref(), host),
        Some(held_b),
        "an undrained stale lane cannot release B"
    );
    lane_b.release_held_lease();
}

#[test]
fn a_stale_lease_renewal_or_release_cannot_change_a_taken_over_lease() {
    use super::super::store_identity::{lease_row, set_lease_expiry};
    use crate::root::durability::take_node;

    for releasing in [false, true] {
        let slots = RecordSlots::new();
        let calls = slots.calls();
        let host = if releasing {
            "stale-release"
        } else {
            "stale-refresh"
        };
        let first = take_node(calls.as_ref(), host).unwrap();
        let node = first.id;
        let lease = first.lease.unwrap();
        let holder_a = lease_row(calls.as_ref(), host).unwrap().0;
        let (crossing, release) = gate_transaction(&slots, move |request| {
            request.mutations.iter().any(|mutation| {
                matches!(mutation,
                Mutation::Put { value, .. } if value.len() == 24 && value[..16] == holder_a
                    && (value[16..] == 0u64.to_be_bytes()) == releasing)
            })
        });
        let work_calls = slots.calls();
        let (settled, outcome) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = if releasing {
                lease.release(work_calls.as_ref()).map(|()| false)
            } else {
                lease.refresh(work_calls.as_ref())
            };
            let _ = settled.send(result);
        });
        crossing
            .recv_timeout(WAIT)
            .expect("A prepared its old ownership transition");
        set_lease_expiry(calls.as_ref(), host, 1);
        let successor = take_node(calls.as_ref(), host).expect("B takes the expired row");
        assert_eq!(successor.id, node);
        let held_b = lease_row(calls.as_ref(), host).unwrap();
        assert_ne!(held_b.0, holder_a);
        release.release();
        assert!(
            !outcome
                .recv_timeout(WAIT)
                .expect("the old ownership decision completes")
                .unwrap(),
            "stale renewal is refused and stale release is a no-op"
        );
        worker.join().unwrap();
        assert_eq!(lease_row(calls.as_ref(), host), Some(held_b));
        successor.lease.unwrap().release(calls.as_ref()).unwrap();
    }
}

#[test]
fn a_lane_releases_its_host_lease_only_after_the_pending_writer_drains_and_retires() {
    use super::super::store_identity::lease_row;
    use crate::root::durability::take_node;

    let slots = RecordSlots::new();
    let calls = slots.calls();
    let host = "release-pending-writer";
    let taken = take_node(calls.as_ref(), host).unwrap();
    let node = taken.id;
    let lane = JournalLane::start(slots.calls(), "test-store").unwrap();
    lane.hold_lease(taken.lease.unwrap());
    let held = lease_row(calls.as_ref(), host).unwrap();
    let mut shipper = lane.shipper();
    let (crossing, release) = gate_transaction(&slots, |request| {
        request.mutations.iter().any(|mutation| {
            matches!(mutation,
            Mutation::Put { schema, .. } if schema == JOURNAL_SCHEMA)
        })
    });
    shipper.ship(&[record(node, 1, 13)]).unwrap();
    crossing
        .recv_timeout(WAIT)
        .expect("the accepted write is in the Store crossing");
    lane.release_held_lease();
    assert_eq!(
        lease_row(calls.as_ref(), host),
        Some(held),
        "pending publication keeps the lease"
    );
    assert_eq!(lane.pending(), 1);
    shipper
        .ship(&[record(node, 2, 17)])
        .expect("an attempted early release did not retire the active writer");
    release.release();
    lane.wait_acked(node, 2, WAIT)
        .expect("both accepted records landed");
    assert!(lane.drain(WAIT));
    lane.release_held_lease();
    assert_eq!(lease_row(calls.as_ref(), host), Some((held.0, 0)));
    assert!(
        lane.refuses_money().is_some(),
        "retirement closes admission"
    );
    assert!(
        shipper.ship(&[record(node, 3, 1)]).is_err(),
        "an old shipper cannot publish after lease release"
    );
    assert_eq!(lane.pending(), 0);
    let successor = take_node(calls.as_ref(), host).unwrap();
    assert_eq!(successor.id, node);
    assert_eq!(
        read_chain(calls.as_ref(), node).unwrap(),
        vec![record(node, 1, 13), record(node, 2, 17)]
    );
    successor.lease.unwrap().release(calls.as_ref()).unwrap();
}

// Probe controls use rows from the existing Store double; only read-boundary selection or a named
// refusal is injected. They inspect traversal directly, without inventing sealed chain data.
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta};
use busbar_contract::store_calls::{StoreCall, StoreFailure};

#[derive(Clone, Copy)]
enum ProbeMode {
    Healthy,
    HighSubset,
    Malformed,
    Overloaded,
}
struct ProbeView {
    inner: Arc<dyn StoreCalls>,
    mode: ProbeMode,
    starts: Mutex<Vec<(Vec<u8>, u32)>>,
    epoch_stores: Vec<Arc<dyn StoreCalls>>,
}
impl ProbeView {
    fn new(slots: &RecordSlots, mode: ProbeMode) -> Self {
        Self {
            inner: slots.calls(),
            mode,
            starts: Mutex::new(Vec::new()),
            epoch_stores: Vec::new(),
        }
    }
}
impl StoreCalls for ProbeView {
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
            let index = {
                let mut starts = self.starts.lock().unwrap();
                let index = starts.len();
                starts.push((prefix.to_vec(), limit));
                index
            };
            if !self.epoch_stores.is_empty() {
                assert_eq!(prefix.len(), 8);
                assert_eq!(limit, JOURNAL_PROBE_ROWS);
                return self.epoch_stores[index.min(self.epoch_stores.len() - 1)]
                    .record_scan(schema, prefix, limit)
                    .await;
            }
            if limit == JOURNAL_PROBE_ROWS {
                match self.mode {
                    ProbeMode::Overloaded => return Err(StoreFailure::Overloaded),
                    ProbeMode::HighSubset => {
                        let mut rows = self.inner.record_scan(schema, prefix, limit + 1).await?;
                        assert_eq!(rows.len(), limit as usize + 1);
                        rows.remove(0);
                        return Ok(rows);
                    }
                    ProbeMode::Malformed => {
                        let mut rows = self.inner.record_scan(schema, prefix, limit).await?;
                        assert_eq!(rows.len(), limit as usize);
                        rows[0].1 = RecordBytes::new(vec![0, 0]).unwrap();
                        return Ok(rows);
                    }
                    ProbeMode::Healthy => {}
                }
            }
            self.inner.record_scan(schema, prefix, limit).await
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

fn probe_rows(count: u64) -> RecordSlots {
    let slots = RecordSlots::new();
    for sequence in 1..=count {
        slots.put_row(JOURNAL_SCHEMA, &part_key(9, sequence, 0), &[0, 1, 42]);
    }
    slots
}

#[test]
fn complete_probe_consumes_one_unsaturated_answer_without_descending() {
    let slots = probe_rows(10);
    let view = ProbeView::new(&slots, ProbeMode::Healthy);
    let prefix = 9u64.to_be_bytes().to_vec();
    let mut keys = Vec::new();
    visit_journal_pages(&view, prefix.clone(), |page| {
        keys.extend(page.into_iter().map(|(key, _)| key));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        keys,
        (1..=10)
            .map(|sequence| part_key(9, sequence, 0).to_vec())
            .collect::<Vec<_>>()
    );
    assert_eq!(*view.starts.lock().unwrap(), vec![(prefix, 4096)]);
}

#[test]
fn exactly_saturated_probe_descends_through_every_nested_saturated_prefix() {
    let slots = probe_rows(4096);
    let view = ProbeView::new(&slots, ProbeMode::Healthy);
    let mut keys = Vec::new();
    visit_journal_pages(&view, 9u64.to_be_bytes().to_vec(), |page| {
        keys.extend(page.into_iter().map(|(key, _)| key));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        keys,
        (1..=4096)
            .map(|sequence| part_key(9, sequence, 0).to_vec())
            .collect::<Vec<_>>()
    );
    let starts = view.starts.lock().unwrap();
    assert_eq!(starts[0].1, 4096);
    assert!(
        starts
            .iter()
            .any(|(prefix, limit)| prefix.len() == 16 && *limit == 256),
        "a saturated deeper prefix must reach the exact record prefixes"
    );
}

#[test]
fn saturated_high_key_subset_cannot_hide_a_corrupt_unreturned_child() {
    let slots = probe_rows(4097);
    slots.put_row(JOURNAL_SCHEMA, &part_key(9, 1, 0), &[0, 0]);
    let view = ProbeView::new(&slots, ProbeMode::HighSubset);
    let result = visit_journal_pages(&view, 9u64.to_be_bytes().to_vec(), |_| Ok(()));
    assert!(result.unwrap_err().contains("invalid journal part count"));
    let starts = view.starts.lock().unwrap();
    assert_eq!(starts[0].1, 4096);
    assert!(
        starts.len() > 1,
        "valid saturated high-key parent must be discarded before children expose corruption"
    );
}

#[test]
fn malformed_saturated_probe_fails_before_any_descent() {
    let slots = probe_rows(4096);
    let view = ProbeView::new(&slots, ProbeMode::Malformed);
    let mut visited = false;
    let result = visit_journal_pages(&view, 9u64.to_be_bytes().to_vec(), |_| {
        visited = true;
        Ok(())
    });
    assert!(result.unwrap_err().contains("invalid journal part count"));
    assert!(!visited);
    assert_eq!(view.starts.lock().unwrap().len(), 1);
}

#[test]
fn overloaded_probe_preserves_the_exhaustive_small_page_fallback() {
    let slots = probe_rows(300);
    let view = ProbeView::new(&slots, ProbeMode::Overloaded);
    let mut keys = Vec::new();
    visit_journal_pages(&view, 9u64.to_be_bytes().to_vec(), |page| {
        keys.extend(page.into_iter().map(|(key, _)| key));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        keys,
        (1..=300)
            .map(|sequence| part_key(9, sequence, 0).to_vec())
            .collect::<Vec<_>>()
    );
    let starts = view.starts.lock().unwrap();
    assert_eq!(starts[0].1, 4096);
    assert!(starts[1..].iter().all(|(_, limit)| *limit == 256));
    assert!(starts.iter().any(|(prefix, _)| prefix.len() == 16));
}

fn proof_records(changed: Option<usize>) -> Vec<JournalRecord> {
    let mut journal = busbar_kernel_wal::Journal::memory_buffered_to(
        9,
        Box::new(busbar_kernel_wal::NullShipper::new()),
        || 1,
    );
    let entries: Vec<_> = (0..6)
        .map(|index| {
            busbar_kernel_wal::Entry::new(
                RecordClass::Transaction,
                vec![if changed == Some(index) {
                    99
                } else {
                    index as u8
                }],
            )
        })
        .collect();
    let token = busbar_kernel::teller::Kernel::new().durability_token();
    journal
        .append(&token, busbar_contract::caps::StepName::Meter, &entries)
        .unwrap()
        .sealed
}

fn proof_store(records: &[JournalRecord], omit: &[u64]) -> RecordSlots {
    let slots = RecordSlots::new();
    for record in records
        .iter()
        .filter(|record| !omit.contains(&record.node_seq))
    {
        let raw = Record::new(record.node, record.node_seq, record.encode());
        for (part, value) in parts_of(&raw).unwrap().into_iter().enumerate() {
            slots.put_row(
                JOURNAL_SCHEMA,
                &part_key(record.node, record.node_seq, part as u16),
                value.as_slice(),
            );
        }
    }
    slots
}

fn proof_epochs(stores: &[&RecordSlots]) -> ProbeView {
    let mut view = ProbeView::new(stores[0], ProbeMode::Healthy);
    view.epoch_stores = stores.iter().map(|store| store.calls()).collect();
    view
}

#[test]
fn sealed_proof_retries_one_gap_and_retains_original_requested_seals() {
    let records = proof_records(None);
    let complete = proof_store(&records, &[]);
    let mixed = proof_store(&records, &[3]);
    let view = proof_epochs(&[&mixed, &mixed, &complete]);
    let seals = [RecordSeal::of(&records[0]), RecordSeal::of(&records[5])];
    verify_stored_chain_with_seals(&view, 9, &seals).unwrap();
    assert_eq!(
        view.starts.lock().unwrap().len(),
        3,
        "one mixed fold, its quarantine-authority scan, and one complete fresh proof"
    );
}

#[test]
fn cold_proof_does_not_acquire_a_gap_retry_budget() {
    let records = proof_records(None);
    let complete = proof_store(&records, &[]);
    let mixed = proof_store(&records, &[3]);
    let view = proof_epochs(&[&mixed, &mixed, &complete]);
    assert!(verify_stored_chain(&view, 9).is_err());
    assert_eq!(
        view.starts.lock().unwrap().len(),
        2,
        "cold proof ends after its original fold and bridge-authority scan"
    );
}

#[test]
fn torn_or_malformed_gap_observations_cannot_heal_on_reread() {
    let records = proof_records(None);
    let complete = proof_store(&records, &[]);
    for count in [0u16, 2] {
        let broken = proof_store(&records, &[]);
        let mut value = count.to_be_bytes().to_vec();
        value.extend_from_slice(&records[2].encode());
        broken.put_row(JOURNAL_SCHEMA, &part_key(9, 3, 0), &value);
        let view = proof_epochs(&[&broken, &complete]);
        assert!(verify_stored_chain_with_seals(&view, 9, &[]).is_err());
        assert!(
            view.starts.lock().unwrap().len() <= 2,
            "a fatal part envelope or torn omitted record must not start a fresh proof"
        );
    }
}

#[test]
fn canonical_consecutive_hash_mismatch_is_fatal_without_retry() {
    let records = proof_records(None);
    let changed = proof_records(Some(0));
    let mut mismatched = records.clone();
    mismatched[0] = changed[0].clone();
    let broken = proof_store(&mismatched, &[]);
    let complete = proof_store(&records, &[]);
    let view = proof_epochs(&[&broken, &complete]);
    assert!(verify_stored_chain_with_seals(&view, 9, &[]).is_err());
    assert_eq!(
        view.starts.lock().unwrap().len(),
        2,
        "consecutive canonical records with a hash mismatch permit only bridge lookup"
    );
}

#[test]
fn fresh_proof_cannot_change_or_omit_original_gap_boundaries_prefix_or_tail() {
    let records = proof_records(None);
    let mixed = proof_store(&records, &[3]);
    for index in [0usize, 1, 3, 5] {
        let changed = proof_records(Some(index));
        let replacement = proof_store(&changed, &[]);
        let view = proof_epochs(&[&mixed, &mixed, &replacement]);
        assert!(
            verify_stored_chain_with_seals(&view, 9, &[]).is_err(),
            "changed original prefix/boundary/tail at index {index} must fail"
        );
        assert_eq!(view.starts.lock().unwrap().len(), 3);
    }
    for omitted in [vec![4], vec![6]] {
        let replacement = proof_store(&records, &omitted);
        let view = proof_epochs(&[&mixed, &mixed, &replacement]);
        assert!(
            verify_stored_chain_with_seals(&view, 9, &[]).is_err(),
            "missing original boundary/tail must fail"
        );
    }
}

#[test]
fn a_second_mixed_gap_exhausts_the_whole_proof_budget() {
    let records = proof_records(None);
    let first = proof_store(&records, &[3]);
    let second = proof_store(&records, &[5]);
    let complete = proof_store(&records, &[]);
    let view = proof_epochs(&[&first, &first, &second, &second, &complete]);
    assert!(verify_stored_chain_with_seals(&view, 9, &[]).is_err());
    assert_eq!(
        view.starts.lock().unwrap().len(),
        4,
        "the fresh proof's gap may inspect quarantine authority but never restart again"
    );
}

#[test]
fn missing_or_changed_requested_seals_never_authorize_retry() {
    let records = proof_records(None);
    let complete = proof_store(&records, &[]);
    let mixed = proof_store(&records, &[3]);
    let view = proof_epochs(&[&mixed, &mixed, &complete]);
    assert!(verify_stored_chain_with_seals(&view, 9, &[RecordSeal::of(&records[2])]).is_err());
    assert_eq!(view.starts.lock().unwrap().len(), 2);
    let view = proof_epochs(&[&complete]);
    let mut seal = RecordSeal::of(&records[0]);
    seal.hash[0] ^= 1;
    assert!(verify_stored_chain_with_seals(&view, 9, &[seal]).is_err());
    assert_eq!(view.starts.lock().unwrap().len(), 1);
}
