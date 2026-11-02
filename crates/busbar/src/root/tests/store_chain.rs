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
        .ship(&[old.clone()])
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
        .ship(&[replacement.clone()])
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
