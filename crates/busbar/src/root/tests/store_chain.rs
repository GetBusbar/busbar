//! The journal on the configured store, at the lane: what the store keeps reads back as the chain,
//! a refused record is retained and re-offered until the store takes it, and a full lane refuses
//! with its reason and drops nothing (ARCHITECT 2026-10-07 H3 ruling).

use super::*;
use crate::root::store_double::RecordSlots;

const WAIT: Duration = Duration::from_secs(5);

/// A record of `len` body bytes for `(node, seq)`.
fn record(node: u64, seq: u64, len: usize) -> Record {
    Record::new(
        node,
        seq,
        (0..len).map(|i| (i % 251) as u8).collect::<Vec<u8>>(),
    )
}

/// A record larger than one slot's bound crosses as parts and reads back whole, in chain order, and
/// only this node's records come back.
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

/// A STORE THAT REFUSES keeps the record at the head of the lane: it is offered again until the
/// store takes it, the verb waiting on it is told the store's reason, and nothing behind it lands
/// first.
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

/// A FULL LANE turns the next batch away (the journal retains it) and refuses new money-bearing
/// work with its reason; nothing it holds is dropped, and it clears once the store takes them.
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

/// THE LEASE IS THE LANE'S (row 159; BUSBAR-1.6.0.md Part 0, no process-global static seam): each
/// lane holds the lease its boot took on a host name in its store. One lane releasing its lease
/// frees its name; another lane of the same process keeps its own lease and refreshes it, so a
/// rival boot on that name watches it stay live and takes a fresh id.
#[test]
fn a_lane_releases_the_lease_it_holds_and_another_lane_keeps_its_own() {
    use crate::root::durability::take_node;
    let slots = RecordSlots::new();
    let lane = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    let other = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    let first = take_node(slots.calls().as_ref(), "host-lane-a").expect("an identity");
    let kept = take_node(slots.calls().as_ref(), "host-lane-b").expect("an identity");
    lane.hold_lease(first.lease.expect("the first boot holds the name's lease"));
    other.hold_lease(kept.lease.expect("the first boot holds the name's lease"));
    // The other lane's flush tick, as a running node's serve loop drives it.
    let stop = Arc::new(AtomicBool::new(false));
    let ticking = {
        let (other, stop) = (other.clone(), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                other.refresh_held_lease();
                std::thread::sleep(Duration::from_millis(
                    super::super::store_identity::LEASE_TTL_MS / 27,
                ));
            }
        })
    };
    lane.release_held_lease();
    let again = take_node(slots.calls().as_ref(), "host-lane-a").expect("an identity");
    let rival = take_node(slots.calls().as_ref(), "host-lane-b").expect("an identity");
    stop.store(true, Ordering::Relaxed);
    ticking.join().expect("the tick thread ends");
    assert_eq!(again.id, first.id, "a released lease is taken again");
    assert_ne!(
        rival.id, kept.id,
        "the other lane's lease was released with the first, or not refreshed"
    );
    assert!(rival.lease.is_none(), "a live lease is never shared");
}

/// RED (row 159): NO STATIC HOLDS THE NODE'S LEASE. Before, `store_identity.rs` kept the boot's
/// lease and the store it is held in in a process-wide `static HELD`; it is now kept on the lane
/// the boot hands its book.
#[test]
fn no_static_holds_the_nodes_lease() {
    let held: Vec<&str> = include_str!("../durability/store_identity.rs")
        .lines()
        .map(|line| line.split("//").next().unwrap_or_default())
        .filter(|code| {
            code.contains("static ")
                && ["HELD", "Held", "NodeLease", "StoreCalls", "LEASE_TICKS"]
                    .iter()
                    .any(|name| code.contains(name))
        })
        .collect();
    assert!(held.is_empty(), "a static holds the node's lease: {held:?}");
}
