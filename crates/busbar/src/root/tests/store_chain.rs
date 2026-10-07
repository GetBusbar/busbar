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
    let lane = JournalLane::start(slots.calls(), "memory").expect("the lane starts");
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
    let lane = JournalLane::start(slots.calls(), "memory").expect("the lane starts");
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
    let lane = JournalLane::with_capacity(slots.calls(), "memory", 2).expect("the lane starts");
    let mut shipper = lane.shipper();
    assert!(lane.refuses_money().is_none(), "an empty lane admits");
    shipper
        .ship(&[record(4, 1, 10), record(4, 2, 10)])
        .expect("two fit");
    let why = lane
        .refuses_money()
        .expect("a full lane refuses new money-bearing work");
    assert!(
        why.contains("`memory`") && why.contains("2 records await"),
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
