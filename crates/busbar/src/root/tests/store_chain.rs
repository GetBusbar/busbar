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
/// lane holds the lease its boot took on a host name in its store. Driven by hand, one flush tick
/// at a time (no clock, no sleep): a lane's tick refreshes its own lease on every
/// `LEASE_REFRESH_TICKS`-th tick; one lane releasing its lease releases it in the store and its
/// ticks refresh nothing after; another lane of the same process keeps its own lease, held and
/// refreshed.
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

    // THE HELD LEASE IS REFRESHED: marked stale, it is untouched until the lane's
    // `LEASE_REFRESH_TICKS`-th tick, which writes it a fresh expiry under the same holder.
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

    // THE RELEASED LANE'S LEASE IS GONE: released in the store, and its ticks refresh nothing.
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

    // THE OTHER LANE'S LEASE IS STILL HELD: untouched by the first lane's release, and refreshed by
    // its own next refresh tick.
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

/// A RETAINED BATCH LARGER THAN THE LANE IS TAKEN ONCE THE LANE IS EMPTY (audit root r4 B-3;
/// ARCHITECT 2026-10-07 H3 ruling, `store_chain.rs` module docs: a full lane fails closed "until the
/// store takes what is queued. No record is dropped."; BUSBAR-1.6.0.md THE DESIGN §7 l.991-998: the
/// kernel writes exactly what it is told, one sealed line per unit). While the store refuses, the
/// fail-closed node still journals what it may (admin units, checkpoints, accruals), so the batch
/// the journal retains and re-offers outgrows the lane's bound. Beside what waits, that batch is
/// still turned away (the bound holds, the green twin); once the store took everything, the empty
/// lane takes it whole, and the node admits once it drains.
///
/// RED before the fix: the lane took a batch only if it fit beside what waits, so a retained batch
/// over the bound was turned away even by an empty lane: `refuses_money` stayed `Some` for good and
/// the batch, held only in memory, never reached the store.
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
