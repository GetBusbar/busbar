use super::LeaseTick;
use crate::root::durability::{
    build_on_store, read_chain, Durability, DurabilityConfig, JournalLane,
};
use crate::root::plane_node::Node;
use crate::root::store_double::RecordSlots;
use busbar_contract::caps::StepName;
use busbar_kernel_wal::{Entry, RecordClass};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(5);

struct PausedStore(RecordSlots);

impl PausedStore {
    fn new(slots: &RecordSlots) -> Self {
        slots.pause(true);
        Self(slots.clone())
    }
}

impl Drop for PausedStore {
    fn drop(&mut self) {
        self.0.pause(false);
    }
}

fn fixture(node_id: u64) -> (RecordSlots, Arc<Mutex<Durability>>, JournalLane, LeaseTick) {
    let slots = RecordSlots::new();
    let lane = JournalLane::with_capacity(slots.calls(), "live-retry-store", 2).unwrap();
    let book = Arc::new(Mutex::new(
        build_on_store(
            &DurabilityConfig { data_dir: None },
            node_id,
            lane.clone(),
            None,
        )
        .unwrap(),
    ));
    let node = Arc::new(Node::new());
    node.bind_book(Arc::clone(&book));
    (slots, book, lane, LeaseTick { node })
}

fn pressure(book: &Mutex<Durability>) {
    let token = busbar_kernel::teller::Kernel::new().durability_token();
    let mut book = book.lock().unwrap();
    for index in 0..3 {
        let appended = book.journal.append(
            &token,
            StepName::Meter,
            &[Entry::new(RecordClass::Load, vec![index])],
        );
        assert_eq!(appended.is_ok(), index < 2);
    }
    assert_eq!(
        book.journal.buffered(),
        1,
        "the third record stays in the WAL"
    );
    assert_eq!(book.journal.dropped_total(), 0);
}

fn assert_three_once(slots: &RecordSlots, node: u64) {
    let records = read_chain(slots.calls().as_ref(), node).unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(
        records
            .iter()
            .map(|record| record.node_seq)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    let journal = busbar_kernel_wal::decode_run(&records).unwrap();
    busbar_kernel_wal::verify_journal(&journal).unwrap();
    assert_eq!(
        journal
            .iter()
            .map(|record| record.body.clone())
            .collect::<Vec<_>>(),
        vec![vec![0], vec![1], vec![2]]
    );
}

#[test]
fn live_tick_reopens_admission_after_store_pressure_without_another_unit() {
    let (slots, book, lane, tick) = fixture(871);
    let paused = PausedStore::new(&slots);
    pressure(&book);
    assert!(tick.node.journal_refusal().is_some());

    tick.tick();
    assert_eq!(lane.pending(), 2);
    assert_eq!(book.lock().unwrap().journal.buffered(), 1);
    drop(paused);
    assert!(lane.drain(WAIT));
    assert!(
        tick.node.journal_refusal().is_some(),
        "the original live latch: WAL debt still refuses"
    );
    assert_eq!(read_chain(slots.calls().as_ref(), 871).unwrap().len(), 2);

    tick.tick();
    assert!(lane.drain(WAIT));
    assert!(
        tick.node.journal_refusal().is_none(),
        "the live node admits after recovery"
    );
    assert_eq!(book.lock().unwrap().journal.buffered(), 0);
    for _ in 0..3 {
        tick.tick();
    }
    assert!(lane.drain(WAIT));
    assert_three_once(&slots, 871);
    drop(tick);
    drop(book);
    let restarted = build_on_store(&DurabilityConfig { data_dir: None }, 871, lane, None).unwrap();
    assert_eq!(restarted.journal.next_seq(), 4);
}

#[test]
fn live_tick_does_not_duplicate_a_batch_with_an_unknown_store_commit() {
    let (slots, book, lane, tick) = fixture(872);
    let paused = PausedStore::new(&slots);
    pressure(&book);
    slots.lose_acks(true);
    drop(paused);
    let until = Instant::now() + WAIT;
    while slots.rows_under(crate::root::durability::JOURNAL_SCHEMA) == 0 {
        assert!(
            Instant::now() < until,
            "the Store commits while its acknowledgement is lost"
        );
        std::thread::yield_now();
    }
    for _ in 0..3 {
        tick.tick();
    }
    assert_eq!(
        lane.pending(),
        2,
        "the unknown candidate stays owned by the lane"
    );
    assert_eq!(book.lock().unwrap().journal.buffered(), 1);
    assert!(tick.node.journal_refusal().is_some());
    slots.lose_acks(false);
    assert!(lane.drain(WAIT));
    tick.tick();
    assert!(lane.drain(WAIT));
    assert!(tick.node.journal_refusal().is_none());
    assert_three_once(&slots, 872);
}
