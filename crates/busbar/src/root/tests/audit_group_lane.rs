// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use crate::root::durability::store_chain::{read_chain, JournalLane};
use crate::root::durability::store_identity::take_node;
use std::sync::Condvar;
use std::time::Duration;

#[derive(Default)]
struct PublicationGate {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}
impl PublicationGate {
    fn enter(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            state = self.changed.wait(state).unwrap();
        }
    }
    fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}
struct ReleaseGate(Arc<PublicationGate>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[test]
fn actual_lane_acknowledges_only_the_whole_published_prefix_and_restarts_without_cleanup() {
    const HOST: &str = "audit-group-lane-restart";
    let slots = RecordSlots::new();
    let taken = take_node(&slots, HOST).unwrap();
    let node = taken.id;
    let lane = JournalLane::with_capacity(slots.calls(), "actual-memory", 32).unwrap();
    lane.hold_lease(taken.lease.unwrap());
    let gate = Arc::new(PublicationGate::default());
    // Created after lane: panic unwinding releases the gate before lane retirement joins it.
    let _release = ReleaseGate(gate.clone());
    let callback = gate.clone();
    slots.on_transaction(move |request| {
        if request.mutations.iter().any(|mutation| matches!(mutation, Mutation::Put { schema, key, .. } if schema == SCHEMA && key == &tip_key(node))) { callback.enter(); }
        None
    });
    let mut sealed = Sealed::for_node(node);
    let records: Vec<_> = (0..3)
        .map(|i| raw(&sealed.audit(START + i * HEAD_SAMPLE_SECONDS)))
        .collect();
    lane.shipper().ship(&records).unwrap();
    {
        let state = gate.state.lock().unwrap();
        let (state, _) = gate
            .changed
            .wait_timeout_while(state, Duration::from_secs(5), |state| !state.0)
            .unwrap();
        assert!(state.0, "the actual final publication reached its gate");
    }
    assert_eq!(lane.pending(), records.len());
    for record in &records {
        assert!(lane
            .wait_acked(node, record.node_seq, Duration::ZERO)
            .is_err());
    }
    gate.release();
    lane.wait_acked(
        node,
        records.last().unwrap().node_seq,
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(lane.pending(), 0);
    for record in &records {
        lane.wait_acked(node, record.node_seq, Duration::ZERO)
            .unwrap();
    }
    slots.on_transaction(|_| None);
    lane.release_held_lease();

    // Reconstruct from actual persisted journal bytes under a freshly taken holder.
    let replay = read_chain(&slots, node).unwrap();
    assert_eq!(replay.len(), records.len());
    for (old, stored) in records.iter().zip(&replay) {
        assert_eq!(old.identity(), stored.identity());
        assert_eq!(old.body, stored.body);
    }
    let taken = take_node(&slots, HOST).unwrap();
    assert_eq!(taken.id, node);
    let restarted = JournalLane::with_capacity(slots.calls(), "actual-memory", 32).unwrap();
    restarted.hold_lease(taken.lease.unwrap());
    let writes = Arc::new(AtomicUsize::new(0));
    let count = writes.clone();
    slots.on_transaction(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        None
    });
    restarted.shipper().ship(&replay).unwrap();
    restarted
        .wait_acked(
            node,
            replay.last().unwrap().node_seq,
            Duration::from_secs(5),
        )
        .unwrap();
    assert_eq!(restarted.pending(), 0);
    assert_eq!(
        writes.load(Ordering::SeqCst),
        0,
        "reconstructed whole-group proof must retire without cleanup or publication"
    );
    slots.on_transaction(|_| None);
    restarted.release_held_lease();
}
