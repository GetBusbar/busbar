// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Retained heads use the Store independently of source-record reconstruction. These tests exercise
//! real conditional requests and restart reads; they do not invent a fixed-audit pruning API.

use super::*;
use crate::root::store_double::RecordSlots;
use busbar_contract::abi::sdk::store::conditional::{Mutation, Request};
use busbar_contract::caps::{DurableWrite, StepName};
use busbar_contract::store_calls::{StoreCalls, StoreFailure};
use busbar_kernel_audit::{Audit as _, AuditChain, AuditSigningKey};
use busbar_kernel_wal::{Entry, Journal, JournalRecord, NullShipper, Record, RecordClass};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const NODE: u64 = 7;
const START: u64 = 1_700_000_000;

struct Sealed {
    audit: AuditChain,
    journal: Journal,
    records: Vec<JournalRecord>,
}

impl Sealed {
    fn new() -> Self {
        Self {
            audit: AuditChain::new()
                .sealing_as(NODE)
                .signing_with(AuditSigningKey::from_seed(&[7; 32])),
            journal: Journal::memory_buffered_to(NODE, Box::new(NullShipper::new()), || START),
            records: Vec::new(),
        }
    }

    fn append(&mut self, entry: Entry) -> JournalRecord {
        self.journal
            .append(
                &busbar_kernel::test_support::tokens::grant::<DurableWrite>(),
                StepName::Audit,
                &[entry],
            )
            .expect("the real memory journal accepts the complete entry");
        self.records = self.journal.replay().unwrap().unwrap();
        self.records.last().unwrap().clone()
    }

    fn audit(&mut self, wall: u64) -> JournalRecord {
        let mut inputs = super::super::audit::tests::inputs(self.audit.next_seq());
        inputs.wall = wall;
        let record = self
            .audit
            .seal(inputs, &busbar_kernel::test_support::tokens::pass());
        self.append(super::super::audit_entry(&record).unwrap())
    }

    fn policy(&mut self) {
        self.append(Entry::new(
            RecordClass::Policy,
            b"unrelated policy".to_vec(),
        ));
    }
}

fn raw(record: &JournalRecord) -> Record {
    Record::new(record.node, record.node_seq, record.encode())
}

fn final_part(record: &JournalRecord) -> (Vec<u8>, Vec<u8>) {
    let encoded = record.encode();
    let chunks: Vec<_> = encoded
        .chunks(super::super::store_chain::PART_BYTES)
        .collect();
    let count = u16::try_from(chunks.len()).expect("the fixture fits the real part count");
    let key = super::super::store_chain::part_key(record.node, record.node_seq, count - 1).to_vec();
    let mut value = count.to_be_bytes().to_vec();
    value.extend_from_slice(chunks.last().unwrap());
    assert!(value.len() <= busbar_contract::MAX_RECORD_BYTES);
    (key, value)
}

fn advance(slots: &RecordSlots, record: &JournalRecord) -> Advance {
    match prepare(slots, &raw(record)).expect("the next sealed record can be prepared") {
        Write::New(advance) => advance,
        _ => panic!("expected a new audit head"),
    }
}

fn commit(slots: &RecordSlots, record: &JournalRecord) -> Result<(), String> {
    let (key, value) = final_part(record);
    advance(slots, record).commit(slots, &HeldLease::default(), key, value)
}

#[test]
fn absent_schema_backfills_signed_samples_and_restarts_without_source_reconstruction() {
    let slots = RecordSlots::new();
    let mut sealed = Sealed::new();
    for wall in [START, START + 1_200, START + 3_600, START + 7_200] {
        sealed.audit(wall);
    }
    let expected = sealed.audit.heads().anchors();
    let restored = initialize(&slots, NODE, &sealed.records).unwrap();
    assert_eq!(restored.anchors(), expected);
    let puts = slots.puts();
    assert_eq!(
        initialize(&slots, NODE, &sealed.records).unwrap().anchors(),
        expected
    );
    assert_eq!(
        slots.puts(),
        puts,
        "a second boot must not rewrite retained samples"
    );
    drop(sealed);

    // A new reader holds neither the old RAM history nor the source records. This is a durable
    // head-store restore, not a claim that the production journal supports pruning.
    let reloaded = load(&slots, NODE)
        .unwrap()
        .expect("independent persisted history");
    assert_eq!(reloaded.anchors(), expected);
    assert!(reloaded
        .anchors()
        .iter()
        .all(|head| head.signature.is_some()));
}

#[test]
fn rejected_final_transaction_publishes_neither_journal_part_nor_head() {
    let slots = RecordSlots::new();
    let mut sealed = Sealed::new();
    let record = sealed.audit(START);
    let (key, _) = final_part(&record);
    let observed = Arc::new(Mutex::new(Vec::<Request>::new()));
    let requests = observed.clone();
    slots.on_transaction(move |request| {
        requests.lock().unwrap().push(request.clone());
        Some(StoreFailure::Refused("definitive test refusal".into()))
    });
    assert!(commit(&slots, &record).is_err());
    assert!(load(&slots, NODE).unwrap().is_none());
    assert!(
        wait_for(slots.record_get(super::super::store_chain::JOURNAL_SCHEMA, &key))
            .unwrap()
            .is_none()
    );
    let observed = observed.lock().unwrap();
    assert_eq!(observed.len(), 1);
    assert!(observed[0]
        .mutations
        .iter()
        .any(|mutation| matches!(mutation,
        Mutation::Put { schema, key: written, .. }
            if schema == super::super::store_chain::JOURNAL_SCHEMA && written == &key)));
    assert!(observed[0]
        .mutations
        .iter()
        .any(|mutation| matches!(mutation,
        Mutation::Put { schema, .. } if schema == SCHEMA)));
    assert_eq!(slots.rows_under(SCHEMA), 0);
}

#[test]
fn accepted_transaction_with_a_lost_answer_replays_the_exact_request_once() {
    let slots = RecordSlots::new();
    let mut sealed = Sealed::new();
    let record = sealed.audit(START);
    let expected = sealed.audit.heads().anchors();
    let observed = Arc::new(Mutex::new(Vec::<Request>::new()));
    let requests = observed.clone();
    slots.on_transaction(move |request| {
        requests.lock().unwrap().push(request.clone());
        None
    });
    slots.lose_acks(true);
    commit(&slots, &record).unwrap();
    let observed = observed.lock().unwrap();
    assert!(
        observed.len() >= 2,
        "the Store really lost the first applied answer"
    );
    assert!(
        observed.iter().all(|request| request == &observed[0]),
        "an unknown commit must retain its operation id and complete request bytes"
    );
    assert_eq!(
        slots.rows_under(SCHEMA),
        2,
        "one sample and one tip, with no duplicate anchor"
    );
    assert_eq!(load(&slots, NODE).unwrap().unwrap().anchors(), expected);
    assert!(
        matches!(prepare(&slots, &raw(&record)).unwrap(), Write::Recorded),
        "replaying a checkpointed record must not clear and rewrite its journal parts"
    );
}

#[test]
fn stale_prepared_head_cannot_overwrite_a_different_committed_head() {
    let slots = RecordSlots::new();
    let mut first = Sealed::new();
    let first_record = first.audit(START);
    let stale = advance(&slots, &first_record);
    let mut winner = Sealed::new();
    let winning_record = winner.audit(START + 1);
    commit(&slots, &winning_record).unwrap();
    let (key, value) = final_part(&first_record);
    assert!(stale
        .commit(&slots, &HeldLease::default(), key, value)
        .is_err());
    assert_eq!(
        load(&slots, NODE).unwrap().unwrap().anchors(),
        winner.audit.heads().anchors()
    );
    let (key, value) = final_part(&winning_record);
    assert_eq!(
        wait_for(slots.record_get(super::super::store_chain::JOURNAL_SCHEMA, &key))
            .unwrap()
            .unwrap()
            .as_slice(),
        value.as_slice()
    );
}

#[test]
fn interrupted_backfill_resumes_without_publishing_a_partial_history() {
    let slots = RecordSlots::new();
    let mut sealed = Sealed::new();
    for hour in 0..4 {
        sealed.audit(START + hour * 3_600);
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    slots.on_transaction(move |_| {
        (observed.fetch_add(1, Ordering::SeqCst) != 0)
            .then(|| StoreFailure::Refused("interrupted migration".into()))
    });
    assert!(initialize(&slots, NODE, &sealed.records).is_err());
    assert!(
        slots.rows_under(SCHEMA) > 0,
        "the interruption follows a real sample commit"
    );
    assert!(
        !matches!(load(&slots, NODE), Ok(Some(_))),
        "a partially backfilled sample set is not a committed history"
    );
    slots.on_transaction(|_| None);
    assert_eq!(
        initialize(&slots, NODE, &sealed.records).unwrap().anchors(),
        sealed.audit.heads().anchors()
    );
    assert_eq!(
        load(&slots, NODE).unwrap().unwrap().anchors(),
        sealed.audit.heads().anchors()
    );
}

#[test]
fn restart_sampling_uses_last_sample_wall_not_tip_wall_or_journal_position() {
    let slots = RecordSlots::new();
    let mut sealed = Sealed::new();
    sealed.audit(START);
    sealed.policy(); // Journal positions and audit positions deliberately diverge.
    sealed.audit(START + 1_800);
    initialize(&slots, NODE, &sealed.records).unwrap();
    assert_eq!(load(&slots, NODE).unwrap().unwrap().tip().unwrap().seq, 2);

    let boundary = sealed.audit(START + 3_600);
    commit(&slots, &boundary).unwrap();
    let backwards = sealed.audit(START - 1);
    commit(&slots, &backwards).unwrap();
    assert_eq!(
        initialize(&slots, NODE, &sealed.records).unwrap().anchors(),
        sealed.audit.heads().anchors()
    );
    let next_boundary = sealed.audit(START + 7_200);
    commit(&slots, &next_boundary).unwrap();
    let restored = load(&slots, NODE).unwrap().unwrap();
    assert_eq!(restored.anchors(), sealed.audit.heads().anchors());
    assert_eq!(
        restored
            .series()
            .iter()
            .map(|head| head.seq)
            .collect::<Vec<_>>(),
        [1, 3, 5]
    );
}

#[test]
fn malformed_existing_checkpoint_refuses_instead_of_rebuilding_from_source() {
    let slots = RecordSlots::new();
    let mut sealed = Sealed::new();
    sealed.audit(START);
    initialize(&slots, NODE, &sealed.records).unwrap();
    let key = tip_key(NODE);
    assert!(wait_for(slots.record_get(SCHEMA, &key)).unwrap().is_some());
    slots.corrupt(SCHEMA, &key);
    assert!(load(&slots, NODE).is_err());
    assert!(
        initialize(&slots, NODE, &sealed.records).is_err(),
        "present corruption cannot be reclassified as a pre-upgrade store"
    );
}

#[test]
fn samples_beyond_one_store_page_restore_every_anchor_including_genesis() {
    let slots = RecordSlots::new();
    let mut sealed = Sealed::new();
    let count = u64::from(PAGE) + 5;
    for hour in 0..count {
        sealed.audit(START + hour * 3_600);
    }
    let expected = sealed.audit.heads().anchors();
    initialize(&slots, NODE, &sealed.records).unwrap();
    drop(sealed);

    let restored = load(&slots, NODE).unwrap().unwrap();
    assert_eq!(restored.series().len() as u64, count);
    assert_eq!(restored.anchors(), expected);
    assert_eq!(restored.series()[0].seq, 1);
    assert!(
        load(&slots, NODE + 1).unwrap().is_none(),
        "another node cannot acquire these anchors"
    );
}

/// Exercise the lane's actual multipart writer. The head checkpoint must accompany the final part
/// of this complete record, and an already committed record must not be cleared on replay.
#[test]
fn actual_multipart_write_reads_back_whole_and_replay_preserves_every_part() {
    let slots = RecordSlots::new();
    let mut sealed = Sealed::new();
    let record = sealed.audit(START);
    let raw = raw(&record);
    let parts = raw
        .body
        .len()
        .div_ceil(super::super::store_chain::PART_BYTES);
    assert!(
        parts > 1,
        "the signed fixture must exercise the real multipart boundary"
    );
    let lease = HeldLease::default();
    super::super::store_chain::put_record(&slots, &lease, &raw).unwrap();

    let kept = super::super::store_chain::read_chain(&slots, NODE).unwrap();
    assert_eq!(kept, vec![raw.clone()]);
    assert_eq!(busbar_kernel_wal::decode_run(&kept).unwrap(), vec![record]);
    assert_eq!(
        slots.rows_under(super::super::store_chain::JOURNAL_SCHEMA),
        parts
    );
    assert_eq!(
        load(&slots, NODE).unwrap().unwrap().anchors(),
        sealed.audit.heads().anchors()
    );

    let puts = slots.puts();
    super::super::store_chain::put_record(&slots, &lease, &raw).unwrap();
    assert_eq!(
        slots.puts(),
        puts,
        "checkpointed replay must not rewrite or clear a part"
    );
    assert_eq!(
        super::super::store_chain::read_chain(&slots, NODE).unwrap(),
        kept
    );
}

/// Every scalar may need all twenty decimal digits. Keep a genuinely signed head at that width
/// inside the real Store slot; duplicating the complete sampled head overflowed this boundary.
#[test]
fn maximum_width_signed_checkpoint_fits_one_real_store_record() {
    let slots = RecordSlots::new();
    let signer = AuditSigningKey::from_seed(&[7; 32]);
    let hash = "f".repeat(64);
    let tip = Head {
        seq: u64::MAX - 1,
        signature: Some(signer.sign_digest(&hash)),
        key_id: Some(signer.key_id().to_string()),
        hash,
        wall: u64::MAX - 1,
    };
    tip.validate().unwrap();
    let expected = Checkpoint {
        version: 1,
        last_sample_seq: tip.seq,
        last_sample_wall: tip.wall,
        tip,
        samples: u64::MAX - 1,
    };
    let encoded = encode(&expected).expect("max-width signed checkpoint must fit the Store bound");
    assert!(encoded.len() <= busbar_contract::MAX_RECORD_BYTES);
    let value = busbar_contract::kinds::RecordBytes::new(encoded).unwrap();
    wait_for(slots.record_put(SCHEMA, &tip_key(NODE), &value)).unwrap();
    assert_eq!(checkpoint(&slots, NODE).unwrap().unwrap().0, expected);
}
