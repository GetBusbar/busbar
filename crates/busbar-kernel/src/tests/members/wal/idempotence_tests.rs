// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::StepName;

use busbar_kernel_wal::record::{Record, FRAME_BYTES};
use busbar_kernel_wal::ship::{NullShipper, ShipError, Shipper};
use busbar_kernel_wal::wal::{Mode, Wal};

use super::fixtures::{durability_token, records, FaultyFactory};

type OfferLog = std::sync::Arc<std::sync::Mutex<Vec<Vec<(u64, u64)>>>>;

const CEILING: u64 = 256 * FRAME_BYTES as u64;

fn on_disk_wal() -> Wal {
    let (factory, _switch, _memory) = FaultyFactory::new();
    Wal::with_parts(
        Box::new(factory),
        Box::new(NullShipper::new()),
        Mode::OnDisk,
        CEILING,
        super::fixtures::wall_ms,
    )
    .expect("a healthy disk opens")
}

#[test]
fn a_reappended_identity_is_passed_over_however_much_its_body_disagrees() {
    let mut wal = on_disk_wal();
    let token = durability_token();

    let first = vec![Record::new(1, 1, b"the body that was committed".to_vec())];
    let ack = wal
        .append_batch(&token, StepName::Meter, &first)
        .expect("a healthy disk takes the first batch");
    assert_eq!(ack.appended, 1);
    assert_eq!(ack.already_present, 0);
    assert!(
        wal.holds(1, 1),
        "the log did not record the identity it wrote"
    );

    let disagreeing = vec![Record::new(1, 1, b"COMPLETELY DIFFERENT CONTENT".to_vec())];
    let ack = wal
        .append_batch(&token, StepName::Meter, &disagreeing)
        .expect("a re-append is not an error");
    assert_eq!(
        ack.appended, 0,
        "a body that disagreed was written under an identity the log already held"
    );
    assert_eq!(ack.already_present, 1);

    let empty = vec![Record::new(1, 1, Vec::new())];
    let ack = wal
        .append_batch(&token, StepName::Meter, &empty)
        .expect("a re-append is not an error");
    assert_eq!(ack.appended, 0);
    assert_eq!(ack.already_present, 1);
}

#[test]
fn two_identities_sharing_one_body_are_two_records() {
    let mut wal = on_disk_wal();
    let token = durability_token();

    let body = b"identical bytes".to_vec();
    let batch = vec![
        Record::new(1, 1, body.clone()),
        Record::new(1, 2, body.clone()),
        // A different NODE at the same number is also a different record: the identity is the pair.
        Record::new(2, 1, body),
    ];
    let ack = wal
        .append_batch(&token, StepName::Meter, &batch)
        .expect("a healthy disk takes the batch");
    assert_eq!(
        ack.appended, 3,
        "records sharing a body were deduplicated as if they shared an identity"
    );
    assert_eq!(ack.already_present, 0);
    assert!(wal.holds(1, 1) && wal.holds(1, 2) && wal.holds(2, 1));
}

#[test]
fn a_batch_that_repeats_an_identity_within_itself_writes_it_once_and_counts_the_rest() {
    let mut wal = on_disk_wal();
    let token = durability_token();

    let batch = vec![
        Record::new(1, 1, b"a".to_vec()),
        Record::new(1, 2, b"b".to_vec()),
        Record::new(1, 1, b"a again".to_vec()),
        Record::new(1, 1, b"a third time".to_vec()),
    ];
    let ack = wal
        .append_batch(&token, StepName::Meter, &batch)
        .expect("a healthy disk takes the batch");
    assert_eq!(
        ack.appended, 2,
        "a repeated number was written more than once"
    );
    assert_eq!(
        ack.already_present, 2,
        "the two repeats inside the batch were not counted as redundant"
    );

    let mixed = vec![
        Record::new(1, 1, b"held".to_vec()),
        Record::new(1, 3, b"new".to_vec()),
        Record::new(1, 3, b"new again".to_vec()),
        Record::new(1, 2, b"held too".to_vec()),
    ];
    let ack = wal
        .append_batch(&token, StepName::Meter, &mixed)
        .expect("a healthy disk takes the batch");
    assert_eq!(ack.appended, 1);
    assert_eq!(
        ack.already_present, 3,
        "the two held numbers and the one internal repeat must all be counted"
    );
}

#[test]
fn the_tracked_identity_count_moves_with_what_the_check_is_actually_holding() {
    let mut wal = on_disk_wal();
    let token = durability_token();
    assert_eq!(
        wal.tracked_identities(),
        0,
        "a fresh log is holding no identities"
    );

    wal.append_batch(&token, StepName::Meter, &records(1, 1, 8, 16))
        .expect("a healthy disk takes the batch");
    let one_writer = wal.tracked_identities();
    assert!(
        (1..=2).contains(&one_writer),
        "eight contiguous records cost {one_writer} remembered identities"
    );

    wal.append_batch(&token, StepName::Meter, &records(1, 9, 8, 16))
        .expect("a healthy disk takes the batch");
    assert_eq!(
        wal.tracked_identities(),
        one_writer,
        "a contiguous run cost a remembered identity per record"
    );

    wal.append_batch(&token, StepName::Meter, &records(2, 1, 8, 16))
        .expect("a healthy disk takes the batch");
    let two_writers = wal.tracked_identities();
    assert!(
        two_writers > one_writer,
        "a second writer did not cost a second mark"
    );

    wal.append_batch(
        &token,
        StepName::Meter,
        &[Record::new(1, 20, b"far ahead".to_vec())],
    )
    .expect("a healthy disk takes the batch");
    assert!(
        wal.tracked_identities() > two_writers,
        "a gap cost the check nothing, so the numbers inside it are being called present"
    );
    assert!(
        !wal.holds(1, 18),
        "a number inside the gap is being reported as held"
    );

    assert!(wal.holds(1, 16), "a number the log wrote is no longer held");
    assert!(wal.holds(1, 20), "the number that was written is not held");
}

/// A shipper that takes everything and records what each offer contained.
#[derive(Default)]
struct RecordingShipper {
    offers: OfferLog,
}

impl Shipper<Record> for RecordingShipper {
    fn ship(&mut self, records: &[Record]) -> Result<(), ShipError> {
        self.offers
            .lock()
            .unwrap()
            .push(records.iter().map(Record::identity).collect());
        Ok(())
    }
}

#[test]
fn an_on_disk_reappend_that_the_log_already_holds_offers_the_store_nothing() {
    let (factory, _switch, _memory) = FaultyFactory::new();
    let shipper = RecordingShipper::default();
    let offers = std::sync::Arc::clone(&shipper.offers);
    let mut wal = Wal::with_parts(
        Box::new(factory),
        Box::new(shipper),
        Mode::OnDisk,
        CEILING,
        super::fixtures::wall_ms,
    )
    .expect("a healthy disk opens");
    let token = durability_token();

    let batch = records(1, 1, 3, 16);
    wal.append_batch(&token, StepName::Meter, &batch)
        .expect("a healthy disk takes the batch");
    let after_first = offers.lock().unwrap().len();

    let ack = wal
        .append_batch(&token, StepName::Meter, &batch)
        .expect("a redundant re-append is not an error");
    assert_eq!(ack.appended, 0);
    assert_eq!(ack.already_present, 3);

    let offers = offers.lock().unwrap();
    assert_eq!(
        offers.len(),
        after_first,
        "an on-disk re-append of records the log already holds offered the store a duplicate \
         delivery: {:?}",
        &offers[after_first..]
    );
}

/// A shipper that refuses its FIRST offer and takes every one after it, recording what each offer
/// contained so the retry's contents can be read back.
#[derive(Default)]
struct RefuseOnceShipper {
    offers: OfferLog,
}

impl Shipper<Record> for RefuseOnceShipper {
    fn ship(&mut self, records: &[Record]) -> Result<(), ShipError> {
        let mut offers = self.offers.lock().unwrap();
        offers.push(records.iter().map(Record::identity).collect());
        if offers.len() == 1 {
            return Err(ShipError::Unavailable("the store is away".into()));
        }
        Ok(())
    }
}

#[test]
fn a_retry_after_a_refused_ship_reoffers_the_debt_without_appending_again() {
    let (factory, _switch, _memory) = FaultyFactory::new();
    let shipper = RefuseOnceShipper::default();
    let offers = std::sync::Arc::clone(&shipper.offers);
    let mut wal = Wal::with_parts(
        Box::new(factory),
        Box::new(shipper),
        Mode::MemoryBuffered,
        CEILING,
        super::fixtures::wall_ms,
    )
    .expect("a healthy disk opens");
    let token = durability_token();

    let batch = records(1, 1, 3, 16);
    wal.append_batch(&token, StepName::Meter, &batch)
        .expect_err("a refused ship is a lost durable write");

    let ack = wal
        .append_batch(&token, StepName::Meter, &batch)
        .expect("the retry ships the debt");
    assert_eq!(
        ack.appended, 0,
        "the retry wrote the records into the log a second time"
    );
    assert!(
        ack.replayed_lost_batch,
        "the retry did not report that it was replaying a lost batch"
    );

    let offers = offers.lock().unwrap();
    assert_eq!(
        offers.len(),
        2,
        "the retry did not re-offer the debt at all"
    );
    assert_eq!(
        offers[0], offers[1],
        "the retry offered the store something other than what it was owed"
    );
    assert_eq!(offers[1], vec![(1, 1), (1, 2), (1, 3)]);

    for seq in 1..=3 {
        assert!(wal.holds(1, seq), "the log stopped holding (1, {seq})");
    }
}
