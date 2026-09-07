// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A RE-APPEND IS DEDUPLICATED ON IDENTITY, NOT ON BODY.
//!
//! The log's identity space is `(node, node_seq)`: a writer numbers its own records upward, and a
//! retry after a lost acknowledgement re-offers the numbers it already sent. What that means, and
//! what nothing here asserted, is that the BODY plays no part. A record whose identity the log
//! already holds is passed over WHATEVER its bytes say — because a writer that reuses a number for
//! different content has broken its own contract, and a log that resolved the disagreement by
//! writing both would hold one identity twice and hand a reader two answers to one question.
//!
//! The other half is the accounting. A caller reads `already_present` to learn how much of what it
//! offered was retained rather than written, and a batch can be redundant in two DIFFERENT ways at
//! once: a number the log already holds, and a number repeated inside the batch the caller has just
//! handed in. Both count, and the second is the one no earlier battery presented at all.
//!
//! And the debt. In memory-buffered mode the store IS durability, so a commit whose records the
//! segment already holds still owes the store those records: a caller that retries after a refused
//! ship appends nothing new, and if the retry did not re-offer, the debt would sit until some
//! unrelated future record happened to carry it — on a node that has gone quiet, forever.

use busbar_caps::StepName;

use crate::record::{Record, FRAME_BYTES};
use crate::ship::{NullShipper, ShipError, Shipper};
use crate::wal::{Mode, Wal};

use super::fixtures::{durability_token, records, FaultyFactory};

/// What each offer to the store contained, in order: one inner vector per `ship` call, holding the
/// identities that call was handed. Shared with the test so a trait-object shipper can still be
/// read back.
type OfferLog = std::sync::Arc<std::sync::Mutex<Vec<Vec<(u64, u64)>>>>;

/// Small enough that a few hundred records roll the log, large enough that a handful do not.
const CEILING: u64 = 256 * FRAME_BYTES as u64;

fn on_disk_wal() -> Wal {
    let (factory, _switch, _memory) = FaultyFactory::new();
    Wal::with_parts(
        Box::new(factory),
        Box::new(NullShipper::new()),
        Mode::OnDisk,
        CEILING,
    )
    .expect("a healthy disk opens")
}

/// A RECORD THE LOG ALREADY HOLDS IS PASSED OVER EVEN WHEN ITS BODY DISAGREES.
///
/// The identity is the whole of the check. Re-offering `(1, 1)` with completely different bytes
/// must append nothing and must be counted as already present — the log does not adjudicate
/// between two bodies claiming one number, because there is no answer it could give that a reader
/// could rely on. What it can guarantee is that the number appears once.
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

    // The SAME identity, a body that shares not one byte with it.
    let disagreeing = vec![Record::new(1, 1, b"COMPLETELY DIFFERENT CONTENT".to_vec())];
    let ack = wal
        .append_batch(&token, StepName::Meter, &disagreeing)
        .expect("a re-append is not an error");
    assert_eq!(
        ack.appended, 0,
        "a body that disagreed was written under an identity the log already held"
    );
    assert_eq!(ack.already_present, 1);

    // And an EMPTY body under the same identity, which is the degenerate version of the same claim.
    let empty = vec![Record::new(1, 1, Vec::new())];
    let ack = wal
        .append_batch(&token, StepName::Meter, &empty)
        .expect("a re-append is not an error");
    assert_eq!(ack.appended, 0);
    assert_eq!(ack.already_present, 1);
}

/// A NEIGHBOURING IDENTITY WITH THE SAME BODY IS A DIFFERENT RECORD.
///
/// The control for the test above, and the half that says the check is keyed on identity rather
/// than on content. Two records with byte-identical bodies at two numbers are two records; a log
/// that deduplicated on the bytes would silently drop the second and leave a hole where a writer
/// believes it wrote.
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

/// A BATCH THAT REPEATS A NUMBER INSIDE ITSELF WRITES IT ONCE, AND SAYS SO.
///
/// Two redundancies, and they are not the same redundancy: a number the LOG already holds, and a
/// number repeated within the ONE call a caller has just made. Both are counted as already present,
/// because from the caller's side both mean "you offered this and I did not write it". A batch
/// whose internal duplicate went uncounted would report fewer redundant records than the caller
/// offered, and a caller reconciling its own outbox against that number concludes it has records
/// the log never saw.
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

    // Both kinds of redundancy in one call: `(1, 1)` and `(1, 2)` are now held, and the batch also
    // repeats `(1, 3)` inside itself.
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

/// THE IDEMPOTENCE CHECK REMEMBERS PER WRITER, AND SAYS HOW MUCH IT IS HOLDING.
///
/// `tracked_identities` is the bound made observable, and it is what every memory assertion in this
/// crate reads. A count that answered a constant would make each of those assertions pass without
/// measuring anything. A contiguous run from one writer costs one mark; a second writer costs a
/// second; and a hole costs a remembered hole on top, which is what makes the number move for a
/// reason a reader can name.
#[test]
fn the_tracked_identity_count_moves_with_what_the_check_is_actually_holding() {
    let mut wal = on_disk_wal();
    let token = durability_token();
    assert_eq!(
        wal.tracked_identities(),
        0,
        "a fresh log is holding no identities"
    );

    // One writer, a contiguous run of eight: a mark, not eight entries.
    wal.append_batch(&token, StepName::Meter, &records(1, 1, 8, 16))
        .expect("a healthy disk takes the batch");
    let one_writer = wal.tracked_identities();
    assert!(
        (1..=2).contains(&one_writer),
        "eight contiguous records cost {one_writer} remembered identities"
    );

    // Eight MORE from the same writer, still contiguous: the mark moves, the cost does not.
    wal.append_batch(&token, StepName::Meter, &records(1, 9, 8, 16))
        .expect("a healthy disk takes the batch");
    assert_eq!(
        wal.tracked_identities(),
        one_writer,
        "a contiguous run cost a remembered identity per record"
    );

    // A second writer: a second mark, and the count MOVED.
    wal.append_batch(&token, StepName::Meter, &records(2, 1, 8, 16))
        .expect("a healthy disk takes the batch");
    let two_writers = wal.tracked_identities();
    assert!(
        two_writers > one_writer,
        "a second writer did not cost a second mark"
    );

    // A hole: the numbers between the mark and this one were never written, and the check has to
    // remember them or it would call them present.
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
    // And the numbers BELOW the gap really were written, so the mark still answers for them.
    assert!(wal.holds(1, 16), "a number the log wrote is no longer held");
    assert!(wal.holds(1, 20), "the number that was written is not held");
}

/// A shipper that takes everything and records what each offer contained.
#[derive(Default)]
struct RecordingShipper {
    offers: OfferLog,
}

impl Shipper for RecordingShipper {
    fn ship(&mut self, records: &[Record]) -> Result<(), ShipError> {
        self.offers
            .lock()
            .unwrap()
            .push(records.iter().map(Record::identity).collect());
        Ok(())
    }
}

/// ON DISK, A WHOLLY REDUNDANT RE-APPEND SHIPS NOTHING.
///
/// The debt-paying branch above belongs to memory-buffered mode, where the store IS durability. On
/// disk the local log is the record and shipping is catch-up work, so a re-append that the segment
/// already holds owes the store nothing on this call — offering it those records again would hand a
/// downstream store a duplicate delivery of a record it has already been given, off a call that
/// wrote nothing. Both halves of the condition matter: the mode, and whether there is anything to
/// offer at all.
#[test]
fn an_on_disk_reappend_that_the_log_already_holds_offers_the_store_nothing() {
    let (factory, _switch, _memory) = FaultyFactory::new();
    let shipper = RecordingShipper::default();
    let offers = std::sync::Arc::clone(&shipper.offers);
    let mut wal = Wal::with_parts(Box::new(factory), Box::new(shipper), Mode::OnDisk, CEILING)
        .expect("a healthy disk opens");
    let token = durability_token();

    let batch = records(1, 1, 3, 16);
    wal.append_batch(&token, StepName::Meter, &batch)
        .expect("a healthy disk takes the batch");
    let after_first = offers.lock().unwrap().len();

    // Every record in this call is one the log already holds: nothing to append, and nothing owed.
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

impl Shipper for RefuseOnceShipper {
    fn ship(&mut self, records: &[Record]) -> Result<(), ShipError> {
        let mut offers = self.offers.lock().unwrap();
        offers.push(records.iter().map(Record::identity).collect());
        if offers.len() == 1 {
            return Err(ShipError::Unavailable("the store is away".into()));
        }
        Ok(())
    }
}

/// A RETRY AFTER A REFUSED SHIP RE-OFFERS THE DEBT AND APPENDS NOTHING.
///
/// In memory-buffered mode the store is where durability lives, so a refused ship is a lost durable
/// write and is reported as one — but the SEGMENT already took those records. The retry therefore
/// has nothing new to append, and the branch it lands in is the one that would otherwise return a
/// clean acknowledgement having shipped nothing. The debt has to be re-offered from THERE, or it
/// waits for a future record to carry it and a node that has gone quiet never sends it at all.
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
    )
    .expect("a healthy disk opens");
    let token = durability_token();

    let batch = records(1, 1, 3, 16);
    wal.append_batch(&token, StepName::Meter, &batch)
        .expect_err("a refused ship is a lost durable write");

    // The retry offers the same records. The segment already holds them, so nothing is appended --
    // and the store must still be handed them.
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

    // The store was offered the SAME three records a second time -- that is the debt being paid,
    // and it is what the branch taken by a batch with nothing new to append exists to do.
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
