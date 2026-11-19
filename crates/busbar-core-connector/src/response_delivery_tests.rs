// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The accepted connection's ledger with no socket: the transport's answers as the driver's items,
//! the carrier's readings as numbers. What a socket adds is proven in
//! `tests/session_delivery_tests.rs`.

use super::*;
use crate::outbound::delivery::Breach;
use crate::outbound::records::{
    Session, WireEnd, WirePart, END_FAILED, END_FLUSH, END_NO_BODY, END_SHUTDOWN, WIRE_CONTROL,
};
use busbar_contract::response_delivery::CarrierFault;
use busbar_contract::storage::StorageSource;
use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
use busbar_plugin_abi::transport::{E_BODY, E_END};

fn source() -> StorageSource {
    ProcessAdmission::new(0).connection_storage(AdmissionClass::Data)
}

fn key(stream: u64) -> ResponseKey {
    ResponseKey {
        node: 9,
        incarnation: 2,
        unit: Some(busbar_contract::ids::UnitKey::new(stream)),
        connection_generation: 7,
        stream,
    }
}

fn progress(accepted: u64, written: u64, complete: u64) -> CarrierProgress {
    CarrierProgress {
        accepted_plaintext: accepted,
        written_plaintext: written,
        complete_records_plaintext: complete,
        fault: None,
    }
}

type Item = (Out, &'static [u8]);

fn part(stream: u64, class: u32, bytes: &'static [u8]) -> Item {
    (
        Out::Part {
            part: WirePart {
                stream,
                class,
                _r: 0,
            },
            len: bytes.len() as u32,
        },
        bytes,
    )
}

fn end(stream: u64, how: u32, arg: u32) -> Item {
    (Out::End(WireEnd { stream, how, arg }), &[])
}

fn answer(ledger: &mut DeliveryLedger, items: &[Item]) -> Result<Outcome, Fault> {
    let outs: Vec<Out> = items.iter().map(|item| item.0).collect();
    ledger.answer(&outs, |index| items[index].1)
}

/// A ledger whose session is stated, as `begin`'s answer does.
fn ledger() -> DeliveryLedger {
    let mut ledger = DeliveryLedger::default();
    answer(
        &mut ledger,
        &[(Out::Session(Session::stated(true, 1 << 20, 4 << 20)), &[])],
    )
    .unwrap();
    ledger
}

/// The connection takes everything queued and its flush succeeds: the carrier reports all of it.
fn flush(ledger: &mut DeliveryLedger) -> u64 {
    let queued = ledger.unwritten().len();
    ledger.took(queued);
    let total = ledger.written;
    ledger.flushed(progress(total, total, total)).unwrap();
    total
}

/// A whole answer with a four-byte body on `stream`.
fn serve(ledger: &mut DeliveryLedger, stream: u64) {
    ledger.emitting(stream, E_BODY, 4);
    ledger.emitting(stream, E_END, 0);
    answer(
        ledger,
        &[
            part(stream, WIRE_CONTROL, b"head"),
            part(stream, WIRE_PAYLOAD, b"body"),
            end(stream, END_FLUSH, 0),
        ],
    )
    .unwrap();
}

#[test]
fn an_answer_is_whole_only_when_the_carrier_took_all_of_it_and_the_flush_succeeded() {
    let mut ledger = ledger();
    let handles = ledger.admit(key(1)).unwrap();
    serve(&mut ledger, 1);
    assert_eq!(ledger.unwritten(), b"headbody");
    assert_eq!(handles.watch.record(), None, "queued is not delivered");
    // The connection took it all; the carrier has written half as whole records.
    ledger.took(8);
    ledger.flushed(progress(8, 8, 4)).unwrap();
    assert_eq!(handles.watch.record(), None, "half is not delivered");
    ledger.flushed(progress(8, 8, 8)).unwrap();
    assert_eq!(
        handles.watch.record(),
        Some(DeliveryRecord {
            state: "whole",
            reason: None,
            body_bytes: 4
        })
    );
    assert_eq!(
        handles.watch.snapshot().terminal,
        Some(DeliveryTerminal::Complete)
    );
    assert!(
        !ledger.has_responses(),
        "its entry is released with its verdict"
    );
}

#[test]
fn a_breach_queues_nothing_of_that_answer_not_even_its_valid_prefix() {
    let mut ledger = ledger();
    let _handles = ledger.admit(key(1)).unwrap();
    assert_eq!(
        answer(
            &mut ledger,
            &[
                part(1, WIRE_CONTROL, b"valid"),
                part(99, WIRE_PAYLOAD, b"x"),
            ],
        )
        .unwrap_err(),
        Fault::Output(Breach::L2)
    );
    assert!(ledger.unwritten().is_empty());
}

#[test]
fn an_owners_stop_reaches_the_connection_once_and_makes_no_verdict() {
    let mut ledger = ledger();
    let handles = ledger.admit(key(1)).unwrap();
    handles.release.freeze(key(1), 1).unwrap();
    handles.cancel.cancel(ResponseStop::Deadline);
    handles.cancel.cancel(ResponseStop::Cancelled);
    assert_eq!(
        handles.release.publish(key(1), 1),
        Err(ResponseStop::Deadline),
        "a stopped answer's record is not stated as in"
    );
    assert_eq!(
        ledger.next_control(),
        Some(DeliveryControl::Cancel {
            stream: 1,
            reason: ResponseStop::Deadline
        }),
        "the first reason wins"
    );
    assert_eq!(ledger.next_control(), None, "asked once");
    assert_eq!(handles.watch.cancellation(), Some(ResponseStop::Deadline));
    assert!(
        handles.watch.snapshot().terminal.is_none(),
        "a stop request is not a verdict: that is still what the socket took"
    );
    let now = Instant::now();
    assert!(ledger.stop(1, ResponseStop::Deadline, now));
    assert!(
        !ledger.stop(1, ResponseStop::Deadline, now),
        "E_RESET goes once"
    );
    assert!(ledger.overdue(now + Duration::from_secs(2), Duration::from_secs(1)));
    // The transport ends the stream: now the verdict, with the owner's own word.
    answer(&mut ledger, &[end(1, END_FAILED, 0)]).unwrap();
    assert_eq!(
        handles.watch.record(),
        Some(DeliveryRecord {
            state: "none",
            reason: Some("deadline"),
            body_bytes: 0
        })
    );
    assert_eq!(
        handles.watch.snapshot().terminal,
        Some(DeliveryTerminal::Failed(ResponseStop::Deadline))
    );
    assert!(!ledger.overdue(now + Duration::from_secs(2), Duration::from_secs(1)));
}

#[test]
fn a_stop_after_the_transports_end_mark_emits_nothing() {
    let mut ledger = ledger();
    let handles = ledger.admit(key(1)).unwrap();
    serve(&mut ledger, 1);
    // The end mark is queued, not yet out: the owner stops the answer.
    assert!(
        !ledger.stop(1, ResponseStop::Cancelled, Instant::now()),
        "nothing is emitted on a stream the transport ended"
    );
    flush(&mut ledger);
    assert_eq!(
        handles.watch.record().map(|record| record.state),
        Some("whole"),
        "every byte went out: the truth is not the stop request"
    );
}

#[test]
fn the_roots_observers_and_its_publication_deliver_nothing() {
    let mut ledger = ledger();
    let handles = ledger.admit(key(1)).unwrap();
    handles.input.producer_ended();
    handles.input.reader_eof();
    handles.input.retired();
    handles.release.freeze(key(1), 3).unwrap();
    handles.release.publish(key(1), 3).unwrap();
    assert!(handles.watch.published());
    assert_eq!(handles.input.observed(), (true, true, true));
    assert_eq!(
        ledger.next_control(),
        None,
        "nothing is released: nothing is held here"
    );
    assert!(handles.watch.snapshot().terminal.is_none());
    assert!(!handles.watch.snapshot().first_payload_written);
    assert_eq!(handles.watch.record(), None);
}

#[test]
fn the_publication_ordinal_is_bound_once_and_to_this_answer() {
    let mut ledger = ledger();
    let handles = ledger.admit(key(1)).unwrap();
    assert_eq!(
        handles.release.freeze(key(2), 1),
        Err(ResponseStop::Integrity),
        "another answer's key"
    );
    assert_eq!(
        handles.release.freeze(key(1), 0),
        Err(ResponseStop::Integrity)
    );
    assert_eq!(
        handles.release.publish(key(1), 1),
        Err(ResponseStop::Integrity),
        "nothing was bound"
    );
    handles.release.freeze(key(1), 4).unwrap();
    handles.release.freeze(key(1), 4).unwrap();
    assert_eq!(
        handles.release.freeze(key(1), 5),
        Err(ResponseStop::Integrity)
    );
    assert_eq!(
        handles.release.publish(key(1), 5),
        Err(ResponseStop::Integrity)
    );
    handles.release.publish(key(1), 4).unwrap();
    // After the verdict nothing is bound or stated.
    ledger.gone(Reason::CallerGone);
    assert_eq!(
        handles.release.publish(key(1), 4),
        Err(ResponseStop::Integrity)
    );
    assert_eq!(
        handles.release.freeze(key(1), 4),
        Err(ResponseStop::Integrity)
    );
}

#[test]
fn an_id_is_never_reused_and_a_connection_has_one_identity() {
    let mut ledger = DeliveryLedger::default();
    let _two = ledger.admit(key(2)).unwrap();
    assert!(ledger.admit(key(2)).is_err());
    assert!(ledger.admit(key(1)).is_err(), "ids only rise");
    assert!(ledger
        .admit(ResponseKey {
            connection_generation: 8,
            ..key(3)
        })
        .is_err());
    assert!(ledger.admit(ResponseKey { node: 1, ..key(3) }).is_err());
    assert!(DeliveryLedger::default()
        .admit(ResponseKey {
            connection_generation: 0,
            ..key(1)
        })
        .is_err());
    let _three = ledger.admit(key(3)).unwrap();
    ledger.gone(Reason::Shutdown);
    assert!(
        ledger.admit(key(4)).is_err(),
        "nothing is admitted on a connection that is gone"
    );
}

#[test]
fn a_later_connection_failure_does_not_rewrite_a_completed_sibling() {
    let mut ledger = ledger();
    let one = ledger.admit(key(1)).unwrap();
    let two = ledger.admit(key(2)).unwrap();
    serve(&mut ledger, 1);
    flush(&mut ledger);
    let whole = one.watch.record();
    assert_eq!(whole.map(|record| record.state), Some("whole"));
    ledger.emitting(2, E_BODY, 4);
    answer(&mut ledger, &[part(2, WIRE_PAYLOAD, b"body")]).unwrap();
    // The write fails with one byte of it on the carrier.
    let written = ledger.written;
    ledger.retire(
        CarrierProgress {
            fault: Some(CarrierFault::Io),
            ..progress(written + 1, written + 1, written + 1)
        },
        Reason::CallerGone,
    );
    assert_eq!(one.watch.record(), whole);
    assert_eq!(
        two.watch.record(),
        Some(DeliveryRecord {
            state: "part",
            reason: Some("caller_gone"),
            body_bytes: 4
        })
    );
}

#[test]
fn a_shutdown_does_not_stand_in_for_the_flush_nor_a_flush_for_the_shutdown() {
    let mut ledger = ledger();
    let closes = ledger.admit(key(1)).unwrap();
    ledger.emitting(1, E_END, 0);
    answer(
        &mut ledger,
        &[
            part(1, WIRE_CONTROL, b"head"),
            end(1, END_SHUTDOWN, END_NO_BODY),
        ],
    )
    .unwrap();
    ledger.shut_down();
    assert_eq!(closes.watch.record(), None, "its bytes are not out");
    flush(&mut ledger);
    assert_eq!(
        closes.watch.record().map(|record| record.state),
        Some("whole")
    );

    let mut ledger = self::ledger();
    let closes = ledger.admit(key(1)).unwrap();
    ledger.emitting(1, E_END, 0);
    answer(
        &mut ledger,
        &[
            part(1, WIRE_CONTROL, b"head"),
            end(1, END_SHUTDOWN, END_NO_BODY),
        ],
    )
    .unwrap();
    flush(&mut ledger);
    assert_eq!(closes.watch.record(), None, "the close has not succeeded");
    ledger.gone(Reason::CallerGone);
    assert_eq!(
        closes
            .watch
            .record()
            .map(|record| (record.state, record.reason)),
        Some(("none", Some("caller_gone")))
    );
}

#[test]
fn a_carriers_fault_delivers_nothing_more() {
    let mut ledger = ledger();
    let handles = ledger.admit(key(1)).unwrap();
    serve(&mut ledger, 1);
    ledger.took(8);
    let total = ledger.written;
    assert_eq!(
        ledger.flushed(CarrierProgress {
            fault: Some(CarrierFault::Io),
            ..progress(total, total, total)
        }),
        Err(ResponseStop::Carrier(CarrierFault::Io))
    );
    assert_eq!(handles.watch.record(), None);
    assert_eq!(
        ledger.flushed(progress(total + 1, total, total)),
        Err(ResponseStop::Integrity),
        "a reading that claims more than was ever queued is not this connection's"
    );
    assert_eq!(
        ledger.flushed(progress(total, total, total + 1)),
        Err(ResponseStop::Integrity)
    );
    assert_eq!(handles.watch.record(), None);
}

#[test]
fn a_ledger_that_is_dropped_leaves_no_owner_waiting() {
    let mut ledger = ledger();
    let handles = ledger.admit(key(1)).unwrap();
    ledger.emitting(1, E_BODY, 4);
    answer(&mut ledger, &[part(1, WIRE_PAYLOAD, b"body")]).unwrap();
    flush(&mut ledger);
    drop(ledger);
    assert_eq!(
        handles.watch.record(),
        Some(DeliveryRecord {
            state: "part",
            reason: Some("caller_gone"),
            body_bytes: 4
        })
    );
}

#[test]
fn a_faulted_session_records_every_open_answer_transport_fault() {
    let mut ledger = ledger();
    let fed = ledger.admit(key(1)).unwrap();
    let unfed = ledger.admit(key(2)).unwrap();
    ledger.emitting(1, E_BODY, 4);
    answer(&mut ledger, &[part(1, WIRE_PAYLOAD, b"body")]).unwrap();
    flush(&mut ledger);
    ledger.faulted();
    assert_eq!(
        fed.watch.record(),
        Some(DeliveryRecord {
            state: "part",
            reason: Some("transport_fault"),
            body_bytes: 4
        })
    );
    assert_eq!(
        unfed.watch.record(),
        Some(DeliveryRecord {
            state: "none",
            reason: Some("transport_fault"),
            body_bytes: 0
        })
    );
    assert_eq!(
        unfed.watch.snapshot().terminal,
        Some(DeliveryTerminal::Failed(ResponseStop::Integrity))
    );
    assert_eq!(
        answer(&mut ledger, &[part(0, WIRE_CONTROL, b"x")]).unwrap_err(),
        Fault::Queue,
        "nothing is queued on a connection that is gone"
    );
}

#[tokio::test]
async fn a_waiter_is_woken_by_the_verdict_and_cancelling_it_changes_nothing() {
    let mut ledger = ledger();
    let handles = ledger.admit(key(1)).unwrap();
    let watch = handles.watch.clone();
    {
        let waiting = watch.terminal();
        tokio::pin!(waiting);
        assert!(futures::poll!(waiting.as_mut()).is_pending());
    }
    assert!(handles.watch.snapshot().terminal.is_none());
    let waiter = tokio::spawn(async move { watch.terminal().await });
    tokio::task::yield_now().await;
    serve(&mut ledger, 1);
    flush(&mut ledger);
    assert_eq!(
        waiter.await.unwrap().terminal,
        Some(DeliveryTerminal::Complete)
    );
}

#[test]
fn a_ledger_makes_nothing_until_its_first_stream_and_has_no_fixed_capacity() {
    let (mut ledger, calls) = crate::support::allocations_during(DeliveryLedger::default);
    assert_eq!(calls, 0, "an empty ledger is no allocation");
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(ledger.poll_control(&mut cx).is_pending());
    assert!(!ledger.has_responses());
    answer(
        &mut ledger,
        &[(Out::Session(Session::stated(true, 1 << 20, 4 << 20)), &[])],
    )
    .unwrap();
    // Far past the old fixed shape (200 responses, 4,096 spans): nothing is refused for room.
    let mut held = Vec::new();
    for stream in 1..=300 {
        held.push(ledger.admit(key(stream)).unwrap());
        ledger.emitting(stream, E_BODY, 1);
    }
    let items: Vec<Item> = (1..=300)
        .map(|stream| part(stream, WIRE_PAYLOAD, b"x"))
        .collect();
    answer(&mut ledger, &items).unwrap();
    flush(&mut ledger);
    for stream in 1..=300 {
        ledger.emitting(stream, E_END, 0);
    }
    let ends: Vec<Item> = (1..=300).map(|stream| end(stream, END_FLUSH, 0)).collect();
    answer(&mut ledger, &ends).unwrap();
    assert!(held.iter().all(|h| h
        .watch
        .record()
        .is_some_and(|record| record.state == "whole")));
    assert!(
        !ledger.has_responses(),
        "held per answer in flight, and nothing after"
    );
}

#[test]
fn anonymous_security_keeps_the_exact_storage_origin_and_progress_reader() {
    use busbar_contract::response_delivery::CarrierProgressReader;
    use busbar_contract::transport::wire::{ConnectionIo, SecuredIo};

    struct TestReader;
    impl CarrierProgressReader for TestReader {
        fn snapshot(&self) -> CarrierProgress {
            progress(0, 0, 0)
        }
    }
    let source = source();
    let reader: Arc<dyn CarrierProgressReader> = Arc::new(TestReader);
    let secured = SecuredIo::anonymous(ConnectionIo {
        io: Box::new(futures::io::Cursor::new(Vec::<u8>::new())),
        progress: Arc::clone(&reader),
        storage: source.clone(),
    });
    assert!(Arc::ptr_eq(&reader, &secured.progress));
    assert!(secured.peer_certificate.is_empty());
    let mut original = source.try_reserve(1).unwrap();
    original
        .try_merge(secured.storage.try_reserve(1).unwrap())
        .unwrap();
    assert_eq!(original.len(), 2);
    assert!(original
        .try_merge(
            ProcessAdmission::new(0)
                .connection_storage(AdmissionClass::Data)
                .try_reserve(1)
                .unwrap()
        )
        .is_err());
}

#[test]
fn the_queue_wipes_each_byte_as_the_connection_takes_it() {
    let mut ledger = ledger();
    answer(&mut ledger, &[part(0, WIRE_CONTROL, b"abcdef")]).unwrap();
    ledger.took(3);
    assert_eq!(ledger.unwritten(), b"def");
    let live = ledger.queue.live_range();
    let block = ledger.queue.allocation();
    assert!(
        block[..live.start].iter().all(|byte| *byte == 0),
        "what the connection took is wiped at once"
    );
    assert_eq!(&block[live], b"def");
    // A write failed: nothing unwritten waits for the connection's drop, and nothing more is queued.
    ledger.discard();
    assert!(ledger.queue.allocation().iter().all(|byte| *byte == 0));
    assert_eq!(
        answer(&mut ledger, &[part(0, WIRE_CONTROL, b"x")]).unwrap_err(),
        Fault::Queue
    );
}
