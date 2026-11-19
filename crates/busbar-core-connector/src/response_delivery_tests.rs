// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The accepted connection's ledger with no socket: the transport's answers as the driver's items,
//! the carrier's readings as numbers. What a socket adds is proven in
//! `tests/session_delivery_tests.rs`.

use super::*;
use crate::outbound::delivery::Breach;
use crate::outbound::records::{
    Session, WireEnd, WirePart, END_FAILED, END_FLUSH, END_NO_BODY, END_SHUTDOWN, WIRE_CONTROL,
    WIRE_PAYLOAD,
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

fn answer(ledger: &mut DeliveryLedger, items: &[Item]) -> Result<Checked, Fault> {
    let outs: Vec<Out> = items.iter().map(|item| item.0).collect();
    ledger.answer(&outs, |index| items[index].1)
}

/// One answer checked, and the bytes the connection is to be given for it, in order, read where
/// `items` holds them.
fn given(ledger: &mut DeliveryLedger, items: &[Item]) -> Vec<u8> {
    let checked = answer(ledger, items).unwrap();
    ledger.give(&checked, |index| items[index].1).pieces.concat()
}

/// The connection's writer took `count` more bytes of the placed runs, counted as the writer counts.
fn took(ledger: &mut DeliveryLedger, count: u64) {
    let queued = ledger.queued;
    Giving {
        pieces: smallvec::SmallVec::new(),
        written: &mut ledger.written,
        queued,
    }
    .took(usize::try_from(count).unwrap());
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

/// The connection takes everything placed and its flush succeeds: the carrier reports all of it.
fn flush(ledger: &mut DeliveryLedger) -> u64 {
    let rest = ledger.queued - ledger.written;
    took(ledger, rest);
    let total = ledger.written;
    ledger.flushed(progress(total, total, total)).unwrap();
    total
}

/// A whole answer with a four-byte body on `stream`: the bytes the connection is to be given.
fn serve(ledger: &mut DeliveryLedger, stream: u64) -> Vec<u8> {
    ledger.emitting(stream, E_BODY, 4);
    ledger.emitting(stream, E_END, 0);
    given(
        ledger,
        &[
            part(stream, WIRE_CONTROL, b"head"),
            part(stream, WIRE_PAYLOAD, b"body"),
            end(stream, END_FLUSH, 0),
        ],
    )
}

#[test]
fn an_answer_is_whole_only_when_the_carrier_took_all_of_it_and_the_flush_succeeded() {
    let mut ledger = ledger();
    let handles = ledger.admit(key(1)).unwrap();
    assert_eq!(serve(&mut ledger, 1), b"headbody");
    assert_eq!(handles.watch.record(), None, "placed is not delivered");
    // The connection took it all; the carrier has written half as whole records.
    took(&mut ledger, 8);
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
fn a_breach_places_nothing_of_that_answer_not_even_its_valid_prefix() {
    let mut ledger = ledger();
    let _handles = ledger.admit(key(1)).unwrap();
    let before = ledger.queued;
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
    assert_eq!(ledger.queued, before, "no byte of it is placed");
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
    took(&mut ledger, 8);
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

/// OPEN-3 16 (money): the ledger copies no answer byte. What the connection is given is read where
/// the caller holds it (the session's charged buffer), placing a run asks the heap for nothing, and a
/// write that failed gives nothing more.
#[test]
fn the_ledger_holds_no_answer_byte_and_gives_the_callers_own() {
    let mut ledger = ledger();
    let held: &'static [u8] = b"abcdef";
    let items = [part(0, WIRE_CONTROL, held)];
    let (checked, calls) = crate::support::allocations_during(|| answer(&mut ledger, &items));
    let checked = checked.unwrap();
    assert_eq!(calls, 0, "placing a run makes nothing");
    assert_eq!(checked.bytes(), 6);
    let block = held.as_ptr_range();
    let giving = ledger.give(&checked, |index| items[index].1);
    assert!(giving.pieces.iter().all(|piece| {
        let range = piece.as_ptr_range();
        block.start <= range.start && range.end <= block.end
    }));
    assert_eq!(giving.pieces.concat(), held);
    drop(giving);
    // The connection took half, then a write failed: the rest is never given, and nothing more is
    // placed.
    took(&mut ledger, 3);
    assert_eq!((ledger.written, ledger.queued), (3, 6));
    ledger.discard();
    assert_eq!(
        answer(&mut ledger, &[part(0, WIRE_CONTROL, b"x")]).unwrap_err(),
        Fault::Queue
    );
    // A run not all given places nothing after it either: it would stand behind bytes that never
    // went out.
    let mut behind = self::ledger();
    given(&mut behind, &[part(0, WIRE_CONTROL, b"abcdef")]);
    took(&mut behind, 5);
    assert_eq!(
        answer(&mut behind, &[part(0, WIRE_CONTROL, b"x")]).unwrap_err(),
        Fault::Queue
    );
    // The writer's count never passes what was placed.
    took(&mut behind, 100);
    assert_eq!((behind.written, behind.queued), (6, 6));
    given(&mut behind, &[part(0, WIRE_CONTROL, b"x")]);
    assert_eq!(behind.queued, 7);
}

// ---- credit for a stream the engine has left (ENGINE-OPEN-2 row 2) ----------------------------

/// Inbound body of `stream` the transport handed up (`STREAM_BODY`), as the driver's item.
fn body(stream: u64, len: u32) -> Item {
    (Out::Body { stream, len }, &[])
}

/// A ledger whose session stated small windows: 64 bytes a stream, 256 the connection.
fn windowed(multiplex: bool) -> DeliveryLedger {
    let session = if multiplex {
        Session::stated(true, 64, 256)
    } else {
        Session::stated(false, 0, 0)
    };
    let mut ledger = DeliveryLedger::default();
    answer(&mut ledger, &[(Out::Session(session), &[])]).unwrap();
    ledger
}

/// The engine resets `stream` and the transport ends it: the engine has left the stream.
fn leave(ledger: &mut DeliveryLedger, stream: u64) {
    assert!(ledger.stop(stream, ResponseStop::Cancelled, Instant::now()));
    answer(ledger, &[end(stream, END_FAILED, 0)]).unwrap();
}

#[test]
fn late_body_of_a_stream_the_engine_left_is_owed_as_credit_at_once_and_only_once() {
    let mut ledger = windowed(true);
    let one = ledger.admit(key(1)).unwrap();
    let _three = ledger.admit(key(3)).unwrap();
    // Forty bytes of the request's body arrived and core's reader took none of them.
    answer(&mut ledger, &[body(1, 40)]).unwrap();
    leave(&mut ledger, 1);
    assert_eq!(
        one.watch.record(),
        Some(DeliveryRecord {
            state: "none",
            reason: Some("cancelled"),
            body_bytes: 0
        })
    );
    // What the stream held when it went is credited as it goes.
    assert_eq!(ledger.take_owed(), Some((1, 40)));
    assert_eq!(ledger.take_owed(), None);
    // The caller's body was already on its way and keeps arriving: ten answers of 64 bytes, two and
    // a half times the connection window. Nobody will read them: all of each is owed at once.
    let mut credited = 40;
    for _ in 0..10 {
        let checked = answer(&mut ledger, &[body(1, 32), body(1, 32)]).unwrap();
        assert!(
            checked.outcome.left.is_empty(),
            "the ledger took what the driver says is owed: nobody else can give it again"
        );
        assert_eq!(
            ledger.take_owed(),
            Some((1, 64)),
            "one credit a stream for one answer"
        );
        assert_eq!(ledger.take_owed(), None, "and it is owed once");
        // The pieces still go up to core; its taking them credits nothing more.
        assert_eq!(ledger.taken(1, 64), None);
        assert_eq!(ledger.take_owed(), None);
        credited += 64;
    }
    assert_eq!(credited, 40 + 640, "every byte of the stream, each once");
    // The connection's other stream receives within the windows the session stated, and its
    // reader's taking is credited as ever.
    assert!(ledger.reads_socket());
    answer(&mut ledger, &[body(3, 64)]).unwrap();
    assert_eq!(ledger.taken(3, 64), Some(64));
}

#[test]
fn credit_owed_for_one_left_stream_is_one_credit_however_it_came_to_be_owed() {
    let mut ledger = windowed(true);
    let _one = ledger.admit(key(1)).unwrap();
    answer(&mut ledger, &[body(1, 40)]).unwrap();
    leave(&mut ledger, 1);
    // The credit for what the stream held is not given yet when its late bytes arrive.
    answer(&mut ledger, &[body(1, 24)]).unwrap();
    assert_eq!(ledger.take_owed(), Some((1, 64)));
    assert_eq!(ledger.take_owed(), None);
}

#[test]
fn a_session_with_one_stream_is_owed_no_credit_for_late_body() {
    let mut ledger = windowed(false);
    let _one = ledger.admit(key(1)).unwrap();
    leave(&mut ledger, 1);
    let checked = answer(&mut ledger, &[body(1, 64)]).unwrap();
    assert!(checked.outcome.left.is_empty());
    assert_eq!(
        ledger.take_owed(),
        None,
        "the engine stops reading its connection instead"
    );
}

#[test]
fn credit_owed_dies_with_the_connection() {
    let mut ledger = windowed(true);
    let _one = ledger.admit(key(1)).unwrap();
    leave(&mut ledger, 1);
    answer(&mut ledger, &[body(1, 64)]).unwrap();
    ledger.gone(Reason::CallerGone);
    assert_eq!(ledger.take_owed(), None, "nobody is left to give it to");
}

// ---- `part` is each answer's own (ENGINE-OPEN-2 row 18, note 3) --------------------------------

/// Two answers carried by ONE answer of the transport (one run): a four-byte head and a four-byte
/// body each. The write fails with `carried` bytes of the run on the carrier as whole records.
/// The states of the two records.
fn cut_at(carried: u64) -> (&'static str, &'static str) {
    let mut ledger = ledger();
    let one = ledger.admit(key(1)).unwrap();
    let three = ledger.admit(key(3)).unwrap();
    ledger.emitting(1, E_BODY, 4);
    ledger.emitting(3, E_BODY, 4);
    let run = given(
        &mut ledger,
        &[
            part(1, WIRE_CONTROL, b"head"),
            part(1, WIRE_PAYLOAD, b"body"),
            part(3, WIRE_CONTROL, b"head"),
            part(3, WIRE_PAYLOAD, b"body"),
        ],
    );
    assert_eq!(run.len(), 16);
    took(&mut ledger, carried);
    ledger.discard();
    ledger.retire(
        CarrierProgress {
            fault: Some(CarrierFault::Io),
            ..progress(carried, carried, carried)
        },
        Reason::CallerGone,
    );
    let state = |handles: &ResponseHandles| {
        let record = handles
            .watch
            .record()
            .expect("a retired answer has its record");
        assert_eq!(record.reason, Some("caller_gone"));
        assert_eq!(
            record.body_bytes, 4,
            "what the transport made for THIS answer"
        );
        record.state
    };
    (state(&one), state(&three))
}

#[test]
fn a_run_cut_by_a_failed_write_is_part_only_for_the_answers_whose_own_body_byte_left() {
    assert_eq!(cut_at(0), ("none", "none"));
    assert_eq!(cut_at(4), ("none", "none"), "the first answer's head alone");
    assert_eq!(cut_at(5), ("part", "none"), "one body byte of the first");
    assert_eq!(cut_at(8), ("part", "none"));
    assert_eq!(
        cut_at(12),
        ("part", "none"),
        "the second answer's head alone is no body byte of it"
    );
    assert_eq!(cut_at(13), ("part", "part"));
    assert_eq!(
        cut_at(16),
        ("part", "part"),
        "all of it on the carrier and no flush: nothing is whole"
    );
}

#[test]
fn a_failed_write_s_last_reading_never_makes_an_ended_answer_whole() {
    let mut ledger = ledger();
    let one = ledger.admit(key(1)).unwrap();
    serve(&mut ledger, 1);
    // Every byte through the end mark is on the carrier, and the flush after it did not succeed.
    took(&mut ledger, 8);
    ledger.discard();
    ledger.retire(
        CarrierProgress {
            fault: Some(CarrierFault::Io),
            ..progress(8, 8, 8)
        },
        Reason::CallerGone,
    );
    assert_eq!(
        one.watch.record(),
        Some(DeliveryRecord {
            state: "part",
            reason: Some("caller_gone"),
            body_bytes: 4
        })
    );
}
