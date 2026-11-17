// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::response_delivery::CarrierFault;

fn ledger(spans: usize, responses: usize) -> DeliveryLedger {
    DeliveryLedger::new(
        NonZeroUsize::new(spans).unwrap(),
        NonZeroUsize::new(responses).unwrap(),
    ).unwrap()
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

fn part(stream: u64, class: WireClass, len: usize) -> WireEvent {
    WireEvent::Part { stream, class, len }
}

fn release(ledger: &mut DeliveryLedger, response: &ResponseHandles, stream: u64) {
    response.release.freeze(key(stream), 1).unwrap();
    response.release.publish(key(stream), 1).unwrap();
    assert_eq!(ledger.next_control(), Some(DeliveryControl::Release { stream }));
}

#[test]
fn real_partial_prefix_is_attributed_once_before_later_io_failure() {
    let mut ledger = ledger(8, 2);
    let first = ledger.admit(key(1)).unwrap();
    let second = ledger.admit(key(2)).unwrap();
    ledger.adopt_batch(&[
        part(1, WireClass::Control, 3),
        part(2, WireClass::Payload, 2),
        part(1, WireClass::Payload, 4),
    ]).unwrap();
    ledger.observe(progress(9, 3, 0)).unwrap();
    assert!(!first.watch.snapshot().first_payload_written);
    assert!(!second.watch.snapshot().first_payload_written);
    let mut last = progress(9, 4, 0);
    last.fault = Some(CarrierFault::Io);
    assert_eq!(ledger.observe(last), Err(ResponseStop::Carrier(CarrierFault::Io)));
    assert!(!first.watch.snapshot().first_payload_written);
    assert!(second.watch.snapshot().first_payload_written);
    assert!(second.watch.snapshot().terminal.is_none());
    ledger.retire_carrier(last, ResponseStop::Carrier(CarrierFault::Io));
    assert_eq!(second.watch.snapshot().terminal,
        Some(DeliveryTerminal::Failed(ResponseStop::Carrier(CarrierFault::Io))));
}

#[test]
fn wire_ready_waits_for_ordered_producer_end_and_reader_eof() {
    let mut ledger = ledger(3, 1);
    let response = ledger.admit(key(1)).unwrap();
    release(&mut ledger, &response, 1);
    ledger.adopt_batch(&[
        part(1, WireClass::Control, 2),
        WireEvent::End { stream: 1, requirement: CompletionRequirement::Flush },
    ]).unwrap();
    ledger.observe(progress(2, 2, 1)).unwrap();
    assert!(ledger.complete_flush(2).is_err());
    ledger.observe(progress(2, 2, 2)).unwrap();
    ledger.complete_flush(2).unwrap();
    assert!(response.watch.snapshot().terminal.is_none());
    ledger.producer_ended(1).unwrap();
    assert!(response.watch.snapshot().terminal.is_none());
    ledger.reader_eof(1).unwrap();
    assert_eq!(response.watch.snapshot(), DeliverySnapshot {
        first_payload_written: false,
        terminal: Some(DeliveryTerminal::Complete),
    });
    ledger.stop(1, ResponseStop::Protocol).unwrap();
    assert_eq!(response.watch.snapshot().terminal, Some(DeliveryTerminal::Complete));
}

#[test]
fn pending_cancel_dominates_release_without_inventing_a_terminal() {
    let mut ledger = ledger(2, 1);
    let response = ledger.admit(key(1)).unwrap();
    response.release.freeze(key(1), 1).unwrap();
    assert!(response.release.publish(key(1), 2).is_err());
    response.release.publish(key(1), 1).unwrap();
    response.cancel.cancel(ResponseStop::Cancelled);
    assert_eq!(ledger.next_control(), Some(DeliveryControl::Cancel {
        stream: 1, reason: ResponseStop::Cancelled,
    }));
    assert_eq!(ledger.next_control(), None);
    assert!(response.watch.snapshot().terminal.is_none());
    assert!(ledger.settle_stopped(1).is_err());
    ledger.quiescent(1).unwrap();
    ledger.settle_stopped(1).unwrap();
    assert_eq!(response.watch.snapshot().terminal,
        Some(DeliveryTerminal::Failed(ResponseStop::Cancelled)));
}

#[test]
fn invalid_answer_does_not_adopt_even_its_valid_prefix() {
    let mut ledger = ledger(3, 1);
    ledger.admit(key(1)).unwrap();
    assert!(ledger.adopt_batch(&[
        part(1, WireClass::Payload, 1), part(99, WireClass::Payload, 1),
    ]).is_err());
    assert_eq!(ledger.adopted_prefix(), 0);
    assert!(ledger.observe(progress(1, 1, 1)).is_err());
}

#[test]
fn response_retirement_requires_protocol_input_and_settlement_ack() {
    let mut ledger = ledger(2, 1);
    let response = ledger.admit(key(1)).unwrap();
    release(&mut ledger, &response, 1);
    ledger.adopt_batch(&[WireEvent::End {
        stream: 1, requirement: CompletionRequirement::Shutdown,
    }]).unwrap();
    ledger.complete_flush(0).unwrap();
    ledger.producer_ended(1).unwrap();
    ledger.reader_eof(1).unwrap();
    assert!(response.watch.snapshot().terminal.is_none());
    ledger.complete_shutdown(0).unwrap();
    assert!(ledger.retire_response(1).is_err());
    assert_eq!(ledger.next_control(), Some(DeliveryControl::Settled { stream: 1 }));
    ledger.settled_ack(1).unwrap();
    assert!(ledger.retire_response(1).is_err());
    ledger.quiescent(1).unwrap();
    ledger.retire_response(1).unwrap();
    assert!(ledger.admit(key(1)).is_err());
    assert!(ledger.admit(key(2)).is_err(), "retained handles still own cell capacity");
    drop(response);
    ledger.admit(key(2)).unwrap();
}

#[test]
fn failed_response_retires_after_cancelled_input_is_joined_without_faking_eof() {
    let mut ledger = ledger(2, 1);
    let response = ledger.admit(key(1)).unwrap();
    ledger.stop(1, ResponseStop::Cancelled).unwrap();
    ledger.quiescent(1).unwrap();
    ledger.settle_stopped(1).unwrap();
    assert_eq!(ledger.next_control(), Some(DeliveryControl::Settled { stream: 1 }));
    ledger.settled_ack(1).unwrap();
    assert!(ledger.retire_response(1).is_err());
    ledger.input_retired(1).unwrap();
    ledger.retire_response(1).unwrap();
    assert_eq!(response.watch.snapshot().terminal, Some(DeliveryTerminal::Failed(ResponseStop::Cancelled)));
}

#[test]
fn dropped_prepared_answer_does_not_consume_offset_or_capacity() {
    let mut ledger = ledger(1, 1);
    ledger.admit(key(1)).unwrap();
    let events = [part(1, WireClass::Payload, 1)];
    drop(ledger.prepare_batch(&events).unwrap());
    assert_eq!(ledger.adopted_prefix(), 0);
    ledger.prepare_batch(&events).unwrap().commit();
    assert_eq!(ledger.adopted_prefix(), 1);
}

#[test]
fn span_capacity_is_returned_by_actual_write_not_plaintext_acceptance() {
    let mut ledger = ledger(1, 1);
    ledger.admit(key(1)).unwrap();
    ledger.adopt_batch(&[part(1, WireClass::Payload, 2)]).unwrap();
    ledger.observe(progress(2, 0, 0)).unwrap();
    assert!(ledger.adopt_batch(&[part(1, WireClass::Control, 1)]).is_err());
    ledger.observe(progress(2, 2, 0)).unwrap();
    ledger.adopt_batch(&[part(1, WireClass::Control, 1)]).unwrap();
}

#[test]
fn later_carrier_failure_does_not_rewrite_a_completed_sibling() {
    let mut ledger = ledger(4, 2);
    let first = ledger.admit(key(1)).unwrap();
    let second = ledger.admit(key(2)).unwrap();
    release(&mut ledger, &first, 1);
    ledger.adopt_batch(&[
        part(1, WireClass::Control, 2),
        WireEvent::End { stream: 1, requirement: CompletionRequirement::Flush },
        part(2, WireClass::Payload, 2),
    ]).unwrap();
    assert_eq!(ledger.next_fence(), Some((2, CompletionRequirement::Flush)));
    ledger.observe(progress(2, 2, 2)).unwrap();
    ledger.complete_flush(2).unwrap();
    ledger.producer_ended(1).unwrap();
    ledger.reader_eof(1).unwrap();
    let mut last = progress(4, 3, 2);
    last.fault = Some(CarrierFault::WriteZero);
    ledger.retire_carrier(last, ResponseStop::Carrier(CarrierFault::WriteZero));
    assert_eq!(first.watch.snapshot().terminal, Some(DeliveryTerminal::Complete));
    assert!(!first.watch.snapshot().first_payload_written);
    assert!(second.watch.snapshot().first_payload_written);
    assert_eq!(second.watch.snapshot().terminal,
        Some(DeliveryTerminal::Failed(ResponseStop::Carrier(CarrierFault::WriteZero))));
}

#[test]
fn shutdown_does_not_stand_in_for_a_checked_flush() {
    let mut ledger = ledger(1, 1);
    let response = ledger.admit(key(1)).unwrap();
    release(&mut ledger, &response, 1);
    ledger.adopt_batch(&[WireEvent::End {
        stream: 1, requirement: CompletionRequirement::Shutdown,
    }]).unwrap();
    ledger.producer_ended(1).unwrap();
    ledger.reader_eof(1).unwrap();
    ledger.complete_shutdown(0).unwrap();
    assert!(response.watch.snapshot().terminal.is_none());
    ledger.complete_flush(0).unwrap();
    assert!(response.watch.snapshot().terminal.is_none());
    ledger.complete_shutdown(0).unwrap();
    assert_eq!(response.watch.snapshot().terminal, Some(DeliveryTerminal::Complete));
}

#[test]
fn abort_and_quiescence_keep_queued_spans_until_actual_retirement() {
    let mut ledger = ledger(2, 1);
    let response = ledger.admit(key(1)).unwrap();
    ledger.adopt_batch(&[
        part(1, WireClass::Payload, 4),
        WireEvent::Abort { stream: 1 },
        WireEvent::Quiescent { stream: 1 },
    ]).unwrap();
    ledger.observe(progress(4, 1, 0)).unwrap();
    assert!(ledger.settle_stopped(1).is_err());
    assert!(response.watch.snapshot().terminal.is_none());
    ledger.retire_carrier(progress(4, 1, 0), ResponseStop::CarrierRetired);
    assert!(response.watch.snapshot().first_payload_written);
    assert_eq!(response.watch.snapshot().terminal, Some(DeliveryTerminal::Failed(ResponseStop::Protocol)));
}

#[test]
fn input_observers_wake_the_owner_but_cannot_publish_terminal_receipts() {
    struct Wakeups(AtomicUsize);
    impl futures::task::ArcWake for Wakeups {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::AcqRel);
        }
    }
    let mut ledger = ledger(1, 1);
    let response = ledger.admit(key(1)).unwrap();
    release(&mut ledger, &response, 1);
    ledger.adopt_batch(&[WireEvent::End {
        stream: 1, requirement: CompletionRequirement::Flush,
    }]).unwrap();
    ledger.complete_flush(0).unwrap();
    let wakeups = Arc::new(Wakeups(AtomicUsize::new(0)));
    let waker = futures::task::waker_ref(&wakeups);
    let mut cx = Context::from_waker(&waker);
    assert!(ledger.poll_control(&mut cx).is_pending());
    response.input.producer_ended();
    response.input.reader_eof();
    assert!(wakeups.0.load(Ordering::Acquire) > 0);
    assert!(response.watch.snapshot().terminal.is_none());
    assert_eq!(ledger.poll_control(&mut cx), Poll::Ready(DeliveryControl::Settled { stream: 1 }));
    assert_eq!(response.watch.snapshot().terminal, Some(DeliveryTerminal::Complete));
}

#[test]
fn carrier_fault_prevents_new_admission_and_pending_release_before_retirement() {
    let mut ledger = ledger(2, 2);
    let response = ledger.admit(key(1)).unwrap();
    response.release.freeze(key(1), 1).unwrap();
    response.release.publish(key(1), 1).unwrap();
    let mut last = progress(0, 0, 0);
    last.fault = Some(CarrierFault::Io);
    assert!(ledger.observe(last).is_err());
    assert!(ledger.admit(key(2)).is_err());
    assert_eq!(ledger.next_control(), None);
    assert!(response.watch.snapshot().terminal.is_none());
    ledger.retire_carrier(last, ResponseStop::Carrier(CarrierFault::Io));
    assert_eq!(ledger.next_control(), Some(DeliveryControl::Settled { stream: 1 }));
}

#[test]
fn metadata_quote_refuses_overflow_before_any_allocation() {
    let one = NonZeroUsize::new(1).unwrap();
    let huge = NonZeroUsize::new(usize::MAX).unwrap();
    assert_eq!(DeliveryLedger::required_storage(huge, one), Err(ResponseStop::Capacity));
    assert_eq!(DeliveryLedger::required_storage(one, huge), Err(ResponseStop::Capacity));
}
