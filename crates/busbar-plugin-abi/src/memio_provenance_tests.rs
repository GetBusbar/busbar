// SPDX-License-Identifier: Apache-2.0
use super::*;
use hyper::serialization::{CompletionRequirement, SerializedClass, SerializedEvent};
use hyper::rt::Write;

#[test]
fn terminal_gate_retains_bytes_until_release_and_does_not_complete_from_input_end() {
    let mut mio = MemIo::new();
    let plan = mio.attributed_output(2, 16, 1024);
    plan.admit(41, 10_000).unwrap();
    plan.record(&[
        SerializedEvent::Span { stream: 41, class: SerializedClass::Payload, len: 3 },
        SerializedEvent::ReleaseBarrier { stream: 41 },
        SerializedEvent::Span { stream: 41, class: SerializedClass::Control, len: 5 },
        SerializedEvent::End { stream: 41, requirement: CompletionRequirement::Flush },
        SerializedEvent::Quiescent { stream: 41 },
    ]).unwrap();
    let mut stream = mio.io();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"abc0\r\n\r\n"), Poll::Ready(Ok(8))));
    assert_eq!(plan.eligible_bytes(), 3);
    plan.input_end(41).unwrap();
    assert_eq!(plan.eligible_bytes(), 3);
    plan.release(41).unwrap();
    assert_eq!(plan.eligible_bytes(), 8);
    assert!(plan.is_live(41));
    plan.settled(41).unwrap();
    // Pending plan entries still hold attribution and cannot lose identity.
    assert!(plan.is_live(41));
}

#[test]
fn rejected_batch_is_atomic_and_poisoned_before_io_acceptance() {
    let mut mio = MemIo::new();
    let plan = mio.attributed_output(1, 1, 64);
    plan.admit(7, 10_000).unwrap();
    assert!(plan.record(&[
        SerializedEvent::Span { stream: 7, class: SerializedClass::Control, len: 9 },
        SerializedEvent::Span { stream: 7, class: SerializedClass::Payload, len: 4 },
    ]).is_err());
    assert!(plan.faulted());
    let mut stream = mio.io();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(Pin::new(&mut stream).poll_write(&mut cx, b"unattributed"), Poll::Ready(Err(_))));
}
