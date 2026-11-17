// SPDX-License-Identifier: Apache-2.0
use super::*;
use hyper::rt::Write;
use hyper::serialization::{CompletionRequirement, SerializedClass, SerializedEvent};

#[test]
fn terminal_gate_retains_bytes_until_release_and_does_not_complete_from_input_end() {
    let mut mio = MemIo::new();
    let plan = mio.attributed_output(2, 16, 1024);
    plan.admit(41, 10_000).unwrap();
    plan.record(&[
        SerializedEvent::Span {
            stream: 41,
            class: SerializedClass::Payload,
            len: 3,
        },
        SerializedEvent::ReleaseBarrier { stream: 41 },
        SerializedEvent::Span {
            stream: 41,
            class: SerializedClass::Control,
            len: 5,
        },
        SerializedEvent::End {
            stream: 41,
            requirement: CompletionRequirement::Flush,
        },
        SerializedEvent::Quiescent { stream: 41 },
    ])
    .unwrap();
    let mut stream = mio.io();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut cx, b"abc0\r\n\r\n"),
        Poll::Ready(Ok(8))
    ));
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
    assert!(
        plan.record(&[
            SerializedEvent::Span {
                stream: 7,
                class: SerializedClass::Control,
                len: 9
            },
            SerializedEvent::Span {
                stream: 7,
                class: SerializedClass::Payload,
                len: 4
            },
        ])
        .is_err()
    );
    assert!(plan.faulted());
    let mut stream = mio.io();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut cx, b"unattributed"),
        Poll::Ready(Err(_))
    ));
}

#[test]
fn short_answers_retain_every_control_payload_boundary_and_end_once() {
    use crate::records::{Nested, Pod, U32s};
    #[derive(Default)]
    struct Short {
        room: usize,
        records: Vec<(u16, Vec<u8>)>,
    }
    impl Writer for Short {
        fn put_parts(&mut self, tag: u16, parts: &[&[u8]]) -> Result<(), Full> {
            self.put(tag, &parts.concat())
        }
        fn put_pod_nested<T: Pod>(
            &mut self,
            _: u16,
            _: &T,
            _: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
        ) -> Result<(), Full> {
            unreachable!()
        }
        fn put(&mut self, tag: u16, bytes: &[u8]) -> Result<(), Full> {
            let size = bytes.len() + 8;
            if size > self.room {
                return Err(Full);
            }
            self.room -= size;
            self.records.push((tag, bytes.to_vec()));
            Ok(())
        }
        fn put_pod<T: Pod>(&mut self, tag: u16, value: &T) -> Result<(), Full> {
            self.put(tag, value.as_bytes())
        }
        fn put_pod_tail<T: Pod>(&mut self, tag: u16, value: &T, tail: &[u8]) -> Result<(), Full> {
            let mut bytes = value.as_bytes().to_vec();
            bytes.extend_from_slice(tail);
            self.put(tag, &bytes)
        }
        fn put_u32s(
            &mut self,
            _: u16,
            _: impl FnOnce(&mut U32s<'_>) -> Result<(), Full>,
        ) -> Result<(), Full> {
            unreachable!()
        }
        fn put_text(&mut self, _: u16, _: &str) -> Result<(), Full> {
            unreachable!()
        }
        fn put_pair(&mut self, _: u16, _: &str, _: &[u8]) -> Result<(), Full> {
            unreachable!()
        }
        fn put_fact(&mut self, _: u32, _: u64) -> Result<(), Full> {
            unreachable!()
        }
        fn put_fact_text(&mut self, _: u32, _: &str) -> Result<(), Full> {
            unreachable!()
        }
        fn put_metric(&mut self, _: u32, _: u32, _: f64, _: &[&str]) -> Result<(), Full> {
            unreachable!()
        }
        fn put_nested(
            &mut self,
            _: u16,
            _: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
        ) -> Result<(), Full> {
            unreachable!()
        }
    }
    let mut mio = MemIo::new();
    let plan = mio.attributed_output(1, 8, 128);
    plan.admit(101, 10_000).unwrap();
    plan.record(&[
        SerializedEvent::Span {
            stream: 101,
            class: SerializedClass::Control,
            len: 3,
        },
        SerializedEvent::Span {
            stream: 101,
            class: SerializedClass::Payload,
            len: 32,
        },
        SerializedEvent::ReleaseBarrier { stream: 101 },
        SerializedEvent::Span {
            stream: 101,
            class: SerializedClass::Control,
            len: 5,
        },
        SerializedEvent::End {
            stream: 101,
            requirement: CompletionRequirement::Flush,
        },
        SerializedEvent::Quiescent { stream: 101 },
    ])
    .unwrap();
    plan.release(101).unwrap();
    let wire = [b"20\r".as_slice(), &[42; 32], b"0\r\n\r\n"].concat();
    let mut stream = mio.io();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut cx, &wire),
        Poll::Ready(Ok(40))
    ));
    let mut all = Vec::new();
    for _ in 0..32 {
        let mut answer = Short {
            room: 32,
            records: Vec::new(),
        };
        let done = mio.flush_attributed(&mut answer).unwrap();
        all.extend(answer.records);
        if done {
            break;
        }
    }
    let mut payload = Vec::new();
    let mut encoded = Vec::new();
    let mut ends = 0;
    for (tag, bytes) in all {
        if tag == tag::WIRE_PART {
            let (header, tail) = crate::records::Rec { tag, body: &bytes }
                .pod_tail::<crate::kinds::transport::transport::WirePart>()
                .unwrap();
            assert_eq!(header.stream, 101);
            encoded.extend_from_slice(tail);
            if header.class == crate::kinds::transport::transport::WIRE_PAYLOAD {
                payload.extend_from_slice(tail);
            }
        } else if tag == tag::WIRE_END {
            ends += 1;
        }
    }
    assert_eq!(encoded, wire);
    assert_eq!(payload, vec![42; 32]);
    assert_eq!(ends, 1);
    assert!(plan.is_live(101));
    plan.input_end(101).unwrap();
    assert!(plan.is_live(101));
    plan.settled(101).unwrap();
    assert!(!plan.is_live(101));
}

#[test]
fn malformed_lifecycle_order_inside_one_batch_is_rejected_atomically() {
    for events in [
        vec![
            SerializedEvent::End {
                stream: 41,
                requirement: CompletionRequirement::Flush,
            },
            SerializedEvent::Span {
                stream: 41,
                class: SerializedClass::Control,
                len: 1,
            },
        ],
        vec![
            SerializedEvent::Abort { stream: 41 },
            SerializedEvent::End {
                stream: 41,
                requirement: CompletionRequirement::Flush,
            },
        ],
    ] {
        let mut mio = MemIo::new();
        let provenance = mio.attributed_output(1, 8, 1024);
        provenance.admit(41, 1_000).unwrap();
        assert!(provenance.record(&events).is_err());
        let pipes = lock(&mio.shared.pipes);
        let plan = pipes.plan.as_ref().unwrap();
        assert!(plan.queue.is_empty());
        assert_eq!(plan.serialized, 0);
        assert!(plan.fault);
    }
}
