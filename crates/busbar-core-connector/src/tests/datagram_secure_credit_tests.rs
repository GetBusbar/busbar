// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Secure input consumption is distinct from the credit needed for its later ABI crossing.

use super::*;
use crate::datagram::{Leg, LineStep, PortAssociations, RawIngress};
use crate::framer::{Yielded, FRAME_CAP};
use crate::publication::Memory;
use std::task::{Context, Poll, Waker};

const PLAINTEXT: &[u8] = b"opened exactly once after credit retirement";

fn established() -> (DatagramFraming, Far, Arc<Scripted>, Instant) {
    let mut rig = rig(Knobs::default());
    rig.first_check();
    rig.pump(200);
    assert!(rig.host.presented());
    assert_eq!(rig.host.bound(), Some(rig.far.addr));
    assert!(rig.door.st.lock().unwrap().secured.is_empty());
    (rig.host, rig.far, rig.door, rig.now)
}

fn packet(far: &mut Far, host: SocketAddr, plaintext: &[u8]) -> Vec<u8> {
    far.a.seal(plaintext).expect("real DTLS seal");
    let (to, packet) = far.a.poll_wire().expect("one sealed DTLS record");
    assert_eq!(to, host);
    assert!(far.a.poll_wire().is_none());
    packet
}

fn received(port: &PortAssociations, id: u64) -> usize {
    let associations = port.lock();
    let framing = associations
        .framings
        .get(&id)
        .or_else(|| associations.out.get(&id)?.continuing.as_ref())
        .expect("the live association is home or owns a continuation");
    framing.secure.as_ref().unwrap().ingest_calls()
}

fn no_original_queued(port: &PortAssociations, id: u64) {
    let associations = port.lock();
    let out = associations.out.get(&id).expect("the accepted secure turn");
    assert!(
        out.owed.is_empty(),
        "consumed raw input is never queued again"
    );
    assert!(out.continuing.as_ref().unwrap().continuing());
}

fn answered(raw: RawIngress, id: u64) -> Yielded {
    let RawIngress::Answered(mut output) = raw else {
        panic!("prepaid output credit admits this real secure datagram");
    };
    assert_eq!(output.len(), 1);
    let (owner, yielded) = output.pop().unwrap();
    assert_eq!(owner, id);
    yielded.unwrap()
}

fn poll(port: &PortAssociations, id: u64, now: Instant) -> LineStep {
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(result) = port.poll_line(id, &mut context, None, false, now, &|_, _| {}) else {
        panic!("the returned association has no outstanding publication barrier");
    };
    result.unwrap()
}

#[test]
fn consumed_secure_datagram_waits_as_a_continuation_and_is_not_reingested() {
    for queued in [false, true] {
        for cancel in [false, true] {
            let (mut host, mut far, door, now) = established();
            let host_addr: SocketAddr = host.local.parse().unwrap();
            let sealed = packet(&mut far, host_addr, PLAINTEXT);
            let before = host.secure.as_ref().unwrap().ingest_calls();

            let probe = Memory::new(Some(usize::MAX));
            host.memory(Arc::clone(&probe));
            assert!(host.prepare_output());
            let crossing = probe.used();
            host.release_output_reservation();
            assert_eq!(probe.used(), 0);
            let reader_bytes = FRAME_CAP;
            let reader_credit = Memory::reservation_size(reader_bytes).unwrap();
            let memory = Memory::new(Some(crossing + reader_credit));
            let credit = memory.reserve(reader_bytes).unwrap();
            let bytes = vec![b'r'; reader_bytes];
            let reader = credit.reader_on(Leg::Upstream);
            let transfer = reader.copying();
            drop(credit);
            let port = PortAssociations::new();
            host.memory(if queued {
                Memory::new(None)
            } else {
                Arc::clone(&memory)
            });
            let id = port.add(host).unwrap();

            let yielded = if queued {
                let input = crate::datagram::Across {
                    stream: 1,
                    bytes: Vec::new(),
                    end_of_frame: true,
                };
                let mut context = Context::from_waker(Waker::noop());
                let Poll::Ready(Ok(LineStep::Batch {
                    yielded,
                    accepted: true,
                })) = port.poll_line(id, &mut context, Some(&input), false, now, &|_, _| {})
                else {
                    panic!("the initial empty Emit returns its first checked batch");
                };
                drop(yielded);
                assert!(port
                    .datagram_incremental(far.addr, &sealed, now, &|_, _| {})
                    .is_empty());
                port.published(id);
                let LineStep::Batch {
                    yielded,
                    accepted: false,
                } = poll(&port, id, now)
                else {
                    panic!("the queued packet follows the completed older Emit");
                };
                assert!(yielded.pieces.is_empty());
                drop(yielded);
                port.published(id);
                let old_memory = {
                    let mut associations = port.lock();
                    associations
                        .out
                        .get_mut(&id)
                        .unwrap()
                        .continuing
                        .as_mut()
                        .unwrap()
                        .memory
                        .replace(Arc::clone(&memory))
                };
                drop(old_memory);
                let LineStep::Batch { yielded, accepted } = poll(&port, id, now) else {
                    panic!("consumed queued raw input publishes its retained secure continuation");
                };
                assert!(
                    !accepted,
                    "an older raw operation never takes a held application job"
                );
                yielded
            } else {
                answered(port.raw_datagram(far.addr, &sealed, now, &|_, _| {}), id)
            };
            assert!(yielded.continuing);
            assert!(
                yielded.pieces.is_empty(),
                "the plaintext ABI crossing still lacks credit"
            );
            drop(yielded);
            assert_eq!(received(&port, id), before + 1);
            assert!(door.st.lock().unwrap().secured.is_empty());
            no_original_queued(&port, id);
            assert_eq!(
                port.raw_busy_dropped(),
                0,
                "this packet was accepted by security"
            );
            port.published(id);
            assert!(matches!(poll(&port, id, now), LineStep::Credit));
            assert_eq!(received(&port, id), before + 1);
            no_original_queued(&port, id);

            if cancel {
                port.remove(id);
                assert!(port.is_empty());
                assert_eq!(
                    memory.used(),
                    reader_credit,
                    "cancel retires owned plaintext"
                );
                drop(bytes);
                drop(reader);
                drop(transfer);
                assert_eq!(memory.used(), 0);
                assert!(door.st.lock().unwrap().secured.is_empty());
                continue;
            }
            drop(bytes);
            drop(reader);
            drop(transfer);
            let LineStep::Batch { yielded, accepted } = poll(&port, id, now) else {
                panic!("actual reader retirement enables the retained plaintext crossing");
            };
            assert!(
                !accepted,
                "resuming secure plaintext takes no fresh application input"
            );
            assert_eq!(yielded.pieces.len(), 1);
            assert_eq!(yielded.pieces[0].stream, 1);
            assert_eq!(yielded.pieces[0].bytes, PLAINTEXT);
            drop(yielded);
            port.published(id);
            assert!(matches!(poll(&port, id, now), LineStep::Complete));
            assert_eq!(received(&port, id), before + 1);
            assert_eq!(door.st.lock().unwrap().secured, vec![PLAINTEXT.to_vec()]);

            let next = b"next independent secure packet";
            let sealed = packet(&mut far, host_addr, next);
            let yielded = answered(port.raw_datagram(far.addr, &sealed, now, &|_, _| {}), id);
            assert_eq!(yielded.pieces.len(), 1);
            assert_eq!(yielded.pieces[0].bytes, next);
            drop(yielded);
            port.published(id);
            assert!(matches!(poll(&port, id, now), LineStep::Complete));
            assert_eq!(received(&port, id), before + 2);
            assert_eq!(
                door.st.lock().unwrap().secured,
                vec![PLAINTEXT.to_vec(), next.to_vec()]
            );
            assert_eq!(port.raw_busy_dropped(), 0);
            port.remove(id);
            assert_eq!(memory.used(), 0);
        }
    }
}

#[test]
fn credit_before_secure_ingest_leaves_the_datagram_unaccepted_and_raw_readiness_counts_it() {
    let (mut host, mut far, door, now) = established();
    let host_addr: SocketAddr = host.local.parse().unwrap();
    let sealed = packet(&mut far, host_addr, PLAINTEXT);
    let before = host.secure.as_ref().unwrap().ingest_calls();
    host.memory(Memory::new(Some(1)));
    assert!(matches!(
        host.datagram_step(far.addr, &sealed, now).unwrap(),
        LineStep::Credit
    ));
    assert!(!host.continuing());
    assert_eq!(host.secure.as_ref().unwrap().ingest_calls(), before);
    let port = PortAssociations::new();
    let id = port.add(host).unwrap();
    assert!(matches!(
        port.raw_datagram(far.addr, &sealed, now, &|_, _| {}),
        RawIngress::BusyDropped
    ));
    assert_eq!(port.raw_busy_dropped(), 1);
    assert!(matches!(
        port.raw_datagram_with_publication(far.addr, &sealed, now, &|_, _| {}, |_| {
            panic!("a no-credit association has no checked continuation to publish");
        }),
        RawIngress::BusyDropped
    ));
    assert_eq!(port.raw_busy_dropped(), 2);
    assert_eq!(received(&port, id), before);
    assert!(door.st.lock().unwrap().secured.is_empty());
    assert!(
        port.lock().out.is_empty(),
        "preaccept refusal creates no continuation or queued copy"
    );
    port.remove(id);
}

#[test]
fn ready_secure_continuation_precedes_the_next_raw_datagram() {
    let (host, mut far, door, now) = established();
    let host_addr: SocketAddr = host.local.parse().unwrap();
    let mut first = packet(&mut far, host_addr, b"first channel message");
    // Two valid records force another checked secure batch before fresh admission.
    first.extend(packet(&mut far, host_addr, b"continued channel message"));
    let second = packet(&mut far, host_addr, b"second channel message");
    let before = host.secure.as_ref().unwrap().ingest_calls();
    let port = PortAssociations::new();
    let id = port.add(host).unwrap();
    let first = answered(port.raw_datagram(far.addr, &first, now, &|_, _| {}), id);
    assert_eq!(first.pieces.len(), 1);
    assert_eq!(first.pieces[0].bytes, b"first channel message");
    drop(first);
    port.published(id);
    {
        let associations = port.lock();
        let out = associations.out.get(&id).unwrap();
        assert!(!out.publishing);
        assert!(out.continuing.is_some());
        assert!(out.owed.is_empty());
    }
    // The Pairing continuation is runnable but deliberately has not been polled.
    let mut continued = Vec::new();
    let second = answered(
        port.raw_datagram_with_publication(far.addr, &second, now, &|_, _| {}, |batches| {
            for (owner, batch) in batches {
                assert_eq!(owner, id);
                let batch = batch.unwrap();
                continued.extend(batch.pieces.iter().map(|piece| piece.bytes.clone()));
                drop(batch);
                port.published(owner);
            }
        }),
        id,
    );
    assert_eq!(continued, vec![b"continued channel message".to_vec()]);
    assert_eq!(second.pieces.len(), 1);
    assert_eq!(second.pieces[0].bytes, b"second channel message");
    drop(second);
    port.published(id);
    assert!(matches!(poll(&port, id, now), LineStep::Complete));
    assert_eq!(received(&port, id), before + 2);
    assert_eq!(
        door.st.lock().unwrap().secured,
        vec![
            b"first channel message".to_vec(),
            b"continued channel message".to_vec(),
            b"second channel message".to_vec()
        ]
    );
    assert_eq!(port.raw_busy_dropped(), 0);
    port.remove(id);
    assert!(port.is_empty());
}

#[test]
fn ready_secure_service_is_bounded_and_does_not_queue_fresh_raw_input() {
    let (mut host, mut far, door, now) = established();
    let memory = Memory::new(None);
    host.memory(Arc::clone(&memory));
    let host_addr: SocketAddr = host.local.parse().unwrap();
    let mut first = packet(&mut far, host_addr, b"first");
    for _ in 0..6 {
        first.extend(packet(&mut far, host_addr, b"continued"));
    }
    let second = packet(&mut far, host_addr, b"fresh");
    let before = host.secure.as_ref().unwrap().ingest_calls();
    let port = PortAssociations::new();
    let id = port.add(host).unwrap();
    drop(answered(
        port.raw_datagram(far.addr, &first, now, &|_, _| {}),
        id,
    ));
    port.published(id);
    let mut batches = 0;
    let raw = port.raw_datagram_with_publication(far.addr, &second, now, &|_, _| {}, |output| {
        for (owner, batch) in output {
            assert_eq!(owner, id);
            assert!(port.lock().out.get(&id).unwrap().publishing);
            let batch = batch.unwrap();
            assert_eq!(batch.pieces.len(), 1);
            assert_eq!(batch.pieces[0].bytes, b"continued");
            batches += 1;
            drop(batch);
            port.published(owner);
        }
    });
    assert!(matches!(raw, RawIngress::BusyDropped));
    assert_eq!(batches, 4, "one shared-port turn has a fixed work budget");
    assert_eq!(
        received(&port, id),
        before + 1,
        "fresh raw input was not ingested"
    );
    no_original_queued(&port, id);
    assert_eq!(port.raw_busy_dropped(), 1);
    assert_eq!(door.st.lock().unwrap().secured.len(), 5);
    port.remove(id);
    assert!(port.is_empty());
    assert_eq!(
        memory.used(),
        0,
        "cancellation retires every retained batch"
    );
}
