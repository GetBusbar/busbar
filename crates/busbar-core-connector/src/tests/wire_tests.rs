// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A framer entry over host sockets at the kernel's transport seam, on real sockets: byte-exact both
//! ways, half-close, a close that ends a parked read or a blocked write, the hand-up of a detached
//! connection with what the framer held, a Unit 0 refusal that is delivered and finalises, one
//! listener per acceptor on one address, and the metadata refusal on a dial.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::transport::wire::{CloseReason, TransportError};
use busbar_contract::{ScratchBytes, StreamId};
use futures::StreamExt;

use super::*;
use crate::support::{worker, Knobs, TestDoor};

/// `w`, its framed connections riding the test carrier (`support::via`) as the root's wires ride
/// the serving connector's address carrier.
fn carried(w: HostWire) -> HostWire {
    w.riding(Arc::new(|| Some(crate::support::via().door)))
}

fn wire() -> Arc<HostWire> {
    Arc::new(carried(HostWire::new(Arc::new(framing(TestDoor::identity("bytes")))).unwrap()))
}

/// `door` stated a FRAMER: its connections ride the test carrier (`support::via`), framed by it.
fn framing(door: TestDoor) -> TestDoor {
    let _ = crate::support::via();
    door.with_role(busbar_contract::abi::transport::ROLE_FRAMER)
}

/// A dialled and an accepted end of one connection, and the address dialled: the test carrier
/// listens and accepts the far end the wire dials.
async fn pair(w: &Arc<HostWire>) -> (Conn, Conn, String) {
    let via = crate::support::via();
    let (listener, mut side, local) =
        crate::listen::listen_through(&via, "127.0.0.1:0").expect("the carrier listens");
    let addr = local.to_string();
    let accept = std::future::poll_fn(|cx| {
        crate::listen::accept_through(&via, listener, &mut side, cx)
    });
    let (client, far) = tokio::join!(w.dial_authority(&addr), accept);
    let (far, peer) = far.unwrap();
    let crate::listen::Got::Carried(far) = far else {
        panic!("the carrier accepted");
    };
    let server = w.accepted(far, peer.to_string()).unwrap();
    (client.unwrap(), server, addr)
}

async fn read_n(w: &HostWire, c: &Conn, n: usize) -> Vec<u8> {
    let mut frames = w.frames(c.clone());
    let mut got = Vec::new();
    while got.len() < n {
        let (_, f) = frames.next().await.expect("a frame").expect("no error");
        got.extend_from_slice(f.bytes.as_slice());
    }
    got
}

#[test]
fn byte_exact_both_ways_through_the_framer() {
    worker().block_on(async {
        let w = wire();
        let (client, server, _l) = pair(&w).await;
        let payload: Vec<u8> = (0..=255_u8).cycle().take(50_000).collect();
        w.write(&client, StreamId(0), ScratchBytes::new(&payload), false)
            .await
            .unwrap();
        assert_eq!(read_n(&w, &server, payload.len()).await, payload);
        w.write(&server, StreamId(0), ScratchBytes::new(b"reply"), false)
            .await
            .unwrap();
        assert_eq!(read_n(&w, &client, 5).await, b"reply");
        assert_ne!(client.id(), server.id(), "two connections, two ids");
        assert_eq!(w.key(), "bytes");
        assert_eq!(w.arrival(&server).transport_chain, vec!["bytes"]);
    });
}

/// RED (C19-TAIL U5): a frame the framer states as text reaches the kernel's seam with
/// `FrameMeta::text` set (the bit's one home); a binary one does not.
#[test]
fn a_text_frame_arrives_as_text_at_the_seam() {
    worker().block_on(async {
        for text in [true, false] {
            let door = TestDoor::new(
                "bytes",
                &["bytes"],
                &[],
                Knobs {
                    text,
                    ..Knobs::default()
                },
            );
            let w = Arc::new(carried(HostWire::new(Arc::new(framing(door))).unwrap()));
            let (client, server, _l) = pair(&w).await;
            w.write(&client, StreamId(0), ScratchBytes::new(b"{}"), false)
                .await
                .unwrap();
            let (_, frame) = w.frames(server).next().await.unwrap().unwrap();
            assert_eq!(frame.bytes.as_slice(), b"{}");
            assert_eq!(frame.meta.text, text, "stated text={text}");
        }
    });
}

/// RED (C19-TAIL U5 write): a write stated as text reaches the framer as a text emit
/// (`EMIT_TEXT`); a binary one does not.
#[test]
fn a_text_write_reaches_the_framer_as_text() {
    worker().block_on(async {
        for text in [true, false] {
            let door = Arc::new(framing(TestDoor::identity("bytes")));
            let w = Arc::new(carried(HostWire::new(door.clone()).unwrap()));
            let (client, server, _l) = pair(&w).await;
            w.write(&client, StreamId(0), ScratchBytes::new(b"{}"), text)
                .await
                .unwrap();
            assert_eq!(read_n(&w, &server, 2).await, b"{}");
            assert_eq!(
                door.count("emit text"),
                usize::from(text),
                "written text={text}"
            );
        }
    });
}

#[test]
fn half_close_lets_the_other_side_keep_writing() {
    worker().block_on(async {
        let w = wire();
        let (client, server, _l) = pair(&w).await;
        // The client's side ends its writing half by handing the stream up and closing it.
        let mut raw = w
            .detach(&client)
            .expect("an idle connection hands its stream up")
            .into_io();
        futures::io::AsyncWriteExt::close(&mut raw).await.unwrap();
        let mut frames = w.frames(server.clone());
        assert!(
            frames.next().await.is_none(),
            "the far end's end ends the frames"
        );
        w.write(
            &server,
            StreamId(0),
            ScratchBytes::new(b"still here"),
            false,
        )
        .await
        .unwrap();
        let mut got = [0_u8; 10];
        futures::io::AsyncReadExt::read_exact(&mut raw, &mut got)
            .await
            .unwrap();
        assert_eq!(&got, b"still here");
    });
}

#[test]
fn close_ends_a_read_parked_on_a_silent_peer() {
    worker().block_on(async {
        let w = wire();
        let (_client, server, _l) = pair(&w).await;
        let mut frames = w.frames(server.clone());
        let w2 = Arc::clone(&w);
        let s2 = server.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            w2.close(s2, CloseReason::Normal);
        });
        let ended = tokio::time::timeout(Duration::from_secs(5), frames.next()).await;
        assert!(matches!(ended, Ok(None)), "the close ends the parked read");
        assert_eq!(w.live(), 1, "only the dialled end is left");
    });
}

#[test]
fn close_interrupts_a_write_blocked_on_a_peer_that_stopped_reading() {
    worker().block_on(async {
        let w = wire();
        let (client, _server, _l) = pair(&w).await;
        let w2 = Arc::clone(&w);
        let c2 = client.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            w2.close(c2, CloseReason::Normal);
        });
        let big = vec![7_u8; 64 * 1024 * 1024];
        let r = tokio::time::timeout(
            Duration::from_secs(10),
            w.write(&client, StreamId(0), ScratchBytes::new(&big), false),
        )
        .await
        .expect("the close interrupts the write");
        assert_eq!(r, Err(TransportError::Closed));
    });
}

#[test]
fn detach_hands_up_the_stream_with_what_the_framer_held() {
    worker().block_on(async {
        let w = wire();
        let (client, server, _l) = pair(&w).await;
        w.write(&client, StreamId(0), ScratchBytes::new(b"early"), false)
            .await
            .unwrap();
        // Read one frame on the server side and leave it in the framer's hands, unconsumed: the
        // detach must hand it up in front of the socket.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let raw = w.detach(&server).expect("hands up");
        assert_eq!(raw.from(), "bytes");
        let mut raw = raw.into_io();
        let mut got = [0_u8; 5];
        futures::io::AsyncReadExt::read_exact(&mut raw, &mut got)
            .await
            .unwrap();
        assert_eq!(&got, b"early");
        assert!(w.detach(&server).is_none(), "handed up once");
    });
}

#[test]
fn a_unit0_refusal_is_delivered_and_finalises_the_connection() {
    worker().block_on(async {
        let w = wire();
        let (client, server, _l) = pair(&w).await;
        let refusal = busbar_contract::unit::Refusal {
            step: busbar_contract::unit::Step::Arrival,
            reason: busbar_contract::unit::RefusalReason::CursorBudget,
            retry_after_secs: None,
            stream: None,
            correlates: None,
        };
        w.unit0_refusal(
            server.clone(),
            None,
            &refusal,
            ScratchBytes::new(b"refused"),
        )
        .await
        .unwrap();
        assert_eq!(read_n(&w, &client, 7).await, b"refused");
        assert!(w.frames(server).next().await.is_none(), "finalised");
    });
}

#[test]
fn a_dial_to_a_metadata_host_or_a_name_is_refused() {
    worker().block_on(async {
        let w = wire();
        for a in [
            "169.254.169.254:80",
            "[fd00:ec2::254]:80",
            "upstream.example:80",
        ] {
            assert_eq!(
                w.dial_authority(a).await.map(|_| ()),
                Err(TransportError::AddressRefused),
                "{a}"
            );
        }
    });
}

#[test]
fn an_entry_that_composes_over_a_layer_is_not_served_over_the_socket() {
    let door = Arc::new(TestDoor::new(
        "over",
        &["over"],
        &["under"],
        Knobs::default(),
    ));
    assert!(HostWire::new(door).is_err());
}

/// Every I/O error kind the seam spells, pinned per arm (the retired carrier's table).
#[test]
fn every_io_error_kind_maps_through_the_table() {
    use std::io::{Error, ErrorKind};
    for (kind, want) in [
        (ErrorKind::ConnectionRefused, TransportError::Refused),
        (ErrorKind::TimedOut, TransportError::Timeout),
        (ErrorKind::ConnectionReset, TransportError::Reset),
        (ErrorKind::ConnectionAborted, TransportError::Reset),
        (ErrorKind::AddrNotAvailable, TransportError::AddressRefused),
        (ErrorKind::InvalidInput, TransportError::AddressRefused),
        (ErrorKind::BrokenPipe, TransportError::Closed),
        (ErrorKind::Other, TransportError::Closed),
    ] {
        assert_eq!(map_io_err(&Error::from(kind)), want, "{kind:?}");
    }
}

/// A dial to an address nothing listens on is refused by the far end; a dialled connection's peer
/// is the address it dialled; a write to a connection already closed is Closed.
#[test]
fn a_dial_to_nothing_is_refused_and_a_closed_connection_takes_no_write() {
    worker().block_on(async {
        let w = wire();
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let nothing = free.local_addr().unwrap().to_string();
        drop(free);
        assert_eq!(
            w.dial_authority(&nothing).await.map(|_| ()),
            Err(TransportError::Refused)
        );
        let (client, _server, addr) = pair(&w).await;
        assert_eq!(client.peer(), addr, "the peer is the address dialled");
        w.close(client.clone(), CloseReason::Normal);
        assert_eq!(
            w.write(&client, StreamId(0), ScratchBytes::new(b"late"), false)
                .await,
            Err(TransportError::Closed)
        );
    });
}

/// A far end that resets the connection ends its frames and the wire forgets it.
#[test]
fn a_reset_from_the_far_end_ends_the_frames_and_deregisters() {
    worker().block_on(async {
        let w = wire();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let (client, far) = tokio::join!(w.dial_authority(&addr), l.accept());
        let client = client.unwrap();
        let (far, _) = far.unwrap();
        assert_eq!(w.live(), 1);
        socket2::SockRef::from(&far)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(far);
        let mut frames = w.frames(client.clone());
        let ended = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(f) = frames.next().await {
                if f.is_err() {
                    break;
                }
            }
        })
        .await;
        assert!(ended.is_ok(), "the reset ends the frames");
        assert_eq!(w.live(), 0, "the reset connection is deregistered");
    });
}

/// The default dial budget is `DIAL_TIMEOUT` (ten seconds) and `with_dial_timeout` replaces it.
#[test]
fn the_dial_budget_defaults_to_the_constant_and_with_dial_timeout_replaces_it() {
    assert_eq!(DIAL_TIMEOUT, Duration::from_secs(10));
    let w = HostWire::new(Arc::new(framing(TestDoor::identity("bytes")))).unwrap();
    assert_eq!(w.dial_timeout, DIAL_TIMEOUT);
    let w = w.with_dial_timeout(Duration::from_millis(250));
    assert_eq!(w.dial_timeout, Duration::from_millis(250));
}

/// A dial to a non-routable address (TEST-NET-1) returns within a bound near the dial budget, not
/// the ten-second default. Where the network hangs the handshake the error is `Timeout`; where the
/// environment answers at once with an unreachable or refused error, the code maps that to `Closed`
/// or `Refused` (no `Timeout`), so the test accepts exactly those three and still bounds the time.
#[test]
fn a_dial_to_a_non_routable_address_returns_within_the_bound_with_the_mapped_error() {
    worker().block_on(async {
        let w = carried(HostWire::new(Arc::new(framing(TestDoor::identity("bytes")))).unwrap())
            .with_dial_timeout(Duration::from_millis(200));
        let started = std::time::Instant::now();
        let r = tokio::time::timeout(Duration::from_secs(8), w.dial_authority("192.0.2.1:9"))
            .await
            .expect("the dial is bounded by its own budget, not left to the outer guard");
        let took = started.elapsed();
        assert!(
            took < Duration::from_secs(5),
            "the dial returned in {took:?}, far past a 200ms budget"
        );
        match r.map(|_| ()) {
            Err(TransportError::Timeout) => {
                assert!(
                    took >= Duration::from_millis(150),
                    "a Timeout came before the budget ran: {took:?}"
                );
            }
            Err(TransportError::Closed | TransportError::Refused) => {}
            other => panic!("unexpected dial outcome: {other:?}"),
        }
        assert_eq!(w.live(), 0, "a failed dial leaves no connection behind");
    });
}

/// A Unit 0 refusal whose send fails (the write half is already shut) still finalises the
/// connection, deregisters it and returns the send's error.
#[test]
fn a_unit0_refusal_whose_send_fails_still_finalises_and_returns_the_error() {
    worker().block_on(async {
        let w = wire();
        let (_client, server, _l) = pair(&w).await;
        let held = w.get(server.id()).expect("held");
        let Some(Io::Carried(carried)) = held.socket() else {
            panic!("an accepted connection is a carried one");
        };
        busbar_contract::io_host::IoHost::shut(
            crate::hostio::process().as_ref(),
            crate::support::OWNER,
            carried.handle().expect("the host's handle"),
            busbar_contract::abi::host::io::DIR_WRITE,
        )
        .unwrap();
        assert!(!held.closed.load(Ordering::Acquire));
        let refusal = busbar_contract::unit::Refusal {
            step: busbar_contract::unit::Step::Arrival,
            reason: busbar_contract::unit::RefusalReason::CursorBudget,
            retry_after_secs: None,
            stream: None,
            correlates: None,
        };
        let r = w
            .unit0_refusal(
                server.clone(),
                None,
                &refusal,
                ScratchBytes::new(b"refused"),
            )
            .await;
        assert_eq!(r, Err(TransportError::Closed), "the send's error returns");
        assert!(held.closed.load(Ordering::Acquire), "finalised");
        assert_eq!(w.live(), 1, "the refused connection is deregistered");
        assert!(w.frames(server).next().await.is_none());
    });
}

/// A detach while a reader still holds the socket returns None and puts the socket back: the
/// connection is still registered and still carries bytes both ways, and detaches once released.
#[test]
fn detach_while_the_socket_is_held_elsewhere_returns_none_and_the_connection_still_works() {
    worker().block_on(async {
        let w = wire();
        let (client, server, _l) = pair(&w).await;
        let reader = w.get(server.id()).unwrap().socket().expect("socket");
        assert!(
            w.detach(&server).is_none(),
            "a held socket is not handed up"
        );
        assert_eq!(w.live(), 2, "the connection stays registered");
        assert!(
            w.get(server.id()).unwrap().socket().is_some(),
            "the socket was put back"
        );
        w.write(&client, StreamId(0), ScratchBytes::new(b"ping"), false)
            .await
            .unwrap();
        assert_eq!(read_n(&w, &server, 4).await, b"ping");
        w.write(&server, StreamId(0), ScratchBytes::new(b"pong"), false)
            .await
            .unwrap();
        assert_eq!(read_n(&w, &client, 4).await, b"pong");
        drop(reader);
        assert!(w.detach(&server).is_some(), "handed up once released");
    });
}

/// A read future dropped while pending loses nothing: the next read on the same connection gets
/// the bytes that arrive afterwards, whole and in order.
#[test]
fn a_cancelled_pending_read_leaves_the_next_read_intact() {
    worker().block_on(async {
        let w = wire();
        let (client, server, _l) = pair(&w).await;
        w.write(&client, StreamId(0), ScratchBytes::new(b"first"), false)
            .await
            .unwrap();
        assert_eq!(read_n(&w, &server, 5).await, b"first");
        {
            let mut frames = w.frames(server.clone());
            let cancelled = tokio::time::timeout(Duration::from_millis(50), frames.next()).await;
            assert!(cancelled.is_err(), "nothing to read: the read was pending");
        }
        w.write(&client, StreamId(0), ScratchBytes::new(b"second"), false)
            .await
            .unwrap();
        w.write(&client, StreamId(0), ScratchBytes::new(b"-third"), false)
            .await
            .unwrap();
        assert_eq!(read_n(&w, &server, 12).await, b"second-third");
        assert_eq!(w.live(), 2, "the cancel did not close the connection");
    });
}

/// Every frame the wire emits carries `meta.bytes` equal to its payload length and none exceeds
/// one read chunk; a payload bigger than a chunk arrives as several frames that add up whole.
#[test]
fn emitted_frames_carry_their_payload_length_and_never_exceed_a_read_chunk() {
    worker().block_on(async {
        let w = wire();
        let (client, server, _l) = pair(&w).await;
        let payload: Vec<u8> = (0..=255_u8)
            .cycle()
            .take(3 * READ_CHUNK_BYTES + 123)
            .collect();
        w.write(&client, StreamId(0), ScratchBytes::new(&payload), false)
            .await
            .unwrap();
        let mut frames = w.frames(server.clone());
        let (mut got, mut count) = (Vec::new(), 0);
        while got.len() < payload.len() {
            let (_, f) = frames.next().await.expect("a frame").expect("no error");
            assert_eq!(f.meta.bytes, f.bytes.as_slice().len() as u64);
            assert!(f.bytes.as_slice().len() <= READ_CHUNK_BYTES);
            got.extend_from_slice(f.bytes.as_slice());
            count += 1;
        }
        assert!(
            count >= 4,
            "a payload of three chunks and more is several frames"
        );
        assert_eq!(got, payload);
    });
}

/// The read chunk is sixteen KiB, and the Debug output names the wire and its key.
#[test]
fn the_read_chunk_is_sixteen_kib_and_debug_names_the_wire() {
    assert_eq!(READ_CHUNK_BYTES, 16 * 1024);
    let shown = format!("{:?}", *wire());
    assert!(shown.contains("HostWire"), "{shown}");
    assert!(shown.contains("bytes"), "{shown}");
}

/// AN ENTRY ADOPTS THE STREAM ANOTHER ENTRY HANDS UP (ARCHITECT Q128 U7: no transport names another,
/// so which entry adopts an upgraded stream is the connector's choice, never a list the entry
/// states): a FRAMER over the host's socket adopts what the carrier under it detached (what it held
/// first) and frames both ways from there.
#[test]
fn a_framer_adopts_the_stream_another_entry_hands_up() {
    worker().block_on(async {
        let upper = Arc::new(
            TestDoor::new("msg", &["msg"], &[], Knobs::default())
                .with_role(busbar_contract::abi::transport::ROLE_FRAMER),
        );
        let framer = HostWire::new(upper).expect("a framer over the host's socket");
        assert_eq!(framer.key(), "msg");

        let lower = wire();
        let (client, server, _l) = pair(&lower).await;
        lower
            .write(&client, StreamId(0), ScratchBytes::new(b"early"), false)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let raw = lower.detach(&server).expect("hands up");
        let adopted = framer
            .adopt_from(raw, Vec::new(), None)
            .await
            .expect("adopted");
        assert_eq!(read_n(&framer, &adopted, 5).await, b"early");
        framer
            .write(&adopted, StreamId(0), ScratchBytes::new(b"over"), false)
            .await
            .unwrap();
        assert_eq!(read_n(&lower, &client, 4).await, b"over");
        framer.close(adopted, CloseReason::Normal);
    });
}

/// RED (SEAM-4n, ARCHITECT ruling): a dialled framing is begun with the FULL target its need
/// declared (`scheme://host:port/path`), never the bare authority; the socket goes to the authority
/// the entry's own `locate` reads off that target. A target that asks for connection security is
/// refused before any socket exists (this wire secures nothing).
#[test]
fn a_dialled_framing_is_begun_with_the_full_declared_target() {
    worker().block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: &'static str = Box::leak(l.local_addr().unwrap().to_string().into_boxed_str());
        let door = Arc::new(framing(TestDoor::new(
            "bytes",
            &["bytes"],
            &[],
            Knobs {
                authority: Some(addr),
                ..Knobs::default()
            },
        )));
        let w = carried(HostWire::new(Arc::clone(&door) as Arc<dyn crate::framer::FramerDoor>).unwrap());
        let target = format!("bytes://{addr}/the/declared/path?q=1");
        let (dialled, far) = tokio::join!(w.dial_target(&target), l.accept());
        dialled.expect("dialled at the authority locate read off the target");
        far.expect("the far end was reached at that authority");
        assert_eq!(
            door.begun_targets.lock().unwrap().last().map(Vec::as_slice),
            Some(target.as_bytes()),
            "the framer was handed the whole declared target"
        );

        let secure = Arc::new(framing(TestDoor::new(
            "bytes",
            &["bytes"],
            &[],
            Knobs {
                authority: Some(addr),
                secure_name: Some("localhost"),
                ..Knobs::default()
            },
        )));
        let w = carried(HostWire::new(Arc::clone(&secure) as Arc<dyn crate::framer::FramerDoor>).unwrap());
        assert_eq!(
            w.dial_target(&target).await.err(),
            Some(TransportError::AddressRefused)
        );
        assert!(
            secure.begun_targets.lock().unwrap().is_empty(),
            "nothing began"
        );
    });
}
