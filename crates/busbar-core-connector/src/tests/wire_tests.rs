// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A framer entry over host sockets at the kernel's transport seam, on real sockets: byte-exact both
//! ways, half-close, a close that ends a parked read or a blocked write, the hand-up of a detached
//! connection with what the framer held, a Unit 0 refusal that is delivered and finalises, one
//! listener per acceptor on one address, and the metadata refusal on a dial.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::transport::wire::{CloseReason, Listener, TransportError};
use busbar_contract::{
    ConfigView, Plugin, ScratchBytes, StreamId, Transport, TransportConfigView, TransportKeyHandle,
};
use futures::StreamExt;

use super::*;
use crate::support::{worker, Knobs, TestDoor};

struct At(String);

impl ConfigView for At {
    fn get_str(&self, _: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _: &str) -> Option<bool> {
        None
    }
}

impl TransportConfigView for At {
    fn bind(&self) -> Option<&str> {
        Some(&self.0)
    }
}

fn wire() -> Arc<HostWire> {
    Arc::new(HostWire::new(Arc::new(TestDoor::identity("bytes"))).unwrap())
}

async fn bound(w: &HostWire) -> Listener {
    w.listen(&At("127.0.0.1:0".into()), &TransportKeyHandle::keyless())
        .await
        .unwrap()
}

/// A dialled and an accepted end of one connection.
async fn pair(w: &Arc<HostWire>) -> (Conn, Conn, Listener) {
    let l = bound(w).await;
    let addr = l.local_addr();
    let (client, server) = tokio::join!(w.dial_authority(&addr), w.accept(&l));
    (client.unwrap(), server.unwrap(), l)
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
        w.write(&client, StreamId(0), ScratchBytes::new(&payload))
            .await
            .unwrap();
        assert_eq!(read_n(&w, &server, payload.len()).await, payload);
        w.write(&server, StreamId(0), ScratchBytes::new(b"reply"))
            .await
            .unwrap();
        assert_eq!(read_n(&w, &client, 5).await, b"reply");
        assert_ne!(client.id(), server.id(), "two connections, two ids");
        assert_eq!(w.key(), "bytes");
        assert_eq!(w.composed_over(), None);
        assert_eq!(w.arrival(&server).transport_chain, vec!["bytes"]);
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
        w.write(&server, StreamId(0), ScratchBytes::new(b"still here"))
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
            w.write(&client, StreamId(0), ScratchBytes::new(&big)),
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
        w.write(&client, StreamId(0), ScratchBytes::new(b"early"))
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
fn each_acceptor_binds_its_own_listener_on_one_address() {
    worker().block_on(async {
        let w = wire();
        let first = bound(&w).await;
        let again = w
            .listen(&At(first.local_addr()), &TransportKeyHandle::keyless())
            .await
            .expect("a second acceptor binds the same address");
        assert_eq!(first.local_addr(), again.local_addr());
        assert_ne!(first.id(), again.id());
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
