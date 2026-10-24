// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A carried connection: the carrier dials what the host admitted for it and nothing else, moves the
//! bytes both ways on its two sides, a read with nothing to read pends and is woken by the host, and
//! a close is the far end's end of stream.

use std::future::poll_fn;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::support;

#[test]
fn a_carried_dial_moves_bytes_both_ways_and_its_close_ends_the_stream() {
    let rt = support::worker();
    rt.block_on(async {
        let far = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = far.local_addr().unwrap().to_string();
        let via = support::via();
        let carried = Carried::dial(
            Arc::clone(&via.door),
            Arc::clone(&via.io),
            &Dest::Authority(at.clone()),
        )
        .unwrap();
        let (mut peer, _) = far.accept().await.unwrap();
        poll_fn(|cx| carried.poll_connected(cx)).await.unwrap();
        let n = poll_fn(|cx| carried.poll_write(cx, b"ping", true))
            .await
            .unwrap();
        assert_eq!(n, 4);
        let mut got = [0_u8; 4];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        // Nothing to read yet: the read pends, and the far end's bytes wake it.
        let mut buf = [0_u8; 16];
        let reader = poll_fn(|cx| carried.poll_read(cx, &mut buf));
        let writer = async {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            peer.write_all(b"pong").await.unwrap();
        };
        let (read, ()) = tokio::join!(reader, writer);
        let (n, end_of_frame) = read.unwrap();
        assert_eq!((&buf[..n], end_of_frame), (&b"pong"[..], true));
        let (peer_at, _) = carried.arrival().unwrap();
        assert_eq!(peer_at, at);
        carried.close();
        let mut rest = Vec::new();
        peer.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    });
}

#[test]
fn a_dial_to_what_was_not_admitted_never_reaches_the_wire() {
    let rt = support::worker();
    rt.block_on(async {
        let via = support::via();
        // The connector admits exactly the destination it dials; a carrier that opened another
        // would be refused by the host. Here the destination is not an address at all.
        let refused = Carried::dial(
            Arc::clone(&via.door),
            Arc::clone(&via.io),
            &Dest::Authority("example.test:80".into()),
        )
        .unwrap_err();
        assert!(matches!(refused, DialFailure::Refused(_)), "{refused:?}");
    });
}
