// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's stream listener against REAL clients on real sockets: an admitted socket is handed up
//! as it arrived, the cap closes the one past it, a dropped listener stops accepting, and accept
//! errors back off as 1.5.5's did.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as Client;

use super::*;
use crate::support::worker;

fn stream(limits: AcceptLimits) -> Listening {
    Listening::bind_stream("127.0.0.1:0", limits).expect("binds")
}

/// 1.5.5's accept backoff: an aborted or interrupted accept retries at once; anything else backs
#[test]
fn accept_errors_back_off_as_1_5_5s_did() {
    worker().block_on(async {
        let mut l = stream(AcceptLimits::default());
        let emfile = std::io::Error::from_raw_os_error(libc::EMFILE);
        let aborted = std::io::Error::from(std::io::ErrorKind::ConnectionAborted);
        assert_eq!(l.next_delay(&aborted), None);
        let delays: Vec<_> = (0..8).map(|_| l.next_delay(&emfile).unwrap()).collect();
        assert_eq!(delays[0], Duration::from_millis(5));
        assert_eq!(delays[1], Duration::from_millis(10));
        assert_eq!(*delays.last().unwrap(), Duration::from_millis(250));
        assert_eq!(l.next_delay(&aborted), None);
        assert_eq!(l.next_delay(&emfile), Some(Duration::from_millis(5)));
    });
}

/// A STREAM listener (the root's own binds) hands each admitted socket up as it arrived, bytes
/// unread, and closes the one past its cap at once.
#[test]
fn a_stream_listener_hands_up_the_socket_as_it_arrived_under_the_cap() {
    worker().block_on(async {
        let mut l = stream(AcceptLimits {
            max_conns: 1,
            ..AcceptLimits::default()
        });
        let addr = l.local_addr();
        let mut c = Client::connect(addr).await.unwrap();
        c.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        let a = l.admit().await;
        assert_eq!(a.peer.ip(), addr.ip());
        assert_eq!(l.live(), 1, "the kernel holds the slot while it serves");
        let mut s = tokio::net::TcpStream::from_std(a.stream).unwrap();
        let mut got = [0_u8; 16];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(
            &got, b"GET / HTTP/1.1\r\n",
            "the bytes as the client sent them"
        );

        let mut past = Client::connect(addr).await.unwrap();
        let polled = tokio::time::timeout(Duration::from_millis(300), l.admit()).await;
        assert!(polled.is_err(), "the one past the cap is never admitted");
        let mut buf = [0_u8; 4];
        let n = tokio::time::timeout(Duration::from_secs(2), past.read(&mut buf))
            .await
            .expect("closed at once")
            .unwrap_or(0);
        assert_eq!(n, 0);
        drop(a.hold);
        assert_eq!(l.live(), 0, "the slot frees with the served connection");
    });
}

/// A dropped listener stops accepting at once.
#[test]
fn a_dropped_listener_stops_accepting_at_once() {
    worker().block_on(async {
        let l = stream(AcceptLimits::default());
        let addr = l.local_addr();
        let live = Client::connect(addr).await;
        assert!(live.is_ok(), "a live listener accepts");
        drop(live);
        drop(l);
        let after = Client::connect(addr).await;
        assert!(
            after.is_err(),
            "a dropped listener's address accepts nothing: {after:?}"
        );
    });
}

/// The whole accept-backoff sequence, at the resolution tokio's timer sleeps (whole milliseconds,
/// rounded up): 5 ms doubling to the 250 ms cap, no jitter, no retry limit.
#[test]
fn the_accept_backoff_sequence_is_5ms_doubling_to_a_250ms_cap() {
    worker().block_on(async {
        let mut l = stream(AcceptLimits::default());
        let emfile = std::io::Error::from_raw_os_error(libc::EMFILE);
        let tick_ms = |d: Duration| d.as_nanos().div_ceil(1_000_000);
        let delays: Vec<_> = (0..64)
            .map(|_| tick_ms(l.next_delay(&emfile).unwrap()))
            .collect();
        let mut want = vec![5, 10, 20, 40, 80, 160];
        want.resize(64, 250);
        assert_eq!(delays, want);
    });
}
