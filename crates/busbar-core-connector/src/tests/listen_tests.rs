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

/// PROBE of the kernel the stop relies on (prints its readings; run with `--no-capture`): a `SO_REUSEPORT` listener
/// that never accepts keeps its share of new connections; shut down, it leaves the group, and the connections
/// already queued on it are reset unless `net.ipv4.tcp_migrate_req` is 1 (then the kernel moves them to another
/// listener of the group).
#[cfg(target_os = "linux")]
#[test]
fn probe_a_shut_reuseport_listener_leaves_the_group_and_resets_its_queue() {
    use std::io::Read;
    let listen = |port: u16| {
        let l = crate::socket::listen(&format!("127.0.0.1:{port}")).unwrap();
        l.set_nonblocking(true).unwrap();
        l
    };
    let drain = |l: &std::net::TcpListener| std::iter::from_fn(|| l.accept().ok()).count();
    let hung = listen(0);
    let port = hung.local_addr().unwrap().port();
    let live = listen(port);
    let migrate = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_migrate_req")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    let queued: Vec<_> = (0..64)
        .map(|_| std::net::TcpStream::connect(("127.0.0.1", port)).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(50));
    let live_before = drain(&live);
    let on_hung = queued.len() - live_before;
    assert!(
        on_hung > 0,
        "a listener that never accepts still gets its share"
    );
    socket2::SockRef::from(&hung)
        .shutdown(std::net::Shutdown::Both)
        .unwrap();
    let after: Vec<_> = (0..64)
        .map(|_| std::net::TcpStream::connect(("127.0.0.1", port)).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(50));
    let live_after = drain(&live);
    let reset = queued
        .iter()
        .filter(|c| {
            // A queued client the live listener drained was closed (EOF); one reset by the shut queue is RST.
            let mut c: &std::net::TcpStream = c;
            c.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
            matches!(c.read(&mut [0u8; 1]), Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset)
        })
        .count();
    println!(
        "probe: tcp_migrate_req={migrate} queued on the idle listener={on_hung}/64; after shutdown: new to the \
         live listener={live_after}/{} (migrated from the shut queue included), queued clients reset={reset}",
        after.len()
    );
    assert!(
        live_after >= after.len(),
        "every new connection reaches the listener still in the group"
    );
    if !migrate {
        assert!(
            reset >= on_hung,
            "without tcp_migrate_req the shut listener's queue is reset"
        );
    }
}

/// A resumed listener rejoins its `SO_REUSEPORT` group: stopped, every connection goes to the other listener;
/// resumed (its worker free again), it binds a new socket on its own worker and new connections reach it again.
#[cfg(target_os = "linux")]
#[test]
fn a_resumed_listener_rejoins_its_reuseport_group() {
    worker().block_on(async {
        let mut first = Listening::bind_stream("127.0.0.1:0", AcceptLimits::default()).unwrap();
        let port = first.local_addr().port();
        let mut second =
            Listening::bind_stream(&format!("127.0.0.1:{port}"), AcceptLimits::default()).unwrap();
        let stop = first.stopper();
        stop.stop();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(first.poll_accept_stream(&mut cx).is_pending());
        std::thread::spawn(move || stop.resume()).join().unwrap();
        // The resumed listener's own task binds its new socket at its next poll.
        assert!(first.poll_accept_stream(&mut cx).is_pending());
        let clients: Vec<_> = (0..64)
            .map(|_| std::net::TcpStream::connect(("127.0.0.1", port)).unwrap())
            .collect();
        let (mut to_first, mut to_second) = (0, 0);
        for _ in 0..clients.len() {
            tokio::select! {
                _ = first.admit() => to_first += 1,
                _ = second.admit() => to_second += 1,
                () = tokio::time::sleep(Duration::from_secs(2)) => break,
            }
        }
        assert_eq!(
            to_first + to_second,
            clients.len(),
            "every connection is admitted"
        );
        assert!(
            to_first > 0,
            "the resumed listener takes its share again ({to_first} of 64)"
        );
    });
}

/// A stopped stream listener leaves its `SO_REUSEPORT` group: with two listeners on one port and the first stopped
/// from another thread (as the core watch stops a hung core's door), every new connection reaches the second.
#[cfg(target_os = "linux")]
#[test]
fn a_stopped_listener_leaves_its_reuseport_group() {
    worker().block_on(async {
        let mut first = Listening::bind_stream("127.0.0.1:0", AcceptLimits::default()).unwrap();
        let port = first.local_addr().port();
        let mut second =
            Listening::bind_stream(&format!("127.0.0.1:{port}"), AcceptLimits::default()).unwrap();
        let stop = first.stopper();
        std::thread::spawn(move || stop.stop()).join().unwrap();
        let clients: Vec<_> = (0..32)
            .map(|_| std::net::TcpStream::connect(("127.0.0.1", port)).unwrap())
            .collect();
        for n in 0..clients.len() {
            assert!(
                tokio::time::timeout(Duration::from_secs(2), second.admit())
                    .await
                    .is_ok(),
                "connection {n} of {} did not reach the listener still in the group",
                clients.len()
            );
        }
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            first.poll_accept_stream(&mut cx).is_pending(),
            "a stopped listener admits nothing"
        );
    });
}
