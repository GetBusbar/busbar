// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host UDP port: a datagram with its peer each way, never blocking, never a wildcard.

use super::*;
use std::time::{Duration, Instant};

/// Read one datagram, waiting at most a second (the reactor's job once the connector drives it).
fn recv(port: &UdpPort) -> (Vec<u8>, SocketAddr) {
    let mut buf = vec![0_u8; MAX_DATAGRAM];
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some((n, peer)) = port.try_recv_from(&mut buf).expect("recv") {
            return (buf[..n].to_vec(), peer);
        }
        assert!(Instant::now() < deadline, "no datagram arrived");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn a_datagram_arrives_whole_with_the_peer_it_came_from_and_is_answered_there() {
    let a = bind("127.0.0.1:0").unwrap();
    let b = bind("127.0.0.1:0").unwrap();
    a.try_send_to(b"stun-ish", b.local_addr()).unwrap().unwrap();
    let (got, peer) = recv(&b);
    assert_eq!(got, b"stun-ish");
    assert_eq!(peer, a.local_addr());
    // A payload far above any MTU still arrives as ONE datagram.
    let big = vec![0x80_u8; 9_000];
    b.try_send_to(&big, peer).unwrap().unwrap();
    assert_eq!(recv(&a).0, big);
}

#[test]
fn one_port_tells_its_peers_apart() {
    let port = bind("127.0.0.1:0").unwrap();
    let x = bind("127.0.0.1:0").unwrap();
    let y = bind("127.0.0.1:0").unwrap();
    x.try_send_to(b"from x", port.local_addr())
        .unwrap()
        .unwrap();
    y.try_send_to(b"from y", port.local_addr())
        .unwrap()
        .unwrap();
    let mut seen = [recv(&port), recv(&port)];
    seen.sort();
    assert_eq!(seen[0], (b"from x".to_vec(), x.local_addr()));
    assert_eq!(seen[1], (b"from y".to_vec(), y.local_addr()));
}

#[test]
fn an_empty_socket_answers_none_at_once() {
    let port = bind("127.0.0.1:0").unwrap();
    let started = Instant::now();
    assert!(port.try_recv_from(&mut [0_u8; 64]).unwrap().is_none());
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "never blocks"
    );
}

#[test]
fn a_wildcard_or_unparsable_bind_is_refused() {
    for bad in ["0.0.0.0:0", "[::]:0", "localhost:3478", "3478"] {
        let e = bind(bad).expect_err(bad);
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{bad}");
    }
}

#[test]
fn ipv6_loopback_binds_when_the_host_has_it() {
    if let Ok(port) = bind("[::1]:0") {
        let peer = bind("[::1]:0").unwrap();
        peer.try_send_to(b"v6", port.local_addr()).unwrap().unwrap();
        assert_eq!(recv(&port), (b"v6".to_vec(), peer.local_addr()));
    }
}
