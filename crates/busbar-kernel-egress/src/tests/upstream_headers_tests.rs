// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The client headers that go upstream: `accept-encoding` is not one of them.

use crate::upstream::{re_derived, strip_re_derived};

/// 1.5.5 built every upstream request's headers itself and sent no `accept-encoding` (its HTTP
#[test]
fn a_clients_accept_encoding_never_goes_upstream() {
    assert!(re_derived("accept-encoding", std::iter::empty()));
    assert!(re_derived("Accept-Encoding", std::iter::empty()));
    assert!(!re_derived("x-trace", std::iter::empty()));

    let mut head = vec![
        (b"accept-encoding".to_vec(), b"gzip".to_vec()),
        (b"x-trace".to_vec(), b"t1".to_vec()),
    ];
    strip_re_derived(&mut head);
    assert_eq!(head, vec![(b"x-trace".to_vec(), b"t1".to_vec())]);
}

/// IF §13 round 23: the framer writes its own protocol handshake lines (`upgrade`, `connection`,
/// `sec-websocket-key`, `sec-websocket-version`, a closed list) after auth `outbound`, so the head a
/// plane hands the kernel loses all four, compared ASCII case-insensitively: no auth style ever sees or
/// signs them and the wire never carries two of one. Catches a handshake line leaking past the strip.
#[test]
fn the_framers_handshake_lines_never_go_upstream() {
    for name in [
        "upgrade",
        "Connection",
        "sec-websocket-key",
        "Sec-WebSocket-Version",
    ] {
        assert!(re_derived(name, std::iter::empty()), "{name}");
    }
    assert!(!re_derived("sec-websocket-protocol", std::iter::empty()));

    let mut head = vec![
        (
            b"Sec-WebSocket-Key".to_vec(),
            b"dGhlIHNhbXBsZSBub25jZQ==".to_vec(),
        ),
        (b"sec-websocket-version".to_vec(), b"13".to_vec()),
        (b"upgrade".to_vec(), b"websocket".to_vec()),
        (b"connection".to_vec(), b"upgrade".to_vec()),
        (b"sec-websocket-protocol".to_vec(), b"chat".to_vec()),
    ];
    strip_re_derived(&mut head);
    assert_eq!(
        head,
        vec![(b"sec-websocket-protocol".to_vec(), b"chat".to_vec())]
    );
}
