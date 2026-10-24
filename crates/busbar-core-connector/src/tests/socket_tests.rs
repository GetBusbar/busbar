// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// A dialled socket is 1.5.5's egress socket: Nagle off, and probed after 60 s idle.
#[test]
fn a_dialled_socket_has_1_5_5_s_options() {
    let l = TcpListener::bind("127.0.0.1:0").expect("a port");
    let s = connect(l.local_addr().expect("its address")).expect("a socket");
    let r = socket2::SockRef::from(&s);
    assert!(r.tcp_nodelay().expect("nodelay"));
    assert!(r.keepalive().expect("keepalive"));
    assert_eq!(r.tcp_keepalive_time().expect("its time"), KEEPALIVE_IDLE);
}
