// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST PORT CLAIM — `common::boot::free_port` hands out a loopback port no other test process
//! will also be handed, and (on Linux) one no other socket can take before the child busbar binds
//! it. The data door binds with `SO_REUSEPORT`, so two busbars given one number both listen and
//! split the connections: the claim, not the child's bind, is what keeps them apart.

mod common;

/// A port this process holds is refused to a second claimant, and the next port handed out is a
/// different one. Against a bare "bind :0 and drop" picker there is no claim to refuse, and this
/// is RED.
#[test]
fn a_claimed_port_is_never_handed_out_twice() {
    let first = common::boot::free_port();
    assert!(
        common::boot::try_reserve(first).is_none(),
        "port {first} is claimed by this process and must be refused to any second claimant"
    );
    for _ in 0..32 {
        assert_ne!(
            common::boot::free_port(),
            first,
            "a claimed port was handed out again"
        );
    }
}

/// A port handed out is OWNED from the moment it was chosen, not merely claimed: a socket that binds
/// as anything else on the machine would (no options) is refused it, a connect before the child
/// listens is refused rather than swallowed, and the child's listener — bound as every root listener
/// is, `SO_REUSEADDR` and `SO_REUSEPORT` — binds it and serves. Against a picker that drops the
/// socket it chose, the plain bind succeeds (the port is anyone's until the child binds it) and
/// this is RED.
#[cfg(target_os = "linux")]
#[test]
fn a_handed_out_port_is_bound_until_the_child_binds_beside_it() {
    use socket2::{Domain, Socket, Type};
    use std::io::{Read, Write};
    let port = common::boot::free_port();
    let at: socket2::SockAddr = std::net::SocketAddr::from(([127, 0, 0, 1], port)).into();

    let stranger = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    let taken = stranger.bind(&at).map_err(|e| e.kind());
    assert_eq!(
        taken,
        Err(std::io::ErrorKind::AddrInUse),
        "port {port} was free for any socket to take before the child bound it"
    );
    drop(stranger);

    let early = std::net::TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.kind());
    assert_eq!(
        early.err(),
        Some(std::io::ErrorKind::ConnectionRefused),
        "a connect before the child listens is refused"
    );

    let child = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    child.set_reuse_address(true).unwrap();
    child.set_reuse_port(true).unwrap();
    child
        .bind(&at)
        .expect("the child's listener binds beside the held socket");
    child.listen(4).unwrap();
    let listener: std::net::TcpListener = child.into();
    let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let (mut served, _) = listener
        .accept()
        .expect("the child's listener takes the connection");
    client.write_all(b"x").unwrap();
    let mut byte = [0u8; 1];
    served.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"x");
}

/// And the reason the claim is needed: a second `SO_REUSEPORT` listener on a port a first one holds
/// binds without error, so a bind can never be the test of "this port is mine".
#[cfg(unix)]
#[test]
fn a_reuseport_listener_shares_a_port_without_any_error() {
    use socket2::{Domain, Socket, Type};
    let listen = |port: u16| {
        let s = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        s.set_reuse_address(true).unwrap();
        s.set_reuse_port(true).unwrap();
        s.bind(&std::net::SocketAddr::from(([127, 0, 0, 1], port)).into())
            .map(|()| s)
    };
    let a = listen(0).expect("first listener");
    let port = a.local_addr().unwrap().as_socket().unwrap().port();
    a.listen(4).unwrap();
    assert!(
        listen(port).is_ok(),
        "a second SO_REUSEPORT bind on {port} succeeded here before; if it now fails, the claim is \
         no longer the only guard and this premise should be re-read"
    );
}
