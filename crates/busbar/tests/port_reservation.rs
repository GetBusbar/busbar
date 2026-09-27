// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST PORT CLAIM — `common::boot::free_port` hands out a loopback port no other test process
//! will also be handed. The data door binds with `SO_REUSEPORT`, so two busbars given one number
//! both listen and split the connections: the claim, not the bind, is what keeps them apart.

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
