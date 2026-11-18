// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `io_host::AddrText` spells a socket address byte for byte as `std` does, in place.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

use busbar_contract::io_host::AddrText;

/// Every form `std` spells is answered with the same bytes `to_string` builds, the longest
/// address included, and the empty text is no address.
#[test]
fn every_socket_address_is_spelled_as_std_spells_it_and_the_longest_fits() {
    let longest = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ),
        65535,
        0,
        u32::MAX,
    ));
    assert_eq!(
        longest.to_string(),
        "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535"
    );
    let mapped: SocketAddr = "[::ffff:255.255.255.255]:65535".parse().unwrap();
    let cases: [SocketAddr; 6] = [
        "127.0.0.1:8080".parse().unwrap(),
        "255.255.255.255:65535".parse().unwrap(),
        "0.0.0.0:0".parse().unwrap(),
        "[::1]:443".parse().unwrap(),
        mapped,
        longest,
    ];
    for addr in cases {
        let text = AddrText::of(&addr);
        assert_eq!(text.as_str(), addr.to_string(), "{addr}");
        assert_eq!(&*text, addr.to_string().as_str(), "{addr}");
        assert_eq!(text, addr.to_string(), "{addr}");
        assert_eq!(format!("{text}"), addr.to_string(), "{addr}");
        assert!(text.len() <= AddrText::CAP, "{addr}");
    }
    assert_eq!(AddrText::default().as_str(), "");
    assert_eq!(AddrText::EMPTY, AddrText::default());
}
