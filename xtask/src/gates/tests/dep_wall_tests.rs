// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn the_ledger_reads_pins_and_refuses_a_carrier_row_and_anything_else() {
    let l = read_ledger("# note\ncarrier\tbusbar-transport-tcp\nbusbar-llm\trustls\nnonsense\n");
    assert!(l.pinned.contains(&("busbar-llm".into(), "rustls".into())));
    assert_eq!(l.pinned.len(), 1);
    assert_eq!(l.errors.len(), 2);
    assert!(l.errors[0].contains("carrier<TAB>busbar-transport-tcp"));
}

#[test]
fn a_carrier_is_the_transport_kind_and_nothing_else() {
    assert!(is_carrier("busbar-transport-stdio"));
    assert!(is_carrier("busbar-transport-http"));
    assert!(!is_carrier("busbar-secret-env"));
    assert!(!is_carrier("busbar-plane-decisions"));
}

#[test]
fn asking_tokio_for_net_or_redis_for_aio_is_an_offence() {
    let p = Pkg {
        name: "x".into(),
        source: None,
        manifest_path: String::new(),
        deps: vec![
            ("tokio".into(), vec!["net".into()], false, true),
            ("redis".into(), vec!["tokio-comp".into()], false, true),
            ("tokio".into(), vec!["net".into()], false, false),
        ],
        features: BTreeMap::new(),
        packages: BTreeMap::new(),
    };
    assert_eq!(asks(&p), ["tokio (net)", "redis (aio)"]);
}

fn paths(text: &str) -> Vec<&'static str> {
    banned_paths(text).into_iter().collect()
}

#[test]
fn a_banned_path_is_read_as_a_path_in_every_spelling() {
    let net = ["std::net"];
    assert_eq!(paths("use std::{io, net::TcpStream};"), net);
    assert_eq!(paths("use std::{io, net::{self, TcpStream}};"), net);
    assert_eq!(paths("use std::{net};"), net);
    assert_eq!(paths("use std::net;"), net);
    assert_eq!(paths("use ::std::net::TcpStream;"), net);
    assert_eq!(
        paths("fn f() { let _ = ::std::net::TcpStream::connect(\"a:1\"); }"),
        net
    );
    assert_eq!(
        paths("fn f() { let _ = std :: net :: UdpSocket::bind(\"a:1\"); }"),
        net
    );
    assert_eq!(
        paths("fn f() { g!(std::net::TcpStream::connect(\"a:1\")); }"),
        net
    );
    assert_eq!(
        paths("use std as s; fn f() { s::net::TcpStream::connect(\"a:1\"); }"),
        net
    );
    assert_eq!(
        paths("fn f() { s::net::TcpStream::connect(\"a:1\"); } use std as s;"),
        net
    );
    assert_eq!(
        paths("extern crate std as s; use s::{net::TcpListener};"),
        net
    );
    assert_eq!(paths("use std::*;"), net);
    assert_eq!(paths("use tokio::{io, net::TcpStream};"), ["tokio::net"]);
    assert_eq!(
        paths("use std::{net::TcpStream}; use tokio::net as n;"),
        ["std::net", "tokio::net"]
    );
}

#[test]
fn a_comment_a_literal_a_neighbour_or_test_code_names_no_banned_path() {
    assert!(paths("// use std::net::TcpStream;\nfn f() {}").is_empty());
    assert!(paths("/* std::net */ fn f() { let _ = \"std::net\"; }").is_empty());
    assert!(paths("use core::net::SocketAddr; use std::io; use netlib::std;").is_empty());
    assert!(paths("use std::{io, sync::Mutex}; use crate::net::Thing;").is_empty());
    assert!(paths("#[cfg(test)]\nmod tests { use std::net::TcpStream; }\nfn f() {}").is_empty());
    assert!(paths("#[cfg(all(test, unix))]\nuse std::net::TcpStream;").is_empty());
    assert!(paths("#[test]\nfn t() { std::net::TcpStream::connect(\"a:1\"); }").is_empty());
    assert!(
        paths("#[tokio::test]\nasync fn t() { tokio::net::TcpStream::connect(\"a\"); }").is_empty()
    );
    // Production code beside a test module is still read.
    assert_eq!(
        paths("#[cfg(test)]\nmod tests {}\nuse std::{io, net::TcpStream};"),
        ["std::net"]
    );
    // `cfg(not(test))` is production.
    assert_eq!(
        paths("#[cfg(not(test))]\nuse std::net::TcpStream;"),
        ["std::net"]
    );
}

#[test]
fn an_address_value_names_no_banned_path_and_a_socket_beside_it_still_does() {
    // What the pinned tcp and http transports write: an address literal parsed, opening nothing.
    for text in [
        "use std::net::SocketAddr; fn f(a: &str) -> bool { a.parse::<SocketAddr>().is_ok() }",
        "fn f(b: &str) { let _ = b.parse::<std::net::Ipv4Addr>(); }",
        "use std::net::{IpAddr, Ipv6Addr, SocketAddrV4, SocketAddrV6, AddrParseError};",
        "use std as s; fn f() { let _ = s::net::Ipv4Addr::LOCALHOST; }",
    ] {
        assert!(paths(text).is_empty(), "{text}");
    }
    // A socket, a resolver, the bare module or a glob beside a value is still a banned path.
    for text in [
        "use std::net::{Ipv4Addr, TcpStream};",
        "use std::net::{SocketAddr, ToSocketAddrs};",
        "fn f() { let _ = std::net::UdpSocket::bind(\"a:1\"); }",
        "use std::net; fn f() -> net::Ipv4Addr { net::Ipv4Addr::LOCALHOST }",
        "use std::net::{self, SocketAddr};",
        "use std::net as n;",
        "use std::net::*;",
    ] {
        assert_eq!(paths(text), ["std::net"], "{text}");
    }
    assert_eq!(paths("use tokio::net::TcpStream;"), ["tokio::net"]);
}

#[test]
fn a_file_that_does_not_lex_is_read_line_by_line_rather_than_skipped() {
    assert_eq!(
        paths("fn f() { std::net::TcpStream::connect(\"a\"); "),
        ["std::net"]
    );
}

#[test]
fn a_grouped_import_in_an_in_tree_plugin_is_a_new_offender() {
    let cx = Ctx::workspace().expect("workspace context");
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-plane-llm/src/planted_grouped_socket.rs",
        "use std::{io, net::TcpStream};\n\
         pub fn dial() -> io::Result<TcpStream> { TcpStream::connect(\"127.0.0.1:1\") }\n",
    );
    let verdict = crate::gates::execute(&DepWallGate, &cx.with_overlay(ov));
    let new = verdict
        .rows
        .iter()
        .find(|r| r.id == ROW_NEW)
        .map(|r| r.detail.clone())
        .unwrap_or_default();
    assert!(
        verdict.red && new.contains("busbar-plane-llm") && new.contains("std::net"),
        "a grouped import of std::net in busbar-plane-llm went unreported: {new}"
    );
}
