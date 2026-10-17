// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn the_ledger_reads_carriers_and_pins_and_refuses_anything_else() {
    let l = read_ledger("# note\ncarrier\tbusbar-transport-tcp\nbusbar-llm\trustls\nnonsense\n");
    assert!(l.carriers.contains("busbar-transport-tcp"));
    assert!(l.pinned.contains(&("busbar-llm".into(), "rustls".into())));
    assert_eq!(l.errors.len(), 1);
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
    };
    assert_eq!(asks(&p), ["tokio (net)", "redis (aio)"]);
}

#[test]
fn every_row_is_proven_able_to_go_red() {
    let cx = Ctx::workspace().expect("workspace context");
    let gate = DepWallGate;
    let report = gate.selftest(&cx);
    crate::gates::verify_report(&gate, &report).expect("every dep-wall row proven RED");
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
fn a_file_that_does_not_lex_is_read_line_by_line_rather_than_skipped() {
    assert_eq!(
        paths("fn f() { std::net::TcpStream::connect(\"a\"); "),
        ["std::net"]
    );
}

#[test]
fn a_pinned_checkout_is_read_from_disk_and_an_absent_one_is_named() {
    let dir = std::env::temp_dir().join(format!("dep-wall-checkout-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("src/door")).unwrap();
    std::fs::write(dir.join("src/lib.rs"), "mod door;\n").unwrap();
    std::fs::write(dir.join("src/door/mod.rs"), "use std::{net::TcpStream};\n").unwrap();
    let read = checkout_sources(&dir.join("src")).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let rels: Vec<&str> = read.iter().map(|(r, _)| r.as_str()).collect();
    assert_eq!(rels, ["door/mod.rs", "lib.rs"]);
    assert_eq!(paths(&read[0].1), ["std::net"]);
    let why = checkout_sources(&dir.join("src")).unwrap_err();
    assert!(why.contains("dep-wall-checkout-"), "{why}");
}
