// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTOR MOVES NO BYTE ITSELF (TRANSPORT-STACK (2); ARCHITECT p2-transport-carrier exit):
//! every connection rides a CARRIER's slots, and the carrier reaches the OS through the host's I/O
//! (`src/hostio.rs`, `io.*`). So no source file of this crate but the host's I/O implementation
//! opens, binds, accepts, registers, spawns or shuts an OS handle. A source scan, comments set
//! aside; the RED arm plants a dial in a scanned file and requires the scan to name it.
//!
//! THE HOST'S I/O IMPLEMENTATION, the only files the scan admits, each for its stated reason:
//!
//! * `hostio.rs` — `io.*` itself: streams, listeners, a program's pipes;
//! * `io.rs`, `socket.rs` — its tools: readiness on the worker's reactor, and the OS sockets;
//! * `udp.rs`, `dtls/` — the DATAGRAM carrier, which is the host's by ruling (THE DESIGN §5,
//!   WEBRTC: "the udp carrier is the host's (in the connector, no carrier plugin)");
//! * `tls/engine.rs` — the kernel's own outbound engine's TLS, over a stream the KERNEL dialled
//!   and hands it (the kernel's legacy egress engine); the connector dials nothing there.

use std::path::{Path, PathBuf};

/// What no file but the host's I/O may name: the OS handles and the calls that make or move them.
const FORBIDDEN: &[&str] = &[
    "TcpStream::connect",
    "TcpListener::bind",
    "TcpListener::accept",
    "UnixStream",
    "UnixListener",
    "UdpSocket",
    "socket2",
    "tokio::net",
    "tokio::process",
    "std::process::Command",
    "Command::new",
    "std::io::pipe",
    "AsyncFd",
    "Registered<",
    "reactor::register",
    "io::register(",
    "socket::connect",
    "socket::listen",
    ".shutdown(",
    "into_raw_fd",
    "from_raw_fd",
];

/// The host's I/O implementation (module docs).
const HOST_IO: &[&str] = &[
    "hostio.rs",
    "io.rs",
    "socket.rs",
    "udp.rs",
    "dtls/",
    "tls/engine.rs",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).expect("read src").flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Every `(file, line, token)` a scanned file names, comments set aside. Test files are not the
/// connector's: their far ends are the test's own sockets.
fn offenders(files: &[(String, String)]) -> Vec<(String, usize, &'static str)> {
    let mut found = Vec::new();
    for (rel, text) in files {
        let exempt = HOST_IO.iter().any(|h| rel == h || rel.starts_with(h))
            || rel.starts_with("tests/")
            || rel.ends_with("_tests.rs")
            || rel.ends_with("/tests.rs")
            || rel == "test_support.rs";
        if exempt {
            continue;
        }
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            for t in FORBIDDEN {
                if code.contains(t) {
                    found.push((rel.clone(), n + 1, *t));
                }
            }
        }
    }
    found
}

fn sources() -> Vec<(String, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&src)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (rel, std::fs::read_to_string(&p).unwrap())
        })
        .collect()
}

#[test]
fn no_source_file_but_the_hosts_io_touches_an_os_handle() {
    let files = sources();
    assert!(
        files.iter().any(|(r, _)| r == "compose.rs") && files.iter().any(|(r, _)| r == "wire.rs"),
        "the scan reads the connector's own sources"
    );
    assert_eq!(offenders(&files), Vec::new());
}

/// THE RED ARM, kept: a dial planted in a connection module is found, by file, line and token; the
/// same text in the host's I/O is its own.
#[test]
fn a_dial_planted_outside_the_hosts_io_is_named() {
    let mut files = sources();
    let compose = files
        .iter_mut()
        .find(|(r, _)| r == "compose.rs")
        .expect("compose.rs");
    compose
        .1
        .push_str("\nfn planted() { let _ = std::net::TcpStream::connect(\"127.0.0.1:1\"); }\n");
    let found = offenders(&files);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, "compose.rs");
    assert_eq!(found[0].2, "TcpStream::connect");
    let mut admitted = sources();
    let host = admitted
        .iter_mut()
        .find(|(r, _)| r == "hostio.rs")
        .expect("hostio.rs");
    host.1.push_str("\nfn planted() { let _ = std::net::TcpStream::connect(\"127.0.0.1:1\"); }\n");
    assert_eq!(offenders(&admitted), Vec::new());
}
