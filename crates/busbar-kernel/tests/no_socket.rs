// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL OPENS NO SOCKET (status row 130; BUSBAR-1.6.0.md THE DESIGN §1 and §5). The kernel is a
//! byte pump that knows nothing about transport: the chain is kernel -> `busbar-core-connector` ->
//! transport plugins, the connector binds every listener and dials every connection, and the
//! composition root serves what the connector hands up. So no production source of this crate may
//! name an operating-system socket, a name resolver, or an HTTP client or server stack, and its
//! manifest may ask for none.
//!
//! The tree does not meet that yet (Law 9: a ratchet armed at today's number). [`PINNED`] holds
//! every `(file, needle)` this scan measured when it was armed, and the scan holds the pin to the
//! tree BOTH ways:
//!
//! * a measured pair the pin does not hold is RED: a new socket, resolver or HTTP stack in the
//!   kernel, never admitted by adding it to the pin in the change that introduced it;
//! * a pinned pair the tree no longer has is RED too: the drain happened, so the pair is struck in
//!   the SAME commit (the pin only goes down).
//!
//! Row 130 is done when [`PINNED`] and [`PINNED_MANIFEST`] are empty.
//!
//! SCOPE. Every `.rs` under `src/` except test scaffolding: a file under a `tests/` directory, a
//! `*_tests.rs` or `tests.rs` file, `src/test_support/**`, and `src/egress/fixtures.rs` (compiled
//! only under `cfg(test)` / `test-support`). Comment lines are blanked first, so prose that names
//! a socket is not a finding. The manifest scan reads `[dependencies]` only (dev-dependencies are
//! test scaffolding).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// What a kernel source may not name: the OS sockets, the resolver, the HTTP client and server
/// stacks, the WebSocket client and the raw socket builder.
const NEEDLES: &[&str] = &[
    "TcpStream",
    "TcpListener",
    "UdpSocket",
    "UnixStream",
    "UnixListener",
    "lookup_host",
    "to_socket_addrs",
    "hyper_util::server",
    "hyper_util::client",
    "serve_connection",
    "hyper::client",
    "hyper::server",
    "tokio_tungstenite",
    "reqwest::",
    "socket2",
    "axum::serve",
];

/// What the kernel's `[dependencies]` may not ask for: the crates that are a socket or an HTTP
/// stack by name, and tokio's `net` feature.
const MANIFEST_NEEDLES: &[&str] = &["hyper-util", "tokio-tungstenite", "reqwest", "socket2"];

/// The tokio feature that is the socket layer.
const TOKIO_NET: &str = "tokio:net";

/// TODAY'S OFFENDERS, measured on predev after row 130 E1 (the hyper serve loop moved to the root).
/// Each line is struck in the commit that drains it.
const PINNED: &[(&str, &str)] = &[
    // E5: the engine pool (the owned hyper-util client, its https connector and resolver).
    ("src/egress/engine/client.rs", "hyper::client"),
    ("src/egress/engine/https.rs", "TcpStream"),
    ("src/egress/engine/https.rs", "hyper_util::client"),
    ("src/egress/engine/mod.rs", "TcpStream"),
    ("src/egress/engine/mod.rs", "hyper_util::client"),
    ("src/egress/engine/observe.rs", "hyper_util::client"),
    ("src/egress/engine/pool.rs", "hyper::client"),
    ("src/egress/engine/resolve.rs", "hyper_util::client"),
    ("src/egress/mod.rs", "reqwest::"),
    ("src/secure.rs", "TcpStream"),
];

/// TODAY'S MANIFEST OFFENDERS, struck as the code that needs each one leaves.
const PINNED_MANIFEST: &[&str] = &["hyper-util", "reqwest", TOKIO_NET];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Whether `rel` (crate-relative, `/`-separated) is test scaffolding the scan leaves out.
fn is_scaffolding(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    rel.contains("/tests/")
        || name.ends_with("_tests.rs")
        || name == "tests.rs"
        || rel.starts_with("src/test_support/")
        || rel == "src/egress/fixtures.rs"
}

/// The production `.rs` files under `root/src`, crate-relative and sorted.
fn production_sources(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .map(|e| e.expect("a directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(root, &path, out);
            } else if path.extension().is_some_and(|x| x == "rs") {
                let rel = path
                    .strip_prefix(root)
                    .expect("under the crate root")
                    .to_string_lossy()
                    .replace('\\', "/");
                if !is_scaffolding(&rel) {
                    out.push(rel);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &root.join("src"), &mut out);
    out
}

/// Every `(file, needle)` a production source under `root` names, comment lines blanked.
fn measure_sources(root: &Path) -> BTreeSet<(String, String)> {
    let mut found = BTreeSet::new();
    for rel in production_sources(root) {
        let text =
            std::fs::read_to_string(root.join(&rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        for line in text.lines() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for needle in NEEDLES {
                if line.contains(needle) {
                    found.insert((rel.clone(), (*needle).to_owned()));
                }
            }
        }
    }
    found
}

/// Every manifest needle `root/Cargo.toml`'s `[dependencies]` asks for (`tokio:net` for tokio's
/// `net` feature).
fn measure_manifest(root: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(root.join("Cargo.toml")).expect("read Cargo.toml");
    let mut found = BTreeSet::new();
    let mut in_deps = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_deps = t == "[dependencies]";
            continue;
        }
        if !in_deps || t.starts_with('#') {
            continue;
        }
        let Some((name, spec)) = t.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if MANIFEST_NEEDLES.contains(&name) {
            found.insert(name.to_owned());
        }
        if name == "tokio" && spec.contains("\"net\"") {
            found.insert(TOKIO_NET.to_owned());
        }
    }
    found
}

/// The two-way verdict of `measured` against `pinned`: the new offenders and the drained pins.
fn verdict<T: Ord + Clone + std::fmt::Debug>(
    measured: &BTreeSet<T>,
    pinned: &BTreeSet<T>,
) -> (Vec<T>, Vec<T>) {
    (
        measured.difference(pinned).cloned().collect(),
        pinned.difference(measured).cloned().collect(),
    )
}

fn pinned_sources() -> BTreeSet<(String, String)> {
    PINNED
        .iter()
        .map(|(f, n)| ((*f).to_owned(), (*n).to_owned()))
        .collect()
}

#[test]
fn the_kernel_names_no_socket_beyond_the_pin() {
    let root = crate_root();
    let files = production_sources(&root);
    assert!(
        files.len() > 100 && files.iter().any(|f| f == "src/lib.rs"),
        "the scan reaches the kernel's sources ({} files)",
        files.len()
    );
    let (new, drained) = verdict(&measure_sources(&root), &pinned_sources());
    assert!(
        new.is_empty(),
        "busbar-kernel names a socket, resolver or HTTP stack the pin does not hold (THE DESIGN \
         §5: every dial and listener is the connector's): {new:?}"
    );
    assert!(
        drained.is_empty(),
        "pinned offenders the tree no longer has: strike them from PINNED in this commit: \
         {drained:?}"
    );
}

#[test]
fn the_kernel_manifest_asks_for_no_socket_beyond_the_pin() {
    let pinned: BTreeSet<String> = PINNED_MANIFEST.iter().map(|s| (*s).to_owned()).collect();
    let (new, drained) = verdict(&measure_manifest(&crate_root()), &pinned);
    assert!(
        new.is_empty(),
        "busbar-kernel's [dependencies] ask for a socket or HTTP stack the pin does not hold: \
         {new:?}"
    );
    assert!(
        drained.is_empty(),
        "pinned manifest offenders the manifest no longer asks for: strike them from \
         PINNED_MANIFEST in this commit: {drained:?}"
    );
}

/// RED arms: a planted dial, listener and resolver are each seen; a planted test file and a comment
/// are not; a pin the tree no longer has is reported drained; a planted manifest asks are seen.
#[test]
fn a_planted_socket_is_seen_and_a_drained_pin_is_reported() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-kernel-no-socket-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src/tests")).expect("mkdir");
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub async fn dial() { let _ = tokio::net::TcpStream::connect(\"127.0.0.1:1\").await; }\n\
         // a comment naming TcpListener is prose\n\
         pub async fn names() { let _ = tokio::net::lookup_host(\"x:0\").await; }\n",
    )
    .expect("write lib");
    std::fs::write(
        dir.join("src/serve.rs"),
        "use hyper_util::server::conn::auto::Builder;\n",
    )
    .expect("write serve");
    std::fs::write(
        dir.join("src/tests/far_end_tests.rs"),
        "fn f() { let _ = std::net::TcpListener::bind(\"127.0.0.1:0\"); }\n",
    )
    .expect("write test file");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[dependencies]\ntokio = { workspace = true, features = [\"rt\", \"net\"] }\n\
         hyper-util = { workspace = true }\n[dev-dependencies]\nreqwest = { workspace = true }\n",
    )
    .expect("write manifest");

    let measured = measure_sources(&dir);
    let want: BTreeSet<(String, String)> = [
        ("src/lib.rs", "TcpStream"),
        ("src/lib.rs", "lookup_host"),
        ("src/serve.rs", "hyper_util::server"),
    ]
    .iter()
    .map(|(f, n)| ((*f).to_owned(), (*n).to_owned()))
    .collect();
    assert_eq!(
        measured, want,
        "the dial, the resolver and the server stack are seen; the comment and the test file are not"
    );

    let pinned: BTreeSet<(String, String)> = [("src/gone.rs", "TcpStream")]
        .iter()
        .map(|(f, n)| ((*f).to_owned(), (*n).to_owned()))
        .collect();
    let (new, drained) = verdict(&measured, &pinned);
    assert_eq!(new.len(), 3, "every unpinned plant is a new offender");
    assert_eq!(
        drained,
        vec![("src/gone.rs".to_owned(), "TcpStream".to_owned())],
        "a pin the tree no longer has is reported drained"
    );

    let manifest = measure_manifest(&dir);
    let want: BTreeSet<String> = ["hyper-util", TOKIO_NET]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(
        manifest, want,
        "tokio's net feature and hyper-util are seen; a dev-dependency is not"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
