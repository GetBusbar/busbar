// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `plugins.fetch` DOWNLOAD AGAINST A FAR END (`busbar-core-connector` `fetch::download`, boot
//! stage 3c). The download rides the connection table the root builds: a connector handed the
//! default distribution's own http transport image as its HTTP carrier (`Connector::carry_natively`,
//! as the root does at boot), trusting the operator's private anchor. Each registry is a loopback TLS
//! far end serving under that anchor; no public root vouches for it.
//!
//! - the request on the wire is `GET <path>` with `accept: */*` and the transport's `host`, nothing else;
//! - a private registry the operator's anchor vouches for downloads over TLS under the default guard;
//! - a stated `Content-Length` over the cap is refused before the body is read, a body over the cap
//!   with no stated length is refused from its bytes, and a small one is kept exactly;
//! - a redirect is refused in the redirect-SSRF words and its `Location` is never dialled;
//! - a registry name the guard refuses only once its resolution answers fails with the guard's own
//!   reason, and nothing is dialled;
//! - an unbound port fails naming the connect failure, never busbar's policy.
//!
//! The refusals before any dial (plaintext, userinfo) are the connector's own tests
//! (`crates/busbar-core-connector/src/tests/fetch_download_tests.rs`).

#![cfg(unix)]

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, OnceLock};
use std::time::Duration;

use busbar_contract::conn::{DeclaredConns, InstanceId, NeedId, PollConns};
use busbar_contract::services::codes::{DEST_INTERNAL, DEST_UNRESOLVABLE};
use busbar_contract::storage::{StorageAccount, StorageDenied, StorageSource};
use busbar_contract::transport::trust::EgressTrust;
use busbar_core_connector::fetch::{download, Table};
use busbar_core_connector::native_dial::NativeCarrier;
use busbar_core_connector::pool::PoolPosture;
use busbar_core_connector::{Connector, DialJudge, Judged, Verdict};
use busbar_plugin_abi::plane::CARRIER_HTTP;
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;

/// The longest any one far end waits on the download.
const PATIENCE: Duration = Duration::from_secs(20);

/// Long enough for a dial already under way to reach a counting listener.
const SETTLE: Duration = Duration::from_millis(200);

/// The artifact every registry here serves whole.
const ARTIFACT: &[u8] = b"artifact";

/// THE PROCESS'S ONE RUNTIME, installed once as the connector's reactor (as the root installs its
/// own at boot) and kept for the life of the test process.
fn runtime() -> &'static tokio::runtime::Runtime {
    static ONE: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    ONE.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        busbar_core_connector::io::install_process_reactor(runtime.handle().clone());
        runtime
    })
}

/// THE OPERATOR'S PRIVATE ANCHOR the registries serve under and the download's connector trusts
/// (`EgressTrust::extra_anchors`): the certificate's DER and its key's DER, for `localhost` and
/// `127.0.0.1`.
fn anchor() -> &'static (Vec<u8>, Vec<u8>) {
    static ONE: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    ONE.get_or_init(|| {
        let certified = busbar_contract::crypto::testing::rcgen::generate_simple_self_signed(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
        ])
        .expect("the private anchor");
        (
            certified.cert.der().to_vec(),
            certified.signing_key.serialize_der(),
        )
    })
}

/// A storage account that admits every reservation.
struct Unmetered;

impl StorageAccount for Unmetered {
    fn try_reserve(&self, _: usize) -> Result<(), StorageDenied> {
        Ok(())
    }
    fn release(&self, _: usize) {}
}

/// The download's table over the connector the root builds, judging every dial through `judge`;
/// the linked image is held for the table's life.
struct Registry {
    table: Table,
    _harness: Harness,
}

fn registry(judge: Arc<dyn DialJudge>) -> Registry {
    runtime();
    let harness = Harness::admit_linked(&busbar_transport_http::PLUGIN, FakeNeeds::new())
        .expect("the linked http image admits");
    let port = harness
        .open_transport("busbar-transport-http", b"{}")
        .expect("the linked http image opens");
    let trust = EgressTrust {
        extra_anchors: vec![anchor().0.clone()],
        ..EgressTrust::default()
    };
    let connector = Arc::new(
        Connector::serving_with_trust(judge, trust, Arc::new(|_, _| {}))
            .expect("the private anchor builds the download's TLS configuration")
            .pooling(PoolPosture {
                max_idle_per_host: 4,
                idle_timeout: Duration::from_secs(60),
            }),
    );
    connector
        .carry_natively(
            vec![NativeCarrier {
                instance: Arc::from("busbar-transport-http"),
                port,
                carrier: CARRIER_HTTP,
                stall_ms: None,
            }],
            StorageSource::new(Arc::new(Unmetered) as Arc<dyn StorageAccount>),
        )
        .expect("the boot hand-over");
    Registry {
        table: Table {
            owner: InstanceId(9),
            secured_need: NeedId(1),
            declared: Arc::clone(&connector) as Arc<dyn DeclaredConns>,
            conns: connector as Arc<dyn PollConns>,
        },
        _harness: harness,
    }
}

/// A judge admitting every loopback address literal and nothing else (an operator whose guard
/// admits its loopback registry).
fn loopback(target: &str, _: u32, _: Judged) -> Option<Result<SocketAddr, Verdict>> {
    Some(
        target
            .parse::<SocketAddr>()
            .ok()
            .filter(|address| address.ip().is_loopback())
            .ok_or(DEST_UNRESOLVABLE),
    )
}

/// The deployment's own dial judge under the owner default (`block_private_addresses`) and the
/// operator's extra `blocked` hosts: the one destination guard, as the root builds it.
fn guarded(blocked: &[&str]) -> Arc<dyn DialJudge> {
    let destinations = busbar_kernel::config::Destinations {
        block_private_addresses: busbar_kernel::config::sections::DEFAULT_BLOCK_PRIVATE_ADDRESSES,
        blocked: blocked.iter().map(|b| (*b).to_owned()).collect(),
        listens: Vec::new(),
    };
    busbar_core_connector::process::judge(
        busbar_core_connector::process::dest_judge(&destinations).expect("a valid guard"),
        &[],
    )
}

/// What a registry does once it has read the request head.
#[derive(Clone, Copy)]
enum Then {
    /// Write the answer whole and close.
    Answer,
    /// Write the answer and hold the connection open until the download hangs up.
    Hold,
}

/// A loopback TLS registry under the [`anchor`] that reads one request head and answers `response`:
/// its address, and the head it read.
fn serve_tls(response: Vec<u8>, then: Then) -> (SocketAddr, mpsc::Receiver<String>) {
    let (cert, key) = anchor();
    let mut config = Arc::unwrap_or_clone(
        busbar_contract::crypto::tls::server_config(|b| {
            b.with_no_client_auth().with_single_cert(
                vec![rustls_pki_types::CertificateDer::from(cert.clone())],
                rustls_pki_types::PrivateKeyDer::try_from(key.clone()).expect("the anchor's key"),
            )
        })
        .expect("the registry's TLS"),
    );
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the registry");
    let far = listener.local_addr().expect("its address");
    let (seen_tx, seen_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((socket, _)) = listener.accept() else {
            return;
        };
        socket.set_read_timeout(Some(PATIENCE)).ok();
        socket.set_write_timeout(Some(PATIENCE)).ok();
        let session = rustls::ServerConnection::new(config).expect("a TLS session");
        let mut stream = rustls::StreamOwned::new(session, socket);
        let mut request = Vec::new();
        let mut byte = [0_u8];
        while !request.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(1) => request.push(byte[0]),
                _ => return,
            }
        }
        let _ = seen_tx.send(String::from_utf8_lossy(&request).into_owned());
        let _ = stream.write_all(&response);
        let _ = stream.flush();
        if matches!(then, Then::Hold) {
            let mut sink = [0_u8; 256];
            while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
            return;
        }
        stream.conn.send_close_notify();
        let _ = stream.flush();
    });
    (far, seen_rx)
}

/// One download of `path` over `registry` from a TLS registry answering `response`: what it got, and
/// the request head the registry read (empty when none arrived).
fn fetch_over(
    registry: &Registry,
    path: &str,
    response: &str,
    then: Then,
    cap: usize,
) -> (Result<Vec<u8>, String>, String) {
    let (far, seen) = serve_tls(response.as_bytes().to_vec(), then);
    let url = format!("https://{far}{path}");
    let got = download(&registry.table, &url, &[], cap);
    let head = seen.recv_timeout(SETTLE).unwrap_or_default();
    (got, head)
}

/// [`fetch_over`] a registry the loopback judge admits.
fn fetch_once(path: &str, response: &str, then: Then, cap: usize) -> (Result<Vec<u8>, String>, String) {
    fetch_over(&registry(Arc::new(loopback)), path, response, then, cap)
}

/// A loopback far end that counts every connection it accepts: its address and the count.
fn counting_listener() -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let at = l.local_addr().expect("its address");
    let seen = Arc::new(AtomicUsize::new(0));
    let counting = Arc::clone(&seen);
    std::thread::spawn(move || {
        for s in l.incoming() {
            if s.is_ok() {
                counting.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    (at, seen)
}

/// THE DOWNLOAD'S WIRE IS 1.5.5's: `GET <path>` with `accept: */*` through the table, and nothing but
/// the transport's own `host` beside it.
#[test]
fn the_plugins_fetch_download_sends_1_5_5s_request_through_the_table() {
    let path = "/releases/busbar-oracle-fetch-1.0.0.tar.gz";
    let (got, head) = fetch_once(
        path,
        "HTTP/1.1 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\nartifact",
        Then::Answer,
        4096,
    );
    assert_eq!(got.as_deref(), Ok(ARTIFACT));
    let mut lines = head.split("\r\n").filter(|line| !line.is_empty());
    assert_eq!(
        lines.next(),
        Some(format!("GET {path} HTTP/1.1").as_str()),
        "{head}"
    );
    let mut fields: Vec<(String, String)> = lines
        .map(|line| {
            let (name, value) = line.split_once(':').expect("a field line");
            (name.trim().to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    fields.sort();
    let host = fields
        .iter()
        .find(|(name, _)| name == "host")
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    assert!(host.starts_with("127.0.0.1:"), "{head}");
    assert_eq!(
        fields,
        vec![
            ("accept".to_owned(), "*/*".to_owned()),
            ("host".to_owned(), host),
        ],
        "the request carries accept */* and the transport's host, nothing else: {head}"
    );
}

/// A private registry downloads under the default guard, over TLS its operator's private anchor
/// vouches for.
#[test]
fn a_private_registry_downloads_over_tls_under_the_default_guard() {
    let (got, head) = fetch_over(
        &registry(guarded(&[])),
        "/releases/busbar-oracle-fetch-1.0.0.tar.gz",
        "HTTP/1.1 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\nartifact",
        Then::Answer,
        4096,
    );
    assert_eq!(got.as_deref(), Ok(ARTIFACT), "{head}");
    assert!(head.starts_with("GET /releases/"), "{head}");
}

/// The cap (`DEFAULT_PLUGIN_FETCH_MAX_BYTES` at boot): a stated `Content-Length` over it is refused
/// from the head, before a body byte is read (the registry sends none and holds the line open); a
/// body over the cap with no stated length is refused from its bytes; a small one is kept exactly.
#[test]
fn the_plugins_fetch_download_refuses_an_oversized_body_and_keeps_a_small_one() {
    let cap = busbar_kernel::config::DEFAULT_PLUGIN_FETCH_MAX_BYTES;
    let over = cap + 1;
    let (got, _) = fetch_once(
        "/big",
        &format!("HTTP/1.1 200 OK\r\ncontent-length: {over}\r\n\r\n"),
        Then::Hold,
        cap,
    );
    let err = got.expect_err("an over-cap download is a clear error");
    assert!(
        err.ends_with(&format!(
            ": declared Content-Length {over} exceeds the {cap}-byte plugins.fetch download cap"
        )),
        "{err}"
    );

    let chunks = "8\r\nxxxxxxxx\r\n".repeat(32);
    let (got, _) = fetch_once(
        "/big-streamed",
        &format!("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n{chunks}0\r\n\r\n"),
        Then::Answer,
        64,
    );
    let err = got.expect_err("an over-cap download with no Content-Length is still refused");
    assert!(
        err.ends_with(
            ": response exceeded the 64-byte plugins.fetch download cap; refusing to buffer a \
             truncated download"
        ),
        "{err}"
    );

    let small = "y".repeat(32);
    let (got, _) = fetch_once(
        "/small",
        &format!("HTTP/1.1 200 OK\r\ncontent-length: 32\r\nconnection: close\r\n\r\n{small}"),
        Then::Answer,
        64,
    );
    assert_eq!(
        got,
        Ok(small.into_bytes()),
        "a within-cap download is the body exactly"
    );
}

/// A redirect is refused in the redirect-SSRF words, and its `Location` is never dialled.
#[test]
fn the_plugins_fetch_download_refuses_to_follow_a_redirect() {
    let (elsewhere, dialled) = counting_listener();
    let (got, _) = fetch_once(
        "/artifact",
        &format!(
            "HTTP/1.1 302 Found\r\nlocation: https://{elsewhere}/metadata\r\ncontent-length: 0\r\n\r\n"
        ),
        Then::Answer,
        4096,
    );
    let err = got.expect_err("a redirect is refused, not followed");
    assert!(
        err.ends_with(
            ": HTTP 302 Found — refusing to follow a plugins.fetch redirect (redirect-SSRF guard)"
        ),
        "{err}"
    );
    std::thread::sleep(SETTLE);
    assert_eq!(
        dialled.load(Ordering::SeqCst),
        0,
        "the Location was never dialled"
    );
}

/// A judge that pends on every name and answers, from another thread, the guard's refusal of an
/// internal address.
fn pended_refusal(_: &str, _: u32, done: Judged) -> Option<Result<SocketAddr, Verdict>> {
    std::thread::spawn(move || done(Err(DEST_INTERNAL)));
    None
}

/// A registry NAME the guard refuses only once its resolution answers (a pended verdict) fails the
/// download with the guard's own reason, and nothing is dialled.
#[test]
fn a_pended_guard_refusal_names_busbars_policy_and_dials_nothing() {
    let registry = registry(Arc::new(pended_refusal));
    let (at, seen) = counting_listener();
    let url = format!("https://registry.localhost:{}/a.tar.gz", at.port());
    let err = download(&registry.table, &url, &[], 4096)
        .expect_err("a refused registry is never downloaded from");
    assert!(
        err.ends_with(
            ": busbar refused it before connecting: the destination guard refuses an internal or \
             loopback address (enable allow_private on its upstream registration to allow it)"
        ),
        "{err}"
    );
    std::thread::sleep(SETTLE);
    assert_eq!(seen.load(Ordering::SeqCst), 0, "nothing was dialled");
}

/// A DIAL FAILURE NAMES THE PATH, NEVER BUSBAR'S POLICY: an unbound port fails with "could not
/// connect to the registry" and the OS's own text.
#[test]
fn a_dial_failure_names_the_registry_not_busbars_policy() {
    let registry = registry(Arc::new(loopback));
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        l.local_addr().expect("its address").port()
    };
    let url = format!("https://127.0.0.1:{port}/a.tar.gz");
    let err = download(&registry.table, &url, &[], 4096).expect_err("nothing listens");
    let sending = format!("GET {url}: error sending request for url ({url})");
    let rest = err
        .strip_prefix(&sending)
        .unwrap_or_else(|| panic!("the 1.5.5 prefix is kept: {err}"));
    let os = rest
        .strip_prefix(": could not connect to the registry: ")
        .unwrap_or_else(|| panic!("the path is named: {err}"));
    assert!(!os.is_empty(), "{err}");
    assert!(!err.contains("busbar refused"), "{err}");
    assert!(!err.contains("destination guard"), "{err}");
}
