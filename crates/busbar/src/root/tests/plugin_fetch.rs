// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `plugins.fetch` DOWNLOAD THROUGH THE ONE CONNECTOR (status row 130 E6): the linked http
//! transport door, dialled by a connector over a real loopback socket to a scripted far end. The
//! request on the wire is 1.5.5's (`GET <path>`, `accept: */*` before `host`: oracle cell
//! `egress.fetch|plugins|url`, known-red until this move), and the download's own rules moved from
//! the kernel's deleted `preflight::plugin_fetch_downloader` hold as its suite held them: an
//! oversized body refused under the cap whether its `Content-Length` is honest or absent, a
//! within-cap body downloaded byte for byte, a redirect refused and never followed.

// The wire rows need the linked http door; a build that leaves it unlinked runs only the pre-check
// row, and the helpers the wire rows share are unused there.
#![cfg_attr(not(linked_every_transport), allow(dead_code, unused_imports))]

use std::sync::{Arc, Mutex};

use busbar_contract::conn::{DeclaredConns, InstanceId, PollConns};
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::registry::Transports;
use busbar_core_connector::{process, Connector};
use busbar_kernel::config::Destinations;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{downloader_over, Table};

const OWNER: InstanceId = InstanceId(9);

/// A connector over this build's linked transport doors whose guard admits the loopback far ends
/// these tests serve (private addresses not blocked).
fn connector() -> Arc<Connector> {
    let dest = crate::root::connector::guard_for(&Destinations {
        block_private_addresses: false,
        ..Destinations::default()
    })
    .expect("the guard");
    let settings = TransportSettings::default();
    let view = Transports::new(
        crate::root::connector::entries(crate::LINKED_TRANSPORT_DOORS, &settings)
            .expect("the linked doors open"),
    )
    .expect("the view");
    Arc::new(Connector::serving(
        view,
        process::judge(dest, &[]),
        None,
        Arc::new(|_| {}),
    ))
}

/// The download over `c`, capped at `cap`.
fn download(c: &Arc<Connector>, cap: usize) -> impl Fn(&str) -> Result<Vec<u8>, String> {
    let c = Arc::clone(c);
    downloader_over(&[], cap, move || Table {
        owner: OWNER,
        declared: Arc::clone(&c) as Arc<dyn DeclaredConns>,
        conns: Arc::clone(&c) as Arc<dyn PollConns>,
    })
}

/// A far end on loopback answering one request with `answer`; what it read is kept.
async fn far_end(answer: Vec<u8>) -> (String, Arc<Mutex<Vec<u8>>>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&seen);
    tokio::spawn(async move {
        let Ok((mut s, _)) = l.accept().await else {
            return;
        };
        let mut head = Vec::new();
        let mut buf = [0_u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => head.extend_from_slice(&buf[..n]),
            }
        }
        *kept.lock().unwrap() = head;
        let _ = s.write_all(&answer).await;
        let _ = s.shutdown().await;
    });
    (addr, seen)
}

/// Run one download of `url` off the runtime, as boot and reload do.
async fn fetch(
    d: impl Fn(&str) -> Result<Vec<u8>, String> + Send + 'static,
    url: String,
) -> Result<Vec<u8>, String> {
    tokio::task::spawn_blocking(move || d(&url)).await.unwrap()
}

/// THE WIRE IS 1.5.5's: the download sends `GET <path>` with the client defaults the http door
/// owns, `accept: */*` and then `host`, and nothing else (oracle cell `egress.fetch|plugins|url`;
/// the kernel engine sent no `accept`), and the artifact comes back byte for byte.
#[cfg(linked_every_transport)]
#[tokio::test(flavor = "multi_thread")]
async fn the_download_sends_1_5_5s_request_through_the_connector() {
    let (addr, seen) = far_end(
        b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\nartifact".to_vec(),
    )
    .await;
    let c = connector();
    let url = format!("http://{addr}/releases/busbar-oracle-fetch-1.0.0.tar.gz");
    let got = fetch(download(&c, 4096), url).await;
    assert_eq!(got.as_deref(), Ok(&b"artifact"[..]));
    let head = String::from_utf8(seen.lock().unwrap().clone()).unwrap();
    assert_eq!(
        head,
        format!(
            "GET /releases/busbar-oracle-fetch-1.0.0.tar.gz HTTP/1.1\r\naccept: */*\r\n\
             host: {addr}\r\n\r\n"
        ),
        "the request on the wire is 1.5.5's"
    );
}

/// An oversized body is refused under the cap, from an honest `Content-Length` (before a body
/// byte) and from a chunked answer with none (counted as it arrives); a within-cap body downloads
/// byte for byte.
#[cfg(linked_every_transport)]
#[tokio::test(flavor = "multi_thread")]
async fn the_download_refuses_an_oversized_body_and_keeps_a_small_one() {
    const CAP: usize = 64;
    let c = connector();

    let mut honest = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", CAP * 4).into_bytes();
    honest.extend_from_slice(&[b'x'; CAP * 4]);
    let (addr, _) = far_end(honest).await;
    let err = fetch(download(&c, CAP), format!("http://{addr}/big"))
        .await
        .expect_err("an over-cap download is a clear error");
    assert!(
        err.contains("declared Content-Length 256 exceeds the 64-byte"),
        "{err}"
    );

    let mut chunked = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n".to_vec();
    for _ in 0..(CAP * 4 / 8) {
        chunked.extend_from_slice(b"8\r\nxxxxxxxx\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let (addr, _) = far_end(chunked).await;
    let err = fetch(download(&c, CAP), format!("http://{addr}/big-streamed"))
        .await
        .expect_err("an over-cap download with no Content-Length is still refused");
    assert!(
        err.contains("response exceeded the 64-byte plugins.fetch download cap"),
        "{err}"
    );

    let mut small = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", CAP / 2).into_bytes();
    small.extend_from_slice(&[b'y'; CAP / 2]);
    let (addr, _) = far_end(small).await;
    assert_eq!(
        fetch(download(&c, CAP), format!("http://{addr}/small")).await,
        Ok(vec![b'y'; CAP / 2]),
        "a within-cap download is the served body exactly"
    );
}

/// A redirect is refused and never followed: the error names it, and the redirect target's bytes
/// never come back.
#[cfg(linked_every_transport)]
#[tokio::test(flavor = "multi_thread")]
async fn the_download_refuses_to_follow_a_redirect() {
    let (addr, _) =
        far_end(b"HTTP/1.1 302 Found\r\nlocation: /metadata\r\ncontent-length: 0\r\n\r\n".to_vec())
            .await;
    let c = connector();
    let url = format!("http://{addr}/artifact");
    let err = fetch(download(&c, 4096), url.clone())
        .await
        .expect_err("a redirect is refused, not followed");
    assert_eq!(
        err,
        format!(
            "GET {url}: HTTP 302 Found — refusing to follow a plugins.fetch redirect \
             (redirect-SSRF guard)"
        )
    );
}

/// RED: the pre-checks refuse before any dial: a public host in plaintext, and a cloud-metadata
/// host (the operator's denylist extending the built-in one).
#[test]
fn the_download_refuses_before_any_dial() {
    let c = Arc::new(Connector::new());
    let blocked = ["registry.internal.example".to_owned()];
    let d = downloader_over(&blocked, 64, move || Table {
        owner: OWNER,
        declared: Arc::clone(&c) as Arc<dyn DeclaredConns>,
        conns: Arc::clone(&c) as Arc<dyn PollConns>,
    });
    assert_eq!(
        d("http://registry.example.com/p.tar.gz"),
        Err(
            "plugins.fetch url must use https for a public host (got 'http://registry.example.com/p.tar.gz')"
                .to_owned()
        )
    );
    let err = d("https://169.254.169.254/latest/p.tar.gz").unwrap_err();
    assert!(err.contains("blocked cloud-metadata host"), "{err}");
    let err = d("https://registry.internal.example/p.tar.gz").unwrap_err();
    assert!(err.contains("blocked cloud-metadata host"), "{err}");
}
