// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNIVERSAL-NEEDS WITNESS (THE DESIGN: connections — "any plugin of any kind reaches the
//!
//! Every door here is core's own, so no plugin is built or loaded (owner ruling: "core knows
//! nothing about plugins just kinds, plugins test themselves and nothing else"): the socket arm
//! drives the plugin loader's in-tree neutral frame door, and the request/response arms (head
//! words and pieces through the table, the sealed opening through TLS, the plugin-fetch download
//! and its guard refusals) drive the in-tree kind-level HTTP/1.1 framer double
//! (`src/tests/http_framer_double.rs`), loaded through the loader's linked path.

use std::sync::OnceLock;

use busbar_contract::conn::{ConnError, PieceKind};
use busbar_contract::crypto::testing::rcgen;

use busbar_core_connector::{carrier, compose, framer, hostio};

#[path = "../src/tests/support.rs"]
mod support;

#[path = "../src/tests/http_framer_double.rs"]
mod http_framer_double;

/// The libraries beside this test binary: uplifted, under `deps/`, or an example `cdylib`.
fn libraries_beside_the_test() -> Vec<std::path::PathBuf> {
    let Some(profile) = std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.parent()?.to_path_buf()))
    else {
        return Vec::new();
    };
    [
        profile.clone(),
        profile.join("deps"),
        profile.join("examples"),
    ]
    .iter()
    .flat_map(|dir| {
        busbar_plugin_loader::list_plugin_files(dir)
            .into_iter()
            .map(move |f| dir.join(f))
    })
    .collect()
}

/// THE CONNECTOR DRIVES A DROPPED-IN DOOR THAT FRAMES THE HOST'S SOCKET against a real far end: the
#[test]
fn the_connector_drives_a_dropped_in_socket_framer_against_a_real_far_end() {
    use busbar_core_connector::compose::{Connection, Dial};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let door = socket_framer_door().expect("a socket-framing door is built beside the test");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut socket, _) = l.accept().await.unwrap();
            let mut buf = [0_u8; 4096];
            while let Ok(n) = socket.read(&mut buf).await {
                if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        let mut c = Connection::dial(
            door,
            &support::via(),
            Dial {
                plaintext_accepted: false,
                target: far,
                tls: None,
                alpn: std::sync::Arc::default(),
                open_timeout: std::time::Duration::from_secs(5),
                opening: Some((Vec::new(), b"opening;".to_vec().into())),
                head_words: Default::default(),
                anchors: None,
            },
        )
        .expect("the connector dials through the door");
        let payload: Vec<u8> = (0..=255_u8).cycle().take(40_000).collect();
        c.write(
            &payload,
            true,
            false,
            &mut std::task::Context::from_waker(std::task::Waker::noop()),
        )
        .expect("the write is taken");
        let mut got = Vec::new();
        while got.len() < 8 + payload.len() {
            let p = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                futures::future::poll_fn(|cx| c.poll_piece(cx)),
            )
            .await
            .expect("the far end answers")
            .expect("no failure")
            .expect("not ended");
            got.extend(p.bytes);
        }
        assert_eq!(&got[..8], b"opening;");
        assert_eq!(&got[8..], &payload[..]);
        c.close();
    });
}

type Pieces = Vec<(PieceKind, Option<u32>, Vec<u8>)>;

/// RED: THE CONNECTOR YIELDS THE FAR END'S HEAD. A response with head fields reads, through the
#[test]
fn a_response_with_head_fields_yields_fields_then_body() {
    let got = pieces_through_the_table(
        "{V} 200 OK\r\nX-B: 1\r\nConnection: keep-alive, x-hop\r\nX-Session-Id: s1\r\n\
          Keep-Alive: timeout=5\r\nx-b: 2\r\nX-Hop: secret\r\ncontent-length: 5\r\n\r\nhello",
    );
    let (kind, status, head) = &got[0];
    assert_eq!((*kind, *status), (PieceKind::Fields, Some(200)), "{got:?}");
    assert_eq!(
        String::from_utf8_lossy(head),
        "x-b: 1\r\nx-b: 2\r\nx-session-id: s1\r\n"
    );

    let (last, between) = got[1..].split_last().expect("pieces after the head");
    assert_eq!(last.0, PieceKind::Completion, "{got:?}");
    let body: Vec<u8> = between
        .iter()
        .inspect(|(k, _, _)| assert_eq!(*k, PieceKind::Body, "{got:?}"))
        .flat_map(|(_, _, b)| b.clone())
        .collect();
    assert_eq!(body, b"hello");
}

/// RED: AN EMPTY HEAD STILL COMES FIRST. A head with no field left after the hop-by-hop drop reads
#[test]
fn an_empty_head_yields_one_empty_fields_piece() {
    let got = pieces_through_the_table("{V} 204 No Content\r\nConnection: close\r\n\r\n");
    assert_eq!(
        got[0],
        (PieceKind::Fields, Some(204), Vec::new()),
        "{got:?}"
    );
    assert_eq!(
        got.iter()
            .filter(|(k, _, _)| *k == PieceKind::Fields)
            .count(),
        1,
        "{got:?}"
    );
}

/// A response template with its version written as the door's own scheme, upper-cased (`{V}`), so
fn respond(scheme: &str, template: &str) -> Vec<u8> {
    template
        .replace("{V}", &format!("{}/1.1", scheme.to_ascii_uppercase()))
        .into_bytes()
}

/// A loopback far end that reads one request head and answers `response`: its address, and the
async fn serve_once(
    response: Vec<u8>,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let far = l.local_addr().unwrap();
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut req = Vec::new();
        let mut buf = [0_u8; 1024];
        while !req.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut buf).await.unwrap();
            assert!(n > 0, "the request head arrives");
            req.extend_from_slice(&buf[..n]);
        }
        let _ = seen_tx.send(String::from_utf8_lossy(&req).into_owned());
        s.write_all(&response).await.unwrap();
    });
    (far, seen_rx)
}

/// THE PRIVATE TRUST ANCHOR the TLS far end serves under and the download's connector trusts (its
/// `EgressTrust::extra_anchors`, as an operator's private registry CA is): the certificate's DER and its
/// key's DER, for `localhost` and `127.0.0.1`. No public root vouches for it.
fn private_anchor() -> &'static (Vec<u8>, Vec<u8>) {
    static ONE: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    ONE.get_or_init(|| {
        let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
        ])
        .unwrap();
        (cert.der().to_vec(), signing_key.serialize_der())
    })
}

/// The request framer's secured claim (`https`): the claim whose located target is secured.
fn secured_claim(door: &dyn busbar_core_connector::framer::FramerDoor) -> &'static str {
    door.facts()
        .claims
        .iter()
        .copied()
        .find(|claim| {
            framer::locate(door, &format!("{claim}://127.0.0.1:443/"))
                .is_ok_and(|located| located.secure)
        })
        .expect("the request framer states its secured claim")
}

/// An oversized body is refused under the cap, from an honest `Content-Length` (before a body
#[test]
fn the_plugins_fetch_download_refuses_an_oversized_body_and_keeps_a_small_one() {
    let big = "x".repeat(256);
    let (got, _) = fetch_once(
        "/big",
        &format!("{{V}} 200 OK\r\ncontent-length: 256\r\n\r\n{big}"),
        64,
    );
    let err = got.expect_err("an over-cap download is a clear error");
    assert!(
        err.contains("declared Content-Length 256 exceeds the 64-byte"),
        "{err}"
    );

    let chunks = "8\r\nxxxxxxxx\r\n".repeat(32);
    let (got, _) = fetch_once(
        "/big-streamed",
        &format!("{{V}} 200 OK\r\ntransfer-encoding: chunked\r\n\r\n{chunks}0\r\n\r\n"),
        64,
    );
    let err = got.expect_err("an over-cap download with no Content-Length is still refused");
    assert!(
        err.contains("response exceeded the 64-byte plugins.fetch download cap"),
        "{err}"
    );

    let small = "y".repeat(32);
    let (got, _) = fetch_once(
        "/small",
        &format!("{{V}} 200 OK\r\ncontent-length: 32\r\nconnection: close\r\n\r\n{small}"),
        64,
    );
    assert_eq!(
        got,
        Ok(small.into_bytes()),
        "a within-cap download is the body exactly"
    );
}

/// A redirect is refused and never followed, in 1.5.5's words.
#[test]
fn the_plugins_fetch_download_refuses_to_follow_a_redirect() {
    let (got, _) = fetch_once(
        "/artifact",
        "{V} 302 Found\r\nlocation: /metadata\r\ncontent-length: 0\r\n\r\n",
        4096,
    );
    let err = got.expect_err("a redirect is refused, not followed");
    assert!(
        err.contains(
            "302 Found — refusing to follow a plugins.fetch redirect (redirect-SSRF guard)"
        ),
        "{err}"
    );
}

/// The deployment's own dial judge: the one destination guard over `destinations`, the owner's
fn guarded(blocked: &[&str]) -> std::sync::Arc<dyn busbar_core_connector::DialJudge> {
    let destinations = busbar_kernel::config::Destinations {
        block_private_addresses: true,
        blocked: blocked.iter().map(|b| (*b).to_owned()).collect(),
        listens: Vec::new(),
    };
    busbar_core_connector::process::judge(
        busbar_core_connector::process::dest_judge(&destinations).expect("a valid guard"),
        &[],
    )
}

/// A loopback far end that counts every connection it accepts: its port and the count.
fn counting_listener() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counting = std::sync::Arc::clone(&seen);
    std::thread::spawn(move || {
        for s in l.incoming() {
            if s.is_ok() {
                counting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    });
    (port, seen)
}

/// RED (F-013): A URL CARRYING USERINFO IS REFUSED IN WORDS, before anything is dialled.
#[test]
fn a_download_url_with_userinfo_is_refused_in_words() {
    let (scheme, table) = fetch_table();
    let (port, seen) = counting_listener();
    let url = format!("{scheme}://fetcher:pw-H10-s3cr3t@127.0.0.1:{port}/a.tar.gz");
    let err = busbar_core_connector::fetch::download(&table, &url, &[], 4096)
        .expect_err("a credentialed URL is never requested");
    assert!(
        err.ends_with(
            ": busbar refused it before connecting: the URL carries userinfo; busbar never \
             sends credentials embedded in a URL"
        ),
        "{err}"
    );
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(
        seen.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing was dialled"
    );
}
