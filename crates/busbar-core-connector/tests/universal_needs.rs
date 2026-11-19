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

type Pieces = Vec<(PieceKind, Option<u32>, Vec<u8>)>;

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

