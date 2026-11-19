// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `plugins.fetch` DOWNLOAD'S REFUSALS BEFORE ANY DIAL (`fetch::download`): a plaintext URL is
//! refused by the https-only rule on every host, and an https URL carrying userinfo is refused by the
//! connection table's own check, each in words, with nothing dialled. The exchange with a far end
//! (the request on the wire, TLS under an operator anchor, the caps, a redirect, a pended guard
//! refusal, a dial failure) is proved through the default distribution's linked http image
//! (`dist/default/tests/plugins_fetch_download.rs`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::conn::{DeclaredConns, InstanceId, NeedId, PollConns};

use crate::fetch::{download, Table};
use crate::Connector;

/// The download's table over a connector of its own, as the root's is shaped.
fn table() -> Table {
    let connector = Arc::new(Connector::new());
    Table {
        owner: InstanceId(9),
        secured_need: NeedId(1),
        declared: Arc::clone(&connector) as Arc<dyn DeclaredConns>,
        conns: connector as Arc<dyn PollConns>,
    }
}

/// A loopback far end that counts every connection it accepts: its port and the count.
fn counting_listener() -> (u16, Arc<AtomicUsize>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = l.local_addr().expect("its address").port();
    let seen = Arc::new(AtomicUsize::new(0));
    let counting = Arc::clone(&seen);
    std::thread::spawn(move || {
        for s in l.incoming() {
            if s.is_ok() {
                counting.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    (port, seen)
}

/// Long enough for a dial already under way to reach the counting listener.
const SETTLE: Duration = Duration::from_millis(200);

/// SEC-2, #297: `plugins.fetch` is core-owned and https only. A plaintext registry URL is refused
/// on every host (public, private, loopback: no loopback exemption, no acceptance admits it) in the
/// rule's own words, and nothing is dialled.
#[test]
fn a_plaintext_registry_is_refused_on_every_host_and_nothing_is_dialled() {
    let table = table();
    let (port, seen) = counting_listener();
    for host in [
        "registry.example.com",
        "10.0.0.7",
        "127.0.0.1",
        "localhost",
    ] {
        let url = format!("http://{host}:{port}/releases/busbar-oracle-fetch-1.0.0.tar.gz");
        let err = download(&table, &url, &[], 4096)
            .expect_err("a plaintext registry is never downloaded from");
        assert_eq!(
            err,
            format!(
                "plugins.fetch url must use https (got '{url}'): a plugin download is never \
                 admitted over plaintext, on any host"
            )
        );
    }
    std::thread::sleep(SETTLE);
    assert_eq!(seen.load(Ordering::SeqCst), 0, "nothing was dialled");
}

/// An https URL carrying userinfo is refused before anything is dialled, naming the userinfo: busbar
/// never sends credentials embedded in a URL. (The operator's view, which never shows the password,
/// is the root's: `the_roots_fetch_names_a_userinfo_refusal_and_never_shows_the_password`.)
#[test]
fn a_download_url_with_userinfo_is_refused_in_words() {
    let table = table();
    let (port, seen) = counting_listener();
    let url = format!("https://fetcher:pw-H10-s3cr3t@127.0.0.1:{port}/a.tar.gz");
    let err = download(&table, &url, &[], 4096).expect_err("a credentialed URL is never requested");
    assert!(
        err.ends_with(
            ": busbar refused it before connecting: the URL carries userinfo; busbar never \
             sends credentials embedded in a URL"
        ),
        "{err}"
    );
    std::thread::sleep(SETTLE);
    assert_eq!(seen.load(Ordering::SeqCst), 0, "nothing was dialled");
}
