// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TLS CONFORMANCE SUBJECT (testing/tls-conformance): the connector's own TLS listener, served
//! on loopback for testssl.sh to assess. It is the production path end to end: a run-time
//! self-signed certificate written as PEM files and read back through `tls::build_server_config`
//! (the one place the server's TLS policy is built), then `Listening::bind` with that config and the
//! protocol offer, framing through the test crate's identity framer door (no plugin) and echoing.
//!
//!     cargo run -p busbar-core-connector --example tls_subject -- <out dir>
//!
//! Writes `<out dir>/cert.pem`, `key.pem`, then `addr` (`ip:port`, written last: its presence is the
//! ready signal) and serves until killed.

use std::sync::Arc;

use busbar_core_connector::listen::{AcceptLimits, Listening};
use busbar_core_connector::{carrier, compose, framer, hostio};
use busbar_kernel::config::secret::SecretResolver;
use busbar_kernel::config::{SecretRef, TlsCfg};

#[allow(dead_code, unsafe_code, unused_imports, clippy::all, clippy::pedantic)]
#[path = "../src/tests/support.rs"]
mod support;

/// The calendar date `days` from today (UTC), as the certificate's validity wants it.
fn days_from_now(days: i64) -> (i32, u8, u8) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs();
    // civil-from-days (H. Hinnant): the UTC calendar date of a day count since 1970-01-01.
    let z = i64::try_from(now / 86_400).expect("a day count") + days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u8::try_from(doy - (153 * mp + 2) / 5 + 1).expect("a day");
    let m = u8::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).expect("a month");
    let y = i32::try_from(yoe + era * 400 + i64::from(m <= 2)).expect("a year");
    (y, m, d)
}

fn main() {
    let dir = std::path::PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: tls_subject <out dir>"),
    );
    std::fs::create_dir_all(&dir).expect("out dir");
    busbar_core_connector::tls::install_crypto_provider();

    // A certificate shaped like a public one a server is deployed with: a 90-day life that has begun,
    // and a CRL distribution point. The assessment's "no HIGH finding" rule reads both.
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("cert params");
    let ((y0, m0, d0), (y1, m1, d1)) = (days_from_now(-1), days_from_now(89));
    params.not_before = rcgen::date_time_ymd(y0, m0, d0);
    params.not_after = rcgen::date_time_ymd(y1, m1, d1);
    params.crl_distribution_points = vec![rcgen::CrlDistributionPoint {
        uris: vec!["http://localhost/subject.crl".to_owned()],
    }];
    let signing_key = rcgen::KeyPair::generate().expect("a key");
    let cert = params
        .self_signed(&signing_key)
        .expect("a self-signed cert");
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, cert.pem()).expect("cert.pem");
    std::fs::write(&key_path, signing_key.serialize_pem()).expect("key.pem");

    let cfg = TlsCfg {
        cert: SecretRef::file(cert_path.to_string_lossy().into_owned()),
        key: SecretRef::file(key_path.to_string_lossy().into_owned()),
        client_ca: None,
    };
    let server =
        busbar_core_connector::tls::build_server_config(&cfg, &SecretResolver::builtins_only())
            .expect("the production TLS config builds");

    let alpn: Vec<Vec<u8>> = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    support::worker().block_on(async move {
        let door = Arc::new(support::TestDoor::identity("bytes"));
        let mut l = Listening::bind(
            Some(door),
            &support::via(),
            "127.0.0.1:0",
            Some(Arc::new(server)),
            alpn,
            AcceptLimits::default(),
        )
        .expect("binds");
        std::fs::write(dir.join("addr"), l.local_addr().to_string()).expect("addr");
        loop {
            let Ok(a) = futures::future::poll_fn(|cx| l.poll_accept(cx)).await else {
                break;
            };
            tokio::spawn(async move {
                let mut conn = a.conn;
                while let Ok(Some(p)) = futures::future::poll_fn(|cx| conn.poll_piece(cx)).await {
                    let waker = std::task::Waker::noop();
                    if conn
                        .emit(
                            p.stream,
                            &p.bytes,
                            false,
                            false,
                            &mut std::task::Context::from_waker(waker),
                        )
                        .is_err()
                    {
                        break;
                    }
                }
                conn.close();
            });
        }
    });
}
