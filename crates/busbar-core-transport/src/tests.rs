// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Unit tests for the core-side connection-security seam.

use super::*;
use busbar_kernel::config::secret::SecretResolver;
use busbar_kernel::config::SecretRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Generate a self-signed server cert for `localhost`. Returns (cert_pem, key_pem).
fn gen_self_signed() -> (String, String) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (cert.pem(), signing_key.serialize_pem())
}

/// Write `contents` to a uniquely-named temp file and return its path.
///
/// `cargo test` runs these `#[tokio::test]`s concurrently, and every caller of [`valid_tls_cfg`]
/// uses the same `tag`s ("cert"/"key") — a wall-clock timestamp alone is not always distinct
/// between two threads racing to call this within the same clock tick, and two tests writing the
/// SAME path concurrently (one's `create`-time truncate landing inside another's write) is exactly
/// how a resolved secret ends up looking like an "EMPTY file" that neither test ever wrote. A
/// process-wide counter makes every call's filename distinct regardless of clock resolution.
fn temp_pem(tag: &str, contents: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    let uniq = format!(
        "busbar-core-transport-test-{tag}-{}-{n}.pem",
        std::process::id(),
    );
    p.push(uniq);
    std::fs::write(&p, contents).unwrap();
    p
}

fn valid_tls_cfg() -> (TlsCfg, String) {
    let (cert_pem, key_pem) = gen_self_signed();
    let cert_file = temp_pem("cert", &cert_pem);
    let key_file = temp_pem("key", &key_pem);
    (
        TlsCfg {
            cert: SecretRef::file(cert_file.to_string_lossy().into_owned()),
            key: SecretRef::file(key_file.to_string_lossy().into_owned()),
            client_ca: None,
        },
        cert_pem,
    )
}

/// `prepare` with `tls_cfg: None` hands back the identity wrap, and running a stream through it
/// leaves the bytes byte-for-byte unchanged — the oracle-clean-by-construction property a plaintext
/// binding depends on.
#[tokio::test]
async fn prepare_plaintext_is_identity_and_passes_bytes_unchanged() {
    let resolver = SecretResolver::builtins_only();
    let security = prepare(
        "plaintext-binding",
        None,
        &resolver,
        /* transport_capable */ false,
    )
    .expect("a plaintext binding never needs transport capability");

    let (mut a, b) = tokio::io::duplex(64);
    let raw: Box<dyn busbar_contract::transport::wire::RawIo> =
        Box::new(TokioAsyncReadCompatExt::compat(b));
    let mut wrapped = security.wrap(raw).await.expect("identity wrap never fails");

    a.write_all(b"hello, plaintext").await.unwrap();
    a.shutdown().await.unwrap();
    let mut got = Vec::new();
    futures::io::AsyncReadExt::read_to_end(&mut wrapped, &mut got)
        .await
        .unwrap();
    assert_eq!(
        got, b"hello, plaintext",
        "identity wrap must not alter a single byte"
    );
}

/// [`build_server_config`] builds a working `rustls::ServerConfig` from the operator's `tls:`
/// config — every field a listener needs (the cert/key pair, http/1.1-only ALPN, no client-cert
/// verifier when `client_ca` is absent) — and `prepare` reaches the same result for a
/// TLS-configured, capable binding.
#[tokio::test]
async fn build_server_config_and_prepare_build_from_operator_config() {
    let (tls, _cert_pem) = valid_tls_cfg();
    let resolver = SecretResolver::builtins_only();

    let config = build_server_config(&tls, &resolver).expect("valid self-signed cert/key");
    assert_eq!(
        config.alpn_protocols,
        vec![b"http/1.1".to_vec()],
        "busbar's axum server speaks http/1.1 only; TLS must not advertise h2"
    );

    let security = prepare("tls-binding", Some(&tls), &resolver, true)
        .expect("a capable transport + valid material must build the TLS wrap");
    // `Tls::wrap` runs a real handshake; that path is exercised end-to-end below. Here we only
    // need `prepare` to have chosen the TLS branch rather than plaintext, which the successful
    // build above already proves it can only have done via `build_server_config`.
    drop(security);
}

/// A syntactically invalid PEM cert errors with the cert named, not a panic — moved here verbatim
/// in spirit from `busbar-kernel`'s former `malformed_cert_errors_clearly` (DECISIONS #40: the
/// parsing this asserts now lives in `build_server_config`, in this crate).
#[test]
fn malformed_cert_errors_clearly() {
    let cert_file = temp_pem("bad-cert", "-----BEGIN CERTIFICATE-----\nnot base64\n");
    let (_c, key_pem) = gen_self_signed();
    let key_file = temp_pem("ok-key", &key_pem);
    let tls = TlsCfg {
        cert: SecretRef::file(cert_file.to_string_lossy().into_owned()),
        key: SecretRef::file(key_file.to_string_lossy().into_owned()),
        client_ca: None,
    };
    let err = build_server_config(&tls, &SecretResolver::builtins_only())
        .expect_err("malformed cert must error");
    assert!(err.contains("cert"), "error must reference the cert: {err}");
}

/// A missing cert FILE errors with the offending path named, not a panic — moved here verbatim in
/// spirit from `busbar-kernel`'s former `bad_cert_path_errors_clearly` (DECISIONS #40).
#[test]
fn bad_cert_path_errors_clearly() {
    let tls = TlsCfg {
        cert: SecretRef::file("/nonexistent/busbar-core-transport/does-not-exist-cert.pem"),
        key: SecretRef::file("/nonexistent/busbar-core-transport/does-not-exist-key.pem"),
        client_ca: None,
    };
    let err = build_server_config(&tls, &SecretResolver::builtins_only())
        .expect_err("missing cert file must error");
    assert!(
        err.contains("cert") && err.contains("does-not-exist-cert.pem"),
        "error must name the offending file: {err}"
    );
}

/// FAIL CLOSED: a `TLS`-configured binding handed to a transport that has not declared
/// `WRAPPABLE_BYTE_STREAM` must never be silently served in plaintext.
#[tokio::test]
async fn prepare_fails_closed_when_transport_is_incapable() {
    let (tls, _cert_pem) = valid_tls_cfg();
    let resolver = SecretResolver::builtins_only();

    // `Arc<dyn ConnectionSecurity>` (the `Ok` type) is not `Debug`, so `expect_err` (which formats
    // it on the failure path) does not apply here — match instead.
    let err = match prepare("incapable-binding", Some(&tls), &resolver, false) {
        Ok(_) => panic!("an incapable transport must never receive a TLS wrap"),
        Err(e) => e,
    };
    assert_eq!(
        err,
        FailClosed::IncapableTransport {
            label: "incapable-binding".to_string()
        }
    );
}

/// FAIL CLOSED: a `TLS`-configured binding whose cert cannot be resolved must never fall back to
/// plaintext — boot must refuse.
#[tokio::test]
async fn prepare_fails_closed_on_missing_cert() {
    let tls = TlsCfg {
        cert: SecretRef::file("/nonexistent/busbar-core-transport/does-not-exist-cert.pem"),
        key: SecretRef::file("/nonexistent/busbar-core-transport/does-not-exist-key.pem"),
        client_ca: None,
    };
    let resolver = SecretResolver::builtins_only();

    let err = match prepare("missing-cert-binding", Some(&tls), &resolver, true) {
        Ok(_) => panic!("a binding whose TLS material cannot be resolved must not come up"),
        Err(e) => e,
    };
    assert!(
        matches!(err, FailClosed::MaterialUnavailable { .. }),
        "expected MaterialUnavailable, got {err:?}"
    );
}

/// The TLS wrap really does run a rustls handshake and carry bytes over it — not just build a
/// `ServerConfig` that nothing then uses. Drives a real `tokio_rustls` client, trusting the same
/// self-signed cert, over an in-memory duplex pipe standing in for the accepted TCP stream.
#[tokio::test]
async fn tls_wrap_completes_a_real_handshake_and_carries_bytes() {
    let (tls, cert_pem) = valid_tls_cfg();
    let resolver = SecretResolver::builtins_only();
    let security = prepare("tls-binding", Some(&tls), &resolver, true)
        .expect("valid TLS config with a capable transport");

    let (server_io, client_io) = tokio::io::duplex(4096);

    let server_task = tokio::spawn(async move {
        let raw: Box<dyn busbar_contract::transport::wire::RawIo> =
            Box::new(TokioAsyncReadCompatExt::compat(server_io));
        let mut wrapped = security
            .wrap(raw)
            .await
            .expect("server handshake must succeed");
        let mut buf = [0u8; 5];
        futures::io::AsyncReadExt::read_exact(&mut wrapped, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"hello");
        futures::io::AsyncWriteExt::write_all(&mut wrapped, b"world")
            .await
            .unwrap();
        futures::io::AsyncWriteExt::flush(&mut wrapped)
            .await
            .unwrap();
    });

    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut client_stream = connector.connect(server_name, client_io).await.unwrap();

    client_stream.write_all(b"hello").await.unwrap();
    client_stream.flush().await.unwrap();
    let mut got = [0u8; 5];
    client_stream.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"world");

    server_task.await.unwrap();
}
