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
        "busbar-core-connector-test-{tag}-{}-{n}.pem",
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
        cert: SecretRef::file("/nonexistent/busbar-core-connector/does-not-exist-cert.pem"),
        key: SecretRef::file("/nonexistent/busbar-core-connector/does-not-exist-key.pem"),
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
        cert: SecretRef::file("/nonexistent/busbar-core-connector/does-not-exist-cert.pem"),
        key: SecretRef::file("/nonexistent/busbar-core-connector/does-not-exist-key.pem"),
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

// ── HANDSHAKES AGAINST THE CONFIG THIS CRATE BUILDS ────────────────────────────────────────────
//
// TLS is core-only connection security: this crate is the one TLS path and it never crosses the
// plugin ABI, so what a TLS listener does to a client is proven here, against the config built from
// the operator's `tls:` block and the `Tls` wrap handed to a listener. Each handshake runs for real —
// a rustls client against a rustls server — over in-memory buffers (or a duplex pipe, through the
// wrap): the whole of the handshake, none of the socket.

/// Generate a CA and a leaf it signs for `sans`. Returns (ca_pem, leaf_cert_pem, leaf_key_pem).
fn gen_ca_and_leaf(sans: Vec<String>) -> (String, String, String) {
    use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};
    let ca_kp = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
    let issuer = Issuer::from_params(&ca_params, ca_kp);
    let leaf_kp = KeyPair::generate().unwrap();
    let leaf_params = CertificateParams::new(sans).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();
    (ca_cert.pem(), leaf_cert.pem(), leaf_kp.serialize_pem())
}

/// A `TlsCfg` over PEM files holding `cert_pem`, `key_pem` and (for mutual TLS) `client_ca_pem`.
fn tls_cfg_from(cert_pem: &str, key_pem: &str, client_ca_pem: Option<&str>) -> TlsCfg {
    let file =
        |tag: &str, pem: &str| SecretRef::file(temp_pem(tag, pem).to_string_lossy().into_owned());
    TlsCfg {
        cert: file("hs-cert", cert_pem),
        key: file("hs-key", key_pem),
        client_ca: client_ca_pem.map(|ca| file("hs-ca", ca)),
    }
}

/// A root store trusting exactly the certificates in `pem`.
fn roots_of(pem: &str) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    roots
}

/// The leaf DER of a PEM chain.
fn leaf_der(pem: &str) -> Vec<u8> {
    rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .expect("a certificate")
        .unwrap()
        .as_ref()
        .to_vec()
}

/// Pump one handshake round trip between `client` and `server` over in-memory buffers, surfacing
/// the first error either side's `process_new_packets` reports.
fn pump(
    client: &mut rustls::ClientConnection,
    server: &mut rustls::ServerConnection,
) -> Result<(), rustls::Error> {
    let mut to_server = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut to_server).unwrap();
    }
    let mut from_client = to_server.as_slice();
    while !from_client.is_empty() {
        server.read_tls(&mut from_client).unwrap();
        server.process_new_packets()?;
    }
    let mut to_client = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut to_client).unwrap();
    }
    let mut from_server = to_client.as_slice();
    while !from_server.is_empty() {
        client.read_tls(&mut from_server).unwrap();
        client.process_new_packets()?;
    }
    Ok(())
}

/// Drive a full handshake between `client_cfg` and `server_cfg`, offering `name` (an IP address
/// offers no SNI, as a dial to a bare socket address does), and hand back both ends once it
/// completes — or the error that ended it.
fn handshake(
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<rustls::ClientConfig>,
    name: rustls::pki_types::ServerName<'static>,
) -> Result<(rustls::ClientConnection, rustls::ServerConnection), rustls::Error> {
    let mut client = rustls::ClientConnection::new(client_cfg, name).unwrap();
    let mut server = rustls::ServerConnection::new(server_cfg).unwrap();
    for _ in 0..16 {
        pump(&mut client, &mut server)?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok((client, server));
        }
    }
    panic!("the handshake neither completed nor failed");
}

/// A client trusting exactly `ca_pem`, presenting no certificate.
fn anonymous_client(ca_pem: &str) -> Arc<rustls::ClientConfig> {
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots_of(ca_pem))
            .with_no_client_auth(),
    )
}

/// The listener has a key because this crate built one from the operator's config, and a real
/// client completes a handshake against it and reads what the server wrote.
///
/// The config is [`build_server_config`]'s, read off the `tls:` block, with nothing in between: the
/// key a listener serves under is the one the operator named, and no other path supplies one.
#[test]
fn the_config_built_from_the_tls_block_serves_a_real_handshake_and_carries_bytes() {
    install_crypto_provider();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let cert_pem = cert.pem();
    let tls = tls_cfg_from(&cert_pem, &signing_key.serialize_pem(), None);
    let server_cfg = Arc::new(
        build_server_config(&tls, &SecretResolver::builtins_only()).expect("a valid pair builds"),
    );

    let (mut client, mut server) = handshake(
        server_cfg,
        anonymous_client(&cert_pem),
        rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
    )
    .expect("a client trusting the configured certificate completes the handshake");

    let payload = b"served under the key the tls: block names";
    std::io::Write::write_all(&mut server.writer(), payload).unwrap();
    pump(&mut client, &mut server).unwrap();
    let mut got = vec![0u8; payload.len()];
    std::io::Read::read_exact(&mut client.reader(), &mut got).unwrap();
    assert_eq!(got.as_slice(), payload);
}

/// The client-cert verifier is the DIFFERENCE a `client_ca` makes, and the only way to see it is to
/// make a client try: the same certificate and key, offered to a client that presents nothing,
/// complete the handshake without a client CA configured and are refused with one.
///
/// Replacing the verifier arm in [`build_server_config`] with `with_no_client_auth()` leaves every
/// assertion about the built config true and turns a listener an operator configured for mTLS into
/// one that takes anonymous clients. This is what goes RED.
#[test]
fn only_the_mutual_tls_config_refuses_a_client_that_offers_no_certificate() {
    install_crypto_provider();
    let (server_ca_pem, server_cert_pem, server_key_pem) =
        gen_ca_and_leaf(vec!["localhost".into()]);
    let (client_ca_pem, _client_leaf_pem, _client_key_pem) =
        gen_ca_and_leaf(vec!["busbar-client".into()]);
    let resolver = SecretResolver::builtins_only();
    let localhost = || rustls::pki_types::ServerName::try_from("localhost").unwrap();

    let server_only = build_server_config(
        &tls_cfg_from(&server_cert_pem, &server_key_pem, None),
        &resolver,
    )
    .unwrap();
    handshake(
        Arc::new(server_only),
        anonymous_client(&server_ca_pem),
        localhost(),
    )
    .expect("server-only TLS asks a client for nothing and completes");

    let mutual = build_server_config(
        &tls_cfg_from(&server_cert_pem, &server_key_pem, Some(&client_ca_pem)),
        &resolver,
    )
    .unwrap();
    let err = handshake(
        Arc::new(mutual),
        anonymous_client(&server_ca_pem),
        localhost(),
    )
    .map(|_| ())
    .expect_err("mutual TLS means the client MUST present a certificate");
    assert!(
        matches!(err, rustls::Error::NoCertificatesPresented),
        "the handshake failed for the wrong reason: {err:?}"
    );
}

/// The mutual-TLS listener THROUGH THE WRAP: `prepare` hands back the `Tls` wrap for a `tls:` block
/// with a `client_ca`, and a client presenting a certificate that chains to that CA completes the
/// handshake over it and exchanges bytes. The refusal half is the cell above; this is the half that
/// proves the wrap is the mutual config and not merely a config that refuses everyone.
#[tokio::test]
async fn the_tls_wrap_serves_a_client_whose_certificate_chains_to_the_client_ca() {
    install_crypto_provider();
    let (server_ca_pem, server_cert_pem, server_key_pem) =
        gen_ca_and_leaf(vec!["localhost".into()]);
    let (client_ca_pem, client_leaf_pem, client_key_pem) =
        gen_ca_and_leaf(vec!["busbar-client".into()]);
    let tls = tls_cfg_from(&server_cert_pem, &server_key_pem, Some(&client_ca_pem));
    let security = prepare(
        "mtls-binding",
        Some(&tls),
        &SecretResolver::builtins_only(),
        true,
    )
    .expect("valid mutual TLS config with a capable transport");

    let (server_io, client_io) = tokio::io::duplex(8192);
    let server_task = tokio::spawn(async move {
        let raw: Box<dyn busbar_contract::transport::wire::RawIo> =
            Box::new(TokioAsyncReadCompatExt::compat(server_io));
        let mut wrapped = security
            .wrap(raw)
            .await
            .expect("a client whose certificate chains to the client CA is served");
        let mut buf = [0u8; 4];
        futures::io::AsyncReadExt::read_exact(&mut wrapped, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"ping");
        futures::io::AsyncWriteExt::write_all(&mut wrapped, b"pong")
            .await
            .unwrap();
        futures::io::AsyncWriteExt::flush(&mut wrapped)
            .await
            .unwrap();
    });

    let chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls::pki_types::CertificateDer::pem_slice_iter(client_leaf_pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(client_key_pem.as_bytes()).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots_of(&server_ca_pem))
        .with_client_auth_cert(chain, key)
        .unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let mut client = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            client_io,
        )
        .await
        .expect("the mutual handshake completes");
    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut got = [0u8; 4];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"pong");
    server_task.await.unwrap();
}

/// A client CA that resolves to bytes with no certificate in it — an operator who pointed the
/// setting at the wrong file — is refused, not quietly turned into an empty root store that would
/// bring the listener up and then refuse every client.
#[test]
fn a_client_ca_with_no_certificates_in_it_is_refused() {
    let (cert_pem, key_pem) = gen_self_signed();
    // A PEM, and a real one — just not one with a certificate anywhere in it.
    let tls = tls_cfg_from(&cert_pem, &key_pem, Some(&key_pem));
    let err = build_server_config(&tls, &SecretResolver::builtins_only()).unwrap_err();
    assert!(err.contains("client_ca"), "{err}");
    assert!(err.contains("no CA certificates"), "{err}");
}

/// A certificate and a key that are not a pair are refused, naming both sources.
#[test]
fn mismatched_cert_and_key_pair_is_refused() {
    let (cert_pem, _key_pem) = gen_self_signed();
    let (_other_cert_pem, other_key_pem) = gen_self_signed();
    let tls = tls_cfg_from(&cert_pem, &other_key_pem, None);
    let err = build_server_config(&tls, &SecretResolver::builtins_only()).unwrap_err();
    assert!(err.contains("not a valid pair"), "{err}");
}

/// A cert source with no certificate in it is refused with a clear message rather than an empty,
/// silently-accepted chain.
#[test]
fn empty_cert_chain_is_refused() {
    let (_cert_pem, key_pem) = gen_self_signed();
    let tls = tls_cfg_from("not a pem cert", &key_pem, None);
    let err = build_server_config(&tls, &SecretResolver::builtins_only()).unwrap_err();
    assert!(err.contains("contains no certificates"), "{err}");
}

/// Which certificate a client that offers `name` is served, as the client saw it.
fn served_leaf(server_cfg: &Arc<ServerConfig>, name: &str) -> Vec<u8> {
    let (client, _server) = handshake(
        Arc::clone(server_cfg),
        accept_any_server_cert(),
        rustls::pki_types::ServerName::try_from(name.to_string()).unwrap(),
    )
    .expect("the handshake completes");
    client
        .peer_certificates()
        .expect("the client sees the server's certificate")[0]
        .as_ref()
        .to_vec()
}

/// A permissive verifier that only lets the chain parse — no root, no name check — for the two
/// cells below, where the client deliberately offers a name the certificate does not carry. What
/// they check is which certificate the listener SERVED, read off the client's view of the peer.
#[derive(Debug)]
struct AcceptAnyServerCert;
impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn accept_any_server_cert() -> Arc<rustls::ClientConfig> {
    Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth(),
    )
}

/// A client offering no SNI (a dial to a bare address offers none) is served the configured
/// certificate, and so is a client naming a host nobody configured: 1.5.5 built one
/// `ServerConfig::with_single_cert` per listener and served it whatever a client offered, and the
/// `tls:` block names exactly one certificate. A listener never refuses a handshake over the name
/// offered.
#[test]
fn any_offered_name_or_none_is_served_the_configured_certificate() {
    install_crypto_provider();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["configured.example".to_string()]).unwrap();
    let cert_pem = cert.pem();
    let tls = tls_cfg_from(&cert_pem, &signing_key.serialize_pem(), None);
    let server_cfg = Arc::new(build_server_config(&tls, &SecretResolver::builtins_only()).unwrap());
    let configured = leaf_der(&cert_pem);

    assert_eq!(
        served_leaf(&server_cfg, "127.0.0.1"),
        configured,
        "no SNI offered: the configured certificate is served"
    );
    assert_eq!(
        served_leaf(&server_cfg, "nobody-configured-this.example"),
        configured,
        "an unknown name: the configured certificate is served, not a refusal"
    );
}
