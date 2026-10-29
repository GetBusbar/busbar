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
/// config — every field a listener needs (the cert/key pair, the ALPN offer, no client-cert
/// verifier when `client_ca` is absent) — and `prepare` reaches the same result for a
/// TLS-configured, capable binding.
///
/// The ALPN offer is `h2, http/1.1`, in that order: OWNER RULING Q137 (2026-10-04), a signed
/// customer-visible change from 1.5.5, which offered `http/1.1` alone. The listener serves HTTP/2 on
/// an `h2` connection; a client offering only `http/1.1` is served as in 1.5.5.
#[tokio::test]
async fn build_server_config_and_prepare_build_from_operator_config() {
    let (tls, _cert_pem) = valid_tls_cfg();
    let resolver = SecretResolver::builtins_only();

    let config = build_server_config(&tls, &resolver).expect("valid self-signed cert/key");
    assert_eq!(
        config.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        "a TLS listener offers h2 then http/1.1 (owner ruling Q137, 2026-10-04)"
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

// ── ALPN: h2 OVER TLS (OWNER RULING Q137, 2026-10-04) ─────────────────────────────────────
//
// A TLS listener offers ALPN `h2, http/1.1`: a client that offers `h2` speaks HTTP/2, one that offers
// only `http/1.1` (or no ALPN at all) is served HTTP/1.1 as in 1.5.5. A connection whose ALPN is `h2`
// is KNOWN to be HTTP/2, so RFC 9113 §3.4 governs its first bytes: one that does not open with the
// connection preface is a connection error, closed with no bytes (no h2 frame layer exists yet).

/// A client offering exactly `protocols` over ALPN, trusting exactly `ca_pem`.
fn offering(ca_pem: &str, protocols: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots_of(ca_pem))
        .with_no_client_auth();
    config.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// The listener's config, built from the `tls:` block, negotiates `h2` with a client that offers it
/// and `http/1.1` with a client that offers only that; a client offering no ALPN negotiates none.
#[test]
fn a_tls_listener_negotiates_h2_when_offered_and_http1_when_only_that_is_offered() {
    install_crypto_provider();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = cert.pem();
    let tls = tls_cfg_from(&cert_pem, &signing_key.serialize_pem(), None);
    let server_cfg = Arc::new(build_server_config(&tls, &SecretResolver::builtins_only()).unwrap());
    let negotiated = |protocols: &[&[u8]]| {
        let (client, server) = handshake(
            Arc::clone(&server_cfg),
            offering(&cert_pem, protocols),
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
        )
        .expect("the handshake completes");
        assert_eq!(client.alpn_protocol(), server.alpn_protocol());
        server.alpn_protocol().map(<[u8]>::to_vec)
    };
    assert_eq!(
        negotiated(&[b"h2", b"http/1.1"]),
        Some(b"h2".to_vec()),
        "a client offering h2 speaks HTTP/2 over TLS (owner ruling Q137)"
    );
    assert_eq!(negotiated(&[b"h2"]), Some(b"h2".to_vec()));
    assert_eq!(
        negotiated(&[b"http/1.1"]),
        Some(b"http/1.1".to_vec()),
        "a client offering only http/1.1 is served HTTP/1.1, as in 1.5.5"
    );
    assert_eq!(
        negotiated(&[]),
        None,
        "a client offering no ALPN negotiates none"
    );
}

/// Drive the `Tls` wrap with a real client offering `protocols`, send `sent` once the handshake is
/// done, and hand back what the server read off the wrapped stream (`want` bytes) — or the error the
/// wrap ended with.
async fn wrap_and_read(
    protocols: &[&[u8]],
    sent: &'static [u8],
    want: usize,
) -> std::io::Result<Vec<u8>> {
    install_crypto_provider();
    let (ca_pem, cert_pem, key_pem) = gen_ca_and_leaf(vec!["localhost".into()]);
    let security = prepare(
        "alpn-binding",
        Some(&tls_cfg_from(&cert_pem, &key_pem, None)),
        &SecretResolver::builtins_only(),
        true,
    )
    .expect("valid TLS config with a capable transport");
    let (server_io, client_io) = tokio::io::duplex(8192);
    let server_task = tokio::spawn(async move {
        let raw: Box<dyn busbar_contract::transport::wire::RawIo> =
            Box::new(TokioAsyncReadCompatExt::compat(server_io));
        let mut wrapped = security.wrap(raw).await?;
        let mut got = vec![0u8; want];
        futures::io::AsyncReadExt::read_exact(&mut wrapped, &mut got).await?;
        Ok::<_, std::io::Error>(got)
    });
    let connector = tokio_rustls::TlsConnector::from(offering(&ca_pem, protocols));
    let mut client = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            client_io,
        )
        .await
        .expect("the handshake completes");
    client.write_all(sent).await.unwrap();
    client.flush().await.unwrap();
    let served = server_task.await.unwrap();
    drop(client);
    served
}

/// The HTTP/2 connection preface (RFC 9113 §3.4) and the SETTINGS frame header a client sends after it.
const PREFACE_AND_SETTINGS: &[u8] =
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// h2spec http2/3.5/2 sends this instead of the preface.
const INVALID_PREFACE: &[u8] = b"INVALID CONNECTION PREFACE\r\n\r\n";

/// On an ALPN `h2` connection the preface and every byte after it reach the server unchanged.
#[tokio::test]
async fn an_h2_connection_that_opens_with_the_preface_is_served_its_bytes_unchanged() {
    let got = wrap_and_read(
        &[b"h2", b"http/1.1"],
        PREFACE_AND_SETTINGS,
        PREFACE_AND_SETTINGS.len(),
    )
    .await
    .expect("a correct preface is served");
    assert_eq!(got, PREFACE_AND_SETTINGS);
}

/// On an ALPN `h2` connection anything but the preface is a connection error (RFC 9113 §3.4): the
/// wrap fails and the connection closes with no bytes, never read as an HTTP/1 request line.
#[tokio::test]
async fn an_h2_connection_that_does_not_open_with_the_preface_is_closed() {
    for sent in [INVALID_PREFACE, &b"GET / HTTP/1.1\r\nhost: x\r\n\r\n"[..]] {
        let err = wrap_and_read(&[b"h2"], sent, sent.len())
            .await
            .expect_err("a known-h2 connection without the preface is not served");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    }
}

/// On an `http/1.1` connection (and one with no ALPN) the first bytes are not screened here: an
/// unparseable request line reaches the HTTP/1 server, which keeps 1.5.5's `400` (Q137 (2)).
#[tokio::test]
async fn an_http1_connection_is_handed_its_bytes_unscreened() {
    for protocols in [&[&b"http/1.1"[..]][..], &[]] {
        let got = wrap_and_read(protocols, INVALID_PREFACE, INVALID_PREFACE.len())
            .await
            .expect("an HTTP/1 connection's bytes are the HTTP/1 server's to judge");
        assert_eq!(got, INVALID_PREFACE);
    }
}

// ── KEY ENCODINGS AND REFUSAL HYGIENE (security.md: "PKCS#8, PKCS#1, SEC1 keys accepted"; "a bad
// cert/key/CA is fatal and names the file, never the bytes") ─────────────────────────────────

/// A 2048-bit RSA key in PKCS#1 form (`BEGIN RSA PRIVATE KEY`) and its self-signed `localhost`
/// certificate (valid 100 years), made with `openssl genrsa -traditional` / `req -x509`. rcgen
/// writes only PKCS#8, so these two encodings need fixtures.
const PKCS1_KEY: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAs9oZ0in3QFiWrn6yJWWSIzADITGmavfgWaH3H6iZ6Ot9ac5Z
mDqjP3gjFxAoyxAr1FfqsLP+rDkvnP9pu3N8gc8+dZbF1eUqG+8sybOMynzt5ZOV
vcaYEfZByugaq3ICJPqiJZ6CKfB8B3raNru+llshBUncgbuegQjGWa/3SO6Ekqf/
IAwPwaVH9489maeqzYjSYqkVdP3RYOBXfmAcPhWX805LCsdscuu7/ccCD9dRptET
WC5nl26afZ4g4qsdAg0aQ4SLXiLECMy+k1hor855pkQEia+fzCj/Tebvpmok3qT1
xImL33hgdIYGD5Lucnz4+c2THOpuMO2Q6IdJdQIDAQABAoIBAACttRSI6/ewYMiN
PMHDsjOOisU1PpwzxAb/oqHxaiCxnFRxqnr1v0BCXnT6MoYsJl7o+oy+ByqRoVS0
n58WvxMpB2pXw5GmGPJ/dRHgeH77YUl7xIA1Yo7bCG5cgDXdOoIlTHlXWGfbtSA1
EX7BCSeahWnPre/TyjfNG1NRgt2WITf3lBzHIbqv2TGjJeJ+SpNi0JfxBLDCPJo8
rZCadDnlPBE/skhd9xmF86pS0akY0sv9tKASbwecKdC5HrFU+f6AkUbnrB7qAOlj
BS8lVHFH7LerHH8jjNsvZi4x0bT/MGM4WiElPFgElaFadJ+B+4Wo0nsRvBoxUePY
qm47AfsCgYEA7kH8CDiP/0jw1r1YiHPfN3PTw2QGun8VbRN8SatzPbdwdVZMlvyQ
8xIGncD0bI4EmyCPVB7yfpL7xdzRXA2j5WrDhDcny+9yy4T5gKi9Ot3m9cq1SNXH
8lM2hRDTWcfl4obajqGAwV24WOKy5fX4TILMNYnP/HAA6/ffMFHMc/cCgYEAwT6z
QVD2uy30BURWu9tKUQQG748LfulGyM5lBx3X+lKepdammzg7s3bt5V5gzimNTA8c
GkhvxtYw4VuzsZYyubEHdS5Ai/+iXLKEo1nIZGwbMMKWlBmioKXImzHMO18uYaOQ
F57uNlhQ342YKnHMVIeYJWwozUODAEk0Db36+vMCgYBkvwITd9dr2yv7oZUOHfEF
QbUJqgIuWg51UQf9HsJcFnU3KIa6UZH5NmYVzsGMJYFNFzeEGpHvc7eCsxzUD/B9
0edawPfTBC1GYbQe8zsQ6UQAKvb9FWi2zvj+y16TWDOc1ekU5rXLDhYlf7amBpw3
vhcbjGqmE7ZQEUAO7ofFgQKBgQC7RiBB9EyoKWiKkifb9jCXQufV0TK60yeeAyc1
Nl7QYLEO1m6vjleNHHyABG6cXPhp9VquvfRVJc5JF62VNJIEEuO/VAuJoTufygFw
rNnfOEVBg9KZxB4uwXsfq6rY/uzcAr7ppUQFtqDphTcqKw5x/NYdriv8gKi75jVj
+/D2sQKBgQCIfxSmQXNqJnY0Zu/zCXPpqSX0T4nwGr9RO7JtHnttLkOzi7RNskMj
XzNgxXGrqXQeVdQYkRInAd66oZ1GK9Loi1aS2ub+Z8aam8tPoPI2NAkPyELegsKb
Uf7KmswvCv4AmC0Gsu4UkU9y5awTSarcGLhLFEjOwR1BEHa4F8ns/g==
-----END RSA PRIVATE KEY-----
"#;

const PKCS1_CERT: &str = r#"
-----BEGIN CERTIFICATE-----
MIIDADCCAeigAwIBAgIUdbNCjZ6s73xWu8PxqXRgWkB7akEwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTAyOTA0NTYxNloYDzIxMjYx
MDA1MDQ1NjE2WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCz2hnSKfdAWJaufrIlZZIjMAMhMaZq9+BZofcfqJno
631pzlmYOqM/eCMXECjLECvUV+qws/6sOS+c/2m7c3yBzz51lsXV5Sob7yzJs4zK
fO3lk5W9xpgR9kHK6BqrcgIk+qIlnoIp8HwHeto2u76WWyEFSdyBu56BCMZZr/dI
7oSSp/8gDA/BpUf3jz2Zp6rNiNJiqRV0/dFg4Fd+YBw+FZfzTksKx2xy67v9xwIP
11Gm0RNYLmeXbpp9niDiqx0CDRpDhIteIsQIzL6TWGivznmmRASJr5/MKP9N5u+m
aiTepPXEiYvfeGB0hgYPku5yfPj5zZMc6m4w7ZDoh0l1AgMBAAGjSDBGMB0GA1Ud
DgQWBBRwt7BE9RfnoqgHERHu60zOVZKA4zAPBgNVHRMBAf8EBTADAQH/MBQGA1Ud
EQQNMAuCCWxvY2FsaG9zdDANBgkqhkiG9w0BAQsFAAOCAQEAIvuAoxcIUawWG+om
rwIOR3MXtc3wuh3ewVfXa2fRKnc7XZhVqDQC41GdOPW09N9B1H6Lpr09sZzNFor+
GbS9vYXghECueG7TqKRsvwTiD0mMMSwBlhEeovEVJqRmDnhkdIwW4iCLGfW+RRJm
Zw9Cyky2T3KzThMxkn0uB2IIJYIU5fB2Fo0HsO4Mw49VFqMfdZjO86B5UsJ8cxh2
uQ5ft4Z1e8ynzVSyGl9TqYoKHT5Uhhq+j6lrh2PZQrH5sgP51kZlONxWbg5KW5La
aQkjH8c7ybL8SH2LZI+KowOXUAXnmQs3OLX5So7zDHex4jrhMmPXlljc9AomCERc
6bzYUA==
-----END CERTIFICATE-----
"#;

/// A P-256 key in SEC1 form (`BEGIN EC PRIVATE KEY`, `openssl ecparam -genkey -noout`) and its self-signed
/// `localhost` certificate (valid 100 years).
const SEC1_KEY: &str = r#"
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGSc6UoTXkJyPydWn7C2uys0D6/ygo6kL2PMn3GfkwYxoAoGCCqGSM49
AwEHoUQDQgAENek//8jDylYZw2mFD0SmSZWIuzfP/GuX4eV5xiZ7mML+yc5l9i2U
lM9zpJwtJ7LAsfn18wWrEtoT4nlpikBYhQ==
-----END EC PRIVATE KEY-----
"#;

const SEC1_CERT: &str = r#"
-----BEGIN CERTIFICATE-----
MIIBdDCCARqgAwIBAgIUHcSILYitnuK4r3xpF84yvDppL6swCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTAyOTA0NTYxNloYDzIxMjYxMDA1
MDQ1NjE2WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQ16T//yMPKVhnDaYUPRKZJlYi7N8/8a5fh5XnGJnuYwv7JzmX2LZSU
z3OknC0nssCx+fXzBasS2hPieWmKQFiFo0gwRjAdBgNVHQ4EFgQUzgCZYkr3/wU5
Ol5myjruBu14DlAwDwYDVR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhv
c3QwCgYIKoZIzj0EAwIDSAAwRQIhALd6awZGREb16KeTvlnLwZ9GxMfqeYfGyVc/
T2oQ/ubQAiBqi7uw7oUthq1/KJLtHYXa4UfAUmO9ZL2ZlSaJfVniUA==
-----END CERTIFICATE-----
"#;

/// PKCS#1 (RSA) and SEC1 (EC) keys build a server config, and the config serves the certificate
/// that key belongs to: the key is matched to the certificate, so a wrong parse would not pair.
/// (PKCS#8 is every other test in this file.)
#[test]
fn pkcs1_and_sec1_keys_build_a_server_config() {
    install_crypto_provider();
    assert!(
        PKCS1_KEY.contains("BEGIN RSA PRIVATE KEY"),
        "fixture is PKCS#1"
    );
    assert!(SEC1_KEY.contains("BEGIN EC PRIVATE KEY"), "fixture is SEC1");
    for (what, cert, key) in [
        ("PKCS#1", PKCS1_CERT.trim(), PKCS1_KEY.trim()),
        ("SEC1", SEC1_CERT.trim(), SEC1_KEY.trim()),
    ] {
        let tls = tls_cfg_from(cert, key, None);
        let server_cfg = Arc::new(
            build_server_config(&tls, &SecretResolver::builtins_only())
                .unwrap_or_else(|e| panic!("a {what} key must build a server config: {e}")),
        );
        assert_eq!(
            served_leaf(&server_cfg, "localhost"),
            leaf_der(cert),
            "{what}: the config serves the certificate its key belongs to"
        );
    }
}

/// A refused key or client CA names the FILE it came from (the operator's one handle on it) and
/// echoes none of its bytes: not the raw text, not its base64. Each file is a PEM section whose body
/// is a marker, so the marker (or its base64) appearing in the error is the leak.
#[test]
fn a_bad_key_or_client_ca_names_its_file_and_never_its_bytes() {
    use base64::Engine;
    const MARKER: &str = "SECRETMARKERBYTES-0123456789";
    let b64 = base64::engine::general_purpose::STANDARD.encode(MARKER);
    let section = |label: &str, body: &str| {
        format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
    };
    let (cert_pem, key_pem) = gen_self_signed();
    let path_of = |tag: &str, pem: &str| temp_pem(tag, pem).to_string_lossy().into_owned();

    // (field, the config, the file the error must name)
    let mut cases: Vec<(&str, TlsCfg, String)> = Vec::new();
    for (label, body) in [
        ("PRIVATE KEY", b64.as_str()),
        ("PRIVATE KEY", MARKER),
        ("RSA PRIVATE KEY", b64.as_str()),
        ("EC PRIVATE KEY", b64.as_str()),
        ("CERTIFICATE", b64.as_str()),
    ] {
        let key_path = path_of("bad-key", &section(label, body));
        cases.push((
            "key",
            TlsCfg {
                cert: SecretRef::file(path_of("ok-cert", &cert_pem)),
                key: SecretRef::file(key_path.clone()),
                client_ca: None,
            },
            key_path,
        ));
    }
    for (label, body) in [("CERTIFICATE", b64.as_str()), ("PRIVATE KEY", b64.as_str())] {
        let ca_path = path_of("bad-ca", &section(label, body));
        cases.push((
            "client_ca",
            TlsCfg {
                cert: SecretRef::file(path_of("ok-cert", &cert_pem)),
                key: SecretRef::file(path_of("ok-key", &key_pem)),
                client_ca: Some(SecretRef::file(ca_path.clone())),
            },
            ca_path,
        ));
    }
    for (field, tls, path) in cases {
        let err = build_server_config(&tls, &SecretResolver::builtins_only())
            .expect_err("a bad key or client CA is refused");
        assert!(
            err.contains(field),
            "{field}: the error names the field: {err}"
        );
        assert!(
            err.contains(&path),
            "{field}: the error names the file {path}: {err}"
        );
        assert!(!err.contains(MARKER), "{field}: raw bytes echoed: {err}");
        assert!(!err.contains(&b64), "{field}: encoded bytes echoed: {err}");
    }
}
