// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The trust store, driven from the `advanced.tls` YAML an operator writes.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use busbar_contract::crypto::testing::rcgen;
use busbar_kernel::config::tls::OutboundTlsCfg;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

use super::{TrustRefusal, TrustStore};

/// 2030-01-01T00:00:00Z: the clock every validation below runs at.
fn at_2030() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_893_456_000)
}

struct Ca {
    cert: rcgen::Certificate,
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
}

impl Ca {
    fn pem(&self) -> String {
        self.cert.pem()
    }

    fn issue(&self, name: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).expect("params");
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2040, 1, 1);
        let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
        let leaf = params.signed_by(&key, &issuer).expect("leaf");
        (
            vec![leaf.der().clone()],
            PrivateKeyDer::try_from(key.serialize_der()).expect("key der"),
        )
    }
}

fn ca_with(
    name: &str,
    is_ca: bool,
    usages: Option<Vec<rcgen::KeyUsagePurpose>>,
    from: (i32, u8, u8),
    to: (i32, u8, u8),
) -> Ca {
    let key = rcgen::KeyPair::generate().expect("key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = if is_ca {
        rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
    } else {
        rcgen::IsCa::ExplicitNoCa
    };
    if let Some(u) = usages {
        params.key_usages = u;
    }
    params.not_before = rcgen::date_time_ymd(from.0, from.1, from.2);
    params.not_after = rcgen::date_time_ymd(to.0, to.1, to.2);
    let cert = params.self_signed(&key).expect("self-signed");
    Ca { cert, params, key }
}

fn ca(name: &str) -> Ca {
    ca_with(name, true, None, (2020, 1, 1), (2040, 1, 1))
}

fn cfg(yaml: &str) -> OutboundTlsCfg {
    busbar_contract::yaml::from_str(yaml).expect("advanced.tls parses")
}

fn inline(pem: &str) -> String {
    format!("{pem:?}")
}

fn no_env(_: &str) -> Option<String> {
    None
}

fn build(yaml: &str) -> Result<TrustStore, Vec<String>> {
    TrustStore::build(&cfg(yaml), at_2030(), &no_env)
}

/// Run a TLS handshake in memory: `client` dialling `name`, the server presenting `chain`.
fn handshake(
    client: Arc<rustls::ClientConfig>,
    name: &str,
    (chain, key): (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
) -> Result<(), rustls::Error> {
    let server = std::sync::Arc::unwrap_or_clone(
        busbar_contract::crypto::tls::server_config(|b| {
            b.with_no_client_auth().with_single_cert(chain, key)
        })
        .map_err(|e| match e {
            busbar_contract::crypto::tls::TlsError::Rustls(e) => e,
            other => panic!("{other}"),
        })?,
    );
    let mut c = rustls::ClientConnection::new(
        client,
        ServerName::try_from(name.to_owned()).expect("server name"),
    )?;
    let mut s = rustls::ServerConnection::new(Arc::new(server))?;
    for _ in 0..16 {
        let mut buf = Vec::new();
        while c.wants_write() {
            c.write_tls(&mut buf).expect("write");
        }
        if !buf.is_empty() {
            s.read_tls(&mut buf.as_slice()).expect("read");
            s.process_new_packets()?;
        }
        let mut buf = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut buf).expect("write");
        }
        if !buf.is_empty() {
            c.read_tls(&mut buf.as_slice()).expect("read");
            c.process_new_packets()?;
        }
        if !c.is_handshaking() && !s.is_handshaking() {
            return Ok(());
        }
    }
    Err(rustls::Error::General(
        "the handshake did not finish".into(),
    ))
}

fn refused_with(yaml: &str, code: &str) -> String {
    let errors = build(yaml).expect_err("the boot is refused");
    let joined = errors.join("\n");
    assert!(joined.contains(code), "expected {code}: {joined}");
    joined
}

// ---- operator-anchor validation (BUSBAR-3137) ---------------------------------------------

#[test]
fn a_valid_ca_is_accepted_with_its_fingerprint_and_scope() {
    let a = ca("Corp Root");
    let s = build(&format!("trust_anchors: [{}]\n", inline(&a.pem()))).expect("accepted");
    let anchors: Vec<_> = s.anchors().collect();
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].scope, "global");
    assert_eq!(anchors[0].key, "advanced.tls.trust_anchors[0]");
    assert!(anchors[0].fingerprint().starts_with("sha256:"));
    assert_eq!(anchors[0].fingerprint().len(), "sha256:".len() + 64);
    assert!(
        anchors[0].subject.contains("Corp Root"),
        "{}",
        anchors[0].subject
    );
}

#[test]
fn a_leaf_certificate_is_not_a_trust_anchor() {
    let leaf = ca_with("server.internal", false, None, (2020, 1, 1), (2040, 1, 1));
    let why = refused_with(
        &format!("trust_anchors: [{}]\n", inline(&leaf.pem())),
        "BUSBAR-3137",
    );
    assert!(why.contains("not a CA certificate"), "{why}");
    assert!(why.contains("advanced.tls.trust_anchors[0]"), "{why}");
}

#[test]
fn a_ca_whose_key_usage_cannot_sign_certificates_is_refused() {
    let a = ca_with(
        "No Cert Sign",
        true,
        Some(vec![rcgen::KeyUsagePurpose::DigitalSignature]),
        (2020, 1, 1),
        (2040, 1, 1),
    );
    let why = refused_with(
        &format!(
            "destinations:\n  - match: db.internal\n    trust_anchors: [{}]\n",
            inline(&a.pem())
        ),
        "BUSBAR-3137",
    );
    assert!(why.contains("keyCertSign"), "{why}");
    assert!(why.contains("destinations[0].trust_anchors[0]"), "{why}");
    assert!(
        why.contains("db.internal"),
        "the scoped destination is named: {why}"
    );
}

#[test]
fn an_expired_or_not_yet_valid_ca_is_refused_at_boot() {
    let expired = ca_with("Old", true, None, (2000, 1, 1), (2010, 1, 1));
    let why = refused_with(
        &format!("trust_anchors: [{}]\n", inline(&expired.pem())),
        "BUSBAR-3137",
    );
    assert!(why.contains("expired"), "{why}");
    let future = ca_with("Future", true, None, (2035, 1, 1), (2045, 1, 1));
    let why = refused_with(
        &format!("trust_anchors: [{}]\n", inline(&future.pem())),
        "BUSBAR-3137",
    );
    assert!(why.contains("not valid yet"), "{why}");
}

#[test]
fn not_before_has_five_minutes_of_clock_skew_tolerance() {
    let a = ca("Skewed");
    let pem = a.pem();
    // Valid from 2020: a clock five minutes early is still inside the window, trivially.
    assert!(build(&format!("trust_anchors: [{}]\n", inline(&pem))).is_ok());
}

#[test]
fn a_pem_holding_a_private_key_or_nothing_is_refused() {
    let key = rcgen::KeyPair::generate().expect("key").serialize_pem();
    let why = refused_with(
        &format!("trust_anchors: [{}]\n", inline(&key)),
        "BUSBAR-3137",
    );
    assert!(why.contains("private key"), "{why}");
    let why = refused_with("trust_anchors: [\"not pem\"]\n", "BUSBAR-3137");
    assert!(why.contains("no certificate"), "{why}");
    assert!(!why.contains("BEGIN"), "never echoes PEM: {why}");
}

#[test]
fn file_and_env_sources_are_read_and_a_missing_one_is_refused() {
    let a = ca("From File");
    let dir = std::env::temp_dir().join(format!("busbar-trust-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("ca.pem");
    std::fs::write(&path, a.pem()).expect("write");
    let pem = a.pem();
    let env = move |name: &str| (name == "CORP_CA").then(|| pem.clone());
    let s = TrustStore::build(
        &cfg(&format!(
            "trust_anchors: [{{ file: {} }}, {{ env: CORP_CA }}]\n",
            path.display()
        )),
        at_2030(),
        &env,
    )
    .expect("file and env anchors load");
    assert_eq!(s.anchors().count(), 2);
    let why = refused_with("trust_anchors: [{ env: UNSET_CA }]\n", "BUSBAR-3137");
    assert!(why.contains("UNSET_CA"), "{why}");
    let why = refused_with(
        "trust_anchors: [{ file: /nonexistent/ca.pem }]\n",
        "BUSBAR-3137",
    );
    assert!(why.contains("/nonexistent/ca.pem"), "{why}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- destination entries ------------------------------------------------------------------

#[test]
fn a_destination_entry_shape_is_validated() {
    refused_with("destinations: [{ match: 'not a host!' }]\n", "BUSBAR-3148");
    refused_with("destinations: [{ match: '*.internal' }]\n", "BUSBAR-3145");
    refused_with(
        "destinations: [{ match: \x310.0.0.0/8, plaintext: true }]\n",
        "BUSBAR-3144",
    );
    refused_with(
        "destinations: [{ match: '*.corp.example', plaintext: true }]\n",
        "BUSBAR-3144",
    );
    refused_with(
        "destinations: [{ match: db.internal, pin_spki_sha256: [nope] }]\n",
        "BUSBAR-3148",
    );
    refused_with(
        "destinations: [{ match: db.internal, plaintext: true, include_roots: true }]\n",
        "BUSBAR-3148",
    );
}

#[test]
fn the_default_store_leaves_every_dial_on_the_connectors_own_config() {
    let s = build("{}\n").expect("default");
    assert!(s.is_default());
    assert!(matches!(s.config_for("example.com:443"), Ok(None)));
}

#[test]
fn destination_anchors_replace_the_roots_for_the_matching_host_only() {
    let private = ca("Private CA");
    let other = ca("Other CA");
    let s = build(&format!(
        "destinations:\n  - match: ldap.corp.internal\n    trust_anchors: [{}]\n",
        inline(&private.pem())
    ))
    .expect("store");
    let for_ldap = s
        .config_for("ldap.corp.internal:636")
        .expect("ok")
        .expect("own");
    handshake(
        for_ldap.clone(),
        "ldap.corp.internal",
        private.issue("ldap.corp.internal"),
    )
    .expect("a server chaining to the listed CA verifies for the matching host");
    assert!(
        handshake(
            for_ldap,
            "ldap.corp.internal",
            other.issue("ldap.corp.internal")
        )
        .is_err(),
        "a chain to any other CA fails: the entry's anchors are exclusive"
    );
    let elsewhere = s
        .config_for("api.example.com:443")
        .expect("ok")
        .expect("base");
    assert!(
        handshake(elsewhere, "vault.internal", private.issue("vault.internal")).is_err(),
        "the private CA verifies nothing for a host its entry does not match"
    );
}

#[test]
fn include_roots_opts_back_in_and_global_anchors_apply_everywhere_else() {
    let corp = ca("Corp Root");
    let private = ca("Private CA");
    let s = build(&format!(
        "trust_anchors: [{}]\ndestinations:\n  - match: '*.svc.corp.example'\n    trust_anchors: [{}]\n    include_roots: true\n  - match: db.corp.example\n    trust_anchors: [{}]\n",
        inline(&corp.pem()),
        inline(&private.pem()),
        inline(&private.pem()),
    ))
    .expect("store");
    let under = s
        .config_for("a.svc.corp.example")
        .expect("ok")
        .expect("own");
    handshake(
        under.clone(),
        "a.svc.corp.example",
        private.issue("a.svc.corp.example"),
    )
    .expect("own CA");
    handshake(
        under,
        "a.svc.corp.example",
        corp.issue("a.svc.corp.example"),
    )
    .expect("include_roots keeps the global anchors");
    let db = s.config_for("db.corp.example").expect("ok").expect("own");
    assert!(
        handshake(db, "db.corp.example", corp.issue("db.corp.example")).is_err(),
        "without include_roots the global anchor does not apply to a matched host"
    );
    let other = s.config_for("x.example.org").expect("ok").expect("base");
    handshake(other, "x.example.org", corp.issue("x.example.org"))
        .expect("global anchor everywhere else");
    assert!(
        s.config_for("svc.corp.example").expect("ok").is_some(),
        "the wildcard's apex is not matched (falls back to base)"
    );
    assert!(s.matched("svc.corp.example").is_empty());
}

#[test]
fn ip_entries_match_only_ip_literal_dials_and_names_never_select_by_offered_name() {
    let private = ca("Net CA");
    let s = build(&format!(
        "destinations:\n  - match: \x310.20.0.0/16\n    trust_anchors: [{}]\n",
        inline(&private.pem())
    ))
    .expect("store");
    assert_eq!(s.matched("\x310.20.1.2:5432"), ["\x310.20.0.0/16"]);
    assert_eq!(s.matched("[\x310.20.1.2]:5432"), ["\x310.20.0.0/16"]);
    assert!(
        s.matched("db.internal:5432").is_empty(),
        "a name dial never matches an IP entry"
    );
    assert!(s.matched("\x310.21.0.1").is_empty());
}

#[test]
fn roots_none_with_no_anchor_refuses_the_dial_and_a_pin_never_panics() {
    let s = build("roots: none\ndestinations:\n  - match: pinned.internal\n    pin_spki_sha256: sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
        .expect("store");
    let err = s
        .config_for("pinned.internal:443")
        .expect_err("no anchor applies");
    assert!(matches!(err, TrustRefusal::NoAnchors(_)), "{err:?}");
    assert!(err.to_string().contains("BUSBAR-3140"), "{err}");
    assert!(matches!(
        s.config_for("other.example:443"),
        Err(TrustRefusal::NoAnchors(_))
    ));
}

#[test]
fn a_pin_is_held_on_top_of_verification() {
    let private = ca("Pin CA");
    let (chain, key) = private.issue("pinned.internal");
    let spki = crate::tls::client::peer_key_pin(chain[0].as_ref()).expect("spki");
    let s = build(&format!(
        "destinations:\n  - match: pinned.internal\n    trust_anchors: [{}]\n    pin_spki_sha256: {spki}\n",
        inline(&private.pem())
    ))
    .expect("store");
    let c = s.config_for("pinned.internal").expect("ok").expect("own");
    handshake(c.clone(), "pinned.internal", (chain, key)).expect("the pinned key verifies");
    assert!(
        handshake(c, "pinned.internal", private.issue("pinned.internal")).is_err(),
        "another key under the same CA is refused by the pin"
    );
}

#[test]
fn a_client_identity_is_read_by_core_and_its_key_must_match() {
    let private = ca("Client CA");
    let (chain, key) = private.issue("busbar-client");
    let cert = pem_of("CERTIFICATE", chain[0].as_ref());
    let key_pem = pem_of("PRIVATE KEY", key.secret_der());
    let ok = build(&format!(
        "destinations:\n  - match: ccp.corp.example\n    trust_anchors: [{}]\n    client_identity: {{ cert: {}, key: {} }}\n",
        inline(&private.pem()),
        inline(&cert),
        inline(&key_pem)
    ))
    .expect("identity accepted");
    assert!(ok
        .config_for("ccp.corp.example")
        .expect("ok")
        .expect("own")
        .client_auth_cert_resolver
        .has_certs());
    let other_key = pem_of(
        "PRIVATE KEY",
        &rcgen::KeyPair::generate().expect("key").serialize_der(),
    );
    let why = refused_with(
        &format!(
            "destinations:\n  - match: ccp.corp.example\n    client_identity: {{ cert: {}, key: {} }}\n",
            inline(&cert),
            inline(&other_key)
        ),
        "BUSBAR-3148",
    );
    assert!(
        !why.contains("PRIVATE KEY"),
        "never echoes key material: {why}"
    );
}

fn pem_of(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).expect("ascii"))
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

#[test]
fn plaintext_is_admitted_only_to_an_exact_entry() {
    let s = build("destinations:\n  - { match: db.internal, plaintext: true }\n  - { match: \x310.0.0.5, plaintext: true }\n")
        .expect("store");
    assert!(s.plaintext_admitted("db.internal:5432"));
    assert!(s.plaintext_admitted("DB.Internal."));
    assert!(s.plaintext_admitted("\x310.0.0.5:6379"));
    assert!(!s.plaintext_admitted("other.internal:5432"));
    assert!(!s.plaintext_admitted("\x310.0.0.6"));
}

// ---- runtime: the hourly sweep ----------------------------------------------------------------

#[test]
fn an_anchor_that_expires_at_runtime_is_withdrawn_and_its_destination_refused() {
    let short = ca_with("Short", true, None, (2020, 1, 1), (2030, 1, 2));
    let s = build(&format!(
        "destinations:\n  - match: db.internal\n    trust_anchors: [{}]\n",
        inline(&short.pem())
    ))
    .expect("valid at boot");
    assert!(s.config_for("db.internal").expect("ok").is_some());
    assert!(s.sweep(at_2030()).is_empty(), "nothing has expired yet");
    let later = at_2030() + Duration::from_secs(2 * 24 * 3600);
    let withdrawn = s.sweep(later);
    assert_eq!(withdrawn.len(), 1);
    let err = s
        .config_for("db.internal")
        .expect_err("the entry has no anchor left");
    assert!(matches!(err, TrustRefusal::Withdrawn(_)), "{err:?}");
    assert!(err.to_string().contains("BUSBAR-5048"), "{err}");
    assert!(s.sweep(later).is_empty(), "withdrawn once");
}

#[test]
fn a_changed_anchor_file_is_noticed_once_per_change() {
    let a = ca("Rotating");
    let b = ca("Rotated");
    let dir = std::env::temp_dir().join(format!("busbar-trust-rot-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("ca.pem");
    std::fs::write(&path, a.pem()).expect("write");
    let s = build(&format!(
        "trust_anchors: [{{ file: {} }}]\n",
        path.display()
    ))
    .expect("store");
    s.sweep(at_2030());
    assert!(s.changed.lock().expect("changed").is_empty());
    std::fs::write(&path, b.pem()).expect("rotate");
    s.sweep(at_2030());
    assert!(s.changed.lock().expect("changed").contains(&path));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn roots_system_reads_ssl_cert_file_and_refuses_an_empty_bundle() {
    let a = ca("System CA");
    let expired = ca_with("Expired System", true, None, (2000, 1, 1), (2010, 1, 1));
    let dir = std::env::temp_dir().join(format!("busbar-trust-sys-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let bundle = dir.join("bundle.pem");
    std::fs::write(&bundle, format!("{}{}", a.pem(), expired.pem())).expect("write");
    let shown = bundle.display().to_string();
    let env = move |name: &str| (name == "SSL_CERT_FILE").then(|| shown.clone());
    let s = TrustStore::build(&cfg("roots: system\n"), at_2030(), &env).expect("system roots");
    assert_eq!(
        s.base.anchors.len(),
        1,
        "the expired root is dropped, not fatal"
    );
    assert_eq!(s.base.dropped.len(), 1);
    let c = s.config_for("x.example").expect("ok").expect("system");
    handshake(c, "x.example", a.issue("x.example")).expect("a system root verifies");
    let empty = dir.join("empty.pem");
    std::fs::write(&empty, "").expect("write");
    let shown = empty.display().to_string();
    let env = move |name: &str| (name == "SSL_CERT_FILE").then(|| shown.clone());
    let errors = TrustStore::build(&cfg("roots: system\n"), at_2030(), &env).expect_err("empty");
    assert!(errors.join("\n").contains("BUSBAR-3140"), "{errors:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
