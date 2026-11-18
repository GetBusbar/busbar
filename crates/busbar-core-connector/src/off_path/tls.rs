// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The TLS seam's off-path code (`crate::tls`): what a listener's binding, a destination's seal, the
//! outbound trust store's build, its boot report, its hourly sweep and a client configuration's
//! first build for a host build or do once per configuration, binding or lifecycle event, never per
//! dial. The request path (the trust store's selection, the handshake wraps) only reads what these
//! built.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use busbar_contract::crypto::tls as crypto_tls;
use busbar_contract::transport::trust::EgressTrust;
use busbar_contract::transport::wire::ConnectionSecurity;
use busbar_kernel::config::secret::SecretResolver;
use busbar_kernel::config::sections::TlsCfg;
use busbar_kernel::config::tls::{OutboundTlsCfg, TlsRoots, TlsSource};
use busbar_kernel::config::SecretRef;
use busbar_kernel::diagnostics as diag;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig};

use crate::tls::client::{BadAnchors, BadClientIdentity, PinnedKeyVerifier};
use crate::tls::store::{
    Anchor, Base, CacheKey, ConfigCache, Entry, EnvFn, Matcher, TrustRefusal, TrustStore,
};
use crate::tls::{FailClosed, Identity, Tls, ALPN_OFFER};

// ---------------------------------------------------------------------------------------------
// The listener side: a binding's server configuration (`crate::tls`).
// ---------------------------------------------------------------------------------------------

/// Resolve a TLS secret reference to its PEM bytes, mapping any resolve error into a clear,
/// source-naming message.
fn read_pem(
    resolver: &dyn busbar_contract::secret::SecretResolve,
    secret: &SecretRef,
    what: &str,
) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
    let resolved = resolver
        .resolve_at_config(
            secret,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .map_err(|e| format!("cannot resolve TLS {what} ({}): {e}", secret.describe()))?;
    Ok(resolved)
}

/// Parse the PEM certificate chain (leaf first). Errors name the secret source.
fn load_cert_chain(
    resolver: &dyn busbar_contract::secret::SecretResolve,
    secret: &SecretRef,
) -> Result<Vec<CertificateDer<'static>>, String> {
    let src = secret.describe();
    let bytes = read_pem(resolver, secret, "cert")?;
    let seal = busbar_kernel::seal::lend();
    let bytes = bytes.expose(&seal);
    let certs = CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse TLS cert ({src}): {e}"))?;
    if certs.is_empty() {
        return Err(format!(
            "TLS cert ({src}) contains no certificates (expected a PEM chain, leaf first)"
        ));
    }
    Ok(certs)
}

/// Parse the PEM private key, accepting PKCS#8, PKCS#1 (RSA), or SEC1 (EC) encodings. NEVER logs key
/// material.
fn load_private_key(
    resolver: &dyn busbar_contract::secret::SecretResolve,
    secret: &SecretRef,
) -> Result<PrivateKeyDer<'static>, String> {
    let src = secret.describe();
    let bytes = read_pem(resolver, secret, "key")?;
    let seal = busbar_kernel::seal::lend();
    let bytes = bytes.expose(&seal);

    use rustls::pki_types::pem::Error as PemError;
    let key = PrivateKeyDer::from_pem_slice(bytes).map_err(|e| match e {
        PemError::NoItemsFound => {
            format!("TLS key ({src}) contains no private key (expected PKCS#8 / PKCS#1 / SEC1 PEM)")
        }
        other => format!("cannot parse TLS key ({src}): {other}"),
    })?;
    Ok(key)
}

/// Busbar's client identity for one destination, from its two secret references.
pub(crate) fn client_identity(
    resolver: &dyn busbar_contract::secret::SecretResolve,
    cert: &SecretRef,
    key: &SecretRef,
) -> Result<busbar_contract::transport::trust::ClientIdentity, String> {
    let chain = load_cert_chain(resolver, cert)?;
    let key = load_private_key(resolver, key)?;
    let identity = busbar_contract::transport::trust::ClientIdentity {
        cert_chain: chain.into_iter().map(|c| c.as_ref().to_vec()).collect(),
        private_key: key.secret_der().to_vec().into(),
    };
    Ok(identity)
}

/// Build the client-cert verifier root store from the operator's CA bundle (mTLS).
fn load_client_roots(
    resolver: &SecretResolver,
    secret: &SecretRef,
) -> Result<RootCertStore, String> {
    let src = secret.describe();
    let bytes = read_pem(resolver, secret, "client_ca")?;
    let seal = busbar_kernel::seal::lend();
    let bytes = bytes.expose(&seal);
    let cas = CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse TLS client_ca ({src}): {e}"))?;
    if cas.is_empty() {
        return Err(format!("TLS client_ca ({src}) contains no CA certificates"));
    }
    let mut roots = RootCertStore::empty();
    for ca in cas {
        roots
            .add(ca)
            .map_err(|e| format!("invalid CA certificate in TLS client_ca ({src}): {e}"))?;
    }
    Ok(roots)
}

/// Construct the rustls [`ServerConfig`] from the operator's [`TlsCfg`], through the crypto
/// backend, which approves it; returned frozen.
pub(crate) fn build_server_config(
    tls: &TlsCfg,
    resolver: &SecretResolver,
) -> Result<Arc<ServerConfig>, String> {
    build_server_config_for_alpn(tls, resolver, &ALPN_OFFER)
}

pub(crate) fn build_server_config_for_alpn(
    tls: &TlsCfg,
    resolver: &SecretResolver,
    alpn: &[&[u8]],
) -> Result<Arc<ServerConfig>, String> {
    let certs = load_cert_chain(resolver, &tls.cert)?;
    let key = load_private_key(resolver, &tls.key)?;

    let verifier = match &tls.client_ca {
        Some(ca) => {
            let roots = load_client_roots(resolver, ca)?;
            let verifier = crypto_tls::client_verifier(Arc::new(roots), |b| b).map_err(|e| {
                format!(
                    "cannot build client-cert verifier from TLS client_ca ({}): {e}",
                    ca.describe()
                )
            })?;
            Some(verifier)
        }
        None => None,
    };

    let config = crypto_tls::server_config(|builder| {
        let builder = match verifier {
            Some(verifier) => builder.with_client_cert_verifier(verifier),
            None => builder.with_no_client_auth(),
        };
        let mut config = builder.with_single_cert(certs, key)?;
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        select_server_output(config)
    })
    .map_err(|e| match e {
        crypto_tls::TlsError::Rustls(e) => format!(
            "TLS cert/key are not a valid pair (cert {}, key {}): {e}",
            tls.cert.describe(),
            tls.key.describe()
        ),
        other => format!("cannot build the TLS server configuration: {other}"),
    })?;
    Ok(config)
}

/// Explicit root-selected output profile for a freshly assembled listener configuration.
pub(crate) fn select_server_output(
    mut config: ServerConfig,
) -> Result<ServerConfig, rustls::Error> {
    config.cert_compressors.clear();
    config.cert_compression_cache = Arc::new(rustls::compress::CompressionCache::Disabled);
    let plan = crypto_tls::write_progress::output_plan()?;
    crypto_tls::write_progress::configure_server(&mut config, plan)?;
    Ok(config)
}

/// Explicit root-selected output profile for a freshly assembled dialer configuration.
pub(crate) fn select_client_output(
    mut config: rustls::ClientConfig,
) -> Result<rustls::ClientConfig, rustls::Error> {
    config.cert_compressors.clear();
    config.cert_compression_cache = Arc::new(rustls::compress::CompressionCache::Disabled);
    let plan = crypto_tls::write_progress::output_plan()?;
    crypto_tls::write_progress::configure_client(&mut config, plan)?;
    Ok(config)
}

/// Reconcile one binding's operator config against its transport's capability and build the opaque
/// connection-security wrap: once per binding, at boot.
pub(crate) fn prepare(
    label: &str,
    tls_cfg: Option<&TlsCfg>,
    resolver: &SecretResolver,
    transport_capable: bool,
) -> Result<Arc<dyn ConnectionSecurity>, FailClosed> {
    prepare_for_alpn(label, tls_cfg, resolver, transport_capable, &ALPN_OFFER)
}

pub(crate) fn prepare_for_alpn(
    label: &str,
    tls_cfg: Option<&TlsCfg>,
    resolver: &SecretResolver,
    transport_capable: bool,
    alpn: &[&[u8]],
) -> Result<Arc<dyn ConnectionSecurity>, FailClosed> {
    let Some(tls) = tls_cfg else {
        return Ok(Arc::new(Identity));
    };
    if !transport_capable {
        return Err(FailClosed::IncapableTransport {
            label: label.to_string(),
        });
    }
    let config = build_server_config_for_alpn(tls, resolver, alpn).map_err(|reason| {
        FailClosed::MaterialUnavailable {
            label: label.to_string(),
            reason,
        }
    })?;
    Ok(Arc::new(Tls::new(config)))
}

// ---------------------------------------------------------------------------------------------
// The dialling side: a destination's client configuration and seal (`crate::tls::client`).
// ---------------------------------------------------------------------------------------------

/// The platform trust anchors every outbound connection starts from.
pub(crate) fn webpki_roots_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// The client TLS config an outbound connection is secured with, given the host's outbound trust.
/// Built through the crypto backend, which approves it; a refusal is reported as the identity
/// error the caller already handles.
pub(crate) fn build_client_config(
    trust: &EgressTrust,
) -> Result<rustls::ClientConfig, BadClientIdentity> {
    let refused = |e: crypto_tls::TlsError| BadClientIdentity(e.to_string());
    if trust.is_unset() {
        return crypto_tls::client_config(|builder| {
            select_client_output(
                builder
                    .with_root_certificates(webpki_roots_store())
                    .with_no_client_auth(),
            )
        })
        .map(Arc::unwrap_or_clone)
        .map_err(refused);
    }
    let roots = trust_roots(trust)?;
    let verifier = pinned_verifier(trust, &roots)?;
    match &trust.client_identity {
        None => crypto_tls::client_config(|builder| {
            select_client_output(wants_client_cert(builder, roots, verifier).with_no_client_auth())
        })
        .map(Arc::unwrap_or_clone)
        .map_err(refused),
        Some(identity) => {
            let key = rustls_pki_types::PrivateKeyDer::try_from(
                identity
                    .private_key
                    .expose(&busbar_kernel::seal::lend())
                    .clone(),
            )
            .map_err(|e| BadClientIdentity(format!("private key: {e}")))?;
            let chain: Vec<rustls_pki_types::CertificateDer<'static>> = identity
                .cert_chain
                .iter()
                .cloned()
                .map(rustls_pki_types::CertificateDer::from)
                .collect();
            crypto_tls::client_config(|builder| {
                select_client_output(
                    wants_client_cert(builder, roots, verifier)
                        .with_client_auth_cert(chain, key)?,
                )
            })
            .map(Arc::unwrap_or_clone)
            .map_err(|e| match e {
                crypto_tls::TlsError::Rustls(e) => {
                    BadClientIdentity(format!("certificate chain: {e}"))
                }
                other => refused(other),
            })
        }
    }
}

/// The client config for a need whose `trust_from` names an operator CA (`pem`, the PEM the need's
/// destination holds).
pub(crate) fn operator_ca_config(pem: &[u8]) -> Result<rustls::ClientConfig, String> {
    let trust = EgressTrust {
        extra_anchors: operator_ca_anchors(pem)?,
        ..EgressTrust::default()
    };
    let config = build_client_config(&trust).map_err(|e| e.to_string())?;
    Ok(config)
}

/// Parse and validate the public certificate roots in an operator PEM bundle.
pub(crate) fn operator_ca_anchors(pem: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let certs = rustls_pki_types::CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("the operator CA does not parse: {e}"))?;
    if certs.is_empty() {
        return Err("the operator CA holds no certificate".into());
    }
    let mut anchors = RootCertStore::empty();
    for cert in &certs {
        anchors
            .add(cert.clone())
            .map_err(|e| format!("the operator CA is not a usable trust anchor: {e}"))?;
    }
    let owned = certs.into_iter().map(|c| c.to_vec()).collect();
    Ok(owned)
}

/// Platform roots plus any extra anchors `trust` names; an anchor rustls cannot use is refused.
fn trust_roots(trust: &EgressTrust) -> Result<RootCertStore, BadClientIdentity> {
    let mut roots = webpki_roots_store();
    for der in &trust.extra_anchors {
        roots
            .add(rustls_pki_types::CertificateDer::from(der.clone()))
            .map_err(|e| BadClientIdentity(format!("a trust anchor is not usable: {e}")))?;
    }
    Ok(roots)
}

/// The pinning verifier `trust` asks for (`None` when it pins no key), built through the backend
/// ahead of the config so the config closure cannot fail on it.
fn pinned_verifier(
    trust: &EgressTrust,
    roots: &RootCertStore,
) -> Result<Option<PinnedKeyVerifier>, BadClientIdentity> {
    if trust.pinned_public_keys.is_empty() {
        return Ok(None);
    }
    pinned_key_verifier(roots.clone(), &trust.pinned_public_keys)
        .map(Some)
        .map_err(BadClientIdentity)
}

/// The verifier half of the client config, before the client-auth choice: `roots`, or the pinning
/// verifier over them when the destination pins a key.
fn wants_client_cert(
    builder: crypto_tls::ClientBuilder,
    roots: RootCertStore,
    pinned: Option<PinnedKeyVerifier>,
) -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::client::WantsClientCert> {
    match pinned {
        None => builder.with_root_certificates(roots),
        Some(verifier) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier)),
    }
}

/// The pinning verifier over `roots` holding the peer to `pins`, or why it cannot be built (an
/// empty root store, as `advanced.tls.roots: none` with no anchor gives): a refusal, never a panic.
pub(crate) fn pinned_key_verifier(
    roots: RootCertStore,
    pins: &[[u8; 32]],
) -> Result<PinnedKeyVerifier, String> {
    let inner = crypto_tls::server_verifier(Arc::new(roots)).map_err(|e| {
        format!(
            "{}: no verifier can be built for this pinned destination: {e}",
            diag::CONFIG_TLS_TRUST_EMPTY.banner()
        )
    })?;
    Ok(PinnedKeyVerifier {
        inner,
        pins: pins.iter().copied().collect(),
    })
}

/// What sealing `anchors` under `base` yields: the canonical key pin and the identity to present.
type SealParts = (Option<String>, Option<Arc<rustls::sign::CertifiedKey>>);

/// The parts of a destination's seal: its far-end key pin, read to its canonical spelling, and
/// busbar's client identity, parsed once; once per destination declaration.
pub(crate) fn seal_parts(
    base: Option<&rustls::ClientConfig>,
    anchors: &busbar_contract::transport::trust::Anchors,
) -> Result<SealParts, BadAnchors> {
    let key_pin = anchors
        .key_pin
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(busbar_contract::transport::trust::canonical_key_pin)
        .transpose()
        .map_err(BadAnchors::KeyPin)?;
    let identity = match &anchors.client_identity {
        None => None,
        Some(identity) => {
            let base = base.ok_or_else(|| {
                BadAnchors::Identity(BadClientIdentity(
                    "the connector secures no connection to present it on".into(),
                ))
            })?;
            let key = rustls_pki_types::PrivateKeyDer::try_from(
                identity
                    .private_key
                    .expose(&busbar_kernel::seal::lend())
                    .clone(),
            )
            .map_err(|e| BadAnchors::Identity(BadClientIdentity(format!("private key: {e}"))))?;
            let chain: Vec<rustls_pki_types::CertificateDer<'static>> = identity
                .cert_chain
                .iter()
                .cloned()
                .map(rustls_pki_types::CertificateDer::from)
                .collect();
            let certified =
                rustls::sign::CertifiedKey::from_der(chain, key, base.crypto_provider()).map_err(
                    |e| BadAnchors::Identity(BadClientIdentity(format!("certificate chain: {e}"))),
                )?;
            Some(Arc::new(certified))
        }
    };
    if !anchors.extra_anchors.is_empty() {
        return Err(BadAnchors::Trust(
            "member CA requires a known effective TLS policy".into(),
        ));
    }
    Ok((key_pin, identity))
}

// ---------------------------------------------------------------------------------------------
// The outbound trust store (`crate::tls::store`): build, boot report, hourly sweep, first build of
// a host's client configuration.
// ---------------------------------------------------------------------------------------------

/// How long before `notAfter` an anchor starts warning (BUSBAR-3139).
const EXPIRY_WARNING: Duration = Duration::from_secs(30 * 24 * 3600);
/// How often the expiry warning repeats.
const EXPIRY_WARNING_REPEAT: Duration = Duration::from_secs(24 * 3600);
/// The clock-skew tolerance on `notBefore` (container clocks).
const NOT_BEFORE_TOLERANCE: Duration = Duration::from_secs(5 * 60);

/// The audit action of one accepted operator anchor.
const AUDIT_ANCHOR: &str = "config.tls_trust_anchor";
/// The audit action of an anchor withdrawn at runtime because it expired.
const AUDIT_WITHDRAWN: &str = "egress.tls_anchor_withdrawn";
/// The audit action of an anchor file whose contents changed since boot.
const AUDIT_FILE_CHANGED: &str = "egress.tls_anchor_file_changed";

/// Where the operating system keeps its CA bundle, tried in order when `SSL_CERT_FILE` and
/// `SSL_CERT_DIR` are unset (`roots: system`).
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/ssl/cert.pem",
    "/usr/local/share/certs/ca-root-nss.crt",
    "/usr/local/etc/openssl/cert.pem",
];

impl Anchor {
    /// The fingerprint, `sha256:<hex>`.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        format!("sha256:{}", hex(&self.sha256))
    }
}

impl ConfigCache {
    /// Hold `config` for the host `key` names.
    pub(crate) fn insert(&mut self, key: CacheKey<'_>, config: Arc<rustls::ClientConfig>) {
        match key {
            CacheKey::Name(name) => {
                self.names.insert(name.to_owned(), config);
            }
            CacheKey::Ip(ip) => {
                self.ips.insert(ip, config);
            }
        }
    }

    /// Forget every held config (a withdrawal changed what a build yields).
    pub(crate) fn clear(&mut self) {
        self.names.clear();
        self.ips.clear();
    }
}

impl TrustStore {
    /// THE STORE `cfg` states, validated at `now`. Every refusal is one coded line naming the key,
    /// the index and the reason; never certificate or key bytes.
    pub fn build(
        cfg: &OutboundTlsCfg,
        now: SystemTime,
        env: EnvFn<'_>,
    ) -> Result<Self, Vec<String>> {
        let mut errors = Vec::new();
        let base = match load_base(cfg.roots, now, env) {
            Ok(b) => b,
            Err(e) => {
                errors.push(e);
                Base {
                    roots: cfg.roots,
                    anchors: Vec::new(),
                    digest: String::new(),
                    source: None,
                    dropped: Vec::new(),
                }
            }
        };
        let mut global = Vec::new();
        for (i, src) in cfg.trust_anchors.iter().enumerate() {
            let key = format!("advanced.tls.trust_anchors[{i}]");
            match load_anchors(src, &key, "global", now, env) {
                Ok(mut a) => global.append(&mut a),
                Err(e) => errors.push(e),
            }
        }
        let mut entries = Vec::new();
        for (i, d) in cfg.destinations.iter().enumerate() {
            match load_entry(i, d, now, env) {
                Ok(e) => entries.push(e),
                Err(mut e) => errors.append(&mut e),
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        let mut plain_names: foldhash::HashSet<String> = foldhash::HashSet::default();
        let mut plain_ips: foldhash::HashSet<IpAddr> = foldhash::HashSet::default();
        for e in &entries {
            if !e.plaintext {
                continue;
            }
            // A plaintext entry is exact (a host or one IP): `load_entry` refuses any other.
            match &e.matcher {
                Matcher::Host(name) => {
                    plain_names.insert(name.clone());
                }
                Matcher::Net(ip, _) => {
                    plain_ips.insert(*ip);
                }
                Matcher::Under(_) => {}
            }
        }
        Ok(Self {
            default: cfg.is_default(),
            base,
            global,
            entries,
            plain_names,
            plain_ips,
            withdrawn: RwLock::default(),
            generation: std::sync::atomic::AtomicU64::new(0),
            cache: Mutex::default(),
            warned: Mutex::default(),
            changed: Mutex::default(),
        })
    }

    /// The client config for `host` on a cache miss: the entries matching it, the config built from
    /// them, and (when `key` names the host) the config held for the next dial of it. A withdrawal
    /// that lands while it builds keeps it out of the cache.
    pub(crate) fn config_miss<'h>(
        &self,
        host: &'h str,
        d: &crate::tls::store::Dialled<'_>,
        key: Option<CacheKey<'_>>,
    ) -> Result<Option<Arc<rustls::ClientConfig>>, TrustRefusal<'h>> {
        let generation = self.generation.load(std::sync::atomic::Ordering::Acquire);
        let matched: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.plaintext && e.matcher.matches(d))
            .map(|(i, _)| i)
            .collect();
        let config = Arc::new(self.build_for(host, &matched, None)?);
        if let Some(key) = key {
            let mut cache = self.cache.lock().expect("tls cache");
            if self.generation.load(std::sync::atomic::Ordering::Acquire) == generation {
                cache.insert(key, Arc::clone(&config));
            }
        }
        Ok(Some(config))
    }

    /// Compose the operator's logical-destination policy with a host-checked Need plan.
    /// SNI affects peer naming only; it never selects operator roots or pins.
    /// Configurations containing client identities are never cached here.
    pub fn config_for_need<'h>(
        &self,
        host: &'h str,
        plan: &crate::need::TlsPlan<'_>,
        alpn: &[Vec<u8>],
    ) -> Result<Arc<rustls::ClientConfig>, TrustRefusal<'h>> {
        let destination = crate::tls::store::dialled(host).ok_or(TrustRefusal::NoAnchors(host))?;
        let matched: Vec<_> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| !entry.plaintext && entry.matcher.matches(&destination))
            .map(|(index, _)| index)
            .collect();
        let mut config = self.build_for(host, &matched, Some(plan))?;
        config.alpn_protocols = alpn.to_vec();
        Ok(Arc::new(config))
    }

    fn build_for<'h>(
        &self,
        host: &'h str,
        matched: &[usize],
        need: Option<&crate::need::TlsPlan<'_>>,
    ) -> Result<rustls::ClientConfig, TrustRefusal<'h>> {
        let withdrawn = self.withdrawn.read().expect("withdrawn").clone();
        let entries: Vec<&Entry> = matched.iter().map(|i| &self.entries[*i]).collect();
        let listed: Vec<&Anchor> = entries.iter().flat_map(|e| e.anchors.iter()).collect();
        let replaces = !listed.is_empty() && !entries.iter().any(|e| e.include_roots);
        let mut roots = RootCertStore::empty();
        let mut own_left = 0usize;
        for a in &listed {
            if withdrawn.contains(&a.sha256) {
                continue;
            }
            own_left += 1;
            roots
                .add(CertificateDer::from(a.der.clone()))
                .map_err(|e| TrustRefusal::Build(format!("anchor {}: {e}", a.fingerprint())))?;
        }
        if !listed.is_empty() && own_left == 0 {
            return Err(TrustRefusal::Withdrawn(host));
        }
        if !replaces {
            roots.extend(self.base.anchors.iter().cloned());
            for a in &self.global {
                if !withdrawn.contains(&a.sha256) {
                    roots
                        .add(CertificateDer::from(a.der.clone()))
                        .map_err(|e| {
                            TrustRefusal::Build(format!("anchor {}: {e}", a.fingerprint()))
                        })?;
                }
            }
        }
        if let Some(anchor) = need.and_then(|plan| plan.trust.as_ref()) {
            for der in &anchor.der {
                roots
                    .add(CertificateDer::from(der.clone()))
                    .map_err(|_| TrustRefusal::Build("instance anchor is invalid".into()))?;
            }
        }
        if roots.is_empty() {
            return Err(TrustRefusal::NoAnchors(host));
        }
        let pins: Vec<[u8; 32]> = entries
            .iter()
            .flat_map(|e| e.pins.iter().copied())
            .collect();
        let waived = need.is_some_and(|plan| plan.waive);
        let instance_identity = need
            .and_then(|plan| plan.cert.as_deref())
            .map(|pem| {
                let chain = CertificateDer::pem_slice_iter(pem.as_slice())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| TrustRefusal::InvalidNeed)?;
                if chain.is_empty() {
                    return Err(TrustRefusal::InvalidNeed);
                }
                let key = PrivateKeyDer::from_pem_slice(pem.as_slice())
                    .map_err(|_| TrustRefusal::InvalidNeed)?;
                Ok((chain, Arc::new(key)))
            })
            .transpose()?;
        let mut identity = entries.iter().find_map(|entry| entry.identity.as_ref());
        if need.is_some() {
            identity = instance_identity.as_ref();
            for operator in entries.iter().filter_map(|entry| entry.identity.as_ref()) {
                if identity.is_some_and(|(chain, key)| {
                    chain != &operator.0 || key.secret_der() != operator.1.secret_der()
                }) {
                    return Err(TrustRefusal::Build("conflicting client identities".into()));
                }
                identity = Some(operator);
            }
        }
        if waived && identity.is_some() {
            return Err(TrustRefusal::Build(
                "unverified TLS cannot present a client identity".into(),
            ));
        }
        let verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>> = if waived {
            let inner = crate::tls::client::unverified_verifier();
            Some(if pins.is_empty() {
                inner
            } else {
                Arc::new(PinnedKeyVerifier {
                    inner,
                    pins: pins.iter().copied().collect(),
                })
            })
        } else if pins.is_empty() {
            None
        } else {
            Some(Arc::new(
                pinned_key_verifier(roots.clone(), &pins).map_err(TrustRefusal::Build)?,
            ))
        };
        crypto_tls::client_config(|builder| {
            let wants = match verifier {
                None => builder.with_root_certificates(roots),
                Some(verifier) => builder
                    .dangerous()
                    .with_custom_certificate_verifier(verifier),
            };
            match identity {
                None => Ok(wants.with_no_client_auth()),
                Some((chain, key)) => wants.with_client_auth_cert(chain.clone(), key.clone_key()),
            }
        })
        .map(Arc::unwrap_or_clone)
        .map_err(|e| TrustRefusal::Build(format!("client identity: {e}")))
    }

    /// THE BOOT REPORT: one BUSBAR-3138 line and one `config.tls_trust_anchor` audit record per
    /// accepted operator anchor; one line describing the base set; BUSBAR-3147 when system roots
    /// were dropped; BUSBAR-3139 for each anchor within 30 days of expiry.
    pub fn report_boot(&self, now: SystemTime) {
        if self.default {
            return;
        }
        tracing::info!(
            diag = %diag::CONFIG_TLS_ANCHOR_ACCEPTED.banner(),
            roots = self.base.roots.as_str(),
            count = self.base.anchors.len(),
            sha256 = %self.base.digest,
            source = self.base.source.as_deref().unwrap_or("-"),
            "advanced.tls: base set loaded"
        );
        if self.base.source.is_some() {
            busbar_kernel::audit_ring::AUDIT.record_by(
                AUDIT_ANCHOR,
                &format!(
                    "tls:roots:{}:{}:{}",
                    self.base.roots.as_str(),
                    self.base.source.as_deref().unwrap_or("-"),
                    self.base.digest
                ),
                busbar_kernel::audit_ring::OUTCOME_APPLIED,
                "system",
            );
        }
        if !self.base.dropped.is_empty() {
            busbar_kernel::diag_warn!(
                diag::CONFIG_TLS_BASE_ROOTS_DROPPED,
                count = self.base.dropped.len(),
                first = %self.base.dropped.first().map(String::as_str).unwrap_or_default(),
                "advanced.tls.roots: system: {} certificate(s) in the OS bundle were not used as \
                 trust anchors (expired, not a CA, or unreadable)",
                self.base.dropped.len()
            );
        }
        for a in self.anchors() {
            tracing::info!(
                diag = %diag::CONFIG_TLS_ANCHOR_ACCEPTED.banner(),
                key = %a.key,
                scope = %a.scope,
                sha256 = %a.fingerprint(),
                subject = %a.subject,
                issuer = %a.issuer,
                not_after = a.not_after,
                "advanced.tls: trust anchor accepted"
            );
            busbar_kernel::audit_ring::AUDIT.record_by(
                AUDIT_ANCHOR,
                &format!("tls:{}:{}", a.scope, a.fingerprint()),
                busbar_kernel::audit_ring::OUTCOME_APPLIED,
                "system",
            );
        }
        self.warn_expiring(now);
    }

    fn warn_expiring(&self, now: SystemTime) {
        let soon = unix(now + EXPIRY_WARNING);
        let mut warned = self.warned.lock().expect("warned");
        for a in self.anchors() {
            if a.not_after > soon || a.not_after <= unix(now) {
                continue;
            }
            let due = warned.get(&a.sha256).is_none_or(|at| {
                now.duration_since(*at).unwrap_or_default() >= EXPIRY_WARNING_REPEAT
            });
            if !due {
                continue;
            }
            warned.insert(a.sha256, now);
            busbar_kernel::diag_warn!(
                diag::CONFIG_TLS_ANCHOR_EXPIRING,
                key = %a.key,
                scope = %a.scope,
                sha256 = %a.fingerprint(),
                not_after = a.not_after,
                "advanced.tls: the trust anchor {} ({}) expires within 30 days; rotate it before \
                 then (an expired anchor is withdrawn and refuses the next boot)",
                a.key,
                a.subject
            );
        }
    }

    /// THE HOURLY SWEEP at `now`: withdraw expired anchors from new connections (BUSBAR-5048,
    /// audited), repeat the expiry warning daily (BUSBAR-3139), and warn once per change when an
    /// anchor file's contents differ from what was loaded (BUSBAR-5049, audited; restart to
    /// apply). Returns the fingerprints withdrawn by this sweep.
    pub fn sweep(&self, now: SystemTime) -> Vec<String> {
        if self.default {
            return Vec::new();
        }
        let mut newly = Vec::new();
        {
            let mut withdrawn = self.withdrawn.write().expect("withdrawn");
            for a in self
                .global
                .iter()
                .chain(self.entries.iter().flat_map(|e| e.anchors.iter()))
            {
                if a.not_after <= unix(now) && withdrawn.insert(a.sha256) {
                    newly.push(a.clone());
                }
            }
        }
        if !newly.is_empty() {
            self.generation
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.cache.lock().expect("tls cache").clear();
        }
        for a in &newly {
            busbar_kernel::diag_warn!(
                diag::EGRESS_TLS_ANCHOR_EXPIRED_WITHDRAWN,
                key = %a.key,
                scope = %a.scope,
                sha256 = %a.fingerprint(),
                not_after = a.not_after,
                "advanced.tls: the trust anchor {} expired and was withdrawn from new connections",
                a.key
            );
            busbar_kernel::audit_ring::AUDIT.record_by(
                AUDIT_WITHDRAWN,
                &format!("tls:{}:{}", a.scope, a.fingerprint()),
                busbar_kernel::audit_ring::OUTCOME_DEGRADED,
                "system",
            );
        }
        self.warn_expiring(now);
        for a in self.anchors() {
            let Some((path, loaded)) = a.file.as_ref() else {
                continue;
            };
            let now_digest = std::fs::read(path).ok().map(|b| sha256(&b));
            let differs = now_digest.as_ref() != Some(loaded);
            let mut changed = self.changed.lock().expect("changed");
            if differs && changed.insert(path.clone()) {
                busbar_kernel::diag_warn!(
                    diag::EGRESS_TLS_ANCHOR_FILE_CHANGED,
                    key = %a.key,
                    path = %path.display(),
                    "advanced.tls: the anchor file {} changed since boot; restart busbar to apply it",
                    path.display()
                );
                busbar_kernel::audit_ring::AUDIT.record_by(
                    AUDIT_FILE_CHANGED,
                    &format!("tls:{}:{}", a.scope, path.display()),
                    busbar_kernel::audit_ring::OUTCOME_DEGRADED,
                    "system",
                );
            } else if !differs {
                changed.remove(path);
            }
        }
        newly.iter().map(Anchor::fingerprint).collect()
    }
}

/// A name, lowercased, without its trailing dot, in its ASCII (IDNA) form: how a destination entry
/// is held.
fn fold_name_owned(host: &str) -> Option<String> {
    let h = host.strip_suffix('.').unwrap_or(host);
    if h.is_empty() {
        return None;
    }
    let ascii = busbar_contract::net::url_host_to_ascii(h).ok()?;
    Some(ascii.to_ascii_lowercase())
}

fn is_label_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|l| {
            !l.is_empty()
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn matcher(i: usize, written: &str) -> Result<Matcher, String> {
    let key = format!("advanced.tls.destinations[{i}].match");
    let bad = || {
        format!(
            "{}: {key}: `{written}` is not a host, a `*.domain` wildcard, an IP or a CIDR",
            diag::CONFIG_TLS_DESTINATION_INVALID.banner()
        )
    };
    let w = written.trim();
    let w = w.trim_start_matches('[').trim_end_matches(']');
    if let Some((ip, len)) = w.split_once('/') {
        let ip: IpAddr = ip.trim_end_matches(']').parse().map_err(|_| bad())?;
        let len: u8 = len.parse().map_err(|_| bad())?;
        let full = if ip.is_ipv4() { 32 } else { 128 };
        if len > full {
            return Err(bad());
        }
        return Ok(Matcher::Net(ip, len));
    }
    if let Ok(ip) = w.parse::<IpAddr>() {
        return Ok(Matcher::Net(ip, if ip.is_ipv4() { 32 } else { 128 }));
    }
    if let Some(domain) = w.strip_prefix("*.") {
        let d = fold_name_owned(domain).ok_or_else(bad)?;
        if !is_label_name(&d) {
            return Err(bad());
        }
        if !d.contains('.') {
            return Err(format!(
                "{}: {key}: `{written}` is a wildcard over a single label; name the domain you own \
                 (for example `*.corp.example.com`)",
                diag::CONFIG_WILDCARD_OVER_PUBLIC_SUFFIX.banner()
            ));
        }
        return Ok(Matcher::Under(format!(".{d}")));
    }
    let n = fold_name_owned(w).ok_or_else(bad)?;
    if !is_label_name(&n) {
        return Err(bad());
    }
    Ok(Matcher::Host(n))
}

fn load_entry(
    i: usize,
    d: &busbar_kernel::config::tls::TlsDestinationCfg,
    now: SystemTime,
    env: EnvFn<'_>,
) -> Result<Entry, Vec<String>> {
    let mut errors = Vec::new();
    let m = matcher(i, &d.matches).map_err(|e| vec![e])?;
    let scope = format!("destinations[{i}] ({})", d.matches.trim());
    let mut anchors = Vec::new();
    for (j, src) in d.trust_anchors.iter().enumerate() {
        let key = format!("advanced.tls.destinations[{i}].trust_anchors[{j}]");
        match load_anchors(src, &key, &scope, now, env) {
            Ok(mut a) => anchors.append(&mut a),
            Err(e) => errors.push(e),
        }
    }
    let mut pins = Vec::new();
    for (j, p) in d.pin_spki_sha256.iter().enumerate() {
        match pin_bytes(p) {
            Some(b) => pins.push(b),
            None => errors.push(format!(
                "{}: advanced.tls.destinations[{i}].pin_spki_sha256[{j}]: not `sha256/<base64>` of a \
                 32-byte SHA-256 SubjectPublicKeyInfo digest",
                diag::CONFIG_TLS_DESTINATION_INVALID.banner()
            )),
        }
    }
    let identity = match &d.client_identity {
        None => None,
        Some(id) => match load_identity(i, id, env) {
            Ok(v) => Some(v),
            Err(e) => {
                errors.push(e);
                None
            }
        },
    };
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(Entry {
        shown: d.matches.trim().to_owned(),
        matcher: m,
        anchors,
        include_roots: d.include_roots,
        pins,
        identity,
        // The `plaintext` row is deleted from `advanced.tls.destinations` (parse refuses it; transport
        // security is `insecure_transport`), so no entry admits plaintext.
        plaintext: false,
    })
}

fn pin_bytes(written: &str) -> Option<[u8; 32]> {
    use base64::Engine as _;
    let canonical = busbar_contract::transport::trust::canonical_key_pin(written).ok()?;
    let b64 = canonical.strip_prefix(busbar_contract::transport::trust::KEY_PIN_TAG)?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    bytes.try_into().ok()
}

fn read_source(src: &TlsSource, env: EnvFn<'_>) -> Result<(Vec<u8>, Option<PathBuf>), String> {
    match src {
        TlsSource::Inline(pem) => Ok((pem.as_bytes().to_vec(), None)),
        TlsSource::Env(name) => env(name)
            .filter(|v| !v.trim().is_empty())
            .map(|v| (v.into_bytes(), None))
            .ok_or_else(|| format!("the environment variable {name} is unset or empty")),
        TlsSource::File(path) => std::fs::read(path)
            .map(|b| (b, Some(PathBuf::from(path))))
            .map_err(|e| format!("cannot read {path}: {e}")),
    }
}

fn load_identity(
    i: usize,
    id: &busbar_kernel::config::tls::TlsClientIdentityCfg,
    env: EnvFn<'_>,
) -> Result<(Vec<CertificateDer<'static>>, Arc<PrivateKeyDer<'static>>), String> {
    let key_name = format!("advanced.tls.destinations[{i}].client_identity");
    let bad = |why: String| {
        format!(
            "{}: {key_name}: {why}",
            diag::CONFIG_TLS_DESTINATION_INVALID.banner()
        )
    };
    let (cert_pem, _) = read_source(&id.cert, env).map_err(|e| bad(format!("cert: {e}")))?;
    let chain = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| bad(format!("cert ({}) does not parse: {e}", id.cert.describe())))?;
    if chain.is_empty() {
        return Err(bad(format!(
            "cert ({}) holds no certificate",
            id.cert.describe()
        )));
    }
    let (key_pem, _) = read_source(&id.key, env).map_err(|e| bad(format!("key: {e}")))?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|_| {
        bad(format!(
            "key ({}) holds no private key busbar can read",
            id.key.describe()
        ))
    })?;
    let signing = busbar_contract::crypto::tls::signing_key(&key)
        .map_err(|e| bad(format!("the key does not sign for the certificate: {e}")))?;
    let certified = rustls::sign::CertifiedKey::new(chain.clone(), signing);
    certified
        .keys_match()
        .map_err(|_| bad("the key is not the certificate's key".into()))?;
    Ok((chain, Arc::new(key)))
}

/// Read, parse and validate one operator anchor source (it may hold several certificates).
fn load_anchors(
    src: &TlsSource,
    key: &str,
    scope: &str,
    now: SystemTime,
    env: EnvFn<'_>,
) -> Result<Vec<Anchor>, String> {
    let refuse = |why: String| {
        format!(
            "{}: {key} ({}, scope {scope}): {why}. See the trust-anchor rotation runbook in \
             docs/configuration.md#advancedtls",
            diag::CONFIG_TLS_ANCHOR_INVALID.banner(),
            src.describe()
        )
    };
    let (pem, file) = read_source(src, env).map_err(refuse)?;
    let text = String::from_utf8_lossy(&pem);
    if text.contains("PRIVATE KEY-----") {
        return Err(refuse(
            "it holds a private key; a trust anchor is a CA certificate only".into(),
        ));
    }
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| refuse(format!("the PEM does not parse: {e}")))?;
    if certs.is_empty() {
        return Err(refuse("it holds no certificate".into()));
    }
    let file = file.map(|p| (p, sha256(&pem)));
    let mut out = Vec::new();
    for (k, cert) in certs.iter().enumerate() {
        let at = if certs.len() > 1 {
            format!("certificate {k}: ")
        } else {
            String::new()
        };
        let facts = ca_facts(cert.as_ref(), now).map_err(|why| refuse(format!("{at}{why}")))?;
        let mut probe = RootCertStore::empty();
        probe.add(cert.clone()).map_err(|e| {
            refuse(format!(
                "{at}rustls does not accept it as a trust anchor: {e}"
            ))
        })?;
        out.push(Anchor {
            der: cert.to_vec(),
            sha256: sha256(cert.as_ref()),
            subject: facts.subject,
            issuer: facts.issuer,
            not_after: facts.not_after,
            scope: scope.to_owned(),
            key: key.to_owned(),
            file: file.clone(),
        });
    }
    Ok(out)
}

struct CaFacts {
    subject: String,
    issuer: String,
    not_after: i64,
}

/// The CA rules an operator anchor is held to, at `now`.
fn ca_facts(der: &[u8], now: SystemTime) -> Result<CaFacts, String> {
    use x509_cert::der::Decode as _;
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
    use x509_cert::Version;
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| format!("it is not an X.509 certificate: {e}"))?;
    let tbs = cert.tbs_certificate();
    if tbs.version() != Version::V3 {
        return Err("it is not an X.509 v3 certificate".into());
    }
    let ca = tbs
        .get_extension::<BasicConstraints>()
        .map_err(|e| format!("its basicConstraints do not parse: {e}"))?
        .is_some_and(|(_, bc)| bc.ca);
    if !ca {
        return Err(
            "it is not a CA certificate (basicConstraints CA:TRUE is absent): list the CA that \
             issued the server's certificate, not the server's own certificate"
                .into(),
        );
    }
    if let Some((_, ku)) = tbs
        .get_extension::<KeyUsage>()
        .map_err(|e| format!("its keyUsage does not parse: {e}"))?
    {
        if !ku.key_cert_sign() {
            return Err("its keyUsage does not include keyCertSign".into());
        }
    }
    let secs = |t: x509_cert::time::Time| {
        i64::try_from(t.to_unix_duration().as_secs()).unwrap_or(i64::MAX)
    };
    let not_before = secs(tbs.validity().not_before);
    let not_after = secs(tbs.validity().not_after);
    let t = unix(now);
    let tolerance = i64::try_from(NOT_BEFORE_TOLERANCE.as_secs()).unwrap_or(0);
    if not_before - tolerance > t {
        return Err(format!("it is not valid yet (notBefore {not_before})"));
    }
    if t >= not_after {
        return Err(format!("it has expired (notAfter {not_after})"));
    }
    Ok(CaFacts {
        subject: tbs.subject().to_string(),
        issuer: tbs.issuer().to_string(),
        not_after,
    })
}

fn load_base(roots: TlsRoots, now: SystemTime, env: EnvFn<'_>) -> Result<Base, String> {
    match roots {
        TlsRoots::Bundled => {
            let anchors: Vec<_> = webpki_roots::TLS_SERVER_ROOTS.to_vec();
            Ok(Base {
                roots,
                digest: digest_of(&anchors),
                anchors,
                source: None,
                dropped: Vec::new(),
            })
        }
        TlsRoots::None => Ok(Base {
            roots,
            anchors: Vec::new(),
            digest: digest_of(&[]),
            source: None,
            dropped: Vec::new(),
        }),
        TlsRoots::System => load_system(now, env),
    }
}

fn system_pem_files(env: EnvFn<'_>) -> (String, Vec<PathBuf>) {
    let mut files = Vec::new();
    let mut source = Vec::new();
    if let Some(f) = env("SSL_CERT_FILE").filter(|f| !f.is_empty()) {
        source.push(format!("SSL_CERT_FILE={f}"));
        files.push(PathBuf::from(f));
    }
    if let Some(dirs) = env("SSL_CERT_DIR").filter(|d| !d.is_empty()) {
        source.push(format!("SSL_CERT_DIR={dirs}"));
        for dir in dirs.split(':').filter(|d| !d.is_empty()) {
            if let Ok(read) = std::fs::read_dir(dir) {
                let mut found: Vec<PathBuf> = read
                    .filter_map(Result::ok)
                    .map(|e| e.path())
                    .filter(|p| p.is_file())
                    .collect();
                found.sort();
                files.extend(found);
            }
        }
    }
    if files.is_empty() && source.is_empty() {
        if let Some(found) = SYSTEM_BUNDLES
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
        {
            source.push(found.display().to_string());
            files.push(found);
        }
    }
    (source.join(" "), files)
}

fn load_system(now: SystemTime, env: EnvFn<'_>) -> Result<Base, String> {
    let (source, files) = system_pem_files(env);
    let mut anchors = Vec::new();
    let mut dropped = Vec::new();
    let mut seen = BTreeSet::new();
    for f in &files {
        let Ok(bytes) = std::fs::read(f) else {
            dropped.push(format!("{}: unreadable", f.display()));
            continue;
        };
        for (k, cert) in CertificateDer::pem_slice_iter(&bytes).enumerate() {
            let cert = match cert {
                Ok(c) => c,
                Err(e) => {
                    dropped.push(format!("{} #{k}: {e}", f.display()));
                    continue;
                }
            };
            if !seen.insert(sha256(cert.as_ref())) {
                continue;
            }
            if let Err(why) = ca_facts(cert.as_ref(), now) {
                dropped.push(format!("{} #{k}: {why}", f.display()));
                continue;
            }
            // rustls derives the anchor (webpki's anchor_from_trusted_cert, owned) on add.
            let mut probe = RootCertStore::empty();
            match probe.add(cert) {
                Ok(()) => anchors.append(&mut probe.roots),
                Err(e) => dropped.push(format!("{} #{k}: {e}", f.display())),
            }
        }
    }
    if anchors.is_empty() {
        return Err(format!(
            "{}: advanced.tls.roots: system: the operating system's CA bundle holds no usable \
             certificate ({}); install the distribution's ca-certificates package, set \
             SSL_CERT_FILE, or use `roots: bundled`",
            diag::CONFIG_TLS_TRUST_EMPTY.banner(),
            if source.is_empty() {
                "no bundle file was found"
            } else {
                source.as_str()
            }
        ));
    }
    Ok(Base {
        roots: TlsRoots::System,
        digest: digest_of(&anchors),
        anchors,
        source: Some(source),
        dropped,
    })
}

fn digest_of(anchors: &[rustls::pki_types::TrustAnchor<'_>]) -> String {
    let mut parts: Vec<Vec<u8>> = anchors
        .iter()
        .map(|a| {
            let mut v = a.subject.to_vec();
            v.extend_from_slice(&a.subject_public_key_info);
            v
        })
        .collect();
    parts.sort();
    let mut ctx = busbar_contract::crypto::Sha256::new();
    for p in &parts {
        ctx.update(&(p.len() as u64).to_be_bytes());
        ctx.update(p);
    }
    format!("sha256:{}", hex(&ctx.finish()))
}

fn sha256(b: &[u8]) -> [u8; 32] {
    busbar_contract::crypto::sha256(b)
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}
