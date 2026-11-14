// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND TLS TRUST STORE (`advanced.tls`): one place that decides which certificate
//! authorities, key pins and client identity an outbound TLS connection uses.
//!
//! * It is built once at boot from [`OutboundTlsCfg`]. Every operator anchor must parse, hold only
//!   certificates, be an X.509 v3 CA (`basicConstraints CA:TRUE`, `keyCertSign` when `keyUsage` is
//!   present), be inside its validity window (`notBefore` with five minutes' tolerance) and be
//!   accepted by rustls; anything else refuses the boot (BUSBAR-3137).
//! * A dial is matched by the host the destination guard judged for it (never by a name a plugin
//!   offers, never by a proxy hop). A matching entry's anchors REPLACE the base set unless it sets
//!   `include_roots`; several matching entries trust the union of their anchors.
//! * Verification is always on. Pins narrow it; nothing widens or skips it.
//! * [`TrustStore::sweep`] (hourly) withdraws an anchor past `notAfter` from new connections,
//!   repeats the 30-day expiry warning once a day, and warns when an anchor file changed on disk.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use busbar_kernel::config::tls::{OutboundTlsCfg, TlsRoots, TlsSource};
use busbar_kernel::diagnostics as diag;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// How long before `notAfter` an anchor starts warning (BUSBAR-3139).
pub const EXPIRY_WARNING: Duration = Duration::from_secs(30 * 24 * 3600);
/// How often the expiry warning repeats.
pub const EXPIRY_WARNING_REPEAT: Duration = Duration::from_secs(24 * 3600);
/// How often [`TrustStore::sweep`] runs.
pub const SWEEP_EVERY: Duration = Duration::from_secs(3600);
/// The clock-skew tolerance on `notBefore` (container clocks).
pub const NOT_BEFORE_TOLERANCE: Duration = Duration::from_secs(5 * 60);

/// The audit action of one accepted operator anchor.
pub const AUDIT_ANCHOR: &str = "config.tls_trust_anchor";
/// The audit action of an anchor withdrawn at runtime because it expired.
pub const AUDIT_WITHDRAWN: &str = "egress.tls_anchor_withdrawn";
/// The audit action of an anchor file whose contents changed since boot.
pub const AUDIT_FILE_CHANGED: &str = "egress.tls_anchor_file_changed";

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

/// One accepted operator anchor, with what its log line and audit record carry.
#[derive(Debug, Clone)]
pub struct Anchor {
    der: Vec<u8>,
    /// SHA-256 of the DER certificate.
    pub sha256: [u8; 32],
    /// The certificate's subject, as text.
    pub subject: String,
    /// The certificate's issuer, as text.
    pub issuer: String,
    /// `notAfter`, Unix seconds.
    pub not_after: i64,
    /// `global` or `destinations[<i>] (<match>)`.
    pub scope: String,
    /// The key it was read from: `advanced.tls.trust_anchors[<i>]` or
    /// `advanced.tls.destinations[<i>].trust_anchors[<j>]`.
    pub key: String,
    /// The file it was read from, and that file's SHA-256 when read, for the drift check.
    file: Option<(PathBuf, [u8; 32])>,
}

impl Anchor {
    /// The fingerprint, `sha256:<hex>`.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        format!("sha256:{}", hex(&self.sha256))
    }
}

/// How a destination entry matches a dial.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Matcher {
    /// An exact host name.
    Host(String),
    /// `*.domain`: any name under `.domain`, never the apex (held with its leading dot).
    Under(String),
    /// An IP or a CIDR: only a dial of an IP literal.
    Net(IpAddr, u8),
}

impl Matcher {
    fn matches(&self, host: &Dialled) -> bool {
        match (self, host) {
            (Self::Host(h), Dialled::Name(n)) => h == n,
            (Self::Under(d), Dialled::Name(n)) => n.ends_with(d.as_str()),
            (Self::Net(net, len), Dialled::Ip(ip)) => covers(*net, *len, *ip),
            _ => false,
        }
    }
}

/// The dialled host, normalized the one way every entry is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Dialled {
    Name(String),
    Ip(IpAddr),
}

/// One `advanced.tls.destinations` entry, validated.
#[derive(Debug)]
struct Entry {
    shown: String,
    matcher: Matcher,
    anchors: Vec<Anchor>,
    include_roots: bool,
    pins: Vec<[u8; 32]>,
    identity: Option<(Vec<CertificateDer<'static>>, Arc<PrivateKeyDer<'static>>)>,
    plaintext: bool,
}

/// Why a dial has no client TLS configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustRefusal {
    /// `roots: none` and nothing else applies to this destination (BUSBAR-3140).
    NoAnchors(String),
    /// Every anchor of the matching entries was withdrawn because it expired (BUSBAR-5048).
    Withdrawn(String),
    /// The configuration could not be built (a key pin or identity rustls refuses).
    Build(String),
}

impl std::fmt::Display for TrustRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAnchors(host) => write!(
                f,
                "{}: no trust anchor applies to `{host}`: advanced.tls.roots is `none` and neither \
                 advanced.tls.trust_anchors nor a matching advanced.tls.destinations entry lists one",
                diag::CONFIG_TLS_TRUST_EMPTY.banner()
            ),
            Self::Withdrawn(host) => write!(
                f,
                "{}: every trust anchor of the advanced.tls.destinations entries matching `{host}` \
                 has expired and was withdrawn; rotate the CA and restart",
                diag::EGRESS_TLS_ANCHOR_EXPIRED_WITHDRAWN.banner()
            ),
            Self::Build(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for TrustRefusal {}

/// The base set, as loaded.
#[derive(Debug, Clone)]
struct Base {
    roots: TlsRoots,
    anchors: Vec<rustls::pki_types::TrustAnchor<'static>>,
    /// SHA-256 over the sorted set, hex.
    digest: String,
    /// Where `system` read from.
    source: Option<String>,
    /// System certificates dropped (expired, not a CA, unparsable), with one reason each.
    dropped: Vec<String>,
}

/// THE TRUST STORE.
#[derive(Debug)]
pub struct TrustStore {
    default: bool,
    base: Base,
    global: Vec<Anchor>,
    entries: Vec<Entry>,
    withdrawn: RwLock<HashSet<[u8; 32]>>,
    generation: std::sync::atomic::AtomicU64,
    cache: Mutex<HashMap<(Vec<usize>, u64), Arc<rustls::ClientConfig>>>,
    warned: Mutex<HashMap<[u8; 32], SystemTime>>,
    changed: Mutex<HashSet<PathBuf>>,
}

/// What reading the environment answers, injectable for tests.
pub type EnvFn<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The process environment.
#[must_use]
pub fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
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
        Ok(Self {
            default: cfg.is_default(),
            base,
            global,
            entries,
            withdrawn: RwLock::default(),
            generation: std::sync::atomic::AtomicU64::new(0),
            cache: Mutex::default(),
            warned: Mutex::default(),
            changed: Mutex::default(),
        })
    }

    /// Whether the deployment wrote nothing: dials use the connector's bundled-roots config, so
    /// every byte on the wire is what it was before the store existed.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.default
    }

    /// Every accepted operator anchor (global, then per destination).
    pub fn anchors(&self) -> impl Iterator<Item = &Anchor> {
        self.global
            .iter()
            .chain(self.entries.iter().flat_map(|e| e.anchors.iter()))
    }

    /// Whether an entry admits plaintext to exactly `host` (a name or an IP literal).
    #[must_use]
    pub fn plaintext_admitted(&self, host: &str) -> bool {
        let Some(d) = dialled(host) else {
            return false;
        };
        self.entries
            .iter()
            .any(|e| e.plaintext && e.matcher.matches(&d))
    }

    /// The entries matching `host`, as written (for a refusal's or a failure's record).
    #[must_use]
    pub fn matched(&self, host: &str) -> Vec<String> {
        let Some(d) = dialled(host) else {
            return Vec::new();
        };
        self.entries
            .iter()
            .filter(|e| !e.plaintext && e.matcher.matches(&d))
            .map(|e| e.shown.clone())
            .collect()
    }

    /// The fingerprints of the operator anchors in force for `host` (never the base set's).
    #[must_use]
    pub fn fingerprints_for(&self, host: &str) -> Vec<String> {
        let withdrawn = self.withdrawn.read().expect("withdrawn");
        let Some(d) = dialled(host) else {
            return Vec::new();
        };
        let matched: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| !e.plaintext && e.matcher.matches(&d))
            .collect();
        let own = matched.iter().flat_map(|e| e.anchors.iter());
        let replaces = matched.iter().any(|e| !e.anchors.is_empty())
            && !matched.iter().any(|e| e.include_roots);
        let global: Box<dyn Iterator<Item = &Anchor>> = if replaces {
            Box::new(std::iter::empty())
        } else {
            Box::new(self.global.iter())
        };
        own.chain(global)
            .filter(|a| !withdrawn.contains(&a.sha256))
            .map(Anchor::fingerprint)
            .collect()
    }

    /// THE CLIENT CONFIG for a dial of `host` (the guard-judged host: a name, or an IP literal,
    /// bracketed or not, with or without a port). `None` = the store is the default and the
    /// connector's own bundled-roots config applies.
    pub fn config_for(
        &self,
        host: &str,
    ) -> Result<Option<Arc<rustls::ClientConfig>>, TrustRefusal> {
        if self.default {
            return Ok(None);
        }
        let d = dialled(host).ok_or_else(|| TrustRefusal::NoAnchors(host.to_owned()))?;
        let matched: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.plaintext && e.matcher.matches(&d))
            .map(|(i, _)| i)
            .collect();
        let generation = self.generation.load(std::sync::atomic::Ordering::Acquire);
        let key = (matched.clone(), generation);
        if let Some(hit) = self.cache.lock().expect("tls cache").get(&key) {
            return Ok(Some(Arc::clone(hit)));
        }
        let config = Arc::new(self.build_for(host, &matched)?);
        self.cache
            .lock()
            .expect("tls cache")
            .insert(key, Arc::clone(&config));
        Ok(Some(config))
    }

    fn build_for(
        &self,
        host: &str,
        matched: &[usize],
    ) -> Result<rustls::ClientConfig, TrustRefusal> {
        let withdrawn = self.withdrawn.read().expect("withdrawn").clone();
        let entries: Vec<&Entry> = matched.iter().map(|i| &self.entries[*i]).collect();
        let listed: Vec<&Anchor> = entries.iter().flat_map(|e| e.anchors.iter()).collect();
        let replaces = !listed.is_empty() && !entries.iter().any(|e| e.include_roots);
        let mut roots = rustls::RootCertStore::empty();
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
            return Err(TrustRefusal::Withdrawn(host.to_owned()));
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
        if roots.is_empty() {
            return Err(TrustRefusal::NoAnchors(host.to_owned()));
        }
        let pins: Vec<[u8; 32]> = entries
            .iter()
            .flat_map(|e| e.pins.iter().copied())
            .collect();
        let pinned = if pins.is_empty() {
            None
        } else {
            Some(
                crate::tls::client::PinnedKeyVerifier::try_new(roots.clone(), &pins)
                    .map_err(TrustRefusal::Build)?,
            )
        };
        let identity = entries.iter().find_map(|e| e.identity.as_ref());
        busbar_contract::crypto::tls::client_config(|builder| {
            let wants = match pinned {
                None => builder.with_root_certificates(roots),
                Some(verifier) => builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier)),
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

/// The host of `target` (`host`, `host:port`, `[v6]:port`, a URL), without port or brackets.
#[must_use]
pub fn host_only(target: &str) -> String {
    match dialled(target) {
        Some(Dialled::Ip(ip)) => ip.to_string(),
        Some(Dialled::Name(n)) => n,
        None => target.to_owned(),
    }
}

/// The dialled host of `target` (`host`, `host:port`, `[v6]:port`, a URL authority), normalized.
fn dialled(target: &str) -> Option<Dialled> {
    let t = target.trim();
    let t = t.split_once("://").map_or(t, |(_, rest)| rest);
    let t = t.split(['/', '?', '#']).next().unwrap_or(t);
    let host = if let Some(inner) = t.strip_prefix('[') {
        inner.split_once(']').map_or(inner, |(h, _)| h)
    } else if t.matches(':').count() == 1 {
        t.split_once(':').map_or(t, |(h, _)| h)
    } else {
        t
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(Dialled::Ip(ip));
    }
    let name = fold_name(host)?;
    Some(Dialled::Name(name))
}

/// A name, lowercased, without its trailing dot, in its ASCII (IDNA) form.
fn fold_name(host: &str) -> Option<String> {
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

fn covers(net: IpAddr, len: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = if len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(len))
            };
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(len))
            };
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
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
        let d = fold_name(domain).ok_or_else(bad)?;
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
    let n = fold_name(w).ok_or_else(bad)?;
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
    if d.plaintext {
        let exact = matches!(m, Matcher::Host(_))
            || matches!(m, Matcher::Net(ip, len) if len == if ip.is_ipv4() { 32 } else { 128 });
        if !exact {
            errors.push(format!(
                "{}: advanced.tls.destinations[{i}]: `plaintext: true` is accepted only on an exact \
                 host or IP, never on a wildcard or a CIDR (`{}`)",
                diag::CONFIG_PLAINTEXT_ENTRY_NOT_EXACT.banner(),
                d.matches.trim()
            ));
        }
        if !d.trust_anchors.is_empty()
            || d.include_roots
            || !d.pin_spki_sha256.is_empty()
            || d.client_identity.is_some()
        {
            errors.push(format!(
                "{}: advanced.tls.destinations[{i}]: a `plaintext: true` entry admits plaintext only; \
                 it cannot also list trust_anchors, include_roots, pin_spki_sha256 or \
                 client_identity (write a separate entry for TLS settings)",
                diag::CONFIG_TLS_DESTINATION_INVALID.banner()
            ));
        }
    }
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
        plaintext: d.plaintext,
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
        let mut probe = rustls::RootCertStore::empty();
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
            match webpki::anchor_from_trusted_cert(&cert) {
                Ok(a) => anchors.push(a.to_owned()),
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

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
