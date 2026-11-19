// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND TLS TRUST STORE (`outbound.tls`): one place that decides which certificate
//! authorities, key pins and client identity an outbound TLS connection uses.
//!
//! * It is built once at boot from the operator's `OutboundTlsCfg`. Every operator anchor must parse, hold only
//!   certificates, be an X.509 v3 CA (`basicConstraints CA:TRUE`, `keyCertSign` when `keyUsage` is
//!   present), be inside its validity window (`notBefore` with five minutes' tolerance) and be
//!   accepted by rustls; anything else refuses the boot (BUSBAR-3137).
//! * A dial is matched by the host the destination guard judged for it (never by a name a plugin
//!   offers, never by a proxy hop). A matching entry's anchors REPLACE the base set unless it sets
//!   `include_roots`; several matching entries trust the union of their anchors.
//! * Verification is always on. Pins narrow it; nothing widens or skips it.
//! * [`TrustStore::sweep`] (hourly) withdraws an anchor past `notAfter` from new connections,
//!   repeats the 30-day expiry warning once a day, and warns when an anchor file changed on disk.

use std::borrow::Cow;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use busbar_kernel::config::tls::TlsRoots;
use busbar_kernel::diagnostics as diag;
use foldhash::{HashMap, HashSet};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// How often [`TrustStore::sweep`] runs.
pub const SWEEP_EVERY: Duration = Duration::from_secs(3600);

/// The longest host name (RFC 1035): a longer one names no destination entry.
const NAME_MAX: usize = 253;

/// One accepted operator anchor, with what its log line and audit record carry.
#[derive(Debug, Clone)]
pub struct Anchor {
    pub(crate) der: Vec<u8>,
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
    /// The key it was read from: `outbound.tls.trust_anchors[<i>]` or
    /// `outbound.tls.destinations[<i>].trust_anchors[<j>]`.
    pub key: String,
    /// The file it was read from, and that file's SHA-256 when read, for the drift check.
    pub(crate) file: Option<(PathBuf, [u8; 32])>,
}

/// How a destination entry matches a dial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Matcher {
    /// An exact host name (held lowercase).
    Host(String),
    /// `*.domain`: any name under `.domain`, never the apex (held lowercase with its leading dot).
    Under(String),
    /// An IP or a CIDR: only a dial of an IP literal.
    Net(IpAddr, u8),
}

impl Matcher {
    pub(crate) fn matches(&self, host: &Dialled<'_>) -> bool {
        match (self, host) {
            (Self::Host(h), Dialled::Name(n)) => h.eq_ignore_ascii_case(n),
            (Self::Under(d), Dialled::Name(n)) => {
                let (n, d) = (n.as_bytes(), d.as_bytes());
                n.len() >= d.len() && n[n.len() - d.len()..].eq_ignore_ascii_case(d)
            }
            (Self::Net(net, len), Dialled::Ip(ip)) => covers(*net, *len, *ip),
            _ => false,
        }
    }
}

/// The dialled host, normalized the one way every entry is (a name is compared ignoring ASCII
/// case).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Dialled<'a> {
    Name(Cow<'a, str>),
    Ip(IpAddr),
}

/// One `outbound.tls.destinations` entry, validated.
#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) shown: String,
    pub(crate) matcher: Matcher,
    pub(crate) anchors: Vec<Anchor>,
    pub(crate) include_roots: bool,
    pub(crate) pins: Vec<[u8; 32]>,
    pub(crate) identity: Option<(Vec<CertificateDer<'static>>, Arc<PrivateKeyDer<'static>>)>,
    pub(crate) plaintext: bool,
}

/// Why a dial has no client TLS configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustRefusal<'h> {
    /// The native Need supplied malformed identity material or requested identity under a waiver.
    InvalidNeed,
    /// `roots: none` and nothing else applies to this destination (BUSBAR-3140). The host is the
    /// caller's own, lent: a refusal copies no name.
    NoAnchors(&'h str),
    /// Every anchor of the matching entries was withdrawn because it expired (BUSBAR-5048). The
    /// host is the caller's own, lent.
    Withdrawn(&'h str),
    /// The configuration could not be built (a key pin or identity rustls refuses).
    Build(String),
}

impl std::fmt::Display for TrustRefusal<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNeed => f.write_str("invalid native TLS identity request"),
            Self::NoAnchors(host) => write!(
                f,
                "{}: no trust anchor applies to `{host}`: outbound.tls.roots is `none` and neither \
                 outbound.tls.trust_anchors nor a matching outbound.tls.destinations entry lists one",
                diag::CONFIG_TLS_TRUST_EMPTY.banner()
            ),
            Self::Withdrawn(host) => write!(
                f,
                "{}: every trust anchor of the outbound.tls.destinations entries matching `{host}` \
                 has expired and was withdrawn; rotate the CA and restart",
                diag::EGRESS_TLS_ANCHOR_EXPIRED_WITHDRAWN.banner()
            ),
            Self::Build(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for TrustRefusal<'_> {}

/// The base set, as loaded.
#[derive(Debug, Clone)]
pub(crate) struct Base {
    pub(crate) roots: TlsRoots,
    pub(crate) anchors: Vec<rustls::pki_types::TrustAnchor<'static>>,
    /// SHA-256 over the sorted set, hex.
    pub(crate) digest: String,
    /// Where `system` read from.
    pub(crate) source: Option<String>,
    /// System certificates dropped (expired, not a CA, unparsable), with one reason each.
    pub(crate) dropped: Vec<String>,
}

/// The host a client config is held for: a name (lowercase) or an IP.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CacheKey<'b> {
    Name(&'b str),
    Ip(IpAddr),
}

/// The client configs built so far, by the host they were built for; emptied when a withdrawal
/// changes what a build yields.
#[derive(Debug, Default)]
pub(crate) struct ConfigCache {
    pub(crate) names: HashMap<String, Arc<rustls::ClientConfig>>,
    pub(crate) ips: HashMap<IpAddr, Arc<rustls::ClientConfig>>,
}

impl ConfigCache {
    fn get(&self, key: &CacheKey<'_>) -> Option<&Arc<rustls::ClientConfig>> {
        match key {
            CacheKey::Name(name) => self.names.get(*name),
            CacheKey::Ip(ip) => self.ips.get(ip),
        }
    }
}

/// THE TRUST STORE.
#[derive(Debug)]
pub struct TrustStore {
    pub(crate) default: bool,
    pub(crate) base: Base,
    pub(crate) global: Vec<Anchor>,
    pub(crate) entries: Vec<Entry>,
    /// The exact host names plaintext is admitted to (an index of the plaintext entries).
    pub(crate) plain_names: HashSet<String>,
    /// The exact IPs plaintext is admitted to (an index of the plaintext entries).
    pub(crate) plain_ips: HashSet<IpAddr>,
    pub(crate) withdrawn: RwLock<HashSet<[u8; 32]>>,
    pub(crate) generation: std::sync::atomic::AtomicU64,
    pub(crate) cache: Mutex<ConfigCache>,
    pub(crate) warned: Mutex<HashMap<[u8; 32], SystemTime>>,
    pub(crate) changed: Mutex<HashSet<PathBuf>>,
}

/// What reading the environment answers, injectable for tests.
pub type EnvFn<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The process environment.
#[must_use]
pub fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

impl TrustStore {
    /// Current trust-withdrawal epoch for native connection/config reuse fences.
    #[must_use]
    pub fn withdrawal_epoch(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Whether operator policy supplies a client identity to this logical destination.
    #[must_use]
    pub fn has_client_identity(&self, host: &str) -> bool {
        dialled(host).is_some_and(|host| {
            self.entries.iter().any(|entry| {
                !entry.plaintext && entry.matcher.matches(&host) && entry.identity.is_some()
            })
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
        match dialled(host) {
            Some(Dialled::Ip(ip)) => self.plain_ips.contains(&ip),
            Some(Dialled::Name(name)) => {
                let mut buf = [0u8; NAME_MAX];
                lowered(&mut buf, &name).is_some_and(|key| self.plain_names.contains(key))
            }
            None => false,
        }
    }

    /// THE CLIENT CONFIG for a dial of `host` (the guard-judged host: a name, or an IP literal,
    /// bracketed or not, with or without a port). `None` = the store is the default and the
    /// connector's own bundled-roots config applies.
    pub fn config_for<'h>(
        &self,
        host: &'h str,
    ) -> Result<Option<Arc<rustls::ClientConfig>>, TrustRefusal<'h>> {
        if self.default {
            return Ok(None);
        }
        let Some(d) = dialled(host) else {
            return Err(TrustRefusal::NoAnchors(host));
        };
        let mut buf = [0u8; NAME_MAX];
        let key = match &d {
            Dialled::Name(name) => lowered(&mut buf, name).map(CacheKey::Name),
            Dialled::Ip(ip) => Some(CacheKey::Ip(*ip)),
        };
        if let Some(key) = &key {
            if let Some(hit) = self.cache.lock().expect("tls cache").get(key) {
                return Ok(Some(Arc::clone(hit)));
            }
        }
        self.config_miss(host, &d, key)
    }
}

/// `name` lowercased into `buf`, or `None` when no entry can hold it (longer than a host name).
fn lowered<'b>(buf: &'b mut [u8; NAME_MAX], name: &str) -> Option<&'b str> {
    let dst = buf.get_mut(..name.len())?;
    dst.copy_from_slice(name.as_bytes());
    dst.make_ascii_lowercase();
    std::str::from_utf8(dst).ok()
}

/// The dialled host of `target` (`host`, `host:port`, `[v6]:port`, a URL authority), normalized.
pub(crate) fn dialled(target: &str) -> Option<Dialled<'_>> {
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
    Some(Dialled::Name(fold_name(host)?))
}

/// A name without its trailing dot, in its ASCII (IDNA) form.
fn fold_name(host: &str) -> Option<Cow<'_, str>> {
    let h = host.strip_suffix('.').unwrap_or(host);
    if h.is_empty() {
        return None;
    }
    busbar_contract::net::url_host_to_ascii(h).ok()
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

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
