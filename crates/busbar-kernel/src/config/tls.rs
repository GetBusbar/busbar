// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND TLS TRUST STORE, as a deployment states it (`advanced.tls`).
//!
//! One store for every outbound TLS connection busbar makes, through the one connector:
//!
//! * `roots`: the base set, `bundled` (default: the Mozilla set busbar ships, 1.5.5 parity),
//!   `system` (the operating system's CA bundle file, read once at boot) or `none`.
//! * `trust_anchors`: CAs trusted for every destination, on top of `roots`.
//! * `destinations`: per-destination entries selected by the host the destination guard judged
//!   for the dial (never by a name a plugin offers). A matching entry's anchors REPLACE the base
//!   set and `trust_anchors` for that dial unless it sets `include_roots: true`. An entry may also
//!   pin the far end's key, present a client identity, or admit plaintext to an exact host.
//!
//! There is no key that disables certificate or host-name verification, and none is reserved.
//! BOOT-TIME: the connector builds the store once; a changed anchor file takes effect at restart.

use serde::{Deserialize, Serialize};

/// `advanced.tls`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundTlsCfg {
    /// The base set: `bundled` (default), `system` or `none`.
    #[serde(default)]
    pub roots: TlsRoots,
    /// CAs trusted for every destination, on top of `roots`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_anchors: Vec<TlsSource>,
    /// Per-destination entries, matched against the guard-judged dial host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<TlsDestinationCfg>,
}

impl OutboundTlsCfg {
    /// Whether the deployment wrote nothing: the bundled roots alone, 1.5.5's posture.
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// The exact hosts and IPs an entry admits plaintext to (`plaintext: true`), as written.
    #[must_use]
    pub fn plaintext_hosts(&self) -> Vec<String> {
        self.destinations
            .iter()
            .filter(|d| d.plaintext)
            .map(|d| d.matches.clone())
            .collect()
    }
}

/// `advanced.proxy_resolution`: who resolves a target's name when an outbound proxy
/// (`HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`) carries the connection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyResolution {
    /// busbar resolves the target, the destination guard judges every address it answers, and the
    /// CONNECT names the judged address: the guard is the boundary behind the proxy too. A name
    /// that does not resolve here is refused.
    #[default]
    Local,
    /// The CONNECT names the target by name. When the name resolves here its addresses are still
    /// judged; when it does not, the address check is the proxy's (split-horizon DNS). BUSBAR-3149
    /// says so at boot.
    Proxy,
}

/// `advanced.tls.roots`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsRoots {
    /// The Mozilla root set busbar ships (`webpki-roots`): 1.5.5's provider TLS roots.
    #[default]
    Bundled,
    /// The operating system's CA bundle (`SSL_CERT_FILE` / `SSL_CERT_DIR` when set, else the
    /// distribution's bundle file), read once at boot.
    System,
    /// No base set: only `trust_anchors` and matching `destinations` anchors are trusted.
    None,
}

impl TlsRoots {
    /// The spelling an operator writes.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bundled => "bundled",
            Self::System => "system",
            Self::None => "none",
        }
    }
}

/// Where one PEM document comes from: a file, an environment variable, or inline text.
///
/// A secret-store reference is refused: the trust store is built before any secret plugin can be
/// reached (a vault's own CA would have to come from the vault), and a CA is public material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum TlsSource {
    /// `{ file: <path> }`: read at boot (and digested by the hourly sweep).
    File(String),
    /// `{ env: <NAME> }`: read at boot.
    Env(String),
    /// Inline PEM text.
    Inline(String),
}

impl TlsSource {
    /// A short, secret-free description: the path, the variable name, or `inline`.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::File(p) => format!("file {p}"),
            Self::Env(n) => format!("env {n}"),
            Self::Inline(_) => "inline".to_owned(),
        }
    }
}

impl<'de> Deserialize<'de> for TlsSource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let value = serde_yaml::Value::deserialize(d)?;
        match value {
            serde_yaml::Value::String(pem) => Ok(Self::Inline(pem)),
            serde_yaml::Value::Mapping(map) => {
                let mut entries = map.into_iter();
                let (Some((k, v)), None) = (entries.next(), entries.next()) else {
                    return Err(D::Error::custom(
                        "a TLS source is `{ file: <path> }`, `{ env: <NAME> }` or inline PEM text",
                    ));
                };
                let key = k.as_str().unwrap_or_default().to_owned();
                let text = v.as_str().map(str::to_owned);
                match (key.as_str(), text) {
                    ("file", Some(p)) if !p.trim().is_empty() => Ok(Self::File(p)),
                    ("env", Some(n)) if !n.trim().is_empty() => Ok(Self::Env(n)),
                    ("file" | "env", _) => Err(D::Error::custom(format!(
                        "a TLS source's `{key}` must be a non-empty string"
                    ))),
                    _ => Err(D::Error::custom(format!(
                        "a TLS source is `{{ file: <path> }}`, `{{ env: <NAME> }}` or inline PEM \
                         text; `{key}` is not accepted (a secret-store reference cannot feed the \
                         trust store: it is built before any secret plugin is reachable)"
                    ))),
                }
            }
            _ => Err(D::Error::custom(
                "a TLS source is `{ file: <path> }`, `{ env: <NAME> }` or inline PEM text",
            )),
        }
    }
}

/// One `advanced.tls.destinations` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsDestinationCfg {
    /// An exact host, a `*.domain` wildcard (names under it, never the apex), an IP or a CIDR.
    /// Name entries match a dial of a name; IP and CIDR entries match only a dial of an IP literal.
    #[serde(rename = "match")]
    pub matches: String,
    /// The CAs this destination is verified against. They REPLACE `roots` and the global
    /// `trust_anchors` for a matching dial unless `include_roots` is set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_anchors: Vec<TlsSource>,
    /// Trust `roots` and the global `trust_anchors` as well as this entry's anchors.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub include_roots: bool,
    /// SHA-256 pins of the far end's SubjectPublicKeyInfo (`sha256/<base64>`), checked on top of
    /// ordinary chain and name verification, never instead of it.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "one_or_many"
    )]
    pub pin_spki_sha256: Vec<String>,
    /// The client certificate busbar presents to this destination when it asks for one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_identity: Option<TlsClientIdentityCfg>,
    /// Admit plaintext (no TLS) to this destination. Accepted only on an exact host or IP, never
    /// with anchors, a pin or a client identity. Credentials are never sent in clear to a host that
    /// is not loopback, whatever this says.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub plaintext: bool,
}

/// A client identity: the certificate chain (leaf first) and its private key, each a PEM source.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsClientIdentityCfg {
    /// The certificate chain, PEM, leaf first.
    pub cert: TlsSource,
    /// The private key, PEM (PKCS#8, PKCS#1 or SEC1). Read by core at boot and never handed to a
    /// plugin.
    pub key: TlsSource,
}

fn one_or_many<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    })
}

#[cfg(test)]
#[path = "tests/tls_cfg_tests.rs"]
mod tests;
