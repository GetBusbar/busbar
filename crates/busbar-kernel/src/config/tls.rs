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
        use busbar_contract::yaml::{Value, ValueExt as _};
        use serde::de::Error as _;
        let value = busbar_contract::yaml::untyped(d)?;
        match value {
            Value::Text(pem) => Ok(Self::Inline(pem)),
            Value::Map(map) => {
                // A key other than `file` or `env` (a secret-store reference's `module`,
                // `settings`) is named, however many entries the map holds.
                if let Some(key) = map
                    .iter()
                    .filter_map(|(k, _)| k.as_str())
                    .find(|k| !matches!(*k, "file" | "env"))
                {
                    return Err(D::Error::custom(format!(
                        "a TLS source is `{{ file: <path> }}`, `{{ env: <NAME> }}` or inline PEM \
                         text; `{key}` is not accepted (a secret-store reference cannot feed the \
                         trust store: it is built before any secret plugin is reachable)"
                    )));
                }
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

/// One `advanced.tls.destinations` entry. Parsed through [`RawTlsDestinationCfg`]: a `plaintext: true` entry and a
/// `verify: pin` entry with no pins are refused at parse (TRANSPORT-SECURITY-POLICY §3, §6).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "RawTlsDestinationCfg")]
pub struct TlsDestinationCfg {
    /// An exact host, a `*.domain` wildcard (names under it, never the apex), an IP or a CIDR.
    /// Name entries match a dial of a name; IP and CIDR entries match only a dial of an IP literal.
    #[serde(rename = "match")]
    pub matches: String,
    /// The CAs this destination is verified against. They REPLACE `roots` and the global
    /// `trust_anchors` for a matching dial unless `include_roots` is set.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub trust_anchors: Vec<TlsSource>,
    /// Trust `roots` and the global `trust_anchors` as well as this entry's anchors.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub include_roots: bool,
    /// SHA-256 pins of the far end's SubjectPublicKeyInfo (`sha256/<base64>`). Without `verify: pin` they are
    /// checked on top of ordinary chain and name verification.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pin_spki_sha256: Vec<String>,
    /// `verify: pin`: the far end is trusted by its pinned key alone, so a private or self-signed server needs no
    /// CA. Requires at least one pin. Absent = ordinary chain and name verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<TlsVerify>,
    /// The client certificate busbar presents to this destination when it asks for one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_identity: Option<TlsClientIdentityCfg>,
}

/// `advanced.tls.destinations[].verify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsVerify {
    /// Trust the far end by its pinned SubjectPublicKeyInfo.
    Pin,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTlsDestinationCfg {
    #[serde(rename = "match")]
    matches: String,
    #[serde(default)]
    trust_anchors: Vec<TlsSource>,
    #[serde(default)]
    include_roots: bool,
    #[serde(default, deserialize_with = "one_or_many")]
    pin_spki_sha256: Vec<String>,
    #[serde(default)]
    verify: Option<TlsVerify>,
    #[serde(default)]
    client_identity: Option<TlsClientIdentityCfg>,
    /// Parsed only to refuse `plaintext: true` with the replacement named; never carried into the config.
    #[serde(default, deserialize_with = "plaintext_refused")]
    _plaintext: bool,
}

impl TryFrom<RawTlsDestinationCfg> for TlsDestinationCfg {
    type Error = String;

    fn try_from(raw: RawTlsDestinationCfg) -> Result<Self, String> {
        if raw.verify == Some(TlsVerify::Pin) && raw.pin_spki_sha256.is_empty() {
            return Err(format!(
                "advanced.tls.destinations entry `{}` sets `verify: pin` but lists no `pin_spki_sha256` pin",
                raw.matches
            ));
        }
        Ok(Self {
            matches: raw.matches,
            trust_anchors: raw.trust_anchors,
            include_roots: raw.include_roots,
            pin_spki_sha256: raw.pin_spki_sha256,
            verify: raw.verify,
            client_identity: raw.client_identity,
        })
    }
}

/// `plaintext: false` parses; `plaintext: true` is refused, naming the replacement.
fn plaintext_refused<'de, D: serde::Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    use serde::de::Error as _;
    if bool::deserialize(d)? {
        return Err(D::Error::custom(
            "`plaintext` on an `advanced.tls.destinations` entry is refused: set `insecure_transport: { accept: plaintext, reason: \"...\" }` on the instance that needs it",
        ));
    }
    Ok(false)
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
