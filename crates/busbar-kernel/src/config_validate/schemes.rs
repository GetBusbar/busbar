// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The scheme table: core's own answer to which carrier a provider destination's URL scheme is dialled over.
//!
//! One table, four rows, owned by core and not by any plugin: whether the scheme is secured, its default port, the
//! carrier `CARRIER_DEFAULT` means for it, and the carriers a plane may name explicitly instead. Any other scheme
//! has no row and is refused. A pure function of the scheme word; it opens nothing and reads no configuration.
//!
//! The carrier numbers are `busbar_plugin_abi::plane`'s; the number this module returns is what
//! `Carriers::get` in the root takes. WebRTC has no destination URL (an association is reached through its
//! rendezvous) and a child process is `upstreams.<name>.command`: neither has a scheme row, so the table is not
//! consulted for them.

use busbar_plugin_abi::plane::{CARRIER_DEFAULT, CARRIER_GRPC, CARRIER_HTTP, CARRIER_WEBSOCKET};

/// One row of the table, for a scheme that has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialScheme {
    /// Whether the destination is secured (TLS). Intent, as `ProviderDestination::secure` is.
    pub secured: bool,
    /// The port a destination without an explicit one is dialled on.
    pub default_port: u16,
    /// The carrier `CARRIER_DEFAULT` means for this scheme.
    default_carrier: u32,
    /// The carriers a plane may name explicitly for this scheme (always includes the default).
    allowed: &'static [u32],
}

/// Why a destination or an explicit carrier choice is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemeRefused {
    /// The destination has no `scheme://` part.
    Missing,
    /// The scheme has no row: it names no carrier core dials.
    Unknown(String),
    /// A plane named a carrier this scheme does not allow (a plane fault, refused at the exchange).
    CarrierNotAllowed {
        /// The scheme, lower case.
        scheme: &'static str,
        /// The carrier number the plane named.
        carrier: u32,
    },
}

impl std::fmt::Display for SchemeRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(
                f,
                "the destination has no scheme: it must begin with one of {ACCEPTED}"
            ),
            Self::Unknown(scheme) => write!(
                f,
                "scheme `{scheme}` is not one core dials: the accepted schemes are {ACCEPTED}"
            ),
            Self::CarrierNotAllowed { scheme, carrier } => write!(
                f,
                "carrier {carrier} cannot carry a `{scheme}` destination: the plane's exchange is refused"
            ),
        }
    }
}

const ACCEPTED: &str = "`http`, `https`, `ws` and `wss`";

const HTTP: DialScheme = DialScheme {
    secured: false,
    default_port: 80,
    default_carrier: CARRIER_HTTP,
    allowed: &[CARRIER_HTTP, CARRIER_GRPC],
};
const HTTPS: DialScheme = DialScheme {
    secured: true,
    default_port: 443,
    ..HTTP
};
const WS: DialScheme = DialScheme {
    secured: false,
    default_port: 80,
    default_carrier: CARRIER_WEBSOCKET,
    allowed: &[CARRIER_WEBSOCKET],
};
const WSS: DialScheme = DialScheme {
    secured: true,
    default_port: 443,
    ..WS
};

/// The row for a scheme word, or the refusal. Schemes compare case-insensitively (the same rule as an
/// `upstreams.<name>.url`), so an existing configuration's `HTTPS://` is not refused for its spelling.
pub fn dial_scheme(scheme: &str) -> Result<DialScheme, SchemeRefused> {
    const ROWS: [(&str, DialScheme); 4] =
        [("http", HTTP), ("https", HTTPS), ("ws", WS), ("wss", WSS)];
    ROWS.iter()
        .find(|(word, _)| scheme.eq_ignore_ascii_case(word))
        .map(|(_, row)| *row)
        .ok_or_else(|| SchemeRefused::Unknown(scheme.to_owned()))
}

/// The row for a destination URL: its scheme is the text before the first `://`.
pub fn dial_scheme_of_url(url: &str) -> Result<DialScheme, SchemeRefused> {
    let (scheme, _) = url.split_once("://").ok_or(SchemeRefused::Missing)?;
    dial_scheme(scheme)
}

impl DialScheme {
    /// The carrier for a plane's choice: `CARRIER_DEFAULT` resolves to this scheme's default, an explicit carrier
    /// must be one the scheme allows. The result is never 0, so it is safe to hand to `Carriers::get`.
    pub fn carrier(&self, named: u32) -> Result<u32, SchemeRefused> {
        if named == CARRIER_DEFAULT {
            return Ok(self.default_carrier);
        }
        if self.allowed.contains(&named) {
            return Ok(named);
        }
        Err(SchemeRefused::CarrierNotAllowed {
            scheme: self.word(),
            carrier: named,
        })
    }

    fn word(&self) -> &'static str {
        match (self.secured, self.default_carrier == CARRIER_WEBSOCKET) {
            (false, false) => "http",
            (true, false) => "https",
            (false, true) => "ws",
            (true, true) => "wss",
        }
    }
}

#[cfg(test)]
#[path = "tests/schemes_tests.rs"]
mod tests;
