// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLIENT ADDRESS: who sent a request, as far as busbar can honestly tell.
//!
//! The listener stamps every request with the socket peer ([`ClientAddr`]). Forwarding headers are
//! read only when that peer is a configured trusted proxy (`advanced.trusted_proxies`), only the one
//! header `advanced.forwarded_header` names, right to left past trusted hops. A source busbar cannot
//! tell is UNKNOWN, never "the proxy": a private peer that forwards for others while no proxy is
//! configured would otherwise put every user behind it in one bucket.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use axum::http::HeaderMap;
use busbar_contract::net::IpNet;

/// The socket peer of the connection a request arrived on, stamped by the listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddr(pub SocketAddr);

/// The one forwarding header honoured from a trusted proxy (`advanced.forwarded_header`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardedHeader {
    /// `X-Forwarded-For` (the default).
    #[default]
    XForwardedFor,
    /// RFC 7239 `Forwarded` (its `for=` parameters).
    Forwarded,
}

impl ForwardedHeader {
    /// The configured spelling, or `None` for an unknown one.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim();
        if name.eq_ignore_ascii_case("x-forwarded-for") {
            Some(Self::XForwardedFor)
        } else if name.eq_ignore_ascii_case("forwarded") {
            Some(Self::Forwarded)
        } else {
            None
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::XForwardedFor => "x-forwarded-for",
            Self::Forwarded => "forwarded",
        }
    }
}

/// `advanced.trusted_proxies` and `advanced.forwarded_header`, resolved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies {
    /// The proxies' networks (the outbound guard's CIDR reader).
    pub nets: Vec<IpNet>,
    /// The header read from them.
    pub header: ForwardedHeader,
}

impl TrustedProxies {
    // `read` (configuration time) is in `crate::off_path::auth::login`.

    fn trusts(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.covers(ip))
    }
}

/// Who sent a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSource {
    /// This address (canonical: an IPv4-mapped IPv6 address is its IPv4 address).
    Known(IpAddr),
    /// busbar cannot tell; per-source limits do not apply.
    Unknown(UnknownSource),
}

/// Why a source is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownSource {
    /// The request carries no [`ClientAddr`] (an embedded or test server).
    NoPeer,
    /// A private or loopback peer forwards for others, and no trusted proxy is configured.
    UnconfiguredProxy,
    /// A trusted proxy forwarded a hop that is not an address (`unknown`, `_hidden`, garbage).
    Unparseable,
}

/// The canonical form an address is grouped under.
#[must_use]
pub fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Resolve the client of a request whose socket peer is `peer`.
#[must_use]
pub fn client_source(
    peer: Option<IpAddr>,
    headers: &HeaderMap,
    trusted: &TrustedProxies,
) -> ClientSource {
    let Some(peer) = peer.map(canonical) else {
        return ClientSource::Unknown(UnknownSource::NoPeer);
    };
    if !trusted.trusts(peer) {
        let forwards = headers.contains_key("x-forwarded-for") || headers.contains_key("forwarded");
        if trusted.nets.is_empty() && forwards && busbar_contract::net::ip_is_internal(&peer) {
            return ClientSource::Unknown(UnknownSource::UnconfiguredProxy);
        }
        return ClientSource::Known(peer);
    }
    let mut nearest = peer;
    for hop in forwarded_hops_nearest_first(headers, trusted.header) {
        let Some(ip) = hop.map(canonical) else {
            return ClientSource::Unknown(UnknownSource::Unparseable);
        };
        if !trusted.trusts(ip) {
            return ClientSource::Known(ip);
        }
        nearest = ip;
    }
    ClientSource::Known(nearest)
}

/// Every hop the header states, NEAREST FIRST: right to left across all its lines, the last line
/// first (the reverse of the order the header states them); `None` for a hop that is not an
/// address, and one `None` for a line that is not text.
fn forwarded_hops_nearest_first(
    headers: &HeaderMap,
    header: ForwardedHeader,
) -> impl Iterator<Item = Option<IpAddr>> + '_ {
    headers
        .get_all(header.name())
        .into_iter()
        .rev()
        .flat_map(move |line| {
            let text = line.to_str().ok();
            let unreadable = text.is_none().then_some(None);
            let xff = text
                .filter(|_| header == ForwardedHeader::XForwardedFor)
                .into_iter()
                .flat_map(|line| {
                    line.split(',')
                        .rev()
                        .map(str::trim)
                        .filter(|h| !h.is_empty())
                        .map(node_address)
                });
            let forwarded = text
                .filter(|_| header == ForwardedHeader::Forwarded)
                .into_iter()
                .flat_map(|line| {
                    line.split(',')
                        .rev()
                        .filter_map(forwarded_for)
                        .map(|v| node_address(v.trim_matches('"')))
                });
            unreadable.into_iter().chain(xff).chain(forwarded)
        })
}

/// The `for=` parameter of one RFC 7239 `Forwarded` element.
fn forwarded_for(element: &str) -> Option<&str> {
    element.split(';').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        k.trim().eq_ignore_ascii_case("for").then_some(v.trim())
    })
}

/// One hop: an IP, `v4:port`, `[v6]` or `[v6]:port`.
fn node_address(hop: &str) -> Option<IpAddr> {
    let hop = hop.trim();
    if let Ok(ip) = hop.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some(rest) = hop.strip_prefix('[') {
        let (inner, _) = rest.split_once(']')?;
        return inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    let (host, port) = hop.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    host.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

/// One per-source bucket: an IPv4 address, or an IPv6 network at one of the aggregate prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceBucket {
    /// One IPv4 address.
    V4(Ipv4Addr),
    /// An IPv6 network: its prefix length and network address.
    V6(u8, Ipv6Addr),
}

impl SourceBucket {
    /// The base bucket of `ip`: the address (IPv4) or its /64 (IPv6).
    #[must_use]
    pub fn base(ip: IpAddr) -> Self {
        match canonical(ip) {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => Self::v6(v6, 64),
        }
    }

    fn v6(v6: Ipv6Addr, len: u8) -> Self {
        match IpNet::masked(IpAddr::V6(v6), len) {
            IpAddr::V6(net) => Self::V6(len, net),
            IpAddr::V4(_) => unreachable!("masking keeps the family"),
        }
    }

    /// The base bucket and, for IPv6, its /48 and /32 aggregates.
    pub fn hierarchy(ip: IpAddr) -> impl Iterator<Item = Self> {
        let aggregates = match canonical(ip) {
            IpAddr::V4(_) => None,
            IpAddr::V6(v6) => Some([Self::v6(v6, 48), Self::v6(v6, 32)]),
        };
        std::iter::once(Self::base(ip)).chain(aggregates.into_iter().flatten())
    }

    /// How this bucket is named in logs and audit (an address or `net/len`).
    #[must_use]
    pub fn label(&self) -> String {
        crate::cold::auth::login::source_label(self)
    }
}

#[cfg(test)]
#[path = "../tests/login_limits_source_tests.rs"]
mod tests;
