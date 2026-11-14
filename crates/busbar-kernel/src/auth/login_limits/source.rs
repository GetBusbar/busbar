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
        match name.trim().to_ascii_lowercase().as_str() {
            "x-forwarded-for" => Some(Self::XForwardedFor),
            "forwarded" => Some(Self::Forwarded),
            _ => None,
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
    /// Read the configured entries; the error names the first bad one.
    pub fn read(entries: &[String], header: Option<&str>) -> Result<Self, String> {
        let mut nets = Vec::with_capacity(entries.len());
        for (i, entry) in entries.iter().enumerate() {
            match IpNet::parse(entry) {
                Ok(net) => nets.push(net),
                Err(busbar_contract::net::IpNetError::HostBitsSet) => {
                    return Err(format!(
                    "advanced.trusted_proxies[{i}]: `{entry}` sets address bits past its prefix \
                         length; write the network address"
                ))
                }
                Err(busbar_contract::net::IpNetError::NotNetwork) => {
                    return Err(format!(
                        "advanced.trusted_proxies[{i}]: `{entry}` is not an IP address or a CIDR"
                    ))
                }
            }
        }
        let header = match header {
            None => ForwardedHeader::default(),
            Some(name) => ForwardedHeader::parse(name).ok_or_else(|| {
                format!(
                    "advanced.forwarded_header: `{name}` is not `x-forwarded-for` or `forwarded`"
                )
            })?,
        };
        Ok(Self { nets, header })
    }

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
    let hops = forwarded_hops(headers, trusted.header);
    let mut nearest = peer;
    for hop in hops.iter().rev() {
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

/// Every hop the header states, left to right, across all its lines in order; `None` for a hop
/// that is not an address.
fn forwarded_hops(headers: &HeaderMap, header: ForwardedHeader) -> Vec<Option<IpAddr>> {
    let mut hops = Vec::new();
    for line in headers.get_all(header.name()) {
        let Ok(line) = line.to_str() else {
            hops.push(None);
            continue;
        };
        match header {
            ForwardedHeader::XForwardedFor => {
                hops.extend(
                    line.split(',')
                        .map(str::trim)
                        .filter(|h| !h.is_empty())
                        .map(node_address),
                );
            }
            ForwardedHeader::Forwarded => {
                for element in line.split(',') {
                    let for_param = element.split(';').find_map(|pair| {
                        let (k, v) = pair.split_once('=')?;
                        k.trim().eq_ignore_ascii_case("for").then_some(v.trim())
                    });
                    if let Some(v) = for_param {
                        hops.push(node_address(v.trim_matches('"')));
                    }
                }
            }
        }
    }
    hops
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
    #[must_use]
    pub fn hierarchy(ip: IpAddr) -> Vec<Self> {
        match canonical(ip) {
            IpAddr::V4(v4) => vec![Self::V4(v4)],
            IpAddr::V6(v6) => vec![Self::v6(v6, 64), Self::v6(v6, 48), Self::v6(v6, 32)],
        }
    }

    /// How this bucket is named in logs and audit (an address or `net/len`).
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::V4(v4) => v4.to_string(),
            Self::V6(len, net) => format!("{net}/{len}"),
        }
    }
}

#[cfg(test)]
#[path = "../tests/login_limits_source_tests.rs"]
mod tests;
