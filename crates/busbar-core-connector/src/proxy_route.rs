// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROXY ROUTE CHOICE: which proxy, if any, a dial goes through (status row 130 E5a). The
//! connector reads the process environment into it once ([`crate::proxy`], the one parser) and
//! every dial it makes asks it. It is the connector's alone: it lived in `busbar-contract` while
//! the composition root handed the same value to the kernel's outbound engine, and moved here when
//! that engine was deleted (u30): the contract holds only cross-kind shapes.
//!
//! The rules are reqwest 0.12's implicit proxy environment, as 1.5.5 shipped them: a secured target
//! uses the secured slot and every other target the plain slot (each set from its own variable,
//! with the catch-all variable as the fallback for both), and the exemption list excludes a host
//! from both before either is read, with curl's rule set (host, domain suffix, IP literal, CIDR).

use std::net::IpAddr;
use std::sync::Arc;

/// ONE PROXY ENDPOINT: where to connect, and the `Proxy-Authorization` value its userinfo became.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyHop {
    host: String,
    port: u16,
    auth: Option<String>,
}

impl std::fmt::Debug for ProxyHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The credential is never rendered.
        f.debug_struct("ProxyHop")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth", &self.auth.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl ProxyHop {
    /// The endpoint `host:port`, presenting `auth` (the whole `Proxy-Authorization` value) when set.
    #[must_use]
    pub fn new(host: String, port: u16, auth: Option<String>) -> Self {
        Self { host, port, auth }
    }

    /// The proxy's host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The proxy's port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The `Proxy-Authorization` value, where the proxy's userinfo set one.
    #[must_use]
    pub fn proxy_authorization(&self) -> Option<&str> {
        self.auth.as_deref()
    }

    /// The proxy's own `host:port`, as a dial reaches it (a v6 host bracketed).
    #[must_use]
    pub fn endpoint(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// THE CHOICE: the secured slot, the plain slot, and the hosts exempt from both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyChoice {
    secured: Option<Arc<ProxyHop>>,
    plain: Option<Arc<ProxyHop>>,
    exempt: NoProxy,
}

impl ProxyChoice {
    /// The choice of a `secured` slot, a `plain` slot, and the exemption list `exempt` as its
    /// variable spells it (comma-separated entries).
    #[must_use]
    pub fn new(secured: Option<Arc<ProxyHop>>, plain: Option<Arc<ProxyHop>>, exempt: &str) -> Self {
        Self {
            secured,
            plain,
            exempt: NoProxy::parse(exempt),
        }
    }

    /// The per-dial choice — `None` → direct (the host is exempt, or no proxy is set for the
    /// target's slot), `Some` → tunnel through that proxy.
    #[must_use]
    pub fn select(&self, secured_target: bool, target_host: &str) -> Option<Arc<ProxyHop>> {
        if self.exempt.matches(target_host) {
            return None;
        }
        if secured_target {
            self.secured.clone()
        } else {
            self.plain.clone()
        }
    }

    /// Whether the exemption list excludes `target_host` from both slots.
    #[must_use]
    pub fn exempts(&self, target_host: &str) -> bool {
        self.exempt.matches(target_host)
    }
}

/// Parsed `NO_PROXY` entries, reqwest's full rule set (hyper-util `matcher::NoProxy`, which
/// documents itself as curl's rules): `*` matches everything; an IP literal matches exactly;
/// a CIDR block (`10.0.0.0/8`, `fd00::/8`) matches by containment; anything else is a domain
/// matched exactly or as a `.`-boundary suffix. Like reqwest, an IP-literal target host is
/// checked ONLY against the IP/CIDR entries and a domain host ONLY against the domain
/// entries.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NoProxy {
    entries: Vec<NoProxyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NoProxyEntry {
    MatchAll,
    /// Lowercased, leading dot stripped (`.google.com` ≡ `google.com`, per curl/reqwest).
    Domain(String),
    Ip(IpAddr),
    /// Network address + prefix length, validated ≤32 (v4) / ≤128 (v6) at parse.
    Cidr(IpAddr, u8),
}

impl NoProxy {
    /// Comma-separated entries, whitespace trimmed, empties dropped. Entry classification
    /// mirrors reqwest: try CIDR, then IP literal, then fall back to domain — a malformed
    /// CIDR (`10.0.0.0/40`) therefore degrades to a domain entry that never matches, exactly
    /// as `ipnet` parse failure does under reqwest, rather than aborting boot.
    fn parse(raw: &str) -> Self {
        let mut entries = Vec::new();
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if part == "*" {
                entries.push(NoProxyEntry::MatchAll);
                continue;
            }
            if let Some((addr, len)) = part.split_once('/') {
                if let (Ok(addr), Ok(len)) = (addr.parse::<IpAddr>(), len.parse::<u8>()) {
                    let max = if addr.is_ipv4() { 32 } else { 128 };
                    if len <= max {
                        entries.push(NoProxyEntry::Cidr(addr, len));
                        continue;
                    }
                }
            } else if let Ok(addr) = part.parse::<IpAddr>() {
                entries.push(NoProxyEntry::Ip(addr));
                continue;
            }
            entries.push(NoProxyEntry::Domain(
                part.trim_start_matches('.').to_ascii_lowercase(),
            ));
        }
        NoProxy { entries }
    }

    fn matches(&self, target_host: &str) -> bool {
        // A URI's host may carry an IPv6 literal in brackets; strip them before the
        // IpAddr parse, as hyper-util's NoProxy::contains does.
        let bare = target_host.trim_start_matches('[').trim_end_matches(']');
        let ip: Option<IpAddr> = bare.parse().ok();
        let host = target_host.to_ascii_lowercase();
        self.entries.iter().any(|entry| match entry {
            NoProxyEntry::MatchAll => true,
            NoProxyEntry::Ip(a) => ip == Some(*a),
            NoProxyEntry::Cidr(net, len) => ip.is_some_and(|h| cidr_contains(net, *len, &h)),
            NoProxyEntry::Domain(d) => {
                ip.is_none()
                    && (host == *d
                        || (host.len() > d.len()
                            && host.ends_with(d.as_str())
                            && host.as_bytes()[host.len() - d.len() - 1] == b'.'))
            }
        })
    }
}

/// CIDR containment by prefix-length bit compare over octets — the ~10 lines that make an
/// `ipnet` dependency unnecessary. Families never cross: a v4 block does not match a v6
/// address and vice versa, INCLUDING v6-mapped forms (`10.0.0.0/8` does NOT match
/// `::ffff:10.0.0.1` — it is a v6 address), matching `ipnet`/reqwest, which do not
/// special-case mapped addresses either.
fn cidr_contains(net: &IpAddr, prefix: u8, addr: &IpAddr) -> bool {
    match (net, addr) {
        (IpAddr::V4(n), IpAddr::V4(a)) => octets_prefix_eq(&n.octets(), &a.octets(), prefix),
        (IpAddr::V6(n), IpAddr::V6(a)) => octets_prefix_eq(&n.octets(), &a.octets(), prefix),
        _ => false,
    }
}

/// The first `prefix` bits of `net` and `addr` are equal. `prefix` is pre-validated against
/// the address width; `/0` matches everything (whole bytes to compare: none, remainder: 0).
fn octets_prefix_eq(net: &[u8], addr: &[u8], prefix: u8) -> bool {
    let whole = usize::from(prefix / 8);
    let rem = prefix % 8;
    if net[..whole] != addr[..whole] {
        return false;
    }
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (net[whole] & mask) == (addr[whole] & mask)
}
