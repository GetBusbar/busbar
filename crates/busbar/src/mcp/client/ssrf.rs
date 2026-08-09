// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DISPATCH-TIME SSRF: an upstream MCP URL is attacker-influenced, so it is validated per request,
//! resolved, and then CONNECTED TO THE ADDRESS THAT WAS VALIDATED.
//!
//! ## Why the existing guard is not enough, stated precisely
//!
//! `config_validate`'s provider-base-URL guard vets ONE operator-supplied string ONCE at startup,
//! and `observability.rs` says in its own comment that DNS rebinding is out of scope for a
//! startup-validated URL. Both are correct for what they guard. Neither is correct here: an MCP
//! server registration can be written through the admin API by anyone holding a `full`-scope token,
//! its tool arguments are per-request nested JSON chosen by a model that just read an upstream's
//! description, and both are re-resolved on every dispatch. Rebinding and TOCTOU are THE threat
//! rather than an edge case.
//!
//! So one piece is reused — the private/link-local/CGNAT/metadata predicate set — and the rest is
//! new:
//!
//! - **Scheme allowlist.** `https` always; `http` only where the operator has opted a server into
//!   private addressing. Everything else — `file:`, `gopher:`, `smb:`, `ftp:`, `data:` — is refused
//!   by absence rather than by a blocklist, because a blocklist of schemes is a list somebody has to
//!   keep up with.
//! - **EVERY resolved address is checked, not the first.** A rebinding resolver answers with a
//!   public address and a loopback address in one reply and lets the connect pick. Checking the
//!   first is checking whichever one the resolver put first.
//! - **RESOLVE-THEN-PIN.** The address that passed the check is the address the connection is made
//!   to ([`PinnedTarget`]), so a second resolution between check and connect cannot change the
//!   destination. This is the part a hostname string compare cannot do, and it is why endpoint
//!   authenticity is established by RESOLVING and pinning rather than by comparing strings.
//! - **No redirects, ever.** A 3xx is a URL the operator never validated, chosen by the upstream, at
//!   the moment a credential is already on the wire. The client is built `Policy::none()` and a 3xx
//!   is surfaced as a refusal rather than followed.
//!
//! ## What this module is NOT
//!
//! It is not on the selection hot path. Selection and dispatch carry SEPARATE budgets: selection
//! targets sub-100µs, while dispatch is milliseconds-class and does DNS. This runs on dispatch, and
//! the separation is what lets it do a blocking-class lookup without breaking the selection number.

use crate::net_guard::{is_alternate_ipv4_encoding, is_cgnat_shared_v4, is_link_local_v6};
use std::net::{IpAddr, SocketAddr};

/// The operator's addressing posture for ONE upstream. Per server rather than global, because the
/// answer genuinely differs: an MCP server on the cluster's internal network is the normal case, and
/// a global "allow private" would extend that decision to every other server at once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SsrfPolicy {
    /// Whether this upstream may live on a private / loopback / CGNAT address.
    ///
    /// Even when set, cloud-metadata addresses stay refused. That is not an oversight: an operator
    /// saying "this MCP server is on our internal network" has said nothing about IMDS, and IMDS is
    /// the address whose whole value to an attacker is that it hands out credentials to anyone who
    /// can make a request from inside.
    pub(crate) allow_private: bool,
}

/// Why a dispatch target was refused. Every arm names the address or scheme, because an SSRF refusal
/// an operator cannot diagnose is an SSRF refusal an operator disables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SsrfRefusal {
    /// The URL had no `http`/`https` scheme, or none at all.
    Scheme(String),
    /// `http` to a public host. Refused because the upstream credential rides the request.
    PlaintextToPublicHost(String),
    /// The URL had no host component.
    NoHost(String),
    /// The host is an alternate IPv4 encoding (`0x7f000001`, `2130706433`, `127.1`) that the OS
    /// resolver expands but a canonical IP-literal check misses.
    ObfuscatedHost(String),
    /// DNS resolution failed or returned nothing.
    Unresolvable { host: String, reason: String },
    /// A resolved address is internal (loopback / private / link-local / CGNAT / unique-local) and
    /// the server is not opted into private addressing.
    InternalAddress { host: String, addr: IpAddr },
    /// A resolved address is a cloud-metadata endpoint. Always refused, `allow_private` or not.
    CloudMetadata { host: String, addr: IpAddr },
    /// The upstream answered a redirect. Never followed — see the module header.
    Redirect { status: u16, location: String },
}

impl std::fmt::Display for SsrfRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsrfRefusal::Scheme(u) => write!(
                f,
                "MCP upstream URL `{u}` must be http(s); no other scheme is dispatched to"
            ),
            SsrfRefusal::PlaintextToPublicHost(u) => write!(
                f,
                "MCP upstream URL `{u}` is plaintext http to a public host, and the upstream \
                 credential rides this request; use https"
            ),
            SsrfRefusal::NoHost(u) => write!(f, "MCP upstream URL `{u}` has no host"),
            SsrfRefusal::ObfuscatedHost(h) => write!(
                f,
                "MCP upstream host `{h}` is an alternate IPv4 encoding the resolver expands; write \
                 the address in dotted-quad form so it can be checked"
            ),
            SsrfRefusal::Unresolvable { host, reason } => {
                write!(f, "MCP upstream host `{host}` did not resolve: {reason}")
            }
            SsrfRefusal::InternalAddress { host, addr } => write!(
                f,
                "MCP upstream host `{host}` resolves to the internal address {addr}; set this \
                 server's `allow_private` if that is deliberate"
            ),
            SsrfRefusal::CloudMetadata { host, addr } => write!(
                f,
                "MCP upstream host `{host}` resolves to the cloud-metadata address {addr}; that is \
                 refused unconditionally"
            ),
            SsrfRefusal::Redirect { status, location } => write!(
                f,
                "MCP upstream answered {status} redirecting to `{location}`; redirects are never \
                 followed because the target was never validated and the credential is already sent"
            ),
        }
    }
}

/// A destination that has PASSED the check, carrying the exact address the connection must be made
/// to.
///
/// The point of the type is that it cannot be constructed except by [`resolve_and_pin`], so a
/// dispatch path cannot connect to something that was never checked — the check is not a call
/// somebody remembers to make, it is the only way to get the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PinnedTarget {
    host: String,
    port: u16,
    addr: SocketAddr,
    https: bool,
}

impl PinnedTarget {
    /// The hostname, preserved for the `Host` header and TLS SNI. Connecting to a pinned IP while
    /// presenting the original name is the whole trick: the certificate is still validated against
    /// the name the operator registered.
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// THE ADDRESS TO CONNECT TO. Not re-resolved.
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn is_https(&self) -> bool {
        self.https
    }
}

/// Cloud metadata service addresses. Refused unconditionally.
///
/// Addresses rather than hostnames, because this check runs AFTER resolution: a hostname denylist is
/// defeated by any name the attacker controls that resolves here, which is the entire attack.
fn is_cloud_metadata(addr: &IpAddr) -> bool {
    match addr {
        // AWS / Azure / GCP / OpenStack / DigitalOcean IMDS, and Alibaba's.
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o == [169, 254, 169, 254] || o == [169, 254, 170, 2] || o == [100, 100, 100, 200]
        }
        // IMDSv6.
        IpAddr::V6(v6) => v6.segments() == [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254],
    }
}

/// Whether `addr` is an address no MCP upstream should be reachable at without an explicit operator
/// opt-in.
fn is_internal(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_documentation()
                || is_cgnat_shared_v4(v4)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || crate::net_guard::is_unique_local_v6(v6)
                || is_link_local_v6(v6)
                // An IPv4-mapped address (`::ffff:127.0.0.1`) is an IPv4 address wearing a v6
                // costume; check the address it maps to, or the whole v4 ruleset is bypassed by a
                // AAAA record.
                || v6
                    .to_ipv4_mapped()
                    .map(|m| is_internal(&IpAddr::V4(m)))
                    .unwrap_or(false)
        }
    }
}

/// Split an `http(s)://host[:port][/path]` URL into `(https, host, port, path)`.
///
/// Hand-written for the same reason `crate::mcp::split_absolute` is: what is wanted is a STRICT
/// recogniser. A permissive parser's job is to find a reading that works, and "find a reading that
/// works" is the opposite of what a security check wants from an attacker-influenced string.
fn split_url(url: &str) -> Result<(bool, String, u16, String), SsrfRefusal> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(SsrfRefusal::Scheme(url.to_string()));
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // Userinfo is refused rather than stripped. `https://evil.test@good.example/` reads as
    // `good.example` to a parser and as `evil.test` to a human skimming a config diff, and a value
    // whose two readings differ has no place on a dispatch path.
    if authority.contains('@') {
        return Err(SsrfRefusal::NoHost(url.to_string()));
    }
    if authority.is_empty() {
        return Err(SsrfRefusal::NoHost(url.to_string()));
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal.
        let (h, tail) = inner
            .split_once(']')
            .ok_or_else(|| SsrfRefusal::NoHost(url.to_string()))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| SsrfRefusal::NoHost(url.to_string()))?,
            None => default_port(https),
        };
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| SsrfRefusal::NoHost(url.to_string()))?,
            ),
            None => (authority.to_string(), default_port(https)),
        }
    };
    if host.is_empty() {
        return Err(SsrfRefusal::NoHost(url.to_string()));
    }
    Ok((https, host, port, path.to_string()))
}

fn default_port(https: bool) -> u16 {
    if https {
        443
    } else {
        80
    }
}

/// THE CHECK, minus the I/O: everything decidable from the URL string alone.
///
/// Split out from [`resolve_and_pin`] so the string-shaped refusals are testable without a resolver,
/// and so a caller that already resolved (the pool, on a cache hit) re-runs the cheap half.
pub(crate) fn precheck(
    url: &str,
    policy: SsrfPolicy,
) -> Result<(bool, String, u16, String), SsrfRefusal> {
    let (https, host, port, path) = split_url(url)?;
    if is_alternate_ipv4_encoding(&host) {
        return Err(SsrfRefusal::ObfuscatedHost(host));
    }
    if !https && !policy.allow_private {
        return Err(SsrfRefusal::PlaintextToPublicHost(url.to_string()));
    }
    Ok((https, host, port, path))
}

/// RESOLVE-THEN-PIN. Resolves `url`'s host, refuses if ANY resolved address is inadmissible, and
/// returns the address the caller must connect to.
///
/// Async because it does DNS, and a dispatch path — after selection, before the outbound
/// `tools/call` — is the one place a per-request DNS lookup belongs.
pub(crate) async fn resolve_and_pin(
    url: &str,
    policy: SsrfPolicy,
) -> Result<PinnedTarget, SsrfRefusal> {
    let (https, host, port, _path) = precheck(url, policy)?;
    let addrs = lookup(&host, port).await?;
    check_addresses(&host, &addrs, policy)?;
    // The FIRST admissible address is pinned. All of them passed, so "first" is a choice between
    // equals rather than a filter, and taking the first preserves the resolver's own ordering
    // (which is where happy-eyeballs and geo-DNS preferences live).
    let addr = *addrs.first().ok_or_else(|| SsrfRefusal::Unresolvable {
        host: host.clone(),
        reason: "resolver returned no addresses".to_string(),
    })?;
    Ok(PinnedTarget {
        host,
        port,
        addr,
        https,
    })
}

async fn lookup(host: &str, port: u16) -> Result<Vec<SocketAddr>, SsrfRefusal> {
    // A bare IP literal needs no resolver, and going through one would let a resolver answer a
    // question that has only one answer.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| SsrfRefusal::Unresolvable {
            host: host.to_string(),
            reason: e.to_string(),
        })?
        .collect();
    if addrs.is_empty() {
        return Err(SsrfRefusal::Unresolvable {
            host: host.to_string(),
            reason: "resolver returned no addresses".to_string(),
        });
    }
    Ok(addrs)
}

/// Refuse if ANY address in `addrs` is inadmissible. Separated from the resolution so the rebinding
/// case — a resolver answering with one good address and one bad one — is testable without a
/// resolver that will do that on demand.
pub(crate) fn check_addresses(
    host: &str,
    addrs: &[SocketAddr],
    policy: SsrfPolicy,
) -> Result<(), SsrfRefusal> {
    for sa in addrs {
        let ip = sa.ip();
        if is_cloud_metadata(&ip) {
            return Err(SsrfRefusal::CloudMetadata {
                host: host.to_string(),
                addr: ip,
            });
        }
        if is_internal(&ip) && !policy.allow_private {
            return Err(SsrfRefusal::InternalAddress {
                host: host.to_string(),
                addr: ip,
            });
        }
    }
    Ok(())
}

/// Turn a response status into a refusal when it is a redirect.
///
/// Called on the dispatch path rather than relying only on the client's `Policy::none()`. Two
/// mechanisms for one hazard is deliberate here: the policy stops the request being MADE, and this
/// stops a 3xx being handed to a JSON-RPC parser that would report "invalid response" and hide the
/// fact that an upstream tried to move the call somewhere else.
pub(crate) fn refuse_redirect(status: u16, location: Option<&str>) -> Result<(), SsrfRefusal> {
    if (300..400).contains(&status) {
        return Err(SsrfRefusal::Redirect {
            status,
            location: location.unwrap_or("<absent>").to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/ssrf_tests.rs"]
mod ssrf_tests;
