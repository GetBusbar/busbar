// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pure, std-only network-address primitives shared by busbar's SSRF guards.
//!
//! These predicates are the *context-free* atoms of the SSRF obfuscation defense: they answer
//! "is this `Ipv4Addr` in the RFC 6598 CGNAT range?", "is this `Ipv6Addr` in the unique-local
//! (`fc00::/7`) or link-local (`fe80::/10`) range?", and "is this host string an alternate (non
//! dotted-quad) IPv4 encoding the OS resolver still expands?" — questions whose answer must NOT
//! depend on which caller is asking. They previously lived as byte-identical copies (or inline
//! bit-mask expressions) in both
//! `config_validate` (the provider-base-URL SSRF guard, which hand-parses a raw config string) and
//! `observability` (the request-log-webhook / OTLP SSRF guard, which reads an already
//! `reqwest::Url::parse`d host). Duplicated *security* logic is the one place where "documented
//! divergence" does not fully neutralize drift: a contributor hardening one guard against a new
//! obfuscation form could silently miss the other copy. Hoisting just these identical primitives
//! into one tested leaf gives them a single source of truth.
//!
//! The *context-specific* wrappers stay with their callers on purpose, because they legitimately
//! differ: `config_validate` keeps `expand_alternate_ipv4` (it re-checks an obfuscated literal
//! against the metadata denylist) and its raw-string `percent_decode_host`; `observability` keeps
//! `is_internal_v4` (which additionally blocks `255.255.255.255` broadcast) and its
//! `METADATA_HOSTS` list shape. This module holds ONLY the parts that are — and must remain —
//! identical.
//!
//! Pure (no I/O, no globals), so each predicate is unit-testable in isolation; the tests live here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Well-known cloud-metadata / internal DNS names that resolve, at connect time, to the IMDS family
/// even though they are not IP literals. Blocked case-insensitively by [`dns_name_is_internal`].
///
/// The `localhost` family is deliberately NOT here: it is a SEPARATE arm in
/// [`dns_name_is_internal`], because `config_validate::ssrf_blocked_host` allows `localhost` (a
/// legitimate local-model upstream) while the webhook, OTLP and A2A-card guards block it. Keeping
/// the two lists apart is what lets one guard opt out of the localhost arm without also opting out
/// of the metadata one.
pub(crate) const METADATA_HOSTS: &[&str] = &["metadata.google.internal", "metadata.internal"];

/// TRUE for an IPv4 literal no busbar guard may connect to: loopback, link-local (which is where the
/// `169.254.169.254` IMDS endpoint lives), RFC1918 private, RFC6598 CGNAT, unspecified, broadcast,
/// and the two cloud-metadata endpoints that sit on PUBLIC / IETF-reserved addresses outside every
/// one of those ranges (Azure WireServer, and OCI IMDS via the `192.0.0.0/24` it sits inside),
/// which the range predicates would otherwise miss entirely.
///
/// This is the predicate `observability::host_is_internal` was written around, hoisted here so the
/// A2A card fetch (`a2a::fetch`) reuses it rather than growing a fourth copy. Duplicated SECURITY
/// logic is the one place a documented divergence does not neutralize drift: a contributor
/// hardening one guard against a new range would silently miss the others.
pub(crate) fn ipv4_is_internal(v4: &Ipv4Addr) -> bool {
    const AZURE_WIRESERVER: Ipv4Addr = Ipv4Addr::new(168, 63, 129, 16);
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_link_local()
        || v4.is_private()
        || is_cgnat_shared_v4(v4)
        || v4.is_unspecified()
        || v4.is_broadcast()
        || *v4 == AZURE_WIRESERVER
        // MULTICAST and DOCUMENTATION arrived here from the MCP client's own copy when the two were
        // unified. The copy had them and this one did not, so the A2A card fetch — which already
        // used this predicate — was the weaker of the two without anyone deciding that. Neither is
        // a plausible destination for an upstream a caller nominates, and `224.0.0.1` reaches every
        // host on the local segment.
        || v4.is_multicast()
        || v4.is_documentation()
        // ── THE THREE ROWS BELOW ARRIVED FROM `a2a::pushnotify`'s PRIVATE COPY when that copy was
        //    torn out. The tear-out is only safe if this predicate already covers everything the
        //    copy covered, and it did not: a plane that stopped using its own table and started
        //    using this one would have SILENTLY WIDENED what it accepts. That is the drift this
        //    module exists to prevent, arriving in the shape of a cleanup.
        //
        // 0.0.0.0/8 "this network" (RFC 1122 §3.2.1.3). `is_unspecified()` is ONLY `0.0.0.0`, so
        // `0.1.2.3` was reachable through every guard that used this predicate — and several
        // stacks route the whole block to the local host.
        || o[0] == 0
        // 192.0.0.0/24 IETF protocol assignments. OCI's IMDS at `192.0.0.192` sits INSIDE this /24,
        // so the /24 subsumes the old single-address constant rather than sitting beside it.
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 198.18.0.0/15 benchmarking (RFC 2544). Not a legitimate destination, and routed inside
        // some fabrics.
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
}

/// TRUE for an IPv6 literal no busbar guard may connect to.
///
/// The ORDER is load-bearing and is the reason this is one function rather than three call sites.
/// `::1` must be caught by `is_loopback()` FIRST: under `to_ipv4()` it canonicalizes to `0.0.0.1`,
/// which is not a v4 loopback, so an embedded-v4 arm placed first would let it through. Then the
/// embedded-v4 arm runs BEFORE the v6 range masks, because `[::ffff:127.0.0.1]` and
/// `[::169.254.169.254]` match no v6 mask at all yet a connecting stack still routes them to the
/// embedded v4 target. `to_ipv4()` rather than `to_ipv4_mapped()`: it is the superset that also
/// covers the IPv4-COMPATIBLE form.
pub(crate) fn ipv6_is_internal(v6: &Ipv6Addr) -> bool {
    if v6.is_loopback() {
        return true;
    }
    if let Some(v4) = v6.to_ipv4() {
        return ipv4_is_internal(&v4);
    }
    v6.is_unspecified() || v6.is_multicast() || is_unique_local_v6(v6) || is_link_local_v6(v6)
}

/// TRUE for a resolved address that is a CLOUD-METADATA endpoint.
///
/// Separate from [`ip_is_internal`] because the two have different POLICIES, not different data: an
/// internal address may be reached when an operator sets `allow_private`, and a metadata endpoint
/// may never be reached at all. Folding them together would make `allow_private` a switch that
/// hands out cloud credentials.
///
/// The v6 arm unwraps with `to_ipv4()`, not `to_ipv4_mapped()`, for the reason [`ipv6_is_internal`]
/// gives: `to_ipv4()` is the superset that also covers the IPv4-COMPATIBLE form, so
/// `[::169.254.169.254]` is caught. A guard that only unwrapped the MAPPED form let exactly that
/// literal through — it matched no v6 range, unwrapped to nothing, and was connected to.
pub(crate) fn ip_is_cloud_metadata(addr: &IpAddr) -> bool {
    /// AWS/Azure/GCP/OpenStack/DigitalOcean IMDS, ECS task metadata, and Alibaba's.
    const V4: &[Ipv4Addr] = &[
        Ipv4Addr::new(169, 254, 169, 254),
        Ipv4Addr::new(169, 254, 170, 2),
        Ipv4Addr::new(100, 100, 100, 200),
        Ipv4Addr::new(168, 63, 129, 16),
        Ipv4Addr::new(192, 0, 0, 192),
    ];
    match addr {
        IpAddr::V4(v4) => V4.contains(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4() {
                return V4.contains(&v4);
            }
            // IMDSv6.
            v6.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254]
        }
    }
}

/// TRUE for any resolved address a busbar guard must refuse to connect to.
///
/// This is the predicate a RESOLVE-THEN-PIN guard applies to what the resolver actually answered,
/// which is the only form of the check that survives a DNS rebind: a name is not an address, and
/// the address is what a socket connects to.
pub(crate) fn ip_is_internal(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => ipv4_is_internal(v4),
        IpAddr::V6(v6) => ipv6_is_internal(v6),
    }
}

/// TRUE for a DNS NAME that is internal by definition rather than by resolution: the cloud-metadata
/// names in [`METADATA_HOSTS`], and the `localhost` family RFC 6761 reserves to loopback.
///
/// A trailing FQDN-root dot is stripped first. `getaddrinfo` resolves `localhost.` and
/// `metadata.google.internal.` to the same targets as the bare spelling, but the trailing dot makes
/// an exact compare miss by one byte — which is a bypass, not a curiosity.
pub(crate) fn dns_name_is_internal(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    if METADATA_HOSTS.iter().any(|m| host.eq_ignore_ascii_case(m)) {
        return true;
    }
    host.eq_ignore_ascii_case("localhost")
        || host
            .rsplit_once('.')
            .is_some_and(|(_, tld)| tld.eq_ignore_ascii_case("localhost"))
}

/// IPv6 unique-local range `fc00::/7` (the first 7 bits are `1111110`). No stable std predicate
/// exists for this range on the pinned toolchain, so the leading bits are checked directly.
pub(crate) fn is_unique_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// IPv6 link-local range `fe80::/10` (the first 10 bits are `1111111010`). No stable std predicate
/// exists for this range on the pinned toolchain, so the leading bits are checked directly.
pub(crate) fn is_link_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// RFC 6598 Shared Address Space `100.64.0.0/10` (a.k.a. CGNAT). NOT covered by
/// `Ipv4Addr::is_private()`, yet routable inside AWS/GCP VPCs and many Kubernetes clusters where it
/// fronts internal services — so it is an SSRF target the private/link-local checks miss. The /10
/// is the addresses whose first octet is `100` and whose top two bits of the second octet are `01`.
pub(crate) fn is_cgnat_shared_v4(v4: &Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// True when `host` is an alternate (non-dotted-quad) IPv4 encoding that `IpAddr::from_str` rejects
/// but the OS resolver (glibc `getaddrinfo`, used by reqwest's default resolver) still maps to an
/// IPv4 address: a bare decimal integer (`2130706433` = 127.0.0.1), a `0x`/`0X` hex literal
/// (`0x7f000001`), a leading-zero octal literal (`017700000001`), or a dotted form with FEWER than
/// four octets (`127.1`, `10.0.1`). On a raw, un-normalized host string these bypass the canonical
/// IP-literal checks while still resolving to loopback / link-local / private targets at connect
/// time, so they must be treated as blocked. A canonical four-octet dotted-quad is NOT matched here
/// (it is handled by the `parse::<IpAddr>()` path); a normal DNS hostname is not matched either.
pub(crate) fn is_alternate_ipv4_encoding(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }

    // Whole-host `0x...` / `0X...` hex literal (e.g. `0x7f000001`). Only when there is no `.`; a
    // dotted per-octet hex form (`0x7f.0.0.1`) is handled by the dotted branch below.
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
        }
    }

    // Dotted form: split on '.'. A canonical dotted-quad has exactly 4 parts and parses via
    // `IpAddr` — leave it to that path. Fewer than 4 numeric parts (e.g. `127.1`, `10.0.1`) is an
    // alternate short form getaddrinfo expands; flag it. Any part using a `0x` hex or leading-zero
    // octal encoding is also an alternate form.
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        // Every part must be a numeric encoding (decimal, hex, or octal) for this to be an IP-ish
        // host at all; if any part has a non-numeric character it's a DNS name → not our concern.
        let all_numeric = parts.iter().all(|p| {
            if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
                !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
            } else {
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
            }
        });
        if !all_numeric {
            return false;
        }
        // Short dotted form (fewer than 4 parts) is an alternate encoding getaddrinfo expands.
        if parts.len() < 4 {
            return true;
        }
        // Four numeric parts: alternate iff any part is hex (`0x`) or leading-zero octal.
        return parts.iter().any(|p| {
            p.starts_with("0x")
                || p.starts_with("0X")
                || (p.len() > 1 && p.starts_with('0') && p.bytes().all(|b| b.is_ascii_digit()))
        });
    }

    // No '.', not `0x`: a bare all-digits host is a decimal integer IP encoding (e.g. `2130706433`).
    host.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
#[path = "tests/net_guard_tests.rs"]
mod tests;
