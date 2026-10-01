// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE URL AND HOST READER — one reader, for every caller that judges where a URL points.
//!
//! Pure and stateless: a string in, a host or a verdict out. No I/O, no clock, no resolution,
//! nothing remembered between two calls. It lives here, outside `abi/`, because a reader shared by
//! the host's destination guard and by a plugin that must judge a URL of its own is a pure helper
//! in `busbar-contract` (BUSBAR-1.6.0.md, the engine-folds paragraph: "a pure, stateless helper in
//! `busbar-contract` outside `abi/`"), and it holds no ABI shape (BUSBAR-1.6.0.md THE DESIGN, one
//! place for every ABI shape: `abi/` is for ABI shapes only). `abi::sdk::net` re-exports it, so
//! a plugin that links only the contract reads a host exactly as the host does.
//!
//! ## Why one reader
//!
//! A URL is judged by one parser and dialled by another. Every bypass this reader closes is a string
//! the two read differently: a parser that ends the authority only at `/` reads
//! `https://127.0.0.1?x` as the host `127.0.0.1?x`, which is no address and no loopback name, while
//! the dialling stack reads `127.0.0.1`. Each copy of a hand parser was a fresh chance to get that
//! wrong, and three copies did.
//!
//! ## Two scheme families
//!
//! [`UrlFamily::Web`] (the four WHATWG special schemes [`UrlFamily::of`] names) is read by the
//! WHATWG URL rules the dialling stacks follow for them: leading and trailing C0/space trimmed,
//! tab/LF/CR deleted anywhere, every `\` read as `/` (so it ends the authority), any run of slashes
//! after the scheme skipped, the host percent-decoded. Every other scheme (`ldap`, `ldaps`, …) is
//! [`UrlFamily::Generic`] and read by RFC 3986: the authority opens with exactly `//` and ends at
//! the first `/`, `?` or `#`, and a `\` inside it is refused rather than guessed at. Both families
//! take the host through the same normalization ([`normalize_host`]): percent-decoded and one
//! trailing FQDN-root dot removed, because the name resolver ignores that dot and an exact compare
//! does not.
//!
//! ## The address predicates
//!
//! The v4/v6 range checks, the embedded-v4 unwrap, the alternate IPv4 spellings the name resolver
//! still expands (`2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`) and the ONE cloud-metadata list
//! live here too, so a range added for one caller is added for every caller.

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Well-known cloud-metadata / internal DNS names that resolve, at connect time, to the IMDS family
/// even though they are not IP literals. Blocked case-insensitively by [`dns_name_is_internal`] and
/// [`host_is_cloud_metadata`]. The metadata ADDRESSES (link-local, Alibaba `100.100.100.200`, Azure
/// WireServer `168.63.129.16`, OCI `192.0.0.192`, the EC2 IPv6 endpoints) are
/// [`ip_is_cloud_metadata`]'s; together the two are the one metadata list.
///
/// The `localhost` family is deliberately NOT here: it is a SEPARATE arm in
/// [`dns_name_is_internal`], because a guard that admits a loopback upstream must still refuse
/// every metadata name. Keeping the two lists apart is what lets one guard opt out of the localhost
/// arm without also opting out of the metadata one.
pub const METADATA_HOSTS: &[&str] = &[
    "metadata.google.internal",
    "metadata.internal",
    "metadata.tencentyun.com",
    "metadata.platformequinix.com",
    "instance-data",
    "instance-data.ec2.internal",
];

/// TRUE for an IPv4 literal no busbar guard may connect to: loopback, link-local (which is where the
/// `169.254.169.254` IMDS endpoint lives), RFC1918 private, RFC6598 CGNAT, unspecified, broadcast,
/// multicast, documentation, `0.0.0.0/8`, `192.0.0.0/24` (OCI IMDS sits inside it),
/// `198.18.0.0/15` benchmarking, and Azure WireServer, which sits on a PUBLIC address outside every
/// one of those ranges.
pub fn ipv4_is_internal(v4: &Ipv4Addr) -> bool {
    const AZURE_WIRESERVER: Ipv4Addr = Ipv4Addr::new(168, 63, 129, 16);
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_link_local()
        || v4.is_private()
        || is_cgnat_shared_v4(v4)
        || v4.is_unspecified()
        || v4.is_broadcast()
        || *v4 == AZURE_WIRESERVER
        || v4.is_multicast()
        || v4.is_documentation()
        // 0.0.0.0/8 "this network" (RFC 1122 section 3.2.1.3): `is_unspecified()` is only
        // `0.0.0.0`, and several stacks route the whole block to the local host.
        || o[0] == 0
        // 192.0.0.0/24 IETF protocol assignments; OCI's IMDS at `192.0.0.192` sits inside it.
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 198.18.0.0/15 benchmarking (RFC 2544), routed inside some fabrics.
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
}

/// TRUE for an IPv6 literal no busbar guard may connect to.
///
/// The ORDER is load-bearing. `::1` must be caught by `is_loopback()` FIRST: under `to_ipv4()` it
/// canonicalizes to `0.0.0.1`, which is not a v4 loopback. Then the embedded-v4 arm runs BEFORE the
/// v6 range masks, because `[::ffff:127.0.0.1]` and `[::169.254.169.254]` match no v6 mask at all
/// yet a connecting stack still routes them to the embedded v4 target ([`embedded_ipv4`]).
pub fn ipv6_is_internal(v6: &Ipv6Addr) -> bool {
    if v6.is_loopback() {
        return true;
    }
    if let Some(v4) = embedded_ipv4(v6) {
        return ipv4_is_internal(&v4);
    }
    v6.is_unspecified() || v6.is_multicast() || is_unique_local_v6(v6) || is_link_local_v6(v6)
}

/// TRUE for an address that is a CLOUD-METADATA endpoint.
///
/// Separate from [`ip_is_internal`] because the two have different POLICIES: an internal address may
/// be reached when an operator opts into private addressing, and a metadata endpoint never. The v4
/// question is a RANGE question: clouds put IMDS anywhere inside `169.254.0.0/16`, and nothing
/// legitimate runs on link-local, so the whole range is metadata. Only the endpoints OUTSIDE
/// link-local are named: Alibaba `100.100.100.200`, Azure WireServer `168.63.129.16`, OCI
/// `192.0.0.192`, and the EC2 IPv6 endpoints `fd00:ec2::254` (IMDS) and `fd00:ec2::23` (task
/// metadata). A v6 answer is unwrapped with [`embedded_ipv4`] first, so the mapped, compatible and
/// NAT64 spellings of a v4 endpoint are that endpoint.
pub fn ip_is_cloud_metadata(addr: &IpAddr) -> bool {
    const NON_LINK_LOCAL_V4: &[Ipv4Addr] = &[
        Ipv4Addr::new(100, 100, 100, 200),
        Ipv4Addr::new(168, 63, 129, 16),
        Ipv4Addr::new(192, 0, 0, 192),
    ];
    const METADATA_V6: &[Ipv6Addr] = &[
        Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254),
        Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x23),
    ];
    fn is_metadata_v4(v4: &Ipv4Addr) -> bool {
        v4.is_link_local() || NON_LINK_LOCAL_V4.contains(v4)
    }
    match addr {
        IpAddr::V4(v4) => is_metadata_v4(v4),
        IpAddr::V6(v6) => match embedded_ipv4(v6) {
            Some(v4) => is_metadata_v4(&v4),
            None => METADATA_V6.contains(v6),
        },
    }
}

/// TRUE for any address a busbar guard must refuse to connect to without an opt-in.
pub fn ip_is_internal(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => ipv4_is_internal(v4),
        IpAddr::V6(v6) => ipv6_is_internal(v6),
    }
}

/// TRUE for a DNS NAME that is internal by definition rather than by resolution: the cloud-metadata
/// names in [`METADATA_HOSTS`], and the `localhost` family RFC 6761 reserves to loopback. A trailing
/// FQDN-root dot is ignored, because the resolver ignores it.
pub fn dns_name_is_internal(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    if METADATA_HOSTS.iter().any(|m| host.eq_ignore_ascii_case(m)) {
        return true;
    }
    host.eq_ignore_ascii_case("localhost")
        || host
            .rsplit_once('.')
            .is_some_and(|(_, tld)| tld.eq_ignore_ascii_case("localhost"))
}

/// IPv6 unique-local range `fc00::/7`.
pub fn is_unique_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// IPv6 link-local range `fe80::/10`.
pub fn is_link_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// RFC 6598 Shared Address Space `100.64.0.0/10` (CGNAT). Not covered by `is_private()`, yet it
/// fronts internal services inside many VPCs and clusters.
pub fn is_cgnat_shared_v4(v4: &Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// Unwrap an embedded IPv4 target from an IPv6 literal, covering EVERY form a connecting stack
/// still routes to an IPv4 destination: IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible
/// (`::a.b.c.d`), and the NAT64 `/96` embeddings (RFC 6052 well-known `64:ff9b::/96`, and any `/96`
/// under the RFC 8215 local-use `64:ff9b:1::/48`), which a DNS64 resolver synthesizes and
/// `to_ipv4()` does not recognise.
pub fn embedded_ipv4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4() {
        return Some(v4);
    }
    // Well-known: the whole 96-bit prefix is fixed. Local-use: only the top 48 bits are, and an
    // operator picks the rest of the /96 (RFC 8215 section 6's own example has a non-zero seg[3]).
    const NAT64_WELL_KNOWN: u16 = 0;
    const NAT64_LOCAL_USE: u16 = 1;
    let seg = v6.segments();
    if seg[0] == 0x0064 && seg[1] == 0xff9b {
        let embeds_v4 = match seg[2] {
            NAT64_WELL_KNOWN => seg[3] == 0 && seg[4] == 0 && seg[5] == 0,
            NAT64_LOCAL_USE => true,
            _ => false,
        };
        if embeds_v4 {
            let [a, b] = seg[6].to_be_bytes();
            let [c, d] = seg[7].to_be_bytes();
            return Some(Ipv4Addr::new(a, b, c, d));
        }
    }
    None
}

/// True when `host` is an alternate (non-dotted-quad) IPv4 encoding that `IpAddr::from_str` rejects
/// but the name resolver (`inet_aton` rules) still maps to an IPv4 address: a bare decimal integer
/// (`2130706433`), a `0x` hex literal (`0x7f000001`), a leading-zero octal part (`0177.0.0.1`), or a
/// dotted form with FEWER than four parts (`127.1`). A canonical dotted-quad and a DNS name are not
/// matched. [`expand_alternate_ipv4`] says which address such a spelling means.
pub fn is_alternate_ipv4_encoding(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
        }
    }
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
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
        if parts.len() < 4 {
            return true;
        }
        return parts.iter().any(|p| {
            p.starts_with("0x")
                || p.starts_with("0X")
                || (p.len() > 1 && p.starts_with('0') && p.bytes().all(|b| b.is_ascii_digit()))
        });
    }
    host.bytes().all(|b| b.is_ascii_digit())
}

/// Expand an alternate (non-dotted-quad) IPv4 encoding to the address the name resolver would
/// connect to. `None` for a canonical dotted-quad (read that with `IpAddr::from_str`), a DNS name,
/// or an out-of-range value.
///
/// The `inet_aton` "parts" forms: 1 to 4 dotted components, the LAST absorbing the remaining low
/// bytes (`a` = 32 bits; `a.b` = a<<24 | b; `a.b.c` = a<<24 | b<<16 | c; `a.b.c.d`), each component
/// decimal, `0x` hex or leading-zero octal.
pub fn expand_alternate_ipv4(host: &str) -> Option<Ipv4Addr> {
    if host.is_empty() {
        return None;
    }
    fn parse_component(p: &str) -> Option<u64> {
        if p.is_empty() {
            return None;
        }
        if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
            if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            u64::from_str_radix(hex, 16).ok()
        } else if p.len() > 1 && p.starts_with('0') {
            if !p.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
                return None;
            }
            u64::from_str_radix(p, 8).ok()
        } else {
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse::<u64>().ok()
        }
    }
    let parts: Vec<&str> = host.split('.').collect();
    let vals: Vec<u64> = parts
        .iter()
        .map(|p| parse_component(p))
        .collect::<Option<Vec<u64>>>()?;
    let is_alternate_octet = |p: &&str, v: &u64| {
        *v > 255
            || p.starts_with("0x")
            || p.starts_with("0X")
            || (p.len() > 1 && p.starts_with('0'))
    };
    let is_canonical_quad = parts.len() == 4
        && !parts
            .iter()
            .zip(&vals)
            .any(|(p, v)| is_alternate_octet(p, v));
    if is_canonical_quad {
        return None;
    }
    let addr: u32 = match vals.as_slice() {
        [a] => u32::try_from(*a).ok()?,
        [a, b] => {
            if *a > 0xff || *b > 0x00ff_ffff {
                return None;
            }
            ((*a as u32) << 24) | (*b as u32)
        }
        [a, b, c] => {
            if *a > 0xff || *b > 0xff || *c > 0x0000_ffff {
                return None;
            }
            ((*a as u32) << 24) | ((*b as u32) << 16) | (*c as u32)
        }
        [a, b, c, d] => {
            if *a > 0xff || *b > 0xff || *c > 0xff || *d > 0xff {
                return None;
            }
            ((*a as u32) << 24) | ((*b as u32) << 16) | ((*c as u32) << 8) | (*d as u32)
        }
        _ => return None,
    };
    Some(Ipv4Addr::from(addr))
}

/// The address a normalized host names, in any spelling the resolver accepts as a literal: a
/// canonical v4 or v6 literal (a v6 zone suffix `%…` is ignored), or an alternate IPv4 spelling
/// ([`expand_alternate_ipv4`]). `None` for a DNS name.
pub fn host_ip(host: &str) -> Option<IpAddr> {
    let literal = if host.contains(':') {
        host.split('%').next().unwrap_or(host)
    } else {
        host
    };
    literal
        .parse::<IpAddr>()
        .ok()
        .or_else(|| expand_alternate_ipv4(literal).map(IpAddr::V4))
}

/// TRUE when a normalized host is a cloud-metadata endpoint by NAME ([`METADATA_HOSTS`], case-blind,
/// one trailing dot ignored) or by ADDRESS in any literal spelling ([`host_ip`] then
/// [`ip_is_cloud_metadata`]). Nothing is resolved.
pub fn host_is_cloud_metadata(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    METADATA_HOSTS.iter().any(|m| name.eq_ignore_ascii_case(m))
        || host_ip(name).is_some_and(|ip| ip_is_cloud_metadata(&ip))
}

/// TRUE when a normalized host is an IPv6 link-local literal (fe80::/10, [`is_link_local_v6`]) in
/// any spelling [`host_ip`] reads, a zone included. Not a metadata fact: the IPv4 link-local range
/// is in the metadata list because the metadata services live there, while this is the IPv6 twin a
/// caller that refuses link-local on every need (the connector endpoint check, PB-100) asks beside
/// [`host_is_cloud_metadata`]. Nothing is resolved.
pub fn host_is_link_local_v6(host: &str) -> bool {
    matches!(host_ip(host), Some(IpAddr::V6(v6)) if is_link_local_v6(&v6))
}

/// True when `host` (already normalized) is a private, loopback, link-local, unspecified or CGNAT
/// target, or the `localhost` name family, or an alternate IPv4 spelling (which is read as private
/// rather than as public, since a connecting stack maps it to an IPv4 target all the same). This
/// keys whether plaintext is acceptable for a hop; it is not the metadata decision.
pub fn host_is_private_or_loopback(host: &str) -> bool {
    let host_lc = host.to_ascii_lowercase();
    if host_lc == "localhost"
        || host_lc
            .rsplit_once('.')
            .is_some_and(|(_, tld)| tld == "localhost")
    {
        return true;
    }
    if is_alternate_ipv4_encoding(host) {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || is_cgnat_shared_v4(&v4)
        }
        Ok(IpAddr::V6(v6)) => {
            let embedded = embedded_ipv4(&v6);
            v6.is_loopback()
                || v6.is_unspecified()
                || is_unique_local_v6(&v6)
                || is_link_local_v6(&v6)
                || embedded.is_some_and(|m| {
                    m.is_loopback()
                        || m.is_private()
                        || m.is_link_local()
                        || m.is_unspecified()
                        || is_cgnat_shared_v4(&m)
                })
        }
        Err(_) => false,
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE HOST READERS
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// Whether a URL claims the given scheme, case-insensitively.
pub fn scheme_is(url: &str, scheme: &str) -> bool {
    url.split_once("://")
        .is_some_and(|(s, _)| s.eq_ignore_ascii_case(scheme))
}

/// Strip a web scheme (`https` or its plaintext twin) case-insensitively, returning the
/// authority+path remainder.
fn strip_scheme(url: &str) -> Option<&str> {
    let (scheme, rest) = url.split_once("://")?;
    (scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http")).then_some(rest)
}

/// Percent-decode a host string (`%XX` → byte). An invalid escape is left verbatim, so a malformed
/// host stays malformed rather than smuggling a blocked literal past a check; a decode that is not
/// UTF-8 keeps the original. A host with no `%` is handed back borrowed.
fn percent_decode_host(host: &str) -> Cow<'_, str> {
    if !host.contains('%') {
        return Cow::Borrowed(host);
    }
    let bytes = host.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    match String::from_utf8(out) {
        Ok(s) => Cow::Owned(s),
        Err(_) => Cow::Borrowed(host),
    }
}

/// The WHATWG basic URL parser's first step, both halves, in its order: trim leading and trailing C0
/// controls and SPACE, then delete every tab/LF/CR anywhere. `" https://169.254.169.254/"` would
/// otherwise hide its scheme, and `"https://169.254.169\t.254/"` its host.
fn strip_whatwg_removed(s: &str) -> Cow<'_, str> {
    let s = s.trim_matches(|c: char| c <= '\u{1f}' || c == ' ');
    if s.contains(['\t', '\n', '\r']) {
        Cow::Owned(s.replace(['\t', '\n', '\r'], ""))
    } else {
        Cow::Borrowed(s)
    }
}

/// THE HOST NORMALIZATION every reader here shares: percent-decoded, then one trailing FQDN-root dot
/// removed (the resolver reads `169.254.169.254.` as `169.254.169.254`). Case is kept; compare
/// names case-blind.
pub fn normalize_host(raw: &str) -> String {
    let decoded = percent_decode_host(raw);
    let decoded = decoded.as_ref();
    decoded.strip_suffix('.').unwrap_or(decoded).to_string()
}

/// The host a dialling stack would read out of an `https://` (or plaintext) URL, after every
/// normalization it performs: the WHATWG trim, the backslash fold that moves the authority
/// boundary, the userinfo drop, the IPv6 bracket, the percent-decode and the trailing dot. `None`
/// for any other scheme.
///
/// This is the reader the 1.5.5 configuration validators use, kept byte-for-byte; a caller judging
/// a URL of any scheme reads it with [`url_host`] or [`parse_url`].
pub fn extract_normalized_host(url: &str) -> Option<String> {
    let url = strip_whatwg_removed(url);
    let rest = strip_scheme(url.as_ref())?;
    normalize_authority(rest)
}

/// The same host extraction over an authority that names no scheme at all (`host:port`). Anything
/// carrying a `://` extracts no host here, so a scheme is never read as a hostname.
pub fn extract_normalized_authority_host(authority: &str) -> Option<String> {
    let authority = strip_whatwg_removed(authority);
    if authority.contains("://") {
        return None;
    }
    normalize_authority(&authority)
}

/// Everything [`extract_normalized_host`] does once the scheme is out of the way, shared by both
/// spellings so neither can read a different host than the other.
fn normalize_authority(rest: &str) -> Option<String> {
    let rest: Cow<'_, str> = if rest.contains('\\') {
        Cow::Owned(rest.replace('\\', "/"))
    } else {
        Cow::Borrowed(rest)
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest.as_ref());
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host: &str = if let Some(after_bracket) = host_port.strip_prefix('[') {
        match after_bracket.split_once(']') {
            Some((inner, _)) => inner,
            None => after_bracket,
        }
    } else {
        match host_port.rsplit_once(':') {
            // A left side that still holds a colon is a bare IPv6 literal: keep it whole.
            Some((left, _)) if !left.contains(':') => left,
            _ => host_port,
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(normalize_host(host))
}

/// Which rules a scheme's URLs are read by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlFamily {
    /// The web schemes [`UrlFamily::of`] names: the WHATWG URL rules (`\` is `/`, slashes after
    /// the scheme skipped, the host percent-decoded).
    Web,
    /// Every other scheme (`ldap`, `ldaps`, …): RFC 3986 (the authority opens with
    /// exactly `//` and ends at the first `/`, `?` or `#`).
    Generic,
}

impl UrlFamily {
    /// The family a (lower-case) scheme is read by.
    #[must_use]
    pub fn of(scheme: &str) -> Self {
        match scheme {
            "http" | "https" | "ws" | "wss" => UrlFamily::Web,
            _ => UrlFamily::Generic,
        }
    }
}

/// A URL read into the parts a destination check needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlParts {
    /// The scheme, lower-cased.
    pub scheme: String,
    /// The rules it was read by.
    pub family: UrlFamily,
    /// The authority carried a userinfo (`…@`). The userinfo itself is never kept: a caller that
    /// must refuse one refuses on this, and nothing here can repeat a password.
    pub userinfo: bool,
    /// The host, unbracketed, through [`normalize_host`]. Case as written.
    pub host: String,
    /// The port the authority spelled, if it spelled one (an empty `:` is none, as WHATWG reads it).
    pub port: Option<u16>,
    /// Everything after the authority. For [`UrlFamily::Web`] it always opens with `/` (so
    /// `https://h?q` gives `/?q`) and every `\` is `/`; for [`UrlFamily::Generic`] it is verbatim
    /// and may be empty.
    pub path: String,
}

/// Why [`parse_url`] would not read a string as a URL with a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlRefusal {
    /// No `scheme:` prefix.
    NoScheme,
    /// A [`UrlFamily::Generic`] URL whose scheme is not followed by `//`.
    NoAuthority,
    /// The host is empty, or holds a byte no host may hold.
    NoHost,
    /// A `\` inside a [`UrlFamily::Generic`] authority, which RFC 3986 does not admit and which a
    /// WHATWG reader would read as a boundary.
    Backslash,
    /// An unclosed `[`, bytes after `]` that are not a port, a bracketed host that is not an IPv6
    /// literal, or an IPv6 literal without brackets.
    Bracket,
    /// A port that is not a decimal number from 0 to 65535.
    Port,
}

impl std::fmt::Display for UrlRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            UrlRefusal::NoScheme => "the URL names no scheme",
            UrlRefusal::NoAuthority => "the URL has no `//` authority",
            UrlRefusal::NoHost => "the URL has no usable host",
            UrlRefusal::Backslash => "the URL authority holds a backslash",
            UrlRefusal::Bracket => "the URL host is not a well-formed IPv6 literal",
            UrlRefusal::Port => "the URL port is not a number from 0 to 65535",
        })
    }
}

impl std::error::Error for UrlRefusal {}

/// A byte no host may hold once decoded: the WHATWG forbidden host code points, and controls.
fn forbidden_in_host(c: char) -> bool {
    c.is_ascii_control()
        || matches!(
            c,
            ' ' | '#' | '%' | '/' | ':' | '<' | '>' | '?' | '@' | '[' | '\\' | ']' | '^' | '|'
        )
}

/// READ A URL OF ANY SCHEME, by its family's rules (see [`UrlFamily`]).
///
/// The authority ends at the first `/`, `?` or `#` (and, for [`UrlFamily::Web`], `\`), so
/// `https://127.0.0.1?x`, `https://localhost#a` and `https://10.0.0.5\x/` read the host the
/// dialling stack reads, and `ldap://evil.example#@127.0.0.1` reads `evil.example`. A userinfo is
/// split at the LAST `@` of the authority and reported, never kept.
///
/// # Errors
///
/// [`UrlRefusal`] when the string has no scheme, no authority, no usable host, a malformed bracket
/// or port, or a backslash inside a [`UrlFamily::Generic`] authority.
pub fn parse_url(url: &str) -> Result<UrlParts, UrlRefusal> {
    let cleaned = strip_whatwg_removed(url);
    let s = cleaned.as_ref();
    let (scheme, after) = s.split_once(':').ok_or(UrlRefusal::NoScheme)?;
    let scheme_ok = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    if !scheme_ok {
        return Err(UrlRefusal::NoScheme);
    }
    let scheme = scheme.to_ascii_lowercase();
    let family = UrlFamily::of(&scheme);
    let rest: Cow<'_, str> = match family {
        // WHATWG: any run of `/` and `\` after a special scheme is skipped, and `\` reads as `/`.
        UrlFamily::Web => {
            let skipped = after.trim_start_matches(['/', '\\']);
            if skipped.contains('\\') {
                Cow::Owned(skipped.replace('\\', "/"))
            } else {
                Cow::Borrowed(skipped)
            }
        }
        UrlFamily::Generic => {
            Cow::Borrowed(after.strip_prefix("//").ok_or(UrlRefusal::NoAuthority)?)
        }
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.contains('\\') {
        return Err(UrlRefusal::Backslash);
    }
    let (userinfo, host_port) = match authority.rfind('@') {
        Some(at) => (true, &authority[at + 1..]),
        None => (false, authority),
    };
    let (host, port) = if let Some(inner) = host_port.strip_prefix('[') {
        let (literal, after) = inner.split_once(']').ok_or(UrlRefusal::Bracket)?;
        if literal.parse::<Ipv6Addr>().is_err() {
            return Err(UrlRefusal::Bracket);
        }
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or(UrlRefusal::Bracket)?),
        };
        (literal.to_string(), port)
    } else {
        let (raw, port) = match host_port.rsplit_once(':') {
            Some((h, _)) if h.contains(':') => return Err(UrlRefusal::Bracket),
            Some((h, p)) => (h, Some(p)),
            None => (host_port, None),
        };
        let host = normalize_host(raw);
        if host.is_empty() || host.contains(forbidden_in_host) {
            return Err(UrlRefusal::NoHost);
        }
        (host, port)
    };
    let port = match port {
        None | Some("") => None,
        Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => {
            Some(p.parse::<u16>().map_err(|_| UrlRefusal::Port)?)
        }
        Some(_) => return Err(UrlRefusal::Port),
    };
    let path = match family {
        UrlFamily::Web if tail.starts_with('/') => tail.to_string(),
        UrlFamily::Web => format!("/{tail}"),
        UrlFamily::Generic => tail.to_string(),
    };
    Ok(UrlParts {
        scheme,
        family,
        userinfo,
        host,
        port,
        path,
    })
}

/// The host of a URL of any scheme, read by [`parse_url`]; `None` when it reads no host.
#[must_use]
pub fn url_host(url: &str) -> Option<String> {
    parse_url(url).ok().map(|p| p.host)
}

/// The host of a DIAL TARGET, which may be spelled as a URL or as a bare `host`, `host:port`,
/// `[v6]` or `[v6]:port` authority (a bare v6 literal is kept whole, a zone suffix too). A target
/// carrying `://`, or opening with a [`UrlFamily::Web`] scheme and `:`, is read as a URL, so its
/// scheme is never read as the host. `None` when no host can be read.
#[must_use]
pub fn target_host(target: &str) -> Option<String> {
    let trimmed = strip_whatwg_removed(target);
    let web_scheme = trimmed
        .split_once(':')
        .is_some_and(|(s, _)| UrlFamily::of(&s.to_ascii_lowercase()) == UrlFamily::Web);
    if web_scheme || trimmed.contains("://") {
        url_host(&trimmed)
    } else {
        extract_normalized_authority_host(&trimmed)
    }
}

#[cfg(test)]
#[path = "tests/net_tests.rs"]
mod net_tests;
