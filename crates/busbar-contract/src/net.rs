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
//! does not. [`parse_url`] then reads a non-ASCII host as its punycode (ACE) name by UTS #46, the
//! mapping busbar 1.5.5's `url` 2.5.8 applied before it dialled ([`url_host_to_ascii`]).
//!
//! ## The address predicates
//!
//! The v4/v6 range checks, the embedded-v4 unwrap, the alternate IPv4 spellings the name resolver
//! still expands (`2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`) and the ONE cloud-metadata list
//! live here too, so a range added for one caller is added for every caller.

use std::borrow::Cow;

/// THE ADDRESS VALUE TYPES A PLUGIN NAMES, through the contract and never through `std::net`.
///
/// An address literal parsed, held, compared or printed (a config value, a log field, an authority
/// judged as a literal) opens nothing, dials nothing, binds nothing and resolves nothing. A plugin
/// that needs one names it here (`busbar_contract::net::SocketAddr`, or `abi::sdk::net::..`), so
/// its own source names no `std::net` path and the dependency wall (`cargo xtask gate dep-wall`)
/// holds without an exemption. These are Rust-side value types only: no ABI shape carries them, and
/// nothing that opens a socket (`TcpStream`, `UdpSocket`, `ToSocketAddrs`, ..) is re-exported.
pub use std::net::{
    AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};

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
/// `to_ipv4()` does not recognise, and the two transition tunnels a relay delivers to an IPv4 host:
/// 6to4 (`2002::/16`, RFC 3056: the IPv4 address is bits 16-47) and Teredo (`2001::/32`, RFC 4380:
/// the client's IPv4 address is bits 96-127, every bit inverted).
pub fn embedded_ipv4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4() {
        return Some(v4);
    }
    let seg = v6.segments();
    if seg[0] == 0x2002 {
        let [a, b] = seg[1].to_be_bytes();
        let [c, d] = seg[2].to_be_bytes();
        return Some(Ipv4Addr::new(a, b, c, d));
    }
    if seg[0] == 0x2001 && seg[1] == 0 {
        let [a, b] = (!seg[6]).to_be_bytes();
        let [c, d] = (!seg[7]).to_be_bytes();
        return Some(Ipv4Addr::new(a, b, c, d));
    }
    // Well-known: the whole 96-bit prefix is fixed. Local-use: only the top 48 bits are, and an
    // operator picks the rest of the /96 (RFC 8215 section 6's own example has a non-zero seg[3]).
    const NAT64_WELL_KNOWN: u16 = 0;
    const NAT64_LOCAL_USE: u16 = 1;
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

/// Whether `s` is a SOCKET LITERAL: `v4:port` or `[v6]:port`, exactly the grammar
/// `std::net::SocketAddr`'s parser accepts (no named zone, no alternate v4 spelling, a port in
/// `0..=65535`, never a bare host). A plugin whose source may not name the system's network module
/// tells a pinned literal from a name here, and accepts exactly what the parser accepts.
#[must_use]
pub fn is_socket_literal(s: &str) -> bool {
    s.parse::<std::net::SocketAddr>().is_ok()
}

/// Whether `s` is a bare IP LITERAL, v4 or v6: exactly the grammar `std::net::IpAddr`'s parser
/// accepts (a dotted quad with no leading zeros or alternate spelling, or an IPv6 address with no
/// brackets, no zone and no port). An IP literal is not a name: a plugin whose source may not name
/// the system's network module tells one from a name here, and accepts exactly what the parser
/// accepts.
#[must_use]
pub fn is_ip_literal(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
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
/// caller that refuses link-local on every need, whatever the egress class (the connector endpoint
/// check), asks beside
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
/// This is the reader the 1.5.5 configuration validators use, kept byte-for-byte for an ASCII host;
/// a caller judging a URL of any scheme reads it with [`url_host`] or [`parse_url`]. A non-ASCII
/// host reads as its punycode name ([`url_host_to_ascii`]), as the dialling stack reads it
/// (`http://ｌｏｃａｌｈｏｓｔ/` names `localhost`), and `None` when UTS #46 refuses it: a host read
/// as written here would be judged as a name no dial reaches.
pub fn extract_normalized_host(url: &str) -> Option<String> {
    let url = strip_whatwg_removed(url);
    let rest = strip_scheme(url.as_ref())?;
    normalize_authority(rest)
}

/// The same host extraction over an authority that names no scheme at all (`host:port`). Anything
/// carrying a `://` extracts no host here, so a scheme is never read as a hostname. A non-ASCII host
/// reads as its punycode name ([`url_host_to_ascii`]), the name a dial of it reaches, and `None`
/// when UTS #46 refuses it.
pub fn extract_normalized_authority_host(authority: &str) -> Option<String> {
    let authority = strip_whatwg_removed(authority);
    if authority.contains("://") {
        return None;
    }
    normalize_authority(&authority)
}

/// Everything [`extract_normalized_host`] does once the scheme is out of the way, shared by both
/// spellings so neither can read a different host than the other. A non-ASCII host is mapped to its
/// punycode name ([`url_host_to_ascii`]) before the root dot is dropped; an ASCII one is
/// [`normalize_host`]'s, byte for byte.
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
    let decoded = percent_decode_host(host);
    let mapped = url_host_to_ascii(decoded.as_ref()).ok()?;
    Some(
        mapped
            .strip_suffix('.')
            .unwrap_or(mapped.as_ref())
            .to_string(),
    )
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
    /// The host, unbracketed, through [`normalize_host`]. An ASCII host keeps its case as written. A
    /// non-ASCII one is read as `url` 2.5.8 read it: under a special scheme ([`is_special_scheme`])
    /// its UTS #46 punycode name ([`url_host_to_ascii`]), under any other its opaque spelling,
    /// percent-encoded. The host is always ASCII.
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
    /// The host is empty, holds a byte no host may hold, or is a non-ASCII name UTS #46 refuses.
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

/// A code point `url` 2.5.8 refuses in an opaque host, checked on the spelling itself, before any
/// decode (`Host::parse_opaque`): `%` is not one of them.
fn forbidden_in_opaque_host(c: char) -> bool {
    matches!(
        c,
        '\0' | '\t'
            | '\n'
            | '\r'
            | ' '
            | '#'
            | '/'
            | ':'
            | '<'
            | '>'
            | '?'
            | '@'
            | '['
            | '\\'
            | ']'
            | '^'
            | '|'
    )
}

/// A decoded host read as the ASCII name a dialling stack dials: an ASCII host as it is, a non-ASCII
/// one through UTS #46 domain-to-ASCII (mapped, normalised, lower-cased, each non-ASCII label
/// punycoded), the WHATWG forbidden domain code points refused in what the mapping produced.
///
/// This is `url` 2.5.8's host parser's own call, `idna::domain_to_ascii_from_cow` with
/// [`idna::AsciiDenyList::URL`] (hyphens allowed, DNS length not checked): the reading busbar 1.5.5
/// dialled an IDN by and sent as its `Host`. `bücher.example` reads `xn--bcher-kva.example`; a
/// full-width `１２７.０.０.１` reads `127.0.0.1`, so the address predicates judge the address it
/// dials. An ASCII host is handed back borrowed, its case kept: callers compare names case-blind.
///
/// # Errors
///
/// [`UrlRefusal::NoHost`] when UTS #46 refuses the name (a disallowed code point, a bad punycode
/// label, a bidi rule broken) or the mapping produced a forbidden domain code point (`ｂ＜.example`
/// maps to `b<.example`).
pub fn url_host_to_ascii(host: &str) -> Result<Cow<'_, str>, UrlRefusal> {
    if host.is_ascii() {
        return Ok(Cow::Borrowed(host));
    }
    idna::domain_to_ascii_from_cow(Cow::Borrowed(host.as_bytes()), idna::AsciiDenyList::URL)
        .map_err(|_| UrlRefusal::NoHost)
}

/// `url` 2.5.8's IPv4 READING of a host already mapped to ASCII ([`url_host_to_ascii`]), the step
/// its host parser takes after the mapping (`Host::parse_cow`: the WHATWG ends-in-a-number check,
/// then the IPv4 parser, `url/src/host.rs` `ends_in_a_number`, `parse_ipv4number`,
/// `parse_ipv4addr`).
/// `Ok(Some(addr))`: `url` dials the host as `addr` (`127.1`, `0x7f.1`, `017700000001` and `0x` all
/// read as an address; one trailing root dot is allowed). `Ok(None)`: the host is a domain to
/// `url`.
///
/// # Errors
///
/// [`UrlRefusal::NoHost`] when the host ends in a number but is no address `url` reads
/// (`1.2.3.4.5`, `999.1.1.1`, `09`): `url` refuses a URL naming it.
pub fn url_host_ipv4(host: &str) -> Result<Option<Ipv4Addr>, UrlRefusal> {
    // The one port of `url`'s IPv4 reading, the one `url`'s special host is read by too.
    if !ends_in_a_number(host) {
        return Ok(None);
    }
    url_ipv4(host).map(Some).ok_or(UrlRefusal::NoHost)
}

/// THE HOST A DESTINATION JUDGE COMPARES, read as the name or address a URL client dials: the
/// brackets dropped, the host mapped to ASCII by UTS #46 ([`url_host_to_ascii`]: `ｌｏｃａｌｈｏｓｔ`
/// reads `localhost`, `①⑥⑨.②⑤④.①⑥⑨.②⑤④` reads `169.254.169.254`, `LOCALHOST。` reads
/// `localhost.`), one trailing root dot dropped, lower-cased. An ASCII host is that host as before,
/// byte for byte, and so is an IPv6 literal (a zone id included), which is never mapped.
///
/// The host is then held to `url`'s IPv4 reading ([`url_host_ipv4`]): the address [`host_ip`] reads
/// out of it must be the address `url` dials it as. An alternate IPv4 spelling (`0x7f.1`,
/// `017700000001`) is handed back as spelled, so a judge reads it as it always did
/// ([`is_alternate_ipv4_encoding`]): measured over every spelling of up to seven characters from
/// `0179x8f.`, no host that spelling test passes reads as a different address under `url`.
///
/// # Errors
///
/// [`UrlRefusal::NoHost`], the host unjudgeable: UTS #46 refuses it, or it ends in a number and
/// `url` reads an address [`host_ip`] does not (`0x` is `0.0.0.0` to `url` and a name to a reader
/// that stops there) or refuses it as no address at all (`1.2.3.4.5`), or it holds a `%` outside an
/// IPv6 literal's zone id. A host reaches a judge decoded (every URL reader here decodes it), so a
/// `%` left in one is an escape this reading does not decode: `%6c%6fcalhost` is `localhost` to a
/// client that decodes it and an unknown name here, so it is judged as neither.
pub fn judged_host(host: &str) -> Result<String, UrlRefusal> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if let Some(at) = h.find('%') {
        // Only an IPv6 literal carries a `%`, opening its zone id (`fe80::1%eth0`, `fe80::1%25eth0`).
        if h[..at].parse::<Ipv6Addr>().is_err() {
            return Err(UrlRefusal::NoHost);
        }
    }
    let fold = |s: &str| s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase();
    if h.contains(':') && (h.is_ascii() || host_ip(h).is_some()) {
        return Ok(fold(h));
    }
    let name = fold(url_host_to_ascii(h)?.as_ref());
    let agrees = match url_host_ipv4(&name) {
        Ok(None) => true,
        Ok(Some(v4)) => host_ip(&name) == Some(IpAddr::V4(v4)),
        Err(_) => false,
    };
    if agrees || is_alternate_ipv4_encoding(&name) {
        Ok(name)
    } else {
        Err(UrlRefusal::NoHost)
    }
}

/// READ A URL OF ANY SCHEME, by its family's rules (see [`UrlFamily`]).
///
/// The authority ends at the first `/`, `?` or `#` (and, for [`UrlFamily::Web`], `\`), so
/// `https://127.0.0.1?x`, `https://localhost#a` and `https://10.0.0.5\x/` read the host the
/// dialling stack reads, and `ldap://evil.example#@127.0.0.1` reads `evil.example`. A userinfo is
/// split at the LAST `@` of the authority and reported, never kept.
///
/// A non-ASCII host is read the way busbar 1.5.5's `url` 2.5.8 read it. Under one of `url`'s
/// special schemes ([`is_special_scheme`]) it is its punycode name ([`url_host_to_ascii`]), so the
/// host judged is the host dialled. Under any other scheme `url` kept it as an OPAQUE host, the
/// host as written with every non-ASCII and C0-control byte percent-encoded (`Host::parse_opaque`),
/// and so does this reader: `ldap://bücher.example` reads `b%C3%BCcher.example`. An ASCII host is
/// read as before under every scheme.
///
/// file: hosts are read opaque; no file: URL is dialled or judged.
///
/// # Errors
///
/// [`UrlRefusal`] when the string has no scheme, no authority, no usable host, a malformed bracket
/// or port, or a backslash inside a [`UrlFamily::Generic`] authority.
pub fn parse_url(url: &str) -> Result<UrlParts, UrlRefusal> {
    parse_url_raw(url).map(|(parts, _)| parts)
}

/// [`parse_url`], and the host exactly as the authority spelled it (the IPv6 literal without its
/// brackets).
fn parse_url_raw(url: &str) -> Result<(UrlParts, String), UrlRefusal> {
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
    let (host, raw_host, port) = if let Some(inner) = host_port.strip_prefix('[') {
        let (literal, after) = inner.split_once(']').ok_or(UrlRefusal::Bracket)?;
        if literal.parse::<Ipv6Addr>().is_err() {
            return Err(UrlRefusal::Bracket);
        }
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or(UrlRefusal::Bracket)?),
        };
        (literal.to_string(), literal.to_string(), port)
    } else {
        let (raw, port) = match host_port.rsplit_once(':') {
            Some((h, _)) if h.contains(':') => return Err(UrlRefusal::Bracket),
            Some((h, p)) => (h, Some(p)),
            None => (host_port, None),
        };
        let decoded = percent_decode_host(raw);
        // A special scheme's host is read decoded, as `url` reads it. Any other scheme's host is
        // read decoded too while that decode is a plain ASCII host (so `%6c%6fcalhost` is judged
        // as `localhost`); one that is not, `url` kept as an opaque host and so does this reader.
        let read_decoded = is_special_scheme(&scheme)
            || (decoded.is_ascii() && !decoded.contains(forbidden_in_host));
        let host = if read_decoded {
            // Decoded first, then mapped, then the one trailing root dot dropped: a mapping can
            // make that dot (a full-width `．` reads `.`), and `url` maps the decoded host too.
            let mapped = url_host_to_ascii(decoded.as_ref())?;
            let host = mapped.strip_suffix('.').unwrap_or(mapped.as_ref());
            if host.is_empty() || host.contains(forbidden_in_host) {
                return Err(UrlRefusal::NoHost);
            }
            host.to_string()
        } else {
            // `url`'s opaque host, byte for byte: the spelling checked as `url` checks it (so a
            // `%25` stands), then percent-encoded, its root dot kept.
            if raw.contains(forbidden_in_opaque_host) {
                return Err(UrlRefusal::NoHost);
            }
            opaque_host(raw)
        };
        (host, raw.to_string(), port)
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
    Ok((
        UrlParts {
            scheme,
            family,
            userinfo,
            host,
            port,
            path,
        },
        raw_host,
    ))
}

/// One of `url`'s SPECIAL schemes with a dialled host (WHATWG: the four web schemes and `ftp`), whose
/// host `url` 2.5.8 maps by UTS #46 (`Host::parse`); every other scheme's host is opaque to it
/// (`Host::parse_opaque`). Takes a lower-case scheme.
///
/// WHATWG's sixth special scheme, the local-file one, is not here: `url` reads its host by a grammar
/// of its own (`Parser::get_file_host`: `localhost` read as no host, a drive letter as a path), which
/// this reader does not follow for it either, and no busbar path dials it, sends it or names its
/// host on a wire. Its host is read as any other non-web scheme's.
#[must_use]
pub fn is_special_scheme(scheme: &str) -> bool {
    // The four web schemes are [`UrlFamily::Web`]'s one list; `url` adds `ftp` to them.
    UrlFamily::of(scheme) == UrlFamily::Web || scheme == "ftp"
}

/// `url`'s opaque host serialisation (`Host::parse_opaque`): every byte outside printable ASCII
/// (the C0 controls, DEL and every non-ASCII byte, `percent_encoding::CONTROLS`) as `%XX`, upper-case
/// hex; every other byte as written.
fn opaque_host(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if !(0x20..0x7f).contains(&b) {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push(char::from(b));
        }
    }
    out
}

/// `url`'s ends-in-a-number check (WHATWG): the last label, or the one before an empty last label,
/// is all digits or an IPv4 number.
fn ends_in_a_number(host: &str) -> bool {
    let mut labels = host.rsplit('.');
    let last = match labels.next() {
        Some("") => match labels.next() {
            Some(l) => l,
            None => return false,
        },
        Some(l) => l,
        None => return false,
    };
    (!last.is_empty() && last.bytes().all(|b| b.is_ascii_digit())) || ipv4_number(last).is_some()
}

/// `url`'s IPv4 number parser (WHATWG): `0x` hex, a leading-`0` octal, or decimal; `Some(None)`
/// for a valid number that overflows 32 bits; `None` for no number.
fn ipv4_number(mut part: &str) -> Option<Option<u32>> {
    if part.is_empty() {
        return None;
    }
    let mut radix = 10;
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        part = hex;
        radix = 16;
    } else if let Some(octal) = part.strip_prefix('0').filter(|o| !o.is_empty()) {
        part = octal;
        radix = 8;
    }
    if part.is_empty() {
        return Some(Some(0));
    }
    let valid = match radix {
        8 => part.bytes().all(|b| (b'0'..=b'7').contains(&b)),
        16 => part.bytes().all(|b| b.is_ascii_hexdigit()),
        _ => part.bytes().all(|b| b.is_ascii_digit()),
    };
    if !valid {
        return None;
    }
    Some(u32::from_str_radix(part, radix).ok())
}

/// `url`'s IPv4 parser (WHATWG): up to four numbers, one trailing empty label ignored, the last
/// number filling the remaining low bytes. `None` where `url` refused the host.
fn url_ipv4(host: &str) -> Option<Ipv4Addr> {
    let mut parts: Vec<&str> = host.split('.').collect();
    if parts.last() == Some(&"") {
        parts.pop();
    }
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut numbers = Vec::with_capacity(parts.len());
    for part in parts {
        numbers.push(ipv4_number(part)??);
    }
    let mut ipv4 = numbers.pop()?;
    if ipv4 > u32::MAX >> (8 * numbers.len() as u32) {
        return None;
    }
    if numbers.iter().any(|n| *n > 255) {
        return None;
    }
    for (i, n) in numbers.iter().enumerate() {
        ipv4 += n << (8 * (3 - i as u32));
    }
    Some(Ipv4Addr::from(ipv4))
}

/// The host of a URL of any scheme, read by [`parse_url`]; `None` when it reads no host.
#[must_use]
pub fn url_host(url: &str) -> Option<String> {
    parse_url(url).ok().map(|p| p.host)
}

/// The host of a URL of any scheme as SPELLED, read as [`parse_url`] reads the authority but not
/// normalised: an IPv6 literal unbracketed (as [`Ipv6Addr`] displays it), any other host exactly
/// as written, a trailing root dot KEPT (`example.com.` is not `example.com` here). For a caller
/// whose rule compares the host a URL reader serialised, byte for byte; `None` when it reads no
/// host.
#[must_use]
pub fn url_host_verbatim(url: &str) -> Option<String> {
    // The spelling [`parse_url_raw`] keeps beside the host it serialised; only a bracketed literal
    // parses as an IPv6 address here (an unbracketed host holds no `:`), and it is shown as
    // `Ipv6Addr` displays it.
    let (_, spelled) = parse_url_raw(url).ok()?;
    Some(
        spelled
            .parse::<Ipv6Addr>()
            .map_or(spelled, |addr| addr.to_string()),
    )
}

/// The host of a DIAL TARGET, which may be spelled as a URL or as a bare `host`, `host:port`,
/// `[v6]` or `[v6]:port` authority (a bare v6 literal is kept whole, a zone suffix too). A target
/// carrying `://`, or opening with a [`UrlFamily::Web`] scheme and `:`, is read as a URL, so its
/// scheme is never read as the host. `None` when no host can be read.
///
/// A URL whose host [`parse_url`] reads only as `url`'s opaque host because its spelling decodes to
/// a forbidden host code point (`ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi`, a socket path; `%25`,
/// `%40`) names no host a dial reaches, and reads `None` here: such a target is refused at the
/// destination check, as it was before the opaque reading, and never dialled as a host.
#[must_use]
pub fn target_host(target: &str) -> Option<String> {
    let trimmed = strip_whatwg_removed(target);
    let web_scheme = trimmed
        .split_once(':')
        .is_some_and(|(s, _)| UrlFamily::of(&s.to_ascii_lowercase()) == UrlFamily::Web);
    if web_scheme || trimmed.contains("://") {
        let (parts, raw) = parse_url_raw(&trimmed).ok()?;
        let literal = parts.host.contains(':');
        if !literal && percent_decode_host(&raw).contains(forbidden_in_host) {
            return None;
        }
        Some(parts.host)
    } else {
        extract_normalized_authority_host(&trimmed)
    }
}

/// A URL's AUTHORITY, split where the dialling stack splits it, borrowed from the string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authority<'a> {
    /// The scheme before `://`, as written; `None` when the string carries none.
    pub scheme: Option<&'a str>,
    /// The userinfo: everything before the authority's LAST `@`. Never a host.
    pub userinfo: Option<&'a str>,
    /// `host[:port]`, as written (brackets and case kept).
    pub host_port: &'a str,
    /// Everything after the authority, as written, from its first delimiter on.
    pub tail: &'a str,
    /// The authority ends at a `\` as at a `/` (no scheme, or a [`UrlFamily::Web`] one).
    pub web: bool,
}

/// THE ONE AUTHORITY SPLIT: every caller that reads a URL's host, strips its userinfo or masks it
/// reads the authority here, so no two of them can end it at different bytes.
///
/// v1.5.5's reading (`host_from_base`): an optional `scheme://`; the
/// authority ends at the first `/`, `?` or `#` and, when the scheme is absent or a
/// [`UrlFamily::Web`] scheme, at the first `\` too (the WHATWG parser the dialling stacks use reads
/// `\` as `/` there); the userinfo is everything before the authority's LAST `@`. So
/// `https://evil.example\@victim.example/` has the authority `evil.example`, the host the socket
/// dials, and no userinfo. Pure: no allocation, no normalisation.
#[must_use]
pub fn url_authority(url: &str) -> Authority<'_> {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r))
            if s.starts_with(|c: char| c.is_ascii_alphabetic())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')) =>
        {
            (Some(s), r)
        }
        _ => (None, url),
    };
    // The scheme lower-cased on the stack (no web scheme is longer than eight bytes), then read
    // by [`UrlFamily::of`]: the one list of web schemes.
    let web = scheme.is_none_or(|s| {
        let mut low = [0u8; 8];
        s.len() <= low.len() && {
            low[..s.len()].copy_from_slice(s.as_bytes());
            low[..s.len()].make_ascii_lowercase();
            std::str::from_utf8(&low[..s.len()]).is_ok_and(|l| UrlFamily::of(l) == UrlFamily::Web)
        }
    });
    let end = if web {
        rest.find(['/', '?', '#', '\\'])
    } else {
        rest.find(['/', '?', '#'])
    }
    .unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (userinfo, host_port) = match authority.rfind('@') {
        Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
        None => (None, authority),
    };
    Authority {
        scheme,
        userinfo,
        host_port,
        tail,
        web,
    }
}

#[cfg(test)]
#[path = "tests/net_tests.rs"]
mod net_tests;
