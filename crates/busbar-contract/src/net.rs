// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE URL AND HOST READER — one reader, for every caller that judges where a URL points.

use std::borrow::Cow;

/// THE ADDRESS VALUE TYPES A PLUGIN NAMES, through the contract and never through `std::net`.
pub use std::net::{
    AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};

/// Well-known cloud-metadata / internal DNS names that resolve, at connect time, to the IMDS family
pub const METADATA_HOSTS: &[&str] = &[
    "metadata.google.internal",
    "metadata.internal",
    "metadata.tencentyun.com",
    "metadata.platformequinix.com",
    "instance-data",
    "instance-data.ec2.internal",
];

/// TRUE for an IPv4 literal no busbar guard may connect to: loopback, link-local (which is where the
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
        || o[0] == 0
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
}

/// TRUE for an IPv6 literal no busbar guard may connect to.
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
pub fn is_cgnat_shared_v4(v4: &Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// Unwrap an embedded IPv4 target from an IPv6 literal, covering EVERY form a connecting stack
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
#[must_use]
pub fn is_socket_literal(s: &str) -> bool {
    s.parse::<std::net::SocketAddr>().is_ok()
}

/// Whether `s` is a bare IP LITERAL, v4 or v6: exactly the grammar `std::net::IpAddr`'s parser
#[must_use]
pub fn is_ip_literal(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// The address a normalized host names, in any spelling the resolver accepts as a literal: a
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
pub fn host_is_cloud_metadata(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    METADATA_HOSTS.iter().any(|m| name.eq_ignore_ascii_case(m))
        || host_ip(name).is_some_and(|ip| ip_is_cloud_metadata(&ip))
}

/// TRUE when a normalized host is an IPv6 link-local literal (fe80::/10, [`is_link_local_v6`]) in
pub fn host_is_link_local_v6(host: &str) -> bool {
    matches!(host_ip(host), Some(IpAddr::V6(v6)) if is_link_local_v6(&v6))
}

/// True when `host` (already normalized) is a private, loopback, link-local, unspecified or CGNAT
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

/// Whether a URL claims the given scheme, case-insensitively.
pub fn scheme_is(url: &str, scheme: &str) -> bool {
    url.split_once("://")
        .is_some_and(|(s, _)| s.eq_ignore_ascii_case(scheme))
}

/// Strip a web scheme (`https` or its plaintext twin) case-insensitively, returning the
fn strip_scheme(url: &str) -> Option<&str> {
    let (scheme, rest) = url.split_once("://")?;
    (scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http")).then_some(rest)
}

/// Percent-decode a host string (`%XX` → byte). An invalid escape is left verbatim, so a malformed
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
fn strip_whatwg_removed(s: &str) -> Cow<'_, str> {
    let s = s.trim_matches(|c: char| c <= '\u{1f}' || c == ' ');
    if s.contains(['\t', '\n', '\r']) {
        Cow::Owned(s.replace(['\t', '\n', '\r'], ""))
    } else {
        Cow::Borrowed(s)
    }
}

/// THE HOST NORMALIZATION every reader here shares: percent-decoded, then one trailing FQDN-root dot
pub fn normalize_host(raw: &str) -> String {
    let decoded = percent_decode_host(raw);
    let decoded = decoded.as_ref();
    decoded.strip_suffix('.').unwrap_or(decoded).to_string()
}

/// The host a dialling stack would read out of an `https://` (or plaintext) URL, after every
pub fn extract_normalized_host(url: &str) -> Option<String> {
    let url = strip_whatwg_removed(url);
    let rest = strip_scheme(url.as_ref())?;
    normalize_authority(rest)
}

/// The same host extraction over an authority that names no scheme at all (`host:port`). Anything
pub fn extract_normalized_authority_host(authority: &str) -> Option<String> {
    let authority = strip_whatwg_removed(authority);
    if authority.contains("://") {
        return None;
    }
    normalize_authority(&authority)
}

/// Everything [`extract_normalized_host`] does once the scheme is out of the way, shared by both
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
pub fn url_host_to_ascii(host: &str) -> Result<Cow<'_, str>, UrlRefusal> {
    if host.is_ascii() {
        return Ok(Cow::Borrowed(host));
    }
    idna::domain_to_ascii_from_cow(Cow::Borrowed(host.as_bytes()), idna::AsciiDenyList::URL)
        .map_err(|_| UrlRefusal::NoHost)
}

/// `url` 2.5.8's IPv4 READING of a host already mapped to ASCII ([`url_host_to_ascii`]), the step
pub fn url_host_ipv4(host: &str) -> Result<Option<Ipv4Addr>, UrlRefusal> {
    if !ends_in_a_number(host) {
        return Ok(None);
    }
    url_ipv4(host).map(Some).ok_or(UrlRefusal::NoHost)
}

/// THE HOST A DESTINATION JUDGE COMPARES, read as the name or address a URL client dials: the
pub fn judged_host(host: &str) -> Result<String, UrlRefusal> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if let Some(at) = h.find('%') {
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
pub fn parse_url(url: &str) -> Result<UrlParts, UrlRefusal> {
    parse_url_raw(url).map(|(parts, _)| parts)
}

/// [`parse_url`], and the host exactly as the authority spelled it (the IPv6 literal without its
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

        let read_decoded = is_special_scheme(&scheme)
            || (decoded.is_ascii() && !decoded.contains(forbidden_in_host));
        let host = if read_decoded {
            let mapped = url_host_to_ascii(decoded.as_ref())?;
            let host = mapped.strip_suffix('.').unwrap_or(mapped.as_ref());
            if host.is_empty() || host.contains(forbidden_in_host) {
                return Err(UrlRefusal::NoHost);
            }
            host.to_string()
        } else {
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
#[must_use]
pub fn is_special_scheme(scheme: &str) -> bool {
    UrlFamily::of(scheme) == UrlFamily::Web || scheme == "ftp"
}

/// `url`'s opaque host serialisation (`Host::parse_opaque`): every byte outside printable ASCII
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
#[must_use]
pub fn url_host_verbatim(url: &str) -> Option<String> {
    let (_, spelled) = parse_url_raw(url).ok()?;
    Some(
        spelled
            .parse::<Ipv6Addr>()
            .map_or(spelled, |addr| addr.to_string()),
    )
}

/// The host of a DIAL TARGET, which may be spelled as a URL or as a bare `host`, `host:port`,
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
