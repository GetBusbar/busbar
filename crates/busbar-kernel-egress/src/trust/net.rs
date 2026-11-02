// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The network guard: what a destination may be dialled.

pub use busbar_contract::net::*;

/// WHY A GUARDED FETCH WAS REFUSED — the FACT, not the sentence.
///
/// Every arm names the URL, host or address that caused it, because a refusal an operator cannot
/// diagnose is a refusal an operator disables. Callers with an established vocabulary convert this
/// into their own refusal type so an operator reading a log still sees the caller's own name for
/// the destination; callers without one render it with the [`std::fmt::Display`] below. What no
/// caller does is re-derive the DECISION, which is the whole reason this enum is here and not there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressRefusal {
    /// The URL had no `http`/`https` scheme, or no scheme at all. Everything else — `file:`,
    /// `gopher:`, `smb:`, `ftp:`, `data:` — is refused by ABSENCE rather than by a blocklist,
    /// because a blocklist of schemes is a list somebody has to keep up with.
    Scheme {
        /// The URL, with any authority credential replaced by a marker.
        url: String,
        /// The scheme it claimed.
        scheme: String,
    },
    /// The URL had no host component, or an unusable authority (userinfo, an unclosed IPv6
    /// bracket, an unparseable port). Carried with any authority credential replaced by a marker,
    /// since a refusal naming a rejected userinfo would otherwise be the one place a password is
    /// written down twice.
    NoHost(String),
}

impl std::fmt::Display for AddressRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressRefusal::Scheme { url, scheme } => write!(
                f,
                "`{url}` uses scheme `{scheme}`; only http(s) is fetched over"
            ),
            AddressRefusal::NoHost(u) => write!(f, "`{u}` has no usable host"),
        }
    }
}

/// A refusal is an error a caller can carry in a cause chain: the egress client's dial judge hands

impl std::error::Error for AddressRefusal {}

/// Split an `http(s)://host[:port][/path]` URL into `(https, host, port, path)`.

pub fn split_url(url: &str) -> Result<(bool, String, u16, String), AddressRefusal> {
    let https = match url.split_once("://").map(|(scheme, _)| scheme) {
        Some(scheme) if scheme.eq_ignore_ascii_case("https") => true,
        Some(scheme) if scheme.eq_ignore_ascii_case("http") => false,
        _ => {
            return Err(AddressRefusal::Scheme {
                url: redact_userinfo(url),
                scheme: scheme_of(url),
            });
        }
    };
    let no_host = || AddressRefusal::NoHost(redact_userinfo(url));
    let parts = parse_url(url).map_err(|_| no_host())?;

    if parts.userinfo {
        return Err(no_host());
    }
    let port = parts.port.unwrap_or_else(|| default_port(https));
    Ok((https, parts.host, port, parts.path))
}

/// The URL as a refusal may repeat it: everything an authority put before its last `@` replaced by a

pub fn redact_userinfo(url: &str) -> String {
    let (prefix, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (&url[..scheme.len() + 3], rest),
        None => ("", url),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{prefix}<redacted>@{}", &rest[at + 1..]),
        None => url.to_string(),
    }
}

/// A provider BASE URL with its authority's userinfo removed: `scheme://user:pass@host:port/path`

pub fn strip_userinfo(url: &str) -> std::borrow::Cow<'_, str> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return std::borrow::Cow::Borrowed(url);
    };
    let authority_end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => std::borrow::Cow::Owned(format!("{scheme}://{}", &rest[at + 1..])),
        None => std::borrow::Cow::Borrowed(url),
    }
}

/// The scheme a string CLAIMS, for a refusal message. Nothing is decided from it — the decision is

fn scheme_of(url: &str) -> String {
    match url.split_once(':') {
        Some((s, _)) if !s.is_empty() && !s.contains('/') => s.to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// The port a scheme implies when the authority names none.
pub fn default_port(https: bool) -> u16 {
    if https {
        443
    } else {
        80
    }
}

/// An operator's allow or block list, canonicalized once instead of once per dial.
///
/// The entries an operator writes are strings, and judging a host against them means trimming each
/// entry, dropping its trailing FQDN dot, and parsing the ones that are IP literals. None of that
/// depends on the host being judged, so none of it belongs on the request path: a deployment with a
/// denylist of any size re-did the whole parse for every candidate of every dial. It is done here,
/// where the list is stated, and a judgement is then a scan over values already in their final form.
#[derive(Debug, Default, Clone)]
struct HostSet {
    /// Hostname (and verbatim) entries, trimmed, trailing dots dropped, lowercased. Empty and
    /// whitespace-only entries are not kept, so they can never match.
    names: Vec<String>,
    /// The entries that are IPv4 literals, parsed.
    v4: Vec<std::net::Ipv4Addr>,
    /// The entries that are IPv6 literals, parsed.
    v6: Vec<std::net::Ipv6Addr>,
}

/// AN OPERATOR'S LIST ENTRY (`security.blocked_metadata_hosts`, `security.allow_metadata_hosts`, a

pub fn list_entry_host(entry: &str) -> Result<std::borrow::Cow<'_, str>, UrlRefusal> {
    let entry = entry.trim();
    if entry.is_ascii() {
        return Ok(std::borrow::Cow::Borrowed(entry));
    }
    let mapped = url_host_to_ascii(entry)?;
    if mapped.trim_end_matches('.').is_empty() {
        return Err(UrlRefusal::NoHost);
    }
    Ok(mapped)
}

impl HostSet {
    /// Canonicalize a list of operator-written entries, each read as a target's host is

    fn parse(entries: &[String]) -> Self {
        let mut set = HostSet::default();
        for entry in entries {
            let Ok(mapped) = list_entry_host(entry) else {
                continue;
            };
            if judged_host(&mapped).is_err() {
                continue;
            }
            let norm = mapped.trim_end_matches('.');
            if norm.is_empty() {
                continue;
            }
            if let Ok(v4) = norm.parse::<std::net::Ipv4Addr>() {
                set.v4.push(v4);
            } else if let Ok(v6) = norm.parse::<std::net::Ipv6Addr>() {
                set.v6.push(v6);
            }
            set.names.push(norm.to_ascii_lowercase());
        }
        set
    }

    /// True when the list names nothing at all — the common case, and the one a dial should spend

    fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// True when the already-normalized `host` (as produced by [`extract_normalized_host`]) matches

    fn matches(&self, host: &str) -> bool {
        use std::net::IpAddr;

        if self.is_empty() {
            return false;
        }

        if self.names.iter().any(|n| n.eq_ignore_ascii_case(host)) {
            return true;
        }

        if self.v4.is_empty() && self.v6.is_empty() {
            return false;
        }

        if let Some(expanded) = expand_alternate_ipv4(host) {
            if self.v4.contains(&expanded) {
                return true;
            }
        }

        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => self.v4.contains(&v4),
            Ok(IpAddr::V6(v6)) => {
                let embedded = embedded_ipv4(&v6);
                self.v6.contains(&v6) || embedded.is_some_and(|m| self.v4.contains(&m))
            }
            Err(_) => false,
        }
    }
}

/// Return `Some(host)` if the given URL targets a CLOUD-METADATA endpoint that must be blocked, else

pub fn ssrf_blocked_host(
    url: &str,
    allow_overrides: &[String],
    allow_all: bool,
    extra_blocked: &[String],
) -> Option<String> {
    if allow_all {
        return None;
    }
    judge_against_lists(
        url,
        &HostSet::parse(allow_overrides),
        &HostSet::parse(extra_blocked),
    )
}

/// The denylist judgement over lists already canonicalized, which is what every arm of it wanted.
fn judge_against_lists(
    url: &str,
    allow_overrides: &HostSet,
    extra_blocked: &HostSet,
) -> Option<String> {
    use std::net::IpAddr;

    let host = extract_normalized_host(url).or_else(|| extract_normalized_authority_host(url))?;
    let host = host.as_str();

    if allow_overrides.matches(host) {
        return None;
    }

    if METADATA_HOSTS.iter().any(|m| m.eq_ignore_ascii_case(host)) {
        return Some(host.to_string());
    }

    if extra_blocked.matches(host) {
        return Some(host.to_string());
    }

    host.parse::<IpAddr>()
        .ok()
        .or_else(|| expand_alternate_ipv4(host).map(IpAddr::V4))
        .filter(ip_is_cloud_metadata)
        .map(|_| host.to_string())
}
