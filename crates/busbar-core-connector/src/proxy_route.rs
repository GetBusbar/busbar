// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROXY ROUTE CHOICE: which proxy, if any, a dial goes through. The connector reads the

use std::sync::Arc;

use hyper_util::client::proxy::matcher::Matcher;

/// ONE PROXY ENDPOINT: where to connect, and the `Proxy-Authorization` value its userinfo became.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyHop {
    host: String,
    port: u16,
    auth: Option<String>,
    /// The proxy's own `host:port` ([`Self::endpoint`]), spelled once with the hop.
    endpoint: String,
    /// What a CONNECT request carries after its `Host` line: the `Proxy-Authorization` line where
    /// set, then the blank line. Spelled once with the hop.
    connect_tail: String,
}

impl std::fmt::Debug for ProxyHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the hop is parsed once from the proxy environment; its endpoint is spelled once"
        )]
        let endpoint = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the hop is parsed once from the proxy environment; its CONNECT tail is spelled once"
        )]
        let connect_tail = match &auth {
            Some(auth) => format!("Proxy-Authorization: {auth}\r\n\r\n"),
            None => "\r\n".to_owned(),
        };
        Self {
            host,
            port,
            auth,
            endpoint,
            connect_tail,
        }
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
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// What a CONNECT request carries after its `Host` line: the `Proxy-Authorization` line where
    /// set, then the blank line.
    #[must_use]
    pub(crate) fn connect_tail(&self) -> &str {
        &self.connect_tail
    }
}

/// THE CHOICE: the secured slot, the plain slot, and the hosts exempt from both.
#[derive(Debug)]
pub struct ProxyChoice {
    secured: Option<Arc<ProxyHop>>,
    plain: Option<Arc<ProxyHop>>,
    exempt: Matcher,
}

/// The intercept the exemption matcher answers with. It is never dialled: only whether
/// the matcher intercepts (not exempt) or not (exempt) is read.
const SENTINEL: &str = "http://no-proxy.invalid";

impl ProxyChoice {
    /// The choice of a `secured` slot, a `plain` slot, and the exemption list `exempt` as its
    #[must_use]
    pub fn new(secured: Option<Arc<ProxyHop>>, plain: Option<Arc<ProxyHop>>, exempt: &str) -> Self {
        Self {
            secured,
            plain,
            exempt: Matcher::builder()
                .http(SENTINEL)
                .https(SENTINEL)
                .no(exempt)
                .build(),
        }
    }

    /// The per-dial choice — `None` → direct (the host is exempt, or no proxy is set for the
    #[must_use]
    pub fn select(&self, secured_target: bool, target_host: &str) -> Option<Arc<ProxyHop>> {
        if self.exempts(target_host) {
            return None;
        }
        if secured_target {
            self.secured.clone()
        } else {
            self.plain.clone()
        }
    }

    /// Whether the exemption list excludes `target_host` from both slots. Matching is
    /// hyper-util's `matcher::Matcher` (curl's rules, built with `builder()`, never
    /// `from_env()`, whose CGI rule would turn every proxy off), with three deliberate
    /// deviations: `*` exempts IP literals too, a bare v6 host is bracketed before it is
    /// matched, and the host must read back unchanged from the `Uri` it forms. A host that
    /// does not is never exempt, so a dial errs toward the proxy, never a silent direct dial.
    #[must_use]
    pub fn exempts(&self, target_host: &str) -> bool {
        http::Uri::try_from(format!("http://{target_host}/"))
            .is_ok_and(|u| self.exempt.intercept(&u).is_none())
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
    fn parse(raw: &str) -> Self {
        // busbar:expect(bp::fresh_buffer, reason = "config: the NO_PROXY list is parsed once from the proxy environment")
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
            #[expect(
                clippy::disallowed_methods,
                reason = "config: each NO_PROXY domain is lower-cased once, as the list is parsed"
            )]
            let domain = part.trim_start_matches('.').to_ascii_lowercase();
            entries.push(NoProxyEntry::Domain(domain));
        }
        NoProxy { entries }
    }

    fn matches(&self, target_host: &str) -> bool {
        let bare = target_host.trim_start_matches('[').trim_end_matches(']');
        let ip: Option<IpAddr> = bare.parse().ok();
        let host = target_host.as_bytes();
        // busbar:expect(bp::state_scan, reason = "config: the operator's NO_PROXY list, fixed at boot and a handful of entries long; no request grows it")
        self.entries.iter().any(|entry| match entry {
            NoProxyEntry::MatchAll => true,
            NoProxyEntry::Ip(a) => ip == Some(*a),
            NoProxyEntry::Cidr(net, len) => ip.is_some_and(|h| cidr_contains(net, *len, &h)),
            NoProxyEntry::Domain(d) => {
                // `d` is lower-cased at parse; the host is compared ASCII-case-insensitively in place.
                let d = d.as_bytes();
                ip.is_none()
                    && (host.eq_ignore_ascii_case(d)
                        || (host.len() > d.len()
                            && host[host.len() - d.len()..].eq_ignore_ascii_case(d)
                            && host[host.len() - d.len() - 1] == b'.'))
            }
        })
    }
}
