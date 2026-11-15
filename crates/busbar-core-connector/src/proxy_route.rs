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
        // The hop is parsed once from the proxy environment: its spellings are made once with it,
        // off the request path.
        let (endpoint, connect_tail) =
            crate::off_path::egress::proxy::hop_spellings(&host, port, auth.as_deref());
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
    /// A `*` entry: hyper-util applies `*` to domain hosts only; ours exempts IP literals too.
    match_all: bool,
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
            match_all: exempt.split(',').any(|p| p.trim() == "*"),
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
        if self.match_all {
            return true;
        }
        // A bare v6 literal is bracketed on the stack (no allocation per dial); one too long to be
        // an address is never exempt.
        let mut bracketed = [0_u8; 64];
        let host = if target_host.contains(':') && !target_host.starts_with('[') {
            let n = target_host.len();
            if n + 2 > bracketed.len() {
                return false;
            }
            bracketed[0] = b'[';
            bracketed[1..=n].copy_from_slice(target_host.as_bytes());
            bracketed[n + 1] = b']';
            let Ok(host) = std::str::from_utf8(&bracketed[..n + 2]) else {
                return false;
            };
            host
        } else {
            target_host
        };
        // `x@192.0.2.1` parses with host() == "192.0.2.1": the read-back refuses it, so userinfo,
        // a path or a port smuggled into the host never turns into an exemption.
        http::Uri::builder()
            .scheme("http")
            .authority(host)
            .path_and_query("/")
            .build()
            .is_ok_and(|u| {
                u.host().is_some_and(|h| h.eq_ignore_ascii_case(host))
                    && self.exempt.intercept(&u).is_none()
            })
    }
}
