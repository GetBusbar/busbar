// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROXY ROUTE CHOICE: which proxy, if any, a dial goes through. The connector reads the

use std::borrow::Cow;
use std::sync::Arc;

use hyper_util::client::proxy::matcher::Matcher;

/// ONE PROXY ENDPOINT: where to connect, and the `Proxy-Authorization` value its userinfo became.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyHop {
    host: String,
    port: u16,
    auth: Option<String>,
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
        let host = if target_host.contains(':') && !target_host.starts_with('[') {
            Cow::Owned(format!("[{target_host}]"))
        } else {
            Cow::Borrowed(target_host)
        };
        // `x@10.0.0.1` parses with host() == "10.0.0.1": the read-back refuses it, so userinfo,
        // a path or a port smuggled into the host never turns into an exemption.
        http::Uri::try_from(format!("http://{host}/")).is_ok_and(|u| {
            u.host().is_some_and(|h| h.eq_ignore_ascii_case(&host))
                && self.exempt.intercept(&u).is_none()
        })
    }
}
