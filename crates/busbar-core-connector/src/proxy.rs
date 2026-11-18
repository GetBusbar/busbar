// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROXY ENVIRONMENT, AS EVERY CONNECTOR DIAL HONOURS IT (the engine's proxy behaviour moves

pub use crate::off_path::egress::proxy::{from_env, parse_proxy, resolve_config};
pub use crate::off_path::proxy::connect_request;
pub use crate::proxy_route::{ProxyChoice, ProxyHop};

/// The raw proxy env, read once — a plain value bag so precedence resolution
/// ([`resolve_config`]) is a pure function tests exercise WITHOUT mutating process env
/// (parallel tests race on env mutation).
#[derive(Default)]
pub struct ProxyEnvValues {
    /// `HTTPS_PROXY` / `https_proxy`.
    pub https: Option<String>,
    /// `HTTP_PROXY` / `http_proxy`.
    pub http: Option<String>,
    /// `ALL_PROXY` / `all_proxy`.
    pub all: Option<String>,
    /// `NO_PROXY` / `no_proxy`.
    pub no: Option<String>,
}

pub(crate) const HTTPS_PROXY_KEYS: [&str; 2] = ["HTTPS_PROXY", "https_proxy"];
pub(crate) const HTTP_PROXY_KEYS: [&str; 2] = ["HTTP_PROXY", "http_proxy"];
pub(crate) const ALL_PROXY_KEYS: [&str; 2] = ["ALL_PROXY", "all_proxy"];
pub(crate) const NO_PROXY_KEYS: [&str; 2] = ["NO_PROXY", "no_proxy"];

/// Hard ceiling on the proxy's CONNECT response head; a real response is one status line + a few
pub const CONNECT_HEAD_CAP: usize = 8 * 1024;

/// Wall-clock bound on the CONNECT handshake — the same 10s the socket connect itself carries.
pub const CONNECT_HANDSHAKE: std::time::Duration = std::time::Duration::from_secs(10);

/// What the proxy has answered so far to a CONNECT for `addr` (`host:port`): `Ok(None)` = its head is not
pub fn connect_answer(head: &[u8], addr: &str) -> Result<Option<usize>, String> {
    let Some(at) = head.windows(4).position(|w| w == b"\r\n\r\n") else {
        if head.len() > CONNECT_HEAD_CAP {
            return Err("proxy CONNECT response head exceeded 8KiB".into());
        }
        return Ok(None);
    };

    let line = head.split(|&b| b == b'\r').next().unwrap_or_default();
    let status_2xx = line
        .split(|&b| b == b' ')
        .nth(1)
        .is_some_and(|code| code.first() == Some(&b'2') && code.len() == 3);
    if !status_2xx {
        return Err(crate::cold::egress::proxy_refused_connect(addr, line));
    }
    Ok(Some(at + 4))
}

/// The host of `target` (`host:port`, a v6 host bracketed), as `NO_PROXY` matches it.
#[must_use]
pub fn host_of(target: &str) -> &str {
    if target.starts_with('[') {
        return target.find(']').map_or(target, |end| &target[..=end]);
    }
    target.rsplit_once(':').map_or(target, |(host, _)| host)
}

/// A whole choice whose BOTH slots point at one proxy at `host:port`: what a test wires directly
#[cfg(test)]
pub(crate) fn test_config(
    host: &str,
    port: u16,
    auth: Option<String>,
    no_proxy: &str,
) -> std::sync::Arc<ProxyChoice> {
    let hop = std::sync::Arc::new(ProxyHop::new(host.to_string(), port, auth));
    std::sync::Arc::new(ProxyChoice::new(Some(hop.clone()), Some(hop), no_proxy))
}

/// The exemption list alone, as tests read it.
#[cfg(test)]
pub(crate) fn no_proxy_matches(entries: &str, target_host: &str) -> bool {
    ProxyChoice::new(None, None, entries).exempts(target_host)
}

#[cfg(test)]
#[path = "tests/proxy_tests.rs"]
mod tests;
