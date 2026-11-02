// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROXY ENVIRONMENT, AS EVERY CONNECTOR DIAL HONOURS IT (the engine's proxy behaviour moves

use std::{ffi::OsString, sync::Arc};

pub use crate::proxy_route::{ProxyChoice, ProxyHop};

/// The proxy env value as a REFUSAL may render it: userinfo replaced by `***`, everything
fn redact_userinfo(v: &str) -> String {
    let parts = busbar_contract::net::url_authority(v);
    let (host_port, tail) = (parts.host_port, parts.tail);
    let shown = if parts.userinfo.is_some() {
        format!("***@{host_port}{tail}")
    } else if tail.contains('@') {
        "***".to_string()
    } else {
        format!("{host_port}{tail}")
    };
    match parts.scheme {
        Some(s) => format!("{s}://{shown}"),
        None => shown,
    }
}

/// Parse a proxy env value (`http://[user:pass@]host[:port]`; a bare `host:port` is accepted
pub fn parse_proxy(v: &str) -> Result<ProxyHop, String> {
    let shown = redact_userinfo(v);
    let url = if v.contains("://") {
        v.to_string()
    } else {
        format!("http://{v}")
    };
    let parsed = url::Url::parse(&url)
        .map_err(|e| format!("proxy env value {shown:?} is not a valid URL: {e}"))?;
    if parsed.scheme() != "http" {
        return Err(format!(
            "proxy env value {shown:?} uses scheme {:?}: only plain http:// CONNECT proxies \
             are supported (an https:// proxy would need TLS-to-proxy, which this tunnel does \
             not speak)",
            parsed.scheme()
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("proxy env value {shown:?} has no host"))?
        .to_string();
    let port = parsed.port().unwrap_or(80);
    let auth = (!parsed.username().is_empty()).then(|| {
        use base64::Engine;

        let creds = [
            percent_decoded(parsed.username()),
            b":".to_vec(),
            percent_decoded(parsed.password().unwrap_or_default()),
        ]
        .concat();
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(creds)
        )
    });
    Ok(ProxyHop::new(host, port, auth))
}

/// `text` with every `%XX` escape decoded to its byte; a `%` not followed by two hex digits is
fn percent_decoded(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| char::from(b).to_digit(16);
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(u8::try_from(hi * 16 + lo).unwrap_or(b'%'));
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

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

const HTTPS_PROXY_KEYS: [&str; 2] = ["HTTPS_PROXY", "https_proxy"];
const HTTP_PROXY_KEYS: [&str; 2] = ["HTTP_PROXY", "http_proxy"];
const ALL_PROXY_KEYS: [&str; 2] = ["ALL_PROXY", "all_proxy"];
const NO_PROXY_KEYS: [&str; 2] = ["NO_PROXY", "no_proxy"];

impl ProxyEnvValues {
    /// Uppercase read before lowercase, empty values treated as unset — hyper-util
    pub fn from_process_env() -> Result<Self, String> {
        Self::from_lookup(|key| std::env::var_os(key))
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<OsString>) -> Result<Self, String> {
        let mut first = |keys: [&str; 2]| -> Result<Option<String>, String> {
            for key in keys {
                let Some(value) = lookup(key) else {
                    continue;
                };
                if value.is_empty() {
                    continue;
                }
                return value
                    .into_string()
                    .map(Some)
                    .map_err(|_| format!("proxy environment variable {key} is not valid Unicode"));
            }
            Ok(None)
        };
        Ok(ProxyEnvValues {
            https: first(HTTPS_PROXY_KEYS)?,

            http: first(HTTP_PROXY_KEYS)?,
            all: first(ALL_PROXY_KEYS)?,
            no: first(NO_PROXY_KEYS)?,
        })
    }
}

/// Resolve the value bag into the per-scheme slots, reqwest's precedence: scheme-specific
pub fn resolve_config(env: &ProxyEnvValues) -> Result<Option<Arc<ProxyChoice>>, String> {
    let all = env
        .all
        .as_deref()
        .map(parse_proxy)
        .transpose()?
        .map(Arc::new);
    let scheme_slot = |v: &Option<String>| -> Result<Option<Arc<ProxyHop>>, String> {
        Ok(match v.as_deref() {
            Some(v) => Some(Arc::new(parse_proxy(v)?)),
            None => all.clone(),
        })
    };
    let https = scheme_slot(&env.https)?;
    let http = scheme_slot(&env.http)?;
    if https.is_none() && http.is_none() {
        return Ok(None);
    }
    Ok(Some(Arc::new(ProxyChoice::new(
        https,
        http,
        env.no.as_deref().unwrap_or(""),
    ))))
}

/// THE PROCESS'S PROXY CHOICE, read once from its environment: `None` when no proxy variable is
pub fn from_env() -> Result<Option<Arc<ProxyChoice>>, String> {
    resolve_config(&ProxyEnvValues::from_process_env()?)
}

/// Hard ceiling on the proxy's CONNECT response head; a real response is one status line + a few
pub const CONNECT_HEAD_CAP: usize = 8 * 1024;

/// Wall-clock bound on the CONNECT handshake — the same 10s the socket connect itself carries.
pub const CONNECT_HANDSHAKE: std::time::Duration = std::time::Duration::from_secs(10);

/// `CONNECT host:port HTTP/1.1` (+ Host, + Proxy-Authorization when configured), the bytes the
#[must_use]
pub fn connect_request(target: &str, proxy: &ProxyHop) -> Vec<u8> {
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(auth) = proxy.proxy_authorization() {
        req.push_str("Proxy-Authorization: ");
        req.push_str(auth);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    req.into_bytes()
}

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
        return Err(format!(
            "proxy refused CONNECT {addr}: {}",
            String::from_utf8_lossy(line)
        ));
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
) -> Arc<ProxyChoice> {
    let hop = Arc::new(ProxyHop::new(host.to_string(), port, auth));
    Arc::new(ProxyChoice::new(Some(hop.clone()), Some(hop), no_proxy))
}

/// The exemption list alone, as tests read it.
#[cfg(test)]
pub(crate) fn no_proxy_matches(entries: &str, target_host: &str) -> bool {
    ProxyChoice::new(None, None, entries).exempts(target_host)
}

#[cfg(test)]
#[path = "tests/proxy_tests.rs"]
mod tests;
