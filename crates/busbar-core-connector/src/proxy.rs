// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROXY ENVIRONMENT, AS EVERY CONNECTOR DIAL HONOURS IT (the engine's proxy behaviour moves

use std::{borrow::Cow, ffi::OsString, sync::Arc};

pub use crate::proxy_route::{ProxyChoice, ProxyHop};

/// The proxy env value as a REFUSAL may render it: userinfo replaced by `***`, everything
fn redact_userinfo(v: &str) -> String {
    let parts = busbar_contract::net::url_authority(v);
    let (host_port, tail) = (parts.host_port, parts.tail);
    #[expect(
        clippy::disallowed_methods,
        reason = "config: the proxy environment is parsed once; its redacted spelling feeds only a refusal"
    )]
    let shown = if parts.userinfo.is_some() {
        format!("***@{host_port}{tail}")
    } else if tail.contains('@') {
        "***".to_owned()
    } else {
        format!("{host_port}{tail}")
    };
    #[expect(
        clippy::disallowed_methods,
        reason = "config: the proxy environment is parsed once; its redacted spelling feeds only a refusal"
    )]
    let schemed = parts.scheme.map(|s| format!("{s}://{shown}"));
    schemed.unwrap_or(shown)
}

/// Parse a proxy env value (`http://[user:pass@]host[:port]`; a bare `host:port` is accepted
pub fn parse_proxy(v: &str) -> Result<ProxyHop, String> {
    let shown = redact_userinfo(v);
    #[expect(
        clippy::disallowed_methods,
        reason = "config: a bare proxy env value is given its scheme once, as the environment is parsed"
    )]
    let url: Cow<'_, str> = if v.contains("://") {
        Cow::Borrowed(v)
    } else {
        Cow::Owned(format!("http://{v}"))
    };
    #[expect(
        clippy::disallowed_methods,
        reason = "config: a refusal of the proxy environment, parsed once"
    )]
    let parsed = url::Url::parse(&url)
        .map_err(|e| format!("proxy env value {shown:?} is not a valid URL: {e}"))?;
    if parsed.scheme() != busbar_contract::http::uri::Scheme::HTTP.as_str() {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a refusal of the proxy environment, parsed once"
        )]
        return Err(format!(
            "proxy env value {shown:?} uses scheme {:?}: only plain http:// CONNECT proxies \
             are supported (an https:// proxy would need TLS-to-proxy, which this tunnel does \
             not speak)",
            parsed.scheme()
        ));
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "config: the proxy host is copied once, as the environment is parsed"
    )]
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("proxy env value {shown:?} has no host"))?
        .to_owned();
    let port = parsed.port().unwrap_or(80);
    #[expect(
        clippy::disallowed_methods,
        reason = "config: the Proxy-Authorization value is spelled once, as the environment is parsed"
    )]
    let auth = (!parsed.username().is_empty()).then(|| {
        use base64::Engine;

        let creds = [
            busbar_contract::net::percent_decoded_bytes(parsed.username()),
            b":".to_vec(),
            busbar_contract::net::percent_decoded_bytes(parsed.password().unwrap_or_default()),
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
    // busbar:expect(bp::fresh_buffer, reason = "config: the proxy userinfo is decoded once, as the environment is parsed")
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
                #[expect(
                    clippy::disallowed_methods,
                    reason = "config: a refusal of the proxy environment, read once"
                )]
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
    // The connection owns these bytes until the tunnel is written: one exactly sized buffer, the
    // hop's tail spelled once with the hop.
    const CONNECT: &[u8] = b"CONNECT ";
    const HOST: &[u8] = b" HTTP/1.1\r\nHost: ";
    const EOL: &[u8] = b"\r\n";
    let tail = proxy.connect_tail().as_bytes();
    let mut req =
        Vec::with_capacity(CONNECT.len() + HOST.len() + EOL.len() + 2 * target.len() + tail.len());
    req.extend_from_slice(CONNECT);
    req.extend_from_slice(target.as_bytes());
    req.extend_from_slice(HOST);
    req.extend_from_slice(target.as_bytes());
    req.extend_from_slice(EOL);
    req.extend_from_slice(tail);
    req
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
        #[expect(
            clippy::disallowed_methods,
            reason = "error: the proxy refused the tunnel; the refusal quotes its status line"
        )]
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
