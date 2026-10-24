// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROXY ENVIRONMENT, AS EVERY CONNECTOR DIAL HONOURS IT (status row 130 E5a; ARCHITECT ruling
//! 2026-10-12: the engine's proxy behaviour moves into the connector UNCHANGED, so every dial
//! through the connector honours `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` exactly
//! as 1.5.5's reqwest clients did).
//!
//! This is the ONE place the proxy environment is read (ARCHITECT ruling 2026-10-12, a move, not a
//! copy): the parser is the kernel engine's former one (`busbar-kernel` `egress/engine/mod.rs`,
//! `mod tunnel`), moved verbatim into here, and it fills the shared choice
//! (`busbar_contract::proxy_route`), which the composition root hands the kernel's remaining
//! engine; the kernel reads no environment of its own. The rules: scheme-scoped slots (https targets use
//! `HTTPS_PROXY`, everything else `HTTP_PROXY`, each falling back to `ALL_PROXY`, uppercase read
//! before lowercase), `NO_PROXY` with reqwest's full rule set (host, domain suffix, IP literal,
//! CIDR), `Proxy-Authorization: Basic` from the proxy URL's userinfo, an `https://` proxy refused
//! loudly, a garbage value a boot refusal that never echoes the proxy password. What changes is
//! where the bytes go: the connection ([`crate::compose`]) dials the proxy, writes
//! [`connect_request`] before anything else, reads the proxy's answer ([`connect_answer`]) and only
//! then runs the secure layer (the target's name, the target's certificate) and the framer over the
//! tunnel, so the proxy sees `CONNECT host:port` and never a decrypted byte. Plain-http targets are
//! tunnelled too (CONNECT for everything, as the engine and `curl -p` do; the request bytes are
//! identical either way).
//!
//! A FRAMED dial is tunnelled (an application protocol over the stream, as 1.5.5's HTTP clients
//! were); a carrier carried as itself (a database's or a directory's raw stream) and a program
//! never are, as 1.5.5's drivers never were.

use std::sync::Arc;

pub use busbar_contract::proxy_route::{ProxyChoice, ProxyHop};

/// The proxy env value as a REFUSAL may render it: userinfo replaced by `***`, everything
/// else verbatim.
///
/// `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` carry `user:password@` (RFC 3986 §3.2.1) in every
/// corporate deployment that authenticates its proxy, and [`parse_proxy`]'s refusals are not
/// swallowed: `resolve_config` hands them to [`from_env`], whose `Err` refuses the boot. Interpolating the raw value put the
/// operator's proxy password on stderr, in the crash report and in whatever CI log collected
/// them. The host, port and scheme are what the operator needs to fix the variable, so they
/// survive — only the credential goes.
///
/// TEXTUAL, not a re-parse, deliberately: the first caller is the arm where `url::Url::parse`
/// has ALREADY FAILED, so a masker that had to parse could only fail the same way and return
/// the raw value. Userinfo is everything before the LAST `@` of the authority — last, because
/// a password may itself contain an unencoded `@` (`svcacct:hunter2-Pr0xyP@ss@proxy.corp`),
/// and the authority ends at the first `/`, `?` or `#` because userinfo may not contain one, and
/// at a `\` because the dialling stack reads it as `/`.
/// An `@` that appears only AFTER the authority cannot be userinfo, but neither can this
/// function prove the value is well-formed enough for that reasoning to hold, so that residue
/// case redacts wholesale rather than print a maybe-credential.
fn redact_userinfo(v: &str) -> String {
    // The authority the one split reads ([`busbar_contract::net::url_authority`]): it ends at a
    // `\` as the dialling stack ends it, so the text after one is never shown as the host.
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
/// too). `https://` proxies are refused loudly: TLS-to-proxy is a different transport this
/// tunnel does not speak, and silently downgrading it to a plain stream would be a lie.
///
/// Every refusal renders the value through [`redact_userinfo`] — see there for why the raw
/// value must never reach the message, and why the host still does.
///
/// # Errors
///
/// The value does not read as an `http://` proxy URL with a host.
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
        // The userinfo as the URL spells it is percent-encoded; the credential is what it
        // encodes, as reqwest decoded it before Basic-encoding it.
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
/// kept as written.
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

impl ProxyEnvValues {
    /// Uppercase read before lowercase, empty values treated as unset — hyper-util
    /// `matcher::Builder::from_env`'s `get_first_env(&["HTTPS_PROXY", "https_proxy"])`
    /// ordering (empty parses to nothing there; skipping it here is the same outcome).
    pub fn from_process_env() -> Self {
        fn first(keys: [&str; 2]) -> Option<String> {
            keys.iter()
                .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        }
        ProxyEnvValues {
            https: first(["HTTPS_PROXY", "https_proxy"]),
            // Read unconditionally — hyper-util's matcher additionally skips uppercase
            // `HTTP_PROXY` under CGI (`REQUEST_METHOD` set; the httpoxy guard). busbar is a
            // server binary, never a CGI child, so the guard's precondition cannot hold and
            // the unconditional read is behavior-identical where this process runs.
            http: first(["HTTP_PROXY", "http_proxy"]),
            all: first(["ALL_PROXY", "all_proxy"]),
            no: first(["NO_PROXY", "no_proxy"]),
        }
    }
}

/// Resolve the value bag into the per-scheme slots, reqwest's precedence: scheme-specific
/// var first, `ALL_PROXY` as the fallback for BOTH slots (hyper-util `Builder::build`:
/// `http: http.or(all)`, `https: https.or(all)`). No proxy var at all → `None`, the direct
/// arm. Any PRESENT value that does not parse is a hard error — reqwest silently ignored
/// garbage and fell through, but silently egressing direct past a configured proxy is the
/// dangerous direction, so busbar refuses to boot instead (documented deviation).
///
/// # Errors
///
/// A set value that does not parse ([`parse_proxy`]).
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
/// set (the direct arm every known deployment takes).
///
/// # Errors
///
/// A proxy variable that is set and does not parse: the boot refuses (fail-loud beats silently
/// egressing direct past a configured proxy), the password never in the text.
pub fn from_env() -> Result<Option<Arc<ProxyChoice>>, String> {
    resolve_config(&ProxyEnvValues::from_process_env())
}

/// Hard ceiling on the proxy's CONNECT response head; a real response is one status line + a few
/// headers. Anything larger is a misbehaving proxy and fails the connect.
pub const CONNECT_HEAD_CAP: usize = 8 * 1024;

/// Wall-clock bound on the CONNECT handshake — the same 10s the socket connect itself carries.
pub const CONNECT_HANDSHAKE: std::time::Duration = std::time::Duration::from_secs(10);

/// `CONNECT host:port HTTP/1.1` (+ Host, + Proxy-Authorization when configured), the bytes the
/// engine's `connect_handshake` wrote, for `target` (`host:port`, a v6 host bracketed).
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
/// complete yet; `Ok(Some(n))` = the tunnel is up and the head is the first `n` bytes (anything
/// after them is the target's); `Err` = the proxy refused (any status but 2xx: RFC 9110, 2xx means
/// the tunnel is established) or its head ran past [`CONNECT_HEAD_CAP`].
///
/// # Errors
///
/// The refusal, in the engine's words.
pub fn connect_answer(head: &[u8], addr: &str) -> Result<Option<usize>, String> {
    let Some(at) = head.windows(4).position(|w| w == b"\r\n\r\n") else {
        if head.len() > CONNECT_HEAD_CAP {
            return Err("proxy CONNECT response head exceeded 8KiB".into());
        }
        return Ok(None);
    };
    // Status line: `HTTP/1.x NNN ...` — accept any 2xx (some proxies say 200 Connection
    // established, some plain 200 OK).
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
/// so parallel tests never race an environment variable.
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
