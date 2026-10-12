// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROXY ENVIRONMENT, AS EVERY CONNECTOR DIAL HONOURS IT (status row 130 E5a; ARCHITECT ruling
//! 2026-10-12: the engine's proxy behaviour moves into the connector UNCHANGED, so every dial
//! through the connector honours `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` exactly
//! as 1.5.5's reqwest clients did).
//!
//! The decision is the kernel engine's owned CONNECT tunnel (`busbar-kernel`
//! `egress/engine/mod.rs`, `mod tunnel`), moved verbatim: scheme-scoped slots (https targets use
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

use std::net::IpAddr;
use std::sync::Arc;

/// One boot-resolved proxy endpoint: where to TCP-connect and what to put in
/// `Proxy-Authorization`. Parsed ONCE at boot; shared by refcount from the per-scheme slots
/// of [`ProxyConfig`].
#[cfg_attr(test, derive(Debug))]
pub struct ProxySpec {
    /// Proxy endpoint as the plain `host:port` CONNECT dial string.
    host: String,
    port: u16,
    /// `Proxy-Authorization: Basic <b64(user:pass)>` prebuilt from the proxy URL's userinfo.
    auth: Option<String>,
}

/// The boot-resolved proxy DECISION, reqwest-scoped: https:// targets use the `https` slot
/// (`HTTPS_PROXY`, `ALL_PROXY` fallback), everything else uses the `http` slot (`HTTP_PROXY`,
/// `ALL_PROXY` fallback), and `NO_PROXY` excludes hosts from both. This mirrors hyper-util's
/// `client::proxy::matcher::Builder::build` (`http: http.or(all)`, `https: https.or(all)`)
/// and `Matcher::intercept` (NO_PROXY first, then the slot picked by `dst.scheme_str()`) —
/// the machinery reqwest 0.12 delegates its implicit env behavior to.
#[cfg_attr(test, derive(Debug))]
pub struct ProxyConfig {
    https: Option<Arc<ProxySpec>>,
    http: Option<Arc<ProxySpec>>,
    no_proxy: NoProxy,
}

impl ProxyConfig {
    /// The per-CONNECT decision: `None` → direct (NO_PROXY-excluded, or no proxy configured
    /// for the target's scheme), `Some` → tunnel through that proxy.
    #[must_use]
    pub fn select(&self, dst_is_https: bool, target_host: &str) -> Option<Arc<ProxySpec>> {
        if self.no_proxy.matches(target_host) {
            return None;
        }
        if dst_is_https {
            self.https.clone()
        } else {
            self.http.clone()
        }
    }
}

/// Parsed `NO_PROXY` entries, reqwest's full rule set (hyper-util `matcher::NoProxy`, which
/// documents itself as curl's rules): `*` matches everything; an IP literal matches exactly;
/// a CIDR block (`10.0.0.0/8`, `fd00::/8`) matches by containment; anything else is a domain
/// matched exactly or as a `.`-boundary suffix. Like reqwest, an IP-literal target host is
/// checked ONLY against the IP/CIDR entries and a domain host ONLY against the domain
/// entries.
#[cfg_attr(test, derive(Debug))]
struct NoProxy {
    entries: Vec<NoProxyEntry>,
}

#[cfg_attr(test, derive(Debug))]
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
    /// mirrors reqwest: try CIDR, then IP literal, then fall back to domain — a malformed
    /// CIDR (`10.0.0.0/40`) therefore degrades to a domain entry that never matches, exactly
    /// as `ipnet` parse failure does under reqwest, rather than aborting boot.
    fn parse(raw: &str) -> Self {
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
            entries.push(NoProxyEntry::Domain(
                part.trim_start_matches('.').to_ascii_lowercase(),
            ));
        }
        NoProxy { entries }
    }

    fn matches(&self, target_host: &str) -> bool {
        // `http::Uri::host()` may carry an IPv6 literal in brackets; strip them before the
        // IpAddr parse, as hyper-util's NoProxy::contains does.
        let bare = target_host.trim_start_matches('[').trim_end_matches(']');
        let ip: Option<IpAddr> = bare.parse().ok();
        let host = target_host.to_ascii_lowercase();
        self.entries.iter().any(|entry| match entry {
            NoProxyEntry::MatchAll => true,
            NoProxyEntry::Ip(a) => ip == Some(*a),
            NoProxyEntry::Cidr(net, len) => ip.is_some_and(|h| cidr_contains(net, *len, &h)),
            NoProxyEntry::Domain(d) => {
                ip.is_none()
                    && (host == *d
                        || (host.len() > d.len()
                            && host.ends_with(d.as_str())
                            && host.as_bytes()[host.len() - d.len() - 1] == b'.'))
            }
        })
    }
}

/// CIDR containment by prefix-length bit compare over octets — the ~10 lines that make an
/// `ipnet` dependency unnecessary. Families never cross: a v4 block does not match a v6
/// address and vice versa, INCLUDING v6-mapped forms (`10.0.0.0/8` does NOT match
/// `::ffff:10.0.0.1` — it is a v6 address), matching `ipnet`/reqwest, which do not
/// special-case mapped addresses either.
fn cidr_contains(net: &IpAddr, prefix: u8, addr: &IpAddr) -> bool {
    match (net, addr) {
        (IpAddr::V4(n), IpAddr::V4(a)) => octets_prefix_eq(&n.octets(), &a.octets(), prefix),
        (IpAddr::V6(n), IpAddr::V6(a)) => octets_prefix_eq(&n.octets(), &a.octets(), prefix),
        _ => false,
    }
}

/// The first `prefix` bits of `net` and `addr` are equal. `prefix` is pre-validated against
/// the address width; `/0` matches everything (whole bytes to compare: none, remainder: 0).
fn octets_prefix_eq(net: &[u8], addr: &[u8], prefix: u8) -> bool {
    let whole = usize::from(prefix / 8);
    let rem = prefix % 8;
    if net[..whole] != addr[..whole] {
        return false;
    }
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (net[whole] & mask) == (addr[whole] & mask)
}

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
/// and the authority ends at the first `/`, `?` or `#` because userinfo may not contain one.
/// An `@` that appears only AFTER the authority cannot be userinfo, but neither can this
/// function prove the value is well-formed enough for that reasoning to hold, so that residue
/// case redacts wholesale rather than print a maybe-credential.
fn redact_userinfo(v: &str) -> String {
    let (scheme, rest) = match v.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, v),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let shown = match authority.rsplit_once('@') {
        Some((_userinfo, host_port)) => format!("***@{host_port}{tail}"),
        None if rest.contains('@') => "***".to_string(),
        None => rest.to_string(),
    };
    match scheme {
        Some(s) => format!("{s}://{shown}"),
        None => shown,
    }
}

/// Parse a proxy env value (`http://[user:pass@]host[:port]`; a bare `host:port` is accepted
/// too). `https://` proxies are refused loudly: TLS-to-proxy is a different transport this
/// tunnel does not speak, and silently downgrading it to TCP would be a lie.
///
/// Every refusal renders the value through [`redact_userinfo`] — see there for why the raw
/// value must never reach the message, and why the host still does.
///
/// # Errors
///
/// The value does not read as an `http://` proxy URL with a host.
pub fn parse_proxy(v: &str) -> Result<ProxySpec, String> {
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
        let creds = format!(
            "{}:{}",
            parsed.username(),
            parsed.password().unwrap_or_default()
        );
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(creds)
        )
    });
    Ok(ProxySpec { host, port, auth })
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
pub fn resolve_config(env: &ProxyEnvValues) -> Result<Option<Arc<ProxyConfig>>, String> {
    let all = env
        .all
        .as_deref()
        .map(parse_proxy)
        .transpose()?
        .map(Arc::new);
    let scheme_slot = |v: &Option<String>| -> Result<Option<Arc<ProxySpec>>, String> {
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
    Ok(Some(Arc::new(ProxyConfig {
        https,
        http,
        no_proxy: NoProxy::parse(env.no.as_deref().unwrap_or("")),
    })))
}

/// THE PROCESS'S PROXY DECISION, read once from its environment: `None` when no proxy variable is
/// set (the direct arm every known deployment takes).
///
/// # Errors
///
/// A proxy variable that is set and does not parse: the boot refuses (fail-loud beats silently
/// egressing direct past a configured proxy), the password never in the text.
pub fn from_env() -> Result<Option<Arc<ProxyConfig>>, String> {
    resolve_config(&ProxyEnvValues::from_process_env())
}

/// Hard ceiling on the proxy's CONNECT response head; a real response is one status line + a few
/// headers. Anything larger is a misbehaving proxy and fails the connect.
pub const CONNECT_HEAD_CAP: usize = 8 * 1024;

/// Wall-clock bound on the CONNECT handshake — the same 10s the TCP connect itself carries.
pub const CONNECT_HANDSHAKE: std::time::Duration = std::time::Duration::from_secs(10);

impl ProxySpec {
    /// The proxy's own authority, `host:port`, as the connection dials it.
    #[must_use]
    pub fn authority(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// `CONNECT host:port HTTP/1.1` (+ Host, + Proxy-Authorization when configured), the bytes the
/// engine's `connect_handshake` wrote, for `authority` (`host:port`, a v6 host bracketed).
#[must_use]
pub fn connect_request(authority: &str, proxy: &ProxySpec) -> Vec<u8> {
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(auth) = &proxy.auth {
        req.push_str("Proxy-Authorization: ");
        req.push_str(auth);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    req.into_bytes()
}

/// What the proxy has answered so far to a CONNECT for `authority`: `Ok(None)` = its head is not
/// complete yet; `Ok(Some(n))` = the tunnel is up and the head is the first `n` bytes (anything
/// after them is the target's); `Err` = the proxy refused (any status but 2xx: RFC 9110, 2xx means
/// the tunnel is established) or its head ran past [`CONNECT_HEAD_CAP`].
///
/// # Errors
///
/// The refusal, in the engine's words.
pub fn connect_answer(head: &[u8], authority: &str) -> Result<Option<usize>, String> {
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
            "proxy refused CONNECT {authority}: {}",
            String::from_utf8_lossy(line)
        ));
    }
    Ok(Some(at + 4))
}

/// The host of `authority` (`host:port`, a v6 host bracketed), as `NO_PROXY` matches it.
#[must_use]
pub fn host_of(authority: &str) -> &str {
    if authority.starts_with('[') {
        return authority
            .find(']')
            .map_or(authority, |end| &authority[..=end]);
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

/// A whole config whose BOTH slots point at one proxy at `host:port`: what a test wires directly
/// so parallel tests never race an environment variable.
#[cfg(test)]
pub(crate) fn test_config(
    host: &str,
    port: u16,
    auth: Option<String>,
    no_proxy: &str,
) -> Arc<ProxyConfig> {
    let spec = Arc::new(ProxySpec {
        host: host.to_string(),
        port,
        auth,
    });
    Arc::new(ProxyConfig {
        https: Some(spec.clone()),
        http: Some(spec),
        no_proxy: NoProxy::parse(no_proxy),
    })
}

/// `NO_PROXY` matching alone, as tests read it.
#[cfg(test)]
pub(crate) fn no_proxy_matches(entries: &str, target_host: &str) -> bool {
    NoProxy::parse(entries).matches(target_host)
}

#[cfg(test)]
#[path = "tests/proxy_tests.rs"]
mod tests;
