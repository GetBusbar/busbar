// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The network guard: what a destination may be dialled.
//!
//! This file holds the URL readers the kernel's own dials use ([`split_url`] and the userinfo
//! helpers) and the configuration-time denylist ([`ssrf_blocked_host`], [`Denylist`]). The judgement
//! a plugin's dial asks through `dest.judge` is the connector's destination guard
//! (`busbar-core-connector` `guard.rs`), built on the same `busbar_contract::net` readers; this
//! file keeps no second copy of it.
//!
//! The pure primitives (metadata list, v4/v6 range predicates, alternate IPv4 spellings, WHATWG host
//! extraction) live in `busbar_contract::net`, the one URL and host reader, and are re-exported here
//! unchanged: a plugin that links only the contract reads a host exactly as this guard does.
// `IpAddr` and `SocketAddr` come through it too: the contract re-exports the address value types.
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
/// one to its connector, which reports the dial as a connect failure caused by it.
impl std::error::Error for AddressRefusal {}

/// Split an `http(s)://host[:port][/path]` URL into `(https, host, port, path)`.
///
/// A STRICT RECOGNISER over the scheme — exactly `https://` or `http://`, anything else is a
/// [`AddressRefusal::Scheme`] — with the host read by the one shared reader
/// ([`parse_url`], WHATWG rules). The authority therefore ends where the dialling stack ends it: at
/// `/`, `?`, `#` or `\`. A reader that ended it only at `/` read `https://127.0.0.1?x` as the host
/// `127.0.0.1?x` — no address, no loopback name, so no refusal — while the stack dialled
/// `127.0.0.1`; `https://localhost#a`, `https://127.0.0.1./`, `https://%6c%6fcalhost/` and
/// `https://10.0.0.5\x/` were the same bypass in other spellings. The host comes back UNBRACKETED,
/// percent-decoded and without a trailing root dot, so it reads the same here as it does to
/// `IpAddr::from_str`. The path always opens with `/` (`https://h?q`
/// gives `/?q`).
///
/// A caller that must also FOLLOW a relative `Location` needs a real URL type to join against and
/// parses with one; it still judges the host it parsed itself. That is the
/// one part of the recognition that is legitimately per-caller, and it is why this is a public
/// helper rather than the only door in.
pub fn split_url(url: &str) -> Result<(bool, String, u16, String), AddressRefusal> {
    let https = if url.starts_with("https://") {
        true
    } else if url.starts_with("http://") {
        false
    } else {
        return Err(AddressRefusal::Scheme {
            url: redact_userinfo(url),
            scheme: scheme_of(url),
        });
    };
    let no_host = || AddressRefusal::NoHost(redact_userinfo(url));
    let parts = parse_url(url).map_err(|_| no_host())?;
    // Userinfo is refused rather than stripped. `https://evil.test@good.example/` reads as
    // `good.example` to a parser and as `evil.test` to a human skimming a config diff, and a value
    // whose two readings differ has no place on a fetch path.
    if parts.userinfo {
        return Err(no_host());
    }
    let port = parts.port.unwrap_or_else(|| default_port(https));
    Ok((https, parts.host, port, parts.path))
}

/// The URL as a refusal may repeat it: everything an authority put before its last `@` replaced by a
/// fixed marker.
///
/// A refusal names the URL that caused it because an operator cannot fix what they cannot see. But a
/// URL's authority is also where a password goes — `https://svc:hunter2@upstream.example/` — and a
/// refusal is written into a card and a log, which are read by more people than the config is and
/// kept for longer. The host stays, because the host is the diagnosis; the credential goes, because
/// it never was.
///
/// Only the authority is touched. A `@` later in the path is part of what the operator wrote and
/// says nothing about a secret.
///
/// Public so a message that repeats an operator's URL outside this guard (a boot validation error,
/// an egress fault's target) renders it the same way.
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
/// becomes `scheme://host:port/path`, and a URL with none comes back borrowed, untouched.
///
/// 1.5.5 accepted `user:pass@` in a provider's `base_url` and dialled, sent and signed the host
/// after it (v1.5.5 `crates/busbar/src/proxy/egress.rs:18`, `host_from_base`; row 74, F25). This is
/// that rule, applied ONCE where the base URL enters the served flow, so the host dialled, the
/// certificate name, the `Host`/`:authority` on the wire and a signed host are all the stripped
/// `host[:port]`, and the userinfo reaches no connection, no message and no table. It is
/// deliberately NOT [`split_url`]'s behaviour: every other dial target keeps the refusal there.
///
/// The authority ends where [`split_url`]'s reader ends it — the first `/`, `?`, `#` or `\` — and
/// the userinfo is everything before its LAST `@`, because a password may itself carry an `@`.
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
/// [`split_url`]'s allowlist — so a string with no `:` at all reports the empty scheme rather than
/// failing to be reported.
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
/// provider's `allow_metadata_hosts`) READ AS A TARGET'S HOST IS READ: trimmed, then mapped to the
/// ASCII name or address a URL client dials ([`url_host_to_ascii`], the mapping
/// [`extract_normalized_host`] reads every target through), so an entry written `ｍｅｔａｄａｔａ.ｉｎｔｅｒｎａｌ`
/// or `１６９.２５４.１６９.２５４` names the target it reads as. An ASCII entry is handed back trimmed,
/// as written. The list judgement drops trailing root dots and compares case-blind after this.
///
/// # Errors
///
/// [`UrlRefusal::NoHost`] when a non-ASCII entry maps to nothing (UTS #46 refuses it, or it maps to
/// only root dots): it would match no target at all, so configuration load refuses it, naming it.
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
    /// ([`list_entry_host`]). An entry that names no host the guard judges (UTS #46 refuses it, a
    /// `%` outside an IPv6 zone id, a last label that reads as a number but is no IPv4 address)
    /// could match no target: it is dropped here, as 1.5.5 matched it to nothing, and configuration
    /// load names it in a warning line.
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
    /// no work on.
    fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// True when the already-normalized `host` (as produced by [`extract_normalized_host`]) matches
    /// any entry, using the EXACT canonicalization the denylist block check uses for operator-
    /// supplied `blocked_metadata_hosts`. This is shared by the allow-override path so an allow
    /// entry unblocks every spelling of an IP the same way a block entry blocks every spelling:
    /// * a hostname entry matches case-insensitively, trailing dot stripped;
    /// * an IP-literal entry matches the parsed connect-host AND its IPv4-mapped/compatible-IPv6 and
    ///   alternate-encoding (decimal-int / hex / octal / short-dotted) spellings.
    fn matches(&self, host: &str) -> bool {
        use std::net::IpAddr;

        if self.is_empty() {
            return false;
        }

        // Hostname / verbatim match (case-insensitive).
        if self.names.iter().any(|n| n.eq_ignore_ascii_case(host)) {
            return true;
        }

        // An IP-literal entry also matches this host's mapped-IPv6 and alternate-encoding
        // spellings, mirroring the block path's `extra_v4`/`extra_v6`.
        if self.v4.is_empty() && self.v6.is_empty() {
            return false;
        }

        // Alternate / obfuscated encodings of THIS host expand to a canonical v4 and re-check.
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
/// `None`. This is the SSRF guard under the metadata-denylist model.
///
/// Threat model: a caller can NEVER influence a destination's configured URL — it names a route,
/// which maps through an operator pool to an operator-configured URL. So there is no caller-driven
/// SSRF. The ONLY real risk is an operator typo / templated-config accidentally pointing a
/// key-bearing lane at a credential-leaking metadata service. Therefore: block a comprehensive
/// metadata DENYLIST and ALLOW EVERYTHING ELSE — loopback, RFC-1918, CGNAT, and public are all
/// legitimate upstreams (a local loopback upstream "just works" with no flag).
///
/// The hardcoded denylist:
/// * link-local `169.254.0.0/16` — catches IMDS `169.254.169.254`, AWS ECS task-creds
///   `169.254.170.2`, Tencent `169.254.0.23`, and any other link-local metadata in one range
///   (nothing legitimate runs on link-local);
/// * `100.100.100.200` (Alibaba Cloud ECS, inside the otherwise-allowed CGNAT /10);
/// * `168.63.129.16` (Azure WireServer / platform);
/// * `192.0.0.192` (Oracle Cloud / OCI IMDS — globally-routable-shaped, so it needs an explicit literal);
/// * the EC2 IMDSv6 `fd00:ec2::254`;
/// * the metadata hostnames in `METADATA_HOSTS`.
///
/// All IP entries are matched through the SAME obfuscation defenses (IPv4-mapped/compatible IPv6,
/// decimal-int / hex / octal encoding, percent-encoded dots, trailing-dot FQDN), not just IMDS.
///
/// `extra_blocked` is `security.blocked_metadata_hosts` — operator additions APPENDED to the
/// hardcoded list (the answer to an unknown cloud's metadata IP/hostname).
///
/// Precedence (the LOCKED one-rule matrix): a host is blocked IFF
/// `!allow_all` AND on-denylist(hardcoded ∪ `extra_blocked`) AND NOT in `allow_overrides`.
///
/// * `allow_all` is `security.allow_all_metadata` — the nuclear override; when `true` the guard is
///   fully disabled and the function always returns `None`.
/// * `allow_overrides` is the UNION of a destination's `allow_metadata_hosts` and the global
///   `security.allow_metadata_hosts` — a surgical carve-out. An entry is matched with the SAME
///   canonicalization as the block check (an IP entry unblocks all its obfuscated spellings —
///   decimal-int, IPv4-mapped/compatible IPv6, trailing-dot — mirroring how a block entry blocks
///   all spellings; a hostname entry matches case-insensitively, trailing dot stripped). Allow
///   always wins: a host on the denylist that ALSO appears in `allow_overrides` is permitted.
pub fn ssrf_blocked_host(
    url: &str,
    allow_overrides: &[String],
    allow_all: bool,
    extra_blocked: &[String],
) -> Option<String> {
    // The one-shot spelling: a caller holding raw entries pays the canonicalization here. A caller
    // that dials repeatedly states its lists once, as a [`Denylist`], and pays it never again.
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // A destination may be spelled as a URL or as a bare `host:port`, and the destination check
    // supports both. Judging only the first spelling meant the operator's denylist never fired for
    // the second — the extraction wanted a `://` and returned nothing without it.
    let host = extract_normalized_host(url).or_else(|| extract_normalized_authority_host(url))?;
    let host = host.as_str();

    // Surgical allow-override: if THIS host matches any allow entry (with the same canonicalization
    // the block check uses), it is permitted regardless of the denylist. Computed up front so allow
    // unconditionally wins over every block arm below.
    if allow_overrides.matches(host) {
        return None;
    }

    // Cloud-metadata / IMDS hostnames (case-insensitive), read from the ONE module-level list so
    // this guard and the resolved-name guard cannot know different names. The IPv4 / IPv6 metadata
    // literals are caught in the IP arms below; these are the DNS names a connecting stack would
    // resolve.
    if METADATA_HOSTS.iter().any(|m| m.eq_ignore_ascii_case(host)) {
        return Some(host.to_string());
    }

    // Operator-supplied extensions to the denylist (`security.blocked_metadata_hosts`). Matched with
    // the SAME canonicalization the allow-override path uses (hostname case-insensitive; IP literal
    // matched against the parsed connect-host and its mapped-IPv6 / alternate-encoding spellings), so
    // an operator who writes `10.99.99.99` also blocks `[::ffff:10.99.99.99]` and the decimal-int
    // form. [`HostSet`] is the single shared canonicalizer for both allow and block.
    if extra_blocked.matches(host) {
        return Some(host.to_string());
    }

    // The hardcoded metadata IP literals.
    // * link-local `169.254.0.0/16` (IMDS `169.254.169.254`, ECS `169.254.170.2`, Tencent
    // `169.254.0.23`, …);
    // * Alibaba `100.100.100.200`; Azure `168.63.129.16`; Oracle Cloud (OCI) `192.0.0.192`;
    // EC2 IMDSv6 `fd00:ec2::254`.
    let imds_v6 = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254);
    let alibaba_v4 = Ipv4Addr::new(100, 100, 100, 200);
    let azure_v4 = Ipv4Addr::new(168, 63, 129, 16);
    // OCI's IMDS lives at the globally-routable-shaped `192.0.0.192` — NOT caught by link-local /
    // private / CGNAT / unspecified, so it needs an explicit literal like Alibaba/Azure.
    let oci_v4 = Ipv4Addr::new(192, 0, 0, 192);
    // Predicate: is this PARSED v4 address a hardcoded metadata target? (link-local /16 + the
    // non-link-local literals.)
    let is_metadata_v4 = |v4: &Ipv4Addr| -> bool {
        v4.is_link_local() || *v4 == alibaba_v4 || *v4 == azure_v4 || *v4 == oci_v4
    };

    // Alternate / non-canonical IPv4 encodings (decimal int `2852039166` = 169.254.169.254, hex,
    // octal, short dotted) that `IpAddr::from_str` rejects but the OS resolver still maps to an IPv4
    // target. Expand them to a canonical address and re-check against the metadata predicate, so an
    // obfuscated metadata literal is caught while a non-metadata obfuscated form (e.g. a decimal
    // loopback) is simply allowed (it is not a metadata target).
    if let Some(expanded) = expand_alternate_ipv4(host) {
        if is_metadata_v4(&expanded) {
            return Some(host.to_string());
        }
    }

    // Canonical IP-literal checks. A hostname that does not parse as an IP and is not in the lists
    // above is ALLOWED — private/loopback/CGNAT/public upstreams are all legitimate.
    let is_blocked = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => is_metadata_v4(&v4),
        Ok(IpAddr::V6(v6)) => {
            // An IPv6 literal embedding an IPv4 address reaches the same v4 target as the bare form,
            // so apply the IDENTICAL metadata predicate to the embedded v4 (covers `[::ffff:a.b.c.d]`
            // mapped AND `[::a.b.c.d]` compatible via `to_ipv4()`).
            let embedded = embedded_ipv4(&v6);
            v6 == imds_v6 || embedded.is_some_and(|m| is_metadata_v4(&m))
        }
        Err(_) => false,
    };

    is_blocked.then(|| host.to_string())
}

// =================================================================================================
//   THE CHECK OVER A SEALED DESTINATION, run once, before anything is dialled.
// =================================================================================================

/// The operator's own additions to, and carve-outs from, the metadata denylist.
///
/// The precedence is the locked one-rule matrix, and it is the reason this is one value rather than
/// three arguments a caller assembles: a host is blocked IFF `!allow_all` AND on-denylist (the
/// hardcoded set union `blocked`) AND NOT in `allowed`. Allow always wins over block, and
/// `allow_all` wins over both — an operator who has disabled the guard has disabled it, and a guard
/// that half-applied would be worse than either answer.
///
/// The two lists are held canonicalized rather than as the strings an operator wrote, and that is
/// why they are stated once through [`Denylist::new`] rather than assigned field by field: trimming
/// an entry, dropping its trailing FQDN dot and parsing the IP literals among them does not depend
/// on the host being judged, so a dial that re-did it was paying for a deployment's configuration
/// on the request path. A field a caller could edit afterwards would be a second, stale answer.
#[derive(Debug, Default, Clone)]
pub struct Denylist {
    /// Operator additions to the denylist: the answer to an unknown cloud's metadata address.
    blocked: HostSet,
    /// Surgical carve-outs. An IP entry unblocks every spelling of that address, the same way a
    /// block entry blocks every spelling of one.
    allowed: HostSet,
    /// The nuclear override. When set, the metadata guard is off wholesale.
    allow_all: bool,
}

impl Denylist {
    /// State a deployment's additions, carve-outs and override, canonicalizing both lists once.
    ///
    /// `blocked` is `security.blocked_metadata_hosts`, `allowed` is the union of a destination's
    /// `allow_metadata_hosts` and the global one, and `allow_all` is `security.allow_all_metadata`.
    #[must_use]
    pub fn new(blocked: &[String], allowed: &[String], allow_all: bool) -> Self {
        Denylist {
            blocked: HostSet::parse(blocked),
            allowed: HostSet::parse(allowed),
            allow_all,
        }
    }

    /// Whether the guard is off wholesale, for a caller reporting what it is running under.
    #[must_use]
    pub fn allows_all(&self) -> bool {
        self.allow_all
    }

    /// THE SAME RULE, ASKED OF AN ADDRESS A NAME RESOLVED TO. The configuration-time check reads the
    /// host the operator wrote; a name is free to resolve somewhere else when it is dialled, so the
    /// dial asks this of every address the name answered with. An address is refused when it is a
    /// cloud-metadata address or an operator-blocked one, unless the name or the address is carved
    /// out, or the guard is off. Private and loopback addresses pass, exactly as they pass at
    /// configuration time.
    #[must_use]
    pub fn refuses_address(&self, host: &str, addr: IpAddr) -> bool {
        let literal = addr.to_string();
        self.lists(host, addr)
            && !(self.allow_all || self.allowed.matches(host) || self.allowed.matches(&literal))
    }

    /// Whether `addr` is on the list at all, override or not: a cloud-metadata address, or one the
    /// operator blocked (by address, or by the name that answered it).
    fn lists(&self, host: &str, addr: IpAddr) -> bool {
        ip_is_cloud_metadata(&addr)
            || self.blocked.matches(&addr.to_string())
            || self.blocked.matches(host)
    }
}
