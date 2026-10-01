// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The network guard: what a destination may be dialled, and to which address.
//!
//! ## Why it is the trust unit's and not a transport's
//!
//! This check was written three times over — once on each fetch path that reached out to a
//! configured URL — and the second copy was already borrowing the first's vocabulary in its own
//! comments. Two implementations of one security control is the shape
//! that produces a metadata bypass: somebody hardens one and the other keeps the hole.
//!
//! It lived in a neutral leaf for exactly that reason, and it is here now for one more: a transport
//! that resolved a name itself was a transport that had to remember to guard it, and every new
//! carrier was a new place to forget. The trust unit already decides where a unit may go — the
//! allow-list, the per-kind rule, the lane — so the address a destination resolves to belongs
//! beside those. Which dials reach this guard is stated in the trust unit's module header: the
//! fetches the host makes on an operator's or a caller's behalf do, and the provider dial is
//! judged by the same metadata denylist twice: once at configuration time, as 1.5.5 judged it, and
//! again over every address its name resolves to when it is dialled ([`DialDenylist`]).
//!
//! ## RESOLVE THEN PIN, and why a name check is not a guard
//!
//! Checking the host STRING and then handing the URL to a client is not a guard, it is a
//! guard-shaped delay. The client performs its OWN name resolution when it connects, and between
//! the check and the connect the name is free to mean something else. That is DNS rebinding, and it
//! is not exotic: a hostile endpoint only has to serve a short TTL and answer the second lookup
//! with `169.254.169.254`.
//!
//! So the name is resolved exactly ONCE per destination, EVERY answered address is judged, and the
//! address that survives is PINNED ([`PinnedTarget`]) and handed to the transport. The socket
//! connects to an address this module already looked at. There is no second lookup for an attacker
//! to win — which is also why [`PinnedTarget::host`] carries the name forward: connecting to the
//! pinned address while presenting the original name is what keeps the certificate validated
//! against the name the operator registered.
//!
//! ## A mixed answer is a hostile answer
//!
//! A resolver answering `[93.184.216.34, 169.254.169.254]` is refused OUTRIGHT rather than pinned
//! to the public address. Picking the good one from a mixed answer would mean the same name is
//! sometimes fine and sometimes not, decided by an ordering the upstream chooses.
//!
//! ## Cloud metadata is refused BEFORE `allow_private` is consulted
//!
//! [`judge_address`] tests [`ip_is_cloud_metadata`] first and unconditionally, and
//! [`judge_host_name`] splits the metadata NAMES out of [`dns_name_is_internal`] for the same
//! reason. An operator saying "this upstream is on our internal network" has said nothing about
//! IMDS. Merging the two arms would make `allow_private` a config flag that hands out cloud
//! credentials. **Do not re-merge them.**
//!
//! ## The pure primitives
//!
//! These predicates are the *context-free* atoms of the SSRF obfuscation defense: they answer
//! "is this `Ipv4Addr` in the RFC 6598 CGNAT range?", "is this `Ipv6Addr` in the unique-local
//! (`fc00::/7`) or link-local (`fe80::/10`) range?", and "is this host string an alternate (non
//! dotted-quad) IPv4 encoding the OS resolver still expands?" — questions whose answer must NOT
//! depend on which caller is asking. They are pure (no I/O, no globals), so each is unit-testable in
//! isolation; the guard above them takes its ONE resolution through a [`Resolver`] seam for the same
//! reason, and because a unit that opened a socket would not be a unit.
//!
//! They live in `busbar_contract::net`, the one URL and host reader, and are re-exported here
//! unchanged: a plugin that links only the contract reads a host exactly as this guard does.

use std::net::{IpAddr, SocketAddr};

// THE PURE PRIMITIVES, re-exported from the one reader in `busbar_contract::net`: the metadata list,
// the v4/v6 range predicates, the alternate IPv4 spellings, the WHATWG host extraction and the
// per-scheme URL reader. They moved there so a plugin that links only the contract judges a host
// exactly as this guard does (BUSBAR-1.6.0.md, the engine-folds paragraph: a shared reader is "a
// pure, stateless helper in `busbar-contract` outside `abi/`"); what stays here is the guard
// itself — the policy, the denylist, and resolve-then-pin.
pub use busbar_contract::net::*;

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE GUARD: one resolve-then-pin, one address judgement, one redirect policy, one body cap.
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// THE KNOBS ONE GUARDED FETCH IS ALLOWED TO HAVE.
///
/// Every field is a thing a CALLER legitimately differs on; there is deliberately no field for a
/// thing a caller may not differ on. There is no `allow_metadata`, and there is no way to spell one:
/// the cloud-metadata refusal is not policy, it is the guard.
///
/// [`Default`] is FAIL-CLOSED in every direction — no private addressing, no plaintext, no
/// redirects, a small body and a short clock — so a caller that forgets a knob gets the strict
/// answer rather than the permissive one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardPolicy {
    /// Whether this fetch may reach a private / loopback / link-local / CGNAT address, and the
    /// `localhost` NAME family with it.
    ///
    /// Even when set, cloud-metadata addresses and cloud-metadata names stay refused. That is not an
    /// oversight: an operator saying "this upstream is on our internal network" has said nothing
    /// about IMDS, and IMDS is the address whose whole value to an attacker is that it hands out
    /// credentials to anyone who can make a request from inside.
    pub allow_private: bool,
    /// Permit a plaintext `http://` endpoint to a host that is NOT private.
    ///
    /// Separate from [`GuardPolicy::allow_private`] because a plaintext fetch of a PUBLIC host is a
    /// different, worse thing than a plaintext fetch of loopback: on the public one, anyone on the
    /// path rewrites the document and reads the credential that rode the request. `allow_private`
    /// admits plaintext too — an operator pointing busbar at `http://127.0.0.1` has made ONE
    /// decision, and making them write two flags would teach that the second one is harmless.
    pub allow_plaintext: bool,
    /// How many redirects may be FOLLOWED. Zero is a legitimate setting: a 3xx is a URL nobody
    /// validated, arriving when the credential is already sent.
    pub max_redirects: u8,
    /// Largest body accepted, in bytes. An unbounded read from an upstream is an unbounded
    /// allocation whose size the upstream chooses.
    pub max_body_bytes: usize,
    /// How long one hop may take, end to end. Held here rather than at the client so the ceiling
    /// travels with the rest of the policy instead of being a fifth argument somebody forgets.
    pub timeout: std::time::Duration,
}

impl Default for GuardPolicy {
    fn default() -> Self {
        Self {
            allow_private: false,
            allow_plaintext: false,
            max_redirects: 0,
            max_body_bytes: 64 * 1024,
            timeout: std::time::Duration::from_secs(10),
        }
    }
}

impl GuardPolicy {
    /// Plaintext is admissible when the caller opted into it, or when it opted into private
    /// addressing at all. One predicate rather than the expression written at each call site,
    /// because the two knobs interacting is exactly the sort of thing that drifts between copies.
    pub fn plaintext_admissible(&self) -> bool {
        self.allow_plaintext || self.allow_private
    }
}

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
    /// `http` where the policy admits no plaintext.
    Plaintext {
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
    /// The host is an alternate IPv4 encoding (`0x7f000001`, `2130706433`, `127.1`) that the OS
    /// resolver expands but a canonical IP-literal check misses.
    ObfuscatedHost(String),
    /// A cloud-metadata NAME. Refused unconditionally, before `allow_private` is consulted.
    MetadataName(String),
    /// The `localhost` family RFC 6761 reserves to loopback, without the opt-in.
    LoopbackName(String),
    /// Resolution failed. NOT the same fact as an empty answer, and collapsing the two would let a
    /// failure read as "nothing internal here".
    Unresolvable {
        /// The name that did not resolve.
        host: String,
        /// What the resolver said about it.
        reason: String,
    },
    /// Resolution succeeded and answered nothing: there is nothing to connect to and nothing to
    /// have judged.
    NoAddresses(String),
    /// An answered address is internal and the policy is not opted into private addressing.
    InternalAddress {
        /// The name that answered with it.
        host: String,
        /// The address answered.
        addr: IpAddr,
    },
    /// An answered address is a cloud-metadata endpoint. Always refused, `allow_private` or not.
    CloudMetadataAddress {
        /// The name that answered with it.
        host: String,
        /// The address answered.
        addr: IpAddr,
    },
    /// A 3xx where the policy follows none.
    Redirect {
        /// The status the upstream answered with.
        status: u16,
        /// Where it wanted the call moved to.
        location: String,
    },
    /// More redirects than the policy permits.
    TooManyRedirects {
        /// The hop bound the policy set.
        limit: u8,
        /// The URL still redirecting when the bound was reached.
        at: String,
    },
    /// The body exceeded [`GuardPolicy::max_body_bytes`].
    BodyTooLarge {
        /// The URL the body came from, with any authority credential replaced by a marker.
        url: String,
        /// How many bytes it was.
        bytes: usize,
    },
}

impl std::fmt::Display for AddressRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressRefusal::Scheme { url, scheme } => write!(
                f,
                "`{url}` uses scheme `{scheme}`; only http(s) is fetched over"
            ),
            AddressRefusal::Plaintext { url, scheme } => write!(
                f,
                "`{url}` uses plaintext `{scheme}` to a host that is not private; a document \
                 fetched over plaintext can be rewritten in flight"
            ),
            AddressRefusal::NoHost(u) => write!(f, "`{u}` has no usable host"),
            AddressRefusal::ObfuscatedHost(h) => write!(
                f,
                "host `{h}` is an alternate IPv4 encoding the resolver expands; write the address \
                 in dotted-quad form so it can be checked"
            ),
            AddressRefusal::MetadataName(h) => write!(
                f,
                "host `{h}` is a cloud-metadata name; that is refused unconditionally"
            ),
            AddressRefusal::LoopbackName(h) => {
                write!(
                    f,
                    "host `{h}` is a loopback name and this fetch is not opted into private \
                           addressing"
                )
            }
            AddressRefusal::Unresolvable { host, reason } => {
                write!(f, "host `{host}` did not resolve: {reason}")
            }
            AddressRefusal::NoAddresses(host) => write!(
                f,
                "host `{host}` resolved to no addresses at all; there is nothing to connect to and \
                 nothing to have judged"
            ),
            AddressRefusal::InternalAddress { host, addr } => {
                write!(f, "host `{host}` resolves to the internal address {addr}")
            }
            AddressRefusal::CloudMetadataAddress { host, addr } => write!(
                f,
                "host `{host}` resolves to the cloud-metadata address {addr}; that is refused \
                 unconditionally"
            ),
            AddressRefusal::Redirect { status, location } => write!(
                f,
                "upstream answered {status} redirecting to `{location}`; this redirect is not \
                 followed because the target was never validated"
            ),
            AddressRefusal::TooManyRedirects { limit, at } => write!(
                f,
                "fetch exceeded {limit} redirect(s), still redirecting at `{at}`"
            ),
            AddressRefusal::BodyTooLarge { url, bytes } => write!(
                f,
                "the document at `{url}` is {bytes} bytes, over the configured ceiling"
            ),
        }
    }
}

/// A DESTINATION THAT PASSED THE CHECK, carrying the exact address the connection must be made to.
///
/// The type cannot be constructed outside this module, so a dispatch path cannot connect to
/// something that was never checked: the check is not a call somebody remembers to make, it is the
/// only way to get the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedTarget {
    host: String,
    port: u16,
    https: bool,
    addr: IpAddr,
}

impl PinnedTarget {
    /// The hostname, preserved for the `Host` header and TLS SNI. Connecting to a pinned IP while
    /// presenting the original name is the whole trick: the certificate is still validated against
    /// the name the operator registered. Pinning the address without preserving the name would turn
    /// a validated TLS connection into an unvalidated one, which trades one hole for a bigger one.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port the URL named, kept rather than re-derived from the scheme.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The scheme the pin was judged under.
    pub fn is_https(&self) -> bool {
        self.https
    }

    /// THE ADDRESS TO CONNECT TO. Not re-resolved.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The same address with its port, for a caller that keys a connection cache on it. The pool
    /// key MUST contain this and not merely the host: a pooled client built for a hostname
    /// re-resolves on its next new connection, which is the TOCTOU the pin exists to close,
    /// reintroduced by the cache in front of it.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr, self.port)
    }
}

/// NAME RESOLUTION, AS A SEAM.
///
/// A trait rather than a direct `to_socket_addrs` call because the hazards this guard exists to
/// defeat are all about WHAT THE RESOLVER SAYS AND WHEN: a mixed answer, an answer that changes
/// between two lookups, a name that resolves to link-local. None of those is reproducible against
/// the real resolver, so none of them would be tested.
pub trait Resolver {
    /// Every address this name currently answers with. `Err` is a resolution FAILURE, not an empty
    /// answer: the two are different facts.
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String>;
}

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
/// [`judge_host_name`] and to `IpAddr::from_str`. The path always opens with `/` (`https://h?q`
/// gives `/?q`).
///
/// A caller that must also FOLLOW a relative `Location` needs a real URL type to join against and
/// parses with one; it still brings the host it parsed back through [`judge_host_name`]. That is the
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
fn redact_userinfo(url: &str) -> String {
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

/// THE SCHEME JUDGEMENT: `https` always; `http` only where the policy admits plaintext.
pub fn judge_scheme(url: &str, https: bool, policy: GuardPolicy) -> Result<(), AddressRefusal> {
    if !https && !policy.plaintext_admissible() {
        return Err(AddressRefusal::Plaintext {
            url: redact_userinfo(url),
            scheme: "http".to_string(),
        });
    }
    Ok(())
}

/// THE STRUCTURAL REFUSALS: everything true about the NAME, so no resolver is consulted.
///
/// **THE METADATA ARM IS SPLIT OUT AND IS UNCONDITIONAL.** [`dns_name_is_internal`] answers for two
/// populations at once — the cloud-metadata names and the `localhost` family — and only the second
/// is something `allow_private` may speak for. Asking the merged question under the knob would make
/// `allow_private: true` a way to fetch `metadata.google.internal`. **Do not re-merge them.**
///
/// `host` must arrive UNBRACKETED; a trailing FQDN-root dot is stripped by the predicates
/// themselves, because `getaddrinfo` resolves `localhost.` to the same target as `localhost` and the
/// extra byte makes an exact compare miss by one.
pub fn judge_host_name(host: &str, policy: GuardPolicy) -> Result<(), AddressRefusal> {
    let bare = host.strip_suffix('.').unwrap_or(host);
    if METADATA_HOSTS.iter().any(|m| bare.eq_ignore_ascii_case(m)) {
        return Err(AddressRefusal::MetadataName(host.to_string()));
    }
    if !policy.allow_private && dns_name_is_internal(host) {
        return Err(AddressRefusal::LoopbackName(host.to_string()));
    }
    if is_alternate_ipv4_encoding(host) {
        return Err(AddressRefusal::ObfuscatedHost(host.to_string()));
    }
    Ok(())
}

/// JUDGE ONE RESOLVED ADDRESS, in the order that makes [`GuardPolicy::allow_private`] safe to have.
///
/// Metadata FIRST and unconditionally, then the internal ranges, which are the only population the
/// knob speaks for. One function rather than a call site per caller so the literal-host arm and the
/// resolved-answer arm cannot be ordered differently.
pub fn judge_address(host: &str, addr: IpAddr, policy: GuardPolicy) -> Result<(), AddressRefusal> {
    if ip_is_cloud_metadata(&addr) {
        return Err(AddressRefusal::CloudMetadataAddress {
            host: host.to_string(),
            addr,
        });
    }
    if ip_is_internal(&addr) && !policy.allow_private {
        return Err(AddressRefusal::InternalAddress {
            host: host.to_string(),
            addr,
        });
    }
    Ok(())
}

/// Refuse if ANY address in the answer is inadmissible.
///
/// A MIXED ANSWER IS A HOSTILE ANSWER: refused whole, never filtered down to the address that
/// happens to be acceptable. A rebinding resolver answers with a public address and a loopback
/// address in one reply and lets the connect pick; checking the first is checking whichever one the
/// resolver put first.
pub fn judge_addresses(
    host: &str,
    addrs: &[IpAddr],
    policy: GuardPolicy,
) -> Result<(), AddressRefusal> {
    for addr in addrs {
        judge_address(host, *addr, policy)?;
    }
    Ok(())
}

/// THE JUDGEMENT AND THE PIN, over an answer somebody else obtained.
///
/// Separated from the resolution so the rebinding case — a resolver answering with one good address
/// and one bad one, or answering differently the second time — is testable without a resolver that
/// will do that on demand. Every caller's resolution funnels through here, which is what makes
/// "there is one address judgement" a fact about the code rather than a claim about discipline.
pub fn pin_answer(
    host: &str,
    port: u16,
    https: bool,
    addrs: &[IpAddr],
    policy: GuardPolicy,
) -> Result<PinnedTarget, AddressRefusal> {
    if addrs.is_empty() {
        return Err(AddressRefusal::NoAddresses(host.to_string()));
    }
    judge_addresses(host, addrs, policy)?;
    // The FIRST admissible address is pinned. All of them passed, so "first" is a choice between
    // equals rather than a filter, and taking the first preserves the resolver's own ordering
    // (which is where happy-eyeballs and geo-DNS preferences live).
    Ok(PinnedTarget {
        host: host.to_string(),
        port,
        https,
        addr: addrs[0],
    })
}

/// RESOLVE THEN PIN, over the caller's resolver seam.
///
/// The order is the design: the structural refusals first, so a hostile name never reaches the
/// resolver; then EXACTLY ONE resolution; then every answered address; then the pin.
///
/// An IP LITERAL is its own answer: judged and pinned without asking a resolver about it. The
/// resolver is not merely unnecessary there, it is wrong — a stub that echoes literals back is one
/// more thing that could disagree with this check.
pub fn resolve_and_pin(
    host: &str,
    port: u16,
    https: bool,
    resolver: &dyn Resolver,
    policy: GuardPolicy,
) -> Result<PinnedTarget, AddressRefusal> {
    judge_host_name(host, policy)?;
    if let Ok(addr) = host.parse::<IpAddr>() {
        return pin_answer(host, port, https, &[addr], policy);
    }
    let addrs = resolver
        .resolve(host)
        .map_err(|reason| AddressRefusal::Unresolvable {
            host: host.to_string(),
            reason,
        })?;
    pin_answer(host, port, https, &addrs, policy)
}

/// Turn a response status into a refusal when it is a redirect the policy does not follow.
///
/// Called on the response path rather than relying only on the client's `Policy::none()`. Two
/// mechanisms for one hazard is deliberate: the client policy stops the request being MADE, and this
/// stops a 3xx being handed to a parser that would report "invalid response" and hide the fact that
/// an upstream tried to move the call somewhere else.
pub fn refuse_redirect(status: u16, location: Option<&str>) -> Result<(), AddressRefusal> {
    if (300..400).contains(&status) {
        return Err(AddressRefusal::Redirect {
            status,
            location: location.unwrap_or("<absent>").to_string(),
        });
    }
    Ok(())
}

/// THE HOP BOUND. A guard applied correctly to an unbounded number of hops is a way to spend the
/// process, so the chain is bounded as well as re-guarded.
pub fn refuse_hop_overflow(hops: u32, at: &str, policy: GuardPolicy) -> Result<(), AddressRefusal> {
    if u32::from(policy.max_redirects) <= hops {
        return Err(AddressRefusal::TooManyRedirects {
            limit: policy.max_redirects,
            at: at.to_string(),
        });
    }
    Ok(())
}

/// THE BODY CAP, checked BEFORE the bytes are parsed. An unbounded read from an upstream is an
/// unbounded allocation an upstream chooses the size of.
pub fn refuse_oversized_body(
    url: &str,
    bytes: usize,
    policy: GuardPolicy,
) -> Result<(), AddressRefusal> {
    if bytes > policy.max_body_bytes {
        return Err(AddressRefusal::BodyTooLarge {
            url: redact_userinfo(url),
            bytes,
        });
    }
    Ok(())
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

impl HostSet {
    /// Canonicalize a list of operator-written entries.
    fn parse(entries: &[String]) -> Self {
        let mut set = HostSet::default();
        for entry in entries {
            let norm = entry.trim().trim_end_matches('.');
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
/// The hardcoded denylist is the addresses [`ip_is_cloud_metadata`] holds (link-local
/// `169.254.0.0/16`, Alibaba `100.100.100.200`, Azure `168.63.129.16`, OCI `192.0.0.192` and the
/// EC2/ECS IPv6 endpoints) and the metadata hostnames in `METADATA_HOSTS`.
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

    // The metadata ADDRESSES are the one list [`ip_is_cloud_metadata`] holds (link-local
    // `169.254.0.0/16`, Alibaba, Azure, OCI and the EC2/ECS IPv6 endpoints), asked of the literal
    // and of an alternate IPv4 spelling the OS resolver would expand to one (decimal `2852039166`,
    // hex, octal, short dotted). A non-metadata obfuscated form is not refused here; it is not a
    // metadata target. A hostname that is not an IP and is not in the lists above is ALLOWED:
    // private, loopback, CGNAT and public upstreams are all legitimate.
    let is_blocked = match expand_alternate_ipv4(host) {
        Some(expanded) => ip_is_cloud_metadata(&IpAddr::V4(expanded)),
        None => host
            .parse::<IpAddr>()
            .is_ok_and(|addr| ip_is_cloud_metadata(&addr)),
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
        if self.allow_all {
            return false;
        }
        let literal = addr.to_string();
        let listed = ip_is_cloud_metadata(&addr)
            || self.blocked.matches(&literal)
            || self.blocked.matches(host);
        listed && !(self.allowed.matches(host) || self.allowed.matches(&literal))
    }
}

/// THE DIAL TABLE: the [`Denylist`] each configured host is judged under when it is dialled.
///
/// The carve-outs are per provider, while the client that dials is shared by every provider of a
/// plane. So the table is keyed by the HOST a provider's URLs name, each host holding the union of the
/// carve-outs of every provider that names it, and every other host is judged under the
/// deployment-wide lists alone. One table, built once per configuration; the judgement is
/// [`Denylist::refuses_address`], the rule the configuration-time check states.
#[derive(Debug, Default, Clone)]
pub struct DialDenylist {
    /// The deployment-wide lists, for a host no provider names.
    default: Denylist,
    /// Per-host lists, keyed lowercase without a trailing dot.
    by_host: std::collections::HashMap<String, Denylist>,
}

impl DialDenylist {
    /// Build the table. `blocked`, `allowed` and `allow_all` are the deployment-wide
    /// `security.blocked_metadata_hosts`, `security.allow_metadata_hosts` and
    /// `security.allow_all_metadata`; `per_host` pairs each host a provider's URLs name with that
    /// provider's own `allow_metadata_hosts`.
    #[must_use]
    pub fn new<'a>(
        blocked: &[String],
        allowed: &[String],
        allow_all: bool,
        per_host: impl IntoIterator<Item = (String, &'a [String])>,
    ) -> Self {
        let mut carve_outs: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for (host, own) in per_host {
            carve_outs
                .entry(dial_key(&host))
                .or_insert_with(|| allowed.to_vec())
                .extend(own.iter().cloned());
        }
        DialDenylist {
            default: Denylist::new(blocked, allowed, allow_all),
            by_host: carve_outs
                .into_iter()
                .map(|(host, own)| (host, Denylist::new(blocked, &own, allow_all)))
                .collect(),
        }
    }

    /// Judge every address `host` answered with. A mixed answer is refused whole, for the reason
    /// [`judge_addresses`] gives: checking only the good address checks whichever one the resolver
    /// put first.
    ///
    /// # Errors
    ///
    /// The first answered address the host's lists refuse.
    pub fn judge(&self, host: &str, addrs: &[IpAddr]) -> Result<(), AddressRefusal> {
        let lists = self.by_host.get(&dial_key(host)).unwrap_or(&self.default);
        match addrs.iter().find(|a| lists.refuses_address(host, **a)) {
            Some(addr) => Err(AddressRefusal::CloudMetadataAddress {
                host: host.to_string(),
                addr: *addr,
            }),
            None => Ok(()),
        }
    }
}

/// A host as the dial table keys it: lowercase, without the FQDN-root dot.
fn dial_key(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Why the trust unit would not let a destination be dialled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkRefusal {
    /// The destination is not one this check applies to: only an upstream is dialled at an address.
    NotAnUpstream,
    /// The destination named a cloud-metadata host, under the precedence rule.
    ///
    /// Its own arm rather than a [`AddressRefusal`], because the denylist is a deployment's statement
    /// about which addresses exist to be reached at all, and the guard below it is about what a
    /// name resolved to. An operator reading a refusal needs to know which of the two answered.
    MetadataDenied(String),
    /// The guard refused the scheme, the name, or an answered address.
    Guard(AddressRefusal),
}

impl std::fmt::Display for NetworkRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkRefusal::NotAnUpstream => {
                write!(f, "only an upstream destination is dialled at an address")
            }
            NetworkRefusal::MetadataDenied(host) => write!(
                f,
                "host `{host}` is on the cloud-metadata denylist; that is not an upstream this \
                 node dials"
            ),
            NetworkRefusal::Guard(g) => write!(f, "{g}"),
        }
    }
}

/// THE CHECK: judge a sealed destination and pin the address a transport will connect to.
///
/// Run once per destination, before any dial, for every carrier. The order is the design's:
///
/// 1. The denylist, over the destination's own authority AND over that authority joined with each
///    declared path. The host a connecting stack reads is the one it finds after WHATWG
///    normalization, and the AUTHORITY is where a spelling that moves the boundary lives — a
///    backslash that terminates it early, a tab inside the literal, a percent-encoded dot. The
///    joined candidates are judged for completeness rather than because a path can smuggle a host
///    past the base: [`join_path`] always separates the two, so a joined candidate's authority ends
///    exactly where the base's does and its verdict is the base's. That is a property of the join
///    and is pinned as one — a join that stopped separating them would make the re-check
///    load-bearing, and it is the re-check that would then catch it.
/// 2. The structural refusals, so a hostile name never reaches a resolver.
/// 3. EXACTLY ONE resolution, through the caller's own seam.
/// 4. Every answered address, judged; a mixed answer refused whole.
/// 5. The pin.
///
/// A destination whose address is a program has no address to judge: nothing is resolved and
/// nothing is pinned. Spawning a process is not a network hop, and pretending it needed a guard
/// would put a check where there is nothing to check.
///
/// # Errors
///
/// The destination is not an upstream, its host is on the denylist, or the guard refused the
/// scheme, the name, or an address the resolver answered with.
pub fn check_destination(
    dest: &busbar_contract::VerifiedDestination,
    paths: &[&str],
    resolver: &dyn Resolver,
    policy: GuardPolicy,
    denylist: &Denylist,
) -> Result<Option<PinnedTarget>, NetworkRefusal> {
    check_destination_facts(&dest.facts(), paths, resolver, policy, denylist)
}

/// The same check, over the facts a destination was sealed FROM.
///
/// The sealed value is the door a transport reaches the guard through, and it stays the published
/// one. But a composition root judges a candidate BEFORE it is sealed — that is the whole point of
/// judging it, and the seal is what the judgement produces — so it holds facts and no seal. Given
/// only the sealed entry, such a caller had no way in and wrote the ordering out a second time,
/// which is the one thing this file exists to stop: two copies of an address judgement drift, and
/// the copy that drifts is the one nobody re-derived.
///
/// So the ordering lives here, once, and [`check_destination`] is a projection onto it rather than a
/// second opinion. Nothing about the sealing rule is loosened by that: a seal was never what made
/// the judgement correct, it is what records that the judgement happened.
///
/// # Errors
///
/// The destination is not an upstream, its host is on the denylist, or the guard refused the
/// scheme, the name, or an address the resolver answered with.
pub fn check_destination_facts(
    facts: &busbar_contract::DestinationFacts,
    paths: &[&str],
    resolver: &dyn Resolver,
    policy: GuardPolicy,
    denylist: &Denylist,
) -> Result<Option<PinnedTarget>, NetworkRefusal> {
    let busbar_contract::DestinationFacts::Upstream { address, .. } = facts else {
        return Err(NetworkRefusal::NotAnUpstream);
    };
    let Some(authority) = address.authority() else {
        // A spawned program is not a network hop.
        return Ok(None);
    };
    match check_structure(authority, paths, policy, denylist)? {
        Structure::Pinned(pinned) => Ok(Some(pinned)),
        Structure::Name { host, port, https } => {
            resolve_and_pin(&host, port, https, resolver, policy)
                .map(Some)
                .map_err(NetworkRefusal::Guard)
        }
    }
}

/// What the structural half of THE CHECK decided about a destination it did not refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Structure {
    /// An IP literal: judged and pinned without a resolver.
    Pinned(PinnedTarget),
    /// A name that passed everything decidable without an answer: the one resolution answers for
    /// it, and [`pin_answer`] judges what it answered.
    Name {
        /// The name, unbracketed.
        host: String,
        /// The port.
        port: u16,
        /// Whether the scheme is `https`.
        https: bool,
    },
}

/// THE STRUCTURAL HALF of [`check_destination_facts`]: steps 1 and 2 of its order, and the pin of
/// an IP literal, with no resolver consulted. A caller that resolves on its own schedule (a service
/// whose resolution may pend) runs this first, resolves a [`Structure::Name`], and judges the answer
/// with [`pin_answer`]; so a refusal decidable from the name answers before any resolution, exactly
/// as it does here.
///
/// # Errors
///
/// The host is on the denylist, or the guard refused the scheme, the name, or the literal address.
pub fn check_structure(
    authority: &str,
    paths: &[&str],
    policy: GuardPolicy,
    denylist: &Denylist,
) -> Result<Structure, NetworkRefusal> {
    // The denylist, over the base and over every path it is joined with.
    if !denylist.allow_all {
        for candidate in std::iter::once(authority.to_string())
            .chain(paths.iter().map(|p| join_path(authority, p)))
        {
            if let Some(host) =
                judge_against_lists(&candidate, &denylist.allowed, &denylist.blocked)
            {
                return Err(NetworkRefusal::MetadataDenied(host));
            }
        }
    }

    // An authority may be spelled as a URL or as a bare `host:port`; both reach the same judgement,
    // because which of the two a lane's configuration used is not a security question.
    let (https, host, port) = match split_url(authority) {
        Ok((https, host, port, _path)) => {
            judge_scheme(authority, https, policy).map_err(NetworkRefusal::Guard)?;
            (https, host, port)
        }
        Err(AddressRefusal::Scheme { .. }) => {
            let (host, port) = split_authority(authority).ok_or_else(|| {
                NetworkRefusal::Guard(AddressRefusal::NoHost(redact_userinfo(authority)))
            })?;
            (true, host, port)
        }
        Err(other) => return Err(NetworkRefusal::Guard(other)),
    };

    judge_host_name(&host, policy).map_err(NetworkRefusal::Guard)?;
    if let Ok(addr) = host.parse::<IpAddr>() {
        return pin_answer(&host, port, https, &[addr], policy)
            .map(Structure::Pinned)
            .map_err(NetworkRefusal::Guard);
    }
    Ok(Structure::Name { host, port, https })
}

/// Join a configured base with a declared path, the way a caller building a request would.
///
/// The SEPARATOR is the security-relevant part, and it is unconditional: exactly one `/` sits
/// between the authority and the fragment however the fragment was written. That is what makes a
/// declared path unable to name a host — a fragment opening with `@`, `//` or a `\` the WHATWG fold
/// turns into a terminator lands after a delimiter that has already closed the authority. Dropping
/// the separator to be tidy about a path that "already has one" would hand the fragment the
/// boundary; the join is naive about the slash on purpose.
fn join_path(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

/// Split a bare `host:port` authority — a lane that names an address rather than a URL.
///
/// A bracketed IPv6 literal comes back unbracketed, so it reads the same here as it does to
/// [`judge_host_name`] and to `IpAddr::from_str`. A missing port defaults to the secure one,
/// because an authority with no scheme said nothing about plaintext and fail-closed is the reading
/// to take.
fn split_authority(authority: &str) -> Option<(String, u16)> {
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    if let Some(inner) = authority.strip_prefix('[') {
        let (host, tail) = inner.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => 443,
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Some((host.to_string(), port.parse().ok()?)),
        _ => Some((authority.to_string(), 443)),
    }
}
