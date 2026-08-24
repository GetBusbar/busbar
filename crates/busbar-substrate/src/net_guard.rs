// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GUARDED FETCH, and the pure network-address primitives it is built from.
//!
//! ## Why the whole control lives here and not on a plane
//!
//! Resolve-then-pin was written twice — once for the MCP dispatch path and once for the A2A card
//! fetch — and the second copy was already reaching for the first's vocabulary in its own doc
//! comments. Two implementations of one security control is the shape that produced this release's
//! cloud-metadata bypass: a contributor hardens one and the other keeps the hole. The rule the
//! owner states for this tree is that a thing used twice, or that COULD be used twice, is core; the
//! third caller (the authorization server's client-metadata-document fetch) is what turned the
//! duplication into a dependency, because a plane's module was about to become an authorization
//! server's security dependency.
//!
//! **What core owns:** the strict URL recogniser, the scheme/plaintext judgement, the structural
//! name refusals, EXACTLY ONE resolution, the judgement of EVERY answered address, the pin, the
//! redirect refusal, the hop bound and the body cap. **What a caller owns:** its own knobs
//! ([`GuardPolicy`]) and its own WORDING. A caller keeps its refusal vocabulary because "MCP
//! upstream URL" and "agent card URL" are different sentences to an operator diagnosing a refusal;
//! it does not keep its own decision.
//!
//! ## RESOLVE THEN PIN, and why a name check is not a guard
//!
//! Checking the host STRING and then handing the URL to an HTTP client is not a guard, it is a
//! guard-shaped delay. The client performs its OWN name resolution when it connects, and between
//! the check and the connect the name is free to mean something else. That is DNS rebinding, and it
//! is not exotic: a hostile endpoint only has to serve a short TTL and answer the second lookup
//! with `169.254.169.254`.
//!
//! So the name is resolved exactly ONCE per hop, EVERY answered address is judged, and the address
//! that survives is PINNED ([`PinnedTarget`]) and handed to the transport. The socket connects to
//! an address this module already looked at. There is no second lookup for an attacker to win.
//!
//! A transport that takes the pinned address and then hands the URL to the client has reinstated
//! the second lookup — it compiles, it reads correctly, and it passes every fixture test, which is
//! why `a2a/transport.rs` replaces its client's resolver outright and `mcp/client/pool.rs` keys the
//! connection cache BY THE PINNED ADDRESS rather than by the host.
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
//! depend on which caller is asking. They previously lived as byte-identical copies (or inline
//! bit-mask expressions) in both
//! `config_validate` (the provider-base-URL SSRF guard, which hand-parses a raw config string) and
//! `observability` (the request-log-webhook / OTLP SSRF guard, which reads an already
//! `reqwest::Url::parse`d host). Duplicated *security* logic is the one place where "documented
//! divergence" does not fully neutralize drift: a contributor hardening one guard against a new
//! obfuscation form could silently miss the other copy. Hoisting just these identical primitives
//! into one tested leaf gives them a single source of truth.
//!
//! The *context-specific* wrappers stay with their callers on purpose, because they legitimately
//! differ: `config_validate` keeps `expand_alternate_ipv4` (it re-checks an obfuscated literal
//! against the metadata denylist) and its raw-string `percent_decode_host`; `observability` keeps
//! `is_internal_v4` (which additionally blocks `255.255.255.255` broadcast) and its
//! `METADATA_HOSTS` list shape. This module holds ONLY the parts that are — and must remain —
//! identical.
//!
//! The predicates are pure (no I/O, no globals), so each is unit-testable in isolation; the guard
//! above them takes its ONE resolution through a [`Resolver`] seam for the same reason — a mixed
//! answer and an answer that changes between two lookups are not reproducible against the real
//! resolver, and an untested SSRF guard is a comment.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Well-known cloud-metadata / internal DNS names that resolve, at connect time, to the IMDS family
/// even though they are not IP literals. Blocked case-insensitively by [`dns_name_is_internal`].
///
/// The `localhost` family is deliberately NOT here: it is a SEPARATE arm in
/// [`dns_name_is_internal`], because `config_validate::ssrf_blocked_host` allows `localhost` (a
/// legitimate local-model upstream) while the webhook, OTLP and A2A-card guards block it. Keeping
/// the two lists apart is what lets one guard opt out of the localhost arm without also opting out
/// of the metadata one.
pub const METADATA_HOSTS: &[&str] = &["metadata.google.internal", "metadata.internal"];

/// TRUE for an IPv4 literal no busbar guard may connect to: loopback, link-local (which is where the
/// `169.254.169.254` IMDS endpoint lives), RFC1918 private, RFC6598 CGNAT, unspecified, broadcast,
/// and the two cloud-metadata endpoints that sit on PUBLIC / IETF-reserved addresses outside every
/// one of those ranges (Azure WireServer, and OCI IMDS via the `192.0.0.0/24` it sits inside),
/// which the range predicates would otherwise miss entirely.
///
/// This is the predicate `observability::host_is_internal` was written around, hoisted here so the
/// A2A card fetch (`a2a::fetch`) reuses it rather than growing a fourth copy. Duplicated SECURITY
/// logic is the one place a documented divergence does not neutralize drift: a contributor
/// hardening one guard against a new range would silently miss the others.
pub fn ipv4_is_internal(v4: &Ipv4Addr) -> bool {
    const AZURE_WIRESERVER: Ipv4Addr = Ipv4Addr::new(168, 63, 129, 16);
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_link_local()
        || v4.is_private()
        || is_cgnat_shared_v4(v4)
        || v4.is_unspecified()
        || v4.is_broadcast()
        || *v4 == AZURE_WIRESERVER
        // MULTICAST and DOCUMENTATION arrived here from the MCP client's own copy when the two were
        // unified. The copy had them and this one did not, so the A2A card fetch — which already
        // used this predicate — was the weaker of the two without anyone deciding that. Neither is
        // a plausible destination for an upstream a caller nominates, and `224.0.0.1` reaches every
        // host on the local segment.
        || v4.is_multicast()
        || v4.is_documentation()
        // ── THE THREE ROWS BELOW ARRIVED FROM `a2a::pushnotify`'s PRIVATE COPY when that copy was
        //    torn out. The tear-out is only safe if this predicate already covers everything the
        //    copy covered, and it did not: a plane that stopped using its own table and started
        //    using this one would have SILENTLY WIDENED what it accepts. That is the drift this
        //    module exists to prevent, arriving in the shape of a cleanup.
        //
        // 0.0.0.0/8 "this network" (RFC 1122 §3.2.1.3). `is_unspecified()` is ONLY `0.0.0.0`, so
        // `0.1.2.3` was reachable through every guard that used this predicate — and several
        // stacks route the whole block to the local host.
        || o[0] == 0
        // 192.0.0.0/24 IETF protocol assignments. OCI's IMDS at `192.0.0.192` sits INSIDE this /24,
        // so the /24 subsumes the old single-address constant rather than sitting beside it.
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 198.18.0.0/15 benchmarking (RFC 2544). Not a legitimate destination, and routed inside
        // some fabrics.
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
}

/// TRUE for an IPv6 literal no busbar guard may connect to.
///
/// The ORDER is load-bearing and is the reason this is one function rather than three call sites.
/// `::1` must be caught by `is_loopback()` FIRST: under `to_ipv4()` it canonicalizes to `0.0.0.1`,
/// which is not a v4 loopback, so an embedded-v4 arm placed first would let it through. Then the
/// embedded-v4 arm runs BEFORE the v6 range masks, because `[::ffff:127.0.0.1]` and
/// `[::169.254.169.254]` match no v6 mask at all yet a connecting stack still routes them to the
/// embedded v4 target. `to_ipv4()` rather than `to_ipv4_mapped()`: it is the superset that also
/// covers the IPv4-COMPATIBLE form.
pub fn ipv6_is_internal(v6: &Ipv6Addr) -> bool {
    if v6.is_loopback() {
        return true;
    }
    if let Some(v4) = v6.to_ipv4() {
        return ipv4_is_internal(&v4);
    }
    v6.is_unspecified() || v6.is_multicast() || is_unique_local_v6(v6) || is_link_local_v6(v6)
}

/// TRUE for a resolved address that is a CLOUD-METADATA endpoint.
///
/// Separate from [`ip_is_internal`] because the two have different POLICIES, not different data: an
/// internal address may be reached when an operator sets `allow_private`, and a metadata endpoint
/// may never be reached at all. Folding them together would make `allow_private` a switch that
/// hands out cloud credentials.
///
/// The v6 arm unwraps with `to_ipv4()`, not `to_ipv4_mapped()`, for the reason [`ipv6_is_internal`]
/// gives: `to_ipv4()` is the superset that also covers the IPv4-COMPATIBLE form, so
/// `[::169.254.169.254]` is caught. A guard that only unwrapped the MAPPED form let exactly that
/// literal through — it matched no v6 range, unwrapped to nothing, and was connected to.
pub fn ip_is_cloud_metadata(addr: &IpAddr) -> bool {
    /// AWS/Azure/GCP/OpenStack/DigitalOcean IMDS, ECS task metadata, and Alibaba's.
    const V4: &[Ipv4Addr] = &[
        Ipv4Addr::new(169, 254, 169, 254),
        Ipv4Addr::new(169, 254, 170, 2),
        Ipv4Addr::new(100, 100, 100, 200),
        Ipv4Addr::new(168, 63, 129, 16),
        Ipv4Addr::new(192, 0, 0, 192),
    ];
    match addr {
        IpAddr::V4(v4) => V4.contains(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4() {
                return V4.contains(&v4);
            }
            // IMDSv6.
            v6.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254]
        }
    }
}

/// TRUE for any resolved address a busbar guard must refuse to connect to.
///
/// This is the predicate a RESOLVE-THEN-PIN guard applies to what the resolver actually answered,
/// which is the only form of the check that survives a DNS rebind: a name is not an address, and
/// the address is what a socket connects to.
pub fn ip_is_internal(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => ipv4_is_internal(v4),
        IpAddr::V6(v6) => ipv6_is_internal(v6),
    }
}

/// TRUE for a DNS NAME that is internal by definition rather than by resolution: the cloud-metadata
/// names in [`METADATA_HOSTS`], and the `localhost` family RFC 6761 reserves to loopback.
///
/// A trailing FQDN-root dot is stripped first. `getaddrinfo` resolves `localhost.` and
/// `metadata.google.internal.` to the same targets as the bare spelling, but the trailing dot makes
/// an exact compare miss by one byte — which is a bypass, not a curiosity.
pub fn dns_name_is_internal(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    if METADATA_HOSTS.iter().any(|m| host.eq_ignore_ascii_case(m)) {
        return true;
    }
    host.eq_ignore_ascii_case("localhost")
        || host
            .rsplit_once('.')
            .is_some_and(|(_, tld)| tld.eq_ignore_ascii_case("localhost"))
}

/// IPv6 unique-local range `fc00::/7` (the first 7 bits are `1111110`). No stable std predicate
/// exists for this range on the pinned toolchain, so the leading bits are checked directly.
pub fn is_unique_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// IPv6 link-local range `fe80::/10` (the first 10 bits are `1111111010`). No stable std predicate
/// exists for this range on the pinned toolchain, so the leading bits are checked directly.
pub fn is_link_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// RFC 6598 Shared Address Space `100.64.0.0/10` (a.k.a. CGNAT). NOT covered by
/// `Ipv4Addr::is_private()`, yet routable inside AWS/GCP VPCs and many Kubernetes clusters where it
/// fronts internal services — so it is an SSRF target the private/link-local checks miss. The /10
/// is the addresses whose first octet is `100` and whose top two bits of the second octet are `01`.
pub fn is_cgnat_shared_v4(v4: &Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// True when `host` is an alternate (non-dotted-quad) IPv4 encoding that `IpAddr::from_str` rejects
/// but the OS resolver (glibc `getaddrinfo`, used by reqwest's default resolver) still maps to an
/// IPv4 address: a bare decimal integer (`2130706433` = 127.0.0.1), a `0x`/`0X` hex literal
/// (`0x7f000001`), a leading-zero octal literal (`017700000001`), or a dotted form with FEWER than
/// four octets (`127.1`, `10.0.1`). On a raw, un-normalized host string these bypass the canonical
/// IP-literal checks while still resolving to loopback / link-local / private targets at connect
/// time, so they must be treated as blocked. A canonical four-octet dotted-quad is NOT matched here
/// (it is handled by the `parse::<IpAddr>()` path); a normal DNS hostname is not matched either.
pub fn is_alternate_ipv4_encoding(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }

    // Whole-host `0x...` / `0X...` hex literal (e.g. `0x7f000001`). Only when there is no `.`; a
    // dotted per-octet hex form (`0x7f.0.0.1`) is handled by the dotted branch below.
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
        }
    }

    // Dotted form: split on '.'. A canonical dotted-quad has exactly 4 parts and parses via
    // `IpAddr` — leave it to that path. Fewer than 4 numeric parts (e.g. `127.1`, `10.0.1`) is an
    // alternate short form getaddrinfo expands; flag it. Any part using a `0x` hex or leading-zero
    // octal encoding is also an alternate form.
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        // Every part must be a numeric encoding (decimal, hex, or octal) for this to be an IP-ish
        // host at all; if any part has a non-numeric character it's a DNS name → not our concern.
        let all_numeric = parts.iter().all(|p| {
            if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
                !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
            } else {
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
            }
        });
        if !all_numeric {
            return false;
        }
        // Short dotted form (fewer than 4 parts) is an alternate encoding getaddrinfo expands.
        if parts.len() < 4 {
            return true;
        }
        // Four numeric parts: alternate iff any part is hex (`0x`) or leading-zero octal.
        return parts.iter().any(|p| {
            p.starts_with("0x")
                || p.starts_with("0X")
                || (p.len() > 1 && p.starts_with('0') && p.bytes().all(|b| b.is_ascii_digit()))
        });
    }

    // No '.', not `0x`: a bare all-digits host is a decimal integer IP encoding (e.g. `2130706433`).
    host.bytes().all(|b| b.is_ascii_digit())
}

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
    /// How many redirects may be FOLLOWED. Zero is a legitimate setting and is the MCP dispatch
    /// path's: a 3xx there is a URL nobody validated, arriving when the credential is already sent.
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
/// into their own refusal type so an operator reading a log still sees "MCP upstream" or "agent
/// card"; callers without one render it with the [`std::fmt::Display`] below. What no caller does is
/// re-derive the DECISION, which is the whole reason this enum is here and not there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardRefusal {
    /// The URL had no `http`/`https` scheme, or no scheme at all. Everything else — `file:`,
    /// `gopher:`, `smb:`, `ftp:`, `data:` — is refused by ABSENCE rather than by a blocklist,
    /// because a blocklist of schemes is a list somebody has to keep up with.
    Scheme { url: String, scheme: String },
    /// `http` where the policy admits no plaintext.
    Plaintext { url: String, scheme: String },
    /// The URL had no host component, or an unusable authority (userinfo, an unclosed IPv6
    /// bracket, an unparseable port).
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
    Unresolvable { host: String, reason: String },
    /// Resolution succeeded and answered nothing: there is nothing to connect to and nothing to
    /// have judged.
    NoAddresses(String),
    /// An answered address is internal and the policy is not opted into private addressing.
    InternalAddress { host: String, addr: IpAddr },
    /// An answered address is a cloud-metadata endpoint. Always refused, `allow_private` or not.
    CloudMetadataAddress { host: String, addr: IpAddr },
    /// A 3xx where the policy follows none.
    Redirect { status: u16, location: String },
    /// More redirects than the policy permits.
    // A2A-only: only the A2A fetch path follows redirects and can overflow the hop limit; the MCP
    // guard callers do not construct this, so with `plane-a2a` off (and MCP on) it is never built.
    #[cfg_attr(not(feature = "plane-a2a"), allow(dead_code))]
    TooManyRedirects { limit: u8, at: String },
    /// The body exceeded [`GuardPolicy::max_body_bytes`].
    BodyTooLarge { url: String, bytes: usize },
}

impl std::fmt::Display for GuardRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardRefusal::Scheme { url, scheme } => write!(
                f,
                "`{url}` uses scheme `{scheme}`; only http(s) is fetched over"
            ),
            GuardRefusal::Plaintext { url, scheme } => write!(
                f,
                "`{url}` uses plaintext `{scheme}` to a host that is not private; a document \
                 fetched over plaintext can be rewritten in flight"
            ),
            GuardRefusal::NoHost(u) => write!(f, "`{u}` has no usable host"),
            GuardRefusal::ObfuscatedHost(h) => write!(
                f,
                "host `{h}` is an alternate IPv4 encoding the resolver expands; write the address \
                 in dotted-quad form so it can be checked"
            ),
            GuardRefusal::MetadataName(h) => write!(
                f,
                "host `{h}` is a cloud-metadata name; that is refused unconditionally"
            ),
            GuardRefusal::LoopbackName(h) => {
                write!(
                    f,
                    "host `{h}` is a loopback name and this fetch is not opted into private \
                           addressing"
                )
            }
            GuardRefusal::Unresolvable { host, reason } => {
                write!(f, "host `{host}` did not resolve: {reason}")
            }
            GuardRefusal::NoAddresses(host) => write!(
                f,
                "host `{host}` resolved to no addresses at all; there is nothing to connect to and \
                 nothing to have judged"
            ),
            GuardRefusal::InternalAddress { host, addr } => {
                write!(f, "host `{host}` resolves to the internal address {addr}")
            }
            GuardRefusal::CloudMetadataAddress { host, addr } => write!(
                f,
                "host `{host}` resolves to the cloud-metadata address {addr}; that is refused \
                 unconditionally"
            ),
            GuardRefusal::Redirect { status, location } => write!(
                f,
                "upstream answered {status} redirecting to `{location}`; this redirect is not \
                 followed because the target was never validated"
            ),
            GuardRefusal::TooManyRedirects { limit, at } => write!(
                f,
                "fetch exceeded {limit} redirect(s), still redirecting at `{at}`"
            ),
            GuardRefusal::BodyTooLarge { url, bytes } => write!(
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
    // MCP-only: the MCP client reads the pinned host back to preserve SNI; the A2A fetch path does
    // not, so with `plane-mcp` off (and A2A on) it has no caller.
    #[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
    pub fn host(&self) -> &str {
        &self.host
    }

    // Read by the refusal suites, which assert that the pin carries the port the URL named rather
    // than the scheme's default. No production caller needs it separately from `socket_addr()`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn port(&self) -> u16 {
        self.port
    }

    // As `port()`: the suites assert the pin remembers the scheme it was judged under.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_https(&self) -> bool {
        self.https
    }

    /// THE ADDRESS TO CONNECT TO. Not re-resolved.
    // A2A-only: the A2A fetch path connects by pinned address; the MCP client keys on
    // `socket_addr()`, so with `plane-a2a` off (and MCP on) this has no caller.
    #[cfg_attr(not(feature = "plane-a2a"), allow(dead_code))]
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
// A2A-only seam: the A2A fetch path resolves-and-pins through this trait; the MCP client's pin is
// built elsewhere, so with `plane-a2a` off (and MCP on) the trait has no user.
#[cfg_attr(not(feature = "plane-a2a"), allow(dead_code))]
pub trait Resolver {
    /// Every address this name currently answers with. `Err` is a resolution FAILURE, not an empty
    /// answer: the two are different facts.
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String>;
}

/// Split an `http(s)://host[:port][/path]` URL into `(https, host, port, path)`.
///
/// Hand-written because what is wanted is a STRICT RECOGNISER. A permissive parser's job is to find
/// a reading that works, and "find a reading that works" is the opposite of what a security check
/// wants from an attacker-influenced string. The host comes back UNBRACKETED, so an IPv6 literal
/// reads the same here as it does to [`judge_host_name`] and to `IpAddr::from_str`.
///
/// A caller that must also FOLLOW a relative `Location` needs a real URL type to join against and
/// parses with one; it still brings the host it parsed back through [`judge_host_name`]. That is the
/// one part of the recognition that is legitimately per-caller, and it is why this is a public
/// helper rather than the only door in.
pub fn split_url(url: &str) -> Result<(bool, String, u16, String), GuardRefusal> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(GuardRefusal::Scheme {
            url: url.to_string(),
            scheme: scheme_of(url),
        });
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // Userinfo is refused rather than stripped. `https://evil.test@good.example/` reads as
    // `good.example` to a parser and as `evil.test` to a human skimming a config diff, and a value
    // whose two readings differ has no place on a fetch path.
    if authority.contains('@') || authority.is_empty() {
        return Err(GuardRefusal::NoHost(url.to_string()));
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal.
        let (h, tail) = inner
            .split_once(']')
            .ok_or_else(|| GuardRefusal::NoHost(url.to_string()))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| GuardRefusal::NoHost(url.to_string()))?,
            None => default_port(https),
        };
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| GuardRefusal::NoHost(url.to_string()))?,
            ),
            None => (authority.to_string(), default_port(https)),
        }
    };
    if host.is_empty() {
        return Err(GuardRefusal::NoHost(url.to_string()));
    }
    Ok((https, host, port, path.to_string()))
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
pub fn judge_scheme(url: &str, https: bool, policy: GuardPolicy) -> Result<(), GuardRefusal> {
    if !https && !policy.plaintext_admissible() {
        return Err(GuardRefusal::Plaintext {
            url: url.to_string(),
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
pub fn judge_host_name(host: &str, policy: GuardPolicy) -> Result<(), GuardRefusal> {
    let bare = host.strip_suffix('.').unwrap_or(host);
    if METADATA_HOSTS.iter().any(|m| bare.eq_ignore_ascii_case(m)) {
        return Err(GuardRefusal::MetadataName(host.to_string()));
    }
    if !policy.allow_private && dns_name_is_internal(host) {
        return Err(GuardRefusal::LoopbackName(host.to_string()));
    }
    if is_alternate_ipv4_encoding(host) {
        return Err(GuardRefusal::ObfuscatedHost(host.to_string()));
    }
    Ok(())
}

/// JUDGE ONE RESOLVED ADDRESS, in the order that makes [`GuardPolicy::allow_private`] safe to have.
///
/// Metadata FIRST and unconditionally, then the internal ranges, which are the only population the
/// knob speaks for. One function rather than a call site per caller so the literal-host arm and the
/// resolved-answer arm cannot be ordered differently.
pub fn judge_address(host: &str, addr: IpAddr, policy: GuardPolicy) -> Result<(), GuardRefusal> {
    if ip_is_cloud_metadata(&addr) {
        return Err(GuardRefusal::CloudMetadataAddress {
            host: host.to_string(),
            addr,
        });
    }
    if ip_is_internal(&addr) && !policy.allow_private {
        return Err(GuardRefusal::InternalAddress {
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
) -> Result<(), GuardRefusal> {
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
) -> Result<PinnedTarget, GuardRefusal> {
    if addrs.is_empty() {
        return Err(GuardRefusal::NoAddresses(host.to_string()));
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
// A2A-only: the resolve-then-pin entry point for the A2A fetch path; with `plane-a2a` off (and MCP
// on) nothing calls it.
#[cfg_attr(not(feature = "plane-a2a"), allow(dead_code))]
pub fn resolve_and_pin(
    host: &str,
    port: u16,
    https: bool,
    resolver: &dyn Resolver,
    policy: GuardPolicy,
) -> Result<PinnedTarget, GuardRefusal> {
    judge_host_name(host, policy)?;
    if let Ok(addr) = host.parse::<IpAddr>() {
        return pin_answer(host, port, https, &[addr], policy);
    }
    let addrs = resolver
        .resolve(host)
        .map_err(|reason| GuardRefusal::Unresolvable {
            host: host.to_string(),
            reason,
        })?;
    pin_answer(host, port, https, &addrs, policy)
}

/// RESOLVE THEN PIN on an async path, through the runtime's own resolver.
///
/// The same judgement and the same pin as [`resolve_and_pin`] — it funnels through the same
/// [`pin_answer`] — differing only in WHO answers the name. That difference is real and is not
/// parameterisable away: a dispatch path inside a runtime must not block a worker on `getaddrinfo`,
/// and a synchronous fetch seam has no runtime to hand a future to. Two doors, one room.
pub async fn resolve_and_pin_async(
    host: &str,
    port: u16,
    https: bool,
    policy: GuardPolicy,
) -> Result<PinnedTarget, GuardRefusal> {
    judge_host_name(host, policy)?;
    if let Ok(addr) = host.parse::<IpAddr>() {
        return pin_answer(host, port, https, &[addr], policy);
    }
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| GuardRefusal::Unresolvable {
            host: host.to_string(),
            reason: e.to_string(),
        })?
        .map(|sa| sa.ip())
        .collect();
    pin_answer(host, port, https, &addrs, policy)
}

/// Turn a response status into a refusal when it is a redirect the policy does not follow.
///
/// Called on the response path rather than relying only on the client's `Policy::none()`. Two
/// mechanisms for one hazard is deliberate: the client policy stops the request being MADE, and this
/// stops a 3xx being handed to a parser that would report "invalid response" and hide the fact that
/// an upstream tried to move the call somewhere else.
pub fn refuse_redirect(status: u16, location: Option<&str>) -> Result<(), GuardRefusal> {
    if (300..400).contains(&status) {
        return Err(GuardRefusal::Redirect {
            status,
            location: location.unwrap_or("<absent>").to_string(),
        });
    }
    Ok(())
}

/// THE HOP BOUND. A guard applied correctly to an unbounded number of hops is a way to spend the
/// process, so the chain is bounded as well as re-guarded.
// A2A-only: only the A2A fetch path follows a redirect chain and bounds its hops; with `plane-a2a`
// off (and MCP on) nothing calls it.
#[cfg_attr(not(feature = "plane-a2a"), allow(dead_code))]
pub fn refuse_hop_overflow(hops: u32, at: &str, policy: GuardPolicy) -> Result<(), GuardRefusal> {
    if u32::from(policy.max_redirects) <= hops {
        return Err(GuardRefusal::TooManyRedirects {
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
) -> Result<(), GuardRefusal> {
    if bytes > policy.max_body_bytes {
        return Err(GuardRefusal::BodyTooLarge {
            url: url.to_string(),
            bytes,
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/net_guard_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/net_guard_fetch_tests.rs"]
mod fetch_tests;
