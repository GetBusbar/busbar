// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The network guard: what a destination may be dialled, and to which address.
//!
//! ## Why it is the trust unit's and not a transport's
//!
//! This check was written three times over — once for a dispatch path, once for a card fetch, once
//! for an authorization server's metadata fetch — and the second copy was already borrowing the
//! first's vocabulary in its own comments. Two implementations of one security control is the shape
//! that produces a metadata bypass: somebody hardens one and the other keeps the hole.
//!
//! It lived in a neutral leaf for exactly that reason, and it is here now for one more: a transport
//! that resolved a name itself was a transport that had to remember to guard it, and every new
//! carrier was a new place to forget. The trust unit already decides where a unit may go — the
//! allow-list, the per-kind rule, the lane — so the address a destination resolves to belongs
//! beside those, checked once for every carrier that will ever exist. A transport receives a
//! destination that has already been judged and an address that has already been pinned.
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
pub enum AddressRefusal {
    /// The URL had no `http`/`https` scheme, or no scheme at all. Everything else — `file:`,
    /// `gopher:`, `smb:`, `ftp:`, `data:` — is refused by ABSENCE rather than by a blocklist,
    /// because a blocklist of schemes is a list somebody has to keep up with.
    Scheme {
        /// The URL as written.
        url: String,
        /// The scheme it claimed.
        scheme: String,
    },
    /// `http` where the policy admits no plaintext.
    Plaintext {
        /// The URL as written.
        url: String,
        /// The scheme it claimed.
        scheme: String,
    },
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
        /// The URL the body came from.
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
/// Hand-written because what is wanted is a STRICT RECOGNISER. A permissive parser's job is to find
/// a reading that works, and "find a reading that works" is the opposite of what a security check
/// wants from an attacker-influenced string. The host comes back UNBRACKETED, so an IPv6 literal
/// reads the same here as it does to [`judge_host_name`] and to `IpAddr::from_str`.
///
/// A caller that must also FOLLOW a relative `Location` needs a real URL type to join against and
/// parses with one; it still brings the host it parsed back through [`judge_host_name`]. That is the
/// one part of the recognition that is legitimately per-caller, and it is why this is a public
/// helper rather than the only door in.
pub fn split_url(url: &str) -> Result<(bool, String, u16, String), AddressRefusal> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(AddressRefusal::Scheme {
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
        return Err(AddressRefusal::NoHost(url.to_string()));
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal.
        let (h, tail) = inner
            .split_once(']')
            .ok_or_else(|| AddressRefusal::NoHost(url.to_string()))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| AddressRefusal::NoHost(url.to_string()))?,
            None => default_port(https),
        };
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| AddressRefusal::NoHost(url.to_string()))?,
            ),
            None => (authority.to_string(), default_port(https)),
        }
    };
    if host.is_empty() {
        return Err(AddressRefusal::NoHost(url.to_string()));
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
pub fn judge_scheme(url: &str, https: bool, policy: GuardPolicy) -> Result<(), AddressRefusal> {
    if !https && !policy.plaintext_admissible() {
        return Err(AddressRefusal::Plaintext {
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
            url: url.to_string(),
            bytes,
        });
    }
    Ok(())
}

// ── The config-side siblings of the IP predicates above: pure string/address work over a URL a
//    deployment wrote down, rather than over an address a resolver answered with. They travel with
//    the predicates for the same reason the predicates were hoisted in the first place — a
//    contributor hardening one obfuscation form must not be able to miss the other copy, because
//    there is no other copy.

/// Whether a URL claims the given scheme, case-insensitively.
pub fn scheme_is(url: &str, scheme: &str) -> bool {
    url.split_once("://")
        .is_some_and(|(s, _)| s.eq_ignore_ascii_case(scheme))
}

/// Strip an `http`/`https` scheme case-insensitively, returning the authority+path remainder.
fn strip_scheme(url: &str) -> Option<&str> {
    let (scheme, rest) = url.split_once("://")?;
    (scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http")).then_some(rest)
}

/// Return `Some(host)` if the given `https://` URL points at an SSRF-sensitive target (loopback,
/// link-local, RFC-1918 private, unique-local IPv6, or a known cloud metadata hostname), else
/// `None`. The host is extracted by string slicing (no URL crate): strip the scheme, take up to the
/// first `/`, `?`, or `#`, drop any `user@` prefix, then separate an IPv6 `[...]` literal or an
/// `host:port` from its port. IP literals are parsed with `IpAddr` and checked against the blocked
/// ranges; non-IP hostnames are matched case-insensitively against the metadata hostname list.
/// Percent-decode a host string (`%XX` → byte), mirroring the RFC 3986 decoding the `url` crate
/// applies to host components at request time. Invalid escapes (`%` not followed by two hex digits)
/// are left verbatim so a malformed host stays malformed (it will still fail every IP/hostname check
/// and be allowed, but it can never be SMUGGLED PAST a check by hiding a blocked literal behind an
/// escape). Only ASCII results are surfaced as decoded bytes; non-UTF-8 decoded output falls back to
/// the original so we never fabricate a misleading host. No new dependency — a small manual scan.
fn percent_decode_host(host: &str) -> String {
    let bytes = host.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    match String::from_utf8(out) {
        Ok(s) => s,
        // Decoded bytes are not valid UTF-8: keep the original literal rather than a lossy host.
        Err(_) => host.to_string(),
    }
}

/// The host a connecting stack would read out of `url`, after every normalization it performs.
///
/// This is the whole obfuscation defense in one place: the tab/LF/CR strip the WHATWG parser does
/// first, the backslash fold that moves the authority boundary, the userinfo drop, the IPv6
/// bracket, the percent-decode, and the trailing FQDN-root dot. A guard that read a different host
/// than the socket connects to is not a guard.
pub fn extract_normalized_host(url: &str) -> Option<String> {
    // Strip ALL ASCII tab (0x09), LF (0x0A), and CR (0x0D) characters from anywhere in the string,
    // FIRST — before any other normalization, mirroring the WHATWG URL spec's basic parser, which
    // removes these three bytes from the whole input as its very first step, before scheme/authority
    // parsing even begins. reqwest's `url` crate implements this removal, so it is not merely a
    // leading/trailing trim: a tab EMBEDDED mid-host is deleted too. Without mirroring it, a
    // `base_url` like `"https://169.254.169\t.254/"` (a tab is a legal byte inside a YAML
    // double-quoted scalar) is seen by this guard as the non-IP, non-metadata-matching host
    // `169.254.169\t.254` (passes every check) while the actual connecting stack deletes the tab and
    // connects to `169.254.169.254` — the real IMDS address. Doing this before the backslash→`/`
    // fold matters too: a stripped tab could otherwise sit between characters that only become a
    // delimiter after this removal (WHATWG strips tab/newline before it looks for `\`/`/` at all).
    let url = url.replace(['\t', '\n', '\r'], "");
    let url = url.as_str();
    // Strip the scheme (case-insensitively — see `scheme_is`). The host extraction is
    // scheme-agnostic; accept either prefix so an `http://` upstream is still metadata-checked.
    let rest = strip_scheme(url)?;
    // Normalize backslashes to forward slashes BEFORE splitting the authority. `https` is a WHATWG
    // "special" scheme, so reqwest's `url` crate converts every `\` to `/` while parsing — meaning a
    // `base_url` like `https://10.0.0.1\x.allowed.com` is parsed by reqwest with authority `10.0.0.1`
    // (the `\` terminates the authority exactly as `/` would) and then CONNECTS to `10.0.0.1` /
    // `169.254.169.254`, even though a hand-parser that split only on `['/', '?', '#']` would see the
    // whole `10.0.0.1\x.allowed.com` as the host — an SSRF credential-relay bypass. Mirroring
    // reqwest's `\`→`/` rewrite here makes the guard see the SAME authority boundary the connecting
    // stack will, closing the bypass.
    let rest = rest.replace('\\', "/");
    // Authority is everything before the first path/query/fragment delimiter.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest.as_str());
    // Drop any "userinfo@" prefix.
    let host_port = authority.rsplit('@').next().unwrap_or(authority);

    // Separate host from port, handling bracketed IPv6 literals (`[::1]:443`).
    let host: &str = if let Some(after_bracket) = host_port.strip_prefix('[') {
        // `[<ipv6>]` optionally followed by `:port`.
        match after_bracket.split_once(']') {
            Some((inner, _)) => inner,
            None => after_bracket, // malformed; treat the remainder as the host
        }
    } else {
        // `host` or `host:port` — split on the last colon only when the left side has no colon
        // (a bare IPv6 without brackets would contain multiple colons; rsplit_once on a single
        // `:` host:port is the common case).
        match host_port.rsplit_once(':') {
            // If the left part still contains a colon it's a bare IPv6 literal; keep the whole.
            Some((left, _)) if !left.contains(':') => left,
            _ => host_port,
        }
    };

    if host.is_empty() {
        return None;
    }

    // Percent-decode the host BEFORE returning. The guard operates on the literal config string, but
    // the `url` crate reqwest uses percent-decodes host components per RFC 3986 at request time — so
    // a `base_url` like `https://169%2E254%2E169%2E254/` would pass every check (not a parseable
    // `IpAddr`, and the `%` defeats `is_alternate_ipv4_encoding`) yet resolve to the IMDS target
    // downstream. Decoding here makes the safety property independent of URL-library details.
    let host_decoded = percent_decode_host(host);

    // Normalize a single trailing FQDN-root dot. glibc getaddrinfo treats a trailing dot as a rooted
    // FQDN and still resolves the literal it precedes — so `169.254.169.254.` connects to exactly the
    // IMDS target the bare form does. Without stripping, an IP-literal+dot does NOT parse as
    // `IpAddr`, defeating every range check.
    let host = host_decoded
        .strip_suffix('.')
        .unwrap_or(host_decoded.as_str());

    Some(host.to_string())
}

/// True when `host` (already normalized by [`extract_normalized_host`]) is a private, loopback, or
/// link-local target — the legitimate LOCAL-MODEL destinations (Ollama / vLLM / LM Studio on
/// `localhost`, `127.0.0.1`, RFC-1918, or a Tailscale CGNAT address). Used to KEY THE SCHEME RULE:
/// plaintext `http://` is permitted to these (a local model rarely terminates TLS and there is no
/// off-box wiretap), while a PUBLIC host must use `https://` (cleartext would leak the API key on the
/// wire). This is NOT the SSRF decision — under the metadata-denylist model these hosts are ALLOWED
/// as upstreams; this predicate only governs whether plaintext is acceptable for the hop.
pub fn host_is_private_or_loopback(host: &str) -> bool {
    use std::net::IpAddr;

    let host_lc = host.to_ascii_lowercase();
    // `localhost` and the `*.localhost` TLD (RFC 6761) resolve to loopback.
    if host_lc == "localhost"
        || host_lc
            .rsplit_once('.')
            .is_some_and(|(_, tld)| tld == "localhost")
    {
        return true;
    }
    // Obfuscated IPv4 encodings that resolve to an internal address (decimal int, hex, octal, short
    // dotted) — treat as private so they at least don't get the public-host plaintext rejection on a
    // technicality. (They are an unusual way to spell a local model, but a connecting stack maps them
    // to an IPv4 target all the same.)
    if is_alternate_ipv4_encoding(host) {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_loopback()        // 127.0.0.0/8
                || v4.is_private()  // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local() // 169.254.0.0/16
                || v4.is_unspecified() // 0.0.0.0
                || is_cgnat_shared_v4(&v4) // 100.64.0.0/10 (RFC 6598 CGNAT, Tailscale)
        }
        Ok(IpAddr::V6(v6)) => {
            let embedded = v6.to_ipv4();
            v6.is_loopback()        // ::1
                || v6.is_unspecified() // ::
                || is_unique_local_v6(&v6) // fc00::/7
                || is_link_local_v6(&v6)   // fe80::/10
                || embedded.is_some_and(|m| {
                    m.is_loopback()
                        || m.is_private()
                        || m.is_link_local()
                        || m.is_unspecified()
                        || is_cgnat_shared_v4(&m)
                })
        }
        Err(_) => false,
    }
}

/// True when the already-normalized `host` (as produced by [`extract_normalized_host`]) matches any
/// entry in `entries`, using the EXACT canonicalization the denylist block check uses for operator-
/// supplied `blocked_metadata_hosts`. This is shared by the allow-override path so an allow entry
/// unblocks every spelling of an IP the same way a block entry blocks every spelling:
/// * a hostname entry matches case-insensitively, trailing dot stripped;
/// * an IP-literal entry matches the parsed connect-host AND its IPv4-mapped/compatible-IPv6 and
///   alternate-encoding (decimal-int / hex / octal / short-dotted) spellings.
///
/// Empty / whitespace-only entries never match.
fn host_matches_any(host: &str, entries: &[String]) -> bool {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    if entries.is_empty() {
        return false;
    }

    // Hostname / verbatim match (case-insensitive, trailing dot stripped on the entry).
    for entry in entries {
        let entry_norm = entry.trim().trim_end_matches('.');
        if !entry_norm.is_empty() && entry_norm.eq_ignore_ascii_case(host) {
            return true;
        }
    }

    // IP-literal entries: parse each once so an entry like `169.254.169.254` also matches this host's
    // mapped-IPv6 and alternate-encoding spellings, mirroring the block path's `extra_v4`/`extra_v6`.
    let entry_v4: Vec<Ipv4Addr> = entries
        .iter()
        .filter_map(|e| e.trim().trim_end_matches('.').parse::<Ipv4Addr>().ok())
        .collect();
    let entry_v6: Vec<Ipv6Addr> = entries
        .iter()
        .filter_map(|e| e.trim().trim_end_matches('.').parse::<Ipv6Addr>().ok())
        .collect();
    if entry_v4.is_empty() && entry_v6.is_empty() {
        return false;
    }

    // Alternate / obfuscated encodings of THIS host expand to a canonical v4 and re-check.
    if let Some(expanded) = expand_alternate_ipv4(host) {
        if entry_v4.contains(&expanded) {
            return true;
        }
    }

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => entry_v4.contains(&v4),
        Ok(IpAddr::V6(v6)) => {
            let embedded = v6.to_ipv4();
            entry_v6.contains(&v6) || embedded.is_some_and(|m| entry_v4.contains(&m))
        }
        Err(_) => false,
    }
}

/// Expand an alternate (non-dotted-quad) IPv4 encoding to its canonical [`std::net::Ipv4Addr`], the
/// way glibc getaddrinfo (reqwest's default resolver) would. Returns `None` for a canonical
/// dotted-quad (handled by `IpAddr::parse`), a DNS name, or an out-of-range value. Used by the SSRF
/// guard to re-check an obfuscated literal (e.g. decimal `2852039166` → `169.254.169.254`) against
/// the metadata denylist rather than blocking ALL obfuscated forms indiscriminately.
///
/// Handles: a whole-host `0x`/`0X` hex or bare decimal/octal integer (interpreted as a 32-bit
/// address); and the inet_aton "parts" forms — 1, 2, 3, or 4 dotted components where the LAST part
/// absorbs the remaining low bytes (`a` = 32-bit; `a.b` = a<<24 | b(24-bit); `a.b.c` = a<<24 |
/// b<<16 | c(16-bit); `a.b.c.d` = the usual quad). Each component may itself be decimal, `0x` hex, or
/// leading-zero octal.
pub fn expand_alternate_ipv4(host: &str) -> Option<std::net::Ipv4Addr> {
    if host.is_empty() {
        return None;
    }

    // Parse a single inet_aton component: `0x..`/`0X..` hex, leading-zero octal, or decimal.
    fn parse_component(p: &str) -> Option<u64> {
        if p.is_empty() {
            return None;
        }
        if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
            if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            u64::from_str_radix(hex, 16).ok()
        } else if p.len() > 1 && p.starts_with('0') {
            // Leading-zero octal (e.g. `0177`). All digits must be 0-7.
            if !p.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
                return None;
            }
            u64::from_str_radix(p, 8).ok()
        } else {
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse::<u64>().ok()
        }
    }

    let parts: Vec<&str> = host.split('.').collect();
    let vals: Vec<u64> = parts
        .iter()
        .map(|p| parse_component(p))
        .collect::<Option<Vec<u64>>>()?;

    // A canonical dotted-quad (4 parts, each a plain 0..=255 decimal with no hex/octal prefix) is
    // left to `IpAddr::parse`. A component is "alternate" if it is out of u8 range OR uses a hex/octal
    // prefix; the quad is canonical iff NO component is alternate.
    let is_alternate_octet = |p: &&str, v: &u64| {
        *v > 255
            || p.starts_with("0x")
            || p.starts_with("0X")
            || (p.len() > 1 && p.starts_with('0'))
    };
    let is_canonical_quad = parts.len() == 4
        && !parts
            .iter()
            .zip(&vals)
            .any(|(p, v)| is_alternate_octet(p, v));
    if is_canonical_quad {
        return None;
    }

    let addr: u32 = match vals.as_slice() {
        // `a` — the whole 32-bit address.
        [a] => u32::try_from(*a).ok()?,
        // `a.b` — a is the top octet, b the low 24 bits.
        [a, b] => {
            if *a > 0xff || *b > 0x00ff_ffff {
                return None;
            }
            ((*a as u32) << 24) | (*b as u32)
        }
        // `a.b.c` — a, b top two octets, c the low 16 bits.
        [a, b, c] => {
            if *a > 0xff || *b > 0xff || *c > 0x0000_ffff {
                return None;
            }
            ((*a as u32) << 24) | ((*b as u32) << 16) | (*c as u32)
        }
        // `a.b.c.d` — the usual quad (reached only for the alternate-encoding case, e.g. per-octet
        // hex/octal, since a canonical quad returned above).
        [a, b, c, d] => {
            if *a > 0xff || *b > 0xff || *c > 0xff || *d > 0xff {
                return None;
            }
            ((*a as u32) << 24) | ((*b as u32) << 16) | ((*c as u32) << 8) | (*d as u32)
        }
        _ => return None,
    };
    Some(std::net::Ipv4Addr::from(addr))
}

/// Return `Some(host)` if the given URL targets a CLOUD-METADATA endpoint that must be blocked, else
/// `None`. This is the SSRF guard under the metadata-denylist model.
///
/// Threat model: a client can NEVER influence a provider `base_url` — it picks a model NAME, which
/// maps through an operator pool to an operator-configured URL. So there is no client-driven SSRF.
/// The ONLY real risk is an operator typo / templated-config accidentally pointing a key-bearing lane
/// at a credential-leaking metadata service. Therefore: block a comprehensive metadata DENYLIST and
/// ALLOW EVERYTHING ELSE — loopback, RFC-1918, CGNAT, and public are all legitimate upstreams (local
/// Ollama/vLLM "just works" with no flag).
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
/// * `allow_overrides` is the UNION of the provider's `allow_metadata_hosts` and the global
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // Nuclear override: the metadata guard is disabled wholesale.
    if allow_all {
        return None;
    }

    let host = extract_normalized_host(url)?;
    let host = host.as_str();

    // Surgical allow-override: if THIS host matches any allow entry (with the same canonicalization
    // the block check uses), it is permitted regardless of the denylist. Computed up front so allow
    // unconditionally wins over every block arm below.
    if host_matches_any(host, allow_overrides) {
        return None;
    }

    // Cloud-metadata / IMDS hostnames (case-insensitive). The IPv4 / IPv6 metadata literals are
    // caught in the IP arms below; these are the DNS names a connecting stack would resolve.
    const METADATA_HOSTS: &[&str] = &[
        "metadata.google.internal",
        "metadata.internal",
        "metadata.tencentyun.com",
        "metadata.platformequinix.com",
        "instance-data",
        "instance-data.ec2.internal",
    ];
    let host_lc = host.to_ascii_lowercase();
    if METADATA_HOSTS.contains(&host_lc.as_str()) {
        return Some(host.to_string());
    }

    // Operator-supplied extensions to the denylist (`security.blocked_metadata_hosts`). Matched with
    // the SAME canonicalization the allow-override path uses (hostname case-insensitive; IP literal
    // matched against the parsed connect-host and its mapped-IPv6 / alternate-encoding spellings), so
    // an operator who writes `10.99.99.99` also blocks `[::ffff:10.99.99.99]` and the decimal-int
    // form. `host_matches_any` is the single shared canonicalizer for both allow and block.
    if host_matches_any(host, extra_blocked) {
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
            let embedded = v6.to_ipv4();
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
#[derive(Debug, Default, Clone)]
pub struct Denylist {
    /// Operator additions to the denylist: the answer to an unknown cloud's metadata address.
    pub blocked: Vec<String>,
    /// Surgical carve-outs. An IP entry unblocks every spelling of that address, the same way a
    /// block entry blocks every spelling of one.
    pub allowed: Vec<String>,
    /// The nuclear override. When set, the metadata guard is off wholesale.
    pub allow_all: bool,
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
///    declared path. The RE-CHECK is not belt and braces — the host a connecting stack reads is the
///    one it finds after WHATWG normalization, and a path fragment can move that boundary (a
///    backslash that terminates the authority early, a tab inside the literal, a percent-encoded
///    dot). A guard that only ever looked at the configured base read a different host than the
///    socket did.
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

    // The denylist, over the base and over every path it is joined with.
    for candidate in
        std::iter::once(authority.to_string()).chain(paths.iter().map(|p| join_path(authority, p)))
    {
        if let Some(host) = ssrf_blocked_host(
            &candidate,
            &denylist.allowed,
            denylist.allow_all,
            &denylist.blocked,
        ) {
            return Err(NetworkRefusal::MetadataDenied(host));
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
                NetworkRefusal::Guard(AddressRefusal::NoHost(authority.to_string()))
            })?;
            (true, host, port)
        }
        Err(other) => return Err(NetworkRefusal::Guard(other)),
    };

    resolve_and_pin(&host, port, https, resolver, policy)
        .map(Some)
        .map_err(NetworkRefusal::Guard)
}

/// Join a configured base with a declared path, the way a caller building a request would.
///
/// Deliberately naive about the slash and nothing else: what is being re-checked is where the HOST
/// boundary ends up, and a fragment that moves it does so whether or not the join was tidy.
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
