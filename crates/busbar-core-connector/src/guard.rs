// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DESTINATION GUARD (OWNER ruling DESTINATION GUARD, ARCHITECT RULING DEST-GUARD): the one
//! check every outbound connection asks, whatever dials it. It is the only code that decides
//! whether an address may be dialled.
//!
//! * [`Guard::judge_name`] runs BEFORE resolution: a cloud-metadata name, an alternate IPv4
//!   spelling, a `localhost` name and an IP literal (judged as its own answer) are decided here,
//!   at once, so a hostile name never reaches a resolver.
//! * [`Guard::judge_answer`] runs AFTER resolution, over EVERY address the name answered: one
//!   refused address refuses the whole answer (a mixed answer is a hostile answer: a rebinding
//!   resolver answers a public and an internal address together and lets the connect pick).
//!   The caller then dials exactly an address judged here (resolve, pin, dial the pin).
//!
//! Per address, in order: the allowlist (`advanced.allow_destinations`) admits; in the provider
//! class only, the 1.5.5 metadata carve-outs admit (below); then the extra refusals
//! (`security.blocked_metadata_hosts`); then cloud metadata is refused, whatever
//! `block_private_addresses` says; then, where `block_private_addresses` holds and the dial's class
//! refuses private addresses ([`PRIVATE_REFUSED_IN`]: the provider class, and a destination from
//! request data or the network), every private address (`busbar_contract::net::ip_is_internal`: RFC 1918, loopback, link-local, CGNAT,
//! unique-local, unspecified and the rest of that list).
//! A HOST allowlist entry never admits a metadata answer (owner Q8): it is how internal DNS is
//! admitted, and it must not become a way to reach IMDS by a rebinding answer. An IP or CIDR entry
//! that covers a metadata address does admit it, because it names it.
//!
//! THE 1.5.5 CARVE-OUTS (ARCHITECT ruling on #413, DEST-GUARD) speak for provider dials only, as
//! they did in 1.5.5, where they were read for a provider's own URLs and nowhere else: a provider's
//! `allow_metadata_hosts` admits only for a host that provider's own URLs name (`base_url`,
//! `token_url`), `security.allow_metadata_hosts` and `security.allow_all_metadata` for any provider
//! dial. No other class (the default class, open-web, loopback-allowed, operator infrastructure)
//! admits metadata through any carve-out; operator infrastructure refuses it whatever they say.
//! The carve-outs and the extra refusals are re-read at every config commit
//! ([`Guard::publish`]); the allowlist and `block_private_addresses` are fixed at boot.
//!
//! The ranges and names are `busbar_contract::net`'s, read only here.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, PoisonError, RwLock};

use busbar_contract::abi::host::conn::connector;
use busbar_contract::abi::host::service::{
    DEST_INTERNAL, DEST_METADATA, DEST_NO_ADDRESSES, DEST_OBFUSCATED,
};
use busbar_contract::net::{
    embedded_ipv4, host_ip, ip_is_cloud_metadata, ip_is_internal, is_alternate_ipv4_encoding,
    METADATA_HOSTS,
};
use busbar_kernel::config::Destinations;

/// THE DEFAULT POLICY, ONE TABLE: the egress classes whose dials the private address refusal holds
/// for (where `block_private_addresses` holds; the allowlist is the escape hatch).
///
/// - `provider` (THE DESIGN §5 destination guard, OWNER DESTINATION GUARD and Q130 (B), scoped by
///   the ARCHITECT ruling CRATES-14: "the 'refused unless allowlisted' default applies to the
///   provider and IdP egress classes only"): a provider dial, its configured `base_url` included, is
///   refused a private or loopback address unless `advanced.allow_destinations` names it.
/// - the default class and `open-web`: a destination from request data or the network.
///
/// Not here: `operator-infrastructure` (THE DESIGN §5 egress-class table, owner 2026-09-27:
/// private, loopback and plaintext allowed; pinned) and `loopback-allowed`. Cloud metadata is
/// refused in every class whatever this table says, a configured NAME rebinding to it included,
/// unless an IP/CIDR allowlist entry names it (or, for a provider dial only, a 1.5.5 carve-out).
pub const PRIVATE_REFUSED_IN: &[u32] = &[
    connector::EGRESS_DEFAULT,
    CARVE_OUT_CLASS,
    connector::EGRESS_OPEN_WEB,
];

/// The one class the 1.5.5 metadata carve-outs are read in ([`Metadata::lifts`]): the provider
/// class, as 1.5.5 read them for provider URLs only. The guard speaks in classes; this is the
/// class's one spelling here.
const CARVE_OUT_CLASS: u32 = connector::EGRESS_PROVIDER;

/// The classes a need whose config names its target is lifted out of, to operator infrastructure:
/// the request-data classes. Never `provider`: a provider dial is refused a private address unless
/// allowlisted whether or not its config names the target (ARCHITECT ruling CRATES-14).
const LIFTED_WHEN_CONFIGURED: &[u32] = &[connector::EGRESS_DEFAULT, connector::EGRESS_OPEN_WEB];

/// The class a dial's address is judged under: a need's own, or (its target named by its config,
/// `configured`, in a request-data class) the operator's own destination, judged as operator
/// infrastructure (THE DESIGN §5 egress-class table, owner-signed 2026-09-27). A provider need
/// keeps its class.
#[must_use]
pub fn judged_class(class: u32, configured: bool) -> u32 {
    let trusted = connector::EGRESS_OPERATOR_INFRASTRUCTURE;
    if configured && LIFTED_WHEN_CONFIGURED.contains(&class) {
        trusted
    } else {
        class
    }
}

/// The config key an allowlist refusal at boot names.
pub const ALLOW_KEY: &str = "advanced.allow_destinations";

/// Why the guard refused a destination: the `DEST_*` verdict, the target name, and the address
/// when an answered (or literal) address decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The `DEST_*` verdict (`busbar_contract::abi::host::service`).
    pub verdict: u64,
    /// The target name as judged.
    pub host: String,
    /// The address that decided it, when one did.
    pub addr: Option<IpAddr>,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let h = &self.host;
        match (self.verdict, self.addr) {
            (DEST_METADATA, Some(a)) => write!(
                f,
                "host `{h}` resolves to the cloud-metadata address {a}; that is refused \
                 unconditionally"
            ),
            (DEST_METADATA, None) => write!(
                f,
                "host `{h}` is a cloud-metadata name; that is refused unconditionally"
            ),
            (DEST_INTERNAL, Some(a)) => write!(
                f,
                "host `{h}` resolves to the internal address {a}; list it in {ALLOW_KEY} to \
                 allow it"
            ),
            (DEST_INTERNAL, None) => write!(
                f,
                "host `{h}` is a loopback name; list it in {ALLOW_KEY} to allow it"
            ),
            (DEST_OBFUSCATED, _) => write!(
                f,
                "host `{h}` is an alternate IPv4 encoding the resolver expands; write the address \
                 in dotted-quad form so it can be checked"
            ),
            _ => write!(
                f,
                "host `{h}` resolved to no addresses at all; there is nothing to connect to and \
                 nothing to have judged"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// One allowlist (or extra-refusal) entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    /// An exact host, lowercased, no trailing dot.
    Host(String),
    /// A `*.domain` wildcard, held as `.domain`: names under it, on a label boundary.
    Under(String),
    /// An IP network: the address and its prefix length (a bare IP is host-length).
    Net(IpAddr, u8),
}

impl Entry {
    fn names(&self, host: &str) -> bool {
        match self {
            Entry::Host(h) => h == host,
            Entry::Under(suffix) => host.ends_with(suffix.as_str()),
            Entry::Net(..) => false,
        }
    }

    fn covers(&self, addr: IpAddr) -> bool {
        let Entry::Net(net, len) = self else {
            return false;
        };
        // A v4 network covers the mapped, compatible and NAT64 spellings of its addresses too.
        match (*net, canonical(addr), addr) {
            (IpAddr::V4(n), IpAddr::V4(a), _) => prefix_eq(&n.octets(), &a.octets(), *len),
            (IpAddr::V6(n), _, IpAddr::V6(a)) => prefix_eq(&n.octets(), &a.octets(), *len),
            _ => false,
        }
    }
}

/// An IPv4-mapped, -compatible or NAT64 IPv6 address is its IPv4 address.
fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => embedded_ipv4(&v6).map_or(addr, IpAddr::V4),
        v4 => v4,
    }
}

fn prefix_eq(net: &[u8], addr: &[u8], len: u8) -> bool {
    let (whole, rest) = (usize::from(len / 8), len % 8);
    net[..whole] == addr[..whole]
        && (rest == 0 || (net[whole] ^ addr[whole]) & (0xff_u8 << (8 - rest)) == 0)
}

/// A target name as the guard compares it: unbracketed, lowercased, one trailing dot dropped.
fn norm(host: &str) -> String {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    h.strip_suffix('.').unwrap_or(h).to_ascii_lowercase()
}

/// The host length of an address's family.
fn full(ip: IpAddr) -> u8 {
    if ip.is_ipv4() {
        32
    } else {
        128
    }
}

/// A 1.5.5 list entry (`allow_metadata_hosts`, `blocked_metadata_hosts`), read as 1.5.5 read it:
/// an address in any literal spelling, else a name. Never refused (their 1.5.5 validation runs at
/// configuration time).
fn legacy(entry: &str) -> Option<Entry> {
    let e = norm(entry.trim());
    if e.is_empty() {
        return None;
    }
    Some(match host_ip(&e) {
        Some(ip) => Entry::Net(ip, full(ip)),
        None => Entry::Host(e),
    })
}

/// A name label the allowlist accepts: letters, digits, `-` and `_`, never empty.
fn is_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|l| {
            !l.is_empty()
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        && !is_alternate_ipv4_encoding(n)
}

/// One `advanced.allow_destinations` entry, or the boot refusal naming it.
fn strict(i: usize, entry: &str) -> Result<Entry, String> {
    let shown = match entry.rfind('@') {
        Some(at) => format!("<redacted>@{}", &entry[at + 1..]),
        None => entry.to_owned(),
    };
    let bad = || {
        format!("{ALLOW_KEY}[{i}]: `{shown}` is not a host, a `*.domain` wildcard, an IP or a CIDR")
    };
    let e = norm(entry.trim());
    let e = e.as_str();
    if let Some((ip, len)) = e.split_once('/') {
        let ip: IpAddr = ip.trim_end_matches(']').parse().map_err(|_| bad())?;
        let len: u8 = len.parse().map_err(|_| bad())?;
        if len > full(ip) {
            return Err(bad());
        }
        if masked(ip, len) != ip {
            return Err(format!(
                "{ALLOW_KEY}[{i}]: `{shown}` sets address bits past its prefix length; write the \
                 network address"
            ));
        }
        return Ok(Entry::Net(ip, len));
    }
    if let Ok(ip) = e.parse::<IpAddr>() {
        return Ok(Entry::Net(ip, full(ip)));
    }
    match e.strip_prefix("*.") {
        Some(domain) if is_name(domain) => Ok(Entry::Under(format!(".{domain}"))),
        None if is_name(e) => Ok(Entry::Host(e.to_owned())),
        _ => Err(bad()),
    }
}

/// `ip` with every bit past `len` cleared.
fn masked(ip: IpAddr, len: u8) -> IpAddr {
    fn clear<const N: usize>(mut o: [u8; N], len: u8) -> [u8; N] {
        for (i, b) in o.iter_mut().enumerate() {
            let keep = len
                .saturating_sub(u8::try_from(i * 8).unwrap_or(u8::MAX))
                .min(8);
            *b &= if keep == 0 { 0 } else { 0xff_u8 << (8 - keep) };
        }
        o
    }
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(clear(v4.octets(), len))),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(clear(v6.octets(), len))),
    }
}

/// The 1.5.5 metadata lists one config commit states: the carve-outs (read in the provider class
/// only) and the extra refusals.
#[derive(Debug, Default)]
struct Metadata {
    /// `security.allow_all_metadata`: every metadata address and extra refusal lifted, for a
    /// provider dial.
    allow_all: bool,
    /// `security.allow_metadata_hosts`: carve-outs for every dial in the carve-out class.
    everywhere: Vec<Entry>,
    /// Each provider's own `allow_metadata_hosts`, keyed by the host its URLs name (the union,
    /// where two providers name one host).
    by_host: HashMap<String, Vec<Entry>>,
    /// `security.blocked_metadata_hosts`.
    blocked: Vec<Entry>,
}

impl Metadata {
    fn from_config(d: &Destinations) -> Metadata {
        let mut by_host: HashMap<String, Vec<Entry>> = HashMap::new();
        for (url, own) in &d.url_allow {
            // The one http(s) URL reader; a URL it cannot read names no host, so carves nothing.
            if let Ok((_, host, _, _)) = busbar_kernel::net_guard::split_url(url) {
                by_host
                    .entry(norm(&host))
                    .or_default()
                    .extend(own.iter().filter_map(|e| legacy(e)));
            }
        }
        Metadata {
            allow_all: d.allow_all_metadata,
            everywhere: d.legacy_allow.iter().filter_map(|e| legacy(e)).collect(),
            by_host,
            blocked: d.blocked.iter().filter_map(|e| legacy(e)).collect(),
        }
    }

    /// Whether a carve-out lifts the refusal of `name` (normalized) answering `addr` (`None`: the
    /// name itself) under `class`: in the provider class only, `allow_all`, or an entry of the
    /// everywhere list or of the providers that name `name` that names the host or the
    /// address.
    fn lifts(&self, name: &str, addr: Option<IpAddr>, class: u32) -> bool {
        if class != CARVE_OUT_CLASS {
            return false;
        }
        let own = self.by_host.get(name).map_or(&[][..], Vec::as_slice);
        self.allow_all
            || self
                .everywhere
                .iter()
                .chain(own)
                .any(|e| e.names(name) || addr.is_some_and(|a| e.covers(a)))
    }
}

/// THE GUARD, built at boot from a deployment's [`Destinations`]; its metadata lists are
/// re-published at every config commit ([`Guard::publish`]), and every clone reads the lists in
/// force now.
#[derive(Debug, Clone)]
pub struct Guard {
    block_private: bool,
    /// `advanced.allow_destinations`.
    allow: Vec<Entry>,
    /// The 1.5.5 metadata lists in force, replaced whole at a commit.
    metadata: Arc<RwLock<Arc<Metadata>>>,
}

impl Default for Guard {
    /// The strict guard: private addresses refused, nothing allowed.
    fn default() -> Self {
        Guard {
            block_private: true,
            allow: Vec::new(),
            metadata: Arc::default(),
        }
    }
}

impl Guard {
    /// The guard a deployment states.
    ///
    /// # Errors
    ///
    /// An `advanced.allow_destinations` entry that is none of host, `*.domain`, IP or CIDR (or a
    /// CIDR with bits past its prefix), named by its index.
    pub fn from_config(d: &Destinations) -> Result<Guard, String> {
        Ok(Guard {
            block_private: d.block_private_addresses,
            allow: d
                .allow
                .iter()
                .enumerate()
                .map(|(i, e)| strict(i, e))
                .collect::<Result<_, _>>()?,
            metadata: Arc::new(RwLock::new(Arc::new(Metadata::from_config(d)))),
        })
    }

    /// A config commit: the metadata lists `d` states (the carve-outs and the extra refusals)
    /// replace the ones in force, for every clone of this guard and every judgement after it, as
    /// 1.5.5 re-read them at every reload. The allowlist and `block_private_addresses` are boot's.
    pub fn publish(&self, d: &Destinations) {
        let lists = Arc::new(Metadata::from_config(d));
        *self
            .metadata
            .write()
            .unwrap_or_else(PoisonError::into_inner) = lists;
    }

    /// The metadata lists in force now.
    fn metadata(&self) -> Arc<Metadata> {
        Arc::clone(&self.metadata.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Whether a private address is refused: where `block_private_addresses` holds and the class
    /// is one [`PRIVATE_REFUSED_IN`] names, or wherever the caller's own configuration refuses
    /// private reach (`strict`, `DEST_REFUSE_PRIVATE`), whatever the deployment says.
    fn refuses_private(&self, class: u32, strict: bool) -> bool {
        strict || (self.block_private && PRIVATE_REFUSED_IN.contains(&class))
    }

    /// The name arm, before any resolution, under egress class `class`. `Ok(Some(ip))`: the host
    /// is an IP literal, judged as its own answer; `Ok(None)`: a name to resolve and then judge
    /// with [`Guard::judge_answer`].
    ///
    /// # Errors
    ///
    /// The [`Refusal`] the name (or the literal) decides.
    pub fn judge_name(&self, host: &str, class: u32) -> Result<Option<IpAddr>, Refusal> {
        self.judge_name_as(host, class, false)
    }

    /// [`Guard::judge_name`], private reach refused whatever the deployment says when `strict`.
    ///
    /// # Errors
    ///
    /// The [`Refusal`] the name (or the literal) decides.
    pub fn judge_name_as(
        &self,
        host: &str,
        class: u32,
        strict: bool,
    ) -> Result<Option<IpAddr>, Refusal> {
        let name = norm(host);
        let refuse = |verdict| {
            Err(Refusal {
                verdict,
                host: host.to_owned(),
                addr: None,
            })
        };
        let m = self.metadata();
        let allowed = self.allow.iter().any(|e| e.names(&name));
        let lifted = allowed || m.lifts(&name, None, class);
        if METADATA_HOSTS.iter().any(|h| name == *h) && !lifted {
            return refuse(DEST_METADATA);
        }
        if m.blocked.iter().any(|e| e.names(&name)) && !lifted {
            return refuse(DEST_METADATA);
        }
        if is_alternate_ipv4_encoding(&name) {
            return refuse(DEST_OBFUSCATED);
        }
        if let Some(ip) = host_ip(&name) {
            self.judge_address(host, ip, class, strict)?;
            return Ok(Some(ip));
        }
        // The `localhost` family RFC 6761 reserves to loopback (the metadata names were decided
        // above).
        let loopback_name = name == "localhost" || name.ends_with(".localhost");
        if loopback_name && self.refuses_private(class, strict) && !allowed {
            return refuse(DEST_INTERNAL);
        }
        Ok(None)
    }

    /// The answer arm, after resolution: EVERY address `host` answered with is judged, and one
    /// refused address refuses the whole answer.
    ///
    /// # Errors
    ///
    /// No address answered ([`DEST_NO_ADDRESSES`]), or the first refused address's [`Refusal`].
    pub fn judge_answer(&self, host: &str, addrs: &[IpAddr], class: u32) -> Result<(), Refusal> {
        self.judge_answer_as(host, addrs, class, false)
    }

    /// [`Guard::judge_answer`], private reach refused whatever the deployment says when `strict`.
    ///
    /// # Errors
    ///
    /// No address answered ([`DEST_NO_ADDRESSES`]), or the first refused address's [`Refusal`].
    pub fn judge_answer_as(
        &self,
        host: &str,
        addrs: &[IpAddr],
        class: u32,
        strict: bool,
    ) -> Result<(), Refusal> {
        if addrs.is_empty() {
            return Err(Refusal {
                verdict: DEST_NO_ADDRESSES,
                host: host.to_owned(),
                addr: None,
            });
        }
        addrs
            .iter()
            .try_for_each(|a| self.judge_address(host, *a, class, strict))
    }

    /// One address `host` stands for, in the order the module header states.
    fn judge_address(
        &self,
        host: &str,
        addr: IpAddr,
        class: u32,
        strict: bool,
    ) -> Result<(), Refusal> {
        let name = norm(host);
        let m = self.metadata();
        let metadata = ip_is_cloud_metadata(&addr);
        let listed = |l: &[Entry]| l.iter().any(|e| e.covers(addr));
        let named = |l: &[Entry]| l.iter().any(|e| e.names(&name));
        // The 1.5.5 carve-outs, a provider dial's only (`Metadata::lifts`): a NAME there admits
        // its metadata answer, as 1.5.5's did; `allow_all_metadata` admits every metadata address
        // and every extra blocked one.
        let admitted = listed(&self.allow)
            || m.lifts(&name, Some(addr), class)
            || (!metadata && named(&self.allow));
        if admitted {
            return Ok(());
        }
        let refuse = |verdict| {
            Err(Refusal {
                verdict,
                host: host.to_owned(),
                addr: Some(addr),
            })
        };
        if metadata || listed(&m.blocked) {
            return refuse(DEST_METADATA);
        }
        if self.refuses_private(class, strict) && ip_is_internal(&addr) {
            return refuse(DEST_INTERNAL);
        }
        Ok(())
    }
}

/// Where one resolution's answer goes: called once, from any thread. `Err` is a resolution
/// failure, not an empty answer.
pub type Resolved = Box<dyn FnOnce(Result<Vec<IpAddr>, String>) + Send>;

/// A resolver that answers off the caller's thread: the guard's one resolution of a name.
pub trait Resolve: Send + Sync {
    /// Resolve `host`, answering through `done` now or later, on any thread; never blocks.
    fn resolve(&self, host: &str, done: Resolved);
}

/// The system resolver, one short-lived thread per resolution, so a slow name never holds a
/// worker.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str, done: Resolved) {
        use std::net::ToSocketAddrs;
        use std::sync::{Arc, Mutex};
        let cell = Arc::new(Mutex::new(Some(done)));
        let mine = Arc::clone(&cell);
        let take = |c: &Mutex<Option<Resolved>>| c.lock().unwrap_or_else(|e| e.into_inner()).take();
        let host = host.to_owned();
        let spawned = std::thread::Builder::new()
            .name("busbar-resolve".into())
            .spawn(move || {
                let answer = (host.as_str(), 0)
                    .to_socket_addrs()
                    .map(|a| a.map(|s| s.ip()).collect())
                    .map_err(|e| e.to_string());
                if let Some(done) = take(&mine) {
                    done(answer);
                }
            });
        if spawned.is_err() {
            if let Some(done) = take(&cell) {
                done(Err("no resolver thread".into()));
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/guard_tests.rs"]
mod tests;
