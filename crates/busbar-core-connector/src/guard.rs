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
//! Per address, in order: the allowlist (`advanced.allow_destinations`, and the 1.5.5 carve-outs
//! that still load) admits; then the extra refusals (`security.blocked_metadata_hosts`); then cloud
//! metadata is refused, whatever `block_private_addresses` says; then, where
//! `block_private_addresses` holds and the destination came from request data or the network
//! ([`PRIVATE_REFUSED_IN`]; a destination the operator configured is trusted, owner Q7), every
//! private address (`busbar_contract::net::ip_is_internal`: RFC 1918, loopback, link-local, CGNAT,
//! unique-local, unspecified and the rest of that list).
//! A HOST allowlist entry never admits a metadata answer (owner Q8): it is how internal DNS is
//! admitted, and it must not become a way to reach IMDS by a rebinding answer. An IP or CIDR entry
//! that covers a metadata address does admit it, because it names it.
//!
//! The ranges and names are `busbar_contract::net`'s, read only here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use busbar_contract::abi::host::conn::connector;
use busbar_contract::abi::host::service::{
    DEST_INTERNAL, DEST_METADATA, DEST_NO_ADDRESSES, DEST_OBFUSCATED,
};
use busbar_contract::net::{
    embedded_ipv4, host_ip, ip_is_cloud_metadata, ip_is_internal, is_alternate_ipv4_encoding,
    METADATA_HOSTS,
};
use busbar_kernel::config::Destinations;

/// THE DEFAULT POLICY, ONE TABLE (OWNER ruling Q7, 2026-10-02: operator infrastructure EXEMPT):
/// the egress classes whose dials the private address refusal holds for. A destination the
/// operator writes into config is trusted (every configured URL and plugin connection: the
/// `provider` and `operator-infrastructure` classes, a
/// `loopback-allowed` need, and any need whose target its config names, see
/// [`crate::Connector`]); the refusal holds for destinations that come from request data or the
/// network (a caller- or plane-named target: the default class, `open-web`). Cloud metadata is
/// refused in every class whatever this table says, a configured NAME rebinding to it included,
/// unless an IP/CIDR allowlist entry names it.
pub const PRIVATE_REFUSED_IN: &[u32] = &[connector::EGRESS_DEFAULT, connector::EGRESS_OPEN_WEB];

/// The class a dial's address is judged under: a need's own, or (its target named by its config,
/// `configured`) the operator's own destination, trusted as operator infrastructure (OWNER Q7).
#[must_use]
pub fn judged_class(class: u32, configured: bool) -> u32 {
    let trusted = connector::EGRESS_OPERATOR_INFRASTRUCTURE;
    if configured && PRIVATE_REFUSED_IN.contains(&class) {
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

/// THE GUARD, built once from a deployment's [`Destinations`].
#[derive(Debug, Clone)]
pub struct Guard {
    block_private: bool,
    allow_all_metadata: bool,
    /// `advanced.allow_destinations`.
    allow: Vec<Entry>,
    /// The 1.5.5 carve-outs: a NAME here admits its metadata answer, as 1.5.5's did.
    legacy: Vec<Entry>,
    /// `security.blocked_metadata_hosts`.
    blocked: Vec<Entry>,
}

impl Default for Guard {
    /// The strict guard: private addresses refused, nothing allowed.
    fn default() -> Self {
        Guard {
            block_private: true,
            allow_all_metadata: false,
            allow: Vec::new(),
            legacy: Vec::new(),
            blocked: Vec::new(),
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
            allow_all_metadata: d.allow_all_metadata,
            allow: d
                .allow
                .iter()
                .enumerate()
                .map(|(i, e)| strict(i, e))
                .collect::<Result<_, _>>()?,
            legacy: d.legacy_allow.iter().filter_map(|e| legacy(e)).collect(),
            blocked: d.blocked.iter().filter_map(|e| legacy(e)).collect(),
        })
    }

    fn refuses_private(&self, class: u32) -> bool {
        self.block_private && PRIVATE_REFUSED_IN.contains(&class)
    }

    /// The name arm, before any resolution, under egress class `class`. `Ok(Some(ip))`: the host
    /// is an IP literal, judged as its own answer; `Ok(None)`: a name to resolve and then judge
    /// with [`Guard::judge_answer`].
    ///
    /// # Errors
    ///
    /// The [`Refusal`] the name (or the literal) decides.
    pub fn judge_name(&self, host: &str, class: u32) -> Result<Option<IpAddr>, Refusal> {
        let name = norm(host);
        let refuse = |verdict| {
            Err(Refusal {
                verdict,
                host: host.to_owned(),
                addr: None,
            })
        };
        let allowed = self.allow.iter().any(|e| e.names(&name));
        let carved = self.legacy.iter().any(|e| e.names(&name));
        if METADATA_HOSTS.iter().any(|m| name == *m)
            && !(self.allow_all_metadata || allowed || carved)
        {
            return refuse(DEST_METADATA);
        }
        if self.blocked.iter().any(|e| e.names(&name))
            && !(self.allow_all_metadata || allowed || carved)
        {
            return refuse(DEST_METADATA);
        }
        if is_alternate_ipv4_encoding(&name) {
            return refuse(DEST_OBFUSCATED);
        }
        if let Some(ip) = host_ip(&name) {
            self.judge_address(host, ip, class)?;
            return Ok(Some(ip));
        }
        // The `localhost` family RFC 6761 reserves to loopback (the metadata names were decided
        // above).
        let loopback_name = name == "localhost" || name.ends_with(".localhost");
        if loopback_name && self.refuses_private(class) && !(allowed || carved) {
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
        if addrs.is_empty() {
            return Err(Refusal {
                verdict: DEST_NO_ADDRESSES,
                host: host.to_owned(),
                addr: None,
            });
        }
        addrs
            .iter()
            .try_for_each(|a| self.judge_address(host, *a, class))
    }

    /// One address `host` stands for, in the order the module header states.
    fn judge_address(&self, host: &str, addr: IpAddr, class: u32) -> Result<(), Refusal> {
        let name = norm(host);
        let metadata = ip_is_cloud_metadata(&addr);
        let listed = |l: &[Entry]| l.iter().any(|e| e.covers(addr));
        let named = |l: &[Entry]| l.iter().any(|e| e.names(&name));
        // `allow_all_metadata` is 1.5.5's nuclear override: every metadata address and every
        // extra blocked one admitted.
        let admitted = listed(&self.allow)
            || listed(&self.legacy)
            || ((metadata || listed(&self.blocked)) && self.allow_all_metadata)
            || (metadata && named(&self.legacy))
            || (!metadata && (named(&self.allow) || named(&self.legacy)));
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
        if metadata || listed(&self.blocked) {
            return refuse(DEST_METADATA);
        }
        if self.refuses_private(class) && ip_is_internal(&addr) {
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
