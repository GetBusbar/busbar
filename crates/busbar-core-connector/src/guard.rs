// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DESTINATION GUARD: the one check every outbound connection asks, whatever dials it. It is

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, PoisonError, RwLock};

use arc_swap::ArcSwap;

use busbar_contract::abi::host::conn::connector;
use busbar_contract::abi::host::service::{
    DEST_INTERNAL, DEST_METADATA, DEST_NO_ADDRESSES, DEST_NO_HOST, DEST_OBFUSCATED,
};
use busbar_contract::net::{
    embedded_ipv4, host_ip, ip_is_cloud_metadata, ip_is_internal, is_alternate_ipv4_encoding,
    is_link_local_v6, judged_host, IpNet, METADATA_HOSTS,
};
use busbar_kernel::config::Destinations;
use foldhash::HashSet;

#[cfg(test)]
use crate::off_path::egress::guard::entry;

/// THE DEFAULT POLICY, ONE TABLE: the egress classes whose dials the private address refusal holds
pub const PRIVATE_REFUSED_IN: &[u32] = &[
    connector::EGRESS_DEFAULT,
    connector::EGRESS_PROVIDER,
    connector::EGRESS_OPEN_WEB,
];

/// The loopback-allowed class: private addresses refused but loopback, and an alternate IPv4
const LOOPBACK_CLASS: u32 = connector::EGRESS_LOOPBACK_ALLOWED;

/// LOOPBACK AS 1.5.5'S COLLECTOR GUARD READ IT (v1.5.5 `crates/busbar/src/observability.rs:620-633`
#[must_use]
pub fn is_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4().is_some_and(|v4| v4.is_loopback()),
    }
}

/// A HOST WRITTEN AS LOOPBACK, as 1.5.5's collector and webrequest guards read the URL's host for
#[must_use]
pub fn names_loopback(host: &str) -> bool {
    let Some(name) = norm(host) else {
        return false;
    };
    match host_ip(&name) {
        Some(ip) => is_loopback(ip),
        None => name == "localhost" || name.ends_with(".localhost"),
    }
}

/// The classes a need whose config names its target is lifted out of, to operator infrastructure:
const LIFTED_WHEN_CONFIGURED: &[u32] = &[connector::EGRESS_DEFAULT];

/// The class a dial's address is judged under: a need's own, or (its target named by its config,
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
pub(crate) const ALLOW_KEY: &str = "advanced.allow_destinations";

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
            (DEST_NO_HOST, _) => write!(
                f,
                "host `{h}` cannot be judged: it maps to no name or address a URL client would \
                 dial (UTS #46 refuses it, it holds a `%` escape outside an IPv6 zone id, or it \
                 ends in a number the guard does not read as the IPv4 address a URL client \
                 dials), so it is refused"
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
pub(crate) enum Entry {
    /// An exact host, lowercased, no trailing dot.
    Host(String),
    /// A `*.domain` wildcard, held as `.domain`: names under it, on a label boundary.
    Under(String),
    /// An IP network (a bare IP is host-length): the shared [`IpNet`] reader and matcher.
    Net(IpNet),
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
        let Entry::Net(net) = self else {
            return false;
        };
        net.covers(addr)
    }
}

/// THE ALLOWLIST, INDEXED once per config commit: an exact host and a `*.domain` suffix are looked
/// up by key (one lookup per label of the judged name, never a sweep of the list); a network is
/// held as its entry.
#[derive(Debug, Clone, Default)]
pub(crate) struct Allow {
    /// Exact hosts, lowercased, no trailing dot.
    pub(crate) hosts: HashSet<String>,
    /// `*.domain` wildcards, each held as `.domain`.
    pub(crate) under: HashSet<String>,
    /// IP networks ([`Entry::Net`]).
    pub(crate) nets: Vec<Entry>,
}

impl Allow {
    /// Whether an entry names `host`: an exact host, or a wildcard on one of its label boundaries.
    fn names(&self, host: &str) -> bool {
        self.hosts.contains(host)
            || host
                .match_indices('.')
                .any(|(at, _)| self.under.contains(&host[at..]))
    }
}

/// An IPv4-mapped, -compatible or NAT64 IPv6 address is its IPv4 address. The IPv6 loopback `::1`
/// is itself, not the IPv4-compatible `0.0.0.1` it would read as.
pub(crate) fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) if v6.is_loopback() => addr,
        IpAddr::V6(v6) => embedded_ipv4(&v6).map_or(addr, IpAddr::V4),
        v4 => v4,
    }
}

/// THE ONE MAPPING every name the guard compares goes through, a target's and a configured
pub(crate) fn norm(host: &str) -> Option<String> {
    judged_host(host).ok()
}

/// The 1.5.5 metadata lists one config commit states: the carve-outs (read in the provider class
/// only) and the extra refusals.
#[derive(Debug, Default)]
pub(crate) struct Metadata {
    /// `security.blocked_metadata_hosts`.
    pub(crate) blocked: Vec<Entry>,
}

/// THE GUARD, built at boot from a deployment's [`Destinations`]; its metadata lists are
/// re-published at every config commit ([`Guard::publish`]), and every clone reads the lists in
/// force now.
#[derive(Debug, Clone)]
pub struct Guard {
    block_private: bool,
    /// `advanced.allow_destinations`.
    allow: Allow,
    /// The 1.5.5 metadata lists in force, replaced whole at a commit.
    metadata: Arc<RwLock<Arc<Metadata>>>,
    /// The node's own listen ports and bound addresses, replaced whole when the boot metadata is
    /// finalised ([`Guard::publish_own`]); every clone reads the set in force now.
    node: Arc<ArcSwap<OwnNode>>,
}

/// The node's own front door: every configured listener's port (`listen`, `admin_listen`, each
/// listener and media listener) and the addresses those listeners are bound to.
#[derive(Debug, Default)]
pub(crate) struct OwnNode {
    pub(crate) ports: Vec<u16>,
    pub(crate) ips: foldhash::HashSet<IpAddr>,
}

impl Default for Guard {
    /// The strict guard: private addresses refused, nothing allowed.
    fn default() -> Self {
        Guard {
            block_private: true,
            allow: Allow::default(),
            metadata: Arc::default(),
            node: Arc::default(),
        }
    }
}

impl Guard {
    /// The guard a deployment states.
    pub fn from_config(d: &Destinations) -> Result<Guard, String> {
        Ok(Guard {
            block_private: d.block_private_addresses,
            allow: crate::off_path::egress::guard::allow_list(d)?,
            metadata: Arc::new(RwLock::new(Arc::new(Metadata::from_config(d)))),
            node: Arc::default(),
        })
    }

    /// Publish the node's own listen ports and the addresses its listeners are bound to (boot
    /// metadata, IF 12.1): what [`Guard::not_the_node`] refuses. Replaces the set whole.
    pub fn publish_own(&self, ports: &[u16], bound: &[IpAddr]) {
        self.node
            .store(Arc::new(crate::off_path::egress::guard::own_node(
                ports, bound,
            )));
    }

    /// The node's own ports (IF 12.1): `addr` is refused `DEST_INTERNAL` when its port is one of
    /// the node's own listen ports and its IP is loopback, unspecified, or one the listeners are
    /// bound to, so no dial reaches a plane route, the admin API or another plugin's listener
    /// through core's front door. A Need dial passes `all_classes = true` (every class); core's own
    /// upstream exchanges and push deliveries pass `false` and keep today's scope, the
    /// loopback-allowed class only. The refusal names no route.
    pub fn not_the_node(
        &self,
        class: u32,
        addr: SocketAddr,
        all_classes: bool,
    ) -> Result<(), Refusal> {
        if !all_classes && class != LOOPBACK_CLASS {
            return Ok(());
        }
        let node = self.node.load();
        let ip = canonical(addr.ip());
        let own_front_door = node.ports.contains(&addr.port())
            && (is_loopback(ip) || ip.is_unspecified() || node.ips.contains(&ip));
        if own_front_door {
            return Err(crate::cold::egress::own_door_refusal(DEST_INTERNAL, addr));
        }
        Ok(())
    }

    /// A config commit: the metadata lists `d` states (the carve-outs and the extra refusals)
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
    fn refuses_private(&self, class: u32, strict: bool) -> bool {
        strict || (self.block_private && PRIVATE_REFUSED_IN.contains(&class))
    }

    /// Whether private address `addr` is refused in the loopback-allowed class: where
    fn refuses_off_loopback(&self, class: u32, addr: IpAddr) -> bool {
        self.block_private && class == LOOPBACK_CLASS && !is_loopback(addr)
    }

    /// The name arm, before any resolution, under egress class `class`. `Ok(Some(ip))`: the host
    pub fn judge_name(&self, host: &str, class: u32) -> Result<Option<IpAddr>, Refusal> {
        self.judge_name_as(host, class, false)
    }

    /// [`Guard::judge_name`], private reach refused whatever the deployment says when `strict`.
    pub fn judge_name_as(
        &self,
        host: &str,
        class: u32,
        strict: bool,
    ) -> Result<Option<IpAddr>, Refusal> {
        self.judge_name_with(host, class, strict, false)
    }

    /// [`Guard::judge_name_as`] for a destination its need holds a PRIVATE REACH to (`reach`, the
    pub fn judge_name_with(
        &self,
        host: &str,
        class: u32,
        strict: bool,
        reach: bool,
    ) -> Result<Option<IpAddr>, Refusal> {
        let refuse = |verdict| Err(crate::cold::egress::refusal(verdict, host, None));

        let Some(name) = norm(host) else {
            return refuse(DEST_NO_HOST);
        };
        let m = self.metadata();
        let allowed = self.allow.names(&name);
        if METADATA_HOSTS.iter().any(|h| name == *h) || m.blocked.iter().any(|e| e.names(&name)) {
            return refuse(DEST_METADATA);
        }

        if is_alternate_ipv4_encoding(&name)
            && !(class == LOOPBACK_CLASS && host_ip(&name).is_some())
        {
            return refuse(DEST_OBFUSCATED);
        }
        if let Some(ip) = host_ip(&name) {
            self.judge_address(host, ip, class, strict, reach)?;
            return Ok(Some(ip));
        }

        let loopback_name = name == "localhost" || name.ends_with(".localhost");
        if loopback_name && self.refuses_private(class, strict) && !allowed && !reach {
            return refuse(DEST_INTERNAL);
        }
        Ok(None)
    }

    /// The answer arm, after resolution: EVERY address `host` answered with is judged, and one
    pub fn judge_answer(&self, host: &str, addrs: &[IpAddr], class: u32) -> Result<(), Refusal> {
        self.judge_answer_with(host, addrs, class, false, false)
    }

    /// [`Guard::judge_answer`] for a destination its need holds a private reach to
    pub fn judge_answer_with(
        &self,
        host: &str,
        addrs: &[IpAddr],
        class: u32,
        strict: bool,
        reach: bool,
    ) -> Result<(), Refusal> {
        if addrs.is_empty() {
            return Err(crate::cold::egress::refusal(DEST_NO_ADDRESSES, host, None));
        }
        addrs
            .iter()
            .try_for_each(|a| self.judge_address(host, *a, class, strict, reach))
    }

    /// One address `host` stands for, in the order the module header states.
    fn judge_address(
        &self,
        host: &str,
        addr: IpAddr,
        class: u32,
        strict: bool,
        reach: bool,
    ) -> Result<(), Refusal> {
        let Some(name) = norm(host) else {
            return Err(crate::cold::egress::refusal(DEST_NO_HOST, host, Some(addr)));
        };
        let m = self.metadata();
        let metadata = ip_is_cloud_metadata(&addr);

        let link_local = matches!(canonical(addr), IpAddr::V6(v6) if is_link_local_v6(&v6));
        let listed = |l: &[Entry]| l.iter().any(|e| e.covers(addr));

        let denied = metadata || listed(&m.blocked);
        let allowlisted = !denied && !link_local && listed(&self.allow.nets);
        let admitted =
            allowlisted || (!denied && !link_local && (self.allow.names(&name) || reach));
        if admitted {
            return Ok(());
        }
        let refuse = |verdict| Err(crate::cold::egress::refusal(verdict, host, Some(addr)));
        if denied || link_local {
            return refuse(DEST_METADATA);
        }
        let refused = self.refuses_private(class, strict) || self.refuses_off_loopback(class, addr);
        if refused && ip_is_internal(&addr) {
            return refuse(DEST_INTERNAL);
        }
        Ok(())
    }
}

/// Where one resolution's answer goes: called once, from any thread. `Err` is a resolution
pub type Resolved = Box<dyn FnOnce(Result<Vec<IpAddr>, String>) + Send>;

/// A resolver that answers off the caller's thread: the guard's one resolution of a name.
pub trait Resolve: Send + Sync {
    /// Resolve `host`, answering through `done` now or later, on any thread; never blocks.
    fn resolve(&self, host: &str, done: Resolved);
}

/// The system resolver, one short-lived thread per resolution, so a slow name never holds a
/// worker. Its threads are CAPPED: at most [`crate::compose::MAX_PENDING_LOOKUPS`] resolutions are
/// in flight at once, and one more is answered at once as a resolution failure, no thread started.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str, done: Resolved) {
        resolve_capped(
            host,
            done,
            crate::compose::MAX_PENDING_LOOKUPS,
            &RESOLVING,
            crate::off_path::guard::system_lookup,
        );
    }
}

/// The resolutions [`SystemResolver`] has in flight.
static RESOLVING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(crate) use crate::off_path::guard::resolve_capped;

#[cfg(test)]
#[path = "tests/guard_tests.rs"]
mod tests;
