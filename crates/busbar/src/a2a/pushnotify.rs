// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PUSH-NOTIFICATION CALLBACKS, and the SSRF guard that makes accepting one safe.
//!
//! A2A lets a client hand busbar a webhook URL to call when a long-running task finishes. That is a
//! caller-supplied URL that busbar's own process will fetch, which is the textbook server-side
//! request forgery primitive: the caller borrows busbar's network position to reach things it cannot
//! reach itself — the cloud metadata service, a private VPC address, a link-local address, a service
//! bound to loopback inside the container.
//!
//! ## RESOLVE-THEN-PIN, and why a plain hostname check is not enough
//!
//! Checking the hostname and then handing the URL to an HTTP client that resolves it AGAIN is a
//! time-of-check/time-of-use hole with a name: DNS rebinding. The attacker's nameserver answers
//! `93.184.216.34` for the check and `169.254.169.254` a moment later for the connect, with a TTL of
//! zero, and the guard was never wrong — it was just answering about a different address than the one
//! the socket used.
//!
//! So validation takes the RESOLVED ADDRESSES as an argument and returns them PINNED. The connect
//! then uses the pinned addresses and never resolves again. This module is therefore PURE: no DNS,
//! no sockets, no globals. That is what lets every hostile case below be a unit test rather than a
//! network fixture, and it is what makes the guard's answer and the socket's destination the same
//! fact rather than two facts that usually agree.
//!
//! ## EVERY address must pass, not just one
//!
//! A hostname can resolve to several addresses, and a client is free to try any of them. Accepting
//! the URL because the FIRST answer was public leaves the attacker choosing the second. So the rule
//! is: if ANY resolved address is internal, the URL is refused. There is no "prefer the public one".
//!
//! ## The address predicates are NOT re-implemented here
//!
//! The CGNAT, unique-local, link-local and alternate-encoding atoms live in [`crate::net_guard`] and
//! are used from there. Duplicated security logic is the one kind of duplication that cannot be made
//! safe by documenting it: somebody hardens one copy against a new obfuscation and never learns the
//! other exists.

// PARTLY MOUNTED. `host_of` and `validate` are on the hot path: `ingress::rpc` guards every
// caller-supplied `pushNotificationConfig.url` through them before `taskstore::set_push_callback`
// stores it, which is why that function still does not validate — the decision lives here, once.
// `revalidate` is the DELIVERY path's half, and nothing delivers a push notification yet: a durable
// callback can outlive the DNS answer that was checked when it was written, so the fresh-resolution
// check belongs to the code that is about to connect rather than to the code that stored it.
#![cfg_attr(not(test), allow(dead_code))]

use std::net::IpAddr;

/// Why a callback URL was refused. Every variant names the property that failed, because "SSRF
/// blocked" alone gives an operator debugging a legitimate callback nothing to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PushNotifyError {
    /// Not a URL this code can reason about.
    Malformed(String),
    /// A scheme other than `https` (or `http`, when the deployment allows it).
    Scheme(String),
    /// No host at all.
    NoHost,
    /// The host is an ALTERNATE IPv4 ENCODING (`2130706433`, `0x7f000001`, `127.1`, `017700000001`).
    /// Refused on the host STRING before any resolution, because these forms bypass a canonical
    /// IP-literal check while the OS resolver still expands them to loopback and private targets.
    ObfuscatedHost(String),
    /// Nothing resolved. Refused rather than allowed: an empty answer means the guard has checked
    /// nothing, and "checked nothing" must never read as "found nothing wrong".
    Unresolved(String),
    /// A resolved address is internal — loopback, private, link-local, unique-local, CGNAT,
    /// unspecified, multicast, broadcast, or a cloud metadata address.
    InternalAddress(IpAddr),
    /// A re-resolution of an already-pinned callback shares NO address with the pin. Both answers
    /// were public, so this is not an SSRF finding — it is "the destination moved", which is a
    /// legitimate DNS change and a takeover attempt shaped identically. Reported as its own thing so
    /// an operator sees the distinction rather than being told a public address is internal.
    PinDrifted { host: String },
}

impl std::fmt::Display for PushNotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PushNotifyError::Malformed(u) => write!(f, "push callback URL is malformed: `{u}`"),
            PushNotifyError::Scheme(s) => write!(
                f,
                "push callback scheme `{s}` is refused; a callback carries task metadata off-box \
                 and must be https"
            ),
            PushNotifyError::NoHost => write!(f, "push callback URL has no host"),
            PushNotifyError::ObfuscatedHost(h) => write!(
                f,
                "push callback host `{h}` is an alternate IPv4 encoding, which resolves to an \
                 address a canonical literal check would not see"
            ),
            PushNotifyError::Unresolved(h) => write!(
                f,
                "push callback host `{h}` resolved to no addresses; nothing was checked, so \
                 nothing is allowed"
            ),
            PushNotifyError::InternalAddress(ip) => write!(
                f,
                "push callback resolves to the INTERNAL address {ip}; delivering there would lend \
                 busbar's network position to the caller"
            ),
            PushNotifyError::PinDrifted { host } => write!(
                f,
                "push callback host `{host}` now resolves to an entirely different address set than \
                 the one pinned when it was registered; delivery is held for an operator to look at"
            ),
        }
    }
}

/// A validated callback: the URL as registered, plus the addresses that were vetted.
///
/// The pinned addresses are the point. A caller that re-resolves `url` at delivery time has thrown
/// the guarantee away, so the delivery path takes `addrs` and connects to those.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PinnedCallback {
    pub(crate) url: String,
    pub(crate) host: String,
    pub(crate) addrs: Vec<IpAddr>,
}

/// The IPv4 cloud metadata address every major provider uses, plus the IPv6 form. These are the
/// single highest-value SSRF target in a cloud deployment: an unauthenticated HTTP GET there returns
/// instance credentials.
const METADATA_V4: [u8; 4] = [169, 254, 169, 254];

/// Is this address one busbar must never be talked into fetching?
///
/// `is_global` is deliberately not used even where it is stable: its definition has moved between
/// toolchain versions, and a security predicate whose meaning depends on the compiler is one that
/// changes behaviour on an unrelated upgrade. The ranges are enumerated instead.
pub(crate) fn is_internal_addr(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || crate::net_guard::is_cgnat_shared_v4(v4)
                || o == METADATA_V4
                // 0.0.0.0/8 "this network" — routed to the local host by several stacks.
                || o[0] == 0
                // 192.0.0.0/24 IETF protocol assignments, 198.18.0.0/15 benchmarking: neither is a
                // legitimate webhook destination and both are reachable inside some fabrics.
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || crate::net_guard::is_unique_local_v6(v6)
                || crate::net_guard::is_link_local_v6(v6)
                // An IPv4-mapped/compatible v6 address is an IPv4 address wearing a hat. Unwrap it
                // and apply the v4 rules, or `::ffff:169.254.169.254` walks straight through.
                || v6
                    .to_ipv4_mapped()
                    .or_else(|| v6.to_ipv4())
                    .is_some_and(|v4| is_internal_addr(&IpAddr::V4(v4)))
        }
    }
}

/// Split a URL into `(scheme, host)` without pulling in a URL parser.
///
/// Deliberately STRICT and small: it accepts `scheme://host[:port][/path…]` and refuses anything it
/// cannot read confidently. A permissive parser here is a liability — the whole job is to agree with
/// what the HTTP client will do, and the safe way to disagree is to REFUSE, not to guess.
fn split_url(url: &str) -> Result<(String, String), PushNotifyError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| PushNotifyError::Malformed(url.to_string()))?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+')
    {
        return Err(PushNotifyError::Malformed(url.to_string()));
    }
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_string();
    // USERINFO IS REFUSED, not stripped. `https://metadata.internal@example.com/` is read one way by
    // a human skimming a config and another way by a parser, and that ambiguity is the entire point
    // of the trick. Refusing costs a legitimate operator nothing: a webhook does not carry
    // credentials in its authority.
    if authority.contains('@') {
        return Err(PushNotifyError::Malformed(url.to_string()));
    }
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal.
        match bracketed.split_once(']') {
            Some((h, _port)) => h.to_string(),
            None => return Err(PushNotifyError::Malformed(url.to_string())),
        }
    } else {
        authority
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or(authority)
    };
    if host.is_empty() {
        return Err(PushNotifyError::NoHost);
    }
    Ok((scheme.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

/// THE HOST a callback URL names, read by the SAME strict parser [`validate`] uses.
///
/// Exposed so a caller that has to RESOLVE the host before it can validate does not need a second,
/// more permissive parser to find out what to resolve. Two parsers is two readings of one URL, and
/// the gap between them is where `https://metadata.internal@example.com/` lives.
pub(crate) fn host_of(url: &str) -> Result<String, PushNotifyError> {
    split_url(url).map(|(_scheme, host)| host)
}

/// VALIDATE a caller-supplied (or busbar-registered) callback URL against the addresses it resolves
/// to RIGHT NOW, and pin those addresses.
///
/// `resolved` is supplied by the caller so this function stays pure and every hostile case is a unit
/// test. The contract on the caller is the one thing that cannot be enforced from here and so is
/// stated as loudly as possible: **connect to the returned `addrs`, never to `host` again.**
///
/// `allow_plaintext` exists for the operator who terminates TLS at a sidecar on the same host. It
/// defaults OFF at every call site: a callback carries task ids and caller attribution, and putting
/// that on the wire in the clear by default would be busbar choosing convenience over the operator's
/// data.
pub(crate) fn validate(
    url: &str,
    resolved: &[IpAddr],
    allow_plaintext: bool,
) -> Result<PinnedCallback, PushNotifyError> {
    let (scheme, host) = split_url(url)?;
    match scheme.as_str() {
        "https" => {}
        "http" if allow_plaintext => {}
        other => return Err(PushNotifyError::Scheme(other.to_string())),
    }
    if crate::net_guard::is_alternate_ipv4_encoding(&host) {
        return Err(PushNotifyError::ObfuscatedHost(host));
    }
    // A canonical IP LITERAL is checked directly and is not subject to the resolver's answer at all
    // — there is nothing to rebind. It still has to pass the same ranges.
    if let Ok(literal) = host.parse::<IpAddr>() {
        if is_internal_addr(&literal) {
            return Err(PushNotifyError::InternalAddress(literal));
        }
        return Ok(PinnedCallback {
            url: url.to_string(),
            host,
            addrs: vec![literal],
        });
    }
    if resolved.is_empty() {
        return Err(PushNotifyError::Unresolved(host));
    }
    // EVERY answer must pass. One internal address in the set is a refusal, because the client is
    // free to try any of them and the attacker is free to order them.
    for ip in resolved {
        if is_internal_addr(ip) {
            return Err(PushNotifyError::InternalAddress(*ip));
        }
    }
    Ok(PinnedCallback {
        url: url.to_string(),
        host,
        addrs: resolved.to_vec(),
    })
}

/// RE-VALIDATE a callback that was pinned earlier, against a FRESH resolution, and require that the
/// answer has not moved into a different address set.
///
/// A durable task row can outlive the DNS answer that was checked when it was written — an interrupt
/// waiting on a human for a day, then a completion to deliver. Trusting the stored pin forever would
/// mean a legitimate DNS change breaks delivery permanently; trusting a fresh resolution blindly
/// would re-open the rebinding hole across the restart boundary. So both: the fresh answer must pass
/// the same guard, AND at least one address must still be one that was pinned before. A callback
/// whose address set has moved ENTIRELY is refused for an operator to look at rather than followed.
pub(crate) fn revalidate(
    pinned: &PinnedCallback,
    fresh: &[IpAddr],
    allow_plaintext: bool,
) -> Result<PinnedCallback, PushNotifyError> {
    let revalidated = validate(&pinned.url, fresh, allow_plaintext)?;
    if revalidated.addrs.iter().any(|a| pinned.addrs.contains(a)) {
        return Ok(revalidated);
    }
    Err(PushNotifyError::PinDrifted {
        host: revalidated.host,
    })
}

#[cfg(test)]
#[path = "tests/pushnotify_tests.rs"]
mod pushnotify_tests;
