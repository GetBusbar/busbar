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
//! The CGNAT, unique-local, link-local and alternate-encoding atoms live in [`busbar_core::net_guard`] and
//! are used from there. Duplicated security logic is the one kind of duplication that cannot be made
//! safe by documenting it: somebody hardens one copy against a new obfuscation and never learns the
//! other exists.

// FULLY MOUNTED, and the last function to get a caller was the most important one. `host_of` and
// `validate` guard registration in `ingress::invoke`; `structural_refusal` is the floor inside
// `taskstore::set_push_callback`; and `revalidate` — which had NO caller anywhere in the tree while
// this plane accepted, validated, pinned and persisted callbacks that nothing ever delivered to —
// is `pushdeliver`'s, run against a fresh resolution before every single delivery. A durable
// callback outlives the DNS answer that was checked when it was written, so the fresh-resolution
// check belongs to the code that is about to connect rather than to the code that stored it.
#![cfg_attr(not(test), allow(dead_code))]

use std::net::IpAddr;

/// Why a callback URL was refused. Every variant names the property that failed, because "SSRF
/// blocked" alone gives an operator debugging a legitimate callback nothing to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PushNotifyError {
    /// Not a URL this code can reason about.
    Malformed(String),
    /// A scheme other than `https`. There is no deployment in which another one is accepted.
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

/// Is this address one busbar must never be talked into fetching?
///
/// THIS IS NOW ONE LINE, and the line is the point. It used to be a forty-line private range table
/// on this plane, and the table was WRONG in a way that reading it could not reveal: Azure's
/// WireServer at `168.63.129.16` is a PUBLIC address, so every range check in the copy missed it,
/// while the copy's own doc comment claimed to cover "a cloud metadata address". A caller could
/// register that as a push callback and have busbar fetch Azure's platform metadata on its behalf.
/// The shared predicate had it; this plane did not, because a copy is only correct on the day it is
/// written.
///
/// The tear-out went the other way too — the three ranges this copy had and the shared predicate
/// did not (`0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`) moved INTO
/// [`busbar_substrate::net_guard::ipv4_is_internal`] first, so no guard lost coverage in the unification. That
/// ordering is the whole discipline: widen the shared predicate to the union, then delete the copy.
pub(crate) fn is_internal_addr(ip: &IpAddr) -> bool {
    busbar_substrate::net_guard::ip_is_internal(ip)
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

/// What the RESOLVER-FREE half of the guard concluded about a URL.
enum Structural {
    /// A canonical IP literal that PASSED the range check. There is nothing to resolve and nothing
    /// to rebind, so this is already a decision.
    Literal { host: String, addr: IpAddr },
    /// A DNS name that passed everything decidable without an answer from a resolver. Whether it is
    /// safe is NOT yet known, and saying so is the point of the separate variant.
    Name(String),
}

/// THE HALF OF THE GUARD THAT NEEDS NO RESOLVER: the scheme, the userinfo trick, the alternate IPv4
/// encodings, and a canonical IP literal's ranges.
///
/// Split out because two callers need exactly this much and cannot have the other half.
/// [`structural_refusal`] is a defence-in-depth check inside a synchronous store method that has no
/// resolver seam and must not grow one; [`validate`] is the full guard and calls this first, so
/// there is ONE implementation of the shared rules rather than two that agree today.
fn structural_check(url: &str) -> Result<Structural, PushNotifyError> {
    let (scheme, host) = split_url(url)?;
    // `https` OR NOTHING, and there is no parameter here through which that could be relaxed. The
    // scheme allowlist is by ABSENCE — `http:`, `file:`, `gopher:`, `data:` are refused because
    // they are not named rather than because a blocklist remembered them.
    if scheme != "https" {
        return Err(PushNotifyError::Scheme(scheme));
    }
    if busbar_substrate::net_guard::is_alternate_ipv4_encoding(&host) {
        return Err(PushNotifyError::ObfuscatedHost(host));
    }
    // A canonical IP LITERAL is checked directly and is not subject to the resolver's answer at all
    // — there is nothing to rebind. It still has to pass the same ranges.
    if let Ok(literal) = host.parse::<IpAddr>() {
        if is_internal_addr(&literal) {
            return Err(PushNotifyError::InternalAddress(literal));
        }
        return Ok(Structural::Literal {
            host,
            addr: literal,
        });
    }
    Ok(Structural::Name(host))
}

/// THE DEFENCE-IN-DEPTH CHECK for a caller that CANNOT resolve — `Some(refusal)` when the URL is
/// refusable without asking a nameserver anything, `None` when it is not yet decidable.
///
/// `None` is NOT "safe". It means "this is a DNS name and the verdict needs an answer this caller
/// cannot obtain", and the only correct thing to do with such a URL is to make sure the code that
/// eventually CONNECTS runs the full [`validate`] against a fresh resolution. That is exactly what
/// [`super::pushdeliver`] does before every delivery.
///
/// This exists because `taskstore::set_push_callback` used to take a bare `Option<String>` and
/// persist whatever it was handed. Its only caller validated first, so the tree was safe by
/// coincidence of call order — and a second caller, or a row rehydrated from a store somebody
/// wrote to directly, had nothing standing between it and a delivery attempt.
pub(crate) fn structural_refusal(url: &str) -> Option<PushNotifyError> {
    structural_check(url).err()
}

/// THE PUSH-CALLBACK SSRF FLOOR — the resolver-free half of the guard, applied at the A2A CALLER
/// boundary (`busbar_core::plane_host::EngineHostImpl::task_set_push_callback`) BEFORE the neutral task
/// store is asked to persist the callback. A2A domain logic that moved OUT of the core engine at the
/// D4 codec inversion so `taskstore::set_push_callback` makes no security decision and stores an
/// already-cleared callback. A URL the structural guard refuses is DROPPED (returned `None`) rather
/// than stored, and the drop is logged loudly: by the time a refusable URL reaches the store
/// something upstream already failed to validate, and the useful response is to make the callback not
/// exist, not to fail a task the caller is owed. The full resolving SSRF decision still runs TWICE
/// elsewhere (`ingress::invoke` before the registration is accepted, `a2a::pushdeliver` before every
/// delivery); this is the floor under both, byte-identical to the pre-cleave `floor_push_callback`.
pub(crate) fn floor_callback(task_id: &str, callback: Option<String>) -> Option<String> {
    match callback {
        Some(url) => match structural_refusal(&url) {
            Some(refusal) => {
                busbar_substrate::diag_error!(
                    busbar_substrate::diagnostics::PLANE_SSRF_CALLBACK_AT_STORE,
                    task = %task_id,
                    error = %refusal,
                    "a2a: a push callback the SSRF guard refuses reached the task store and was \
                     DROPPED; the caller that stored it did not validate first"
                );
                None
            }
            None => Some(url),
        },
        None => None,
    }
}

/// VALIDATE a caller-supplied (or busbar-registered) callback URL against the addresses it resolves
/// to RIGHT NOW, and pin those addresses.
///
/// `resolved` is supplied by the caller so this function stays pure and every hostile case is a unit
/// test. The contract on the caller is the one thing that cannot be enforced from here and so is
/// stated as loudly as possible: **connect to the returned `addrs`, never to `host` again.**
///
/// **`https` IS THE ONLY ACCEPTABLE SCHEME, AND THERE IS NO PARAMETER THAT CHANGES THAT.** A
/// callback carries task ids and caller attribution, and busbar's own callers are told there is no
/// per-registration flag, no deployment setting and no exception that relaxes this — so the guard
/// takes no argument that could. This function once had an `allow_plaintext` parameter, nominally
/// for an operator terminating TLS at a sidecar; that operator path was never built, no config key
/// ever reached it, and a knob nothing can set is not a feature, it is a hole waiting for a caller.
pub(crate) fn validate(url: &str, resolved: &[IpAddr]) -> Result<PinnedCallback, PushNotifyError> {
    let host = match structural_check(url)? {
        Structural::Literal { host, addr } => {
            return Ok(PinnedCallback {
                url: url.to_string(),
                host,
                addrs: vec![addr],
            });
        }
        Structural::Name(host) => host,
    };
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
) -> Result<PinnedCallback, PushNotifyError> {
    let revalidated = validate(&pinned.url, fresh)?;
    if revalidated.addrs.iter().any(|a| pinned.addrs.contains(a)) {
        return Ok(revalidated);
    }
    Err(PushNotifyError::PinDrifted {
        host: revalidated.host,
    })
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/pushnotify_tests.rs"]
mod pushnotify_tests;
