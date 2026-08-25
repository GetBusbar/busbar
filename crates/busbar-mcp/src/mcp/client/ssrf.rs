// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DISPATCH-TIME SSRF: an upstream MCP URL is attacker-influenced, so it is validated per request,
//! resolved, and then CONNECTED TO THE ADDRESS THAT WAS VALIDATED.
//!
//! ## THE GUARD IS NOT HERE. This module is its dispatch-time CALLER and its VOCABULARY.
//!
//! Resolve-then-pin, the address judgement, the redirect refusal and the strict URL recogniser all
//! live in [`busbar_core::net_guard`], because they were written twice — once here and once for the A2A
//! card fetch — and a security control with two implementations is a security control with one
//! copy that gets hardened and one that does not. That is not hypothetical: this module once kept
//! its own composite address predicate built from imported atoms, and the composite unwrapped IPv6
//! with `to_ipv4_mapped()` where the shared one uses `to_ipv4()`, so `[::169.254.169.254]` — the
//! IPv4-COMPATIBLE spelling of the AWS metadata endpoint — matched no v6 mask, unwrapped to
//! nothing, and was connected to.
//!
//! What stays here is what is genuinely THIS caller's: its knobs, and its WORDING. An operator
//! diagnosing a refusal needs to read "MCP upstream URL", not "a fetch was refused", and the remedy
//! sentence names `allow_private` on a SERVER registration. [`SsrfRefusal`] is therefore a
//! rendering of [`busbar_core::net_guard::GuardRefusal`] rather than a second decision about it.
//!
//! ## Why the existing startup guards are not enough, stated precisely
//!
//! `config_validate`'s provider-base-URL guard vets ONE operator-supplied string ONCE at startup,
//! and `observability.rs` says in its own comment that DNS rebinding is out of scope for a
//! startup-validated URL. Both are correct for what they guard. Neither is correct here: an MCP
//! server registration can be written through the admin API by anyone holding a `full`-scope token,
//! its tool arguments are per-request nested JSON chosen by a model that just read an upstream's
//! description, and both are re-resolved on every dispatch. Rebinding and TOCTOU are THE threat
//! rather than an edge case.
//!
//! ## What this caller sets, and what it refuses to make settable
//!
//! - **Scheme allowlist.** `https` always; `http` only where the operator has opted a server into
//!   private addressing. Everything else — `file:`, `gopher:`, `smb:`, `ftp:`, `data:` — is refused
//!   by absence rather than by a blocklist, because a blocklist of schemes is a list somebody has to
//!   keep up with.
//! - **No redirects, ever.** [`SsrfPolicy`] lowers to `max_redirects: 0`. A 3xx is a URL the
//!   operator never validated, chosen by the upstream, at the moment a credential is already on the
//!   wire.
//! - **Cloud metadata, whatever `allow_private` says.** The knob relaxes the private/loopback arms
//!   and nothing else; the metadata arm is decided before the knob is read, in core.
//!
//! ## What this module is NOT
//!
//! It is not on the selection hot path. Selection and dispatch carry SEPARATE budgets: selection
//! targets sub-100µs, while dispatch is milliseconds-class and does DNS. This runs on dispatch, and
//! the separation is what lets it do a blocking-class lookup without breaking the selection number.

use busbar_core::net_guard::{self, GuardPolicy, GuardRefusal, PinnedTarget};
use std::net::{IpAddr, SocketAddr};

/// The operator's addressing posture for ONE upstream. Per server rather than global, because the
/// answer genuinely differs: an MCP server on the cluster's internal network is the normal case, and
/// a global "allow private" would extend that decision to every other server at once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SsrfPolicy {
    /// Whether this upstream may live on a private / loopback / CGNAT address.
    ///
    /// Even when set, cloud-metadata addresses stay refused. That is not an oversight: an operator
    /// saying "this MCP server is on our internal network" has said nothing about IMDS, and IMDS is
    /// the address whose whole value to an attacker is that it hands out credentials to anyone who
    /// can make a request from inside.
    pub(crate) allow_private: bool,
}

impl SsrfPolicy {
    /// LOWER THIS CALLER'S ONE KNOB INTO THE SHARED POLICY.
    ///
    /// The three fields this path does not expose are set here rather than defaulted, because each
    /// is a decision and a default would hide it. `allow_plaintext: false` — plaintext follows
    /// `allow_private` on this path and has no separate opt-in, so a public `http://` upstream is
    /// refused whatever else is set. `max_redirects: 0` — a 3xx is never followed on a dispatch
    /// that already sent a credential. The body ceiling is `busbar_core::proxy`'s streaming cap, applied
    /// by the transport as it reads rather than by a length check afterwards, so the value here is
    /// the same number and not a second opinion about it.
    pub(crate) fn guard(self) -> GuardPolicy {
        GuardPolicy {
            allow_private: self.allow_private,
            allow_plaintext: false,
            max_redirects: 0,
            max_body_bytes: busbar_core::proxy::max_upstream_buffered_bytes(),
            timeout: DISPATCH_CONNECT_TIMEOUT,
        }
    }
}

/// How long ONE dispatch hop may spend getting a connection up. The overall request ceiling is the
/// caller's (it varies per tool call); this is the connect-side floor the pool builds every pinned
/// client with, held beside the policy so the two travel together.
pub(crate) const DISPATCH_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Why a dispatch target was refused. Every arm names the address or scheme, because an SSRF refusal
/// an operator cannot diagnose is an SSRF refusal an operator disables.
///
/// This is the MCP dispatch path's RENDERING of [`GuardRefusal`], not a second judgement: every
/// value is constructed by the `From` below and by nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SsrfRefusal {
    /// The URL had no `http`/`https` scheme, or none at all.
    Scheme(String),
    /// `http` to a public host. Refused because the upstream credential rides the request.
    PlaintextToPublicHost(String),
    /// The URL had no host component.
    NoHost(String),
    /// The host is an alternate IPv4 encoding (`0x7f000001`, `2130706433`, `127.1`) that the OS
    /// resolver expands but a canonical IP-literal check misses.
    ObfuscatedHost(String),
    /// The host IS a cloud-metadata name. Refused before any lookup and whatever `allow_private`
    /// says — the name is the destination, and resolving it first would only add a way to be told
    /// something else.
    MetadataHostName(String),
    /// The host is in the `localhost` family RFC 6761 reserves to loopback, and the server is not
    /// opted into private addressing.
    LoopbackHostName(String),
    /// DNS resolution failed or returned nothing.
    Unresolvable { host: String, reason: String },
    /// A resolved address is internal (loopback / private / link-local / CGNAT / unique-local) and
    /// the server is not opted into private addressing.
    InternalAddress { host: String, addr: IpAddr },
    /// A resolved address is a cloud-metadata endpoint. Always refused, `allow_private` or not.
    CloudMetadata { host: String, addr: IpAddr },
    /// The upstream answered a redirect. Never followed — see the module header.
    Redirect { status: u16, location: String },
    /// A SHARED BOUND THIS PATH DOES NOT SET: the redirect-chain limit and the body ceiling belong
    /// to a fetch that FOLLOWS redirects and reads a whole document, and dispatch does neither —
    /// it refuses the first 3xx outright and streams its body under `busbar_core::proxy`'s cap.
    ///
    /// Carried rather than flattened into one of the arms above so that if the guard ever hands
    /// this path a bound it does not set, an operator reads the actual reason instead of a nearby
    /// one. Rendering the shared refusal verbatim is the honest answer to "this should not happen".
    Bound(GuardRefusal),
}

impl From<GuardRefusal> for SsrfRefusal {
    fn from(g: GuardRefusal) -> Self {
        match g {
            GuardRefusal::Scheme { url, .. } => SsrfRefusal::Scheme(url),
            GuardRefusal::Plaintext { url, .. } => SsrfRefusal::PlaintextToPublicHost(url),
            GuardRefusal::NoHost(url) => SsrfRefusal::NoHost(url),
            GuardRefusal::ObfuscatedHost(host) => SsrfRefusal::ObfuscatedHost(host),
            GuardRefusal::MetadataName(host) => SsrfRefusal::MetadataHostName(host),
            GuardRefusal::LoopbackName(host) => SsrfRefusal::LoopbackHostName(host),
            GuardRefusal::Unresolvable { host, reason } => {
                SsrfRefusal::Unresolvable { host, reason }
            }
            // An empty answer and a failed lookup are different FACTS in core and are kept apart
            // there; this path has always reported them with one sentence, and the sentence is the
            // part an operator has in a runbook.
            GuardRefusal::NoAddresses(host) => SsrfRefusal::Unresolvable {
                host,
                reason: "resolver returned no addresses".to_string(),
            },
            GuardRefusal::InternalAddress { host, addr } => {
                SsrfRefusal::InternalAddress { host, addr }
            }
            GuardRefusal::CloudMetadataAddress { host, addr } => {
                SsrfRefusal::CloudMetadata { host, addr }
            }
            GuardRefusal::Redirect { status, location } => {
                SsrfRefusal::Redirect { status, location }
            }
            other @ (GuardRefusal::TooManyRedirects { .. } | GuardRefusal::BodyTooLarge { .. }) => {
                SsrfRefusal::Bound(other)
            }
        }
    }
}

impl std::fmt::Display for SsrfRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsrfRefusal::Scheme(u) => write!(
                f,
                "MCP upstream URL `{u}` must be http(s); no other scheme is dispatched to"
            ),
            SsrfRefusal::PlaintextToPublicHost(u) => write!(
                f,
                "MCP upstream URL `{u}` is plaintext http to a public host, and the upstream \
                 credential rides this request; use https"
            ),
            SsrfRefusal::NoHost(u) => write!(f, "MCP upstream URL `{u}` has no host"),
            SsrfRefusal::ObfuscatedHost(h) => write!(
                f,
                "MCP upstream host `{h}` is an alternate IPv4 encoding the resolver expands; write \
                 the address in dotted-quad form so it can be checked"
            ),
            SsrfRefusal::MetadataHostName(h) => write!(
                f,
                "MCP upstream host `{h}` is a cloud-metadata name; that is refused unconditionally"
            ),
            SsrfRefusal::LoopbackHostName(h) => write!(
                f,
                "MCP upstream host `{h}` is a loopback name; set this server's `allow_private` if \
                 that is deliberate"
            ),
            SsrfRefusal::Unresolvable { host, reason } => {
                write!(f, "MCP upstream host `{host}` did not resolve: {reason}")
            }
            SsrfRefusal::InternalAddress { host, addr } => write!(
                f,
                "MCP upstream host `{host}` resolves to the internal address {addr}; set this \
                 server's `allow_private` if that is deliberate"
            ),
            SsrfRefusal::CloudMetadata { host, addr } => write!(
                f,
                "MCP upstream host `{host}` resolves to the cloud-metadata address {addr}; that is \
                 refused unconditionally"
            ),
            SsrfRefusal::Redirect { status, location } => write!(
                f,
                "MCP upstream answered {status} redirecting to `{location}`; redirects are never \
                 followed because the target was never validated and the credential is already sent"
            ),
            SsrfRefusal::Bound(g) => write!(f, "MCP upstream fetch refused: {g}"),
        }
    }
}

/// THE CHECK, minus the I/O: everything decidable from the URL string alone.
///
/// Split out from [`pin_upstream`] so the string-shaped refusals are testable without a resolver,
/// and so a caller that already resolved (the pool, on a cache hit) re-runs the cheap half.
///
/// The ORDER is core's and is the same one the card fetch gets: recognise, then the scheme, then the
/// structural name refusals with the metadata arm ahead of the knob.
pub(crate) fn precheck(
    url: &str,
    policy: SsrfPolicy,
) -> Result<(bool, String, u16, String), SsrfRefusal> {
    let guard = policy.guard();
    let (https, host, port, path) = net_guard::split_url(url)?;
    net_guard::judge_scheme(url, https, guard)?;
    net_guard::judge_host_name(&host, guard)?;
    Ok((https, host, port, path))
}

/// RESOLVE-THEN-PIN for one dispatch. Resolves `url`'s host, refuses if ANY resolved address is
/// inadmissible, and returns the address the caller must connect to.
///
/// Async because it does DNS, and a dispatch path — after selection, before the outbound
/// `tools/call` — is the one place a per-request DNS lookup belongs. The judgement and the pin are
/// [`busbar_core::net_guard`]'s; what is here is the URL this path starts from and the wording it reports
/// in.
pub(crate) async fn pin_upstream(
    url: &str,
    policy: SsrfPolicy,
) -> Result<PinnedTarget, SsrfRefusal> {
    let (https, host, port, _path) = precheck(url, policy)?;
    Ok(net_guard::resolve_and_pin_async(&host, port, https, policy.guard()).await?)
}

/// Refuse if ANY address in `addrs` is inadmissible.
///
/// Kept as this path's door onto [`net_guard::judge_addresses`] because dispatch carries
/// `SocketAddr`s (it has a port to connect to) while the judgement is about the ADDRESS. The
/// ordering that makes `allow_private` safe — metadata before the knob — is core's and is not
/// restated here.
// NO PRODUCTION CALLER: the pin path judges through `busbar_core::net_guard` directly, which is the whole
// point of the unification. This stays because the MCP refusal SUITE drives every range, every
// metadata endpoint and the mixed-answer case through it, and what those tests prove that core's own
// suite cannot is that THIS PLANE still renders them in THIS PLANE's words. Deleting it would trade
// a wording regression for a dead-code warning.
#[cfg_attr(any(not(test), busbar_mcp_native), allow(dead_code))]
pub(crate) fn check_addresses(
    host: &str,
    addrs: &[SocketAddr],
    policy: SsrfPolicy,
) -> Result<(), SsrfRefusal> {
    let ips: Vec<IpAddr> = addrs.iter().map(|sa| sa.ip()).collect();
    Ok(net_guard::judge_addresses(host, &ips, policy.guard())?)
}

/// Turn a response status into a refusal when it is a redirect.
///
/// Called on the dispatch path rather than relying only on the client's `Policy::none()`. Two
/// mechanisms for one hazard is deliberate here: the policy stops the request being MADE, and this
/// stops a 3xx being handed to a JSON-RPC parser that would report "invalid response" and hide the
/// fact that an upstream tried to move the call somewhere else.
pub(crate) fn refuse_redirect(status: u16, location: Option<&str>) -> Result<(), SsrfRefusal> {
    Ok(net_guard::refuse_redirect(status, location)?)
}

#[cfg(all(test, not(busbar_mcp_native)))]
#[path = "tests/ssrf_tests.rs"]
mod ssrf_tests;
