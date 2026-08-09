// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AGENT CARD FETCH, and the SSRF guard that is the only reason it is allowed to exist.
//!
//! Everything else on this plane decides. This is the one module that REACHES OUT, at a URL an
//! operator wrote and following redirects a stranger controls, and it therefore carries the whole
//! server-side-request-forgery surface of the A2A plane on its own.
//!
//! ## RESOLVE THEN PIN, and why a name check is not a guard
//!
//! Checking the host STRING and then handing the URL to an HTTP client is not a guard, it is a
//! guard-shaped delay. The client performs its OWN name resolution when it connects, and between
//! the check and the connect the name is free to mean something else. That is DNS rebinding, and it
//! is not exotic: a hostile card endpoint only has to serve a short TTL and answer the second
//! lookup with `169.254.169.254`.
//!
//! So the name is resolved exactly ONCE per hop, EVERY answered address is judged, and the address
//! that survives is PINNED and handed to the transport. The socket connects to an address this
//! module already looked at. There is no second lookup for an attacker to win, which is what makes
//! the time-of-check/time-of-use gap not merely narrow but absent.
//!
//! ## Every address in the answer, not the one we would have used
//!
//! A resolver answering `[93.184.216.34, 169.254.169.254]` is refused OUTRIGHT rather than pinned to
//! the public address. Picking the good one from a mixed answer would mean the same name is
//! sometimes fine and sometimes not, decided by ordering the upstream chooses, and "the guard
//! depends on which address the resolver listed first" is not a property anyone can reason about.
//! A mixed answer is a hostile answer.
//!
//! ## A redirect is a fresh, fully untrusted URL
//!
//! Every hop is re-guarded from scratch: scheme, host form, resolution, every address, and a new
//! pin. A redirect is the attacker's most direct way to move the request, and treating it as a
//! continuation of an already-approved fetch is how a guarded fetch of a public host ends up
//! reading `http://169.254.169.254/latest/meta-data/`. The chain is also BOUNDED, because a guard
//! that is applied correctly to an unbounded number of hops is a way to spend the process.
//!
//! ## What this module deliberately does NOT do
//!
//! It does not verify the card. A fetched document is bytes, and the trust decision belongs to
//! [`super::jws`] against the operator's out-of-band key. Keeping the two apart is what stops "we
//! fetched it safely" from being read as "it is genuine".

use std::net::IpAddr;

use crate::net_guard::{dns_name_is_internal, ip_is_internal, is_alternate_ipv4_encoding};

use super::card::{WELL_KNOWN_CARD_PATH, WELL_KNOWN_CARD_PATH_LEGACY};

/// The operator's fetch policy. Config, therefore intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FetchPolicy {
    /// How many redirects may be FOLLOWED. Zero is a legitimate setting and means "the card must be
    /// at the URL I wrote".
    pub(crate) max_redirects: u8,
    /// Largest card body accepted, in bytes. A card is a small JSON document; an unbounded read
    /// from an upstream is an unbounded allocation an upstream chooses the size of.
    pub(crate) max_body_bytes: usize,
    /// Permit a plaintext `http://` card endpoint.
    ///
    /// DEFAULT FALSE, and this is the one knob here that weakens anything, so it is spelled out:
    /// the `agents:` grammar accepts an `http://` URL because a developer running an agent on a
    /// laptop is a real case, but a card fetched over plaintext can be rewritten in flight by
    /// anyone on the path, and a rewritten card is exactly what the pin exists to catch. A signed
    /// card still fails JWS verification, so this is not a hole in the trust root — it is a hole in
    /// everything that is not the trust root, which is why it is opt-in.
    pub(crate) allow_plaintext: bool,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self {
            max_redirects: 3,
            max_body_bytes: 512 * 1024,
            allow_plaintext: false,
        }
    }
}

/// Why a fetch was refused. Every arm names the URL or address that caused it, because an operator
/// reading "SSRF guard refused the card fetch" with no target cannot tell a misconfiguration from
/// an attack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FetchRefusal {
    /// Not parseable as a URL at all.
    NotAUrl(String),
    /// Not `https://` (and `allow_plaintext` is off).
    NotHttps { url: String, scheme: String },
    /// A URL with no host: `file:`, `data:`, an authority-less form.
    NoHost(String),
    /// The host is internal BY NAME, before any resolution: a cloud-metadata name, the `localhost`
    /// family, or an alternate IPv4 encoding a resolver still expands to an internal address.
    InternalHostName { host: String, why: &'static str },
    /// The name resolved, and an answered address is internal. Carries the offending address, so
    /// the operator sees WHAT it resolved to rather than being told only that it did.
    InternalAddress { host: String, addr: IpAddr },
    /// Resolution failed.
    ResolutionFailed { host: String, err: String },
    /// Resolution succeeded and answered nothing. Refused rather than treated as "no internal
    /// address found": an empty answer has nothing to connect to and nothing to have judged.
    NoAddresses(String),
    /// More redirects than the policy permits.
    TooManyRedirects { limit: u8, at: String },
    /// A 3xx with no usable `Location`.
    RedirectWithoutLocation { at: String, status: u16 },
    /// The transport failed.
    Transport { url: String, err: String },
    /// A non-2xx, non-3xx status.
    Status { url: String, status: u16 },
    /// The body exceeded [`FetchPolicy::max_body_bytes`].
    BodyTooLarge { url: String, bytes: usize },
    /// The body is not a JSON object, so it is not a card.
    NotACard { url: String, err: String },
}

impl std::fmt::Display for FetchRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchRefusal::NotAUrl(u) => write!(f, "agent card URL is not a URL: `{u}`"),
            FetchRefusal::NotHttps { url, scheme } => write!(
                f,
                "agent card URL `{url}` uses scheme `{scheme}`; a card fetched over plaintext can \
                 be rewritten in flight. Use https://, or set the endpoint's plaintext opt-in."
            ),
            FetchRefusal::NoHost(u) => write!(f, "agent card URL `{u}` has no host"),
            FetchRefusal::InternalHostName { host, why } => write!(
                f,
                "SSRF guard refused the agent card fetch: host `{host}` is {why}"
            ),
            FetchRefusal::InternalAddress { host, addr } => write!(
                f,
                "SSRF guard refused the agent card fetch: host `{host}` resolved to the internal \
                 address {addr}"
            ),
            FetchRefusal::ResolutionFailed { host, err } => {
                write!(f, "agent card host `{host}` did not resolve: {err}")
            }
            FetchRefusal::NoAddresses(host) => write!(
                f,
                "agent card host `{host}` resolved to no addresses at all; there is nothing to \
                 connect to and nothing to have judged"
            ),
            FetchRefusal::TooManyRedirects { limit, at } => write!(
                f,
                "agent card fetch exceeded {limit} redirect(s), still redirecting at `{at}`"
            ),
            FetchRefusal::RedirectWithoutLocation { at, status } => write!(
                f,
                "agent card fetch got HTTP {status} from `{at}` with no usable Location header"
            ),
            FetchRefusal::Transport { url, err } => {
                write!(f, "agent card fetch of `{url}` failed: {err}")
            }
            FetchRefusal::Status { url, status } => {
                write!(f, "agent card fetch of `{url}` returned HTTP {status}")
            }
            FetchRefusal::BodyTooLarge { url, bytes } => write!(
                f,
                "agent card at `{url}` is {bytes} bytes, over the configured ceiling"
            ),
            FetchRefusal::NotACard { url, err } => {
                write!(f, "the document at `{url}` is not an agent card: {err}")
            }
        }
    }
}

/// A URL that PASSED the guard, together with the address it was pinned to.
///
/// The pair is the whole contract: a caller that has one of these connects to `addr` and sends
/// `url`'s host in the `Host` header. Handing a transport the URL alone would re-open the second
/// lookup this type exists to close.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PinnedTarget {
    pub(crate) url: reqwest::Url,
    pub(crate) addr: IpAddr,
}

/// Name resolution, as a seam.
///
/// A trait rather than a direct `to_socket_addrs` call because the hazards this module exists to
/// defeat are all about WHAT THE RESOLVER SAYS AND WHEN: a mixed answer, an answer that changes
/// between two lookups, a name that resolves to link-local. None of those is reproducible against
/// the real resolver, so none of them would be tested, and an untested SSRF guard is a comment.
pub(crate) trait Resolver {
    /// Every address this name currently answers with. `Err` is a resolution failure, NOT an empty
    /// answer: the two are different facts and collapsing them would let a failure read as "nothing
    /// internal here".
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String>;
}

/// One HTTP response, reduced to what a card fetch reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HttpResponse {
    pub(crate) status: u16,
    /// The `Location` header, verbatim, for a 3xx. Never followed by the transport itself.
    pub(crate) location: Option<String>,
    pub(crate) body: Vec<u8>,
}

/// The HTTP round trip, as a seam.
///
/// `get` takes the PINNED ADDRESS as a separate argument and an implementation MUST connect to it
/// rather than re-resolving `url`. A transport that ignores it has silently reintroduced the second
/// lookup, so this is the one place the signature is doing security work rather than plumbing.
///
/// An implementation MUST NOT follow redirects; a 3xx is returned for this module to re-guard.
pub(crate) trait Transport {
    fn get(&self, url: &reqwest::Url, addr: IpAddr) -> Result<HttpResponse, String>;
}

/// GUARD ONE URL AND PIN IT.
///
/// The order is the design. Cheap structural refusals first, so a hostile name never reaches the
/// resolver; then exactly one resolution; then EVERY answered address; then the pin.
pub(crate) fn resolve_and_pin(
    url: &str,
    resolver: &dyn Resolver,
    policy: &FetchPolicy,
) -> Result<PinnedTarget, FetchRefusal> {
    let parsed =
        reqwest::Url::parse(url).map_err(|_| FetchRefusal::NotAUrl(url.trim().to_string()))?;

    let scheme = parsed.scheme().to_ascii_lowercase();
    let scheme_ok = scheme == "https" || (policy.allow_plaintext && scheme == "http");
    if !scheme_ok {
        return Err(FetchRefusal::NotHttps {
            url: parsed.to_string(),
            scheme,
        });
    }

    let Some(raw_host) = parsed.host_str() else {
        return Err(FetchRefusal::NoHost(parsed.to_string()));
    };
    // `host_str` keeps an IPv6 literal bracketed, and preserves a trailing FQDN-root dot. Both
    // spellings resolve to the same target and both defeat a naive exact compare, so they are
    // normalized away BEFORE any check rather than after some of them.
    let host = raw_host.strip_prefix('[').unwrap_or(raw_host);
    let host = host.strip_suffix(']').unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);

    // ── STRUCTURAL REFUSALS: true about the NAME, so no resolver is consulted. ──
    if dns_name_is_internal(host) {
        return Err(FetchRefusal::InternalHostName {
            host: host.to_string(),
            why: "a cloud-metadata or loopback name",
        });
    }
    if is_alternate_ipv4_encoding(host) {
        return Err(FetchRefusal::InternalHostName {
            host: host.to_string(),
            why: "an alternate IPv4 encoding a resolver still expands to an internal address",
        });
    }
    // An IP LITERAL is its own answer: judge it and pin it without asking a resolver about it. The
    // resolver is not merely unnecessary here, it is wrong — a stub that echoes literals back is
    // one more thing that could disagree with this check.
    if let Ok(addr) = host.parse::<IpAddr>() {
        if ip_is_internal(&addr) {
            return Err(FetchRefusal::InternalAddress {
                host: host.to_string(),
                addr,
            });
        }
        return Ok(PinnedTarget { url: parsed, addr });
    }

    // ── EXACTLY ONE RESOLUTION, and every address in it is judged. ──
    let addrs = resolver
        .resolve(host)
        .map_err(|err| FetchRefusal::ResolutionFailed {
            host: host.to_string(),
            err,
        })?;
    if addrs.is_empty() {
        return Err(FetchRefusal::NoAddresses(host.to_string()));
    }
    // A MIXED ANSWER IS A HOSTILE ANSWER. Refused whole, never filtered down to the address that
    // happens to be acceptable — see the module note.
    if let Some(bad) = addrs.iter().find(|a| ip_is_internal(a)) {
        return Err(FetchRefusal::InternalAddress {
            host: host.to_string(),
            addr: *bad,
        });
    }

    Ok(PinnedTarget {
        url: parsed,
        addr: addrs[0],
    })
}

/// A card that was fetched, with the chain it was fetched over.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct FetchedCard {
    /// The raw document, AS RECEIVED. Never a re-serialization: both hashes are taken over what
    /// arrived, so anything that round-trips it before hashing has changed what was approved.
    pub(crate) document: serde_json::Value,
    /// Every URL in the chain, in order, starting with the one asked for. Recorded because an
    /// operator approving a card is entitled to see that it came from three redirects away.
    pub(crate) chain: Vec<String>,
    /// The address the FINAL hop was pinned to.
    pub(crate) addr: IpAddr,
}

/// The two well-known discovery paths, canonical first.
///
/// Both are tried on every fetch because the path MOVED between protocol revisions and an upstream
/// pinned to an older `protocolVersion` is still serving the old one. Canonical first so a host
/// serving both is read at the current path.
pub(crate) fn discovery_urls(endpoint: &str) -> Result<Vec<String>, FetchRefusal> {
    let base = reqwest::Url::parse(endpoint)
        .map_err(|_| FetchRefusal::NotAUrl(endpoint.trim().to_string()))?;
    let mut out = Vec::new();
    for path in [WELL_KNOWN_CARD_PATH, WELL_KNOWN_CARD_PATH_LEGACY] {
        // Joined onto the ORIGIN, not onto the endpoint path: the well-known paths are defined at
        // the root of the authority, and joining them onto `/agents/planner/` would look for the
        // card somewhere the specification never puts it.
        let mut u = base.clone();
        u.set_path(path);
        u.set_query(None);
        u.set_fragment(None);
        out.push(u.to_string());
    }
    Ok(out)
}

/// FETCH ONE CARD, guarding and re-pinning at every hop.
pub(crate) fn fetch_card(
    url: &str,
    resolver: &dyn Resolver,
    transport: &dyn Transport,
    policy: &FetchPolicy,
) -> Result<FetchedCard, FetchRefusal> {
    let mut current = url.to_string();
    let mut chain = Vec::new();
    let mut hops: u32 = 0;

    loop {
        // EVERY HOP IS GUARDED FROM SCRATCH. A redirect is a URL a stranger chose; that the
        // previous hop passed says nothing at all about this one.
        let target = resolve_and_pin(&current, resolver, policy)?;
        chain.push(target.url.to_string());

        let resp =
            transport
                .get(&target.url, target.addr)
                .map_err(|err| FetchRefusal::Transport {
                    url: target.url.to_string(),
                    err,
                })?;

        if (300..400).contains(&resp.status) {
            if u32::from(policy.max_redirects) <= hops {
                return Err(FetchRefusal::TooManyRedirects {
                    limit: policy.max_redirects,
                    at: target.url.to_string(),
                });
            }
            let location = resp
                .location
                .as_deref()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .ok_or_else(|| FetchRefusal::RedirectWithoutLocation {
                    at: target.url.to_string(),
                    status: resp.status,
                })?;
            // Resolved RELATIVE TO THE HOP THAT SENT IT, which is what a client does, so a relative
            // `Location` cannot be mistaken for an absolute one and quietly land on a default host.
            let next = target.url.join(location).map_err(|_| {
                // An unparseable Location is a refusal, never a silent stop at the 3xx: stopping
                // would return "no card here" for what is actually a malformed redirect.
                FetchRefusal::RedirectWithoutLocation {
                    at: target.url.to_string(),
                    status: resp.status,
                }
            })?;
            current = next.to_string();
            hops += 1;
            continue;
        }

        if !(200..300).contains(&resp.status) {
            return Err(FetchRefusal::Status {
                url: target.url.to_string(),
                status: resp.status,
            });
        }

        if resp.body.len() > policy.max_body_bytes {
            return Err(FetchRefusal::BodyTooLarge {
                url: target.url.to_string(),
                bytes: resp.body.len(),
            });
        }
        let document: serde_json::Value =
            serde_json::from_slice(&resp.body).map_err(|e| FetchRefusal::NotACard {
                url: target.url.to_string(),
                err: e.to_string(),
            })?;
        if !document.is_object() {
            return Err(FetchRefusal::NotACard {
                url: target.url.to_string(),
                err: "the document is not a JSON object".to_string(),
            });
        }
        return Ok(FetchedCard {
            document,
            chain,
            addr: target.addr,
        });
    }
}

#[cfg(test)]
#[path = "tests/fetch_tests.rs"]
mod fetch_tests;
