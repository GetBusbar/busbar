// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AGENT CARD FETCH: the card-shaped part of a guarded fetch, over the guard in
//! [`crate::net_guard`].
//!
//! Everything else on this plane decides. This is the one module that REACHES OUT, at a URL an
//! operator wrote and following redirects a stranger controls, and it therefore carries the whole
//! server-side-request-forgery surface of the A2A plane on its own.
//!
//! ## THE GUARD IS NOT HERE, and that is the point
//!
//! Resolve-then-pin, the address judgement, the metadata arm that sits ahead of `allow_private`, the
//! hop bound and the body cap all live in [`crate::net_guard`]. They were written twice — once here
//! and once for the MCP dispatch path — and the doc comments in each copy had already started
//! citing the other's function names as the reason an ordering was correct. A security control that
//! has to cite its twin to explain itself has two implementations and one of them will be the stale
//! one; on the MCP side that had already happened, and the stale copy was a live cloud-metadata
//! bypass.
//!
//! What is here is the part that is genuinely about CARDS: the two well-known discovery paths, the
//! redirect CHAIN (this fetch follows redirects; the dispatch path follows none), the JSON-object
//! shape a card must have, and this plane's refusal WORDING — an operator reading a log needs
//! "agent card URL" and a remedy that names `allow_private:` on a REGISTRATION.
//!
//! ## RESOLVE THEN PIN, restated because every reader of this file needs it
//!
//! Checking the host STRING and then handing the URL to an HTTP client is not a guard, it is a
//! guard-shaped delay. The client performs its OWN name resolution when it connects, and between
//! the check and the connect the name is free to mean something else. That is DNS rebinding, and it
//! is not exotic: a hostile card endpoint only has to serve a short TTL and answer the second
//! lookup with `169.254.169.254`.
//!
//! So the name is resolved exactly ONCE per hop, EVERY answered address is judged, and the address
//! that survives is PINNED and handed to the transport. A resolver answering
//! `[93.184.216.34, 169.254.169.254]` is refused OUTRIGHT rather than pinned to the public address:
//! a mixed answer is a hostile answer.
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

use busbar_substrate::net_guard::{self, GuardPolicy, GuardRefusal, PinnedTarget};

use super::card::{WELL_KNOWN_CARD_PATH, WELL_KNOWN_CARD_PATH_LEGACY};

/// NAME RESOLUTION, AS A SEAM — core's, re-exported because it is this plane's fetch seam too.
///
/// Re-exported rather than redeclared: a second trait with the same shape would let a transport be
/// written against one and a guard against the other, which is how two implementations of one
/// control start.
pub(crate) use busbar_substrate::net_guard::Resolver;

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
    /// MAY THIS FETCH REACH A PRIVATE OR LOOPBACK ADDRESS. The `agents.<name>.allow_private:` knob,
    /// lowered per registration by [`super::plane::A2aPlane::fetch_policy_for`].
    ///
    /// The SAME name and the same meaning as the `tools:` grammar's, because it is one operator
    /// concept and two spellings of it would be two things to learn and two things to get wrong.
    /// It relaxes the loopback/private ARMS of the guard and NOTHING else: a cloud-metadata name
    /// and a cloud-metadata address are refused with this set, because
    /// [`busbar_substrate::net_guard::judge_address`] tests the metadata arm BEFORE it reads this flag, and
    /// the alternate-IPv4-encoding arm is likewise unconditional. An `allow_private` that reached
    /// IMDS would be a config flag that hands out cloud credentials.
    pub(crate) allow_private: bool,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self {
            max_redirects: 3,
            max_body_bytes: 512 * 1024,
            allow_plaintext: false,
            allow_private: false,
        }
    }
}

impl FetchPolicy {
    /// LOWER THIS PLANE'S REGISTRATION KNOBS INTO THE SHARED POLICY.
    ///
    /// Every field maps across unchanged except the clock, which this type does not carry: the card
    /// ceiling is a property of the HOP and lives on the transport that opens the socket
    /// ([`super::transport::CARD_FETCH_TIMEOUT`]). The relay reuses this same policy for its guard
    /// and then holds its socket to its OWN, longer ceiling, because a relayed `message/send` is the
    /// backend agent doing the work the caller asked for rather than a small document read — so the
    /// value carried here is the guard's default and never the relay's override.
    pub(crate) fn guard(&self) -> GuardPolicy {
        GuardPolicy {
            allow_private: self.allow_private,
            allow_plaintext: self.allow_plaintext,
            max_redirects: self.max_redirects,
            max_body_bytes: self.max_body_bytes,
            timeout: super::transport::CARD_FETCH_TIMEOUT,
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
    /// A SHARED REFUSAL THIS CALLER DOES NOT PRODUCE: [`GuardRefusal::Redirect`] is the
    /// never-follow-a-3xx arm, and this fetch FOLLOWS redirects under
    /// [`FetchPolicy::max_redirects`] and reports an over-long chain as
    /// [`FetchRefusal::TooManyRedirects`] instead.
    ///
    /// Carried verbatim rather than folded into a nearby arm so that a refusal core grows later
    /// arrives at an operator as itself. The conversion below is TOTAL on purpose: a new shared
    /// refusal must be given a sentence here, not silently dropped into whichever arm happened to
    /// be last.
    Guard(GuardRefusal),
}

/// RENDER A SHARED REFUSAL IN THIS PLANE'S VOCABULARY.
///
/// The three name arms all become [`FetchRefusal::InternalHostName`] with the `why` this plane has
/// always printed, and BOTH address arms become [`FetchRefusal::InternalAddress`] — a metadata
/// address is reported here as an internal one, with the sentence saying it is refused whatever
/// `allow_private` is set to. That collapse is this plane's WORDING and not its decision: core
/// keeps the two apart, which is what stops the knob from ever speaking for the metadata arm.
impl From<GuardRefusal> for FetchRefusal {
    fn from(g: GuardRefusal) -> Self {
        match g {
            GuardRefusal::Scheme { url, scheme } | GuardRefusal::Plaintext { url, scheme } => {
                FetchRefusal::NotHttps { url, scheme }
            }
            GuardRefusal::NoHost(url) => FetchRefusal::NoHost(url),
            GuardRefusal::MetadataName(host) => FetchRefusal::InternalHostName {
                host,
                why: "a cloud-metadata name",
            },
            GuardRefusal::LoopbackName(host) => FetchRefusal::InternalHostName {
                host,
                why: "a loopback name; set this registration's `allow_private: true` if that is \
                      deliberate",
            },
            GuardRefusal::ObfuscatedHost(host) => FetchRefusal::InternalHostName {
                host,
                why: "an alternate IPv4 encoding a resolver still expands to an internal address",
            },
            GuardRefusal::Unresolvable { host, reason } => {
                FetchRefusal::ResolutionFailed { host, err: reason }
            }
            GuardRefusal::NoAddresses(host) => FetchRefusal::NoAddresses(host),
            GuardRefusal::InternalAddress { host, addr }
            | GuardRefusal::CloudMetadataAddress { host, addr } => {
                FetchRefusal::InternalAddress { host, addr }
            }
            GuardRefusal::TooManyRedirects { limit, at } => {
                FetchRefusal::TooManyRedirects { limit, at }
            }
            GuardRefusal::BodyTooLarge { url, bytes } => FetchRefusal::BodyTooLarge { url, bytes },
            other @ GuardRefusal::Redirect { .. } => FetchRefusal::Guard(other),
        }
    }
}

impl std::fmt::Display for FetchRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchRefusal::NotAUrl(u) => write!(f, "agent card URL is not a URL: `{u}`"),
            FetchRefusal::NotHttps { url, scheme } => write!(
                f,
                "agent card URL `{url}` uses scheme `{scheme}`; a card fetched over plaintext can \
                 be rewritten in flight. Use https://, or set this registration's \
                 `allow_private: true` if the endpoint is a loopback or private one you meant."
            ),
            FetchRefusal::NoHost(u) => write!(f, "agent card URL `{u}` has no host"),
            FetchRefusal::InternalHostName { host, why } => write!(
                f,
                "SSRF guard refused the agent card fetch: host `{host}` is {why}"
            ),
            FetchRefusal::InternalAddress { host, addr } => write!(
                f,
                "SSRF guard refused the agent card fetch: host `{host}` resolved to the internal \
                 address {addr}; set this registration's `allow_private: true` if reaching it is \
                 deliberate. A cloud-metadata address is refused whatever that is set to."
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
            FetchRefusal::Guard(g) => {
                write!(f, "SSRF guard refused the agent card fetch: {g}")
            }
        }
    }
}

/// One HTTP response, reduced to what a card fetch reads.
///
/// This is the neutral, host-owned [`busbar_substrate::egress::Response`], re-exported under this plane's
/// historical name so the card-fetch and relay call sites read unchanged. It lives in
/// [`crate::egress`] rather than here because the same buffered round trip serves the MCP dispatch
/// path too, and a return type owned by one plane could not be returned to the other. Its
/// `peer_spki` / `client_identity_offered` fields carry the exact per-hop observations this plane's
/// verifier reads ([`super::verify`] refuses a `cert_spki`/`mtls` registration whose card did not
/// arrive over the connection those fields describe).
pub(crate) use busbar_substrate::egress::Response as HttpResponse;

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

/// GUARD ONE HOP AND PIN IT: the card fetch's door onto [`busbar_substrate::net_guard::resolve_and_pin`].
///
/// Returns the parsed URL BESIDE the pin, because the two are needed together and for different
/// things: the socket goes to [`PinnedTarget::addr`], and the request carries the URL — its host in
/// the `Host` header and as TLS SNI, its path on the wire, and its origin as the base a relative
/// `Location` is joined against. Handing a transport the URL alone would re-open the second lookup
/// the pin exists to close.
///
/// ## Why this parses with a URL type where the dispatch path uses a strict recogniser
///
/// The one difference between the two callers of the guard that could NOT be parameterised away.
/// The MCP dispatch path wants a strict recogniser on an attacker-influenced string, and gets
/// [`busbar_substrate::net_guard::split_url`]. This path must FOLLOW redirects, and following one means
/// joining a relative `Location` against the hop that sent it exactly as a client would — which
/// needs a real URL type and its resolution rules, not a splitter. Both then bring the host they
/// parsed through the SAME [`busbar_substrate::net_guard::judge_host_name`] and the same resolve-then-pin, so
/// what differs is the recognition and never the judgement.
pub(crate) fn guard_hop(
    url: &str,
    resolver: &dyn Resolver,
    policy: &FetchPolicy,
) -> Result<(reqwest::Url, PinnedTarget), FetchRefusal> {
    let guard = policy.guard();
    let parsed =
        reqwest::Url::parse(url).map_err(|_| FetchRefusal::NotAUrl(url.trim().to_string()))?;

    // The scheme allowlist is by ABSENCE: `https` always, `http` only where the policy admits
    // plaintext, and everything else — `file:`, `data:`, `gopher:` — refused because it is not
    // named rather than because a blocklist remembered it.
    let scheme = parsed.scheme().to_ascii_lowercase();
    let https = match scheme.as_str() {
        "https" => true,
        "http" => false,
        _ => {
            return Err(FetchRefusal::NotHttps {
                url: parsed.to_string(),
                scheme,
            })
        }
    };
    // `allow_private` ADMITS PLAINTEXT, and the predicate that says so is core's, so this plane and
    // the dispatch plane cannot answer it differently. An operator pointing busbar at
    // `http://127.0.0.1` has made ONE decision; making them write two flags would teach that the
    // second one is harmless. `allow_plaintext` stays its own field because a plaintext fetch of a
    // PUBLIC host is a different, worse thing than a plaintext fetch of loopback.
    if net_guard::judge_scheme(parsed.as_str(), https, guard).is_err() {
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
    let port = parsed
        .port_or_known_default()
        .unwrap_or_else(|| net_guard::default_port(https));

    // ── THE GUARD. Structural name refusals, then EXACTLY ONE resolution, then EVERY answered
    //    address, then the pin. All of it core's, including the ordering that keeps the
    //    cloud-metadata arm ahead of `allow_private`.
    let target = net_guard::resolve_and_pin(host, port, https, resolver, guard)?;
    Ok((parsed, target))
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
    /// The transport-layer identity of the hop that actually served the card: the
    /// [`HttpResponse::peer_spki`] of the LAST hop, never of the first.
    ///
    /// The last hop is the only one that matters and saying so is not pedantry: a redirect chain
    /// can start at a host an operator pinned and end anywhere, and pinning the certificate of the
    /// server that merely pointed at the card would authenticate the signpost rather than the
    /// document.
    pub(crate) peer_spki: Option<String>,
    /// Whether the hop that actually served the card carried busbar's client certificate for this
    /// registration ([`HttpResponse::client_identity_offered`]). The LAST hop's, for the same
    /// reason the peer pin is the last hop's: the mutual half is about the connection the document
    /// came over, not about the one that pointed at it.
    pub(crate) client_identity_offered: bool,
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
        let (url, pin) = guard_hop(&current, resolver, policy)?;
        chain.push(url.to_string());

        let resp = transport
            .get(&url, pin.addr())
            .map_err(|err| FetchRefusal::Transport {
                url: url.to_string(),
                err,
            })?;

        if (300..400).contains(&resp.status) {
            // THE HOP BOUND IS CORE'S. A guard applied correctly to an unbounded chain is a way to
            // spend the process, and the bound is the same one every guarded fetch gets.
            net_guard::refuse_hop_overflow(hops, url.as_str(), policy.guard())?;
            let location = resp
                .location
                .as_deref()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .ok_or_else(|| FetchRefusal::RedirectWithoutLocation {
                    at: url.to_string(),
                    status: resp.status,
                })?;
            // Resolved RELATIVE TO THE HOP THAT SENT IT, which is what a client does, so a relative
            // `Location` cannot be mistaken for an absolute one and quietly land on a default host.
            let next = url.join(location).map_err(|_| {
                // An unparseable Location is a refusal, never a silent stop at the 3xx: stopping
                // would return "no card here" for what is actually a malformed redirect.
                FetchRefusal::RedirectWithoutLocation {
                    at: url.to_string(),
                    status: resp.status,
                }
            })?;
            current = next.to_string();
            hops += 1;
            continue;
        }

        if !(200..300).contains(&resp.status) {
            return Err(FetchRefusal::Status {
                url: url.to_string(),
                status: resp.status,
            });
        }

        // THE BODY CAP IS CORE'S, and it is applied BEFORE the bytes are parsed.
        net_guard::refuse_oversized_body(url.as_str(), resp.body.len(), policy.guard())?;
        let document: serde_json::Value =
            serde_json::from_slice(&resp.body).map_err(|e| FetchRefusal::NotACard {
                url: url.to_string(),
                err: e.to_string(),
            })?;
        if !document.is_object() {
            return Err(FetchRefusal::NotACard {
                url: url.to_string(),
                err: "the document is not a JSON object".to_string(),
            });
        }
        return Ok(FetchedCard {
            document,
            chain,
            addr: pin.addr(),
            peer_spki: resp.peer_spki,
            client_identity_offered: resp.client_identity_offered,
        });
    }
}

#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/fetch_tests.rs"]
mod fetch_tests;
