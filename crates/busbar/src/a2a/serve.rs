// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RECEIVING: busbar SERVES its fronted agents' Agent Cards, with every URL rewritten
//! through busbar.
//!
//! ## The backend URL is the one thing that must not be published
//!
//! A caller reaching a fronted agent talks to busbar, and busbar authenticates, authorises, meters
//! and provenances the task. Publishing the backend endpoint publishes the way around all of that.
//! So the rewrite is not cosmetic and it is not "mostly": [`rewrite_card`] rewrites every endpoint
//! member, and `tests/serve_tests.rs` walks the whole served document — every string at every
//! depth, including members busbar does not model — and fails if the backend authority appears
//! anywhere in it.
//!
//! ## The vendor's signature is REMOVED, and BUSBAR'S REPLACES IT
//!
//! A card busbar has rewritten is no longer the document the vendor signed, so the vendor's
//! signature over it cannot verify. Carrying it would publish a signature that fails, which is
//! worse than publishing none: a client that checks would reject busbar's card, and a client that
//! does not check is being shown a credential-shaped member that means nothing. So `signatures` is
//! dropped — and then busbar signs the document it is actually publishing, with its own
//! ([`super::sign::CardSigner`]) key, over the SAME canonicalisation busbar demands of every card
//! it verifies. An external caller therefore has something to pin busbar BY, which is what makes
//! busbar the trusted-issuer side of its own trust model rather than only the verifier side.
//!
//! The signature is attached LAST, after the rewrite and after the leak check. Signing earlier
//! would sign a document that is not the one served, and a signature over a different document is
//! the failure this whole member exists to avoid.
//!
//! Signing is OPTIONAL AT THE SEAM and refuses nothing: a deployment with no signing key (the
//! governance-off test path) serves the card unsigned rather than serving no card. That is stated
//! rather than silent, because the alternative — refusing to serve — would turn "this deployment
//! has no governance" into "this deployment has no A2A", which is a different decision than the one
//! being made here.
//!
//! ## The backend's `securitySchemes` are REPLACED, not merged
//!
//! The backend's schemes describe how to authenticate TO THE BACKEND, which no external caller ever
//! reaches. Publishing them would tell a caller to present a credential to busbar that busbar does
//! not accept, and would leak the backend's auth posture. The served card advertises exactly one
//! scheme: busbar's own `a2a_inbound` credential.

use serde_json::{json, Map, Value};

use super::card::CardError;
use super::inbound::CREDENTIAL_KIND_A2A_INBOUND;

/// The security-scheme NAME busbar advertises on every card it serves. Fixed rather than
/// per-agent: a caller reads one name across every fronted agent in a deployment.
pub(crate) const INBOUND_SCHEME_NAME: &str = "busbarA2aInbound";

/// The HTTP header an inbound A2A caller presents its busbar credential on.
pub(crate) const INBOUND_HEADER: &str = "authorization";

/// Why a card could not be served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ServeError {
    /// The cached backend card is not a JSON object.
    Card(CardError),
    /// busbar's own public URL is not a URL, so there is nothing to rewrite TO. Refused rather than
    /// served un-rewritten: serving the backend's own endpoints because our base URL was
    /// misconfigured is the failure this whole module exists to prevent.
    BadPublicUrl(String),
    /// The rewritten card could not be signed. Refused rather than served unsigned: a deployment
    /// that HAS a signing key and failed to use it would be publishing a card whose missing
    /// signature is indistinguishable, to a caller, from a deployment that never had one.
    Sign(super::sign::SignError),
    /// The backend authority still appears in the card after the rewrite, at the named paths.
    ///
    /// Refused rather than served with a warning. The served card's entire purpose is to point
    /// callers at busbar, and one that also tells them where the backend is has handed a caller the
    /// way around every control busbar applies.
    BackendLeak {
        agent_id: String,
        host: String,
        at: Vec<String>,
    },
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeError::Card(e) => write!(f, "{e}"),
            ServeError::Sign(e) => write!(f, "{e}"),
            ServeError::BadPublicUrl(u) => write!(
                f,
                "cannot serve an agent card: `public_url` is not a URL (`{u}`), so there is no \
                 busbar endpoint to rewrite the backend's URLs to. Refused rather than served \
                 un-rewritten."
            ),
            ServeError::BackendLeak { agent_id, host, at } => write!(
                f,
                "refusing to serve the card for `{agent_id}`: the backend authority `{host}` still \
                 appears at {at:?} after the rewrite. A served card that names the backend hands a \
                 caller the way around every control busbar applies."
            ),
        }
    }
}

/// THE PATH busbar mounts a fronted agent on. One per agent, derived from the agent id, so a
/// caller's endpoint is stable and says which agent it reaches.
pub(crate) fn agent_endpoint(public_url: &str, agent_id: &str) -> Result<String, ServeError> {
    absolute(public_url, &format!("{MOUNT_PATH}/agents/{agent_id}"))
}

/// THE PLANE'S MOUNT, the one path prefix the A2A plane claims. Every route this plane serves is
/// under it, and [`crate::plane::PlaneDispatch`] matches on it at a segment boundary, so `/a2ax` is
/// somebody else's path.
pub(crate) const MOUNT_PATH: &str = "/a2a";

/// The RFC 9728 protected-resource metadata path for this plane: the well-known prefix with the
/// plane's mount appended, exactly as the sibling plane composes its own.
pub(crate) const METADATA_PATH: &str = "/.well-known/oauth-protected-resource/a2a";

/// THE PLANE'S CANONICAL URI — the RFC 8707 resource indicator a token must be minted FOR to be
/// spendable here, and the audience [`crate::plane::PlaneAdmission`] carries.
///
/// Derived from `public_url` rather than configured separately, and that is the point: the card
/// this plane serves points callers at [`agent_endpoint`], which is derived from the same value.
/// One reading means the audience a caller is told to ask for and the audience busbar demands
/// cannot drift apart, which is precisely the confused-deputy gap an independently configured
/// audience would open.
pub(crate) fn canonical_uri(public_url: &str) -> Result<String, ServeError> {
    absolute(public_url, MOUNT_PATH)
}

/// The absolute URL of this plane's metadata document, as quoted into a `WWW-Authenticate`
/// challenge. Same base, same reading.
pub(crate) fn metadata_url(public_url: &str) -> Result<String, ServeError> {
    absolute(public_url, METADATA_PATH)
}

/// One reading of `public_url`: parse it, replace the path wholesale, drop query and fragment.
///
/// The path is REPLACED rather than joined, so a `public_url` carrying a path of its own cannot
/// produce `/some/prefix/a2a/agents/x` here while the router serves `/a2a/agents/x` — two spellings
/// of one endpoint, one of which 404s.
fn absolute(public_url: &str, path: &str) -> Result<String, ServeError> {
    let mut u = reqwest::Url::parse(public_url)
        .map_err(|_| ServeError::BadPublicUrl(public_url.trim().to_string()))?;
    u.set_path(path);
    u.set_query(None);
    u.set_fragment(None);
    Ok(u.to_string())
}

/// REWRITE a fronted agent's backend card into the card busbar serves.
///
/// The backend document is the input and is never mutated: the cached card is what the fingerprint
/// was taken over, and a rewrite in place would change what an operator approved.
///
/// `backend_url` is taken as well as the card because THE MODELLED FIELDS ARE NOT ENOUGH. The first
/// version of this function rewrote `supportedInterfaces[].url` and the top-level `url`, which is
/// every endpoint the specification defines — and a card carrying
/// `x-vendor-extensions.mirrors[0]: "https://internal-planner.corp.example/a2a/eu"` sailed straight
/// through it, published by busbar, with the backend authority intact. Cards carry unmodelled
/// members by design; a rewrite that only covers the ones busbar parses is a rewrite that covers
/// the cards nobody was trying to leak through.
///
/// `signer` is busbar's own agent-card issuer key. `None` means this deployment holds no signing
/// key at all; see the module note on why that serves an unsigned card rather than refusing.
pub(crate) fn rewrite_card(
    backend_card: &Value,
    backend_url: &str,
    public_url: &str,
    agent_id: &str,
    signer: Option<&super::sign::CardSigner>,
) -> Result<Value, ServeError> {
    let obj = backend_card
        .as_object()
        .ok_or(ServeError::Card(CardError::NotAnObject))?;
    let endpoint = agent_endpoint(public_url, agent_id)?;
    let backend_host = reqwest::Url::parse(backend_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_lowercase));

    let mut out = obj.clone();

    // ── EVERY ENDPOINT MEMBER, rewritten to busbar's. ──
    //
    // `supportedInterfaces[].url` is the modelled one. A top-level `url` is the pre-v0.3 spelling
    // and is rewritten too, because an upstream pinned to an older `protocolVersion` still serves
    // it and a caller reading it would reach the backend directly.
    if let Some(Value::Array(interfaces)) = out.get_mut("supportedInterfaces") {
        for iface in interfaces.iter_mut() {
            if let Some(iface) = iface.as_object_mut() {
                if iface.contains_key("url") {
                    iface.insert("url".to_string(), Value::String(endpoint.clone()));
                }
            }
        }
    }
    if out.contains_key("url") {
        out.insert("url".to_string(), Value::String(endpoint.clone()));
    }

    // ── THE VENDOR'S SIGNATURE, dropped. See the module note. ──
    out.remove("signatures");

    // ── THE SECURITY SCHEMES, replaced. See the module note. ──
    out.insert(
        "securitySchemes".to_string(),
        Value::Object(inbound_security_schemes()),
    );
    out.insert("security".to_string(), inbound_security_requirement());

    // ── AND THEN EVERY OTHER STRING IN THE DOCUMENT, at every depth. ──
    //
    // A sweep rather than a longer list of field names, because the hazard is a member busbar has
    // never heard of. Only URL-SHAPED strings whose host IS the backend's are touched: a description
    // that happens to mention the vendor's public site is not an endpoint, and rewriting it would
    // make busbar's card say something the vendor did not.
    let mut served = Value::Object(out);
    if let Some(host) = backend_host.as_deref() {
        rewrite_backend_urls(&mut served, host, &endpoint);
        // FAIL CLOSED ON WHAT THE SWEEP COULD NOT FIX. A remaining mention is a string that is not
        // a URL busbar can rewrite but still names the backend — a bare authority in a free-text
        // member, say. Serving it anyway would publish the way around busbar in the one document
        // whose entire purpose is to point callers at busbar.
        //
        // BUSBAR'S OWN ENDPOINT IS EXEMPT, and only that exact string. When busbar and the agent it
        // fronts share a host — a sidecar, a single-node deployment, a hermetic rig — the endpoint
        // the rewrite just WROTE contains the backend's authority, and scanning for the authority
        // alone reported busbar's own published URL as a leak of the backend. That refused every
        // card such a deployment could serve, so a co-located busbar could front nothing at all.
        // The string the rewrite itself produced is not a way around busbar; it IS busbar. Every
        // other mention on the same host — a bare authority in free text, a second port — still
        // refuses, which is what `busbars_own_endpoint_is_not_a_leak_when_it_shares_a_host_with_the_backend`
        // asserts in both directions.
        let mut remaining = Vec::new();
        collect_mentions(&served, host, &endpoint, &mut remaining);
        if !remaining.is_empty() {
            return Err(ServeError::BackendLeak {
                agent_id: agent_id.to_string(),
                host: host.to_string(),
                at: remaining,
            });
        }
    }

    // ── AND LAST, BUSBAR'S OWN SIGNATURE, over the document that is actually served. ──
    //
    // After the rewrite and after the leak check, because a signature over anything other than the
    // published bytes is a signature over a document nobody will ever see.
    match signer {
        Some(signer) => Ok(signer.sign_card(&served).map_err(ServeError::Sign)?),
        None => Ok(served),
    }
}

/// THE ONE DESCRIPTION of how a caller authenticates to this plane.
///
/// Shared by the fronted-agent cards and by busbar's own card at the well-known path, because two
/// copies of an auth description drift and the drifted one is the document a client actually reads.
/// The published card is how a caller LEARNS which scheme to present; if it disagrees with what the
/// middleware enforces, every conformant client is wrong through no fault of its own.
fn inbound_security_schemes() -> Map<String, Value> {
    let mut schemes = Map::new();
    schemes.insert(
        INBOUND_SCHEME_NAME.to_string(),
        json!({
            "type": "http",
            "scheme": "bearer",
            "description": format!(
                "A busbar credential of kind `{CREDENTIAL_KIND_A2A_INBOUND}`, presented on the \
                 `{INBOUND_HEADER}` header. busbar authorises it against this fronted agent and \
                 meters the task against the presenting key's budget."
            ),
        }),
    );
    schemes
}

fn inbound_security_requirement() -> Value {
    json!([{ INBOUND_SCHEME_NAME: [] }])
}

/// BUSBAR'S OWN AGENT CARD, served unauthenticated at [`super::card::WELL_KNOWN_CARD_PATH`].
///
/// WHY THIS EXISTS AT ALL. The A2A protocol specification makes it a MUST — "A2A Servers MUST make
/// an Agent Card available" — and names the path `/.well-known/agent-card.json`. Until this existed
/// busbar
/// answered 404 there, which meant busbar was not discoverable by any conformant A2A client: a
/// stock client asks the well-known path FIRST and has nowhere else to look. The conformance
/// battery reported this as `SUBJECT NOT REACHABLE`, and the tempting fix was to point the battery
/// at the mounted path instead. That would have turned the leg green and left the product
/// undiscoverable — the check would have been measuring our harness rather than our conformance.
///
/// WHY IT IS UNAUTHENTICATED. The specification never writes "this path MUST be unauthenticated",
/// and that silence is worth stating rather than papering over. But the two-tier model only works
/// one way round: the public card is what TELLS a caller which schemes to present — the extended
/// card's client "MUST authenticate the request using one of the schemes declared in the public
/// `AgentCard.securitySchemes`", in the specification's own words. Requiring a credential to read
/// the document that names the
/// credential is circular, so this is served with `RouteAuth::None`, exactly like the RFC 9728
/// metadata path next to it.
///
/// WHAT IS DELIBERATELY NOT IN IT — the part that is a SECURITY decision, not a formatting one:
///
///   * **No skills, and no enumeration of the fronted agents.** busbar is a gateway; the skills
///     belong to the agents behind it. Publishing them here would hand an unauthenticated caller
///     the internal agent inventory — every agent id, every capability, every vendor — from a path
///     that by design cannot ask who is asking. The per-agent cards stay behind `RouteAuth::Key`
///     where they already are, and a caller who is entitled to one gets it there.
///   * **`extendedAgentCard: false`.** busbar does not implement `getAuthenticatedExtendedCard`.
///     Claiming a capability the binary does not have is the exact defect this release keeps
///     finding: a document asserting a property nothing tested. When that verb lands, this flips,
///     and not before.
///
/// The card IS signed when this deployment holds a signing key, for the same reason a fronted card
/// is: it gives an external caller something to pin busbar by.
pub(crate) fn self_card(
    public_url: &str,
    signer: Option<&super::sign::CardSigner>,
) -> Result<Value, ServeError> {
    let card = json!({
        "protocolVersion": super::registry::DEFAULT_PROTOCOL_VERSION,
        "name": "busbar",
        "description":
            "An AI gateway. Agents reach the agents busbar fronts through this endpoint; busbar \
             authorises, meters and records every task. The agents themselves are not listed here \
             — ask for the one you are entitled to at the per-agent card path.",
        "version": env!("CARGO_PKG_VERSION"),
        "provider": { "organization": "busbar" },
        "supportedInterfaces": [
            { "url": canonical_uri(public_url)?, "protocolBinding": "JSONRPC" }
        ],
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "capabilities": {
            "streaming": true,
            "pushNotifications": true,
            "stateTransitionHistory": true,
            "extendedAgentCard": false,
        },
        "skills": [],
        "securitySchemes": Value::Object(inbound_security_schemes()),
        "security": inbound_security_requirement(),
    });

    match signer {
        Some(signer) => Ok(signer.sign_card(&card).map_err(ServeError::Sign)?),
        None => Ok(card),
    }
}

/// Replace every URL-shaped string whose host is the backend's with busbar's endpoint, at every
/// depth. Object KEYS are deliberately not rewritten: a key is a member name, and renaming one
/// changes the document's shape rather than where it points.
fn rewrite_backend_urls(v: &mut Value, backend_host: &str, endpoint: &str) {
    match v {
        Value::String(s) => {
            if reqwest::Url::parse(s)
                .ok()
                .and_then(|u| u.host_str().map(str::to_lowercase))
                .is_some_and(|h| h == backend_host)
            {
                *s = endpoint.to_string();
            }
        }
        Value::Array(a) => a
            .iter_mut()
            .for_each(|x| rewrite_backend_urls(x, backend_host, endpoint)),
        Value::Object(o) => o
            .values_mut()
            .for_each(|x| rewrite_backend_urls(x, backend_host, endpoint)),
        _ => {}
    }
}

/// Every remaining mention of the backend host, with the JSON path it sits at, so the refusal names
/// the member an operator has to look at rather than merely that one exists.
///
/// `ours` is busbar's OWN published endpoint, and a string equal to it is never a mention: see the
/// note at the call site. The comparison is exact equality, not a prefix or a host match — anything
/// looser would exempt the very free-text mention the scan exists to catch.
fn collect_mentions(v: &Value, backend_host: &str, ours: &str, out: &mut Vec<String>) {
    fn walk(v: &Value, host: &str, ours: &str, path: &str, out: &mut Vec<String>) {
        match v {
            Value::String(s) => {
                if s != ours && s.to_lowercase().contains(host) {
                    out.push(path.to_string());
                }
            }
            Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    walk(x, host, ours, &format!("{path}[{i}]"), out);
                }
            }
            Value::Object(o) => {
                for (k, x) in o {
                    if k.to_lowercase().contains(host) {
                        out.push(format!("{path}.{k} (member NAME)"));
                    }
                    walk(x, host, ours, &format!("{path}.{k}"), out);
                }
            }
            _ => {}
        }
    }
    walk(v, backend_host, ours, "$", out);
}

#[cfg(test)]
#[path = "tests/serve_tests.rs"]
mod serve_tests;
