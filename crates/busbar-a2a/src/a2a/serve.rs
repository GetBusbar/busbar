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
//! ## The card describes BUSBAR, so it advertises only the bindings busbar serves
//!
//! Once every interface's `url` is busbar's, the `protocolBinding` beside it is a claim about what
//! BUSBAR speaks at that address, not about the backend. Carrying the backend's through published a
//! gRPC interface at busbar's own endpoint — a protocol busbar does not implement — and
//! `supportedInterfaces` is an ORDERED list a conformant client selects from, so a client picking
//! that entry was directed at busbar for something nothing there answers. It is the same defect as a
//! card advertising an address its own router does not serve, one member down.
//!
//! So an entry whose binding busbar cannot serve is DROPPED, and which bindings those are is read
//! off what busbar MOUNTS rather than named here. A card left with NO interface at all is refused
//! ([`ServeError::NoServableBinding`]) rather than served with an empty list, because that member is
//! the only thing that tells a client how to reach the agent.
//!
//! ## "WHAT BUSBAR SERVES" IS A QUESTION ABOUT AN ADDRESS, and there are two of them
//!
//! Two cards leave this file and they point at different places. [`self_card`] points at the plane's
//! own mount, where both the JSON-RPC envelope and `a2a::rest`'s HTTP+JSON paths are served, so it
//! publishes [`servable_bindings`] — the plane's whole wire-format list, which is why arming a
//! binding on the plane publishes it here with nobody editing this file. [`rewrite_card`] points at
//! ONE fronted agent, `/a2a/agents/{id}`, where the only thing mounted is the JSON-RPC handler, so it
//! publishes [`agent_address_bindings`].
//!
//! Those were the same list while the plane spoke one dialect, and asking one of them for the other's
//! answer is a live defect the moment it grows a second: it publishes an interface at busbar's own
//! address for a binding busbar does not answer THERE, which is the defect this whole section is
//! about, one address down.
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
//!
//! ## And it is spelled the way the NORMATIVE definition spells it
//!
//! SPEC 1.4 makes `a2a.proto` "the single authoritative normative definition of all protocol data
//! objects", and the generated `a2a.json` an explicitly "non-normative build artifact". `SecurityScheme`
//! there is a `oneof` over five variants, so a scheme is `{"httpAuthSecurityScheme": {…}}` and a
//! caller identifies the mechanism by WHICH VARIANT KEY IS SET. busbar used to publish the OpenAPI
//! spelling instead — `{"type": "http", "scheme": "bearer"}` — which sets no variant at all: a
//! conformant client (the A2A project's own SDK parses cards straight into the protobuf message)
//! reads a scheme it cannot classify, so it cannot work out how to authenticate and the first call
//! comes back as an opaque `401` it has no way to act on. The requirement member beside it,
//! `AgentCard.security_requirements` (proto field 9), is a `SecurityRequirement` whose `schemes` is
//! `map<string, StringList>`, so it is `[{"schemes": {"<name>": {"list": []}}}]` and not the sample
//! card's `[{"<name>": []}]`.
//!
//! Both of the backend's spellings are REMOVED before busbar's are inserted. The rewrite passes
//! unmodelled members through by design, so leaving the backend's `security` behind while writing
//! busbar's `securityRequirements` would publish the backend's auth posture beside busbar's — the
//! exact leak the replacement exists to prevent, surviving under the other name.

use busbar_substrate::diag_debug;
use busbar_substrate::diagnostics::A2A_EXTENDED_CARD_AGENT_OMITTED;
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
    /// The backend offers no interface whose `protocolBinding` busbar can serve.
    ///
    /// Refused rather than served with an empty `supportedInterfaces`. That member is where an A2A
    /// client SELECTS its transport, so a card with none says "busbar fronts this agent" and gives
    /// the client no way to reach it — and the alternative, keeping the backend's binding, would
    /// publish a protocol busbar does not speak at an address only busbar answers.
    NoServableBinding {
        agent_id: String,
        /// The bindings the backend offered, in the order the card listed them.
        offered: Vec<String>,
        /// The bindings busbar serves AT THIS AGENT'S ADDRESS, as [`agent_address_bindings`]
        /// reads them off the route mounted there.
        served: Vec<String>,
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
            ServeError::NoServableBinding {
                agent_id,
                offered,
                served,
            } => write!(
                f,
                "refusing to serve the card for `{agent_id}`: it offers {offered:?}, and busbar \
                 serves {served:?}. Publishing an interface at busbar's address for a protocol \
                 busbar does not speak would send a conformant client to an endpoint nothing \
                 answers, and publishing no interface at all would give it nothing to select."
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

/// THE BINDINGS BUSBAR SERVES AT THE PLANE'S OWN MOUNT, read off the A2A plane rather than written
/// down here.
///
/// A card busbar serves points every interface at BUSBAR'S OWN ADDRESS, so the `protocolBinding` on
/// that interface is a claim about what BUSBAR speaks, not about what the backend speaks. The set of
/// protocols busbar speaks on this plane is already stated once, in the A2A plane's registry
/// [`crate::plane::wire_format_names`] — the same list that decides whether the plane has earned a superset IR and what its
/// ingress metric label may say. Reading it here rather than restating it is what makes this
/// function a RULE: when the HTTP+JSON and gRPC bindings land on the A2A plane, that list grows and
/// these cards start advertising them, with nobody having to remember this function exists. Written
/// as a literal `["JSONRPC"]` it would be a fact about today, and the day the plane moved it would
/// quietly keep publishing the pre-change answer — which is exactly the failure mode that put a
/// gRPC interface at busbar's address in the first place.
///
/// The A2A card spelling of a binding is the plane's wire-format name upper-cased (`jsonrpc` →
/// `JSONRPC`, `http+json` → `HTTP+JSON`, `grpc` → `GRPC`), so the servability checks compare
/// case-insensitively and exactly, never by prefix.
pub(crate) fn servable_bindings() -> Vec<String> {
    (super::PLANE_DECL.wire_format_names)()
        .iter()
        .map(|f| f.to_uppercase())
        .collect()
}

/// THE BINDINGS BUSBAR SERVES AT ONE FRONTED AGENT'S ADDRESS, which is a SMALLER set than
/// [`servable_bindings`] — and the two being one answer was a live defect for as long as the plane
/// spoke one dialect.
///
/// `servable_bindings` answers for the PLANE'S mount, which is where busbar's own card points and
/// where `a2a::rest` hangs the HTTP+JSON paths: `/a2a/message:send`, `/a2a/tasks/{id}` and the rest.
/// A fronted agent's card is rewritten to [`agent_endpoint`] — `/a2a/agents/{id}` — and the only
/// thing mounted there is `ingress::invoke`, which reads a JSON-RPC envelope. The HTTP+JSON binding
/// spells its operation in the REQUEST LINE, and under that prefix there is no request line that
/// names one.
///
/// Answering the plane's list here would publish `{"url": "<busbar>/a2a/agents/x",
/// "protocolBinding": "HTTP+JSON"}` — an interface at busbar's own address for a binding busbar does
/// not answer THERE. That is the same defect as the gRPC entry this filter was written to drop, one
/// address down, and it re-entered the moment the plane armed its second binding. See
/// `a_binding_the_plane_serves_only_at_its_own_mount_is_not_published_at_an_agents_address`.
///
/// THE gRPC BINDING IS OUT FOR THE SAME REASON AND NOT A WEAKER ONE. busbar really does serve it,
/// so it is on the PLANE'S list — but it is served at `/lf.a2a.v1.A2AService` for the plane, where
/// the agent is resolved from the caller's catalogue. There is no spelling of a gRPC address that
/// means "this one fronted agent", so publishing it on an agent's card would name an endpoint that
/// answers a different question from the one the card was fetched to answer.
///
/// IT IS DERIVED FROM THE HANDLER, not spelled: the transport `ingress::invoke` labels its requests
/// with is the binding it reads, so this answers that transport's name and cannot drift from what
/// that route actually does. When a per-agent REST mount lands, it lands beside its entry here.
fn agent_address_bindings() -> Vec<String> {
    vec![busbar_substrate::transport::Transport::JsonRpc
        .name()
        .to_uppercase()]
}

/// Whether busbar can serve `binding` at ONE AGENT'S address. See [`agent_address_bindings`].
fn can_serve_binding_for_agent(binding: &str) -> bool {
    agent_address_bindings()
        .iter()
        .any(|f| f.eq_ignore_ascii_case(binding))
}

/// THE PROTOCOL VERSIONS BUSBAR SERVES, read off the ingress that actually admits them.
///
/// `AgentInterface.protocol_version` is a REQUIRED member of the 1.0 card, and busbar's own card
/// carried no interface version at all — so a client reading the card had to guess which semantics
/// the endpoint speaks, and the top-level `protocolVersion` it would have fallen back to said
/// `0.3.0`, which is BOTH the wrong version (busbar admits `1.0` as well) and the wrong spelling
/// (SPEC 3.6: patch numbers "SHOULD NOT be used in requests, responses and Agent Cards").
///
/// Read from [`super::receive::SUPPORTED_A2A_VERSIONS`] rather than written down here, for the same
/// reason [`servable_bindings`] is read off the plane: the card is a claim about what the endpoint
/// admits, and a second list is a second answer to one question. The day the ingress stops speaking
/// a version, the card stops advertising it without anyone remembering this function exists.
fn served_protocol_versions() -> &'static [&'static str] {
    super::receive::SUPPORTED_A2A_VERSIONS
}

/// THE PATH busbar mounts a fronted agent on. One per agent, derived from the agent id, so a
/// caller's endpoint is stable and says which agent it reaches.
pub(crate) fn agent_endpoint(public_url: &str, agent_id: &str) -> Result<String, ServeError> {
    absolute(public_url, &format!("{MOUNT_PATH}/agents/{agent_id}"))
}

/// THE PLANE'S MOUNT, the path prefix the A2A plane's HTTP bindings are served under. Every route
/// this plane serves over HTTP is under it, and [`crate::plane::PlaneDispatch`] matches on it at a
/// segment boundary, so `/a2ax` is somebody else's path.
pub(crate) const MOUNT_PATH: &str = "/a2a";

/// THE PATH PREFIX THE gRPC BINDING IS SERVED AT, and busbar did not choose it.
///
/// gRPC derives a request path from the `.proto`'s package and service name — `lf.a2a.v1` and
/// `A2AService` in the a2aproject's own canonical `a2a.proto`, vendored by `a2a-pb` — and a client
/// is given an AUTHORITY, never a path prefix, so there is no spelling of this that could live under
/// [`MOUNT_PATH`]. Written as a constant beside the mount it is not under, because "the A2A plane
/// answers here too" is a fact the mount table has to be told
/// ([`crate::plane::PlaneDispatch::mount`]) or this binding's tokens go unchecked for audience.
pub(crate) const GRPC_MOUNT_PATH: &str = "/lf.a2a.v1.A2AService";

/// The RFC 9728 protected-resource metadata path for this plane: the well-known prefix with the
/// plane's mount appended, exactly as the sibling plane composes its own.
pub(crate) const METADATA_PATH: &str = "/.well-known/oauth-protected-resource/a2a";

/// THE PLANE'S CANONICAL URI — the RFC 8707 resource indicator a token must be minted FOR to be
/// spendable here, and the audience [`busbar_substrate::plane::PlaneAdmission`] carries.
///
/// Derived from `public_url` rather than configured separately, and that is the point: the card
/// this plane serves points callers at [`agent_endpoint`], which is derived from the same value.
/// One reading means the audience a caller is told to ask for and the audience busbar demands
/// cannot drift apart, which is precisely the confused-deputy gap an independently configured
/// audience would open.
pub(crate) fn canonical_uri(public_url: &str) -> Result<String, ServeError> {
    absolute(public_url, MOUNT_PATH)
}

/// THE ADDRESS A gRPC CLIENT IS GIVEN for this deployment — the AUTHORITY of `public_url`, and
/// deliberately not a URL.
///
/// A2A models its bindings as interfaces of one agent, each with a `url`, and it is tempting to give
/// the gRPC interface the same `<public_url>/a2a` the JSON-RPC one carries. That string is not
/// addressable by any gRPC client: a channel is opened against `host:port` and the RPC path comes
/// from the service descriptor, so a scheme and a path are at best ignored and at worst a name
/// resolution failure. The specification's own gRPC binding says the interface url is the endpoint's
/// authority for exactly this reason.
///
/// So the card publishes the authority, and the two facts a caller needs — WHERE to dial and WHAT
/// to dial for — stay derived from the same `public_url` the JSON-RPC interface and the RFC 8707
/// audience are derived from. One reading, three bindings.
pub(crate) fn grpc_endpoint(public_url: &str) -> Result<String, ServeError> {
    let u = reqwest::Url::parse(public_url)
        .map_err(|_| ServeError::BadPublicUrl(public_url.trim().to_string()))?;
    let host = u
        .host_str()
        .ok_or_else(|| ServeError::BadPublicUrl(public_url.trim().to_string()))?;
    match u.port_or_known_default() {
        Some(port) => Ok(format!("{host}:{port}")),
        None => Ok(host.to_string()),
    }
}

/// THE URL A SERVED CARD PUBLISHES FOR ONE BINDING, which is not the same string for all three.
///
/// `http_endpoint` is the busbar address the HTTP bindings answer at — the plane's own endpoint on
/// busbar's card, a fronted agent's endpoint on a fronted agent's card — and every binding but gRPC
/// takes it verbatim. gRPC takes [`grpc_endpoint`]; see there for why a URL is not addressable.
///
/// It exists as one function because both cards go through it. The first version of the fronted-agent
/// rewrite wrote the HTTP endpoint into EVERY surviving interface, which was right while `GRPC` was
/// a binding busbar filtered OUT — and became, the moment the plane started serving gRPC, the very
/// defect that filter was written to prevent: `{"url": "https://busbar/a2a/agents/x",
/// "protocolBinding": "GRPC"}`, a gRPC interface at an address no gRPC client can dial.
fn binding_url(binding: &str, public_url: &str, http_endpoint: &str) -> Result<String, ServeError> {
    if binding.eq_ignore_ascii_case(busbar_substrate::plane::WIRE_GRPC) {
        return grpc_endpoint(public_url);
    }
    Ok(http_endpoint.to_string())
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
    signer: Option<&super::sign::CardSigner<'_>>,
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
    //
    // AND THE BINDING IS FILTERED, NOT CARRIED. Once the url is busbar's, the entry's
    // `protocolBinding` is a claim about what BUSBAR speaks at that address. Passing the backend's
    // through published `{"url": "<busbar>/a2a/agents/x", "protocolBinding": "GRPC"}` — a gRPC
    // interface at an address busbar does not serve gRPC on. busbar now serves gRPC, and this is
    // STILL that defect: the gRPC binding answers at `/lf.a2a.v1.A2AService` for the plane, not for
    // one fronted agent, so an agent's card advertising it would send a caller somewhere that
    // resolves an agent from the catalogue instead of the one whose card it just read.
    // `supportedInterfaces` is an ORDERED list a client selects from, so that is not a cosmetic
    // surplus: a conformant client picking it is directed at busbar for a protocol nothing there
    // answers.
    //
    // Which bindings survive is [`agent_address_bindings`] — what busbar answers at THIS address —
    // and NOT [`servable_bindings`], which answers for the plane's own mount. The two were the same
    // list while the plane spoke one dialect; see `agent_address_bindings` for what reading the
    // wider one here would publish.
    if let Some(Value::Array(interfaces)) = out.get_mut("supportedInterfaces") {
        let offered: Vec<String> = interfaces
            .iter()
            .filter_map(|i| i.get("protocolBinding")?.as_str().map(str::to_string))
            .collect();
        let offered_any = !interfaces.is_empty();
        interfaces.retain(|iface| match iface.get("protocolBinding") {
            // A named binding busbar cannot serve is dropped: see above.
            Some(Value::String(b)) => can_serve_binding_for_agent(b),
            // An entry naming NO binding makes no claim busbar would be making falsely — the
            // specification's default reading is JSON-RPC, which is what busbar answers at the
            // rewritten address. Kept rather than dropped, so the filter removes false claims only.
            _ => true,
        });
        if offered_any && interfaces.is_empty() {
            return Err(ServeError::NoServableBinding {
                agent_id: agent_id.to_string(),
                offered,
                // What busbar serves AT THE ADDRESS this card would have pointed at. Reporting the
                // plane's wider list would tell an operator busbar speaks HTTP+JSON here and leave
                // them looking for a configuration mistake that does not exist.
                served: agent_address_bindings(),
            });
        }
        // AND EACH SURVIVOR IS POINTED AT THE ADDRESS ITS OWN BINDING IS ANSWERED ON. An entry
        // naming no binding reads as JSON-RPC by the specification's default, which is what the
        // retain above already relies on, so it takes the HTTP endpoint like the JSON-RPC entries.
        //
        // Every survivor takes the HTTP endpoint TODAY, because the retain above admits only the
        // bindings served at THIS address and gRPC is not one of them. It is written as the general
        // question anyway — the one `binding_url` answers for busbar's own card — so that the day
        // `agent_address_bindings` grows an entry, it cannot grow one that publishes a dialable
        // address for a binding no client can dial.
        for iface in interfaces.iter_mut() {
            let binding = iface
                .get("protocolBinding")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if let Some(iface) = iface.as_object_mut() {
                if iface.contains_key("url") {
                    let url = binding_url(&binding, public_url, &endpoint)?;
                    iface.insert("url".to_string(), Value::String(url));
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
    //
    // The backend's requirement member is removed under BOTH of its spellings first. `security` is
    // the sample card's name and `securityRequirements` the proto's; busbar publishes the proto's,
    // and an untouched `security` would ride through the unmodelled-member passthrough and publish
    // the backend's auth posture next to busbar's.
    out.remove("security");
    out.remove("securityRequirements");
    out.insert(
        "securitySchemes".to_string(),
        Value::Object(inbound_security_schemes()),
    );
    out.insert(
        "securityRequirements".to_string(),
        inbound_security_requirement(),
    );

    // ── THE EXTENDED-CARD CAPABILITY, claimed. The verb is BUSBAR'S at this address. ──
    //
    // `GetExtendedAgentCard` is answered by busbar itself, before the catalogue is consulted
    // (`receive.rs`), on every inbound path — including this fronted agent's. The backend's own
    // capability declaration is about the BACKEND's endpoint and rides through the passthrough
    // untouched otherwise, so a backend that (correctly, about itself) declared nothing left this
    // card DENYING a capability the address it points at actually serves. SPEC 3.3.4 makes the
    // false declaration a MUST violation in both directions: a client either misses the
    // authenticated capabilities or, told `false`, must be answered `UnsupportedOperationError` by
    // an endpoint that would happily serve the card. The declaration follows the verb, and the
    // verb here is busbar's — the same rule that already replaces the auth posture above.
    match out.get_mut("capabilities") {
        Some(Value::Object(caps)) => {
            caps.insert("extendedAgentCard".to_string(), Value::Bool(true));
        }
        _ => {
            out.insert(
                "capabilities".to_string(),
                json!({ "extendedAgentCard": true }),
            );
        }
    }

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

/// The RFC 7235 authentication scheme a caller presents on [`INBOUND_HEADER`]. Spelled exactly as
/// the `WWW-Authenticate` challenge an unauthenticated caller receives spells it
/// ([`crate::auth::challenge`]), so the card and the challenge describe one mechanism rather than
/// two.
pub(crate) const INBOUND_AUTH_SCHEME: &str = "Bearer";

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
        // PROTO `SecurityScheme` is a oneof: the VARIANT KEY is what tells a client which of the
        // five mechanisms this is, and it is the only thing that does. See the module note on why
        // the OpenAPI spelling this replaced classified as none of them.
        //
        // `bearerFormat` is deliberately ABSENT. It is a hint about how the token is shaped, and the
        // honest values are two: busbar's own credential is `bbk_<payload>.<signature>` and is
        // explicitly NOT a JWT (`governance::signing` — no header, no `alg`, therefore no
        // algorithm-confusion surface), while a deployment whose chain names an operator IdP admits
        // that IdP's JWT as well. A card claiming `"JWT"` would be wrong about the first and a card
        // claiming busbar's format would be wrong about the second, so the member is omitted and the
        // description says what to present instead.
        json!({
            "httpAuthSecurityScheme": {
                "scheme": INBOUND_AUTH_SCHEME,
                "description": format!(
                    "A busbar credential of kind `{CREDENTIAL_KIND_A2A_INBOUND}`, presented on the \
                     `{INBOUND_HEADER}` header. busbar authorises it against this fronted agent and \
                     meters the task against the presenting key's budget."
                ),
            }
        }),
    );
    schemes
}

/// PROTO `AgentCard.security_requirements`: a repeated `SecurityRequirement`, whose `schemes` is
/// `map<string, StringList>`. The empty list is "this scheme, no scopes" — busbar scopes a caller by
/// the grants on the presented key, not by an OAuth scope string.
fn inbound_security_requirement() -> Value {
    json!([{ "schemes": { INBOUND_SCHEME_NAME: { "list": [] } } }])
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
///     where they already are, and a caller who is entitled to one gets it there. The agents a
///     caller MAY reach are named on the EXTENDED card ([`extended_card`]), which is the
///     authenticated half of exactly this two-tier split — and which is why the omission here costs
///     a legitimate caller nothing.
///
/// `extendedAgentCard` is `true`, and it is true: [`extended_card`] is the verb behind it. It read
/// `false` for as long as busbar had no such verb, which was the honest position at the time — a
/// document asserting a property nothing tested is the defect this release keeps finding — and it
/// flips here because the verb landed, not because the member looked untidy.
///
/// The card IS signed when this deployment holds a signing key, for the same reason a fronted card
/// is: it gives an external caller something to pin busbar by.
pub(crate) fn self_card(
    public_url: &str,
    signer: Option<&super::sign::CardSigner<'_>>,
) -> Result<Value, ServeError> {
    let card = self_card_document(public_url, Vec::new())?;
    match signer {
        Some(signer) => Ok(signer.sign_card(&card).map_err(ServeError::Sign)?),
        None => Ok(card),
    }
}

/// THE INTERFACES BUSBAR PUBLISHES: every binding it serves, at every protocol version it admits.
///
/// The cross product, and it is a cross product because both axes are real. SPEC 3.6.2: *"Agents
/// CAN expose multiple interfaces for the same transport with different versions under the same or
/// different URLs"* — which is precisely busbar's shape, since one endpoint reads the `A2A-Version`
/// header and answers with the semantics it names.
///
/// ORDERED NEWEST-FIRST, because `supportedInterfaces` is an ordered list whose first entry the
/// specification makes the PREFERRED one. A client that takes the first entry should be steered at
/// the current protocol version rather than at the compatibility one.
fn published_interfaces(public_url: &str) -> Result<Vec<Value>, ServeError> {
    let http_endpoint = canonical_uri(public_url)?;
    let mut versions: Vec<&str> = served_protocol_versions().to_vec();
    versions.reverse();
    let mut out = Vec::new();
    for binding in servable_bindings() {
        // THE ADDRESS THIS BINDING IS ANSWERED ON, which is not one string for all three. The two
        // HTTP bindings take the plane's mount; gRPC takes the AUTHORITY, because a channel is
        // opened against `host:port` and a URL is not dialable. See [`binding_url`].
        let url = binding_url(&binding, public_url, &http_endpoint)?;
        for version in &versions {
            // NO `tenant` MEMBER, and that is a statement rather than an omission. The proto marks
            // it optional and defines it as the value a client puts in the request when calling the
            // agent — for a deployment that partitions its surface by tenant. busbar does not: its
            // routes carry no tenant segment, and every caller's partitioning is its virtual key's
            // scopes, which is a different mechanism entirely. Publishing an EMPTY tenant would be
            // worse than publishing none: a conformant client would echo it and address
            // `/{tenant}/…` with an empty segment, at a path busbar does not serve.
            out.push(json!({
                "url": url,
                "protocolBinding": binding,
                "protocolVersion": version,
            }));
        }
    }
    Ok(out)
}

/// BUSBAR'S OWN CARD AS A DOCUMENT, before signing, with `skills` supplied by the caller.
///
/// One builder for the public card and the extended card, because the ONLY difference between them
/// is that member. Two builders would let the two documents drift on the interfaces they publish,
/// the schemes they demand or the capabilities they claim — and a client that replaced its cached
/// public card with the extended one (which SPEC 3.1.11 tells it to do) would then be holding a
/// different set of claims about the same endpoint.
fn self_card_document(public_url: &str, skills: Vec<Value>) -> Result<Value, ServeError> {
    Ok(json!({
        // NO TOP-LEVEL `protocolVersion`, and its removal is the fix rather than an omission. It
        // said `0.3.0`: a patch number, which SPEC 3.6 says a card must not carry, naming a version
        // busbar was no longer alone in speaking. The 1.0 `AgentCard` has no such member at all —
        // the version moved ONTO each interface, which is where `published_interfaces` now puts it,
        // and the specification's own sample card (SPEC 8.5) carries none either. Publishing one
        // version for an endpoint that admits two was the defect; publishing it per interface says
        // the true thing, including to the 0.3 client, which finds a `0.3` interface waiting.
        "name": "busbar",
        "description":
            "An AI gateway. Agents reach the agents busbar fronts through this endpoint; busbar \
             authorises, meters and records every task. The agents themselves are not listed on \
             the public card — an authenticated caller is shown the ones it may reach.",
        "version": env!("CARGO_PKG_VERSION"),
        // BOTH members, because the proto marks BOTH `REQUIRED` (`AgentProvider.url`,
        // `AgentProvider.organization` — google.api.field_behavior). A card carrying the
        // organization alone was an incomplete AgentProvider on every conformant reader, and the
        // extended card inherits this member through the one builder.
        "provider": { "organization": "busbar", "url": "https://getbusbar.com" },
        "supportedInterfaces": published_interfaces(public_url)?,
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        // NO `stateTransitionHistory`, and its absence is the fix rather than an omission — the
        // same fix, one member over, as the top-level `protocolVersion` above. The 1.0
        // `AgentCapabilities` (SPEC 1.4 makes `a2a.proto` normative) defines exactly `streaming`,
        // `push_notifications`, `extensions` and `extended_agent_card`; `state_transition_history`
        // was removed in the revision, so no ProtoJSON reader can parse it and the specification's
        // strict schema refuses a card that carries it — which is what kept the TCK's
        // `CARD-EXT-001` red after the other two members were fixed. The BEHAVIOUR the old member
        // claimed is unchanged and still served: task history is returned per request under
        // `historyLength`, which needs no capability flag.
        "capabilities": {
            "streaming": true,
            "pushNotifications": true,
            "extendedAgentCard": true,
        },
        "skills": skills,
        "securitySchemes": Value::Object(inbound_security_schemes()),
        // `securityRequirements`, NOT `security`. SPEC 1.4 makes `a2a.proto` normative and
        // `a2a.json` an explicitly non-normative build artifact, and the proto spells this member
        // `securityRequirements`. The `security` spelling comes from the sample card, and the TCK's
        // own `CARD-EXT-001` validator rejects it by name — so the two branches that met here had
        // independently found the two halves of one answer: one renamed the member, the other
        // measured the rejection.
        "securityRequirements": inbound_security_requirement(),
    }))
}

/// ONE FRONTED AGENT THIS CALLER IS ENTITLED TO, as the extended card needs it.
pub(crate) struct EntitledAgent<'a> {
    /// The OPERATOR's id for the agent. This is the id the caller addresses
    /// (`/a2a/agents/{agent_id}`) and the id `scope_allowed("agent", …)` is asked about, so it is
    /// the only identifier the extended card publishes for it.
    pub(crate) agent_id: &'a str,
    /// The REAL backend endpoint. Never published; taken so the leak sweep has a host to scan for,
    /// exactly as [`rewrite_card`] takes it.
    pub(crate) backend_url: &'a str,
    /// The backend's card AS CACHED, for the human-readable name and description.
    pub(crate) card: Option<&'a Value>,
}

/// BUSBAR'S EXTENDED AGENT CARD — `GetExtendedAgentCard` / `agent/getAuthenticatedExtendedCard`.
///
/// # WHAT BUSBAR PUBLISHES HERE, AND WHY IT IS NOT THE BACKENDS' CARDS MERGED
///
/// For an ordinary agent the extended card is "the same card with more detail". For a GATEWAY it is
/// a MERGE across upstreams, and a merge is a data-exposure decision before it is a conformance
/// one: the naive implementation unions every fronted agent's `skills[]` and hands every
/// authenticated caller the whole inventory — every agent id, every capability, every vendor —
/// including the agents that caller may not invoke. That is not a conformance miss, it is one
/// tenant reading another's.
///
/// So the answer is built from the CALLER'S OWN CATALOGUE and nothing else. The entries are exactly
/// the registrations `scope_allowed("agent", …)` admits for this key — the same judgement that
/// decides dispatch — so the card cannot promise what a submission would refuse, and cannot show a
/// caller an agent it could not have reached anyway.
///
/// # ONE SKILL PER AGENT, IDENTIFIED BY BUSBAR'S OWN AGENT ID
///
/// The backends' own `skills[]` are deliberately NOT republished, and the reason is mechanical
/// rather than aesthetic. Skill ids are upstream-authored and namespaced by nothing, so two fronted
/// vendors both declaring `summarise` produce two entries with one id. That is not merely confusing:
/// [`super::card::skill_digests`] REFUSES a card with a duplicate skill id, so a peer verifying
/// busbar's card by the same rule busbar applies to everyone else's would reject it outright.
/// Namespacing them (`planner/summarise`) would fix the collision and break the thing they are for,
/// because `metadata.skill` is matched against the backend's own id by
/// [`super::registry::judge`].
///
/// One skill per AGENT has neither problem: agent ids are unique by construction (they are the
/// operator's own keys), and the id published is the one the caller actually addresses. A caller
/// that wants the agent's declared skills fetches that agent's card at the per-agent path, which it
/// is already entitled to do.
///
/// # THE BACKEND AUTHORITY IS SCANNED FOR HERE TOO
///
/// The name and description come from a vendor-authored document, so the same hazard
/// [`rewrite_card`] exists for applies: a description naming the backend host publishes the way
/// around busbar. Each agent's contribution is scanned against ITS OWN backend host and DROPPED if
/// it mentions it — dropped rather than refusing the whole card, because one upstream's careless
/// prose must not be able to deny every other agent's entry to every caller.
pub(crate) fn extended_card(
    public_url: &str,
    entitled: &[EntitledAgent<'_>],
    signer: Option<&super::sign::CardSigner<'_>>,
) -> Result<Value, ServeError> {
    let mut skills = Vec::new();
    for agent in entitled {
        let Some(skill) = agent_skill(agent) else {
            continue;
        };
        skills.push(skill);
    }
    let card = self_card_document(public_url, skills)?;
    match signer {
        Some(signer) => Ok(signer.sign_card(&card).map_err(ServeError::Sign)?),
        None => Ok(card),
    }
}

/// One entitled agent as a skill, or `None` where publishing it would name the backend.
fn agent_skill(agent: &EntitledAgent<'_>) -> Option<Value> {
    let parsed = agent
        .card
        .and_then(|c| super::card::parse(c).ok())
        .unwrap_or_default();
    let skill = json!({
        "id": agent.agent_id,
        // The vendor's own words where it has them, and busbar's id where it does not. An empty
        // name is a required member with nothing in it, which is a card a strict client rejects.
        "name": if parsed.name.is_empty() { agent.agent_id } else { parsed.name.as_str() },
        "description": parsed.description,
        // TAGS GROUP; IDENTITY IDENTIFIES. Every entry here is one fronted agent, which is the
        // group, and the id above is the identity.
        "tags": ["agent"],
        "inputModes": parsed.default_input_modes,
        "outputModes": parsed.default_output_modes,
    });
    // THE SAME LEAK CHECK THE SERVED CARD GETS, per agent, over the strings this entry contributes.
    // `rewrite_card`'s sweep cannot cover this: it runs over one backend's document against one
    // backend's host, and this document is many backends' text in one place.
    let host = reqwest::Url::parse(agent.backend_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_lowercase))?;
    let mut mentions = Vec::new();
    collect_mentions(&skill, &host, "", &mut mentions);
    if mentions.is_empty() {
        Some(skill)
    } else {
        diag_debug!(
            A2A_EXTENDED_CARD_AGENT_OMITTED,
            agent = %agent.agent_id,
            at = ?mentions,
            "a2a: an agent is omitted from the extended card because its card names the backend \
             authority in text busbar cannot rewrite"
        );
        None
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

#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/serve_tests.rs"]
mod serve_tests;
