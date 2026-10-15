// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARDS BUSBAR SERVES, as the engine served them (`busbar-a2a`'s `serve.rs`, moved): busbar's
//! own card at the well-known path, and a fronted agent's card with every URL rewritten through
//! busbar. Pure: the document is built here and signed by the caller's [`Signer`], which reaches the
//! host's `sign` service (the plane holds no signing key).
//!
//! ## The backend URL is the one thing that must not be published
//!
//! A caller reaching a fronted agent talks to busbar, and busbar authenticates, authorises, meters
//! and provenances the task. Publishing the backend endpoint publishes the way around all of that.
//! So [`rewrite_card`] rewrites every endpoint member, sweeps every URL-shaped string at every depth
//! whose host is the backend's, and REFUSES a card that still names the backend authority after the
//! sweep.
//!
//! ## The card describes BUSBAR, so it advertises only the bindings busbar serves AT ITS ADDRESS
//!
//! Busbar's own card points at the plane's mount, where the JSON-RPC envelope, the HTTP+JSON paths
//! and (at the gRPC service path) the gRPC binding answer ([`SERVABLE_BINDINGS`]). A fronted agent's
//! card points at `/a2a/agents/{id}`, where only the JSON-RPC envelope is mounted
//! ([`AGENT_ADDRESS_BINDINGS`]); an entry whose binding busbar cannot serve there is dropped, and a
//! card left with no interface at all is refused.
//!
//! ## The vendor's signature is REMOVED, and BUSBAR'S REPLACES IT; its schemes are REPLACED
//!
//! A rewritten card is no longer the document the vendor signed, so its signature is dropped and
//! busbar signs the document it publishes, over the same canonicalisation it demands of every card it
//! verifies. The backend's security schemes describe how to reach the BACKEND; the served card
//! advertises exactly busbar's own inbound credential, in the normative proto spelling.

use serde_json::{json, Map, Value};

/// The security-scheme NAME busbar advertises on every card it serves.
pub const INBOUND_SCHEME_NAME: &str = "busbarA2aInbound";

/// The HTTP header an inbound A2A caller presents its busbar credential on.
pub const INBOUND_HEADER: &str = "authorization";

/// The RFC 7235 authentication scheme a caller presents on [`INBOUND_HEADER`].
pub const INBOUND_AUTH_SCHEME: &str = "Bearer";

/// The credential kind an inbound A2A caller presents.
pub const CREDENTIAL_KIND_A2A_INBOUND: &str = "a2a_inbound";

/// THE BINDINGS BUSBAR SERVES AT THE PLANE'S OWN MOUNT, in the card's spelling (the plane's
/// wire-format names upper-cased, the canonical one first).
pub const SERVABLE_BINDINGS: &[&str] = &["JSONRPC", "HTTP+JSON", "GRPC"];

/// THE BINDINGS BUSBAR SERVES AT ONE FRONTED AGENT'S ADDRESS (`/a2a/agents/{id}`): the JSON-RPC
/// envelope alone. The gRPC binding answers for the plane, never for one agent, and the HTTP+JSON
/// binding spells its operation in a request line no per-agent path carries.
pub const AGENT_ADDRESS_BINDINGS: &[&str] = &["JSONRPC"];

/// The gRPC binding's card spelling.
const GRPC_BINDING: &str = "GRPC";

/// The `cache-control` busbar's own card is served with.
pub const OWN_CARD_CACHE_CONTROL: &str = "public, max-age=3600";

/// The media type busbar's own card is served as.
pub const OWN_CARD_MEDIA_TYPE: &str = "application/json; charset=utf-8";

/// SIGNS A CARD'S SIGNING INPUT: the key id the signature is under, and the signature bytes.
pub trait Signer {
    /// The key id signatures are made under; `None` when the deployment holds no signing key.
    fn kid(&mut self) -> Option<String>;
    /// The signature over `input`; `None` when no signature could be made.
    fn sign(&mut self, input: &[u8]) -> Option<Vec<u8>>;
}

/// Unpadded base64url (RFC 7515 section 2), over the contract's one base64 alphabet.
#[must_use]
pub fn b64url(bytes: &[u8]) -> String {
    busbar_contract::media::base64_encode(bytes)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// SIGN `card` with busbar's key: the card with busbar's signature under `signatures`, any earlier
/// one replaced. A deployment with no signing key serves the card unsigned (`Ok(card)`); a key that
/// would not sign refuses (`Err`), so a served card's missing signature always means "no key".
///
/// # Errors
///
/// The card cannot be canonicalised, or the key would not sign.
pub fn sign_card(card: &Value, signer: &mut dyn Signer) -> Result<Value, String> {
    let Some(kid) = signer.kid() else {
        return Ok(card.clone());
    };
    let payload = crate::a2a::card::signing_payload(card)
        .map_err(|e| format!("cannot sign the agent card: {e}"))?;
    let payload_b64 = b64url(payload.as_bytes());
    let protected = crate::a2a::canonical::canonicalize(&json!({ "alg": "EdDSA", "kid": kid }))
        .map_err(|e| format!("cannot sign the agent card: {e}"))?;
    let protected_b64 = b64url(protected.as_bytes());
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let signature = signer.sign(signing_input.as_bytes()).ok_or_else(|| {
        "cannot sign the agent card: the host holds no card-signing key".to_string()
    })?;
    let mut out: Map<String, Value> = card
        .as_object()
        .ok_or_else(|| "cannot sign the agent card: the card is not a JSON object".to_string())?
        .clone();
    out.insert(
        "signatures".to_string(),
        json!([{ "protected": protected_b64, "signature": b64url(&signature) }]),
    );
    Ok(Value::Object(out))
}

/// THE ADDRESS A gRPC CLIENT IS GIVEN: the AUTHORITY of `public_url` (`host:port`), not a URL.
#[must_use]
pub fn grpc_endpoint(public_url: &str) -> Option<String> {
    let u = url::Url::parse(public_url).ok()?;
    let host = u.host_str()?;
    Some(match u.port_or_known_default() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// The URL a served card publishes for one binding: gRPC takes the authority, every other binding
/// the busbar address `http_endpoint` its HTTP bindings answer at.
fn binding_url(binding: &str, public_url: &str, http_endpoint: &str) -> Option<String> {
    if binding.eq_ignore_ascii_case(GRPC_BINDING) {
        return grpc_endpoint(public_url);
    }
    Some(http_endpoint.to_string())
}

/// THE PATH busbar mounts a fronted agent on, absolute.
#[must_use]
pub fn agent_endpoint(public_url: &str, agent_id: &str) -> Option<String> {
    crate::a2a::public::absolute(
        public_url,
        &crate::mounted_route(&crate::ROUTE_AGENT.replace("{agent_id}", agent_id)),
    )
}

/// THE ONE DESCRIPTION of how a caller authenticates to this plane (proto `SecurityScheme`, a
/// oneof whose variant key names the mechanism).
fn inbound_security_schemes() -> Map<String, Value> {
    let mut schemes = Map::new();
    schemes.insert(
        INBOUND_SCHEME_NAME.to_string(),
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

/// Proto `AgentCard.security_requirements`: this scheme, no scopes.
fn inbound_security_requirement() -> Value {
    json!([{ "schemes": { INBOUND_SCHEME_NAME: { "list": [] } } }])
}

/// THE INTERFACES BUSBAR PUBLISHES: every binding it serves, at every protocol version it admits,
/// newest version first.
fn published_interfaces(public_url: &str) -> Option<Vec<Value>> {
    let http_endpoint = crate::a2a::public::absolute(public_url, crate::MOUNT_PATH)?;
    let mut versions: Vec<&str> = crate::agent_arrival::SUPPORTED_VERSIONS.to_vec();
    versions.reverse();
    let mut out = Vec::new();
    for binding in SERVABLE_BINDINGS {
        let url = binding_url(binding, public_url, &http_endpoint)?;
        for version in &versions {
            out.push(json!({
                "url": url,
                "protocolBinding": binding,
                "protocolVersion": version,
            }));
        }
    }
    Some(out)
}

/// BUSBAR'S OWN CARD AS A DOCUMENT, before signing, with `skills`: the public card carries none
/// (no fronted agent is enumerated from an unauthenticated path), the extended card the caller's.
/// `None` when `public_url` is not a URL.
#[must_use]
pub fn self_card_document(public_url: &str, skills: Vec<Value>) -> Option<Value> {
    Some(json!({
        "name": "busbar",
        "description":
            "An AI gateway. Agents reach the agents busbar fronts through this endpoint; busbar \
             authorises, meters and records every task. The agents themselves are not listed on \
             the public card — an authenticated caller is shown the ones it may reach.",
        "version": crate::agent_door::VERSION,
        "provider": { "organization": "busbar", "url": "https://getbusbar.com" },
        "supportedInterfaces": published_interfaces(public_url)?,
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "capabilities": {
            "streaming": true,
            "pushNotifications": true,
            "extendedAgentCard": true,
        },
        "skills": skills,
        "securitySchemes": Value::Object(inbound_security_schemes()),
        "securityRequirements": inbound_security_requirement(),
    }))
}

/// Why a fronted agent's card could not be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeError {
    /// The cached backend card is not a JSON object, or the public base is not a URL.
    Unbuildable(String),
    /// The backend offers no interface busbar can serve at the agent's address.
    NoServableBinding,
    /// The backend authority still appears after the rewrite.
    BackendLeak(Vec<String>),
}

/// REWRITE a fronted agent's backend card into the card busbar serves (before signing).
///
/// # Errors
///
/// [`ServeError`]: a card that is no object, a public base that is no URL, a card with no binding
/// busbar serves at the agent's address, or a backend authority the sweep could not remove.
pub fn rewrite_card(
    backend_card: &Value,
    backend_url: &str,
    public_url: &str,
    agent_id: &str,
) -> Result<Value, ServeError> {
    let obj = backend_card
        .as_object()
        .ok_or_else(|| ServeError::Unbuildable("the card is not a JSON object".to_string()))?;
    let endpoint = agent_endpoint(public_url, agent_id).ok_or_else(|| {
        ServeError::Unbuildable(format!("`public_url` is not a URL (`{public_url}`)"))
    })?;
    let backend_host = url::Url::parse(backend_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_lowercase));
    let can_serve = |b: &str| {
        AGENT_ADDRESS_BINDINGS
            .iter()
            .any(|f| f.eq_ignore_ascii_case(b))
    };

    let mut out = obj.clone();
    if let Some(Value::Array(interfaces)) = out.get_mut("supportedInterfaces") {
        let offered_any = !interfaces.is_empty();
        interfaces.retain(|iface| match iface.get("protocolBinding") {
            Some(Value::String(b)) => can_serve(b),
            _ => true,
        });
        if offered_any && interfaces.is_empty() {
            return Err(ServeError::NoServableBinding);
        }
        for iface in interfaces.iter_mut() {
            let binding = iface
                .get("protocolBinding")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if let Some(iface) = iface.as_object_mut() {
                if iface.contains_key("url") {
                    let url = binding_url(&binding, public_url, &endpoint).ok_or_else(|| {
                        ServeError::Unbuildable(format!(
                            "`public_url` is not a URL (`{public_url}`)"
                        ))
                    })?;
                    iface.insert("url".to_string(), Value::String(url));
                }
            }
        }
    }
    if out.contains_key("url") {
        out.insert("url".to_string(), Value::String(endpoint.clone()));
    }
    out.remove("signatures");
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
    // THE AGENT'S OWN CAPABILITIES, as it states them: busbar relays a fronted agent's extended
    // card read to the agent itself, so the served card may promise one only where the agent's
    // card does. A card stating none is served with an empty `capabilities` (the member the card
    // shape requires), claiming nothing on the agent's behalf.
    if !matches!(out.get("capabilities"), Some(Value::Object(_))) {
        out.insert("capabilities".to_string(), json!({}));
    }
    let mut served = Value::Object(out);
    if let Some(host) = backend_host.as_deref() {
        rewrite_backend_urls(&mut served, host, &endpoint);
        let mut remaining = Vec::new();
        collect_mentions(&served, host, &endpoint, &mut remaining);
        if !remaining.is_empty() {
            return Err(ServeError::BackendLeak(remaining));
        }
    }
    Ok(served)
}

/// ONE FRONTED AGENT A CALLER IS ENTITLED TO, as the extended card needs it.
pub struct EntitledAgent<'a> {
    /// The operator's id for the agent: the id the caller addresses.
    pub agent_id: &'a str,
    /// The real backend endpoint; never published, scanned for.
    pub backend_url: &'a str,
    /// The backend's card as held, for its name, description and modes.
    pub card: Option<&'a Value>,
}

/// BUSBAR'S EXTENDED CARD (before signing): busbar's own card with one skill per agent the caller
/// is entitled to, each identified by busbar's agent id; an agent whose card names its backend in
/// text busbar cannot rewrite is omitted.
#[must_use]
pub fn extended_card_document(public_url: &str, entitled: &[EntitledAgent<'_>]) -> Option<Value> {
    let skills = entitled.iter().filter_map(agent_skill).collect();
    self_card_document(public_url, skills)
}

/// One entitled agent as a skill, or `None` where publishing it would name the backend.
fn agent_skill(agent: &EntitledAgent<'_>) -> Option<Value> {
    let parsed = agent
        .card
        .and_then(crate::a2a::agent_card::parse)
        .unwrap_or_default();
    let skill = json!({
        "id": agent.agent_id,
        "name": if parsed.name.is_empty() { agent.agent_id } else { parsed.name.as_str() },
        "description": parsed.description,
        "tags": ["agent"],
        "inputModes": parsed.default_input_modes,
        "outputModes": parsed.default_output_modes,
    });
    let host = url::Url::parse(agent.backend_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_lowercase))?;
    let mut mentions = Vec::new();
    collect_mentions(&skill, &host, "", &mut mentions);
    mentions.is_empty().then_some(skill)
}

/// Replace every URL-shaped string whose host is the backend's with busbar's endpoint, at every
/// depth (member names are never rewritten).
fn rewrite_backend_urls(v: &mut Value, backend_host: &str, endpoint: &str) {
    match v {
        Value::String(s) => {
            if url::Url::parse(s)
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

/// Every remaining mention of the backend host, with its JSON path; busbar's own endpoint (`ours`,
/// exact) is never a mention.
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
#[path = "tests/served_card_tests.rs"]
mod tests;
