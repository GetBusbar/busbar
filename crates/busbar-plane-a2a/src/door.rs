// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE'S DOOR, its declarations: what the plane states once in its Statement tail, what
//! each generation publishes in its snapshot, and how `validate`/`open` read the settings blob.
//!
//! ## What the kernel hands the plane
//!
//! The settings blob is the plane's own section value — the `agents:` map — as JSON, with the
//! kernel's reserved sub-keys already read and stripped (`BUSBAR-1.6.0.md` THE DESIGN, "Config"): the
//! hook bindings and `upstream_credentials` never reach the plane, and neither do the kernel-owned
//! trust keys each entry carries ([`crate::a2a::config::TRUST_KEYS`]), which the kernel parses and
//! judges first. The plane judges the rest with the same grammar the engine uses,
//! [`crate::a2a::config::AgentsCfg`] and [`crate::a2a::config::validate_agent`].
//!
//! ## What is written down here and pinned elsewhere
//!
//! The tail's strings, the route table and the admin routes are stated here as constants. The
//! engine that still serves A2A states the same facts in its own declaration and router, and a
//! test on the engine's side pins the two equal, entry by entry, until the engine is gone.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{KindTailHead, Section, SECTION_DECLARING};
use busbar_contract::abi::plane::{
    AdminRoute, BillableClass, PinMechanism, PlaneTail, TrustKey, CLAIM_EXACT, CLAIM_OPEN,
    CLAIM_PATTERN, INGRESS_REQUEST_RESPONSE, INGRESS_RESPONSE_STREAM, MECHANISM_ROOT,
    PIN_FINGERPRINT, SHAPE_PIECEWISE, TRUST_PIN, TRUST_RECOVERY_BACKOFF, TRUST_REVERIFY_TTL,
};
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::publish::{AdminRouteSpec, ClaimSpec, SnapshotSpec};

use crate::a2a::config::{
    AgentsCfg, DEFAULT_REVERIFY_TTL, REFUSE_PASSTHROUGH_SECTION, SUBJECT_NOUN,
};
use crate::claims::{DOCUMENT_TRANSPORT, FRAMED_TRANSPORT};
use crate::surface::{BINDING_DOCUMENT, BINDING_FRAMED, BINDING_TARGET};

/// The grant kind that admits traffic on this plane: one registered agent.
pub const SCOPE: &str = "agent";
/// The plane's human label.
pub const LABEL: &str = "A2A";
/// The singular noun for one registration in the `agents:` section, in admin responses.
pub const ADMIN_NOUN: &str = "agent";
/// The record resource kind a registration is audited under.
pub const AUDIT_KIND: &str = "a2a_agent";
/// The versioned domain busbar signs the agent cards it serves under.
pub const CARD_SIGNING_DOMAIN: &str = "a2a/agent-card-signing/v1";
/// The `kid` prefix of busbar's card signatures.
pub const CARD_KID_PREFIX: &str = "busbar-a2a-card-";
/// The one billable class a hop's moved bytes are counted in, and its family.
pub const BYTES_FAMILY: &str = "byte";
/// The fee unit this plane declares: one per request.
pub const FEE_PER_REQUEST: &str = busbar_contract::plane::PER_REQUEST;
/// The recovery backoff an entry that spells none gets: fifteen minutes.
pub const DEFAULT_RECOVERY_BACKOFF: &str = "15m";

/// An absent string.
const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The plane's settings sections, as its Statement states them: `agents:` is the one it declares.
pub const SECTIONS: &[Section] = &[Section {
    name: abi_str(crate::CONFIG_SECTION),
    flags: SECTION_DECLARING,
    _reserved: 0,
}];

/// The three bindings, in the order the engine names its wire formats.
const DIALECTS: &[AbiStr] = &[
    abi_str(BINDING_DOCUMENT),
    abi_str(BINDING_TARGET),
    abi_str(BINDING_FRAMED),
];

const SCOPE_KINDS: &[AbiStr] = &[abi_str(SCOPE)];

const BILLABLE_CLASSES: &[BillableClass] = &[BillableClass {
    class: abi_str(crate::meta::CLASS_BYTES.as_str()),
    family: abi_str(BYTES_FAMILY),
}];

const FEE_UNITS: &[AbiStr] = &[abi_str(FEE_PER_REQUEST)];

const RECORD_KINDS: &[AbiStr] = &[
    abi_str(crate::records::KIND_TASK),
    abi_str(crate::records::KIND_TASK_EVENT),
];

/// The pin's four mechanisms; three are authenticity roots and `unpinned` is not.
const PIN_MECHANISMS: &[PinMechanism] = &[
    PinMechanism {
        token: abi_str("jws_issuer_key"),
        flags: MECHANISM_ROOT,
        _reserved: 0,
    },
    PinMechanism {
        token: abi_str("cert_spki"),
        flags: MECHANISM_ROOT,
        _reserved: 0,
    },
    PinMechanism {
        token: abi_str("mtls"),
        flags: MECHANISM_ROOT,
        _reserved: 0,
    },
    PinMechanism {
        token: abi_str("unpinned"),
        flags: 0,
        _reserved: 0,
    },
];

/// The kernel-owned trust keys of one entry, the ABI spelling of
/// [`crate::a2a::config::TRUST_KEYS`]; declaration order is judgement order.
const TRUST_KEYS: &[TrustKey] = &[
    TrustKey {
        key: abi_str("pin"),
        role: TRUST_PIN,
        flags: PIN_FINGERPRINT,
        default: NONE,
        mechanisms: PIN_MECHANISMS.as_ptr(),
        mechanisms_len: PIN_MECHANISMS.len(),
    },
    TrustKey {
        key: abi_str("reverify_ttl"),
        role: TRUST_REVERIFY_TTL,
        flags: 0,
        default: abi_str(DEFAULT_REVERIFY_TTL),
        mechanisms: std::ptr::null(),
        mechanisms_len: 0,
    },
    TrustKey {
        key: abi_str("recovery_backoff"),
        role: TRUST_RECOVERY_BACKOFF,
        flags: 0,
        default: abi_str(DEFAULT_RECOVERY_BACKOFF),
        mechanisms: std::ptr::null(),
        mechanisms_len: 0,
    },
];

/// THE STATEMENT TAIL: the plane's static facts.
pub const TAIL: &PlaneTail = &PlaneTail {
    head: KindTailHead {
        size: std::mem::size_of::<PlaneTail>() as u32,
        _reserved: 0,
    },
    flags: 0,
    ingress: INGRESS_REQUEST_RESPONSE | INGRESS_RESPONSE_STREAM,
    dispatch_shape: SHAPE_PIECEWISE,
    _reserved: 0,
    scope: abi_str(SCOPE),
    label: abi_str(LABEL),
    subject_noun: abi_str(SUBJECT_NOUN),
    admin_noun: abi_str(ADMIN_NOUN),
    audit_kind: abi_str(AUDIT_KIND),
    signing_domain: abi_str(CARD_SIGNING_DOMAIN),
    signing_kid_prefix: abi_str(CARD_KID_PREFIX),
    cli_help: NONE,
    dialects: DIALECTS.as_ptr(),
    dialects_len: DIALECTS.len(),
    dialect_auth: std::ptr::null(),
    dialect_auth_len: 0,
    scope_kinds: SCOPE_KINDS.as_ptr(),
    scope_kinds_len: SCOPE_KINDS.len(),
    op_classes: std::ptr::null(),
    op_classes_len: 0,
    billable_classes: BILLABLE_CLASSES.as_ptr(),
    billable_classes_len: BILLABLE_CLASSES.len(),
    route_cost: std::ptr::null(),
    route_cost_len: 0,
    fee_units: FEE_UNITS.as_ptr(),
    fee_units_len: FEE_UNITS.len(),
    record_kinds: RECORD_KINDS.as_ptr(),
    record_kinds_len: RECORD_KINDS.len(),
    egress_targets: std::ptr::null(),
    egress_targets_len: 0,
    record_chains: std::ptr::null(),
    record_chains_len: 0,
    trust_keys: TRUST_KEYS.as_ptr(),
    trust_keys_len: TRUST_KEYS.len(),
    refusal_statuses: std::ptr::null(),
    refusal_statuses_len: 0,
    caller_credential_refusal: abi_str(REFUSE_PASSTHROUGH_SECTION),
};

/// One path the plane answers on: the verb, the target, the transport claim it arrives over, and
/// whether the route admits a caller with no credential at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// The verb.
    pub verb: &'static str,
    /// The target path; a `{name}` segment is a path variable.
    pub target: &'static str,
    /// The transport claim it arrives over.
    pub carrier: &'static str,
    /// No inbound credential: a discovery document or the push callback.
    pub open: bool,
}

/// The carrier the document and target bindings arrive over.
const CARRIER: &str = DOCUMENT_TRANSPORT;

const fn keyed(verb: &'static str, target: &'static str) -> Route {
    Route {
        verb,
        target,
        carrier: CARRIER,
        open: false,
    }
}

const fn open(verb: &'static str, target: &'static str) -> Route {
    Route {
        verb,
        target,
        carrier: CARRIER,
        open: true,
    }
}

/// EVERY ROUTE THE PLANE SERVES, in the order the engine mounts them: the document binding's
/// named operations, then the two discovery documents, the catalogue entry, the JSON-RPC
/// endpoint in both spellings, the push callback and the framed binding's service.
pub const ROUTES: &[Route] = &[
    keyed("POST", "/a2a/message:send"),
    keyed("POST", "/a2a/message:stream"),
    keyed("GET", "/a2a/tasks"),
    keyed("GET", "/a2a/tasks/{id}"),
    keyed("POST", "/a2a/tasks/{id}"),
    keyed("POST", "/a2a/tasks/{id}/pushNotificationConfigs"),
    keyed("GET", "/a2a/tasks/{id}/pushNotificationConfigs"),
    keyed("GET", "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}"),
    keyed(
        "DELETE",
        "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}",
    ),
    keyed("GET", "/a2a/extendedAgentCard"),
    open("GET", "/.well-known/oauth-protected-resource/a2a"),
    open("GET", "/.well-known/agent-card.json"),
    keyed("GET", "/a2a/agents/{agent_id}"),
    keyed("POST", "/a2a/agents/{agent_id}"),
    keyed("POST", "/a2a"),
    keyed("POST", "/a2a/"),
    open("POST", "/a2a/push"),
    Route {
        verb: "POST",
        target: "/lf.a2a.v1.A2AService/{method}",
        carrier: FRAMED_TRANSPORT,
        open: false,
    },
];

/// The trust verbs the plane serves on the kernel's admin mount, relative to it: `(verb, target)`.
pub const ADMIN_VERBS: &[(&str, &str)] = &[
    ("POST", "/agents/{name}/connect"),
    ("POST", "/agents/{name}/approve"),
];

const fn admin_route(i: usize) -> AdminRoute {
    AdminRoute {
        verb: abi_str(ADMIN_VERBS[i].0),
        target: abi_str(ADMIN_VERBS[i].1),
        flags: 0,
        _reserved: 0,
    }
}

/// [`ADMIN_VERBS`] in the ABI's spelling.
pub const ADMIN_ROUTES: &[AdminRoute] = &[admin_route(0), admin_route(1)];

/// THE TRUST VERBS' OpenAPI FRAGMENT, each path keyed under `admin_prefix` (the engine passes the
/// kernel's admin mount; the door's snapshot passes none and states the paths relative to it).
pub fn openapi_fragment(admin_prefix: &str) -> serde_json::Value {
    let ap = |rel: &str| format!("{admin_prefix}{rel}");
    serde_json::json!({
        ap(ADMIN_VERBS[0].1): {
            "post": {
                "summary": "Fetch a registered agent's card, verify it against the operator's out-of-band root, and report the fingerprint. Approves nothing and writes nothing",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK (the derived trust state and the fingerprint a human is being asked to approve; a card that could not be authenticated is still a 200 — the reason is in `failure` and the state is `error`)"},
                }
            }
        },
        ap(ADMIN_VERBS[1].1): {
            "post": {
                "summary": "Lock a registered agent to the card fingerprint the operator has SEEN. The card is re-fetched and re-verified, and an approval naming any other fingerprint is refused",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK (the registration's state AFTER the approval, read off the live registry)"},
                }
            }
        }
    })
}

/// `validate` and `open`: the settings blob read as the `agents:` section. An empty blob is the
/// empty section. The error is the grammar's own sentence.
///
/// # Errors
///
/// The first rule the section breaks, in the grammar's words.
pub fn read_settings(settings: &[u8]) -> Result<AgentsCfg, String> {
    if settings.is_empty() {
        return Ok(AgentsCfg::default());
    }
    serde_json::from_slice::<AgentsCfg>(settings).map_err(|e| e.to_string())
}

/// ONE GENERATION'S SNAPSHOT, owned, for the SDK to publish until that generation's `retire`.
///
/// With a readable `public_url` the plane is admitted: it states its audience and its
/// protected-resource metadata document, and it claims its routes. Without one it claims nothing,
/// as the engine does today: a plane with no public base has no audience a token could name.
#[must_use]
pub fn snapshot_spec(public_url: Option<&str>) -> SnapshotSpec {
    let admitted = public_url.and_then(|p| {
        Some((
            crate::a2a::public::absolute(p, crate::MOUNT_PATH)?,
            crate::a2a::public::absolute(p, crate::METADATA_PATH)?,
        ))
    });
    let (audience, resource_metadata, claims) = match admitted {
        Some((a, m)) => (Some(a), Some(m), ROUTES.iter().map(claim).collect()),
        None => (None, None, Vec::new()),
    };
    SnapshotSpec {
        claims,
        admin_routes: ADMIN_ROUTES
            .iter()
            .zip(ADMIN_VERBS)
            .map(|(r, (verb, target))| AdminRouteSpec::new(verb, target, r.flags))
            .collect(),
        openapi: Some(openapi_fragment("").to_string().into_bytes()),
        audience,
        resource_metadata,
    }
}

/// A route as the snapshot's claim: an open route takes no inbound credential; a target with a
/// path variable is a pattern, one level per variable, and any other target matches exactly.
fn claim(r: &Route) -> ClaimSpec {
    ClaimSpec::new(r.verb, r.target, r.carrier, claim_flags(r))
}

/// The claim flags a route states.
#[must_use]
pub fn claim_flags(r: &Route) -> u32 {
    let mut flags = if r.target.contains('{') {
        CLAIM_PATTERN
    } else {
        CLAIM_EXACT
    };
    if r.open {
        flags |= CLAIM_OPEN;
    }
    flags
}

#[cfg(test)]
#[path = "tests/door.rs"]
mod tests;
