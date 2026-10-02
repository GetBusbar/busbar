// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PLANE'S DOOR, its declarations: what the plane states once in its Statement tail, what
//! each generation publishes in its snapshot, and how `validate`/`open` read the settings blob.
//!
//! ## What the kernel hands the plane
//!
//! The settings blob is the plane's own section value, the `tools:` map, as JSON, with the kernel's
//! reserved sub-keys already read and stripped: the hook bindings and `upstream_credentials` never
//! reach the plane, and neither do the kernel-owned trust keys each entry carries
//! ([`crate::config::TRUST_KEYS`]), which the kernel parses and judges first. The plane judges the
//! rest with the grammar the engine uses, [`crate::config::ToolsCfg`] and
//! [`crate::config::validate_server`].
//!
//! ## What is written down here and pinned elsewhere
//!
//! The tail's strings, the route table and the admin routes are stated here as constants. The
//! engine that still serves MCP states the same facts in its own declaration and router, and a test
//! on the engine's side pins the two equal, entry by entry, until the engine is gone.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{KindTailHead, Section, SECTION_DECLARING};
use busbar_contract::abi::plane::{
    AdminRoute, BillableClass, OpClass, PinMechanism, PlaneTail, TrustKey, CLAIM_EXACT, CLAIM_OPEN,
    INGRESS_DUPLEX_SESSION, INGRESS_REQUEST_RESPONSE, INGRESS_RESPONSE_STREAM, MECHANISM_ROOT,
    SHAPE_PIECEWISE, TRUST_PIN, TRUST_REVERIFY_TTL,
};
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::publish::{AdminRouteSpec, ClaimSpec, SnapshotSpec};

use crate::claims::{CARRIER_HTTP, CARRIER_SSE, CARRIER_STDIO, DEFAULT_METADATA, DEFAULT_MOUNT};
use crate::config::{ToolsCfg, DEFAULT_MCP_VERIFY_TTL, SECTION, SUBJECT_NOUN};

/// The grant kind that admits traffic on this plane: one registered server.
pub const SCOPE: &str = "mcp_server";
/// The second grant kind: one tool of a registered server, keyed on its published name.
pub const SCOPE_TOOL: &str = "mcp_tool";
/// The plane's human label.
pub const LABEL: &str = "MCP";
/// The singular noun for one registration, in admin responses.
pub const ADMIN_NOUN: &str = "mcp-server";
/// The record resource kind a registration is audited under.
pub const AUDIT_KIND: &str = "mcp_server";
/// The section this plane owns beside `tools:`: its endpoint block.
pub const ENDPOINT_SECTION: &str = "mcp";
/// The one wire dialect: JSON-RPC 2.0, carried over each of the plane's transports.
pub const DIALECT: &str = "jsonrpc";
/// The billable class a call is counted in, and its family.
pub const CALLS_FAMILY: &str = "count";
/// The billable class a hop's moved bytes are counted in, and its family.
pub const BYTES_FAMILY: &str = "byte";
/// The fee unit this plane declares: one per request.
pub const FEE_PER_REQUEST: &str = busbar_contract::plane::PER_REQUEST;

/// An absent string.
const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// THE SECTIONS THE PLANE'S STATEMENT DECLARES: `tools:`, which it owns and judges, and its endpoint
/// block beside it.
pub const SECTIONS: &[Section] = &[
    Section {
        name: abi_str(SECTION),
        flags: SECTION_DECLARING,
        _reserved: 0,
    },
    Section {
        name: abi_str(ENDPOINT_SECTION),
        flags: 0,
        _reserved: 0,
    },
];

const DIALECTS: &[AbiStr] = &[abi_str(DIALECT)];

const SCOPE_KINDS: &[AbiStr] = &[abi_str(SCOPE), abi_str(SCOPE_TOOL)];

const BILLABLE_CLASSES: &[BillableClass] = &[
    BillableClass {
        class: abi_str(crate::meta::CLASS_TOOL_CALLS.as_str()),
        family: abi_str(CALLS_FAMILY),
    },
    BillableClass {
        class: abi_str(crate::meta::CLASS_BYTES.as_str()),
        family: abi_str(BYTES_FAMILY),
    },
];

const FEE_UNITS: &[AbiStr] = &[abi_str(FEE_PER_REQUEST)];

const RECORD_KINDS: &[AbiStr] = &[
    abi_str(crate::records::KIND_CALL),
    abi_str(crate::records::KIND_DEMOTION),
];

/// The pin's four mechanisms; three are authenticity roots and `unpinned` is not.
const PIN_MECHANISMS: &[PinMechanism] = &[
    PinMechanism {
        token: abi_str("pinned_pubkey"),
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

/// The kernel-owned trust keys of one entry, the ABI spelling of [`crate::config::TRUST_KEYS`];
/// declaration order is judgement order. The pin carries no fingerprint: a server here offers
/// none an operator could approve out of band.
const TRUST_KEYS: &[TrustKey] = &[
    TrustKey {
        key: abi_str("pin"),
        role: TRUST_PIN,
        flags: 0,
        default: NONE,
        mechanisms: PIN_MECHANISMS.as_ptr(),
        mechanisms_len: PIN_MECHANISMS.len(),
    },
    TrustKey {
        key: abi_str("verify_ttl"),
        role: TRUST_REVERIFY_TTL,
        flags: 0,
        default: abi_str(DEFAULT_MCP_VERIFY_TTL),
        mechanisms: std::ptr::null(),
        mechanisms_len: 0,
    },
];

/// The operation class of the child-process carrier's session verbs, which no method row carries.
pub const OP_SESSION: &str = "session";

/// The index of [`OP_SESSION`] in the tail's operation classes: after every method row's class.
pub const OP_CLASS_SESSION: u32 = crate::ops::OP_CLASSES.len() as u32;

const fn op_class(i: usize) -> OpClass {
    OpClass {
        op: abi_str(crate::ops::OP_CLASSES[i].as_str()),
        name: abi_str(crate::ops::OP_CLASSES[i].as_str()),
    }
}

/// The operation classes, in [`crate::ops::OP_CLASSES`] order, then [`OP_SESSION`].
const OP_CLASS_TABLE: &[OpClass] = &[
    op_class(0),
    op_class(1),
    op_class(2),
    op_class(3),
    op_class(4),
    op_class(5),
    op_class(6),
    op_class(7),
    op_class(8),
    op_class(9),
    op_class(10),
    op_class(11),
    op_class(12),
    op_class(13),
    op_class(14),
    op_class(15),
    op_class(16),
    OpClass {
        op: abi_str(OP_SESSION),
        name: abi_str(OP_SESSION),
    },
];

/// The tail index of an operation class; a class the table does not hold reads as the session
/// class.
#[must_use]
pub fn op_class_index(op: busbar_contract::ids::OpClassId) -> u32 {
    crate::ops::OP_CLASSES
        .iter()
        .position(|c| *c == op)
        .map_or(OP_CLASS_SESSION, |i| i as u32)
}

/// The status of a verb the endpoint does not serve.
pub const STATUS_METHOD_NOT_ALLOWED: u32 = 405;

/// The served engine's body for a verb the endpoint does not serve.
#[must_use]
pub fn method_not_allowed_body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "error": "method_not_allowed",
        "error_description":
            "MCP revision 2026-07-28 has no GET stream and no sessions; the endpoint accepts POST only.",
    }))
    .unwrap_or_default()
}

/// THE STATEMENT TAIL: the plane's static facts.
pub const TAIL: &PlaneTail = &PlaneTail {
    head: KindTailHead {
        size: std::mem::size_of::<PlaneTail>() as u32,
        _reserved: 0,
    },
    flags: 0,
    ingress: INGRESS_REQUEST_RESPONSE | INGRESS_RESPONSE_STREAM | INGRESS_DUPLEX_SESSION,
    dispatch_shape: SHAPE_PIECEWISE,
    _reserved: 0,
    scope: abi_str(SCOPE),
    label: abi_str(LABEL),
    subject_noun: abi_str(SUBJECT_NOUN),
    admin_noun: abi_str(ADMIN_NOUN),
    audit_kind: abi_str(AUDIT_KIND),
    signing_domain: NONE,
    signing_kid_prefix: NONE,
    cli_help: NONE,
    dialects: DIALECTS.as_ptr(),
    dialects_len: DIALECTS.len(),
    dialect_auth: std::ptr::null(),
    dialect_auth_len: 0,
    scope_kinds: SCOPE_KINDS.as_ptr(),
    scope_kinds_len: SCOPE_KINDS.len(),
    op_classes: OP_CLASS_TABLE.as_ptr(),
    op_classes_len: OP_CLASS_TABLE.len(),
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
};

/// One path the plane answers on: the verb, the target, the transport claim it arrives over, and
/// whether the route admits a caller with no credential at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// The verb.
    pub verb: &'static str,
    /// The target path, or the named stream a child-process carrier arrives on.
    pub target: &'static str,
    /// The transport claim it arrives over.
    pub carrier: &'static str,
    /// No inbound credential: the discovery document.
    pub open: bool,
}

/// EVERY ROUTE THE PLANE SERVES, in the order the engine mounts them: the discovery document, the
/// endpoint's three verbs, the event-framed answer on the same path, and the named stream a
/// locally launched session arrives on.
pub const ROUTES: &[Route] = &[
    Route {
        verb: "GET",
        target: DEFAULT_METADATA,
        carrier: CARRIER_HTTP,
        open: true,
    },
    Route {
        verb: "POST",
        target: DEFAULT_MOUNT,
        carrier: CARRIER_HTTP,
        open: false,
    },
    Route {
        verb: "GET",
        target: DEFAULT_MOUNT,
        carrier: CARRIER_HTTP,
        open: false,
    },
    Route {
        verb: "DELETE",
        target: DEFAULT_MOUNT,
        carrier: CARRIER_HTTP,
        open: false,
    },
    Route {
        verb: "POST",
        target: DEFAULT_MOUNT,
        carrier: CARRIER_SSE,
        open: false,
    },
    Route {
        verb: "POST",
        target: crate::claims::STDIO_STREAM,
        carrier: CARRIER_STDIO,
        open: false,
    },
];

/// The trust verbs the plane serves on the kernel's admin mount, relative to it: `(verb, target)`.
pub const ADMIN_VERBS: &[(&str, &str)] = &[
    ("POST", "/tools/{name}/connect"),
    ("GET", "/tools/{name}/changes"),
    ("GET", "/tools/{name}/health"),
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
pub const ADMIN_ROUTES: &[AdminRoute] = &[admin_route(0), admin_route(1), admin_route(2)];

/// `validate` and `open`: the settings blob read as the `tools:` section. An empty blob is the
/// empty section. The error is the grammar's own sentence.
///
/// # Errors
///
/// The first rule the section breaks, in the grammar's words.
pub fn read_settings(settings: &[u8]) -> Result<ToolsCfg, String> {
    if settings.is_empty() {
        return Ok(ToolsCfg::default());
    }
    serde_json::from_slice::<ToolsCfg>(settings).map_err(|e| e.to_string())
}

/// ONE GENERATION'S SNAPSHOT, owned, for the SDK to publish until that generation's `retire`.
///
/// With a readable `public_url` the plane is admitted: it states its audience (the endpoint's
/// absolute URI) and its protected-resource metadata document, and it claims its routes. Without
/// one it claims nothing: a plane with no public base has no audience a token could name.
#[must_use]
pub fn snapshot_spec(public_url: Option<&str>) -> SnapshotSpec {
    let admitted = public_url.map(|p| {
        let base = p.trim_end_matches('/');
        (
            format!("{base}{DEFAULT_MOUNT}"),
            format!("{base}{DEFAULT_METADATA}"),
        )
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
        openapi: None,
        audience,
        resource_metadata,
    }
}

/// A route as the snapshot's claim: an open route takes no inbound credential, and every target
/// matches exactly.
fn claim(r: &Route) -> ClaimSpec {
    let flags = if r.open {
        CLAIM_EXACT | CLAIM_OPEN
    } else {
        CLAIM_EXACT
    };
    ClaimSpec::new(r.verb, r.target, r.carrier, flags)
}

#[cfg(test)]
#[path = "tests/door.rs"]
mod tests;
