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
//! ([`crate::tools_config::TRUST_KEYS`]), which the kernel parses and judges first. The plane judges the
//! rest with the grammar the engine uses, [`crate::tools_config::ToolsCfg`] and
//! [`crate::tools_config::validate_server`].
//!
//! ## What is written down here and pinned elsewhere
//!
//! The tail's strings, the route table and the admin routes are stated here as constants. The
//! engine that still serves MCP states the same facts in its own declaration and router, and a test
//! on the engine's side pins the two equal, entry by entry, until the engine is gone.

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, EGRESS_PROVIDER, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::{KindTailHead, Section, SECTION_DECLARING};
use busbar_contract::abi::plane::{
    AdminRoute, BillableClass, OpClass, PinMechanism, PlaneTail, RecordChain, TrustKey,
    CHAIN_DIGESTS_SCOPE, CHAIN_LENGTH_PREFIXED, CLAIM_EXACT, CLAIM_OPEN, INGRESS_REQUEST_RESPONSE,
    INGRESS_RESPONSE_STREAM, MECHANISM_ROOT, SHAPE_PIECEWISE, TRUST_PIN, TRUST_PRIVATE_REACH,
    TRUST_REVERIFY_TTL,
};
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::publish::{AdminRouteSpec, ClaimSpec, SnapshotSpec};

use crate::tool_claims::{
    CARRIER_HTTP, CARRIER_SSE, CARRIER_STDIO, DEFAULT_METADATA, DEFAULT_MOUNT, TASK_RUN_MOUNT,
};
use crate::tools_config::{ToolsCfg, DEFAULT_MCP_VERIFY_TTL, SECTION, SUBJECT_NOUN};

/// The grant kind that admits traffic on this plane: one registered server.
pub const SCOPE: &str = "mcp_server";
/// The signing domain busbar's own ask state is sealed under ([`crate::seal`]): the host's `sign`
/// derives this domain's subkey from the deployment's fleet-shared key.
pub const ASK_SIGNING_DOMAIN: &str = "mcp/ask-state/v1";
/// The key-id prefix of those seals.
pub const ASK_KID_PREFIX: &str = "busbar-mcp-ask-";
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

/// WHERE EACH REGISTERED SERVER IS REACHED: its registration's `url`, as a member-target path
/// (`busbar_contract::section::MEMBER_TARGET_PREFIX`): one member route per server, at its own URL.
pub const MEMBER_TARGET: &str = "settings.*.url";
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

/// THE SECRET REFERENCES ITS SECTION HOLDS, by settings path (`*` = every registration, every
/// entry): a server's RFC 8693 subject token (busbar's own) and a stdio child's environment values
/// that are references (a pipe has no header block, so `env:` is the one channel a child gets a
/// credential through). The kernel enumerates them so `--validate` and boot resolve each one.
pub const SECRET_REFS: &[AbiStr] = &[
    abi_str("settings.*.token_exchange.subject_token"),
    abi_str("settings.*.env.*"),
];

/// The far end's response fields the plane reads: the answer's media type (a JSON document or an
/// event stream) and a session revision's session id.
pub const KEEP_RESPONSE_HEADERS: &[AbiStr] = &[
    abi_str(crate::framing::CONTENT_TYPE),
    abi_str(crate::adapt::H_SESSION_ID),
];

/// The index of [`NEEDS`]' first need: the relayed calls to the registered servers reached at a URL.
pub const NEED_UPSTREAM: u32 = 0;

/// The index of [`NEEDS`]' second need: the `transport: stdio` registrations, each a PROGRAM the
/// host keeps running (ARCHITECT round 5 Q-L3B-STDIO-UPSTREAM (A)).
pub const NEED_PROGRAM: u32 = 1;

/// WHERE EACH STDIO SERVER IS REACHED: its registration's own program, as the member-program path
/// (`busbar_contract::section::MEMBER_PROGRAM`): its `command`, `args` and `env`.
pub const MEMBER_PROGRAM: &str = busbar_contract::section::MEMBER_PROGRAM;

/// The program need's response field the plane reads: the generation of the child a lease reached.
pub const KEEP_PROGRAM_HEADERS: &[AbiStr] =
    &[abi_str(busbar_contract::conn::PROGRAM_GENERATION_FIELD)];

const NO_DETAILS: Blob = Blob {
    ptr: std::ptr::null(),
    len: 0,
    fmt: BLOB_ABSENT,
    flags: 0,
};

/// THE PLANE'S CONNECTION NEEDS: outbound over http to the servers the operator registered at a URL,
/// governed as upstreams a plane reaches (no auth style is named here: each member's credential is
/// the binding the kernel seals for it, and it adds the fields when it sends); and the `transport:
/// stdio` servers, each the program its registration names, run by the host as the operator's own
/// infrastructure with no credential (a pipe carries none), one long-lived child per server.
pub const NEEDS: &[Need] = &[
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_PROVIDER,
        transport: abi_str(CARRIER_HTTP),
        auth: NONE,
        // Each registered server is reached at its own `url` (ARCHITECT Q-L3B-ROUTES).
        target_from: abi_str(MEMBER_TARGET),
        trust_from: NONE,
        details: NO_DETAILS,
        keep_response_headers: KEEP_RESPONSE_HEADERS.as_ptr(),
        keep_response_headers_len: KEEP_RESPONSE_HEADERS.len(),
        timeout_ms: 0,
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    },
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_OPERATOR_INFRASTRUCTURE,
        transport: abi_str(CARRIER_STDIO),
        auth: NONE,
        target_from: abi_str(MEMBER_PROGRAM),
        trust_from: NONE,
        details: NO_DETAILS,
        keep_response_headers: KEEP_PROGRAM_HEADERS.as_ptr(),
        keep_response_headers_len: KEEP_PROGRAM_HEADERS.len(),
        timeout_ms: 0,
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    },
];

const DIALECTS: &[AbiStr] = &[abi_str(DIALECT)];

const SCOPE_KINDS: &[AbiStr] = &[abi_str(SCOPE), abi_str(SCOPE_TOOL)];

const BILLABLE_CLASSES: &[BillableClass] = &[
    BillableClass {
        class: abi_str(crate::tool_meta::CLASS_TOOL_CALLS.as_str()),
        family: abi_str(CALLS_FAMILY),
    },
    BillableClass {
        class: abi_str(crate::tool_meta::CLASS_BYTES.as_str()),
        family: abi_str(BYTES_FAMILY),
    },
    // THE FEE UNIT is also a class (the tail check holds `fee_units ⊆ billable_classes`, ARCHITECT
    // Q-L5-FEE (C)): reported `1` on an answer the caller is served with a success, so a unit whose
    // caller is answered otherwise has its `per_request` refunded, as 1.5.5 refunded it.
    BillableClass {
        class: abi_str(FEE_PER_REQUEST),
        family: abi_str(FEE_FAMILY),
    },
];

/// The family of the fee unit's class: a count of 0 or 1.
pub const FEE_FAMILY: &str = "count";

/// The tail index of the fee unit's class in [`BILLABLE_CLASSES`].
pub const CLASS_FEE_INDEX: u32 = 2;

const FEE_UNITS: &[AbiStr] = &[abi_str(FEE_PER_REQUEST)];

const RECORD_KINDS: &[AbiStr] = &[
    abi_str(crate::tool_records::KIND_CALL),
    abi_str(crate::tool_records::KIND_DEMOTION),
    abi_str(crate::tool_records::KIND_APPROVAL),
    abi_str(crate::tool_records::KIND_TASK),
];

/// The kind a completed ask exchange's approval is claimed under, once ([`RECORD_KINDS`]): the
/// spent-approval ledger is the host's one-time `records.claim` (ARCHITECT Q-L3B-ASK).
pub const KIND_APPROVAL: &str = crate::tool_records::KIND_APPROVAL;

/// The index of the call record's kind in [`RECORD_KINDS`].
pub const RECORD_CALL: u32 = 0;

/// The index of the task kind in [`RECORD_KINDS`]: a task's result chunks are written under it.
pub const RECORD_TASK: u32 = 3;

/// The kind a task's work handle is opened under (`work.open`, [`RECORD_KINDS`]).
pub const KIND_TASK: &str = crate::tool_records::KIND_TASK;

/// THE CALL LOG IS A CHAIN: each caller's call records are hash-chained by the host, the prelude
/// (`prev_hash`, the scope, `seq`) LengthPrefixed with the scope in the digest, then the plane's own
/// fields ([`crate::record::call_suffix`]) joined raw.
const RECORD_CHAINS: &[RecordChain] = &[RecordChain {
    kind: RECORD_CALL,
    framing: CHAIN_LENGTH_PREFIXED,
    flags: CHAIN_DIGESTS_SCOPE,
    _reserved: 0,
}];

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

/// The kernel-owned trust keys of one entry, the ABI spelling of [`crate::tools_config::TRUST_KEYS`];
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
    TrustKey {
        key: abi_str("allow_private"),
        role: TRUST_PRIVATE_REACH,
        flags: 0,
        default: NONE,
        mechanisms: std::ptr::null(),
        mechanisms_len: 0,
    },
];

const fn op_class(i: usize) -> OpClass {
    OpClass {
        op: abi_str(crate::tool_ops::OP_CLASSES[i].as_str()),
        name: abi_str(crate::tool_ops::OP_CLASSES[i].as_str()),
    }
}

/// The operation classes, in [`crate::tool_ops::OP_CLASSES`] order.
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
];

/// The tail index of an operation class, where the table holds it.
#[must_use]
pub fn op_class_index(op: busbar_contract::ids::OpClassId) -> Option<u32> {
    crate::tool_ops::OP_CLASSES
        .iter()
        .position(|c| *c == op)
        .map(|i| i as u32)
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

/// The status an arrival from a browser origin the deployment does not admit is refused with.
pub const STATUS_FORBIDDEN_ORIGIN: u32 = 403;

/// THE DNS-REBINDING REFUSAL's body (the served engine's `ForbiddenOrigin` words, as its envelope
/// rendered them): an OAuth-style error object, not a JSON-RPC one.
#[must_use]
pub fn forbidden_origin_body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "error": "invalid_origin",
        "error_description":
            "This Origin is not allowed. Browser origins must be listed in mcp.allowed_origins.",
    }))
    .unwrap_or_default()
}

/// THE BROWSER ORIGINS the deployment admits beyond loopback: the `mcp:` block's
/// `allowed_origins` (none when it writes no block).
///
/// # Errors
///
/// The block, written and malformed, in its grammar's words.
pub fn allowed_origins(owned: &[u8]) -> Result<Vec<String>, String> {
    if owned.is_empty() {
        return Ok(Vec::new());
    }
    let Some(block) = serde_json::from_slice::<serde_json::Value>(owned)
        .map_err(|e| e.to_string())?
        .get(ENDPOINT_SECTION)
        .cloned()
    else {
        return Ok(Vec::new());
    };
    let cfg: crate::endpoint::McpCfg = serde_json::from_value(block).map_err(|e| e.to_string())?;
    Ok(cfg.allowed_origins)
}

/// THE STATEMENT TAIL: the plane's static facts.
pub const TAIL: &PlaneTail = &PlaneTail {
    head: KindTailHead {
        size: std::mem::size_of::<PlaneTail>() as u32,
        _reserved: 0,
    },
    // THE GATE-FIRST HOOK ORDER (spec Part 3 section 12 "Hooks"; ARCHITECT ruling on the mcp
    // fold): the served engine ran an entry's decision gates over the invocation BEFORE its
    // rewrite chain (`tools.hooks` / `tools.<server>.hooks`), and the door's units keep that order.
    flags: busbar_contract::abi::plane::TAIL_HOOKS_GATED,
    ingress: INGRESS_REQUEST_RESPONSE | INGRESS_RESPONSE_STREAM,
    dispatch_shape: SHAPE_PIECEWISE,
    _reserved: 0,
    scope: abi_str(SCOPE),
    label: abi_str(LABEL),
    subject_noun: abi_str(SUBJECT_NOUN),
    admin_noun: abi_str(ADMIN_NOUN),
    audit_kind: abi_str(AUDIT_KIND),
    signing_domain: abi_str(ASK_SIGNING_DOMAIN),
    signing_kid_prefix: abi_str(ASK_KID_PREFIX),
    cli_help: abi_str(crate::tool_meta::HELP_FLAGS),
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
    record_chains: RECORD_CHAINS.as_ptr(),
    record_chains_len: RECORD_CHAINS.len(),
    trust_keys: TRUST_KEYS.as_ptr(),
    trust_keys_len: TRUST_KEYS.len(),
    refusal_statuses: std::ptr::null(),
    refusal_statuses_len: 0,
    caller_credential_refusal: NONE,
    admin_routes: ADMIN_ROUTES.as_ptr(),
    admin_routes_len: ADMIN_ROUTES.len(),
    admin_openapi: Blob {
        ptr: ADMIN_OPENAPI.as_ptr(),
        len: ADMIN_OPENAPI.len(),
        fmt: busbar_contract::abi::mechanism::call::BLOB_JSON,
        flags: 0,
    },
};

/// One path the plane answers on: the verb, the target, the transport claim it arrives over, and
/// whether the route admits a caller with no credential at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// The verb.
    pub verb: &'static str,
    /// The target path.
    pub target: &'static str,
    /// The transport claim it arrives over.
    pub carrier: &'static str,
    /// No inbound credential: the discovery document.
    pub open: bool,
}

/// EVERY ROUTE THE PLANE SERVES, in the order the engine mounts them: the discovery document, the
/// endpoint's three verbs, and the event-framed answer on the same path.
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
    // THE TASK-RUN CLAIM (ARCHITECT round 5 Q-L3B-TASKS (b) → (A)): a task's continuation, nested
    // by the unit that created the task.
    Route {
        verb: "POST",
        target: TASK_RUN_MOUNT,
        carrier: CARRIER_HTTP,
        open: false,
    },
    // THE LINE CARRIER (ARCHITECT Q1a, round 4 Q-L3B-STDIO-SHAPE (B)): the host holds the process's
    // own stdin/stdout open as one carrier session and opens a unit per line.
    Route {
        verb: "POST",
        target: DEFAULT_MOUNT,
        carrier: CARRIER_STDIO,
        open: false,
    },
];

/// The index of the task-run claim in [`ROUTES`].
pub const TASK_RUN_ROUTE: usize = 5;

/// The index of the line carrier's claim in [`ROUTES`].
pub const LINE_ROUTE: usize = 6;

/// The word each admin verb is audited under (`connect` reaches the operator's estate and can
/// quarantine a server, so it is audited; the two reads are not), in [`ADMIN_VERBS`] order.
pub const ADMIN_AUDIT: &[&str] = &["connect", "", ""];

/// THE TRUST VERBS' OpenAPI FRAGMENT, each path relative to the admin mount (the kernel keys it
/// under the mount): the served engine's text.
pub const ADMIN_OPENAPI: &str = r#"{"/tools/{name}/connect":{"post":{"summary":"Fetch a registered MCP server's LIVE tool list, hash it, and record the observation. Approves nothing: adopting what was seen is a separate operator act","security":[{"adminToken":[]}],"parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"OK (the derived trust state and changes queue; a refresh that landed a quarantine is still a 200 — the drift is in the body)"}}}},"/tools/{name}/changes":{"get":{"summary":"The changes queue for one MCP server, derived from the LAST observation. Contacts nothing","security":[{"adminToken":[]}],"parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"OK"}}}},"/tools/{name}/health":{"get":{"summary":"Whether one MCP server currently serves, and why not when it does not","security":[{"adminToken":[]}],"parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"OK"}}}}}"#;

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
        audit_verb: abi_str(ADMIN_AUDIT[i]),
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
pub fn read_tools_section(settings: &[u8]) -> Result<ToolsCfg, String> {
    if settings.is_empty() {
        return Ok(ToolsCfg::default());
    }
    let cfg = serde_json::from_slice::<ToolsCfg>(settings).map_err(|e| e.to_string())?;
    // The published names are judged over the whole section, as the kernel judges the effective
    // registry (file and overlay): two servers publishing one name refuse it.
    crate::tools_config::validate_published_names(&cfg)?;
    Ok(cfg)
}

/// ONE POOL of the section (the unified `pools:` its registrations resolved to, handed at the
/// section's reserved `pools` key): its interchangeable servers in the operator's order, the first
/// the primary, and the operations (bare tool names) it may perform twice.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolPool {
    /// The member servers, in order.
    pub members: Vec<String>,
    /// The operations a member that answered with a failure may be repeated on another member for.
    pub repeatable: Vec<String>,
}

/// THE SETTINGS `open` and `refresh` are handed: the section ([`read_tools_section`]) and the pools the
/// kernel carries at its reserved `pools` key (ARCHITECT round 4 Q-L3B-SURFACES (h)). The operator's
/// own document never reaches this reader (`validate` reads the section as written).
///
/// # Errors
///
/// The section's refusal, or pools that are not `{name: {members: [..], repeatable: [..]}}`.
pub fn read_open(
    settings: &[u8],
) -> Result<(ToolsCfg, std::collections::BTreeMap<String, ToolPool>), String> {
    if settings.is_empty() {
        return Ok((ToolsCfg::default(), std::collections::BTreeMap::new()));
    }
    let mut value: serde_json::Value =
        serde_json::from_slice(settings).map_err(|e| e.to_string())?;
    let stated = value
        .as_object_mut()
        .and_then(|m| m.remove(busbar_contract::section::RESERVED_POOLS_KEY));
    let mut pools = std::collections::BTreeMap::new();
    if let Some(stated) = stated {
        let map = stated
            .as_object()
            .ok_or("the section's pools are not a map")?;
        let list = |v: Option<&serde_json::Value>| -> Result<Vec<String>, String> {
            v.map_or(Ok(Vec::new()), |v| {
                serde_json::from_value::<Vec<String>>(v.clone()).map_err(|e| e.to_string())
            })
        };
        for (name, pool) in map {
            pools.insert(
                name.clone(),
                ToolPool {
                    members: list(pool.get(busbar_contract::section::POOL_MEMBERS_KEY))?,
                    repeatable: list(pool.get(busbar_contract::section::POOL_REPEATABLE_KEY))?,
                },
            );
        }
    }
    let rest = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    Ok((read_tools_section(&rest)?, pools))
}

/// ONE GENERATION'S SNAPSHOT, owned, for the SDK to publish until that generation's `retire`.
///
/// With a readable `public_url` the plane is admitted: it states its audience (the endpoint's
/// absolute URI) and its protected-resource metadata document, and it claims its routes. Without
/// one it claims nothing: a plane with no public base has no audience a token could name.
#[must_use]
pub fn endpoint_snapshot_spec(public_url: Option<&str>) -> SnapshotSpec {
    snapshot_spec_for(public_url.map(under_public_url))
}

/// The audience and metadata document of an endpoint mounted under the deployment's public base
/// URL: the fixed mount and its RFC 9728 document beneath that base.
#[must_use]
pub fn under_public_url(public_url: &str) -> (String, String) {
    let base = public_url.trim_end_matches('/');
    (
        format!("{base}{DEFAULT_MOUNT}"),
        format!("{base}{DEFAULT_METADATA}"),
    )
}

/// THE ENDPOINT THE PLANE STATES ITS CLAIMS UNDER (ARCHITECT Q-L3B-AUD, predev's rule): its own
/// `mcp:` block's canonical URI when the document writes one (`owned`, the other sections it owns,
/// keyed by section name), else the deployment's public base URL; `None` when it states neither.
/// The block is judged by its grammar ([`crate::endpoint::McpResource::from_cfg`]): the audience is
/// the canonical URI verbatim and the metadata document the one it derives.
///
/// # Errors
///
/// The block, written and malformed, in its grammar's words.
pub fn admitted_endpoint(
    public_url: Option<&str>,
    owned: &[u8],
) -> Result<Option<(String, String)>, String> {
    let block = if owned.is_empty() {
        None
    } else {
        serde_json::from_slice::<serde_json::Value>(owned)
            .map_err(|e| e.to_string())?
            .get(ENDPOINT_SECTION)
            .cloned()
    };
    match block {
        Some(block) => {
            let cfg: crate::endpoint::McpCfg =
                serde_json::from_value(block).map_err(|e| e.to_string())?;
            let resource =
                crate::endpoint::McpResource::from_cfg(&cfg).map_err(|e| e.to_string())?;
            Ok(Some((
                resource.canonical_uri().to_string(),
                resource.metadata_url().to_string(),
            )))
        }
        None => Ok(public_url.map(under_public_url)),
    }
}

/// THE PROTECTED-RESOURCE FACTS its `mcp:` block states (ARCHITECT Q-L3B-RFC9728): its
/// authorization servers and scopes, as the JSON object `PlaneSnapshot::resource_facts` carries, from
/// which the kernel renders the RFC 9728 document; `None` when the document writes no block.
///
/// # Errors
///
/// The block, written and malformed, in its grammar's words.
pub fn resource_facts(owned: &[u8]) -> Result<Option<Vec<u8>>, String> {
    if owned.is_empty() {
        return Ok(None);
    }
    let Some(block) = serde_json::from_slice::<serde_json::Value>(owned)
        .map_err(|e| e.to_string())?
        .get(ENDPOINT_SECTION)
        .cloned()
    else {
        return Ok(None);
    };
    let cfg: crate::endpoint::McpCfg = serde_json::from_value(block).map_err(|e| e.to_string())?;
    let resource = crate::endpoint::McpResource::from_cfg(&cfg).map_err(|e| e.to_string())?;
    Ok(Some(
        serde_json::json!({
            "authorization_servers": resource.authorization_servers(),
            "scopes_supported": resource.scopes_supported(),
        })
        .to_string()
        .into_bytes(),
    ))
}

/// ONE GENERATION'S SNAPSHOT under `admitted` (the endpoint's audience and metadata document,
/// [`admitted`]); with none it claims nothing.
#[must_use]
pub fn snapshot_spec_for(admitted: Option<(String, String)>) -> SnapshotSpec {
    snapshot_spec_with(admitted, None)
}

/// [`snapshot_spec_for`], stating its protected-resource `facts` ([`resource_facts`]) beside.
#[must_use]
pub fn snapshot_spec_with(
    admitted: Option<(String, String)>,
    facts: Option<Vec<u8>>,
) -> SnapshotSpec {
    let (audience, resource_metadata, claims) = match admitted {
        Some((a, m)) => (Some(a), Some(m), ROUTES.iter().map(claim).collect()),
        None => (None, None, Vec::new()),
    };
    SnapshotSpec {
        claims,
        admin_routes: ADMIN_ROUTES
            .iter()
            .zip(ADMIN_VERBS)
            .zip(ADMIN_AUDIT)
            .map(|((r, (verb, target)), audit)| AdminRouteSpec {
                audit_verb: (*audit).to_string(),
                ..AdminRouteSpec::new(verb, target, r.flags)
            })
            .collect(),
        openapi: None,
        resource_facts: facts.filter(|_| audience.is_some()),
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
