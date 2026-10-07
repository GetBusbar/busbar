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

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPEN_WEB, EGRESS_PROVIDER, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::{KindTailHead, Section, SECTION_DECLARING};
use busbar_contract::abi::plane::{
    AdminRoute, BillableClass, OpClass, PinMechanism, PlaneTail, RecordChain, TrustKey,
    CHAIN_DIGESTS_SCOPE, CHAIN_PIPE_SEPARATED, CLAIM_EXACT, CLAIM_OPEN, CLAIM_PATTERN,
    INGRESS_REQUEST_RESPONSE, INGRESS_RESPONSE_STREAM, MECHANISM_PEER_KEY, MECHANISM_ROOT,
    PIN_FINGERPRINT, SHAPE_PIECEWISE, TAIL_HOOKS_GATED, TRUST_PIN, TRUST_PRIVATE_REACH,
    TRUST_RECOVERY_BACKOFF, TRUST_REVERIFY_TTL,
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

/// [`DIALECTS`] index of the JSON-RPC line's dialect.
pub const DIALECT_DOCUMENT: u32 = 0;
/// [`DIALECTS`] index of the HTTP+JSON line's dialect.
pub const DIALECT_TARGET: u32 = 1;
/// [`DIALECTS`] index of the gRPC line's dialect.
pub const DIALECT_FRAMED: u32 = 2;

const fn op_class(i: usize) -> OpClass {
    OpClass {
        op: abi_str(crate::ops::OP_CLASSES[i].as_str()),
        name: abi_str(crate::ops::OP_CLASSES[i].as_str()),
    }
}

/// The operation classes, in [`crate::ops::OP_CLASSES`] order: `arrive` names one by its index.
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
];

/// The [`OP_CLASS_TABLE`] index of `op`; `None` when the plane does not declare it.
#[must_use]
pub fn op_class_index(op: busbar_contract::ids::OpClassId) -> Option<u32> {
    crate::ops::OP_CLASSES
        .iter()
        .position(|c| *c == op)
        .and_then(|i| u32::try_from(i).ok())
}

const BILLABLE_CLASSES: &[BillableClass] = &[
    BillableClass {
        class: abi_str(crate::meta::CLASS_BYTES.as_str()),
        family: abi_str(BYTES_FAMILY),
    },
    // THE FEE UNIT is also a class (the tail check holds `fee_units ⊆ billable_classes`, ARCHITECT
    // Q-L5-FEE (C)): reported `1` once the unit is served (its hop left the plane for the agent, or
    // the plane answered the verb itself), so a unit refused before that has its `per_request`
    // refunded, as the served engine gave the admission's fee back to a hop refused before the
    // socket.
    BillableClass {
        class: abi_str(FEE_PER_REQUEST),
        family: abi_str(FEE_FAMILY),
    },
];

/// The family of the fee unit's class: a count of 0 or 1.
pub const FEE_FAMILY: &str = "count";

/// The tail index of the bytes class in the billable classes.
pub const CLASS_BYTES_INDEX: u32 = 0;

/// The tail index of the fee unit's class in the billable classes.
pub const CLASS_FEE_INDEX: u32 = 1;

const FEE_UNITS: &[AbiStr] = &[abi_str(FEE_PER_REQUEST)];

/// [`crate::records::HELD_KINDS`] in the ABI's spelling.
const RECORD_KINDS: &[AbiStr] = &[
    abi_str(crate::records::HELD_KINDS[0]),
    abi_str(crate::records::HELD_KINDS[1]),
    abi_str(crate::records::HELD_KINDS[2]),
    abi_str(crate::records::HELD_KINDS[3]),
];

/// THE TASK CHAIN (ARCHITECT ruling B1, 2026-10-07; `BUSBAR-1.6.0.md` Part 3, the chain section, and THE
/// DESIGN's route pump): the task-event kind is chained, pipe-separated with its scope in the digest, the
/// framing the engine's per-task chain was sealed under (`prev|task|seq|ts|kind|context|principal|
/// agent|state`). The host frames the prelude and keeps and verifies the chain; the plane writes
/// only each event's own fields ([`crate::tasks::suffix`]).
const RECORD_CHAINS: &[RecordChain] = &[RecordChain {
    kind: crate::records::TASK_EVENT_INDEX,
    framing: CHAIN_PIPE_SEPARATED,
    flags: CHAIN_DIGESTS_SCOPE,
    _reserved: 0,
}];

/// The pin's four mechanisms; three are authenticity roots and `unpinned` is not. `cert_spki` and
/// `mtls` pin the agent's KEY: the host seals it into the agent's member route and the connector
/// enforces it on every connection to the agent (Q-DEL-A2A-SPKI).
const PIN_MECHANISMS: &[PinMechanism] = &[
    PinMechanism {
        token: abi_str("jws_issuer_key"),
        flags: MECHANISM_ROOT,
        _reserved: 0,
    },
    PinMechanism {
        token: abi_str("cert_spki"),
        flags: MECHANISM_ROOT | MECHANISM_PEER_KEY,
        _reserved: 0,
    },
    PinMechanism {
        token: abi_str("mtls"),
        flags: MECHANISM_ROOT | MECHANISM_PEER_KEY,
        _reserved: 0,
    },
    PinMechanism {
        token: abi_str("unpinned"),
        flags: 0,
        _reserved: 0,
    },
];

/// The kernel-owned trust keys of one entry: the ABI spelling of
/// [`crate::a2a::config::TRUST_KEYS`], then the registration's private reach, which the door path
/// hands the host (the grammar keeps reading `allow_private` itself); declaration order is
/// judgement order.
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
    // THE REGISTRATION'S PRIVATE REACH (1.5.5's per-agent `allow_private: true`, ARCHITECT ruling
    // on FLIP-A2A, SEAM-4f1): the host seals it into the agent's anchors and the one guard admits
    // the agent's own private or loopback destination on [`NEED_AGENT`]; never a metadata address.
    // An agent without it is refused every private address by the guard.
    TrustKey {
        key: abi_str(PRIVATE_REACH_KEY),
        role: TRUST_PRIVATE_REACH,
        flags: 0,
        default: NONE,
        mechanisms: std::ptr::null(),
        mechanisms_len: 0,
    },
];

/// The per-registration key holding an agent's private reach (`allow_private`).
pub const PRIVATE_REACH_KEY: &str = "allow_private";

/// The [`NEEDS`] index of the plane's own outbound hops to a caller's push callback, each to the
/// target the plane names at the dial.
pub const NEED_OPEN_WEB: u32 = 0;

/// The [`NEEDS`] index of the relayed calls to the registered agents: one member route per agent,
/// sealed by the kernel at its own `url` (ARCHITECT Q-DEL-A2A-EGRESS = Q-L3B-ROUTES); the trust
/// verbs fetch an agent's card over it, at the well-known paths of the agent's own origin.
pub const NEED_AGENT: u32 = 1;

/// The [`NEEDS`] index of the relayed calls to the registered agents whose card's binding is gRPC
/// (spec line 2026-09-30: "gRPC on its own listener; transport de-frames, plane transcodes"): the
/// same member route as [`NEED_AGENT`], at the agent's own `url`, carried over the grpc transport,
/// held to the same pin and client identity. The kernel binds a registration member on every
/// member-target need its plane states, and an ATTEMPT names this one
/// ([`crate::plane_door::attempt_need`]).
pub const NEED_GRPC: u32 = 2;

/// THE MEMBER-TARGET PATH of [`NEED_AGENT`] (`busbar_contract::section::MEMBER_TARGET_PREFIX`): each
/// registered agent is reached at its own `url`, the plane spelling the path of every request it
/// sends. The agent's `pin` stays the plane's trust key (`TRUST_KEYS`), judged as 1.5.5 judged it.
pub const MEMBER_TARGET: &str = "settings.*.url";

/// WHERE [`NEED_AGENT`]'s TRUST ANCHORS COME FROM, beside the agent's pin (Q-DEL-A2A-SPKI): each
/// registered agent's `client_identity` (`{cert, key}`, secret references), busbar's client
/// certificate for it, which the connector presents on every connection to the agent; the agent's
/// `pin` key, under `cert_spki` and `mtls`, is the far end's key the connector holds it to.
pub const CLIENT_IDENTITY_FROM: &str = "settings.*.client_identity";

/// The far end's response fields the plane reads: the answer's media type (a JSON document or an
/// event stream), and where a card fetch is redirected to.
const KEEP_RESPONSE_HEADERS: &[AbiStr] =
    &[abi_str(crate::relay::H_CONTENT_TYPE), abi_str("location")];

/// THE SECRET REFERENCES ITS SECTION HOLDS, by settings path (`*` = every registered agent): the
/// leased outbound delegation credential and busbar's own client certificate and key for a mutual
/// handshake. The kernel enumerates them so `--validate` and boot resolve each one, as 1.5.5 did.
pub const SECRET_REFS: &[AbiStr] = &[
    abi_str("settings.*.upstream_credential.secret"),
    abi_str("settings.*.client_identity.cert"),
    abi_str("settings.*.client_identity.key"),
];

/// THE PLANE'S CONNECTION NEEDS: its own outbound hops over http under the `open-web` class (public
/// destinations over a secure connection only; metadata hosts refused before the dial), with no auth
/// style and no configured target; and the relayed calls to the registered agents, governed as
/// upstreams a plane reaches, each at its own `url`: over http ([`NEED_AGENT`]) and over grpc
/// ([`NEED_GRPC`]), the two under the same trust anchors.
pub const NEEDS: &[Need] = &[
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_OPEN_WEB,
        transport: abi_str(DOCUMENT_TRANSPORT),
        auth: NONE,
        target_from: NONE,
        trust_from: NONE,
        details: Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
        },
        keep_response_headers: std::ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: 0,
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    },
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_PROVIDER,
        transport: abi_str(DOCUMENT_TRANSPORT),
        auth: NONE,
        target_from: abi_str(MEMBER_TARGET),
        trust_from: abi_str(CLIENT_IDENTITY_FROM),
        details: Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
        },
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
        egress_class: EGRESS_PROVIDER,
        transport: abi_str(FRAMED_TRANSPORT),
        auth: NONE,
        target_from: abi_str(MEMBER_TARGET),
        trust_from: abi_str(CLIENT_IDENTITY_FROM),
        details: Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
        },
        keep_response_headers: KEEP_RESPONSE_HEADERS.as_ptr(),
        keep_response_headers_len: KEEP_RESPONSE_HEADERS.len(),
        timeout_ms: 0,
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    },
];

/// THE STATEMENT TAIL: the plane's static facts.
pub const TAIL: &PlaneTail = &PlaneTail {
    head: KindTailHead {
        size: std::mem::size_of::<PlaneTail>() as u32,
        _reserved: 0,
    },
    // THE HOOK ORDER 1.5.5 USED FOR THIS PLANE (ARCHITECT ruling Q-FOLD-A2A-2; spec Part 3 section
    // 12 "Hooks", per attachment where 1.5.5 differed): the agent's gates screen the projected
    // `{tool, arguments}` first, keyed on the request's session, fail-closed, a veto at the hook's
    // own status; then its `prompt: rw` rewrites, each applied here in `project`.
    flags: TAIL_HOOKS_GATED,
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
    caller_credential_refusal: abi_str(REFUSE_PASSTHROUGH_SECTION),
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
    Route {
        verb: "POST",
        target: "/lf.a2a.v1.A2AService/{method}",
        carrier: FRAMED_TRANSPORT,
        open: false,
    },
];

/// Which line of the one A2A dialect a route is (spec ruling log 2026-09-30, a2a plane: JSON-RPC,
/// REST and gRPC are its lines, each with its own refusal dialect), or an open document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Line {
    /// The JSON-RPC endpoint, in both spellings, and one agent addressed by name.
    Document,
    /// The HTTP+JSON binding's named operations and the authenticated card.
    Target,
    /// The gRPC service.
    Framed,
    /// A discovery document, the push callback, or one agent's card.
    Open,
}

impl Line {
    /// The [`DIALECTS`] index its refusals are rendered in; `None` for an open document, whose
    /// refusals are its own slice's.
    #[must_use]
    pub const fn dialect(self) -> Option<u32> {
        match self {
            Line::Document => Some(DIALECT_DOCUMENT),
            Line::Target => Some(DIALECT_TARGET),
            Line::Framed => Some(DIALECT_FRAMED),
            Line::Open => None,
        }
    }
}

/// The line `route` is.
#[must_use]
pub fn line_of(route: &Route) -> Line {
    if route.carrier == FRAMED_TRANSPORT {
        return Line::Framed;
    }
    if route.open || (route.verb == "GET" && route.target == "/a2a/agents/{agent_id}") {
        return Line::Open;
    }
    if route.verb == "POST" && matches!(route.target, "/a2a" | "/a2a/" | "/a2a/agents/{agent_id}") {
        return Line::Document;
    }
    Line::Target
}

/// The trust verbs the plane serves on the kernel's admin mount, relative to it: `(verb, target)`;
/// then busbar's own push callback, a PUBLIC route ([`PUSH_ROUTE`]).
pub const ADMIN_VERBS: &[(&str, &str)] = &[
    ("POST", "/agents/{name}/connect"),
    ("POST", "/agents/{name}/approve"),
    ("POST", "/a2a/push"),
];

/// BUSBAR'S OWN PUSH CALLBACK's index in [`ADMIN_VERBS`]: `POST /a2a/push`, a PUBLIC route
/// (`ROUTE_PUBLIC`) on the data listener's mount beside the plane's claims, served by `serve` to
/// an agent that holds no busbar key (ARCHITECT ruling Q3c, 2026-10-04; its kernel path is
/// SEAM-4o's). It is not a claim: the plane is not a second claimant of the path.
pub const PUSH_ROUTE: usize = 2;

/// The word the kernel's audit row names each [`ADMIN_VERBS`] request by: the engine's audit verbs
/// (the shared `connect`, and `approve`); the push callback is never audited (the engine's was not).
pub const ADMIN_AUDIT_VERBS: [&str; 3] = ["connect", "approve", ""];

const fn admin_route(i: usize, flags: u32) -> AdminRoute {
    AdminRoute {
        verb: abi_str(ADMIN_VERBS[i].0),
        target: abi_str(ADMIN_VERBS[i].1),
        flags,
        _reserved: 0,
        audit_verb: abi_str(ADMIN_AUDIT_VERBS[i]),
    }
}

/// [`ADMIN_VERBS`] in the ABI's spelling.
pub const ADMIN_ROUTES: &[AdminRoute] = &[
    admin_route(0, 0),
    admin_route(1, 0),
    admin_route(PUSH_ROUTE, busbar_contract::abi::plane::ROUTE_PUBLIC),
];

/// THE TRUST VERBS' OpenAPI FRAGMENT, each path relative to the admin mount (the kernel keys it
/// under the mount): the served engine's text. Each verb's `200` names its typed body by `$ref`,
/// `approve` names its required request body (`ApproveReq`, the one-field `{"fingerprint": …}`
/// document) the same way, and the neutral `components.schemas` key carries both bodies
/// (`A2aTrustView`, `ApproveReq`) as data, since a door links no schema generator; the kernel's
/// fold inserts them into the admin document's `#/components/schemas` (ARCHITECT Q2). It is the
/// committed admin `openapi.json`'s entry verbatim (the scope, security, operation id, plane mark
/// and error statuses are the admin generator's own stamps), which the admin crate's drift test
/// holds.
pub const ADMIN_OPENAPI: &str = r##"{"/agents/{name}/connect":{"post":{"summary":"Fetch a registered agent's card, verify it against the operator's out-of-band root, and report the fingerprint. Approves nothing and writes nothing","security":[{"adminToken":[]}],"parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"OK (the derived trust state and the fingerprint a human is being asked to approve; a card that could not be authenticated is still a 200 — the reason is in `failure` and the state is `error`)","content":{"application/json":{"schema":{"$ref":"#/components/schemas/A2aTrustView"}}}}}}},"/agents/{name}/approve":{"post":{"summary":"Lock a registered agent to the card fingerprint the operator has SEEN. The card is re-fetched and re-verified, and an approval naming any other fingerprint is refused","security":[{"adminToken":[]}],"parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/ApproveReq"}}},"required":true},"responses":{"200":{"description":"OK (the registration's state AFTER the approval, read off the live registry)","content":{"application/json":{"schema":{"$ref":"#/components/schemas/A2aTrustView"}}}}}}},"components":{"schemas":{"A2aTrustView":{"description":"THE TRUST VIEW of one registered agent — what both verbs answer with.\n\nThe sibling of the tool-serving plane's trust view and shaped like it on purpose: an\noperator console rendering both planes should be rendering one component. It is NOT the same\ntype, because the two planes' capability vocabularies differ (a `tools:` entry has an approved\ndigest per tool; an `agents:` entry has a skill set on a card) and merging them would mean one\nof the planes filling in fields that mean nothing to it.","properties":{"added":{"description":"Offered now, never ruled on.","items":{"type":"string"},"type":"array"},"changed":{"description":"Approved, but offered at a DIFFERENT digest. THIS IS THE RUG-PULL ROW.","items":{"type":"string"},"type":"array"},"failure":{"description":"Why the contact failed, when it did.","type":["string","null"]},"fingerprint":{"description":"THE CANONICAL CARD FINGERPRINT AN OPERATOR IS BEING ASKED TO APPROVE. Surfaced explicitly\nrather than left for a caller to dig out, because this is the one string that goes in front\nof the human and `approve` refuses anything else.","type":["string","null"]},"name":{"type":"string"},"observed_skills":{"description":"How many skills the observation carried.","format":"uint","minimum":0,"type":"integer"},"pin_changed":{"description":"The presented identity is not the locked one. Its own axis: adopting a new identity is a\ndifferent act from adopting new content.","type":"boolean"},"pin_mechanism":{"description":"The operator's word for the authenticity root, as the OBSERVED pin names it. Never\ninterpreted by the machine.","type":"string"},"removed":{"description":"Approved, and no longer offered.","items":{"type":"string"},"type":"array"},"state":{"description":"`pending`, `approved`, `quarantined`, `suspended` or `error`. DERIVED on every read from the\nstanding approval and the sighting, so there is no stored state to go stale.","type":"string"}},"required":["name","state","pin_mechanism","fingerprint","pin_changed","added","changed","removed","observed_skills","failure"],"type":"object"},"ApproveReq":{"additionalProperties":false,"description":"The `approve` request body. ONE required field, and it is required because it is the operator's\nevidence that they looked.","properties":{"fingerprint":{"description":"The canonical card fingerprint EXACTLY as `connect` reported it.","type":"string"}},"required":["fingerprint"],"type":"object"}}}}"##;

/// THE TRUST VERBS' OpenAPI FRAGMENT ([`ADMIN_OPENAPI`]), each path keyed under `admin_prefix`
/// (the door's snapshot passes none and states the paths relative to the admin mount).
#[must_use]
pub fn openapi_fragment(admin_prefix: &str) -> serde_json::Value {
    let Ok(serde_json::Value::Object(paths)) = serde_json::from_str(ADMIN_OPENAPI) else {
        return serde_json::Value::Object(serde_json::Map::new());
    };
    serde_json::Value::Object(
        paths
            .into_iter()
            .map(|(rel, item)| {
                // The `components` key is no path: it is the bodies the paths' `$ref`s name.
                if rel == "components" {
                    (rel, item)
                } else {
                    (format!("{admin_prefix}{rel}"), item)
                }
            })
            .collect(),
    )
}

/// `validate` and `open`: the settings blob read as the `agents:` section. An empty blob is the
/// empty section. The error is the grammar's own sentence, without the JSON reader's position: the
/// kernel hands the section it read from the config file, so a position in the blob it built would
/// point nowhere the operator wrote (the kernel's own parse of the file names the line).
///
/// # Errors
///
/// The first rule the section breaks, in the grammar's words.
pub fn read_settings(settings: &[u8]) -> Result<AgentsCfg, String> {
    if settings.is_empty() {
        return Ok(AgentsCfg::default());
    }
    serde_json::from_slice::<AgentsCfg>(settings).map_err(|e| {
        let text = e.to_string();
        let at = format!(" at line {} column {}", e.line(), e.column());
        match text.strip_suffix(&at) {
            Some(sentence) if e.line() > 0 => sentence.to_string(),
            _ => text,
        }
    })
}

/// THE SECTION A DEALT `validate` BLOB CARRIES. The boot's stage-3g deal hands a declared-verb
/// plugin `{<verb>: <section>}` (`config_validate::deal`), where `open` and `refresh` are handed the
/// section itself; the one verb this plane declares is [`crate::CONFIG_SECTION`], so a blob that is
/// exactly `{agents: …}` is unwrapped to its section and any other blob is the section already.
#[must_use]
pub fn dealt_section(settings: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    match serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(settings) {
        Ok(map) if map.len() == 1 => match map.get(crate::CONFIG_SECTION) {
            Some(section) => serde_json::to_vec(section).map_or(
                std::borrow::Cow::Borrowed(settings),
                std::borrow::Cow::Owned,
            ),
            None => std::borrow::Cow::Borrowed(settings),
        },
        _ => std::borrow::Cow::Borrowed(settings),
    }
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
            .zip(ADMIN_AUDIT_VERBS)
            .map(|((r, (verb, target)), audit)| {
                AdminRouteSpec::new(verb, target, r.flags).audited(audit)
            })
            .collect(),
        openapi: Some(openapi_fragment("").to_string().into_bytes()),
        audience,
        resource_metadata,
        resource_facts: None,
    }
}

/// A route as the snapshot's claim: an open route takes no inbound credential; a target with a
/// path variable is a pattern, one level per variable, and any other target matches exactly. Its
/// refusals are rendered in its line's dialect; an open document's in the JSON-RPC one.
fn claim(r: &Route) -> ClaimSpec {
    let mut spec = ClaimSpec::new(r.verb, r.target, r.carrier, claim_flags(r));
    spec.refusal_dialect =
        u16::try_from(line_of(r).dialect().unwrap_or(DIALECT_DOCUMENT)).unwrap_or_default();
    spec
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

/// THE AUDIT ROW every admitted unit of this plane leaves (the engine's `receive::AUDIT_ACTION`),
/// written as a `RECORD_AUDIT` record write on the unit's answer (SEAM-L(k)): `applied` when the
/// unit was served (its hop left the plane, or the plane answered it), `rejected` when it was
/// refused after its admission (a gate, a budget, a breaker, a hop that never left).
pub const AUDIT_ACTION: &str = "agent.call";

/// The resource an agent's row names (the kernel's `agent_key`: `agent:<id>`).
#[must_use]
pub fn agent_resource(agent: &str) -> String {
    format!("agent:{agent}")
}

/// The resource busbar's extended card's row names: the plane pool (the `agents` section).
pub const PLANE_POOL_RESOURCE: &str = crate::CONFIG_SECTION;

/// The audit record write for `resource`, `applied` or rejected, its words in `arena`.
#[must_use]
pub fn audit_write(
    arena: &mut busbar_contract::abi::sdk::HostBuf<'_, u8>,
    resource: &str,
    applied: bool,
) -> busbar_contract::abi::plane::RecordWrite {
    use busbar_contract::abi::plane::{AUDIT_APPLIED, AUDIT_REJECTED, RECORD_AUDIT};
    busbar_contract::abi::plane::RecordWrite {
        kind: if applied {
            AUDIT_APPLIED
        } else {
            AUDIT_REJECTED
        },
        op: RECORD_AUDIT,
        key: arena.span(AUDIT_ACTION.as_bytes()),
        value: arena.span(resource.as_bytes()),
    }
}

#[cfg(test)]
#[path = "tests/door.rs"]
mod tests;
