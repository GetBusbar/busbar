// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PLANE'S DOOR: the plane kind's memory-ABI table (`busbar_contract::abi::plane`) built
//! with the SDK's `plugin_door!` on its safe surface, over the exchange's sans-I/O answers
//! ([`crate::exchange`], `BUSBAR-1.6.0.md` Part 3, section 12). [`door`] is the LINKED door; the
//! same function is the DROPPED door once a `cdylib` exports it (`examples/llm_door.rs`, through
//! `busbar_contract::export_door!`), so the two cannot answer differently. `tests/conformance.rs`
//! loads both through the one loader and requires one transcript (Part 2 #2).
//!
//! The composition root links [`door`] on its `plane-door` axis under the llm fold's
//! development-only switch `llm-on-driver` (`BUSBAR-1.6.0.md` Part 3, section 12, "The switch") and
//! binds it through the loader's one load beside the dropped-in plane doors. The default build links
//! no llm door. With the switch on, the serve path composes this door with the kernel-owned sections
//! it reads and mounts its claims as the data routes, ahead of the root's existing llm row, so every
//! arrival this door claims is served through the plane driver and the row answers none of them.
//!
//! One unit, as the plane driver serves it:
//!
//! | crossing | here |
//! |---|---|
//! | `arrive` | [`crate::exchange::arrive::arrive`]: the dialect, the operation and the model, or the previous release's refusal; a probe claim needs no principal |
//! | `on_piece`, ATTEMPT | [`crate::exchange::attempt::build`] for the member the walk picked (or [`crate::exchange::probe::request`] for a probe unit) |
//! | `on_piece`, the caller's body | the far-end body the attempt wrote for this member |
//! | `on_piece`, the far end | [`crate::exchange::reply::Reply`]: the caller's head, bytes, verdict and cumulative counts |
//! | `refusal` | [`crate::exchange::refuse`]: the declined arrival's own envelope, else the kernel's refusal in the unit's dialect |
//!
//! The plane states its paths as claims, like every plane ([`claims`], ARCHITECT Q-FL1): each
//! dialect's own paths, then the previous release's fallback as prefix claims on `/`, which the
//! claim precedence ranks below every more specific claim. Its detection decides the dialect of an
//! arrival as the previous release's did.
//!
//! An answer is computed ONCE per piece and kept with its unit: a re-call after a short answer or
//! `more = 1` re-delivers it, never re-computes it. Every kernel or far-end piece reads the host's
//! `clock.now` once ([`Services::clock_now`]); the plane reads no clock of its own.
//!
//! COUNTS, NEVER MONEY: a unit reports the far end's cumulative token counts, and each open count
//! it counted beside them ([`OPEN_CLASSES`]), in the tail's billable classes; the kernel prices
//! them.

use std::collections::{BTreeMap, HashMap};
use std::mem::size_of;
use std::ptr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::hook::{REQUEST_HAS_MAX_TOKENS, REQUEST_HAS_TOOLS, REQUEST_STREAM};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_PROVIDER, KEEP_ALL_EXCEPT_DENIED,
};
use busbar_contract::abi::host::service::ClockReading;
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, InHead, OutHead, Outcome, Span, BLOB_ABSENT,
};
use busbar_contract::abi::mechanism::door::{
    KindTailHead, Section, Statement, SECTION_CONSUMED, SECTION_DECLARING,
};
use busbar_contract::abi::mechanism::lifecycle::{
    GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, BillableClass, DialectAuth, OnPieceIn, OnPieceOut, OpClass, OutField,
    PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot,
    PlaneTail, ProjectIn, ProjectOut, RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount,
    CANCEL_ABORTED, CANCEL_OK_PARTIAL, CLAIM_EXACT, CLAIM_PROBE, EMIT_DONE, EMIT_TO_FAR_END,
    FROM_CALLER, FROM_FAR_END, FROM_KERNEL, INGRESS_REQUEST_RESPONSE, INGRESS_RESPONSE_STREAM,
    PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_NONE, PRINCIPAL_REQUIRED, REFUSAL_GATE, ROUTE_DIRECT,
    ROUTE_POOL, SHAPE_PIECEWISE, SPAN_ABSENT, TAIL_FALLBACK, TAIL_PROBES, UNITS_FLOOR,
    UNITS_REPORTED, VERDICT_HARD, VERDICT_NONE, VERDICT_OK, VERDICT_RETRY,
};
use busbar_contract::abi::plane::{PlaneCancelIn, PlaneCancelOut};
use busbar_contract::abi::plane::{RecordWrite, AUDIT_DEGRADED, AUDIT_NONE, RECORD_AUDIT};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::publish::{AdminRouteSpec, ClaimSpec, SnapshotSpec};
use busbar_contract::abi::sdk::{
    open_failed, Generations, HostBuf, Instance, Lent, Out, Safe, SafeSlot, Services,
};
use busbar_contract::abi::transport::{FAULT_CALLER, FAULT_HARD, FAULT_NONE, FAULT_TRANSIENT};
use busbar_contract::ids::{MeterClassDecl, OpClassId};
use busbar_contract::plane::PlaneMeta;
use busbar_contract::upstream::Disposition;
use serde_json::Value;

use crate::codec::ir::rerank::SEARCH_UNITS_CLASS;
use crate::dialect::DIALECTS;
use crate::exchange::arrive::{self, envelope_for, Arrived, Declined};
use crate::exchange::attempt::{self, stream_intent, FarRequest};
use crate::exchange::reply::{At, Fault, Piece, Reply, ReplyCtx, Units, Verdict};
use crate::exchange::shaping::{sections, Shaping};
use crate::exchange::{handler_of, probe, project, refuse};
use crate::LlmPlane;

// ── the Statement ────────────────────────────────────────────────────────────────────────────────

/// The version the Statement names: the crate's (a test pins the two equal).
pub const VERSION: &str = "1.6.0";

/// The most calls the kernel keeps in flight on one instance.
const MAX_INFLIGHT: u32 = 1024;

/// The human label.
const LABEL: &str = "LLM";
/// One registration of the `pools:` map.
const POOL_NOUN: &str = "pool";

/// The transport claim a far end is reached over.
const TRANSPORT: &str = "http";

/// An absent string.
const NONE: AbiStr = AbiStr {
    ptr: ptr::null(),
    len: 0,
};

const fn section(name: &'static str, flags: u32) -> Section {
    Section {
        name: abi_str(name),
        flags,
        _reserved: 0,
    }
}

/// `pools:` declared; `providers:`, `models:` and `limits:` read beside it.
const SECTIONS: &[Section] = &[
    section(sections::POOLS, SECTION_DECLARING),
    section(sections::PROVIDERS, SECTION_CONSUMED),
    section(sections::MODELS, SECTION_CONSUMED),
    section(sections::LIMITS, SECTION_CONSUMED),
    // The plane's own: the webhook receivers it answers on public routes (new in 1.6.0).
    section(crate::exchange::webhook::SECTION, 0),
];

const OPS: &[OpClassId] = <LlmPlane as PlaneMeta>::OP_CLASSES;
const METER: &[MeterClassDecl] = <LlmPlane as PlaneMeta>::METER_CLASSES;

const fn dialect(i: usize) -> AbiStr {
    abi_str(DIALECTS[i].name)
}

const fn op(i: usize) -> OpClass {
    let name = abi_str(OPS[i].as_str());
    OpClass { op: name, name }
}

/// THE TOKEN CLASSES' CARD NAMES, in [`METER`]'s order: the classes 1.5.5's `rate_card:` prices
/// (`input`, `output`, `cache_read`, `cache_write`), which the previous release's plane declaration
/// ledgered its four token tiers under, so a door-served count is priced by the card as written.
pub const TOKEN_CLASSES: [&str; 4] = [
    busbar_contract::records::UNIT_INPUT,
    busbar_contract::records::UNIT_OUTPUT,
    busbar_contract::records::UNIT_CACHE_READ,
    busbar_contract::records::UNIT_CACHE_WRITE,
];

const fn billable(i: usize) -> BillableClass {
    BillableClass {
        class: abi_str(TOKEN_CLASSES[i]),
        family: abi_str(METER[i].family),
    }
}

const DIALECT_NAMES: &[AbiStr] = &[
    dialect(0),
    dialect(1),
    dialect(2),
    dialect(3),
    dialect(4),
    dialect(5),
];
const OP_CLASSES: &[OpClass] = &[op(0), op(1), op(2), op(3), op(4), op(5), op(6)];
/// THE OPEN CLASSES a far end counts beside its tokens, each `(class, family)`: every name the
/// reply can report in its open counts, enumerated from the codec (a counted billing names its
/// class there, and only a rerank's search units do: `codec/ir/rerank.rs`, priced under
/// `rate_card.<model>.units`), so no reported count is dropped. They follow the token classes in
/// the tail's billable classes.
pub const OPEN_CLASSES: &[(&str, &str)] = &[(SEARCH_UNITS_CLASS, "units")];

const fn open_class(k: usize) -> BillableClass {
    BillableClass {
        class: abi_str(OPEN_CLASSES[k].0),
        family: abi_str(OPEN_CLASSES[k].1),
    }
}

/// THE FEE UNIT the plane counts: one per billable request (`busbar_contract::plane::PER_REQUEST`),
/// reported as a count of 1 exactly where 1.5.5 billed its flat request fee (a reply whose caller
/// status is a success) and never where 1.5.5 refunded it (owner #77, money-B1: the plane's report is
/// the ONE fee decider). It is the last of the tail's billable classes, and never usage.
pub const FEE_CLASS: &str = busbar_contract::plane::PER_REQUEST;
/// [`FEE_CLASS`]'s index in the tail's billable classes.
pub const FEE_CLASS_INDEX: u32 = (METER.len() + OPEN_CLASSES.len()) as u32;

const BILLABLE_CLASSES: &[BillableClass] = &[
    billable(0),
    billable(1),
    billable(2),
    billable(3),
    open_class(0),
    BillableClass {
        class: abi_str(FEE_CLASS),
        family: abi_str("request"),
    },
];
/// The tail's fee units: [`FEE_CLASS`].
const FEE_UNITS: &[AbiStr] = &[abi_str(FEE_CLASS)];
const _: () = assert!(
    DIALECTS.len() == DIALECT_NAMES.len()
        && OPS.len() == OP_CLASSES.len()
        && METER.len() + OPEN_CLASSES.len() + 1 == BILLABLE_CLASSES.len(),
    "the tail states every dialect, op class and token class the plane declares"
);

/// THE OUTBOUND AUTH STYLES THE PLANE'S MEMBERS ARE BOUND UNDER (the design's auth points): each
/// dialect's default ([`DIALECTS`]' `egress_style`), then the provider `auth:` overrides the
/// configuration grammar accepts (`api-key` is also a dialect default), each named once. One
/// outbound need per style ([`NEEDS`]): a member dials the need its resolved style names.
pub const EGRESS_STYLES: &[&str] = &[
    DIALECTS[1].egress_style,
    DIALECTS[0].egress_style,
    DIALECTS[2].egress_style,
    DIALECTS[3].egress_style,
    "jwt-bearer",
    "oauth-client-credentials",
];
const _: () = assert!(
    const_eq(DIALECTS[1].egress_style, DIALECTS[4].egress_style)
        && const_eq(DIALECTS[1].egress_style, DIALECTS[5].egress_style)
        && !const_eq(DIALECTS[0].egress_style, DIALECTS[1].egress_style)
        && !const_eq(DIALECTS[2].egress_style, DIALECTS[1].egress_style)
        && !const_eq(DIALECTS[3].egress_style, DIALECTS[1].egress_style),
    "EGRESS_STYLES names every dialect's default style, each once"
);

const fn dialect_auth(i: usize) -> DialectAuth {
    let params = DIALECTS[i].egress_params.as_bytes();
    DialectAuth {
        dialect: i as u32,
        _reserved: 0,
        style: abi_str(DIALECTS[i].egress_style),
        // The default style's parameters (ARCHITECT RULING 2026-10-03, Q-L6-AUTHPARAMS).
        params: if params.is_empty() {
            Blob::ABSENT
        } else {
            Blob {
                ptr: params.as_ptr(),
                len: params.len(),
                fmt: busbar_contract::abi::mechanism::call::BLOB_JSON,
                flags: 0,
            }
        },
    }
}

/// THE TAIL'S `dialect_auth`: each dialect's default outbound style (ARCHITECT Q-L1-AUTH (A)).
const DIALECT_AUTH: &[DialectAuth] = &[
    dialect_auth(0),
    dialect_auth(1),
    dialect_auth(2),
    dialect_auth(3),
    dialect_auth(4),
    dialect_auth(5),
];

const fn const_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The response head fields the plane never reads, beyond the kernel's own strip list: what a far
/// end derives from busbar's own credential and tenant, every dialect's governed response fields
/// ([`DIALECTS`]' `governed_response_headers`, each named once). Every other field crosses, so a
/// same-dialect answer relays the far end's head (OWNER ruling 2026-10-02, dialect fidelity F2).
pub const DENY_RESPONSE_HEADERS: &[&str] = &[
    DIALECTS[0].governed_response_headers[0],
    DIALECTS[1].governed_response_headers[0],
    DIALECTS[1].governed_response_headers[1],
];
const DENIED: &[AbiStr] = &[
    abi_str(DENY_RESPONSE_HEADERS[0]),
    abi_str(DENY_RESPONSE_HEADERS[1]),
    abi_str(DENY_RESPONSE_HEADERS[2]),
];

const fn need(auth: &'static str) -> Need {
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_PROVIDER,
        transport: abi_str(TRANSPORT),
        auth: abi_str(auth),
        target_from: NONE,
        trust_from: NONE,
        details: Blob {
            ptr: ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
        },
        keep_response_headers: ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: 0,
        keep_mode: KEEP_ALL_EXCEPT_DENIED,
        _reserved: 0,
        deny_response_headers: DENIED.as_ptr(),
        deny_response_headers_len: DENIED.len(),
    }
}

/// THE PLANE'S NEEDS: outbound to a configured provider over the claim's transport, one per
/// outbound style a member may be bound under ([`EGRESS_STYLES`]), each naming its style, as the
/// decisions plane's one need names its.
pub const NEEDS: &[Need] = &[
    need(EGRESS_STYLES[0]),
    need(EGRESS_STYLES[1]),
    need(EGRESS_STYLES[2]),
    need(EGRESS_STYLES[3]),
    need(EGRESS_STYLES[4]),
    need(EGRESS_STYLES[5]),
];

/// THE RESOURCE A GRANT NAMES on this plane: a pool (a key's `allowed_pools`, the previous release's
/// `scope_kinds: ["pool"]`), so the kernel judges a route as named against the caller's grant.
const SCOPE_KINDS: &[AbiStr] = &[abi_str("pool")];

/// THE STATEMENT TAIL: the plane's static facts.
pub const TAIL: &PlaneTail = &PlaneTail {
    head: KindTailHead {
        size: size_of::<PlaneTail>() as u32,
        _reserved: 0,
    },
    flags: TAIL_FALLBACK | TAIL_PROBES,
    ingress: INGRESS_REQUEST_RESPONSE | INGRESS_RESPONSE_STREAM,
    // The kernel pushes the caller's body and the far end's answer piece by piece.
    dispatch_shape: SHAPE_PIECEWISE,
    _reserved: 0,
    scope: abi_str(sections::POOLS),
    label: abi_str(LABEL),
    // What one registration of the `pools:` map is called, in a refusal naming it ("a pool may not
    // be named `hooks`") and in the admin surface, as the previous release's declaration named it.
    subject_noun: abi_str(POOL_NOUN),
    admin_noun: abi_str(POOL_NOUN),
    audit_kind: NONE,
    signing_domain: NONE,
    signing_kid_prefix: NONE,
    cli_help: NONE,
    dialects: DIALECT_NAMES.as_ptr(),
    dialects_len: DIALECT_NAMES.len(),
    dialect_auth: DIALECT_AUTH.as_ptr(),
    dialect_auth_len: DIALECT_AUTH.len(),
    scope_kinds: SCOPE_KINDS.as_ptr(),
    scope_kinds_len: SCOPE_KINDS.len(),
    op_classes: OP_CLASSES.as_ptr(),
    op_classes_len: OP_CLASSES.len(),
    billable_classes: BILLABLE_CLASSES.as_ptr(),
    billable_classes_len: BILLABLE_CLASSES.len(),
    route_cost: ptr::null(),
    route_cost_len: 0,
    fee_units: FEE_UNITS.as_ptr(),
    fee_units_len: FEE_UNITS.len(),
    record_kinds: ptr::null(),
    record_kinds_len: 0,
    egress_targets: ptr::null(),
    egress_targets_len: 0,
    record_chains: ptr::null(),
    record_chains_len: 0,
    trust_keys: ptr::null(),
    trust_keys_len: 0,
    refusal_statuses: crate::refusal::REFUSAL_STATUSES.as_ptr(),
    refusal_statuses_len: crate::refusal::REFUSAL_STATUSES.len(),
    caller_credential_refusal: NONE,
    admin_routes: ptr::null(),
    admin_routes_len: 0,
    admin_openapi: Blob::ABSENT,
};

/// THE STATEMENT: the plane's key and version, its sections, its needs and its tail.
pub const STATEMENT: Statement = Statement {
    kind_tail: ptr::from_ref(TAIL).cast::<KindTailHead>(),
    sections: SECTIONS.as_ptr(),
    sections_len: SECTIONS.len(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    ..statement(<LlmPlane as PlaneMeta>::KEY, VERSION, MAX_INFLIGHT)
};

// ── the settings ─────────────────────────────────────────────────────────────────────────────────

/// The settings blob read as the plane's tables: `{section: value}` for the sections it reads; an
/// empty blob is no section at all.
///
/// # Errors
///
/// Why the blob does not describe a generation the plane can serve.
pub fn read_settings(settings: &[u8]) -> Result<Shaping, String> {
    let value = if settings.is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_slice(settings).map_err(|e| e.to_string())?
    };
    Shaping::from_settings(&value)
}

// ── what the door keeps ──────────────────────────────────────────────────────────────────────────

/// One answer to one piece, in plain data, before it is written into the host's buffers.
#[derive(Debug, Default)]
struct Answer {
    /// The bytes and fields are bound for the far end; otherwise for the caller.
    to_far_end: bool,
    /// The far-end request's verb and target, on the answer that opens it.
    request: Option<(Vec<u8>, Vec<u8>)>,
    /// The caller's status, on the answer that opens the caller's reply; `0` otherwise.
    status: u32,
    /// Head fields: the far-end request's, or the caller's reply's.
    fields: Vec<(Vec<u8>, Vec<u8>)>,
    /// The bytes.
    bytes: Vec<u8>,
    /// The cumulative units.
    units: Vec<UnitCount>,
    /// `VERDICT_*`.
    verdict: u32,
    /// `FAULT_*`: the breaker's reading of this answer, written once, on its first window.
    fault: u8,
    /// The caller's reply is complete.
    done: bool,
    /// The unit's audit rows, `(action, resource)`, each written as a degraded `RECORD_AUDIT`:
    /// what a TRANSLATE attempt could not carry (1.5.5's `egress.control_unrepresentable` rows).
    audits: Vec<(Vec<u8>, Vec<u8>)>,
}

/// The action of a dropped control's audit row (1.5.5's).
const DROPPED_CONTROL: &[u8] = b"egress.control_unrepresentable";

impl Answer {
    /// The walk ends here: nothing for the far end, nothing more for the caller.
    fn hard() -> Self {
        Answer {
            verdict: VERDICT_HARD,
            done: true,
            ..Answer::default()
        }
    }
}

/// An answer part-way out.
#[derive(Debug)]
struct Pending {
    answer: Answer,
    /// Bytes of `answer.bytes` already emitted.
    sent: usize,
    /// The head, fields and units are out.
    opened: bool,
}

/// What the door keeps for one unit, from its `arrive` to its end.
struct UnitState {
    /// The generation's tables the unit arrived on.
    shaping: Arc<Shaping>,
    /// The arrival, read once at `arrive`.
    arrived: Option<Arrived>,
    /// The caller's head fields, kept for every attempt's request.
    caller: Vec<(Vec<u8>, Vec<u8>)>,
    /// The arrival's refusal, rendered from at `refusal`.
    declined: Option<Declined>,
    /// A probe unit: no caller, one member.
    probe: bool,
    /// The current attempt's member.
    member: String,
    /// The request the current attempt wrote.
    request: Option<FarRequest>,
    /// The current attempt's answer.
    reply: Option<Reply>,
    /// The clock at the attempt's start (monotonic nanoseconds).
    started: Option<u64>,
    /// The answer the driver's re-call is owed.
    pending: Option<Pending>,
    /// `project` found the body unreadable: the unit's refusal reads the previous release's
    /// unreadable-body sentence.
    unreadable: bool,
    /// The far end's last cumulative counts, as the unit last reported them.
    reported: Vec<UnitCount>,
    /// The caller was answered under a success status: the request's fee unit was incurred.
    fee: bool,
}

impl UnitState {
    fn new(shaping: Arc<Shaping>) -> Self {
        UnitState {
            shaping,
            arrived: None,
            caller: Vec::new(),
            declined: None,
            probe: false,
            member: String::new(),
            request: None,
            reply: None,
            started: None,
            pending: None,
            unreadable: false,
            reported: Vec::new(),
            fee: false,
        }
    }

    fn caller_fields(&self) -> Vec<(&[u8], &[u8])> {
        self.caller
            .iter()
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
            .collect()
    }
}

/// One instance: every live generation's snapshot and tables, the units in flight, and the host's
/// clock.
pub struct LlmDoor {
    generations: Generations<PlaneSnapshot>,
    shapings: Mutex<BTreeMap<u64, Arc<Shaping>>>,
    units: Mutex<HashMap<u64, UnitState>>,
    tickets: Mutex<HashMap<Ticket, u64>>,
    services: Option<Services>,
    /// The public webhook routes its owned section states, in the order its snapshot states them:
    /// `serve`'s route index names one.
    webhooks: Vec<AdminRouteSpec>,
}

/// A lock, through a poisoning: the maps it guards hold no invariant a panicking holder breaks.
fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl LlmDoor {
    /// The newest generation's tables.
    fn current(&self) -> Option<Arc<Shaping>> {
        guard(&self.shapings)
            .last_key_value()
            .map(|(_, s)| Arc::clone(s))
    }

    /// One reading of the host's clock; none when the host serves no clock.
    fn clock(&self) -> Option<ClockReading> {
        let handle = CompletionHandle {
            ticket: Ticket::NONE,
            seq: 0,
            _reserved: 0,
        };
        self.services.and_then(|s| s.clock_now(handle).ok())
    }
}

// ── the claims ───────────────────────────────────────────────────────────────────────────────────

/// One claim: its verb, its target, whether the target is exact (else its whole subtree), and the
/// dialect a refusal on it wears before `arrive` has read the arrival.
type ClaimRow = (&'static str, &'static str, bool, &'static str);

/// The verbs the previous release's fallback answered on any path (a dialect path hit with another
/// verb reads the dialect's 405 from `arrive`; any other path its not-found).
const FALLBACK_VERBS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/// THE DIALECTS' OWN PATHS (ARCHITECT Q-FL1, 2026-10-02), each with the dialect its path shape
/// names (the rule [`crate::exchange::arrive::envelope_for`] renders a refusal by): exact where
/// the previous release named one path, the whole subtree where it named a family.
const DIALECT_CLAIMS: [ClaimRow; 7] = [
    ("POST", "/v1/messages", true, "anthropic"),
    ("POST", "/v1/chat/completions", true, "openai"),
    ("POST", "/v1/responses", true, "responses"),
    ("POST", "/v2/chat", true, "cohere"),
    ("POST", "/v1beta/models", false, "gemini"),
    ("POST", "/model", false, "bedrock"),
    ("POST", "/v1/models", false, "openai"),
];

/// THE PLANE'S CLAIMS: [`DIALECT_CLAIMS`], then the previous release's fallback, a prefix claim on
/// `/` per verb wearing the residual default dialect. The fallback reaches every path at any depth
/// no more specific claim or kernel route takes (CG-62); the router has no plane-shaped branch.
#[must_use]
pub fn claims() -> Vec<ClaimSpec> {
    let fallback = crate::exchange::arrive::envelope_for("/");
    DIALECT_CLAIMS
        .iter()
        .copied()
        .chain(
            FALLBACK_VERBS
                .iter()
                .map(|&verb| (verb, "/", false, fallback)),
        )
        .map(|(verb, target, exact, dialect)| {
            let flags = if exact { CLAIM_EXACT } else { 0 };
            let mut claim = ClaimSpec::new(verb, target, TRANSPORT, flags);
            claim.refusal_dialect = u16::try_from(dialect_index(dialect)).unwrap_or(0);
            claim
        })
        .collect()
}

/// The generation's snapshot: the plane's claims.
fn snapshot(webhooks: &[AdminRouteSpec]) -> SnapshotSpec {
    SnapshotSpec {
        claims: claims(),
        admin_routes: webhooks.to_vec(),
        ..SnapshotSpec::default()
    }
}

// ── the answers ──────────────────────────────────────────────────────────────────────────────────

fn dialect_index(name: &str) -> u32 {
    DIALECTS
        .iter()
        .position(|d| d.name == name)
        .and_then(|i| u32::try_from(i).ok())
        .unwrap_or(0)
}

/// THE ROUTE AN ARRIVAL NAMES (ARCHITECT Q-SW6 / Q-FL3, 2026-10-02): the model it asked for, as the
/// entry inside the plane's own sections, and what that entry is. The previous release resolved the
/// model as a pool first, then as a configured model (its by-model lane); the plane says which by its
/// own tables, and the kernel resolves the entry. A model that is neither is named as a direct entry
/// the kernel does not hold, so the kernel refuses it (`no_destination`, rendered as 1.5.5's 404).
#[must_use]
pub fn route_of<'a>(shaping: &Shaping, model: &'a str) -> (u8, &'a str) {
    let class = if shaping.pools.contains_key(model) {
        ROUTE_POOL
    } else {
        ROUTE_DIRECT
    };
    (class, model)
}

fn op_class_index(arrived: &Arrived) -> u32 {
    OPS.iter()
        .position(|op| op.as_str() == arrived.operation.name())
        .and_then(|i| u32::try_from(i).ok())
        .unwrap_or(0)
}

fn owned(fields: &[(String, Vec<u8>)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    fields
        .iter()
        .map(|(n, v)| (n.as_bytes().to_vec(), v.clone()))
        .collect()
}

/// The far end's cumulative counts, in the tail's billable-class order: tokens in, tokens out,
/// cache read, cache write, then each open class it counted ([`OPEN_CLASSES`]). Nothing until the
/// far end has reported a count.
#[must_use]
pub fn counts(units: &Units) -> Vec<UnitCount> {
    let tokens = [
        units.tokens_in,
        units.tokens_out,
        units.cache_read,
        units.cache_write,
    ];
    let mut out = Vec::new();
    let source = if units.floor {
        UNITS_FLOOR
    } else {
        UNITS_REPORTED
    };
    if units.stated || tokens.iter().any(|&n| n != 0) {
        out.extend(tokens.iter().zip(0u32..).map(|(&amount, class)| UnitCount {
            class,
            source,
            amount,
        }));
    }
    for (name, &amount) in &units.open {
        match OPEN_CLASSES
            .iter()
            .position(|(class, _)| *class == name.as_str())
        {
            Some(k) => out.push(UnitCount {
                class: u32::try_from(METER.len() + k).unwrap_or(u32::MAX),
                source: UNITS_REPORTED,
                amount,
            }),
            // Every open class the codec can count is stated above: a name outside the table is a
            // defect, reported, never counted as zero in silence.
            None => {
                tracing::warn!(class = %name, "an open count names a class the plane does not state");
            }
        }
    }
    out
}

/// THE BREAKER'S READING of a judged answer (ARCHITECT BREAKER OUTCOME: one neutral vocabulary,
/// stated apart from the walk's verdict), as 1.5.5's classifier recorded it per disposition (v1.5.5
/// `crates/busbar-llm/src/engine/attempt/classify.rs`): the caller's own bad input records nothing
/// against the destination; a transient failure (an `error_map` entry naming `rate_limit` among
/// them) counts toward the pool cell's trip; a refused credential or account trips every cell; a
/// request too large for the window fails over with nothing recorded. A 2xx that failed after its
/// head (a stream's terminal error, a cut body, an untranslatable answer, a failed generation) is
/// the compensating transient 1.5.5 recorded.
#[must_use]
pub fn breaker_fault(f: Option<&Fault>) -> u8 {
    match f {
        None => FAULT_NONE,
        Some(Fault::Transient(_)) => FAULT_TRANSIENT,
        Some(Fault::Judged { disposition, .. }) => match disposition {
            Disposition::ClientFault => FAULT_CALLER,
            Disposition::TransientUpstream => FAULT_TRANSIENT,
            Disposition::HardDown => FAULT_HARD,
            Disposition::ContextLength => FAULT_NONE,
        },
    }
}

fn verdict(v: Verdict) -> u32 {
    match v {
        Verdict::None => VERDICT_NONE,
        Verdict::Ok => VERDICT_OK,
        Verdict::Retry => VERDICT_RETRY,
        Verdict::Hard => VERDICT_HARD,
    }
}

/// THE REQUEST'S FEE UNIT on `answer` (owner #77, money-B1: the plane's report is the one fee
/// decider): incurred when the caller's reply opens under a success status, which is where 1.5.5
/// kept its flat request fee (its finish refunded the fee for a non-2xx caller status, and only
/// then). From that answer on, every answer that carries counts carries the fee unit's 1 beside the
/// far end's last cumulative counts; an answer that carries none leaves the last report standing.
/// A probe is no billable request.
fn fee_unit(unit: &mut UnitState, answer: &mut Answer) {
    if !answer.units.is_empty() {
        unit.reported.clone_from(&answer.units);
    }
    let incurred =
        !unit.fee && !unit.probe && !answer.to_far_end && (200..=299).contains(&answer.status);
    unit.fee |= incurred;
    if unit.fee && (incurred || !answer.units.is_empty()) {
        answer.units.clone_from(&unit.reported);
        answer.units.push(UnitCount {
            class: FEE_CLASS_INDEX,
            source: UNITS_REPORTED,
            amount: 1,
        });
    }
}

/// THE UNIT'S STICKY-ROUTING KEY, as 1.5.5 derived it (v1.5.5 `crates/busbar/src/ingress/mod.rs`
/// `affinity_header_for`, `crates/busbar/src/proxy/engine/mod.rs` the affinity hash): the value of
/// the pool's affinity header (`header`, matched case-blind) where the caller sent one readable as
/// text, else the operation's body key (chat's non-empty `system`); `None` = no affinity. The kernel
/// hashes it and picks the member; the plane never does.
#[must_use]
pub fn affinity_key(
    header: &str,
    caller: &[(&[u8], &[u8])],
    handler: Option<&dyn busbar_contract::codec::OperationHandler>,
    body: Option<&Value>,
) -> Option<String> {
    let visible = |v: &[u8]| v.iter().all(|b| *b == b'\t' || (0x20..0x7f).contains(b));
    caller
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(header.as_bytes()))
        .map(|(_, v)| *v)
        .filter(|v| visible(v))
        .and_then(|v| std::str::from_utf8(v).ok())
        .map(str::to_string)
        .or_else(|| {
            let (h, b) = (handler?, body?);
            h.body_affinity_key(b).map(str::to_string)
        })
}

/// A reply piece as the caller's answer.
fn to_caller(piece: Piece<'_>) -> Answer {
    let fault = breaker_fault(piece.fault.as_ref());
    let (status, fields) = piece
        .head
        .map_or((0, Vec::new()), |h| (u32::from(h.status), owned(&h.fields)));
    Answer {
        status,
        fields,
        bytes: piece.bytes.into_owned(),
        units: counts(&piece.units),
        verdict: verdict(piece.verdict),
        fault,
        done: piece.done,
        ..Answer::default()
    }
}

/// A rendered refusal as the caller's whole answer.
fn answered(r: refuse::Rendered) -> Answer {
    Answer {
        status: u32::from(r.status),
        fields: owned(&r.fields),
        bytes: r.body,
        done: true,
        ..Answer::default()
    }
}

/// The time-like inputs of a far-end piece, from the host's clock.
fn at(clock: Option<ClockReading>, started: Option<u64>) -> At {
    match clock {
        Some(c) => At {
            now_s: c.wall_ns / 1_000_000_000,
            elapsed_ms: started.map(|s| c.mono_ns.saturating_sub(s) / 1_000_000),
        },
        None => At::default(),
    }
}

/// One piece of a unit, as `on_piece` lends it.
struct PieceIn<'a> {
    last: bool,
    status: Option<u32>,
    fields: Vec<(&'a [u8], &'a [u8])>,
    bytes: &'a [u8],
    member: &'a [u8],
    pool: &'a [u8],
    passthrough: bool,
    clock: Option<ClockReading>,
}

/// An ATTEMPT: the far-end request for the member the walk picked.
fn attempt(unit: &mut UnitState, piece: &PieceIn<'_>) -> Answer {
    unit.member = String::from_utf8_lossy(piece.member).into_owned();
    unit.reply = None;
    unit.request = None;
    unit.started = piece.clock.map(|c| c.mono_ns);
    let built = if unit.probe {
        unit.shaping
            .lane(&unit.member)
            .and_then(probe::request)
            .ok_or(None)
    } else if let Some(arrived) = &unit.arrived {
        let pool = String::from_utf8_lossy(piece.pool);
        let caller = unit.caller_fields();
        attempt::build(arrived, &caller, &unit.shaping, &pool, &unit.member).map_err(Some)
    } else {
        Err(None)
    };
    match built {
        Ok(request) => {
            // A control the far end's dialect cannot carry, one degraded row each (`<control> on
            // <dialect>`, the row 1.5.5 wrote as it translated the request).
            let egress = unit.shaping.lane(&unit.member).map_or("", |l| l.dialect);
            let answer = Answer {
                to_far_end: true,
                request: Some((
                    request.verb.as_bytes().to_vec(),
                    request.target.as_bytes().to_vec(),
                )),
                fields: owned(&request.fields),
                audits: request
                    .dropped_controls
                    .iter()
                    .map(|c| {
                        (
                            DROPPED_CONTROL.to_vec(),
                            format!("{c} on {egress}").into_bytes(),
                        )
                    })
                    .collect(),
                ..Answer::default()
            };
            unit.request = Some(request);
            answer
        }
        // The attempt answers the caller itself: the far end is not reached.
        Err(Some(refused)) => answered(refuse::answered(&refused)),
        Err(None) => Answer::hard(),
    }
}

/// One piece of the far end's answer.
fn far_end(unit: &mut UnitState, piece: &PieceIn<'_>) -> Answer {
    let Some(lane) = unit.shaping.lane(&unit.member) else {
        return Answer::hard();
    };
    // A probe's answer is the far end's own: the breaker classifies it by its status.
    let Some(arrived) = &unit.arrived else {
        let v = match piece.status {
            None => VERDICT_NONE,
            Some(s) if (200..300).contains(&s) => VERDICT_OK,
            Some(_) => VERDICT_HARD,
        };
        return Answer {
            status: piece.status.unwrap_or(0),
            bytes: piece.bytes.to_vec(),
            verdict: v,
            done: piece.last,
            ..Answer::default()
        };
    };
    let ctx = ReplyCtx {
        arrived,
        lane,
        intent: handler_of(arrived)
            .map(|h| stream_intent(h, arrived.parsed.as_ref()))
            .unwrap_or_default(),
        passthrough: piece.passthrough,
    };
    if let Some(status) = piece.status {
        unit.reply = Some(Reply::new(
            &ctx,
            u16::try_from(status).unwrap_or(0),
            &piece.fields,
        ));
    }
    let Some(reply) = unit.reply.as_mut() else {
        return Answer::hard();
    };
    let mut fed = reply.feed(&ctx, piece.bytes, piece.last, at(piece.clock, unit.started));
    // An answer member the caller's dialect has no form for, one degraded row each (`<path> from
    // <dialect>`, the row 1.5.5 wrote as it delivered the translated answer).
    let dropped = std::mem::take(&mut fed.dropped);
    let mut answer = to_caller(fed);
    answer.audits = dropped
        .iter()
        .map(|p| {
            (
                DROPPED_CONTROL.to_vec(),
                format!("{p} from {}", lane.dialect).into_bytes(),
            )
        })
        .collect();
    answer
}

/// The plane's answer to one piece.
fn answer(unit: &mut UnitState, from: u32, piece: &PieceIn<'_>) -> Answer {
    match from {
        FROM_KERNEL => attempt(unit, piece),
        // The kernel re-pushes the caller's body on every attempt; what goes to the far end is the
        // body the attempt wrote for this member.
        FROM_CALLER => Answer {
            to_far_end: true,
            bytes: unit
                .request
                .as_ref()
                .map(|r| r.body.clone())
                .unwrap_or_default(),
            ..Answer::default()
        },
        FROM_FAR_END => far_end(unit, piece),
        _ => Answer::hard(),
    }
}

// ── the host buffers ─────────────────────────────────────────────────────────────────────────────

/// `(written, needed)` of every buffer an answer fills, short as a whole when one is short.
fn settle(
    out: &mut Out<'_, OnPieceOut>,
    fields: &HostBuf<'_, OutField>,
    units: &HostBuf<'_, UnitCount>,
    records: &HostBuf<'_, RecordWrite>,
    arena: &HostBuf<'_, u8>,
) -> bool {
    let short = !(fields.fits() && units.fits() && records.fits() && arena.fits());
    let (fw, fnd) = fields.settle(short);
    let (uw, und) = units.settle(short);
    let (rw, rnd) = records.settle(short);
    let (aw, and) = arena.settle(short);
    out.set(|o| &o.records_written, rw as u32);
    out.set(|o| &o.records_needed, rnd as u32);
    out.set(|o| &o.fields_written, fw as u32);
    out.set(|o| &o.fields_needed, fnd as u32);
    out.set(|o| &o.units_written, uw as u32);
    out.set(|o| &o.units_needed, und as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, and as u64);
    short
}

/// Write the unit's pending answer's next chunk: its head, fields and units first (FAILED, with
/// the sizes it needs, when they do not fit), then as many bytes as the reply buffer holds,
/// `more = 1` while any are left. Answers the outcome and whether the caller's reply is complete.
fn deliver(
    unit: &mut UnitState,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> (Outcome, bool) {
    let Some(p) = unit.pending.as_mut() else {
        return (Outcome::Fault, false);
    };
    if !p.opened {
        let (mut fields, mut units, mut records, mut arena) = (
            input.fields_buf(),
            input.units_buf(),
            input.records_buf(),
            input.arena_buf(),
        );
        let request = p
            .answer
            .request
            .as_ref()
            .map(|(v, t)| (arena.span(v), arena.span(t)));
        for (name, value) in &p.answer.fields {
            fields.push(OutField {
                name: arena.span(name),
                value: arena.span(value),
            });
        }
        units.extend(&p.answer.units);
        for (action, resource) in &p.answer.audits {
            records.push(RecordWrite {
                kind: AUDIT_DEGRADED,
                op: RECORD_AUDIT,
                key: arena.span(action),
                value: arena.span(resource),
            });
        }
        if settle(out, &fields, &units, &records, &arena) {
            return (Outcome::Failed, false);
        }
        if let Some((verb, target)) = request {
            out.set(|o| &o.verb, verb);
            out.set(|o| &o.target, target);
        }
        out.set(|o| &o.reply_status, p.answer.status);
        p.opened = true;
    }
    let rest = &p.answer.bytes[p.sent..];
    let n = input.reply_buf().stream(rest);
    if n == 0 && !rest.is_empty() {
        // No room for a single byte: `more = 1` with nothing emitted is a FAULT by the contract.
        return (Outcome::Fault, false);
    }
    p.sent += n;
    let more = p.sent < p.answer.bytes.len();
    let to_far_end = p.answer.to_far_end;
    let done = p.answer.done && !more;
    let far = if to_far_end { EMIT_TO_FAR_END } else { 0 };
    out.set(|o| &o.emitted, n as u64);
    out.set(|o| &o.more, u32::from(more));
    out.set(|o| &o.verdict, p.answer.verdict);
    // Once per answer: a reading recorded on every window of a long answer would count it again.
    out.set(|o| &o.fault, std::mem::take(&mut p.answer.fault));
    out.set(|o| &o.flags, far | if done { EMIT_DONE } else { 0 });
    if !more {
        unit.pending = None;
    }
    (Outcome::Ready, done && !to_far_end)
}

// ── the slots ────────────────────────────────────────────────────────────────────────────────────

/// One slot body on the SDK's safe surface, over this plane's [`LlmDoor`].
macro_rules! slot {
    ($(#[$doc:meta])* $name:ident, $in:ty, $out:ty,
     |$inst:pat_param, $input:pat_param, $o:pat_param| $body:block) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = LlmDoor;
            fn call($inst: Instance<'_, LlmDoor>, $input: Lent<'_, $in>, $o: Out<'_, $out>)
                -> Outcome $body
        }
    };
}

slot!(
    /// `validate`: the settings read as the plane's tables, or refused in the reader's words.
    Validate, ValidateIn, OutHead, |_, input, mut out| {
        match read_settings(input.field(|i| &i.settings).bytes()) {
            Ok(_) => Outcome::Ready,
            Err(words) => out.fail(Refusal::refused(words)),
        }
    }
);

slot!(
    /// `open`: the instance, its host clock, and the first generation's tables and snapshot.
    Open, PlaneOpenIn, PlaneOpenOut, |instance, input, mut out| {
        let open = input.field(|i| &i.open);
        let shaping = match read_settings(open.field(|o| &o.settings).bytes()) {
            Ok(shaping) => shaping,
            Err(words) => return open_failed(open, &mut out, |o| &o.open.err_len, &words),
        };
        let webhooks = match crate::exchange::webhook::routes(input.field(|i| &i.owned).bytes()) {
            Ok(routes) => routes,
            Err(words) => return open_failed(open, &mut out, |o| &o.open.err_len, &words),
        };
        let door = LlmDoor {
            generations: Generations::new(),
            shapings: Mutex::new(BTreeMap::from([(open.generation, Arc::new(shaping))])),
            units: Mutex::new(HashMap::new()),
            tickets: Mutex::new(HashMap::new()),
            services: open.host().and_then(|h| Services::of(&h)),
            webhooks,
        };
        let spec = snapshot(&door.webhooks);
        out.publish(|o| &o.snapshot, &door.generations, open.generation, &spec);
        instance.open(door);
        Outcome::Ready
    }
);

slot!(
    /// `refresh`: the new tables judged, and the next generation's snapshot.
    Refresh, RefreshIn, PlaneRefreshOut, |instance, input, mut out| {
        let Some(door) = instance.get() else {
            return Outcome::Failed;
        };
        let shaping = match read_settings(input.field(|i| &i.settings).bytes()) {
            Ok(shaping) => shaping,
            Err(words) => return out.fail(Refusal::refused(words)),
        };
        guard(&door.shapings).insert(input.generation, Arc::new(shaping));
        let spec = snapshot(&door.webhooks);
        out.publish(|o| &o.snapshot, &door.generations, input.generation, &spec);
        Outcome::Ready
    }
);

slot!(
    /// `retire`: the generation's snapshot and tables are dropped; a unit that arrived on them
    /// keeps its own hold until it ends.
    Retire, GenIn, OutHead, |instance, input, _| {
        if let Some(door) = instance.get() {
            door.generations.retire(input.generation);
            guard(&door.shapings).remove(&input.generation);
        }
        Outcome::Ready
    }
);

slot!(
    /// `tick`: none wanted.
    Tick, TickIn, TickOut, |_, _, mut out| {
        out.set(|o| &o.next_tick_ns, 0);
        Outcome::Ready
    }
);

slot!(
    /// `drive`: no session has unsolicited output.
    Drive, PlaneDriveIn, PlaneDriveOut, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `cancel`: the unit on the cancelled ticket ends; nothing it owed is delivered.
    Cancel, PlaneCancelIn, PlaneCancelOut, |instance, input, mut out| {
        let mut partial = false;
        if let Some(door) = instance.get() {
            if let Some(unit) = guard(&door.tickets).remove(&input.cancel.ticket) {
                partial = guard(&door.units)
                    .remove(&unit)
                    .is_some_and(|u| u.reply.as_ref().is_some_and(Reply::partial));
            }
        }
        // A caller that left a usable part of the answer leaves a PARTIAL unit: the units the
        // answer stated so far bill (1.5.5's drop arm; item 367 for a buffered relay). Any other
        // cancel bills nothing.
        out.set(
            |o| &o.cancel.disposition,
            if partial { CANCEL_OK_PARTIAL } else { CANCEL_ABORTED },
        );
        Outcome::Ready
    }
);

slot!(
    /// `release`: this plane answers under no lease.
    Release, ReleaseIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `close`: the SDK drops the instance and every snapshot it still holds.
    Close, InHead, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `arrive`: the dialect, the operation and the op class of an arrival, kept with its unit by
    /// the kernel's key; a probe claim needs no principal; a declined arrival is refused with the
    /// previous release's status and keeps its refusal for `refusal`.
    Arrive, ArriveIn, ArriveOut, |instance, input, mut out| {
        let Some(door) = instance.get() else {
            return Outcome::Failed;
        };
        let Some(shaping) = door.current() else {
            return Outcome::Failed;
        };
        let given = input.get();
        let mut unit = UnitState::new(shaping);
        unit.caller = input
            .fields()
            .iter()
            .map(|f| {
                (
                    f.field(|f| &f.name).bytes().to_vec(),
                    f.field(|f| &f.value).bytes().to_vec(),
                )
            })
            .collect();
        if given.claim == CLAIM_PROBE {
            unit.probe = true;
            out.set(|o| &o.principal_need, PRINCIPAL_NONE);
            guard(&door.units).insert(given.unit, unit);
            return Outcome::Ready;
        }
        let method = String::from_utf8_lossy(input.field(|i| &i.method).bytes()).into_owned();
        let target = String::from_utf8_lossy(input.field(|i| &i.target).bytes()).into_owned();
        let body = input.field(|i| &i.body).bytes();
        let caller = unit.caller_fields();
        let arrival = arrive::arrive(&method, &target, &caller, body, &*unit.shaping);
        drop(caller);
        match arrival {
            Ok(arrived) => {
                out.set(|o| &o.op_class, op_class_index(&arrived));
                out.set(|o| &o.dialect, dialect_index(arrived.dialect));
                out.set(|o| &o.principal_need, PRINCIPAL_REQUIRED);
                let (class, entry) = route_of(&unit.shaping, &arrived.model);
                out.route(class, entry);
                let handler = handler_of(&arrived);
                if handler.is_some_and(|h| stream_intent(h, arrived.parsed.as_ref()).wants_stream) {
                    out.stream();
                }
                if class == ROUTE_POOL {
                    if let Some(key) = affinity_key(
                        unit.shaping.affinity_header(entry),
                        &unit.caller_fields(),
                        handler,
                        arrived.parsed.as_ref(),
                    ) {
                        out.affinity(&key);
                    }
                }
                unit.arrived = Some(arrived);
                guard(&door.units).insert(given.unit, unit);
                Outcome::Ready
            }
            Err(declined) => {
                out.set(|o| &o.refusal, declined.why.code());
                out.set(|o| &o.refusal_status, u32::from(declined.status));
                unit.declined = Some(declined);
                guard(&door.units).insert(given.unit, unit);
                out.fail(Refusal::bare())
            }
        }
    }
);

slot!(
    /// `on_piece`: the plane's answer to the piece, computed once and delivered in host-sized
    /// chunks; a unit whose caller's reply is complete ends.
    OnPiece, OnPieceIn, OnPieceOut, |instance, input, mut out| {
        let Some(door) = instance.get() else {
            return Outcome::Failed;
        };
        let given = input.get();
        let key = given.unit;
        // The unit leaves the map for the call, so its answer is computed with no lock held.
        let Some(mut unit) = guard(&door.units).remove(&key) else {
            return Outcome::Fault;
        };
        guard(&door.tickets).insert(given.head.ticket, key);
        if unit.pending.is_none() {
            let piece = PieceIn {
                last: given.flags & PIECE_LAST != 0,
                status: (given.flags & PIECE_HAS_STATUS != 0).then_some(given.status_code),
                fields: input
                    .head_fields()
                    .iter()
                    .map(|f| (f.field(|f| &f.name).bytes(), f.field(|f| &f.value).bytes()))
                    .collect(),
                bytes: input.field(|i| &i.bytes).bytes(),
                member: input.field(|i| &i.member).bytes(),
                pool: input.field(|i| &i.pool).bytes(),
                passthrough: given.passthrough != 0,
                clock: if given.from == FROM_CALLER { None } else { door.clock() },
            };
            let mut answer = answer(&mut unit, given.from, &piece);
            fee_unit(&mut unit, &mut answer);
            unit.pending = Some(Pending {
                answer,
                sent: 0,
                opened: false,
            });
        }
        let (outcome, ended) = deliver(&mut unit, input, &mut out);
        if ended {
            guard(&door.tickets).remove(&given.head.ticket);
        } else {
            guard(&door.units).insert(key, unit);
        }
        outcome
    }
);

slot!(
    /// `refusal`: a declined arrival in its own envelope, else the kernel's refusal in the unit's
    /// dialect (or, before `arrive`, the dialect the target names). The unit ends.
    RefusalSlot, RefusalIn, RefusalOut, |instance, input, mut out| {
        let Some(door) = instance.get() else {
            return Outcome::Failed;
        };
        let given = input.get();
        let held = guard(&door.units).remove(&given.unit);
        let rendered = match &held {
            Some(UnitState {
                declined: Some(d), ..
            }) if given.plane_code != 0 => refuse::declined(d),
            _ => {
                let arrived = held.as_ref().and_then(|u| u.arrived.as_ref());
                let envelope = match arrived {
                    Some(a) => a.dialect,
                    None => {
                        let target =
                            String::from_utf8_lossy(input.field(|i| &i.target).bytes()).into_owned();
                        let path = target.split_once('?').map_or(target.as_str(), |(p, _)| p);
                        envelope_for(path)
                    }
                };
                // A model that resolved to no destination reads the previous release's not-found
                // sentence, which names the model the caller asked for; every other refusal reads
                // the kernel's own text.
                let unreadable = held.as_ref().is_some_and(|u| u.unreadable);
                let text = match arrived {
                    _ if unreadable => project::UNREADABLE_BODY_MESSAGE.to_string(),
                    Some(a) if given.reason == crate::refusal::reason::NO_DESTINATION => {
                        refuse::model_not_found(
                            &a.model,
                            a.path_model
                                .as_ref()
                                .and_then(|p| p.model_not_found_message.as_deref()),
                        )
                    }
                    _ => String::from_utf8_lossy(input.field(|i| &i.text).bytes()).into_owned(),
                };
                let status = u16::try_from(given.status).unwrap_or(500);
                if given.cause == REFUSAL_GATE {
                    refuse::gate_refusal(envelope, status, &text)
                } else {
                    refuse::kernel_refusal(envelope, given.reason, status, &text, given.retry_after_s)
                }
            }
        };
        let (mut reply, mut fields, mut arena) =
            (input.reply_buf(), input.fields_buf(), input.arena_buf());
        reply.extend(&rendered.body);
        for (name, value) in &rendered.fields {
            fields.push(OutField {
                name: arena.span(name.as_bytes()),
                value: arena.span(value),
            });
        }
        let short = !(reply.fits() && fields.fits() && arena.fits());
        let (rw, rnd) = reply.settle(short);
        let (fw, fnd) = fields.settle(short);
        let (aw, and) = arena.settle(short);
        out.set(|o| &o.reply_written, rw as u64);
        out.set(|o| &o.reply_needed, rnd as u64);
        out.set(|o| &o.fields_written, fw as u32);
        out.set(|o| &o.fields_needed, fnd as u32);
        out.set(|o| &o.arena_written, aw as u64);
        out.set(|o| &o.arena_needed, and as u64);
        if short {
            // The driver re-calls once with the buffers this named: the unit stays for it.
            if let Some(unit) = held {
                guard(&door.units).insert(given.unit, unit);
            }
            Outcome::Failed
        } else {
            Outcome::Ready
        }
    }
);

slot!(
    /// `serve`: a public webhook route its owned section states, its caller already verified by the
    /// kernel under the route's scheme (the plane never sees the secret): the event acknowledged.
    Serve, ServeIn, ServeOut, |instance, input, mut out| {
        let Some(door) = instance.get() else {
            return Outcome::Failed;
        };
        let route = input.get().route as usize;
        if door.webhooks.get(route).is_none() {
            return Outcome::Refused;
        }
        let (status, body) = crate::exchange::webhook::receive(input.field(|i| &i.body).bytes());
        let fields: &[(&str, &str)] = if body.is_empty() {
            &[]
        } else {
            &[("content-type", "application/json")]
        };
        out.answer(&input, status, fields, &body, AUDIT_NONE)
    }
);

slot!(
    /// `hydrate`: the plane keeps no durable state.
    Hydrate, GenIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `start`: the plane runs nothing of its own.
    Start, GenIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `project`: the hook view of the unit's request ([`crate::exchange::project`]), its strings in
    /// the host's arena and its turns in the host's turn buffer; with a request-stage hook's
    /// rewrite, the rewrite applied to the unit's request first (kept as the unit's request, so
    /// every attempt is written from it), the rewritten body answered and THAT body projected. A
    /// body the operation's reader refuses is REFUSED, and the unit's refusal then reads the
    /// previous release's unreadable-body sentence.
    Project, ProjectIn, ProjectOut, |instance, input, mut out| {
        let Some(door) = instance.get() else {
            return Outcome::Failed;
        };
        let given = input.get();
        let mut units = guard(&door.units);
        // A unit that never arrived (or arrived declined, or as a probe) has nothing to project.
        let Some(arrived) = units.get_mut(&given.unit).and_then(|u| u.arrived.as_mut()) else {
            return Outcome::Refused;
        };
        let rewrite = input.field(|i| &i.rewrite).bytes();
        let rewritten = if rewrite.is_empty() {
            None
        } else {
            project::apply_rewrite(arrived, rewrite)
        };
        let view = match project::project(arrived) {
            Ok(view) => view,
            Err(project::Unreadable) => {
                if let Some(unit) = units.get_mut(&given.unit) {
                    unit.unreadable = true;
                }
                return Outcome::Refused;
            }
        };
        let dialect = arrived.dialect;
        let pool = arrived.model.clone();
        drop(units);
        let (signals, mut arena, mut turns) =
            (input.signals_buf(), input.arena_buf(), input.messages_buf());
        let pool = arena.span(pool.as_bytes());
        let dialect = arena.span(dialect.as_bytes());
        let system = view.system.as_deref().map(|s| arena.span(s.as_bytes()));
        let end_user = view.end_user.as_deref().map(|s| arena.span(s.as_bytes()));
        for (role, text) in &view.turns {
            let role = arena.span(role.as_bytes());
            let text = arena.span(text.as_bytes());
            turns.push_turn(&arena, role, text);
        }
        let body = rewritten.as_deref().map(|b| arena.span(b));
        let short = !(signals.fits() && arena.fits() && turns.fits());
        let (sw, snd) = signals.settle(short);
        let (aw, and) = arena.settle(short);
        let (tw, tnd) = turns.settle(short);
        out.set(|o| &o.signals_needed, snd as u32);
        out.set(|o| &o.arena_written, aw as u64);
        out.set(|o| &o.arena_needed, and as u64);
        out.set(|o| &o.messages_needed, tnd as u32);
        out.set(|o| &o.body, Span { offset: SPAN_ABSENT, len: 0 });
        if short {
            // The driver re-calls once with the buffers this named, the same rewrite with it:
            // applying it again to the request it already rewrote writes the same body.
            return Outcome::Failed;
        }
        let mut flags = 0;
        if view.max_tokens.is_some() {
            flags |= REQUEST_HAS_MAX_TOKENS;
        }
        if view.has_tools {
            flags |= REQUEST_HAS_TOOLS;
        }
        if view.stream {
            flags |= REQUEST_STREAM;
        }
        out.host_str(|o| &o.view.pool, &arena, pool);
        out.host_str(|o| &o.view.ingress_dialect, &arena, dialect);
        out.set(|o| &o.view.message_count, view.turn_count as u64);
        out.set(|o| &o.view.total_chars, view.text_chars as u64);
        out.set(|o| &o.view.max_tokens, view.max_tokens.unwrap_or(0));
        out.set(|o| &o.view.flags, flags);
        out.host_rows(|o| &o.view.signals, &signals);
        out.set(|o| &o.view.signals_len, sw);
        if let Some(system) = system {
            out.host_str(|o| &o.prompt.system, &arena, system);
        }
        out.set(|o| &o.prompt.message_count, tw as u64);
        out.host_rows(|o| &o.prompt.messages, &turns);
        out.set(|o| &o.prompt.messages_len, tw);
        if let Some(end_user) = end_user {
            out.host_str(|o| &o.end_user, &arena, end_user);
        }
        out.set(
            |o| &o.rewritten,
            body.unwrap_or(Span { offset: SPAN_ABSENT, len: 0 }),
        );
        Outcome::Ready
    }
);

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::plane::Ops,
    statement: STATEMENT,
    lifecycle: {
        validate: Safe<Validate>, open: Safe<Open>, refresh: Safe<Refresh>, retire: Safe<Retire>,
        tick: Safe<Tick>, drive: Safe<Drive>, cancel: Safe<Cancel>, release: Safe<Release>,
        close: Safe<Close>,
    },
    kind_ops: {
        arrive: Safe<Arrive>, on_piece: Safe<OnPiece>, refusal: Safe<RefusalSlot>,
        serve: Safe<Serve>, hydrate: Safe<Hydrate>, start: Safe<Start>, project: Safe<Project>,
    },
}
