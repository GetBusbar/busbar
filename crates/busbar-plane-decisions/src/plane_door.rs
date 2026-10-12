// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DECISIONS PLANE'S DOOR: the plane kind's memory-ABI table (`busbar_contract::abi::plane`)
//! built with the SDK's `plugin_door!` on its safe surface, over this plane's answers to the plane
//! driver ([`crate::driven`], `BUSBAR-1.6.0.md` Part 3, section 12). [`door`] is the LINKED door;
//! the same function is the DROPPED door once a `cdylib` exports it (`examples/decisions_door.rs`,
//! through `busbar_contract::export_door!`), so the two cannot answer differently.
//! `tests/conformance.rs` loads both through the one loader and requires one transcript.
//!
//! The composition root links [`door`] on its `plane-door` axis under the plane's one switch
//! `plane-decisions` (`BUSBAR-1.6.0.md` Part 3, section 12, "The switch": the fold is complete and
//! its development-only switch is gone) and binds it through the loader's one load beside the
//! dropped-in plane doors. The plane's registry row is this door's Statement, folded by the kernel;
//! the serve path composes the bound door and hands it its arrivals through the plane driver.
//!
//! * The Statement: the plane's key and version, `decisions:` declared and `providers:` consumed,
//!   its one outbound need, and the tail [`TAIL`] (every list read off [`crate::driven::tail`]).
//! * `validate`, `open`, `refresh`: the settings blob read as the `decisions:` section
//!   ([`crate::config::DecisionsSection`]); a generation's snapshot claims
//!   [`crate::driven::served_claims`] for its model count, keeps its [`crate::driven::Models`],
//!   and binds no audience (the operation is served on the plain data plane to a keyed caller).
//!   `retire` drops a generation.
//! * `arrive`: [`crate::driven::arrive`]; an unclaimed request is refused at 404; a claimed one
//!   routes by its top-level `model` over the newest generation ([`crate::driven::Models::resolve`]).
//! * `on_piece`: the ATTEMPT's request head ([`crate::driven::attempt_request`]), the caller's body to the
//!   far end unchanged ([`crate::driven::caller_piece`]), and the far end's answer held to its last
//!   piece, its count read, then relayed unchanged ([`crate::driven::FarEndReading`]).
//! * `refusal`: [`crate::driven::refusal_body`].
//! * `serve` and `project` are REFUSED: the plane publishes no admin route and binds no hook view.
//!   `hydrate`, `start`, `tick`, `drive`, `release` and `close` hold nothing; `cancel` and
//!   `refusal` end their unit and drop its state.

use std::collections::BTreeMap;
use std::mem::size_of;
use std::ptr;

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_PROVIDER, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Outcome, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::{
    KindTailHead, Section, Statement, SECTION_CONSUMED, SECTION_DECLARING,
};
use busbar_contract::abi::mechanism::lifecycle::{
    GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, BillableClass, DialectAuth, OnPieceIn, OnPieceOut, OpClass, OutField,
    PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot,
    PlaneTail, ProjectIn, ProjectOut, RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount,
    CANCEL_ABORTED, CLAIM_EXACT, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END,
    FROM_KERNEL, INGRESS_REQUEST_RESPONSE, PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_NONE,
    PRINCIPAL_OPTIONAL, PRINCIPAL_REQUIRED, ROUTE_DIRECT, SHAPE_WHOLE, UNITS_REPORTED,
};
use busbar_contract::abi::plane::{PlaneCancelIn, PlaneCancelOut};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::publish::{ClaimSpec, SnapshotSpec};
use busbar_contract::abi::sdk::{
    open_failed, Generations, HostBuf, Instance, Keyed, Lent, Out, Safe, SafeSlot,
};
use busbar_contract::plane::PlaneMeta;

use crate::codec::{CONTENT_TYPE_JSON, FIELD_CONTENT_TYPE, FIELD_RETRY_AFTER};
use crate::config::DecisionsSection;
use crate::driven::{self, tail, CallerAnswer, FarEndReading, Models, PrincipalNeed, Unrouted};
use crate::{claims, DecisionPlane};

/// The version the Statement names: the crate's (a test pins the two equal).
pub const VERSION: &str = "1.6.0";

/// The most calls the kernel keeps in flight on one instance.
const MAX_INFLIGHT: u32 = 64;

/// The most units the instance keeps state for at once. At the cap a NEW unit is refused (fail
/// closed, counted in [`DecisionsDoor::refused_at_cap`]); a live unit is never evicted to make
/// room, so no unit in flight loses its request or its count.
pub const MAX_UNITS: usize = 4096;

/// [`ArriveOut::refusal`]: the request names no operation this plane claims.
pub const UNCLAIMED: u32 = 1;

/// [`ArriveOut::refusal`]: the instance holds [`MAX_UNITS`] live units and takes no new one.
pub const AT_CAPACITY: u32 = 2;

/// [`ArriveOut::refusal`]: the request names no model and several are configured (400).
pub const NO_MODEL_NAMED: u32 = 3;

/// [`ArriveOut::refusal`]: the request's `model` is not a string (400).
pub const MODEL_NOT_A_NAME: u32 = 4;

/// [`ArriveOut::refusal`]: the request names a model this generation does not configure (404).
pub const UNKNOWN_MODEL: u32 = 5;

/// The refusal code of a request that routes nowhere.
const fn unrouted_code(why: Unrouted) -> u32 {
    match why {
        Unrouted::NoneNamed => NO_MODEL_NAMED,
        Unrouted::NotAName => MODEL_NOT_A_NAME,
        Unrouted::Unknown => UNKNOWN_MODEL,
    }
}

/// The status an unclaimed request is refused at.
const STATUS_NOT_FOUND: u32 = 404;

/// The status a unit refused at [`MAX_UNITS`] wears: an arrive refusal is a 4xx, and this one asks
/// the caller to come back.
const STATUS_AT_CAPACITY: u32 = 429;

/// The words a unit refused at [`MAX_UNITS`] carries.
const WORDS_AT_CAPACITY: &str = "the decisions plane is at its limit of units in flight";

/// The human label.
const LABEL: &str = "Decisions";

/// An absent string.
const NONE: AbiStr = AbiStr {
    ptr: ptr::null(),
    len: 0,
};

/// `decisions:` declared, `providers:` consumed ([`tail::SECTION_DECLARING`],
/// [`tail::SECTIONS_CONSUMED`]).
const SECTIONS: &[Section] = &[
    Section {
        name: abi_str(tail::SECTION_DECLARING),
        flags: SECTION_DECLARING,
        _reserved: 0,
    },
    Section {
        name: abi_str(tail::SECTIONS_CONSUMED[0]),
        flags: SECTION_CONSUMED,
        _reserved: 0,
    },
];

const DIALECTS: &[AbiStr] = &[abi_str(tail::DIALECTS[0])];

/// The dialect's default outbound style ([`tail::DIALECT_AUTH`]).
const DIALECT_AUTH: &[DialectAuth] = &[DialectAuth {
    dialect: tail::DIALECT_AUTH[0].0,
    _reserved: 0,
    style: abi_str(tail::DIALECT_AUTH[0].1),
    params: Blob::ABSENT,
}];

const SCOPE_KINDS: &[AbiStr] = &[abi_str(tail::SCOPE_KINDS[0])];

const OP_CLASSES: &[OpClass] = &[OpClass {
    op: abi_str(tail::OP_CLASSES[0].as_str()),
    name: abi_str(tail::OP_CLASSES[0].as_str()),
}];

/// One of [`tail::BILLABLE_CLASSES`], as the tail states it.
const fn billable(i: usize) -> BillableClass {
    BillableClass {
        class: abi_str(tail::BILLABLE_CLASSES[i].0.as_str()),
        family: abi_str(tail::BILLABLE_CLASSES[i].1),
    }
}

const BILLABLE_CLASSES: &[BillableClass] = &[billable(0), billable(1), billable(2), billable(3)];

/// The fee unit the plane counts ([`tail::FEE_UNITS`]).
const FEE_UNITS: &[AbiStr] = &[abi_str(tail::FEE_UNITS[0])];

/// The far end's one response field the plane relays: the document type of the answer.
const KEEP_RESPONSE_HEADERS: &[AbiStr] = &[abi_str(FIELD_CONTENT_TYPE)];

/// THE PLANE'S ONE NEED ([`tail::NEEDS`]): outbound to a configured provider, over the claim's
/// transport, decorated under the egress scheme the kernel holds the credential for.
pub const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_PROVIDER,
    transport: abi_str(tail::NEEDS[0].0),
    auth: abi_str(tail::NEEDS[0].1),
    target_from: NONE,
    trust_from: NONE,
    details: Blob {
        ptr: ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    },
    keep_response_headers: KEEP_RESPONSE_HEADERS.as_ptr(),
    keep_response_headers_len: KEEP_RESPONSE_HEADERS.len(),
    timeout_ms: 0,
    keep_mode: KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: core::ptr::null(),
    deny_response_headers_len: 0,
}];

/// THE STATEMENT TAIL: the plane's static facts, every list [`crate::driven::tail`]'s.
pub const TAIL: &PlaneTail = &PlaneTail {
    head: KindTailHead {
        size: size_of::<PlaneTail>() as u32,
        _reserved: 0,
    },
    flags: 0,
    ingress: INGRESS_REQUEST_RESPONSE,
    // The kernel gathers the caller's whole body and pushes it as one piece.
    dispatch_shape: SHAPE_WHOLE,
    _reserved: 0,
    scope: abi_str(tail::SCOPE_KINDS[0]),
    label: abi_str(LABEL),
    subject_noun: abi_str(tail::SUBJECT_NOUN),
    admin_noun: abi_str(tail::ADMIN_NOUN),
    audit_kind: abi_str(tail::AUDIT_KIND),
    signing_domain: NONE,
    signing_kid_prefix: NONE,
    cli_help: NONE,
    dialects: DIALECTS.as_ptr(),
    dialects_len: DIALECTS.len(),
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
    refusal_statuses: ptr::null(),
    refusal_statuses_len: 0,
    caller_credential_refusal: NONE,
    admin_routes: ptr::null(),
    admin_routes_len: 0,
    admin_openapi: Blob::ABSENT,
    stream_ceiling_secs: 0,
};

/// THE STATEMENT: the plane's key and version, its sections, its need and its tail.
pub const STATEMENT: Statement = Statement {
    kind_tail: ptr::from_ref(TAIL).cast::<KindTailHead>(),
    sections: SECTIONS.as_ptr(),
    sections_len: SECTIONS.len(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    ..statement(<DecisionPlane as PlaneMeta>::KEY, VERSION, MAX_INFLIGHT)
};

/// The settings blob read as the `decisions:` section; an empty blob is the empty section.
///
/// The blob is ONE JSON object `{decisions: <section>}` (`BUSBAR-1.6.0.md` section 4: "a plane's
/// settings reach it as ONE validated JSON object `{section: value}`"), the shape the boot's deal
/// hands every door; the bare section is read too, since a section never carries a member named
/// after its own verb (its grammar refuses unknown members), so the two cannot be confused.
///
/// # Errors
///
/// The section's first broken rule, in the grammar's words.
pub fn read_settings(settings: &[u8]) -> Result<DecisionsSection, String> {
    if settings.is_empty() {
        return Ok(DecisionsSection::default());
    }
    let mut value: serde_json::Value =
        serde_json::from_slice(settings).map_err(|e| e.to_string())?;
    let section = match value.as_object_mut() {
        Some(blob) if blob.len() == 1 && blob.contains_key(tail::SECTION_DECLARING) => blob
            .remove(tail::SECTION_DECLARING)
            .unwrap_or(serde_json::Value::Null),
        _ => value,
    };
    if section.is_null() {
        return Ok(DecisionsSection::default());
    }
    serde_json::from_value(section).map_err(|e| e.to_string())
}

/// `validate`'s blob: what stage 3g deals a plane (`{<verb>: <section>}`; the kernel's own judges hand
/// the same shape), read at the `decisions:` section. An empty blob, or one that writes no
/// `decisions:`, is the empty section.
///
/// # Errors
///
/// A blob that is not a map of sections, or the section's first broken rule.
pub fn read_dealt(settings: &[u8]) -> Result<DecisionsSection, String> {
    if settings.is_empty() {
        return Ok(DecisionsSection::default());
    }
    let value: serde_json::Value = serde_json::from_slice(settings).map_err(|e| e.to_string())?;
    let serde_json::Value::Object(mut verbs) = value else {
        return Err("the dealt settings are not a map of the plane's sections".to_string());
    };
    match verbs.remove(tail::SECTION_DECLARING) {
        None | Some(serde_json::Value::Null) => Ok(DecisionsSection::default()),
        Some(section) => serde_json::from_value(section).map_err(|e| e.to_string()),
    }
}

/// ONE GENERATION'S MODELS, each in its dialect: its override, else the protocol of the provider
/// it names in `providers` (the referenced providers' dialect fields the plane is handed at open,
/// THE DESIGN section 4).
///
/// # Errors
///
/// [`Models::of`]'s: every model in no dialect this plane speaks, and every model that sets an
/// `upstream_model` that can never take effect.
pub fn models_of(
    section: &DecisionsSection,
    providers: &BTreeMap<String, String>,
) -> Result<Models, String> {
    Models::of(section, |name, cfg| {
        driven::dialect_of(
            name,
            model_override(cfg),
            providers.get(&cfg.provider).map(String::as_str),
        )
    })
}

/// THE REFERENCED PROVIDERS' PROTOCOLS, by provider name: the dialect facts the host hands at
/// `open` (`PlaneOpenIn::providers`, THE DESIGN section 4). A host that hands none leaves every
/// model to its own override.
fn provider_dialects(open: Lent<'_, PlaneOpenIn>) -> BTreeMap<String, String> {
    open.providers()
        .iter()
        .filter_map(|p| {
            let name = p.field(|f| &f.name).as_str().ok()?;
            let protocol = p.field(|f| &f.protocol).as_str().ok()?;
            Some((name.to_owned(), protocol.to_owned()))
        })
        .collect()
}

/// WHAT `validate` CAN JUDGE OF THE DIALECTS: `validate` is handed no provider facts, so it judges
/// each model's own override (a dialect this plane does not speak, or an `upstream_model` its
/// dialect can never splice); a model resolved through its provider is judged at `open`.
///
/// # Errors
///
/// [`Models::of`]'s words for the overrides.
pub fn judge_overrides(section: &DecisionsSection) -> Result<(), String> {
    Models::of(section, |name, cfg| match model_override(cfg) {
        Some(dialect) => driven::dialect_of(name, Some(dialect), None),
        // Judged at `open`, against its provider's protocol.
        None => Ok(crate::dialect::JEV),
    })
    .map(drop)
}

/// A model's own dialect override (#51), when it states one.
fn model_override(cfg: &busbar_contract::config::ModelCfg) -> Option<&str> {
    cfg.protocol.as_deref()
}

/// ONE GENERATION'S SNAPSHOT for `models`: the claims [`driven::served_claims`] serves, each an
/// exact target over the claim's transport. It binds no audience: the operation is served on the
/// plain data plane to a keyed caller, as the llm plane's is, and its refusals are its dialect's.
#[must_use]
pub fn snapshot_spec(models: &Models) -> SnapshotSpec {
    SnapshotSpec {
        claims: driven::served_claims(models)
            .iter()
            .map(|(verb, target)| ClaimSpec {
                // A refusal before `arrive` wears the dialect the path names.
                refusal_dialect: crate::dialect::of_path(target)
                    .and_then(|d| u16::try_from(d).ok())
                    .unwrap_or(0),
                ..ClaimSpec::new(verb, target, claims::TRANSPORT, CLAIM_EXACT)
            })
            .collect(),
        // THE GENERATION'S LISTED NAMES (THE DESIGN section 2, DECISIONS D8): every configured
        // decisions model; the kernel appends them to `/v1/models`, scope-filtered.
        listed: models.names().map(str::to_owned).collect(),
        ..SnapshotSpec::default()
    }
}

/// One unit the instance keeps, from its ATTEMPT to the far end's last piece.
#[derive(Debug, Default)]
struct Unit {
    /// An ATTEMPT opened the request bound for the far end; the caller's body follows it there.
    attempt: bool,
    /// The far end's answer, read as it is relayed.
    reading: FarEndReading,
    /// The piece answered short: its re-call carries the same piece, which is not read twice.
    recall: bool,
    /// What a `more = 1` answer still owes the host, and how much of it is written.
    owed: Vec<u8>,
    /// How much of [`Unit::owed`] is written.
    at: usize,
    /// The `EMIT_*` bits the owed bytes carry.
    owed_flags: u32,
    /// The caller's fields the far end receives ([`driven::relayed_fields`]), kept from `arrive`
    /// (the caller's head crosses once) for every ATTEMPT of the unit.
    caller: Vec<(Vec<u8>, Vec<u8>)>,
    /// The far end's status, read off its first piece; the request fee is judged on it.
    status: Option<u32>,
    /// The far end's document type, read off its first piece and relayed with the held answer.
    content_type: Option<Vec<u8>>,
    /// The ticket the unit's pieces cross on: a `cancel` names the unit by it.
    ticket: Option<Ticket>,
    /// The dialect it arrived in: its far-end request, its count and its refusals follow it.
    dialect: u32,
    /// The name the caller body's top-level `model` is spliced to ([`driven::splice_model`]):
    /// the routed model's `upstream_model`, where the request named it and it differs.
    upstream: Option<String>,
}

/// One instance: every live generation's snapshot, and the units in flight.
#[derive(Debug)]
pub struct DecisionsDoor {
    /// Every live generation's snapshot, with its models (a request routes over the newest).
    generations: Generations<PlaneSnapshot, Models>,
    /// Every live unit's state, from its arrival to its end: its last piece, its refusal or its
    /// cancel, whichever comes first. Never more than [`MAX_UNITS`].
    units: Keyed<u64, Unit>,
    /// How many units were refused, by why ([`Refused`]): the SDK's per-instance keyed state.
    refused: Keyed<Refused, u64>,
    /// The protocols of the providers the section references, as `open` was handed them.
    providers: BTreeMap<String, String>,
}

/// Why a unit was refused by the instance itself, counted per instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Refused {
    /// [`MAX_UNITS`] units were live.
    AtCap,
    /// Its answer passed [`driven::ANSWER_BACKSTOP`].
    OverBackstop,
    /// Its far end answered a success with no whole decision count ([`driven::Uncounted`]).
    Uncounted,
}

impl DecisionsDoor {
    /// An instance with no generation and no unit.
    fn new() -> Self {
        Self {
            generations: Generations::new(),
            units: Keyed::new(),
            refused: Keyed::new(),
            providers: BTreeMap::new(),
        }
    }

    /// Count one unit refused for `why`.
    fn count(&self, why: Refused) {
        self.refused
            .with_all(|counts| *counts.entry(why).or_default() += 1);
    }

    /// How many units were refused at [`MAX_UNITS`].
    #[must_use]
    pub fn refused_at_cap(&self) -> u64 {
        self.refused.get(&Refused::AtCap).unwrap_or(0)
    }

    /// How many success answers were refused for stating no whole decision count.
    #[must_use]
    pub fn refused_uncounted(&self) -> u64 {
        self.refused.get(&Refused::Uncounted).unwrap_or(0)
    }

    /// How many units were refused past [`driven::ANSWER_BACKSTOP`].
    #[must_use]
    pub fn refused_over_backstop(&self) -> u64 {
        self.refused.get(&Refused::OverBackstop).unwrap_or(0)
    }

    /// How many units the instance holds state for.
    #[must_use]
    pub fn live_units(&self) -> usize {
        self.units.len()
    }
}

/// One slot body on the SDK's safe surface, over this plane's [`DecisionsDoor`].
macro_rules! slot {
    ($(#[$doc:meta])* $name:ident, $in:ty, $out:ty,
     |$inst:pat_param, $input:pat_param, $o:pat_param| $body:block) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = DecisionsDoor;
            fn call($inst: Instance<'_, DecisionsDoor>, $input: Lent<'_, $in>, $o: Out<'_, $out>)
                -> Outcome $body
        }
    };
}

slot!(
    /// `validate`: the settings read as the section, or refused in the grammar's words.
    Validate, ValidateIn, OutHead, |_, input, mut out| {
        match read_dealt(input.field(|i| &i.settings).bytes()).and_then(|s| judge_overrides(&s)) {
            Ok(()) => Outcome::Ready,
            Err(words) => out.fail(Refusal::refused(words)),
        }
    }
);

slot!(
    /// `open`: the instance, and the first generation's snapshot.
    Open, PlaneOpenIn, PlaneOpenOut, |instance, input, mut out| {
        let open = input.field(|i| &i.open);
        let section = match read_settings(open.field(|o| &o.settings).bytes()) {
            Ok(section) => section,
            Err(words) => return open_failed(open, &mut out, |o| &o.open.err_len, &words),
        };
        let mut plane = DecisionsDoor::new();
        plane.providers = provider_dialects(input);
        let models = match models_of(&section, &plane.providers) {
            Ok(models) => models,
            Err(words) => return open_failed(open, &mut out, |o| &o.open.err_len, &words),
        };
        let spec = snapshot_spec(&models);
        out.publish_with(|o| &o.snapshot, &plane.generations, open.generation, &spec, models);
        instance.open(plane);
        Outcome::Ready
    }
);

slot!(
    /// `refresh`: the new section judged, and the next generation's snapshot.
    Refresh, RefreshIn, PlaneRefreshOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let section = match read_settings(input.field(|i| &i.settings).bytes()) {
            Ok(section) => section,
            Err(words) => return out.fail(Refusal::refused(words)),
        };
        // The providers are the ones handed at `open`: a model that names another is refused.
        let models = match models_of(&section, &plane.providers) {
            Ok(models) => models,
            Err(words) => return out.fail(Refusal::refused(words)),
        };
        let spec = snapshot_spec(&models);
        out.publish_with(|o| &o.snapshot, &plane.generations, input.generation, &spec, models);
        Outcome::Ready
    }
);

slot!(
    /// `retire`: the generation's snapshot is dropped.
    Retire, GenIn, OutHead, |instance, input, _| {
        if let Some(plane) = instance.get() {
            plane.generations.retire(input.generation);
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
    /// `cancel`: the unit on the cancelled ticket ends and its state is dropped. A unit is never
    /// answered before its far end has, so nothing is moved.
    Cancel, PlaneCancelIn, PlaneCancelOut, |instance, input, mut out| {
        if let Some(plane) = instance.get() {
            let ticket = input.get().cancel.ticket;
            if !ticket.is_none() {
                plane
                    .units
                    .with_all(|units| units.retain(|_, unit| unit.ticket != Some(ticket)));
            }
        }
        out.set(|o| &o.cancel.disposition, CANCEL_ABORTED);
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
    /// `arrive`: a claimed request's op class, principal need, dialect and route (its one model,
    /// directly: ARCHITECT Q-SW6/Q-FL3); an unclaimed one is refused at 404.
    Arrive, ArriveIn, ArriveOut, |instance, input, mut out| {
        let verb = input.field(|i| &i.method).as_str().unwrap_or_default();
        let target = input.field(|i| &i.target).as_str().unwrap_or_default();
        let Some(arrived) = driven::arrive(verb, target) else {
            out.set(|o| &o.refusal, UNCLAIMED);
            out.set(|o| &o.refusal_status, STATUS_NOT_FOUND);
            return out.fail(Refusal::bare());
        };
        out.set(|o| &o.op_class, arrived.op_class);
        out.set(|o| &o.dialect, arrived.dialect);
        out.set(
            |o| &o.principal_need,
            match arrived.principal {
                PrincipalNeed::None => PRINCIPAL_NONE,
                PrincipalNeed::Required => PRINCIPAL_REQUIRED,
                PrincipalNeed::Optional => PRINCIPAL_OPTIONAL,
            },
        );
        if let Some(plane) = instance.get() {
            // THE ROUTE (DECISIONS D8b), over the newest generation's models, by the request's
            // top-level `model`; refused here, before the unit holds any state.
            let models = plane.generations.current().unwrap_or_default();
            let routed = models.resolve(arrived.dialect, input.field(|i| &i.body).bytes());
            let (model, upstream) = match routed {
                Ok(routed) => (routed.model.to_owned(), routed.upstream.map(str::to_owned)),
                Err(why) => {
                    out.set(|o| &o.refusal, unrouted_code(why));
                    out.set(|o| &o.refusal_status, why.status());
                    return out.fail(Refusal::refused(why.words()));
                }
            };
            // The caller's head crosses here once: keep what the far end receives of it.
            let caller = driven::relayed_fields(input.fields().iter().map(|f| {
                (
                    f.field(|f| &f.name).bytes(),
                    f.field(|f| &f.value).bytes(),
                )
            }));
            let unit = input.get().unit;
            let held = plane.units.with_all(|units| match unit_of(units, unit) {
                Some(state) => {
                    state.caller = caller;
                    state.upstream = upstream;
                    state.dialect = arrived.dialect;
                    true
                }
                None => false,
            });
            if !held {
                plane.count(Refused::AtCap);
                out.set(|o| &o.refusal, AT_CAPACITY);
                out.set(|o| &o.refusal_status, STATUS_AT_CAPACITY);
                return out.fail(Refusal::refused(WORDS_AT_CAPACITY));
            }
            out.route(ROUTE_DIRECT, &model);
        }
        Outcome::Ready
    }
);

/// `(written, needed)` of every buffer an answer fills, short as a whole when one is short.
fn settle(
    out: &mut Out<'_, OnPieceOut>,
    fields: &HostBuf<'_, OutField>,
    units: &HostBuf<'_, UnitCount>,
    arena: &HostBuf<'_, u8>,
) -> bool {
    let short = !(fields.fits() && units.fits() && arena.fits());
    let (fw, fnd) = fields.settle(short);
    let (uw, und) = units.settle(short);
    let (aw, and) = arena.settle(short);
    out.set(|o| &o.fields_written, fw as u32);
    out.set(|o| &o.fields_needed, fnd as u32);
    out.set(|o| &o.units_written, uw as u32);
    out.set(|o| &o.units_needed, und as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, and as u64);
    short
}

/// Write what `unit` owes into the reply buffer, as much as fits; `more = 1` while any is left,
/// and its flags (with `EMIT_DONE` held back until the last byte) on every write. Answers whether
/// the unit is done.
fn pay(unit: &mut Unit, input: Lent<'_, OnPieceIn>, out: &mut Out<'_, OnPieceOut>) -> bool {
    let n = input.reply_buf().stream(&unit.owed[unit.at..]);
    unit.at += n;
    paid(unit, n, out)
}

/// The answer's head after `n` bytes were written: `more`, the flags, and whether the unit is done.
fn paid(unit: &mut Unit, n: usize, out: &mut Out<'_, OnPieceOut>) -> bool {
    let more = unit.at < unit.owed.len();
    let done = !more && unit.owed_flags & EMIT_DONE != 0;
    out.set(|o| &o.emitted, n as u64);
    out.set(|o| &o.more, u32::from(more));
    out.set(
        |o| &o.flags,
        if more {
            unit.owed_flags & !EMIT_DONE
        } else {
            unit.owed_flags
        },
    );
    if !more {
        unit.owed.clear();
        unit.at = 0;
    }
    done
}

/// Owe the borrowed `bytes` under `flags`: what fits is written straight from them, and only what
/// a narrow reply buffer leaves over is kept for the `more` re-calls. Answers whether the unit is
/// done.
fn owe(
    unit: &mut Unit,
    bytes: &[u8],
    flags: u32,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> bool {
    let n = input.reply_buf().stream(bytes);
    unit.owed.clear();
    unit.owed.extend_from_slice(&bytes[n..]);
    unit.at = 0;
    unit.owed_flags = flags;
    paid(unit, n, out)
}

/// Owe the owned `bytes` under `flags` (moved in, not copied), and pay what fits now. Answers
/// whether the unit is done.
fn owe_owned(
    unit: &mut Unit,
    bytes: Vec<u8>,
    flags: u32,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> bool {
    unit.owed = bytes;
    unit.at = 0;
    unit.owed_flags = flags;
    pay(unit, input, out)
}

/// An ATTEMPT: the request bound for the far end, its verb, target and dialect fields. A new
/// attempt starts a new far-end answer. Named `attempt_piece`, not `attempt`, so it is not a
/// cross-plane re-spelling of llm/a2a's `attempt` (structure-lint plane-dup; ARCHITECT ruling 2b
/// 2026-10-04).
fn attempt_piece(
    unit: &mut Unit,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> Outcome {
    let request = driven::attempt_request(unit.dialect, &[]);
    let (mut fields, units, mut arena) = (input.fields_buf(), input.units_buf(), input.arena_buf());
    let verb = arena.span(request.verb.as_bytes());
    let target = arena.span(request.target.as_bytes());
    for (name, value) in request.fields {
        fields.push(OutField {
            name: arena.span(name.as_bytes()),
            value: arena.span(value),
        });
    }
    for (name, value) in &unit.caller {
        fields.push(OutField {
            name: arena.span(name),
            value: arena.span(value),
        });
    }
    if settle(out, &fields, &units, &arena) {
        return Outcome::Failed;
    }
    *unit = Unit {
        attempt: true,
        caller: std::mem::take(&mut unit.caller),
        ticket: unit.ticket,
        upstream: unit.upstream.take(),
        dialect: unit.dialect,
        ..Unit::default()
    };
    out.set(|o| &o.verb, verb);
    out.set(|o| &o.target, target);
    out.set(|o| &o.flags, EMIT_TO_FAR_END);
    Outcome::Ready
}

/// One piece of the far end's answer: HELD until its last piece ([`FarEndReading`]), then relayed
/// to the caller unchanged and whole, with its status and document type and its count. An answer
/// past [`driven::ANSWER_BACKSTOP`] is refused, before any byte of it reaches the caller. Answers
/// the outcome and whether the unit is done.
fn far_end(
    plane: &DecisionsDoor,
    unit: &mut Unit,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> (Outcome, bool) {
    let given = input.get();
    let bytes = input.field(|i| &i.bytes).bytes();
    let first = given.flags & PIECE_HAS_STATUS != 0;
    let last = given.flags & PIECE_LAST != 0;
    if !unit.recall {
        if unit.reading.piece(bytes).is_err() {
            plane.count(Refused::OverBackstop);
            return (Outcome::Refused, true);
        }
        if first {
            unit.status = Some(given.status_code);
            unit.content_type = input
                .head_fields()
                .iter()
                .find(|f| {
                    f.field(|f| &f.name)
                        .bytes()
                        .eq_ignore_ascii_case(FIELD_CONTENT_TYPE.as_bytes())
                })
                .map(|f| f.field(|f| &f.value).bytes().to_vec());
        }
    }
    let (mut fields, mut units, mut arena) =
        (input.fields_buf(), input.units_buf(), input.arena_buf());
    if last {
        if let Some(value) = &unit.content_type {
            fields.push(OutField {
                name: arena.span(FIELD_CONTENT_TYPE.as_bytes()),
                value: arena.span(value),
            });
        }
        // THE ONE SUCCESS RULE ($): a success with no whole count is refused, loudly and counted,
        // before a byte of it reaches the caller; it is never served free.
        let Ok(settled) = unit.reading.settle(unit.dialect, unit.status) else {
            plane.count(Refused::Uncounted);
            return (Outcome::Refused, true);
        };
        for count in settled.units() {
            units.push(UnitCount {
                class: count.class,
                source: UNITS_REPORTED,
                amount: count.amount,
            });
        }
    }
    if settle(out, &fields, &units, &arena) {
        unit.recall = true;
        return (Outcome::Failed, false);
    }
    unit.recall = false;
    if !last {
        // Held: nothing reaches the caller before the answer is whole.
        return (Outcome::Ready, false);
    }
    if let Some(status) = unit.status {
        out.set(|o| &o.reply_status, status);
    }
    let answer = unit.reading.take_answer();
    let done = owe_owned(unit, answer, EMIT_DONE, input, out);
    (Outcome::Ready, done)
}

/// `unit`'s state in `units`, a new one started when there is room: `None` when [`MAX_UNITS`]
/// live units are held and `key` is none of them. A live unit is never evicted.
fn unit_of(units: &mut BTreeMap<u64, Unit>, key: u64) -> Option<&mut Unit> {
    if units.len() >= MAX_UNITS && !units.contains_key(&key) {
        return None;
    }
    Some(units.entry(key).or_default())
}

slot!(
    /// `on_piece`: the ATTEMPT's request head, the caller's body to the far end, and the far
    /// end's answer to the caller. A finished unit is forgotten.
    OnPiece, OnPieceIn, OnPieceOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let given = input.get();
        let bytes = input.field(|i| &i.bytes).bytes();
        plane.units.with_all(|units| {
            let Some(unit) = unit_of(units, given.unit) else {
                plane.count(Refused::AtCap);
                return Outcome::Refused;
            };
            if !given.head.ticket.is_none() {
                unit.ticket = Some(given.head.ticket);
            }
            // A re-call after `more = 1` carries no bytes, no flags and no attempt: it is paid from
            // what is owed.
            let continues = bytes.is_empty() && given.flags == 0 && given.attempt_no == 0;
            let (outcome, done) = if continues && unit.at < unit.owed.len() {
                (Outcome::Ready, pay(unit, input, &mut out))
            } else {
                match given.from {
                    FROM_KERNEL if given.attempt_no != 0 => {
                        (attempt_piece(unit, input, &mut out), false)
                    }
                    FROM_CALLER => match driven::caller_piece(bytes, given.flags & PIECE_LAST != 0) {
                        CallerAnswer::Empty => (Outcome::Refused, true),
                        CallerAnswer::Keep if unit.attempt => {
                            // `upstream_model`, spliced into the top-level `model` value alone;
                            // a body with no `model` string passes through unchanged.
                            match unit
                                .upstream
                                .as_deref()
                                .and_then(|name| driven::splice_model(bytes, name))
                            {
                                Some(spliced) => {
                                    owe_owned(unit, spliced, EMIT_TO_FAR_END, input, &mut out)
                                }
                                None => owe(unit, bytes, EMIT_TO_FAR_END, input, &mut out),
                            };
                            (Outcome::Ready, false)
                        }
                        CallerAnswer::Keep => (Outcome::Ready, false),
                    },
                    FROM_FAR_END => far_end(plane, unit, input, &mut out),
                    _ => (Outcome::Refused, false),
                }
            };
            if done {
                units.remove(&given.unit);
            }
            outcome
        })
    }
);

slot!(
    /// `refusal`: the kernel's status and text in this dialect's error shape, as JSON, and the
    /// wait the kernel handed beside it (`retry_after_s`, a limit's rolling window or the walk's
    /// floor) as `Retry-After`, as every plane answers it. The unit ends, and its state is dropped.
    RefusalSlot, RefusalIn, RefusalOut, |instance, input, mut out| {
        let given = input.get();
        if let Some(plane) = instance.get() {
            plane.units.remove(&given.unit);
        }
        let status = u16::try_from(given.status).unwrap_or(0);
        let text = input.field(|i| &i.text).as_str().unwrap_or_default();
        let body = driven::refusal_body(given.dialect, status, text);
        let (mut reply, mut fields, mut arena) =
            (input.reply_buf(), input.fields_buf(), input.arena_buf());
        reply.extend(&body);
        fields.push(OutField {
            name: arena.span(FIELD_CONTENT_TYPE.as_bytes()),
            value: arena.span(CONTENT_TYPE_JSON),
        });
        if given.retry_after_s > 0 {
            let wait = given.retry_after_s.to_string();
            fields.push(OutField {
                name: arena.span(FIELD_RETRY_AFTER.as_bytes()),
                value: arena.span(wait.as_bytes()),
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
            Outcome::Failed
        } else {
            Outcome::Ready
        }
    }
);

slot!(
    /// `serve`: the plane publishes no admin route.
    Serve, ServeIn, ServeOut, |_, _, _| { Outcome::Refused }
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
    /// `project`: the plane binds no hook view; it never reads the decision content.
    Project, ProjectIn, ProjectOut, |_, _, _| { Outcome::Refused }
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

#[cfg(test)]
#[path = "tests/plane_door.rs"]
mod tests;
