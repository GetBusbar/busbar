// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S DOOR, SERVED: the slots the kernel calls over the plane ABI, on the SDK's safe
//! surface. [`door`] is the LINKED door; the same function is the DROPPED door once a `cdylib`
//! exports it (`busbar_contract::export_door!`), so the two cannot answer differently.
//!
//! The lifecycle is this plane's own:
//!
//! * `validate` reads the settings blob as the `tools:` section ([`door::read_tools_section`]) and
//!   refuses in the grammar's words;
//! * `open` judges the same section, reads the deployment's public base URL, keeps the host
//!   services it was handed and publishes the first generation's snapshot
//!   ([`door::endpoint_snapshot_spec`]); `refresh` judges the new section and publishes the next generation
//!   over the base URL `open` was given; `retire` drops a generation's snapshot, and what the plane
//!   held for it ([`Held`]) with it. A request is answered from the newest live generation
//!   ([`McpDoor::current`]);
//! * `tick` is the clock of the subscriptions held as K6 sessions on the HTTP carrier and `drive`
//!   names the ones whose step is due ([`door_listen`]), `cancel` drops the cancelled unit, and
//!   `release`/`close` hold nothing the SDK does not already drop.
//!
//! The request path (THE DESIGN Part 3, the plane driver):
//!
//! * `arrive` decides what the arrival is ([`crate::tool_arrival::decide`]) and keeps it, with the
//!   generation it arrived under and how its answer is framed ([`crate::framing::Framing`]),
//!   keyed by the unit. A refused arrival states its refusal in its own words.
//! * `on_piece` answers. The kernel's ATTEMPT piece names the member its walk picked; the caller's
//!   body then either is answered from what the plane holds ([`crate::answer`]) or, for a
//!   `tools/call` the caller may make ([`crate::call::admit_call`]), becomes the request bound for that
//!   member ([`crate::call::outbound`]). The far end's answer is settled into the caller's
//!   ([`crate::call::settle_call`]). An answer the reply buffer cannot hold is written over several
//!   calls (`more = 1`).
//! * Every visibility question a request asks is the kernel's ENTITLEMENT answer for the unit's
//!   principal (`entitlement.check`), asked once per grant per unit: nothing is visible to a unit
//!   the kernel did not entitle.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneDriveIn, PlaneDriveOut, PlaneOpenIn,
    PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot, ProjectIn, ProjectOut, RecordWrite, RefusalIn,
    RefusalOut, ServeIn, ServeOut, UnitCount, CANCEL_ABORTED, EMIT_DONE, EMIT_TO_FAR_END,
    FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_REQUIRED,
    RECORD_PUT, REFUSAL_ARRIVE, REFUSAL_GATE, ROUTE_DIRECT, ROUTE_POOL, UNITS_REPORTED,
    VERDICT_RETRY,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::publish::{Generations, Keyed};
use busbar_contract::abi::sdk::services::ServiceError;
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot, Services};
use serde_json::Value;

use crate::answer::Answer;
use crate::ask::AskDecision;
use crate::call::{Admission, AdmittedCall, Settled};
use crate::catalogue::Catalogue;
use crate::door;
use crate::framing::{
    Framing, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, EVENT_STREAM, JSON, NO_STORE,
};
use crate::tool_arrival::Disposition;
use crate::tools_config::ToolsCfg;

/// The most calls the kernel keeps in flight on one instance, as the transport doors state it.
const MAX_INFLIGHT: u32 = 64;

/// The version the Statement names: the crate's (a test pins the two equal).
pub const VERSION: &str = "1.6.0";

/// THE STATEMENT: the plane's name and version, the settings sections it declares
/// ([`door::SECTIONS`]), its outbound needs ([`door::NEEDS`]) and its tail ([`door::TAIL`]).
pub const STATEMENT: Statement = Statement {
    kind_tail: (door::TAIL as *const busbar_contract::abi::plane::PlaneTail).cast::<KindTailHead>(),
    sections: door::SECTIONS.as_ptr(),
    sections_len: door::SECTIONS.len(),
    needs: door::NEEDS.as_ptr(),
    needs_len: door::NEEDS.len(),
    secret_refs: door::SECRET_REFS.as_ptr(),
    secret_refs_len: door::SECRET_REFS.len(),
    ..statement(crate::PLANE_KEY, VERSION, MAX_INFLIGHT)
};

/// THE CLAIMS AXIS: the pure plane the boot seal registers under its key, and the bytes it claims,
/// sealed against every other plane's so a tie is refused at boot (the transport each names must be
/// registered).
pub const PLANE: crate::McpPlane = crate::McpPlane::EMPTY;
/// The bytes [`PLANE`] claims.
pub const CLAIMS: &[busbar_contract::grammar::Claim] =
    <crate::McpPlane as busbar_contract::plane::PlaneMeta>::CLAIMS;

/// WHAT THE PLANE HOLDS FOR ONE GENERATION: the catalogue built from its section, and the section
/// itself (each member's registration).
#[derive(Debug)]
pub struct Held {
    /// The catalogue.
    pub catalogue: Catalogue,
    /// The section it was built from.
    pub section: ToolsCfg,
    /// The pools its servers are members of ([`door::read_open`]).
    pub pools: BTreeMap<String, door::ToolPool>,
}

impl Held {
    /// What a generation holds over `section`.
    #[must_use]
    pub fn of(generation: u64, section: ToolsCfg) -> Self {
        Held {
            catalogue: Catalogue::build(generation, &section),
            section,
            pools: BTreeMap::new(),
        }
    }

    /// What a generation holds over `section`, its servers in `pools`.
    #[must_use]
    pub fn pooled(
        generation: u64,
        section: ToolsCfg,
        pools: BTreeMap<String, door::ToolPool>,
    ) -> Self {
        Held {
            pools,
            ..Held::of(generation, section)
        }
    }

    /// The pool `server` is a member of, by name, when it is one (the first in name order).
    #[must_use]
    pub fn pool_of(&self, server: &str) -> Option<(&str, &door::ToolPool)> {
        self.pools
            .iter()
            .find(|(_, p)| p.members.iter().any(|m| m == server))
            .map(|(name, p)| (name.as_str(), p))
    }
}

/// One instance: the public base URL `open` was given, the host services, every live generation's
/// snapshot with what the plane holds for it, and the units in flight.
pub struct McpDoor {
    /// The endpoint its claims are stated under: its audience and metadata document
    /// ([`door::admitted`]).
    admitted: Option<(String, String)>,
    /// Its protected-resource facts ([`door::resource_facts`]).
    facts: Option<Vec<u8>>,
    /// The browser origins it admits beyond loopback ([`door::allowed_origins`]).
    origins: Vec<String>,
    services: Option<Services>,
    generations: Generations<PlaneSnapshot, Held>,
    units: Keyed<u64, CallUnit>,
    /// Each principal's roots epoch: moved by its `notifications/roots/list_changed`, sealed into
    /// an exchange that asks for roots.
    roots: Keyed<String, u64>,
    /// The host tables `open` handed it: the connector a `connect` reaches its server through.
    host: Option<busbar_contract::abi::sdk::conn::Host>,
    /// Each registered server's last sighting (`connect`): what the trust views and the dispatch
    /// gate judge against the section's approval.
    sightings: Keyed<String, crate::trust::Sighting>,
    /// THE LOCAL HALF OF THE SPENT-APPROVAL LEDGER: each nonce this instance redeemed, until the
    /// state it records lapses. Consulted before the host's one-time claim, so a node refuses its
    /// own replay without a round trip, and the whole gate where the host binds no store.
    spent: Keyed<String, u64>,
    /// THE LOCAL HALF OF THE PER-UPSTREAM SAMPLING BUDGET: each registered server's minute window
    /// ([`crate::tool_sampling::SampleWindow`]), counted before a completion slot's claim is issued
    /// on the host's ledger, and the whole gate where the host binds no store.
    sampled: Keyed<String, crate::tool_sampling::SampleWindow>,
    /// When each registered server's tool list was last fetched (Unix ms, the kernel's clock): what
    /// verify-on-call reads its `verify_ttl` against.
    checked: Keyed<String, u64>,
    /// The host's wake (`HostTables::wake`): a task's continuation and a held subscription are woken
    /// through it when what they wait for moves.
    wake: Option<busbar_contract::abi::sdk::services::Wake>,
    /// The subscriptions held as K6 sessions on the HTTP carrier, by stream ([`door_listen`]).
    listens: Keyed<u64, door_listen::Listening>,
    /// The instance's driver ticket and the tick clock, as its last `tick` handed them.
    driver: Keyed<(), (Ticket, u64)>,
    /// THE STDIO SERVERS' GREETINGS: the generation of each member's child the door ran
    /// `initialize` on ([`door_program`]), once per generation.
    greeted: Keyed<String, u64>,
    /// The requests of a stdio child's own the door answered, by member, generation and id: one
    /// answer each, whichever exchange read it first.
    answered: Keyed<(String, u64, String), ()>,
    /// THE TASKS this instance holds, by `taskId` (SEP-2663, [`door_tasks`]).
    tasks: Keyed<String, crate::tool_tasks::Task>,
    /// The result chunks of dropped tasks still to strike, by `taskId`: how many.
    strikes: Keyed<String, u32>,
}

impl McpDoor {
    /// What a request arriving now is answered from: the newest live generation's.
    #[must_use]
    pub fn current(&self) -> Option<Arc<Held>> {
        self.generations.current()
    }
}

/// The settings blob read as the `tools:` section, or the refusal in the grammar's words.
fn section(bytes: &[u8]) -> Result<ToolsCfg, Refusal> {
    door::read_tools_section(bytes).map_err(Refusal::refused)
}

/// The settings `open`/`refresh` are handed: the section and its pools.
fn opened_section(bytes: &[u8]) -> Result<(ToolsCfg, BTreeMap<String, door::ToolPool>), Refusal> {
    door::read_open(bytes).map_err(Refusal::refused)
}

/// The public base URL the host lent, when it states one.
fn public_url(bytes: &[u8]) -> Option<String> {
    std::str::from_utf8(bytes)
        .ok()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// One slot body on the SDK's safe surface, over this plane's [`McpDoor`].
macro_rules! slot {
    ($(#[$doc:meta])* $name:ident, $in:ty, $out:ty,
     |$inst:pat_param, $input:pat_param, $o:pat_param| $body:block) => {
        $(#[$doc])*
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = McpDoor;
            fn call($inst: Instance<'_, McpDoor>, $input: Lent<'_, $in>, $o: Out<'_, $out>)
                -> Outcome $body
        }
    };
}

slot!(
    /// `validate`: the settings read as the section, or refused in the grammar's words.
    Validate, ValidateIn, OutHead, |_, input, mut out| {
        match section(input.field(|i| &i.settings).bytes()) {
            Ok(_) => Outcome::Ready,
            Err(refusal) => out.fail(refusal),
        }
    }
);

slot!(
    /// `open`: the instance over the section, the public base URL and the host services, and the
    /// first generation's snapshot.
    Open, PlaneOpenIn, PlaneOpenOut, |instance, input, mut out| {
        let (cfg, pools) = match opened_section(input.field(|i| &i.open.settings).bytes()) {
            Ok(opened) => opened,
            Err(refusal) => return out.fail(refusal),
        };
        let generation = input.get().open.generation;
        let owned = input.field(|i| &i.owned).bytes();
        let admitted = match door::admitted_endpoint(
            public_url(input.field(|i| &i.public_url).bytes()).as_deref(),
            owned,
        ) {
            Ok(admitted) => admitted,
            Err(text) => return out.fail(Refusal::refused(text)),
        };
        let facts = match door::resource_facts(owned) {
            Ok(facts) => facts,
            Err(text) => return out.fail(Refusal::refused(text)),
        };
        let origins = match door::allowed_origins(owned) {
            Ok(origins) => origins,
            Err(text) => return out.fail(Refusal::refused(text)),
        };
        let plane = McpDoor {
            admitted,
            facts,
            origins,
            services: input
                .field(|i| &i.open)
                .host()
                .and_then(|h| Services::of(h.get())),
            host: input
                .field(|i| &i.open)
                .host()
                .map(|h| busbar_contract::abi::sdk::conn::Host::of(h.get())),
            sightings: Keyed::new(),
            spent: Keyed::new(),
            sampled: Keyed::new(),
            checked: Keyed::new(),
            wake: input
                .field(|i| &i.open)
                .host()
                .and_then(|h| busbar_contract::abi::sdk::services::Wake::of(h.get())),
            listens: Keyed::new(),
            driver: Keyed::new(),
            tasks: Keyed::new(),
            strikes: Keyed::new(),
            generations: Generations::new(),
            units: Keyed::new(),
            roots: Keyed::new(),
            greeted: Keyed::new(),
            answered: Keyed::new(),
        };
        let spec = door::snapshot_spec_with(plane.admitted.clone(), plane.facts.clone());
        let held = Held::pooled(generation, cfg, pools);
        out.publish_with(|o| &o.snapshot, &plane.generations, generation, &spec, held);
        instance.open(plane);
        Outcome::Ready
    }
);

slot!(
    /// `refresh`: the new section judged, and the next generation's snapshot over the same public base
    /// URL.
    Refresh, RefreshIn, PlaneRefreshOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let (cfg, pools) = match opened_section(input.field(|i| &i.settings).bytes()) {
            Ok(opened) => opened,
            Err(refusal) => return out.fail(refusal),
        };
        let generation = input.get().generation;
        let spec = door::snapshot_spec_with(plane.admitted.clone(), plane.facts.clone());
        let held = Held::pooled(generation, cfg, pools);
        out.publish_with(|o| &o.snapshot, &plane.generations, generation, &spec, held);
        // A subscription held as a session compares what its caller can see on the move.
        door_listen::wake_all(plane);
        Outcome::Ready
    }
);

slot!(
    /// `retire`: the generation's snapshot is dropped.
    Retire, GenIn, OutHead, |instance, input, _| {
        if let Some(plane) = instance.get() {
            plane.generations.retire(input.get().generation);
        }
        Outcome::Ready
    }
);

slot!(
    /// `tick`: the clock of the subscriptions held as sessions ([`door_listen::tick`]), every
    /// [`door_listen::POLL_NS`].
    Tick, TickIn, TickOut, |instance, input, mut out| {
        let given = input.get();
        let next = instance
            .get()
            .map_or(0, |plane| door_listen::tick(plane, given.head.ticket, given.now_ns));
        out.set(|o| &o.next_tick_ns, next);
        Outcome::Ready
    }
);

slot!(
    /// `drive`: the subscriptions held as sessions whose step is due ([`door_listen::drive`]).
    Drive, PlaneDriveIn, PlaneDriveOut, |instance, input, mut out| {
        match instance.get() {
            Some(plane) => door_listen::drive(plane, input, &mut out),
            None => Outcome::Ready,
        }
    }
);

slot!(
    /// `cancel`: the cancelled unit's state is dropped; nothing it holds had moved.
    Cancel, CancelIn, CancelOut, |instance, input, mut out| {
        if let Some(plane) = instance.get() {
            let ticket = input.get().ticket;
            // A task's continuation the kernel cancelled leaves its task cancelled.
            door_tasks::cancelled(plane, ticket);
            plane.units.with_all(|m| m.retain(|_, u| u.ticket != Some(ticket)));
            door_listen::cancelled(plane, ticket);
        }
        out.set(|o| &o.disposition, CANCEL_ABORTED);
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

// ── the request path ──────────────────────────────────────────────────────────────────────────

/// The most units the instance keeps state for at once; past it, the oldest is dropped first.
pub const MAX_UNITS: usize = 4096;

/// One unit's state, from its arrival to its end.
struct CallUnit {
    /// The unit's own key, as the kernel minted it.
    key: u64,
    /// What the plane held for the generation it arrived under.
    held: Option<Arc<Held>>,
    /// What the arrival is.
    disposition: Disposition,
    /// The request's `params`.
    params: Option<Value>,
    /// How its answer is framed; `None` = one JSON document.
    framing: Option<Framing>,
    /// The caller's `Mcp-Param-*` head fields, kept from the arrival (the head crosses once).
    param_fields: Vec<(String, String)>,
    /// The ticket its pieces cross on, once one has.
    ticket: Option<Ticket>,
    /// The host services its pieces have issued on the ticket, so every handle is fresh.
    issued: u32,
    /// The kernel's entitlement answers, by `"<scope kind>:<name>"`.
    entitled: BTreeMap<String, bool>,
    /// The member the kernel's walk picked for the current attempt.
    member: Option<String>,
    /// Which attempt of the walk is current (`0` before the first ATTEMPT piece): each attempt's
    /// verify-on-call fetch numbers its handles apart from the last's.
    attempt: u32,
    /// The relayed call, once admitted.
    relay: Option<Relay>,
    /// What it is writing, part way through.
    pending: Option<Pending>,
    /// The approval it is claiming on the host's ledger: the nonce and the handle the claim was
    /// issued under, re-issued when the unit is called again after the claim pended.
    claim: Option<(String, u32)>,
    /// Verify-on-call's sighting, kept while the kernel's trust book stamps it.
    verified: Option<crate::trust::Sighting>,
    /// The door's own exchange with a stdio member's child, while it pends ([`door_program`]).
    program: Option<(door_program::Purpose, crate::tool_program::ProgramExchange)>,
    /// The attempt whose stdio member the door greeted ([`door_program::ready`]).
    readied: Option<u32>,
    /// What the unit is to the tasks extension ([`door_tasks`]).
    task: Option<door_tasks::TaskUnit>,
}

/// A relayed `tools/call`: what was admitted, the round in flight and the far end's answer so far.
struct Relay {
    admitted: AdmittedCall,
    round: u32,
    /// The far end's status, from its answer's first piece.
    status: u32,
    /// The far end's answer is an event stream.
    sse: bool,
    /// The far end's answer, gathered until its last piece.
    far: Vec<u8>,
    /// The continuation of the further round in flight (MRTR): the upstream asked for something
    /// busbar grants and satisfies, and the retry carrying the answer is on the door's own need.
    next: Option<(Value, &'static str)>,
    /// The progress the rounds before the one in flight relayed.
    frames: Vec<Value>,
    /// The sampling ask being satisfied (its completions run as nested units), kept across the
    /// pends of its host calls.
    sample: Option<crate::tool_sampling::SampleRun>,
    /// A call relayed to a stdio member: its answer read by id among its child's messages.
    program: Option<door_program::ProgramRelay>,
    /// A `token_exchange:` member's down-scope for this caller, stated on every round's request.
    scope: Option<String>,
}

/// The most progress frames one request relays: a progress stream is untrusted upstream input,
/// bounded across every round of one call as the served engine bounded it.
const MAX_PROGRESS_FRAMES: usize = 256;

/// An answer part way through being written: its head (written with its first bytes), its bytes
/// and how many went, and where it goes.
struct Pending {
    /// The status the caller's answer starts with; `0` for a request bound for the far end.
    status: u32,
    /// The head fields, written with the first call.
    fields: Vec<(String, String)>,
    /// For the far end: the verb and the target.
    request: Option<(&'static str, String)>,
    bytes: Vec<u8>,
    sent: usize,
    /// The head is written.
    headed: bool,
    /// The unit's reply ends with these bytes.
    done: bool,
    /// The record writes that ride with its first call: `(kind, key, value)`.
    records: Vec<(u32, Vec<u8>, Vec<u8>)>,
    /// The counts its first call reports (the unit's cumulative usage, read off the far end).
    units: Vec<UnitCount>,
}

/// The host's clock, for the call log's `ts`: the kernel's one clock (`clock.now`), whole Unix
/// seconds, on a fresh handle of the unit's ticket. `None` when the host serves no clock, and then
/// no call record is written (a record never carries a time the plane made up).
fn clock_s(services: Option<Services>, ticket: Ticket, unit: &mut CallUnit) -> Option<u64> {
    let services = services?;
    let handle = CompletionHandle {
        ticket,
        seq: unit.issued,
        _reserved: 0,
    };
    unit.issued += 1;
    services
        .clock_now(handle)
        .ok()
        .map(|r| r.wall_ns / 1_000_000_000)
}

/// THE CALL LOG RECORD of one call, as it is written to the host's record seam: the call kind,
/// keyed by the caller's chain scope, the plane's own fields ([`crate::record::call_suffix`]).
#[must_use]
pub fn call_record(
    line: &crate::call::CallLine,
    scope: &str,
    generation: u64,
    ts: u64,
) -> (u32, Vec<u8>, Vec<u8>) {
    (
        door::RECORD_CALL,
        scope.as_bytes().to_vec(),
        crate::record::call_suffix(
            ts,
            &line.server,
            &line.tool,
            line.outcome,
            &line.reason,
            &line.tool_digest,
            generation,
        ),
    )
}

impl Pending {
    /// With the call log's record of `line`, under `scope` and `generation`, at `ts` (the host
    /// clock's reading; none, no record).
    fn logged(
        mut self,
        line: Option<&crate::call::CallLine>,
        scope: &str,
        generation: u64,
        ts: Option<u64>,
    ) -> Self {
        if let (Some(line), Some(ts)) = (line, ts) {
            self.records.push(call_record(line, scope, generation, ts));
        }
        self
    }

    /// The caller's answer `(status, body)` in `framing`, with `progress` ahead of it, done.
    fn answer(status: u32, body: Vec<u8>, framing: Option<&Framing>, progress: &[Value]) -> Self {
        let (bytes, streamed) = match framing {
            Some(f) => f.frame(status, body, progress),
            None => (body, false),
        };
        let fields = if streamed {
            vec![
                (CONTENT_TYPE.to_string(), EVENT_STREAM.to_string()),
                (CACHE_CONTROL.to_string(), NO_STORE.to_string()),
            ]
        } else if bytes.is_empty() {
            Vec::new()
        } else {
            // A WHOLE answer states its length, as the served engine's JSON answers did (an event
            // stream is relayed piece by piece and states none).
            vec![
                (CONTENT_TYPE.to_string(), JSON.to_string()),
                (CONTENT_LENGTH.to_string(), bytes.len().to_string()),
            ]
        };
        // THE FEE UNIT: earned by an answer the caller is served with a success (1.5.5 refunded the
        // per-request fee of an end whose caller status was not a success).
        let units = if (200..=299).contains(&status) {
            vec![UnitCount {
                class: door::CLASS_FEE_INDEX,
                source: UNITS_REPORTED,
                amount: 1,
            }]
        } else {
            Vec::new()
        };
        Pending {
            status,
            fields,
            request: None,
            bytes,
            sent: 0,
            headed: false,
            done: true,
            records: Vec::new(),
            units,
        }
    }

    /// Reporting the one tool call a server answered: the call is counted once the upstream has
    /// answered the round, never for a refused, unreachable or failed leg (the class is a response
    /// class: a call that never reached a server is not a call this node made).
    fn counted(mut self) -> Self {
        self.units.push(UnitCount {
            class: CLASS_TOOL_CALLS_INDEX,
            source: UNITS_REPORTED,
            amount: 1,
        });
        self
    }

    /// The request bound for the far end.
    fn far(outbound: crate::call::OutboundCall) -> Self {
        Pending {
            status: 0,
            fields: outbound.fields,
            request: Some((outbound.verb, outbound.target)),
            bytes: outbound.body,
            sent: 0,
            headed: false,
            done: false,
            records: Vec::new(),
            units: Vec::new(),
        }
    }
}

/// The tail index of the tool-call class ([`door::TAIL`]'s billable classes: tool calls, then
/// bytes); a reported count names its class by it.
const CLASS_TOOL_CALLS_INDEX: u32 = 0;

/// Keep `value` under `key` in `map`, dropping the smallest keys first past `cap`.
fn keep<V>(map: &Keyed<u64, V>, cap: usize, key: u64, value: V) {
    map.with_all(|m| {
        while m.len() >= cap && !m.contains_key(&key) {
            if m.pop_first().is_none() {
                break;
            }
        }
        m.insert(key, value);
    });
}

/// The operation class a disposition is counted under: its row's, or the notification class. A
/// refused arrival is counted under none.
fn op_class(disposition: &Disposition) -> Option<u32> {
    match disposition {
        Disposition::Request { row, .. } => door::op_class_index(row.op),
        Disposition::Notice { .. } => door::op_class_index(crate::tool_ops::OP_NOTIFICATION),
        Disposition::Refused(_) => None,
    }
}

/// A refusal as the text a refused arrival carries: the plane's own words, read back by
/// [`RefusalSlot`].
fn refusal_text(refusal: &crate::tool_arrival::Refusal) -> String {
    serde_json::json!({
        "status": refusal.status,
        "id": refusal.id,
        "code": refusal.code,
        "message": refusal.message,
        "data": refusal.data,
    })
    .to_string()
}

/// [`ArriveOut::refusal`]: the arrival is refused in the plane's own words, at its own status (the
/// words ride in the head's error, and `refusal` renders them).
pub const REFUSED_IN_OWN_WORDS: u32 = 1;

/// [`ArriveOut::refusal`]: the arrival names the discovery document, which is not answered on the
/// request path.
pub const UNSERVED: u32 = 2;

/// The status of an arrival the request path does not serve.
const STATUS_NOT_FOUND: u32 = 404;

/// REFUSED in the plane's own `text`, at `status`: `refusal` renders them.
fn refused_arrival(out: &mut Out<'_, ArriveOut>, status: u32, text: String) -> Outcome {
    out.set(|o| &o.refusal, REFUSED_IN_OWN_WORDS);
    out.set(|o| &o.refusal_status, status);
    out.fail(Refusal::refused(text))
}

/// The words of an arrival on a verb the endpoint does not serve.
const NOT_ALLOWED_TEXT: &str = r#"{"allow":"POST"}"#;

/// The words of an arrival from a browser origin the deployment does not admit.
const FORBIDDEN_ORIGIN_TEXT: &str = r#"{"origin":"forbidden"}"#;

/// The head field a browser names its origin in.
const ORIGIN: &str = "origin";

/// The head field a caller names its session in, for an incremental gate scan.
const SESSION_FIELD: &str = "x-session-id";

/// What a refused arrival said.
enum Words {
    /// A JSON-RPC refusal.
    Rpc(crate::tool_arrival::Refusal),
    /// A verb the endpoint does not serve.
    NotAllowed,
    /// A browser origin the deployment does not admit.
    ForbiddenOrigin,
}

/// A refused arrival's words read back.
fn words_of(text: &[u8]) -> Option<Words> {
    if text == NOT_ALLOWED_TEXT.as_bytes() {
        return Some(Words::NotAllowed);
    }
    if text == FORBIDDEN_ORIGIN_TEXT.as_bytes() {
        return Some(Words::ForbiddenOrigin);
    }
    refusal_of(text).map(Words::Rpc)
}

/// A refused arrival's JSON-RPC refusal read back.
fn refusal_of(text: &[u8]) -> Option<crate::tool_arrival::Refusal> {
    let v: Value = serde_json::from_slice(text).ok()?;
    Some(crate::tool_arrival::Refusal {
        status: u32::try_from(v.get("status")?.as_u64()?).ok()?,
        id: v.get("id").filter(|i| !i.is_null()).cloned(),
        code: v.get("code")?.as_i64()?,
        message: v.get("message")?.as_str()?.to_string(),
        data: v.get("data").filter(|d| !d.is_null()).cloned(),
    })
}

/// The head-field name prefix of SEP-2243's custom parameter headers.
const PARAM_FIELD_PREFIX: &str = "mcp-param-";

slot!(
    /// `arrive`: the arrival decided and kept with its generation and its framing; a refused one
    /// refused in its own words.
    Arrive, ArriveIn, ArriveOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let claim = door::ROUTES.get(input.get().claim as usize);
        let body = input.field(|i| &i.body).bytes();
        let fields = input.fields();
        if claim.is_some_and(|r| r.open) {
            // The discovery document is not answered on the request path.
            out.set(|o| &o.refusal, UNSERVED);
            out.set(|o| &o.refusal_status, STATUS_NOT_FOUND);
            return out.fail(Refusal::bare());
        }
        // THE ORIGIN FIRST (the served engine's order: who may speak at all, one field read): a
        // browser origin that is neither loopback nor on the operator's allowlist is refused, the
        // DNS-rebinding defence. A request with no `Origin` is not a browser's, and goes on.
        let origin = fields
            .iter()
            .find(|f| {
                f.field(|f| &f.name)
                    .as_str()
                    .is_ok_and(|n| n.eq_ignore_ascii_case(ORIGIN))
            })
            .and_then(|f| f.field(|f| &f.value).as_str().ok());
        if origin.is_some_and(|o| !busbar_contract::jsonrpc::origin_admitted(o, &plane.origins)) {
            return refused_arrival(
                &mut out,
                door::STATUS_FORBIDDEN_ORIGIN,
                FORBIDDEN_ORIGIN_TEXT.to_string(),
            );
        }
        if claim.is_some_and(|r| r.verb != "POST") {
            return refused_arrival(                &mut out,
                door::STATUS_METHOD_NOT_ALLOWED,
                NOT_ALLOWED_TEXT.to_string(),
            );
        }
        // A TASK'S CONTINUATION (ARCHITECT round 5 Q-L3B-TASKS (b) → (A)): the task it runs, and the
        // call it carries, decided below as the `tools/call` it is.
        let task_run = (input.get().claim as usize == door::TASK_RUN_ROUTE)
            .then(|| door_tasks::run_arrival(body));
        if let Some(None) = task_run {
            let refusal = door_tasks::unknown_arrival();
            return refused_arrival(&mut out, refusal.status, refusal_text(&refusal));
        }
        let task_run = task_run.flatten();
        // A task's continuation carries its call in its body: it is decided under the fields that
        // call implies.
        let task_body = task_run.as_ref().map(|(_, _, call)| call.clone());
        let mirrored = task_run
            .as_ref()
            .and_then(|(_, _, call)| serde_json::from_slice::<Value>(call).ok())
            .map(|v| crate::codec::mirrored(&v))
            .unwrap_or_default();
        let body: &[u8] = task_body.as_deref().unwrap_or(body);
        let field = |name: &str| {
            fields
                .iter()
                .find(|f| {
                    f.field(|f| &f.name)
                        .as_str()
                        .is_ok_and(|n| n.eq_ignore_ascii_case(name))
                })
                .and_then(|f| f.field(|f| &f.value).as_str().ok())
                .or_else(|| {
                    mirrored
                        .iter()
                        .find(|(n, _)| n.eq_ignore_ascii_case(name))
                        .map(|(_, v)| v.as_str())
                })
        };
        let disposition = crate::tool_arrival::decide(body, field);
        if let Disposition::Refused(refusal) = &disposition {
            return refused_arrival(&mut out, refusal.status, refusal_text(refusal));
        }
        let Some(op_class) = op_class(&disposition) else {
            return Outcome::Failed;
        };
        out.set(|o| &o.op_class, op_class);
        out.set(|o| &o.principal_need, PRINCIPAL_REQUIRED);
        out.set(|o| &o.dialect, 0);
        let value = serde_json::from_slice::<Value>(body).ok();
        let framing = match (&disposition, value.as_ref()) {
            (Disposition::Request { row, .. }, Some(v)) => {
                Framing::of(field("accept"), row.method, v)
            }
            _ => None,
        };
        let param_fields = fields
            .iter()
            .filter_map(|f| {
                let name = f.field(|f| &f.name).as_str().ok()?.to_ascii_lowercase();
                let value = f.field(|f| &f.value).as_str().ok()?;
                name.starts_with(PARAM_FIELD_PREFIX).then(|| (name, value.to_string()))
            })
            .collect();
        // THE ROUTE (ARCHITECT Q-SW6 / Q-FL3): a relayed call names the one registered server its
        // published tool is served by, a DIRECT entry of the `tools:` section; the kernel resolves
        // (plane key, entry) and never parses the name.
        let held = plane.current();
        let relayed = match (&disposition, held.as_ref(), value.as_ref()) {
            (Disposition::Request { row, .. }, Some(held), Some(v))
                if row.op == crate::tool_ops::OP_TOOL_CALL =>
            {
                v.get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str)
                    .and_then(|name| held.catalogue.tool(name))
                    .map(|entry| entry.server.clone())
            }
            _ => None,
        };
        // Every other arrival (a listing, a read, a notice, a call naming no published tool) is the
        // plane's own to answer: it names no entry and is admitted with no walk (Q-L3B-LOCAL).
        // A server that is a member of a pool routes over the POOL (ARCHITECT round 4
        // Q-L3B-SURFACES (h)): the kernel's one walk fails it over, under the breaker; a tool the
        // pool does not name `repeatable:` is performed at most once.
        match relayed {
            Some(server) => match held.as_ref().and_then(|h| {
                let (name, pool) = h.pool_of(&server)?;
                let bare = value
                    .as_ref()
                    .and_then(|v| v.pointer("/params/name"))
                    .and_then(Value::as_str)
                    .and_then(|n| h.catalogue.tool(n))
                    .map(|t| t.tool.clone())?;
                Some((name.to_string(), pool.repeatable.contains(&bare)))
            }) {
                Some((pool, repeatable)) => {
                    out.route(ROUTE_POOL, &pool);
                    if !repeatable {
                        out.once();
                    }
                }
                None => out.route(ROUTE_DIRECT, &server),
            },
            None => out.local(),
        }
        // THE SUBSCRIPTION ON THE HTTP CARRIER (ARCHITECT round 5 Q-L3B-K6-HTTP (a)): a K6 session,
        // the long-lived response its caller leg ([`door_listen`]).
        if matches!(&disposition, Disposition::Request { row, .. }
            if row.op == crate::tool_ops::OP_SUBSCRIPTIONS_LISTEN)
        {
            out.session();
        }
        // THE ADMISSION ESTIMATE of busbar's own ask: a prompt whose operator asks its caller first
        // costs the round it asks, on the caller's budget, as the served engine charged it (a
        // retry carrying the answers asks nothing, and is charged nothing).
        if let (Disposition::Request { row, .. }, Some(held), Some(v)) =
            (&disposition, held.as_ref(), value.as_ref())
        {
            if door_listen::asks_a_round(row.op, held, v) {
                let mut units = input.units_buf();
                units.push(UnitCount {
                    class: door::CLASS_FEE_INDEX,
                    source: busbar_contract::abi::plane::UNITS_ESTIMATED,
                    amount: 1,
                });
                let short = !units.fits();
                let (uw, und) = units.settle(short);
                out.set(|o| &o.units_written, uw as u32);
                out.set(|o| &o.units_needed, und as u32);
                if short {
                    return Outcome::Failed;
                }
            }
        }
        let unit = CallUnit {
            key: input.get().unit,
            held,
            disposition,
            params: value.and_then(|v| v.get("params").cloned()),
            framing,
            param_fields,
            ticket: None,
            issued: 0,
            entitled: BTreeMap::new(),
            member: None,
            attempt: 0,
            relay: None,
            pending: None,
            claim: None,
            verified: None,
            program: None,
            readied: None,
            task: task_run.map(|(reference, params, _)| door_tasks::TaskUnit::run(reference, params)),
        };
        keep(&plane.units, MAX_UNITS, input.get().unit, unit);
        Outcome::Ready
    }
);

/// THE KERNEL'S ENTITLEMENT ANSWERS for `unit`'s principal, one per grant in `grants` not yet
/// asked: `entitlement.check` of `"<kind>:<name>"`. Every handle the unit issues on its ticket is
/// fresh. No host services, a refused or failed call: not entitled.
fn ask_entitlements(
    services: Option<Services>,
    ticket: Ticket,
    unit: &mut CallUnit,
    grants: &[(&'static str, &str)],
) {
    for (kind, name) in grants {
        let target = format!("{kind}:{name}");
        if unit.entitled.contains_key(&target) {
            continue;
        }
        let answer = services.is_some_and(|s| {
            let handle = CompletionHandle {
                ticket,
                seq: unit.issued,
                _reserved: 0,
            };
            unit.issued += 1;
            s.entitled(handle, &target).unwrap_or(false)
        });
        unit.entitled.insert(target, answer);
    }
}

/// What one piece came to.
enum Step {
    /// Nothing to write: the piece was taken.
    Taken,
    /// The plane declines the piece.
    Declined,
    /// Write what is pending.
    Write,
    /// A host service pended (the approval's claim): called again on its wake.
    Pending,
    /// Held open (a task's continuation waiting on its phase): called again on a wake, or at this
    /// instant of the host's monotonic clock (`0` = on a wake only).
    Wait(u64),
    /// The walk's member is one this unit may not be sent to: declined, the walk moves on.
    Decline,
}

/// THE DOOR'S SEAL ([`crate::ask::Seal`]) over the host's services for one unit: the state signed
/// by the host's `sign` under the door's signing domain ([`crate::seal`]), a nonce from its
/// `random.fill`, and a completed exchange's approval spent once, first against the instance's own
/// ledger and then by the host's one-time `records.claim` of [`door::KIND_APPROVAL`]. A claim that
/// pends leaves [`Self::pending`] set; the unit answers PENDING and decides again on the wake, the
/// claim re-issued under the handle it was first issued under.
struct DoorSeal<'a> {
    services: Services,
    ticket: Ticket,
    issued: &'a mut u32,
    claim: &'a mut Option<(String, u32)>,
    spent: &'a Keyed<String, u64>,
    pending: bool,
}

impl DoorSeal<'_> {
    /// A fresh handle on the unit's ticket.
    fn handle(&mut self) -> CompletionHandle {
        let handle = CompletionHandle {
            ticket: self.ticket,
            seq: *self.issued,
            _reserved: 0,
        };
        *self.issued += 1;
        handle
    }

    /// The host's signature of `data` under the door's signing domain; `None` when it signs none.
    fn sign(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let handle = self.handle();
        let (mut buf, mut spans) = (
            [0u8; 256],
            [busbar_contract::abi::host::service::ItemSpan {
                key: busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 },
                value: busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 },
            }; 1],
        );
        self.services
            .sign(handle, data, &mut buf, &mut spans)
            .ok()
            .map(|s| s.signature.to_vec())
    }

    /// The kernel's wall clock, in Unix seconds.
    fn now(&mut self) -> u64 {
        let handle = self.handle();
        self.services
            .clock_now(handle)
            .map_or(0, |r| r.wall_ns / 1_000_000_000)
    }
}

impl crate::ask::Seal for DoorSeal<'_> {
    fn mint(&mut self, state: &crate::ask::AskState) -> Option<String> {
        crate::seal::seal_state(state, &mut |data| self.sign(data))
    }

    fn open(&mut self, blob: &str) -> Result<crate::ask::AskState, crate::ask::Rejected> {
        crate::seal::unseal_state(blob, &mut |data| self.sign(data))
    }

    fn nonce(&mut self) -> Option<String> {
        let handle = self.handle();
        let mut bytes = [0u8; 16];
        self.services.random_fill(handle, &mut bytes).ok()?;
        Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    fn redeem(&mut self, nonce: &str, expires_at: u64, now: u64) -> bool {
        // THE LOCAL HALF, test-and-set: a nonce this instance already took is refused here. Taken
        // on the first call only: a re-call after the claim pended re-issues the claim.
        let seq = match self.claim.as_ref() {
            Some((claimed, seq)) if claimed == nonce => *seq,
            _ => {
                let fresh = self.spent.with_all(|seen| {
                    seen.retain(|_, expiry| *expiry >= now);
                    seen.insert(nonce.to_string(), expires_at).is_none()
                });
                if !fresh {
                    return false;
                }
                let seq = self.handle().seq;
                *self.claim = Some((nonce.to_string(), seq));
                seq
            }
        };
        let handle = CompletionHandle {
            ticket: self.ticket,
            seq,
            _reserved: 0,
        };
        let ttl_ms = expires_at.saturating_sub(now).max(1).saturating_mul(1000);
        match self
            .services
            .records_claim(handle, door::KIND_APPROVAL, nonce.as_bytes(), ttl_ms)
        {
            std::task::Poll::Pending => {
                self.pending = true;
                false
            }
            // THE HOST'S LEDGER answered: its word is final.
            std::task::Poll::Ready(Ok(won)) => won,
            // No store bound (or no claim served): the local half was the whole gate.
            std::task::Poll::Ready(Err(
                ServiceError::Declined(Outcome::Refused) | ServiceError::Unserved,
            )) => true,
            // A ledger that cannot say whether the approval was spent is not read as "it was not".
            std::task::Poll::Ready(Err(_)) => false,
        }
    }
}

/// The answer to the caller's body: from what the plane holds, or the relayed call admitted.
/// What verify-on-call came to.
enum Looked {
    /// The sighting the gate reads is fresh: judge the call.
    Fresh,
    /// A host service pended (the fetch, or the stamp): called again on its wake.
    Pending,
}

/// VERIFY-ON-CALL (the rug-pull defence, before the call): the called server's live tool list is
/// fetched over the door's own need when its last fetch is older than its `verify_ttl` (default
/// [`crate::tools_config::DEFAULT_MCP_VERIFY_TTL`]; `0` = every call; never fetched = now), digested,
/// stamped on the kernel's trust book and kept, so the trust gate judges the call against what the
/// server serves NOW. A fetch that fails is the `error` state, which serves nothing (fail closed).
/// A registration with no `url:` has nothing to fetch, and a host that lends the door no connector
/// relays nothing either. The fetch carries the member's binding, as its relayed calls do (ARCHITECT
/// round 5 Q-L3B-DOOR-EXCHANGE): a `passthrough` registration's is lent the unit's caller
/// credential, a `token_exchange:` registration's exchanges for its approved set
/// ([`crate::tool_scope::registration_scope`]).
fn verify_on_call(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    ticket: Ticket,
    unit: &mut CallUnit,
    held: &Held,
    server: &str,
) -> Looked {
    use crate::trust::Sighting;
    let Some(def) = held.section.servers.get(server) else {
        return Looked::Fresh;
    };
    // A `transport: stdio` member is fetched from its own child ([`door_program::tools_listed`]).
    let program = door_program::is_program(def);
    if (def.url.is_empty() && !program) || !plane.host.is_some_and(|h| h.lends_connector()) {
        return Looked::Fresh;
    }
    let Some(services) = plane.services else {
        return Looked::Fresh;
    };
    let now_ms = {
        let handle = CompletionHandle {
            ticket,
            seq: unit.issued,
            _reserved: 0,
        };
        unit.issued += 1;
        services
            .clock_now(handle)
            .map_or(0, |r| r.wall_ns / 1_000_000)
    };
    let sighting = match unit.verified.take() {
        Some(kept) => kept,
        None => {
            let ttl_ms = busbar_contract::duration::parse_duration_secs(
                def.verify_ttl
                    .as_deref()
                    .unwrap_or(crate::tools_config::DEFAULT_MCP_VERIFY_TTL),
            )
            .unwrap_or(0)
            .saturating_mul(1000);
            let fresh = plane
                .checked
                .get(&server.to_string())
                .is_some_and(|at| ttl_ms > 0 && now_ms.saturating_sub(at) < ttl_ms);
            if fresh {
                return Looked::Fresh;
            }
            let base = VERIFY_SEQ.saturating_add(unit.attempt.saturating_mul(ROUND_SEQ_SPAN));
            if program {
                let std::task::Poll::Ready(answer) =
                    door_program::tools_listed(plane, ticket, unit, def, server, base)
                else {
                    return Looked::Pending;
                };
                match answer {
                    Ok((response, id)) => sighting_of(Ok(response), id),
                    Err(reason) => sighting_of(Err(reason), 0),
                }
            } else {
                // The verify fetch carries the member's down-scope (token_exchange) or the caller's
                // lent credential (passthrough) through the connector binding (Q-L3B-DOOR-EXCHANGE).
                let url = def.url.clone();
                let scope = crate::tool_scope::exchanges(
                    def,
                    held.section.effective_upstream_credentials(server),
                )
                .then(|| crate::tool_scope::registration_scope(server, def));
                let answer = exchange_at(instance, plane.host.as_ref(), base, &url, || {
                    let mut request =
                        crate::client::jsonrpc::tools_list(&url, CONNECT_REQUEST_ID, None);
                    scoped(&mut request.headers, scope.as_deref());
                    busbar_contract::abi::sdk::exchange::Request {
                        method: b"POST".to_vec(),
                        target: crate::call::path_of(&url).into_bytes(),
                        fields: request
                            .headers
                            .iter()
                            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
                            .collect(),
                        body: request.body,
                        timeout_ms: CONNECT_TIMEOUT_MS,
                    }
                });
                let std::task::Poll::Ready(answer) = answer else {
                    return Looked::Pending;
                };
                sighting_of(answer.map_err(|e| e.to_string()), CONNECT_REQUEST_ID)
            }
        }
    };
    if let Sighting::Seen(obs) = &sighting {
        let handle = CompletionHandle {
            ticket,
            seq: SIGHT_SEQ,
            _reserved: 0,
        };
        if services
            .trust_sight(handle, server, &crate::trust::catalogue_hash(obs))
            .is_pending()
        {
            unit.verified = Some(sighting);
            return Looked::Pending;
        }
    }
    plane.sightings.insert(server.to_string(), sighting);
    plane.checked.insert(server.to_string(), now_ms);
    Looked::Fresh
}

fn answer_body(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    ticket: Ticket,
    caller: &str,
    unit: &mut CallUnit,
) -> Option<Step> {
    let services = plane.services;
    let principal = if caller.is_empty() {
        crate::ask::UNGOVERNED
    } else {
        caller
    };
    // A TASK'S CONTINUATION runs its own phases; a `tasks/*` verb is answered from the task.
    if door_tasks::is_run(unit) {
        return Some(door_tasks::begin(plane, ticket, principal, unit));
    }
    if let Disposition::Request { row, id } = &unit.disposition {
        if [
            crate::tool_ops::OP_TASK_GET,
            crate::tool_ops::OP_TASK_UPDATE,
            crate::tool_ops::OP_TASK_CANCEL,
        ]
        .contains(&row.op)
        {
            let (op, id) = (row.op, id.clone());
            return Some(door_tasks::verb(plane, ticket, principal, unit, op, &id));
        }
    }
    let held = unit.held.clone()?;
    let mut params = unit.params.clone();
    let disposition = unit.disposition.clone();
    // THE POOL'S TWIN (ARCHITECT round 4 Q-L3B-SURFACES (h)): the kernel's walk picked another
    // member of the called tool's pool. The call is that member's own tool, admitted as its own
    // (its grants, its trust state, its argument guard), and interchangeable only when its approved
    // digest is the primary's; a member with no such twin is declined, and the walk moves on.
    if let (Disposition::Request { row, .. }, Some(member)) = (&disposition, unit.member.clone()) {
        if row.op == crate::tool_ops::OP_TOOL_CALL {
            match twin_of(&held, params.as_ref(), &member) {
                Twin::Same => {}
                Twin::Declined => return Some(Step::Decline),
                Twin::Call(published) => {
                    if let Some(p) = params.as_mut().and_then(Value::as_object_mut) {
                        p.insert("name".to_string(), Value::String(published));
                    }
                }
            }
        }
    }
    if let Disposition::Notice { method } = &disposition {
        if method == crate::ask::NOTIFY_ROOTS_LIST_CHANGED {
            plane
                .roots
                .with_all(|m| *m.entry(principal.to_string()).or_insert(0) += 1);
        }
    }
    let roots_epoch = plane.roots.get(&principal.to_string()).unwrap_or(0);
    let generation = held.catalogue.generation();
    let named_tool = match &disposition {
        Disposition::Request { row, id } if row.op == crate::tool_ops::OP_TOOL_CALL => {
            Some(id.clone())
        }
        _ => None,
    };
    // The grants this answer can ask: a call asks its own tool's two, any other request every
    // grant the catalogue holds.
    let grants = match &named_tool {
        Some(_) => params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .and_then(|name| held.catalogue.tool(name))
            .map(|t| {
                vec![
                    (door::SCOPE, t.server.as_str()),
                    (door::SCOPE_TOOL, t.namespaced.as_str()),
                ]
            })
            .unwrap_or_default(),
        None => held.catalogue.grants(),
    };
    ask_entitlements(services, ticket, unit, &grants);
    // VERIFY-ON-CALL, for a call the caller is entitled to make: the gate below judges what the
    // server serves now.
    if named_tool.is_some() {
        let called = params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .and_then(|name| held.catalogue.tool(name))
            .map(|t| (t.server.clone(), t.namespaced.clone()));
        if let Some((server, namespaced)) = called {
            let entitled = |kind: &str, name: &str| {
                unit.entitled
                    .get(&format!("{kind}:{name}"))
                    .copied()
                    .unwrap_or(false)
            };
            if entitled(door::SCOPE, &server) && entitled(door::SCOPE_TOOL, &namespaced) {
                if let Looked::Pending =
                    verify_on_call(instance, plane, ticket, unit, &held, &server)
                {
                    return Some(Step::Pending);
                }
                // A stdio member's child is greeted (once per generation) before the call.
                if let Some(member) = unit.member.clone() {
                    if let Looked::Pending =
                        door_program::ready(plane, ticket, unit, &held, &member)
                    {
                        return Some(Step::Pending);
                    }
                }
            }
        }
    }
    let mut seal = services.map(|services| DoorSeal {
        services,
        ticket,
        issued: &mut unit.issued,
        claim: &mut unit.claim,
        spent: &plane.spent,
        pending: false,
    });
    let entitled = &unit.entitled;
    let admit = |kind: &str, name: &str| {
        entitled
            .get(&format!("{kind}:{name}"))
            .copied()
            .unwrap_or(false)
    };
    if let Some(id) = named_tool {
        let fields = &unit.param_fields;
        let header = |name: &str| {
            fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        let mut ask = |entry: &crate::catalogue::ToolEntry, arguments: &Value| {
            decide_ask(
                &held,
                Site {
                    principal,
                    roots_epoch,
                    method: crate::codec::METHOD_TOOLS_CALL,
                    server: &entry.server,
                    capability: &entry.namespaced,
                    rounds: &entry.ask_caller,
                },
                params.as_ref(),
                arguments,
                seal.as_mut(),
            )
        };
        let refused_as = |entry: &crate::catalogue::ToolEntry| {
            let def = held.section.servers.get(&entry.server)?;
            let last = plane.sightings.get(&entry.server).unwrap_or_default();
            crate::trust::refused_as(def, &last, &entry.tool)
        };
        let admission = crate::call::admit_trusted(
            &held.catalogue,
            &id,
            params.as_ref(),
            &header,
            &admit,
            &refused_as,
            &|entry: &crate::catalogue::ToolEntry| {
                held.section
                    .servers
                    .get(&entry.server)
                    .is_some_and(|d| d.allow_private)
            },
            &mut ask,
        );
        if seal.is_some_and(|s| s.pending) {
            return Some(Step::Pending);
        }
        return Some(match admission {
            Admission::Asked(body, line) => {
                unit.pending = Some(
                    Pending::answer(200, body, unit.framing.as_ref(), &[]).logged(
                        Some(&line),
                        principal,
                        generation,
                        clock_s(services, ticket, unit),
                    ),
                );
                Step::Write
            }
            Admission::Refused(refusal, line) => {
                unit.pending = Some(
                    Pending::answer(refusal.status, refusal.body(), unit.framing.as_ref(), &[])
                        .logged(
                            line.as_ref(),
                            principal,
                            generation,
                            clock_s(services, ticket, unit),
                        ),
                );
                Step::Write
            }
            // THE TASK PATH: the call is admitted and answered, so the only question left is whether
            // the answer is a result or a task — the operator's declaration crossed with the
            // caller's (SEP-2663).
            Admission::Go(admitted) if door_tasks::creates(&admitted.entry, params.as_ref()) => {
                door_tasks::create(plane, ticket, principal, unit, &admitted, params.as_ref())
            }
            Admission::Go(admitted) => {
                let Some(member) = unit.member.clone() else {
                    // No member to send it to: the walk's terminal is the kernel's to render.
                    unit.relay = Some(Relay::of(admitted));
                    return Some(Step::Taken);
                };
                let def = held.section.servers.get(&member)?;
                let mut relay = Relay::of(admitted);
                let mut outbound = if door_program::is_program(def) {
                    // A stdio member: the call carries the unit's own id on the child.
                    let id = door_program::id_of(unit.key, 0);
                    relay.program = Some(door_program::ProgramRelay::waiting(id));
                    crate::call::outbound_program(&relay.admitted, &member, def, None, id)?
                } else {
                    crate::call::outbound(&relay.admitted, &member, def, 0, None)?
                };
                // A member's token_exchange down-scope / passthrough lend rides its outbound
                // (Q-L3B-DOOR-EXCHANGE); a stdio child carries none.
                if relay.program.is_none() {
                    relay.scope =
                        exchange_scope(services, ticket, unit, &held, &member, &relay.admitted);
                    scoped(&mut outbound.fields, relay.scope.as_deref());
                }
                unit.pending = Some(Pending::far(outbound));
                unit.relay = Some(relay);
                Step::Write
            }
        });
    }
    // A tool whose live sighting is quarantined is hidden from the listing.
    let quarantined = |entry: &crate::catalogue::ToolEntry| {
        held.section.servers.get(&entry.server).is_some_and(|def| {
            let last = plane.sightings.get(&entry.server).unwrap_or_default();
            matches!(last, crate::trust::Sighting::Seen(_))
                && crate::trust::refused_as(def, &last, &entry.tool) == Some("quarantined")
        })
    };
    let answer = crate::answer::answer(
        &disposition,
        params.as_ref(),
        &held.catalogue,
        &admit,
        quarantined,
    );
    let (status, body) = match answer {
        Answer::Here { status, body } => (status, body),
        Answer::Far => match &disposition {
            Disposition::Request { row, id } if row.op == crate::tool_ops::OP_PROMPT_GET => {
                let prompt =
                    crate::reads::prompt_named(&held.catalogue, id, params.as_ref(), &admit)
                        .ok()?;
                let arguments = params
                    .as_ref()
                    .and_then(|p| p.get("arguments"))
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));
                let site = Site {
                    principal,
                    roots_epoch,
                    method: "prompts/get",
                    server: &prompt.server,
                    capability: &prompt.namespaced,
                    rounds: &prompt.ask_caller,
                };
                let decided = decide_ask(&held, site, params.as_ref(), &arguments, seal.as_mut());
                if seal.is_some_and(|s| s.pending) {
                    return Some(Step::Pending);
                }
                match decided {
                    AskDecision::Proceed => {
                        (200, crate::reads::prompts_get(prompt, id, params.as_ref()))
                    }
                    AskDecision::Refuse(refusal) => {
                        let r = refusal.refusal(id);
                        (r.status, r.body())
                    }
                    AskDecision::Ask {
                        asks,
                        request_state,
                        ..
                    } => (
                        200,
                        crate::ask::input_required_result(id, &asks, &request_state),
                    ),
                }
            }
            _ => return Some(Step::Declined),
        },
    };
    unit.pending = Some(Pending::answer(status, body, unit.framing.as_ref(), &[]));
    Some(Step::Write)
}

/// What the walk's member is to a call named on a pool's member.
enum Twin {
    /// The member the call names.
    Same,
    /// Another member of its pool, whose own tool is published as this name.
    Call(String),
    /// A member this call may not be sent to.
    Declined,
}

/// The member `member` of the called tool's pool, as the call to send it: the tool it serves under
/// the same upstream name, approved with the digest of the pool's primary.
fn twin_of(held: &Held, params: Option<&Value>, member: &str) -> Twin {
    let Some(selected) = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .and_then(|n| held.catalogue.tool(n))
    else {
        return Twin::Same;
    };
    if selected.server == member {
        return Twin::Same;
    }
    let Some((_, pool)) = held.pool_of(&selected.server) else {
        return Twin::Declined;
    };
    if !pool.members.iter().any(|m| m == member) {
        return Twin::Declined;
    }
    let primary = pool
        .members
        .first()
        .and_then(|p| held.catalogue.tool_on(p, &selected.tool))
        .and_then(|t| t.schema_hash.clone());
    match held.catalogue.tool_on(member, &selected.tool) {
        // Interchangeable only on the PRIMARY's approved digest: an unapproved primary pools nothing.
        Some(twin) if primary.is_some() && twin.schema_hash == primary => {
            Twin::Call(twin.namespaced.clone())
        }
        _ => Twin::Declined,
    }
}

/// Where busbar's own ask is decided: who asks, under which roots epoch, and on what.
struct Site<'a> {
    principal: &'a str,
    roots_epoch: u64,
    method: &'a str,
    server: &'a str,
    capability: &'a str,
    rounds: &'a [crate::tools_config::AskRoundCfg],
}

/// BUSBAR'S OWN ASK for one request ([`crate::ask::decide`]), bound to the unit's principal, the
/// generation's catalogue and the request's arguments, sealed by `seal` ([`DoorSeal`]); `None` (no
/// host services) or a host that signs nothing is a deployment with no sealer, and a capability that
/// asks its caller is refused as one with no signing key refuses it.
fn decide_ask(
    held: &Held,
    site: Site<'_>,
    params: Option<&Value>,
    arguments: &Value,
    seal: Option<&mut DoorSeal<'_>>,
) -> AskDecision {
    let cap = held
        .section
        .servers
        .get(site.server)
        .and_then(|d| d.max_caller_ask_rounds)
        .unwrap_or(crate::tools_config::DEFAULT_MAX_CALLER_ASK_ROUNDS);
    let null = Value::Null;
    let capabilities = params
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(crate::codec::META_CLIENT_CAPABILITIES))
        .unwrap_or(&null);
    let retry = crate::ask::Retry {
        responses: params.and_then(|p| p.get("inputResponses")),
        state: params
            .and_then(|p| p.get("requestState"))
            .and_then(Value::as_str),
    };
    // No signing key, no sealer: an ask busbar cannot seal is one it cannot verify the answer to.
    let mut seal = seal;
    if !site.rounds.is_empty() && seal.as_deref_mut().is_some_and(|s| s.sign(b"").is_none()) {
        seal = None;
    }
    let now = seal.as_deref_mut().map_or(0, DoorSeal::now);
    let bind = crate::ask::Bind {
        principal: site.principal,
        method: site.method,
        capability: site.capability,
        generation: held.catalogue.generation(),
        now,
        roots_epoch: site.roots_epoch,
    };
    crate::ask::decide(
        site.rounds,
        cap,
        capabilities,
        retry,
        bind,
        &crate::ask::digest_arguments(arguments),
        seal.map(|s| s as &mut dyn crate::ask::Seal),
    )
}

impl Relay {
    fn of(admitted: AdmittedCall) -> Self {
        Relay {
            admitted,
            round: 0,
            status: 0,
            sse: false,
            far: Vec::new(),
            next: None,
            frames: Vec::new(),
            sample: None,
            program: None,
            scope: None,
        }
    }
}

/// THE DOWN-SCOPE a `token_exchange:` member's token is asked for on this unit's call (ARCHITECT
/// round 5 Q-L3B-EXCHANGE (B), [`crate::tool_scope::caller_downscope`]): the kernel's entitlement
/// answers for every tool the member serves, and whether the caller's tool grant is a wildcard (a
/// grant no tool name can be: only a wildcard holds it). `None` for a member that does not
/// exchange.
fn exchange_scope(
    services: Option<Services>,
    ticket: Ticket,
    unit: &mut CallUnit,
    held: &Held,
    member: &str,
    admitted: &AdmittedCall,
) -> Option<String> {
    let def = held.section.servers.get(member)?;
    if !crate::tool_scope::exchanges(def, held.section.effective_upstream_credentials(member)) {
        return None;
    }
    let called = held
        .catalogue
        .tool_on(member, &admitted.entry.tool)
        .map_or_else(
            || format!("{member}_{}", admitted.entry.tool),
            |t| t.namespaced.clone(),
        );
    let mut names = vec![String::new()];
    names.extend(
        held.catalogue
            .tools_for(&|kind: &str, name: &str| kind != door::SCOPE || name == member)
            .into_iter()
            .map(|t| t.namespaced.clone()),
    );
    let grants: Vec<(&'static str, &str)> = names
        .iter()
        .map(|n| (door::SCOPE_TOOL, n.as_str()))
        .collect();
    ask_entitlements(services, ticket, unit, &grants);
    let entitled = |name: &str| {
        unit.entitled
            .get(&format!("{}:{name}", door::SCOPE_TOOL))
            .copied()
            .unwrap_or(false)
    };
    Some(crate::tool_scope::caller_downscope(
        &held.catalogue,
        member,
        &called,
        entitled(""),
        &entitled,
    ))
}

/// State `scope` on a request bound for a `token_exchange:` member: the host's own field
/// (`abi::auth::SCOPE_REQUEST_FIELD`), which the host takes into the member's auth call and no wire
/// carries.
fn scoped(fields: &mut Vec<(String, String)>, scope: Option<&str>) {
    if let Some(scope) = scope {
        fields.push((
            busbar_contract::abi::auth::SCOPE_REQUEST_FIELD.to_string(),
            scope.to_string(),
        ));
    }
}

slot!(
    /// `on_piece`: the ATTEMPT names the member; the caller's body is answered from what the plane
    /// holds or sent on as the relayed call; the far end's answer is settled into the caller's. An
    /// answer is written over as many calls as the reply buffer takes, and the unit ends with it.
    OnPiece, OnPieceIn, OnPieceOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let piece = input.get();
        // A piece of a session (a subscription on the HTTP carrier) is the session's.
        if piece.stream != 0 {
            return door_listen::piece(plane, input, &mut out);
        }
        let key = piece.unit;
        let ticket = piece.head.ticket;
        let member = input.field(|i| &i.member).as_str().unwrap_or_default().to_string();
        let caller = input.field(|i| &i.caller_ref).as_str().unwrap_or_default().to_string();
        let bytes = input.field(|i| &i.bytes).bytes();
        let far_type = input
            .head_fields()
            .iter()
            .find(|f| {
                f.field(|f| &f.name)
                    .as_str()
                    .is_ok_and(|n| n.eq_ignore_ascii_case(CONTENT_TYPE))
            })
            .and_then(|f| f.field(|f| &f.value).as_str().ok().map(str::to_string));
        // A stdio member's lease names the generation of the child it reached in its head.
        let far_generation = input
            .head_fields()
            .iter()
            .find(|f| {
                f.field(|f| &f.name).as_str().is_ok_and(|n| {
                    n.eq_ignore_ascii_case(busbar_contract::conn::PROGRAM_GENERATION_FIELD)
                })
            })
            .and_then(|f| f.field(|f| &f.value).as_str().ok()?.trim().parse::<u64>().ok());
        let step = plane.units.with(&key, |unit| {
            let unit = unit?;
            unit.ticket = Some(ticket);
            // A re-call after `more = 1` carries nothing new: write what is still pending.
            if unit.pending.is_some() {
                return Some(Step::Write);
            }
            // A task's continuation, called again part way through a phase that waits.
            let principal = if caller.is_empty() {
                crate::ask::UNGOVERNED
            } else {
                caller.as_str()
            };
            if let Some(step) = door_tasks::resume(plane, ticket, principal, unit) {
                return Some(step);
            }
            match piece.from {
                FROM_KERNEL if piece.attempt_no > 0 => {
                    unit.member = Some(member);
                    unit.attempt = piece.attempt_no;
                    unit.verified = None;
                    Some(Step::Taken)
                }
                FROM_KERNEL => Some(Step::Taken),
                FROM_CALLER if piece.flags & PIECE_LAST == 0 => Some(Step::Taken),
                FROM_CALLER => answer_body(&instance, plane, ticket, &caller, unit),
                FROM_FAR_END => {
                    let held = unit.held.clone();
                    let framing = unit.framing.clone();
                    let task_run = door_tasks::is_run(unit);
                    let relay = unit.relay.as_mut()?;
                    let def = held
                        .as_ref()
                        .and_then(|h| h.section.servers.get(unit.member.as_deref()?));
                    // A re-call on a further round's (or a sampling completion's) wake carries the
                    // same piece: it is not read twice.
                    let mut settled = match relay.next.clone() {
                        Some((continuation, kind)) => Settled::Next { continuation, kind },
                        // The run is kept on the relay: its payload is read from there.
                        None if relay.sample.is_some() => Settled::Sample {
                            payload: Value::Null,
                        },
                        // A stdio member: its answer is the message carrying the call's id.
                        None if relay.program.is_some() => {
                            let member = unit.member.as_deref().unwrap_or_default();
                            let (Some(def), Some(program)) = (def, relay.program.as_mut()) else {
                                return None;
                            };
                            let last = piece.flags & PIECE_LAST != 0;
                            let head = far_generation.filter(|_| piece.flags & PIECE_HAS_STATUS != 0);
                            let far = door_program::far(
                                plane, ticket, member, def, program, head, bytes, last,
                            );
                            let wait = program.wait;
                            let progress = door_program::progress(program);
                            match far {
                                door_program::Far::Taken => {
                                    relay.frames.extend(progress);
                                    return Some(Step::Taken);
                                }
                                door_program::Far::Pending => {
                                    relay.frames.extend(progress);
                                    return Some(Step::Pending);
                                }
                                door_program::Far::Settled(Ok(answer)) => {
                                    relay.frames.extend(progress);
                                    relay.status = 200;
                                    relay.far = answer;
                                    crate::call::settle_call_as(
                                        &relay.admitted,
                                        Some(def),
                                        relay.status,
                                        &relay.far,
                                        false,
                                        relay.round,
                                        wait,
                                    )
                                }
                                door_program::Far::Settled(Err(reason)) => {
                                    relay.frames.extend(progress);
                                    relay.status = 0;
                                    crate::call::upstream_failed(&relay.admitted, &reason)
                                }
                            }
                        }
                        None => {
                            if piece.flags & PIECE_HAS_STATUS != 0 {
                                relay.status = piece.status_code;
                                relay.sse = far_type
                                    .as_deref()
                                    .is_some_and(|t| t.starts_with(EVENT_STREAM));
                            }
                            relay.far.extend_from_slice(bytes);
                            if piece.flags & PIECE_LAST == 0 {
                                return Some(Step::Taken);
                            }
                            crate::call::settle_call(
                                &relay.admitted,
                                def,
                                relay.status,
                                &relay.far,
                                relay.sse,
                                relay.round,
                            )
                        }
                    };
                    // THE FURTHER ROUNDS (MRTR): the upstream asked for something busbar grants
                    // and can satisfy, so the retry carrying the answer is sent on the door's own
                    // need to the same registration, round by round, under the round cap the
                    // judgement holds; each answer is settled as the first was.
                    // The progress every round relayed, in arrival order, bounded as one request's.
                    let mut frames = std::mem::take(&mut relay.frames);
                    loop {
                        match settled {
                            Settled::Next { continuation, kind } => {
                                let Some(def) = def else {
                                    settled = further_round_refused(&relay.admitted, kind);
                                    continue;
                                };
                                let member = unit.member.clone().unwrap_or_default();
                                let round = relay.round + 1;
                                let base = ROUND_SEQ.saturating_add(round.saturating_mul(ROUND_SEQ_SPAN));
                                // A stdio member's further round goes to its own child, by id.
                                if let Some(program) = relay.program.as_mut() {
                                    let id = door_program::id_of(key, round);
                                    let Some(outbound) = crate::call::outbound_program(
                                        &relay.admitted,
                                        &member,
                                        def,
                                        Some(&continuation),
                                        id,
                                    ) else {
                                        settled = further_round_refused(&relay.admitted, kind);
                                        continue;
                                    };
                                    relay.next = Some((continuation, kind));
                                    let std::task::Poll::Ready(answer) = door_program::round(
                                        plane, ticket, &member, def, program, outbound.body, id, base,
                                    ) else {
                                        relay.frames = frames;
                                        return Some(Step::Pending);
                                    };
                                    relay.next = None;
                                    relay.round = round;
                                    frames.extend(door_program::progress(program));
                                    frames.truncate(MAX_PROGRESS_FRAMES);
                                    settled = match answer {
                                        Ok(reply) => {
                                            relay.status = 200;
                                            relay.far = reply;
                                            crate::call::settle_call_as(
                                                &relay.admitted,
                                                Some(def),
                                                relay.status,
                                                &relay.far,
                                                false,
                                                relay.round,
                                                id,
                                            )
                                        }
                                        Err(reason) => {
                                            relay.status = 0;
                                            relay.far.clear();
                                            crate::call::upstream_failed(&relay.admitted, &reason)
                                        }
                                    };
                                    continue;
                                }
                                let Some(mut outbound) = crate::call::outbound(
                                    &relay.admitted,
                                    &member,
                                    def,
                                    round,
                                    Some(&continuation),
                                ) else {
                                    settled = further_round_refused(&relay.admitted, kind);
                                    continue;
                                };
                                scoped(&mut outbound.fields, relay.scope.as_deref());
                                relay.next = Some((continuation, kind));
                                let answer = exchange_at(
                                    &instance,
                                    plane.host.as_ref(),
                                    base,
                                    &def.url,
                                    || busbar_contract::abi::sdk::exchange::Request {
                                        method: outbound.verb.as_bytes().to_vec(),
                                        target: outbound.target.into_bytes(),
                                        fields: outbound
                                            .fields
                                            .iter()
                                            .map(|(n, v)| {
                                                (n.as_bytes().to_vec(), v.as_bytes().to_vec())
                                            })
                                            .collect(),
                                        body: outbound.body,
                                        timeout_ms: CONNECT_TIMEOUT_MS,
                                    },
                                );
                                let std::task::Poll::Ready(answer) = answer else {
                                    relay.frames = frames;
                                    return Some(Step::Pending);
                                };
                                relay.next = None;
                                relay.round = round;
                                if relay.sse {
                                    frames.extend(crate::call::progress_frames(&relay.far));
                                    frames.truncate(MAX_PROGRESS_FRAMES);
                                }
                                match answer {
                                    Ok(reply) => {
                                        relay.status = u32::from(reply.status);
                                        relay.sse = reply.fields.iter().any(|(n, v)| {
                                            n.eq_ignore_ascii_case(CONTENT_TYPE.as_bytes())
                                                && v.starts_with(EVENT_STREAM.as_bytes())
                                        });
                                        relay.far = reply.body;
                                    }
                                    Err(_) => {
                                        relay.status = 0;
                                        relay.far.clear();
                                    }
                                }
                                settled = crate::call::settle_call(
                                    &relay.admitted,
                                    Some(def),
                                    relay.status,
                                    &relay.far,
                                    relay.sse,
                                    relay.round,
                                );
                            }
                            // A granted sampling ask: one completion per entry, each a nested unit
                            // under the caller's key and budget ([`crate::tool_sampling`]); its
                            // answer is the next round's continuation, sent as a roots answer is.
                            Settled::Sample { payload } => {
                                let member = unit
                                    .member
                                    .clone()
                                    .unwrap_or_else(|| relay.admitted.entry.server.clone());
                                let run = relay.sample.get_or_insert_with(|| {
                                    crate::tool_sampling::SampleRun::new(payload)
                                });
                                let mut host = DoorSampler {
                                    services: plane.services,
                                    ticket,
                                    base: SAMPLE_SEQ.saturating_add(
                                        relay
                                            .round
                                            .saturating_mul(crate::tool_sampling::SAMPLE_SEQ_SPAN),
                                    ),
                                    windows: &plane.sampled,
                                };
                                let std::task::Poll::Ready(answer) = run.drive(
                                    &member,
                                    def.and_then(|d| d.sampling.as_ref()),
                                    &mut host,
                                ) else {
                                    relay.frames = frames;
                                    return Some(Step::Pending);
                                };
                                relay.sample = None;
                                settled = match answer {
                                    Ok(continuation) => Settled::Next {
                                        continuation,
                                        kind: "sampling",
                                    },
                                    Err(reason) => crate::call::ask_refused(
                                        &relay.admitted,
                                        &crate::call::AskRefusal::Unsatisfiable {
                                            server: relay.admitted.entry.server.clone(),
                                            kind: "sampling".to_string(),
                                            reason,
                                        },
                                    ),
                                };
                            }
                            answered @ Settled::Answer { .. } => {
                                settled = answered;
                                break;
                            }
                        }
                    }
                    if relay.sse {
                        frames.extend(crate::call::progress_frames(&relay.far));
                        frames.truncate(MAX_PROGRESS_FRAMES);
                    }
                    let progress = frames;
                    let Settled::Answer { status, body, line } = settled else {
                        return None;
                    };
                    // A TASK'S CONTINUATION ends in its task, never in a caller's answer.
                    if task_run {
                        let leg =
                            crate::call::leg_of(relay.status, &relay.far, relay.sse, relay.round);
                        let answered = relay.status != 0;
                        return Some(door_tasks::continuation_answered(
                            plane, ticket, principal, unit, leg, answered, &body,
                        ));
                    }
                    let progress = relay_progress(&relay.admitted, progress);
                    let scope = if caller.is_empty() {
                        crate::ask::UNGOVERNED
                    } else {
                        caller.as_str()
                    };
                    let generation = held.as_ref().map_or(0, |h| h.catalogue.generation());
                    let answered = relay.status != 0;
                    let ts = clock_s(plane.services, ticket, unit);
                    let pending = Pending::answer(status, body, framing.as_ref(), &progress)
                        .logged(Some(&line), scope, generation, ts);
                    unit.pending = Some(if answered {
                        pending.counted()
                    } else {
                        pending
                    });
                    Some(Step::Write)
                }
                _ => Some(Step::Declined),
            }
        });
        match step {
            None | Some(Step::Declined) => Outcome::Refused,
            Some(Step::Taken) => Outcome::Ready,
            Some(Step::Pending) => Outcome::Pending,
            Some(Step::Decline) => {
                out.set(|o| &o.verdict, VERDICT_RETRY);
                Outcome::Ready
            }
            Some(Step::Wait(at)) => {
                if at != 0 {
                    out.wake_at(at);
                }
                Outcome::Pending
            }
            Some(Step::Write) => {
                let finished = plane.units.with(&key, |unit| {
                    let unit = unit?;
                    let pending = unit.pending.as_mut()?;
                    Some(write(&input, &mut out, pending))
                });
                match finished {
                    None => Outcome::Failed,
                    Some(Err(())) => Outcome::Failed,
                    Some(Ok(Written::More)) => Outcome::Ready,
                    Some(Ok(Written::Sent)) => {
                        plane.units.with(&key, |unit| {
                            if let Some(unit) = unit {
                                unit.pending = None;
                            }
                        });
                        Outcome::Ready
                    }
                    Some(Ok(Written::Done)) => {
                        plane.units.remove(&key);
                        Outcome::Ready
                    }
                }
            }
        }
    }
);

/// A refused further round: the engine's unsatisfiable-ask refusal for an ask of `kind` this path
/// cannot carry to the far end.
fn further_round_refused(admitted: &AdmittedCall, kind: &str) -> Settled {
    let refusal = crate::call::AskRefusal::Unsatisfiable {
        server: admitted.entry.server.clone(),
        kind: kind.to_string(),
        reason: "the plane carries one request to the far end per attempt, so a further round is \
                 not sent; the ask terminates here and is not proxied to you"
            .to_string(),
    };
    crate::call::ask_refused(admitted, &refusal)
}

/// The far end's progress frames, mapped to the caller's own `progressToken` (none when the caller
/// asked for no progress).
fn relay_progress(admitted: &AdmittedCall, mut frames: Vec<Value>) -> Vec<Value> {
    let Some(token) = admitted.progress_token.clone() else {
        return Vec::new();
    };
    for f in &mut frames {
        if let Some(p) = f.get_mut("params").and_then(Value::as_object_mut) {
            p.insert("progressToken".to_string(), token.clone());
        }
    }
    frames
}

/// What one write came to.
enum Written {
    /// More is waiting.
    More,
    /// All of it went, and the unit goes on (a request sent to the far end).
    Sent,
    /// All of it went, and the unit's reply is complete.
    Done,
}

/// Write as much of `pending` as the host's buffers hold: its head with the first call, then its
/// bytes. `Err` = the head's buffers are short (re-called once with what they need).
fn write(
    input: &Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
    pending: &mut Pending,
) -> Result<Written, ()> {
    if !pending.headed {
        let (mut fields, mut arena) = (input.fields_buf(), input.arena_buf());
        for (name, value) in &pending.fields {
            fields.push(OutField {
                name: arena.span(name.as_bytes()),
                value: arena.span(value.as_bytes()),
            });
        }
        let request = pending
            .request
            .as_ref()
            .map(|(verb, target)| (arena.span(verb.as_bytes()), arena.span(target.as_bytes())));
        let mut records = input.records_buf();
        for (kind, key, value) in &pending.records {
            records.push(RecordWrite {
                kind: *kind,
                op: RECORD_PUT,
                key: arena.span(key),
                value: arena.span(value),
            });
        }
        let mut units = input.units_buf();
        for count in &pending.units {
            units.push(*count);
        }
        let short = !(fields.fits() && arena.fits() && records.fits() && units.fits());
        let (fw, fnd) = fields.settle(short);
        let (rw, rnd) = records.settle(short);
        let (uw, und) = units.settle(short);
        let (aw, and) = arena.settle(short);
        out.set(|o| &o.records_written, rw as u32);
        out.set(|o| &o.records_needed, rnd as u32);
        out.set(|o| &o.units_written, uw as u32);
        out.set(|o| &o.units_needed, und as u32);
        out.set(|o| &o.fields_written, fw as u32);
        out.set(|o| &o.fields_needed, fnd as u32);
        out.set(|o| &o.arena_written, aw as u64);
        out.set(|o| &o.arena_needed, and as u64);
        if short {
            return Err(());
        }
        if let Some((verb, target)) = request {
            out.set(|o| &o.verb, verb);
            out.set(|o| &o.target, target);
        }
        out.set(|o| &o.reply_status, pending.status);
        pending.headed = true;
    }
    let mut reply = input.reply_buf();
    let n = reply.stream(pending.bytes.get(pending.sent..).unwrap_or_default());
    pending.sent += n;
    out.set(|o| &o.emitted, n as u64);
    let mut flags = 0;
    if pending.request.is_some() {
        flags |= EMIT_TO_FAR_END;
    }
    if pending.sent < pending.bytes.len() {
        out.set(|o| &o.more, 1);
        out.set(|o| &o.flags, flags);
        return Ok(Written::More);
    }
    if pending.done {
        flags |= EMIT_DONE;
    }
    out.set(|o| &o.flags, flags);
    Ok(if pending.done {
        Written::Done
    } else {
        Written::Sent
    })
}

slot!(
    /// `refusal`: a refused arrival's own words rendered with its own status; any other refusal
    /// rendered as the one error envelope with no id.
    RefusalSlot, RefusalIn, RefusalOut, |instance, input, mut out| {
        let given = input.get();
        // The request id the refused unit's caller sent, where its arrival read one: an answer the
        // caller cannot correlate is not an answer.
        let unit_id = instance.get().and_then(|plane| {
            plane.units.with(&given.unit, |unit| match unit.map(|u| &u.disposition) {
                Some(Disposition::Request { id, .. }) => Some(id.clone()),
                _ => None,
            })
        });
        let text = input.field(|i| &i.text).bytes();
        // The tool a refused `tools/call` named, where its arrival read one.
        let called = instance.get().and_then(|plane| {
            plane.units.with(&given.unit, |unit| {
                let unit = unit?;
                matches!(&unit.disposition, Disposition::Request { row, .. }
                    if row.op == crate::tool_ops::OP_TOOL_CALL)
                .then(|| unit.params.as_ref()?.get("name")?.as_str().map(str::to_string))
                .flatten()
            })
        });
        // What the refused unit is to the tasks extension: a call that would have created a task
        // (its budget refusal is the served engine's task-path words), or a task's continuation
        // (its task fails).
        let (creates_task, run_reference) = instance
            .get()
            .and_then(|plane| {
                plane.units.with(&given.unit, |unit| {
                    unit.map(|u| (door_tasks::creates_task(u), door_tasks::run_reference(u)))
                })
            })
            .unwrap_or((false, None));
        if let (Some(plane), Some(reference)) = (instance.get(), run_reference.as_deref()) {
            let message = std::str::from_utf8(text).unwrap_or_default();
            door_tasks::continuation_refused(plane, given.unit, reference, message);
        }
        let (status, body, allow) = if given.cause == REFUSAL_ARRIVE {
            match words_of(text) {
                Some(Words::Rpc(refusal)) => (refusal.status, refusal.body(), false),
                Some(Words::NotAllowed) => (
                    door::STATUS_METHOD_NOT_ALLOWED,
                    door::method_not_allowed_body(),
                    true,
                ),
                Some(Words::ForbiddenOrigin) => (
                    door::STATUS_FORBIDDEN_ORIGIN,
                    door::forbidden_origin_body(),
                    false,
                ),
                None => return Outcome::Failed,
            }
        } else {
            let message = std::str::from_utf8(text).unwrap_or_default();
            // THE CALLER'S BUDGET said no (a spent budget, a rate, a frozen group): said in the
            // served engine's words, its reason the one the caller acts on.
            let budget = [
                busbar_contract::abi::plane::RefusalCode::OverBudget,
                busbar_contract::abi::plane::RefusalCode::RateLimited,
                busbar_contract::abi::plane::RefusalCode::GroupFrozen,
            ]
            .into_iter()
            .any(|r| r.code() == given.reason);
            // A CALL THE CALLER IS NOT GRANTED (the kernel's grant check said no before the plane
            // decided it): answered as the served engine answered it, `404 not_granted` in the
            // words an unknown tool gets.
            let ungranted = given.reason
                == busbar_contract::abi::plane::RefusalCode::ScopeDenied.code()
                && !creates_task;
            if let (true, Some(name)) = (ungranted, called.as_deref()) {
                let refusal = crate::call::not_granted(
                    unit_id.as_ref().unwrap_or(&Value::Null),
                    name,
                );
                (refusal.status, refusal.body(), false)
            } else {
            let refusal = if budget && creates_task {
                door_tasks::budget_refused(unit_id.clone(), message)
            } else if budget {
                crate::tool_arrival::Refusal {
                    status: given.status,
                    id: unit_id.clone(),
                    code: crate::codec::CODE_REFUSED,
                    message: format!("this request was refused by your budget: {message}"),
                    data: Some(serde_json::json!({ "reason": "budget_exhausted" })),
                }
            } else {
                crate::tool_arrival::Refusal {
                    status: given.status,
                    id: unit_id.clone(),
                    code: crate::codec::CODE_REFUSED,
                    message: message.to_string(),
                    // A HOOK'S VETO carries the served engine's reason (`hook_rejected`).
                    data: (given.cause == REFUSAL_GATE).then(|| {
                        serde_json::json!({ "reason": busbar_contract::vocab::REASON_HOOK_REJECTED })
                    }),
                }
            };
            (0, refusal.body(), false)
            }
        };
        let (mut reply, mut field_buf, mut arena) =
            (input.reply_buf(), input.fields_buf(), input.arena_buf());
        reply.extend(&body);
        if allow {
            field_buf.push(OutField {
                name: arena.span(b"allow"),
                value: arena.span(b"POST"),
            });
        }
        field_buf.push(OutField {
            name: arena.span(CONTENT_TYPE.as_bytes()),
            value: arena.span(JSON.as_bytes()),
        });
        let short = !(reply.fits() && field_buf.fits() && arena.fits());
        let (rw, rnd) = reply.settle(short);
        let (fw, fnd) = field_buf.settle(short);
        let (aw, and) = arena.settle(short);
        out.set(|o| &o.reply_written, rw as u64);
        out.set(|o| &o.reply_needed, rnd as u64);
        out.set(|o| &o.fields_written, fw as u32);
        out.set(|o| &o.fields_needed, fnd as u32);
        out.set(|o| &o.arena_written, aw as u64);
        out.set(|o| &o.arena_needed, and as u64);
        if short {
            return Outcome::Failed;
        }
        out.set(|o| &o.status, status);
        Outcome::Ready
    }
);

/// The server name a trust verb's target names (`/tools/{name}/<verb>`), its query cut.
fn verb_subject(target: &[u8]) -> Option<String> {
    let path = std::str::from_utf8(target).ok()?;
    let path = path.split('?').next().unwrap_or(path);
    let mut segments = path.trim_start_matches('/').split('/');
    let (_section, name) = (segments.next()?, segments.next()?);
    (!name.is_empty()).then(|| name.to_string())
}

/// A `connect` paused on the kernel's trust book: the sighting its fetch landed.
struct Sighted(crate::trust::Sighting);

/// The completion handle `trust.sight` is issued on: past every handle the connect's exchange
/// issues on the request's ticket.
const SIGHT_SEQ: u32 = 1 << 30;

/// The completion handle a `connect`'s clock reading is issued on: past `trust.sight`'s.
const CONNECT_CLOCK_SEQ: u32 = SIGHT_SEQ + 1;

/// The first handle verify-on-call's fetch numbers its connector services from on a unit's ticket:
/// clear of the unit's own handles (counted from `0`) and of the further rounds'.
const VERIFY_SEQ: u32 = 1 << 29;

/// The first handle a further round's (MRTR) exchange numbers its services from, per round
/// ([`ROUND_SEQ_SPAN`] apart): each exchange on one ticket counts its own handles.
const ROUND_SEQ: u32 = 1 << 28;

/// How many handles one further round's exchange may number.
const ROUND_SEQ_SPAN: u32 = 1 << 12;

/// The first handle a sampling ask's host calls (its clock, its budget's claims, its nested
/// completions) number from, per answered round ([`crate::tool_sampling::SAMPLE_SEQ_SPAN`] apart):
/// above [`SIGHT_SEQ`], so clear of the unit's own handles, the further rounds' and every attempt's
/// verify-on-call fetch.
const SAMPLE_SEQ: u32 = 3 << 29;

/// The bytes a nested completion's reply is first read into; a longer one is re-read once, on the
/// same handle, at the size the host names (up to [`crate::tool_sampling::MAX_COMPLETION_BYTES`]).
const SAMPLE_REPLY_BYTES: usize = 64 * 1024;

/// The spans a nested completion's reply is first read into: its body's, and its head fields'.
const SAMPLE_REPLY_SPANS: usize = 64;

/// THE SAMPLING SATISFIER'S HOST ([`crate::tool_sampling::SampleHost`]) over the host's services
/// for one unit: the kernel's clock, the local half of the per-upstream budget and its one-time
/// slot claims of [`door::KIND_APPROVAL`], and `unit.nest` for each completion. Every call is
/// numbered from `base`; a call that pends is re-issued under the number it was first issued under.
struct DoorSampler<'a> {
    services: Option<Services>,
    ticket: Ticket,
    base: u32,
    windows: &'a Keyed<String, crate::tool_sampling::SampleWindow>,
}

impl DoorSampler<'_> {
    fn handle(&self, seq: u32) -> CompletionHandle {
        CompletionHandle {
            ticket: self.ticket,
            seq: self.base.saturating_add(seq),
            _reserved: 0,
        }
    }
}

impl crate::tool_sampling::SampleHost for DoorSampler<'_> {
    fn now_secs(&mut self, seq: u32) -> u64 {
        let handle = self.handle(seq);
        self.services
            .and_then(|s| s.clock_now(handle).ok())
            .map_or(0, |r| r.wall_ns / 1_000_000_000)
    }

    fn reserve(&mut self, server: &str, cap: u32, now: u64) -> Result<u32, String> {
        self.windows.with_all(|windows| {
            let window = windows.entry(server.to_string()).or_insert((now / 60, 0));
            crate::tool_sampling::reserve_sample_slot(window, server, cap, now)
        })
    }

    fn claim(
        &mut self,
        seq: u32,
        key: &str,
        ttl_ms: u64,
    ) -> std::task::Poll<crate::tool_sampling::SlotClaim> {
        use crate::tool_sampling::SlotClaim;
        use std::task::Poll;
        let Some(services) = self.services else {
            return Poll::Ready(SlotClaim::Unbound);
        };
        match services.records_claim(
            self.handle(seq),
            door::KIND_APPROVAL,
            key.as_bytes(),
            ttl_ms,
        ) {
            Poll::Pending => Poll::Pending,
            // THE HOST'S LEDGER answered: its word is final.
            Poll::Ready(Ok(true)) => Poll::Ready(SlotClaim::Won),
            Poll::Ready(Ok(false)) => Poll::Ready(SlotClaim::Lost),
            Poll::Ready(Err(ServiceError::Declined(Outcome::Refused) | ServiceError::Unserved)) => {
                Poll::Ready(SlotClaim::Unbound)
            }
            Poll::Ready(Err(_)) => Poll::Ready(SlotClaim::Unreadable),
        }
    }

    fn complete(
        &mut self,
        seq: u32,
        body: &[u8],
    ) -> std::task::Poll<crate::tool_sampling::Completion> {
        use crate::tool_sampling::{
            Completion, COMPLETION_FAILED, COMPLETION_OVERSIZED, MAX_COMPLETION_BYTES,
        };
        use busbar_contract::abi::host::service::ItemSpan;
        use busbar_contract::abi::mechanism::call::Span;
        use busbar_contract::abi::mechanism::check::SPAN_ABSENT;
        use std::task::Poll;
        let Some(services) = self.services else {
            return Poll::Ready(Completion::Unserved);
        };
        let handle = self.handle(seq);
        let absent = Span {
            offset: SPAN_ABSENT,
            len: 0,
        };
        let mut sizes = (SAMPLE_REPLY_BYTES, SAMPLE_REPLY_SPANS);
        // At most twice: a short answer is re-issued ONCE, on the same handle, at the size it names.
        for _ in 0..2 {
            let mut buf = vec![0u8; sizes.0];
            let mut spans = vec![
                ItemSpan {
                    key: absent,
                    value: absent,
                };
                sizes.1
            ];
            let answer = services.unit_nest(
                handle,
                crate::tool_sampling::COMPLETION_VERB,
                crate::tool_sampling::COMPLETION_TARGET,
                body,
                &mut buf,
                &mut spans,
            );
            match answer {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(nested)) => {
                    return Poll::Ready(Completion::Answered {
                        status: nested.status,
                        body: nested.body.to_vec(),
                    })
                }
                Poll::Ready(Err(ServiceError::Short { bytes, items })) => {
                    let bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
                    let items = usize::try_from(items).unwrap_or(usize::MAX);
                    if bytes > MAX_COMPLETION_BYTES.saturating_add(SAMPLE_REPLY_BYTES)
                        || items > SAMPLE_REPLY_SPANS.saturating_mul(16)
                    {
                        return Poll::Ready(Completion::Failed(COMPLETION_OVERSIZED));
                    }
                    sizes = (bytes.max(sizes.0), items.max(sizes.1));
                }
                // Nothing serves the claim, or the host refused the nested unit (no nesting, too
                // deep, too many at once): no completion server answers this ask.
                Poll::Ready(Err(
                    ServiceError::Declined(Outcome::Refused) | ServiceError::Unserved,
                )) => return Poll::Ready(Completion::Unserved),
                Poll::Ready(Err(_)) => return Poll::Ready(Completion::Failed(COMPLETION_FAILED)),
            }
        }
        Poll::Ready(Completion::Failed(COMPLETION_FAILED))
    }
}

/// ONE EXCHANGE ON A UNIT'S TICKET, its connector services numbered from `base` (a unit's ticket
/// carries several exchanges, one after another: each counts its own handles, so none reads
/// another's stored answer), parked on the instance while it pends.
fn exchange_at(
    instance: &Instance<'_, McpDoor>,
    host: Option<&busbar_contract::abi::sdk::conn::Host>,
    base: u32,
    url: &str,
    request: impl FnOnce() -> busbar_contract::abi::sdk::exchange::Request,
) -> std::task::Poll<
    Result<
        busbar_contract::abi::sdk::exchange::ExchangeResponse,
        busbar_contract::abi::sdk::conn::ConnFailure,
    >,
> {
    use busbar_contract::abi::sdk::exchange::{exchange, Exchange};
    let Some(host) = host else {
        return std::task::Poll::Ready(Err(busbar_contract::abi::sdk::conn::ConnFailure::Unarmed));
    };
    let mut state = match instance.resume::<Exchange>() {
        Some(parked) => *parked,
        None => match Exchange::request(request()) {
            Ok(s) => s,
            Err(e) => return std::task::Poll::Ready(Err(e)),
        },
    };
    let answer = exchange(
        &mut host.connector_from(instance.ticket(), base),
        &mut state,
        0,
        Some(url),
    );
    if answer.is_pending() {
        instance.park(state);
    }
    answer
}

/// The JSON-RPC id a `connect`'s `tools/list` carries: one request, correlated by this id.
const CONNECT_REQUEST_ID: u64 = 1;

/// How long a `connect`'s fetch may take: an upstream is not trusted to answer, and an operator
/// verb that hangs is one that gets killed and retried.
const CONNECT_TIMEOUT_MS: u64 = 30_000;

/// THE SIGHTING a `connect`'s exchange landed: the server's tool list re-hashed, or why the contact
/// failed, in the served engine's words.
fn sighting_of(
    answer: Result<busbar_contract::abi::sdk::exchange::ExchangeResponse, String>,
    sent_id: u64,
) -> crate::trust::Sighting {
    use crate::client::jsonrpc::{parse_response, RpcOutcome};
    use crate::trust::Sighting;
    let response = match answer {
        Ok(r) => r,
        Err(reason) => return Sighting::Failed(reason),
    };
    let failed = |reason: String| Sighting::Failed(reason);
    match parse_response(&response.body, sent_id) {
        RpcOutcome::Result(value) => match crate::trust::observe(&value) {
            Ok(obs) => Sighting::Seen(obs),
            Err(reason) => failed(reason),
        },
        RpcOutcome::Error { code, message } => failed(format!(
            "the upstream answered JSON-RPC error {code}: {message}"
        )),
        RpcOutcome::InputRequired { kind } => failed(format!(
            "the upstream answered `tools/list` with an input-required result asking for `{}`; a \
             tool list is not a dispatch and busbar has no round to meter that ask against, so it \
             is refused here",
            kind.key()
        )),
        RpcOutcome::Malformed(reason) => failed(format!(
            "the upstream returned HTTP {} and a body that is not a JSON-RPC response: {reason}",
            response.status
        )),
        RpcOutcome::Uncorrelated(reason) => failed(format!(
            "the upstream returned HTTP {} and a JSON-RPC response busbar cannot correlate to this \
             refresh: {reason}",
            response.status
        )),
    }
}

/// Write a trust verb's answer: `status` and `body` (`content_type`), and the audit outcome.
fn served(
    input: &Lent<'_, ServeIn>,
    out: &mut Out<'_, ServeOut>,
    status: u32,
    body: &[u8],
    content_type: &str,
    audit: u32,
) -> Outcome {
    out.answer(input, status, &[(CONTENT_TYPE, content_type)], body, audit)
}

slot!(
    /// `serve`: the trust verbs over the section's registrations (ARCHITECT Q-L3B-VERBS):
    /// `connect` fetches the server's live tool list over the door's own need, re-hashes it, records
    /// the sighting's catalogue hash on the kernel's trust book (`trust.sight`) and answers the trust
    /// view; `changes` answers the same view off the last sighting, contacting nothing; `health`
    /// answers whether it serves. An unregistered name is `404` before anything else; a
    /// `passthrough` registration refuses `connect` with `400` before any network I/O (its credential
    /// belongs to a caller, and an operator's refresh has none). An error answer's body is the
    /// operator-facing message alone: the kernel frames it in the admin taxonomy.
    Serve, ServeIn, ServeOut, |instance, input, mut out| {
        use busbar_contract::abi::plane::{AUDIT_APPLIED, AUDIT_REJECTED};
        use crate::trust::Sighting;
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let route = input.get().route as usize;
        let held = plane.current();
        let name = verb_subject(input.field(|i| &i.target).bytes());
        let found = held
            .as_ref()
            .zip(name.as_ref())
            .and_then(|(h, n)| h.section.servers.get(n).cloned().map(|d| (h, n, d)));
        let Some((held, name, def)) = found else {
            return served(&input, &mut out, crate::tool_arrival::STATUS_NOT_FOUND, b"", "text/plain", 0);
        };
        let verb = door::ADMIN_VERBS.get(route).map_or("", |(_, t)| t.rsplit('/').next().unwrap_or(""));
        let last = plane.sightings.get(name).unwrap_or_default();
        match verb {
            "changes" => {
                let view = crate::trust::trust_view(name, &def, &last);
                return served(&input, &mut out, 200, view.as_bytes(), JSON, 0);
            }
            "health" => {
                let view = crate::trust::health_view(name, &def, &last);
                return served(&input, &mut out, 200, view.as_bytes(), JSON, 0);
            }
            "connect" => {}
            _ => return served(&input, &mut out, crate::tool_arrival::STATUS_NOT_FOUND, b"", "text/plain", 0),
        }
        if held.section.effective_upstream_credentials(name)
            == Some(busbar_contract::config::UpstreamCreds::Passthrough)
        {
            let message = format!(
                "server `{name}` is configured `upstream_credentials: passthrough`, so its \
                 credential belongs to a caller; an operator-driven refresh has no caller and \
                 busbar will not substitute its own"
            );
            return served(&input, &mut out, 400, message.as_bytes(), "text/plain", AUDIT_REJECTED);
        }
        // THE FETCH, unless a pause on the trust book already holds what it landed.
        let sighting = match instance.resume::<Sighted>() {
            Some(sighted) => sighted.0,
            // A `transport: stdio` server is fetched from its own child.
            None if door_program::is_program(&def) => {
                let std::task::Poll::Ready((answer, id)) =
                    door_program::connect_child(&instance, plane, &def, name)
                else {
                    return Outcome::Pending;
                };
                sighting_of(
                    answer.map(|body| busbar_contract::abi::sdk::exchange::ExchangeResponse {
                        status: 200,
                        reason: None,
                        fields: Vec::new(),
                        body,
                    }),
                    id,
                )
            }
            None if def.url.is_empty() => Sighting::Failed(format!(
                "server `{name}` registers no `url:` this door can reach it at"
            )),
            None => {
                let op = busbar_contract::abi::sdk::exchange::Op::new(&instance, plane.host.as_ref());
                let url = def.url.clone();
                // A `token_exchange:` registration's binding exchanges for its approved set.
                let scope = crate::tool_scope::exchanges(
                    &def,
                    held.section.effective_upstream_credentials(name),
                )
                .then(|| crate::tool_scope::registration_scope(name, &def));
                let answer = op.exchange(0, Some(&url), || {
                    let mut request =
                        crate::client::jsonrpc::tools_list(&url, CONNECT_REQUEST_ID, None);
                    scoped(&mut request.headers, scope.as_deref());
                    Ok(busbar_contract::abi::sdk::exchange::Request {
                        method: b"POST".to_vec(),
                        target: crate::call::path_of(&url).into_bytes(),
                        fields: request
                            .headers
                            .iter()
                            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
                            .collect(),
                        body: request.body,
                        timeout_ms: CONNECT_TIMEOUT_MS,
                    })
                });
                let std::task::Poll::Ready(answer) = answer else {
                    return Outcome::Pending;
                };
                sighting_of(answer.map_err(|e| e.to_string()), CONNECT_REQUEST_ID)
            }
        };
        // THE KERNEL'S TRUST BOOK records the observed catalogue (it stamps the re-verification
        // clock); the answer is the plane's comparison, which is what the operator is looking at.
        if let (Sighting::Seen(obs), Some(services)) = (&sighting, plane.services) {
            let handle = CompletionHandle {
                ticket: instance.ticket(),
                seq: SIGHT_SEQ,
                _reserved: 0,
            };
            if services
                .trust_sight(handle, name, &crate::trust::catalogue_hash(obs))
                .is_pending()
            {
                instance.park(Sighted(sighting));
                return Outcome::Pending;
            }
        }
        plane.sightings.insert(name.clone(), sighting.clone());
        // THE FRESHNESS CLOCK records that the operator's connect LOOKED, whatever it saw (the
        // served engine's settle stamped `last_checked_ms` on every observation): a call within
        // `verify_ttl` of it reuses this sighting rather than fetching the list again.
        if let Some(services) = plane.services {
            let handle = CompletionHandle {
                ticket: instance.ticket(),
                seq: CONNECT_CLOCK_SEQ,
                _reserved: 0,
            };
            if let Ok(now) = services.clock_now(handle) {
                plane.checked.insert(name.clone(), now.wall_ns / 1_000_000);
            }
        }
        let view = crate::trust::trust_view(name, &def, &sighting);
        served(&input, &mut out, 200, view.as_bytes(), JSON, AUDIT_APPLIED)
    }
);

slot!(
    /// `hydrate`: nothing to restore. The plane's durable records (the call log, the demotions) are
    /// the host's, kept and verified on its record seam, and the trust state they feed is the
    /// kernel's: no plane-side state outlives a restart.
    Hydrate, GenIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `start`: no background work. Re-verification is the kernel's trust tick, and a stale server is
    /// re-verified on the call that names it.
    Start, GenIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `project`: a `tools/call` as the hook kind's request view: one turn of tool arguments
    /// ([`crate::call::invocation`]), named by the plane's key, the `{tool, arguments}` body, and the
    /// prompt view a content-granted hook reads (the one `user` turn, the arguments as JSON text, as
    /// the served engine projected an invocation). A request-stage hook's rewrite
    /// ([`crate::call::rewritten`]) is applied first: the rewritten request is answered in
    /// `rewritten` (the body the kernel keeps and re-pushes from then on) and is the body projected.
    /// Any other request carries no invocation for a hook to read: REFUSED.
    Project, ProjectIn, ProjectOut, |instance, input, mut out| {
        let body = input.field(|i| &i.body).bytes();
        let rewrite = input.field(|i| &i.rewrite).bytes();
        let rewritten = (!rewrite.is_empty())
            .then(|| crate::call::rewritten(body, rewrite))
            .flatten();
        let Some(invocation) = crate::call::invocation(rewritten.as_deref().unwrap_or(body)) else {
            // ANY OTHER REQUEST carries no invocation for a hook to read, and names no entry its
            // hooks are attached to: an empty view (the served engine fired no hook on it), never a
            // refusal (a bound hook stage asks every routed unit).
            out.set(
                |o| &o.body,
                busbar_contract::abi::mechanism::call::Span {
                    offset: busbar_contract::abi::plane::SPAN_ABSENT,
                    len: 0,
                },
            );
            return Outcome::Ready;
        };
        // AN APPLIED REWRITE IS THE UNIT'S REQUEST FROM NOW ON (`ProjectIn::unit`): the call the
        // door admits and relays is decided from the rewritten params, never the caller's.
        if let (Some(rewritten), Some(plane)) = (rewritten.as_deref(), instance.get()) {
            let params = serde_json::from_slice::<Value>(rewritten)
                .ok()
                .and_then(|v| v.get("params").cloned());
            plane.units.with(&input.get().unit, |unit| {
                if let Some(unit) = unit {
                    unit.params = params;
                }
            });
        }
        let shape = busbar_contract::ir::facts::IrFacts::shape(&invocation);
        // THE ENTRY the call's hooks are attached to: the registered server its published tool is
        // served by (the served engine fired `tools.hooks` and `tools.<server>.hooks` by server).
        let entry = instance
            .get()
            .and_then(McpDoor::current)
            .and_then(|held| held.catalogue.tool(&invocation.tool).map(|t| t.server.clone()))
            .unwrap_or_default();
        // THE SESSION an incremental gate scan is keyed on: the caller's `x-session-id`, as the
        // served engine read it; none when the caller sent none.
        let session = input
            .fields()
            .iter()
            .find(|f| {
                f.field(|f| &f.name)
                    .as_str()
                    .is_ok_and(|n| n.eq_ignore_ascii_case(SESSION_FIELD))
            })
            .and_then(|f| f.field(|f| &f.value).as_str().ok())
            .filter(|v| !v.is_empty())
            .map(str::to_string);
        let projected = serde_json::to_vec(&serde_json::json!({
            "tool": invocation.tool,
            "arguments": invocation.arguments,
        }))
        .unwrap_or_default();
        let turns: Vec<(&str, String)> = busbar_contract::ir::facts::IrFacts::content(&invocation)
            .iter()
            .map(|item| (item.author(), item.screenable_text().into_owned()))
            .collect();
        let (mut arena, signals, mut messages) =
            (input.arena_buf(), input.signals_buf(), input.messages_buf());
        let pool = arena.span(entry.as_bytes());
        let session = session.as_deref().map(|s| arena.span(s.as_bytes()));
        let dialect = arena.span(crate::PLANE_KEY.as_bytes());
        let body = arena.span(&projected);
        let rewritten = rewritten.as_deref().map(|r| arena.span(r));
        let turns: Vec<_> = turns
            .iter()
            .map(|(role, text)| (arena.span(role.as_bytes()), arena.span(text.as_bytes())))
            .collect();
        for (role, text) in turns {
            messages.push_turn(&arena, role, text);
        }
        let short = !arena.fits() || !messages.fits();
        let (written, needed) = arena.settle(short);
        let (turns_written, turns_needed) = messages.settle(short);
        out.set(|o| &o.arena_written, written as u64);
        out.set(|o| &o.arena_needed, needed as u64);
        out.set(|o| &o.messages_needed, turns_needed as u32);
        if short {
            return Outcome::Failed;
        }
        out.host_str(|o| &o.view.pool, &arena, pool);
        if let Some(session) = session {
            out.host_octets(|o| &o.view.session, &arena, session);
        }
        out.host_str(|o| &o.view.ingress_dialect, &arena, dialect);
        out.host_list(|o| &o.view.signals, |o| &o.view.signals_len, &signals);
        out.set(|o| &o.view.message_count, shape.turn_count as u64);
        out.set(|o| &o.view.total_chars, shape.text_chars as u64);
        let mut flags = 0;
        if shape.has_tools {
            flags |= busbar_contract::abi::hook::REQUEST_HAS_TOOLS;
        }
        out.set(|o| &o.view.flags, flags);
        out.set(|o| &o.body, body);
        out.host_rows(|o| &o.prompt.messages, &messages);
        out.set(|o| &o.prompt.messages_len, turns_written);
        out.set(|o| &o.prompt.message_count, turns_written as u64);
        if let Some(rewritten) = rewritten {
            out.set(|o| &o.rewritten, rewritten);
        }
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

/// THE SUBSCRIPTIONS HELD AS SESSIONS ON THE HTTP CARRIER (Q-L3B-K6-HTTP (a)): a child of the door,
/// so it reads the door's own unit and answer state.
#[path = "door_listen.rs"]
mod door_listen;
/// THE STDIO SERVERS' LEG (Q-L3B-STDIO-UPSTREAM (A)): a child of the door, so it reads the door's own
/// unit and relay state.
#[path = "door_program.rs"]
mod door_program;
/// THE TASKS EXTENSION'S UNITS (ARCHITECT round 5 Q-L3B-TASKS (b) → (A)): a child of the door, so it
/// reads the door's own unit and answer state.
#[path = "door_tasks.rs"]
mod door_tasks;
