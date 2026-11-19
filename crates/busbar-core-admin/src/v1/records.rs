// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `/records` WIRE SHAPE (ADMIN-API-1.6 §3.3, §3.4): one definition, which the node fills and
//! the generated document describes, so the two cannot drift.

use std::collections::BTreeMap;

use busbar_contract::caps::{ReasonCode, StepName};
use busbar_contract::plane::codes::{class_of, RefusalClass};
use serde::Serialize;

/// The `schema` every [`UnitRecord`] carries.
pub const UNIT_RECORD_SCHEMA: &str = "busbar.unit_record.v1";

/// Complete selected-attempt records; legacy items retain their v1 shape.
pub const UNIT_RECORD_SCHEMA_V2: &str = "busbar.unit_record.v2";

/// At most this many sealed records are scanned per request (V6): a filtered page may be short
/// or empty with a cursor that continues.
pub const RECORDS_SCAN_BOUND: u64 = 10_000;

/// `limit` when none is sent.
pub const RECORDS_LIMIT_DEFAULT: usize = 200;

/// The largest `limit` served.
pub const RECORDS_LIMIT_MAX: usize = 1_000;

/// The longest `wait`, in seconds.
pub const RECORDS_WAIT_MAX_SECS: u64 = 30;

/// `GET /records`: one page of the node's per-unit records, oldest first.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct RecordsPage {
    /// Which deployment, node and process answered.
    pub source: RecordsSource,
    /// The records, oldest first.
    pub items: Vec<UnitRecord>,
    /// Always a string: the position after the last record scanned. Send it back to continue.
    pub next_cursor: String,
    /// True when the page reached the node's newest sealed record.
    pub complete: bool,
}

/// Who answered a `/records` read. Records are per node: the `core/process` view `nodes` lists every node.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct RecordsSource {
    /// `dep_` + 32 hex; null before the node has published its identity.
    pub deployment_id: Option<String>,
    /// `node_` + 16 hex: the node whose chain this is.
    pub node_id: String,
    /// The 32-hex boot nonce of the answering process; null when it has none.
    pub process_boot_nonce: Option<String>,
}

/// One unit, as its sealed audit record says (ADMIN-API-1.6 §3.4). Every field is derived from
/// sealed bytes; nothing sealed before recipe `v7` is resolved from current configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct UnitRecord {
    /// `busbar.unit_record.v1`.
    pub schema: &'static str,
    /// The record's chain position, as decimal text.
    pub seq: String,
    /// The node-qualified unit id, `node_<16 hex>.<32 hex>.<unit key>`: the data plane's
    /// `X-Request-Id` and the join key to content. Null before `v7`, or with no boot nonce.
    pub unit: Option<String>,
    /// The unit key, per node and per boot: not a join id.
    pub unit_key: String,
    /// The arrival, in milliseconds since the epoch.
    pub arrived_at_ms: u64,
    /// `ms` for `v7` records; `s` before, whose arrival is the sealed second times 1000.
    pub arrived_at_precision: &'static str,
    /// The operation class.
    pub op_class: String,
    /// `plane` when the instance is known to this node, else null.
    pub category: Option<&'static str>,
    /// The instance's kind id, derived at read; null when the instance no longer exists.
    pub kind: Option<&'static str>,
    /// The instance, derived from the sealed destination.
    pub instance: Option<String>,
    /// The sealed destination lane.
    pub target: Option<String>,
    /// The model, derived from the sealed destination.
    pub model: Option<String>,
    /// Sealed (`v7`); null before.
    pub provider: Option<String>,
    /// Sealed (`v7`); null before.
    pub pool: Option<String>,
    /// Sealed (`v7`); null before.
    pub group: Option<String>,
    /// The `/keys` id of the caller; null for an arrival that never resolved.
    pub key: Option<String>,
    /// The end user, when `records.user` is on (null until the plane projects one).
    pub user: Option<String>,
    /// The allow-listed request labels (empty unless `records.labels` names some).
    pub labels: BTreeMap<String, String>,
    /// The instance's projected facts (empty until the kind declares `record_attributes`).
    pub attributes: BTreeMap<String, String>,
    /// `completed`, `refused`, `failed`, `aborted` or `timed_out`.
    pub outcome: &'static str,
    /// `complete`, `turn_complete`, `partial` or `error`.
    pub finish: &'static str,
    /// Why the unit did not complete; null when it did.
    pub reason: Option<UnitReason>,
    /// The answer's HTTP status; null when none was sealed.
    pub status: Option<u16>,
    /// The unit's timing (`v7`); null before.
    pub timing: Option<UnitTiming>,
    /// The first four attempts.
    pub attempts: Vec<UnitAttempt>,
    /// Every attempt, including those beyond the four.
    pub attempts_total: u32,
    /// What the unit used.
    pub usage: UnitUsage,
    /// Complete signed partition evidence, present only on v2 items.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing: Option<UnitBilling>,
    /// The unit's spend in micro-units (1e-6 of the cost unit), priced at read by the rule
    /// `/usage` uses, as exact decimal text (at most three fractional places): the exact sum of
    /// the unit's lines and fee, truncated once to whole nano-units. Null when unpriced (a class
    /// the card holds unpriced, or no card entry found).
    pub spend_micros: Option<String>,
    /// The sealed rate-card entry key (hex), or a legacy recipe's ordinal.
    pub rate_card_version: Option<String>,
    /// The entry that priced the answer, after amendments.
    pub priced_by: Option<String>,
    /// Whether `spend_micros` is served.
    pub priced: bool,
    /// `{deployment_id}/{YYYY-MM-DD}/{unit}`, when content export is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_ref: Option<String>,
    /// The record's digest: joins `/audit/range`.
    pub hash: String,
}

/// Why a unit did not complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct UnitReason {
    /// The step it ended at, when it ended at one.
    pub stage: Option<&'static str>,
    /// The reason code (`components.x-busbar-unit-reasons`).
    pub code: &'static str,
    /// `client`, `policy`, `upstream` or `engine`.
    pub class: &'static str,
    /// The hook that vetoed the unit, by the key the deployment configured it under. Absent when
    /// a hook did not refuse it (and on a record sealed before the hook rows carried their
    /// decision).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook: Option<String>,
}

/// A unit's timing, in microseconds; a member is null when it was not measured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct UnitTiming {
    /// To the first body write.
    pub ttft_us: Option<u64>,
    /// Until the last frame was handed over.
    pub total_us: Option<u64>,
    /// Queueing, under hot-path tracing only.
    pub queue_us: Option<u64>,
}

/// One attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct UnitAttempt {
    /// Its position, from 1.
    pub n: u32,
    /// The lane it was made at.
    pub target: String,
    /// `ok`, `failover`, `failed` or `cancelled`.
    pub outcome: &'static str,
    /// Why it did not answer; null when it did.
    pub reason: Option<String>,
    /// Its duration in microseconds, under hot-path tracing only.
    pub us: Option<u64>,
}

/// What a unit used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct UnitUsage {
    /// Counts by class, as exact decimal text.
    pub classes: BTreeMap<String, String>,
    /// How many request fees were charged.
    pub fee_count: u32,
}

/// Exact captured monetary era; an absent entry remains unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct BillingEra {
    /// Original entry effective date in milliseconds.
    pub effective_from: u64,
    /// Original 24-hex entry identity.
    pub entry_id: Option<String>,
}

/// One selected source, including a known zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct BillingQuantity {
    /// Exact decimal quantity.
    pub count: String,
    /// `reported`, `floor` or `estimated`.
    pub source: &'static str,
}

/// All signed raw and derived quantities for one declared class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct BillingClass {
    /// Reported quantity, null when unknown.
    pub reported: Option<String>,
    /// Observed lower bound, null when unknown.
    pub floor: Option<String>,
    /// Estimate, null when unknown.
    pub estimated: Option<String>,
    /// Producer's source selection.
    pub selected: Option<BillingQuantity>,
    /// Producer's eligible bill; never an estimate.
    pub billed: Option<BillingQuantity>,
    /// Independent physical high-water quantity.
    pub rate_high_water: String,
}

/// One retained session or preparation; diagnostic attempts never truncate this list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct BillingPartition {
    /// `session` or `attempt`.
    pub scope: &'static str,
    /// Nonzero preparation ordinal for an attempt.
    pub preparation: Option<u32>,
    /// Actual committed dispatch ordinal, if any.
    pub dispatch: Option<u32>,
    /// `session`, `model` or `registration`.
    pub kind: &'static str,
    /// Original configured instance.
    pub instance: String,
    /// Qualified logical lane.
    pub lane: String,
    /// Actual configured provider.
    pub provider: Option<String>,
    /// Actual selected pool.
    pub selected_pool: Option<String>,
    /// Canonical resource identity.
    pub resource: Option<String>,
    /// `prepared`, `committed`, `no_send`, or null for session.
    pub transport: Option<&'static str>,
    /// `complete`, `partial` or `unknown` source coverage.
    pub finality: &'static str,
    /// All declared classes, including unknown and zero.
    pub classes: BTreeMap<String, BillingClass>,
    /// Historical entry used for this component, null if unpriced.
    pub priced_by: Option<String>,
}

/// The single logical fee, whose ownership is independent of the delivered target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct BillingFee {
    /// `not_owner`, `charged`, `refunded` or `unknown`.
    pub state: &'static str,
    /// Original fee lane; null means the flat fee base.
    pub lane: Option<String>,
    /// Original fee era.
    pub era: BillingEra,
    /// Historical entry used for the fee, null if no fee was priced.
    pub priced_by: Option<String>,
}

/// Full selected billing provenance from one signed immutable unit revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct UnitBilling {
    /// Extension version, currently 1.
    pub version: u32,
    /// Accepted revision as exact decimal text.
    pub revision: String,
    /// Original request pool.
    pub request_pool: String,
    /// Original routing generation as exact decimal text.
    pub routing_generation: String,
    /// Original usage era.
    pub era: BillingEra,
    /// Original host instance, present even with no session quantities.
    pub session_instance: String,
    /// Original qualified host lane.
    pub session_lane: String,
    /// Actual original host provider, if any.
    pub session_provider: Option<String>,
    /// `none`, `host_origin` or `delivered_preparation`.
    pub logical_request: &'static str,
    /// Logical request's delivered preparation, if any.
    pub logical_preparation: Option<u32>,
    /// Original logical fee.
    pub fee: BillingFee,
    /// `end`, `failed`, `cancel` or `recovered_running`.
    pub disposition: &'static str,
    /// Captured cancellation reason, if any.
    pub reason: Option<String>,
    /// Captured far-end response evidence.
    pub far_end_answered: bool,
    /// Captured caller write evidence.
    pub caller_bytes_committed: bool,
    /// Actual delivered preparation ordinal, if any.
    pub final_target: Option<u32>,
    /// Number of committed dispatches, distinct from diagnostic attempts_total.
    pub dispatched: u32,
    /// Complete ordered partitions.
    pub partitions: Vec<BillingPartition>,
}

/// THE CLASS OF A REASON as a record names it: `client`, `policy`, `upstream` or `engine`, from
/// the one reason table's class (`abi::plane::class_of`). No new capture.
#[must_use]
pub fn unit_reason_class(reason: ReasonCode) -> &'static str {
    match class_of(reason) {
        RefusalClass::Unreadable
        | RefusalClass::Rejected
        | RefusalClass::TooLarge
        | RefusalClass::NotFound => "client",
        RefusalClass::Unauthenticated
        | RefusalClass::Forbidden
        | RefusalClass::Throttled
        | RefusalClass::QuotaExhausted => "policy",
        RefusalClass::Unreachable | RefusalClass::Timeout => "upstream",
        RefusalClass::Busy
        | RefusalClass::Unavailable
        | RefusalClass::PlaneFault
        | RefusalClass::NodeFault => "engine",
    }
}

/// `components.x-busbar-unit-reasons` (ADMIN-API-1.6 §3.4, SF-1): every refusal and failure
/// `ReasonCode` with its class and the steps it can end a unit at, plus the one code a record
/// names without a `ReasonCode` (`timed_out`). A superseded unit names `superseded`.
#[must_use]
pub fn unit_reasons() -> BTreeMap<&'static str, (&'static str, Vec<&'static str>)> {
    let steps: Vec<&'static str> = StepName::ALL.iter().map(|s| s.as_str()).collect();
    let mut out: BTreeMap<&'static str, (&'static str, Vec<&'static str>)> = ReasonCode::ALL
        .iter()
        .map(|reason| (reason.as_str(), (unit_reason_class(*reason), steps.clone())))
        .collect();
    out.insert(TIMED_OUT, ("upstream", steps));
    out
}

/// The code of a unit that timed out.
pub const TIMED_OUT: &str = "timed_out";
