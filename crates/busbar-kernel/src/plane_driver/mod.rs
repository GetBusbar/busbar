// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod answer;
mod cancel;
pub mod dispatch;
pub mod door;
mod far_end;
pub(crate) mod hooks;
pub mod host;
pub mod image_identity;
mod money;
pub mod native_hook_bindings;
pub mod plane_judge;
pub mod port;
pub mod port_admin;
pub mod port_admission;
pub mod port_auth;
pub mod port_billing;
pub mod port_carrier;
pub mod port_channels;
pub mod port_charge;
pub mod port_duplex;
pub mod port_egress;
pub mod port_fetch;
pub mod port_hooks;
pub mod port_intents;
pub mod port_money;
pub mod port_observations;
pub mod port_probes;
pub mod port_routes;
pub mod port_serve;
pub mod port_services;
pub mod port_session;
pub mod port_upstream;
pub mod port_work;
pub mod provider_catalog;
pub mod request_admission;
pub use money::native_attempt::NativeRequestMoney;
pub(crate) use money::native_attempt::PreparedRateAttempt;
pub(crate) use money::native_attempt::{NativeAttempt, NativeAttemptError, NativeCommitError};
pub(crate) use money::observation_budget_id;
pub use money::SelectedTerminalReceipt;
pub use money::{AdmissionRollback, NativeAdmissionError};
pub(crate) mod needs;
pub mod registry;
mod route;
pub mod route_identity;
pub mod route_input;
pub mod route_tables;
pub mod slots;
mod timing;
pub mod usage;

use std::sync::Arc;

use busbar_contract::abi::plane::UnitCount;
use busbar_contract::caps::ReasonCode;
use busbar_contract::plane::codes::{class_of, RefusalClass};

pub use answer::PlaneAnswer;
pub use cancel::{CancelBill, Checkpoint, MoneySeam, OpenUnitEvidence};
#[cfg(test)]
pub(crate) use far_end::tests::lent_on_egress;
pub use far_end::{
    fixed_breaker, AuthBinding, BreakerSource, ConfiguredAuthBinding, Egress, EgressFarEnd,
    MemberFacts, MemberRoute, MemberSignals, MemberStanding, ResponseKeep, Ride, UnitRoute,
    DEFAULT_ERROR_BODY_MAX,
};
pub use hooks::{
    CallerKey, CandidateFacts, Candidates, Constraint, HookJournal, HookRead, HooksRan, Restrict,
};
pub use host::{
    engine_host, engine_host_from_handle, live_standing, policy_standing, standing_over,
    EngineHost, EngineHostImpl,
};
pub use money::{
    EndPost, FeeRefund, MeasurementRequestGuard, MeasurementRequestState, ObservationPolicy,
    ObservationRuntimeError, ParentMoney, PlaneMoney, ReservedRequestLineage,
    ReturnedTicketReservation, SpentTicketReservation, TicketAdoption, TicketReservation, UnitEnd,
    UnitMoney, UsageFold, UsageView,
};
pub use needs::{resolve_member_needs, MemberAuth, NeedRefusal};
pub use route::{CallerEnd, FarEnd, FarPiece, OutboundRequest, Pick, RoutedScope, SessionInput};

use crate::auth::CallerRefKey;

pub type CallerRefs = Arc<std::sync::RwLock<Option<Arc<CallerRefKey>>>>;

pub fn refusal_status(reason: ReasonCode) -> u32 {
    class_status(class_of(reason))
}

pub const fn class_status(class: RefusalClass) -> u32 {
    match class {
        RefusalClass::Unreadable | RefusalClass::Rejected => 400,
        RefusalClass::Unauthenticated => 401,
        RefusalClass::Forbidden => 403,
        RefusalClass::NotFound => 404,
        RefusalClass::TooLarge => 413,
        RefusalClass::Throttled | RefusalClass::Busy | RefusalClass::QuotaExhausted => 429,
        RefusalClass::PlaneFault => 502,
        RefusalClass::Timeout => 504,
        RefusalClass::Unreachable | RefusalClass::Unavailable | RefusalClass::NodeFault => 503,
    }
}

pub trait AuditSink: Send + Sync {
    fn record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str);
}

/// THE KERNEL'S OWN AUDIT CHAIN (`audit::journal`, read by `GET /audit`): the sink a unit's audit
/// row is written to unless another is named. The same chokepoint a plane's admin-audit emit
/// reached before it was served through its door.
#[derive(Debug, Clone, Copy, Default)]
pub struct CoreAudit;

impl AuditSink for CoreAudit {
    fn record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str) {
        crate::audit::auditlog::emit_admin_hostless_now(action, resource, outcome, principal);
    }
}

pub type HeadFields = Vec<(Vec<u8>, Vec<u8>)>;

/// What arrived: the claim it matched and the caller's request, as the kernel keeps it.
#[derive(Debug, Clone)]
pub struct Arrival {
    /// Index into the plane's snapshot claims.
    pub claim: u32,
    /// The request method.
    pub method: Vec<u8>,
    /// The request target.
    pub target: Vec<u8>,
    /// The head fields.
    pub fields: HeadFields,
    /// The caller's body, kept for every attempt.
    pub body: bytes::Bytes,
    /// IF §12.23: the line-carrier id (`PlaneReq.carrier`): non-zero exactly on a line read by `serve_lines`, 0 on
    /// every other arrival. Only the host line carrier sets it; no client field can.
    pub carrier: u64,
}

/// What `arrive` said.
#[derive(Debug, Clone)]
pub struct Decoded {
    /// Index into the plane's operation classes.
    pub op_class: u32,
    /// `PRINCIPAL_*`.
    pub principal_need: u32,
    /// Index into the plane's dialects.
    pub dialect: u32,
    /// The expected units (the admission estimate).
    pub expected: Vec<UnitCount>,
    /// The entry it routes over: the name inside the plane's own section, opaque
    /// bytes the kernel never parses; `None` = it named none.
    pub pool: Option<Vec<u8>>,
    /// What [`Decoded::pool`] names: `ROUTE_POOL` or `ROUTE_DIRECT`, or how the
    /// unit routes with no entry named (`ROUTE_LOCAL`, `ROUTE_SCOPE`, `ROUTE_SCOPE_LOCAL`).
    pub route: u8,
    /// The `ROUTE_*` flag bits its `arrive` stated (`ROUTE_ONCE`, `ROUTE_SESSION`,
    /// `ROUTE_STREAM`).
    pub route_flags: u8,
    /// The trust facts its `arrive` stated (a counterparty, and an item at a digest), which
    /// the kernel's Approve judges; `None` = the unit rests on no counterparty.
    pub trust: Option<busbar_contract::plane_calls::ArrivedTrust>,
    /// The sticky-routing key its `arrive` stated, opaque; `None` = none.
    pub affinity: Option<Vec<u8>>,
}

#[must_use]
pub fn sticky_hash(key: &[u8]) -> u64 {
    crate::store::key_hash_bytes(key)
}

/// A refusal or failure the plane rendered, for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The status number.
    pub status: u32,
    /// The head fields.
    pub fields: HeadFields,
    /// The body.
    pub body: Vec<u8>,
}
