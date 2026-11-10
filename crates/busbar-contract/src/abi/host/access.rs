// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Closed kind ceilings for host operations. These never replace core-issued grants.
//!
//! The same rows generate SDK method eligibility and runtime dispatch admission.
//! Unknown operations are denied. A plugin cannot implement a permission for its own
//! marker: `KindMarker` is sealed, and the existing markers are foreign types.

//! The supported view retains its kind even when reconstructed through `Host::services`.
//! ```
//! use busbar_contract::{abi::{sdk::{conn::Host, services::Services}, mechanism::ticket::{Ticket, CompletionHandle}}, plugin::markers::{PlaneKind, TransportKind}};
//! fn plane(host: &Host<PlaneKind>) {
//!     let services: Option<Services<PlaneKind>> = host.services();
//!     if let Some(services) = services {
//!         let _ = services.records_get(CompletionHandle::ZERO, "declared", b"key", &mut []);
//!     }
//! }
//! fn transport(host: &Host<TransportKind>) { let _ = host.io(Ticket::NONE); }
//! ```
//!
//! A Store cannot obtain records through the retained host view.
//! ```compile_fail,E0277
//! use busbar_contract::{abi::{sdk::conn::Host, mechanism::ticket::CompletionHandle}, plugin::markers::StoreKind};
//! fn store(host: &Host<StoreKind>) {
//!     let _ = host.services().unwrap().records_get(CompletionHandle::ZERO, "declared", b"key", &mut []);
//! }
//! ```
//!
//! An Auth cannot acquire the transport I/O facade.
//! ```compile_fail,E0277
//! use busbar_contract::{abi::{sdk::conn::Host, mechanism::ticket::Ticket}, plugin::markers::AuthKind};
//! fn auth(host: &Host<AuthKind>) { let _ = host.io(Ticket::NONE); }
//! ```
//!
//! A Secret cannot turn its proven lifecycle loan into a Plane service view.
//! ```compile_fail,E0308
//! use busbar_contract::{abi::sdk::{lent::KindHostLoan, services::Services}, plugin::markers::{SecretKind, PlaneKind}};
//! fn secret(loan: KindHostLoan<'_, SecretKind>) { let _ = Services::<PlaneKind>::of(loan); }
//! ```
//!
//! A plain host loan does not prove the current invocation's kind.
//! ```compile_fail,E0308
//! use busbar_contract::{abi::sdk::{lent::HostLoan, conn::Host}, plugin::markers::PlaneKind};
//! fn loan(loan: HostLoan<'_>) { let _ = Host::<PlaneKind>::of(loan); }
//! ```
//!
//! Raw reconstruction is unavailable in the shipping SDK.
//! ```compile_fail,E0624
//! use busbar_contract::{abi::{sdk::conn::Host, mechanism::ticket::HostTables}, plugin::markers::PlaneKind};
//! fn raw(tables: &HostTables) { let _ = unsafe { Host::<PlaneKind>::from_raw(tables) }; }
//! ```
//!
//! A plugin cannot grant itself an omitted permission.
//! ```compile_fail,E0117
//! use busbar_contract::{abi::host::{access::Permitted, service::op}, plugin::markers::StoreKind};
//! impl Permitted<{op::RECORDS_GET}> for StoreKind {}
//! ```
//!
//! Custom tables cannot supply their own kind checks.
//! ```compile_fail,E0277
//! use busbar_contract::{abi::{sdk::door::{KindOps, Lifecycle}, mechanism::KindCode}, plugin::markers::SecretKind};
//! #[derive(Clone, Copy)] struct Forged;
//! unsafe impl KindOps for Forged {
//!     type Marker = SecretKind;
//!     type Lifecycle = Lifecycle;
//!     const KIND: KindCode = KindCode::Secret;
//! }
//! ```

//! A trampoline cannot use one kind's input/output table under another kind's authority.
//! ```compile_fail,E0277
//! use busbar_contract::abi::{auth, secret, sdk::{door::{kind_op, Entry}, capture::CaptureHome}};
//! use busbar_contract::plugin::markers::AuthKind;
//! fn swapped<S, H>() where S: Entry<Kind = AuthKind, In = secret::ResolveIn, Out = secret::ResolveOut>, H: CaptureHome {
//!     let _ = kind_op::<auth::Ops, secret::Ops, S, H, {secret::slot::RESOLVE}>();
//! }
//! ```

//! Outbound custody is available only to planes.
//! ```compile_fail,E0277
//! use busbar_contract::{abi::{sdk::conn::Host, sdk::services::OutboundScope, mechanism::ticket::CompletionHandle}, plugin::markers::TransportKind};
//! fn transport(host: &Host<TransportKind>, scope: OutboundScope<'_>) {
//!     let _ = host.services().unwrap().outbound_bind(CompletionHandle::ZERO, scope, 1);
//! }
//! ```

use super::service::op;
use crate::abi::mechanism::KindCode;
use crate::plugin::{markers::*, KindMarker};

/// Compile-time permission to name a host service on a kind's SDK client.
pub trait Permitted<const OP: u32>: KindMarker {}

/// Additional authority the host must verify after the kind ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    Lifecycle,
    Need,
    Records,
    Signing,
    Unit,
    Work,
    Trust,
    Credential,
    Export,
    Framing,
}

/// Whether a service can be used during cleanup without originating new work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Lifecycle,
    Active,
    Drain,
}

/// A complete operation policy, shared by the SDK and loader.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub op: u32,
    pub name: &'static str,
    pub kinds: u8,
    pub authority: Authority,
    pub phase: Phase,
}

impl Policy {
    pub const fn admits(self, kind: KindCode) -> bool {
        self.kinds & (1 << (kind as u8 - 1)) != 0
    }
}

macro_rules! permission {
    ($op:ident; all) => { impl<K: KindMarker> Permitted<{ op::$op }> for K {} };
    ($op:ident; $($kind:ident),+) => { $(impl Permitted<{ op::$op }> for $kind {})+ };
}
macro_rules! kind_mask {
    (all) => { 0x7f };
    ($($kind:ident),+) => { 0 $(| (1 << ($kind::CODE as u8 - 1)))+ };
}
macro_rules! services {
    ($($op:ident: $authority:ident, $phase:ident => [$($kind:ident),+];)+) => {
        $(permission!($op; $($kind),+);)+
        pub const SERVICES: &[Policy] = &[$(Policy {
            op: op::$op, name: stringify!($op), kinds: kind_mask!($($kind),+),
            authority: Authority::$authority, phase: Phase::$phase,
        }),+];
    };
}

services! {
    CLOCK_NOW: Lifecycle, Lifecycle => [all];
    RECORDS_GET: Records, Active => [PlaneKind, AuthKind, HookKind];
    RECORDS_LIST: Records, Active => [PlaneKind, AuthKind, HookKind];
    RECORDS_CLAIM: Records, Active => [PlaneKind, AuthKind, HookKind];
    DEST_JUDGE: Need, Active => [all];
    SIGN: Signing, Active => [PlaneKind, AuthKind, TransportKind];
    UNIT_NEST: Unit, Active => [PlaneKind];
    WORK_OPEN: Work, Active => [PlaneKind];
    WORK_FIND: Work, Active => [PlaneKind];
    WORK_SETTLE: Work, Drain => [PlaneKind];
    WORK_RESUME: Work, Active => [PlaneKind];
    TRUST_SIGHT: Trust, Active => [PlaneKind];
    TRUST_DUE: Trust, Active => [PlaneKind];
    VERIFY_LOOKUP: Records, Active => [PlaneKind, AuthKind, HookKind];
    VERIFY_STORE: Records, Active => [PlaneKind, AuthKind, HookKind];
    ENTITLEMENT_CHECK: Unit, Active => [PlaneKind];
    CONTENT_SCAN: Unit, Active => [PlaneKind];
    HOOK_CALL: Unit, Active => [PlaneKind];
    RANDOM_FILL: Lifecycle, Lifecycle => [all];
    NEED_ADMIT: Need, Active => [all];
    TRUST_VERIFY: Trust, Active => [PlaneKind];
    RECORDS_SECRET: Credential, Active => [AuthKind];
    DISK_APPEND: Export, Active => [ExportKind];
    SNAPSHOT_READ: Export, Active => [ExportKind];
    TRUST_SIGHT_ITEM: Trust, Active => [PlaneKind];
    TRUST_SERVES: Trust, Active => [PlaneKind];
    TRUST_DECIDE: Trust, Active => [PlaneKind];
    TRUST_STATE: Trust, Active => [PlaneKind];
    SESSION_EMIT: Unit, Active => [PlaneKind];
    AUTH_CALL: Framing, Active => [TransportKind];
    UNIT_HAND_IN: Framing, Active => [TransportKind];
    UNIT_REFUSE: Framing, Drain => [TransportKind];
    TICKET_MINT: Unit, Active => [PlaneKind];
    TICKET_TAKE: Unit, Active => [PlaneKind];
    WORK_STATUS: Work, Drain => [PlaneKind];
    OUTBOUND_AUTHORIZE: Unit, Active => [PlaneKind];
}

/// Lookup is exhaustive over the advertised service table; unknown codes fail closed.
pub fn service(op: u32) -> Option<&'static Policy> {
    SERVICES.get(op as usize).filter(|row| row.op == op)
}

/// Raw host I/O is a transport capability, separate from the common connector.
pub trait RawIo: KindMarker {}
impl RawIo for TransportKind {}

// The table order and coverage are also part of the wire's append-only vocabulary.
const _: () = {
    assert!(SERVICES.len() == super::service::SERVICES as usize);
    let mut i = 0;
    while i < SERVICES.len() {
        assert!(SERVICES[i].op == i as u32);
        i += 1;
    }
};

/// Closed negotiated extension operations. Wire readers match exhaustively onto these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extension {
    InspectWork,
    InspectCarrierSessions,
    ObserveRecordChain,
    CommitRecords,
    AcknowledgeSettlement,
}

/// Read-only inspection is scoped to the plane owning work and carrier sessions.
pub trait Inspect: KindMarker {}
impl Inspect for PlaneKind {}

/// Extensions use the same kind, phase and authority rules as table callbacks.
pub const fn extension(op: Extension) -> Policy {
    let (name, authority, phase) = match op {
        Extension::InspectWork => ("inspection.work", Authority::Work, Phase::Active),
        Extension::InspectCarrierSessions => (
            "inspection.carrier_sessions",
            Authority::Unit,
            Phase::Active,
        ),
        Extension::ObserveRecordChain => {
            ("records.observe_chain", Authority::Records, Phase::Active)
        }
        Extension::CommitRecords => ("records.commit", Authority::Records, Phase::Active),
        Extension::AcknowledgeSettlement => {
            ("records.settlement_ack", Authority::Records, Phase::Drain)
        }
    };
    Policy {
        op: op as u32,
        name,
        kinds: kind_mask!(PlaneKind),
        authority,
        phase,
    }
}

macro_rules! table_policies {
    ($name:ident, $codes:path; $($op:ident: $authority:ident, $phase:ident => [$($kind:ident),+];)+) => {
        pub const $name: &[Policy] = &[$({
            use $codes as codes;
            Policy { op: codes::$op, name: stringify!($op), kinds: kind_mask!($($kind),+),
                     authority: Authority::$authority, phase: Phase::$phase }
        }),+];
    };
}
table_policies! { CONNECTORS, super::conn::connector::service;
    ESTABLISH: Need, Active => [all];
    REJECT_ENDPOINT: Need, Active => [all];
    SIDE_STREAM: Need, Active => [all];
    READ: Need, Drain => [all];
    WRITE: Need, Drain => [all];
    UPGRADE_SECURE: Need, Active => [all];
    FACTS: Need, Drain => [all];
    CHECKOUT: Need, Active => [all];
    CHECKIN: Need, Drain => [all];
    CLOSE: Need, Drain => [all];
    RANDOM: Lifecycle, Lifecycle => [all];
    IDENTITY: Lifecycle, Lifecycle => [all];
    READ_REPLY: Need, Drain => [all];
    WRITE_REQUEST: Need, Drain => [all];
}
table_policies! { IO, super::io::op;
    OPEN: Framing, Active => [TransportKind];
    LISTEN: Framing, Active => [TransportKind];
    ACCEPT: Framing, Active => [TransportKind];
    READ: Framing, Drain => [TransportKind];
    WRITE: Framing, Drain => [TransportKind];
    READY: Framing, Drain => [TransportKind];
    SHUT: Framing, Drain => [TransportKind];
    CLOSE: Framing, Drain => [TransportKind];
    SPAWN: Framing, Active => [TransportKind];
    ENDS: Framing, Drain => [TransportKind];
}

pub fn connector(op: u32) -> Option<&'static Policy> {
    CONNECTORS.get(op as usize).filter(|row| row.op == op)
}
pub fn io(op: u32) -> Option<&'static Policy> {
    IO.get(op as usize).filter(|row| row.op == op)
}
const _: () = {
    assert!(CONNECTORS.len() == super::conn::connector::SERVICES as usize);
    assert!(IO.len() == super::io::SLOTS as usize);
    let mut i = 0;
    while i < CONNECTORS.len() {
        assert!(CONNECTORS[i].op == i as u32);
        i += 1;
    }
    i = 0;
    while i < IO.len() {
        assert!(IO[i].op == i as u32);
        i += 1;
    }
};
