// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The authority, the interner and the one implementor of the kernel's `Units` trait.
//!
//! Three things the design draws have, until now, existed in the tree only as test doubles: an
//! implementor of `busbar_kernel::teller::Units`, an implementor of
//! `busbar_kernel::inflight::ArrivalDoor`, and a live `busbar_contract::Registration`. This file is
//! where the production ones live, and it is the only place in the workspace entitled to name all
//! fourteen units at once.
//!
//! ## Fourteen units, twelve methods
//!
//! The mapping is not one-to-one and never was. Two of the twelve methods reach more than one unit,
//! three reach none, and five units are never reached through `Units` at all:
//!
//! | `Units` method | unit(s) reached |
//! |---|---|
//! | `arrival` | none — the kernel's own gate over the configured budgets |
//! | `decode` | the claimed plane, not a unit |
//! | `authenticate` | the auth unit |
//! | `verify` | the trust unit, reading the breaker unit's view |
//! | `approve` | the scope unit |
//! | `admit` | the admission unit, priced by the cost unit |
//! | `route` | the egress unit, over the breaker, egress-auth and transport-key units |
//! | `meter` | the usage unit |
//! | `audit` | the audit unit, then the ledger unit |
//! | `audit_refused` | the audit unit — the door a unit that never passed Admit leaves through |
//! | `encode` | the claimed plane, not a unit |
//! | `evidence` | the usage and cost units, read once by the exit path |
//!
//! Reached elsewhere, and bound by the root rather than by a step: the WAL unit sits under the
//! ledger on the durability path; the verbs unit is a destination at Route, holding the admin
//! token; the transport-key unit runs at listen, dial and upgrade, outside the loop entirely; the
//! egress-auth unit is called from inside Route by the egress unit; and the breaker unit is
//! consulted at Verify and recorded at Route without ever being a step of its own.
//!
//! ## Why every method is unimplemented here
//!
//! This file is the skeleton: the shape is what has to be right first, because it is what every
//! later step binds against, and a shape that compiles against the real trait is a claim that can
//! be checked. The bodies arrive one plane at a time — admin, then the other three, then the
//! reference plane last — and nothing calls into this type until the plane whose step it runs has
//! been switched over.

use std::sync::Mutex;

use busbar_caps::{
    Admit, AdmitToken, Approve, Arrival, Audit, Authenticate, Decision, Decode, Encode, Hold,
    Meter, Outcome, PrincipalId, Refusal, Route, UnitToken, UsageToken, VerifiedDestination,
    Verify,
};
use busbar_kernel::inflight::ArrivalDoor;
use busbar_kernel::teller::{AccrualMeter, Evidence, UnitCtx, Units};
use busbar_unit_admission::{Door, InMemoryCells};
use busbar_unit_auth::{Auth, AuthChain};
use busbar_unit_breaker::BreakerUnit;
use busbar_unit_egress::EgressUnit;
use busbar_unit_trust::Trust;

/// Take the kernel's seal. Boot only, once per process.
///
/// The seal is the node's whole authority: every token a unit is ever lent is minted from it, for
/// the length of one call, and there is no second way to obtain one. Calling this twice would give
/// a process two authorities, which is why the composition root calls it exactly once and hands the
/// kernel around by reference from there.
#[must_use]
pub fn new_kernel() -> busbar_kernel::teller::Kernel {
    busbar_kernel::teller::Kernel::new()
}

/// Open the vocabulary interner.
///
/// Config-derived open-vocabulary keys — a lane, a pool, a model, a provider host, a dialect name,
/// a loaded plugin's key — are leaked into `&'static str` exactly once, here, at registration. The
/// resulting allocation is fixed and countable; a leak per connection or per dial is a defect
/// rather than a variant of the rule. [`crate::root::vocabulary`] is what enforces the "exactly
/// once, and never after boot" half.
#[must_use]
pub fn new_registration() -> busbar_contract::Registration {
    busbar_contract::Registration::new()
}

/// The admission unit, standing at the in-flight table's arrival door.
///
/// The kernel's in-flight table takes a `&dyn ArrivalDoor` and, until this existed, the only
/// implementor in the tree was a test double — which made "a hold cannot exist without the unit's
/// own token" true everywhere except in the one place that mattered. The binding is a delegation
/// and nothing else: the admission unit already exports the constructor, and a root that computed
/// anything here would be a root deciding what a unit is for.
#[derive(Debug, Default, Clone, Copy)]
pub struct AdmissionDoor;

impl ArrivalDoor for AdmissionDoor {
    fn arrival_hold(&self, principal: PrincipalId, token: &AdmitToken<Admit>) -> Hold {
        busbar_unit_admission::arrival_hold(principal, token)
    }
}

/// The long-lived objects the root owns, behind the one trait the loop reaches a unit through.
///
/// Only the units with state across requests are fields. The other eight are facades — free
/// functions or unit structs the step calls with the facts it was handed — and holding an empty
/// value for each of them would be furniture rather than structure.
///
/// The cell store is deliberately the reference in-memory one at this step. Production wants
/// sharded, canonical-order locking rather than the single lock this takes, and the admission unit
/// says so in its own documentation; the store is a type parameter on the door precisely so
/// swapping it is a composition change and not a unit change.
pub struct ProductionUnits {
    /// The admission unit's long-lived door. Its ledger cells are hydrated once, at boot, and are
    /// never re-read on the request path.
    pub door: Door<InMemoryCells>,
    /// The egress unit's rotation memory. The walk itself is a per-request value.
    pub egress: EgressUnit,
    /// Every `(pool, destination)` breaker cell and every destination's lifetime budget, behind the
    /// port the egress unit reaches it through.
    ///
    /// There is exactly one of these and it is reached only here. Two breaker units would be two
    /// sets of cells: a trip recorded through one would be invisible to the other, and a lane the
    /// walk had benched would still read as ready at Verify.
    pub breaker: crate::root::adapters::BreakerAdapter,
    /// The authentication chain, resolved from configuration at boot.
    pub auth: Auth,
    /// The trust unit. Stateless: it is handed the pool view and the kind facts per call.
    pub trust: Trust,
    /// The arrival door, bound to the admission unit and to nothing else.
    pub arrival_door: AdmissionDoor,
    /// The journal, the ledger and the audit unit's two chains.
    ///
    /// Behind one lock because all four are append-only and a unit's settlement touches more than
    /// one of them: the record is sealed, the ledger moves and the journal takes the batch, and a
    /// reader that saw two of the three would be reading a half-settled unit.
    pub durability: Mutex<crate::root::durability::Durability>,
    /// What the usage unit meters against — built from the configured rate cards, never from the
    /// unit's own default, because an empty lane expansion disputes every pooled posting.
    pub meter_policy: crate::root::policy::MeterPolicyHandle,
    /// What the scope unit reads at Approve. Silence is a refusal.
    pub scope_policy: crate::root::policy::ScopePolicy,
}

impl ProductionUnits {
    /// Assemble the units the loop reaches, over what the root already built.
    ///
    /// Everything expensive — opening a journal, hydrating the ledger cells, resolving the auth
    /// chain, reading the rate cards — has happened by the time this is called. This is the
    /// assembly, not the work. Every argument is a value configuration decided, which is the shape
    /// that makes it impossible to construct these units and forget one.
    #[must_use]
    pub fn new(
        auth_chain: AuthChain,
        durability: crate::root::durability::Durability,
        breaker_policy: crate::root::adapters::BreakerPolicy,
        meter_policy: crate::root::policy::MeterPolicyHandle,
        scope_policy: crate::root::policy::ScopePolicy,
    ) -> Self {
        ProductionUnits {
            door: Door::new(InMemoryCells::new()),
            breaker: crate::root::adapters::BreakerAdapter::new(BreakerUnit::new(), breaker_policy),
            egress: EgressUnit::new(),
            auth: Auth::new(auth_chain),
            trust: Trust,
            arrival_door: AdmissionDoor,
            durability: Mutex::new(durability),
            meter_policy,
            scope_policy,
        }
    }
}

impl Units for ProductionUnits {
    fn arrival(&self, _token: &UnitToken<Arrival>, _ctx: &UnitCtx) -> Decision<Arrival> {
        todo!("the kernel's arrival gate: size, rate, source, cursor and spill budgets from config")
    }

    fn decode(&self, _token: &UnitToken<Decode>, _ctx: &UnitCtx) -> Decision<Decode> {
        todo!("the claimed plane's decode_ingress")
    }

    fn authenticate(
        &self,
        _token: &UnitToken<Authenticate>,
        _ctx: &UnitCtx,
    ) -> Decision<Authenticate> {
        todo!("the auth unit's resolve, over the cache, the key verifier and the revocation view")
    }

    fn verify(
        &self,
        _token: &UnitToken<Verify>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
    ) -> Decision<Verify> {
        todo!("the trust unit's verify, reading the breaker unit through the lane view")
    }

    fn approve(
        &self,
        _token: &UnitToken<Approve>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> Decision<Approve> {
        todo!("the scope unit's required_scope, then the hook seats the root composes around it")
    }

    fn admit(
        &self,
        _token: &UnitToken<Admit>,
        _admit: &AdmitToken<Admit>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> Decision<Admit> {
        todo!("the admission unit, bound to the pinned arrival epoch and priced by the cost unit")
    }

    fn route(
        &self,
        _token: &UnitToken<Route>,
        _ctx: &UnitCtx,
        _meter: &AccrualMeter,
    ) -> Decision<Route> {
        todo!("the egress unit's walk, over the twenty-two borrowed views of a route request")
    }

    fn meter(
        &self,
        _token: &UnitToken<Meter>,
        _usage: &UsageToken,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
    ) -> Decision<Meter> {
        todo!("the usage unit's meter, against the policy built from the configured rate cards")
    }

    fn audit(
        &self,
        _token: &UnitToken<Audit>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> Decision<Audit> {
        todo!("the audit unit's record stream, then the ledger settle on the exit path")
    }

    fn audit_refused(
        &self,
        _token: &UnitToken<Audit>,
        _ctx: &UnitCtx,
        _refusal: &Refusal,
    ) -> Decision<Audit> {
        todo!("the second audit door: a unit that never passed Admit, and was charged nothing")
    }

    fn encode(
        &self,
        _token: &UnitToken<Encode>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> Decision<Encode> {
        todo!("the claimed plane's encode_response, encode_refusal or encode_end")
    }

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        todo!("what the usage and cost units reported, read once by the settlement table")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The point of the skeleton: the shape compiles against the real trait, and the real trait is
    /// the kernel's. A `ProductionUnits` that did not satisfy `Units` would be a plan, not a root.
    #[test]
    fn production_units_is_the_kernels_units_trait() {
        fn assert_units<U: Units>() {}
        assert_units::<ProductionUnits>();
    }

    /// The arrival door is the admission unit's, and a hold it opens reserves nothing — the point
    /// of the arrival hold is that even a refusal is an event with a cell of its own to settle.
    #[test]
    fn the_arrival_door_opens_a_hold_that_reserves_nothing() {
        let kernel = new_kernel();
        let door = AdmissionDoor;
        let hold = busbar_kernel::inflight::arrival_hold(&kernel, &door, PrincipalId::new("k-7"));
        assert_eq!(hold.reserved(), 0);
        assert_eq!(hold.principal(), &PrincipalId::new("k-7"));
    }

    /// The whole assembly, end to end: a kernel, a durability stack that opened nothing, the
    /// configured breaker ladders, the configured metering policy and a scope policy that permits
    /// only what it was told about — composed into the one type the loop reaches a unit through.
    ///
    /// Every argument is a value configuration decided. That is the shape that makes it impossible
    /// to build these units and forget one: there is no constructor that fills a policy in from a
    /// default, so a deployment that never read its rate cards does not compile.
    #[test]
    fn the_units_assemble_from_values_configuration_decided() {
        let durability = crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_unit_wal::NullShipper::new()),
            Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal cannot fail to open");

        let units = ProductionUnits::new(
            AuthChain::new(Vec::new(), false),
            durability,
            crate::root::adapters::BreakerPolicy::new(),
            crate::root::policy::build(&crate::root::policy::MeterPolicyConfig::default()),
            crate::root::policy::ScopePolicy::new(),
        );

        // The journal opened nothing, the ledger is dual-writing, and the scope policy permits
        // nothing until it is told to. All three are the safe end of a choice that had an unsafe
        // end, and all three are checkable here rather than at the first request.
        let durability = units.durability.lock().expect("durability lock");
        assert!(!durability.on_disk());
        assert!(durability.ledger.is_dual_writing());
        assert!(units.scope_policy.is_empty());
    }

    /// The interner is idempotent, which is what makes "leaked exactly once" a property of the
    /// type rather than of the caller's discipline.
    #[test]
    fn the_interner_leaks_a_repeated_key_once() {
        let mut registration = new_registration();
        let first = registration.key("lane-a");
        let second = registration.key("lane-a");
        assert!(std::ptr::eq(first, second));
        assert_eq!(registration.len(), 1);
    }
}
