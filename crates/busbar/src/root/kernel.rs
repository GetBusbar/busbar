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
//! ## One plane at a time
//!
//! The bodies arrive one plane at a time — admin first, then the other three, then the reference
//! plane last — and the first of them has landed. Every method therefore begins with the same
//! question: is this unit one the admin bindings opened? If it is, the step runs against the units
//! that plane composes over. If it is not, the step REFUSES, naming the step it refused at.
//!
//! The refusal is deliberate and is not a placeholder. A unit that reached this type on a plane
//! this root does not yet drive was routed to the wrong loop, and there are only two honest answers
//! to that: end it saying so, or panic. Serving it half-composed — arriving it, admitting it, and
//! then finding at Route that nothing knows what it is — would charge a request slot for a unit that
//! could never have been answered. A refusal at the first step costs nothing and says exactly what
//! happened, which is what makes the coexistence window safe to be in.

// The authenticate step's three seams, declared from here for the length of one window.
//
// The declaration belongs beside its siblings in the root's own module list, and the source file is
// already exactly where that list will name it — the `#[path]` is what lets the file sit in its
// final place while the list is being written by another hand. When the list gains
// `pub mod auth_bindings;`, these two lines become `pub use super::auth_bindings;` and every call
// site is unchanged, because the name they reach it by is the same one either way.
#[path = "auth_bindings.rs"]
pub mod auth_bindings;

use std::sync::{Arc, Mutex};

use busbar_caps::{
    Admit, AdmitToken, Approve, Arrival, Audit, Authenticate, Decision, Decode, Encode, Hold,
    Meter, Outcome, PrincipalId, Refusal, Route, UnitToken, UsageToken, VerifiedDestination,
    Verify,
};
use busbar_kernel::inflight::ArrivalDoor;
use busbar_kernel::teller::{AccrualMeter, Evidence, UnitCtx, Units};
use busbar_unit_admission::{Door, InMemoryCells};
use busbar_unit_auth::{Auth, AuthChain};
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
    /// The three seams the authenticate step is handed beside the request: the credential cache, the
    /// signed-key verifier and the revocation view.
    ///
    /// One per node rather than one per plane, for the reason the cache's own documentation gives
    /// about a flush: two caches would be two answers to "has this credential been seen", and an
    /// operator who flushed one would leave the other serving a verdict the flush was meant to have
    /// killed.
    pub auth_bindings: auth_bindings::AuthBindings,
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
    /// The admin plane's bindings: the seam an operation's body is reached through, and the table
    /// of admin units the loop is currently walking.
    ///
    /// One plane's bindings rather than five, because one plane has been switched. The other four
    /// arrive as their own fields as their own steps land, and until then their step methods say so
    /// rather than answering for a plane that is still served elsewhere.
    pub admin: crate::root::units_admin::AdminBinding,
    /// The store, behind the published ABI. The verbs unit's disaster-recovery subset and its
    /// sealed idempotency cache both reach it, and both reach the same one.
    pub store: Arc<dyn busbar_unit_verbs::store::Store + Send + Sync>,
    /// The credential the kernel lends the verbs unit for the length of an execution.
    ///
    /// Minted once, at boot, from the node's one authority — the second token in the tree minted
    /// outside the loop, for the same reason as the first: a kernel verb is a Route destination
    /// rather than a step, so no step's token stands in for it.
    pub admin_token: busbar_caps::AdminToken,
}

impl ProductionUnits {
    /// Assemble the units the loop reaches, over what the root already built.
    ///
    /// Everything expensive — opening a journal, hydrating the ledger cells, resolving the auth
    /// chain, reading the rate cards — has happened by the time this is called. This is the
    /// assembly, not the work. Every argument is a value configuration decided, which is the shape
    /// that makes it impossible to construct these units and forget one.
    // The argument list IS the point, and shortening it would cost the property the doc comment
    // above claims. Every parameter is one decision configuration made; bundling them into a struct
    // would give that struct a `Default`, and a `Default` is exactly how a deployment ends up with a
    // metering policy it never read its rate cards for. A long list that cannot be built wrong beats
    // a short one that can.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        kernel: &busbar_kernel::teller::Kernel,
        auth_chain: AuthChain,
        durability: crate::root::durability::Durability,
        breaker_policy: crate::root::adapters::BreakerPolicy,
        meter_policy: crate::root::policy::MeterPolicyHandle,
        scope_policy: crate::root::policy::ScopePolicy,
        admin: crate::root::units_admin::AdminBinding,
        store: Arc<dyn busbar_unit_verbs::store::Store + Send + Sync>,
    ) -> Self {
        ProductionUnits {
            door: Door::new(InMemoryCells::new()),
            // The breaker unit's one diagnostic reaches the node's own logging rather than the
            // noop the crate defaults to. What an operator gets out of the binding is the line
            // saying an `error_map` entry they wrote names a class that does not exist; what the
            // request path gets is nothing at all, because the mapping was ignored before the
            // binding and is ignored after it.
            breaker: crate::root::adapters::BreakerAdapter::with_diagnostics(
                crate::root::adapters::root_diagnostics(),
                breaker_policy,
            ),
            egress: EgressUnit::new(),
            auth: Auth::new(auth_chain),
            // The unbound posture, which is the one a node has until it is handed a directory:
            // the cache is real, and the two authorities are absent rather than permissive. A
            // deployment whose keys are busbar's own binds them through
            // `ProductionUnits::with_auth_bindings` at boot, where the governance state exists.
            auth_bindings: auth_bindings::AuthBindings::without_directory(),
            trust: Trust,
            arrival_door: AdmissionDoor,
            durability: Mutex::new(durability),
            meter_policy,
            scope_policy,
            admin,
            store,
            // Minted once, at boot, from the node's one authority. The verbs unit is lent it for the
            // length of an execution and holds nothing after; there is no second way to obtain one.
            admin_token: kernel.admin_token(),
        }
    }

    /// The units an administrative listener needs, and only those.
    ///
    /// One plane has been switched onto the loop, and this is the composition for it: the journal is
    /// memory-buffered because the administrative surface writes no money and probes no directory,
    /// the metering policy is the empty one because the plane declares no meter classes to price
    /// against, and the store is the unconfigured one because no admin operation this root drives
    /// reaches the disaster-recovery subset. Every one of those is a decision this constructor
    /// MAKES rather than defaults into, and each is the reason the corresponding argument of
    /// [`ProductionUnits::new`] is not asked for here.
    ///
    /// When the other four planes switch, they come in through `new` with the configuration they
    /// actually need. This constructor exists because an admin-only node genuinely needs less, not
    /// because the rest is unfinished.
    #[cfg(feature = "root-admin")]
    #[must_use]
    pub fn admin_only(dispatch: Arc<dyn crate::root::units_admin::AdminDispatch>) -> Self {
        let kernel = new_kernel();
        let durability = crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_unit_wal::NullShipper::new()),
            Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal cannot fail to open");

        ProductionUnits::new(
            &kernel,
            AuthChain::new(Vec::new(), false),
            durability,
            crate::root::adapters::BreakerPolicy::new(),
            crate::root::policy::build(&crate::root::policy::MeterPolicyConfig::default()),
            crate::root::policy::ScopePolicy::new(),
            crate::root::units_admin::AdminBinding::new(dispatch),
            Arc::new(crate::root::units_admin::RefusingStore),
        )
    }

    /// Bind the authenticate step's three seams to a node's virtual-key directory.
    ///
    /// Separate from [`ProductionUnits::new`] because the directory is not a value configuration
    /// decided — it is a live handle on the governance state, which exists only after the store is
    /// open and the keys are hydrated, and threading it through the constructor would make every
    /// caller that has no directory pass an absence.
    #[must_use]
    pub fn with_auth_bindings(mut self, bindings: auth_bindings::AuthBindings) -> Self {
        self.auth_bindings = bindings;
        self
    }

    /// The scope an admin credential carries.
    ///
    /// A deployment that mounts the administrative listener behind its own credential grants the
    /// full tier: 1.5.5's admin token is not scoped below it, and narrowing it here would refuse
    /// operations the previous release admitted. The scope unit's matrix is still what decides what
    /// that grant reaches — the grant is the ceiling, the matrix is the door.
    fn admin_grant(&self) -> busbar_unit_verbs::VerbScope {
        busbar_unit_verbs::VerbScope::Full
    }
}

/// Every step below asks the same question first: which plane is this unit's? One plane has been
/// switched onto this loop, so the answer is either the admin plane or a plane whose own steps have
/// not landed yet. The unswitched answer is a refusal naming the step, never a panic and never a
/// silent pass: a unit that reached here on a plane this root does not yet drive was routed wrongly,
/// and the honest answer is to say so and end it rather than to serve it half-composed.
impl ProductionUnits {
    /// Whether this unit is one the admin bindings are walking.
    ///
    /// Membership of the table, not a guess from the context: the surface that opened the unit is
    /// what put it there, so a unit that is in the table is one this root composed and a unit that
    /// is not is one it did not.
    fn is_admin(&self, ctx: &UnitCtx) -> bool {
        self.admin.units.holds(ctx.key)
    }
}

impl Units for ProductionUnits {
    fn arrival(&self, token: &UnitToken<Arrival>, ctx: &UnitCtx) -> Decision<Arrival> {
        if self.is_admin(ctx) {
            return crate::root::units_admin::arrival(&self.admin, token, ctx);
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::NoDestination))
    }

    fn decode(&self, token: &UnitToken<Decode>, ctx: &UnitCtx) -> Decision<Decode> {
        if self.is_admin(ctx) {
            return crate::root::units_admin::decode(&self.admin, token, ctx);
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::DecodeFailed))
    }

    fn authenticate(
        &self,
        token: &UnitToken<Authenticate>,
        ctx: &UnitCtx,
    ) -> Decision<Authenticate> {
        if self.is_admin(ctx) {
            return crate::root::units_admin::authenticate(&self.auth, &self.admin, token, ctx);
        }
        Decision::refuse(
            token,
            Refusal::new(busbar_caps::ReasonCode::Unauthenticated),
        )
    }

    fn verify(
        &self,
        token: &UnitToken<Verify>,
        _trust: &busbar_caps::TrustToken,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> Decision<Verify> {
        if self.is_admin(ctx) {
            return crate::root::units_admin::verify(&self.admin, token, ctx, principal);
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::NoDestination))
    }

    fn approve(
        &self,
        token: &UnitToken<Approve>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> Decision<Approve> {
        if self.is_admin(ctx) {
            return crate::root::units_admin::approve(
                &self.admin,
                self.admin_grant(),
                token,
                ctx,
                principal,
                destinations,
            );
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::ScopeDenied))
    }

    fn admit(
        &self,
        token: &UnitToken<Admit>,
        admit: &AdmitToken<Admit>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> Decision<Admit> {
        if self.is_admin(ctx) {
            return crate::root::units_admin::admit(
                &self.admin,
                token,
                admit,
                ctx,
                principal,
                destinations,
            );
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::NoDestination))
    }

    fn route(
        &self,
        token: &UnitToken<Route>,
        ctx: &UnitCtx,
        meter: &AccrualMeter,
    ) -> Decision<Route> {
        if self.is_admin(ctx) {
            return crate::root::units_admin::route(
                &self.admin,
                Arc::clone(&self.store),
                &self.admin_token,
                token,
                ctx,
                meter,
            );
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::NoDestination))
    }

    fn meter(
        &self,
        token: &UnitToken<Meter>,
        usage: &UsageToken,
        ctx: &UnitCtx,
        provisional: &Outcome,
    ) -> Decision<Meter> {
        if self.is_admin(ctx) {
            return crate::root::units_admin::meter(token, usage, ctx, provisional);
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::Unpriced))
    }

    fn audit(&self, token: &UnitToken<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> Decision<Audit> {
        if self.is_admin(ctx) {
            let durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
            return crate::root::units_admin::audit(
                &self.admin,
                &durability.legacy,
                token,
                ctx,
                outcome,
            );
        }
        Decision::proceed(token, crate::root::units_admin::unresolved_facts(outcome))
    }

    fn audit_refused(
        &self,
        token: &UnitToken<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> Decision<Audit> {
        if self.is_admin(ctx) {
            let durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
            return crate::root::units_admin::audit_refused(
                &self.admin,
                &durability.legacy,
                token,
                ctx,
                refusal,
            );
        }
        Decision::proceed(
            token,
            crate::root::units_admin::unresolved_facts(&Outcome::Refused(
                refusal.step(),
                refusal.reason(),
            )),
        )
    }

    fn encode(
        &self,
        token: &UnitToken<Encode>,
        ctx: &UnitCtx,
        outcome: &Outcome,
    ) -> Decision<Encode> {
        if self.is_admin(ctx) {
            return crate::root::units_admin::encode(&self.admin, token, ctx, outcome);
        }
        Decision::refuse(token, Refusal::new(busbar_caps::ReasonCode::DecodeFailed))
    }

    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        if self.is_admin(ctx) {
            return crate::root::units_admin::evidence(ctx);
        }
        // Nothing located, nothing accrued, no upstream candidate: a unit this root did not compose
        // reached no destination, and the settlement table's answer for that is zero on every row.
        Evidence::default()
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

        let kernel = new_kernel();
        let units = ProductionUnits::new(
            &kernel,
            AuthChain::new(Vec::new(), false),
            durability,
            crate::root::adapters::BreakerPolicy::new(),
            crate::root::policy::build(&crate::root::policy::MeterPolicyConfig::default()),
            crate::root::policy::ScopePolicy::new(),
            crate::root::units_admin::AdminBinding::new(std::sync::Arc::new(
                crate::root::units_admin::RefusingDispatch,
            )),
            std::sync::Arc::new(crate::root::units_admin::RefusingStore),
        );

        // Nothing is in flight before anything arrives, which is the machine-checkable half of
        // "an entry that outlived its unit would be a leak per request".
        assert!(units.admin.units.is_empty());

        // The journal opened nothing, the ledger is dual-writing, and the scope policy permits
        // nothing until it is told to. All three are the safe end of a choice that had an unsafe
        // end, and all three are checkable here rather than at the first request.
        let durability = units.durability.lock().expect("durability lock");
        assert!(!durability.on_disk());
        assert!(durability.ledger.is_dual_writing());
        assert!(units.scope_policy.is_empty());
    }

    /// The breaker unit the root assembles reports an unrecognized `error_map` class rather than
    /// swallowing it.
    ///
    /// The unit's own default sink is a noop, which is 1.5.5's behaviour for the classification
    /// RESULT and also for the warning — the mapping is ignored either way, and before this
    /// binding nothing said so. What is asserted here is the composition: the sink the root builds
    /// is reached from the unit the root assembled, through the port the egress unit classifies
    /// over, without any test double standing in for either side.
    ///
    /// The sink is a recording one rather than the tracing one, because what needs proving is that
    /// the value ARRIVES; where it goes afterwards is `adapters::TracingDiagnostics`, and asserting
    /// on a log line would be asserting on the subscriber a test happened to install.
    #[test]
    fn an_unrecognized_error_map_class_reaches_the_roots_sink() {
        #[derive(Debug, Default)]
        struct RecordingSink(Mutex<Vec<String>>);

        impl busbar_unit_breaker::classify::Diagnostics for RecordingSink {
            fn unrecognized_error_map_value(&self, value: &str) {
                self.0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(value.to_string());
            }
        }

        let durability = crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_unit_wal::NullShipper::new()),
            Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal cannot fail to open");

        let kernel = new_kernel();
        let mut units = ProductionUnits::new(
            &kernel,
            AuthChain::new(Vec::new(), false),
            durability,
            crate::root::adapters::BreakerPolicy::new(),
            crate::root::policy::build(&crate::root::policy::MeterPolicyConfig::default()),
            crate::root::policy::ScopePolicy::new(),
            crate::root::units_admin::AdminBinding::new(Arc::new(
                crate::root::units_admin::RefusingDispatch,
            )),
            Arc::new(crate::root::units_admin::RefusingStore),
        );

        // The same assembly the constructor performs, over a sink this test can read back. The
        // production sink is `adapters::root_diagnostics()`; the width is the same one, which is
        // what makes the substitution a substitution rather than a different composition.
        let sink = Arc::new(RecordingSink::default());
        units.breaker = crate::root::adapters::BreakerAdapter::with_diagnostics(
            Arc::clone(&sink) as crate::root::adapters::DiagnosticsSink,
            crate::root::adapters::BreakerPolicy::new(),
        );

        let destination = busbar_unit_breaker::DestinationId::new(11);
        units.breaker.unit().set_error_map(
            destination,
            std::collections::HashMap::from([("503".to_string(), "rate_limt".to_string())]),
        );

        let classified = busbar_unit_egress::ports::Breaker::classify(
            &units.breaker,
            destination,
            busbar_unit_egress::ports::UpstreamStatus {
                code: Some(503),
                class: None,
                retry_after: None,
            },
        );

        assert_eq!(
            sink.0.lock().expect("sink lock").as_slice(),
            ["rate_limt".to_string()],
            "the unrecognized class reached the sink the root bound"
        );
        assert_eq!(
            classified.disposition,
            busbar_unit_egress::ports::Disposition::TransientUpstream,
            "and the mapping stayed ignored: the 503 classified from its HTTP status"
        );
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
