// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The agent-to-agent plane, driven through the kernel.
//!
//! One plane, one file, every step. The kernel calls twelve methods in a fixed order and hands each
//! one the token for its own step; what this file does is answer those twelve calls with the units,
//! for units the A2A plane claimed. Nothing here decides anything a unit owns — the auth chain says
//! who is calling, the trust unit says where a unit may go, the scope unit says whether the caller
//! may ask, the door says whether it is paid for, the egress unit walks the pool, the usage unit
//! folds the meter and the audit unit seals the end. What this file owns is the WIRING, which is
//! the composition root's whole job.
//!
//! ## What the plane already answered, and why nothing is asked twice
//!
//! The plane's own methods take a `Unit<'u>` and a `Ctx<'u>`, both of which the kernel builds and
//! neither of which crosses `Units`' twelve signatures. So the plane's answers arrive here as
//! [`A2aDraft`] — a by-value record of what `decode_ingress`, `verify`, `approve`, `admit`, `route`,
//! `meter` and `audit` returned for this unit, read ONCE where the kernel had the borrow. A step
//! that re-scanned the body to recover a fact the draft already carries would be an allocation
//! outside the arena on the request path, which is the one thing the arena exists to make
//! impossible.
//!
//! ## The record legs are not routed by the egress unit
//!
//! This plane's durable state — tasks, task events, push configurations and pins — reaches the node
//! through record legs on the route plan, and the egress unit has no arm for one: its walk resolves
//! a pool and dials a member, and a plane record is neither. [`RecordLegs`] is the binding, over the
//! published store protocol's own eight kind-tagged operations, and it is the composition root that
//! drives them because a plane may not hold a store and a unit may not know a schema.
//!
//! ## Where this composition still binds to the A2A plugin crate
//!
//! The plane crate is pure and names only the contract and the codec. The composition around it is
//! not yet pure, and the honest list of what still lives in `busbar-a2a` is short and specific:
//!
//! 1. **The agent-card pin.** `busbar_a2a::a2a::pin::{CardPin, approve_registration}` and
//!    `busbar_a2a::a2a::verify` hold the JWS-issuer-key mechanism, the fingerprint an operator
//!    approves and the re-verification ladder. The trust unit's network guard judges the ADDRESS a
//!    name resolves to; it has no opinion about the document that address serves. So the pin is
//!    carried into [`A2aBindings::pinned`] as a decided fact, and the deciding still happens there.
//! 2. **The audit action literal.** `agent.call` is spelled in the plugin's own receive path and in
//!    the gating rig; this file pins its copy against the rig's script rather than against a
//!    constant, because the plugin's constant is crate-private.
//! 3. **The claim list's route pin.** The plane crate's own claim test reads
//!    `crates/busbar-a2a/src/a2a/*.rs` through `include_str!` to prove every mounted route is
//!    claimed. That is a source-level seam, not a Cargo edge, and it is the reason the claim list
//!    and the served routes cannot silently diverge.
//! 4. **The durable task set's boot hook.** `busbar_a2a::taskstore::TASKS` owns its own
//!    write/restore path against the same store this file reaches through [`RecordLegs`]. Both write
//!    the same kinds; the plugin's hook is what hydrates them at boot.
//!
//! Nothing else. The plane kind, the claims, the operation classes, the meter class, the record
//! schemas and every wire shape are the pure crate's.
//!
//! ## Two seams the kernel has not opened, stated rather than worked around
//!
//! - **The trust unit's seal.** `Trust::verify` requires a `TrustToken` as well as the step's own
//!   `UnitToken<Verify>`, and the kernel mints an admit token and a transport-key token publicly
//!   but not a trust token. So the token is carried into [`A2aBindings`] by whoever holds the seal
//!   rather than minted here. The judgement itself — the guards, the network guard, the per-kind
//!   rules — is [`A2aUnits::verified_lanes`], which needs no token and is testable without one.
//! - **The egress walk is asynchronous and the step is not.** `Egress::route` returns a future and
//!   `Units::route` returns a `Decision<Route>`. What this file's route step does is everything the
//!   walk needs decided before it can be polled — the record legs driven, the network guard
//!   answered, the breaker's readiness read — and it hands back the plan. The dial is the caller's
//!   to await, and it is the caller that owns the transport.

use std::sync::{Arc, Mutex};

use busbar_caps::{
    Admit, AdmitToken, Approve, Arrival, ArrivalRecord, Audit, AuditFacts, Authenticate,
    Decision, Decode, Encode, Meter, Outcome, PrincipalId, ReasonCode, Refusal,
    Route, RoutePlan, ScopeFacts, TrustToken, UnitToken, UsageToken, Verify, VerifiedDestination,
};
use busbar_contract::dest::{DestinationFacts, Leg};
use busbar_contract::ids::{ClaimKey, LaneId, OpClassId, RecordSchemaId};
use busbar_contract::unit::{FinishClass, ResourceLocator};
use busbar_kernel::teller::{AccrualMeter, Evidence, UnitCtx, Units};
use busbar_plane_a2a::{ops, records};
use busbar_unit_admission::{Admission as _, AdmissionUnit, CellStore, Door, Estimate, Pricer};
use busbar_unit_audit::{Audit as _, AuditInputs};
use busbar_unit_auth::{Auth, AuthRequest};
use busbar_unit_scope::{Grants, Scope};
use busbar_unit_trust::{
    kind_permitted, kind_rule_passes, GuardPolicy, KindFacts, OriginKind, PoolView, Resolver,
};
use busbar_unit_usage::{KernelCounts, LegDeclaration, LocatedValue, RetainedLocatorValues};

/// The action an audited unit of this plane is recorded under.
///
/// One literal, because the gating rig asserts on it byte for byte: a served `message/send` seals
/// exactly one entry, action `agent.call`, outcome applied, resource `agent:probe`. The plugin
/// crate spells the same word in its own receive path, but spells it crate-privately, so this copy
/// is pinned against the rig's script instead — a copy that is checked is not a second opinion.
pub const AUDIT_ACTION: &str = "agent.call";

/// The kind of resource this plane's approvals are written over.
///
/// The plane emits the locator and the deployment's policy judges it. The kind is the plane's own
/// word for what it fronts, and the scope entry is written against the pair `(claim, op class)`.
pub const SCOPE_KIND_AGENT: &str = "agent";

/// The claim key the scope policy's entries for this plane are written under.
///
/// A declared claim carries a transport and a selector and no name of its own, so the pairing that
/// makes `(claim, op class)` writable is the root's: this is the plane's registry key, which is the
/// only name both halves already agree on.
pub const CLAIM_A2A: ClaimKey = ClaimKey::new("a2a");

/// The one class a unit of this plane is metered under.
///
/// Declared by the plane, named here because the metering step folds against it and the settlement
/// table reports it. A second class named here would be a class the plane never declared.
pub const CLASS_BYTES: busbar_contract::ids::MeterClassId = busbar_plane_a2a::meta::CLASS_BYTES;

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE RECORD LEGS
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// Why a record leg did not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegError {
    /// The leg named an operation the schema does not declare.
    ///
    /// A declaration rather than a convention, and refused here rather than attempted: a schema's
    /// operation set is what the trust unit checks a plane record leg against, and a leg that got
    /// past that check with an undeclared operation would be a hole in the check rather than a
    /// generous reading of it.
    UndeclaredOp {
        /// The schema the leg named.
        schema: &'static str,
        /// The operation it asked for.
        op: &'static str,
    },
    /// The store refused or failed.
    Store(String),
}

/// What one record leg came back with.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LegResult {
    /// The body a read returned, where the leg read one.
    pub body: Option<Vec<u8>>,
    /// The bodies a scan returned, oldest first for an append-only kind.
    pub bodies: Vec<Vec<u8>>,
    /// Whether a redemption was the first one. A spent token answers `false`.
    pub redeemed: bool,
}

/// Everything one record write carries besides its body.
///
/// The sidecar is typed on purpose: the store keys, orders and retention-sweeps on these columns
/// and never decodes the body, so a record whose identity lived inside its own bytes would be a
/// record the store could not sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegKey<'a> {
    /// The record's identity within its kind.
    pub id: &'a str,
    /// The parent an append-only child hangs off. `None` for a top-level kind.
    pub parent: Option<&'a str>,
    /// Monotonic sequence within the parent, for the append-only kinds.
    pub seq: u64,
    /// The record's timestamp, which is the axis retention compares against.
    pub ts: u64,
    /// Whether retention may drop the row once it is older than a cutoff.
    pub terminal: bool,
}

/// The plane's durable state, reached through the published store protocol and nothing else.
///
/// The four schemas this plane declares map onto the store's eight kind-tagged operations one for
/// one. There is no second path: a plane holds no store, and a unit knows no schema, so the mapping
/// belongs exactly here and nowhere else.
pub struct RecordLegs {
    store: Arc<dyn busbar_api::Store>,
}

impl std::fmt::Debug for RecordLegs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecordLegs")
    }
}

impl RecordLegs {
    /// Bind the legs to a store.
    ///
    /// The store is the one the loader resolved, at the published protocol version the registry's
    /// floor admits. A deployment that named none gets the in-tree memory store, which is the
    /// shipped default and the reason a zero-configuration boot has somewhere to put a task.
    #[must_use]
    pub fn new(store: Arc<dyn busbar_api::Store>) -> Self {
        RecordLegs { store }
    }

    /// Whether a schema declares an operation at all.
    ///
    /// Asked before every leg runs. The plane's own declaration is the answer, so a schema that
    /// gains or loses an operation changes this without anything here being edited.
    fn declares(schema: RecordSchemaId, op: &'static str) -> bool {
        records::operations_for(schema).contains(&op)
    }

    /// Run one leg.
    ///
    /// Every arm is a single call onto the store. The dispatch is on the operation the plane's
    /// route plan named, which is why an undeclared operation is a refusal here rather than a panic
    /// or a silent no-op: the plan said something the schema does not offer, and the honest answer
    /// is to say so.
    ///
    /// # Errors
    ///
    /// The schema does not declare the operation, or the store refused.
    pub fn run(
        &self,
        schema: RecordSchemaId,
        op: &'static str,
        key: &LegKey<'_>,
        body: &[u8],
    ) -> Result<LegResult, LegError> {
        if !Self::declares(schema, op) {
            return Err(LegError::UndeclaredOp {
                schema: schema.as_str(),
                op,
            });
        }
        let kind = schema.as_str();
        let fail = |e: busbar_api::StoreError| LegError::Store(e.0);
        match op {
            records::OP_GET => Ok(LegResult {
                body: self.store.get_plane_record(kind, key.id).map_err(fail)?,
                ..LegResult::default()
            }),
            records::OP_PUT => {
                self.store
                    .upsert_plane_record(&self.record(kind, key, body))
                    .map_err(fail)?;
                Ok(LegResult::default())
            }
            records::OP_APPEND => {
                self.store
                    .append_plane_record(&self.record(kind, key, body))
                    .map_err(fail)?;
                Ok(LegResult::default())
            }
            records::OP_SCAN => {
                // A scan of an append-only kind is narrowed to one parent and answers oldest-first;
                // a scan of a top-level kind is the whole kind. Which of the two a schema wants is
                // carried by the leg's key, not guessed from the schema.
                let selector = match key.parent {
                    Some(parent) => busbar_api::PlaneSelector::Parent(parent.to_string()),
                    None => busbar_api::PlaneSelector::All,
                };
                Ok(LegResult {
                    bodies: self.store.list_plane_records(kind, &selector).map_err(fail)?,
                    ..LegResult::default()
                })
            }
            records::OP_DELETE => {
                self.store.delete_plane_record(kind, key.id).map_err(fail)?;
                Ok(LegResult::default())
            }
            records::OP_REDEEM => Ok(LegResult {
                // The token is spent exactly once and the answer is which call spent it. A second
                // redemption answers false rather than failing: two agents racing one callback is
                // an ordinary event, and only one of them is the first.
                redeemed: self
                    .store
                    .redeem_plane_token(kind, key.id, key.ts, key.ts)
                    .map_err(fail)?,
                ..LegResult::default()
            }),
            other => Err(LegError::UndeclaredOp {
                schema: kind,
                op: other,
            }),
        }
    }

    /// The neutral envelope one write goes into.
    fn record(&self, kind: &str, key: &LegKey<'_>, body: &[u8]) -> busbar_api::PlaneRecord {
        busbar_api::PlaneRecord {
            kind: kind.to_string(),
            id: key.id.to_string(),
            parent: key.parent.map(str::to_string),
            seq: key.seq,
            ts: key.ts,
            disposition: if key.terminal {
                busbar_api::PlaneDisposition::Terminal
            } else {
                busbar_api::PlaneDisposition::Active
            },
            body: body.to_vec(),
        }
    }

    /// Drive every record leg of a route plan, in the plan's own order.
    ///
    /// The order is the plane's and is load-bearing: a cancellation reads the row, hops, writes the
    /// row and appends the event, and a run that reordered those would append an event for a state
    /// the row never reached. Upstream legs are skipped here — they are the egress unit's.
    ///
    /// # Errors
    ///
    /// The first leg that refuses stops the run and is returned; the legs before it have already
    /// happened, which is why a plan's record legs are ordered so that a failure leaves the durable
    /// state readable rather than half-written.
    pub fn run_plan(&self, legs: &[Leg], key: &LegKey<'_>, body: &[u8]) -> Result<Vec<LegResult>, LegError> {
        let mut results = Vec::new();
        for leg in legs {
            if let DestinationFacts::PlaneRecord { schema, op } = leg.destination {
                results.push(self.run(schema, op, key, body)?);
            }
        }
        Ok(results)
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   WHAT THE PLANE ANSWERED
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// Everything the plane said about one unit, read once.
///
/// The kernel holds the borrow that lets a plane be asked; these are its answers, carried forward
/// by value so every later step reads what the plane said rather than re-deriving it. A field here
/// is a fact the plane produced, never a fact this file computed.
#[derive(Debug, Clone)]
pub struct A2aDraft {
    /// What the decode step recognised. `None` is a body this plane does not carry.
    pub op: Option<OpClassId>,
    /// The scheme alternative the plane narrowed the claim to. `None` on the three open surfaces,
    /// whose claims declare no scheme at all.
    pub narrowing: Option<&'static str>,
    /// The alternatives the matched claim declared. Empty on an open surface.
    pub declared_schemes: &'static [&'static str],
    /// Whether the principal is the bound session's rather than these bytes'.
    pub from_session: bool,
    /// The credential the transport masked out of the frame, where one arrived.
    pub credential: Option<String>,
    /// The audience an audience-bound ingress requires.
    pub expected_aud: Option<String>,
    /// Where the plane says this unit goes.
    pub destination: DestinationFacts,
    /// The resource the plane named for the approval, where it named one.
    pub resource: Option<ResourceLocator>,
    /// The legs of the plane's route plan, in the plan's order.
    pub legs: Vec<Leg>,
    /// The whole request document's length, which is what this plane prices its input on.
    pub request_bytes: u64,
    /// What the metering step's locator carried — the size of the answer the plane read.
    pub response_bytes: u64,
    /// How the plane says the unit finished.
    pub finish: FinishClass,
    /// Whether the answer arrives as a run of events rather than one reply.
    pub streaming: bool,
    /// What the transport recorded about the arrival.
    pub arrival: ArrivalRecord,
}

impl A2aDraft {
    /// Whether this operation reaches an agent rather than only this node's own records.
    ///
    /// The fee's origin rule and the request slot's both read it, and both read it off the verified
    /// set rather than off the method name — which is why it is derived from the destination the
    /// plane produced and not from a second table of operation names.
    #[must_use]
    pub fn has_upstream(&self) -> bool {
        matches!(
            self.destination,
            DestinationFacts::Upstream { .. } | DestinationFacts::SessionUpstream { .. }
        ) || self.legs.iter().any(|l| {
            matches!(
                l.destination,
                DestinationFacts::Upstream { .. } | DestinationFacts::SessionUpstream { .. }
            )
        })
    }
}

/// Which scope one operation class of this plane requires.
///
/// Read-only for the projections a caller may take of state it already owns, full for everything
/// that moves a task or changes what an agent is told. The distinction is the deployment's to
/// override through its own policy; what this function is, is the DEFAULT the root declares so that
/// a policy which mentions this plane at all mentions every one of its classes.
///
/// A class absent from the policy is a refusal, never a pass, so an operation class added to the
/// plane and forgotten here is refused rather than opened.
#[must_use]
pub fn declared_scope(op: OpClassId) -> Scope {
    match op {
        ops::OP_TASK_GET
        | ops::OP_TASK_LIST
        | ops::OP_PUSH_CONFIG_GET
        | ops::OP_PUSH_CONFIG_LIST
        | ops::OP_AGENT_CARD => Scope::ReadOnly,
        _ => Scope::Full,
    }
}

/// The scope policy entries this plane needs, folded onto whatever the deployment already declared.
///
/// Every operation class the plane declares gets an entry, because the scope unit reads silence as
/// a refusal and a plane with a partly-declared policy is a plane whose remaining operations are
/// unreachable for a reason nobody can find in a configuration file.
#[must_use]
pub fn scope_policy(base: crate::root::policy::ScopePolicy) -> crate::root::policy::ScopePolicy {
    ops::OP_CLASSES
        .iter()
        .fold(base, |policy, op| {
            policy.declaring(CLAIM_A2A, *op, declared_scope(*op))
        })
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE BINDINGS
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// The long-lived halves one unit of this plane is driven over.
///
/// Everything expensive has already happened by the time one of these is borrowed: the journal is
/// open, the ledger cells are hydrated, the auth chain is resolved and the rate cards are read.
/// What is here is the assembly, and every field is a value configuration decided.
pub struct A2aBindings<'r, S: CellStore> {
    /// The authentication chain, as configuration resolved it.
    pub auth: &'r Auth,
    /// The credential cache, the signed-key verifier and the revocation view the chain is handed
    /// beside the request. Borrowed rather than owned, and borrowed from the node's one set: a
    /// second cache would be a second answer to "has this credential been seen".
    pub auth_bindings: &'r crate::root::kernel::auth_bindings::AuthBindings,
    /// The seal the trust unit's verified destinations are minted under. Carried rather than minted
    /// because the kernel mints it and this is not the kernel.
    pub trust_token: &'r TrustToken,
    /// What the deployment says about its pools and this caller's key.
    pub pools: &'r dyn PoolView,
    /// What the per-kind destination rules consult.
    pub kinds: &'r dyn KindFacts,
    /// The name resolver the network guard runs its one resolution through.
    pub resolver: &'r dyn Resolver,
    /// How far the network guard lets this plane's hops reach.
    pub guard: GuardPolicy,
    /// The deployment's additions to and carve-outs from the metadata denylist.
    pub denylist: &'r busbar_unit_trust::Denylist,
    /// The agents whose cards an operator has approved, by configured name.
    ///
    /// The pin itself is decided in the A2A plugin, where the JWS issuer key and the approved
    /// fingerprint live; what reaches here is the decision. An agent absent from this list has not
    /// been approved and is not reached.
    pub pinned: &'r [&'r str],
    /// The admission unit's long-lived door.
    pub door: &'r Door<S>,
    /// What the door prices a unit against.
    pub pricer: &'r Pricer,
    /// The plane's durable records.
    pub records: &'r RecordLegs,
    /// What the usage unit folds against.
    pub meter_policy: &'r crate::root::policy::MeterPolicyHandle,
    /// What the scope unit reads at approve.
    pub scope_policy: &'r crate::root::policy::ScopePolicy,
    /// The journal, the ledger and the two audit chains.
    pub durability: &'r Mutex<crate::root::durability::Durability>,
    /// The pool this unit's agent is reached on.
    pub pool: &'r str,
    /// The arrival epoch, pinned. Never a fresh clock read on the request path.
    pub now: u64,
    /// The sealed origin the audit record is written under.
    ///
    /// Sealed by the kernel and carried here for the same reason the trust token is: `Origin::seal`
    /// takes the kernel's seal, and this is not the kernel. `UnitCtx` hands each step the origin's
    /// KIND, which is what the destination rules read; the sealed value is what the record needs.
    pub origin: busbar_caps::Origin,
}

/// What the steps recorded as they ran.
///
/// The settlement table reads this once, at the exit. It is behind a lock because the steps take
/// `&self` and the exit reads what they wrote; there is one of these per unit, so the lock is never
/// contended and its only job is to make the write legal.
#[derive(Debug, Default)]
struct Progress {
    /// Who the authenticate step settled on.
    principal: Option<PrincipalId>,
    /// The grants that principal holds.
    grants: Option<Grants>,
    /// What the verify step sealed.
    lanes: Vec<LaneId>,
    /// What the record legs came back with.
    legs: Vec<LegResult>,
    /// What the metering step folded.
    metered: Option<u64>,
    /// Whether the metering step disputed its own reading.
    disputed: bool,
    /// The hash the audit chain sealed this unit under.
    audit_hash: Option<String>,
    /// The bytes the encode step reported.
    encoded: u64,
}

/// One unit of the A2A plane, driven through the kernel's ten steps and its one exit.
pub struct A2aUnits<'r, S: CellStore> {
    bindings: A2aBindings<'r, S>,
    draft: A2aDraft,
    grants: Grants,
    progress: Mutex<Progress>,
}

impl<'r, S: CellStore> A2aUnits<'r, S> {
    /// Drive one unit.
    ///
    /// The draft is what the plane already said; the grants are what the caller's credential
    /// carries. Both are inputs because both are decided before the first step runs, and a step
    /// that produced either of them would be a step deciding its own inputs.
    #[must_use]
    pub fn new(bindings: A2aBindings<'r, S>, draft: A2aDraft, grants: Grants) -> Self {
        A2aUnits {
            bindings,
            draft,
            grants,
            progress: Mutex::new(Progress::default()),
        }
    }

    /// What the plane said about this unit.
    #[must_use]
    pub fn draft(&self) -> &A2aDraft {
        &self.draft
    }

    /// The verify judgement, without the seal.
    ///
    /// Everything the trust unit decides about where this unit may go, in the order that makes the
    /// order matter: the pool guards first, because nothing may refuse a request that has already
    /// been charged; then the agent-card pin, because an agent nobody approved is not one to dial;
    /// then the network guard, because the address a name answers with is part of where a unit may
    /// go and asking after the dial is asking too late; then the per-kind rules.
    ///
    /// A destination that carries no lane — every one of this plane's record legs — is not priced
    /// on one and does not enter the sealed set. That is not an exclusion: a record leg is reached
    /// through the plan, not through the pool walk.
    ///
    /// # Errors
    ///
    /// A guard refused, the agent is unpinned, the network guard refused the address, or the
    /// destination's own kind rule did not pass.
    pub fn verified_lanes(&self, origin: OriginKind) -> Result<Vec<LaneId>, Refusal> {
        // Guard one, two and three: the pool's allow-list, every fallback pool reachable from it,
        // and the unpriced-name gate.
        if let Err(refusal) = busbar_unit_trust::destination_guard(
            self.bindings.pools,
            self.bindings.pool,
            UNPRICED_MESSAGE,
        ) {
            return Err(Refusal::new(refusal.kind.reason()));
        }

        // The agent-card pin. An operator approved a fingerprint or did not; this file reads the
        // decision and does not re-derive it, because the mechanism that produced it is the
        // plugin's and the plugin is where a re-derivation would have to live.
        if self.dials_an_agent() && !self.agent_is_pinned() {
            return Err(Refusal::new(ReasonCode::NoDestination));
        }

        let candidates = self.candidates();
        let mut lanes = Vec::new();
        for candidate in &candidates {
            if !kind_permitted(origin, candidate) {
                continue;
            }
            if !kind_rule_passes(candidate, self.bindings.kinds) {
                continue;
            }
            let Some(lane) = candidate.lane() else {
                continue;
            };
            // The network guard, once, before any dial, for every carrier there will ever be. What
            // a transport receives is an address somebody already looked at.
            self.guard_destination(candidate)?;
            lanes.push(lane);
        }
        Ok(lanes)
    }

    /// Every destination this unit could reach: the one the plane verified, plus each leg's.
    fn candidates(&self) -> Vec<DestinationFacts> {
        let mut candidates = vec![self.draft.destination];
        for leg in &self.draft.legs {
            if !candidates.contains(&leg.destination) {
                candidates.push(leg.destination);
            }
        }
        candidates
    }

    /// Whether anything about this unit reaches an agent over the network.
    fn dials_an_agent(&self) -> bool {
        self.draft.has_upstream()
    }

    /// Whether the agent this unit would dial has an approved card.
    fn agent_is_pinned(&self) -> bool {
        match self.draft.destination {
            DestinationFacts::Upstream { lane, .. } => {
                self.bindings.pinned.iter().any(|a| *a == lane.as_str())
            }
            // A paired session's upstream was pinned when the session opened; re-asking here would
            // be asking about a connection that is already carrying frames.
            DestinationFacts::SessionUpstream { .. } => true,
            _ => false,
        }
    }

    /// Run the network guard over one candidate, converting its refusal into the loop's.
    fn guard_destination(&self, candidate: &DestinationFacts) -> Result<(), Refusal> {
        guard_destination(
            candidate,
            self.bindings.resolver,
            self.bindings.guard,
            self.bindings.denylist,
        )
        .map_err(|_| Refusal::new(ReasonCode::NoDestination))
    }

    /// The hold this unit is sized against.
    ///
    /// One class, because this plane declares one. The priced input is the whole request document,
    /// which is what the plane's admit facts point at, and the flat fee applies only where the
    /// verified set contains an agent — a push the agent sent draws no client's slot and posts no
    /// fee.
    fn estimate(&self) -> Estimate {
        Estimate {
            per_class: vec![busbar_unit_admission::ClassEstimate {
                class: CLASS_BYTES.as_str().to_string(),
                quantity: self.draft.request_bytes,
                max_unit_price_nanos: 0,
            }],
            fee_nanos: if self.draft.has_upstream() {
                u64::try_from(self.bindings.pricer.price_per_request_cents().max(0))
                    .unwrap_or(0)
                    .saturating_mul(NANOS_PER_CENT)
            } else {
                0
            },
        }
    }

    /// The audit record one ending seals.
    fn audit_inputs(&self, outcome: Outcome, principal: Option<&PrincipalId>) -> AuditInputs {
        let progress = self.progress.lock().expect("progress lock");
        AuditInputs {
            subject: match principal.or(progress.principal.as_ref()) {
                Some(p) => busbar_unit_audit::Subject::PrincipalId(p.as_str().to_string()),
                None => busbar_unit_audit::Subject::Arrival,
            },
            what: busbar_unit_audit::What {
                unit_key: busbar_contract::ids::UnitKey::new(0),
                // The action, not the operation class. The rig reads this word, and the plane's own
                // class is carried beside it on the facts the step returns.
                op_class: busbar_unit_audit::OpClassId::new(AUDIT_ACTION),
                destination: self
                    .draft
                    .resource
                    .map(|r| format!("{}:{}", r.kind, r.name)),
                parent: None,
                pre_hook_head: None,
                post_hook_head: None,
            },
            wall: self.bindings.now,
            mono: self.bindings.now,
            origin: self.bindings.origin,
            outcome: busbar_unit_audit::OutcomeFacts {
                unit_end: outcome,
                step: outcome.step(),
                finish: audit_finish(self.draft.finish),
                hook_failed: false,
                emission_delta: 0,
                stale_policy: false,
            },
            amount: busbar_unit_audit::Amount {
                lines: Vec::new(),
                pre_tier: 0,
                priced: 0,
                tier_bp: 0,
                fee_count: u32::from(self.draft.has_upstream()),
                currency: String::new(),
                rate_card_version: 0,
                bucket_chain_ref: String::new(),
            },
            controls: busbar_unit_audit::Controls::default(),
            correlation_label: None,
        }
    }
}

/// The words a caller sees when the name it asked for has no configured rate.
///
/// Carried as one static because the trust unit takes it as one: the text names what was asked for
/// and nothing about the money behind it.
const UNPRICED_MESSAGE: &str = "no agent is configured under that name";

/// How many nano-units one cent is.
const NANOS_PER_CENT: u64 = 10_000_000;

/// The audit unit's spelling of a finish class.
///
/// Two crates name the same four endings and neither depends on the other, so the mapping is
/// written once, here, where both are in scope. Totality is what makes it safe: a fifth ending
/// would not compile.
fn audit_finish(finish: FinishClass) -> busbar_unit_audit::FinishClass {
    match finish {
        FinishClass::Complete => busbar_unit_audit::FinishClass::Complete,
        FinishClass::TurnComplete => busbar_unit_audit::FinishClass::TurnComplete,
        FinishClass::Partial => busbar_unit_audit::FinishClass::Partial,
        FinishClass::Error => busbar_unit_audit::FinishClass::Error,
    }
}

impl<S: CellStore> Units for A2aUnits<'_, S> {
    fn arrival(&self, token: &UnitToken<Arrival>, _ctx: &UnitCtx) -> Decision<Arrival> {
        // The gate itself is the kernel's, over the configured budgets, and it has already run by
        // the time a plane's units are reached. What this step carries forward is what the
        // transport recorded, which is what the later steps read the source and the chain from.
        Decision::proceed(token, self.draft.arrival.clone())
    }

    fn decode(&self, token: &UnitToken<Decode>, _ctx: &UnitCtx) -> Decision<Decode> {
        // The plane read the bytes; this is its answer. A body carrying a method this plane does
        // not name is a refusal at the step that read it, not a guess at the nearest class.
        match self.draft.op {
            Some(op) => Decision::proceed(token, op),
            None => Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed)),
        }
    }

    fn authenticate(&self, token: &UnitToken<Authenticate>, _ctx: &UnitCtx) -> Decision<Authenticate> {
        // The three open surfaces of this protocol declare no scheme, so there is nothing to narrow
        // within and nothing to present: the chain answers for the anonymous principal or it
        // denies, and either answer is the chain's. Everything else presents a bearer credential
        // and is narrowed to the one alternative the claim declares.
        let request = AuthRequest {
            candidate: self.draft.credential.as_deref(),
            scheme: self.draft.narrowing,
            declared_schemes: self.draft.declared_schemes,
            expected_aud: self.draft.expected_aud.as_deref(),
            in_handshake: false,
            now: self.bindings.now,
            // A bound session's principal is the cached one; an unbound session re-authenticates
            // every unit, which is what makes revocation gate new units on this plane at all.
            new_unit: !self.draft.from_session,
        };
        // The chain's answer is the chain's, and a decision has no reader on it by design — the only
        // thing that opens one is the loop, with the kernel's seal. So the principal the audit and
        // the settlement need is recorded at the next step, which is handed it.
        // The three seams the chain cannot own, from the node's one set. The revocation view is
        // what the `new_unit` answer above is FOR: an unbound session asks it every unit, a bound
        // one never does, and neither question could be asked at all while the argument was absent.
        let seams = self.bindings.auth_bindings;
        self.bindings.auth.resolve(
            &request,
            seams.cache(),
            seams.keys(),
            seams.revocations(),
            None,
            token,
        )
    }

    fn verify(
        &self,
        token: &UnitToken<Verify>,
        trust: &TrustToken,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> Decision<Verify> {
        {
            // The first step that is handed the principal is the first that can record it. The
            // audit and the settlement both read it and neither is handed it again.
            let mut progress = self.progress.lock().expect("progress lock");
            progress.principal = Some(principal.clone());
            progress.grants = Some(self.grants);
        }
        match self.verified_lanes(trust_origin(ctx.origin)) {
            Err(refusal) => Decision::refuse(token, refusal),
            Ok(lanes) => {
                self.progress.lock().expect("progress lock").lanes = lanes.clone();
                // An empty set is a legitimate answer and is NOT a refusal here. A pool with every
                // lane excluded proceeds through the door, draws its slot and retains it, and ends
                // at the pool's own exhaustion terminal — refusing here would move the charge.
                Decision::proceed(
                    token,
                    lanes
                        .into_iter()
                        .map(|lane| VerifiedDestination::seal(trust, lane))
                        .collect(),
                )
            }
        }
    }

    fn approve(
        &self,
        token: &UnitToken<Approve>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> Decision<Approve> {
        let Some(op) = self.draft.op else {
            return Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed));
        };
        // Silence is a refusal. A pair the deployment's policy says nothing about has not been
        // authorized, and there is deliberately no arm here that reads an absent entry as a
        // permissive one.
        let Some(needed) = busbar_unit_scope::required_scope(CLAIM_A2A, op, self.bindings.scope_policy)
        else {
            return Decision::refuse(token, Refusal::new(ReasonCode::ScopeDenied));
        };
        match busbar_unit_scope::approve(self.grants, needed) {
            Err(_) => Decision::refuse(token, Refusal::new(ReasonCode::ScopeDenied)),
            Ok(()) => {
                // The plane says WHAT is being asked for; the resource travels with the approval so
                // the record names the agent rather than the method.
                let mut facts = ScopeFacts::default();
                if let Some(resource) = self.draft.resource {
                    let _ = facts.resources.push(resource);
                }
                Decision::proceed(token, facts)
            }
        }
    }

    fn admit(
        &self,
        token: &UnitToken<Admit>,
        admit: &AdmitToken<Admit>,
        _ctx: &UnitCtx,
        principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> Decision<Admit> {
        // The decision is the shipped release's, evaluated by the unit that owns it: pass one
        // checks every bucket of the pool-filtered chain and charges nothing, pass two charges. The
        // epoch is the pinned arrival epoch and never a fresh clock read, because a check and a
        // charge that read two different clocks are a check of one window and a charge in another.
        let chain = busbar_unit_admission::BucketChain::unchecked(Vec::new(), Vec::new());
        let mut unit = AdmissionUnit::new(
            self.bindings.door,
            self.bindings.pricer,
            self.bindings.pool,
            self.bindings.now,
        );
        unit.admit(&self.estimate(), principal, &chain, admit, token)
    }

    fn route(&self, token: &UnitToken<Route>, _ctx: &UnitCtx, meter: &AccrualMeter) -> Decision<Route> {
        // The record legs, in the plan's order, before anything is dialled. They are what says
        // whether this caller may see the task at all and what the agent's own name for it is, and
        // the hop that follows carries that name.
        let key = LegKey {
            id: "",
            parent: None,
            seq: 0,
            ts: self.bindings.now,
            terminal: matches!(self.draft.finish, FinishClass::Complete | FinishClass::Error),
        };
        match self.bindings.records.run_plan(&self.draft.legs, &key, &[]) {
            Err(LegError::UndeclaredOp { .. }) => {
                return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination))
            }
            Err(LegError::Store(_)) => {
                return Decision::refuse(token, Refusal::new(ReasonCode::DurabilityUnavailable))
            }
            Ok(results) => self.progress.lock().expect("progress lock").legs = results,
        }

        // The bytes the request carried accrue as the unit runs; the answer's bytes settle at the
        // metering step. The meter is the kernel's running total and the hold is applied to it at
        // the exit, which is why this is an accrual and not a posting.
        meter.accrue(self.draft.request_bytes);

        // A plan with no leg at all is an operation this plane does not carry: a refusal at the
        // routing step, not a panic and not a guess.
        if self.draft.legs.is_empty() {
            return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
        }

        let mut plan = RoutePlan::default();
        for leg in &self.draft.legs {
            let _ = plan.legs.push(Leg {
                destination: leg.destination,
            });
        }
        Decision::proceed(token, plan)
    }

    fn meter(
        &self,
        token: &UnitToken<Meter>,
        usage: &UsageToken,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
    ) -> Decision<Meter> {
        // One class, one line, and the quantity is one the plane already had in front of it: the
        // size of the document it read. There is no pointer to walk, so the locator carried the
        // value and this step folds it.
        let retained = RetainedLocatorValues::new(vec![LocatedValue {
            class: CLASS_BYTES,
            quantity: self.draft.response_bytes,
            source: busbar_caps::QuantitySource::Locator {
                direction: busbar_contract::ids::ClassDirection::Input,
                // The quantity was not at a pointer: it is the size of the document the plane just
                // read, which the locator carried by value precisely for this case.
                ptr: busbar_caps::LocatorPtr::new(""),
            },
        }]);
        // The kernel's own floor for this unit is what it moved on the way in. It is the tripwire
        // beside the located figure, never the charge.
        let kernel = KernelCounts::new(vec![busbar_unit_usage::KernelLine {
            class: CLASS_BYTES,
            quantity: self.draft.request_bytes,
            // A byte is a byte: the class's own quantity is the quantity, so the floor divides by
            // one. The plane declared that divisor and this is the declaration read back.
            source: busbar_caps::QuantitySource::KernelBytes { divisor: 1 },
        }]);
        // This protocol's answers name no lane — the lane is the agent's and the trust unit sealed
        // it — so only the legs that exist are declared. A declared leg absent at runtime is a
        // dispute; a leg absent by declaration is skipped, and that is the difference this says.
        let declared = LegDeclaration {
            admit_locator: false,
            verified: true,
            response: false,
        };
        match busbar_unit_usage::meter(
            &retained,
            &kernel,
            self.bindings.meter_policy.policy(),
            &declared,
            usage,
        ) {
            Err(_) => Decision::refuse(token, Refusal::new(ReasonCode::MeterDisputed)),
            Ok(metered) => {
                let mut progress = self.progress.lock().expect("progress lock");
                progress.metered = Some(self.draft.response_bytes);
                progress.disputed = metered.disputed();
                Decision::proceed(token, metered.usage)
            }
        }
    }

    fn audit(&self, token: &UnitToken<Audit>, _ctx: &UnitCtx, outcome: &Outcome) -> Decision<Audit> {
        let inputs = self.audit_inputs(*outcome, None);
        let record = {
            let mut durability = self.bindings.durability.lock().expect("durability lock");
            durability.record.seal(inputs, token)
        };
        self.progress.lock().expect("progress lock").audit_hash = Some(record.hash);
        // The class the plane named is the class that priced the unit, read back off the draft. A
        // different class here would be this file disputing the plane's own earlier answer.
        Decision::proceed(
            token,
            AuditFacts {
                op_class: self.draft.op.unwrap_or(ops::OP_MESSAGE_SEND),
                finish: self.draft.finish,
            },
        )
    }

    fn audit_refused(
        &self,
        token: &UnitToken<Audit>,
        _ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> Decision<Audit> {
        // The second door: a unit that never passed the first one, and was charged nothing. It is
        // sealed on the same chain, because a refusal is an event with a record of its own.
        let outcome = Outcome::Refused(refusal.step(), refusal.reason());
        let inputs = self.audit_inputs(outcome, None);
        let record = {
            let mut durability = self.bindings.durability.lock().expect("durability lock");
            durability.record.seal(inputs, token)
        };
        self.progress.lock().expect("progress lock").audit_hash = Some(record.hash);
        Decision::proceed(
            token,
            AuditFacts {
                op_class: self.draft.op.unwrap_or(ops::OP_MESSAGE_SEND),
                finish: FinishClass::Error,
            },
        )
    }

    fn encode(&self, token: &UnitToken<Encode>, _ctx: &UnitCtx, _outcome: &Outcome) -> Decision<Encode> {
        // The plane's encoders take the unit's arena, and this signature carries neither an arena
        // nor the plane's draft, so the bytes are written where the borrow lives and this step
        // reports what left. That is a statement about the seam, not a shortcut: a root that
        // allocated a second buffer here would be writing the wire format twice.
        let bytes = self.progress.lock().expect("progress lock").encoded;
        Decision::proceed(
            token,
            busbar_contract::wire::Frame {
                direction: busbar_contract::wire::Direction::Outbound,
                stream: busbar_contract::ids::StreamId(0),
                bytes: busbar_contract::bounded::SlabBytes::new(Arc::from(&[][..])),
                meta: busbar_contract::wire::FrameMeta {
                    bytes,
                    transport_units: None,
                    status: None,
                },
            },
        )
    }

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        let progress = self.progress.lock().expect("progress lock");
        Evidence {
            located: progress.metered,
            accrued_floor: self.draft.request_bytes,
            // Nothing is required of a card that does not price this class. With a card that does,
            // the located figure is what settles and the floor is the tripwire beside it.
            locator_required: false,
            terminal_error: matches!(self.draft.finish, FinishClass::Error),
            recovered: false,
            dispatched: !progress.legs.is_empty(),
            checkpointed: 0,
            variance: None,
            lane_mismatch: None,
            settle_record_lost: false,
            class: Some(CLASS_BYTES),
            // The fee's origin rule and the request slot's are the same rule: a client unit whose
            // verified set contains an agent draws one, and a push the agent sent draws none.
            upstream_candidate: self.draft.has_upstream(),
            fee: busbar_kernel::teller::FeeEvidence::default(),
        }
    }
}

/// Judge one destination's address, before any dial.
///
/// The guard's own published entry, `net::check_destination`, takes a
/// `busbar_contract::VerifiedDestination`, and the only constructor for one takes the contract's
/// kernel seal — which a composition root does not have and must not name. So the guard is reached
/// through the primitives it is itself written over, in the order it writes them: the metadata
/// denylist first, because a deployment's statement about which addresses exist to be reached at all
/// is answered before anything is resolved; then the scheme; then exactly one resolution, pinned.
/// Every judgement here is one of the guard's own functions, so this is the guard's ordering reached
/// a different way rather than a second opinion about addressing.
///
/// A destination that is not a network hop — a record leg, a client delivery, a kernel verb — has no
/// address and passes: there is nothing to have judged.
///
/// # Errors
///
/// The denylist blocked the host, the scheme is not one the policy admits, the name did not resolve,
/// or an answered address is internal or a cloud-metadata endpoint.
pub fn guard_destination(
    candidate: &DestinationFacts,
    resolver: &dyn Resolver,
    policy: GuardPolicy,
    denylist: &busbar_unit_trust::Denylist,
) -> Result<(), busbar_unit_trust::NetworkRefusal> {
    use busbar_unit_trust::net;
    let DestinationFacts::Upstream { address, .. } = candidate else {
        return Ok(());
    };
    let Some(authority) = address.authority() else {
        // A spawned program is not a network hop, so there is no address to have judged.
        return Ok(());
    };
    if let Some(host) = net::ssrf_blocked_host(
        authority,
        &denylist.allowed,
        denylist.allow_all,
        &denylist.blocked,
    ) {
        return Err(busbar_unit_trust::NetworkRefusal::MetadataDenied(host));
    }
    // An authority may be spelled as a URL or as a bare `host:port`, and which of the two a
    // deployment wrote is not a security question: both reach the same judgement.
    let (https, host, port) = match net::split_url(authority) {
        Ok((https, host, port, _path)) => {
            net::judge_scheme(authority, https, policy)
                .map_err(busbar_unit_trust::NetworkRefusal::Guard)?;
            (https, host, port)
        }
        Err(_) => {
            let (host, port) = split_authority(authority).ok_or_else(|| {
                busbar_unit_trust::NetworkRefusal::Guard(
                    busbar_unit_trust::AddressRefusal::NoHost(authority.to_string()),
                )
            })?;
            (true, host, port)
        }
    };
    net::resolve_and_pin(&host, port, https, resolver, policy)
        .map(|_pinned| ())
        .map_err(busbar_unit_trust::NetworkRefusal::Guard)
}

/// The trust unit's spelling of where a unit came from.
///
/// Two crates name the same origins and neither depends on the other. The mapping is written once,
/// here, where both are in scope, and it is total: an origin added to either would not compile. The
/// nested arm carries a parent key the destination rules never read, which is exactly why the two
/// spellings are not one type.
fn trust_origin(kind: busbar_caps::OriginKind) -> OriginKind {
    match kind {
        busbar_caps::OriginKind::Client => OriginKind::Client,
        busbar_caps::OriginKind::Provider => OriginKind::Provider,
        busbar_caps::OriginKind::Tick => OriginKind::Tick,
        busbar_caps::OriginKind::Arrival => OriginKind::Arrival,
        busbar_caps::OriginKind::Handshake => OriginKind::Handshake,
        busbar_caps::OriginKind::Bootstrap => OriginKind::Bootstrap,
        busbar_caps::OriginKind::Nested { .. } => OriginKind::Nested,
        busbar_caps::OriginKind::Delivery { .. } => OriginKind::Delivery,
    }
}

/// An authority written as a bare `host:port`, split into the two.
///
/// Only reached when the guard's own URL recogniser says the string carries no scheme. It is a
/// split and not a parse: everything that needs judging is judged by the guard's own functions, and
/// a host that survives this still goes through every one of them.
fn split_authority(authority: &str) -> Option<(String, u16)> {
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Some((host.to_string(), port.parse().ok()?)),
        _ => Some((
            authority.to_string(),
            busbar_unit_trust::net::default_port(true),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The audit action is the word the gating rig reads.
    ///
    /// The plugin crate spells the same word crate-privately, so the pin is against the rig, which
    /// is the surface an operator and the ledger both see. If either moves, this goes red rather
    /// than the audit chain quietly recording an action nothing queries.
    #[test]
    fn the_audit_action_is_the_word_the_rig_reads() {
        let rig = include_str!("../../../../scripts/a2a-subject/h2-audit-record.sh");
        assert!(
            rig.contains(AUDIT_ACTION),
            "the rig no longer asserts on {AUDIT_ACTION}"
        );
        assert_eq!(AUDIT_ACTION, "agent.call");
    }

    /// The resource kind is the plane's own word, and the rig reads the pair.
    #[test]
    fn the_resource_is_the_agent() {
        let rig = include_str!("../../../../scripts/a2a-subject/h2-audit-record.sh");
        assert!(rig.contains(&format!("{SCOPE_KIND_AGENT}:probe")));
    }

    /// Every operation class the plane declares gets a scope entry.
    ///
    /// Silence is a refusal, so a class the policy never mentions is unreachable. This is what
    /// makes "the deployment forgot one" a compile-time-shaped question rather than a support call.
    #[test]
    fn every_operation_class_is_declared() {
        let policy = scope_policy(crate::root::policy::ScopePolicy::new());
        assert_eq!(policy.len(), ops::OP_CLASSES.len());
        for op in ops::OP_CLASSES {
            assert!(
                busbar_unit_scope::PolicyView::required_scope(&policy, CLAIM_A2A, *op).is_some(),
                "{op} has no scope entry"
            );
        }
    }

    /// The projections are read-only and everything that moves a task is not.
    #[test]
    fn a_projection_is_read_only_and_a_send_is_not() {
        assert_eq!(declared_scope(ops::OP_TASK_GET), Scope::ReadOnly);
        assert_eq!(declared_scope(ops::OP_TASK_LIST), Scope::ReadOnly);
        assert_eq!(declared_scope(ops::OP_AGENT_CARD), Scope::ReadOnly);
        assert_eq!(declared_scope(ops::OP_MESSAGE_SEND), Scope::Full);
        assert_eq!(declared_scope(ops::OP_TASK_CANCEL), Scope::Full);
        assert_eq!(declared_scope(ops::OP_PUSH_EVENT), Scope::Full);
    }

    /// A read-only grant does not reach a send.
    #[test]
    fn a_read_only_grant_does_not_reach_a_send() {
        let held = Grants::of(Scope::ReadOnly);
        assert!(busbar_unit_scope::approve(held, declared_scope(ops::OP_TASK_GET)).is_ok());
        assert!(busbar_unit_scope::approve(held, declared_scope(ops::OP_MESSAGE_SEND)).is_err());
    }

    /// A leg naming an operation its schema does not declare is refused, not attempted.
    #[test]
    fn an_undeclared_operation_is_refused() {
        let legs = RecordLegs::new(Arc::new(RecordingStore::default()));
        let key = LegKey {
            id: "t-1",
            parent: None,
            seq: 0,
            ts: 0,
            terminal: false,
        };
        // The event chain is hash-linked, so it is append-and-read and never overwritten. Asking it
        // to accept a replacement is the exact mistake this refusal exists to catch.
        let err = legs
            .run(records::SCHEMA_TASK_EVENT, records::OP_PUT, &key, b"{}")
            .expect_err("an undeclared operation must not run");
        assert_eq!(
            err,
            LegError::UndeclaredOp {
                schema: records::SCHEMA_TASK_EVENT.as_str(),
                op: records::OP_PUT,
            }
        );
    }

    /// Every operation every schema declares reaches the store.
    ///
    /// Totality over the plane's own declaration: an operation declared with no arm here would be a
    /// leg the plan can name and nothing can run.
    #[test]
    fn every_declared_operation_reaches_the_store() {
        let store = Arc::new(RecordingStore::default());
        let legs = RecordLegs::new(store.clone());
        let key = LegKey {
            id: "t-1",
            parent: Some("p-1"),
            seq: 1,
            ts: 7,
            terminal: false,
        };
        for schema in records::RECORD_SCHEMAS {
            for op in records::operations_for(*schema) {
                legs.run(*schema, op, &key, b"{}")
                    .unwrap_or_else(|e| panic!("{schema} {op} did not run: {e:?}"));
            }
        }
        // Four schemas, and every one of them was reached under its own name.
        let seen = store.kinds();
        for schema in records::RECORD_SCHEMAS {
            assert!(seen.contains(&schema.as_str().to_string()), "{schema} unreached");
        }
    }

    /// The four schemas this plane declares are the four the conversion table names.
    #[test]
    fn the_four_schemas_are_the_planes_own() {
        let names: Vec<&str> = records::RECORD_SCHEMAS.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), 4);
        assert!(names.contains(&records::SCHEMA_PUSH_CONFIG.as_str()));
        assert!(names.contains(&records::SCHEMA_PIN.as_str()));
    }

    /// A plan's record legs run in the plan's own order and its upstream leg is left alone.
    ///
    /// The order is load-bearing: a cancellation reads the row, hops, writes the row and appends
    /// the event. A run that reordered those would append an event for a state the row never
    /// reached, and the hop is not this binding's to make.
    #[test]
    fn a_plan_runs_its_record_legs_in_order_and_skips_the_hop() {
        let store = Arc::new(RecordingStore::default());
        let legs = RecordLegs::new(store.clone());
        let plan = vec![
            leg_record(records::SCHEMA_TASK, records::OP_GET),
            Leg {
                destination: DestinationFacts::Upstream {
                    transport: "http",
                    address: busbar_contract::UpstreamAddress::socket("agent.example:443"),
                    lane: LaneId::new("probe"),
                },
            },
            leg_record(records::SCHEMA_TASK, records::OP_PUT),
            leg_record(records::SCHEMA_TASK_EVENT, records::OP_APPEND),
        ];
        let key = LegKey {
            id: "t-1",
            parent: Some("t-1"),
            seq: 1,
            ts: 3,
            terminal: true,
        };
        let results = legs.run_plan(&plan, &key, b"{}").expect("the legs run");
        assert_eq!(results.len(), 3, "the hop is not a record leg");
        assert_eq!(
            store.calls(),
            vec![
                format!("get {}", records::SCHEMA_TASK),
                format!("put {}", records::SCHEMA_TASK),
                format!("append {}", records::SCHEMA_TASK_EVENT),
            ]
        );
    }

    /// A store that refuses stops the plan at the leg that refused.
    #[test]
    fn a_refusing_store_stops_the_plan() {
        let legs = RecordLegs::new(Arc::new(RefusingStore));
        let plan = vec![leg_record(records::SCHEMA_TASK, records::OP_PUT)];
        let key = LegKey {
            id: "t-1",
            parent: None,
            seq: 0,
            ts: 0,
            terminal: false,
        };
        assert!(matches!(
            legs.run_plan(&plan, &key, b"{}"),
            Err(LegError::Store(_))
        ));
    }

    /// A record leg carries no lane, so it never enters the sealed set.
    ///
    /// Not an exclusion — a record is reached through the plan, not through the pool walk — and the
    /// distinction matters because an excluded lane is one the walk skipped and a record leg was
    /// never a lane at all.
    #[test]
    fn a_record_leg_is_not_priced_on_a_lane() {
        let record = DestinationFacts::PlaneRecord {
            schema: records::SCHEMA_TASK,
            op: records::OP_GET,
        };
        assert!(record.lane().is_none());
        let upstream = DestinationFacts::Upstream {
            transport: "http",
            address: busbar_contract::UpstreamAddress::socket("agent.example:443"),
            lane: LaneId::new("probe"),
        };
        assert_eq!(upstream.lane(), Some(LaneId::new("probe")));
    }

    /// A draft whose plan reaches an agent draws the fee; one that only touches records does not.
    #[test]
    fn only_a_hop_to_an_agent_carries_the_fee() {
        let mut draft = draft(ops::OP_TASK_LIST);
        draft.destination = DestinationFacts::PlaneRecord {
            schema: records::SCHEMA_TASK,
            op: records::OP_SCAN,
        };
        draft.legs = vec![leg_record(records::SCHEMA_TASK, records::OP_SCAN)];
        assert!(!draft.has_upstream());

        let mut sending = draft.clone();
        sending.destination = DestinationFacts::Upstream {
            transport: "http",
            address: busbar_contract::UpstreamAddress::socket("agent.example:443"),
            lane: LaneId::new("probe"),
        };
        assert!(sending.has_upstream());
    }

    /// The four endings map one for one onto the audit unit's own four.
    #[test]
    fn every_ending_has_an_audited_spelling() {
        assert_eq!(
            audit_finish(FinishClass::Complete),
            busbar_unit_audit::FinishClass::Complete
        );
        assert_eq!(
            audit_finish(FinishClass::TurnComplete),
            busbar_unit_audit::FinishClass::TurnComplete
        );
        assert_eq!(
            audit_finish(FinishClass::Partial),
            busbar_unit_audit::FinishClass::Partial
        );
        assert_eq!(
            audit_finish(FinishClass::Error),
            busbar_unit_audit::FinishClass::Error
        );
    }

    /// A record leg has no address, so the guard has nothing to have judged and says so.
    #[test]
    fn a_record_leg_is_not_a_network_hop() {
        let resolver = FixedResolver(vec![]);
        assert!(guard_destination(
            &DestinationFacts::PlaneRecord {
                schema: records::SCHEMA_TASK,
                op: records::OP_GET,
            },
            &resolver,
            GuardPolicy::default(),
            &busbar_unit_trust::Denylist::default(),
        )
        .is_ok());
    }

    /// A cloud-metadata endpoint is refused, and it is refused whatever the deployment opted into.
    ///
    /// An operator saying "this agent is on our internal network" has said nothing about the address
    /// whose whole value to an attacker is that it hands out credentials to anyone inside. The two
    /// arms are separate in the guard for exactly this reason and must not be merged.
    #[test]
    fn a_metadata_endpoint_is_refused_even_when_private_addressing_is_allowed() {
        let resolver = FixedResolver(vec!["169.254.169.254".parse().expect("an address")]);
        let permissive = GuardPolicy {
            allow_private: true,
            allow_plaintext: true,
            ..GuardPolicy::default()
        };
        let refusal = guard_destination(
            &upstream("http://metadata.google.internal/"),
            &resolver,
            permissive,
            &busbar_unit_trust::Denylist::default(),
        )
        .expect_err("a metadata endpoint is not reachable");
        assert!(matches!(
            refusal,
            busbar_unit_trust::NetworkRefusal::MetadataDenied(_)
        ));
    }

    /// A private address is refused by default and reachable only when the deployment said so.
    ///
    /// Both halves matter: the default is what a deployment that wrote nothing gets, and the opt-in
    /// is what the conformance rig's own loopback agent needs.
    #[test]
    fn a_private_address_needs_the_operators_word() {
        let resolver = FixedResolver(vec!["127.0.0.1".parse().expect("an address")]);
        let dest = upstream("http://agent.internal:8080/");
        assert!(guard_destination(
            &dest,
            &resolver,
            GuardPolicy::default(),
            &busbar_unit_trust::Denylist::default(),
        )
        .is_err());
        let opted_in = GuardPolicy {
            allow_private: true,
            ..GuardPolicy::default()
        };
        assert!(guard_destination(
            &dest,
            &resolver,
            opted_in,
            &busbar_unit_trust::Denylist::default(),
        )
        .is_ok());
    }

    /// A name that answers nothing is refused, and it is refused before anything is dialled.
    #[test]
    fn a_name_that_answers_nothing_is_refused() {
        let resolver = FixedResolver(vec![]);
        assert!(guard_destination(
            &upstream("https://agent.example/"),
            &resolver,
            GuardPolicy::default(),
            &busbar_unit_trust::Denylist::default(),
        )
        .is_err());
    }

    /// A public address over TLS is reached.
    #[test]
    fn a_public_address_over_tls_is_reached() {
        let resolver = FixedResolver(vec!["93.184.216.34".parse().expect("an address")]);
        assert!(guard_destination(
            &upstream("https://agent.example/"),
            &resolver,
            GuardPolicy::default(),
            &busbar_unit_trust::Denylist::default(),
        )
        .is_ok());
    }

    /// A bare `host:port` reaches the same judgement a URL does.
    #[test]
    fn a_bare_authority_is_judged_like_a_url() {
        let resolver = FixedResolver(vec!["127.0.0.1".parse().expect("an address")]);
        assert!(guard_destination(
            &upstream("agent.internal:8080"),
            &resolver,
            GuardPolicy::default(),
            &busbar_unit_trust::Denylist::default(),
        )
        .is_err());
    }

    /// Every origin has a spelling on the trust unit's side.
    #[test]
    fn every_origin_has_a_trust_side_spelling() {
        use busbar_caps::OriginKind as K;
        assert_eq!(trust_origin(K::Client), OriginKind::Client);
        assert_eq!(trust_origin(K::Provider), OriginKind::Provider);
        assert_eq!(trust_origin(K::Tick), OriginKind::Tick);
        assert_eq!(trust_origin(K::Arrival), OriginKind::Arrival);
        assert_eq!(trust_origin(K::Handshake), OriginKind::Handshake);
        assert_eq!(trust_origin(K::Bootstrap), OriginKind::Bootstrap);
        let parent = busbar_contract::ids::UnitKey::new(1);
        assert_eq!(trust_origin(K::Nested { parent }), OriginKind::Nested);
        assert_eq!(trust_origin(K::Delivery { parent }), OriginKind::Delivery);
    }

    /// The origin gate over this plane's two destination kinds, read off the unit rather than
    /// restated.
    ///
    /// Both of this plane's kinds are reachable by a caller and by an agent's push — which is what
    /// makes the push path run all the same steps as a request — and neither is reachable by an
    /// arrival, which has not got as far as a plane. The one asymmetry is the hop: an agent pushing
    /// to this node does not get to make this node dial out.
    #[test]
    fn the_origin_gate_over_this_planes_kinds() {
        let record = DestinationFacts::PlaneRecord {
            schema: records::SCHEMA_TASK,
            op: records::OP_GET,
        };
        let hop = upstream("https://agent.example/");
        assert!(kind_permitted(OriginKind::Client, &record));
        assert!(kind_permitted(OriginKind::Client, &hop));
        assert!(kind_permitted(OriginKind::Provider, &record));
        assert!(!kind_permitted(OriginKind::Provider, &hop));
        assert!(!kind_permitted(OriginKind::Arrival, &record));
        assert!(!kind_permitted(OriginKind::Arrival, &hop));
    }

    // ── fixtures ────────────────────────────────────────────────────────────────────────────────

    /// One upstream destination at an authority.
    fn upstream(authority: &'static str) -> DestinationFacts {
        DestinationFacts::Upstream {
            transport: "http",
            address: busbar_contract::UpstreamAddress::socket(authority),
            lane: LaneId::new("probe"),
        }
    }

    /// A resolver that answers the same addresses for every name.
    ///
    /// Resolution is an input to the guard and never an ambient fact, which is what makes a guard
    /// test a test rather than a network call.
    struct FixedResolver(Vec<std::net::IpAddr>);

    impl Resolver for FixedResolver {
        fn resolve(&self, _host: &str) -> Result<Vec<std::net::IpAddr>, String> {
            Ok(self.0.clone())
        }
    }


    /// One record leg of a plan.
    fn leg_record(schema: RecordSchemaId, op: &'static str) -> Leg {
        Leg {
            destination: DestinationFacts::PlaneRecord { schema, op },
        }
    }

    /// A draft carrying the shape one served request has.
    fn draft(op: OpClassId) -> A2aDraft {
        A2aDraft {
            op: Some(op),
            narrowing: Some("bearer"),
            declared_schemes: &["bearer"],
            from_session: false,
            credential: None,
            expected_aud: None,
            destination: DestinationFacts::Upstream {
                transport: "http",
                address: busbar_contract::UpstreamAddress::socket("agent.example:443"),
                lane: LaneId::new("probe"),
            },
            resource: Some(ResourceLocator {
                kind: SCOPE_KIND_AGENT,
                name: "probe",
            }),
            legs: Vec::new(),
            request_bytes: 128,
            response_bytes: 256,
            finish: FinishClass::Complete,
            streaming: false,
            arrival: ArrivalRecord {
                source: "127.0.0.1:1".to_string(),
                port: 8080,
                alpn: None,
                sni: None,
                peer_cert: None,
                transport_chain: vec!["tcp", "http"],
            },
        }
    }

    /// The eight governance methods the store contract requires and this file's legs never touch.
    ///
    /// Written once as a macro rather than twice by hand: what these fixtures exist to exercise is
    /// the record path, and a copy of the key and usage surface in each of them would be eighty
    /// lines saying nothing about the thing under test. Every one is empty, which is exactly what a
    /// store that keeps no governance rows does.
    macro_rules! no_governance_rows {
        () => {
            fn put_key(&self, _key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
                Ok(())
            }
            fn get_key(&self, _id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
                Ok(None)
            }
            fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
                Ok(Vec::new())
            }
            fn delete_key(&self, _id: &str) -> busbar_api::StoreResult<()> {
                Ok(())
            }
            fn get_usage(
                &self,
                _bucket_id: &str,
                _window_start: u64,
            ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
                Ok(busbar_api::UsageLedger::default())
            }
            fn put_usage(
                &self,
                _bucket_id: &str,
                _window_start: u64,
                _ledger: &busbar_api::UsageLedger,
            ) -> busbar_api::StoreResult<()> {
                Ok(())
            }
            fn add_metering(&self, _delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
                Ok(())
            }
            fn list_metering(
                &self,
                _bucket: u64,
            ) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
                Ok(Vec::new())
            }
        };
    }

    /// A store that remembers which kind-tagged operation it was asked for.
    #[derive(Default)]
    struct RecordingStore {
        calls: Mutex<Vec<String>>,
    }

    impl RecordingStore {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("calls lock").clone()
        }

        fn kinds(&self) -> Vec<String> {
            self.calls()
                .iter()
                .filter_map(|c| c.split_once(' ').map(|(_, k)| k.to_string()))
                .collect()
        }

        fn note(&self, what: &str, kind: &str) {
            self.calls
                .lock()
                .expect("calls lock")
                .push(format!("{what} {kind}"));
        }
    }

    impl busbar_api::Store for RecordingStore {
        no_governance_rows!();

        fn upsert_plane_record(&self, record: &busbar_api::PlaneRecord) -> busbar_api::StoreResult<()> {
            self.note("put", &record.kind);
            Ok(())
        }

        fn get_plane_record(
            &self,
            kind: &str,
            _id: &str,
        ) -> busbar_api::StoreResult<Option<Vec<u8>>> {
            self.note("get", kind);
            Ok(None)
        }

        fn append_plane_record(&self, record: &busbar_api::PlaneRecord) -> busbar_api::StoreResult<()> {
            self.note("append", &record.kind);
            Ok(())
        }

        fn list_plane_records(
            &self,
            kind: &str,
            _selector: &busbar_api::PlaneSelector,
        ) -> busbar_api::StoreResult<Vec<Vec<u8>>> {
            self.note("scan", kind);
            Ok(Vec::new())
        }

        fn delete_plane_record(&self, kind: &str, _id: &str) -> busbar_api::StoreResult<()> {
            self.note("delete", kind);
            Ok(())
        }

        fn redeem_plane_token(
            &self,
            kind: &str,
            _token: &str,
            _expires_at: u64,
            _now: u64,
        ) -> busbar_api::StoreResult<bool> {
            self.note("redeem", kind);
            Ok(true)
        }
    }

    /// A store that refuses everything, so a failure on the record path is a testable event.
    struct RefusingStore;

    impl busbar_api::Store for RefusingStore {
        no_governance_rows!();

        fn upsert_plane_record(
            &self,
            _record: &busbar_api::PlaneRecord,
        ) -> busbar_api::StoreResult<()> {
            Err(busbar_api::StoreError("the store is unavailable".to_string()))
        }
    }
}
