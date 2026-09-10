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

use busbar_api::{PlaneDisposition, PlaneRecord, PlaneSelector, Store as AbiStore, StoreError};
use busbar_caps::{
    Admit, AdmitToken, Approve, Arrival, ArrivalRecord, Audit, AuditFacts, Authenticate, Decision,
    Decode, Encode, Meter, Outcome, PrincipalId, ReasonCode, Refusal, Route, RoutePlan, ScopeFacts,
    TrustToken, UnitToken, UsageToken, VerifiedDestination, Verify,
};
use busbar_contract::dest::{DestinationFacts, Leg};
use busbar_contract::ids::{ClaimKey, LaneId, OpClassId, RecordSchemaId};
use busbar_contract::unit::{FinishClass, ResourceLocator};
use busbar_kernel::slice::{DoorGrant, GroupLeaseSlip};
use busbar_kernel::teller::{AccrualMeter, Evidence, UnitCtx, Units};
use busbar_plane_a2a::{ops, records};
use busbar_unit_admission::{Admission as _, AdmissionUnit, CellStore, Door, Estimate, Pricer};
use busbar_unit_audit::{Audit as _, AuditInputs};
use busbar_unit_auth::{Auth, AuthRequest};
use busbar_unit_scope::{Grants, Scope};
use busbar_unit_trust::{
    kind_permitted, kind_rule_passes, BreakerQuery, BreakerView, GuardPolicy, KindFacts,
    OriginKind, PoolView, Resolver,
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
    /// The body the leg carried is longer than one record may be.
    ///
    /// Its own variant and not a store failure, because nothing failed and nothing was attempted:
    /// the ceiling is the architecture's, the kernel enforces it before the sink is touched, and a
    /// caller told "the store is unavailable" would retry a write that can never succeed.
    Oversize {
        /// How many bytes the leg offered.
        bytes: usize,
        /// How many a record may hold.
        cap: usize,
    },
    /// The store refused or failed.
    Store(String),
    /// A capability leg asked whether a token was still live and the answer was NO.
    ///
    /// Its own variant and not a `Store` failure, because nothing failed: the store answered, and
    /// the answer was that this token no longer authorises anything. Folding the two together would
    /// render a revoked token as an outage — telling the operator to go and look at a database that
    /// is working perfectly, and telling the caller to retry something that will never succeed.
    ///
    /// It stops the plan where it is raised, which is why the plane puts the check FIRST: the legs
    /// that record the move have not run, so a callback refused here writes nothing, appends no
    /// provenance event and leaves the stored task exactly as it was.
    TokenNotLive,
}

/// What one record leg came back with.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LegResult {
    /// The body a read returned, where the leg read one.
    pub body: Option<Vec<u8>>,
    /// The bodies a scan returned, oldest first for an append-only kind.
    pub bodies: Vec<Vec<u8>>,
    /// Whether the callback token the leg checked is STILL LIVE. A token whose task has finished, or
    /// whose deadline has passed, answers `false`.
    ///
    /// It is a liveness reading and not a redemption, so asking twice answers the same twice: one
    /// task legitimately receives several callbacks, and a reading that changed under the question
    /// would refuse every one after the first.
    pub live: bool,
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
    ///
    /// It is also the NOW a liveness check is judged at, and it is the arrival epoch the root pinned
    /// rather than a fresh clock read — the same reading every other step of this unit is judged
    /// against, so a token cannot be live for one leg of a plan and lapsed for the next.
    pub ts: u64,
    /// The instant past which a capability carried by this key is dead, whatever else is true.
    ///
    /// Separate from [`LegKey::ts`] and that separation is the fix: passing the same value as both
    /// the deadline and the clock asks "is now past now", which is false for every token ever
    /// presented, so every token verified. A deadline has to be a different number from the clock it
    /// is compared against or it is not a deadline.
    pub expires_at: u64,
    /// Whether retention may drop the row once it is older than a cutoff.
    ///
    /// Also what makes the revocation leg bite: a push callback that moved its task to an ending is
    /// the callback after which the task's token must stop working, and this is the plan's one
    /// reading of whether that happened.
    pub terminal: bool,
}

/// The plane's durable state, reached through the published store protocol and nothing else.
///
/// The four schemas this plane declares map onto the store's eight kind-tagged operations one for
/// one. There is no second path: a plane holds no store, and a unit knows no schema, so the mapping
/// belongs exactly here and nowhere else.
pub struct RecordLegs {
    store: Arc<dyn AbiStore>,
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
    pub fn new(store: Arc<dyn AbiStore>) -> Self {
        RecordLegs { store }
    }

    /// Run one leg.
    ///
    /// The three checks — the schema is declared, the operation is within that schema's declared
    /// operations, the body is within the record ceiling — are NOT made here. They are the kernel's,
    /// in [`busbar_kernel::pump::run_record_leg`], and this method is the call onto it. There used to
    /// be a second copy of the first check in this file, which is one copy too many for a rule the
    /// architecture states once: a leg is validated in the one place a leg is run.
    ///
    /// # Errors
    ///
    /// The schema does not declare the operation, the body is oversize, or the store refused.
    pub fn run(
        &self,
        schema: RecordSchemaId,
        op: &'static str,
        key: &LegKey<'_>,
        body: &[u8],
    ) -> Result<LegResult, LegError> {
        busbar_kernel::pump::run_record_leg(self, &Schemas, schema, op, &key.as_kernel(), body)
            .map(LegResult::from)
            .map_err(LegError::from)
    }

    /// One already-validated operation, mapped onto the published store protocol's eight
    /// kind-tagged verbs.
    ///
    /// Every arm is a single call onto the store, and the mapping is BYTE-FOR-BYTE the one this file
    /// has always made: the same verb, with the same arguments, in the same order. What moved out of
    /// it is the validation, not the dispatch, because the dispatch is the vocabulary of this plane
    /// and the published protocol underneath it — which is exactly the half a composition root owns.
    fn perform_op(
        &self,
        schema: RecordSchemaId,
        op: &'static str,
        key: &LegKey<'_>,
        body: &[u8],
    ) -> Result<LegResult, LegError> {
        let kind = schema.as_str();
        let fail = |e: StoreError| LegError::Store(e.0);
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
                    Some(parent) => PlaneSelector::Parent(parent.to_string()),
                    None => PlaneSelector::All,
                };
                Ok(LegResult {
                    bodies: self
                        .store
                        .list_plane_records(kind, &selector)
                        .map_err(fail)?,
                    ..LegResult::default()
                })
            }
            records::OP_DELETE => {
                self.store.delete_plane_record(kind, key.id).map_err(fail)?;
                Ok(LegResult::default())
            }
            records::OP_VERIFY_LIVE => Ok(LegResult {
                // THE DEADLINE AND THE CLOCK ARE TWO DIFFERENT NUMBERS. This leg used to redeem, and
                // it passed `key.ts` as BOTH the expiry and the now — which asks the store whether
                // now is past now. It never is, so the answer was yes for every token ever presented,
                // and a callback token captured off the wire kept working for as long as the process
                // lived. The deadline is the task's, carried on the key; the now is the arrival epoch
                // the root pinned.
                //
                // Nothing is spent. One task draws several callbacks — `working`, `input-required`,
                // `completed` — and all of them are the same capability being used for what it is
                // for. What ends the token is the task ending, which `OP_REVOKE` below records.
                live: self
                    .store
                    .plane_token_live(kind, key.id, key.expires_at, key.ts)
                    .map_err(fail)?,
                ..LegResult::default()
            }),
            records::OP_REVOKE => {
                // ONLY on the update that made the task terminal, and inert on every other. A task
                // that moved to `working` has more to report and must keep its token; a task that
                // moved to `completed` has nothing left to say, so the capability that spoke for it
                // is retired here and the next callback carrying it fails the check above.
                //
                // A no-op is a successful leg, not a skipped one: the plan is fixed and every leg in
                // it runs, so "there was nothing to revoke yet" has to be an ordinary answer rather
                // than an absence the caller has to interpret.
                if key.terminal {
                    self.store.delete_plane_record(kind, key.id).map_err(fail)?;
                }
                Ok(LegResult::default())
            }
            other => Err(LegError::UndeclaredOp {
                schema: kind,
                op: other,
            }),
        }
    }

    /// The neutral envelope one write goes into.
    fn record(&self, kind: &str, key: &LegKey<'_>, body: &[u8]) -> PlaneRecord {
        PlaneRecord {
            kind: kind.to_string(),
            id: key.id.to_string(),
            parent: key.parent.map(str::to_string),
            seq: key.seq,
            ts: key.ts,
            disposition: if key.terminal {
                PlaneDisposition::Terminal
            } else {
                PlaneDisposition::Active
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
    pub fn run_plan(
        &self,
        legs: &[Leg],
        key: &LegKey<'_>,
        body: &[u8],
    ) -> Result<Vec<LegResult>, LegError> {
        busbar_kernel::pump::run_record_plan(self, &Schemas, legs, &key.as_kernel(), body)
            .map(|answers| answers.into_iter().map(LegResult::from).collect())
            .map_err(LegError::from)
    }
}

/// The same legs, over a store that publishes the CONTRACT's three record verbs.
///
/// [`RecordLegs`] above binds to `AbiStore` and is the 1.5.5 path: eight kind-tagged
/// operations, byte for byte what the previous release's callers drive. This one binds to
/// `busbar_contract::kinds::RecordSink` — `record_put`, `record_get`, `record_scan` — which is what
/// a store-kind plugin actually implements, and it is the binding a deployment that named a
/// contract-native backend runs on.
///
/// TWO BINDINGS AND ONE RUNNER. Both go through [`busbar_kernel::pump::run_record_leg`], so the
/// three checks happen once and in the kernel for both; what differs is only which verbs the sink
/// publishes. That is the composition root's half and nobody else's — the plane holds no store, the
/// backend names no kernel, and this file is the only thing holding both.
pub struct SinkRecordLegs {
    sink: Arc<dyn busbar_contract::kinds::RecordSink>,
}

impl std::fmt::Debug for SinkRecordLegs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SinkRecordLegs")
    }
}

impl SinkRecordLegs {
    /// Bind the legs to a record sink.
    #[must_use]
    pub fn new(sink: Arc<dyn busbar_contract::kinds::RecordSink>) -> Self {
        SinkRecordLegs { sink }
    }

    /// Run one leg. The validation is the kernel's, exactly as it is for [`RecordLegs::run`].
    ///
    /// # Errors
    ///
    /// The schema or the operation is undeclared, the body is oversize, or the sink refused.
    pub fn run(
        &self,
        schema: RecordSchemaId,
        op: &'static str,
        key: &LegKey<'_>,
        body: &[u8],
    ) -> Result<LegResult, LegError> {
        busbar_kernel::pump::run_record_leg(self, &Schemas, schema, op, &key.as_kernel(), body)
            .map(LegResult::from)
            .map_err(LegError::from)
    }

    /// The key a record is stored under, as one opaque byte string.
    ///
    /// The contract's verbs key on BYTES, and the columns a leg carries have to be folded into them
    /// without losing the two properties the plane reads back: an append-only child is keyed by its
    /// parent AND its sequence, so a second append never replaces the first, and the sequence is
    /// big-endian so the sink's key order IS sequence order. A top-level record is keyed by its id
    /// alone, so a put replaces exactly what the plane asked it to.
    ///
    /// The NUL separator is what keeps a parent's prefix from reaching into a longer parent's rows:
    /// `t-1` and `t-10` are different chains, and a prefix of `t-1` without the terminator would
    /// scan both.
    fn sink_key(key: &LegKey<'_>) -> Vec<u8> {
        match key.parent {
            Some(parent) => {
                let mut bytes = Vec::with_capacity(parent.len() + 9);
                bytes.extend_from_slice(parent.as_bytes());
                bytes.push(0);
                bytes.extend_from_slice(&key.seq.to_be_bytes());
                bytes
            }
            None => key.id.as_bytes().to_vec(),
        }
    }
}

/// The contract's record sink, presented to the kernel as the sink a record leg lands in.
///
/// Three verbs answer four of this plane's operations, and the other three are refused rather than
/// approximated. `delete`, `revoke` and `verify_live` are not expressible in `put`/`get`/`scan`: a
/// delete faked as a put of an empty body is a row that still reads back, and a liveness answer
/// invented here would be this file deciding a capability question that belongs to the backend that
/// holds the deadline. A schema whose plane declares those operations needs a backend that publishes
/// them, and saying so is the honest answer — the kernel carries the sink's own words through.
impl busbar_kernel::pump::RecordStore for SinkRecordLegs {
    fn perform(
        &self,
        schema: RecordSchemaId,
        op: &'static str,
        key: &busbar_kernel::pump::RecordKey<'_>,
        body: &[u8],
    ) -> Result<busbar_kernel::pump::RecordAnswer, String> {
        let key = LegKey {
            id: key.id,
            parent: key.parent,
            seq: key.seq,
            ts: key.ts,
            expires_at: key.expires_at,
            terminal: key.terminal,
        };
        let at = SinkRecordLegs::sink_key(&key);
        let fail = |e: busbar_contract::kinds::StoreError| e.to_string();
        match op {
            records::OP_GET => Ok(busbar_kernel::pump::RecordAnswer {
                body: self
                    .sink
                    .record_get(schema, &at)
                    .map_err(fail)?
                    .map(|v| v.as_slice().to_vec()),
                ..busbar_kernel::pump::RecordAnswer::default()
            }),
            // A put REPLACES under its key and an append cannot, because an append's key carries its
            // own sequence. One verb, two operations, and the difference is in the key rather than
            // in a second write path that could drift from the first.
            records::OP_PUT | records::OP_APPEND => {
                let value = busbar_contract::kinds::RecordBytes::new(body.to_vec())
                    // Unreachable: the kernel checked this body against the SAME ceiling
                    // (`busbar_contract::bounded::MAX_RECORD_BYTES`) before calling. Carried as a
                    // sink refusal rather than unwrapped, because a panic on the request path is
                    // never the right answer to a case that says the check above stopped working.
                    .map_err(|bytes| format!("record body of {bytes} bytes is over the ceiling"))?;
                self.sink.record_put(schema, &at, &value).map_err(fail)?;
                Ok(busbar_kernel::pump::RecordAnswer::default())
            }
            records::OP_SCAN => {
                // A scan of an append-only schema is narrowed to one parent; a scan of a top-level
                // schema is the whole schema. Which of the two is carried by the leg's key, not
                // guessed from the schema — the same reading `RecordLegs` makes above.
                let prefix = match key.parent {
                    Some(parent) => {
                        let mut bytes = parent.as_bytes().to_vec();
                        bytes.push(0);
                        bytes
                    }
                    None => Vec::new(),
                };
                Ok(busbar_kernel::pump::RecordAnswer {
                    bodies: self
                        .sink
                        // UNBOUNDED ON PURPOSE. The published path's `list_plane_records` answers a
                        // selection in full, and a plan that read a truncated one would act on a
                        // history missing its most recent rows without anything saying so. The bound
                        // that exists is the ceiling on each record, which the kernel already
                        // enforced; a smaller number here would be this file inventing a limit the
                        // plane never asked for.
                        .record_scan(schema, &prefix, u32::MAX)
                        .map_err(fail)?
                        .into_iter()
                        .map(|(_, v)| v.as_slice().to_vec())
                        .collect(),
                    ..busbar_kernel::pump::RecordAnswer::default()
                })
            }
            other => Err(format!(
                "this store publishes the record verbs only; `{other}` on `{}` needs a backend that declares it",
                schema.as_str()
            )),
        }
    }
}

/// This plane's record schemas and their operation tables, as the kernel reads them.
///
/// The declaration is the plane crate's and is not restated: a schema that gains or loses an
/// operation changes what the kernel refuses without anything here being edited.
struct Schemas;

impl busbar_kernel::pump::RecordSchemas for Schemas {
    fn schemas(&self) -> &'static [RecordSchemaId] {
        records::RECORD_SCHEMAS
    }

    fn operations_for(&self, schema: RecordSchemaId) -> &'static [&'static str] {
        records::operations_for(schema)
    }
}

/// The published store protocol, presented to the kernel as the sink a record leg lands in.
///
/// This is the whole of what the composition root still owns on this path: the kernel validated the
/// leg, and this turns the operation the plane spelled into the store verb that performs it.
impl busbar_kernel::pump::RecordStore for RecordLegs {
    fn perform(
        &self,
        schema: RecordSchemaId,
        op: &'static str,
        key: &busbar_kernel::pump::RecordKey<'_>,
        body: &[u8],
    ) -> Result<busbar_kernel::pump::RecordAnswer, String> {
        let key = LegKey {
            id: key.id,
            parent: key.parent,
            seq: key.seq,
            ts: key.ts,
            expires_at: key.expires_at,
            terminal: key.terminal,
        };
        match self.perform_op(schema, op, &key, body) {
            Ok(result) => Ok(busbar_kernel::pump::RecordAnswer {
                body: result.body,
                bodies: result.bodies,
                // ONLY the liveness question answers the liveness question. Every other operation
                // says nothing about a capability, and saying `Some(false)` for them would stop
                // every plan on its first write.
                live: (op == records::OP_VERIFY_LIVE).then_some(result.live),
            }),
            Err(LegError::Store(why)) => Err(why),
            // Unreachable in practice: `perform_op` is only ever reached through the kernel's own
            // validation, so the operation it is handed is one this schema declared. Carried as a
            // sink failure rather than unwrapped, because a panic on the request path is never the
            // right answer to a case that says the check above it stopped working.
            Err(other) => Err(format!("{other:?}")),
        }
    }
}

impl LegKey<'_> {
    /// The same key, in the kernel's spelling.
    ///
    /// Two structs and one conversion rather than one struct, because the kernel's is the one every
    /// plane's record legs are carried on and this one is this file's own published shape, which the
    /// plane's tests and its callers already name.
    fn as_kernel(&self) -> busbar_kernel::pump::RecordKey<'_> {
        busbar_kernel::pump::RecordKey {
            id: self.id,
            parent: self.parent,
            seq: self.seq,
            ts: self.ts,
            expires_at: self.expires_at,
            terminal: self.terminal,
        }
    }
}

impl From<busbar_kernel::pump::RecordAnswer> for LegResult {
    fn from(answer: busbar_kernel::pump::RecordAnswer) -> Self {
        LegResult {
            body: answer.body,
            bodies: answer.bodies,
            // A leg that asked no liveness question is not a leg whose capability is dead: the
            // absent answer reads as `false` here exactly as it always did, and the only reader of
            // this field is the plan's own capability leg.
            live: answer.live.unwrap_or(false),
        }
    }
}

impl From<busbar_kernel::pump::RecordRefusal> for LegError {
    fn from(refusal: busbar_kernel::pump::RecordRefusal) -> Self {
        use busbar_kernel::pump::RecordRefusal as R;
        match refusal {
            // A schema no plane declared and an operation no schema declares are the same answer to
            // the caller — the plan named something that does not exist — and they were one variant
            // here before the kernel told the two apart. Kept as one so the refusal this plane
            // renders is unchanged.
            R::UndeclaredSchema { schema, op } | R::UndeclaredOp { schema, op } => {
                LegError::UndeclaredOp { schema, op }
            }
            R::Oversize { bytes, cap } => LegError::Oversize { bytes, cap },
            R::Sink(why) => LegError::Store(why),
            R::NotLive => LegError::TokenNotLive,
        }
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

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE PRODUCER
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// What the plane's own decode step said about one arrival, copied out by value.
///
/// ## Why this type exists at all
///
/// The plane answers `decode_ingress` with a `UnitDraft<'u>` whose every field BORROWS — from the
/// arena the context carries and from the frame the transport still owns. Neither outlives the call
/// the borrow was taken in. [`A2aDraft`] is by-value precisely so that it can, so something has to
/// carry the scalars across that boundary, and this is that something: the driver reads the plane's
/// answer ONCE, where the borrow is live, and copies out the handful of facts the ten steps go on to
/// need. A step that re-scanned the body to recover one of them would be doing the allocation the
/// arena exists to make impossible.
///
/// ## What is here and what is deliberately not
///
/// Only what the DECODE step and the TRANSPORT know. The destination, the resource, the legs and the
/// streaming flag are absent because the plane answers those from its own op-keyed tables, and
/// [`A2aDraft::from_decoded`] asks it rather than being told — one table, asked twice, never copied.
#[cfg(feature = "root-a2a-serve")]
#[derive(Debug, Clone, Default)]
pub struct Decoded {
    /// The operation class the plane recognised. `None` is a body this plane does not carry.
    pub op: Option<OpClassId>,
    /// The whole request document's length, which is what this plane prices its input on.
    pub request_bytes: u64,
    /// The credential the transport masked out of the frame, where one arrived.
    pub credential: Option<String>,
    /// The audience an audience-bound ingress requires.
    pub expected_aud: Option<String>,
    /// Whether the principal is the bound session's rather than these bytes'.
    pub from_session: bool,
    /// The scheme alternative the claim was narrowed to. `None` on the three open surfaces.
    pub narrowing: Option<&'static str>,
    /// The alternatives the matched claim declared. Empty on an open surface.
    pub declared_schemes: &'static [&'static str],
}

#[cfg(feature = "root-a2a-serve")]
impl A2aDraft {
    /// THE PRODUCTION PRODUCER: one arrival the plane has read, as the record the ten steps consume.
    ///
    /// This is the leg the root was missing. `A2aDraft` and [`A2aBindings`] described a unit of this
    /// plane precisely and completely, and nothing on any serving path built one — every construction
    /// in the workspace was a test's, which is the same sentence as "the plane's decode reaches no
    /// step". This function is that sentence removed.
    ///
    /// ## Every plane-owned field is ASKED, never restated
    ///
    /// The destination, the resource, the legs and the streaming flag come from
    /// `A2aPlane::{destination_for, resource_for, route_plan_for, streaming_for}` — the very tables
    /// the plane's own `verify`, `approve`, `route` and `audit` steps answer from. They are asked
    /// here rather than restated because a restatement is a second opinion: the root's producer and
    /// the kernel's steps would drift, and the one that drifted quietly is the one that reaches a
    /// customer. The plane's steps read those tables off a `Unit`, which only the kernel's seal can
    /// mint and which this file may not name; the tables themselves need no unit, which is why they
    /// are sayable here at all.
    ///
    /// ## What the ending has not happened yet
    ///
    /// `response_bytes` is zero and `finish` is [`FinishClass::Complete`]. Both are properties of an
    /// ANSWER, and at the moment an arrival is decoded there is not one: the metering step fills the
    /// first from the locator the plane's `meter` returns, and the audit step fills the second from
    /// the ending the loop reached. A producer that guessed either would be writing down a result
    /// before the unit ran.
    #[must_use]
    pub fn from_decoded(
        plane: &busbar_plane_a2a::A2aPlane,
        decoded: &Decoded,
        arrival: ArrivalRecord,
    ) -> Self {
        // ASKED, in all four cases, and asked of the plane. A body whose operation the plane did not
        // recognise names no agent, reaches no record and walks no leg — so it gets the destination
        // the plane itself calls unreachable, which the trust unit refuses, rather than a
        // destination this file invented for it.
        let destination = decoded
            .op
            .map_or_else(busbar_plane_a2a::A2aPlane::unreachable_destination, |op| {
                plane.destination_for(op)
            });
        let legs = decoded.op.map_or_else(Vec::new, |op| {
            plane.route_plan_for(op).legs.as_slice().to_vec()
        });
        let resource = decoded.op.and_then(|_| plane.resource_for());
        let streaming = decoded.op.is_some_and(|op| plane.streaming_for(op));
        A2aDraft {
            op: decoded.op,
            narrowing: decoded.narrowing,
            declared_schemes: decoded.declared_schemes,
            from_session: decoded.from_session,
            credential: decoded.credential.clone(),
            expected_aud: decoded.expected_aud.clone(),
            destination,
            resource,
            legs,
            request_bytes: decoded.request_bytes,
            // The answer has not been written yet; the metering and audit steps fill these two.
            response_bytes: 0,
            finish: FinishClass::Complete,
            streaming,
            arrival,
        }
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
    ops::OP_CLASSES.iter().fold(base, |policy, op| {
        policy.declaring(CLAIM_A2A, *op, declared_scope(*op))
    })
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE ONE SEAM THIS PLANE'S MOUNTED SURFACE IS REACHED THROUGH
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// THE SEAM IS NOT THIS PLANE'S, and that is why it is not defined here.
///
/// [`PlaneAnswer`] and [`MountDispatch`] used to be `A2aAnswer` and `A2aDispatch`, written in this
/// file because this was the first plane whose leg had a mount to reach. Nothing in either of them
/// was ever about A2A: the argument is an `OpClassId`, which every plane declares, and the answer is
/// a status, headers and bytes, which every surface writes. So when the MCP leg needed the same seam
/// the two types moved out to [`crate::root::transports`] — where [`PlaneLeg`] already is — rather
/// than being copied under a second pair of names. Two structs with the same three fields are two
/// things that can drift, and the first thing to drift between them would have been a difference
/// nobody meant.
///
/// Re-exported here rather than merely moved, so this plane's units read as one file.
///
/// [`PlaneLeg`]: crate::root::transports::PlaneLeg
pub use crate::root::transports::{MountDispatch, PlaneAnswer};

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
    /// The breaker the dialled kinds' rules are judged against. The same one the walk's own pre-walk
    /// filter reads, so a lane excluded for an open breaker is excluded once and identically.
    pub breaker: &'r dyn BreakerView,
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
    /// The buckets this caller is judged and charged against: its own attribution bucket, then the
    /// group its key is bound to, then that group's parent, to the root.
    ///
    /// BORROWED, never built here. A chain is a walk of the boot-resolved group table and its
    /// contents are owned strings; resolving one inside the admission step would put a fresh vector
    /// of them on the door's path for every single unit, for an answer that cannot change while the
    /// caller and the policy epoch stay the same. So the root resolves it once, where it resolves
    /// the caller, and every unit of that caller reads the same one.
    ///
    /// `None` is the fail-closed arm and NOT the uncapped one: it is a caller bound to a group this
    /// node's configuration does not have, whose caps therefore could not be read. A caller bound
    /// to no group at all — the ordinary posture for a deployment with no `groups:` section — has a
    /// perfectly good chain of one uncapped attribution bucket, and gets it.
    pub chain: Option<&'r busbar_unit_admission::BucketChain>,
    /// What the door prices a unit against.
    pub pricer: &'r Pricer,
    /// What the deployment's card charges for a byte of the priced document, in nano-units.
    ///
    /// The highest such price over the destinations this unit may reach, read out of the card once
    /// by the root rather than looked up per unit — the maximum for the reason the estimate's own
    /// documentation gives, and read here rather than in the admission step so the door never
    /// reaches a rate table. Zero on a deployment whose card prices this plane's byte class at
    /// nothing, which is a reservation carrying the flat fee alone and not a missing one.
    pub bytes_nanos: u64,
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
    /// HOW LONG A TASK'S CAPABILITIES MAY OUTLIVE ITS LAST MOVE, in seconds.
    ///
    /// The bound on the push callback token, and the answer to "what if the task never reaches an
    /// ending". Terminal revocation retires a token the moment its task finishes, but a backend that
    /// accepts a task and then goes silent forever would otherwise leave one live indefinitely — so
    /// there is a deadline as well, and the token is dead at whichever comes first.
    ///
    /// Read off the deployment rather than hard-coded at the leg, because it is the same question a
    /// deployment already answers about how long it keeps a task at all: a capability that outlives
    /// the row it names is a capability for nothing.
    pub task_ttl_secs: u64,
    /// THE SECOND CLOCK the audit record carries, pinned at the same arrival — a MONOTONIC reading,
    /// which is a different measurement from `now` above and not a second spelling of it.
    ///
    /// The record has two clocks because one of them can lie: a wall clock that is stepped by an
    /// operator, by NTP or by a leap second can hand two events of one unit timestamps that run
    /// backwards, and a reader cannot tell that from a unit whose steps genuinely ran out of order.
    /// The monotonic reading cannot go backwards, so it is what ORDERS the record and the wall
    /// reading is what DATES it. Fill this from the wall clock and the record has one clock written
    /// in two fields: it still dates correctly and it orders nothing at all, which is exactly the
    /// property the second field exists to provide.
    ///
    /// Supplied by the composition root from the node's own monotonic source and pinned once at
    /// arrival, the same shape the voice plane's node gives its units — a unit does not read clocks,
    /// and one that read this one here would be reading it per step rather than per unit.
    pub mono: u64,
    /// THE ONE WAY THIS UNIT REACHES THE SURFACE THAT ANSWERS ITS OPERATION.
    ///
    /// `None` is a unit that runs the ten steps and produces no bytes, which is exactly the posture
    /// every unit of this plane had before a mount existed: the loop decides, the exit reports zero
    /// bytes, and nothing is served. It is an `Option` rather than a required binding because that
    /// posture is a real one and not a missing source — a build without the serving switch composes
    /// no dispatch, and the boot assembly must not refuse for the absence of a thing it deliberately
    /// did not build.
    ///
    /// Bound per arrival, because a unit of this plane is. See [`MountDispatch`].
    pub dispatch: Option<&'r dyn MountDispatch>,
    /// The sealed origin the audit record is written under.
    ///
    /// Sealed by the kernel and carried here for the same reason the trust token is: `Origin::seal`
    /// takes the kernel's seal, and this is not the kernel. `UnitCtx` hands each step the origin's
    /// KIND, which is what the destination rules read; the sealed value is what the record needs.
    pub origin: busbar_caps::Origin,
}

/// A lock this plane holds, taken the way the root takes its locks.
///
/// A poisoned lock is read through rather than refused. The panic that poisoned it happened
/// somewhere else, and what is behind these two locks is written once per field and then read — so
/// a reader after a panic sees a prefix of the truth rather than a corrupted one. The alternative
/// is a node whose audit chain stops sealing, and whose exit path stops settling, because one
/// unrelated unit panicked once: a poisoned node-global lock would take every later request with
/// it, which is a far larger failure than the one that poisoned it.
fn read_through_poison<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|p| p.into_inner())
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
    /// WHAT THE SURFACE ANSWERED, where the route step reached it.
    ///
    /// `None` on every unit that ended before Route, which is the property the gate rests on: a
    /// refusal at Verify, Approve or Admit leaves this empty because the seam was never touched, and
    /// an empty answer is what the mount reads to know the surface was never asked.
    answer: Option<PlaneAnswer>,
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

    /// WHAT THE SURFACE ANSWERED, for the mount that has to write it back out.
    ///
    /// `None` is a unit whose Route step was never reached — refused at Verify, Approve or Admit —
    /// and therefore a unit for which no surface was asked anything. The mount renders the loop's own
    /// refusal for that case rather than sending a request back down to be refused a second time,
    /// which is the rule the administrative mount states: a refusal path may not execute anything.
    ///
    /// The status and the headers are read HERE and not off the encoded frame, because a frame
    /// carries neither. That is the seam's shape rather than a gap: the exit path carries the whole
    /// answer, the Encode step carries the bytes it is measured on, and neither re-derives the other.
    #[must_use]
    pub fn answer(&self) -> Option<PlaneAnswer> {
        read_through_poison(&self.progress).answer.clone()
    }

    /// The balance one unit of this plane settles into: the caller's own attribution bucket, in
    /// nano-units, across every pool.
    ///
    /// The plane names the balance because the plane is what knows which pot its traffic belongs
    /// in; the ledger keeps it. An uncapped attribution bucket is still a balance, which is the
    /// point — a deployment that configured no group still has one figure per principal.
    #[must_use]
    pub fn balance(principal: &PrincipalId) -> busbar_unit_ledger::totals::TotalsKey {
        busbar_unit_ledger::totals::TotalsKey::new(
            busbar_unit_ledger::totals::BucketId::new(principal.as_str()),
            busbar_unit_ledger::totals::CapDimension::NanoUnits,
            busbar_unit_ledger::totals::BucketScope::All,
        )
    }

    /// **The exit arm.** Move the books for what this unit posted, and put the posting on the
    /// journal.
    ///
    /// The loop's exit path takes the hold out of its cell, applies what the unit spent and settles
    /// it — that is where the hold stops existing. What comes back is the POSTING, and until it
    /// reaches here it has moved no balance and left no record. So this is the far end of the
    /// reservation's life: the door opened it sized off the estimate, the route and metering steps
    /// accrued against it, and the settlement here releases the residual and carries out whatever
    /// nothing could back.
    ///
    /// The window comes off the unit's pinned arrival epoch, never a fresh clock read, so a request
    /// that straddled a boundary posts in the window it was admitted in.
    ///
    /// # Errors
    ///
    /// The journal could not make the record durable. The books have already moved: value was
    /// delivered, and a settlement is not rolled back because a write failed.
    pub fn settle(
        &self,
        principal: &PrincipalId,
        posted: busbar_caps::Posted,
        token: &busbar_caps::DurabilityToken,
    ) -> Result<crate::root::durability::Settled, busbar_caps::DurabilityLost> {
        let key = Self::balance(principal);
        let at = crate::root::durability::Settling {
            key: &key,
            window: busbar_unit_admission::budget_window(
                busbar_unit_admission::window::WINDOW_DAY,
                self.bindings.now,
            ),
            durability: token,
            // The loop has no exit step of its own; the figure this posting is OF is the metering
            // step's, and that is the step a durability loss here is attributed to.
            step: busbar_caps::StepName::Meter,
            // The posting's own two clocks, the same pair the audit record carries and read the same
            // way: the wall epoch dates it, the monotonic reading orders it. A posting stamped twice
            // off the wall clock is a posting a stepped clock can reorder against its own record.
            stamp: crate::root::durability::PostingStamp {
                rate_card_version: 0,
                wall: self.bindings.now,
                mono: self.bindings.mono,
            },
        };
        let mut durability = read_through_poison(self.bindings.durability);
        durability.settle_posted(&at, posted)
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

        // The breaker, asked at the unit's pinned arrival epoch and about the pool it named — the
        // same question, spelled the same way, that the pre-walk filter asks.
        let at = BreakerQuery {
            breaker: self.bindings.breaker,
            pool: self.bindings.pool,
            now: self.bindings.now,
        };

        let candidates = self.candidates();
        let mut lanes = Vec::new();
        for candidate in &candidates {
            if !kind_permitted(origin, candidate) {
                continue;
            }
            if !kind_rule_passes(candidate, self.bindings.kinds, &at) {
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
    ///
    /// Every refusal the guard can raise becomes the one reason this step has for "there is nowhere
    /// to go", so which of them answered is not visible to a caller. The pin is dropped because
    /// nothing on this path dials through this seam today; it is returned by the guard so that the
    /// caller which eventually does will not resolve the name a second time.
    fn guard_destination(&self, candidate: &DestinationFacts) -> Result<(), Refusal> {
        guard_destination(
            candidate,
            self.bindings.resolver,
            self.bindings.guard,
            self.bindings.denylist,
        )
        .map(|_pinned| ())
        .map_err(|_| Refusal::new(ReasonCode::NoDestination))
    }

    /// The hold this unit is sized against.
    ///
    /// One class, because this plane declares one. The priced input is the whole request document,
    /// which is what the plane's admit facts point at, and the flat fee applies only where the
    /// verified set contains an agent AND the unit is a caller's — a push the agent sent draws no
    /// client's slot and posts no fee, so the hold does not size for one. The rule is
    /// [`fee_could_land`], which reads the same evidence the settlement reads.
    fn estimate(&self, origin: busbar_caps::OriginKind) -> Estimate {
        Estimate {
            per_class: vec![busbar_unit_admission::ClassEstimate {
                class: CLASS_BYTES.as_str().to_string(),
                quantity: self.draft.request_bytes,
                max_unit_price_nanos: self.bindings.bytes_nanos,
            }],
            fee_nanos: if fee_could_land(&self.draft, origin) {
                u64::try_from(self.bindings.pricer.price_per_request_cents().max(0))
                    .unwrap_or(0)
                    .saturating_mul(NANOS_PER_CENT)
            } else {
                0
            },
        }
    }

    /// The audit record one ending seals.
    fn audit_inputs(
        &self,
        ctx: &UnitCtx,
        outcome: Outcome,
        principal: Option<&PrincipalId>,
    ) -> AuditInputs {
        let progress = read_through_poison(&self.progress);
        // The record does not decide the fee a second time. It reads the same evidence the exit
        // path settles from, through the same function, so a row that says one and a posting that
        // says none cannot both be true of one unit.
        let (fee_count, _) = busbar_kernel::teller::fee_count(&fee_evidence(
            &self.draft,
            ctx.origin,
            progress.metered.is_some(),
        ));
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
            // The two clocks, and they are two READINGS: the wall epoch dates the record and the
            // monotonic reading orders it. Both pinned at arrival, so a unit is stamped once.
            // The two clocks, and they are two READINGS: the wall epoch dates the record and the
            // monotonic reading orders it. Both pinned at arrival, so a unit is stamped once.
            wall: self.bindings.now,
            mono: self.bindings.mono,
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
                fee_count,
                currency: String::new(),
                rate_card_version: 0,
                bucket_chain_ref: String::new(),
            },
            controls: busbar_unit_audit::Controls::default(),
            correlation_label: None,
        }
    }
}

/// Whether a plan's legs fit the route plan the loop carries.
///
/// The bound belongs to the contract and is read from it here, so a plane cannot drift from the
/// plan it is filling: the number this compares against and the number the plan holds are the same
/// number, and there is nowhere to write a second one.
fn plan_fits(legs: &[Leg]) -> bool {
    legs.len() <= busbar_contract::MAX_LEGS
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

/// What this plane asks the authentication chain, for one draft.
///
/// The three open surfaces of this protocol declare no scheme, so there is nothing to narrow within
/// and nothing to present: the chain answers for the anonymous principal or it denies, and either
/// answer is the chain's. Everything else presents a bearer credential and is narrowed to the one
/// alternative the claim declares.
///
/// It is a function rather than four lines inside the step because the authenticate CELL drives the
/// same request the step does. A cell that rebuilt this shape by hand would be pinning its own copy,
/// and the copy is the one that drifts — the audience in particular, which is the whole reason a
/// token minted for another plane does not open this one.
fn auth_request(draft: &A2aDraft, now: u64) -> AuthRequest<'_> {
    AuthRequest {
        candidate: draft.credential.as_deref(),
        scheme: draft.narrowing,
        declared_schemes: draft.declared_schemes,
        expected_aud: draft.expected_aud.as_deref(),
        in_handshake: false,
        now,
        // A bound session's principal is the cached one; an unbound session re-authenticates every
        // unit, which is what makes revocation gate new units on this plane at all.
        new_unit: !draft.from_session,
    }
}

/// What this plane's arrival step answers, for one draft.
///
/// The gate itself is the kernel's, over the configured budgets, and it has already run by the time
/// a plane's units are reached — a unit the in-flight table refused never gets here at all. What is
/// left for the plane is to carry forward what the TRANSPORT recorded, which is what the later steps
/// read the source and the composed chain from.
///
/// It is a function rather than a line inside the step for the same reason `auth_request` is: the
/// arrival CELL drives the answer the step gives rather than a hand-built copy of it. The chain is
/// the field that makes this matter — a copy that re-derived it from the plane's own claims would
/// agree with itself while the step quietly stopped reporting the layer the bytes actually came in
/// on.
fn arrival_answer(draft: &A2aDraft, token: &UnitToken<Arrival>) -> Decision<Arrival> {
    Decision::proceed(token, draft.arrival.clone())
}

impl<S: CellStore> Units for A2aUnits<'_, S> {
    fn arrival(&self, token: &UnitToken<Arrival>, _ctx: &UnitCtx) -> Decision<Arrival> {
        arrival_answer(&self.draft, token)
    }

    fn decode(&self, token: &UnitToken<Decode>, _ctx: &UnitCtx) -> Decision<Decode> {
        // The plane read the bytes; this is its answer. A body carrying a method this plane does
        // not name is a refusal at the step that read it, not a guess at the nearest class.
        match self.draft.op {
            Some(op) => Decision::proceed(token, op),
            None => Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed)),
        }
    }

    fn authenticate(
        &self,
        token: &UnitToken<Authenticate>,
        _ctx: &UnitCtx,
    ) -> Decision<Authenticate> {
        let request = auth_request(&self.draft, self.bindings.now);
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
            let mut progress = read_through_poison(&self.progress);
            progress.principal = Some(principal.clone());
            progress.grants = Some(self.grants);
        }
        match self.verified_lanes(trust_origin(ctx.origin)) {
            Err(refusal) => Decision::refuse(token, refusal),
            Ok(lanes) => {
                read_through_poison(&self.progress).lanes = lanes.clone();
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
        let Some(needed) =
            busbar_unit_scope::required_scope(CLAIM_A2A, op, self.bindings.scope_policy)
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
        ctx: &UnitCtx,
        principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> Decision<Admit> {
        // The decision is the shipped release's, evaluated by the unit that owns it: pass one
        // checks every bucket of the pool-filtered chain and charges nothing, pass two charges. The
        // epoch is the pinned arrival epoch and never a fresh clock read, because a check and a
        // charge that read two different clocks are a check of one window and a charge in another.
        // The chain the deployment configured, not an empty one. An empty chain is a yes from every
        // cap at once: no gauge is raised, no window bucket is read and no freeze flag is
        // consulted, so a group's `concurrent: 1` would admit every unit that ever arrives. Read
        // from the binding rather than resolved here, so this step allocates nothing to be judged.
        let Some(chain) = self.bindings.chain else {
            // Fail-closed, and rendered the way the door renders it for the same cause: a principal
            // whose caps cannot be read is over quota, not merely rate-limited.
            return Decision::refuse(token, Refusal::new(ReasonCode::OverBudget));
        };
        let mut unit = AdmissionUnit::new(
            self.bindings.door,
            self.bindings.pricer,
            self.bindings.pool,
            self.bindings.now,
        );
        let decision = unit.admit(&self.estimate(ctx.origin), principal, chain, admit, token);
        // What the door counted, said out loud. The names are the interned ones the root handed the
        // chain's groups at registration; the loop records one lease per name on this unit's slot,
        // where its end and the node's sweep can both give them back. Empty on a refusal, and empty
        // for a chain with no capped group — this crate does not decide either.
        for group in unit.group_leases() {
            leases.counted(group);
        }
        // AND THE COUNT ITSELF, which is the cap rather than a reading of it. The door raises a
        // gauge per capped group when it says yes and lowers it when the grant is dropped, so a
        // grant that dies with this call is a cap released before the unit it admitted has done
        // anything — every unit admitted against a count of zero. Handed to the slot, it is what
        // makes the group's `concurrent` limit refuse the next unit while this one is in the air,
        // and the slot's release at the unit's end is what makes it admit again afterwards.
        if let Some(grant) = unit.take_grant() {
            leases.holding(DoorGrant::new(grant));
        }
        decision
    }

    fn route(
        &self,
        token: &UnitToken<Route>,
        _ctx: &UnitCtx,
        meter: &AccrualMeter,
    ) -> Decision<Route> {
        // The plan has to FIT before any of it happens. The route plan the loop carries is bounded,
        // and the legs are run below before they are put on it — so a plan longer than the bound
        // used to run in full and then be trimmed to what fitted, with every leg past the bound
        // already done and no part of the answer saying so. The bound is asked here, where the
        // answer is still a refusal rather than a durable write to take back.
        if !plan_fits(&self.draft.legs) {
            return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
        }

        // The record legs, in the plan's order, before anything is dialled. They are what says
        // whether this caller may see the task at all and what the agent's own name for it is, and
        // the hop that follows carries that name.
        let key = LegKey {
            id: "",
            parent: None,
            seq: 0,
            ts: self.bindings.now,
            // The deadline is measured from THIS unit's arrival, so a task that keeps reporting keeps
            // its token alive and one that goes silent loses it a TTL after its last word. Saturating
            // because a deployment configuring an enormous TTL should get "effectively never" rather
            // than a wrapped instant already in the past — which would be a deadline that refuses
            // everything, the failure mode this whole change exists to avoid the mirror image of.
            expires_at: self
                .bindings
                .now
                .saturating_add(self.bindings.task_ttl_secs),
            terminal: matches!(
                self.draft.finish,
                FinishClass::Complete | FinishClass::Error
            ),
        };
        match self.bindings.records.run_plan(&self.draft.legs, &key, &[]) {
            // Both are the plan naming something it may not run — an operation the schema does not
            // declare, or a body over the record ceiling — and both are refused before anything is
            // written, which is why they share the reason the plane already rendered for the first.
            Err(LegError::UndeclaredOp { .. } | LegError::Oversize { .. }) => {
                return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination))
            }
            Err(LegError::Store(_)) => {
                return Decision::refuse(token, Refusal::new(ReasonCode::DurabilityUnavailable))
            }
            // REVOKED, not unavailable. The store answered; the answer was that this token no longer
            // authorises anything, because the task it was minted for has ended or its deadline has
            // passed. Refusing at ROUTE is what makes the money side follow without being touched:
            // the unit never reaches an upstream leg and never settles, so a refused callback posts
            // nothing, while an accepted one keeps posting exactly what it posted before.
            Err(LegError::TokenNotLive) => {
                return Decision::refuse(token, Refusal::new(ReasonCode::Revoked))
            }
            Ok(results) => read_through_poison(&self.progress).legs = results,
        }

        // The bytes the request carried accrue as the unit runs; the answer's bytes settle at the
        // metering step. The meter is the kernel's running total and the hold is applied to it at
        // the exit, which is why this is an accrual and not a posting.
        meter.accrue(self.draft.request_bytes);
        // How far this unit's reservation may still grow, read off the same chain the door was
        // judged against. Offered here rather than at the door because it is a reading of the window
        // as it is NOW, and the exit is where it is spent. Zero is a top-up that does not happen,
        // never a unit that does not run.
        meter.offer_headroom({
            // The same chain the door was judged against — the same value, not a second copy of it
            // — so a top-up is measured against the window that admitted this unit rather than
            // against nothing at all. A caller whose caps could not be read is a headroom of zero:
            // a reservation that does not grow, never a unit that does not run.
            match self.bindings.chain {
                None => 0,
                Some(chain) => AdmissionUnit::new(
                    self.bindings.door,
                    self.bindings.pricer,
                    self.bindings.pool,
                    self.bindings.now,
                )
                .headroom_nanos(chain),
            }
        });

        // A plan with no leg at all is an operation this plane does not carry: a refusal at the
        // routing step, not a panic and not a guess.
        if self.draft.legs.is_empty() {
            return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
        }

        let mut plan = RoutePlan::default();
        for leg in &self.draft.legs {
            // Unreachable, because the bound was asked at the top of this step. It is written as a
            // refusal rather than ignored so that the day the two stop agreeing is a day this step
            // says no, not a day a leg disappears off the plan it already ran.
            if plan
                .legs
                .push(Leg {
                    destination: leg.destination,
                })
                .is_err()
            {
                return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
            }
        }

        // THE DISPATCH SEAM, and it is the LAST thing this step does. Every gate this plane has is
        // already behind it: a unit refused at Verify, Approve or Admit never arrives here, and a
        // unit whose plan did not fit, whose record legs refused or whose capability was revoked
        // returned above. So the surface is asked exactly once, for a unit that has been decided.
        //
        // THE LOOP DECIDES THE PATH; THE BYTES ARE THE SURFACE'S. No status is computed here, no
        // header is added and no body is touched — the whole answer is recorded and the exit path
        // carries it out. That is the property a mount can be measured on: an answer this file could
        // have re-derived is an answer that can differ from the one the caller used to get.
        //
        // The MONEY does not move through here. The metering step reads the draft's own figures and
        // the settlement reads the same evidence it always did; what this records is the bytes the
        // Encode step reports on, which is the answer's size and not a priced quantity.
        // THE BUFFERING IS THIS PLANE'S CHOICE AND IT IS MADE HERE. `execute` hands back the
        // surface's own response with its body unread; this plane's exit path carries BYTES, and the
        // Encode step reports the answer's size, so this plane asks for those bytes. `collected` does
        // it generically over the seam's two methods — the mount does not do it on every plane's
        // behalf, because a plane that streams its answer would be buffered against its will.
        //
        // The three values are the same three the seam used to hand back, in the same order, so the
        // figure recorded below and the frame it rides out on are byte-for-byte what they were.
        if let (Some(dispatch), Some(op)) = (self.bindings.dispatch, self.draft.op) {
            let answer = crate::root::transports::collected(dispatch, op);
            let mut progress = read_through_poison(&self.progress);
            progress.encoded = answer.body.len() as u64;
            progress.answer = Some(answer);
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
        let retained = RetainedLocatorValues::new(vec![bytes_located(&self.draft)]);
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
                let mut progress = read_through_poison(&self.progress);
                progress.metered = Some(self.draft.response_bytes);
                progress.disputed = metered.disputed();
                Decision::proceed(token, metered.usage)
            }
        }
    }

    fn audit(&self, token: &UnitToken<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> Decision<Audit> {
        let inputs = self.audit_inputs(ctx, *outcome, None);
        let record = {
            let mut durability = read_through_poison(self.bindings.durability);
            durability.record.seal(inputs, token)
        };
        read_through_poison(&self.progress).audit_hash = Some(record.hash);
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
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> Decision<Audit> {
        // The second door: a unit that never passed the first one, and was charged nothing. It is
        // sealed on the same chain, because a refusal is an event with a record of its own.
        let outcome = Outcome::Refused(
            refusal.step().unwrap_or(busbar_caps::StepName::Admit),
            refusal.reason(),
        );
        let inputs = self.audit_inputs(ctx, outcome, None);
        let record = {
            let mut durability = read_through_poison(self.bindings.durability);
            durability.record.seal(inputs, token)
        };
        read_through_poison(&self.progress).audit_hash = Some(record.hash);
        Decision::proceed(
            token,
            AuditFacts {
                op_class: self.draft.op.unwrap_or(ops::OP_MESSAGE_SEND),
                finish: FinishClass::Error,
            },
        )
    }

    fn encode(
        &self,
        token: &UnitToken<Encode>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> Decision<Encode> {
        // The plane's encoders take the unit's arena, and this signature carries neither an arena
        // nor the plane's draft, so the bytes are written where the borrow lives and this step
        // reports what left. That is a statement about the seam, not a shortcut: a root that
        // allocated a second buffer here would be writing the wire format twice.
        //
        // WHAT THE SURFACE WROTE, where the Route step reached one. The body travels on the frame
        // because the frame is what a driver hands a transport; the STATUS and the HEADERS do not,
        // because a frame has no field for either — they leave through [`A2aUnits::answer`], read by
        // the mount, which is the same division the administrative plane's exit path has. Reporting
        // the status here as well would be the one answer written down twice.
        //
        // Empty for a unit that never reached the seam. That is not a body this file invented for a
        // refusal: it is the honest statement that nothing answered, and the mount renders the loop's
        // own refusal from the ending instead.
        let progress = read_through_poison(&self.progress);
        let bytes = progress.encoded;
        let body: Arc<[u8]> = progress
            .answer
            .as_ref()
            .map_or_else(|| Arc::from(&[][..]), |answer| Arc::from(&answer.body[..]));
        drop(progress);
        Decision::proceed(
            token,
            busbar_contract::wire::Frame {
                direction: busbar_contract::wire::Direction::Outbound,
                stream: busbar_contract::ids::StreamId(0),
                bytes: busbar_contract::bounded::SlabBytes::new(body),
                meta: busbar_contract::wire::FrameMeta {
                    bytes,
                    transport_units: None,
                    status: None,
                    status_code: None,
                    retry_after_secs: None,
                },
            },
        )
    }

    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        let progress = read_through_poison(&self.progress);
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
            fee: fee_evidence(&self.draft, ctx.origin, progress.metered.is_some()),
        }
    }
}

/// The facts this plane's flat per-request fee is decided from.
///
/// Written once, as a function over the draft rather than as a table each caller fills in, because
/// the exit path and the audit record are two readers of ONE decision: a settlement that posted a
/// fee against a record that says none is a discrepancy nothing downstream can resolve, and the
/// only way to make that unrepresentable is to have one place decide it.
///
/// The origin is the client rule the request slot is drawn under — a push the agent sent is not a
/// caller's request and pays nothing. The upstream is the KIND of leg the plane verified, not its
/// price: with no rate card the fee still posts. The relayed frame is the metering step's own
/// locator, which is set when the plane read an answer to hand back; a unit that never got that far
/// relayed nothing. This transport carries no status leg of its own — the answer document IS the
/// response — so the plane's finish is the single source, and an error ending posts nothing.
fn fee_evidence(
    draft: &A2aDraft,
    origin: busbar_caps::OriginKind,
    relayed_first_response_frame: bool,
) -> busbar_kernel::teller::FeeEvidence {
    busbar_kernel::teller::FeeEvidence {
        client_open_or_one_shot: origin == busbar_caps::OriginKind::Client,
        selected_upstream: draft.has_upstream(),
        relayed_first_response_frame,
        status_at: None,
        status: None,
        finish: Some(draft.finish),
    }
}

/// This plane's one metered line: how many bytes, and which side of the exchange they came off.
///
/// One class, one line, and the quantity is one the plane already had in front of it: the size of
/// the document it read. There is no pointer to walk, so the locator carries the value.
///
/// The DIRECTION is the side that quantity was measured on, and here that is the response — the
/// answer document, not the request. It is not a label: a direction is what a class cap, a rate-card
/// entry and a usage projection all partition on, so a line metered against one side while the
/// deployment configured the other is a line silently exempt from its own limit. Written out here,
/// beside the field it describes, so the two cannot be changed apart.
fn bytes_located(draft: &A2aDraft) -> LocatedValue {
    LocatedValue {
        class: CLASS_BYTES,
        quantity: draft.response_bytes,
        source: busbar_caps::QuantitySource::Locator {
            direction: busbar_contract::ids::ClassDirection::Response,
            // The quantity was not at a pointer: it is the size of the document the plane just
            // read, which the locator carried by value precisely for this case.
            ptr: busbar_caps::LocatorPtr::new(""),
        },
    }
}

/// Whether the flat fee could land on this unit AT ALL — the question the hold has to size for.
///
/// The hold is a promise that the settlement will fit, so what it reserves has to be decided by the
/// same rule the settlement is. The kernel's fee needs three things true together; two of them —
/// the client origin and the selected upstream — are already known at the door, and the third, the
/// relayed frame, cannot be and only ever makes the charge SMALLER. So the door sizes for the two it
/// knows, which is the largest fee this unit could ever be asked for.
///
/// Read off the evidence rather than restated beside it, and that is the point of the function: a
/// hold that spelled the origin rule a second time is a second rule, and the one that drifts is the
/// one nobody re-derived. Spelled twice, a provider push on a thin bucket was refused `OverBudget`
/// for a fee its own settlement would never have posted.
fn fee_could_land(draft: &A2aDraft, origin: busbar_caps::OriginKind) -> bool {
    // `false` for the relay: it is not knowable at the door and it is not part of this question.
    let evidence = fee_evidence(draft, origin, false);
    evidence.client_open_or_one_shot && evidence.selected_upstream
}

/// Judge one destination's address, before any dial.
///
/// This is the trust unit's own check, reached through the entry that takes the facts a destination
/// is sealed FROM — a composition root judges a candidate before it is sealed, because the seal is
/// what the judgement produces. It used to be the guard's ordering written out a second time here,
/// over the same primitives; two copies of an address judgement drift, and the copy that drifts is
/// the one nobody re-derived.
///
/// A destination that is not a network hop — a record leg, a client delivery, a kernel verb — has no
/// address and passes: there is nothing to have judged. The pin travels back rather than being
/// dropped here, so a caller that goes on to dial does not resolve the name a second time.
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
) -> Result<Option<busbar_unit_trust::PinnedTarget>, busbar_unit_trust::NetworkRefusal> {
    match busbar_unit_trust::net::check_destination_facts(
        candidate,
        &[],
        resolver,
        policy,
        denylist,
    ) {
        // Only an upstream is dialled at an address. Every other kind reaches its destination
        // without one, so "this is not an upstream" is this caller's pass, not its refusal.
        Err(busbar_unit_trust::NetworkRefusal::NotAnUpstream) => Ok(None),
        other => other,
    }
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

#[cfg(test)]
#[path = "tests/units_a2a.rs"]
mod tests;
