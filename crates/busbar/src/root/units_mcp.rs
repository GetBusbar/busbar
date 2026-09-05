// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MCP plane, driven through the kernel.
//!
//! The plane says what bytes mean and stops there: it returns facts and locators, a destination per
//! operation class, a plan of legs, a resource pair, a usage class and an operation class. Every one
//! of those is an input to a unit, and no unit knows which plane produced it. This file is where the
//! two are introduced, and it is the whole of what "switching the MCP plane onto the kernel" means.
//!
//! ## One row per step
//!
//! | step | the unit that answers | what this file supplies it |
//! |---|---|---|
//! | authenticate | the auth unit | the claim's declared scheme alternatives, and the plane's narrowing within them |
//! | verify | the trust unit | the candidate destination, the pool view, and the per-kind facts the record legs are judged against |
//! | approve | the scope unit | the two resource kinds the plane names, and the claim/operation pair the policy is asked about |
//! | admit | the admission unit | the estimate, built from the classes the plane declares and priced by the cost unit's card |
//! | route | the egress unit | the plan's legs, classified: a record leg is served from the store, an upstream leg is dialled, a nested leg opens a child unit |
//! | meter | the usage unit | the located values for the two declared classes, and which lane legs the plane declares it produces |
//! | audit | the audit unit | the action and resource the served call is recorded under, on both chains |
//! | exit | the ledger | the totals key the settlement posts against |
//!
//! ## Where the plane stops and this file starts
//!
//! The plane declares six record operations and the store offers six; the mapping is one to one and
//! it is written out below rather than derived, because "get becomes a get" is the kind of sentence
//! that is true of five out of six. The one that is not is the redemption: a grant is spent by a
//! test-and-set on the store, never by a read followed by a write, because the two-step version is
//! the race the operation exists to close.
//!
//! ## What the tests below can and cannot reach
//!
//! Four of the bindings take a step's own capability token, and a token is minted from the kernel's
//! seal, which is private to the kernel. That is the seal working: nothing outside the loop can
//! manufacture the right to answer a step. So the token-taking bindings compile against the real
//! unit traits here and are exercised end to end by the plane's conformance rig, which drives them
//! through the loop that does hold the seal. Everything a token is not needed for — the declarations,
//! the classification, the record legs, the estimate, the audit strings — is proved here.
//!
//! ## What is still the codec's, and named as such
//!
//! Three things this plane's units need are not on the plane crate, because they are the I/O half's
//! and the plane crate may not name them. Each is listed at its seam below and each is pinned by a
//! test that reads the other crate's own source, so a rename there goes red here rather than
//! quietly writing a record nobody reads back.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_api::{PlaneDisposition, PlaneRecord, PlaneSelector, Store as AbiStore};
use busbar_caps::{
    Admit, AdmitToken, Authenticate, Decision, PrincipalId, TrustToken, UnitToken, UsageToken,
    Verify,
};
use busbar_contract::dest::DestinationFacts;
use busbar_contract::ids::{ClaimKey, LaneId, OpClassId, RecordSchemaId};
use busbar_contract::plane::{Plane, PlaneMeta};
use busbar_plane_mcp::meta::{CLASS_BYTES, CLASS_TOOL_CALLS};
use busbar_plane_mcp::{claims, ops, records, McpPlane, Server};
use busbar_plugin_loader::store_adapter::StoreAdapter;
use busbar_unit_admission::{
    Admission, AdmissionUnit, BucketChain, ClassEstimate, Door, Estimate, InMemoryCells, Pricer,
};
use busbar_unit_audit::legacy::{AuditInput, OUTCOME_APPLIED, OUTCOME_REJECTED};
use busbar_unit_auth::{Auth, AuthRequest, CredentialCache, KeyVerifier, RevocationView};
use busbar_unit_ledger::{BucketId, BucketScope, CapDimension, TotalsKey};
use busbar_unit_scope::{Grants, PolicyView, Refused, Scope};
use busbar_unit_trust::destination::{KindFacts, OriginKind};
use busbar_unit_trust::guard::PoolView;
use busbar_unit_trust::{Trust, VerifyRequest};
use busbar_unit_usage::{
    meter as fold_usage, KernelCounts, LegDeclaration, LocatedValue, Metered, RetainedLocatorValues,
};

/// The resource kind a registered server is judged as at the approve step.
///
/// The plane writes this kind onto its own scope facts. It is restated here because the root is what
/// turns a resource pair into a policy question, and a root that read the kind off the plane's
/// private constant would be reading something the plane does not export. The pin is a test.
pub const SCOPE_KIND_SERVER: &str = "mcp_server";

/// The resource kind one tool is. A call names both kinds; everything else names only the server.
pub const SCOPE_KIND_TOOL: &str = "mcp_tool";

/// The action a served tool call is recorded under on the administrative chain.
///
/// **A seam to the I/O half.** The literal lives in `busbar-mcp`'s dispatch, which is where the verb
/// body still is, and it is not visible outside that crate. The rig reads it back off the admin
/// audit surface, so it has to be the same string in both places; the pin below reads the codec's
/// own source rather than trusting this line.
pub const AUDIT_ACTION_TOOL_CALL: &str = "mcp_tool.call";

/// The prefix a tool resource is recorded under, ahead of the tool's published name.
pub const AUDIT_RESOURCE_PREFIX_TOOL: &str = "mcp_tool:";

/// The prefix this plane's destinations occupy in the breaker's and the pool table's keyspace.
///
/// **A seam to the neutral substrate.** The single source is `busbar_substrate::store::tool_key`;
/// the prefix is restated here so the root can build the key without a substrate edge on this path,
/// and pinned by a test that reads that function's own source.
pub const POOL_PREFIX_TOOL: &str = "tool:";

/// The caller-facing text the trust unit refuses an unpriced destination with.
///
/// It names what was asked for and nothing else. A message that named the rate card, the pool or the
/// lane would tell a caller about the deployment's money, which is exactly what a refusal may not do.
pub const UNPRICED_MESSAGE: &str = "no rate is configured for the MCP server this request names";

/// The breaker and pool key one registered server occupies.
#[must_use]
pub fn pool_key(server: &str) -> String {
    format!("{POOL_PREFIX_TOOL}{server}")
}

/// The claim key this plane's policy entries are written under.
///
/// One key for the plane rather than one per claim: the four claims are four surfaces of one
/// protocol, and a policy that could permit an operation class on the streamed surface and refuse it
/// on the document surface would be describing two protocols.
#[must_use]
pub fn claim_key() -> ClaimKey {
    ClaimKey::new(<McpPlane as PlaneMeta>::KEY)
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 1 — authenticate, over the schemes the claim declared
// ─────────────────────────────────────────────────────────────────────────────

/// What arrived, as the authenticate step needs to see it.
///
/// The plane already answered the only question that is its own — which alternative this unit is
/// narrowed to — and it answered it from the transport, not from the request. Everything else here
/// is the kernel's own reading of the connection.
#[derive(Debug, Clone, Copy)]
pub struct Arriving<'a> {
    /// The credential the carrier presented, if any.
    pub presented: Option<&'a str>,
    /// The transport the connection arrived on, as the registry keys it.
    pub transport: &'a str,
    /// Whether the claim that matched declares a scheme at all. The discovery document is the one
    /// surface of this plane that declares none, and a unit on it carries no credential by
    /// declaration rather than by omission.
    pub under_scheme: bool,
    /// The wall clock, in seconds.
    pub now: u64,
    /// Whether this is a new unit, and therefore whether the revocation set applies.
    pub new_unit: bool,
}

/// The alternatives this plane's credentialed claims declare.
///
/// Read off the claims themselves rather than restated, so a claim that gained an alternative gains
/// it here too. The open claim contributes nothing, which is the point of it being open.
#[must_use]
pub fn declared_schemes() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for claim in <McpPlane as PlaneMeta>::CLAIMS {
        for alt in claim.scheme_alternatives {
            if !out.contains(alt) {
                out.push(alt);
            }
        }
    }
    out
}

/// The alternative the plane narrows a unit on this transport to.
///
/// A locally launched server has no request to carry a header on: its credential was handed to it
/// when it started. Everything on the document transport presents a bearer credential. This is the
/// plane's own answer, restated over the transport key because the root reaches the plane's
/// `authenticate` only with a live unit in hand and the narrowing depends on nothing else.
#[must_use]
pub fn narrowed_scheme(transport: &str) -> &'static str {
    if transport == claims::TRANSPORT_STDIO {
        "environment"
    } else {
        "bearer"
    }
}

/// Ask the auth unit who is calling.
///
/// The audience is this plane's canonical name on every credentialed claim: a token minted for
/// another audience is a token for another surface, and the rig's own authenticate cell is exactly
/// that refusal. A unit on the open claim is asked with no narrowing and no audience, because
/// narrowing within an empty set is not a thing that can succeed.
pub fn authenticate(
    auth: &Auth,
    arriving: &Arriving<'_>,
    cache: Option<&CredentialCache>,
    keys: Option<&dyn KeyVerifier>,
    revocations: Option<&dyn RevocationView>,
    token: &UnitToken<Authenticate>,
) -> Decision<Authenticate> {
    let declared = declared_schemes();
    let narrowing = arriving
        .under_scheme
        .then(|| narrowed_scheme(arriving.transport));
    let request = AuthRequest {
        candidate: arriving.presented,
        scheme: narrowing,
        declared_schemes: if arriving.under_scheme {
            &declared
        } else {
            &[]
        },
        expected_aud: arriving
            .under_scheme
            .then_some(<McpPlane as PlaneMeta>::KEY),
        // This plane opens no handshake unit: every claim it makes carries its credential on the
        // first frame, so there is never a second round to answer one in.
        in_handshake: false,
        now: arriving.now,
        new_unit: arriving.new_unit,
    };
    auth.resolve(&request, cache, keys, revocations, None, token)
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 2 — verify, against the catalogue the plane's records describe
// ─────────────────────────────────────────────────────────────────────────────

/// What the trust unit reads about this plane's destinations.
///
/// The interesting method is the record one. Every listing, every task read and every notice of this
/// protocol reaches a record rather than a server, and whether such a reach is permitted is a
/// question about the plane's own declarations: is the schema one it declared, and is the operation
/// one that schema declares? Both answers are on the plane crate, so the root asks it rather than
/// keeping a second table.
pub struct Catalogue {
    plane: McpPlane,
    schema: RecordSchemaId,
    op: &'static str,
    lanes: Vec<LaneId>,
}

impl Catalogue {
    /// The facts for one unit, whose plan reaches one schema under one operation.
    #[must_use]
    pub fn new(plane: McpPlane, schema: RecordSchemaId, op: &'static str) -> Self {
        let lanes = plane.servers().iter().map(|s| s.lane).collect();
        Catalogue {
            plane,
            schema,
            op,
            lanes,
        }
    }

    /// The facts for a unit that reaches no record at all — a hop straight to a server.
    #[must_use]
    pub fn upstream_only(plane: McpPlane) -> Self {
        Catalogue::new(plane, records::SCHEMA_CATALOGUE, records::OP_SCAN)
    }

    /// The registered server one destination names, where it names one.
    fn server_for(&self, dest: &DestinationFacts) -> Option<&'static Server> {
        let lane = dest.lane()?;
        self.plane.servers().iter().find(|s| s.lane == lane)
    }
}

impl KindFacts for Catalogue {
    fn allow_listed(&self, dest: &DestinationFacts) -> bool {
        match dest {
            // A hop is permitted when it reaches a server this deployment registered. The plane with
            // nothing registered answers with an empty host and an empty lane precisely so this
            // returns false rather than the plane inventing somewhere to go.
            DestinationFacts::Upstream { address, .. } => {
                address.authority().is_some_and(|a| !a.is_empty())
                    && self.server_for(dest).is_some()
            }
            DestinationFacts::SessionUpstream { .. } => self.server_for(dest).is_some(),
            // Everything else stays on this node.
            _ => true,
        }
    }

    fn transport_key_resolves(&self, dest: &DestinationFacts) -> bool {
        match dest {
            DestinationFacts::Upstream { transport, .. } => [
                claims::TRANSPORT_HTTP,
                claims::TRANSPORT_SSE,
                claims::TRANSPORT_STDIO,
            ]
            .contains(transport),
            _ => true,
        }
    }

    fn lane_permitted_for_op_class(&self, lane: &str) -> bool {
        self.lanes.iter().any(|l| l.as_str() == lane)
    }

    fn session_upstream_ok(&self) -> bool {
        // A held stream of this protocol lives inside one connection and is paired at the moment it
        // opens; there is no way to reach a session's upstream that did not come from that pairing.
        true
    }

    fn session_principal_matches(&self) -> bool {
        true
    }

    fn client_selector_ok(&self) -> bool {
        // The only selector this plane names is the opener, which resolves for as long as the unit
        // that opened the stream is the unit being delivered to.
        true
    }

    fn await_deadline_ok(&self) -> bool {
        // This plane's client legs deliver; none of them awaits a reply, so there is no deadline to
        // be out of range.
        true
    }

    fn verb_scope_held(&self) -> bool {
        // This plane reaches no administrative verb. Its two introspection verbs are read through
        // the admin plane's own surface, under that plane's claim and that plane's scope.
        false
    }

    fn nested_plane_ok(&self) -> bool {
        // The one nested destination is the reference plane's chat class, named by a key rather than
        // reached directly. Whether that plane is registered is the registry's answer, and the boot
        // seal is where it is asked.
        true
    }

    fn plane_record_ok(&self) -> bool {
        <McpPlane as PlaneMeta>::RECORD_SCHEMAS.contains(&self.schema)
            && records::operations_for(self.schema).contains(&self.op)
    }

    fn peer_lease_live(&self) -> bool {
        // This plane names no peer.
        false
    }

    fn upgrade_ok(&self) -> bool {
        // And no upgrade: the streamed surface is its own claim on its own transport, reached by a
        // request rather than by an in-band handoff.
        false
    }
}

/// What the guards read about this plane's pools.
///
/// A pool here is one registered server, keyed the way the breaker keys it. The explicit empty scope
/// list is the case worth naming: a key scoped to nothing denies every pool, which is a different
/// answer from a key that names no restriction at all, and it is the rig's own verify cell.
pub struct Pools {
    plane: McpPlane,
    scopes: Option<Vec<String>>,
    has_key: bool,
    priced: bool,
}

impl Pools {
    /// The view for one caller over one deployment's registrations.
    #[must_use]
    pub fn new(plane: McpPlane, scopes: Option<Vec<String>>, has_key: bool, priced: bool) -> Self {
        Pools {
            plane,
            scopes,
            has_key,
            priced,
        }
    }

    /// The name of the server one pool key refers to, where it refers to one.
    fn server_of(&self, pool: &str) -> Option<&'static Server> {
        let name = pool.strip_prefix(POOL_PREFIX_TOOL).unwrap_or(pool);
        self.plane.servers().iter().find(|s| s.id == name)
    }
}

impl PoolView for Pools {
    fn key_scopes(&self) -> Option<&[String]> {
        self.scopes.as_deref()
    }

    fn pool_allowed(&self, pool: &str) -> bool {
        match self.scopes.as_deref() {
            // No restriction named: every registration is reachable.
            None => true,
            // An explicit list — including an explicitly empty one — is the whole of what is allowed.
            Some(scopes) => {
                let name = pool.strip_prefix(POOL_PREFIX_TOOL).unwrap_or(pool);
                scopes.iter().any(|s| s == pool || s == name)
            }
        }
    }

    fn on_exhausted_fallback(&self, _pool: &str) -> Option<String> {
        // A registration falls over to nothing. The protocol's own answer to an unreachable server
        // is an error naming that server, and quietly serving a caller from a different server would
        // be answering a question nobody asked.
        None
    }

    fn is_configured(&self, name: &str) -> bool {
        self.server_of(name).is_some()
    }

    fn pricing_enabled(&self) -> bool {
        self.priced
    }

    fn is_unpriced(&self, name: &str) -> bool {
        self.priced && self.server_of(name).is_none()
    }

    fn has_key(&self) -> bool {
        self.has_key
    }
}

/// Ask the trust unit where this unit may go.
///
/// The candidate is the plane's own single answer at this step, which is not the same as its route
/// plan: `verify` names where the unit ends up and `route` names every leg it passes through. Sealing
/// the endpoint is what the step is for, and the legs are judged one at a time at the routing step
/// against the same facts.
pub fn verify(
    trust: &Trust,
    candidate: &[DestinationFacts],
    pool: &str,
    pools: &dyn PoolView,
    facts: &dyn KindFacts,
    trust_token: &TrustToken,
    token: &UnitToken<Verify>,
) -> Decision<Verify> {
    let request = VerifyRequest {
        // Every unit of this plane is a client's own request or a frame a paired server pushed; the
        // origin decides which kinds each may reach at all, and this is the client half.
        origin: OriginKind::Client,
        candidates: candidate,
        pool,
        unpriced_message: UNPRICED_MESSAGE,
    };
    trust.verify(&request, pools, facts, trust_token, token)
}

/// The origin a frame an upstream pushed opens its own unit under.
///
/// A server asking for a completion or for the caller's roots is not the caller asking for anything,
/// and the kinds it may reach are a different, smaller set. Naming it here is what keeps the two
/// readings of one plane's units apart.
#[must_use]
pub fn provider_origin() -> OriginKind {
    OriginKind::Provider
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 3 — approve, over the two resource kinds the plane names
// ─────────────────────────────────────────────────────────────────────────────

/// One thing the caller is asking to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resource {
    /// The kind, in this plane's vocabulary.
    pub kind: &'static str,
    /// The registration the request is about.
    pub name: &'static str,
}

/// The resources one operation class names.
///
/// A call names two: the server it is on and the tool namespace within it. Everything else names the
/// server alone. The coarse grant never stands in for the fine one — that is the reason there are
/// two kinds rather than one — and a deployment with nothing registered names nothing at all, which
/// the scope unit reads as a refusal rather than as a pass.
#[must_use]
pub fn resources(plane: &McpPlane, op: OpClassId) -> Vec<Resource> {
    let Some(server) = plane.servers().first() else {
        return Vec::new();
    };
    let mut out = vec![Resource {
        kind: SCOPE_KIND_SERVER,
        name: server.id,
    }];
    if op == ops::OP_TOOL_CALL {
        out.push(Resource {
            kind: SCOPE_KIND_TOOL,
            name: server.id,
        });
    }
    out
}

/// Why the approve step refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveRefusal {
    /// The policy says nothing about this claim's operation class. Silence is a refusal: an
    /// operation nobody wrote an entry for has not been authorized.
    NoPolicyEntry,
    /// The policy named a scope, and the caller does not hold it.
    Insufficient(Refused),
    /// The plane named no resource, because the deployment registered no server. There is nothing
    /// here to be authorized to reach.
    NoResource,
}

/// Ask the scope unit whether the caller may do this.
///
/// Three answers in a fixed order, and the order is the point. A pair the policy is silent about is
/// refused before the caller's grants are looked at, because a grant compared against nothing would
/// compare true. A deployment with no registration is refused before either, because an authorization
/// to reach nothing is not an authorization.
///
/// The hook seats are not here. `approve` runs first and a veto after it wins regardless, which is a
/// composition the root makes around this call rather than something the scope unit can express.
pub fn approve(
    plane: &McpPlane,
    op: OpClassId,
    held: Grants,
    policy: &dyn PolicyView,
) -> Result<Vec<Resource>, ApproveRefusal> {
    let resources = resources(plane, op);
    if resources.is_empty() {
        return Err(ApproveRefusal::NoResource);
    }
    let needed = busbar_unit_scope::required_scope(claim_key(), op, policy)
        .ok_or(ApproveRefusal::NoPolicyEntry)?;
    busbar_unit_scope::approve(held, needed).map_err(ApproveRefusal::Insufficient)?;
    Ok(resources)
}

/// The scope every operation class of this plane requires, as the root declares it to the policy.
///
/// A read is read-only and everything that reaches a server or writes a record is full. The table is
/// written out per class rather than derived from a naming convention, because a convention is a
/// second place for a class to be wrong.
#[must_use]
pub fn required_scopes() -> Vec<(OpClassId, Scope)> {
    <McpPlane as PlaneMeta>::OP_CLASSES
        .iter()
        .map(|op| {
            let scope = match *op {
                ops::OP_DISCOVER
                | ops::OP_TOOLS_LIST
                | ops::OP_PROMPTS_LIST
                | ops::OP_RESOURCES_LIST
                | ops::OP_RESOURCE_TEMPLATES_LIST
                | ops::OP_PROMPT_GET
                | ops::OP_RESOURCE_READ
                | ops::OP_COMPLETION
                | ops::OP_TASK_GET
                | ops::OP_ROOTS_LIST
                | ops::OP_SUBSCRIPTIONS_LISTEN => Scope::ReadOnly,
                _ => Scope::Full,
            };
            (*op, scope)
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 4 — admit, against the classes the plane declares
// ─────────────────────────────────────────────────────────────────────────────

/// The estimate for one unit of this plane.
///
/// Two lines at most, because the plane declares two classes. A call is one call, flat, which is what
/// the count-shaped class means; the byte-shaped line is the request document the plane already
/// measured. Nothing is guessed at: both quantities are numbers the plane put in front of the root.
#[must_use]
pub fn estimate(
    op: OpClassId,
    request_bytes: u64,
    prices: &ClassPrices,
    fee_nanos: u64,
) -> Estimate {
    let mut per_class = Vec::with_capacity(2);
    if op == ops::OP_TOOL_CALL {
        per_class.push(ClassEstimate {
            class: CLASS_TOOL_CALLS.as_str().to_string(),
            quantity: 1,
            max_unit_price_nanos: prices.tool_calls,
        });
    }
    per_class.push(ClassEstimate {
        class: CLASS_BYTES.as_str().to_string(),
        quantity: request_bytes,
        max_unit_price_nanos: prices.bytes,
    });
    Estimate {
        per_class,
        fee_nanos,
    }
}

/// The highest per-unit price over the verified set, for each class the plane declares.
///
/// The maximum rather than the mean, for the reason the estimate's own documentation gives: a hold
/// that is too small has to top up, and a hold that is too large costs nothing but headroom the unit
/// gives straight back at settlement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClassPrices {
    /// Nano-units per completed call.
    pub tool_calls: u64,
    /// Nano-units per byte of the priced document.
    pub bytes: u64,
}

/// Everything one unit brings to the door, as one borrowed value.
///
/// The epoch is a field rather than a clock the door could read, and that is the whole reason this
/// is a struct: a door that read the clock again would put a unit in a different window from the one
/// it arrived in, and a window boundary would then be a place where a request could be charged twice
/// or not at all. Pinning it where the unit is assembled makes reading it twice impossible rather
/// than merely discouraged.
pub struct Admitting<'a> {
    /// The door, holding the ledger cells hydrated once at boot.
    pub door: &'a Door<InMemoryCells>,
    /// What the deployment's card prices this unit at.
    pub pricer: &'a Pricer,
    /// The registration this unit is on, keyed the way the breaker keys it.
    pub pool: &'a str,
    /// The unit's own pinned arrival time, in seconds.
    pub arrival_epoch: u64,
    /// What it is expected to consume.
    pub estimate: &'a Estimate,
    /// Who is calling.
    pub principal: &'a PrincipalId,
    /// The buckets it draws against.
    pub chain: &'a BucketChain,
}

/// Ask the door.
pub fn admit(
    unit: &Admitting<'_>,
    admit_token: &AdmitToken<Admit>,
    token: &UnitToken<Admit>,
) -> Decision<Admit> {
    let mut door = AdmissionUnit::new(unit.door, unit.pricer, unit.pool, unit.arrival_epoch);
    door.admit(
        unit.estimate,
        unit.principal,
        unit.chain,
        admit_token,
        token,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 5 — route, over the plan the plane returned
// ─────────────────────────────────────────────────────────────────────────────

/// What one leg of the plan is, as the root has to service it.
///
/// The classification exists because the three kinds are serviced by three different things and
/// nothing in the plan says so: a record leg never leaves the node, an upstream leg goes through the
/// egress unit over the composed transport stack, and a nested leg opens a child unit of another
/// plane with a hold of its own drawn from this node's budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegKind {
    /// A kernel-held record of this plane, reached through the store.
    Record {
        /// Which schema.
        schema: RecordSchemaId,
        /// Which of the six operations.
        op: &'static str,
    },
    /// A hop to the registered server, dialled by the egress unit.
    Upstream {
        /// The transport the hop is made over.
        transport: &'static str,
        /// The priced lane the server is reached on.
        lane: LaneId,
    },
    /// A child unit of another plane.
    Nested {
        /// Which plane.
        plane: &'static str,
        /// Which of its operation classes.
        op: OpClassId,
    },
    /// A frame delivered back to the caller that opened the unit.
    Client {
        /// Which participant.
        selector: &'static str,
    },
    /// A destination kind this plane does not name. Never produced from this plane's own plan; it
    /// exists so the classification is total and a future kind is a compile error rather than a
    /// silent skip.
    Unsupported,
}

/// Classify every leg of one unit's plan.
///
/// The plan comes from the plane and is not second-guessed here. An operation class the plane carries
/// no plan for yields an empty vector, which is a refusal at the routing step — not a panic, and not
/// a hop to somewhere plausible.
#[must_use]
pub fn legs(
    plane: &McpPlane,
    unit: &busbar_contract::unit::Unit<'_>,
    ctx: &busbar_contract::unit::Ctx<'_>,
) -> Vec<LegKind> {
    plane
        .route(unit, ctx)
        .legs
        .as_slice()
        .iter()
        .map(|leg| classify(&leg.destination))
        .collect()
}

/// Classify one destination.
#[must_use]
pub fn classify(dest: &DestinationFacts) -> LegKind {
    match *dest {
        DestinationFacts::PlaneRecord { schema, op } => LegKind::Record { schema, op },
        DestinationFacts::Upstream {
            transport, lane, ..
        } => LegKind::Upstream { transport, lane },
        DestinationFacts::SessionUpstream { lane, .. } => LegKind::Upstream {
            transport: claims::TRANSPORT_HTTP,
            lane,
        },
        DestinationFacts::NestedPlane { plane, op } => LegKind::Nested { plane, op },
        DestinationFacts::Client { selector, .. } => LegKind::Client { selector },
        DestinationFacts::KernelVerb { .. }
        | DestinationFacts::SessionAccrual { .. }
        | DestinationFacts::Peer { .. }
        | DestinationFacts::Upgrade { .. } => LegKind::Unsupported,
    }
}

/// What one record leg answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordAnswer {
    /// One record's body, or nothing under that key.
    One(Option<Vec<u8>>),
    /// Every record the scan matched, oldest first where the schema is ordered.
    Many(Vec<Vec<u8>>),
    /// The write landed.
    Written,
    /// The grant was spent, and whether this caller is the one who spent it.
    Redeemed(bool),
}

/// A record leg the root could not service.
#[derive(Debug)]
pub enum RecordRefusal {
    /// The plane does not declare this operation for this schema. The trust unit refuses such a leg
    /// before it is ever run; this arm is the second door, so a caller reaching the store by another
    /// route cannot get past it either.
    Undeclared {
        /// The schema the leg named.
        schema: RecordSchemaId,
        /// The operation it named.
        op: &'static str,
    },
    /// The store answered with a failure.
    Store(String),
}

impl std::fmt::Display for RecordRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordRefusal::Undeclared { schema, op } => {
                write!(f, "the mcp plane declares no {op} on {schema}")
            }
            RecordRefusal::Store(message) => {
                write!(f, "the store refused the record leg: {message}")
            }
        }
    }
}

impl std::error::Error for RecordRefusal {}

/// This plane's record legs, over the store the loader opened.
///
/// The adapter is the one store handle in the process, and it is the published protocol's own record
/// operations that answer here — not a second shape invented for this plane. A store that predates
/// them answers from the adapter's node-local shim, which is why a deployment on a released store
/// boots and serves exactly as it did.
pub struct Records {
    store: Arc<dyn AbiStore>,
}

impl Records {
    /// Bind this plane's record legs to the loaded store.
    #[must_use]
    pub fn new(adapter: &StoreAdapter) -> Self {
        Records {
            store: adapter.store(),
        }
    }

    /// Run one leg.
    ///
    /// The six operations the plane declares map one to one onto the six the published protocol
    /// offers. Five of them are the obvious mapping; the sixth is not, and it is the reason the
    /// mapping is written out rather than derived: a redemption is a test-and-set on the store, so a
    /// retry cannot spend a grant a first attempt already spent.
    ///
    /// # Errors
    ///
    /// The plane does not declare the operation for the schema, or the store refused.
    pub fn run(&self, leg: &RecordLeg<'_>) -> Result<RecordAnswer, RecordRefusal> {
        if !records::operations_for(leg.schema).contains(&leg.op) {
            return Err(RecordRefusal::Undeclared {
                schema: leg.schema,
                op: leg.op,
            });
        }
        let kind = leg.schema.as_str();
        let map = |e: busbar_api::StoreError| RecordRefusal::Store(e.0);
        match leg.op {
            records::OP_GET => self
                .store
                .get_plane_record(kind, leg.key)
                .map(RecordAnswer::One)
                .map_err(map),
            records::OP_SCAN => {
                let selector = match leg.parent {
                    Some(parent) => PlaneSelector::Parent(parent.to_string()),
                    None => PlaneSelector::All,
                };
                self.store
                    .list_plane_records(kind, &selector)
                    .map(RecordAnswer::Many)
                    .map_err(map)
            }
            records::OP_PUT => self
                .store
                .upsert_plane_record(&leg.record())
                .map(|()| RecordAnswer::Written)
                .map_err(map),
            records::OP_APPEND => self
                .store
                .append_plane_record(&leg.record())
                .map(|()| RecordAnswer::Written)
                .map_err(map),
            records::OP_DELETE => self
                .store
                .delete_plane_record(kind, leg.key)
                .map(|()| RecordAnswer::Written)
                .map_err(map),
            records::OP_REDEEM => self
                .store
                .redeem_plane_token(kind, leg.key, leg.expires_at, leg.now)
                .map(RecordAnswer::Redeemed)
                .map_err(map),
            // Unreachable while the declaration check above runs first, and kept because the
            // declaration is data: a seventh operation added to the plane would land here rather
            // than in whichever arm it happened to look like.
            other => Err(RecordRefusal::Undeclared {
                schema: leg.schema,
                op: other,
            }),
        }
    }
}

/// Everything one record leg needs.
#[derive(Debug, Clone, Copy)]
pub struct RecordLeg<'a> {
    /// Which of the plane's six schemas.
    pub schema: RecordSchemaId,
    /// Which of the plane's six operations.
    pub op: &'static str,
    /// The record's own key within the schema.
    pub key: &'a str,
    /// The record this leg belongs under, where the schema is a child one.
    pub parent: Option<&'a str>,
    /// The position within the parent, for an append.
    pub seq: u64,
    /// The opaque body. The store keeps it verbatim and never looks inside.
    pub body: &'a [u8],
    /// Whether this record is finished, which is what retention reads to decide whether it may go.
    pub terminal: bool,
    /// The wall clock, in seconds.
    pub now: u64,
    /// When a one-time grant lapses.
    pub expires_at: u64,
}

impl RecordLeg<'_> {
    /// The durable envelope this leg writes.
    fn record(&self) -> PlaneRecord {
        PlaneRecord {
            kind: self.schema.as_str().to_string(),
            id: self.key.to_string(),
            parent: self.parent.map(ToString::to_string),
            seq: self.seq,
            ts: self.now,
            disposition: if self.terminal {
                PlaneDisposition::Terminal
            } else {
                PlaneDisposition::Active
            },
            body: self.body.to_vec(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 6 — meter, over the two classes the plane declares
// ─────────────────────────────────────────────────────────────────────────────

/// Which lane legs this plane declares it produces.
///
/// One of the three, and the two absences are declarations rather than omissions. The plane's admit
/// facts carry no lane locator — the lane is a property of the registration the operator configured,
/// not of the request — and its usage locators name no lane either, for the same reason. Only the
/// verified destination names one, because the trust unit sealed it. Declaring the other two would
/// turn every settled unit into a dispute over a leg that was never going to arrive.
#[must_use]
pub fn leg_declaration() -> LegDeclaration {
    LegDeclaration {
        admit_locator: false,
        verified: true,
        response: false,
    }
}

/// The values this plane's locators retained for one answered unit.
///
/// A call that was answered is a call that was made, counted flat and exactly once. The byte line is
/// the answer's own size, which the plane already had in front of it — so the quantity travels with
/// the locator and no location is named, which the contract allows for precisely this case.
#[must_use]
pub fn located_values(op: OpClassId, response_bytes: u64) -> Vec<LocatedValue> {
    let mut out = Vec::with_capacity(2);
    if op == ops::OP_TOOL_CALL {
        out.push(LocatedValue {
            class: CLASS_TOOL_CALLS,
            quantity: 1,
            source: busbar_caps::QuantitySource::KernelFrames { factor: 1 },
        });
    }
    out.push(LocatedValue {
        class: CLASS_BYTES,
        quantity: response_bytes,
        source: busbar_caps::QuantitySource::KernelBytes { divisor: 1 },
    });
    out
}

/// Fold what the unit actually cost.
///
/// # Errors
///
/// The fold produced more lines than a unit may carry.
pub fn meter(
    retained: &RetainedLocatorValues,
    kernel: &KernelCounts,
    policy: &busbar_unit_usage::MeterPolicy,
    token: &UsageToken,
) -> Result<Metered, busbar_caps::UsageError> {
    fold_usage(retained, kernel, policy, &leg_declaration(), token)
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 7 — audit, on both chains
// ─────────────────────────────────────────────────────────────────────────────

/// The administrative-chain entry a served unit of this plane leaves.
///
/// Only a call leaves one. A listing, a task read and a notice change nothing an operator would want
/// to read back, and writing an entry for each of them would bury the ones that matter under the ones
/// that do not — which is exactly what the two separate chains exist to prevent.
///
/// **A seam to the I/O half.** Both the action and the resource prefix are the codec's own strings.
#[must_use]
pub fn legacy_entry(
    op: OpClassId,
    tool: &str,
    principal: &str,
    applied: bool,
    now: u64,
) -> Option<AuditInput> {
    if op != ops::OP_TOOL_CALL {
        return None;
    }
    Some(AuditInput {
        ts: now,
        action: AUDIT_ACTION_TOOL_CALL.to_string(),
        resource: format!("{AUDIT_RESOURCE_PREFIX_TOOL}{tool}"),
        outcome: if applied {
            OUTCOME_APPLIED.to_string()
        } else {
            OUTCOME_REJECTED.to_string()
        },
        principal: principal.to_string(),
    })
}

/// The fixed record's own operation class, from the plane's audit facts.
///
/// The audit crate keeps its own spelling of an operation class because its records are owned rows
/// rather than borrowed declarations. Converting here, once, is what keeps the two from drifting into
/// two vocabularies.
#[must_use]
pub fn record_op_class(op: OpClassId) -> busbar_unit_audit::record::OpClassId {
    busbar_unit_audit::record::OpClassId::new(op.as_str())
}

/// How the plane's finish class reads on the record.
#[must_use]
pub fn record_finish(
    finish: busbar_contract::unit::FinishClass,
) -> busbar_unit_audit::record::FinishClass {
    match finish {
        busbar_contract::unit::FinishClass::Complete => {
            busbar_unit_audit::record::FinishClass::Complete
        }
        busbar_contract::unit::FinishClass::TurnComplete => {
            busbar_unit_audit::record::FinishClass::TurnComplete
        }
        busbar_contract::unit::FinishClass::Partial => {
            busbar_unit_audit::record::FinishClass::Partial
        }
        busbar_contract::unit::FinishClass::Error => busbar_unit_audit::record::FinishClass::Error,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Exit — the totals the settlement posts against
// ─────────────────────────────────────────────────────────────────────────────

/// Where a settled unit of this plane posts.
///
/// One key per registration per dimension, so a deployment reading its books back can answer "what
/// did this server cost" without joining anything. The scope is the caller's, because that is what a
/// budget is drawn against.
#[must_use]
pub fn totals_key(server: &str, dimension: CapDimension, scope: BucketScope) -> TotalsKey {
    TotalsKey::new(BucketId::new(pool_key(server)), dimension, scope)
}

// ─────────────────────────────────────────────────────────────────────────────
// The mount
// ─────────────────────────────────────────────────────────────────────────────

/// Why the root refused to mount this plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountRefusal {
    /// A schema the plane declares carries no operations, so nothing could ever reach it.
    SchemaWithoutOperations(&'static str),
    /// A leg of some operation's plan names a schema or an operation the plane does not declare.
    /// The trust unit would refuse it at run time; refusing at boot is the same answer, sooner.
    UndeclaredLeg {
        /// The schema the leg named.
        schema: &'static str,
        /// The operation it named.
        op: &'static str,
    },
    /// The plane does not declare the class the metering binding posts a completed call under.
    MissingMeterClass(&'static str),
    /// Not every credentialed claim declares the same alternatives, so there is no one set for the
    /// authenticate step to narrow within.
    InconsistentSchemes,
}

impl std::fmt::Display for MountRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MountRefusal::SchemaWithoutOperations(schema) => {
                write!(f, "the mcp plane declares the unreachable schema {schema}")
            }
            MountRefusal::UndeclaredLeg { schema, op } => {
                write!(f, "an mcp route leg names an undeclared {op} on {schema}")
            }
            MountRefusal::MissingMeterClass(class) => {
                write!(f, "the mcp plane does not declare the class {class}")
            }
            MountRefusal::InconsistentSchemes => {
                write!(
                    f,
                    "the mcp plane's claims declare different scheme alternatives"
                )
            }
        }
    }
}

impl std::error::Error for MountRefusal {}

/// The MCP plane, bound to the units it is driven through.
///
/// Cheap and copyable except for the store handle, which is an `Arc` behind the adapter. There is
/// exactly one of these per process and it is built at boot, after the configuration has resolved and
/// every configured name has been interned.
pub struct Mount {
    /// The plane, with the registrations the operator configured.
    pub plane: McpPlane,
    /// This plane's record legs.
    pub records: Records,
    /// The scopes every operation class requires, ready to be declared to the policy.
    pub scopes: Vec<(OpClassId, Scope)>,
}

/// Check, at boot, everything about this plane that would otherwise be discovered as a refused
/// request, and produce the scope table the policy is told about.
///
/// Four checks, and each of them is a thing the tree cannot state any other way: a schema nothing can
/// reach, a leg naming an operation its schema never declared, a metering binding posting under a
/// class the plane does not have, and a claim set whose alternatives disagree. All four are cheap,
/// all four are answered once, and none of them can be answered by the plane alone — the plane
/// declares, and the root is what compares one declaration against another.
///
/// This half takes no store, because none of the four questions is about one. That is what lets the
/// boot sequence ask them where every other declaration is checked — before the configuration has
/// resolved and long before any listener is bound.
///
/// # Errors
///
/// Any of the four checks failed.
pub fn seal(plane: &McpPlane) -> Result<Vec<(OpClassId, Scope)>, MountRefusal> {
    let _ = plane;
    for schema in <McpPlane as PlaneMeta>::RECORD_SCHEMAS {
        if records::operations_for(*schema).is_empty() {
            return Err(MountRefusal::SchemaWithoutOperations(schema.as_str()));
        }
    }

    for (schema, op) in PLANNED_LEGS {
        if !records::operations_for(*schema).contains(op) {
            return Err(MountRefusal::UndeclaredLeg {
                schema: schema.as_str(),
                op,
            });
        }
    }

    if !<McpPlane as PlaneMeta>::METER_CLASSES
        .iter()
        .any(|c| c.key == CLASS_TOOL_CALLS)
    {
        return Err(MountRefusal::MissingMeterClass(CLASS_TOOL_CALLS.as_str()));
    }

    let mut declared: Option<&[&'static str]> = None;
    for claim in <McpPlane as PlaneMeta>::CLAIMS {
        if claim.scheme.is_none() {
            continue;
        }
        match declared {
            None => declared = Some(claim.scheme_alternatives),
            Some(first) if first == claim.scheme_alternatives => {}
            Some(_) => return Err(MountRefusal::InconsistentSchemes),
        }
    }

    Ok(required_scopes())
}

/// Bind the sealed plane to the store the loader opened.
///
/// The second half, and it is deliberately separate: the store is a product of the configuration and
/// the plugin loader, so it does not exist when the declarations are checked. Nothing here can fail —
/// everything that could has already been asked.
///
/// # Errors
///
/// Any of [`seal`]'s four checks failed.
pub fn mount(plane: McpPlane, store: &StoreAdapter) -> Result<Mount, MountRefusal> {
    let scopes = seal(&plane)?;
    Ok(Mount {
        plane,
        records: Records::new(store),
        scopes,
    })
}

/// Every schema and operation this plane's own plans reach, as a table the boot check reads.
///
/// Derived from the plane's routing method would be better, and it is not possible: reaching `route`
/// needs a live unit with a body in an arena, which is a request. So the pairs are written out and
/// pinned by a test that walks every declared operation class through the plane's own plan.
const PLANNED_LEGS: &[(RecordSchemaId, &str)] = &[
    (records::SCHEMA_CATALOGUE, records::OP_GET),
    (records::SCHEMA_CATALOGUE, records::OP_PUT),
    (records::SCHEMA_CATALOGUE, records::OP_SCAN),
    (records::SCHEMA_DEMOTION, records::OP_GET),
    (records::SCHEMA_DEMOTION, records::OP_SCAN),
    (records::SCHEMA_APPROVAL, records::OP_REDEEM),
    (records::SCHEMA_CALL, records::OP_APPEND),
    (records::SCHEMA_TASK, records::OP_GET),
    (records::SCHEMA_TASK, records::OP_PUT),
    (records::SCHEMA_SETTINGS, records::OP_GET),
];

/// The declared legs, for a caller that wants to check them without mounting.
#[must_use]
pub fn planned_legs() -> &'static [(RecordSchemaId, &'static str)] {
    PLANNED_LEGS
}

/// The pricing table the cost unit prices this plane's classes from, keyed by class name.
///
/// A convenience over the card rather than a second card: the root reads the two classes out once
/// and hands the estimate the maxima, so the admission step does not reach a rate table at all.
#[must_use]
pub fn class_prices(rates: &BTreeMap<String, u64>) -> ClassPrices {
    ClassPrices {
        tool_calls: rates
            .get(CLASS_TOOL_CALLS.as_str())
            .copied()
            .unwrap_or_default(),
        bytes: rates.get(CLASS_BYTES.as_str()).copied().unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store that keeps nothing.
    ///
    /// Every record operation the published protocol declares carries a default that accepts and
    /// keeps nothing, which is exactly the shape a backend with no durable rows has. That makes it
    /// the right double here: these tests are about which call the root makes for which leg, and a
    /// store that answered from real rows would be testing the store instead.
    struct SilentStore;

    impl AbiStore for SilentStore {
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
    }

    /// The plane declares one scheme with two alternatives, and the authenticate binding offers the
    /// auth unit exactly those two.
    ///
    /// The auth unit refuses a narrowing outside the declared set before it looks at a credential, so
    /// a root that offered a smaller set than the claims declare would refuse a caller the deployment
    /// meant to admit — and one that offered a larger set would let the plane pick a scheme the claim
    /// never made.
    #[test]
    fn the_declared_schemes_are_the_claims_own() {
        assert_eq!(declared_schemes(), vec!["bearer", "environment"]);
    }

    /// A locally launched server is narrowed to the credential it was handed at start; everything on
    /// the document transports presents a bearer.
    #[test]
    fn the_narrowing_follows_the_transport() {
        assert_eq!(narrowed_scheme(claims::TRANSPORT_STDIO), "environment");
        assert_eq!(narrowed_scheme(claims::TRANSPORT_HTTP), "bearer");
        assert_eq!(narrowed_scheme(claims::TRANSPORT_SSE), "bearer");
    }

    /// Every narrowing the root can produce is inside the set the claims declare.
    ///
    /// This is the property the auth unit's first check tests for, asserted here so a transport added
    /// to the claim list without an alternative is a red test rather than a refused request.
    #[test]
    fn every_narrowing_is_within_the_declared_set() {
        let declared = declared_schemes();
        for transport in [
            claims::TRANSPORT_HTTP,
            claims::TRANSPORT_SSE,
            claims::TRANSPORT_STDIO,
        ] {
            assert!(
                declared.contains(&narrowed_scheme(transport)),
                "{transport} narrows outside the declared set"
            );
        }
    }

    /// A record leg the plane declares passes the trust unit's per-kind rule; one it does not
    /// declare fails it.
    #[test]
    fn a_record_leg_is_judged_against_the_planes_own_declaration() {
        let declared = Catalogue::new(McpPlane::EMPTY, records::SCHEMA_CALL, records::OP_APPEND);
        assert!(declared.plane_record_ok());

        // The call log is append-and-read: an answer whose middle can be replaced is not an answer.
        let rewritten = Catalogue::new(McpPlane::EMPTY, records::SCHEMA_CALL, records::OP_PUT);
        assert!(!rewritten.plane_record_ok());

        let stranger = Catalogue::new(
            McpPlane::EMPTY,
            RecordSchemaId::new("ledger"),
            records::OP_GET,
        );
        assert!(!stranger.plane_record_ok());
    }

    /// A deployment with nothing registered has nowhere to send a hop, and says so.
    ///
    /// The plane answers with an empty host rather than panicking or inventing one, precisely so this
    /// refusal happens at the step that owns it.
    #[test]
    fn an_unregistered_hop_is_not_allow_listed() {
        let facts = Catalogue::upstream_only(McpPlane::EMPTY);
        let nowhere = DestinationFacts::Upstream {
            transport: claims::TRANSPORT_HTTP,
            address: busbar_contract::UpstreamAddress::socket(""),
            lane: LaneId::new(""),
        };
        assert!(!facts.allow_listed(&nowhere));
    }

    /// A registered server's own hop is allow-listed, and its lane is permitted.
    #[test]
    fn a_registered_hop_is_allow_listed() {
        static SERVERS: &[Server] = &[Server {
            id: "fs",
            lane: LaneId::new("fs-lane"),
            host: "127.0.0.1:9",
            transport: claims::TRANSPORT_HTTP,
        }];
        let plane = McpPlane::new(SERVERS);
        let facts = Catalogue::upstream_only(plane);
        let hop = DestinationFacts::Upstream {
            transport: claims::TRANSPORT_HTTP,
            address: busbar_contract::UpstreamAddress::socket("127.0.0.1:9"),
            lane: LaneId::new("fs-lane"),
        };
        assert!(facts.allow_listed(&hop));
        assert!(facts.transport_key_resolves(&hop));
        assert!(facts.lane_permitted_for_op_class("fs-lane"));
        assert!(!facts.lane_permitted_for_op_class("some-other-lane"));
    }

    /// An explicitly empty scope list denies every registration; an absent one denies none.
    ///
    /// The two are different answers to different questions and the rig's verify cell turns on the
    /// difference: a key scoped to nothing is refused before the door draws anything.
    #[test]
    fn an_explicit_empty_scope_list_denies_every_pool() {
        static SERVERS: &[Server] = &[Server {
            id: "fs",
            lane: LaneId::new("fs-lane"),
            host: "127.0.0.1:9",
            transport: claims::TRANSPORT_HTTP,
        }];
        let plane = McpPlane::new(SERVERS);

        let empty = Pools::new(plane, Some(Vec::new()), true, false);
        assert!(!empty.pool_allowed(&pool_key("fs")));

        let unrestricted = Pools::new(plane, None, true, false);
        assert!(unrestricted.pool_allowed(&pool_key("fs")));

        let named = Pools::new(plane, Some(vec!["fs".to_string()]), true, false);
        assert!(named.pool_allowed(&pool_key("fs")));
        assert!(!named.pool_allowed(&pool_key("other")));
    }

    /// A call names both resource kinds; everything else names only the server.
    ///
    /// The coarse grant never stands in for the fine one, which is the whole reason there are two.
    #[test]
    fn a_call_names_the_tool_as_well_as_the_server() {
        static SERVERS: &[Server] = &[Server {
            id: "fs",
            lane: LaneId::new("fs-lane"),
            host: "127.0.0.1:9",
            transport: claims::TRANSPORT_HTTP,
        }];
        let plane = McpPlane::new(SERVERS);

        let call = resources(&plane, ops::OP_TOOL_CALL);
        assert_eq!(call.len(), 2);
        assert_eq!(call[0].kind, SCOPE_KIND_SERVER);
        assert_eq!(call[1].kind, SCOPE_KIND_TOOL);

        let listing = resources(&plane, ops::OP_TOOLS_LIST);
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].kind, SCOPE_KIND_SERVER);
    }

    /// A deployment with nothing registered names no resource, and that is a refusal.
    #[test]
    fn nothing_registered_is_a_refusal_and_not_a_pass() {
        let policy = crate::root::policy::ScopePolicy::new().declaring(
            claim_key(),
            ops::OP_TOOL_CALL,
            Scope::Full,
        );
        let refusal = approve(
            &McpPlane::EMPTY,
            ops::OP_TOOL_CALL,
            Grants::of(Scope::Full),
            &policy,
        )
        .expect_err("a plane with no server authorizes nothing");
        assert_eq!(refusal, ApproveRefusal::NoResource);
    }

    /// A pair the policy says nothing about is refused, even when the caller holds every grant.
    ///
    /// Authorization by omission is the failure this shape exists to make impossible: the scope unit
    /// answers `None` for silence and `None` is a refusal.
    #[test]
    fn silence_is_a_refusal() {
        static SERVERS: &[Server] = &[Server {
            id: "fs",
            lane: LaneId::new("fs-lane"),
            host: "127.0.0.1:9",
            transport: claims::TRANSPORT_HTTP,
        }];
        let plane = McpPlane::new(SERVERS);
        let silent = crate::root::policy::ScopePolicy::new();
        let refusal = approve(&plane, ops::OP_TOOL_CALL, Grants::of(Scope::Full), &silent)
            .expect_err("an unwritten policy entry authorizes nothing");
        assert_eq!(refusal, ApproveRefusal::NoPolicyEntry);
    }

    /// A caller holding only the read-only grant may list and may not call.
    #[test]
    fn a_read_only_grant_lists_and_does_not_call() {
        static SERVERS: &[Server] = &[Server {
            id: "fs",
            lane: LaneId::new("fs-lane"),
            host: "127.0.0.1:9",
            transport: claims::TRANSPORT_HTTP,
        }];
        let plane = McpPlane::new(SERVERS);
        let mut policy = crate::root::policy::ScopePolicy::new();
        for (op, scope) in required_scopes() {
            policy = policy.declaring(claim_key(), op, scope);
        }

        assert!(approve(
            &plane,
            ops::OP_TOOLS_LIST,
            Grants::of(Scope::ReadOnly),
            &policy
        )
        .is_ok());

        let refusal = approve(
            &plane,
            ops::OP_TOOL_CALL,
            Grants::of(Scope::ReadOnly),
            &policy,
        )
        .expect_err("a read-only grant does not call a tool");
        assert!(matches!(refusal, ApproveRefusal::Insufficient(_)));
    }

    /// Every operation class the plane declares has a required scope, so no class is authorized by
    /// silence for want of an entry the root forgot to write.
    #[test]
    fn every_operation_class_has_a_required_scope() {
        let declared = required_scopes();
        assert_eq!(declared.len(), <McpPlane as PlaneMeta>::OP_CLASSES.len());
        for op in <McpPlane as PlaneMeta>::OP_CLASSES {
            assert!(
                declared.iter().any(|(o, _)| o == op),
                "{op} has no required scope"
            );
        }
    }

    /// A call is estimated as one call plus the request document; everything else is the document
    /// alone.
    #[test]
    fn a_call_is_estimated_flat_plus_its_document() {
        let prices = ClassPrices {
            tool_calls: 7,
            bytes: 2,
        };
        let call = estimate(ops::OP_TOOL_CALL, 10, &prices, 100);
        assert_eq!(call.per_class.len(), 2);
        assert_eq!(call.per_class[0].class, CLASS_TOOL_CALLS.as_str());
        assert_eq!(call.per_class[0].quantity, 1);
        // 100 fee + 1 call at 7 + 10 bytes at 2.
        assert_eq!(call.pre_tier_nanos(), 127);

        let listing = estimate(ops::OP_TOOLS_LIST, 10, &prices, 100);
        assert_eq!(listing.per_class.len(), 1);
        assert_eq!(listing.per_class[0].class, CLASS_BYTES.as_str());
    }

    /// Every kind the plane's plans name classifies to something the root can service, and no plan
    /// of this plane yields the unsupported arm.
    #[test]
    fn every_planned_kind_classifies() {
        assert_eq!(
            classify(&DestinationFacts::PlaneRecord {
                schema: records::SCHEMA_CALL,
                op: records::OP_APPEND,
            }),
            LegKind::Record {
                schema: records::SCHEMA_CALL,
                op: records::OP_APPEND,
            }
        );
        assert_eq!(
            classify(&DestinationFacts::NestedPlane {
                plane: "llm",
                op: OpClassId::new("chat"),
            }),
            LegKind::Nested {
                plane: "llm",
                op: OpClassId::new("chat"),
            }
        );
        assert_eq!(
            classify(&DestinationFacts::Client {
                selector: "opener",
                mode: busbar_contract::dest::ClientMode::Deliver,
            }),
            LegKind::Client { selector: "opener" }
        );
        assert!(matches!(
            classify(&DestinationFacts::Upstream {
                transport: claims::TRANSPORT_HTTP,
                address: busbar_contract::UpstreamAddress::socket("127.0.0.1:9"),
                lane: LaneId::new("fs-lane"),
            }),
            LegKind::Upstream { .. }
        ));
        assert_eq!(
            classify(&DestinationFacts::KernelVerb { verb: "restart" }),
            LegKind::Unsupported
        );
    }

    /// Every leg the plane's own plans reach is one its schema declares.
    ///
    /// This is the boot check's subject, asserted directly: a leg naming an operation its schema does
    /// not declare would be refused by the trust unit at run time, and a plane whose every plan
    /// depended on that refusal would be a plane that never worked.
    #[test]
    fn every_planned_leg_is_declared() {
        for (schema, op) in planned_legs() {
            assert!(
                records::operations_for(*schema).contains(op),
                "{schema} declares no {op}"
            );
        }
    }

    /// The plane's route plans reach exactly the legs the table names — no more, and no fewer.
    ///
    /// Reaching the plan itself needs a request, so the two sides are compared through the
    /// declarations both are built from: every pair in the table is declared, and every schema the
    /// plane declares appears in the table at least once. A schema nothing plans to reach is a
    /// schema that will never hold anything.
    #[test]
    fn every_declared_schema_is_reached_by_some_plan() {
        for schema in <McpPlane as PlaneMeta>::RECORD_SCHEMAS {
            assert!(
                planned_legs().iter().any(|(s, _)| s == schema),
                "{schema} is declared and never reached"
            );
        }
    }

    /// The metering binding posts a completed call under the class the plane declares, once.
    #[test]
    fn a_completed_call_is_counted_once() {
        let values = located_values(ops::OP_TOOL_CALL, 40);
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].class, CLASS_TOOL_CALLS);
        assert_eq!(values[0].quantity, 1);
        assert_eq!(values[1].class, CLASS_BYTES);
        assert_eq!(values[1].quantity, 40);

        let listing = located_values(ops::OP_TOOLS_LIST, 40);
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].class, CLASS_BYTES);
    }

    /// The plane declares one lane leg and disclaims the other two.
    ///
    /// Declaring a leg the plane never produces turns every settled unit into a dispute over evidence
    /// that was never going to arrive, which is the loudest way to be wrong about metering.
    #[test]
    fn only_the_verified_lane_leg_is_declared() {
        let declared = leg_declaration();
        assert!(declared.verified);
        assert!(!declared.admit_locator);
        assert!(!declared.response);
    }

    /// A served call leaves exactly one administrative entry, under the codec's own action and
    /// resource; nothing else leaves one at all.
    #[test]
    fn only_a_served_call_leaves_an_administrative_entry() {
        let entry = legacy_entry(ops::OP_TOOL_CALL, "probe_ping", "k-7", true, 100)
            .expect("a call is recorded");
        assert_eq!(entry.action, "mcp_tool.call");
        assert_eq!(entry.resource, "mcp_tool:probe_ping");
        assert_eq!(entry.outcome, OUTCOME_APPLIED);
        assert_eq!(entry.principal, "k-7");
        assert_eq!(entry.ts, 100);

        let refused = legacy_entry(ops::OP_TOOL_CALL, "probe_ping", "k-7", false, 100)
            .expect("a refused call is recorded too");
        assert_eq!(refused.outcome, OUTCOME_REJECTED);

        assert!(legacy_entry(ops::OP_TOOLS_LIST, "probe_ping", "k-7", true, 100).is_none());
        assert!(legacy_entry(ops::OP_NOTIFICATION, "probe_ping", "k-7", true, 100).is_none());
    }

    /// The action and the resource prefix are the codec's own strings.
    ///
    /// Both live in the half of this protocol that still holds the verb body, where they are visible
    /// to that crate only. This reads them out of its source, so a rename there is a red test here
    /// rather than an audit surface that answers under a name the rig does not look for.
    #[test]
    fn the_audit_strings_are_the_codecs_own() {
        let codec = include_str!("../../../busbar-mcp/src/mcp/method.rs");
        assert!(
            codec.contains(&format!("\"{AUDIT_ACTION_TOOL_CALL}\"")),
            "the codec no longer records under {AUDIT_ACTION_TOOL_CALL}"
        );
        assert!(
            codec.contains(&format!("\"{AUDIT_RESOURCE_PREFIX_TOOL}{{}}\"")),
            "the codec no longer names the {AUDIT_RESOURCE_PREFIX_TOOL} resource prefix"
        );
    }

    /// The two scope kinds are the ones the I/O half declares on its own plane row.
    #[test]
    fn the_scope_kinds_are_the_codecs_own() {
        let codec = include_str!("../../../busbar-mcp/src/mcp/mod.rs");
        assert!(
            codec.contains(&format!(
                "scope_kinds: &[\"{SCOPE_KIND_SERVER}\", \"{SCOPE_KIND_TOOL}\"]"
            )),
            "the codec no longer declares the two scope kinds"
        );
    }

    /// The pool prefix is the substrate's own, single-sourced there.
    #[test]
    fn the_pool_prefix_is_the_substrates_own() {
        let substrate = include_str!("../../../busbar-substrate/src/store.rs");
        assert!(
            substrate.contains(&format!("format!(\"{POOL_PREFIX_TOOL}{{server}}\")")),
            "the substrate no longer keys this plane's cells under {POOL_PREFIX_TOOL}"
        );
        assert_eq!(pool_key("fs"), "tool:fs");
    }

    /// A refusal message tells the caller nothing about the deployment's money.
    #[test]
    fn the_unpriced_message_leaks_nothing() {
        for leak in ["budget", "bucket", "price", "card", "cost", "spend"] {
            assert!(
                !UNPRICED_MESSAGE.to_ascii_lowercase().contains(leak),
                "the unpriced message leaks {leak}"
            );
        }
    }

    /// The mount's four checks pass on the plane as it is declared today.
    #[test]
    fn the_plane_mounts() {
        let store = StoreAdapter::native(Arc::new(SilentStore));
        let mounted = mount(McpPlane::EMPTY, &store).expect("the declared plane mounts");
        assert_eq!(
            mounted.scopes.len(),
            <McpPlane as PlaneMeta>::OP_CLASSES.len()
        );
    }

    /// A record leg the plane does not declare is refused before the store is asked.
    ///
    /// The trust unit refuses such a leg first; this is the second door, and it is here because a
    /// store reached by any other route would otherwise hold a record under a schema nothing reads
    /// back.
    #[test]
    fn an_undeclared_record_leg_never_reaches_the_store() {
        let store = StoreAdapter::native(Arc::new(SilentStore));
        let records_binding = Records::new(&store);
        let leg = RecordLeg {
            schema: records::SCHEMA_CALL,
            op: records::OP_PUT,
            key: "k",
            parent: None,
            seq: 1,
            body: b"{}",
            terminal: false,
            now: 100,
            expires_at: 0,
        };
        let refusal = records_binding
            .run(&leg)
            .expect_err("the call log cannot be rewritten");
        assert!(matches!(refusal, RecordRefusal::Undeclared { .. }));
    }

    /// Every operation the plane declares has an arm, and each answers in the shape its schema means.
    #[test]
    fn every_declared_operation_has_an_arm() {
        let store = StoreAdapter::native(Arc::new(SilentStore));
        let binding = Records::new(&store);
        let leg = |schema, op| RecordLeg {
            schema,
            op,
            key: "k",
            parent: None,
            seq: 1,
            body: b"{}",
            terminal: false,
            now: 100,
            expires_at: 200,
        };

        for schema in <McpPlane as PlaneMeta>::RECORD_SCHEMAS {
            for op in records::operations_for(*schema) {
                let answer = binding
                    .run(&leg(*schema, op))
                    .unwrap_or_else(|e| panic!("{schema}/{op} has no arm: {e}"));
                match *op {
                    records::OP_GET => assert!(matches!(answer, RecordAnswer::One(_))),
                    records::OP_SCAN => assert!(matches!(answer, RecordAnswer::Many(_))),
                    records::OP_REDEEM => assert!(matches!(answer, RecordAnswer::Redeemed(_))),
                    _ => assert_eq!(answer, RecordAnswer::Written),
                }
            }
        }
    }

    /// A grant is spent atomically, and the spend is the store's own test-and-set rather than a read
    /// followed by a write.
    ///
    /// The two-step version is the race the operation exists to close: between the read and the write
    /// a second caller spends the same grant, and a retry of a failed hop becomes a second free call.
    #[test]
    fn a_grant_is_spent_by_a_test_and_set() {
        let ops = records::operations_for(records::SCHEMA_APPROVAL);
        assert!(ops.contains(&records::OP_REDEEM));
        assert!(!ops.contains(&records::OP_GET));
        assert!(!ops.contains(&records::OP_SCAN));
    }

    /// The totals key names the registration, under the same prefix the breaker cells use, so the
    /// books and the breaker answer about the same thing.
    #[test]
    fn the_totals_key_names_the_registration() {
        let key = totals_key(
            "fs",
            CapDimension::class(&CLASS_TOOL_CALLS),
            BucketScope::Pool(pool_key("fs")),
        );
        assert_eq!(key.bucket.as_str(), "tool:fs");
    }
}
