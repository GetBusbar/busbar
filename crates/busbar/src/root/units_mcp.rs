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
use std::sync::{Arc, Mutex};

use busbar_caps::{
    Admit, AdmitToken, Approve, Arrival, ArrivalRecord, Audit, AuditFacts, Authenticate, Decision,
    Decode, Encode, Meter, Outcome, PrincipalId, ReasonCode, Refusal, Route, RoutePlan, ScopeFacts,
    StepName, TrustToken, UnitToken, UsageToken, Verify,
};
use busbar_contract::dest::{DestinationFacts, Leg};
use busbar_contract::ids::{ClaimKey, LaneId, OpClassId, RecordSchemaId};
use busbar_contract::plane::{Plane, PlaneMeta};
use busbar_contract::VirtualKeyDirectory;
use busbar_kernel::slice::{DoorGrant, GroupLeaseSlip};
use busbar_kernel::teller::{AccrualMeter, Evidence, UnitCtx, Units};
use busbar_plane_mcp::meta::{CLASS_BYTES, CLASS_TOOL_CALLS};
use busbar_plane_mcp::{claims, ops, records, McpPlane, Server};
use busbar_plugin_loader::store_adapter::StoreAdapter;

use crate::root::store::{PlaneRecords, RecordAnswer, RecordLeg, RecordRefusal};
use busbar_unit_admission::{
    Admission, AdmissionUnit, BucketChain, ClassEstimate, Door, Estimate, InMemoryCells, Pricer,
};
use busbar_unit_audit::legacy::{AuditInput, OUTCOME_APPLIED, OUTCOME_REJECTED};
use busbar_unit_audit::{Audit as _, AuditInputs};
use busbar_unit_auth::{Auth, AuthRequest, CredentialCache};
use busbar_unit_ledger::{BucketId, BucketScope, CapDimension, TotalsKey};
use busbar_unit_scope::{Grants, PolicyView, Refused, Scope};
use busbar_unit_trust::destination::{KindFacts, OriginKind};
use busbar_unit_trust::guard::PoolView;
use busbar_unit_trust::lane::{BreakerQuery, BreakerView};
use busbar_unit_trust::net::{Denylist, GuardPolicy, Resolver};
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
// Step 0 — arrival, over the connection the transport recorded
// ─────────────────────────────────────────────────────────────────────────────

/// One connection as the transport stack recorded it, paired with the claim it was matched by.
///
/// The record is borrowed rather than owned because the kernel holds it for the whole unit and this
/// step neither keeps nor edits it.
#[derive(Debug, Clone, Copy)]
pub struct Arrived<'a> {
    /// What the transports wrote about the connection, bottom layer first.
    pub record: &'a ArrivalRecord,
    /// The transport named by the claim that matched, which is the layer this plane believes it is
    /// answering on.
    pub claim_transport: &'a str,
}

/// The connection's own facts, carried forward for the steps that resolve against them.
///
/// The gate itself is the kernel's — the in-flight table, the rate, the cursor and spill budgets are
/// all decided before any plane is known, and this step never sees them. What a plane's binding owes
/// here is the handover, and the handover has one way of going wrong that only the plane can catch:
/// the claim and the stack must be describing the same connection. Everything downstream depends on
/// it. The scheme narrowing is a function of the transport; the audience is a function of whether
/// the claim carries a scheme at all; every location the later steps resolve is resolved against
/// this record and re-resolved after an upgrade. A record handed on under the wrong claim is a unit
/// authenticated for one surface and answered on another.
pub fn arrival(arrived: &Arrived<'_>, token: &UnitToken<Arrival>) -> Decision<Arrival> {
    // A claim is the ONLY way this plane names a transport, so a transport no claim names is one no
    // unit of this plane may arrive on — whatever else the node has registered.
    if !claims::declares(arrived.claim_transport) {
        return Decision::refuse(token, Refusal::new(ReasonCode::HandoffMismatch));
    }
    // And the claim's transport is the TOP of the composed chain, not merely somewhere in it. The
    // streamed surface stands on the document one, so a chain that ended at `sse` contains `http`;
    // reading membership rather than the top would let a stream be matched as a request.
    if arrived.record.transport_chain.last() != Some(&arrived.claim_transport) {
        return Decision::refuse(token, Refusal::new(ReasonCode::HandoffMismatch));
    }
    Decision::proceed(token, arrived.record.clone())
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 0b — decode, through the plane's own reading of the envelope
// ─────────────────────────────────────────────────────────────────────────────

/// What the plane made of one inbound frame.
///
/// Three answers rather than two, because "not a unit" is not one thing. A notice nothing
/// recognises is dropped and a partial frame is waited on, and neither is a refusal: this protocol
/// forbids answering a message that carries no identifier, so refusing one would be an answer to a
/// caller who is owed silence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read<'u> {
    /// A draft the loop runs. Boxed because the fact map is a fixed array sized for the declared
    /// key ceiling, and an enum whose other arms are empty should not be that wide everywhere.
    Unit(Box<Decoded<'u>>),
    /// A notice this node does not recognise. Counted, never answered.
    Dropped,
    /// Not a whole frame yet.
    NeedMore,
}

/// What the plane's read of one request body yielded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded<'u> {
    /// The operation class the plane's method table named.
    pub op: OpClassId,
    /// Whether the unit holds its direction open rather than being answered once.
    pub streaming: bool,
    /// The facts the plane read off the bytes, including the caller's metadata block.
    pub facts: busbar_contract::bounded::Facts<'u>,
}

/// Read one inbound frame through the plane's own ingress decoder.
///
/// The root does not parse this protocol and must not: the envelope shape, the method table and the
/// pointer table are all the plane's, and a second reading here would be a second grammar. What the
/// root owns is the mapping from the plane's decode failure onto the loop's closed reason
/// vocabulary, which is the thing the journal and the refusal both name.
///
/// # Errors
/// Returns the reason a refusal at the decode step carries when the plane could not read the bytes.
pub fn read_ingress<'u>(
    plane: &McpPlane,
    frames: &mut busbar_contract::wire::FrameCursor<'u>,
    ctx: &busbar_contract::unit::Ctx<'u>,
) -> Result<Read<'u>, ReasonCode> {
    let ingress = plane
        .decode_ingress(frames, None, ctx)
        .map_err(|failure| match failure {
            // The arena running out is a budget, not a misread body, and the two carry different
            // reasons because a caller who is over a bound and a caller who sent nonsense are owed
            // different answers.
            busbar_contract::wire::Decode::Oversize => ReasonCode::ArenaBudget,
            _ => ReasonCode::DecodeFailed,
        })?;
    Ok(match ingress {
        busbar_contract::plane::Ingress::OneShot(draft) => Read::Unit(Box::new(Decoded {
            op: draft.op,
            streaming: false,
            facts: draft.facts,
        })),
        busbar_contract::plane::Ingress::Open(draft) => Read::Unit(Box::new(Decoded {
            op: draft.op,
            streaming: true,
            facts: draft.facts,
        })),
        busbar_contract::plane::Ingress::Discard { .. } => Read::Dropped,
        busbar_contract::plane::Ingress::NeedMore => Read::NeedMore,
        // This plane opens no handshake unit and closes no session of its own — every claim it
        // makes carries its credential on the first frame. A decoder that started answering either
        // would be a plane whose shape changed, and carrying such a frame on as a unit would give
        // it a class nobody decoded.
        _ => return Err(ReasonCode::DecodeFailed),
    })
}

/// Answer the decode step with the class the plane named.
///
/// The bytes are read once, at the one step entitled to read them, and this restates that answer
/// rather than re-deriving it: re-reading here would advance the codec a second time over the same
/// frame and could disagree with the draft every later step is built from.
pub fn decode(read: &Result<Read<'_>, ReasonCode>, token: &UnitToken<Decode>) -> Decision<Decode> {
    match read {
        Ok(Read::Unit(decoded)) => Decision::proceed(token, decoded.op),
        // Neither of these opens a unit, so neither should have reached a step. Refusing rather
        // than inventing a class is the honest answer to a caller of this binding that got the
        // sequencing wrong.
        Ok(Read::Dropped | Read::NeedMore) => {
            Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed))
        }
        Err(reason) => Decision::refuse(token, Refusal::new(*reason)),
    }
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

/// The alternative the plane narrows a unit on this claim key to.
///
/// A locally launched server has no request to carry a header on: its credential was handed to it
/// when it started. Everything on the document transport presents a bearer credential. This is the
/// plane's own answer, restated over the claim key because the root reaches the plane's
/// `authenticate` only with a live unit in hand and the narrowing depends on nothing else.
///
/// The question is asked by NAME (`claims::is_stdio`) rather than compared here. What arrives is a
/// `&str` claim key out of the plane's own claim vocabulary, never the engine's `Transport` axis —
/// but a bare `if transport == claims::TRANSPORT_STDIO` is indistinguishable, to a reader and to the
/// axis lint alike, from the agnostic root forking on the wire carrier it may not see. Asking the
/// plane its own named question says what is meant and leaves the comparison in the plane that owns
/// the constant.
#[must_use]
pub fn narrowed_scheme(claim_key: &str) -> &'static str {
    if claims::is_stdio(claim_key) {
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
    directory: Option<&dyn VirtualKeyDirectory>,
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
    auth.resolve(&request, cache, directory, None, token)
}

/// Ask the auth unit who is calling, over the node's own bindings.
///
/// The form above takes the two seams one at a time because that is the shape the unit's own
/// signature has, and a test that wants to state exactly one of them says so by handing one
/// `None`. This is the form a dispatch uses, and it is the one that closes the gap: the seams are
/// not two arguments a caller has to remember to fill in, they are the node's one set, reached
/// through the value that holds them. A dispatch calling [`authenticate`] directly could pass
/// `None` twice and compile; calling this one cannot.
pub fn authenticate_bound(
    auth: &Auth,
    arriving: &Arriving<'_>,
    bindings: &crate::root::kernel::auth_bindings::AuthBindings,
    token: &UnitToken<Authenticate>,
) -> Decision<Authenticate> {
    authenticate(
        auth,
        arriving,
        bindings.cache(),
        bindings.directory(),
        token,
    )
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
pub struct Catalogue<'r> {
    plane: McpPlane,
    schema: RecordSchemaId,
    op: &'static str,
    lanes: Vec<LaneId>,
    net: NetSeam<'r>,
}

/// What the network guard is run over, as this root binds it.
///
/// The three halves travel together because they are one decision: which resolver answers, how far
/// the policy lets a hop reach, and what the operator added to or carved out of the metadata
/// denylist. Passing them singly is how a caller ends up guarding with one deployment's policy and
/// another deployment's denylist.
#[derive(Clone, Copy)]
pub struct NetSeam<'r> {
    /// The one resolution the guard makes goes through here.
    pub resolver: &'r dyn Resolver,
    /// How far this plane's hops may reach.
    pub policy: GuardPolicy,
    /// The deployment's additions to and carve-outs from the metadata denylist.
    pub denylist: &'r Denylist,
}

impl<'r> Catalogue<'r> {
    /// The facts for one unit, whose plan reaches one schema under one operation.
    #[must_use]
    pub fn new(
        plane: McpPlane,
        schema: RecordSchemaId,
        op: &'static str,
        net: NetSeam<'r>,
    ) -> Self {
        let lanes = plane.servers().iter().map(|s| s.lane).collect();
        Catalogue {
            plane,
            schema,
            op,
            lanes,
            net,
        }
    }

    /// The facts for a unit that reaches no record at all — a hop straight to a server.
    #[must_use]
    pub fn upstream_only(plane: McpPlane, net: NetSeam<'r>) -> Self {
        Catalogue::new(plane, records::SCHEMA_CATALOGUE, records::OP_SCAN, net)
    }

    /// Where one lane sits in the registered-server table, which is the position the breaker keys
    /// its cells by.
    fn lane_index(&self, lane: &LaneId) -> Option<usize> {
        self.plane.servers().iter().position(|s| s.lane == *lane)
    }

    /// The registered server one destination names, where it names one.
    fn server_for(&self, dest: &DestinationFacts) -> Option<&'static Server> {
        let lane = dest.lane()?;
        self.plane.servers().iter().find(|s| s.lane == lane)
    }
}

impl KindFacts for Catalogue<'_> {
    fn net_guard_passes(&self, dest: &DestinationFacts) -> bool {
        match busbar_unit_trust::net::check_destination_facts(
            dest,
            &[],
            self.net.resolver,
            self.net.policy,
            self.net.denylist,
        ) {
            // Only an upstream is dialled at an address; every other kind of this plane's
            // destinations reaches where it is going without one, so "not an upstream" is this
            // caller's pass rather than its refusal. A spawned stdio server has an address that is
            // a program, and the guard answers `Ok(None)` for it for the same reason.
            Ok(_) | Err(busbar_unit_trust::NetworkRefusal::NotAnUpstream) => true,
            Err(_) => false,
        }
    }

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

    fn unit_price_within_max(&self, _dest: &DestinationFacts) -> bool {
        // A card that states no maximum unit price has said nothing for a price to be over. Reading
        // that silence as a ceiling of zero would exclude every registered server on every
        // deployment whose card predates the field.
        true
    }

    fn breaker_admits(&self, dest: &DestinationFacts, at: &BreakerQuery<'_>) -> bool {
        // The mapping is this root's — a lane name is a position in the registered-server table and
        // nothing outside here knows the order. The QUESTION is the query's, so the answer here is
        // the same answer the pre-walk's filter gives about the same lane at the same moment.
        match dest.lane().and_then(|lane| self.lane_index(&lane)) {
            Some(index) => at.admits_lane(index),
            // A destination priced on no registered lane has no position for the breaker to hold an
            // opinion about; the allow-list conjunct beside this one has already refused it.
            None => true,
        }
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
    views: Views<'_>,
    now: u64,
    trust_token: &TrustToken,
    token: &UnitToken<Verify>,
) -> Decision<Verify> {
    let request = VerifyRequest {
        // Every unit of this plane is a client's own request or a frame a paired server pushed; the
        // origin decides which kinds each may reach at all, and this is the client half.
        origin: OriginKind::Client,
        candidates: candidate,
        pool,
        // The unit's pinned arrival epoch, carried in rather than read here: the readiness peek this
        // step takes has to be the same moment the walk's own filter takes.
        now,
        unpriced_message: UNPRICED_MESSAGE,
    };
    trust.verify(
        &request,
        views.pools,
        views.facts,
        views.breaker,
        trust_token,
        token,
    )
}

/// The three tables the trust unit reads, as this root binds them.
///
/// They travel together because they are read together and about the same request: the pools this
/// caller's key may use, the per-kind facts, and the breaker whose answer must match the walk's.
/// Handing them singly is how a caller ends up asking one deployment's breaker about another
/// deployment's pool.
#[derive(Clone, Copy)]
pub struct Views<'v> {
    /// What the deployment says about its pools and this caller's key.
    pub pools: &'v dyn PoolView,
    /// What the per-kind destination rules consult.
    pub facts: &'v dyn KindFacts,
    /// The breaker the dialled kinds' rules are judged against.
    pub breaker: &'v dyn BreakerView,
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

/// Ask the door, and put what its yes counted onto the unit's slot.
///
/// The slip is the second half of the answer and not a courtesy: the door raises a gauge per capped
/// group when it says yes and lowers it when the grant is dropped, so a grant that dies with this
/// call is a cap released before the unit it admitted has done anything — and a group written
/// `concurrent: 1` would then admit every unit that ever arrives. Handed to the slot, the count is
/// held for as long as the unit is in the air and given back at whichever of its two ends arrives
/// first, which is what makes the limit a limit.
///
/// The names beside it are what the door counted, said out loud: one lease per capped group, interned
/// where the root interned them, recorded on the same slot. Empty on a refusal and empty for a chain
/// with no capped group — neither is decided here.
pub fn admit(
    unit: &Admitting<'_>,
    admit_token: &AdmitToken<Admit>,
    token: &UnitToken<Admit>,
    leases: &GroupLeaseSlip,
) -> Decision<Admit> {
    let mut door = AdmissionUnit::new(unit.door, unit.pricer, unit.pool, unit.arrival_epoch);
    let decision = door.admit(
        unit.estimate,
        unit.principal,
        unit.chain,
        admit_token,
        token,
    );
    for group in door.group_leases() {
        leases.counted(group);
    }
    if let Some(grant) = door.take_grant() {
        leases.holding(DoorGrant::new(grant));
    }
    decision
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
// The exit — the reservation the door opened is closed here, and only here
// ─────────────────────────────────────────────────────────────────────────────

/// What one unit of this plane IS, as far as the money is concerned.
///
/// Two facts and not one: the operation class the record names, and whether the plan the plane
/// returned reaches the registered server. The second is what the flat fee turns on, and it is READ
/// OFF THE PLAN rather than written down here as a list of which classes hop — a list here would be
/// a second copy of the plane's routing, and the copy that drifts is the one nobody re-derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    /// Which operation class ran.
    pub op: OpClassId,
    /// Whether any leg of the plan goes to the registered server.
    pub hops_upstream: bool,
}

impl Shape {
    /// The shape of one unit, from its class and the plan the root already classified.
    #[must_use]
    pub fn of(op: OpClassId, legs: &[LegKind]) -> Self {
        Self {
            op,
            hops_upstream: legs
                .iter()
                .any(|leg| matches!(leg, LegKind::Upstream { .. })),
        }
    }
}

/// The facts this plane's flat per-request fee is decided from.
///
/// Written once, as a function over the unit's shape rather than as a table each caller fills in,
/// because the exit path and the audit record are two readers of ONE decision: a settlement that
/// posted a fee against a record that says none is a discrepancy nothing downstream can resolve, and
/// the only way to make that unrepresentable is to have one place decide it. The estimate takes a fee
/// into the hold; without this, the hold reserved a fee no path could ever post, and the reservation
/// was money set aside against a charge that did not exist.
///
/// The origin is the client rule the request slot is drawn under — a notification the server pushed
/// is not a caller's request and pays nothing. The upstream is the KIND of leg the plan carries, not
/// its price: with no rate card the fee still posts, which is why a listing answered entirely from
/// this node's own records draws none. The relayed frame is the metering step's own locator, which is
/// set when the plane read an answer to hand back; a unit that never got that far relayed nothing.
/// This protocol carries no status leg of its own — the answer document IS the response — so the
/// plane's finish is the single source, and an error ending posts nothing.
#[must_use]
pub fn fee_evidence(
    shape: Shape,
    origin: busbar_caps::OriginKind,
    relayed_first_response_frame: bool,
    finish: busbar_contract::unit::FinishClass,
) -> busbar_kernel::teller::FeeEvidence {
    busbar_kernel::teller::FeeEvidence {
        client_open_or_one_shot: origin == busbar_caps::OriginKind::Client,
        selected_upstream: shape.hops_upstream,
        relayed_first_response_frame,
        status_at: None,
        status: None,
        finish: Some(finish),
    }
}

/// What one ended unit of this plane consumed, as the exit and the record both read it.
///
/// One borrowed value rather than a list of arguments, for the same reason the door's is one: the
/// settlement and the audit record are two READERS of one set of facts, and two call sites filling
/// the same figures in independently is exactly where a posting that says one thing and a row that
/// says another comes from.
pub struct Ended<'a> {
    /// What the unit is, as far as the money is concerned.
    pub shape: Shape,
    /// Where the unit came from.
    pub origin: busbar_caps::OriginKind,
    /// The plane's own verdict on the ending.
    pub finish: busbar_contract::unit::FinishClass,
    /// The request document the hold was sized against, which is the kernel's own floor.
    pub request_bytes: u64,
    /// What the metering step located, where it ran. `None` is a unit that never got an answer to
    /// hand back — and it is also this plane's answer to "was a response relayed".
    pub metered: Option<u64>,
    /// Whether any leg of the plan was dispatched.
    pub dispatched: bool,
    /// Who was calling, where the loop resolved them.
    pub principal: Option<&'a PrincipalId>,
    /// What the record names as the thing acted on.
    pub resource: Option<Resource>,
}

/// The evidence one ended unit settles against.
///
/// The class is the byte-shaped one: the floor and the located figure are both readings of the
/// document, and the call-shaped line is a flat count rather than what the amount is denominated in.
#[must_use]
pub fn evidence(ended: &Ended<'_>) -> Evidence {
    Evidence {
        located: ended.metered,
        accrued_floor: ended.request_bytes,
        // Nothing is required of a card that does not price this class. With a card that does, the
        // located figure is what settles and the floor is the tripwire beside it.
        locator_required: false,
        terminal_error: matches!(ended.finish, busbar_contract::unit::FinishClass::Error),
        recovered: false,
        dispatched: ended.dispatched,
        checkpointed: 0,
        variance: None,
        lane_mismatch: None,
        settle_record_lost: false,
        class: Some(CLASS_BYTES),
        // The fee's upstream rule and the request slot's are the same rule, read from the same fact.
        upstream_candidate: ended.shape.hops_upstream,
        fee: fee_evidence(
            ended.shape,
            ended.origin,
            ended.metered.is_some(),
            ended.finish,
        ),
    }
}

/// **The exit arm.** Move the books for what one unit posted, and put the posting on the journal.
///
/// The loop's exit path takes the hold out of its cell, applies what the unit spent and settles it —
/// that is where the hold stops existing. What comes back is the POSTING, and until it reaches here
/// it has moved no balance and left no record. So this is the far end of the reservation's life: the
/// door opened it, the metering step accrued against it, and the settlement here releases what was
/// never used and carries out what nothing could back.
///
/// `at` carries the unit's two pinned clocks, so a request that straddled a window boundary posts in
/// the window it was admitted in rather than the one it happened to finish in.
///
/// # Errors
///
/// The journal could not make the record durable. The books have already moved: value was delivered,
/// and a settlement is not rolled back because a write failed.
pub fn settle(
    durability: &mut crate::root::durability::Durability,
    principal: &PrincipalId,
    at: Clocks,
    token: &busbar_caps::DurabilityToken,
    posted: busbar_caps::Posted,
) -> Result<crate::root::durability::Settled, busbar_caps::DurabilityLost> {
    let key = balance(principal);
    let settling = crate::root::durability::Settling {
        key: &key,
        window: busbar_unit_admission::budget_window(
            busbar_unit_admission::window::WINDOW_DAY,
            at.wall,
        ),
        durability: token,
        // The loop has no exit step of its own; the figure this posting is OF is the metering
        // step's, and that is the step a durability loss here is attributed to.
        step: StepName::Meter,
        stamp: crate::root::durability::PostingStamp {
            rate_card_version: 0,
            wall: at.wall,
            mono: at.mono,
        },
    };
    durability.settle_posted(&settling, posted)
}

/// The two clocks one unit's posting is stamped with, both read once, where the unit arrived.
///
/// Two readings and not one. The wall clock says which window the money belongs to and is the figure
/// an operator recognises; the monotonic reading is what ORDERS one unit's events against another's,
/// and it is a second clock precisely because the first one can move — an operator correcting a
/// drifting node, an NTP step, a leap second. A stamp whose monotonic field is the wall clock keeps
/// none of what the second clock was for: two units that arrived in the same second are stamped
/// identically, and a chain read back after the clock moved backwards has records out of order with
/// nothing to say so.
///
/// Both are PINNED WHERE THE UNIT ARRIVED and carried here, never read again at the exit, for the
/// reason the door's own epoch is pinned: a unit that straddled a boundary must post in the window
/// it was admitted in, and its ordering must be its arrival's rather than its ending's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clocks {
    /// The wall clock at arrival, in whole seconds.
    pub wall: u64,
    /// The node's monotonic reading at arrival.
    pub mono: u64,
}

/// The monotonic clock one node's MCP postings are ordered by.
///
/// A counter the root holds and this plane's units read, rather than a clock a step could read for
/// itself: a reading taken at the exit would order units by when they finished, which is not the
/// order anything about them happened in. It is the same shape the voice leg's node keeps, and for
/// the same reason.
#[derive(Debug, Default)]
pub struct Mono(std::sync::atomic::AtomicU64);

impl Mono {
    /// A node's clock, starting where every node's does.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The next reading. Taken once, where a unit arrives.
    pub fn tick(&self) -> u64 {
        self.0.fetch_add(1, std::sync::atomic::Ordering::AcqRel)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 7 — audit, on both chains
// ─────────────────────────────────────────────────────────────────────────────

/// The record one ending seals on the audit chain.
///
/// The record does not decide the fee a second time. It reads the same evidence the exit path
/// settles from, through the same function, so a row that says one fee and a posting that says none
/// cannot both be true of one unit.
///
/// The clocks are the unit's pinned pair, exactly as the settlement's are: a record stamped at the
/// exit and a posting stamped at arrival are two accounts of one moment.
#[must_use]
pub fn audit_inputs(
    ended: &Ended<'_>,
    outcome: Outcome,
    origin: busbar_caps::Origin,
    at: Clocks,
) -> AuditInputs {
    let (fee_count, _) = busbar_kernel::teller::fee_count(&fee_evidence(
        ended.shape,
        ended.origin,
        ended.metered.is_some(),
        ended.finish,
    ));
    AuditInputs {
        subject: match ended.principal {
            Some(who) => busbar_unit_audit::Subject::PrincipalId(who.as_str().to_string()),
            None => busbar_unit_audit::Subject::Arrival,
        },
        what: busbar_unit_audit::What {
            unit_key: busbar_contract::ids::UnitKey::new(0),
            op_class: record_op_class(ended.shape.op),
            destination: ended
                .resource
                .map(|resource| format!("{}:{}", resource.kind, resource.name)),
            parent: None,
            pre_hook_head: None,
            post_hook_head: None,
        },
        wall: at.wall,
        mono: at.mono,
        origin,
        outcome: busbar_unit_audit::OutcomeFacts {
            unit_end: outcome,
            step: outcome.step(),
            finish: record_finish(ended.finish),
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

/// The balance one unit of this plane settles into: the caller's own attribution bucket, in
/// nano-units, across every pool.
///
/// The bucket is the PRINCIPAL's, which is the same bucket the other planes settle into and the same
/// one `/usage` reads back. A registration-shaped bucket would answer "what did this server cost"
/// and nothing else: the caller's spend on this plane would be missing from every figure a principal
/// is quoted, and the reconciliation identity — the ledger's postings against the rows the usage
/// projection keeps — would carry a difference no operator could ever close, because the two sides
/// would be counting different things rather than disagreeing about one.
///
/// Every pool, because an attribution bucket is not a budget: the caps a deployment configures are
/// walked at the door, and what settles here is the money one caller spent, whatever it was spent
/// through.
#[must_use]
pub fn balance(principal: &PrincipalId) -> TotalsKey {
    TotalsKey::new(
        BucketId::new(principal.as_str()),
        CapDimension::NanoUnits,
        BucketScope::All,
    )
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
    pub records: PlaneRecords,
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
        records: PlaneRecords::of(store, records::operations_for),
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

// ─────────────────────────────────────────────────────────────────────────────
// THE LEG — one MCP request, through the loop the units serve
// ─────────────────────────────────────────────────────────────────────────────

/// What the plane made of one arriving request, as an OWNED value every step reads.
///
/// Owned, and that is the whole reason this type exists rather than the borrowed [`Read`] above.
/// The loop hands each step `&self` and nothing else, so whatever the steps read has to outlive the
/// arena the bytes were decoded in; a draft that borrowed the frame would tie the unit's lifetime to
/// the cursor and the loop would not compile. So the read happens ONCE, at the one step entitled to
/// read it, and what survives is the answer rather than the bytes.
pub struct McpDraft {
    /// The class the plane's method table named, or the reason it could not read the body.
    pub op: Result<OpClassId, ReasonCode>,
    /// Whether the unit holds its direction open rather than being answered once.
    pub streaming: bool,
    /// The credential the transport masked out of the frame, where one arrived.
    pub credential: Option<String>,
    /// The claim this unit arrived under, which is how this plane names a transport.
    pub claim_transport: &'static str,
    /// Whether that claim declares a scheme at all. The discovery surface declares none.
    pub under_scheme: bool,
    /// Whether the principal is a bound session's rather than these bytes'.
    pub from_session: bool,
    /// What the transports wrote about the connection, bottom layer first.
    pub arrival: ArrivalRecord,
    /// Where the plane says this unit ends up.
    pub destination: DestinationFacts,
    /// The legs of the plane's route plan, in the plan's order.
    pub legs: Vec<Leg>,
    /// The record key each leg names, in the plan's order. A leg that names none carries the empty
    /// string, which is what the schema's own key vocabulary calls "the whole of it".
    pub record_keys: Vec<String>,
    /// The body a record leg writes. The store keeps it verbatim and never looks inside.
    pub record_body: Vec<u8>,
    /// The whole request document's length, which is what this plane prices its input on.
    pub request_bytes: u64,
    /// What the metering step's locator carries — the size of the answer the plane read.
    pub response_bytes: u64,
    /// How the plane says the unit finished.
    pub finish: busbar_contract::unit::FinishClass,
}

impl McpDraft {
    /// **The production caller of [`read_ingress`].** Read one arriving request through the plane's
    /// own ingress decoder and keep what the steps need.
    ///
    /// The decode failure is CARRIED rather than raised, because the step that answers for it is the
    /// decode step and the loop has not reached it yet. A constructor that returned an error here
    /// would be refusing a unit before the loop opened one, and the journal would carry no row for
    /// a request that was certainly answered.
    #[must_use]
    pub fn read<'u>(
        plane: &McpPlane,
        frames: &mut busbar_contract::wire::FrameCursor<'u>,
        ctx: &busbar_contract::unit::Ctx<'u>,
        wire: Wire<'_>,
    ) -> Self {
        let (op, streaming) = match read_ingress(plane, frames, ctx) {
            Ok(Read::Unit(decoded)) => (Ok(decoded.op), decoded.streaming),
            // Neither a dropped notice nor a partial frame opens a unit, and neither is a class.
            // The decode step renders both the way it renders a body this plane does not carry.
            Ok(Read::Dropped | Read::NeedMore) => (Err(ReasonCode::DecodeFailed), false),
            Err(reason) => (Err(reason), false),
        };
        McpDraft {
            op,
            streaming,
            credential: wire.credential.map(ToString::to_string),
            claim_transport: wire.claim_transport,
            under_scheme: wire.under_scheme,
            from_session: wire.from_session,
            arrival: wire.arrival.clone(),
            destination: wire.destination,
            legs: wire.legs.to_vec(),
            record_keys: wire.record_keys.iter().map(|k| (*k).to_string()).collect(),
            record_body: wire.record_body.to_vec(),
            request_bytes: wire.request_bytes,
            response_bytes: 0,
            finish: busbar_contract::unit::FinishClass::Complete,
        }
    }

    /// Every leg of the plan, classified.
    #[must_use]
    pub fn leg_kinds(&self) -> Vec<LegKind> {
        self.legs.iter().map(|l| classify(&l.destination)).collect()
    }

    /// Whether anything about this unit reaches the registered server.
    ///
    /// Read off the plan the plane produced rather than off a second table of method names, for the
    /// reason the fee's own documentation gives: the fee rule and the request-slot rule are one
    /// rule, and a rule spelled twice is two rules with one of them drifting.
    #[must_use]
    pub fn has_upstream(&self) -> bool {
        matches!(self.destination, DestinationFacts::Upstream { .. })
            || self
                .legs
                .iter()
                .any(|l| matches!(l.destination, DestinationFacts::Upstream { .. }))
    }
}

/// What the transport and the plane already decided, as the read is handed it.
///
/// One borrowed value rather than nine arguments, for the reason the door's is one: every field is
/// a fact somebody else established before this unit existed, and a constructor taking them singly
/// is a constructor a caller can fill in wrongly one at a time.
#[derive(Clone, Copy)]
pub struct Wire<'a> {
    /// What the transports wrote about the connection.
    pub arrival: &'a ArrivalRecord,
    /// The claim that matched, which is how this plane names a transport.
    pub claim_transport: &'static str,
    /// Whether that claim declares a scheme.
    pub under_scheme: bool,
    /// Whether the principal is a bound session's.
    pub from_session: bool,
    /// The credential the carrier presented, where one arrived.
    pub credential: Option<&'a str>,
    /// Where the plane says this unit ends up.
    pub destination: DestinationFacts,
    /// The plan the plane returned.
    pub legs: &'a [Leg],
    /// The record key each leg names, in the plan's order.
    pub record_keys: &'a [&'a str],
    /// The body a record leg writes.
    pub record_body: &'a [u8],
    /// The whole request document's length.
    pub request_bytes: u64,
}

/// Everything one MCP unit is driven against, assembled once at boot.
///
/// Every field is a value configuration decided and nothing here is built per request: the door's
/// cells are hydrated, the auth chain is resolved, the rate card is read and the record legs are
/// bound to the store the loader opened. A binding assembled per unit would be a node whose answers
/// depend on which request asked.
pub struct McpBindings<'r> {
    /// The plane, with the registrations the operator configured.
    pub plane: McpPlane,
    /// The authentication chain, as configuration resolved it.
    pub auth: &'r Auth,
    /// The node's one set of authentication seams — the credential cache and the revocation view.
    pub auth_bindings: &'r crate::root::kernel::auth_bindings::AuthBindings,
    /// The trust unit.
    pub trust: &'r Trust,
    /// The three tables the trust unit reads.
    pub views: Views<'r>,
    /// The admission unit's long-lived door.
    pub door: &'r Door<InMemoryCells>,
    /// What the door prices a unit against.
    pub pricer: &'r Pricer,
    /// The buckets this caller is judged and charged against.
    ///
    /// `None` is the fail-closed arm and NOT the uncapped one: it is a caller bound to a group this
    /// node's configuration does not have, whose caps therefore could not be read.
    pub chain: Option<&'r BucketChain>,
    /// The highest per-unit price over the verified set, for each class the plane declares.
    pub prices: ClassPrices,
    /// The flat per-request fee, in nano-units, where one could land at all.
    pub fee_nanos: u64,
    /// This plane's kernel-held record legs, over the store the loader opened.
    pub records: &'r PlaneRecords,
    /// What the usage unit folds against.
    pub meter_policy: &'r crate::root::policy::MeterPolicyHandle,
    /// What the scope unit reads at approve.
    pub scope_policy: &'r crate::root::policy::ScopePolicy,
    /// The journal, the ledger and the two audit chains.
    pub durability: &'r Mutex<crate::root::durability::Durability>,
    /// The registration this unit is on, keyed the way the breaker keys it.
    pub pool: &'r str,
    /// The unit's two pinned clocks, both read once, where the unit arrived.
    pub at: Clocks,
    /// The sealed origin the audit record is written under.
    pub origin: busbar_caps::Origin,
    /// When a one-time grant this plan redeems lapses.
    pub expires_at: u64,
}

/// A lock this plane holds, taken the way the root takes its locks.
///
/// A poisoned lock is read through rather than refused. The panic that poisoned it happened
/// somewhere else, and what is behind it is written once per field and then read — so a reader
/// after a panic sees a prefix of the truth rather than a corrupted one. The alternative is a node
/// whose audit chain stops sealing because one unrelated unit panicked once.
fn read_through_poison<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|p| p.into_inner())
}

/// What the steps recorded as they ran.
///
/// The settlement table and the audit record read this once, at the end. It is behind a lock
/// because the steps take `&self` and the end reads what they wrote; there is one of these per unit,
/// so the lock is never contended and its only job is to make the write legal.
#[derive(Debug, Default)]
struct Progress {
    /// Who the loop settled on. **Recorded at the step that is handed it** — verify is the first
    /// step the loop hands a principal, and the audit record and the settlement both read it back
    /// from here rather than being handed it again.
    principal: Option<PrincipalId>,
    /// What the record legs answered.
    legs: Vec<RecordAnswer>,
    /// What the metering step located.
    metered: Option<u64>,
    /// Whether the metering step disputed its own reading.
    disputed: bool,
    /// The hash the audit chain sealed this unit under, recorded at the audit step, which is the
    /// step that sees it.
    head: Option<String>,
    /// The bytes the encode step reported.
    encoded: u64,
}

/// One unit of the MCP plane, driven through the kernel's ten steps and its one exit.
///
/// This is what "the MCP plane enters the Teller loop" means, and it is the whole of it: the ten
/// steps below answer with the units every other plane is answered by, in the order the loop calls
/// them and in no other. Nothing here decides anything a unit decides — every arm is a handover.
pub struct McpUnits<'r> {
    bindings: McpBindings<'r>,
    draft: McpDraft,
    grants: Grants,
    leg_kinds: Vec<LegKind>,
    progress: Mutex<Progress>,
}

impl<'r> McpUnits<'r> {
    /// Drive one unit.
    ///
    /// The draft is what the plane already said; the grants are what the caller's credential
    /// carries. Both are inputs because both are decided before the first step runs, and a step
    /// that produced either of them would be a step deciding its own inputs.
    #[must_use]
    pub fn new(bindings: McpBindings<'r>, draft: McpDraft, grants: Grants) -> Self {
        let leg_kinds = draft.leg_kinds();
        McpUnits {
            bindings,
            draft,
            grants,
            leg_kinds,
            progress: Mutex::new(Progress::default()),
        }
    }

    /// What the plane said about this unit.
    #[must_use]
    pub fn draft(&self) -> &McpDraft {
        &self.draft
    }

    /// The hash the audit chain sealed this unit under, once the audit step has run.
    #[must_use]
    pub fn head(&self) -> Option<String> {
        read_through_poison(&self.progress).head.clone()
    }

    /// **The exit arm.** Move the books for what this unit posted, and put the posting on the
    /// journal.
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
        let mut durability = read_through_poison(self.bindings.durability);
        settle(&mut durability, principal, self.bindings.at, token, posted)
    }

    /// The operation class this unit is, where the decode step read one.
    ///
    /// A body this plane does not carry has no class, and the arms that need one to name a record
    /// or a resource ask this and answer for the absence rather than substituting a plausible
    /// neighbour: a refused unit recorded under somebody else's class is a row that lies.
    fn op(&self) -> Option<OpClassId> {
        self.draft.op.ok()
    }

    /// What this unit IS, as far as the money is concerned.
    fn shape(&self) -> Shape {
        Shape::of(self.op().unwrap_or(ops::OP_NOTIFICATION), &self.leg_kinds)
    }

    /// The hold this unit is sized against.
    fn estimate(&self) -> Estimate {
        estimate(
            self.op().unwrap_or(ops::OP_NOTIFICATION),
            self.draft.request_bytes,
            &self.bindings.prices,
            if self.draft.has_upstream() {
                self.bindings.fee_nanos
            } else {
                0
            },
        )
    }

    /// What this unit consumed, as the exit and the record both read it.
    fn ended<'p>(&'p self, progress: &'p Progress, origin: busbar_caps::OriginKind) -> Ended<'p> {
        Ended {
            shape: self.shape(),
            origin,
            finish: self.draft.finish,
            request_bytes: self.draft.request_bytes,
            metered: progress.metered,
            dispatched: !progress.legs.is_empty() || self.draft.has_upstream(),
            principal: progress.principal.as_ref(),
            resource: self
                .op()
                .and_then(|op| resources(&self.bindings.plane, op).first().copied()),
        }
    }

    /// Seal one ending on the audit chain and keep the head it sealed.
    fn seal(&self, token: &UnitToken<Audit>, ctx: &UnitCtx, outcome: Outcome) -> Decision<Audit> {
        let inputs = {
            let progress = read_through_poison(&self.progress);
            audit_inputs(
                &self.ended(&progress, ctx.origin),
                outcome,
                self.bindings.origin,
                self.bindings.at,
            )
        };
        let record = {
            let mut durability = read_through_poison(self.bindings.durability);
            durability.record.seal(inputs, token)
        };
        // The head is recorded HERE, at the step that sees it. Nothing earlier could have it and
        // nothing later is handed it again.
        read_through_poison(&self.progress).head = Some(record.hash);
        Decision::proceed(
            token,
            AuditFacts {
                op_class: self.op().unwrap_or(ops::OP_NOTIFICATION),
                finish: self.draft.finish,
            },
        )
    }
}

impl Units for McpUnits<'_> {
    fn arrival(&self, token: &UnitToken<Arrival>, _ctx: &UnitCtx) -> Decision<Arrival> {
        arrival(
            &Arrived {
                record: &self.draft.arrival,
                claim_transport: self.draft.claim_transport,
            },
            token,
        )
    }

    fn decode(&self, token: &UnitToken<Decode>, _ctx: &UnitCtx) -> Decision<Decode> {
        // The bytes were read once, where the draft was built, and this restates that answer rather
        // than re-deriving it: a second read here would advance the codec a second time over the
        // same frame and could disagree with the draft every later step is built from.
        match self.draft.op {
            Ok(op) => Decision::proceed(token, op),
            Err(reason) => Decision::refuse(token, Refusal::new(reason)),
        }
    }

    fn authenticate(
        &self,
        token: &UnitToken<Authenticate>,
        _ctx: &UnitCtx,
    ) -> Decision<Authenticate> {
        authenticate_bound(
            self.bindings.auth,
            &Arriving {
                presented: self.draft.credential.as_deref(),
                transport: self.draft.claim_transport,
                under_scheme: self.draft.under_scheme,
                now: self.bindings.at.wall,
                // A bound session's principal is the cached one; an unbound session
                // re-authenticates every unit, which is what makes revocation gate new units on
                // this plane at all.
                new_unit: !self.draft.from_session,
            },
            self.bindings.auth_bindings,
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
            // The first step the loop hands the principal is the first step that can record it.
            let mut progress = read_through_poison(&self.progress);
            progress.principal = Some(principal.clone());
        }
        let mut candidates = vec![self.draft.destination];
        for leg in &self.draft.legs {
            if !candidates.contains(&leg.destination) {
                candidates.push(leg.destination);
            }
        }
        let _ = ctx;
        verify(
            self.bindings.trust,
            &candidates,
            self.bindings.pool,
            self.bindings.views,
            self.bindings.at.wall,
            trust,
            token,
        )
    }

    fn approve(
        &self,
        token: &UnitToken<Approve>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[busbar_caps::VerifiedDestination],
    ) -> Decision<Approve> {
        let Some(op) = self.op() else {
            return Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed));
        };
        match approve(
            &self.bindings.plane,
            op,
            self.grants,
            self.bindings.scope_policy,
        ) {
            // A deployment that registered nothing has nothing here to be authorized to reach, and
            // a pair the policy is silent about has not been authorized. Both are the scope unit's
            // one refusal, because both are "the caller may not do this".
            Err(_) => Decision::refuse(token, Refusal::new(ReasonCode::ScopeDenied)),
            Ok(resources) => {
                // The plane says WHAT is being asked for; the resources travel with the approval so
                // the record names the server and the tool rather than the method.
                let mut facts = ScopeFacts::default();
                for resource in resources {
                    let _ = facts
                        .resources
                        .push(busbar_contract::unit::ResourceLocator {
                            kind: resource.kind,
                            name: resource.name,
                        });
                }
                Decision::proceed(token, facts)
            }
        }
    }

    fn admit(
        &self,
        token: &UnitToken<Admit>,
        admit_token: &AdmitToken<Admit>,
        _ctx: &UnitCtx,
        principal: &PrincipalId,
        _destinations: &[busbar_caps::VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> Decision<Admit> {
        // An empty chain is a yes from every cap at once: no gauge is raised, no window bucket is
        // read and no freeze flag is consulted. A caller whose caps could not be read is OVER
        // QUOTA, not merely rate-limited, and that is the fail-closed arm.
        let Some(chain) = self.bindings.chain else {
            return Decision::refuse(token, Refusal::new(ReasonCode::OverBudget));
        };
        let estimate = self.estimate();
        admit(
            &Admitting {
                door: self.bindings.door,
                pricer: self.bindings.pricer,
                pool: self.bindings.pool,
                // The pinned arrival epoch and never a fresh clock read: a check and a charge that
                // read two different clocks are a check of one window and a charge in another.
                arrival_epoch: self.bindings.at.wall,
                estimate: &estimate,
                principal,
                chain,
            },
            admit_token,
            token,
            leases,
        )
    }

    fn route(
        &self,
        token: &UnitToken<Route>,
        _ctx: &UnitCtx,
        meter: &AccrualMeter,
    ) -> Decision<Route> {
        // The plan has to FIT before any of it happens. The bound belongs to the contract and is
        // read from it, so the number this compares against and the number the plan holds are the
        // same number and there is nowhere to write a second one.
        if self.draft.legs.len() > busbar_contract::MAX_LEGS {
            return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
        }
        // A plan with no leg at all is an operation this plane does not carry: a refusal at the
        // routing step, not a panic and not a hop to somewhere plausible.
        if self.draft.legs.is_empty() {
            return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
        }

        // The KERNEL-HELD RECORD LEGS, in the plan's order, before anything is dialled. They are
        // what says whether this caller may see the thing at all, and the hop that follows carries
        // what they answered.
        let mut answers = Vec::new();
        for (at, kind) in self.leg_kinds.iter().enumerate() {
            let LegKind::Record { schema, op } = *kind else {
                continue;
            };
            let key = self.draft.record_keys.get(at).map_or("", String::as_str);
            match self.bindings.records.run(&RecordLeg {
                schema,
                op,
                key,
                parent: None,
                seq: 0,
                body: &self.draft.record_body,
                terminal: matches!(
                    self.draft.finish,
                    busbar_contract::unit::FinishClass::Complete
                        | busbar_contract::unit::FinishClass::Error
                ),
                now: self.bindings.at.wall,
                expires_at: self.bindings.expires_at,
            }) {
                // The plan naming an operation its schema never declared. The trust unit refuses
                // such a leg before it is ever run; reaching here means something got past it, and
                // the answer is the same one, not a softer one.
                Err(RecordRefusal::Undeclared { .. }) => {
                    return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination))
                }
                Err(RecordRefusal::Store(_)) => {
                    return Decision::refuse(token, Refusal::new(ReasonCode::DurabilityUnavailable))
                }
                Ok(answer) => answers.push(answer),
            }
        }
        read_through_poison(&self.progress).legs = answers;

        // The bytes the request carried accrue as the unit runs; the answer's bytes settle at the
        // metering step. The meter is the kernel's running total and the hold is applied to it at
        // the exit, which is why this is an accrual and not a posting.
        meter.accrue(self.draft.request_bytes);
        // How far this unit's reservation may still grow, read off the same chain the door was
        // judged against. Zero is a top-up that does not happen, never a unit that does not run.
        meter.offer_headroom(match self.bindings.chain {
            None => 0,
            Some(chain) => AdmissionUnit::new(
                self.bindings.door,
                self.bindings.pricer,
                self.bindings.pool,
                self.bindings.at.wall,
            )
            .headroom_nanos(chain),
        });

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
        Decision::proceed(token, plan)
    }

    fn meter(
        &self,
        token: &UnitToken<Meter>,
        usage: &UsageToken,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
    ) -> Decision<Meter> {
        let op = self.op().unwrap_or(ops::OP_NOTIFICATION);
        let retained = RetainedLocatorValues::new(located_values(op, self.draft.response_bytes));
        // The kernel's own floor for this unit is what it moved on the way in. It is the tripwire
        // beside the located figure, never the charge.
        let kernel = KernelCounts::new(vec![busbar_unit_usage::KernelLine {
            class: CLASS_BYTES,
            quantity: self.draft.request_bytes,
            // A byte is a byte: the class's own quantity is the quantity, so the floor divides by
            // one. The plane declared that divisor and this is the declaration read back.
            source: busbar_caps::QuantitySource::KernelBytes { divisor: 1 },
        }]);
        match meter(
            &retained,
            &kernel,
            self.bindings.meter_policy.policy(),
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
        self.seal(token, ctx, *outcome)
    }

    fn audit_refused(
        &self,
        token: &UnitToken<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> Decision<Audit> {
        // The second door: a unit that never passed the first one, and was charged nothing. It is
        // sealed on the same chain, because a refusal is an event with a record of its own.
        self.seal(
            token,
            ctx,
            Outcome::Refused(refusal.step().unwrap_or(StepName::Admit), refusal.reason()),
        )
    }

    fn encode(
        &self,
        token: &UnitToken<Encode>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> Decision<Encode> {
        // The plane's encoders take the unit's arena, and this signature carries neither an arena
        // nor the plane's draft, so the bytes are written where the borrow lives — see
        // [`refusal_of`], which is how the root hands the loop's ending back to the plane to render
        // — and this step reports what left. A root that allocated a second buffer here would be
        // writing the wire format twice.
        let bytes = read_through_poison(&self.progress).encoded;
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
                    status_code: None,
                    retry_after_secs: None,
                },
            },
        )
    }

    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        let progress = read_through_poison(&self.progress);
        evidence(&self.ended(&progress, ctx.origin))
    }
}

/// **The bytes the caller is owed, from the ending the loop sealed.**
///
/// The loop decides how a unit ended and the PLANE renders it — that is the split, and this is the
/// hinge. What the root owns is the join between the kernel's own closed vocabulary and the
/// contract's spelling of it, so that a refusal a caller reads is the refusal the loop raised rather
/// than an envelope this file wrote out by hand. The reason side of the join already exists as one
/// `From` in the capability crate, walked by that crate's own tests; the step side is written here,
/// totally, so a step added to the loop does not compile until a caller can be told which one it was.
///
/// `None` is a unit that SETTLED. A settled unit's bytes are its answer, which the plane writes from
/// the unit's own arena, and rendering a refusal for one would be inventing an error nothing raised.
#[must_use]
pub fn refusal_of(
    ended: &busbar_kernel::teller::Ended,
) -> Option<busbar_contract::unit::Refusal<'static>> {
    let (step, reason) = match ended {
        busbar_kernel::teller::Ended::Settled { end, .. } => match end.outcome() {
            Outcome::Refused(step, reason) => (step, reason),
            // Every other ending either delivered an answer or lost the unit before one could be
            // written, and neither is a refusal a caller is owed an envelope for.
            _ => return None,
        },
        // The node's own sweep took the hold first, so this unit will not produce an answer at all.
        busbar_kernel::teller::Ended::AlreadySettled => return None,
    };
    Some(busbar_contract::unit::Refusal {
        step: refusal_step(step),
        reason: reason.into(),
        retry_after_secs: None,
        stream: None,
        correlates: None,
    })
}

/// The contract's spelling of the step a refusal was raised at.
///
/// Two crates name the same ten steps and neither depends on the other, so the mapping is written
/// once, here, where both are in scope. Totality is what makes it safe: an eleventh step would not
/// compile.
#[must_use]
pub fn refusal_step(step: busbar_caps::StepName) -> busbar_contract::unit::Step {
    match step {
        StepName::Arrival => busbar_contract::unit::Step::Arrival,
        StepName::Decode => busbar_contract::unit::Step::Decode,
        StepName::Authenticate => busbar_contract::unit::Step::Authenticate,
        StepName::Verify => busbar_contract::unit::Step::Verify,
        StepName::Approve => busbar_contract::unit::Step::Approve,
        StepName::Admit => busbar_contract::unit::Step::Admit,
        StepName::Route => busbar_contract::unit::Step::Route,
        StepName::Meter => busbar_contract::unit::Step::Meter,
        StepName::Audit => busbar_contract::unit::Step::Audit,
        StepName::Encode => busbar_contract::unit::Step::Encode,
    }
}

#[cfg(test)]
#[path = "tests/units_mcp.rs"]
mod tests;
