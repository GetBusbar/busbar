// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE SERVING SWITCH, ON THE WHOLE FILE. The leg is composition rather than a byte diverted, but it
// is composition of the SERVING path — it names `A2aDraft::from_decoded`, which exists only under
// this feature — so the whole module is behind it. Declared in `root/mod.rs` under `root-a2a`
// instead, because everything here reaches into the A2A plane's units and a module gated on the
// serving switch alone would be reaching across a feature boundary the root's own escape test
// (`tests::a_plane_gated_module_is_named_only_from_code_under_the_same_feature`) exists to refuse.
#![cfg(feature = "root-a2a-serve")]

//! THE A2A PLANE'S LEG: an OWNED assembly, built once at boot, that produces one unit per arrival.
//!
//! ## The finding this file is the answer to
//!
//! [`crate::root::units_a2a::A2aBindings`] describes one unit of the A2A plane precisely and
//! completely — twenty-three halves, every one of them a value configuration decided. It is
//! BORROWED: `A2aBindings<'r, S>` holds `&'r` references to things that have to outlive the request.
//! Nothing in the workspace held those things. Every construction of it was a test's, which is the
//! same sentence as "the A2A plane's decode reaches no step of the kernel", and it is why the
//! conformance battery had never once been run through the loop.
//!
//! Ten of the twenty-three had no production source at all: the pool view and the kind facts existed
//! only for MCP, the one `Resolver` implementation was `pub(crate)` inside the legacy plugin, and
//! the guard, the denylist, the pin list, the pricer, the byte price, the pool and the task deadline
//! were unresolved at boot. This file resolves all of them, and it resolves each one FROM THE PLACE
//! THAT ALREADY ANSWERS IT — see [`SOURCES`], which is the whole table and is checked against the
//! bindings' own source at test time so a field cannot be added without a source being named for it.
//!
//! ## Owned, and why that is the shape rather than a convenience
//!
//! A `PlaneLeg` is asked for a unit AFTER an arrival exists ([`crate::root::transports::PlaneLeg`]),
//! and the bindings a unit runs over borrow from things assembled long before. So the leg owns the
//! long-lived halves — the door, the chain table, the journal, the card, the agent set — and
//! [`A2aLeg::walk`] borrows from `&self` to build one `A2aBindings` on the stack, for the length of
//! one call. Nothing per-request is allocated that outlives the request, and nothing per-boot is
//! rebuilt per request: a chain resolved inside the admission step, or a rate looked up per unit,
//! would be work on the request path for an answer that cannot change between two of them.
//!
//! ## NO INVENTED CONFIGURATION
//!
//! Not one key here is new. Every field is either read from the configuration the legacy
//! `busbar-a2a` plugin already resolves — with that resolution mirrored, not reinterpreted — or is a
//! value the composition root already holds for its other planes. A field whose source could not be
//! named REFUSES BOOT, by name, in [`A2aLeg::assemble`]; there is deliberately no arm that supplies
//! a default. A default here is a deployment served under a policy nobody wrote down.
//!
//! ## What this file does NOT do
//!
//! It decides nothing. The auth chain says who is calling, the trust unit says where a unit may go,
//! the scope unit says whether the caller may ask, the door says whether it is paid for, the usage
//! unit folds the meter and the audit unit seals the end. What is here is the WIRING, which is the
//! composition root's whole job — and the twelve step answers are
//! [`crate::root::units_a2a::A2aUnits`]'s, unchanged and untouched by this file.

use std::sync::{Arc, Mutex};

use busbar_caps::{Origin, TrustToken};
use busbar_contract::ids::RecordSchemaId;
use busbar_kernel::teller::{Ended, Kernel, Run, UnitCtx};
use busbar_plane_a2a::{ops, records, A2aPlane};
use busbar_unit_admission::{BucketChain, Door, GroupTable, InMemoryCells, Pricer};
use busbar_unit_auth::Auth;
use busbar_unit_scope::{Grants, Scope};
use busbar_unit_trust::lane::BreakerView;
use busbar_unit_trust::net::{Denylist, GuardPolicy};

use crate::root::durability::Durability;
use crate::root::kernel::auth_bindings::AuthBindings;
use crate::root::policy::{MeterPolicyHandle, ScopePolicy};
use crate::root::registrations::{KindRules, Kinds, NetSeam, Pools};
use crate::root::units_a2a::{A2aBindings, A2aDraft, A2aUnits, Decoded, RecordLegs, CLASS_BYTES};
use busbar_api::Store as AbiStore;

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE FIELD → SOURCE TABLE
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// WHERE EVERY ONE OF THE TWENTY-THREE BINDINGS COMES FROM.
///
/// One row per field of `A2aBindings`, and the test beside this file reads that struct's own source
/// and asserts the two agree — so a binding added without a source named for it does not compile a
/// green test. That check is the point of the table existing as data rather than as prose: a comment
/// saying "every field is sourced" is worth nothing the day a field is added.
///
/// The second column is a LOCATION, not a description. Where the legacy plugin already resolves the
/// value, the row names the plugin file and the key, because that resolution is the one being
/// mirrored and the mirror has to be checkable against it. Where the root already holds the value
/// for another plane, the row names the root's own resolution.
pub const SOURCES: &[(&str, &str)] = &[
    // ── the caller's identity ────────────────────────────────────────────────────────────────────
    (
        "auth",
        "root: the node's configured auth chain (`kernel::auth_bindings`), the same one the \
              admin mount is built with",
    ),
    (
        "auth_bindings",
        "root: the node's ONE `AuthBindings` — cache, key verifier, revocation view — \
                       over the governance directory",
    ),
    // ── the seals the kernel mints ───────────────────────────────────────────────────────────────
    (
        "trust_token",
        "kernel: `Kernel::trust_token()`; a unit may not mint one and this is not the \
                     kernel either, so it is lent",
    ),
    (
        "origin",
        "kernel: `Kernel::origin(OriginKind::Client)`; sealed, for the audit record",
    ),
    // ── the one seam the answer comes back through ───────────────────────────────────────────────
    (
        "dispatch",
        "root: the mount's per-arrival seam onto the surface the operation is already \
                mounted on — `None` on a build with no mount, which is a posture and not a \
                missing source",
    ),
    // ── where a unit may go ──────────────────────────────────────────────────────────────────────
    (
        "pools",
        "root: `registrations::Pools` over `A2aPlane::agents()`, keyed under the plane's own \
               region of the pool keyspace",
    ),
    (
        "kinds",
        "root: `registrations::Kinds` over the same agent set, with this plane's `KindRules`",
    ),
    (
        "breaker",
        "root: the node's ONE breaker adapter — the same cells the egress walk's pre-filter \
                 reads",
    ),
    (
        "resolver",
        "substrate: `net_guard::SystemResolver`, the one name resolution in the tree \
                  (moved out of `busbar-a2a`'s `transport.rs`)",
    ),
    (
        "guard",
        "legacy `crates/busbar-a2a/src/a2a/fetch.rs::FetchPolicy::guard()`, narrowed per agent \
               by `agents.<name>.allow_private` (`config.rs`, default false)",
    ),
    (
        "denylist",
        "root: `config_validate::metadata_denylist_entries()` ∪ \
                  `security.blocked_metadata_hosts`, the same set `--print-metadata-blocklist` \
                  prints",
    ),
    (
        "pinned",
        "legacy `agents.<name>.pin.fingerprint`: an agent whose declared pin carries an \
                approved fingerprint, exactly as `pin.rs`'s artifact reads it",
    ),
    // ── whether it is paid for ───────────────────────────────────────────────────────────────────
    (
        "door",
        "root: the node's ONE admission door, ledger cells hydrated at boot",
    ),
    (
        "chain",
        "root: `policy::group_table(...).chain_for(principal, group)`, resolved where the root \
               resolves the caller",
    ),
    (
        "pricer",
        "root: `kernel::ROOT_CARD`, the process's LIVE rates — read on every walk and never \
                captured, so an apply moves this door and the engine's own spend projection \
                together",
    ),
    (
        "bytes_nanos",
        "root: the SAME live rates, asked for this plane's one class on the lanes this \
                     deployment's own agents are reached over",
    ),
    // ── the durable half ─────────────────────────────────────────────────────────────────────────
    (
        "records",
        "root: `RecordLegs` over the node's one store, at the published protocol",
    ),
    (
        "durability",
        "root: the node's ONE book — journal, ledger and the two audit chains",
    ),
    // ── what the units read ──────────────────────────────────────────────────────────────────────
    (
        "meter_policy",
        "root: `policy::build` over the configured rate cards",
    ),
    (
        "scope_policy",
        "root: `units_a2a::scope_policy`, the twelve entries `main()` already seals",
    ),
    // ── the request's own coordinates ────────────────────────────────────────────────────────────
    (
        "pool",
        "legacy `crates/busbar-a2a/src/a2a/receive.rs::PLANE_POOL`, the plane's own configuration \
         section name, restated here as `PLANE_POOL`",
    ),
    (
        "now",
        "the arrival's pinned wall epoch, read ONCE per unit and never per step",
    ),
    (
        "mono",
        "the node's monotonic source, pinned at the same arrival — a different measurement \
              from `now`, not a second spelling of it",
    ),
    (
        "task_ttl_secs",
        "legacy `crates/busbar-a2a/src/taskstore.rs::ACTIVE_TASK_ABANDON_SECS`, the \
                       bound the abandon sweep already retires a task's token at",
    ),
];

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THIS PLANE'S KIND RULES
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// The prefix this plane's destinations occupy in the breaker's and the pool table's keyspace.
///
/// **A seam to the neutral substrate.** The single source is `busbar_substrate::store::agent_key`,
/// which the legacy route path already keys its breaker cells with
/// (`crates/busbar-a2a/src/a2a/route.rs`); the prefix is restated here so the root can build the key
/// without a substrate edge on this path, and it is pinned by a test that reads that function's own
/// source. The MCP sibling states its own the same way and for the same reason.
pub const POOL_PREFIX_AGENT: &str = "agent:";

/// The pool one unit of this plane is admitted and metered against.
///
/// NOT a name this file chose. The legacy receiving path spells it once, as its `PLANE_POOL`, which
/// is the plane's own configuration section name, and every admission and every meter on that path
/// names it.
///
/// **Restated rather than depended on.** A plane leg names no codec: the root carries no edge to
/// the codec crate that declares the section name, and reading that crate's source at build time
/// would be an edge nobody wrote down — so the value is written here, and the MCP sibling states
/// its own pool prefix the same way and for the same reason. What pins it is the plane's own path
/// grammar (`a2a/agents/<name>`), which this leg's claim table and the plane's declarations both
/// read, and the byte-identity cells that drive one request through the leg and the legacy path
/// and compare what each admitted and metered against.
pub const PLANE_POOL: &str = "agents";

/// HOW LONG A TASK'S CAPABILITIES MAY OUTLIVE ITS LAST MOVE, in seconds.
///
/// The legacy plugin's own bound, `taskstore.rs::ACTIVE_TASK_ABANDON_SECS`, which is the instant its
/// sweep abandons a task that has gone silent and therefore the instant that task's push-callback
/// token stops naming anything live. Read here as the same number rather than as a new configuration
/// key: a deployment that has never written this down has an answer already, and inventing a key for
/// it would give one node two deadlines.
pub const TASK_TTL_SECS: u64 = 86_400;

/// The six facts that are THIS plane's rather than the shared view's.
///
/// Data, not a branch — see [`crate::root::registrations::KindRules`].
const A2A_RULES: KindRules = KindRules {
    // The two transports a hop of this protocol is made over, read off the plane's own claims rather
    // than spelled again: the document binding and the framed one, and nothing else.
    transports: &[
        busbar_plane_a2a::claims::TRANSPORT_HTTP,
        busbar_plane_a2a::claims::TRANSPORT_GRPC,
    ],
    // This plane reaches no administrative verb. Its operator surface — connect, approve — is the
    // admin plane's, under that plane's claim and that plane's scope.
    verb_scope_held: false,
    // And names no nested plane: every destination it declares is an agent, a record or a client
    // delivery.
    nested_plane_ok: true,
    // No peer lease.
    peer_lease_live: false,
    // And no in-band upgrade: the streamed surface is its own claim on its own path.
    upgrade_ok: false,
    record_ok: a2a_record_ok,
};

/// Whether one record leg is one this plane declared, asked of the plane's own tables.
///
/// The declaration is the plane crate's and is not restated: a schema that gains or loses an
/// operation changes what the trust unit refuses without a line here being edited.
fn a2a_record_ok(schema: RecordSchemaId, op: &'static str) -> bool {
    records::RECORD_SCHEMAS.contains(&schema) && records::operations_for(schema).contains(&op)
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE RESOLVER BRIDGE
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// THE RESOLVER BRIDGE IS NOT THIS PLANE'S, and that is why it is not defined here.
///
/// It landed in this file because this leg needed it first, and nothing in it was ever about A2A:
/// the argument is a host name and the answer is a list of addresses, and the whole content of the
/// type is the join between two identically-shaped `Resolver` traits that may not name each other.
/// The MCP leg needs the same join, so the type moved to [`crate::root::registrations`] — beside
/// [`NetSeam`], which is the value it is handed to — rather than gaining an mcp-shaped twin.
///
/// Re-exported here under the name it already had, so this leg reads as one file.
pub use crate::root::registrations::SystemResolver;

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE BOOT REFUSAL
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// A binding whose source this deployment does not have.
///
/// A REFUSAL AT BOOT and never a default. The whole of the risk this type exists against is the
/// alternative: a leg assembled with an empty auth chain admits anonymously, a leg assembled with an
/// empty group table says yes to every cap, and a leg assembled with no denylist guards nothing —
/// and every one of those boots clean, serves traffic and looks healthy, because an absent control
/// has no failing test of its own. So the assembly says which field it could not source, by name,
/// and the node does not bind a listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingSource {
    /// The `A2aBindings` field that could not be sourced.
    pub field: &'static str,
    /// Where it would have come from, in the words of [`SOURCES`].
    pub source: &'static str,
}

impl std::fmt::Display for MissingSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the composition root did not seal: the A2A leg's `{}` has no source on this \
             deployment, and it is sourced from {}",
            self.field, self.source
        )
    }
}

/// WHERE THE FACTS THE LEG READS OFF ONE ARRIVAL COME FROM.
///
/// A SECOND TABLE, deliberately, and not four more rows on [`SOURCES`]. That table is one row per
/// field of `A2aBindings` and is checked against that struct's own source, so a row for something
/// which is not a binding would fail the check that makes the table worth having. What is here is
/// the other half of the same accounting: the boot-resolved values [`A2aLeg::decode`] needs in order
/// to answer [`Decoded`] with what a request actually carries, rather than with the anonymous
/// posture it answered with while nothing on the serving path had a source for them.
///
/// One row today, and it is the one the boundary rests on.
pub const DECODE_SOURCES: &[(&str, &str)] = &[(
    "expected_aud",
    "the RFC 8707 canonical URI `<public_url>/a2a`, derived exactly where the plane's own \
     protected-resource metadata derives it (`crates/busbar-a2a/src/a2a/serve.rs::canonical_uri`) \
     — ONE reading, so the audience a caller is told to ask for and the audience this node demands \
     cannot drift apart",
)];

/// Where in [`SOURCES`] or [`DECODE_SOURCES`] one field is described, so a refusal quotes the table
/// rather than a copy.
fn source_of(field: &'static str) -> &'static str {
    SOURCES
        .iter()
        .chain(DECODE_SOURCES)
        .find(|(name, _)| *name == field)
        .map_or("a source this table does not name", |(_, where_)| *where_)
}

/// Refuse the assembly, naming the field.
fn missing(field: &'static str) -> MissingSource {
    MissingSource {
        field,
        source: source_of(field),
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   WHAT THE ROOT HANDS IN
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// The sources the composition root resolved, offered to the assembly.
///
/// Every field that could genuinely be absent on a real deployment is an `Option`, and the assembly
/// refuses on the first one that is. The fields that cannot be absent — the plane's own agent set,
/// the kernel's seals, the two clocks — are not options, because "the kernel did not mint a token"
/// is not a deployment state and offering an arm for it would be inventing a failure mode.
pub struct A2aLegSources<'k> {
    /// The plane, carrying the agents this deployment configured.
    pub plane: A2aPlane,
    /// The kernel the two seals are lent from.
    pub kernel: &'k Kernel,
    /// The node's configured authentication chain.
    pub auth: Option<Auth>,
    /// The node's one credential cache, key verifier and revocation view.
    pub auth_bindings: Option<AuthBindings>,
    /// The node's one breaker, behind the trust unit's own port.
    pub breaker: Option<Arc<dyn BreakerView + Send + Sync>>,
    /// How far this plane's hops may reach, mirrored off the legacy fetch policy.
    pub guard: Option<GuardPolicy>,
    /// The operator's metadata denylist.
    pub denylist: Option<Denylist>,
    /// The agents whose cards carry an approved fingerprint.
    pub pinned: Option<Vec<String>>,
    /// The node's one admission door.
    pub door: Option<Door<InMemoryCells>>,
    /// The configured group table the caller's bucket chain is walked out of.
    pub groups: Option<GroupTable>,
    /// THE DEPLOYMENT'S RESOLVED RATES, as the process's own holder had them when this leg was
    /// assembled.
    ///
    /// NOT the price this leg charges. It is the proof that a resolution has HAPPENED — a leg
    /// composed before the boot's rate apply would have nothing to price against, and refusing at
    /// assembly is how that ordering mistake is found at boot rather than on the first request. The
    /// price a unit is actually admitted against is read from the same holder on every walk, so an
    /// operator's apply moves this door and the engine's own spend projection together; the value
    /// kept here is what a walk falls back to if the holder is somehow emptied under it, which is
    /// the last rates this node genuinely resolved and never a figure nobody wrote.
    pub rates: Option<Arc<crate::root::kernel::RootRates>>,
    /// The node's one store, for this plane's durable records.
    pub store: Option<Arc<dyn AbiStore>>,
    /// What the usage unit folds against.
    pub meter_policy: Option<MeterPolicyHandle>,
    /// What the scope unit reads at approve.
    pub scope_policy: Option<ScopePolicy>,
    /// The node's one book.
    pub durability: Option<Arc<Mutex<Durability>>>,
    /// THE AUDIENCE A CREDENTIAL HAS TO HAVE BEEN MINTED FOR to be spendable on this plane.
    ///
    /// The RFC 8707 canonical URI, `<public_url>/a2a`. `None` is a deployment that configured no
    /// `public_url`, which is exactly the deployment the legacy plugin serves no A2A routes on at
    /// all — its `admission()` is `None` and its route list is empty — so the assembly refuses
    /// rather than serving a surface whose tokens nothing could be checked against.
    pub expected_aud: Option<String>,
    /// The scopes this deployment's key is restricted to, where it is restricted.
    ///
    /// `None` is "no restriction named", which is a different answer from `Some(vec![])` — a key
    /// scoped to nothing denies every pool. Not an `Option<Option<_>>` on the sources for that
    /// reason: both readings are legitimate configurations, so neither is a missing source.
    pub key_scopes: Option<Vec<String>>,
    /// Whether this deployment prices this plane at all.
    pub priced: bool,
    /// Whether the caller presented a key at all.
    pub has_key: bool,
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE LEG
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// THE A2A PLANE'S LEG, owned and assembled once.
///
/// Everything expensive has already happened by the time one of these is walked: the journal is
/// open, the ledger cells are hydrated, the auth chain is resolved and the rate card is read. What a
/// walk does is borrow from here, ask the plane what the bytes are, and run the ten steps.
pub struct A2aLeg {
    plane: A2aPlane,
    auth: Auth,
    /// The door an address this protocol DECLARED OPEN is served through: none.
    ///
    /// Built once beside the deployment's own, because it is a constant of the protocol rather than
    /// a value configuration picks — see [`crate::root::data_plane::open_door`]. Which of the two a
    /// unit is judged behind is decided per ADDRESS, off the plane's own declared surface, and never
    /// per operation.
    open_auth: Auth,
    auth_bindings: AuthBindings,
    trust_token: TrustToken,
    origin: Origin,
    breaker: Arc<dyn BreakerView + Send + Sync>,
    resolver: SystemResolver,
    guard: GuardPolicy,
    denylist: Denylist,
    /// Owned strings, borrowed as `&[&str]` for the length of one walk. The binding wants the
    /// narrower shape because a unit reads it and never keeps it; the leg has to own it because
    /// a boot-resolved list cannot borrow from the boot that resolved it.
    pinned: Vec<String>,
    door: Door<InMemoryCells>,
    groups: GroupTable,
    /// The rates this node had resolved when the leg was assembled. See [`A2aLegSources::rates`]:
    /// what a walk prices against is the holder's LIVE value, and this is the fallback and the proof
    /// that a resolution had happened before a listener was bound.
    rates_at_assembly: Arc<crate::root::kernel::RootRates>,
    records: RecordLegs,
    meter_policy: MeterPolicyHandle,
    scope_policy: ScopePolicy,
    durability: Arc<Mutex<Durability>>,
    key_scopes: Option<Vec<String>>,
    /// The RFC 8707 canonical URI a credential presented here must name. See
    /// [`A2aLegSources::expected_aud`].
    expected_aud: String,
    priced: bool,
    has_key: bool,
    /// When this process started, for the monotonic half of a unit's clock reading. The wall reading
    /// dates a unit and this one ORDERS it; filling both from the wall clock gives a unit one clock
    /// written twice, which still dates correctly and orders nothing at all.
    started: std::time::Instant,
}

impl std::fmt::Debug for A2aLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("A2aLeg")
    }
}

impl A2aLeg {
    /// Assemble the leg, or REFUSE BOOT naming the field that has no source.
    ///
    /// # Errors
    ///
    /// One of the sources in [`SOURCES`] is absent on this deployment. The refusal names the field
    /// and quotes the table's own row for it, so an operator reads what to configure rather than
    /// which line of Rust returned `None`.
    pub fn assemble(sources: A2aLegSources<'_>) -> Result<Self, MissingSource> {
        Ok(A2aLeg {
            plane: sources.plane,
            auth: sources.auth.ok_or_else(|| missing("auth"))?,
            open_auth: Auth::new(crate::root::data_plane::open_door()),
            auth_bindings: sources
                .auth_bindings
                .ok_or_else(|| missing("auth_bindings"))?,
            // MINTED, not offered: the kernel is the only thing that can, and it is handed in whole
            // rather than as two tokens so a caller cannot pass a token from one kernel and an
            // origin from another.
            trust_token: sources.kernel.trust_token(),
            origin: sources.kernel.origin(busbar_caps::OriginKind::Client),
            breaker: sources.breaker.ok_or_else(|| missing("breaker"))?,
            resolver: SystemResolver,
            guard: sources.guard.ok_or_else(|| missing("guard"))?,
            denylist: sources.denylist.ok_or_else(|| missing("denylist"))?,
            pinned: sources.pinned.ok_or_else(|| missing("pinned"))?,
            door: sources.door.ok_or_else(|| missing("door"))?,
            groups: sources.groups.ok_or_else(|| missing("chain"))?,
            rates_at_assembly: sources.rates.ok_or_else(|| missing("pricer"))?,
            records: RecordLegs::new(sources.store.ok_or_else(|| missing("records"))?),
            meter_policy: sources
                .meter_policy
                .ok_or_else(|| missing("meter_policy"))?,
            scope_policy: sources
                .scope_policy
                .ok_or_else(|| missing("scope_policy"))?,
            durability: sources.durability.ok_or_else(|| missing("durability"))?,
            key_scopes: sources.key_scopes,
            expected_aud: sources
                .expected_aud
                .ok_or_else(|| missing("expected_aud"))?,
            priced: sources.priced,
            has_key: sources.has_key,
            started: std::time::Instant::now(),
        })
    }

    /// The plane this leg serves, for a caller that has to hand the same one to the driver.
    #[must_use]
    pub fn plane(&self) -> &A2aPlane {
        &self.plane
    }

    /// **Whether these bytes are a unit THIS PLANE has** — asked of the plane, answered by the plane.
    ///
    /// The question a mount has to ask before it takes a request off the surface that already
    /// answers it. A body whose operation this plane cannot name is not a unit of this plane; it is a
    /// request the mounted router's own routing answers, with the document, the 404 or the 405 that
    /// release pinned, and a loop that took it would be manufacturing a status for bytes it never
    /// claimed.
    ///
    /// It runs the plane's decode and nothing else — no step, no seam, no clock that a unit would be
    /// judged against — so asking it costs one reading of the body and decides nothing.
    #[must_use]
    pub fn recognises(&self, arrival: &busbar_contract::transport::Arrival<'_>) -> bool {
        self.decode(arrival, 0).op.is_some()
    }

    /// **The plane's own refusal document for one ending**, for a mount that has to write it.
    ///
    /// Rendered by the PLANE, through the same two helpers the generic driver uses, so a caller
    /// refused by the mounted loop and one refused by the driven loop read the same bytes — carrying
    /// their own request identifier back to them, which is the whole reason a refusal is the plane's
    /// to write rather than the mount's.
    ///
    /// `None` for an ending this plane has no rendering for: an abort and a timeout name no reason,
    /// so a document for one would have to have a reason invented for it. A missing body is the
    /// truthful answer to "what did the plane say about this".
    #[must_use]
    pub fn render_refusal(
        &self,
        arrival: &busbar_contract::transport::Arrival<'_>,
        ended: &busbar_kernel::teller::Ended,
    ) -> Option<Vec<u8>> {
        let refusal = crate::root::transports::refusal_of(ended)?;
        let clock = busbar_contract::unit::Clock {
            unix_secs: 0,
            monotonic_nanos: 0,
        };
        crate::root::plane_ctx::with_frames(arrival, clock, |ctx, frames| {
            use busbar_contract::Plane as _;
            // The draft is read again, HERE, because the encoder needs it to put the caller's own
            // request identifier on the answer — and it borrows the arena this context carries, so
            // it cannot have been kept from the walk. That is the same seam the leg's own decode
            // names: an answer correlated to the wrong request is worse than an uncorrelated one, so
            // it is re-read rather than cached on anything an attacker chooses.
            let read = self.plane.decode_ingress(frames, None, ctx);
            let draft = match &read {
                Ok(busbar_contract::Ingress::OneShot(d))
                | Ok(busbar_contract::Ingress::Open(d))
                | Ok(busbar_contract::Ingress::Handshake(d)) => Some(&**d),
                _ => None,
            };
            self.plane
                .encode_refusal(&refusal, draft, None, ctx)
                .ok()
                .map(|bytes| bytes.as_slice().to_vec())
        })
    }

    /// The pool view for one caller, over this deployment's agents.
    fn pools(&self) -> Pools<busbar_plane_a2a::Agent> {
        Pools::over(
            self.plane.agents(),
            POOL_PREFIX_AGENT,
            self.key_scopes.clone(),
            self.has_key,
            self.priced,
        )
    }

    /// The per-kind facts for one unit, whose plan reaches one schema under one operation.
    ///
    /// The schema and the operation come off the draft the plane produced, so the record question
    /// the trust unit asks is about the leg this unit actually walks rather than about a
    /// representative one.
    fn kinds<'r>(
        &'r self,
        schema: RecordSchemaId,
        op: &'static str,
    ) -> Kinds<'r, busbar_plane_a2a::Agent> {
        Kinds::over(
            self.plane.agents(),
            schema,
            op,
            A2A_RULES,
            NetSeam {
                resolver: &self.resolver,
                policy: self.guard,
                denylist: &self.denylist,
            },
        )
    }

    /// The record leg this unit's plan reaches first, where it reaches one.
    ///
    /// A plan with no record leg is asked about the schema the plane declares for a task, under a
    /// read — which is the narrowest true statement available and is NOT a pass: the allow-list and
    /// the guard conjuncts beside it are what decide an upstream hop, and the record conjunct only
    /// ever has to be true of a plan that has a record leg in it.
    fn record_leg_of(draft: &A2aDraft) -> (RecordSchemaId, &'static str) {
        draft
            .legs
            .iter()
            .find_map(|leg| match leg.destination {
                busbar_contract::dest::DestinationFacts::PlaneRecord { schema, op } => {
                    Some((schema, op))
                }
                _ => None,
            })
            .unwrap_or((records::SCHEMA_TASK, records::OP_GET))
    }

    /// One caller's bucket chain, resolved where the root resolves the caller.
    ///
    /// `None` is the FAIL-CLOSED arm and not the uncapped one: it is a caller bound to a group this
    /// node's configuration does not have, whose caps therefore could not be read, and the admission
    /// step refuses it over budget. A caller bound to no group at all has a perfectly good chain of
    /// one uncapped attribution bucket and gets it.
    fn chain_for(
        &self,
        who: &busbar_caps::PrincipalId,
        group: Option<&str>,
    ) -> Option<BucketChain> {
        self.groups.chain_for(who.as_str(), group).ok()
    }

    /// **WHAT THIS NODE PRICES A UNIT AT RIGHT NOW**, read from the process's holder per walk.
    ///
    /// Never captured. A leg that pinned its price at assembly would go on admitting against a fee
    /// the operator had already replaced: the engine's own spend projection reprices on every apply
    /// and reload, and a boot-bound door would not — so the identity that says the two are one money
    /// would hold exactly until somebody edited a figure. One `Arc` per walk, taken once at the top,
    /// so every step of one unit is judged against ONE resolution even if an apply lands mid-walk.
    ///
    /// The fallback is the rates this leg was assembled over, which the assembly refused to be
    /// without. It is the last figures this node genuinely resolved and never a price nobody wrote.
    fn rates(&self, at_ms: u64) -> Arc<crate::root::kernel::RootRates> {
        self.rates_from(&crate::root::kernel::ROOT_CARD, at_ms)
    }

    /// [`A2aLeg::rates`] against one named holder.
    ///
    /// The holder is a parameter and the process's own is supplied one line up, so the reading can
    /// be exercised against a holder of its own rather than by repricing the binary's. A cell that
    /// had to move the node's card in order to observe this would be a cell that moved it for every
    /// other cell in the same process.
    fn rates_from(
        &self,
        holder: &crate::root::kernel::RootHistory,
        at_ms: u64,
    ) -> Arc<crate::root::kernel::RootRates> {
        holder
            .pin_rates(at_ms)
            .unwrap_or_else(|| Arc::clone(&self.rates_at_assembly))
    }

    /// WHAT A BYTE OF THIS PLANE'S PRICED DOCUMENT COSTS, off the card, for the admission estimate.
    ///
    /// The MAXIMUM over the lanes this deployment's own agents are reached on, because that is what
    /// the estimate the door reads is FOR: an upper bound on what the unit about to run could cost,
    /// taken before anything is known about which agent it reaches. A mean would under-reserve on
    /// the dearest lane and an arbitrary pick would under-reserve on all but one.
    ///
    /// A lane the card does not name prices at nothing HERE and is refused elsewhere — the card's
    /// own `lane_unpriced` is what fails an unpriced lane closed, and folding that refusal into a
    /// maximum would turn "this lane has no entry" into "this lane is free".
    fn bytes_nanos(&self, card: &busbar_unit_cost::RateCard) -> u64 {
        self.plane
            .agents()
            .iter()
            .map(|agent| {
                card.lane_rates(agent.lane.as_str(), crate::root::kernel::node_currency())
                    .map_or(0, |rates| rates.nanos_per_unit(CLASS_BYTES.as_str()))
            })
            .max()
            .unwrap_or(0)
    }

    /// The bindings one unit runs over, borrowed from this leg for the length of one call.
    #[allow(clippy::too_many_arguments)]
    fn bindings<'r>(
        &'r self,
        pools: &'r Pools<busbar_plane_a2a::Agent>,
        kinds: &'r Kinds<'r, busbar_plane_a2a::Agent>,
        pinned: &'r [&'r str],
        chain: Option<&'r BucketChain>,
        now: u64,
        mono: u64,
        dispatch: Option<&'r dyn crate::root::transports::MountDispatch>,
        pricer: &'r Pricer,
        bytes_nanos: u64,
        open: bool,
    ) -> A2aBindings<'r, InMemoryCells> {
        A2aBindings {
            // THE DOOR THIS UNIT IS JUDGED BEHIND, chosen per ADDRESS. The deployment's own chain
            // guards the addresses the deployment guards; an address this protocol DECLARED open is
            // served through no door, because that is where a conformant client looks first and
            // running the chain there refuses every caller before it can learn what to present.
            auth: if open { &self.open_auth } else { &self.auth },
            auth_bindings: &self.auth_bindings,
            trust_token: &self.trust_token,
            pools,
            kinds,
            breaker: self.breaker.as_ref(),
            resolver: &self.resolver,
            guard: self.guard,
            denylist: &self.denylist,
            pinned,
            door: &self.door,
            chain,
            pricer,
            bytes_nanos,
            records: &self.records,
            meter_policy: &self.meter_policy,
            scope_policy: &self.scope_policy,
            durability: &self.durability,
            pool: PLANE_POOL,
            now,
            task_ttl_secs: TASK_TTL_SECS,
            mono,
            dispatch,
            origin: self.origin,
        }
    }

    /// **Whether the address this arrival names is one THIS PLANE DECLARED OPEN.**
    ///
    /// Asked of the plane's own declared surface through the generic reader, so the answer here and
    /// the answer a mount composed over the same surface gives are one reading. The request line is
    /// the arrival's own reserved facts — never a header and never a path this file spelled — and an
    /// arrival that publishes neither is not an open address, which is the fail-closed reading.
    fn addresses_openly(&self, arrival: &busbar_contract::transport::Arrival<'_>) -> bool {
        use busbar_contract::transport::facts;
        let (Some(path), Some(method)) = (arrival.fact(facts::PATH), arrival.fact(facts::METHOD))
        else {
            return false;
        };
        crate::root::data_plane::addresses_openly(&busbar_plane_a2a::surface::SURFACE, path, method)
    }

    /// What the plane made of one arrival, read ONCE.
    ///
    /// ## The seam this reads across, stated rather than hidden
    ///
    /// `PlaneLeg::walk` is handed the arrival and nothing else, so the leg asks the plane what the
    /// bytes are here. The driver above it has already asked the same question, inside its own arena,
    /// to obtain the draft its refusal encoder needs — so on the mounted path the plane's decode runs
    /// twice for one request. That is a property of the seam r31d landed and not of this file: the
    /// driver's answer BORROWS its own arena and cannot cross back out of it, and widening `walk` to
    /// carry a decoded answer would put a plane-shaped value on a trait that deliberately has none.
    /// It is named in the hand-back as an open item rather than worked around with a cache, because
    /// a cache keyed on anything an arrival carries is a cache an attacker chooses the key of.
    fn decode(&self, arrival: &busbar_contract::transport::Arrival<'_>, now: u64) -> Decoded {
        let clock = busbar_contract::unit::Clock {
            unix_secs: now,
            monotonic_nanos: self.started.elapsed().as_nanos(),
        };
        let request_bytes = arrival.body.len() as u64;
        let op = crate::root::plane_ctx::with_frames(arrival, clock, |ctx, frames| {
            use busbar_contract::Plane as _;
            match self.plane.decode_ingress(frames, None, ctx) {
                Ok(busbar_contract::Ingress::OneShot(d))
                | Ok(busbar_contract::Ingress::Open(d))
                | Ok(busbar_contract::Ingress::Handshake(d)) => Some(d.op),
                // Every other answer is the plane saying these bytes are not a unit of its own: a
                // frame of an already-open unit, a close, a discard, or a body it could not read.
                // The draft that comes out of `None` reaches nowhere and is refused at decode, which
                // is the step that read it.
                _ => None,
            }
        });
        // WHAT THE REQUEST CARRIES ABOUT ITSELF, read off the arrival's own reserved fact rather
        // than off a header. A transport publishes the credential WHOLE — the scheme word travels
        // with it, because deciding what a scheme means is the chain's — so this is the one place
        // the two halves are told apart, and it is told apart once for both readers below.
        let presented = arrival
            .fact(busbar_contract::transport::facts::CREDENTIAL)
            .map(presented_credential);
        // AND THE OPEN ADDRESSES STAY OPEN. This protocol serves its protected-resource metadata and
        // its own agent card unauthenticated, because that is where a conformant client looks FIRST
        // and the metadata document is how a caller learns which audience to ask for — demanding
        // that audience to read it refuses every caller before it can find out what to present.
        //
        // Asked per ADDRESS and never per operation. The card operation is served at three addresses
        // — two open discovery ones and one credentialed extended card — so an operation-shaped
        // answer either refuses the discovery addresses or opens the credentialed one. The question
        // goes to the plane's own declared surface, which answers it per dispatch.
        let under_scheme = op.is_some() && !self.addresses_openly(arrival);
        Decoded {
            op,
            request_bytes,
            // The bare credential, with the scheme word taken off exactly once. The chain is handed
            // the secret and never the carrier's spelling of it.
            credential: presented.as_ref().and_then(|(_, token)| token.clone()),
            // THE AUDIENCE, on every credentialed surface and on no open one. A bearer minted for
            // another resource is a bearer for another surface, and this is the field that makes the
            // authenticate step say so — it is the boundary the plane's own protected-resource
            // metadata advertises, so a caller is told to ask for the same string this demands.
            expected_aud: under_scheme.then(|| self.expected_aud.clone()),
            // Nothing on this plane's mounted path is a bound session: every claim carries its
            // credential on the request, so every unit re-authenticates and revocation bites.
            from_session: false,
            // NARROWED BY WHAT ARRIVED, within what the plane declared. A carrier the plane's claims
            // do not name narrows to nothing, and narrowing to nothing inside a NON-EMPTY declared
            // set is a refusal at the authenticate step — which is the fail-closed answer and the
            // reason this is a lookup rather than a constant.
            narrowing: under_scheme
                .then(|| presented.as_ref().and_then(|(scheme, _)| *scheme))
                .flatten(),
            declared_schemes: if under_scheme {
                declared_schemes()
            } else {
                &[]
            },
        }
    }
}

/// The scheme alternatives this plane's credentialed claims declare, read off the claims themselves.
///
/// Read rather than restated, so a claim that gained an alternative gains it here too. The open
/// claims contribute nothing, which is the whole point of them being open.
fn declared_schemes() -> &'static [&'static str] {
    busbar_plane_a2a::claims::CLAIMS
        .iter()
        .map(|claim| claim.scheme_alternatives)
        .find(|alts| !alts.is_empty())
        .unwrap_or(&[])
}

/// One presented credential, split into the carrier it named and the secret it carried.
///
/// The scheme word is stripped ONCE and case-insensitively — `bearer <t>` is the same credential as
/// `Bearer <t>` on the wire — and the word is matched against the alternatives the plane DECLARED
/// rather than against a literal here, so the narrowing and the strip cannot disagree about which
/// carrier this is.
///
/// A credential with no recognised carrier keeps its bytes and names no scheme. That is the
/// fail-closed pair: the chain is handed exactly what arrived, and the narrowing is absent, which
/// the authenticate step reads as a unit that did not narrow within a set that has alternatives.
///
/// An EMPTY secret is `None` rather than `Some("")`, the same distinction the transport already
/// makes when it publishes the fact at all: a chain handed a blank credential is being told one was
/// presented and is blank.
fn presented_credential(value: &str) -> (Option<&'static str>, Option<String>) {
    let trimmed = value.trim_start();
    let split = trimmed.split_once(' ').and_then(|(word, rest)| {
        declared_schemes()
            .iter()
            .find(|alt| alt.eq_ignore_ascii_case(word))
            .map(|alt| (*alt, rest.trim_start()))
    });
    let (scheme, secret) = match split {
        Some((alt, rest)) => (Some(alt), rest),
        None => (None, trimmed),
    };
    (scheme, (!secret.is_empty()).then(|| secret.to_string()))
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE LEG ON THE LOOP
// ═════════════════════════════════════════════════════════════════════════════════════════════════

impl crate::root::transports::PlaneLeg for A2aLeg {
    /// Assemble one unit FROM the arrival and walk it through the kernel's ten steps.
    ///
    /// This is the method the blanket implementation could not provide and the reason `PlaneLeg`
    /// exists as a trait at all: the units this returns cannot be built before the arrival is,
    /// because the bindings they run over carry facts the arrival decided — what the plane made of
    /// the bytes, when they landed, which caller's chain they are judged against.
    ///
    /// The kernel, the hold cell, the leases, the gauge and the canary are the DRIVER'S and arrive
    /// whole; a leg that made its own would be balancing its own books beside the node's.
    fn walk(
        &self,
        arrival: &busbar_contract::transport::Arrival<'_>,
        kernel: &Kernel,
        ctx: &UnitCtx,
        run: Run<'_>,
    ) -> Ended {
        // NO SEAM ON THIS PATH. A driver that walks a leg learns an ending and nothing else, and a
        // leg walked without a mount behind it has no surface to reach — so the units run the ten
        // steps and report zero bytes, which is exactly the posture this leg had before a mount
        // existed. The mount's own path is [`A2aLeg::serve`], which supplies the seam and reads the
        // answer back out.
        self.serve(arrival, kernel, ctx, run, None).0
    }
}

impl A2aLeg {
    /// Walk one arrival WITH the seam the mount composes, and hand back the ending AND the answer.
    ///
    /// The one method a mount needs and the driver does not. `PlaneLeg::walk` above is the same walk
    /// with no seam and the answer dropped, which is what makes the two paths one body rather than
    /// two: a second assembly of the bindings would be a second chance for a mounted unit and a
    /// driven one to be judged differently.
    ///
    /// The answer is `None` for a unit that ended before Route. That is the GATE working: a refusal
    /// at Verify, Approve or Admit ends the unit before the seam is touched, so there is nothing to
    /// report, and the caller renders the loop's own refusal instead of asking the surface a second
    /// time.
    pub fn serve(
        &self,
        arrival: &busbar_contract::transport::Arrival<'_>,
        kernel: &Kernel,
        ctx: &UnitCtx,
        run: Run<'_>,
        dispatch: Option<&dyn crate::root::transports::MountDispatch>,
    ) -> (Ended, Option<crate::root::transports::PlaneAnswer>) {
        // THE TWO CLOCKS, PINNED ONCE, HERE. Two readings and not one number written twice: the wall
        // epoch dates the unit and the monotonic reading orders it. Read at the top of the walk so
        // every step of this unit is judged against the same moment — a check in one window and a
        // charge in another is exactly what a per-step clock read produces.
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let now = wall.as_secs();
        // The same reading in the units the rate-card history is dated in, so the entry this unit
        // is priced against is the one in force at the instant it arrived and not a second later.
        let now_ms = u64::try_from(wall.as_millis()).unwrap_or(u64::MAX);
        let mono = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);

        let decoded = self.decode(arrival, now);
        let draft = A2aDraft::from_decoded(
            &self.plane,
            &decoded,
            busbar_contract::wire::ArrivalRecord {
                source: arrival.fact("peer").unwrap_or_default().to_string(),
                port: 0,
                alpn: None,
                sni: None,
                peer_cert: None,
                transport_chain: arrival.chain.to_vec(),
            },
        );

        // The per-request views, on this stack frame, borrowing the boot-resolved sets.
        let pools = self.pools();
        let (schema, op) = Self::record_leg_of(&draft);
        let kinds = self.kinds(schema, op);
        let pinned: Vec<&str> = self.pinned.iter().map(String::as_str).collect();
        // THE CHAIN, resolved ONCE per unit rather than inside the admission step. Anonymous until
        // the authenticate step says otherwise, which is what the chain is keyed on: the door reads
        // the caller's own attribution bucket, and a caller bound to no group has one uncapped one.
        let chain = self.chain_for(&busbar_caps::PrincipalId::new(""), None);
        // THE MONEY, PINNED ONCE, HERE, exactly as the two clocks above are and for the same
        // reason: a unit admitted against one resolution and settled against another is a request
        // priced by how long it took.
        let rates = self.rates(now_ms);
        let bytes_nanos = rates.with_card(|card| self.bytes_nanos(card)).unwrap_or(0);
        // WHETHER THIS ADDRESS IS ONE THE PLANE DECLARED OPEN, read ONCE and used by both halves of
        // the same decision: which door this unit is judged behind, and which grants it carries.
        let open = self.addresses_openly(arrival);

        let bindings = self.bindings(
            &pools,
            &kinds,
            &pinned,
            chain.as_ref(),
            now,
            mono,
            dispatch,
            rates.pricer(),
            bytes_nanos,
            open,
        );
        // THE GRANTS ARE THE CALLER'S, and this arrival presented no credential, so they are the
        // anonymous set. Read-only is what an unidentified caller holds; the approve step compares
        // it against the policy's own entry for the class and refuses what it does not cover.
        //
        // EXCEPT ON AN ADDRESS THIS PROTOCOL DECLARED OPEN, where the scope step has nothing to
        // decide: there is no identity to narrow, because the declaration says this address admits
        // an unidentified caller, and the operation's real authority is the surface's to check —
        // the push callback's token is INSIDE the request and is where the shipped release checks
        // it. A loop that admitted the caller at the door and refused it at Approve turned every
        // real push delivery into a refusal before the surface saw the token.
        //
        // The narrowness is the safety argument, and it is worth stating: only an address the
        // plane's own surface declares OPEN reaches this arm, this protocol declares three, and two
        // of them are read-only discovery.
        let grants = Grants::of(if open {
            draft
                .op
                .map_or(Scope::ReadOnly, crate::root::units_a2a::declared_scope)
        } else {
            Scope::ReadOnly
        });
        let units = A2aUnits::new(bindings, draft, grants);
        let ended = busbar_kernel::teller::run_unit(kernel, &units, ctx, run);
        // READ AFTER THE WALK and off the units the walk ran against, which is the only place it
        // exists: the loop's ending carries a frame and a frame carries no status and no headers.
        let answer = units.answer();
        (ended, answer)
    }
}

/// The operation classes this plane declares, for a caller that wants to check the leg covers them.
#[must_use]
pub fn declared_classes() -> &'static [busbar_contract::ids::OpClassId] {
    ops::OP_CLASSES
}

#[cfg(test)]
#[path = "tests/units_a2a_leg.rs"]
mod tests;
