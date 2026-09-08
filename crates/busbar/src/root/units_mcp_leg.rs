// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE SERVING SWITCH, ON THE WHOLE FILE, for the reason the A2A sibling's leg carries the same line:
// the leg is composition rather than a byte diverted, but it is composition of the SERVING path.
// Declared in `root/mod.rs` under `root-mcp` instead, because everything here reaches into the MCP
// plane's units and a module gated on the serving switch alone would be reaching across a feature
// boundary the root's own escape test exists to refuse.
#![cfg(feature = "root-mcp-serve")]

//! THE MCP PLANE'S LEG: an OWNED assembly, built once at boot, that produces one unit per arrival.
//!
//! ## The finding this file is the answer to
//!
//! [`crate::root::units_mcp::McpBindings`] describes one unit of the MCP plane precisely and
//! completely. It is BORROWED: `McpBindings<'r>` holds `&'r` references to things that have to
//! outlive the request, and nothing in the workspace held those things. Every construction of it was
//! a cell's, which is the same sentence as "the MCP plane's decode reaches no step of the kernel".
//!
//! This file resolves them, and it resolves each one FROM THE PLACE THAT ALREADY ANSWERS IT — see
//! [`SOURCES`], which is the whole table and is checked against the bindings' own source at test
//! time, so a field cannot be added without a source being named for it.
//!
//! ## Owned, and why that is the shape rather than a convenience
//!
//! A [`crate::root::transports::PlaneLeg`] is asked for a unit AFTER an arrival exists, and the
//! bindings a unit runs over borrow from things assembled long before. So the leg owns the
//! long-lived halves — the door, the group table, the book, the store, the registration set — and
//! [`McpLeg::serve`] borrows from `&self` to build one `McpBindings` on the stack, for the length of
//! one call. Nothing per-request is allocated that outlives the request, and nothing per-boot is
//! rebuilt per request.
//!
//! ## NO INVENTED CONFIGURATION
//!
//! Not one key here is new. Every field is either read from the configuration the legacy
//! `busbar-mcp` plugin already resolves — with that resolution mirrored, not reinterpreted — or is a
//! value the composition root already holds for its other planes. A field whose source could not be
//! named REFUSES BOOT, by name, in [`McpLeg::assemble`]; there is deliberately no arm that supplies
//! a default. A default here is a deployment served under a policy nobody wrote down.
//!
//! ## THE MONEY IS READ LIVE, NEVER CAPTURED AT BOOT
//!
//! The two prices this plane's estimate is sized against and the flat fee beside them are read from
//! [`crate::root::kernel::ROOT_CARD`] at the top of every walk — the process's own card holder,
//! which the engine's rate-apply seam swaps on boot AND on every live apply or reload. A leg that
//! captured either at boot would go on pricing this node's ledger against rates the operator has
//! already replaced: the usage projection would reprice on an apply and the ledger would not, and
//! the identity that says the two are one money would hold only until the first fee changed.
//!
//! The card is PINNED once per unit and every step of that unit prices against the one pinned
//! reading, which is what makes an apply landing mid-request unable to reprice a request halfway
//! through.
//!
//! ## What this file does NOT do
//!
//! It decides nothing. The auth chain says who is calling, the trust unit says where a unit may go,
//! the scope unit says whether the caller may ask, the door says whether it is paid for, the usage
//! unit folds the meter and the audit unit seals the end. What is here is the WIRING, and the twelve
//! step answers are [`crate::root::units_mcp::McpUnits`]'s, unchanged and untouched by this file.

use std::sync::{Arc, Mutex};

use busbar_contract::ids::RecordSchemaId;
use busbar_kernel::teller::{Ended, Kernel, Run, UnitCtx};
use busbar_plane_mcp::{claims, records, McpPlane};
use busbar_unit_admission::{BucketChain, Door, GroupTable, InMemoryCells, Pricer};
use busbar_unit_auth::Auth;
use busbar_unit_scope::{Grants, Scope};
use busbar_unit_trust::lane::BreakerView;
use busbar_unit_trust::net::{Denylist, GuardPolicy};

use crate::root::durability::Durability;
use crate::root::kernel::auth_bindings::AuthBindings;
use crate::root::policy::{MeterPolicyHandle, ScopePolicy};
use crate::root::registrations::{NetSeam, SystemResolver};
use crate::root::units_mcp::{
    claim_key, pool_key, required_scopes, Arrived, Catalogue, ClassPrices, Clocks, McpBindings,
    McpDraft, McpUnits, Pools, Records,
};

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE FIELD → SOURCE TABLE
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// WHERE EVERY ONE OF THE EIGHTEEN BINDINGS COMES FROM.
///
/// One row per field of `McpBindings`, and the cell beside this file reads that struct's own source
/// and asserts the two agree — so a binding added without a source named for it does not compile a
/// green test. That check is the point of the table existing as data rather than as prose: a comment
/// saying "every field is sourced" is worth nothing the day a field is added.
///
/// The second column is a LOCATION, not a description. Where the legacy plugin already resolves the
/// value, the row names the resolution being mirrored, because the mirror has to be checkable
/// against it. Where the root already holds the value for another plane, the row names the root's
/// own resolution.
pub const SOURCES: &[(&str, &str)] = &[
    // ── what the bytes mean ──────────────────────────────────────────────────────────────────────
    (
        "plane",
        "root: `McpPlane` over the registrations the operator configured, the SAME plane value \
         `root::registry` registers — never a second one built here, because two planes are two \
         registration sets",
    ),
    // ── the caller's identity ────────────────────────────────────────────────────────────────────
    (
        "auth",
        "root: the node's configured auth chain (`kernel::auth_bindings`), the same one the admin \
         mount is built with",
    ),
    (
        "auth_bindings",
        "root: the node's ONE `AuthBindings` — cache, key verifier, revocation view — over the \
         governance directory",
    ),
    // ── where a unit may go ──────────────────────────────────────────────────────────────────────
    (
        "pools",
        "root: `registrations::Pools` over `McpPlane::servers()`, keyed under this plane's own \
         region of the pool keyspace (`units_mcp::POOL_PREFIX_TOOL`)",
    ),
    (
        "kinds",
        "root: `registrations::Kinds` over the same server set, with this plane's `MCP_RULES` and \
         the node's one network-guard seam — reached through `units_mcp::Catalogue`",
    ),
    (
        "breaker",
        "root: the node's ONE breaker adapter — the same cells the egress walk's pre-filter reads",
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
        "LIVE: `kernel::ROOT_CARD.pin()` → `RateCard::per_request_fee_cents()` → `Pricer::flat`, \
         read at the top of every walk and never captured at boot",
    ),
    (
        "prices",
        "LIVE: `kernel::ROOT_CARD.pin()` → `lane_rates(<the registration's own lane>)` → \
         `nanos_per_unit` for this plane's two declared classes. The lane is the registration's, \
         which is the key the rate card already hangs a price on and the key the breaker already \
         uses; no class-keyed table is invented, and no reading is taken at boot",
    ),
    // ── the durable half ─────────────────────────────────────────────────────────────────────────
    (
        "records",
        "root: `units_mcp::Records` over the node's one store adapter, at the published protocol",
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
        "root: `units_mcp::required_scopes()` declared under `units_mcp::claim_key()` — one entry \
         per operation class the plane declares, because the scope unit reads silence as a refusal",
    ),
    // ── the request's own coordinates ────────────────────────────────────────────────────────────
    (
        "pool",
        "root: `units_mcp::pool_key(<the registration this unit names>)`, which is the key the \
         breaker and the pool table already use — pinned against `busbar_substrate::store::tool_key`",
    ),
    (
        "at",
        "the arrival's pinned wall epoch and the node's monotonic reading, both taken ONCE per unit \
         and never per step — two measurements, not one number written twice",
    ),
    // ── the one seam the answer comes back through ───────────────────────────────────────────────
    (
        "dispatch",
        "root: the mount's per-arrival seam onto the surface the operation is already mounted on — \
         `None` on a build with no mount, which is a posture and not a missing source",
    ),
    // ── the seal the kernel mints ────────────────────────────────────────────────────────────────
    (
        "origin",
        "kernel: `Kernel::origin(OriginKind::Client)`; sealed, for the audit record",
    ),
];

/// WHERE THE FACTS THE LEG READS OFF ONE ARRIVAL COME FROM.
///
/// A SECOND TABLE, deliberately, and not more rows on [`SOURCES`]. That table is one row per field
/// of `McpBindings` and is checked against that struct's own source, so a row for something which is
/// not a binding would fail the check that makes the table worth having. What is here is the other
/// half of the same accounting: the boot-resolved values [`McpLeg::decode`] needs in order to answer
/// [`McpDraft`] with what a request actually carries.
pub const DECODE_SOURCES: &[(&str, &str)] = &[
    (
        "presented",
        "the arrival's own reserved credential fact, published WHOLE by the transport — the scheme \
         word travels with it, because deciding what a scheme means is the chain's",
    ),
    (
        "under_scheme",
        "the plane's own claim table: a claim that declares no scheme has nothing to narrow WITHIN \
         and no audience to demand, and the discovery document is the one surface of this plane \
         that declares none",
    ),
    (
        "claim_transport",
        "the transport the mount published, matched against this plane's own three claim \
         constants — a carrier no claim names carries the empty string forward, which the arrival \
         step refuses as a handoff mismatch",
    ),
];

/// The audience a credential presented on this plane must name is NOT sourced here, and that is a
/// statement rather than a gap.
///
/// `units_mcp::authenticate` derives it from the plane's own canonical key, and it does so for every
/// credentialed claim. There is nothing for the leg to supply and nothing for it to get wrong: a
/// leg that carried an audience of its own would be a second answer to which tokens open this
/// surface, which is the worst possible thing to hold two answers to.
///
/// The legacy plugin's `mcp.canonical_uri` is the RFC 8707 resource indicator this node PUBLISHES,
/// and it is the mount's to advertise rather than the leg's to demand.
pub const AUDIENCE_IS_THE_PLANES: &str =
    "units_mcp::authenticate, from <McpPlane as PlaneMeta>::KEY, on every credentialed claim";

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
    /// The `McpBindings` field that could not be sourced.
    pub field: &'static str,
    /// Where it would have come from, in the words of [`SOURCES`].
    pub source: &'static str,
}

impl std::fmt::Display for MissingSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the composition root did not seal: the MCP leg's `{}` has no source on this \
             deployment, and it is sourced from {}",
            self.field, self.source
        )
    }
}

impl std::error::Error for MissingSource {}

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
/// refuses on the first one that is. The fields that cannot be absent — the plane's own server set,
/// the kernel's seal, the two clocks — are not options, because "the kernel did not mint an origin"
/// is not a deployment state and offering an arm for it would be inventing a failure mode.
pub struct McpLegSources<'k> {
    /// The plane, carrying the registrations this deployment configured.
    pub plane: McpPlane,
    /// The kernel the sealed origin is lent from.
    pub kernel: &'k Kernel,
    /// The node's configured authentication chain.
    pub auth: Option<Auth>,
    /// The node's one credential cache, key verifier and revocation view.
    pub auth_bindings: Option<AuthBindings>,
    /// The node's one breaker, behind the trust unit's own port.
    pub breaker: Option<Arc<dyn BreakerView + Send + Sync>>,
    /// How far this plane's hops may reach, mirrored off the legacy plugin's own upstream policy.
    pub guard: Option<GuardPolicy>,
    /// The operator's metadata denylist.
    pub denylist: Option<Denylist>,
    /// The node's one admission door.
    pub door: Option<Door<InMemoryCells>>,
    /// The configured group table the caller's bucket chain is walked out of.
    pub groups: Option<GroupTable>,
    /// The node's one store, for this plane's durable records.
    pub store: Option<Arc<dyn busbar_api::Store>>,
    /// What the usage unit folds against.
    pub meter_policy: Option<MeterPolicyHandle>,
    /// What the scope unit reads at approve.
    pub scope_policy: Option<ScopePolicy>,
    /// The node's one book.
    pub durability: Option<Arc<Mutex<Durability>>>,
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

/// THE MCP PLANE'S LEG, owned and assembled once.
///
/// Everything expensive has already happened by the time one of these is walked: the journal is
/// open, the ledger cells are hydrated, the auth chain is resolved and the store is opened. What a
/// walk does is borrow from here, ask the plane what the bytes are, pin the card, and run the
/// twelve steps.
pub struct McpLeg {
    plane: McpPlane,
    auth: Auth,
    auth_bindings: AuthBindings,
    origin: busbar_caps::Origin,
    breaker: Arc<dyn BreakerView + Send + Sync>,
    resolver: SystemResolver,
    guard: GuardPolicy,
    denylist: Denylist,
    door: Door<InMemoryCells>,
    groups: GroupTable,
    records: Records,
    meter_policy: MeterPolicyHandle,
    scope_policy: ScopePolicy,
    durability: Arc<Mutex<Durability>>,
    key_scopes: Option<Vec<String>>,
    priced: bool,
    has_key: bool,
    /// The pool this deployment's units are admitted and metered against, interned once.
    ///
    /// `tool:<the first registration's name>`, which is the key the breaker and the pool table
    /// already use. Owned because the binding wants a `&str` for the length of one walk and a
    /// boot-resolved key cannot borrow from the boot that resolved it.
    pool: String,
    /// When this process started, for the monotonic half of a unit's clock reading. The wall reading
    /// dates a unit and this one ORDERS it; filling both from the wall clock gives a unit one clock
    /// written twice, which still dates correctly and orders nothing at all.
    started: std::time::Instant,
}

impl std::fmt::Debug for McpLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("McpLeg")
    }
}

impl McpLeg {
    /// Assemble the leg, or REFUSE BOOT naming the field that has no source.
    ///
    /// # Errors
    ///
    /// One of the sources in [`SOURCES`] is absent on this deployment. The refusal names the field
    /// and quotes the table's own row for it, so an operator reads what to configure rather than
    /// which line of Rust returned `None`.
    pub fn assemble(sources: McpLegSources<'_>) -> Result<Self, MissingSource> {
        Ok(McpLeg {
            pool: pool_key(sources.plane.servers().first().map_or("", |s| s.id)),
            plane: sources.plane,
            auth: sources.auth.ok_or_else(|| missing("auth"))?,
            auth_bindings: sources
                .auth_bindings
                .ok_or_else(|| missing("auth_bindings"))?,
            // SEALED BY THE KERNEL, not offered: `Origin::seal` takes the kernel's seal and this is
            // not the kernel. The kernel is handed in whole rather than as a sealed value so a
            // caller cannot pass one kernel's origin beside another kernel's tokens.
            origin: sources.kernel.origin(busbar_caps::OriginKind::Client),
            breaker: sources.breaker.ok_or_else(|| missing("breaker"))?,
            resolver: SystemResolver,
            guard: sources.guard.ok_or_else(|| missing("kinds"))?,
            denylist: sources.denylist.ok_or_else(|| missing("kinds"))?,
            door: sources.door.ok_or_else(|| missing("door"))?,
            groups: sources.groups.ok_or_else(|| missing("chain"))?,
            records: Records::over(sources.store.ok_or_else(|| missing("records"))?),
            meter_policy: sources
                .meter_policy
                .ok_or_else(|| missing("meter_policy"))?,
            scope_policy: sources
                .scope_policy
                .ok_or_else(|| missing("scope_policy"))?,
            durability: sources.durability.ok_or_else(|| missing("durability"))?,
            key_scopes: sources.key_scopes,
            priced: sources.priced,
            has_key: sources.has_key,
            started: std::time::Instant::now(),
        })
    }

    /// The scope policy this plane needs, folded onto whatever the deployment already declared.
    ///
    /// Every operation class the plane declares gets an entry, because the scope unit reads silence
    /// as a refusal and a plane with a partly-declared policy is a plane whose remaining operations
    /// are unreachable for a reason nobody can find in a configuration file.
    #[must_use]
    pub fn scope_policy(base: ScopePolicy) -> ScopePolicy {
        required_scopes()
            .into_iter()
            .fold(base, |policy, (op, scope)| {
                policy.declaring(claim_key(), op, scope)
            })
    }

    /// The plane this leg serves, for a caller that has to hand the same one to the driver.
    #[must_use]
    pub fn plane(&self) -> &McpPlane {
        &self.plane
    }

    /// The pool this leg's units are admitted and metered against.
    #[must_use]
    pub fn pool(&self) -> &str {
        &self.pool
    }

    /// **Whether these bytes are a unit THIS PLANE has** — asked of the plane, answered by the
    /// plane.
    ///
    /// The question a mount has to ask before it takes a request off the surface that already
    /// answers it. A body whose operation this plane cannot name is not a unit of this plane; it is
    /// a request the mounted router's own routing already answers, with the document, the 404, the
    /// 405 or the `-32601` that release pinned, and a loop that took it would be manufacturing a
    /// status for bytes it never claimed.
    ///
    /// It runs the plane's decode and nothing else — no step, no seam, no clock a unit would be
    /// judged against — so asking it costs one reading of the body and decides nothing.
    #[must_use]
    pub fn recognises(&self, arrival: &busbar_contract::transport::Arrival<'_>) -> bool {
        self.decode(arrival, 0).op.is_some()
    }

    /// **The plane's own refusal document for one ending**, for a mount that has to write it.
    ///
    /// Rendered by the PLANE, through the same helper the generic driver uses, so a caller refused
    /// by the mounted loop and one refused by the driven loop read the same bytes — carrying their
    /// own request identifier back to them, which is the whole reason a refusal is the plane's to
    /// write rather than the mount's.
    ///
    /// `None` for an ending this plane has no rendering for: an abort and a timeout name no reason,
    /// so a document for one would have to have a reason invented for it here.
    #[must_use]
    pub fn render_refusal(
        &self,
        arrival: &busbar_contract::transport::Arrival<'_>,
        ended: &Ended,
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
            // it cannot have been kept from the walk. An answer correlated to the wrong request is
            // worse than an uncorrelated one, so it is re-read rather than cached on anything an
            // attacker chooses.
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

    /// The pool view for one caller, over this deployment's registrations.
    fn pools(&self) -> Pools {
        Pools::new(
            self.plane,
            self.key_scopes.clone(),
            self.has_key,
            self.priced,
        )
    }

    /// The per-kind facts for one unit, whose plan reaches one schema under one operation.
    ///
    /// The schema and the operation come off the draft the plane produced, so the record question
    /// the trust unit asks is about the leg this unit actually walks rather than a representative
    /// one.
    fn kinds(&self, schema: RecordSchemaId, op: &'static str) -> Catalogue<'_> {
        Catalogue::new(
            self.plane,
            schema,
            op,
            NetSeam {
                resolver: &self.resolver,
                policy: self.guard,
                denylist: &self.denylist,
            },
        )
    }

    /// The record leg this unit's plan reaches first, where it reaches one.
    ///
    /// A plan with no record leg is asked about the catalogue under a scan — the narrowest true
    /// statement available, and NOT a pass: the allow-list and the guard conjuncts beside it are
    /// what decide an upstream hop, and the record conjunct only ever has to be true of a plan that
    /// has a record leg in it.
    fn record_leg_of(draft: &McpDraft) -> (RecordSchemaId, &'static str) {
        draft
            .plan
            .iter()
            .find_map(|destination| match destination {
                busbar_contract::dest::DestinationFacts::PlaneRecord { schema, op } => {
                    Some((*schema, *op))
                }
                _ => None,
            })
            .unwrap_or((records::SCHEMA_CATALOGUE, records::OP_SCAN))
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

    /// **THE MONEY, PINNED ONCE PER UNIT, off the process's live card.**
    ///
    /// Two readings out of one pinned `Arc`: what a unit of this plane costs per completed call and
    /// per priced byte, and what the flat per-request fee is. Both come from the card the engine's
    /// rate-apply seam last swapped in — at boot and on every apply or reload — so a fee the
    /// operator changed moves this node's ledger and the usage projection together.
    ///
    /// The classes are looked up on the REGISTRATION'S OWN LANE, which is the key the rate card
    /// already hangs a price on and the key the breaker already uses. No class-keyed table is
    /// invented and no configuration key is added: `lane_rates(lane).nanos_per_unit(class)` is the
    /// card's own published reading.
    ///
    /// A node that has read no configuration yet holds no card, and the honest answer for that is
    /// nothing priced and no fee — which is exactly what the card holder's own documentation says a
    /// report arriving that early should be priced at.
    fn money(&self) -> (ClassPrices, Pricer) {
        let Some(card) = crate::root::kernel::ROOT_CARD.pin() else {
            return (ClassPrices::default(), Pricer::flat(0));
        };
        let lane = self.plane.servers().first().map_or("", |s| s.lane.as_str());
        let prices = card
            .lane_rates(lane)
            .map_or_else(ClassPrices::default, |r| ClassPrices {
                tool_calls: r.nanos_per_unit(busbar_plane_mcp::meta::CLASS_TOOL_CALLS.as_str()),
                bytes: r.nanos_per_unit(busbar_plane_mcp::meta::CLASS_BYTES.as_str()),
            });
        (prices, Pricer::flat(card.per_request_fee_cents()))
    }

    /// What the plane made of one arrival, read ONCE.
    ///
    /// ## The seam this reads across, stated rather than hidden
    ///
    /// `PlaneLeg::walk` is handed the arrival and nothing else, so the leg asks the plane what the
    /// bytes are here. A driver above it has already asked the same question, inside its own arena,
    /// to obtain the draft its refusal encoder needs — so on the driven path the plane's decode runs
    /// twice for one request. That is a property of the `PlaneLeg` seam and not of this file: the
    /// driver's answer BORROWS its own arena and cannot cross back out of it, and widening `walk` to
    /// carry a decoded answer would put a plane-shaped value on a trait that deliberately has none.
    /// It is named in the hand-back as an open item rather than worked around with a cache, because
    /// a cache keyed on anything an arrival carries is a cache an attacker chooses the key of.
    fn decode(&self, arrival: &busbar_contract::transport::Arrival<'_>, now: u64) -> McpDraft {
        let clock = busbar_contract::unit::Clock {
            unix_secs: now,
            monotonic_nanos: self.started.elapsed().as_nanos(),
        };
        let record = busbar_contract::wire::ArrivalRecord {
            source: arrival.fact("peer").unwrap_or_default().to_string(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: arrival.chain.to_vec(),
        };
        // WHAT THE REQUEST CARRIES ABOUT ITSELF, read off the arrival's own reserved fact rather
        // than off a header. A transport publishes the credential WHOLE — the scheme word travels
        // with it, because deciding what a scheme means is the chain's — and this plane's own
        // `authenticate` binding is what narrows within the declared set.
        let presented = arrival.fact(busbar_contract::transport::facts::CREDENTIAL);
        crate::root::plane_ctx::with_frames(arrival, clock, |ctx, frames| {
            let read = crate::root::units_mcp::read_ingress(&self.plane, frames, ctx);
            McpDraft::read(
                &self.plane,
                &read,
                arrival.body.len() as u64,
                &Arrived {
                    record: &record,
                    claim_transport: arrival.transport,
                },
                presented,
                // A CLAIM THAT DECLARES A SCHEME DEMANDS ONE, and the question is the PLANE'S —
                // asked of its own claim table by carrier AND address, never re-derived here. Two
                // of this plane's four claims are made over the same carrier and one of them
                // deliberately carries none: the discovery document is what a caller reads to find
                // out how to authenticate, so demanding a credential there would close the one
                // surface this protocol leaves open on purpose.
                claims::declares_scheme(
                    arrival.transport,
                    arrival
                        .fact(busbar_contract::transport::facts::PATH)
                        .unwrap_or_default(),
                ),
            )
        })
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE LEG ON THE LOOP
// ═════════════════════════════════════════════════════════════════════════════════════════════════

impl crate::root::transports::PlaneLeg for McpLeg {
    /// Assemble one unit FROM the arrival and walk it through the kernel's twelve steps.
    ///
    /// This is the method the blanket implementation could not provide and the reason `PlaneLeg`
    /// exists as a trait at all: the units this returns cannot be built before the arrival is,
    /// because the bindings they run over carry facts the arrival decided — what the plane made of
    /// the bytes, when they landed, and which card was live when they did.
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
        // leg walked without a mount behind it has no surface to reach — so the units run the twelve
        // steps and report zero bytes, which is exactly the posture this leg had before a mount
        // existed. The mount's own path is [`McpLeg::serve`], which supplies the seam and reads the
        // answer back out.
        self.serve(arrival, kernel, ctx, run, None).0
    }
}

impl McpLeg {
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
        dispatch: Option<&dyn crate::root::transports::PlaneDispatch>,
    ) -> (Ended, Option<crate::root::transports::PlaneAnswer>) {
        // THE TWO CLOCKS, PINNED ONCE, HERE. Two readings and not one number written twice: the wall
        // epoch dates the unit and the monotonic reading orders it. Read at the top of the walk so
        // every step of this unit is judged against the same moment — a check in one window and a
        // charge in another is exactly what a per-step clock read produces.
        let at = Clocks {
            wall: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            mono: u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        };

        let draft = self.decode(arrival, at.wall);

        // The per-request views, on this stack frame, borrowing the boot-resolved sets.
        let pools = self.pools();
        let (schema, op) = Self::record_leg_of(&draft);
        let kinds = self.kinds(schema, op);
        // THE CHAIN, resolved ONCE per unit rather than inside the admission step. Anonymous until
        // the authenticate step says otherwise, which is what the chain is keyed on: the door reads
        // the caller's own attribution bucket, and a caller bound to no group has one uncapped one.
        let chain = self.chain_for(&busbar_caps::PrincipalId::new(""), None);
        // AND THE CARD, pinned once for this unit's whole life — see [`McpLeg::money`].
        let (prices, pricer) = self.money();

        let units = McpUnits::new(
            McpBindings {
                plane: &self.plane,
                auth: &self.auth,
                auth_bindings: &self.auth_bindings,
                pools: &pools,
                kinds: &kinds,
                breaker: self.breaker.as_ref(),
                door: &self.door,
                chain: chain.as_ref(),
                pricer: &pricer,
                prices,
                records: &self.records,
                meter_policy: &self.meter_policy,
                scope_policy: &self.scope_policy,
                durability: &self.durability,
                pool: &self.pool,
                at,
                dispatch,
                origin: self.origin,
            },
            draft,
            // THE GRANTS ARE THE CALLER'S, and an arrival that presented nothing holds the anonymous
            // set. Read-only is what an unidentified caller holds; the approve step compares it
            // against the policy's own entry for the class and refuses what it does not cover.
            Grants::of(Scope::ReadOnly),
        );
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
    <McpPlane as busbar_contract::plane::PlaneMeta>::OP_CLASSES
}

/// The classes this plane says it ANSWERS through the loop, which is the mount's own shadow set.
#[must_use]
pub fn answered_classes() -> &'static [busbar_contract::ids::OpClassId] {
    busbar_plane_mcp::served::ANSWERED
}

#[cfg(test)]
#[path = "tests/units_mcp_leg.rs"]
mod tests;
