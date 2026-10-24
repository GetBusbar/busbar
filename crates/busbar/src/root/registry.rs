// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The boot seal: the linked transports, the linked planes' declared claims, and the checks that
//! answer before a listener is bound. It names no transport and no plane: both come from the linked
//! tables (`LINKED.transports`, `LINKED.claims`), which are the manifest's data.
//!
//! ## What the claim check reads, and what it does not
//!
//! Stated first, because the name "claim overlap check" promises more than this file can keep. The
//! claims compared here are each plane's DECLARED claims — `PlaneMeta::CLAIMS`, the pure plane
//! crate's own compile-time words. The paths a request is actually routed on are a different
//! object: each installed `busbar_kernel::plane::registry::PlaneDecl`'s `claims` hook, evaluated over
//! the plane's runtime object at app build, is what `build_dispatch` mounts, and nothing here reads
//! it. So a clean seal says the declarations do not tie; it does not say two planes' LIVE, configured
//! routes cannot collide. That second check belongs where the live claims are folded
//! (`build_dispatch`), which is not this file, and until it exists a live collision is resolved by
//! whatever that fold does with it rather than refused at boot.
//!
//! ## Why the claims travel separately
//!
//! A plane declares its claims as an associated constant, which is the right shape — the claims are
//! the plane's own words, fixed at compile time, and a selector derived from configuration would be
//! a plane deciding at boot what it is for. But an associated constant cannot be read through a
//! trait object, and the registry stores `Arc<dyn Plugin>`. So each linked plane's entry hands the
//! seal both — the pure plane (`PLANE`) and its claims (`CLAIMS`) — as one row of the linked claims
//! table, and the pairing is read from the plane that made the claims rather than typed here.
//!
//! ## The two checks, and what each catches
//!
//! `seal_claims` is the cross-plane overlap rule. Within one plane, claims are an ordered pattern
//! set with most-specific-wins precedence, so two of a plane's own claims may overlap and are not
//! compared here. Across planes, an overlap is a question the same order answers: where the two
//! claims sit at different precedence the more specific one takes the bytes, and the pair is
//! RESOLVED — recorded, with the winner named. Where the precedence ties there is no principled way
//! to decide which plane owns the bytes, and that is the REFUSAL, answered at boot with both claims
//! named rather than at the first request. Claims whose scheme sets are disjoint never overlap at
//! all: one request carries one credential.
//!
//! `check_composition` is the transport rule, in both directions: every layer a transport declares
//! it can be built over must be registered, and every layer the root actually built it over must be
//! one it declares. Neither half implies the other — a transport can declare a layer nobody
//! registered, and a root can compose a transport over a layer it never declared.
//!
//! ## The declared claim set seals, and this is where that is measured
//!
//! **164 of the cross-plane pairs overlap** — 100 across selector families and 64 within the path
//! family. Both numbers follow from the overlap rule as the design writes it, and neither is a
//! rounding of the other. (The decisions plane joining the seal, item 251, added eleven: its two
//! exact paths against every header claim, and its `/v1/models` against the model-serving plane's
//! `v1/models/<tail>` pattern — which the order settles in the exact path's favour.)
//!
//! The 90 are the conservative arm, and they are conservative because a request really does carry
//! both a path and a header: `HeaderPresent("x-api-key")` and `ExactPath("/tools")` can be true of one
//! arrival, so an overlap is the honest answer rather than a limitation. The 63 are what is left
//! inside the path family once the grammar reads a suffix and a substring as the segment
//! constraints they are: a suffix pins a pattern's last segments, a substring carrying slashes asks
//! for consecutive whole ones, and a pattern with a literal in the way cannot produce a path that
//! satisfies either. That reading is what took the path-family count from 119 to 65, and naming the
//! audio surface one path at a time rather than as a prefix — so that the two one-shot audio
//! operations belong to the plane the inventory gives them to, instead of being described by two
//! planes at once — took it from 65 to 63, and the decisions plane's `/v1/models` made it 64. Of the
//! 64, 24 involve a pattern ending in a tail (which
//! can supply whatever the fragment asks for), 24 are a fragment landing inside a pattern's
//! variable segment, and 16 are two fragment forms that can be satisfied at once by writing a path
//! with both. Every one of them is a real shape, not a gap in the reasoning.
//!
//! All 164 are settled by the sealed order, and none of them is a refusal. That is not the check
//! being softened: every one of the 164 is a pair whose two claims sit at different precedence, so
//! the order already says which plane takes bytes both describe, and the pair is recorded in
//! `resolved` with its winner named. The tests below pin the count at 164, the refusal count at
//! zero and the sealed order itself, so a declaration change that turns a resolved pair into a tie —
//! the shape nothing can decide — has to say so here. A root that skipped the check to get a node
//! running would be choosing which plane's DECLARATION owns a shape by accident of registration
//! order, which is the one thing the check exists to prevent — for the declarations. See the section
//! above for the live routes it does not reach.
//!
//! ## No transport is built over another
//!
//! A transport is linked or dropped in only as its memory-ABI door, and the host serves every door
//! over its own sockets: the carrier is the connector's choice from the target's scheme (ARCHITECT
//! Q128 U7). A door that names a transport it composes over is refused at its build
//! (`HostWire::new`), so every registered row records no layer, and `check_composition` holds each
//! declaration against that. There is no transport trait whose instance could answer otherwise
//! (step 36).
//!
//! ## The fold, bottom-up — both doors, one pass
//!
//! The rows are the linked wires (`LINKED.transports`, manifest order) followed by the wires
//! DROPPED INTO `plugins.dir` (scan order), each a memory-ABI transport door admitted through the
//! one dispatcher's door validation and served over the host's sockets by the connector
//! (`crate::root::doors`) — #2 rule (1): one contract, one loading path; #3: a transport is
//! swappable, compiled in OR dropped in. (The HOT-tier transport decl and its adapter are deleted,
//! row 84.) The fold does not ask which door a row came in by, except to build it.
//!
//! A wire is built once every layer it declares that this build carries is built, in row order
//! otherwise — so a layer always exists before anything that names it — and is handed no layer: a
//! linked or dropped-in door is served by the connector over the host's sockets. Its registered row
//! records no layer, and `check_composition` holds that against the declaration.
//!
//! A dropped-in wire claiming a key a linked wire already holds is refused by the registry exactly
//! as a second linked row with that key would be: two plugins of one kind declaring one key.

use std::sync::Arc;

use busbar_contract::transport::TransportSettings;
use busbar_contract::{check_composition, CompositionError, Plugin, Registered};
use busbar_core_connector::wire::HostWire;
use busbar_kernel::registry::{seal_claims, ClaimConflict, PlaneClaim, Registry, ResolvedOverlap};

use crate::root::linked::{Linked, LinkedClaims, LinkedTransport};

/// Why a node will not boot.
///
/// Every arm is a statement about the composition, not about a request: an operator sees it once,
/// at start-up, with both offending names in the message, and the process does not go on to serve.
#[derive(Debug)]
pub enum BootRefusal {
    /// Two planes claim bytes that could both match.
    ClaimOverlap(Box<ClaimConflict>),
    /// A transport declares a layer nobody registered, or was built over one it does not declare.
    Composition(CompositionError),
    /// Linked transports declare layers over each other, so none of them can be built first.
    Uncomposable {
        /// The first transport, in manifest order, that could not be placed.
        transport: &'static str,
    },
    /// A plane claims bytes on a transport no crate in the tree provides.
    ///
    /// The design lists thirteen transports and six wires exist. What the root owes is that a claim
    /// on one of the missing seven is a refusal an operator sees at boot, with the plane and the
    /// transport named — never a silent 404 at the first request that would have matched it.
    UnregisteredClaimTransport {
        /// The plane that made the claim.
        plane: &'static str,
        /// The transport it claimed on.
        transport: &'static str,
    },
    /// The registry itself refused an entry.
    Registry(busbar_kernel::registry::RegistryError),
    /// The breaker and egress units' hand-kept metric label banks disagree on a label both carry,
    /// so one breaker disposition would reach the scrape under two label values.
    LabelDrift(crate::root::adapters::LabelDrift),
}

impl std::fmt::Display for BootRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClaimOverlap(conflict) => write!(f, "{conflict}"),
            Self::Composition(err) => write!(f, "{err}"),
            Self::Uncomposable { transport } => write!(
                f,
                "transport `{transport}` composes over layers that compose over it, so no order \
                 builds it"
            ),
            Self::UnregisteredClaimTransport { plane, transport } => write!(
                f,
                "plane `{plane}` claims on transport `{transport}`, which no crate provides"
            ),
            Self::Registry(err) => write!(f, "{err:?}"),
            Self::LabelDrift(drift) => write!(f, "{drift}"),
        }
    }
}

impl std::error::Error for BootRefusal {}

/// What the boot seal produced: a registry nothing may add to after it, and the claim order every
/// arriving connection is matched against.
pub struct BootRegistry {
    /// The registry, at the generation the checks were answered against.
    pub registry: Registry,
    /// Every plane's claims, paired with the plane that made them.
    pub claims: Vec<PlaneClaim>,
    /// Indices into `claims`, most specific first, ties broken by declaration order so the walk is
    /// stable across boots.
    pub precedence: Vec<usize>,
    /// Every cross-plane pair that could both match and was settled by that order, with the winning
    /// claim named. Not a warning list: it is the record of which plane owns a shape two planes both
    /// describe, answered once at boot rather than per request.
    pub resolved: Vec<ResolvedOverlap>,
    /// Every transport as the composition check read it, in the order the fold built them.
    pub registered: Vec<Registered>,
    /// The keys of the rows that came in DROPPED IN rather than linked.
    pub dropped: Vec<&'static str>,
}

impl BootRegistry {}

/// The cleanliness crate's route every build carries: the admin surface's one claim, sealed after
/// the linked planes' under the surface's own key. A claimant, never a plugin (THE DESIGN §6 step
/// 3: "a plane, a plugin's inbound need, or a cleanliness crate's route (admin, oauth2)"; §8: the
/// cleanliness crates "are never plugins"), so the plugin registry holds nothing for it.
fn core_claims() -> impl Iterator<Item = PlaneClaim> {
    busbar_core_admin::admin_codec::claims::CLAIMS
        .iter()
        .map(|claim| PlaneClaim {
            plane: busbar_core_admin::admin_codec::KEY,
            claim: *claim,
        })
}

/// Every claimant's claims, paired with the key that names it: the linked planes in manifest
/// order, then the admin surface's route. Declaration order is what breaks precedence ties.
#[must_use]
pub fn plane_claims(planes: &[LinkedClaims]) -> Vec<PlaneClaim> {
    planes
        .iter()
        .flat_map(|row| {
            let plane = (row.plane)().key();
            row.claims.iter().map(move |claim| PlaneClaim {
                plane,
                claim: *claim,
            })
        })
        .chain(core_claims())
        .collect()
}

/// A transport entry in the registry, under one of the schemes it claims: its own, and each one past
/// it under its own key (the entry's wire serves them all; ONE ENTRY PER PLUGIN, the schemes are its
/// claims). A transport is a door the connector serves, not a trait object the registry holds
/// (step 36), so the registry holds its key.
struct Claimed(&'static str);

impl Plugin for Claimed {
    fn key(&self) -> &'static str {
        self.0
    }
    fn kind(&self) -> busbar_contract::Kind {
        busbar_contract::Kind::Transport
    }
    fn abi(&self) -> busbar_contract::transport::AbiVersion {
        busbar_contract::transport::TRANSPORT_ABI
    }
}

/// One folded wire: its row as the composition check reads it, and the boot's admission of its entry
/// (`HostWire::new`: a claim, no layer).
pub type Built = (Registered, Arc<HostWire>);

/// A transport DOOR dropped into `plugins.dir`: a memory-ABI entry admitted through the one
/// dispatcher's door validation and served over the host's sockets (`crate::root::doors`).
pub struct DroppedDoor {
    /// Its registry key: its own claim.
    pub key: &'static str,
    /// Every scheme it claims, its own first (each is registered under its own key).
    pub claims: Vec<&'static str>,
    /// The layers it declares.
    pub composes_over: Vec<&'static str>,
    /// The auth points it offers, read off its Statement's `extensions` at load by the same reader
    /// a linked door's are (`abi::transport::EXT_OFFERED_POINTS`; compiled-in = dropped-in).
    pub offered: busbar_contract::abi::auth::AuthPoints,
    /// The claims it opens at an UPGRADE (their row's `unit0_trigger`), read off its Statement at
    /// load by the same reader a linked door's are: its upgrade lines, beside the linked rows'
    /// (`crate::root::serve::upgrade_carriers`; compiled-in = dropped-in).
    pub upgrades: Vec<&'static str>,
    /// The boot's admission of the entry (`HostWire::new`: a claim, no layer).
    pub wire: Arc<HostWire>,
    /// The opened door the wire serves: the entry the connector serves for it, after the linked
    /// rows (`crate::root::connector::boot`).
    pub door: Arc<dyn busbar_core_connector::framer::FramerDoor>,
}

/// The transports a plugins directory contributes.
#[derive(Clone, Copy)]
pub struct Dropped {
    /// Memory-ABI transport doors.
    pub doors: &'static [DroppedDoor],
}

impl Dropped {
    /// Nothing dropped in.
    pub const NONE: Self = Self { doors: &[] };
}

/// One row of the transport axis, whichever door it came in by.
#[derive(Clone, Copy)]
enum Row<'r> {
    /// A wire this build links.
    Linked(&'r LinkedTransport),
    /// A transport door dropped into `plugins.dir`.
    Door(&'static DroppedDoor),
}

impl Row<'_> {
    fn key(self) -> &'static str {
        match self {
            Row::Linked(row) => (row.key)(),
            Row::Door(door) => door.key,
        }
    }

    fn composes_over(self) -> &'static [&'static str] {
        match self {
            Row::Linked(row) => (row.composes_over)(),
            Row::Door(door) => door.composes_over.as_slice(),
        }
    }
}

/// FOLD THE TRANSPORTS, BOTTOM-UP, BOTH DOORS IN ONE PASS.
///
/// The rows are `linked` then `dropped` (module docs). Each round builds the first row whose every
/// declared layer this composition carries is already built — so a layer always exists before
/// anything that names it. Every row is a door the host serves over its own sockets and is built
/// over nothing (no transport names another, ARCHITECT Q128 U7; a door that names a layer is refused
/// at its build), so its registered row records no layer, which `check_composition` holds against
/// its declaration.
///
/// # Errors
///
/// Rows declare layers over each other and none can be built first.
pub fn compose(
    linked: &[LinkedTransport],
    dropped: Dropped,
    settings: &TransportSettings,
) -> Result<Vec<Built>, BootRefusal> {
    let rows: Vec<Row<'_>> = linked
        .iter()
        .map(Row::Linked)
        .chain(dropped.doors.iter().map(Row::Door))
        .collect();
    let mut built: Vec<Built> = Vec::with_capacity(rows.len());
    let mut pending: Vec<Row<'_>> = rows.clone();
    let at = |built: &[Built], key: &str| built.iter().position(|(r, _)| r.key == key);
    while !pending.is_empty() {
        let ready = pending.iter().position(|row| {
            row.composes_over()
                .iter()
                .all(|layer| at(&built, layer).is_some() || !rows.iter().any(|r| r.key() == *layer))
        });
        let Some(ready) = ready else {
            return Err(BootRefusal::Uncomposable {
                transport: pending[0].key(),
            });
        };
        let row = pending.remove(ready);
        let (transport, claims): (Arc<HostWire>, Vec<&'static str>) = match row {
            Row::Linked(row) => ((row.build)(settings), (row.claims)()),
            Row::Door(door) => (Arc::clone(&door.wire), door.claims.clone()),
        };
        let registered = Registered {
            key: row.key(),
            composes_over: row.composes_over(),
            composed_over: None,
        };
        // ONE ENTRY, ITS SCHEMES ITS CLAIMS (TRANSPORT-STACK, ONE ENTRY PER PLUGIN): every scheme
        // the entry claims past its own is registered under its own key, served by the same wire,
        // composed over nothing (no transport names another).
        let also: Vec<&'static str> = claims
            .into_iter()
            .filter(|c| *c != registered.key)
            .collect();
        built.push((registered, Arc::clone(&transport)));
        for key in also {
            let claimed = Registered {
                key,
                composes_over: &[],
                composed_over: None,
            };
            built.push((claimed, Arc::clone(&transport)));
        }
    }
    Ok(built)
}

/// Register every axis and answer both boot checks.
///
/// Transports go in bottom-up and planes over them, then the claims are checked across planes and
/// ordered within them, then the composition is checked in both directions. Nothing binds a
/// listener until all of it has answered.
///
/// # Errors
///
/// Two planes claim bytes that could both match; a transport declares a layer nobody registered or
/// was built over one it does not declare; or the registry refused an entry.
pub fn seal(
    linked: &Linked,
    dropped: Dropped,
    settings: TransportSettings,
) -> Result<BootRegistry, BootRefusal> {
    let registered: Vec<Registered> = compose(linked.transports, dropped, &settings)?
        .into_iter()
        .map(|(row, _)| row)
        .collect();
    let registry = register_all(&registered, linked.claims)?;

    let claims = plane_claims(linked.claims);
    let sealed = seal_claims(&claims);
    if let Some(refused) = sealed.refused.first() {
        return Err(BootRefusal::ClaimOverlap(Box::new(ClaimConflict {
            left: claims[refused.left].clone(),
            right: claims[refused.right].clone(),
            reason: refused.reason,
        })));
    }

    check_composition(&registered).map_err(BootRefusal::Composition)?;
    check_claim_transports(&claims, &registered)?;
    // The two units' metric label banks are duplicate literals kept in step by hand; this is the
    // one boot check that compares them, and it runs here because this is the check every boot
    // passes through. A drift refuses the boot naming both spellings, rather than splitting one
    // breaker disposition into two label values on the scrape.
    crate::root::adapters::check_label_banks().map_err(BootRefusal::LabelDrift)?;

    Ok(BootRegistry {
        registry,
        claims,
        precedence: sealed.order,
        resolved: sealed.resolved,
        registered,
        dropped: dropped.doors.iter().map(|d| d.key).collect(),
    })
}

/// SEAL THE COMPOSITION ON THE BOOT PATH, or refuse the boot.
///
/// Run from `run()` once the deployment's limits are resolved and before any listener binds, in
/// every build: the transports it composes carry the operator's `limits.request_body_max_bytes`,
/// so it reads the configuration the served door reads. The rows are the linked wires and the ones
/// dropped into the configured `plugins.dir` (`crate::root::boot::dropped_transports`). A
/// composition that does not seal is a node that must not bind a listener, so the refusal goes to
/// standard error and the process exits 2 — not a warning and not a log line, because a node that
/// refused to boot has no boot to log. Nothing is written on the success path; the sealed registry
/// is handed back for the listeners to serve from.
pub fn seal_or_exit(linked: &Linked, settings: TransportSettings) -> BootRegistry {
    let dropped = crate::root::boot::dropped_transports(&settings);
    seal(linked, dropped, settings).unwrap_or_else(|refusal| {
        eprintln!("busbar: the composition root did not seal: {refusal}");
        std::process::exit(2);
    })
}

/// Every claim names a transport the root actually registered.
///
/// Neither of the two checks the kernel and the contract own covers this. `check_claims` compares
/// claims to each other and never looks at what is registered; `check_composition` reads the
/// transports and never looks at the claims. The gap between them is a plane claiming bytes on a
/// transport that does not exist, which would otherwise be discovered as a request that matched
/// nothing — so the root closes it, at boot, naming both sides.
///
/// # Errors
///
/// A claim names a transport no registered row provides.
fn check_claim_transports(
    claims: &[PlaneClaim],
    registered: &[Registered],
) -> Result<(), BootRefusal> {
    for claim in claims {
        if !registered.iter().any(|r| r.key == claim.claim.transport) {
            return Err(BootRefusal::UnregisteredClaimTransport {
                plane: claim.plane,
                transport: claim.claim.transport,
            });
        }
    }
    Ok(())
}

/// Put every transport and every linked plane into one registry, transports first, in the order
/// they were built and linked. The admin surface is no plugin and registers nothing here.
///
/// # Errors
///
/// The registry refused an entry — a duplicate key, or a kind it does not take.
fn register_all(
    registered: &[Registered],
    planes: &[LinkedClaims],
) -> Result<Registry, BootRefusal> {
    let mut registry = Registry::new();
    // Every row is registered under its own key: an entry's own scheme and each scheme it claims
    // past it, so the registry's key is the scheme.
    let transports = registered
        .iter()
        .map(|row| Arc::new(Claimed(row.key)) as Arc<dyn Plugin>);
    let planes = planes.iter().map(|row| (row.plane)());
    for plugin in transports.chain(planes).collect::<Vec<_>>() {
        registry.register(plugin).map_err(BootRefusal::Registry)?;
    }
    Ok(registry)
}

#[cfg(test)]
#[path = "tests/registry.rs"]
mod tests;
