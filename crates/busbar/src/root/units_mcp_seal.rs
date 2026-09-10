// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PLANE'S BOOT SEAL: everything about this plane that would otherwise be discovered as
//! a refused request, asked once, before any listener is bound.
//!
//! ## Why this is its own file
//!
//! [`crate::root::units_mcp`] is the twelve steps and the unit assembled over them — the REQUEST
//! path, every line of it reached per arrival. Nothing here is: `seal` runs once at boot and `mount`
//! runs once after the store is open. Two lifetimes in one file is how a reader ends up looking for
//! a per-request cost in a function that runs before the first connection, and it is why the
//! structural cap that forced this split is a cap worth having.
//!
//! Re-exported from `units_mcp`, so every caller and every cell reads the same names it always did.
//!
//! **The cells did not move with it, and that is deliberate.** Every one of them —
//! `a_well_formed_node_seals`, the three registration refusals, `the_seal_reads_the_node…`,
//! `the_plane_mounts`, `every_planned_leg_is_declared` — sits in `tests/units_mcp.rs` beside the
//! fixtures it shares with the step cells: one store double, one registration set, one plane. A
//! second copy of those fixtures next to a second test file is two chances for a cell about the
//! seal and a cell about a step to be judging different deployments, which is the thing the shared
//! fixture exists to prevent. They reach these names through the re-export, unchanged.

use busbar_contract::{
    ids::{OpClassId, RecordSchemaId},
    plane::PlaneMeta,
    transport::check_surface,
    transport::SurfaceError,
};
use busbar_plugin_loader::store_adapter::StoreAdapter;
use busbar_unit_scope::Scope;
use std::collections::BTreeMap;

use crate::root::units_mcp::{required_scopes, ClassPrices, Records};
use busbar_plane_mcp::{
    claims, meta::CLASS_BYTES, meta::CLASS_TOOL_CALLS, records, served::ANSWERED, surface::SURFACE,
    McpPlane,
};

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
    /// Two registrations carry the same name.
    ///
    /// The name is the pool key, the breaker key and the resource the scope unit judges, all three.
    /// Two rows under one name is a deployment where the breaker one of them opened is the breaker
    /// the other is refused by, and where a grant written for one authorizes the other.
    DuplicateRegistration(&'static str),
    /// A registration names a transport no claim of this plane declares.
    ///
    /// The arrival step refuses a unit on an undeclared transport, so a registration reached over
    /// one is a server nothing could ever answer from. Refusing at boot is the same answer, sooner.
    UnclaimedTransport {
        /// The registration.
        server: &'static str,
        /// The transport it named.
        transport: &'static str,
    },
    /// A registration names no priced lane.
    ///
    /// The lane is what the rate card hangs a price on and what the breaker keys its cells by. A
    /// registration with none is one every dialled unit is refused at as unpriced — which is the
    /// right refusal and the wrong place for it, because nothing about the request caused it.
    UnpricedRegistration(&'static str),
    /// An operation the plane says it answers is not one the plane declares.
    UnansweredClass(&'static str),
    /// The plane's served surface is not one a mount will boot on.
    ///
    /// The vocabulary's own check, asked here: an operation nothing can address, two rows at one
    /// address, a malformed mount, or a dispatch naming a binding the surface does not declare.
    SurfaceRefused(SurfaceError),
}

/// The plane's own registry key, read rather than transcribed.
///
/// Every refusal below is about ONE plane and says so; the word it says is the one the plane
/// registers under, so a plane renamed at its own declaration renames itself in the boot refusals
/// too, and this file does not carry a second spelling that could disagree with the first.
const PLANE: &str = <McpPlane as PlaneMeta>::KEY;

impl std::fmt::Display for MountRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MountRefusal::SchemaWithoutOperations(schema) => {
                write!(
                    f,
                    "the {PLANE} plane declares the unreachable schema {schema}"
                )
            }
            MountRefusal::UndeclaredLeg { schema, op } => {
                write!(
                    f,
                    "an {PLANE} route leg names an undeclared {op} on {schema}"
                )
            }
            MountRefusal::MissingMeterClass(class) => {
                write!(f, "the {PLANE} plane does not declare the class {class}")
            }
            MountRefusal::InconsistentSchemes => {
                write!(
                    f,
                    "the {PLANE} plane's claims declare different scheme alternatives"
                )
            }
            MountRefusal::DuplicateRegistration(server) => {
                write!(f, "two {PLANE} registrations are both named {server}")
            }
            MountRefusal::UnclaimedTransport { server, transport } => {
                write!(
                    f,
                    "the {PLANE} registration {server} is reached over {transport}, which no claim \
                     of this plane declares"
                )
            }
            MountRefusal::UnpricedRegistration(server) => {
                write!(f, "the {PLANE} registration {server} names no priced lane")
            }
            MountRefusal::UnansweredClass(op) => {
                write!(f, "the {PLANE} plane answers {op} and does not declare it")
            }
            MountRefusal::SurfaceRefused(error) => {
                write!(
                    f,
                    "the {PLANE} plane's served surface will not mount: {error}"
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
/// Each check is a thing the tree cannot state any other way: a schema nothing can reach, a leg
/// naming an operation its schema never declared, a metering binding posting under a class the plane
/// does not have, a claim set whose alternatives disagree, a served surface no mount will boot on,
/// an operation the plane says it answers and does not declare — and, over the argument, the four
/// things a REGISTRATION can be wrong about. All of them are cheap, all of them are answered once,
/// and none of them can be answered by the plane alone: the plane declares, and the root is what
/// compares one declaration against another.
///
/// ## The argument is read, and that is the substance of this function rather than a detail
///
/// It used to open with `let _ = plane;`. Every check below the discard was over the plane's
/// associated CONSTANTS, which are the same on every deployment — so the function was a boot check
/// of the build and never of the node, and the whole class of thing an operator can get wrong went
/// unasked. A registration named twice, reached over a transport no claim declares, or priced on no
/// lane was discovered as a refused request in production, one request at a time, by whoever hit it.
///
/// This half takes no store, because none of these questions is about one. That is what lets the
/// boot sequence ask them where every other declaration is checked — before the configuration has
/// resolved and long before any listener is bound.
///
/// # Errors
///
/// Any of the checks failed.
pub fn seal(plane: &McpPlane) -> Result<Vec<(OpClassId, Scope)>, MountRefusal> {
    // ── THE REGISTRATIONS, which are this node's and not this build's ────────────────────────────
    for (index, server) in plane.servers().iter().enumerate() {
        if plane.servers()[..index].iter().any(|s| s.id == server.id) {
            return Err(MountRefusal::DuplicateRegistration(server.id));
        }
        if !claims::declares(server.transport) {
            return Err(MountRefusal::UnclaimedTransport {
                server: server.id,
                transport: server.transport,
            });
        }
        if server.lane.as_str().is_empty() {
            return Err(MountRefusal::UnpricedRegistration(server.id));
        }
    }

    // ── THE SERVED SURFACE, asked of the vocabulary that will mount it ───────────────────────────
    check_surface(&SURFACE).map_err(MountRefusal::SurfaceRefused)?;

    // ── WHAT THE PLANE SAYS IT ANSWERS, against what it declares ─────────────────────────────────
    for op in ANSWERED {
        if !<McpPlane as PlaneMeta>::OP_CLASSES.contains(op) {
            return Err(MountRefusal::UnansweredClass(op.as_str()));
        }
    }

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
