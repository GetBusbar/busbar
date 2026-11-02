// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
        }
    }
}

impl std::error::Error for BootRefusal {}

pub struct BootRegistry {
    pub registry: Registry,

    pub claims: Vec<PlaneClaim>,

    pub precedence: Vec<usize>,

    pub resolved: Vec<ResolvedOverlap>,

    pub registered: Vec<Registered>,

    pub dropped: Vec<&'static str>,
}

impl BootRegistry {}

fn core_claims() -> impl Iterator<Item = PlaneClaim> {
    busbar_core_admin::admin_codec::claims::CLAIMS
        .iter()
        .map(|claim| PlaneClaim {
            plane: busbar_core_admin::admin_codec::KEY,
            claim: *claim,
        })
}

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

pub type Built = (Registered, Arc<HostWire>);

/// A transport DOOR dropped into `plugins.dir`: a memory-ABI entry admitted through the one
/// dispatcher's door validation and served over the host's sockets (`crate::root::doors`).
#[derive(Clone)]
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
#[derive(Clone)]
pub struct Dropped {
    /// A snapshot of the memory-ABI transport doors. An owned inventory may be replaced after
    /// Store recovery without invalidating a reader or permanently retaining obsolete doors.
    pub doors: std::borrow::Cow<'static, [DroppedDoor]>,
}

impl Dropped {
    pub const NONE: Self = Self {
        doors: std::borrow::Cow::Borrowed(&[]),
    };
}

/// One row of the transport axis, whichever door it came in by.
#[derive(Clone, Copy)]
enum Row<'r> {
    /// A wire this build links.
    Linked(&'r LinkedTransport),
    /// A transport door dropped into `plugins.dir`.
    Door(&'r DroppedDoor),
}

impl<'r> Row<'r> {
    fn key(self) -> &'static str {
        match self {
            Row::Linked(row) => (row.key)(),
            Row::Door(door) => door.key,
        }
    }

    fn composes_over(self) -> &'r [&'static str] {
        match self {
            Row::Linked(row) => (row.composes_over)(),
            Row::Door(door) => door.composes_over.as_slice(),
        }
    }
}

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
            composes_over: match row {
                Row::Linked(row) => std::borrow::Cow::Borrowed((row.composes_over)()),
                Row::Door(door) => std::borrow::Cow::Owned(door.composes_over.clone()),
            },
            composed_over: None,
        };

        let also: Vec<&'static str> = claims
            .into_iter()
            .filter(|c| *c != registered.key)
            .collect();
        built.push((registered, Arc::clone(&transport)));
        for key in also {
            let claimed = Registered {
                key,
                composes_over: std::borrow::Cow::Borrowed(&[]),
                composed_over: None,
            };
            built.push((claimed, Arc::clone(&transport)));
        }
    }
    Ok(built)
}

pub fn seal(
    linked: &Linked,
    dropped: Dropped,
    settings: TransportSettings,
) -> Result<BootRegistry, BootRefusal> {
    let registered: Vec<Registered> = compose(linked.transports, dropped.clone(), &settings)?
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

    Ok(BootRegistry {
        registry,
        claims,
        precedence: sealed.order,
        resolved: sealed.resolved,
        registered,
        dropped: dropped.doors.iter().map(|d| d.key).collect(),
    })
}

pub fn seal_or_exit(linked: &Linked, settings: TransportSettings) -> BootRegistry {
    let dropped = crate::root::boot::dropped_transports(&settings);
    seal(linked, dropped, settings).unwrap_or_else(|refusal| {
        eprintln!("busbar: the composition root did not seal: {refusal}");
        std::process::exit(2);
    })
}

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

fn register_all(
    registered: &[Registered],
    planes: &[LinkedClaims],
) -> Result<Registry, BootRefusal> {
    let mut registry = Registry::new();

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
