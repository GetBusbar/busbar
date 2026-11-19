// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;

use busbar_kernel::registry::{seal_claims, ClaimConflict, PlaneClaim};

use crate::root::linked::LinkedClaims;

/// Why a node will not boot.
///
/// Every arm is a statement about the composition, not about a request: an operator sees it once,
/// at start-up, with both offending names in the message, and the process does not go on to serve.
#[derive(Debug)]
pub(crate) enum BootRefusal {
    /// Two planes claim bytes that could both match.
    ClaimOverlap(Box<ClaimConflict>),
    /// A plane claims bytes on a transport protocol no installed or admitted transport provides.
    ///
    /// Core provides no transport of its own: every protocol comes from a `kind: transport` plugin,
    /// linked or dropped in and admitted. What the root owes is that a claim on a protocol none of
    /// them provides is a coded refusal an operator sees at boot (BUSBAR-9201), with the plane and
    /// the protocol named and the kind of plugin to install, never a silent 404 at the first
    /// request that would have matched it. It names no plugin: which one provides the protocol is
    /// the deployment's choice.
    UnregisteredClaimTransport {
        /// The plane that made the claim.
        plane: &'static str,
        /// The transport protocol it claimed on.
        transport: &'static str,
    },
    /// Two planes of one kind declare one key.
    DuplicateKey {
        /// The kind they both are.
        kind: busbar_contract::Kind,
        /// The key they both declare.
        key: &'static str,
    },
}

impl std::fmt::Display for BootRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClaimOverlap(conflict) => write!(f, "{conflict}"),
            Self::UnregisteredClaimTransport { plane, transport } => write!(
                f,
                "{}",
                busbar_kernel::diagnostics::coded::composition_transport_unprovided(
                    plane, transport
                )
            ),
            Self::DuplicateKey { kind, key } => {
                write!(f, "two {kind:?} plugins both declare the key {key:?}")
            }
        }
    }
}

impl std::error::Error for BootRefusal {}

fn core_claims() -> impl Iterator<Item = PlaneClaim> {
    busbar_core_admin::admin_codec::claims::CLAIMS
        .iter()
        .map(|claim| PlaneClaim {
            plane: busbar_core_admin::admin_codec::KEY,
            claim: *claim,
        })
}

#[must_use]
pub(crate) fn plane_claims(planes: &[LinkedClaims]) -> Vec<PlaneClaim> {
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

/// A transport DOOR dropped into `plugins.dir`: a memory-ABI entry admitted through the one
/// dispatcher's door validation and served over the host's sockets (`crate::root::doors`).
#[derive(Clone)]
pub(crate) struct DroppedDoor {
    /// Its registry key: its own claim.
    #[cfg(test)]
    pub key: &'static str,
    /// The claims it opens at an UPGRADE (their row's `unit0_trigger`), read off its Statement at
    /// load by the same reader a linked door's are: its upgrade lines, beside the linked rows'
    /// (`crate::root::serve::upgrade_carriers`; compiled-in = dropped-in).
    pub upgrades: Vec<&'static str>,
    /// The opened door the wire serves: the entry the connector serves for it, after the linked
    /// rows (`crate::root::connector::boot`).
    pub door: Arc<dyn busbar_core_connector::framer::FramerDoor>,
}

/// The transports a plugins directory contributes.
#[derive(Clone)]
pub(crate) struct Dropped {
    /// A snapshot of the memory-ABI transport doors. An owned inventory may be replaced after
    /// Store recovery without invalidating a reader or permanently retaining obsolete doors.
    pub doors: std::borrow::Cow<'static, [DroppedDoor]>,
}

impl Dropped {
    #[cfg(test)]
    pub(crate) const NONE: Self = Self {
        doors: std::borrow::Cow::Borrowed(&[]),
    };
}

/// The composition facts the connector's boot does not already refuse: planes declaring one key
/// twice within their kind, plane claims that overlap, and claims on a transport `served` does not
/// answer. Transport keys and claims are refused at the connector's boot (`Transports::new`), and a
/// transport naming a layer where its door opens (`wire::unlayered`).
pub(crate) fn check(
    planes: &[LinkedClaims],
    served: &dyn Fn(&str) -> bool,
) -> Result<(), BootRefusal> {
    let mut keys = HashSet::new();
    for row in planes {
        let plane = (row.plane)();
        let (kind, key) = (plane.kind(), plane.key());
        if !keys.insert((kind, key)) {
            return Err(BootRefusal::DuplicateKey { kind, key });
        }
    }
    let claims = plane_claims(planes);
    if let Some(refused) = seal_claims(&claims).refused.first() {
        return Err(BootRefusal::ClaimOverlap(Box::new(ClaimConflict {
            left: claims[refused.left].clone(),
            right: claims[refused.right].clone(),
            reason: refused.reason,
        })));
    }
    check_claim_transports(&claims, served)
}

/// [`check`] against the build's carrier table (deletion plan E4): a claim's transport is served when the build
/// assigns a MIN-3 transport image the carrier its word means. An installed old-interface door still serves the
/// words it claims until the old interface is cut. A carrier table the build cannot read is an explained exit 2.
pub(crate) fn check_or_exit(planes: &[LinkedClaims]) {
    let carriers = crate::root::min3_framers::assigned(crate::LINKED_CARRIERS).unwrap_or_else(|why| {
        eprintln!("busbar: the composition root did not seal: {why}");
        crate::root::exit::exit(2);
    });
    let connector = crate::root::connector::the();
    let served =
        |word: &str| carriers.serves_claim(word) || connector.framer_for(word).is_some();
    check(planes, &served).unwrap_or_else(|refusal| {
        match refusal {
            // The deployment's installed plugins, not the build: the coded line says what to install.
            BootRefusal::UnregisteredClaimTransport { .. } => eprintln!("[error] {refusal}"),
            _ => eprintln!("busbar: the composition root did not seal: {refusal}"),
        }
        crate::root::exit::exit(2);
    });
}

fn check_claim_transports(
    claims: &[PlaneClaim],
    served: &dyn Fn(&str) -> bool,
) -> Result<(), BootRefusal> {
    match claims.iter().find(|claim| !served(claim.claim.transport)) {
        Some(claim) => Err(BootRefusal::UnregisteredClaimTransport {
            plane: claim.plane,
            transport: claim.claim.transport,
        }),
        None => Ok(()),
    }
}

#[cfg(test)]
#[path = "tests/registry.rs"]
mod tests;
