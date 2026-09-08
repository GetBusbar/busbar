// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROTOCOL REGISTRY, and the composition root's ONE write into both protocol seams.
//!
//! The registry itself — `Registry`, the process singleton, `decl_for`, the detection folds,
//! `known_protocols`, `ProtocolDecl` and the whole declaration vocabulary — lives on the pure value
//! leaf this module re-exports whole (the `proto` module of the values crate), so every historical
//! `busbar_substrate::proto::…` path resolves to the same item it always did.
//!
//! What this module ADDS is [`install_protocols_with_path_ingress`], the fold of the two seams a
//! path-model dialect registers through. It could not live on the value leaf, because the arrival
//! half ([`crate::ingress::arrival::install_path_ingress`]) is this crate's, not the leaf's; and it
//! no longer belongs in the retiring engine crate, because the type it was said to be held by — the
//! "engine-only `Arrival`" — relocated to [`crate::ingress::arrival::PathIngress`] and the engine's
//! spelling of it had become a `pub use` of this one. With both halves neutral the fold is neutral,
//! so it sits beside them and the composition root names no retiring crate to register a protocol.

pub use busbar_substrate_values::proto::*;

use crate::ingress::arrival::{install_path_ingress, PathIngress};

/// THE COMPOSITION ROOT'S ONE WRITE INTO BOTH PROTOCOL SEAMS — the declarations AND their path-model
/// arrivals, registered together so the second seam [`install_protocols`] gained when `path_ingress`
/// split off [`ProtocolDecl`] cannot drift from the first. Folds the two installs into one call and,
/// before either lands, asserts the PARITY that keeps the split honest:
///
/// **Every declaration whose model is in the URL path (`has_model_in_url`) MUST register a
/// `path_ingress` arrival.** A path-model protocol installed WITHOUT its arrival would resolve no
/// arrival and SILENTLY fall through to the body-model branch — a wrong-behavior 404-shaped bug.
/// Asserting it here makes that drift a LOUD PANIC at boot, and it is asserted BEFORE either install
/// so a refused boot leaves both seams unwritten rather than one of the two.
///
/// # Panics
/// - if a `has_model_in_url` decl has no registered arrival (the parity failure above).
/// - if either underlying install was already called (two composition roots).
pub fn install_protocols_with_path_ingress(
    decls: Vec<&'static ProtocolDecl>,
    path_ingress: Vec<(&'static str, PathIngress)>,
) {
    if let Some(name) = first_path_model_without_arrival(
        &decls,
        &path_ingress.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
    ) {
        panic!(
            "protocol '{name}' declares has_model_in_url == true but registered no path_ingress \
             arrival: a request naming its URL model would silently fall through to the body-model \
             branch. Register its arrival alongside its declaration."
        );
    }
    install_protocols(decls);
    install_path_ingress(path_ingress);
}

#[cfg(test)]
#[path = "tests/proto.rs"]
mod tests;
