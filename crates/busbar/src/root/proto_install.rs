// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION ROOT'S ONE WRITE INTO BOTH PROTOCOL SEAMS.
//!
//! MOVED VERBATIM from the legacy core's `proto/registry.rs` — the composition root owns the boot
//! installers, and this one had exactly one caller: `register_protocols` in this crate's `main.rs`.
//! Its old home carried a doc line claiming it had to stay there because it named a core-only
//! `Arrival`. That was stale by the time it was read: core's `ingress::path_ingress` is itself a
//! re-export of `busbar_substrate::ingress::arrival::{install_path_ingress, PathIngress}`, and the
//! parity guard `first_path_model_without_arrival` lives in the neutral values leaf. Every name
//! below is neutral, so nothing core-only travelled with the move and no re-export back into the
//! legacy crate is needed: the one reader is the composition root itself.
//!
//! The behaviour, the fold order and the refusal text are byte-identical to the function this
//! replaced. Nothing new is asserted, nothing new is logged.

use busbar_substrate::ingress::arrival::{install_path_ingress, PathIngress};
use busbar_substrate::proto::{first_path_model_without_arrival, install_protocols, ProtocolDecl};

/// THE COMPOSITION ROOT'S ONE WRITE INTO BOTH PROTOCOL SEAMS — the declarations AND their path-model
/// arrivals, registered together so the second seam [`install_protocols`] gained when `path_ingress`
/// split off `ProtocolDecl` cannot drift from the first. Folds the two installs into one
/// call and, before either lands, asserts the PARITY that keeps the split honest:
///
/// **Every declaration whose model is in the URL path (`has_model_in_url`) MUST register a
/// `path_ingress` arrival.** A path-model protocol installed WITHOUT its arrival would resolve no
/// arrival and SILENTLY fall through to the body-model branch — a wrong-behavior 404-shaped bug.
/// Asserting it here makes that drift a LOUD PANIC at boot.
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
