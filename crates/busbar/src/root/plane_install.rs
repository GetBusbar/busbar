// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION ROOT'S ONE WRITE INTO THE PLANE AXIS.
//!
//! MOVED VERBATIM from the legacy core's `plane/registry.rs`, beside its protocol twin
//! (`proto_install`): the composition root owns the boot installers, and this one had exactly one
//! caller, `register_planes` in this crate's `main.rs`. It could not move while the plane LIST lived
//! in core — core's readers of that list cannot name a root module — and it can now that the list is
//! contract data (`busbar_contract::plane::registry`): the root writes the contract slot, core reads
//! it, and neither names the other.
//!
//! One installer, two tables, because a declaration is two things: the FACTS a plane states (its key,
//! section and scope kinds — the contract list every layer folds) and the BEHAVIOUR a layer runs for
//! it (the fn-pointer row the substrate keeps, keyed by the same key). Both refusal sentences are the
//! ones this function has always raised, byte-identical.

use busbar_substrate::plane::registry::{install_plane_behaviours, PlaneDecl};

/// INSTALL PLANE DECLARATIONS — the composition root's one write into the plane axis, called from
/// `main` (`register_planes`) before any config load or validation touches a plane.
///
/// Also registers each plane's scope kinds with the neutral scope-kind wire registry, so a
/// `VirtualKey` grant of a plane's kind serializes to its `allowed_{kind}s` wire field. The fold used
/// to do this on first read; the contract cannot name that registry, so the install site does it —
/// idempotent, the same set, earlier.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
/// - if called after the plane list was first read: a declaration installed after another layer
///   resolved against the smaller set means two layers of one process disagree about which planes
///   exist.
pub fn install_planes(decls: &'static [&'static PlaneDecl]) {
    assert!(
        busbar_contract::plane::registry::install(decls.iter().map(|d| d.declaration()).collect()),
        "install_planes called twice: there is one composition root, and it registers once"
    );
    assert!(
        !busbar_contract::plane::registry::first_read(),
        "install_planes called after the plane list was first read; register in main before any \
         config load or validation touches a plane"
    );
    install_plane_behaviours(decls);
    for decl in decls {
        for kind in decl.scope_kinds {
            busbar_api::register_scope_kind(kind);
        }
    }
}

#[cfg(test)]
mod tests {
    /// INSTALL BEFORE FIRST READ, enforced. The only test in this binary that calls
    /// [`super::install_planes`], deliberately: it is a write to the process slot, and a second call
    /// anywhere else here would make this test's outcome depend on execution order. The read is
    /// forced first so the install has something to refuse to follow.
    #[test]
    #[should_panic(expected = "install_planes called after the plane list was first read")]
    fn install_planes_after_first_read_panics() {
        let _ = busbar_contract::plane::registry::plane_decls();
        super::install_planes(&[]);
    }
}
