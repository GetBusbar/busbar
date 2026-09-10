// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel-owned literals of the node's own surface.
//!
//! Closed structure, not open vocabulary. The lean-core rule forbids the kernel comparing against a
//! key a plugin varies; these are not that. They are the shape of the node's own surface, fixed by
//! the design and pinned byte for byte by the parity battery, and a plane that has to claim one has
//! no way to name it otherwise: a plugin's manifest may name this crate and nothing else in the
//! workspace, so a literal shared between a kernel-side crate and a plugin crate has to live here
//! or be transcribed by hand in both. It was transcribed by hand, with a hand-written assertion
//! guarding the copy that could not check the original.

/// The one prefix every kernel admin verb is mounted under.
pub const ADMIN_PREFIX: &str = "/api/v1/admin";

/// A PLANE'S SERVED SURFACE AS DATA, reachable at this crate's own `surface` module.
///
/// The vocabulary itself is not new — it is the same declaration a mount already reads. What is
/// new is WHERE A PLANE AUTHOR SPELLS IT. Until this face the only path to it went through the
/// module named for the wire kind, and a plane that declares its own served surface was made to
/// write that kind's name to reach a type that is about the plane and not about the wire: a plane
/// declares WHICH OPERATIONS IT ANSWERS AND HOW EACH IS ADDRESSED, and how the bytes get there is
/// the other side of the seam. The spelling made the blindness rule false in the one direction it
/// is most load-bearing, and the isolation matrix counted it — correctly — as the plane naming a
/// crate its manifest may not name.
///
/// So the names are offered here, beside the node's own literals, in a module whose name is the
/// thing being declared. The types are the same types; a plane written against either path links
/// the same code. What changes is that `busbar-contract` is once again the whole of what a plugin
/// author reads.
pub use crate::transport::surface::{
    binding_at, check_surface, match_target, resolve_document, resolve_service, resolve_target,
    Answering, Bar, BindingDecl, Capture, Dispatch, Operation, SurfaceError, WireSurface,
};
