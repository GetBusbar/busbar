// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE PLACE IN THE ROOT THAT NAMES A DIALECT CRATE.
//!
//! A dialect is registered by CLAIM, not by call: a dialect crate publishes one `const` — its
//! location row and its rungs of its plane's detection ladder — and a composition root seals that
//! constant into the plane it names. Nothing in `registry.rs` knows a dialect's name, its rungs, its
//! pointers or its type; it iterates the tables below and asks each entry what it declares. That is
//! what makes the next dialect a Cargo dependency and one row here, rather than an edit to the boot.
//!
//! ## Why the tables are here rather than in `registry.rs`
//!
//! So the claim "the root does not name a dialect" is CHECKABLE by reading one file. `registry.rs`
//! is the boot's logic and this file is the boot's data; a dialect crate that appeared in the logic
//! would be a special case for one vendor on the path every request takes, which is precisely the
//! shape the dialect kind exists to remove. The kind-isolation gate scores the manifest edge, and
//! this file is where the edge is spent.
//!
//! ## Why the entries are `const` and not built
//!
//! A plane holds a `&'static` registry with no interior mutability, sealed before the first request
//! (see `busbar_plane_llm::registry`). A table that were built at boot would need somewhere to live
//! and would be a thing that could be built twice; a `const` cannot be, so registration is
//! construction and the claims a boot proved disjoint are the claims that are in force.
//!
//! ## The order of a table
//!
//! Registration order breaks a tie between two dialects that declare the SAME rung, exactly as
//! declaration order breaks a tie between two planes. The plane's own remaining rungs are always
//! walked first; the entries below follow in the order they are written.

use busbar_plane_llm::registry::DialectEntry;

/// The dialects of the `llm` plane this build carries.
///
/// One row per dialect crate, and adding one is adding ONE LINE. `busbar-plane-llm-openai` was the
/// first of the six the plane's ladder was written for and `busbar-plane-llm-responses` is the
/// second; the remaining four are still the plane's own rows and move here, one row at a time, as
/// each is cut out.
///
/// The two rows here are one vendor's two request surfaces, and they are two rows for the same
/// reason they are two crates: the boot has no way to tell "a vendor" from "a wire vocabulary", and
/// it should not have one. What it seals is a row and a ladder, whoever wrote them.
///
/// ORDER IS REGISTRATION ORDER, and registration order breaks a tie between two dialects that
/// declare the same rung. These two declare 7, 14 and 10 and tie nowhere, so the order below is not
/// currently deciding anything — which is exactly why it is worth saying that it is the order the
/// boot uses, so the day two dialects do tie the answer is written down here rather than discovered.
pub const LLM: &[DialectEntry] = &[
    busbar_plane_llm_openai::dialect::ENTRY,
    busbar_plane_llm_responses::dialect::ENTRY,
];
