// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROTOCOL REGISTRY — a protocol is a DECLARATION, and core looks it up rather than matching
//! on its name.
//!
//! WHAT THIS REPLACED, and why the shape matters more than the saving. Until this module existed,
//! resolving a protocol was `match name { "anthropic" => …, "openai" => …, _ => None }` in
//! `proto/mod.rs`, with a second copy of the same match in `handlers::request_handler` and a third
//! in `ProtocolRegistry::with_builtins`. Every other axis in busbar is already a plugin — store,
//! auth, hooks, export — and the protocol axis was the last place where adding a capability meant
//! editing core. A `match` on a string literal is exactly that edit.
//!
//! **A REGISTRY WHOSE POPULATION IS A `match` IN CORE HAS NOT REMOVED THE MATCH, IT HAS MOVED IT.**
//! So [`builtin_decls`] is DATA — a slice of `&'static ProtocolDecl`, one entry per protocol, each
//! declared in the protocol's OWN module — and [`Registry::new`] takes an ITERATOR of declarations,
//! so a protocol that is not in that slice joins by being handed to the same constructor.
//!
//! THE REGISTRY RUNTIME RELOCATED DOWN to the neutral `busbar_substrate::proto` (the reverse-edge
//! rule): `Registry`, the process singleton, `decl_for`, the detection folds
//! and `known_protocols` now live on the substrate so an extracted protocol crate (`busbar-llm`)
//! resolves them through the neutral ABI rather than reaching BACK into `busbar-core`. This module
//! re-exports every one of them at its historical `busbar_core::proto::registry::…` path so every
//! in-core / plugin caller compiles unchanged and the values are byte-identical. What STAYS here is
//! the population glue core alone owns: the built-in table (empty in production; core's own test
//! set named in a `tests/` file the lint excludes and handed to the substrate through its
//! `set_test_builtins` hook), and [`install_protocols_with_path_ingress`], which names the core-only
//! `Arrival`.

// WHICH INBOUND AUTH SCHEME a protocol's clients present. DECLARED metadata, never a branch: the
// verification itself stays in the auth layer. Relocated to the neutral `busbar_substrate::proto`
// leaf (Batch A) so `busbar-mcp` names it without depending on `busbar-core`; re-exported here so
// `registry::IngressAuth`, the `ProtocolDecl` field, and every plugin caller are unchanged.
pub use busbar_substrate::proto::IngressAuth;

// `ProtocolDecl` and its `EgressAuthHeaders` builder type RELOCATED DOWN to the neutral
// `busbar_substrate::proto` leaf (Batch C-6) so an extracted protocol crate (`busbar-mcp`, the
// `busbar-llm` dialects) names the declaration WITHOUT reaching into `busbar-core`. Re-exported here
// at their historical `busbar_core::proto::registry::{ProtocolDecl, EgressAuthHeaders}` paths so the
// built-in table, and every core / plugin caller, are unchanged.
pub use busbar_substrate::proto::{EgressAuthHeaders, ProtocolDecl};
// The generic detection ABI relocated to `busbar_substrate::proto` alongside `ProtocolDecl`: the
// opaque claim strength and the two predicate types each dialect states on its own decl, so the
// router/residual detection is a fold over registered predicates and core names no dialect.
pub use busbar_substrate::proto::{
    ClaimStrength, ClaimsFn, ResidualClaimsFn, VendorResponseMetadataFn,
};

// THE REGISTRY RUNTIME — relocated to `busbar_substrate::proto`, re-exported here at its historical
// paths so `crate::proto::registry::{Registry, install_protocols, decl_for, …}` resolve unchanged.
// The detection/lookup accessors get a `cfg(test)` veneer below (they seed the substrate's core-test
// built-in hook); `Registry`, `install_protocols`, and the pure folds are direct re-exports.
pub use busbar_substrate::proto::{
    first_path_model_without_arrival, install_protocols, merged_boot_decls, Registry,
};

/// THE BUILT-INS — one line per protocol, and every line is DATA. Production carries NO built-in
/// protocol rows: every protocol is a plugin crate the composition root installs through
/// [`install_protocols`]. Naming a protocol crate's `&DECL` here would be a protocol-crate symbol
/// reference in neutral source — a side channel around the ABI — so this stays empty.
///
/// Core's OWN test binary still needs the shipped protocol set; the plugin crates are dev-dependencies
/// there. That list names `busbar_llm::DECLS` and `busbar_mcp::PROTO_DECL`, which belong OFF the
/// neutral source, so it is defined in the test module ([`test_builtins`], a `tests/` file the
/// neutral-purity lint excludes) and handed to the substrate registry through its
/// [`busbar_substrate::proto::set_test_builtins`] hook by the `cfg(test)` accessors below.
#[cfg(not(test))]
static BUILTIN_DECLS: &[&ProtocolDecl] = &[];

/// The built-in declarations. Empty in production and under `test-support`; under core's own
/// `#[cfg(test)]` binary it is the test-module list, so no protocol crate is named in neutral source.
#[cfg(not(test))]
pub fn builtin_decls() -> &'static [&'static ProtocolDecl] {
    BUILTIN_DECLS
}

/// The extracted-dialect built-in list for core's OWN test binary — `busbar_llm::DECLS` and
/// `busbar_mcp::PROTO_DECL`, named in a `tests/` file the neutral-purity lint excludes so the neutral
/// source spells no protocol crate.
#[cfg(test)]
#[path = "tests/registry_builtins.rs"]
mod test_builtins;

#[cfg(test)]
pub fn builtin_decls() -> &'static [&'static ProtocolDecl] {
    test_builtins::TEST_BUILTIN_DECLS
}

// ── THE REGISTRY SINGLETON RE-EXPORTS ─────────────────────────────────────────────────────────────
// Production/`test-support`: direct re-exports of the substrate runtime (no core-test built-ins to
// fold). Core's OWN `#[cfg(test)]` binary needs its shipped protocol set (named in `test_builtins`,
// off the neutral source) folded as the boot-fold TAIL, so its accessors first SEED the substrate's
// core-test built-in hook with [`builtin_decls`] — idempotent, allocation-free, and self-healing
// (seeding GROWS the memo's target size so a registry already folded without the tail re-folds WITH
// it on the next read regardless of call order). `known_protocols` MUST be a direct re-export in every
// build so `busbar_llm::PLANE_DECL.wire_format_names` and `busbar_core::proto::known_protocols` are the
// SAME fn pointer (the plane-decl identity pin); it seeds nothing and relies on the accessors below
// (read on essentially every request path) having seeded the hook first.
#[cfg(not(test))]
pub(crate) use busbar_substrate::proto::registry;
#[cfg(not(test))]
pub use busbar_substrate::proto::{
    declared_verbs, detect_protocol, residual_default_protocol, residual_protocol_for_path,
};

#[cfg(test)]
pub(crate) fn registry() -> &'static Registry {
    busbar_substrate::proto::set_test_builtins(builtin_decls);
    busbar_substrate::proto::registry()
}

/// RESOLVE A PROTOCOL BY NAME — THE ONE by-name protocol resolution in busbar (the `structure-lint`
/// census pins it), and the function the `match` at `proto/mod.rs` became. A thin wrapper over the
/// relocated [`Registry::decl`] on the substrate; stays in core so its `registry()` acquire seeds
/// core's own-test built-in tail. Allocates nothing: everything a caller reads off the declaration is
/// a `&'static` constant that was declared, not built.
pub fn decl_for(name: &str) -> Option<&'static ProtocolDecl> {
    registry().decl(name)
}

#[cfg(test)]
pub fn detect_protocol(path: &str, headers: &axum::http::HeaderMap) -> Option<&'static str> {
    busbar_substrate::proto::set_test_builtins(builtin_decls);
    busbar_substrate::proto::detect_protocol(path, headers)
}

#[cfg(test)]
pub fn residual_protocol_for_path(path: &str) -> Option<&'static str> {
    busbar_substrate::proto::set_test_builtins(builtin_decls);
    busbar_substrate::proto::residual_protocol_for_path(path)
}

#[cfg(test)]
pub fn residual_default_protocol() -> Option<&'static str> {
    busbar_substrate::proto::set_test_builtins(builtin_decls);
    busbar_substrate::proto::residual_default_protocol()
}

#[cfg(test)]
#[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
pub fn declared_verbs() -> &'static [crate::operation::Operation] {
    busbar_substrate::proto::set_test_builtins(builtin_decls);
    busbar_substrate::proto::declared_verbs()
}

/// THE COMPOSITION ROOT'S ONE WRITE INTO BOTH PROTOCOL SEAMS — the declarations AND their path-model
/// arrivals, registered together so the second seam [`install_protocols`] gained when `path_ingress`
/// split off `ProtocolDecl` (Batch C-6) cannot drift from the first. Folds the two installs into one
/// call and, before either lands, asserts the PARITY that keeps the split honest:
///
/// **Every declaration whose model is in the URL path (`has_model_in_url`) MUST register a
/// `path_ingress` arrival.** A path-model protocol installed WITHOUT its arrival would resolve no
/// arrival and SILENTLY fall through to the body-model branch — a wrong-behavior 404-shaped bug.
/// Asserting it here makes that drift a LOUD PANIC at boot. Stays in `busbar-core` because it names
/// the core-only `Arrival` (`crate::ingress::path_ingress`).
///
/// # Panics
/// - if a `has_model_in_url` decl has no registered arrival (the parity failure above).
/// - if either underlying install was already called (two composition roots).
#[allow(dead_code)] // pub-widened and called by the busbar binary's `register_protocols`
pub fn install_protocols_with_path_ingress(
    decls: Vec<&'static ProtocolDecl>,
    path_ingress: Vec<(&'static str, crate::ingress::path_ingress::PathIngress)>,
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
    crate::ingress::path_ingress::install_path_ingress(path_ingress);
}
