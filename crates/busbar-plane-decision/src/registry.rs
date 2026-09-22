//! THE DECISION PLANE'S VOCABULARY DECLARATION — crate-local, and NOT reached from anywhere else in
//! this workspace yet.
//!
//! ## What this is, and what it deliberately is not yet
//!
//! [`busbar_substrate::plane::registry::PlaneDecl`] is the neutral seam an extracted plane hands the
//! composition root so it joins the running node without core naming it (see that type's own module
//! docs: "an EXTRACTED plane crate constructs its own `PlaneDecl` ... without a path back to core").
//! Building one is possible standalone — every field this module cannot yet answer is `None`, which
//! is a real, typed answer ("this plane contributes no such seam THIS generation"), not a stub. What
//! is NOT here is anything that makes `PLANE_DECL` reachable: no root `Cargo.toml`/`main.rs` change,
//! no entry in `busbar_core::plane::registry::BUILTIN_PLANE_DECLS`, no `BuildCtx` field for a
//! decision-plane runtime slot. Wiring those is explicitly the job of config-model Stage 1 (the
//! registry-driven prepass lift of the `decisions` verb) and Stage 2 (transport-by-scheme resolution
//! for the `typesafe` provider) — see `CONFIG-MODEL-RULING.md`'s owner ruling on jev being in 1.6.0
//! and the dictator sign-off section for jev v5. Until then this constant
//! compiles, is tested for its own field values, and is named by nothing outside this crate.
//!
//! ## Fields answered `None` here, and why each is honest rather than a placeholder
//!
//! - `build`/`claims`/`admission` close over no runtime slot: jev contributes no app-state object of
//!   its own this generation (there is nothing yet for `BuildCtx` to hand this plane — no field
//!   named for it), so `build` returns `None` unconditionally and `claims`/`admission` — which only
//!   have something to say once `build` has produced a slot to inspect — answer the empty/`None`
//!   case honestly rather than downcasting a slot that can never arrive.
//! - `routes`/`admin_routes`/`openapi`/`config_validate`/`hydrate`/`start`/`on_swap`/
//!   `parse_section`/`parse_endpoint`/`lower_endpoint`/`build_runtime`/`viewer`/
//!   `retain_verify_gates`/`default_section`/`named_def_list`/`named_def_get`/`registry_contains`/
//!   `reresolve_gates`/`card_signing_domain`/`card_kid_prefix`/`resolve_provider`: every one of
//!   these is `None` for the SAME reason the ones above are — each answers a question about a
//!   registered, wired plane (an admin surface to mount, a config section to install-time-parse
//!   against `DeployCfg`, a provider merge to run) that config-model Stage 1/2 has not yet made
//!   possible to ask. `busbar-mcp`'s own `PLANE_DECL` (the model this one is built against) answers
//!   every one of these with a real function; the difference here is not the type, it is that this
//!   plane has not been given anything to hand those functions yet.
//! - `owned_config_sections: &[]`: the Stage 1 contract for every plane, in force until sections
//!   start moving out of core's concrete `DeployCfg` (`CONFIG-MODEL-RULING.md` R1).

use busbar_substrate::plane::registry::PlaneDecl;

/// The wire formats this plane translates between — one, the `jev` dialect. A function rather than
/// a bare slice only because [`PlaneDecl::wire_format_names`] is typed as one; jev's dialect list
/// does not vary at runtime the way the LLM plane's protocol registry does.
fn wire_format_names() -> &'static [&'static str] {
    &["jev"]
}

/// THE DECISION PLANE'S VOCABULARY, crate-local. See the module doc for what is and is not wired.
pub const PLANE_DECL: PlaneDecl = PlaneDecl {
    // THE KEY IS THE PLANE'S OWN, named once so this declaration and `PlaneMeta::KEY`
    // (`meta.rs`) cannot drift apart. Both are the literal `"decision"` — the crate names it twice
    // because `PlaneMeta` cannot borrow a value from `PlaneDecl` (the latter is neutral seam data,
    // the former is the contract's own trait), and `tests/registry.rs` pins the two equal.
    key: "decision",
    // A MOUNTED plane, not the fallback catch-all — the LLM plane holds that role unconditionally.
    fallback: false,
    config_section: "decisions",
    scope_kinds: &["decision_provider"],
    subject_noun: "decision provider",
    admin_noun: "decision-provider",
    audit_kind: "decision_provider",
    wire_format_names,
    // No runtime slot exists yet for this plane to downcast (see module doc): both answer the
    // honest "nothing to claim/admit this generation" case.
    claims: |_slot| Vec::new(),
    admission: |_slot| None,
    build: |_ctx| None,
    routes: None,
    admin_routes: None,
    openapi: None,
    hydrate: None,
    start: None,
    config_validate: None,
    card_signing_domain: None,
    card_kid_prefix: None,
    named_def_list: None,
    named_def_get: None,
    registry_contains: None,
    reresolve_gates: None,
    // `openapi_schemas` is itself `#[cfg(feature = "openapi-schema")]` on `PlaneDecl` — a field this
    // crate cannot conditionally match (it declares no `[features]` at all, on purpose; see
    // `Cargo.toml`). None of the four gate commands enable that feature workspace-wide, so the field
    // does not exist in the struct this literal builds and is correctly omitted rather than gated.
    on_swap: None,
    parse_section: None,
    parse_endpoint: None,
    lower_endpoint: None,
    build_runtime: None,
    viewer: None,
    retain_verify_gates: None,
    default_section: None,
    // Stage 1 contract: every plane declares no owned sections until they start moving out of
    // core's concrete `DeployCfg` (`CONFIG-MODEL-RULING.md` R1).
    owned_config_sections: &[],
    resolve_provider: None,
};

#[cfg(test)]
#[path = "tests/registry.rs"]
mod tests;
