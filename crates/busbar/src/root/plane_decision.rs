// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The decision plane's registry declaration, written by the composition root because the plane
//! itself may not write it.
//!
//! ## Why this file exists at all, when the other four planes have no counterpart
//!
//! Every other plane hands the binary a `&'static PlaneDecl` of its own — `busbar_llm::PLANE_DECL`,
//! `busbar_mcp::PLANE_DECL`, `busbar_a2a::PLANE_DECL`, `busbar_voice::PLANE_DECL`. Each of those
//! four lives in an IMPURE HOST crate that already path-deps `busbar-kernel`, so naming a kernel
//! type costs it nothing. `busbar-plane-decision` has no host crate: the signed jev design makes it
//! ONE crate, the pure plane and its own typed `decisions:` section together, and a pure plane's
//! manifest may name `busbar-contract` and nothing else (the dep wall, DECISIONS #40). `PlaneDecl`
//! is a `busbar-kernel` type. The plane crate therefore CANNOT hold its own declaration — it used
//! to, in a `src/registry.rs` nothing outside the crate ever read, and that file was deleted
//! precisely because carrying it cost the crate a forbidden kernel edge; its own
//! `tests/invariance.rs` is the witness that keeps the edge gone.
//!
//! So the declaration is written HERE. That is not a workaround: the composition root is defined as
//! the one place entitled to name the kernel, the units, the planes and the transports together,
//! and this file names exactly two of them — the kernel type and the plane whose identity it
//! declares. Nothing else in the tree is allowed to do it, and the plane crate is unchanged.
//!
//! ## Reads, does not restate
//!
//! Everything the plane already says about itself is READ off the contract's `PlaneMeta` rather
//! than spelled again here: the registry key is `DecisionPlane`'s own `KEY`. A second literal
//! `"decision"` in this file would be a string that could drift from the plane's, and the drift
//! would show up as a registry installing one name while the plane answers to another. The one
//! value this file does have to spell is [`CONFIG_SECTION`] — see its own note.
//!
//! ## What this declaration DOES and, more importantly, what it does NOT
//!
//! It declares IDENTITY and nothing else. `claims`, `admission` and `build` are the inert trio:
//! this plane claims no path, binds no audience and contributes no runtime slot, so installing it
//! mounts no route, admits no caller and changes no byte a configured deployment serves. That is
//! the honest shape for the state the plane is actually in — a complete nine-method `impl Plane`
//! with no unit path in `root/` yet to drive it. It is also exactly the shape the LLM plane's own
//! declaration ships with (`claims: |_| Vec::new()`, `admission: |_| None`, `build: |_| None`), so
//! it is a stated position in this codebase rather than a placeholder invented here.
//!
//! What installing it DOES buy, and the reason #48's gate column asks for it: the plane joins the
//! process plane axis, and its declaring section `decisions:` joins
//! `busbar_kernel::plane::config::config_sections()` — the fold every cross-plane hook-reference
//! refusal is judged against. Before this, a hook named `decisions.<x>` was a name no reader
//! recognised as another plane's.
//!
//! ## The one thing this does NOT wire, stated plainly rather than left to be discovered
//!
//! An operator cannot yet WRITE a `decisions:` block. `parse_section` and `default_section` are
//! `None` here, and they would not be enough on their own: the top-level key would also have to be
//! lifted by `busbar_kernel::config::prepass`, whose key list is frozen at
//! `["mcp", "oauth_as", "tools", "agents", "streams"]`, and `DeployCfg` is `deny_unknown_fields`,
//! so a `decisions:` document is refused before any plane seam is consulted. Wiring that grammar is
//! a config-seam stage of its own — it moves a kernel-side list — and doing it inside a
//! registration change would be two landings in one. The plane's typed
//! `busbar_plane_decision::config::DecisionsSection` is already written and tested and is what that
//! stage will lower through.

use busbar_contract::plane::PlaneMeta;
use busbar_plane_decision::DecisionPlane;

/// THE DECLARING SECTION for the decision plane — the top-level `config.yaml` noun whose mere
/// existence declares this plane, beside `pools:`, `tools:`, `agents:` and `streams:`.
///
/// Spelled here rather than read off the plane crate because the plane crate declares no constant
/// for it: the name is ruled in the owner's config-model sign-off and is written down in
/// `busbar_plane_decision::config`'s module doc and in that crate's `CONFIG_SCHEMA`, both as prose
/// rather than as an item. This is the ONE value in this file that is a restatement, it is named
/// once, and both places that need it below read this constant rather than a second literal.
///
/// PLURAL, and deliberately not the registry key: the key is the plane's identity (`decision`, what
/// `DecisionPlane::KEY` says) and the section is the operator's noun for the set of configured
/// decision models (`decisions`). The MCP plane's key/section pair (`mcp` / `tools`) and the voice
/// plane's (`voice` / `streams`) differ for the same reason.
pub const CONFIG_SECTION: &str = "decisions";

/// THE DECISION PLANE'S REGISTRY DECLARATION — the `&'static PlaneDecl` `register_planes()`
/// installs, and the composition root's whole knowledge of this plane.
///
/// See the module doc for why it is written here and not in the plane crate, and for what it
/// deliberately leaves unwired.
pub const PLANE_DECL: busbar_kernel::plane::registry::PlaneDecl =
    busbar_kernel::plane::registry::PlaneDecl {
        // THE KEY IS THE PLANE'S OWN, read through the contract trait the plane implements, so this
        // declaration and the plane cannot drift apart.
        key: <DecisionPlane as PlaneMeta>::KEY,
        // A registered plane, not the fallback catch-all — that flag is the LLM plane's and exactly
        // one build-in sets it.
        fallback: false,
        config_section: CONFIG_SECTION,
        // ONE granularity, and it is the one the plane's own `approve` step emits a locator for: a
        // grant names a configured decision PROVIDER. jev exposes no finer resource — there is no
        // per-operation grant, because both operations are billed against the same provider account.
        scope_kinds: &["decision_provider"],
        subject_noun: "decision provider",
        admin_noun: "decision-provider",
        audit_kind: "decision_provider",
        // ONE wire format. jev is HTTP+JSON, request-line-addressed — the operation is named by the
        // verb and the path (`POST /v1/systemone`, `GET /v1/models`), never by a member inside the
        // body. A single-format plane earns no superset IR, and `Plane::has_superset_ir` stays
        // derived from this list's length rather than from a second declaration.
        wire_format_names: || &[busbar_kernel::plane::WIRE_HTTP_JSON],
        // THE INERT TRIO — see the module doc. The plane declares two exact-path claims of its own
        // (`busbar_plane_decision::claims::CLAIMS`), and they are NOT re-declared here on purpose:
        // a path returned from this hook is a path `PlaneDispatch` mounts and resolves an audience
        // through, and a plane with no unit path to answer on it would be a mounted door with
        // nothing behind it. Identity first; the door is opened by the change that gives this plane
        // a `root/units_decision.rs` to answer from.
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        // NO DURABLE STATE TO RESTORE AND NOTHING TO START. jev is a stateless request/response
        // passthrough and declares no record schemas (`busbar_plane_decision::records`), so there is
        // no boot replay to run and no background loop to spawn.
        hydrate: None,
        start: None,
        config_validate: None,
        // jev signs no agent card — it fronts nobody and publishes no identity document.
        card_signing_domain: None,
        card_kid_prefix: None,
        // `decisions:` is a model-serving section (`models:` + the two reserved members), not a
        // 1.5.3 named-definition map, so the generic admin CRUD never routes here — the same shape
        // the LLM plane's `pools:` declares.
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        #[cfg(feature = "openapi-schema")]
        openapi_schemas: None,
        on_swap: None,
        // THE CONFIG-GRAMMAR SEAM, DELIBERATELY UNWIRED — see the module doc's last section for the
        // precise reason and for what has to move first.
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
        // THIS PLANE OWNS `decisions:` AND NOBODY ELSE DOES. Unlike `pools`/`models`/`providers`,
        // the section was never a concrete `DeployCfg` field — it is greenfield, post-1.5.5 — so
        // claiming it evicts nothing from core and the dup-claim guard admits it. What the claim
        // buys is that a SECOND claimant of `decisions` is now a boot refusal by construction, which
        // is the whole reason the guard exists. Voice's `streams` claim is the precedent.
        owned_config_sections: &[CONFIG_SECTION],
        // The providers/models/pools merge is the LLM plane's seam; a decision provider is resolved
        // from this plane's own section, not from the `providers:` catalog merge.
        resolve_provider: None,
    };

#[cfg(test)]
#[path = "tests/plane_decision.rs"]
mod tests;
