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
//! ## The grammar seam, and the ONE thing the dep wall makes this file do differently
//!
//! An operator CAN write a `decisions:` block. The top-level key is lifted by
//! `busbar_kernel::config::prepass`, whose key list is
//! `["mcp", "oauth_as", "tools", "agents", "streams", "decisions"]`, and lands on
//! `DeployCfg.decisions` — the neutral boxed carrier `busbar_kernel::plane::config::DecisionsSection`
//! — which lowers through THIS declaration's [`PLANE_DECL`]`.parse_section` /
//! [`PLANE_DECL`]`.default_section` hooks, exactly as `tools:`, `agents:` and `streams:` lower
//! through their own planes'. With those two hooks `None` the seam falls through to an UNTYPED raw
//! capture: the section's `deny_unknown_fields` never runs, and `decisions: "hello"` parses. That is
//! a config an operator writes that does nothing, which is worse than one that is rejected, so both
//! hooks are wired — see [`decisions_parse_section`] and [`decisions_default_section`].
//!
//! The four sibling planes put those two functions in their own crate, beside the typed section
//! they lower. This one cannot, and for the same reason the declaration itself is here:
//! `Box<dyn PlaneCfg>` is a `busbar-kernel` type and `busbar-plane-decision` may name
//! `busbar-contract` and nothing else (the dep wall, DECISIONS #40). So the hooks are written HERE,
//! over the plane's own already-written and already-tested
//! `busbar_plane_decision::config::DecisionsSection`, and the ONE piece of mechanism this file adds
//! that the other four do not need is [`DecisionsCfg`]: a newtype, because the trait
//! (`busbar-kernel`'s) and the section (`busbar-plane-decision`'s) are both foreign to this crate
//! and an `impl PlaneCfg for DecisionsSection` written here would be an orphan. The newtype carries
//! no grammar of its own — it wraps, and every method below either forwards or answers for a
//! section shape that has no such thing.
//!
//! ## What the section reaches, and what it does not
//!
//! Stated here rather than left to be discovered. What it reaches: the BOOT REFUSAL surface. A
//! `decisions:` that is not a mapping, or that carries a member the plane does not declare, fails
//! `--validate` and fails boot, naming the key. The parsed value is banked on `DeployCfg.decisions`
//! and reads back as the plane's own `DecisionsSection` through `PlaneCfg::as_any`. What it does
//! NOT reach: any request. `build` is `None` and the plane has no unit path in `root/` yet, so
//! `decisions.models.<m>` names a lane nothing dispatches to. That is the same state `claims`,
//! `admission` and `build` are in, and it is why this file wires the CONFIG seam and not a runtime
//! one.

use busbar_contract::plane::PlaneMeta;
use busbar_plane_decision::config::DecisionsSection;
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
        // THE CONFIG-GRAMMAR SEAM. `decisions:` is deserialized through the plane's OWN typed
        // section, so `deny_unknown_fields` runs inside the block and a scalar where a mapping
        // belongs is a refusal rather than a raw capture. Written here rather than in the plane
        // crate because the boxed return type is a kernel one — see the module doc.
        parse_section: Some(decisions_parse_section),
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        // The empty `decisions:`, so an ABSENT section decodes to the plane's own
        // `DecisionsSection::default()` rather than falling back to the neutral raw capture — the
        // carrier's type must not depend on whether the operator wrote the block.
        default_section: Some(decisions_default_section),
        // THIS PLANE OWNS `decisions:` AND NOBODY ELSE DOES. Unlike `pools`/`models`/`providers`,
        // the section was never a concrete `DeployCfg` field — it is greenfield, post-1.5.5 — so
        // claiming it evicts nothing from core and the dup-claim guard admits it. What the claim
        // buys is that a SECOND claimant of `decisions` is now a boot refusal by construction, which
        // is the whole reason the guard exists. Voice's `streams` claim is the precedent.
        owned_config_sections: &[CONFIG_SECTION],
        // The class the plane crate declares (`busbar_plane_decision::meta`), by its own symbol.
        billable_classes: &[busbar_kernel::plane::registry::BillableClass {
            class: busbar_plane_decision::meta::CLASS_DECISION.as_str(),
            family: "decision",
        }],
        // The providers/models/pools merge is the LLM plane's seam; a decision provider is resolved
        // from this plane's own section, not from the `providers:` catalog merge.
        resolve_provider: None,
    };

/// THE PLANE'S TYPED `decisions:` SECTION, WEARING THE KERNEL'S NEUTRAL SECTION TRAIT.
///
/// A newtype and nothing else. `busbar_kernel::plane::config::PlaneCfg` is a `busbar-kernel` trait
/// and [`DecisionsSection`] is a `busbar-plane-decision` type; both are foreign to this crate, so
/// the impl below could not be written for the section directly (orphan rule). The four sibling
/// planes have no such problem because each of them owns one side of the pair — which is the whole
/// of why this wrapper exists, and the whole of what it does. It adds no field, no default and no
/// serde attribute: the grammar an operator writes is [`DecisionsSection`]'s, unchanged.
#[derive(Debug, Clone, Default)]
pub struct DecisionsCfg(pub DecisionsSection);

impl busbar_kernel::plane::config::PlaneCfg for DecisionsCfg {
    /// The `decisions:` section carries NO secret reference. The EXHAUSTIVE destructure (no `..`) is
    /// what keeps that true: a credential-bearing member added to the plane's section fails to
    /// compile here until someone decides, at this line, whether it is a secret — the same
    /// anti-omission force `ToolsCfg`/`AgentsCfg`/`StreamsCfg` carry. `models.<m>.provider` is a
    /// NAME into `providers:`, and the credential lives on the provider entry, which core's own walk
    /// already enumerates; `upstream_credentials` is a two-variant mode, not a secret.
    fn secret_refs(&self) -> Vec<(String, &busbar_api::SecretRef)> {
        let DecisionsSection {
            models: _,
            hooks: _,
            upstream_credentials: _,
        } = &self.0;
        Vec::new()
    }

    /// `decisions:` is a MODEL-SERVING section (`models:` plus the two reserved members), not a
    /// 1.5.3 named-definition map — the same shape `pools:` and `streams:` have. The decl's
    /// `named_def_list`/`named_def_get`/`registry_contains` are all `None`, so the generic admin
    /// CRUD never routes a write here and these four answer for a registry that does not exist.
    /// `models` is a map of lanes, NOT a definition registry: reporting its keys as `def_names`
    /// would fold them into the global pool-name uniqueness sets and invent a collision rule
    /// nothing ruled.
    fn contains_def(&self, _name: &str) -> bool {
        false
    }

    fn def_names(&self) -> Vec<&str> {
        Vec::new()
    }

    fn entry_document(&self, _name: &str) -> Option<serde_json::Value> {
        None
    }

    fn insert_def(&mut self, _name: &str, _def: &serde_json::Value) -> Result<(), String> {
        Err("`decisions:` has no named definitions".to_string())
    }

    /// The reserved section-level `hooks:` attach list, handed over verbatim. There are no
    /// per-registration containers: a decision model is a lane, not a hook seat, and the plane seats
    /// none of its own.
    fn container_gates(&self) -> busbar_kernel::plane::config::ContainerGateInputs {
        busbar_kernel::plane::config::ContainerGateInputs {
            section_hooks: self.0.hooks.clone(),
            containers: Vec::new(),
        }
    }

    /// No cross-registration rule. Every rule this section has is about ONE entry and is enforced by
    /// [`DecisionsSection`]'s own `Deserialize`; there is no section-wide constraint spanning the
    /// `models` map.
    fn validate_registry(&self) -> Result<(), String> {
        Ok(())
    }

    /// True when the operator wrote CONTENT — anything other than the plane's own empty section.
    /// Spelled field by field rather than as `!= Default::default()` because the section derives no
    /// `PartialEq`, and exhaustively for the same anti-omission reason as `secret_refs`: a member
    /// added without a decision here would make a configured deployment read as unconfigured, and
    /// the deletion-gate leg that refuses a `decisions:` naming a compiled-out plane reads exactly
    /// this answer.
    fn is_present(&self) -> bool {
        let DecisionsSection {
            models,
            hooks,
            upstream_credentials,
        } = &self.0;
        !models.is_empty() || !hooks.is_empty() || upstream_credentials.is_some()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_box(&self) -> Box<dyn busbar_kernel::plane::config::PlaneCfg> {
        Box::new(self.clone())
    }

    fn clone_arc_any(&self) -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
        std::sync::Arc::new(self.clone())
    }
}

/// `PLANE_DECL.parse_section` — deserialize `decisions:` through the plane's own typed shape, boxed
/// as the neutral [`busbar_kernel::plane::config::PlaneCfg`]. Mirror of `mcp_parse_section` /
/// `a2a_parse_section` / `streams_parse_section`, with the one difference the dep wall forces: the
/// function lives in the composition root and boxes [`DecisionsCfg`] rather than the section itself.
///
/// The refusal NAMES THE KEY. The `serde_yaml::Value` intermediate carries no source position, so
/// without the prefix an operator reading a failed `--validate` is told the name of a Rust type they
/// have never seen instead of the name of the block they wrote. `export.<n>.durable` sets the
/// standard this follows: a declared surface that cannot be honoured as written refuses loudly and
/// says which key it means.
fn decisions_parse_section(
    v: &serde_yaml::Value,
) -> Result<Box<dyn busbar_kernel::plane::config::PlaneCfg>, String> {
    serde_yaml::from_value::<DecisionsSection>(v.clone())
        .map(|c| Box::new(DecisionsCfg(c)) as Box<dyn busbar_kernel::plane::config::PlaneCfg>)
        .map_err(|e| format!("`{CONFIG_SECTION}:` is not valid: {e}"))
}

/// `PLANE_DECL.default_section` — the empty `decisions:`, so an ABSENT section decodes to
/// [`DecisionsSection::default`] rather than to the neutral raw capture. Mirror of
/// `a2a_default_section` / `mcp_default_section` / `streams_default_section`.
fn decisions_default_section() -> Box<dyn busbar_kernel::plane::config::PlaneCfg> {
    Box::<DecisionsCfg>::default()
}

#[cfg(test)]
#[path = "tests/plane_decision.rs"]
mod tests;
