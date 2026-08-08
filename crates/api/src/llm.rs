// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PLANE: its marker, the candidate facts it contributes, and the short spelling of its own
//! candidate.
//!
//! This is one instantiation of [`crate::RoutingPlane`], and everything in it is a noun the
//! neutral core deliberately does not know. A member of an LLM pool is a MODEL served by a PROVIDER, with a
//! context-window ceiling and an operator-declared tier. None of those four is a fact another plane
//! can fill, so none of them is a field on every candidate of every plane.
//!
//! `tier` is here rather than beside `tags` on purpose, and it is the closest call in the split.
//! Both are operator-declared labels; the difference is that `tags` is an open set the machine never
//! reads, while `tier` names a rung on the model ladder a cost model is written against. The first
//! is grouping and is neutral; the second is a statement about models.

/// The LLM plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LlmPlane;

impl crate::RoutingPlane for LlmPlane {
    const KEY: &'static str = "llm";
    type Facts<'a> = LlmFacts<'a>;
}

/// The LLM plane's per-candidate facts. Serialized FLATTENED onto the candidate's own hook-wire
/// object, so the wire a hook parses is unchanged by the plane split: these four keys sit beside the
/// neutral ones exactly as they always have.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LlmFacts<'a> {
    /// The member's model name.
    pub model: &'a str,
    /// Upstream provider name. Projected so a hook can implement a provider-preference strategy.
    pub provider: &'a str,
    /// Member context-window ceiling. Projected so a hook can route by context-fit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_max: Option<usize>,
    /// The operator-declared tier this member sits on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<&'a str>,
}

/// The LLM plane's candidate. The alias exists so the plane's own code reads the way it did before
/// the split, without the neutral core having to name a plane to provide it.
pub type LlmCandidate<'a> = crate::Candidate<'a, LlmPlane>;
