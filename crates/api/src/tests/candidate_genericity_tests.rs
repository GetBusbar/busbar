// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GENERICITY PROOF for the candidate projection: the neutral core is instantiated over two
//! deliberately different plane-fact shapes, and the fact that a ranking over it can be written ONCE
//! is the claim being tested.
//!
//! This is the same posture as the trust lifecycle's proof and for the same reason. The split is
//! being made ahead of the second plane, so "is it actually neutral?" cannot be a claim in a comment;
//! it has to be something that fails.
//!
//! The two shapes are not near-twins:
//!
//! - a single-value fact, one borrowed name and nothing else, which is what a plane whose members
//!   are addressed by name has to offer;
//! - a multi-value fact carrying a borrowed name, an owned enum and a nested struct, which is what a
//!   plane whose members carry a transport and a trust posture has to offer.
//!
//! A core that had absorbed "the facts are a couple of string slices" would not host the second, and
//! a core that had absorbed any one plane's field names could host neither.

use super::*;
use crate::{Plane, SignalBag};

/// Shape one: a single borrowed name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Named;

#[derive(Debug, Clone, serde::Serialize)]
struct NamedFacts<'a> {
    handle: &'a str,
}

impl Plane for Named {
    const NAME: &'static str = "named";
    type Facts<'a> = NamedFacts<'a>;
}

/// Shape two: a borrowed name, an owned enum and a nested struct. Deliberately nothing like the
/// first, and deliberately nothing like the LLM plane's four scalars.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layered;

#[derive(Debug, Clone, serde::Serialize)]
enum Reach {
    Local,
    Remote,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Posture {
    verified: bool,
    generation: u32,
}

#[derive(Debug, Clone, serde::Serialize)]
struct LayeredFacts<'a> {
    handle: &'a str,
    reach: Reach,
    posture: Posture,
}

impl Plane for Layered {
    const NAME: &'static str = "layered";
    type Facts<'a> = LayeredFacts<'a>;
}

/// ONE ranking, written once, over any plane. This function is the proof: if a neutral field had
/// leaked into a plane, or a plane fact had leaked into the core, this could not be written without
/// a parameter it does not have.
fn cheapest_first<P: Plane>(candidates: &[Candidate<'_, P>]) -> Vec<usize> {
    let mut keyed: Vec<(usize, Option<f64>)> = candidates.iter().map(|c| (c.idx, c.cost)).collect();
    keyed.sort_by(|(ia, ka), (ib, kb)| match (ka, kb) {
        (Some(a), Some(b)) => a
            .partial_cmp(b)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(ia.cmp(ib)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => ia.cmp(ib),
    });
    keyed.into_iter().map(|(idx, _)| idx).collect()
}

/// Build a candidate on any plane from the neutral values plus that plane's facts. Every neutral
/// field is set from the same arguments whichever plane is being built, which is the whole assertion
/// the neutral/specific line makes.
fn candidate<P: Plane>(idx: usize, cost: Option<f64>, facts: P::Facts<'_>) -> Candidate<'_, P> {
    Candidate {
        idx,
        weight: 1,
        tags: &[],
        cost,
        latency_ms: Some(12.0),
        available_concurrency: 4,
        budget_remaining: Some(99),
        rate_headroom: Some(0.5),
        signals: SignalBag::new(),
        facts,
    }
}

/// The single-value plane ranks on the neutral signals.
#[test]
fn one_ranking_serves_a_single_value_plane() {
    let cands = [
        candidate::<Named>(0, Some(9.0), NamedFacts { handle: "a" }),
        candidate::<Named>(1, Some(2.0), NamedFacts { handle: "b" }),
        candidate::<Named>(2, None, NamedFacts { handle: "c" }),
    ];
    assert_eq!(cheapest_first(&cands), vec![1, 0, 2]);
}

/// The multi-value plane ranks identically, through the SAME function, with no line added to it.
#[test]
fn the_same_ranking_serves_a_multi_value_plane() {
    let cands = [
        candidate::<Layered>(
            0,
            Some(9.0),
            LayeredFacts {
                handle: "a",
                reach: Reach::Local,
                posture: Posture {
                    verified: true,
                    generation: 1,
                },
            },
        ),
        candidate::<Layered>(
            1,
            Some(2.0),
            LayeredFacts {
                handle: "b",
                reach: Reach::Remote,
                posture: Posture {
                    verified: false,
                    generation: 7,
                },
            },
        ),
        candidate::<Layered>(
            2,
            None,
            LayeredFacts {
                handle: "c",
                reach: Reach::Remote,
                posture: Posture {
                    verified: true,
                    generation: 2,
                },
            },
        ),
    ];
    assert_eq!(cheapest_first(&cands), vec![1, 0, 2]);
}

/// The plane NAME travels with the plane and is never inferred by the core. It is what an audit row
/// records and a metric labels, and the machine never reads it.
#[test]
fn the_plane_name_belongs_to_the_plane_not_the_core() {
    assert_eq!(Named::NAME, "named");
    assert_eq!(Layered::NAME, "layered");
    assert_eq!(crate::Llm::NAME, "llm");
}

/// THE RATCHET, and the reason this file is more than two instantiations.
///
/// Two instantiations prove the core COMPILES for two shapes today. They do not stop the next change
/// from writing one plane's noun into the neutral projection, and the moment a plane's noun is a
/// field on the neutral candidate, every other plane fills it with a lie or with `None` forever. So
/// the module's own CODE is checked for plane vocabulary, and a violation is a failing test rather
/// than a review comment somebody has to remember to make.
///
/// PROSE is exempt and must be: the doc comments explain the parameter by naming exactly the planes
/// it exists for, and that explanation is the most useful thing in the file. So whole-line comments
/// are stripped and only the remaining code is judged.
#[test]
fn the_neutral_candidate_names_no_plane_in_its_code() {
    const BANNED: &[&str] = &[
        "llm",
        "Llm",
        "LLM",
        "mcp",
        "Mcp",
        "MCP",
        "a2a",
        "A2a",
        "A2A",
        "model",
        "Model",
        "provider",
        "Provider",
        "context_max",
        "tier",
        "Tier",
        "tool",
        "Tool",
        "agent",
        "Agent",
        "skill",
        "Skill",
        "server",
        "Server",
        "prompt",
        "Prompt",
        "token",
        "Token",
    ];
    let source = include_str!("../candidate.rs");
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in BANNED {
        assert!(
            !code.contains(needle),
            "the plane-neutral candidate projection names `{needle}` in its CODE. A field only one \
             plane can fill is a field every other plane fills with nothing forever: move the noun \
             out to the plane's own facts."
        );
    }
}

/// The neutral core's FIELD SET is the contract, and it is pinned here so that widening it is a
/// deliberate act with a test to change rather than a field somebody adds while passing through.
/// Every entry costs every request of every plane, which is why the list is short and why the
/// declared, cost-gated signal bag exists beside it.
#[test]
fn the_neutral_field_set_is_pinned() {
    let c = candidate::<Named>(0, Some(1.0), NamedFacts { handle: "a" });
    // Destructured exhaustively: adding a neutral field stops this compiling, which is the point.
    let Candidate {
        idx: _,
        weight: _,
        tags: _,
        cost: _,
        latency_ms: _,
        available_concurrency: _,
        budget_remaining: _,
        rate_headroom: _,
        signals: _,
        facts: _,
    } = c;
}
