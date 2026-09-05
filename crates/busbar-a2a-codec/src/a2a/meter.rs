// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! METERING ATTRIBUTION: whose budget an A2A task bills, and — the harder half — what busbar
//! does NOT claim to meter.
//!
//! ## The chain reaches different depths in the two directions, and one diagram would lie
//!
//! **RECEIVING**, busbar owns both altitudes. The task bills the PRESENTING key's budget, and so
//! does its downstream L2 MCP spend, because that spend is busbar's own traffic one altitude down.
//! The chain closes end to end.
//!
//! **DELEGATING**, the chain TERMINATES AT THE HOP. busbar meters the hop it made — who delegated,
//! to which registered agent, under which `contextId`, with what terminal state — against the
//! INITIATING key. It does not meter the callee's own downstream tool or model spend, because that
//! traffic never touches busbar's plane. The callee is a black box, and a gateway that reported a
//! number for what happens inside one would be reporting a guess.
//!
//! That asymmetry is the reason this module exists as a type rather than as a convention.
//! [`Attribution::covers_callee_internal_spend`] is `false` on the delegating arm and there is no
//! way to construct one where it is `true`, so "the hop, not the black box behind it" is a property
//! of the type rather than a sentence somebody has to remember.
//!
//! ## Over-limit is refused BEFORE the backend
//!
//! 429 plus `Retry-After`, ahead of the work, for the same reason the 403 is: on this plane the
//! work may be a long-running task that reached down into L2 tools, and a limit enforced after it
//! has already cost the operator the thing the limit was for.

// PARTLY UNMOUNTED. `Attribution::receiving` is on the hot path (`ingress::invoke` bills the
// presenting key through it). `Attribution::delegating`, `Direction::Delegating` and `Admission`
// are the delegating direction's half: nothing delegates outward yet, and `Admission` is this
// plane's own window arithmetic, which the ingress does not use because it meters through the
// shared governance ledger rather than a second one.
#![cfg_attr(not(test), allow(dead_code))]

/// Which direction a metered A2A event belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// busbar is the SERVER: an external agent delegated a task to a busbar-fronted agent.
    Receiving,
    /// busbar is the CLIENT: a fronted agent delegated out to a registered agent.
    Delegating,
}

/// WHAT IS BILLED, TO WHOM, AND HOW FAR THE CLAIM REACHES.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribution {
    pub direction: Direction,
    /// The key whose budget this bills.
    ///
    /// RECEIVING: the PRESENTING key. DELEGATING: the INITIATING key — the one that started the
    /// chain, not a synthetic identity for the fronted agent. A hop billed to the agent rather than
    /// to whoever set it in motion is a hop nobody's budget constrains, and a budget nobody's
    /// budget constrains is not a budget.
    pub billed_key_id: String,
    /// The fronted agent, on the receiving side; the DELEGATING fronted agent, on the outbound one.
    pub agent_id: String,
    /// The registered agent the hop went TO. Delegating only.
    pub target_agent_id: Option<String>,
    /// The session grouping key: busbar's metering attribution and provenance key.
    pub context_id: String,
    pub task_id: String,
    /// Whether busbar's downstream L2 MCP spend on this task is billed to the same key.
    ///
    /// TRUE on receiving (it is busbar's own traffic) and FALSE on delegating (there is none:
    /// busbar made one hop).
    pub covers_downstream_l2_spend: bool,
    /// ALWAYS FALSE, on both arms, and it is a field rather than an omission so that the claim is
    /// visible where the numbers are read.
    ///
    /// The callee's internal tool and model spend is the vendor's plane. It never touches busbar,
    /// so busbar cannot meter it, and a gateway that quietly reported it as zero would be reporting
    /// a number that reads as "they spent nothing".
    pub covers_callee_internal_spend: bool,
}

impl Attribution {
    /// RECEIVING: the task and its downstream L2 MCP calls bill the presenting key.
    pub fn receiving(
        presenting_key_id: impl Into<String>,
        agent_id: impl Into<String>,
        context_id: impl Into<String>,
        task_id: impl Into<String>,
    ) -> Self {
        Self {
            direction: Direction::Receiving,
            billed_key_id: presenting_key_id.into(),
            agent_id: agent_id.into(),
            target_agent_id: None,
            context_id: context_id.into(),
            task_id: task_id.into(),
            covers_downstream_l2_spend: true,
            covers_callee_internal_spend: false,
        }
    }

    /// DELEGATING: THE HOP is metered, billed to the initiating key. The black box behind it is
    /// not.
    pub fn delegating(
        initiating_key_id: impl Into<String>,
        from_agent_id: impl Into<String>,
        target_agent_id: impl Into<String>,
        context_id: impl Into<String>,
        task_id: impl Into<String>,
    ) -> Self {
        Self {
            direction: Direction::Delegating,
            billed_key_id: initiating_key_id.into(),
            agent_id: from_agent_id.into(),
            target_agent_id: Some(target_agent_id.into()),
            context_id: context_id.into(),
            task_id: task_id.into(),
            // busbar made ONE hop. There is no downstream L2 traffic of busbar's own on this arm,
            // and the callee's is not busbar's.
            covers_downstream_l2_spend: false,
            covers_callee_internal_spend: false,
        }
    }
}

/// The admission answer for one task, before any backend runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Admitted; charge it.
    Admit,
    /// Over the key's limit. 429, with `Retry-After` in seconds.
    OverLimit { retry_after_secs: u64 },
}

impl Admission {
    pub fn status(&self) -> Option<u16> {
        match self {
            Admission::Admit => None,
            Admission::OverLimit { .. } => Some(429),
        }
    }
}

/// ADMIT OR REFUSE ONE TASK against the billed key's remaining allowance.
///
/// Reaching the limit is over it: an operator who wrote the number they consider unacceptable did
/// not mean "one more than this".
pub fn admit(used: u64, limit: Option<u64>, window_remaining_secs: u64) -> Admission {
    match limit {
        None => Admission::Admit,
        Some(limit) if used < limit => Admission::Admit,
        Some(_) => Admission::OverLimit {
            // At least one second: a `Retry-After: 0` invites an immediate retry, which is a
            // client-side hot loop pointed at a gateway that just said no.
            retry_after_secs: window_remaining_secs.max(1),
        },
    }
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/meter_tests.rs"]
mod meter_tests;
