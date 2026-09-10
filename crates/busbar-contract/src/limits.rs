// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONFIGURED LIMIT TREE AS PLAIN DATA — the one vocabulary shared by the crate that parses a
//! `groups:` section, the crate that projects it into enforcement buckets, and every engine that
//! resolves a model with or without a composition root behind it.
//!
//! It is contract data for the same reason the RESOLVED form beside it is ([`crate::ids::BucketRef`],
//! [`crate::ids::BucketScope`], [`crate::ids::BucketChain`]): a limit is what a unit is judged
//! against. Declaring it here is also what keeps the section-to-projection RELAY singular — a relay
//! can only be written where both sides can be named, and a reader that cannot reach the one relay
//! writes a copy of it. Two readings of one `groups:` section that must agree exactly is how a
//! deployment comes to be admitted against one set of ledger cells and billed against another,
//! silently, because both readings are internally consistent and neither knows the other exists.
//!
//! Only CHOSEN VALUES cross here. The field names, the serde shape and the validation belong to
//! whoever parses; the bucket a limit lands in, how repeats fold and whose exhaustion behaviour
//! governs belong to whoever projects. No arithmetic, and no `Default`: a limit tree is relayed from
//! a configuration or it is not there at all.

/// Which counter one configured limit caps.
///
/// The neutral spelling of the limit grammar's metric, in the order the grammar declares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitMetric {
    /// Request count per window.
    Requests,
    /// Total tokens per window, every class summed.
    Tokens,
    /// Uncached-input tokens per window.
    TokensInput,
    /// Output tokens per window.
    TokensOutput,
    /// Cache-read tokens per window.
    TokensCacheRead,
    /// Cache-write tokens per window.
    TokensCacheWrite,
    /// Spend per window, in the currency's minor units.
    Budget,
    /// In-flight requests, instantaneous: never windowed and never pool-scoped.
    Concurrent,
}

/// A kind-tagged reference to a scope a limit is qualified to, or downgrades to.
///
/// The kind rides along with the value because the bucket id carries both, and a bucket id is a
/// ledger row name: the row a scoped limit charges must be the row the previous release charged for
/// the same configuration, kind and all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSpec {
    /// The reference's kind, as the grammar spells it.
    pub kind: String,
    /// The referenced name, which is what the door compares a request's pool against.
    pub value: String,
}

/// One configured limit, as the projection reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitSpec {
    /// Which counter it caps.
    pub metric: LimitMetric,
    /// The cap.
    pub amount: u64,
    /// The window word, or none for the one windowless metric.
    pub window: Option<&'static str>,
    /// The scope the limit is qualified to, or none for a group-wide limit.
    pub scope: Option<ScopeSpec>,
    /// Where a spend cap sends exhausted traffic instead of refusing it, if it declared one.
    pub downgrade_to: Option<ScopeSpec>,
}

/// One configured group, as the projection reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSpec {
    /// The group's name as a composition root interned it at boot, if one did.
    ///
    /// `None` is not an error and not a degraded reading: the projection is unaffected either way,
    /// and a caller reading the interned names back simply does not see this one. An engine with no
    /// root behind it relays every group with `None` here and is judged identically.
    pub lease_id: Option<&'static str>,
    /// The parent group's name, if any.
    pub parent: Option<String>,
    /// `false` freezes the group and every descendant.
    pub enabled: bool,
    /// The group's limits, in configuration order.
    pub limits: Vec<LimitSpec>,
}
