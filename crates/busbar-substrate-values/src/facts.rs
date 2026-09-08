// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL FACT ROWS a node reports about the things it holds — one lane's live health, and one
//! installed plugin's catalog entry.
//!
//! ## Why a carrier, and why here
//!
//! A node's administrative reads are crossing, one operation at a time, from the surface that used
//! to answer them to the composition root's loop. Everything that crosses that seam is NEUTRAL:
//! names, counts, words, flags and numbers, never a view struct and never a config type. The reads
//! crossed so far answer from facts small enough to cross as a tuple or as a struct the root owns.
//!
//! These two do not. A lane's live health is eleven readings and an installed plugin's row is
//! fifteen fields, and BOTH SIDES have to name the shape: the loop renders the bytes, and the
//! surface underneath still folds the same rows into the views it embeds elsewhere — a pool's
//! members into the effective-config read, a plugin's row into the re-scan result. A shape named by
//! two crates has to live in a third one both may depend on, and a positional tuple of eleven or
//! fifteen is a shape nobody can read a call site of.
//!
//! So the carriers live in the neutral substrate, beside the other value families a codec or a plane
//! names. Every FIELD of both is a scalar, a string or a flag the node already answers with; neither
//! type knows what an operation is, what a route is, or which surface will render it. That is the
//! whole property that lets an operation cross without its shape crossing with it.
//!
//! ## What is deliberately NOT here
//!
//! No rendering. Neither of these carries a serializer derive, a wire name or a field order, because
//! the bytes an operation answers with are the composition root's to write and the view a surface
//! embeds is that surface's to build. Two renderings, one fact.

/// ONE LANE'S LIVE HEALTH, as the node's own signals report it at one instant.
///
/// The readings a reliability dashboard ranks a pool member on: whether it can take dispatch, how
/// long it has left if it cannot, how much concurrency and how many requests are on it right now,
/// how fast it has been answering, and the running tallies of what it has answered.
///
/// **One instant, one row.** Every field is read against the same clock reading, which is why they
/// travel together rather than as separate accessors: `usable` and `cooldown_remaining_seconds` are
/// two halves of one breaker verdict, and a reader that sampled them apart could report a member as
/// usable with seconds still on its cooldown.
///
/// **Per POOL, not per lane, where the two differ.** `usable` and `cooldown_remaining_seconds` are
/// the breaker cell of this lane WITHIN one pool, because that is the cell routing actually ranks
/// on; the tallies and the concurrency beside them are genuinely lane-global counters. The
/// distinction is load-bearing — a lane whose cell is tripped in this pool and closed in another is
/// two different answers to "usable", and reporting the lane-wide aggregate would mislabel it in one
/// of them.
#[derive(Debug, Clone, PartialEq)]
pub struct LaneHealth {
    /// The lane's configured model name — the identity every other reading on this row belongs to.
    pub model: String,
    /// This member's SWRR weight within the pool it was read for.
    pub weight: u32,
    /// Whether the lane can currently take dispatch in this pool: its breaker cell is closed or
    /// recovered, and the lane is not hard-down.
    pub usable: bool,
    /// Seconds left on a tripped breaker cell's cooldown in this pool; `0` when it is not cooling.
    pub cooldown_remaining_seconds: u64,
    /// Free concurrency slots on this lane right now. Lane-global: permits are shared across every
    /// pool the lane is a member of.
    pub available_concurrency: usize,
    /// Requests in flight on this lane right now. Lane-global, for the same reason.
    pub inflight: i64,
    /// The lane's latency EWMA in milliseconds, or `None` when no sample has been taken yet.
    ///
    /// The one non-integral reading on this row, and `None` is a different statement from `0.0`: a
    /// lane nothing has been dispatched to has NO latency, and a zero would claim it answered
    /// instantly.
    pub latency_ms: Option<f64>,
    /// Successful request tallies for this lane. Lane-global and monotonic.
    pub ok: u64,
    /// Errored request tallies for this lane. Lane-global and monotonic.
    pub err: u64,
    /// Whether the lane is hard-down, which is a different condition from a transiently-tripped
    /// breaker.
    pub dead: bool,
    /// MONOTONIC count of closed-to-open breaker trips on this lane. A breaker episode can open and
    /// close entirely between two reads, so a consumer alerting on trips diffs this count rather
    /// than trying to catch the live edge.
    pub trip_count: u64,
    /// Epoch seconds of the most recent trip, or `None` for a lane that has never tripped.
    pub last_trip_at: Option<u64>,
}

/// ONE INSTALLED PLUGIN, as the node's catalog scan reports it.
///
/// A plugin is either COMPILED IN — baked into the binary behind a feature — or a signed artifact in
/// the node's plugin directory, read out of its manifest and re-evaluated against the trust posture
/// the node is actually running. This row carries both, which is why so many of its fields are
/// optional: a compiled-in plugin has no manifest to carry a version, a publisher or a schema, and
/// saying so with `None` is a different statement from inventing an empty one.
///
/// **Never a secret, and never a path.** Names, words, flags, one integer and one relative URL the
/// node resolved for itself. Nothing on this row is material, and nothing on it is a filesystem
/// location — `file` is the artifact's bare filename, which is the segment the sibling operations
/// key off, not somewhere on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginFacts {
    /// The plugin's name: its module name for a compiled-in one, its manifest name for an artifact.
    pub name: String,
    /// The plugin KIND, as the word the node reports it by. Each kind is a distinct engine contract.
    pub kind: &'static str,
    /// How the plugin got here — compiled into the binary, loaded as an artifact, or registered at
    /// runtime over a transport — as the word the node reports it by.
    pub loader: &'static str,
    /// Whether the plugin is currently active, where activation is a fact this level tracks at all;
    /// `None` where it is a per-pool concern this row does not summarize.
    pub active: Option<bool>,
    /// For an artifact, the name it resolves under; `None` for a compiled-in plugin.
    pub target: Option<String>,
    /// The artifact FILENAME, which is the path segment the sibling per-plugin operations key off.
    /// `None` for a row with no backing artifact to name.
    pub file: Option<String>,
    /// Whether this row's plugin declares a settings schema at all — the same fact `schema_url`
    /// being present carries, kept as its own flag so a catalog renders which rows are configurable
    /// without null-checking a URL.
    pub has_schema: bool,
    /// The artifact's semantic version, from its signed manifest.
    pub version: Option<String>,
    /// The publisher the manifest declares.
    pub publisher: Option<String>,
    /// The engine interface version the manifest declares.
    pub interface_version: Option<u32>,
    /// The node's own trust verdict for the artifact, re-evaluated against the posture it is
    /// running, as the word it reports it by. `None` for a row with no artifact to judge.
    pub trust: Option<&'static str>,
    /// Whether the artifact validated as something this node can load. `None` where there is nothing
    /// to validate.
    pub valid: Option<bool>,
    /// Why an artifact did not validate: a short, secret-free reason.
    pub error: Option<String>,
    /// The relative location this node resolved for the plugin's settings schema, present whenever
    /// the manifest declared one AT ALL — including a declaration that does not parse, which is a
    /// worse and distinct condition from having declared none.
    pub schema_url: Option<String>,
    /// Why a DECLARED settings schema does not parse. Distinct from a manifest that never declared
    /// one, where this and `schema_url` are both `None`.
    pub schema_error: Option<String>,
}

/// WHY A NODE HAS NO CATALOG TO REPORT for the kind it was asked about.
///
/// Two conditions and no more, because the catalog read has exactly two ways to answer with
/// something other than rows: the caller named a kind this node keeps no catalog for, and the scan
/// that would produce the rows could not be started within its bound.
///
/// **The MESSAGE travels and the code does not.** The prose belongs to the node — it names the kinds
/// this node actually keeps, and it is the sentence a client has been reading — but which stable code
/// and which status a condition renders under is the question of whoever answers the request, and
/// this carrier deliberately does not decide it. That is the same split the composition root already
/// keeps for every other refusal it renders: the condition comes from the node, the pairing is the
/// answerer's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogRefusal {
    /// The caller named a kind this node has no catalog for. The string is the node's own sentence,
    /// which names the kinds it does keep.
    UnknownKind(String),
    /// The scan could not even START within its bound, and was abandoned rather than left to hang
    /// the request. A retryable condition, and the string says so.
    Unavailable(String),
}

impl CatalogRefusal {
    /// The node's own sentence for this condition.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            CatalogRefusal::UnknownKind(message) | CatalogRefusal::Unavailable(message) => message,
        }
    }
}
