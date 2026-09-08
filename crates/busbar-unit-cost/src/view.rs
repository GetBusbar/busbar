// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin READ VIEWS that carry a figure: usage, spend and the budget headroom beside it.
//!
//! WHY THESE SHAPES LIVE IN THE COST UNIT. A plane says what HAPPENED; the cost unit says what it
//! COST. The admin plane renders these documents without ever naming a figure, and the shapes that
//! DO name one (`spend_cents`, `spend_micros`, `budget_cap`, `budget_remaining_cents`) belong to the
//! crate that owns the money vocabulary. Nothing here computes: every field is filled by whatever
//! already derived the number (the governance bucket read, the metering rollup), so no arithmetic
//! moved with the types and no second pricing policy can grow here. The crate rule the manifest
//! states — no clock, no store, no config parser, no plane — still holds: these are `serde` shapes
//! over integers and strings.
//!
//! WIRE-FROZEN, MOVED VERBATIM. Field order, every `serde` attribute and every doc comment are the
//! 1.5.5 admin contract's, unchanged: the doc comments are the `description` strings `schemars`
//! emits into `openapi.json`, so a reworded line here is a changed published document. Additive-only
//! (a field may be ADDED; none is removed or renamed).

// The moved shapes carry EXACTLY the doc comments the admin contract shipped with — several fields
// were never documented there, and adding a sentence now would add a `description` to the served
// OpenAPI document. The crate-level `deny(missing_docs)` is relaxed for this module for that reason
// alone; every other item in this crate still carries its documentation.
#![allow(missing_docs)]

use serde::Serialize;

/// `GET /groups/{name}/usage`: one group's DERIVED current-window usage, one row per
/// enforcement bucket (each `(window, pool?)` its limits materialise), against that bucket's
/// caps. The dashboard read: spend/tokens/requests per tier vs the budgets, straight off the
/// ledger x the CURRENT rate card (reprice-on-read, nothing stored). The customer's self-service
/// tool consumes this per group (`user:<sub>` leaf = one person's view) and re-scopes it.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct GroupUsageView {
    /// The group name (echoed from the path).
    pub group: String,
    /// `false` = the group is FROZEN (`enabled: false`): every request through it rejects.
    pub enabled: bool,
    /// One row per enforcement bucket, in the group's resolved bucket order. Empty for a group
    /// with only a `concurrent` limit (or none); there is no windowed ledger to read.
    pub buckets: Vec<GroupBucketUsageView>,
    /// Epoch seconds the read was taken at (the windows below are current AS OF this instant).
    pub as_of: u64,
}

/// One `(window, pool?)` enforcement bucket's usage vs caps inside a [`GroupUsageView`].
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct GroupBucketUsageView {
    /// The accounting window: `minute` | `hour` | `day` | `month` | `total`.
    pub window: &'static str,
    /// The pool scope for a pool-qualified bucket; absent for a group-wide bucket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool: Option<String>,
    /// Requests admitted this window (the requests-limit truth: failures are not refunded).
    pub requests: u64,
    /// Total tokens ledgered this window (all tiers).
    pub tokens: u64,
    /// Spend derived at read time (tokens x current rate card), abstract cents.
    pub spend_cents: i64,
    /// The bucket's caps, when configured (absent = uncapped on that metric).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requests_cap: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_cap: Option<u64>,
    /// Per-tier token caps mirroring the cost tiers, when configured (absent = uncapped on that
    /// tier): `tokens_input` = uncached input, `tokens_output` = output, `tokens_cache_read`,
    /// `tokens_cache_write` = cache creation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_input_cap: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_output_cap: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_cache_read_cap: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_cache_write_cap: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_cap: Option<i64>,
    /// Cents left under `budget_cap` (floored at 0); absent when no budget cap is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_remaining_cents: Option<i64>,
}

/// Fleet METERING read (`GET /api/v1/admin/usage`) — the FinOps surface. Design principle:
/// busbar exposes the RAW INPUTS of cost, not just its own number. Every row carries the full token
/// SPLIT (input / output / cache-read / cache-creation — each prices differently), so a consumer
/// with its own (special/negotiated) price catalog reconstructs cost independently; `spend_micros`
/// is busbar's DERIVED estimate from the operator's configured global prices, computed at read time
/// (raw counts are what's stored — a price change re-prices history consistently).
///
/// Time base — THE PINNED SHAPE RULING: a usage response is ALWAYS exactly
/// ONE fixed UTC-day metering bucket (`window`). `?window=<bucket-start-epoch>` selects a PAST
/// bucket (default: the current one); a multi-window series is the CLIENT fetching N buckets — or
/// a future additive `?from=&to=` returning an ARRAY OF THIS SAME PER-BUCKET SHAPE, never a
/// differently-shaped merged view. Billing periods aggregate client-side from day buckets (raw
/// counts are stored, so the math is exact). Deliberately decoupled from per-key budget windows so
/// per-model aggregation across keys is well-defined; budget ENFORCEMENT state lives on
/// `GET /keys/{id}/usage`, not here. Empty aggregations when governance is disabled. No secrets —
/// key ids/names only, never a token.
///
/// LEDGER RULE (one loud contract sentence): `spend_micros` is a MUTABLE ESTIMATE — derived at
/// read time from the operator's CURRENT prices, so a price change re-prices history. Never store
/// it as a ledger charge; bill from the raw token split.
/// The denomination reported alongside every `spend_micros` in the admin usage response. A SINGLE
/// source of truth so a future removal (returning to the currency-agnostic stance) is one line.
/// Emitted ONLY on `GET /api/v1/admin/usage` (the `currency` field of `UsageView`), never on the
/// per-key views (those stay currency-agnostic raw-split ledgers).
pub const USAGE_CURRENCY: &str = "USD";

/// Serialize helper: `UsageView::currency` is a fixed contract constant, not a stored field.
fn serialize_usage_currency<S: serde::Serializer>(_: &(), s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(USAGE_CURRENCY)
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct UsageView {
    /// The UTC-day metering bucket this response aggregates: `[start, end)` epoch seconds.
    pub window: UsageWindow,
    /// Freshness marker: the epoch this read was computed at (counters accumulate live).
    pub as_of: u64,
    /// The denomination of every `spend_micros` in this response (`USAGE_CURRENCY`, currently
    /// `"USD"`). A single-const source of truth so removal is one line. Emitted only here.
    #[serde(serialize_with = "serialize_usage_currency")]
    #[cfg_attr(feature = "openapi-schema", schemars(with = "String"))]
    pub currency: (),
    pub total: UsageBreakdown,
    /// Per-(model, provider) aggregation: cost attribution by model (the FinOps unit).
    pub by_model: Vec<ModelUsageView>,
    /// Per-key aggregation (same raw-split shape). CAPPED at the top 1000 rows by spend (the
    /// FinOps-relevant ordering); `by_key_truncated` says the cap fired, never a silent cut.
    pub by_key: Vec<KeyUsageView>,
    /// True when `by_key` was truncated to the cap (a deployment with more active keys than the
    /// cap). `by_model` is never capped (bounded by the configured model fleet).
    pub by_key_truncated: bool,
    /// The summed remainder BEYOND the `by_key` cap, present exactly when `by_key_truncated`, so
    /// every unit of consumption is attributable at least to "others" (FinOps completeness:
    /// `total == sum(by_key) + others`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub others: Option<UsageBreakdown>,
}

/// A metering window: `[start, end)` epoch seconds.
#[derive(Debug, Clone, Copy, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct UsageWindow {
    pub start: u64,
    pub end: u64,
}

/// The raw consumption counts + the derived spend estimate: the one shape shared by `total`,
/// `by_model` rows, and `by_key` rows, so a consumer writes ONE aggregation reader.
#[derive(Debug, Clone, Copy, Default, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct UsageBreakdown {
    /// Uncached input tokens (normalized additive-cache convention).
    pub tokens_input: u64,
    pub tokens_output: u64,
    pub tokens_cache_read: u64,
    pub tokens_cache_creation: u64,
    pub requests: u64,
    /// Busbar's derived cost estimate in MICRO-units of the ABSTRACT cost unit (1e-6 unit -
    /// integer math, sub-cent precise, no float drift), recomputed at read time from the raw token
    /// split x the operator's CURRENT per-model rate card. Busbar attaches no currency - the rate
    /// card's numbers are whatever unit the operator priced in; display/denomination is entirely
    /// the consumer's concern. A consumer with its own per-model catalog recomputes from the raw
    /// token split instead.
    pub spend_micros: i64,
}

/// One (model, provider) row of the per-model aggregation.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct ModelUsageView {
    pub model: String,
    pub provider: String,
    #[serde(flatten)]
    pub usage: UsageBreakdown,
}

/// One key's row of the per-key aggregation: the key id/name (never the secret) + its counts.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct KeyUsageView {
    pub id: String,
    /// The key's display name; `None` when the key was deleted after metering accumulated (history
    /// outlives the key; the id still attributes it).
    pub name: Option<String>,
    #[serde(flatten)]
    pub usage: UsageBreakdown,
}

// The SCHEMA-ONLY mirror of `GET /keys/{id}/usage`, whose handler builds an ad-hoc
// `serde_json::json!({…})` body: it exists so the generator can emit a typed `$ref`, is never
// serialized at runtime, and is compiled only under the CI-only `openapi-schema` feature — exactly
// as it was in the admin contract's `schema` module, which now names it from here.
#[cfg(feature = "openapi-schema")]
#[allow(dead_code)]
mod schema_only {
    use schemars::JsonSchema;
    use serde::Serialize;

    /// `GET /keys/{id}/usage`: the key's all-time attribution counters (a 1.5.0 key bucket accrues in
    /// the `total` window; limits live on the bound group's own windows) plus the fraction of the
    /// tightest `requests`/`tokens` limit across the group chain remaining (`null` = no such limit).
    #[derive(Serialize, JsonSchema)]
    pub struct KeyMeteringView {
        pub id: String,
        /// Always `"total"` (the key attribution window).
        pub budget_period: String,
        /// Always `0` (the all-time window start).
        pub window_start: u64,
        pub as_of: u64,
        /// The bound `groups:` entry (`null` = unlimited key).
        pub group: Option<String>,
        pub spend_cents: i64,
        pub tokens: u64,
        pub requests: u64,
        pub rate_headroom: Option<f64>,
    }
}

#[cfg(feature = "openapi-schema")]
pub use schema_only::KeyMeteringView;
