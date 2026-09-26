// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The model-serving config SHAPE, as neutral vocabulary.
//!
//! [`ModelCfg`] is the per-entry shape a model-serving plane's `models:` map deserializes into —
//! `pools.models.<name>` (the LLM plane) and `decisions.models.<name>` (the jev decision plane,
//! DECISIONS #47) both reuse this ONE type rather than each inventing a look-alike. Before this
//! module existed it lived kernel-side (`busbar_kernel::config::providers::ModelCfg`), which meant
//! any plane naming it also named the kernel — a violation of DECISIONS #40's dep-wall (a plugin
//! crate's entire workspace dependency closure is `busbar-contract` and nothing else). It moved here
//! verbatim (DECISIONS #38: `busbar-contract` is the one contract/ABI crate holding the neutral
//! vocab every side of the seam shares) — same field names, same order, same types, same serde
//! attributes, so no config key and no wire byte changed. `busbar-kernel` re-exports it at its
//! historical `config::providers::ModelCfg` / `config::ModelCfg` paths so every existing kernel-side
//! caller keeps compiling unchanged.

use serde::Deserialize;

/// A single model-serving entry: what a `models:` map's value deserializes into.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ModelCfg {
    /// Lifetime request cap for this model entry. `-1` (the default, via [`neg1`]) means unlimited.
    #[serde(default = "neg1")]
    pub max_requests: i64,
    /// The `providers:` entry this model is served through — the transport-agnostic connection
    /// (base_url, error_map, credential ref).
    pub provider: String,
    /// Per-lane concurrency limiter: the max number of in-flight requests admitted to this lane at
    /// once (excess requests park on the lane's semaphore until a slot frees or the request budget
    /// expires). OPTIONAL — omitted means UNBOUNDED (no concurrency cap), the same opt-in-limiter
    /// posture as `max_requests` (default -1 = unlimited). Set a positive integer to opt into a cap;
    /// `0` is rejected at boot (`config_validate`) as a lane that admits nothing. Unbounded is
    /// realized as a `Semaphore` seeded with `tokio::sync::Semaphore::MAX_PERMITS` (see main.rs) —
    /// "effectively unbounded"; a literal `usize::MAX` would panic (tokio caps permits at
    /// `MAX_PERMITS`).
    #[serde(default)]
    pub max_concurrent: Option<usize>,
    /// Default max output tokens injected when a cross-protocol translation targets a backend that
    /// REQUIRES `max_tokens` (Anthropic Messages) and the source request omitted it (legal for
    /// OpenAI). Unset falls back to `proto::DEFAULT_MAX_TOKENS`. Must be > 0 when set.
    #[serde(default)]
    pub default_max_tokens: Option<u32>,
    /// Optional upstream model name override. When set, this value is sent to the provider as the
    /// model identifier in the request body and URL path, instead of the config key. Useful when
    /// the provider expects a different model string (e.g. Bedrock model IDs).
    #[serde(default)]
    pub upstream_model: Option<String>,
    /// Per-ATTEMPT time-to-response-headers cap (ms). If this lane has not returned response headers
    /// within the budget, the attempt is abandoned (transient → breaker) and the request FAILS OVER
    /// to the next member — the hang detector. Model-level default; a pool member's
    /// `attempt_timeout_ms` overrides it per workload. Absent = bounded only by the request budget.
    #[serde(default)]
    pub attempt_timeout_ms: Option<u64>,
    /// Operator declaration that THIS model accepts reasoning/thinking request parameters
    /// (Anthropic `thinking`, Gemini `thinkingConfig`, OpenAI `reasoning_effort`). Capability is
    /// per-MODEL, not per-provider (Sonnet takes `thinking`, Haiku 400s on it), and busbar keeps no
    /// model database — this flag is the operator asserting what they deployed, in the same family
    /// as `context_max`/`cost_per_mtok`. When absent/false, a cross-protocol reasoning ask is
    /// DROPPED at the seam with a warn (never sent, so a non-reasoning model can never 400 from
    /// translation). A pool member's `reasoning` overrides this per pool. Same-protocol passthrough
    /// is byte-exact and ignores the flag.
    #[serde(default)]
    pub reasoning: Option<bool>,
    /// Operator declaration that THIS model accepts prompt-cache markers on dialects where the
    /// marker is model-gated (Bedrock Converse `cachePoint`: Claude accepts it, Amazon Nova
    /// hard-rejects it with 400 "extraneous key"). Same family as `reasoning` — busbar keeps no
    /// model database, the operator asserts what they deployed. When absent/false, cross-protocol
    /// `cache_control` breakpoints headed to such a dialect are DROPPED at the seam with a warn
    /// (the request proceeds uncached — fail-safe, never a translation-induced 400). Dialects
    /// whose cache form is universally accepted (Anthropic `cache_control`) ignore this flag, as
    /// does same-protocol passthrough (byte-exact).
    #[serde(default)]
    pub prompt_caching: Option<bool>,
}

/// The serde default for `ModelCfg::max_requests` (`-1` = unlimited).
pub fn neg1() -> i64 {
    -1
}

/// `upstream_credentials:` — the OTHER reserved member every model-serving section carries next to
/// [`ModelCfg`], and it arrived here for the same reason and by the same route. It lived in
/// `busbar-api`, which meant the one pure plane that reused it (`busbar-plane-decision`, the jev
/// decision plane) had to name `busbar-api` in its manifest — the only pure plane that did — and
/// that edge dragged `sha2 -> cpufeatures -> libc` into a plane's dependency closure, which the
/// transitive source denylist bans outright. The type itself needs none of that: two unit variants
/// and two serde derives. It moved here verbatim — same name, same variants, same order, same serde
/// attributes, so no config key and no wire byte changed — and `busbar-api` re-exports it at its
/// historical `crate::config::UpstreamCreds` path so every kernel-side caller keeps compiling
/// unchanged, exactly as `busbar-kernel` re-exports [`ModelCfg`]. The value this buys is measured,
/// not asserted: `cargo xtask gate denylist` names the offending path in full.
/// The UPSTREAM-credential mode (`upstream_credentials:`) — whose credential reaches the provider.
/// DISTINCT from authentication (which auth module, if any, ran at the front door — that's the
/// `auth.chain`): `Own` (default) signs the upstream call with busbar's configured lane key;
/// `Passthrough` forwards the CALLER's credential upstream. A proto writer uses THIS to resolve an
/// otherwise-ambiguous credential scheme to the single native header the caller's real client
/// produces. (Split out of the old `AuthMode`, now its own config key — `AuthMode` is gone.)
// `Serialize` is additive and is what lets a config section carrying this field be projected back
// to a raw definition document — the base half of the config overlay's per-entry MERGE
// (`NamedMapSection::entry_as_document`). A section whose entry cannot round-trip to a document
// cannot be patched per field, only replaced wholesale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamCreds {
    /// Sign the upstream call with this deployment's OWN configured lane credential. The default.
    #[default]
    Own,
    /// Forward the CALLER's credential upstream unchanged.
    Passthrough,
}
