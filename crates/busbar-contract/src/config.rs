// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The model-serving config SHAPE, as neutral vocabulary.

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
    /// THE MODEL'S DIALECT OVERRIDE (#51): the wire protocol this model is spoken in when it
    /// differs from its provider's `protocol`; absent = the provider's. The plane that serves the
    /// model resolves model to dialect itself (THE DESIGN section 4); the kernel checks no dialect.
    /// Appended last, so the refusal of an unknown member lists it last.
    #[serde(default)]
    pub protocol: Option<String>,
}

/// The serde default for `ModelCfg::max_requests` (`-1` = unlimited).
pub fn neg1() -> i64 {
    -1
}

/// `upstream_credentials:` — the OTHER reserved member every model-serving section carries next to
/// [`ModelCfg`], and it arrived here for the same reason and by the same route. It lived in
/// `busbar-api`, which meant the one pure plane that reused it (the jev decisions
/// plane) had to name `busbar-api` in its manifest — the only pure plane that did — and
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamCreds {
    /// Sign the upstream call with this deployment's OWN configured lane credential. The default.
    #[default]
    Own,
    /// Forward the CALLER's credential upstream unchanged.
    Passthrough,
    /// Require a host-held connection belonging to this authenticated caller.
    Connection,
}

pub mod dialect_styles;

/// Why [`outbound_owner`] found no single owner for an outbound style word (IF §12.10 item 3, §12.18).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerRefusal {
    /// No admitted auth plugin declares the word as a D_OUTBOUND_STYLE item.
    None,
    /// Several do, in admission order.
    Several(Vec<Box<str>>),
}

impl OwnerRefusal {
    /// Core's CONFIG text for the binding `binding` (operator vocabulary, e.g. `auth.<p>-outbound`).
    #[must_use]
    pub fn text(&self, binding: &str, word: &str) -> String {
        match self {
            Self::None => format!(
                "`{binding}`: no admitted auth plugin implements the outbound style `{word}`; write `module:`"
            ),
            Self::Several(owners) => format!(
                "`{binding}`: several admitted auth plugins implement the outbound style `{word}`: {}; write `module:`",
                owners.join(", ")
            ),
        }
    }
}

/// The owner of an outbound style word: the unique admitted auth plugin (identity, in admission order) whose
/// D_OUTBOUND_STYLE items contain `word`. The one pure function K9's `resolve_styles` and K6's implicit
/// bindings share (IF §12.18); core keeps no style-to-plugin table.
pub fn outbound_owner<'s, 'w, S: AsRef<[&'w str]>>(
    styles: &[(&'s str, S)],
    word: &str,
) -> Result<&'s str, OwnerRefusal> {
    let mut owners = styles
        .iter()
        .filter(|(_, words)| words.as_ref().iter().any(|w| *w == word))
        .map(|(identity, _)| *identity);
    match (owners.next(), owners.next()) {
        (Some(only), None) => Ok(only),
        (None, _) => Err(OwnerRefusal::None),
        (Some(first), Some(second)) => Err(OwnerRefusal::Several(
            [first, second]
                .into_iter()
                .chain(owners)
                .map(Box::from)
                .collect(),
        )),
    }
}

#[cfg(test)]
mod outbound_owner_tests {
    use super::{outbound_owner, OwnerRefusal};

    /// Guards the unique-owner rule K9 and K6 share: zero or several owners refuse with core's text.
    #[test]
    fn the_owner_is_the_unique_declaring_plugin() {
        let styles: [(&str, &[&str]); 2] =
            [("a", &["bearer", "api-key"]), ("b", &["oauth-connection"])];
        assert_eq!(outbound_owner(&styles, "api-key"), Ok("a"));
        assert_eq!(
            outbound_owner(&styles, "jwt-bearer"),
            Err(OwnerRefusal::None)
        );
        let twice: [(&str, &[&str]); 2] = [("a", &["bearer"]), ("b", &["bearer"])];
        let refused = outbound_owner(&twice, "bearer").unwrap_err();
        assert_eq!(refused, OwnerRefusal::Several(vec!["a".into(), "b".into()]));
        assert_eq!(
            refused.text("auth.p-outbound", "bearer"),
            "`auth.p-outbound`: several admitted auth plugins implement the outbound style `bearer`: a, b; write `module:`"
        );
        assert_eq!(
            OwnerRefusal::None.text("auth.p-outbound", "jwt-bearer"),
            "`auth.p-outbound`: no admitted auth plugin implements the outbound style `jwt-bearer`; write `module:`"
        );
    }
}
