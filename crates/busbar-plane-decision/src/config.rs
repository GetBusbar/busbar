//! The typed shape of the `decisions:` config section.
//!
//! The config-model ruling (owner, 2026-09-19, the jev v5 dictator sign-off) is explicit about
//! this section's shape: `DecisionsSection { models: Map<String, ModelCfg>, hooks,
//! upstream_credentials }`, reusing `ModelCfg` VERBATIM rather than inventing a second model type —
//! the uniform model-serving map applies to `pools` and `decisions` alike (per the ruling's
//! correction on the uniform `models` schema). This
//! is greenfield: `decisions` never shipped a `1.5.5` shape, so there is no migration to honor and
//! no byte-identity floor to hold — the section either parses or the whole document is refused, the
//! same fail-closed posture `deny_unknown_fields` gives every other section.
//!
//! `ModelCfg` is [`busbar_contract::config::ModelCfg`] (DECISIONS #40/#38 — moved out of
//! `busbar-kernel` so a plugin crate reusing it need not also depend on the kernel; see that
//! module's own doc). Same type, same field names, same wire bytes — only the module path moved.
//!
//! ## Canonical shape (from the ruling)
//!
//! ```yaml
//! decisions:
//!   models:
//!     jev: { provider: typesafe, upstream_model: jev-1.13.0 }
//! ```
//!
//! `jev` here is the busbar-facing model name a caller targets; `provider` names a `providers:`
//! entry (the transport-agnostic connection — base_url, error_map, credential ref); `upstream_model`
//! is the real string sent to the provider, omitted meaning "send the key verbatim".
//!
//! ## Reserved sibling keys
//!
//! `hooks` and `upstream_credentials` are the two reserved members every model-serving section
//! carries alongside its `models` map (the ruling's R4/R-C: the shared pair stays `{hooks,
//! upstream_credentials}`, with `models` itself reserved only inside model-serving planes). `hooks`
//! is a list of names into the top-level `hooks:` registry — this crate carries no `HookCfg` type of
//! its own (that lives in busbar-core, which this crate may not depend on), so the reserved member
//! is typed as the list of names a plane names its hooks by, exactly as `busbar-plane-a2a`'s own
//! `CONFIG_SCHEMA` declares its `hooks` member. `upstream_credentials` reuses
//! [`busbar_contract::config::UpstreamCreds`] verbatim — the same type `PoolCfg` already names for
//! its own per-section override — rather than a second `own`/`passthrough` enum.
//!
//! That type used to live in the legacy plugin-facing crate, and naming it was the ONLY reason this
//! plane depended on that crate — the only one of the five that did. The dependency was not free:
//! it reached banned source through `sha2 -> cpufeatures -> libc`, which the transitive source
//! denylist forbids any pure plugin kind, and which went unreported for as long as this crate was
//! in no kind list. The type moved to the contract beside `ModelCfg`, so both reserved shapes now
//! arrive from the one crate a plugin may name, and the edge is deleted rather than waived.

use std::collections::HashMap;

use serde::Deserialize;

use busbar_contract::config::{ModelCfg, UpstreamCreds};

/// The `decisions:` section, typed.
///
/// `deny_unknown_fields`: a typo'd top-level member of `decisions:` must fail boot, not be silently
/// ignored — the same posture every other section in this workspace takes.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct DecisionsSection {
    /// The busbar-facing model names this deployment exposes on the decision plane, each bound to a
    /// provider connection. REQUIRED-shaped in practice (an empty map means no `jev:` target is
    /// reachable, which is a valid but inert configuration rather than a refusal).
    #[serde(default)]
    pub models: HashMap<String, ModelCfg>,
    /// The reserved hook-name list every model-serving section carries. Each entry names an
    /// existing top-level `hooks:` registration; validating that the name resolves and that the
    /// hook it resolves to is one this plane may run is a boot-time concern this crate does not
    /// perform standalone (it has no `HookCfg` to check a kind against) — the same posture
    /// `busbar-plane-a2a`'s own reserved `hooks` member takes.
    #[serde(default)]
    pub hooks: Vec<String>,
    /// The reserved upstream-credential override: `own` (this deployment's own credential, the
    /// default) or `passthrough` (relay the caller's). `None` means inherit whatever the
    /// deployment-wide default is.
    #[serde(default)]
    pub upstream_credentials: Option<UpstreamCreds>,
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
