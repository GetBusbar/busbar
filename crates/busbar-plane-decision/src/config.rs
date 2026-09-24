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

use std::collections::{HashMap, HashSet};

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

/// THE ONE WIRE DIALECT THIS PLANE SPEAKS.
///
/// jev is a direct HTTP+JSON passthrough with no translating IR (`plane.rs`'s single
/// `wire_format_names` entry, `PLANE_DECL` in the composition root) — there is no dialect adapter
/// behind it the way the LLM plane's `openai`/`anthropic`/… translators exist. BUSBAR-1.6.0.md #51
/// (OWNER-LOCKED 2026-09-20) rules the resolution/interpretation split explicitly: "the PLANE then
/// interprets the resolved dialect against what it supports: knows it ⇒ use it; doesn't ⇒ FAIL
/// (fail-closed) — e.g. the decisions plane (only jev) handed `anthropic` fails. Dialect validation
/// is the plane's job, never the kernel's." This constant is that knowledge, kept on the plane side
/// of the seam so no kernel file ever spells the literal `"jev"` (#49: the kernel names no plane or
/// transport-protocol string).
pub const JEV_PROTOCOL: &str = "jev";

/// CROSS-REFERENCE VALIDATION for a parsed `decisions:` section, run once the whole document is
/// known (siblings included) — the same moment the pools plane's own model→provider check runs
/// (`config_validate::validate`'s "model … references unknown provider" rule) and the `tools:`
/// plane's own hook-reference check runs (`config/mod.rs`'s `resolve`). This function is PURE and
/// kernel-free by construction (the dep wall, DECISIONS #40, forbids this crate naming a kernel
/// type), so the composition root — the one place allowed to name both this crate's types and the
/// kernel's (`busbar/src/root/plane_decision.rs`) — hands it borrowed, already-resolved primitives:
///
///   * `provider_protocols`: every configured `providers:` entry's NAME mapped to its RESOLVED
///     `protocol` (post catalog-merge, the same value `providers.<p>.protocol` resolves to
///     everywhere else) — so a `decisions.models.<m>.provider` reference is checked for EXISTENCE
///     and, when it exists, its dialect is checked against [`JEV_PROTOCOL`] (#51).
///   * `known_hooks`: every NAME defined in the top-level `hooks:` map — so a `decisions.hooks`
///     reference is checked for existence, exactly as `tools.hooks`/`tools.<server>.hooks` are.
///
/// Returns one error string per violation (never panics, never short-circuits on the first one —
/// an operator with several mistakes sees all of them, matching every other collector in
/// `config_validate`). Each message NAMES THE KEY PATH (`decisions.models.<m>.provider`,
/// `decisions.hooks`) and the valid choices, in the same style as the existing
/// `config_validate::validate` refusals it mirrors ("model '{}' references unknown provider '{}'").
pub fn validate_cross_refs(
    section: &DecisionsSection,
    provider_protocols: &HashMap<String, String>,
    known_hooks: &HashSet<String>,
) -> Vec<String> {
    let mut errors = Vec::new();

    let mut provider_names: Vec<&str> = provider_protocols.keys().map(String::as_str).collect();
    provider_names.sort_unstable();

    let mut model_names: Vec<&str> = section.models.keys().map(String::as_str).collect();
    model_names.sort_unstable();
    for model_name in model_names {
        let model_cfg = &section.models[model_name];
        match provider_protocols.get(&model_cfg.provider) {
            None => {
                errors.push(format!(
                    "decisions.models.{model_name}.provider names '{}', which is not defined in \
                     the top-level `providers:` map. Valid providers: {}. Define it there, or fix \
                     the reference.",
                    model_cfg.provider,
                    if provider_names.is_empty() {
                        "(none configured)".to_string()
                    } else {
                        provider_names.join(", ")
                    }
                ));
            }
            Some(protocol) if protocol != JEV_PROTOCOL => {
                errors.push(format!(
                    "decisions.models.{model_name}.provider '{}' resolves to protocol '{protocol}', \
                     but the decision plane speaks only '{JEV_PROTOCOL}' (jev is a direct HTTP+JSON \
                     passthrough with no translating IR — BUSBAR-1.6.0.md #51: an unknown dialect \
                     FAILS CLOSED rather than boot). Point decisions.models.{model_name} at a \
                     provider whose protocol resolves to '{JEV_PROTOCOL}', or remove this model.",
                    model_cfg.provider
                ));
            }
            Some(_) => {}
        }
    }

    let mut hook_names: Vec<&str> = known_hooks.iter().map(String::as_str).collect();
    hook_names.sort_unstable();
    for hook in &section.hooks {
        if !known_hooks.contains(hook) {
            errors.push(format!(
                "decisions.hooks names '{hook}', which is not defined in the top-level `hooks:` \
                 map. Valid hooks: {}. Define it there, or remove the reference.",
                if hook_names.is_empty() {
                    "(none configured)".to_string()
                } else {
                    hook_names.join(", ")
                }
            ));
        }
    }

    errors
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
