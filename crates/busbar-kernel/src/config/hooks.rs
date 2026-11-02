// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::{Deserialize, Serialize};

use super::groups::GroupCfg;
use super::pools::{STRATEGY_CHEAPEST, STRATEGY_FASTEST, STRATEGY_LEAST_BUSY, STRATEGY_USAGE};
use super::PolicyOnError;

/// One entry in the top-level `hooks:` NAMED-DEFINITION map (1.5.3). The map KEY is the hook
/// INSTANCE id (the name a pool or the all-pools list references); this value says which plugin backs
/// it and how it is scoped. The SAME `module` may back MULTIPLE named hooks (e.g. `pii-eng` and
/// `pii-all`, same module, different `groups:`) — the name is the instance, the module is just the
/// plugin. `groups:`/`phase:` are the SELECTION axes: a hook fires only for callers in its `groups:`
/// scope, at the pipeline stages in its `phase:` list. The remaining fields are the existing hook
/// role/projection vocabulary (`kind`, `prompt`, `on_error`, …). `deny_unknown_fields`: a typo'd key
/// fails boot, never a silent no-op. Converted to a runtime [`HookCfg`] registry entry by
/// busbar-core's `hook_cfg_from_def` (`module:` → `plugin:`); `groups:`/`phase:` carry onto the
/// `HookCfg`.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookDefCfg {
    /// The `kind: hook` PLUGIN backing this named hook (by signed-manifest name/alias). REQUIRED,
    /// non-empty; an unresolvable/wrong-kind reference is a fail-closed plugin-preflight error.
    pub module: String,
    /// The module's own opaque settings (busbar never interprets them; pushed to the plugin via
    /// `configure`).
    #[serde(default)]
    pub settings: serde_json::Map<String, serde_json::Value>,
    /// SCOPE: the caller groups this hook fires for. Omit or `[]` = ALL callers. A USER is a leaf
    /// group (e.g. `user:bob`); membership walks the `groups:` tree (self OR any ancestor).
    #[serde(default)]
    pub groups: Vec<String>,
    /// PHASE: the pipeline stages this hook fires at, generalizing the tap's single `at:` value to a list. An omitted `phase:` means only the four fixed [`CORE_HOOK_PHASES`], never every future stage. A named definition carries no legacy `at:`, and the resolved set is exposed as `fires_at` through [`HookCfg::resolved_stages`].
    ///
    ///
    ///
    ///
    ///
    #[serde(default)]
    pub phase: Vec<HookStage>,
    /// The hook's MODE: `gate` (fire-and-wait) or `tap` (fire-and-forget). Default `gate` (a named
    /// hook attached to a pool is a decision point by default).
    #[serde(default)]
    pub kind: Option<HookKind>,
    /// Gate decision deadline in ms (default 1).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Gate failure posture (`reject` | `nothing` | named fallback chain). Default `nothing`.
    #[serde(default)]
    pub on_error: Option<OnErrorCfg>,
    /// Gate restrict empty-intersection behavior.
    #[serde(default)]
    pub on_empty: Option<PolicyOnError>,
    /// PROMPT access grant (`no` | `ro` | `rw`).
    #[serde(default)]
    pub prompt: Option<PromptAccess>,
    /// Caller-identity access grant (`no` | `ro`).
    #[serde(default)]
    pub user: Option<UserAccess>,
    /// Ordering key (default 0).
    #[serde(default)]
    pub priority: Option<u16>,
}

pub type HookDefs = indexmap::IndexMap<String, HookDefCfg>;

/// A structured `on_error:` value: a reserved keyword stays BARE
/// (`nothing` | `weighted` | `reject` | `first`); a fallback-hook reference is `{ hook: <name> }`.
#[derive(Debug, Clone, PartialEq)]
pub enum OnErrorCfg {
    /// One of the reserved terminals (see [`on_error_terminal`]).
    Terminal(String),
    /// A fallback hook reference.
    Hook(String),
}

impl OnErrorCfg {
    pub fn as_name(&self) -> &str {
        match self {
            OnErrorCfg::Terminal(s) | OnErrorCfg::Hook(s) => s,
        }
    }
}

impl<'de> Deserialize<'de> for OnErrorCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct HookRefBody {
            hook: String,
        }

        let value = serde_yaml::Value::deserialize(deserializer)?;
        match value {
            serde_yaml::Value::String(word) => {
                if on_error_terminal(&word).is_some() {
                    Ok(OnErrorCfg::Terminal(word))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "on_error keyword '{word}' is not one of the reserved terminals \
                         (nothing | weighted | reject | first); a fallback HOOK is referenced \
                         structured: `on_error: {{ hook: {word} }}`"
                    )))
                }
            }
            v @ serde_yaml::Value::Mapping(_) => {
                let body: HookRefBody =
                    serde_yaml::from_value(v).map_err(serde::de::Error::custom)?;
                if body.hook.trim().is_empty() {
                    return Err(serde::de::Error::custom(
                        "on_error: { hook: … } must name a non-empty hook",
                    ));
                }
                Ok(OnErrorCfg::Hook(body.hook))
            }
            _ => Err(serde::de::Error::custom(
                "on_error is a bare terminal (nothing | weighted | reject | first) or a \
                 structured hook reference `{ hook: <name> }`",
            )),
        }
    }
}

/// A hook's MODE — the `kind:` key. A hook is one thing; `tap`/`gate` just say whether busbar waits
/// for a reply. `tap` = fire-and-forget (watch). `gate` = fire-and-wait (decide: nothing / reject /
/// restrict / order / rewrite). Only a gate can influence dispatch; a gate named in a pool's `hooks:`
/// list must be `kind: gate`.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HookKind {
    Tap,
    Gate,
}

/// A hook's PROMPT access grant (`prompt:`) — the trust ladder for request content, monotonic
/// `no ⊂ ro ⊂ rw`. DEFAULT `no` (shape-only; no prompt text leaves the process). `ro` sends the
/// prompt for READ-ONLY inspection (PII screening, guardrails, audit). `rw` additionally lets a GATE
/// return a `rewrite` arm that mutates the body (compression, redaction) — rewrite REQUIRES read, so
/// it is the top rung of the SAME ladder, not a separate flag. Immutable after registration.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PromptAccess {
    #[default]
    No,
    Ro,
    Rw,
}

impl PromptAccess {
    pub fn sends_prompt(self) -> bool {
        !matches!(self, PromptAccess::No)
    }

    pub fn can_rewrite(self) -> bool {
        matches!(self, PromptAccess::Rw)
    }
}

/// A hook's caller-IDENTITY access grant (`user:`). `no` (default) = no identity in the payload; `ro`
/// = the governance key id/name (NEVER the secret) + the body end-user field. No `rw`: identity is
/// established by the auth plugin and hooks never rewrite it. Immutable after registration.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UserAccess {
    #[default]
    No,
    Ro,
}

impl UserAccess {
    pub fn sends_user(self) -> bool {
        matches!(self, UserAccess::Ro)
    }
}

/// The pipeline stage a TAP observes (`at:`). Parsed now; the seam that fires taps at each stage
/// lands in a later slice. Inert on a gate.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HookStage {
    Request,
    Candidate,
    Routing,
    Response,
}

impl HookStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            HookStage::Request => "request",
            HookStage::Candidate => "candidate",
            HookStage::Routing => "routing",
            HookStage::Response => "response",
        }
    }
}

pub const ALL_HOOK_STAGES: &[HookStage] = &[
    HookStage::Request,
    HookStage::Candidate,
    HookStage::Routing,
    HookStage::Response,
];

pub const CORE_HOOK_PHASES: &[HookStage] = &[
    HookStage::Request,
    HookStage::Candidate,
    HookStage::Routing,
    HookStage::Response,
];

pub fn default_on_error() -> String {
    ON_ERROR_NOTHING.to_string()
}

pub const ON_ERROR_WEIGHTED: &str = "weighted";
pub const ON_ERROR_REJECT: &str = "reject";
pub const ON_ERROR_FIRST: &str = "first";

pub const ON_ERROR_NOTHING: &str = "nothing";

pub fn on_error_terminal(name: &str) -> Option<PolicyOnError> {
    match name {
        ON_ERROR_WEIGHTED | ON_ERROR_NOTHING => Some(PolicyOnError::Weighted),
        ON_ERROR_REJECT => Some(PolicyOnError::Reject),
        ON_ERROR_FIRST => Some(PolicyOnError::First),
        _ => None,
    }
}

pub const RESERVED_HOOK_NAMES: &[&str] = &[
    ON_ERROR_WEIGHTED,
    ON_ERROR_REJECT,
    ON_ERROR_FIRST,
    ON_ERROR_NOTHING,
    STRATEGY_CHEAPEST,
    STRATEGY_FASTEST,
    STRATEGY_LEAST_BUSY,
    STRATEGY_USAGE,
    "tokens",
];

pub fn is_reserved_hook_name(name: &str) -> bool {
    RESERVED_HOOK_NAMES.contains(&name) || (!name.is_empty() && name == super::operator_provider())
}

pub const FROZEN_HOOK_NAME_WORD_SPACE: &[&str] = &[
    "cheapest",
    "fastest",
    "first",
    "least_busy",
    "nothing",
    "reject",
    "tokens",
    "usage",
    "weighted",
];

/// A named entry in the top-level `hooks:` registry — a single hook (tap or gate) and the `kind: hook`
/// PLUGIN that backs it. A hook is now a dlopen plugin under the hybrid ABI (the 1.5.0 retirement of
/// the out-of-process socket/webhook transport): exactly ONE `plugin:` reference names the signed
/// plugin (by manifest name/alias), loaded like a store/auth plugin. Shared runtime knobs carry over
/// from the 1.2.1 policy block. A pool references a GATE by name via its `hook:` key; global taps/gates
/// via `global_hooks:` (or inline `global: true`).
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HookCfg {
    /// The hook's MODE: `tap` (fire-and-forget) or `gate` (fire-and-wait, returns a reply arm).
    pub kind: HookKind,

    /// The `kind: hook` PLUGIN backing this hook, by signed-manifest name or alias — resolved against
    /// the same validated plugin registry that store/auth plugins load through (fail-closed: an
    /// unresolvable or wrong-kind reference refuses to boot). This REPLACES the retired
    /// `socket`/`webhook` out-of-process transports: a hook now runs in-process behind the frozen
    /// plugin ABI. Required and non-empty.
    ///
    /// FREEZE BLOCKER: the WIRE name is `module`, matching the locked grammar's one word for "which
    /// plugin backs this instance" everywhere (`hooks.<n>.module`, `identity-providers.<n>.module`,
    /// `export.<n>.module`, `store.module`). The Rust field keeps the older `plugin` spelling only
    /// because it is referenced at ~100 internal sites; nothing user-facing says `plugin:` any more.
    /// 1.6.0 owner rule: a 1.5.5 config/overlay must still parse byte-for-byte, so `alias = "plugin"`
    /// is RESTORED as READ-ONLY back-compat — a config overlay written by an earlier build still
    /// loads. Serialization always emits `module`.
    #[serde(rename = "module", alias = "plugin")]
    pub plugin: String,

    /// Hard wall-clock deadline for a gate decision, in milliseconds (default 1). An in-process gate
    /// is microseconds; RAISE it for a hook plugin that does real work (a DB/network/model call).
    /// On timeout the decision is coerced to `on_error` and the request proceeds.
    #[serde(default = "default_policy_timeout_ms")]
    pub timeout_ms: u64,
    /// Fallback when a GATE times out/errors/saturates — a NAME resolved against the same registry
    /// as any hook (default `weighted` = proceed as busbar normally would). Reserved terminals:
    /// `nothing` (do not participate — a failing gate drops out and cannot displace another gate's
    /// verdict; the posture for non-routing gates like compressors) | `weighted` (same behavior,
    /// named as the ordering floor) | `reject` (fail closed — security gates set this) | `first`.
    /// Any other name is a
    /// fallback HOOK (a built-in ranking strategy or another gate) fired when this one fails; its
    /// own `on_error` chains further, and boot validation proves every chain terminates (unknown
    /// names, taps, and cycles are boot errors).
    #[serde(default = "default_on_error")]
    pub on_error: String,
    /// PROMPT access grant: `no` (default, shape-only) | `ro` (read prompt content) | `rw` (read +
    /// may `rewrite` the body). The single trust ladder for request content; `rw` is how a gate is
    /// granted rewrite. Immutable after registration. `rw` on a tap is a config error.
    #[serde(default)]
    pub prompt: PromptAccess,
    /// Caller-IDENTITY access grant: `no` (default) | `ro` (governance key id/name — never the secret
    /// — + body end-user field). Enables route-by-who gates. Immutable after registration.
    #[serde(default)]
    pub user: UserAccess,
    /// Hook ordering key (default 0). Orders the rewrite transform chain and the phase-2 decision
    /// chain (which reject surfaces; which order is "last" — see design-hooks-v2). Ascending;
    /// ties keep globals before pool gates, then config order.
    #[serde(default)]
    pub priority: u16,
    /// GATE restrict empty-intersection behavior (default `reject`, fail-closed; `weighted` is the
    /// advisory escape — the gate's restriction is skipped). Applied per gate in the phase-2
    /// reconcile.
    #[serde(default)]
    pub on_empty: Option<PolicyOnError>,
    /// TAP observation stage (`request`/`route`/`attempt`/`completion`; unset = `request`).
    /// `request` observes the (post-rewrite) request; `route` the post-reconcile candidate set;
    /// `attempt` every dispatch attempt (the failover story); `completion` the outcome — including
    /// the SYNTHETIC rejected completion, so audit taps see denials. Inert on a gate.
    /// 1.6.0 owner rule: a 1.5.5 hook definition carrying the legacy single `at:` key must still
    /// parse and behave byte-for-byte, so this field is RESTORED (`fires_at_stage` precedence
    /// below).
    #[serde(default)]
    pub at: Option<HookStage>,
    /// OPAQUE settings map pushed to the hook via the `configure` op: sent to the plugin at
    /// load and re-pushed (commit-on-ack) by `PATCH /api/v1/admin/hooks/{name}/settings`. Busbar
    /// never interprets the contents.
    #[serde(default)]
    pub settings: serde_json::Map<String, serde_json::Value>,
    /// The "decision observability" DECLARED-SIGNAL surface: the typed
    /// [`busbar_contract::signal::Signal`] catalog entries this hook wants computed + projected onto its own
    /// wire payload. Default empty (no signal beyond the always-on core fields) — the zero-cost
    /// default this whole design protects. Parsed via `Signal`'s own `#[serde(rename_all =
    /// "snake_case")]` derive, so an unrecognized name is a BOOT-TIME config error (this struct is
    /// `deny_unknown_fields`; a typo'd catalog name fails closed at parse, never a silent runtime
    /// no-op) — the "plugin references the typed `Signal` constant" contract, expressed here as
    /// the canonical name of that constant rather than a free-typed string a human could misspell
    /// undetected. Every hook's declaration is UNIONED once per config generation into the
    /// process-wide `RequestedSignals` bitmask (`hooks::requested_signals`) that gates every
    /// compute fn — declaring a signal here is necessary AND sufficient for it to start being
    /// computed + projected; nothing else (a code change, a recompile) is required.
    #[serde(default)]
    pub signals: Vec<busbar_contract::signal::Signal>,
    /// Fire on EVERY request — inline sugar for adding this name to `global_hooks:`. Default false.
    #[serde(default)]
    pub global: bool,
    /// Mark this hook as THE default — the base a pool inherits when it names no hook of its own.
    /// REPLACEMENT semantics (unlike `global:`, which is an overlay ON TOP of the base): a `default`
    /// hook becomes the base, so the compiled-in backstop (`weighted`) is not used. Exactly like
    /// `auth: [sso]` means the built-in `tokens` is not loaded. AT MOST ONE hook may set `default:
    /// true` (boot AND every admin apply → error naming both); 0 ⇒ the compiled-in backstop. Only an
    /// ordering hook (one that returns `order`) is a meaningful default. Default false. Resolution:
    /// `hooks::resolve_pool_ordering` gives this hook to every pool whose base is unnamed.
    #[serde(default)]
    pub default: bool,
    /// 1.5.3 named-hook SCOPE: the caller groups this hook fires for. A hook fires only for a request
    /// whose caller belongs to one of these groups (self OR any ancestor in the `groups:` tree — a
    /// USER is a leaf group, e.g. `user:bob`). EMPTY (the default) = ALL callers (unscoped). Populated
    /// from the top-level `hooks:` definition map's `groups:` key; consulted at firing time by
    /// [`caller_in_hook_groups`]. Immutable after registration.
    #[serde(default)]
    pub groups: Vec<String>,
    /// 1.5.3 named-hook PHASE set: the pipeline stages this hook fires at. GENERALIZES the single
    /// tap `at:` to a list. EMPTY (the default) falls back to `at:`, which pins exactly one stage and
    /// so preserves 1.5.5 single-stage behavior byte-for-byte; with BOTH omitted the hook fires at
    /// THE FOUR CORE STAGES and only those — the frozen meaning of an omitted `phase:`, see FREEZE
    /// BLOCKER on [`CORE_HOOK_PHASES`]. (`--migrate-config` still writes an EXPLICIT `phase:
    /// [request]` onto a legacy tap that carried neither, so migrating never widens one, but the
    /// legacy `at:` rung stays live so an un-migrated 1.5.5 overlay keeps behaving exactly as it did.)
    /// Consulted by [`HookCfg::fires_at_stage`]. Inert on a gate (gates fire at every decision point).
    #[serde(default)]
    pub phase: Vec<HookStage>,
}

impl HookCfg {
    /// Whether this hook observes at `stage` (freeze blocker — see [`CORE_HOOK_PHASES`]).
    ///
    /// Precedence, frozen (1.6.0 owner rule: 1.5.5 must be felt byte-for-byte, so the legacy single
    /// `at:` rung is RESTORED):
    /// 1. a non-empty `phase:` LIST is authoritative — the hook fires at exactly those stages;
    /// 2. otherwise the legacy single `at:` (the admin-API registration surface still carries it),
    ///    which pins one stage;
    /// 3. otherwise — BOTH omitted — the hook fires at THE FOUR CORE STAGES, and only those. Never
    ///    "every stage that will ever exist": a stage added by a later release is not in
    ///    [`CORE_HOOK_PHASES`], so it cannot retroactively widen a hook that already shipped.
    pub fn fires_at_stage(&self, stage: HookStage) -> bool {
        if !self.phase.is_empty() {
            return self.phase.contains(&stage);
        }
        match self.at {
            Some(at) => at == stage,
            None => CORE_HOOK_PHASES.contains(&stage),
        }
    }

    pub fn resolved_stages(&self) -> Vec<HookStage> {
        ALL_HOOK_STAGES
            .iter()
            .copied()
            .filter(|stage| self.fires_at_stage(*stage))
            .collect()
    }
}

pub fn caller_in_hook_groups(
    caller_group: Option<&str>,
    hook_groups: &[String],
    groups_tree: &std::collections::BTreeMap<String, GroupCfg>,
) -> bool {
    if hook_groups.is_empty() {
        return true;
    }
    let Some(start) = caller_group else {
        return false;
    };
    let mut cursor = Some(start);
    for _ in 0..=groups_tree.len() {
        let Some(name) = cursor else { break };
        if hook_groups.iter().any(|g| g == name) {
            return true;
        }
        cursor = groups_tree.get(name).and_then(|g| g.parent.as_deref());
    }
    false
}

pub const DEFAULT_POLICY_TIMEOUT_MS: u64 = 1;

pub fn default_policy_timeout_ms() -> u64 {
    DEFAULT_POLICY_TIMEOUT_MS
}

#[cfg(test)]
#[path = "tests/hooks.rs"]
mod default_on_error_tests;
