// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `hooks:` config SHAPES: the named DEFINITION entry (`HookDefCfg`), the runtime registry
//! entry (`HookCfg`), the structured `on_error:` value, the mode/access/stage enums, the reserved
//! terminal and strategy vocabulary, and the two pure scope predicates (`fires_at_stage`,
//! `caller_in_hook_groups`). Plain serde data; the definition-to-registry LOWERING and the
//! validation of hook references stay in busbar-core, which re-exports every item here at its
//! historical `config::` path.

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
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first.
    pub settings: serde_json::Map<String, serde_json::Value>,
    /// SCOPE: the caller groups this hook fires for. Omit or `[]` = ALL callers. A USER is a leaf
    /// group (e.g. `user:bob`); membership walks the `groups:` tree (self OR any ancestor).
    #[serde(default)]
    pub groups: Vec<String>,
    /// PHASE: the pipeline stages this hook fires at (generalizes the single tap `at:` to a list).
    /// Omit = THE FOUR CORE STAGES and only those, never "every stage that will ever exist" (the
    /// frozen meaning of an omitted `phase:`, see the FREEZE BLOCKER on [`CORE_HOOK_PHASES`]; this
    /// doc line used to say "all stages", which is the reading that note exists to rule out).
    /// A named definition never carries the legacy `at:`, so the resolved set is readable over the
    /// admin API as `fires_at` (see [`HookCfg::resolved_stages`]).
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

/// The top-level `hooks:` NAMED-DEFINITION map (1.5.3): instance name → [`HookDefCfg`]. Insertion
/// order is preserved so the resolved registry / firing order is deterministic. This REPLACES the
/// removed `global_hooks:` list — a hook is DEFINED here once and REFERENCED by bare name (at the
/// all-pools `pools.hooks:` list or a per-pool `hooks:` list).
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
    /// The flat NAME the existing on_error chain machinery resolves (terminal word or hook name).
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
    /// Whether the prompt projection is built + sent (both `ro` and `rw`).
    pub fn sends_prompt(self) -> bool {
        !matches!(self, PromptAccess::No)
    }
    /// Whether the hook may return a `rewrite` arm (only `rw`).
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
    /// Whether the caller-identity projection is built + sent (`ro`).
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
    /// The ONE wire spelling of a stage, shared by every surface that names one: the serde
    /// representation above, the admin read projection's `at`/`phase`/`fires_at`, and any
    /// diagnostic. Kept as a method rather than re-matched per call site because the admin
    /// projection used to carry its own copy of this mapping, which is exactly how a wire
    /// vocabulary drifts from the one the parser accepts.
    pub const fn as_str(self) -> &'static str {
        match self {
            HookStage::Request => "request",
            HookStage::Candidate => "candidate",
            HookStage::Routing => "routing",
            HookStage::Response => "response",
        }
    }
}

/// EVERY stage this build knows, in pipeline order: the domain [`HookCfg::fires_at_stage`] is asked
/// about when resolving a hook's actual stage set.
///
/// Deliberately a SEPARATE constant from [`CORE_HOOK_PHASES`], not an alias for it, even though the
/// two are byte-identical today. They answer different questions and are frozen to DIVERGE: this one
/// is "which stages exist", which grows with every release that adds one; `CORE_HOOK_PHASES` is
/// "which stages an omitted `phase:` means", which is FROZEN at the four and must never grow (see its
/// FREEZE BLOCKER). Collapsing them would re-introduce the precise defect that freeze note exists to
/// prevent: an added stage would silently join the default set and widen every already-deployed
/// unscoped hook.
///
/// Pinned by `all_hook_stages_lists_every_stage_variant` in the admin hook-stage projection tests.
pub const ALL_HOOK_STAGES: &[HookStage] = &[
    HookStage::Request,
    HookStage::Candidate,
    HookStage::Routing,
    HookStage::Response,
];

/// # FREEZE BLOCKER: THE FROZEN MEANING OF AN OMITTED `phase:`
///
/// **`phase:` omitted means THESE FOUR CORE STAGES — it does NOT mean "every stage that will ever
/// exist".** The distinction is the whole finding: if omission meant "all stages", then adding a
/// tool-invocation stage or an agent-delegation stage in a later release would retroactively make
/// every already-deployed unscoped hook start firing at brand-new points in a brand-new plane —
/// silently widening what an operator signed off on, with no config change and no diagnostic. Pinning
/// the default to this frozen list means a later stage is strictly ADDITIVE: to fire there, a hook
/// must NAME it.
///
/// Two further properties, frozen with it:
///
/// - **`phase:` is PLANE-NEUTRAL.** These four names describe the shape of a request's lifecycle
///   (arrive → choose candidates → dispatch → finish), which every plane shares. A later plane REUSES
///   them; it does NOT re-type `phase:` into a per-plane enum, because a re-typed `phase:` would break
///   every existing hook definition.
/// - **An INAPPLICABLE phase silently does not fire** — it is NOT a config error. A hook named on both
///   `pools:` and (later) `tools:` may legitimately want a phase that only one plane reaches; making
///   that an error would mean an operator could not write one hook definition for two planes, which
///   is precisely the reuse the named-definition pattern exists to enable.
///
/// Pinned by `omitted_phase_is_exactly_the_four_core_stages` in the config tests.
pub const CORE_HOOK_PHASES: &[HookStage] = &[
    HookStage::Request,
    HookStage::Candidate,
    HookStage::Routing,
    HookStage::Response,
];

/// The serde default for a hook's `on_error` — `nothing`: a failing gate
/// DOES NOT PARTICIPATE by default — it cannot steer, and it cannot displace another gate's
/// verdict. Security gates opt into `reject`; ordering gates name `weighted` explicitly.
pub fn default_on_error() -> String {
    ON_ERROR_NOTHING.to_string()
}

/// The RESERVED on_error terminal names — every fallback chain must bottom out on one.
pub const ON_ERROR_WEIGHTED: &str = "weighted";
pub const ON_ERROR_REJECT: &str = "reject";
pub const ON_ERROR_FIRST: &str = "first";
/// The explicit DO-NOT-PARTICIPATE terminal: the failing gate simply drops out of the decision —
/// it cannot steer, and it cannot displace any OTHER gate's verdict (in the concurrent reconcile a
/// non-participating outcome is skipped by every pass). The right posture for a gate whose job is
/// orthogonal to routing (e.g. a compressor): its failure should never reshape traffic. Internally
/// identical to the `weighted` terminal — "didn't participate" and "busbar's normal ordering" are
/// the same behavior — but the NAME teaches the correct mental model.
pub const ON_ERROR_NOTHING: &str = "nothing";

/// Map an `on_error` NAME to its reserved terminal, if it is one. `None` = the name is a fallback
/// hook reference (a ranking strategy or a registry gate), resolved by routing / validated at boot.
pub fn on_error_terminal(name: &str) -> Option<PolicyOnError> {
    match name {
        ON_ERROR_WEIGHTED | ON_ERROR_NOTHING => Some(PolicyOnError::Weighted),
        ON_ERROR_REJECT => Some(PolicyOnError::Reject),
        ON_ERROR_FIRST => Some(PolicyOnError::First),
        _ => None,
    }
}

/// Names a hook may NOT take, enforced on EVERY hook-write path (boot validation, config apply, and
/// the runtime register/PUT API). Two reasons, one rule:
/// - REGISTRY UNIQUENESS: the native ranking strategies + built-in auth modules already answer to
///   their names — two things can't answer to one name.
/// - UNION DISAMBIGUATION: `on_error` is a string union of "reserved terminal"
///   vs "fallback hook name". Reserving EVERY terminal word (`weighted`/`reject`/`first`/`nothing`)
///   as an illegal hook name makes the union closed and unambiguous for machine consumers: a value
///   in this set is a terminal; anything else is a hook reference — no hook can ever collide.
/// # FREEZE BLOCKER: THE HOOK-NAME NAMESPACE IS CLOSED AS OF 1.5.3
///
/// `RESERVED_HOOK_NAMES` and the pool `hooks:` strategy keywords share ONE word space: a bare word in
/// a pool's `hooks:` list is EITHER a built-in ordering strategy OR a reference to a hook the operator
/// defined, and a bare word in `on_error:` is EITHER a reserved terminal OR a fallback hook name.
///
/// **Therefore this list must NEVER GROW.** Adding a bare terminal in a later release (a new
/// `on_error` word, a new ranking strategy, a bounded-default floor) would retroactively
/// INVALIDATE a config that is legal today: an operator's hook named `least_bad` boots fine in 1.5.3
/// and would become a boot failure — or, worse, silently rebind to the new built-in — the moment the
/// word were reserved. That is exactly the break 1.5.3 exists to make impossible.
///
/// **Every future terminal must therefore arrive STRUCTURED, never as a new bare word.** The
/// mechanism already ships: `on_error:` takes `{ hook: <name> }` for a hook reference
/// ([`OnErrorCfg`]), so a new BEHAVIOR gets a new structured key (e.g. `on_error: { strategy: x }`,
/// `hooks: [{ strategy: x }]`) which no bare name can ever collide with. A structured form is
/// unambiguously not a name, so it costs zero words from the frozen space.
///
/// Pinned by `reserved_hook_names_are_frozen` in the config tests, which asserts the EXACT contents
/// (not a subset) so that adding a word here fails a test that points back at this comment.
pub const RESERVED_HOOK_NAMES: &[&str] = &[
    // on_error terminals (see ON_ERROR_*) — includes `weighted`, which is ALSO the native floor.
    ON_ERROR_WEIGHTED,
    ON_ERROR_REJECT,
    ON_ERROR_FIRST,
    ON_ERROR_NOTHING,
    // native ranking strategies (PoolPolicy::native_name)
    STRATEGY_CHEAPEST,
    STRATEGY_FASTEST,
    STRATEGY_LEAST_BUSY,
    STRATEGY_USAGE,
    // built-in auth modules (AuthModule::name)
    "tokens",
    "admin-tokens",
];

/// The FROZEN 1.5.3 hook-name word space (freeze blocker) — the UNION of [`RESERVED_HOOK_NAMES`]
/// and the pool-`hooks:` strategy keywords accepted bare by `is_strategy_name`. This is the exact
/// set of words an operator may NOT use as a hook name, and it is closed forever (see
/// [`RESERVED_HOOK_NAMES`] for why, and for the structured escape hatch every future terminal uses).
///
/// Kept as its own constant, rather than derived, so the freeze is a VALUE a test can pin literally:
/// `hook_name_word_space_is_frozen` asserts both that this equals the runtime union AND that its
/// contents are exactly these eleven words.
// Consumed by the freeze test (`reserved_hook_names_are_frozen`) rather than by runtime code — that
// is the POINT: it is the declared, reviewable VALUE of the freeze, and the test proves it equals
// the runtime union.
pub const FROZEN_HOOK_NAME_WORD_SPACE: &[&str] = &[
    "admin-tokens",
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
    // ── plugin reference (exactly one, required) ─────────────────────────────────────────────────
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
    /// 1.6.0 CLEAN SLATE: the `alias = "plugin"` READ-ONLY back-compat was REMOVED — the only wire
    /// spelling is `module`. A persisted OVERLAY written by a pre-1.6.0 build that still spells this
    /// `plugin:` is auto-migrated to `module:` at boot (busbar-core's
    /// `config::overlay::migrate_legacy_hook_keys`), and `busbar --migrate-config` rewrites
    /// `plugin:` → `module:` in a config file, so removing the alias never bricks a durable overlay.
    #[serde(rename = "module")]
    pub plugin: String,
    // ── shared runtime knobs ─────────────────────────────────────────────────────────────────────
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
    /// OPAQUE settings map pushed to the hook via the `configure` op: sent to the plugin at
    /// load and re-pushed (commit-on-ack) by `PATCH /api/v1/admin/hooks/{name}/settings`. Busbar
    /// never interprets the contents.
    #[serde(default)]
    // settings-leak-lint: allow — operator CONFIG struct, not a projection: this is the
    // `settings:` the operator WROTE. Every admin read of it serves
    // `service::settings_keys(&…settings)`, or passes the tree through
    // `service::redact_settings_bags` first.
    pub settings: serde_json::Map<String, serde_json::Value>,
    /// The "decision observability" DECLARED-SIGNAL surface: the typed
    /// [`busbar_api::Signal`] catalog entries this hook wants computed + projected onto its own
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
    pub signals: Vec<busbar_api::Signal>,
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
    /// 1.5.3 named-hook PHASE set: the pipeline stages this hook fires at. This is the SOLE stage-
    /// scoping spelling in 1.6.0 (the legacy single tap `at:` key it once generalized was REMOVED —
    /// clean slate). EMPTY (the default) means the hook fires at THE FOUR CORE STAGES and only those —
    /// the frozen meaning of an omitted `phase:`, see FREEZE BLOCKER on [`CORE_HOOK_PHASES`].
    /// (`busbar --migrate-config` rewrites a legacy `at: <stage>` into `phase: [<stage>]` so a
    /// single-stage tap keeps firing at exactly one stage; a persisted overlay is auto-migrated the
    /// same way at boot.) Consulted by [`HookCfg::fires_at_stage`]. Inert on a gate (gates fire at
    /// every decision point).
    #[serde(default)]
    pub phase: Vec<HookStage>,
}

impl HookCfg {
    /// Whether this hook observes at `stage` (freeze blocker — see [`CORE_HOOK_PHASES`]).
    ///
    /// Precedence, frozen (1.6.0 dropped the legacy single `at:` rung — clean slate):
    /// 1. a non-empty `phase:` LIST is authoritative — the hook fires at exactly those stages;
    /// 2. otherwise — `phase:` omitted — the hook fires at THE FOUR CORE STAGES, and only those. Never
    ///    "every stage that will ever exist": a stage added by a later release is not in
    ///    [`CORE_HOOK_PHASES`], so it cannot retroactively widen a hook that already shipped.
    pub fn fires_at_stage(&self, stage: HookStage) -> bool {
        if !self.phase.is_empty() {
            return self.phase.contains(&stage);
        }
        CORE_HOOK_PHASES.contains(&stage)
    }

    /// The RESOLVED stage set: every stage this hook ACTUALLY fires at, in pipeline order.
    ///
    /// This is the honest answer to the only question an operator asks about stage scoping, and
    /// `phase:` does not answer it alone. Reading `phase:` back tells you the literal echo, not what it
    /// resolves to: an EMPTY `phase:` means "the four core stages", which the raw field does not say.
    /// So the admin read projects this alongside the literal `phase:` spelling.
    ///
    /// Computed by asking [`Self::fires_at_stage`], the SAME predicate the firing path consults,
    /// once per stage, so the read cannot drift from the behavior it describes. A future stage is
    /// picked up here for free the moment it joins [`ALL_HOOK_STAGES`].
    pub fn resolved_stages(&self) -> Vec<HookStage> {
        ALL_HOOK_STAGES
            .iter()
            .copied()
            .filter(|stage| self.fires_at_stage(*stage))
            .collect()
    }
}

/// Whether a caller bound to `caller_group` is "in" one of `hook_groups` (the named-hook scope
/// check, 1.5.3). An EMPTY `hook_groups` means the hook is UNSCOPED and fires for every caller
/// (returns `true` regardless of `caller_group`). Otherwise the caller matches iff its group — OR any
/// ancestor of it, walked through the `groups:` tree's `parent` chain — appears in `hook_groups`; a
/// caller with NO group binding never matches a scoped hook. This reuses the same acyclic `groups:`
/// tree the governance limit chain walks, so a hook scoped to `engineering` fires for a caller in a
/// `user:bob` leaf whose chain climbs through `engineering`. The walk is bounded by the tree size (a
/// validated-acyclic tree cannot revisit a node without a cycle), so an untrusted/malformed tree can
/// never spin here.
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

/// The default hard wall-clock deadline for a gate decision, in milliseconds. Used by serde's
/// `default = "default_policy_timeout_ms"`. Also the single source of truth consumed at the
/// resolution sites in busbar-core's `limits` and `hooks` modules.
pub const DEFAULT_POLICY_TIMEOUT_MS: u64 = 1;

pub fn default_policy_timeout_ms() -> u64 {
    DEFAULT_POLICY_TIMEOUT_MS
}
