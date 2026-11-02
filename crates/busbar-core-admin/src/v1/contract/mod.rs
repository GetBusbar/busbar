// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::Serialize;

pub mod taxonomy;

pub use busbar_kernel::admin::gate::{
    required_scope, ADMIN_PREFIX, API_ROOT, PATH_ADMIN_AUTH, PATH_CONFIG_VALIDATE,
    PATH_PLUGINS_INSPECT,
};

pub const PATH_HOOKS: &str = "/hooks";

pub const PATH_GROUPS: &str = "/groups";

pub const LIST_LIMIT_MAX: usize = 1000;
pub const LIST_LIMIT_DEFAULT: usize = 200;

pub const VERSIONS_LIMIT_DEFAULT: usize = 100;

pub use busbar_contract::authz::{Grants, Scope};

/// The stable v1 error taxonomy. Each variant maps to a fixed `code` (the machine-stable branch key
/// tooling switches on — NEVER `message`) and an HTTP status the JSON-REST adapter uses. A non-HTTP
/// transport reads `code` and ignores the status. Adding a variant is additive; an existing
/// `code` string is frozen.
///
/// Some variants are exercised only by endpoints in upcoming slices (conflict/forbidden land with the
/// mutation surface); the taxonomy is defined whole so the frozen contract + its test lock exist from
/// the start.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum AdminError {
    /// The named resource does not exist. `code = not_found`. `what` NAMES the missing thing (the
    /// message is `"<what> not found"`), and the optional `note` appends a parenthetical reason for
    /// the cases where "missing" has a cause worth stating — e.g. a single-key read on a server with
    /// governance disabled, where no key CAN exist. Build one with [`AdminError::not_found`] /
    /// [`AdminError::not_found_because`] rather than the variant, so the phrasing stays in one place.
    NotFound {
        what: String,
        note: Option<&'static str>,
    },
    /// No/invalid admin credential (the auth middleware could not authenticate the caller).
    /// `code = unauthorized`. Distinct from `forbidden` (authenticated but under-scoped).
    Unauthorized,
    /// The path exists on the surface but not with this HTTP method. `code = method_not_allowed`.
    MethodNotAllowed,
    /// The principal's scope is insufficient for the endpoint. `code = forbidden`. Carries the scope
    /// that WOULD have sufficed, for a precise client message (never leaks other principals' data).
    Forbidden { needed: Scope },
    /// The request is structurally invalid (bad field, unknown enum, failed validation). `code =
    /// invalid_request`.
    Validation(String),
    /// Optimistic-concurrency mismatch: the caller's `If-Match` is STALE — re-read the resource
    /// and retry. `code = version_conflict`. Split from `conflict`: a client must distinguish
    /// RETRYABLE (this) from TERMINAL state conflicts without string-matching the human message.
    VersionConflict(String),
    /// A TERMINAL state conflict: the request contradicts server state in a way a retry cannot fix
    /// (governance disabled, base-defined hook, immutable grant change, in-flight idempotency
    /// reservation). `code = conflict`.
    Conflict(String),
    /// The principal exhausted its per-minute mutation budget. `code = rate_limited`.
    RateLimited,
    /// An internal failure (store/plugin). `code = internal`. The human `message` is generic; details
    /// are logged server-side, never returned.
    Internal,
    /// A operation that is normally fast could not complete (or even START) within its bound and was
    /// abandoned rather than left to hang the request indefinitely. `code = unavailable`. Unlike
    /// [`AdminError::Internal`] the message is specific and caller-safe (e.g. "the plugin catalog
    /// scan is taking too long") — this is a timeout/backpressure signal the caller can retry, not an
    /// internal defect. First user: `GET /plugins?type=store`'s `CATALOG_SCAN_GATE` wait.
    Unavailable(String),
    /// A usage read over a class the rate card in force does not price (#42: a card is PRESENT, so
    /// an unpriced class refuses rather than reading 0). `code = unpriced_class`, 409: the state
    /// of the card, not the request, is what a retry cannot fix. `class` is `None` when the card
    /// names no entry for the lane at all (then no class of it is priced).
    UnpricedClass { lane: String, class: Option<String> },
}

use busbar_kernel::admin::gate::ApiError;

impl AdminError {
    pub fn not_found(what: impl Into<String>) -> Self {
        AdminError::NotFound {
            what: what.into(),
            note: None,
        }
    }

    pub fn not_found_because(what: impl Into<String>, why: &'static str) -> Self {
        AdminError::NotFound {
            what: what.into(),
            note: Some(why),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            AdminError::NotFound { .. } => "not_found",
            AdminError::Unauthorized => ApiError::Unauthorized.code(),
            AdminError::MethodNotAllowed => ApiError::MethodNotAllowed.code(),
            AdminError::Forbidden { .. } => "forbidden",
            AdminError::Validation(_) => "invalid_request",
            AdminError::VersionConflict(_) => "version_conflict",
            AdminError::Conflict(_) => "conflict",
            AdminError::RateLimited => ApiError::RateLimited.code(),
            AdminError::Internal => ApiError::Internal.code(),
            AdminError::Unavailable(_) => ApiError::Unavailable(String::new()).code(),
            AdminError::UnpricedClass { .. } => "unpriced_class",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            AdminError::NotFound { .. } => 404,
            AdminError::Unauthorized => ApiError::Unauthorized.http_status(),
            AdminError::MethodNotAllowed => ApiError::MethodNotAllowed.http_status(),
            AdminError::Forbidden { .. } => 403,
            AdminError::Validation(_) => 400,
            AdminError::VersionConflict(_) => 409,
            AdminError::Conflict(_) => 409,
            AdminError::RateLimited => ApiError::RateLimited.http_status(),
            AdminError::Internal => ApiError::Internal.http_status(),
            AdminError::Unavailable(_) => ApiError::Unavailable(String::new()).http_status(),
            AdminError::UnpricedClass { .. } => 409,
        }
    }

    pub fn message(&self) -> String {
        match self {
            AdminError::NotFound {
                what,
                note: Some(why),
            } => format!("{what} not found ({why})"),
            AdminError::NotFound { what, note: None } => format!("{what} not found"),
            AdminError::Unauthorized => ApiError::Unauthorized.message(),
            AdminError::MethodNotAllowed => ApiError::MethodNotAllowed.message(),
            AdminError::Forbidden { needed } => {
                format!(
                    "insufficient scope: this endpoint requires `{}`",
                    needed.as_str()
                )
            }
            AdminError::Validation(msg) => msg.clone(),
            AdminError::VersionConflict(msg) => msg.clone(),
            AdminError::Conflict(msg) => msg.clone(),
            AdminError::RateLimited => ApiError::RateLimited.message(),
            AdminError::Internal => ApiError::Internal.message(),
            AdminError::Unavailable(msg) => msg.clone(),
            AdminError::UnpricedClass { lane, class } => match class {
                Some(class) => format!(
                    "usage cannot be priced: the rate card in force names no price for class \
                     `{class}` of `{lane}`"
                ),
                None => format!(
                    "usage cannot be priced: the rate card in force names no price for `{lane}`"
                ),
            },
        }
    }
}

impl From<busbar_kernel::config::transaction::TxnError> for AdminError {
    fn from(e: busbar_kernel::config::transaction::TxnError) -> Self {
        match e {
            busbar_kernel::config::transaction::TxnError::Validation(msg) => {
                AdminError::Validation(msg)
            }
            busbar_kernel::config::transaction::TxnError::Conflict(msg) => {
                AdminError::Conflict(msg)
            }
            busbar_kernel::config::transaction::TxnError::Internal => AdminError::Internal,
        }
    }
}

/// The compiled-in plugin catalog + topology + uptime returned by `GET /api/v1/admin/info`. Powers
/// version negotiation for tooling AND the compliance-by-compilation proof: `auth_modules`/`hook_plugins` reflect
/// the ACTUAL binary (feature-gated at compile time), not config, so `--no-default-features` shows a
/// provably smaller surface. No LLM content, ever.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct InfoView {
    /// busbar semantic version (`CARGO_PKG_VERSION`).
    pub version: &'static str,
    pub build: BuildInfo,
    /// Seconds since process start, or `None` if the start instant was never stamped.
    pub uptime_seconds: Option<u64>,
    /// Epoch seconds of process start, the BOOT EPOCH marker: `config_version` (and any
    /// process-local counter) resets on restart, so a consumer that sees `started_at` change knows
    /// to read a counter reset as "new epoch", never as "reverted".
    pub started_at: Option<u64>,
    pub topology: TopologyInfo,
    /// Whether config-overlay persistence is enabled, i.e. the config is MUTABLE with a writable
    /// `config.overlay` backend: `true` = API-applied config changes are durable across restarts;
    /// `false` = the config is LOCKED (`config.locked: true`) and admin-API config mutations are
    /// refused. Lets tooling tell an operator whether runtime changes are accepted and durable.
    pub config_persistence: bool,
    /// Monotonic config version: `0` at boot, +1 per API config apply. Drift-detection: re-read and
    /// compare to tell whether the running config changed. Process-local (resets on restart).
    pub config_version: u64,
}

/// The compiled-in feature proof (`InfoView.build`).
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct BuildInfo {
    /// Auth modules baked into this binary (e.g. `["tokens"]`; empty under `--no-default-features`).
    pub auth_modules: Vec<&'static str>,
    /// Hook plugins baked into this binary — the served description's example is read off the
    /// compiled-in list itself ([`hook_plugins_description`]).
    #[cfg_attr(feature = "openapi-schema", schemars(description = hook_plugins_description()))]
    pub hook_plugins: Vec<&'static str>,
    /// The inline SWRR floor: ALWAYS `true` (compiled in unconditionally, non-removable).
    pub weighted_floor: bool,
}

/// Pool/model/provider counts (`InfoView.topology`).
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct TopologyInfo {
    pub pools: usize,
    pub models: usize,
    pub providers: usize,
}

/// A pool in the topology read (`GET /api/v1/admin/pools`). Summary shape today: name + the member
/// models and their weights. LIVE per-member status (breaker state, available concurrency, latency
/// EWMA, budget/rate headroom) is an additive follow-up; the field set
/// only grows.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct PoolView {
    pub name: String,
    pub members: Vec<PoolMemberView>,
}

/// One member of a pool: the model it targets and its SWRR weight.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct PoolMemberView {
    pub model: String,
    pub weight: u32,
}

/// The LIVE per-pool detail read (`GET /api/v1/admin/pools/{name}`), the reliability/capacity dashboard
/// data: each member's breaker state, concurrency headroom, in-flight
/// count, latency EWMA, and success/error tallies, read from the SAME store signals the routing seam
/// ranks on. No LLM content, no credentials.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct PoolDetailView {
    pub name: String,
    pub members: Vec<PoolMemberStatusView>,
}

/// One member's live status within a pool. The breaker signal is the release-exposed
/// `usable`/`cooldown_remaining_seconds` pair (a lane in breaker cooldown reports `usable: false` with the
/// seconds remaining), the same summary `/stats` surfaces.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct PoolMemberStatusView {
    pub model: String,
    pub weight: u32,
    /// Whether the lane can currently take dispatch (breaker closed / recovered). `false` while a
    /// tripped breaker cools down or the lane is dead.
    pub usable: bool,
    /// Seconds until a tripped breaker's cooldown elapses; `0` when not cooling down. (`_seconds`
    /// suffix: the one unit-suffix spelling across the surface, like `uptime_seconds`.)
    pub cooldown_remaining_seconds: u64,
    /// Free concurrency slots on this lane right now (lane-global; permits are shared across pools).
    pub available_concurrency: usize,
    /// In-flight requests on this lane right now.
    pub inflight: i64,
    /// Latency EWMA in milliseconds, or `None` if no sample yet.
    pub latency_ms: Option<f64>,
    /// Successful and errored request tallies for this lane.
    pub ok: u64,
    pub err: u64,
    /// Whether the lane is hard-down/dead (distinct from a transiently-tripped breaker).
    pub dead: bool,
    /// MONOTONIC count of Closed→Open breaker trips on this lane. Breaker episodes are transient
    /// and can open+close entirely between two polls, so a consumer alerting on trips diffs this
    /// count instead of trying to catch the live edge. Carried across config apply and
    /// restart with the rest of the learned health.
    pub trip_count: u64,
    /// Epoch seconds of the most recent trip; `None` = never tripped.
    pub last_trip_at: Option<u64>,
}

/// A model lane in the topology read (`GET /api/v1/admin/models`): the config key + its upstream
/// provider. No credentials, ever.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct ModelView {
    pub model: String,

    #[serde(rename = "provider")]
    pub upstream: String,
}

/// A provider in the topology read (`GET /api/v1/admin/providers`): the provider name + how many model
/// lanes route through it.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct ProviderView {
    #[serde(rename = "provider")]
    pub upstream: String,
    pub model_count: usize,
}

/// A hook definition in the registry read (`GET /api/v1/admin/hooks`, `GET /api/v1/admin/hooks/{name}`): the
/// plugin catalog read. Projects the DEFINITION (kind, transport, grants, ordering, stage), never a
/// secret, INCLUDING the `settings:` bag, which is projected as KEY NAMES only (see
/// [`HookView::settings_keys`]). `global` reports whether the hook fires on EVERY request. There is
/// no `global_hooks:` config key to write: 1.5.3 deleted it, and a hook is now DEFINED once in the
/// top-level `hooks:` named map (its `module:` naming the `kind: hook` plugin that backs it) and
/// ATTACHED by bare name, at the reserved all-pools key `pools.hooks:`, which is what makes it
/// global, or at one pool's own `hooks:` list. On THIS API the same hook is written with
/// `global: true`; the wire and the config file are deliberately different surfaces. Live connection
/// status (`health`) is a separate endpoint. Additive-only.
///
/// `groups:` and `phase:` are the config-file SELECTION axes (which callers, which pipeline stages),
/// and this view used to omit both. That was not a decision to keep them file-only: both are
/// WRITABLE over this API (`POST`/`PUT /hooks` deserialize `config::HookCfg` verbatim, which is the
/// documented "paste a `hooks:` entry" contract), so omitting them made a field an operator can set
/// through the API one they could not read back through it. `groups` and the stage pair
/// (`phase` + `fires_at`) close that.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct HookView {
    pub name: String,
    /// `"tap"` (fire-and-forget) or `"gate"` (fire-and-wait).
    pub kind: &'static str,
    pub transport: HookTransportView,
    /// Prompt access grant: `"no"` | `"ro"` | `"rw"`.
    pub prompt: &'static str,
    /// Caller-identity access grant: `"no"` | `"ro"`.
    pub user: &'static str,
    /// Rewrite/reject ordering key (transform-chain order + reject tie-break).
    pub priority: u16,
    /// The LEGACY single-valued tap stage (`"request"`/`"candidate"`/`"routing"`/`"response"`), or
    /// `null`. Kept for back-compat and NOT the field to read: `null` here does NOT mean "a gate"
    /// and does not mean "unscoped". Every hook written in the current top-level `hooks:` grammar
    /// has `at: null` by construction (`config::hook_cfg_from_def` never sets it, and
    /// `--migrate-config` rewrites a legacy `at:` into `phase:`), so this field is `null` for
    /// essentially every hook a running deployment has. Read `fires_at`.
    /// 1.6.0 owner rule: a 1.5.5 client reading this view must see this field byte-for-byte, so it
    /// is RESTORED alongside `phase`/`fires_at`.
    pub at: Option<&'static str>,
    /// Gate fallback on timeout/error, a CLOSED, unambiguous string union: one of the
    /// reserved terminals (`"weighted"` | `"reject"` | `"first"` | `"nothing"`) or the NAME of the
    /// fallback hook the chain continues through. Unambiguous by construction: the terminal words
    /// are ILLEGAL hook names on every write path (`config::RESERVED_HOOK_NAMES`), so a value in
    /// the terminal set is always a terminal and anything else is always a hook reference.
    pub on_error: String,
    /// Gate decision deadline in milliseconds.
    pub timeout_ms: u64,
    /// The KEY NAMES of the hook's opaque settings bag, sorted, WITHOUT their values, the same
    /// redacted projection [`NamedDefView::settings_keys`] carries, produced by the same helper.
    ///
    /// This used to be the bag itself, under a doc comment claiming hook settings are "never a
    /// secret by contract". That claim was retracted for `NamedDefView` and it is no more true here:
    /// a hook's settings bag is a `SecretRef` carrier by design (`hooks::HookEnv::resolve_hook_settings`
    /// resolves it before every configure push), and `config::secret::resolve_settings` forwards a
    /// non-object bag verbatim, so a literal credential is fully supported too. `GET /hooks` and
    /// `GET /hooks/{name}` serve this at READ-ONLY admin scope. The values are readable only where
    /// they are writable: the config file and the config overlay.
    pub settings_keys: Vec<String>,
    /// Whether this hook fires on every request (globally wired).
    pub global: bool,
    /// The `phase:` STAGE LIST exactly as configured, empty when unset. The literal config echo,
    /// for an operator diffing what they wrote against what busbar parsed. It is NOT the effective
    /// answer on its own: empty means "fall back", and what it falls back TO is `at:` if set and the
    /// four core stages otherwise. For the effective answer read `fires_at`.
    pub phase: Vec<&'static str>,
    /// The RESOLVED stage set: the stages this hook ACTUALLY fires at, in pipeline order, never
    /// empty. This is the field that answers "when does this hook run", and it is computed by
    /// `config::HookCfg::resolved_stages` through the same `fires_at_stage` predicate the firing
    /// path uses, so it cannot disagree with runtime behavior. It reflects the frozen precedence
    /// (a non-empty `phase:` wins, else the legacy single `at:`, else the four core stages) without
    /// asking the reader to re-derive it from the two spellings above.
    pub fires_at: Vec<&'static str>,
    /// The `groups:` CALLER SCOPE exactly as configured: the caller groups this hook fires for,
    /// empty meaning ALL callers (unscoped). The other half of "when does this hook run", and the
    /// same writable-but-unreadable gap `phase` had.
    pub groups: Vec<String>,
}

pub use busbar_kernel::api::NamedDefView;

/// A group definition in the registry read (`GET /api/v1/admin/groups`,
/// `GET /api/v1/admin/groups/{name}`): the limit-tree read surface. Projects the `groups:` config
/// entry faithfully (parent chain, enabled freeze flag, the ordered limits, the `child_default`
/// budget template for auto-provisioned children), never a secret. This is the READ shape; the
/// WRITE verbs accept a `GroupCfg` verbatim (paste a config.yaml group block). Additive-only.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct GroupView {
    pub name: String,
    /// The parent group whose limits this one is ANDed under (the enforcement chain). `None` = a
    /// root group. Skipped from the body when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// `false` FREEZES the group (every request charging through it is rejected; history kept).
    pub enabled: bool,
    /// The group's own limits, enforced together (AND). Order preserved from config.
    pub limits: Vec<LimitView>,
    /// The limit template stamped onto children auto-provisioned under this group (e.g. a
    /// `user:<sub>` leaf on first self-mint). Skipped from the body when the group sets none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_default: Option<Vec<LimitView>>,
}

/// One limit inside a `GroupView`: an explicit `{ metric, amount, per, pool }` projection of a
/// config `LimitCfg`. The config file's compact `{ budget: 3000, per: month }` form is
/// deserialize-only sugar; the read API projects it explicitly so a consumer never has to know
/// the metric is the map key. `per` is `None` only for `concurrent` (an instantaneous gauge, no
/// window); `pool` is present only on a pool-scoped limit.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct LimitView {
    /// One of `requests` | `tokens` | `budget` | `concurrent`.
    pub metric: &'static str,
    /// The cap amount (requests/tokens/cents, or the in-flight gauge for `concurrent`).
    pub amount: u64,
    /// The accounting window: `minute` | `hour` | `day` | `month` | `total`. Absent for `concurrent`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub per: Option<&'static str>,
    /// The pool scope: present when the limit carries `pool: <name>` (it accounts and enforces
    /// only that pool's traffic, per `(group, pool)`); absent for a group-wide limit.
    #[serde(rename = "pool", skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The budget-exhaustion behavior: `block` or `downgrade`. Absent = block (the default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_exhaust: Option<&'static str>,
    /// Where `on_exhaust: downgrade` sends exhausted traffic. Present iff downgrading.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downgrade_to: Option<String>,
}

impl LimitView {
    pub fn from_cfg(l: &busbar_kernel::config::LimitCfg) -> Self {
        LimitView {
            metric: l.metric.as_str(),
            amount: l.amount,
            per: l.per.map(|w| w.as_str()),
            scope: l.scope.as_ref().map(|s| s.value.clone()),
            on_exhaust: l.on_exhaust.map(|e| match e {
                busbar_kernel::config::groups::OnExhaust::Block => "block",
                busbar_kernel::config::groups::OnExhaust::Downgrade => "downgrade",
            }),
            downgrade_to: l.downgrade_to.as_ref().map(|s| s.value.clone()),
        }
    }
}

impl GroupView {
    pub fn from_cfg(name: &str, cfg: &busbar_kernel::config::GroupCfg) -> Self {
        GroupView {
            name: name.to_string(),
            parent: cfg.parent.clone(),
            enabled: cfg.enabled,
            limits: cfg.limits.iter().map(LimitView::from_cfg).collect(),
            child_default: cfg
                .child_default
                .as_ref()
                .map(|cd| cd.limits.iter().map(LimitView::from_cfg).collect()),
        }
    }
}

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
    #[serde(rename = "pool", skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
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

/// The transport half of a `HookView`. As of 1.5.0 a hook is EITHER a compiled-in kind (no
/// transport at all) or a signed `kind: hook` dlopen'd plugin (`target` = the plugin NAME, not a
/// socket path or URL); the retired 1.4.x socket/webhook sidecar transports are gone.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct HookTransportView {
    /// `"plugin"` for a signed dlopen'd hook plugin, or `"none"` for a hook with no plugin
    /// transport (compiled-in kinds, or a misconfigured entry).
    pub kind: &'static str,
    /// The plugin's NAME (not a path or URL). `None` when `kind` is `"none"`.
    pub target: Option<String>,
}

/// The live health of one hook's transport (`GET /api/v1/admin/hooks/{name}/health`). Checks
/// whether the hook resolves to a LOADED `kind: hook` plugin in the process's plugin registry;
/// this is a plugin-LOAD status check, not a network reachability probe: it never opens a
/// connection, and it cannot tell you whether a `kind: hook` plugin's own configured external
/// endpoint (e.g. `busbar-webrequest-hook`'s `settings.url`) is actually reachable, only that the
/// plugin itself is loaded. Never fires the hook. Additive-only.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct HookHealthView {
    pub name: String,
    pub transport: HookTransportView,
    /// `Some(true)` = resolves to a loaded `kind: hook` plugin; `Some(false)` = it does not
    /// (wrong kind, or not installed/loaded), always `Some`, never `None`, as of 1.5.0's
    /// in-process plugin model.
    pub reachable: Option<bool>,
    /// A short human note on the resolution (why `false`, or the resolved plugin's kind). Never a
    /// secret.
    pub detail: Option<String>,
}

/// One plugin in the plugin catalog (`GET /api/v1/admin/plugins?type=`). A plugin is either
/// COMPILED-IN (baked into the binary, feature-gated, provably removable via `--no-default-features`)
/// or a signed DYNAMIC-LIBRARY plugin (a loadable `.so`/`.dll`/`.dylib`, dlopen'd over the signed
/// plugin ABI; this covers `auth`, `hooks`, and `store` plugin kinds alike as of 1.5.0; the
/// retired 1.4.x socket/webhook "external" transport is gone). `active` is `Some(true/false)`
/// where activation is tracked (auth modules: in the chain?; hook plugins: configured = true;
/// dynamic store: the configured `store.module`) and `None` where it is a per-pool concern not
/// summarized here (compiled-in ranking policies). Additive-only.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct PluginView {
    pub name: String,
    /// `"auth"`, `"hooks"`, or `"store"`: the plugin TYPE (each a distinct engine contract).
    pub r#type: &'static str,
    /// `"compiled-in"` or `"plugin"` (a dlopen'd dynamic-library plugin: auth, hook, and store
    /// kinds alike as of 1.5.0's signed plugin ABI).
    pub loader: &'static str,
    /// Whether the plugin is currently active, where tracked; `None` when activation is not summarized
    /// at this level.
    pub active: Option<bool>,
    /// For a dynamic-library plugin, its NAME (not a socket path or URL, the retired 1.4.x
    /// transport target). `None` for compiled-in.
    pub target: Option<String>,
    /// The artifact FILENAME in `plugins.dir`: the `{file}` path segment `DELETE
    /// /plugins/{file}` and `GET /plugins/{file}/schema` key off (a list row previously
    /// carried no field a client could feed straight back into either sibling endpoint; `target`
    /// is documented as the manifest NAME, not necessarily the on-disk filename, and is not a
    /// reliable substitute). `None` for compiled-in/external rows, which have no backing artifact
    /// to name. Additive; existing consumers reading only the pre-1.5.1 fields are unaffected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// `true` iff `GET /plugins/{file}/schema` would resolve this row's `file` to a manifest that
    /// declares `settings_schema` at all, i.e. iff `schema_url` below is non-null, so a plugin
    /// catalog can render which rows are configurable in one list call instead of a fetch per row.
    /// Mirrors `schema_url.is_some()`; kept as its own boolean rather than requiring the
    /// caller to null-check `schema_url` for the same fact. `false` for compiled-in/external rows
    /// (no manifest to carry a schema) and for a dynamic-library row whose manifest never set
    /// `settings_schema`. Additive.
    pub has_schema: bool,
    /// The plugin's semantic version, from its signed sidecar manifest (dynamic-library plugins only).
    /// `None` for compiled-in/external, or a dynamic plugin with no/invalid manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The manifest's declared publisher (dynamic-library plugins with a manifest).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// The store C-ABI (`interface_version`) the manifest declares (dynamic-library plugins with a
    /// manifest). Operator-facing name for the "ABI" the engine speaks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_version: Option<u32>,
    /// The server-side trust verdict for a dynamic-library plugin, re-evaluated against the running
    /// `plugins.trust` posture: `"trusted"` (signed by an allowlisted publisher), `"unverified"`
    /// (loaded but not verified, the posture permits it), or `"rejected"` (the `halt` posture would
    /// refuse it). `None` for compiled-in/external.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust: Option<&'static str>,
    /// For a dynamic-library plugin: whether the library validated as a busbar store plugin the engine
    /// can load (ABI handshake). `None` for compiled-in/external.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
    /// Why a dynamic-library plugin did not validate (`valid: false`): a short, secret-free reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Server-resolved path to this plugin's `GET /plugins/{name}/schema` endpoint: ALWAYS a
    /// relative path under the admin origin
    /// (the client MUST reject an absolute/cross-origin value rather than fetch it; this endpoint
    /// only ever emits the admin-prefixed relative form, never anything else). Non-null whenever the
    /// manifest declared a `settings_schema` AT ALL, even if it's unparseable (following it then
    /// surfaces `schema_error`: a present-but-corrupt schema is a worse, distinct
    /// condition from "no schema declared", never folded into the same `null`).
    /// `null` for a compiled-in/external row (no manifest to carry a schema at all) and for any
    /// dynamic-library row whose manifest never set `settings_schema`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_url: Option<String>,
    /// A manifest that SET `settings_schema` but whose value fails to parse (carried onto the
    /// list row too), distinct from a manifest that never set the
    /// field at all (`schema_url: null`, this field also `None`). `schema_url` stays non-null in
    /// this case; the operator sees the row is degraded from the list alone, before ever following
    /// the URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_error: Option<String>,
}

impl PluginView {
    pub fn basic(
        name: String,
        r#type: &'static str,
        loader: &'static str,
        active: Option<bool>,
        target: Option<String>,
    ) -> Self {
        Self {
            name,
            r#type,
            loader,
            active,
            target,
            file: None,
            has_schema: false,
            version: None,
            publisher: None,
            interface_version: None,
            trust: None,
            valid: None,
            error: None,
            schema_url: None,
            schema_error: None,
        }
    }
}

/// The result of installing a dynamic-library store plugin (`POST /api/v1/admin/plugins`). The
/// engine RE-VERIFIED the uploaded bytes against the running trust posture (the client is never
/// trusted), validated the ABI handshake, and atomically wrote the library (+ its manifest sidecar)
/// into the plugins directory. `active` takes effect on the next store (re)load; a store change
/// applies on restart / `store.module` apply, not as a hot swap (design: store install is
/// boot-time/config-apply). Additive-only; never a secret.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct PluginInstallView {
    /// The library FILENAME written into the plugins directory (the handle `DELETE` takes).
    pub file: String,
    /// The plugin name from its manifest (or the filename when unsigned).
    pub name: String,
    /// The store C-ABI (`interface_version`) the engine validated the library against.
    pub interface_version: u32,
    /// The server-side trust verdict from the RE-VERIFY: `"trusted"` | `"unverified"`. (A `"rejected"`
    /// verdict is an error, never a success body.)
    pub trust: &'static str,
    /// The manifest version, when the upload carried a signed manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The manifest publisher, when signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// A human note: this install is durable in the folder but takes effect on the next store (re)load.
    pub note: &'static str,
}

/// The result of removing a dynamic-library plugin (`DELETE /api/v1/admin/plugins/{file}`) — the
/// library and its manifest sidecar are deleted from the plugins directory. `204 No Content` is the
/// wire response; this view backs the OpenAPI schema for tooling that models a body.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct PluginRemoveView {
    pub file: String,
    pub removed: bool,
}

/// The result of re-scanning the plugins directory (`POST /api/v1/admin/plugins/reload`): the
/// current dynamic-library inventory, each with its ABI-validity. Reconciles the reported set to the
/// folder (the folder is the source of truth), exactly as `config/reload` reconciles config to disk.
/// A store change still applies on the next store (re)load, not as a hot swap.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct PluginReloadView {
    /// The dynamic-library plugins now present in the directory, sorted by filename.
    pub plugins: Vec<PluginView>,
    /// A human note on when a store change actually takes effect.
    pub note: &'static str,
}

/// The result of an EXPLICIT plugin ROLLBACK (`POST /api/v1/admin/plugins/rollback`, 1.5.0
/// rollback-friendly versioning): the operator deliberately pinned a plugin DOWN to a prior version and
/// the engine hot-swapped to that artifact. The pin is persisted (survives restart) and the trust
/// floor was lowered to EXACTLY the pinned version for THIS plugin; a lower artifact still cannot
/// load, and an automatic/silent replay of an old artifact is still refused (only this explicit,
/// audited action lowered the floor). Additive-only; never a secret.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct PluginRollbackView {
    /// The plugin's canonical manifest name that was pinned.
    pub name: String,
    /// The library FILENAME the rollback selected in the plugins directory.
    pub file: String,
    /// The version the plugin was pinned DOWN to (now serving), from the target artifact's manifest.
    pub version: String,
    /// The manifest publisher of the pinned artifact (`busbar` = first-party).
    pub publisher: String,
    /// The now-live config version after the hot swap (the ETag the response also carries).
    pub config_version: u64,
    /// A human note on the rollback's semantics + durability.
    pub note: &'static str,
}

/// The ingress auth chain read (`GET /api/v1/admin/auth`): the ordered module names that authenticate
/// callers + the upstream-credential mode. Never a secret: module names and the mode are config
/// identifiers, not credentials. An empty `chain` is the open front door (admits every request).
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct AuthView {
    /// Ordered auth-chain module names (`[]` = open front door).
    pub chain: Vec<String>,
    /// `"own"` (busbar signs egress with its configured key) or `"passthrough"` (forward the caller's
    /// credential upstream).
    pub upstream_credentials: &'static str,
    /// Whether the front door is open (empty chain admits unconditionally).
    pub open: bool,
}

/// A cursor-paginated list envelope. `items` is this page; `next_cursor` is `Some` when more remain.
/// Generic over the item view so every list endpoint shares one shape.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "openapi-schema", schemars(rename = "Page_{T}"))]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    pub fn single(items: Vec<T>) -> Self {
        Self {
            items,
            next_cursor: None,
        }
    }
}

pub fn encode_offset_cursor(offset: usize) -> String {
    use std::fmt::Write;
    format!("o:{offset}")
        .bytes()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

pub fn decode_offset_cursor(cursor: &str) -> Option<usize> {
    if cursor.is_empty() || !cursor.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..cursor.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(cursor.get(i..i + 2)?, 16).ok())
        .collect();
    let s = String::from_utf8(bytes?).ok()?;
    s.strip_prefix("o:")?.parse::<usize>().ok()
}

#[cfg(test)]
#[path = "tests/cursor_tests.rs"]
mod cursor_tests;

/// The EFFECTIVE config snapshot (`GET /api/v1/admin/config`): the running configuration as busbar
/// resolved it, for drift detection (compare against your desired config) and one-shot inspection.
/// Composed from the same REDACTED reads as the individual endpoints (auth chain names, pool/model/
/// provider topology, hook definitions, global-hook wiring), so it carries NO secret: no client
/// tokens, no provider keys, no hook payloads. Additive-only; the source-layer annotation (base vs
/// overlay) lands with the config overlay substrate.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct EffectiveConfigView {
    /// The monotonic config version at the time of this read (see `InfoView.config_version`), so a
    /// drift-detection read gets the config AND its version in one call.
    pub version: u64,
    pub auth: AuthView,
    pub pools: Vec<PoolView>,
    pub models: Vec<ModelView>,
    pub providers: Vec<ProviderView>,
    pub hooks: Vec<HookView>,
    /// Names fired on EVERY request: the hooks attached at the reserved all-pools key `pools.hooks:`
    /// in `config.yaml` (the 1.5.3 replacement for the DELETED `global_hooks:` key; that key no
    /// longer parses), plus any hook this API declares with `global: true`. The response FIELD name
    /// stays `global_hooks`; only the config-file spelling changed.
    pub global_hooks: Vec<String>,
    /// The plane sections the running configuration writes whose plane the process did not open at
    /// boot: a plane is opened once, at process start, when its section is configured, so each is
    /// stored and validated but serves nothing until the next RESTART. Omitted when none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reload_to_apply: Vec<String>,
}

pub const USAGE_CURRENCY: &str = "USD";

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
    /// THE RATE-CARD VERSION THIS READ WAS PRICED AT (#44, Q93): the seq of the dated rate-card
    /// history snapshot every row of this response resolved its card through: the `?as_of` the caller
    /// named, else the history's head when the read was taken. Asking `?as_of=<this>` again re-derives
    /// the same figures, so an invoice cut from this response names the card that priced it. `null`
    /// when this node has resolved no rate-card history. New in 1.6.0; pricing provenance only, never a
    /// pricing input (#79).
    pub rate_card_version: Option<u64>,
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

/// One plane-declared class's consumption on a usage row: its raw count and its cost.
///
/// NEW IN 1.6.0 (1.5.5's usage rows carried the token split alone, and 1.5.5 served no plane that
/// declares a class of its own): ledgered by the FLIP-A2A ruling. `cost` is in the same MICRO-units
/// as [`UsageBreakdown::spend_micros`], priced by the same card in force at the row's instant, and is
/// part of that row's `spend_micros`, never added to it a second time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct ClassUsage {
    /// The raw count the plane's ledger lines recorded under the class.
    pub count: u64,
    /// What the card in force priced that count at, in micro-units.
    pub cost: i64,
}

/// The raw consumption counts + the derived spend estimate: the one shape shared by `total`,
/// `by_model` rows, and `by_key` rows, so a consumer writes ONE aggregation reader.
#[derive(Debug, Clone, Default, Serialize)]
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
    /// THE PLANE-DECLARED CLASSES the row's ledger lines counted outside the token split, keyed by
    /// the class name the plane declares (new in 1.6.0, [`ClassUsage`]). Absent when the row carries
    /// none, so a token-only row reads exactly as 1.5.5's.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub classes: std::collections::BTreeMap<String, ClassUsage>,
}

/// One (model, provider) row of the per-model aggregation.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct ModelUsageView {
    pub model: String,

    #[serde(rename = "provider")]
    pub upstream: String,
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

/// The admin-plane auth read (`GET /api/v1/admin/admin-auth`): which modules guard the ADMIN surface
/// (distinct from the ingress `auth` chain). `modules` is the live `admin_auth` chain (the SAME
/// resource `PUT /api/v1/admin/admin-auth` writes), so a read-after-write is coherent. An empty chain is
/// the open (anonymous, full-authority) dev posture, `configured: false`. Never a secret.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct AdminAuthView {
    /// Whether an admin credential chain is configured. `false` = the empty chain = open dev posture.
    pub configured: bool,
    /// The active admin-plane guard module names, the `admin_auth` chain verbatim (by default the
    /// operator credential's provider alone), reported in order. Empty when the admin plane is open.
    #[cfg_attr(feature = "openapi-schema", schemars(description = modules_description()))]
    pub modules: Vec<String>,
}

#[cfg(feature = "openapi-schema")]
fn hook_plugins_description() -> String {
    format!(
        "Hook plugins baked into this binary (e.g. `{:?}`).",
        crate::v1::service::hook_plugins_compiled_in()
    )
}

#[cfg(feature = "openapi-schema")]
fn modules_description() -> String {
    format!(
        "The active admin-plane guard module names, the `admin_auth` chain verbatim (e.g.\n`[\"{}\"]`), reported in order. Empty when the admin plane is open.",
        busbar_kernel::config::operator_module()
    )
}

/// The result of `POST /api/v1/admin/config/validate`, a DRY-RUN: does a proposed config resolve +
/// validate, WITHOUT applying anything. `ok` is the verdict; `errors` lists every structural/resolution
/// failure at once (empty when `ok`). A well-formed request always returns 200 with this view (a valid
/// request that describes an INVALID config is `ok: false`, not an HTTP error); only a MALFORMED request
/// body is an `invalid_request`. Env-var interpolation is out of scope; this checks structure and
/// cross-reference resolution, not runtime secret presence.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct ConfigValidateView {
    pub ok: bool,
    pub errors: Vec<String>,
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
