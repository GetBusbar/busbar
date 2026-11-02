// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::Arc;

use busbar_kernel::store::LaneRuntime;

pub use busbar_kernel::topology::{worker_stripe, worker_stripes};

pub use busbar_kernel::plane_driver::slots::runtime_slot_key;

pub type ContainerGateMap = HashMap<String, Vec<(u16, crate::hooks::ResolvedPolicy)>>;

pub type PlaneGateMap = std::collections::BTreeMap<&'static str, ContainerGateMap>;

#[allow(clippy::type_complexity)]
pub type ContainerRewriteMap =
    HashMap<String, Vec<(std::time::Duration, Arc<dyn crate::hooks::RoutingPolicy>)>>;

pub type PlaneRewriteMap = std::collections::BTreeMap<&'static str, ContainerRewriteMap>;

/// `Clone` is the config-apply enabler: cloning an `App` shares the live-state `Arc`s (store, auth,
/// governance — the things that must SURVIVE a config change) and deep-copies the
/// config-derived collections (lanes, pools, hooks, …). So `apply` builds the next snapshot as
/// `let mut next = (*current).clone(); /* mutate config-derived fields */` and `AppHandle::swap`s it,
/// while in-flight requests keep serving on the old snapshot and the SAME breaker/latency state.
#[derive(Clone)]
pub struct App {
    /// TELEMETRY BANK slots for THIS config generation (see `telemetry.rs`): every hot-path metric
    /// site resolves its pre-registered per-thread slot through this table instead of building a
    /// recorder key per emission. Rebuilt whenever a new snapshot changes the pool/lane label space
    /// (`build_app` / config apply); identical label sets re-intern to the same process-lifetime
    /// slots, so counts accumulate monotonically across generations. Observation only — THE RULE:
    /// enforcement counts never go through the bank.
    pub(crate) tslots: Arc<crate::telemetry::AppSlots>,
    /// THE FALLBACK PLANE'S RUNTIME SLOT KEY — the interned `runtime_slot_key` of the plane that
    /// DECLARES itself fallback ([`crate::plane_driver::dispatch::fallback_decl`]; a key naming no plane when none
    /// does), under which THIS config generation's runtime object rides in [`App::plane_slots`], the
    /// same opaque slot every other registered plane carries its own runtime object in. Resolved ONCE
    /// at build (`appbuild` / the test fixture) so the money-path read ([`App::engine_tables_view`])
    /// is a single cheap `plane_slots` lookup + ONE downcast, never the interning `runtime_slot_key`
    /// call.
    /// An ABSENT slot — the featureless binary boots with no fallback plane configured, so none was
    /// inserted — reads as the substrate-resident empty view, never a panic. Neutral: names no dialect.
    pub fallback_runtime_key: &'static str,
    /// THE PUBLISHED INSTANCES' ADMIN TABLE ([`crate::plane_driver::serve::ServeTables`]): the one
    /// the composition root publishes its door planes into, created with the boot generation and
    /// carried onto every generation built after it (a clone shares the one table). The admin
    /// router's fallback and every stated admin route answer off it.
    pub serve_tables: crate::plane_driver::serve::ServeTables,
    /// The composition root's rules this generation was built under
    /// ([`crate::appbuild::RootRules`]): every build after it (an apply, a rebuild, a
    /// dry run) is judged by them.
    pub root_rules: Arc<dyn crate::appbuild::RootRules>,
    /// The composition root's projection of the configuration this generation was built from
    /// ([`crate::appbuild::ConfigProjection`]); `None` when the root bound none.
    pub config_projection: Option<Arc<dyn std::any::Any + Send + Sync>>,
    /// The kernel's own tables over the `pools:`/`models:` sections this generation resolved: the
    /// read seam's answer when no plane contributed a runtime of its own (a door-served plane walks
    /// these sections through its door).
    pub config_tables: Arc<busbar_kernel::plane_driver::route_tables::ConfigTables>,
    pub store: Arc<dyn LaneRuntime>,
    /// THE OPERATIONAL LIMITS THIS GENERATION GOES LIVE WITH (`limits:` resolved). Published
    /// process-wide by [`AppHandle::swap`] at the moment the generation is installed — never while it
    /// is being built or judged, so a refused apply's limits are never in force (BUSBAR-1.6.0.md THE
    /// DESIGN §6 item 8). `None` for a hand-built test generation, which publishes nothing.
    pub limits: Option<crate::config::LimitsResolved>,
    /// THE NEUTRAL PER-SESSION SUBSTRATE ([`crate::session::SessionStore`]) — PROCESS-LIFETIME, reused
    /// across `build_app_from_config` applies, because a session's state
    /// (today the gate's cleared-scan set; tomorrow any tenant) must survive a config swap or every
    /// apply would forget every live session. Present unconditionally (an empty bounded map is cheap);
    /// whether the gate hot path CONSULTS it is the operator opt-in `incremental_scan`.
    pub session_store: Arc<crate::session::SessionStore>,
    /// Operator opt-in (env `BUSBAR_INCREMENTAL_SCAN`) for the gate's incremental-scan tenant. `false`
    /// (the default) ⇒ every gate screens the full projection every turn, byte-identical to 1.5.4; the
    /// firing sites pass `incremental: None`. Env-driven, not config, so activating it does not touch
    /// the frozen `config-schema.snapshot.json` / config-stability gate.
    pub incremental_scan: bool,
    /// THE PER-PLANE FAILOVER POOL MAPS, keyed by the plane's stable
    /// decl key (the opaque registry key) — a registry-keyed map in place of the former plane-named
    /// pool field, so core carries no plane vocabulary in its own field names. Each plane's
    /// entry is its own resolved pool-member set (member selection derives lanes from member position).
    /// Read on the plane's submission/route path through [`App::plane_pools`].
    #[allow(dead_code)]
    pub plane_pools: std::collections::BTreeMap<
        &'static str,
        std::collections::BTreeMap<String, crate::config::pools::CandidatePoolCfg>,
    >,
    pub auth: Arc<crate::auth::AuthMiddleware>,
    /// GLOBAL rewrite hooks — the `prompt: rw` gates named in `global_hooks`, resolved to their
    /// transports and sorted by ascending `priority` (the transform-chain order). Fired before
    /// dispatch to mutate the request body (compression/redaction). Empty (the default) = no rewrite
    /// pass, zero cost. Only `rw` gates land here — the grant is enforced at RESOLUTION, so a
    /// `ro`/`no` hook can never rewrite (the bidirectional grant holds by construction). Each entry is
    /// `(per-hook transform deadline, transport)`.
    pub rewrite_hooks: Vec<(std::time::Duration, Arc<dyn crate::hooks::RoutingPolicy>)>,
    /// Global request-stage taps from `global_hooks` are resolved to transports and spawned off the request path before dispatch. A tap cannot delay or fail the request. The default empty list has zero cost. Entries are `(per-hook deadline, send_prompt, transport)`; `send_prompt` carries the tap's `prompt: ro` grant, so granted taps receive prompt content and `prompt: no` taps receive only shape. This list serves the request stage.
    ///
    ///
    ///
    ///
    ///
    ///
    pub tap_hooks: Vec<crate::hooks::TapEntry>,
    /// GLOBAL taps observing at the CANDIDATE stage (`at: candidate`) — fired once per request when the
    /// decision reconcile has produced the final candidate set. Same triple shape as `tap_hooks`.
    pub tap_hooks_candidate: Vec<crate::hooks::TapEntry>,
    /// GLOBAL taps observing at the ROUTING stage (`at: routing`) — fired per failover attempt with
    /// the attempt number / dispatched target / remaining candidates / previous failure.
    pub tap_hooks_routing: Vec<crate::hooks::TapEntry>,
    /// GLOBAL taps observing at the RESPONSE stage (`at: response`) — fired once per request
    /// with the outcome (`ok`/`failed`/`rejected_by_gate` — the SYNTHETIC completion, so audit taps
    /// see gate denials too) and response status.
    pub tap_hooks_response: Vec<crate::hooks::TapEntry>,
    /// GLOBAL DECISION gates — the non-rewrite `kind: gate` hooks in `global_hooks`, resolved to
    /// their full `ResolvedPolicy` (transport + on_error/on_empty/grants), each with its `priority`.
    /// Fired CONCURRENTLY on every request in the phase-2 decision reconcile, merged with the pool's
    /// own gates into one priority-sorted chain (reject wins / restricts intersect / order
    /// last-wins). Empty (the default) = no global gates, zero cost. Pre-sorted ascending by
    /// priority so the merge's stable sort keeps globals-first on ties.
    pub global_gates: Vec<(u16, crate::hooks::ResolvedPolicy)>,
    /// THE PER-POOL ROUTING POLICY / DECISION GATES / REWRITE CHAINS, resolved ONCE at config apply
    /// The resolved values are core-owned `ResolvedPolicy` / `Arc<dyn RoutingPolicy>`
    /// objects over admitted plugins. A plane's `build_runtime` cannot
    /// resolve them because it has no `hook_env` or
    /// usable current `&App`. They are resolved and read
    /// core-side, keyed by pool, and exposed through [`App::pool_policy`],
    /// [`App::pool_gates`], and [`App::pool_rewrites`]. The facade returns the same
    /// objects produced by `hooks::resolve_pool_*`, without storing them across
    /// the plane seam. An absent pool uses the
    /// zero-cost default: no policy and an empty chain.
    pub pool_orderings: std::collections::HashMap<String, crate::hooks::ResolvedPolicy>,
    pub pool_decision_gates:
        std::collections::HashMap<String, Vec<(u16, crate::hooks::ResolvedPolicy)>>,
    #[allow(clippy::type_complexity)]
    pub pool_rewrite_chains: std::collections::HashMap<
        String,
        Vec<(
            std::time::Duration,
            std::sync::Arc<dyn crate::hooks::RoutingPolicy>,
        )>,
    >,
    /// THE PER-PLANE PER-CONTAINER SUBMISSION GATES, keyed by the plane's stable decl key (the opaque
    /// registry key) — one generic registry-keyed map in place of the former per-plane
    /// gate fields, so core carries no plane vocabulary in its own
    /// field names. Each plane's entry maps container → resolved `(hook_id, ResolvedPolicy)` gate list
    /// (`<section>.hooks:` ∪ `<section>.<container>.hooks:`), same combine rule and zero-cost absence
    /// as before. Composed at config apply by `appbuild` (and re-resolved on swap through
    /// [`busbar_kernel::plane_driver::slots::ContainerGateSink`]); read on the dispatch path by
    /// [`App::plane_gates`]. Empty for a plane that attaches nothing — the lookup costs one probe.
    #[allow(dead_code)]
    pub plane_gates: PlaneGateMap,
    /// THE PER-PLANE PER-CONTAINER REWRITE (`prompt: rw`) CHAINS, keyed by the plane's stable decl key —
    /// the TAP/observe-transform twin of [`Self::plane_gates`]. Each plane's entry maps container →
    /// resolved `(deadline, transport)` rewrite list (`<section>.hooks:` ∪ `<section>.<container>.hooks:`,
    /// the `prompt: rw` members only). Composed at config apply by `appbuild` and re-resolved on swap
    /// through the same [`busbar_kernel::plane_driver::slots::ContainerGateSink`] callback the gates use. Empty
    /// for a plane that attaches no rewrite hook — the tap firing site's lookup costs one probe and the
    /// path stays byte-identical.
    #[allow(dead_code)]
    pub plane_rewrites: PlaneRewriteMap,
    /// The plugin-resolution environment for hooks: the validated plugin registry + the root's hook
    /// axis over it. Threaded to the admin control-plane reads/writes (configure/status/schema) and the
    /// Prometheus scrape so they open a hook's `kind: hook` plugin the same way the request path's
    /// resolved transports did. Cheap to clone (Arc-backed). Replaces the retired webhook client the
    /// out-of-process transport needed.
    pub hook_env: crate::hooks::HookEnv,
    /// The raw `hooks:` registry (name → definition) as configured, for the Admin API v1 hooks READ
    /// surface (`GET /api/v1/admin/hooks`). This is the DEFINITION set, distinct
    /// from the RESOLVED transports in `rewrite_hooks`/`tap_hooks` (which the request path fires). Empty
    /// when no hooks are configured. Read-only after construction; the config-plane mutation surface
    /// swaps a new `App` snapshot rather than mutating this in place.
    pub hook_registry: HashMap<String, crate::config::HookCfg>,
    /// The "decision observability" signal catalog's config-generation
    /// `RequestedSignals` bitmask — the UNION of every hook's declared `signals:` — built ONCE
    /// alongside `hook_registry` above and recomputed by `admin::v1::service::rebuild_hook_derived`
    /// on every snapshot that rewrites that registry (so a hook registered through the admin API
    /// declaring `signals:` is honoured on the very next request, not only after a restart) — never
    /// per request. All-zero (the default) when no hook
    /// anywhere declares a catalog signal, which is the zero-cost path every `requested.wants(_)`
    /// check downstream short-circuits on.
    pub requested_signals: crate::hooks::RequestedSignals,
    /// Does this config generation grant ANY hook access to prompt CONTENT (`prompt: ro` / `rw`)?
    /// Built ONCE alongside `requested_signals` above by `hooks::any_content_hook`, and recomputed
    /// on every snapshot that rewrites `hook_registry` — never per request.
    ///
    /// This is the gate on building the request IR for the hook seam: `false` (the default, and
    /// every deployment that runs no content hook) means the IR is never built and the request path
    /// pays nothing at all. See `hooks::any_content_hook` for why the gate keys on the deployment's
    /// grants rather than on the request's protocols.
    pub any_content_hook: bool,
    /// The config generation's UNION OF EXPORT PROJECTIONS — the union across every configured
    /// `export:` instance of the streams (and fields) it subscribes to. Built ONCE per config apply
    /// from the resolved `export:` block, never per request.
    ///
    /// THE COMPUTE GATE, and deliberately the SAME mechanism as `requested_signals` directly above:
    /// the read runs ONLY when something declared it, never call-then-discard. Nothing subscribed ⇒
    /// core never assembles that stream's records at all. It supersedes the one-off
    /// `export::request_log_configured()` boolean this replaced — one mechanism for "did anybody ask
    /// for this", not two.
    pub(crate) export_projections: crate::export::projection::ProjectionUnion,
    /// The `global_hooks:` list — names fired on every request (plus any hook with inline `global:
    /// true`). Carried for the hooks read surface so a definition can report whether it is globally
    /// wired. Read-only after construction.
    pub global_hooks: Vec<String>,
    /// Hook names defined in the BASE config file (pre-overlay). `PUT /api/v1/admin/hooks/{name}` on a
    /// base hook is a 409 (edit the file, don't shadow it); API-registered (overlay) hooks replace
    /// freely. Immutable after boot.
    pub base_hook_names: std::collections::HashSet<String>,
    /// The raw `groups:` registry (name → definition) as the EFFECTIVE config resolves it (base +
    /// overlay), for the Admin API v1 groups READ + MUTATION surface (`GET/POST/PUT/DELETE
    /// /api/v1/admin/groups`). This is the source-of-truth `GroupCfg` map — distinct from the LOSSY
    /// projection in `cost.groups()` (which buckets limits per window and drops `child_default`).
    /// A group mutation swaps a new `App` snapshot (clone → mutate this map → re-validate → rebuild
    /// `cost` via `CostModel::with_groups`), never mutating in place. Empty when none configured.
    pub groups_registry: std::collections::BTreeMap<String, crate::config::GroupCfg>,
    /// Group names defined in the BASE config file (pre-overlay). A `PUT`/`DELETE` on a base group is
    /// a 409 (edit config.yaml — the API cannot silently shadow or subtract operator file config, and
    /// the additive overlay can't durably remove a base group); API-created (overlay) groups mutate
    /// freely. Immutable after boot — mirrors `base_hook_names`.
    #[allow(dead_code)]
    pub base_group_names: std::collections::HashSet<String>,
    /// The EFFECTIVE `identity-providers:` NAMED-DEFINITION map (base `config.yaml` + the overlay's
    /// API-applied entries). The READ side of the generic named-map admin CRUD
    /// (`GET /api/v1/admin/identity-providers[/{name}]`); the WRITE side never mutates this in place
    /// — it rewrites the overlay section and rebuilds a whole `App` from disk, exactly as
    /// `PUT /config/settings` does, because an IdP change re-resolves the auth + admin chains.
    pub identity_providers: crate::config::IdentityProviders,
    /// The EFFECTIVE `export:` NAMED-DEFINITION map — the exporter twin of `identity_providers`,
    /// serving `GET /api/v1/admin/export[/{name}]`. The lowered runtime projection lives in the
    /// recorder / plugin-route table, never here.
    pub export_defs: crate::config::ExportDefs,

    /// Per-principal ADMIN MUTATION rate limiter. Arc-shared across apply snapshots so the
    /// windows survive every swap.
    pub(crate) mutation_limiter: Arc<crate::ratelimit::MutationLimiter>,
    /// The admin side's state (the config VERSION HISTORY, typed and filled by the admin service),
    /// behind the admin seam's one slot. Arc-shared across apply snapshots (survives every swap).
    pub admin: Arc<crate::admin::seam::AdminSlot>,
    /// The ADMIN auth chain (`admin_auth:` module names, default: the operator credential) — executed by
    /// the auth middleware for `/admin` paths. Empty = the explicit OPEN admin posture (dev).
    pub admin_chain: Vec<String>,
    /// The RESOLVED admin auth modules — every `admin_auth:` entry opened through the auth kind's
    /// registry (1.5.2 admin-plane OIDC). Keyed by the config module name (the same string
    /// `admin_chain` names and `role_bindings.<module>` binds); the operator credential is held apart
    /// (`AdminAuthChain::operator`), opened over its token's digest. Each external module's call
    /// is offloaded off the reactor (a plugin can do blocking JWKS/introspection I/O).
    /// Rebuilt on boot AND reload (`build_app_from_config`), Arc-shared so `App::clone` is cheap.
    pub admin_modules: Arc<crate::auth::AdminAuthChain>,
    /// The RESOLVED hosted-login methods (`auth.methods:`, 1.5.2) — each opened as a login
    /// capable `kind: auth` plugin over ABI v2, keyed by the config method/module name (insertion
    /// order = login-page button order). Carries the CORE-only confidential-client secret and the
    /// `browser_login` flag. `GET /auth/token` renders a button per method with a button and drives
    /// its begin/callback. Rebuilt on boot AND reload; Arc-shared for cheap `App::clone`.
    pub(crate) login_methods: Arc<crate::auth::login::LoginMethods>,
    /// busbar's PUBLIC base origin (top-level `public_url:`, 1.5.2) — the origin the hosted login
    /// page builds its `/auth/token` authorize/redirect links from and shows devs as their BYOK
    /// `base_url` (verbatim, no `/v1`). `None` ⇒ no hosted login (config_validate requires it when
    /// any `browser_login` method is configured). Rebuilt on every apply/reload.
    pub public_url: Option<String>,
    /// THE AUTHORIZATION SERVER (`oauth_as:`), or `None` when this deployment is not one.
    ///
    /// `None` is the whole zero-cost-when-off property: nothing is constructed, nothing is
    /// allocated, no signing key exists, no sweeper runs and no route is mounted. See
    /// `crate::oauth_as`.
    ///
    /// TYPE-ERASED (`Arc<dyn Any + Send + Sync>`, not `Arc<busbar_core_oauth2::plane::AsPlane>`): the
    /// concrete plane object lives in the sibling `busbar-core-oauth2` crate, which depends on
    /// busbar-core ONE-WAY — core naming `busbar_core_oauth2::plane::AsPlane` here would be the reverse
    /// edge Cargo refuses as a cycle. The real type is built and downcast on the `busbar-core-oauth2`
    /// side of the seam (`crate::oauth_as::seam`); core only carries the opaque handle and knows
    /// `Some`/`None`.
    pub oauth_as: Option<Arc<dyn std::any::Any + Send + Sync>>,
    /// DEMOTIONS THAT OUTLIVE THE PROCESS THAT TOOK THEM — the write side of the durable quarantine
    /// record, and the reason a restart no longer hands a demoted upstream its approval back.
    ///
    /// Arc-shared across config applies for the same reason the two fields above are, and with one
    /// extra: the durable sink is attached to it ONCE at boot, so an instance rebuilt on an apply
    /// would be an instance with no sink — a quarantine that stopped being written down because
    /// somebody edited an unrelated section of config. See [`crate::trust::demotion`].
    pub demotion_record: Arc<crate::trust::demotion::DemotionRecord>,
    /// THE NODE'S AMENDMENT JOURNAL (item 404): every hook or export content access this node seals,
    /// and the sink that makes them durable. The SAME instance on every generation — the one the
    /// node's governance owns ([`crate::governance::GovState::amendments`]), carried across every
    /// config apply — and an instance, never a process static, so two nodes never share one. Its
    /// durable sink is bound on it once at boot, as the demotion record's is.
    pub amendments: Arc<crate::audit::amend::NodeAmendments>,
    /// PLANE DISPATCH for this config generation: which plane an inbound path belongs to, and — for
    /// an audience-bound plane — what a token presented there must carry and where a refused caller
    /// is told to go. Consulted by the auth middleware on every request, which is why it is a
    /// prebuilt table rather than a per-request derivation.
    pub planes: Arc<crate::plane_driver::dispatch::PlaneDispatch>,
    /// THE TYPE-ERASED PLANE SLOT MAP, keyed by each plane's stable decl key — the app-state seam
    /// an extracted plane crate contributes its runtime object through, without core naming that
    /// object's type. `PlaneDecl::claims`/`admission` already read a plane's object through exactly
    /// this kind of erasure (`&dyn Any`), and this map generalises it to an owned, `App`-carried slot.
    ///
    /// Every registered plane reads its runtime object ONLY through this map: each plane's own typed
    /// `App` field was deleted, and that plane's own accessor downcasts its slot inside its own
    /// module, so nothing OUTSIDE that module names its runtime type. Every extracted plane follows
    /// the same pattern (the D4 step, now complete, mirrors this across every registered plane).
    ///
    /// Absent from this map is the same fact as an unconfigured plane: a plane the operator did not
    /// configure contributes no slot (see [`crate::plane_driver::registry::PlaneDecl::build`]).
    pub plane_slots: std::collections::BTreeMap<&'static str, Arc<dyn std::any::Any + Send + Sync>>,
    /// LAW 7 — this generation's configured plane sections (`RootCfg::plane_sections`). `None` only on
    /// a test fixture that states none, where every linked plane counts as configured.
    pub plane_sections: Option<std::collections::BTreeSet<&'static str>>,
    /// Per-module `max_admin_scope:` ceilings (from the auth chain entries) - consulted at admin
    /// scope resolution.
    pub auth_scope_caps: std::collections::HashMap<String, String>,
    /// `auth.role_bindings:` - module -> role -> operator policy (nested by module). Read by
    /// the admin authorization resolution and the governance re-key; an unbound role grants
    /// nothing (fail closed).
    pub role_bindings: crate::config::RoleBindings,
    /// The config.yaml path busbar booted from — `POST /api/v1/admin/config/reload` re-runs the boot
    /// disk-load pipeline against it. `None` (tests / ephemeral) ⇒ reload is `invalid_request`.
    pub config_path: Option<std::path::PathBuf>,
    /// The providers.yaml path (same role as `config_path`).
    pub providers_path: Option<std::path::PathBuf>,
    /// The typed Store-backed runtime config anchor. The historical field name is retained for
    /// callers; it never contains a path. `None` is locked management. The base-config Store
    /// remains the anchor across applies, including changes to the effective governance Store.
    pub overlay_path: Option<Arc<crate::config::overlay::OverlayStore>>,
    /// Monotonic config version — `0` at boot, incremented by each API config apply (the swap builds
    /// the next snapshot with `config_version + 1`). Exposed on `GET /api/v1/admin/info` so drift-detection
    /// tooling can tell whether the running config changed since a prior read. Process-local (resets on
    /// restart).
    pub config_version: u64,
    /// Anti-sprawl cap on keys BOUND TO ONE GROUP.
    /// Because a `user:<sub>` leaf IS the principal, this is effectively "max keys per principal".
    /// `0` = unlimited (default). Enforced at `POST /keys`; carried on the snapshot so a config apply
    /// can change it (survives `App::clone`).
    pub max_keys_per_principal: usize,
    /// Anti-sprawl cap on the NUMBER of groups a mint may AUTO-PROVISION
    /// (`limits.max_auto_provisioned_groups`). The key cap bounds a group's contents; this bounds
    /// the tree's SHAPE, which a `mint`-scope credential could otherwise grow without bound
    /// `0` = unlimited (default). Carried on the snapshot for the same reason as
    /// `max_keys_per_principal`.
    pub max_auto_provisioned_groups: usize,
    /// governance runtime (virtual keys + budgets/limits store). `None` = disabled.
    pub governance: Option<std::sync::Arc<crate::governance::GovState>>,
    /// The SECRET RESOLVER seam: resolves a config [`crate::config::SecretRef`] to bytes via
    /// the built-in `env`/`file` modules or a loaded `kind: secret` plugin. Held so the TLS listener
    /// (built after `build_app` returns) resolves cert/key/CA references through the same seam that
    /// resolved provider keys and the admin token at build time.
    pub secret_resolver: std::sync::Arc<crate::config::secret::SecretResolver>,
    /// The resolved COST MODEL (rate card + budget groups + flat fee), rebuilt with the config on
    /// every apply/reload while `governance` (the token ledger) survives the swap - which is what
    /// makes a rate-card correction reprice every past and future derived figure on the next read.
    pub cost: std::sync::Arc<crate::cost::CostModel>,
    /// The directory the signed plugin tarballs live in (`plugins.dir`, default `plugins`). Carried
    /// on the snapshot so the Admin API plugin catalog (`GET /api/v1/admin/plugins?type=store`) and
    /// the install/remove/reload endpoints operate on the SAME directory the boot store-load
    /// resolves against — one source of truth, and it survives config swaps (`App::clone` copies it).
    pub plugins_dir: std::path::PathBuf,
    /// The whole `plugins.*` block (master switch + trust + floors) — re-used at admin-install to
    /// RE-VERIFY an uploaded plugin server-side (the client is never trusted) and to project each
    /// catalog entry's trust verdict. Carried on the snapshot (not a global) so it is testable and
    /// survives swaps.
    pub plugins_cfg: crate::config::PluginsCfg,
    /// The composition root's PLUGIN ADMISSION ([`crate::preflight::RootInstall`]'s `admission`,
    /// over the one trust builder boot admits plugins under): every admin moment that judges a
    /// plugin (catalog, install, inspect, rollback) resolves `plugins_cfg` through it and through
    /// nothing else, so the operator surface reports the verdict boot reaches. `None` = no root
    /// installed one.
    pub plugin_admission: Option<&'static dyn crate::admission::PluginAdmission>,

    /// The self-serve (token-exchange) key lifetime in seconds, resolved from `auth.key_ttl`
    /// (`parse_duration_secs`, default [`crate::governance::mint_policy::DEFAULT_KEY_TTL_SECS`] = 90d). This is where
    /// the Step-1 `auth.key_ttl` field is finally READ: `POST /auth/token` mints every self key with
    /// `exp = now + self_key_ttl_secs`. Rebuilt on every apply/reload with the rest of the snapshot.
    pub self_key_ttl_secs: u64,
    /// The RESOLVED mint policy (`auth.policy:`, 1.6.0), built once at boot from the config and read
    /// on every mint: the deployment-wide TTL ceiling (`max_ttl`) + allowed binding modes + the
    /// per-role `mint_ceilings` (the delegated-app-admin caps, review H2/H3). `Default` (empty) = no
    /// policy ⇒ byte-identical pre-1.6.0 behavior. See [`crate::governance::mint_policy::MintPolicy`].
    pub mint_policy: std::sync::Arc<crate::governance::mint_policy::MintPolicy>,
    /// Per-request correlation-id generator: `fetch_add(1, Relaxed)` stamps a fresh `u64` on every
    /// inbound request (see [`App::next_request_id`]), so a routing DECISION (the hook seam) can be
    /// joined to its OUTCOME (the response tap) and per-request log lines are correlatable — a
    /// single monotonic atomic, never a UUID/String, so it costs no per-request allocation, RNG
    /// draw, or syscall on the hot path.
    ///
    /// SEEDED ONCE AT BOOT from OS entropy (`state::seed_request_id_counter`), not zero, so ids are
    /// a real cross-restart join key (two runs of the process don't restamp the same small integers
    /// starting at 1) — see that function's doc for the entropy source + fallback.
    ///
    /// Lives on `App` (not a bare `static AtomicU64`) so it is Arc-shared like `store`/
    /// `probe_schedule`: a config apply's `(*current).clone()` and a REBUILD's carry-over from
    /// `prior` (`build_app_from_config`) both keep the SAME counter instance, so ids stay monotonic
    /// across a config reload the way `admin`/`mutation_limiter` already do — and it is
    /// constructible per-test (no hidden global), matching this file's existing "no global mutable
    /// state" convention for live per-process counters (see `QueuedDepth`, `VersionLog`).
    pub request_id_counter: Arc<std::sync::atomic::AtomicU64>,
    /// The live PLUGIN HTTP ROUTE TABLE: the collision-checked, namespace-confined
    /// `{path, method}` → owning-plugin index behind every registered plugin route (`/metrics`, a
    /// hook's `/feedback`). Carried on the snapshot (Arc-shared for cheap `App::clone`) so the mounted
    /// route handler resolves the CURRENT owner on every request — a hot-swapped telemetry plugin never
    /// leaves a stale route. Empty until an export/hook plugin declares a route; an empty table
    /// is inert (no mounts, `declared_auth` returns `None`, so the auth middleware is unaffected).
    pub plugin_routes: Arc<crate::plugin_routes::PluginRouteTable>,
    /// The plugin-route PATHS this PROCESS can actually serve: the [`plugin_routes`] table's path set
    /// as it stood at BOOT, carried forward byte-identical through every rebuild
    /// (`build_app_from_config` inherits it from `prior`; only a fresh boot, `prior == None`, seeds it).
    ///
    /// It is deliberately NOT `plugin_routes.paths()` of the current snapshot: each declared path is
    /// registered on the axum router once, at boot, and a config apply swaps only `Arc<App>` — the
    /// router is never rebuilt. So a config that ADDS a path (an `export:` prometheus instance where
    /// none existed at boot) is durably stored and live on the snapshot, yet the path keeps 404ing
    /// until a restart. This is the only thing that knows the difference, and it is what lets a config
    /// mutation tell the operator "restart required" instead of silently no-opping
    /// ([`crate::plugin_routes::paths_awaiting_restart`]).
    pub boot_route_paths: Arc<std::collections::HashSet<String>>,
    /// The plane SECTIONS this generation's configuration writes whose plane the process did not
    /// open at boot ([`crate::appbuild::RootRules::planes_awaiting_restart`]): stored and
    /// validated, given no slot, and served from the next restart. Sorted; empty when every
    /// written plane is served.
    pub planes_awaiting_restart: Vec<String>,
}

pub struct AppParts {
    pub fallback_runtime_key: &'static str,

    pub serve_tables: crate::plane_driver::serve::ServeTables,

    pub root_rules: Arc<dyn crate::appbuild::RootRules>,

    pub config_projection: Option<Arc<dyn std::any::Any + Send + Sync>>,

    pub config_tables: Arc<busbar_kernel::plane_driver::route_tables::ConfigTables>,

    pub store: Arc<dyn LaneRuntime>,

    pub limits: Option<crate::config::LimitsResolved>,

    pub session_store: Arc<crate::session::SessionStore>,

    pub incremental_scan: bool,

    pub plane_pools: std::collections::BTreeMap<
        &'static str,
        std::collections::BTreeMap<String, crate::config::pools::CandidatePoolCfg>,
    >,

    pub auth: Arc<crate::auth::AuthMiddleware>,

    pub rewrite_hooks: Vec<(std::time::Duration, Arc<dyn crate::hooks::RoutingPolicy>)>,

    pub tap_hooks: Vec<crate::hooks::TapEntry>,

    pub tap_hooks_candidate: Vec<crate::hooks::TapEntry>,

    pub tap_hooks_routing: Vec<crate::hooks::TapEntry>,

    pub tap_hooks_response: Vec<crate::hooks::TapEntry>,

    pub global_gates: Vec<(u16, crate::hooks::ResolvedPolicy)>,

    pub pool_orderings: std::collections::HashMap<String, crate::hooks::ResolvedPolicy>,

    pub pool_decision_gates:
        std::collections::HashMap<String, Vec<(u16, crate::hooks::ResolvedPolicy)>>,

    pub pool_rewrite_chains: ContainerRewriteMap,

    pub plane_gates: PlaneGateMap,

    pub plane_rewrites: PlaneRewriteMap,

    pub hook_env: crate::hooks::HookEnv,

    pub hook_registry: HashMap<String, crate::config::HookCfg>,

    pub requested_signals: crate::hooks::RequestedSignals,

    pub any_content_hook: bool,

    pub global_hooks: Vec<String>,

    pub base_hook_names: std::collections::HashSet<String>,

    pub groups_registry: std::collections::BTreeMap<String, crate::config::GroupCfg>,

    pub base_group_names: std::collections::HashSet<String>,

    pub identity_providers: crate::config::IdentityProviders,

    pub export_defs: crate::config::ExportDefs,

    pub admin: Arc<crate::admin::seam::AdminSlot>,

    pub admin_chain: Vec<String>,

    pub admin_modules: Arc<crate::auth::AdminAuthChain>,

    pub public_url: Option<String>,

    pub oauth_as: Option<Arc<dyn std::any::Any + Send + Sync>>,

    pub demotion_record: Arc<crate::trust::demotion::DemotionRecord>,

    pub amendments: Arc<crate::audit::amend::NodeAmendments>,

    pub planes: Arc<crate::plane_driver::dispatch::PlaneDispatch>,

    pub plane_slots: std::collections::BTreeMap<&'static str, Arc<dyn std::any::Any + Send + Sync>>,

    pub plane_sections: Option<std::collections::BTreeSet<&'static str>>,

    pub auth_scope_caps: std::collections::HashMap<String, String>,

    pub role_bindings: crate::config::RoleBindings,

    pub config_path: Option<std::path::PathBuf>,

    pub providers_path: Option<std::path::PathBuf>,

    pub overlay_path: Option<Arc<crate::config::overlay::OverlayStore>>,

    pub config_version: u64,

    pub max_keys_per_principal: usize,

    pub max_auto_provisioned_groups: usize,

    pub governance: Option<std::sync::Arc<crate::governance::GovState>>,

    pub secret_resolver: std::sync::Arc<crate::config::secret::SecretResolver>,

    pub cost: std::sync::Arc<crate::cost::CostModel>,

    pub plugins_dir: std::path::PathBuf,

    pub plugins_cfg: crate::config::PluginsCfg,

    pub plugin_admission: Option<&'static dyn crate::admission::PluginAdmission>,

    pub self_key_ttl_secs: u64,

    pub mint_policy: std::sync::Arc<crate::governance::mint_policy::MintPolicy>,

    pub request_id_counter: Arc<std::sync::atomic::AtomicU64>,

    pub plugin_routes: Arc<crate::plugin_routes::PluginRouteTable>,

    pub boot_route_paths: Arc<std::collections::HashSet<String>>,

    pub planes_awaiting_restart: Vec<String>,
}

#[must_use]
pub fn planes_awaiting_restart_added(installed: &App, previous: &App) -> Vec<String> {
    installed
        .planes_awaiting_restart
        .iter()
        .filter(|s| !previous.planes_awaiting_restart.contains(s))
        .cloned()
        .collect()
}

impl App {
    pub(crate) fn assemble(
        parts: AppParts,
        tslots: Arc<crate::telemetry::AppSlots>,
        export_projections: crate::export::projection::ProjectionUnion,
        mutation_limiter: Arc<crate::ratelimit::MutationLimiter>,
        login_methods: Arc<crate::auth::login::LoginMethods>,
    ) -> Self {
        let AppParts {
            fallback_runtime_key,
            serve_tables,
            root_rules,
            config_projection,
            config_tables,
            store,
            limits,
            session_store,
            incremental_scan,
            plane_pools,
            auth,
            rewrite_hooks,
            tap_hooks,
            tap_hooks_candidate,
            tap_hooks_routing,
            tap_hooks_response,
            global_gates,
            pool_orderings,
            pool_decision_gates,
            pool_rewrite_chains,
            plane_gates,
            plane_rewrites,
            hook_env,
            hook_registry,
            requested_signals,
            any_content_hook,
            global_hooks,
            base_hook_names,
            groups_registry,
            base_group_names,
            identity_providers,
            export_defs,
            admin,
            admin_chain,
            admin_modules,
            public_url,
            oauth_as,
            demotion_record,
            amendments,
            planes,
            plane_slots,
            plane_sections,
            auth_scope_caps,
            role_bindings,
            config_path,
            providers_path,
            overlay_path,
            config_version,
            max_keys_per_principal,
            max_auto_provisioned_groups,
            governance,
            secret_resolver,
            cost,
            plugins_dir,
            plugins_cfg,
            plugin_admission,
            self_key_ttl_secs,
            mint_policy,
            request_id_counter,
            plugin_routes,
            boot_route_paths,
            planes_awaiting_restart,
        } = parts;
        Self {
            tslots,
            fallback_runtime_key,
            serve_tables,
            root_rules,
            config_projection,
            config_tables,
            store,
            limits,
            session_store,
            incremental_scan,
            plane_pools,
            auth,
            rewrite_hooks,
            tap_hooks,
            tap_hooks_candidate,
            tap_hooks_routing,
            tap_hooks_response,
            global_gates,
            pool_orderings,
            pool_decision_gates,
            pool_rewrite_chains,
            plane_gates,
            plane_rewrites,
            hook_env,
            hook_registry,
            requested_signals,
            any_content_hook,
            export_projections,
            global_hooks,
            base_hook_names,
            groups_registry,
            base_group_names,
            identity_providers,
            export_defs,
            mutation_limiter,
            admin,
            admin_chain,
            admin_modules,
            login_methods,
            public_url,
            oauth_as,
            demotion_record,
            amendments,
            planes,
            plane_slots,
            plane_sections,
            auth_scope_caps,
            role_bindings,
            config_path,
            providers_path,
            overlay_path,
            config_version,
            max_keys_per_principal,
            max_auto_provisioned_groups,
            governance,
            secret_resolver,
            cost,
            plugins_dir,
            plugins_cfg,
            plugin_admission,
            self_key_ttl_secs,
            mint_policy,
            request_id_counter,
            plugin_routes,
            boot_route_paths,
            planes_awaiting_restart,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn from_test_parts(parts: AppParts) -> Self {
        Self::assemble(
            parts,
            Arc::new(crate::telemetry::AppSlots::default()),
            crate::export::projection::ProjectionUnion::default(),
            Arc::new(crate::ratelimit::MutationLimiter::new()),
            Arc::new(crate::auth::login::LoginMethods::empty()),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn set_test_telemetry<'a>(
        &mut self,
        pools: &[(&'a str, Vec<usize>)],
        by_model: &[(&'a str, usize)],
        lane_model: impl Fn(usize) -> Option<&'a str>,
        plane: &'static str,
    ) {
        self.tslots = Arc::new(crate::telemetry::AppSlots::build(
            pools, by_model, lane_model, plane,
        ));
    }

    pub fn flush_verified_credentials(&self, module: Option<&str>) -> Result<u64, String> {
        let mut flushed = 0;
        let mut failure = None;
        for (_, instance) in self
            .admin_modules
            .modules
            .iter()
            .filter(|(name, _)| module.is_none_or(|m| m == name.as_str()))
        {
            match instance.calls.refresh() {
                Ok(count) => flushed += count,
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        match self.auth.flush_verified(module) {
            Ok(count) => flushed += count,
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(flushed), Err)
    }
}

impl App {
    pub fn plane_configured(&self, decl: &crate::plane_driver::registry::PlaneDeclaration) -> bool {
        decl.fallback
            || self
                .plane_sections
                .as_ref()
                .is_none_or(|s| s.contains(decl.config_section))
    }

    pub fn engine_tables_view(
        &self,
    ) -> &dyn busbar_kernel::plane_driver::route_tables::EngineTablesView {
        let key = self.fallback_runtime_key;
        match (
            crate::plane_driver::registry::plane_decl_for(
                crate::plane_driver::dispatch::fallback_key(),
            )
            .and_then(|d| d.viewer),
            self.plane_slot(key),
        ) {
            (Some(viewer), Some(slot)) => viewer(slot.as_ref()),
            _ => &*self.config_tables,
        }
    }

    pub fn oauth_as_any(&self) -> Option<&Arc<dyn std::any::Any + Send + Sync>> {
        self.oauth_as.as_ref()
    }
}

impl App {
    pub fn upstream_creds(&self) -> crate::auth::UpstreamCreds {
        self.engine_tables_view().upstream_creds()
    }

    pub fn next_request_id(&self) -> u64 {
        self.request_id_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    pub fn plane_slot(&self, key: &str) -> Option<&Arc<dyn std::any::Any + Send + Sync>> {
        self.plane_slots.get(key)
    }

    pub fn plane_slot_mut(
        &mut self,
        key: &str,
    ) -> Option<&mut Arc<dyn std::any::Any + Send + Sync>> {
        self.plane_slots.get_mut(key)
    }

    pub fn fallback_runtime_key(&self) -> &'static str {
        self.fallback_runtime_key
    }

    pub fn plane_gates(&self, plane_key: &str) -> Option<&ContainerGateMap> {
        self.plane_gates.get(plane_key)
    }

    pub fn plane_rewrites(&self, plane_key: &str) -> Option<&ContainerRewriteMap> {
        self.plane_rewrites.get(plane_key)
    }

    pub fn pool_policy(&self, pool: &str) -> Option<&crate::hooks::ResolvedPolicy> {
        self.pool_orderings.get(pool)
    }

    pub fn pool_gates(&self, pool: &str) -> &[(u16, crate::hooks::ResolvedPolicy)] {
        self.pool_decision_gates
            .get(pool)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    #[allow(clippy::type_complexity)]
    pub fn pool_rewrites(
        &self,
        pool: &str,
    ) -> &[(
        std::time::Duration,
        std::sync::Arc<dyn crate::hooks::RoutingPolicy>,
    )] {
        self.pool_rewrite_chains
            .get(pool)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn publish_limits(&self) {
        if let Some(limits) = &self.limits {
            busbar_kernel::config::limits::publish(limits);
        }
    }

    pub fn plane_pools(
        &self,
        plane_key: &str,
    ) -> Option<&std::collections::BTreeMap<String, crate::config::pools::CandidatePoolCfg>> {
        self.plane_pools.get(plane_key)
    }

    pub fn resolve_container_gates<'a>(
        &self,
        containers: impl Iterator<Item = (&'a str, &'a [String])>,
        section_hooks: &[String],
    ) -> HashMap<String, Vec<(u16, crate::hooks::ResolvedPolicy)>> {
        crate::hooks::resolve_container_gates(
            containers,
            section_hooks,
            &self.hook_registry,
            &self.hook_env,
            self.config_version,
        )
    }

    #[allow(clippy::type_complexity)]
    pub fn resolve_container_rewrites<'a>(
        &self,
        containers: impl Iterator<Item = (&'a str, &'a [String])>,
        section_hooks: &[String],
    ) -> HashMap<String, Vec<(std::time::Duration, Arc<dyn crate::hooks::RoutingPolicy>)>> {
        crate::hooks::resolve_container_rewrites(
            containers,
            section_hooks,
            &self.hook_registry,
            &self.hook_env,
            self.config_version,
        )
    }
}

impl busbar_kernel::plane_driver::slots::PlaneSlots for App {
    fn plane_slot(&self, key: &str) -> Option<&Arc<dyn std::any::Any + Send + Sync>> {
        App::plane_slot(self, key)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl busbar_kernel::plane_driver::slots::ContainerGateSink for App {
    fn reresolve_container_gates(
        &mut self,
        plane_key: &str,
        containers: &[(&str, &[String])],
        section_hooks: &[String],
    ) {
        let gates = self.resolve_container_gates(containers.iter().copied(), section_hooks);

        let rewrites = self.resolve_container_rewrites(containers.iter().copied(), section_hooks);

        if let Some(static_key) =
            crate::plane_driver::registry::plane_decl_for(plane_key).map(|d| d.key)
        {
            self.plane_gates.insert(static_key, gates);
            self.plane_rewrites.insert(static_key, rewrites);
        }
    }
}

pub fn seed_request_id_counter() -> u64 {
    let mut buf = [0u8; 8];
    match getrandom::fill(&mut buf) {
        Ok(()) => u64::from_le_bytes(buf),
        Err(_) => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    }
}

pub struct AppHandle {
    current: arc_swap::ArcSwap<App>,

    #[cfg(debug_assertions)]
    swapping: std::sync::atomic::AtomicBool,

    snapshot_host: std::sync::Mutex<Option<Arc<dyn busbar_kernel::plane_driver::EngineHost>>>,

    attach: std::sync::OnceLock<fn(&Arc<dyn busbar_kernel::plane_driver::EngineHost>)>,

    appliers: std::sync::Mutex<Vec<SharedApplier>>,

    door_refuser: std::sync::OnceLock<busbar_kernel::plane_routes::PlaneRefuseByPathFn>,
}

pub type Applier = Box<dyn Fn(&Arc<App>) + Send + Sync>;
type SharedApplier = Arc<dyn Fn(&Arc<App>) + Send + Sync>;

impl AppHandle {
    pub fn new(app: Arc<App>) -> Self {
        Self {
            current: arc_swap::ArcSwap::new(app),
            #[cfg(debug_assertions)]
            swapping: std::sync::atomic::AtomicBool::new(false),
            snapshot_host: std::sync::Mutex::new(None),
            attach: std::sync::OnceLock::new(),
            appliers: std::sync::Mutex::new(Vec::new()),
            door_refuser: std::sync::OnceLock::new(),
        }
    }

    pub fn bind_door_refuser(&self, refuser: busbar_kernel::plane_routes::PlaneRefuseByPathFn) {
        let _first = self.door_refuser.set(refuser);
    }

    pub fn door_refusal(
        &self,
        refusal: &busbar_kernel::plane_routes::KernelRefusal<'_>,
    ) -> Option<axum::response::Response> {
        self.door_refuser.get().and_then(|refuse| refuse(refusal))
    }

    pub fn on_apply(&self, applier: Applier) {
        self.appliers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::from(applier));
    }

    pub fn attach_on_swap(&self, attach: fn(&Arc<dyn busbar_kernel::plane_driver::EngineHost>)) {
        let _ = self.attach.set(attach);
    }

    pub fn set_snapshot_host(&self, host: Arc<dyn busbar_kernel::plane_driver::EngineHost>) {
        let previous = self
            .snapshot_host
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(host);
        drop(previous);
    }

    pub fn load(&self) -> Arc<App> {
        self.current.load_full()
    }

    pub fn snapshot(&self) -> arc_swap::Guard<Arc<App>> {
        self.current.load()
    }

    pub fn swap(&self, next: Arc<App>) {
        self.swap_with_commit(next, || Ok(None), &mut false)
            .expect("a swap with no price preparation cannot refuse publication");
    }

    fn swap_with_commit(
        &self,
        next: Arc<App>,
        confirm: impl FnOnce() -> Result<Option<crate::appbuild::ConfirmedLimits>, String>,
        published: &mut bool,
    ) -> Result<(), String> {
        #[cfg(debug_assertions)]
        let _swap_guard =
            {
                struct Guard<'a>(&'a std::sync::atomic::AtomicBool);
                impl Drop for Guard<'_> {
                    fn drop(&mut self) {
                        self.0.store(false, std::sync::atomic::Ordering::Release);
                    }
                }
                assert!(
                !self.swapping.swap(true, std::sync::atomic::Ordering::AcqRel),
                "AppHandle::swap ran concurrently with another swap on the same handle — every \
                 mutation must funnel through the serialized persist-then-swap path"
            );
                Guard(&self.swapping)
            };

        let prior = self.load();
        for decl in crate::plane_driver::registry::plane_decls() {
            if let Some(on_swap) = decl.on_swap {
                on_swap(
                    &*prior as &dyn busbar_kernel::plane_driver::slots::PlaneSlots,
                    &*next as &dyn busbar_kernel::plane_driver::slots::PlaneSlots,
                );
            }
        }

        let confirmed = confirm()?;
        let committed = match confirmed {
            Some(confirmed) => Some(confirmed.keep()),
            None => {
                next.publish_limits();
                None
            }
        };
        self.current.store(next.clone());
        *published = true;
        crate::export::plugin::queue_refresh(&next.export_defs, next.config_version);
        if let Some(committed) = committed {
            committed.notify();
        }

        let host = crate::plane_driver::engine_host(&next);
        if let Some(attach) = self.attach.get() {
            attach(&host);
        }
        self.set_snapshot_host(host);

        let appliers = self
            .appliers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for applier in appliers {
            applier(&next);
        }
        Ok(())
    }

    pub fn commit_and_swap(
        &self,
        next: Arc<App>,
        persist: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        persist()?;
        let mut publication = UnpublishedOverlay::new(self.load().overlay_path.clone());
        self.swap_with_commit(next, || Ok(None), &mut publication.published)
    }

    pub fn commit_rates_and_swap(
        &self,
        next: Arc<App>,
        persist: impl FnOnce() -> Result<(), String>,
        limits: crate::appbuild::InstalledLimits,
        origin: &str,
    ) -> Result<(), String> {
        self.publish_rates_and_swap(next, persist, limits, origin, RatePreparation::Mutation)
    }

    pub fn reload_rates_and_swap(
        &self,
        next: Arc<App>,
        persist: impl FnOnce() -> Result<(), String>,
        limits: crate::appbuild::InstalledLimits,
        origin: &str,
    ) -> Result<(), String> {
        self.publish_rates_and_swap(next, persist, limits, origin, RatePreparation::Reload)
    }

    fn publish_rates_and_swap(
        &self,
        next: Arc<App>,
        persist: impl FnOnce() -> Result<(), String>,
        limits: crate::appbuild::InstalledLimits,
        origin: &str,
        preparation: RatePreparation,
    ) -> Result<(), String> {
        persist()?;
        let mut publication = UnpublishedOverlay::new(self.load().overlay_path.clone());
        self.swap_with_commit(
            next,
            || {
                crate::rate_apply::with_origin(origin, || {
                    let prepared = match preparation {
                        RatePreparation::Mutation => limits.prepare_rates(),
                        RatePreparation::Reload => limits.prepare_rates_for_reload(),
                    }?;
                    prepared.confirm_activation().map(Some)
                })
            },
            &mut publication.published,
        )
    }
}

enum RatePreparation {
    Mutation,
    Reload,
}

struct UnpublishedOverlay {
    overlay: Option<Arc<crate::config::overlay::OverlayStore>>,
    published: bool,
}

impl UnpublishedOverlay {
    fn new(overlay: Option<Arc<crate::config::overlay::OverlayStore>>) -> Self {
        Self {
            overlay,
            published: false,
        }
    }
}

impl Drop for UnpublishedOverlay {
    fn drop(&mut self) {
        if !self.published {
            if let Some(overlay) = &self.overlay {
                overlay.require_reload();
            }
        }
    }
}

pub struct CurrentApp(pub Arc<App>);

impl<S> axum::extract::FromRequestParts<S> for CurrentApp
where
    Arc<AppHandle>: axum::extract::FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        if let Some(admission) = parts.extensions.get::<crate::inbound::RequestAdmission>() {
            return Ok(CurrentApp(admission.app()));
        }
        if let Some(app) = parts.extensions.get::<Arc<App>>() {
            return Ok(CurrentApp(Arc::clone(app)));
        }

        let axum::extract::State(handle) =
            axum::extract::State::<Arc<AppHandle>>::from_request_parts(parts, state).await?;
        Ok(CurrentApp(handle.load()))
    }
}

#[cfg(test)]
#[path = "tests/state_tests.rs"]
mod state_tests;

#[cfg(test)]
#[path = "tests/app_parts_tests.rs"]
mod app_parts_tests;
