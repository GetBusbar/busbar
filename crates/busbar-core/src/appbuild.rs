//! APP CONSTRUCTION — how a `busbar` process's App comes to exist: the environment axes, the
//! boot banners, config load from disk, and `build_app_from_config` (the one function that turns a
//! validated `RootCfg` into a living `App`). Reached from the binary's `run()` AND from the admin
//! plane's config PATCH/reload path (`admin/v1/json/*` re-runs the load pipeline on a live apply),
//! which is why this is core and not bin: a hot reload that called UP into the composition root
//! would be the dependency inversion the core split exists to remove.

use std::collections::HashMap;
use std::sync::Arc;

use crate::auth::AuthMiddleware;
use crate::diagnostics::{
    diag_error, diag_warn, DEPRECATED_ENV_VAR_HONORED, DURABLE_KEYS_INERT,
    GOVERNANCE_STORE_EPHEMERAL, OAUTH_AS_EPHEMERAL_SIGNING_KEY, OPEN_RELAY_NO_AUTH,
    PLUGINS_FETCH_RELOAD_MISS, PROVIDER_API_KEY_UNRESOLVED, SAFE_MODE_OVERLAY_QUARANTINED,
    STATEFUL_PLANE_EPHEMERAL_STORE, STORE_SECRET_REF_UNRESOLVED,
};
use crate::preflight::{
    build_secret_resolver, plugin_fetch_downloader, plugins_preflight, resolve_admin_token,
    resolve_signing_key, validate_secret_refs,
};
use crate::router::project_auth_scope_caps;
use crate::state::App;
use crate::store::{HealthState, LaneData};
#[allow(unused_imports)]
use crate::{
    admin, audit, auth, auth_cache, billing, breaker, catalogue, config, config_validate,
    core_routes, cost, durable, egress_auth, endpoints, eventstream, export, failover, governance,
    handlers, hooks, ingress, ir, json, limits, lossless, media, metrics, net_guard, oauth_as,
    observability, operation, plane, plugin_routes, profile, proto, proxy, sigv4, state, store,
    telemetry, tls, transport, trust,
};
use busbar_substrate::plane_host::{
    AffinityInput, AuthStyleInput, ClientSettingsInput, FailoverInput, HealthInput,
    HealthModeInput, LaneInput, OnExhaustedInput, PlaneBuildInput, PoolInput, PoolMemberInput,
};

// The upstream-request timeout, pool-idle, and request-body caps that used to live here as `const`s
// are now operator-tunable (`limits.upstream_request_timeout_secs` / `pool_max_idle_per_host` /
// `request_body_max_bytes`), each defaulting to its historical value at the config layer. They are
// threaded from `cfg.limits` into the client builder and router below; the egress translate-body cap
// is COUPLED to `request_body_max_bytes` via `crate::limits::translate_body_max_bytes`.

/// Environment variable name for the config.yaml path — the one irreducible bootstrap env var.
pub const ENV_CONFIG: &str = "BUSBAR_CONFIG";

/// DEPRECATED (1.5.3) environment variable name for the providers.yaml path — migrated to the
/// top-level `providers_file:` key in config.yaml. Still honored, with a deprecation warning, so an
/// operator's existing pin keeps working across the upgrade.
pub const ENV_PROVIDERS: &str = "BUSBAR_PROVIDERS";

/// DEPRECATED (1.5.3) environment variable name for the config-overlay backend path — migrated to
/// `config.overlay.file` in config.yaml. Still honored, with a deprecation warning, only when
/// `config.overlay` is unset.
pub const ENV_CONFIG_OVERLAY: &str = "BUSBAR_CONFIG_OVERLAY";

/// DEPRECATED (1.5.3) environment variable that forces HTTP/2 prior-knowledge for cleartext
/// upstreams — migrated to `advanced.upstream_h2_prior_knowledge`. Still honored, with a warning.
pub const ENV_UPSTREAM_H2_PRIOR_KNOWLEDGE: &str = "BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE";

/// DEPRECATED (1.5.3) environment variable that pins the shared upstream client to HTTP/1.1 —
/// migrated to `advanced.upstream_http1_only`. Still honored, with a warning.
pub const ENV_UPSTREAM_HTTP1_ONLY: &str = "BUSBAR_UPSTREAM_HTTP1_ONLY";

/// A deprecated boolean env override on top of a config value: an UNSET var defers to the config
/// value; a set var wins, with anything other than empty/`"0"` reading as `true`.
fn upstream_bool_env_override(env: Option<std::ffi::OsString>, config_val: bool) -> bool {
    match env {
        Some(v) => v != "0" && !v.is_empty(),
        None => config_val,
    }
}

/// Default path to the deployment config file.
///
/// A UNIX path, and it is NOT made platform-conditional on purpose. On Windows `/etc/busbar/...` is
/// drive-relative — it resolves against whatever drive the process is running from — so the default
/// is not a usable location there and `BUSBAR_CONFIG` is effectively required. That is the right
/// failure: the miss is loud (the config file is not found, named, at startup, before anything is
/// served) and the fix is one env var. Inventing a second default like
/// `C:\ProgramData\busbar\config.yaml` would instead make busbar SILENTLY read a *different* file
/// per platform, and this constant is the bootstrap of every other trust decision in the process —
/// "which file is my config" is the one question that must never have a platform-dependent answer
/// nobody was told about. Documented for operators in `docs/operations.md`.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/busbar/config.yaml";

/// Return the open-relay banner to emit when the auth chain is EMPTY (open front door), or `None`
/// when an auth module is engaged. `chain_empty` = the resolved `auth.chain` is empty. `auth_present`
/// distinguishes an explicit empty chain (operator opted in) from a missing `auth:` block
/// (serde-defaulted to open — the silent foot-gun the banner must call out).
pub fn open_relay_banner(chain_empty: bool, auth_present: bool) -> Option<&'static str> {
    if !chain_empty {
        return None;
    }
    Some(if auth_present {
        "auth is DISABLED (auth.chain is empty) — busbar is running as an OPEN RELAY; do not run this in production"
    } else {
        "auth is DISABLED: no `auth:` block in config — busbar is running as an OPEN RELAY (anyone can use it). Add `auth:` with `chain: [keys]` (and mint virtual keys via the admin API) before exposing it; do not run this in production"
    })
}

/// Return the INERT-KEYS banner to emit when a DURABLE governance store still holds virtual keys
/// from a prior run but the running `auth.chain` does NOT name the `keys` verifier. Enforcement of a
/// virtual key is now decided by the CHAIN SHAPE, not the admin token: only when `keys` is in the
/// data-plane chain does any request resolve to (and get governed by) a stored vkey. So if `keys`
/// is absent, the persisted keys' per-key controls (budget, RPM/TPM, allowed_pools) are silently
/// NOT enforced — no data-plane request ever resolves them. A RAM store can never reach this state
/// (it starts empty every boot), so this is scoped to durable stores. Returns `None` when the state
/// does not apply (RAM store, no keys, or `keys` IS in the chain). `key_count` is the number of keys
/// the store reports at boot; `keys_in_chain` is whether `auth.chain` names the `keys` verifier.
pub fn inert_durable_keys_banner(
    store_is_durable: bool,
    key_count: usize,
    keys_in_chain: bool,
) -> Option<String> {
    if store_is_durable && key_count > 0 && !keys_in_chain {
        Some(format!(
            "durable governance store contains {key_count} key(s) but auth.chain does not name the \
             `keys` verifier — those keys are INERT and NOT enforced (per-key budget / RPM / TPM / \
             allowed_pools are bypassed; no data-plane request resolves them). Add `keys` to \
             auth.chain to enforce them."
        ))
    } else {
        None
    }
}

/// Return the STATEFUL-PLANE ephemeral-store WARN to emit, or `None` when no sharper warn applies.
///
/// The generic [`crate::diagnostics::GOVERNANCE_STORE_EPHEMERAL`] notice beside the store resolution
/// speaks to GOVERNANCE state (keys / usage / ledgers). MCP and A2A are ALSO stateful planes: their
/// in-flight TASK state lives only in the resolved store, so on the RAM store it is dropped on
/// restart and any task that was mid-flight breaks on its next request. This returns a sharper warn
/// NAMING that consequence — but ONLY when the RAM store is resolved AND a stateful plane is actually
/// configured (`mcp_stateful` = an MCP server or tool-pool is present; `a2a_stateful` = an A2A agent
/// or agent-pool is present). An LLM-only deployment is STATELESS — a restart costs it nothing — so
/// it gets only the generic notice: a sharper warn there would be noise that trains operators to
/// ignore warnings. This is a WARN, never a boot-block: a durable store is opt-in and RAM is the
/// convenience default, so busbar does not refuse to start.
pub fn stateful_plane_ephemeral_store_warn(
    store_is_memory: bool,
    mcp_stateful: bool,
    a2a_stateful: bool,
) -> Option<&'static str> {
    if store_is_memory && (mcp_stateful || a2a_stateful) {
        Some(
            "Stateful plane task state will NOT survive a restart — in-flight tasks will break on the next \
             request. Configure a durable store (sqlite/postgres).",
        )
    } else {
        None
    }
}

/// Map a provider's `Option<config::ProviderAuth>` to the NEUTRAL [`AuthStyleInput`] the carrier holds
/// (`None` ⇒ the protocol's native auth). The LLM plane maps it back to drive `egress_auth::*`.
fn auth_style_of(auth: Option<config::ProviderAuth>) -> AuthStyleInput {
    match auth {
        None => AuthStyleInput::Default,
        Some(config::ProviderAuth::Bearer) => AuthStyleInput::Bearer,
        Some(config::ProviderAuth::ApiKey) => AuthStyleInput::ApiKey,
        Some(config::ProviderAuth::JwtBearer) => AuthStyleInput::JwtBearer,
        Some(config::ProviderAuth::OAuthClientCredentials) => {
            AuthStyleInput::OAuthClientCredentials
        }
    }
}

/// Mirror a provider `health:` block into the neutral [`HealthInput`] carrier field.
fn health_input_of(h: &config::HealthCfg) -> HealthInput {
    HealthInput {
        mode: match h.mode {
            config::HealthMode::None => HealthModeInput::None,
            config::HealthMode::Dead => HealthModeInput::Dead,
            config::HealthMode::Active => HealthModeInput::Active,
        },
        interval_secs: h.interval_secs,
        timeout_secs: h.timeout_secs,
    }
}

/// Mirror a pool `failover:` block into the neutral [`FailoverInput`] carrier field.
fn failover_input_of(f: &config::FailoverCfg) -> FailoverInput {
    FailoverInput {
        timeout_secs: f.timeout_secs,
        exclusions: f.exclusions.clone(),
        max_hops: f.max_hops,
    }
}

/// Mirror a pool `affinity:` block into the neutral [`AffinityInput`] carrier field (the single
/// supported `session` mode is implied by presence; only the header name is carried).
fn affinity_input_of(a: &config::AffinityCfg) -> AffinityInput {
    AffinityInput {
        header_name: a.header_name.clone(),
    }
}

/// Mirror a pool `on_exhausted:` policy into the neutral [`OnExhaustedInput`] carrier field.
fn on_exhausted_input_of(o: &config::OnExhausted) -> OnExhaustedInput {
    match o {
        config::OnExhausted::Status503 => OnExhaustedInput::Status503,
        config::OnExhausted::FallbackPool(name) => OnExhaustedInput::FallbackPool(name.clone()),
        config::OnExhausted::LeastBad => OnExhaustedInput::LeastBad,
        config::OnExhausted::Queue { max_ms } => OnExhaustedInput::Queue { max_ms: *max_ms },
    }
}

/// Resolve each model's single `context_max` from the pool members that reference it.
///
/// A model is realized as exactly one lane (keyed by model name in `by_model`), so its
/// context window must be single-valued across every pool that lists it. We accept the same
/// `context_max` repeated (including the same `Some(_)` in multiple pools, and a mix of an
/// explicit value with `None` — the explicit value wins, since `None` only means "unspecified
/// here"), but reject two DIFFERENT explicit limits for the same model: that is an operator
/// contradiction that previously resolved nondeterministically to whichever pool iterated last.
pub fn resolve_model_context_max(
    pools: &HashMap<String, config::PoolCfg>,
) -> Result<HashMap<String, Option<usize>>, String> {
    let mut resolved: HashMap<String, Option<usize>> = HashMap::new();
    for pool in pools.values() {
        for m in &pool.members {
            match resolved.get(&m.model) {
                // First sighting of this model, or this member adds no opinion (None) — keep what
                // we have / record what we got.
                None => {
                    resolved.insert(m.model.clone(), m.context_max);
                }
                Some(None) => {
                    // Previously unspecified; let any value (including another None) refine it.
                    resolved.insert(m.model.clone(), m.context_max);
                }
                Some(Some(existing)) => match m.context_max {
                    // No opinion here, or an identical opinion — both fine, keep the explicit value.
                    None => {}
                    Some(c) if c == *existing => {}
                    Some(c) => {
                        return Err(format!(
                            "model '{}' has conflicting context_max across pools ({} vs {}); a model maps to one lane and must declare a single context_max",
                            m.model, existing, c
                        ));
                    }
                },
            }
        }
    }
    Ok(resolved)
}

/// Hard cap on live per-session slots in the neutral session substrate (see [`crate::session`]). The
/// memory-safety bound: on overflow the least-recently-used unpinned slot is evicted, so the store can
/// never grow without limit however many distinct sessions arrive.
const SESSION_STORE_CAPACITY: usize = 65_536;
/// Default TTL for a session slot, in epoch millis of idle time. An hour of no touch and the slot is
/// swept — long enough that an active multi-turn session keeps its cleared-scan set, short enough that
/// abandoned sessions cost nothing.
const SESSION_STORE_TTL_MS: u64 = 60 * 60 * 1_000;

/// Everything the DISK half of configuration produces, shared by boot and runtime reload.
pub struct LoadedConfig {
    pub deploy: config::DeployCfg,
    pub defs: HashMap<String, config::ProviderDef>,
    /// The RESOLVED providers-catalog path actually read (1.5.3): `config.providers_file` relative to
    /// the config dir, the `--providers` flag override, or `providers.yaml` next to the
    /// config. Carried so callers display / re-use the same file across a reload.
    pub providers_path: std::path::PathBuf,
    /// The resolved config-overlay backend path (1.5.3): `Some` = a writable file backend (mutable
    /// config); `None` = either the config is LOCKED (`config.locked: true`) or its backend is not
    /// writable (a read-only config mount — busbar boots and serves, but refuses config mutations).
    /// The boot invariant guarantees `overlay_path.is_none()` whenever busbar cannot durably persist,
    /// so a `Some` path is always one that was probed writable.
    pub overlay_path: Option<std::path::PathBuf>,
    /// `config.locked` (1.5.3): `true` ⇒ admin-API config mutations are refused at runtime.
    pub config_locked: bool,
    /// `true` ⇒ the config did NOT declare `config.locked: true`, but its overlay backend is not
    /// writable (the read-only config mount the documented Docker quickstart creates). Busbar boots
    /// and serves; admin-API config mutations are refused because they could not be persisted.
    /// Distinguished from `config_locked` so the boot log can tell the operator which of the two
    /// postures they are in — one they chose, one the filesystem chose for them.
    pub config_read_only: bool,
    /// The persisted overlay document (API-registered hooks), applied onto the RESOLVED config
    /// (`overlay::merge_into(&mut RootCfg, …)`) after `config::resolve` - the runtime registry is
    /// synthesized there, so the overlay merges post-resolve. `None` = absent / safe mode.
    pub overlay_doc: Option<config::overlay::OverlayDoc>,
    /// `${VAR}` refs that were UNSET during interpolation. Empty under Strict (boot/reload); populated
    /// under Lenient (--validate), where it becomes the "set these at runtime" note.
    pub unset_env_vars: Vec<String>,
}

/// `providers_override`: the `--providers` flag path (Some ⇒ passed), or the live providers path a
/// runtime reload wants to re-use. When `None`, the catalog path is resolved from
/// `config.providers_file` (relative to the config dir) or defaults to `providers.yaml` next to the
/// resolved config.yaml (1.5.3).
#[cold] // boot/admin-only — keeps hot text dense (never inlined into a warm path)
#[inline(never)]
pub fn load_config_from_disk(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    safe_mode: bool,
    env_mode: config::EnvSubst,
) -> Result<LoadedConfig, String> {
    let mut unset_env_vars: Vec<String> = Vec::new();
    // 1.5.3: read + parse config.yaml FIRST — it may name the providers catalog (`providers_file:`).
    let raw_config = std::fs::read_to_string(config_path).map_err(|e| {
        format!(
            "cannot read config file '{}': {e} (set {ENV_CONFIG})",
            config_path.display()
        )
    })?;
    let interpolated_config =
        config::interpolate_env_with(&raw_config, env_mode, &mut unset_env_vars)
            .map_err(|e| format!("config.yaml: {e}"))?;
    // LOUD FAIL-CLOSED on a 1.x config: detect the 1.x structural markers BEFORE the
    // typed parse, so an outdated config gets the NAMED "run --migrate-config" error instead of
    // a pile of unknown-field messages - and, critically, so nothing from 1.x can half-parse
    // into 1.5.0 semantics (the `allowed_pools: []` all->none flip, vanished budgets).
    if let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&interpolated_config) {
        let markers = config::migrate::detect_legacy_markers(&doc);
        if !markers.is_empty() {
            return Err(format!(
                "config.yaml: {}",
                config::migrate::legacy_config_error(&markers)
            ));
        }
    }
    // The 1.6.0-additive keys come off the document FIRST (see `config::prepass`), so what the
    // frozen 1.5.5-shaped structs parse — and what they name in an unknown-key refusal — is the
    // 1.5.5 document and nothing else.
    let deploy: config::DeployCfg =
        config::deploy_from_yaml_str(&interpolated_config).map_err(|e| {
            format!(
                "config.yaml: invalid YAML: {}",
                config::augment_config_error(e)
            )
        })?;

    // 1.6.0: resolve the providers CATALOG path. Precedence: the explicit override (the `--providers`
    // flag, or a runtime reload re-using its boot path) > `config.providers_file`
    // (relative to the config dir) > `providers.yaml` next to the resolved config.yaml.
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let providers_path: std::path::PathBuf = match providers_override {
        Some(p) => p.to_path_buf(),
        None => match deploy.providers_file.as_deref() {
            Some(f) => {
                let p = std::path::Path::new(f);
                if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    config_dir.join(p)
                }
            }
            None => config_dir.join("providers.yaml"),
        },
    };
    let raw_providers = std::fs::read_to_string(&providers_path).map_err(|e| {
        format!(
            "cannot read providers file '{}': {e} (set `providers_file:` in config.yaml, or {ENV_PROVIDERS})",
            providers_path.display()
        )
    })?;
    let interpolated_providers =
        config::interpolate_env_with(&raw_providers, env_mode, &mut unset_env_vars)
            .map_err(|e| format!("providers.yaml: {e}"))?;
    let defs: HashMap<String, config::ProviderDef> = serde_yaml::from_str(&interpolated_providers)
        .map_err(|e| format!("providers.yaml: invalid YAML: {e}"))?;

    // 1.5.3: resolve the config-management posture + overlay backend from the `config:` block, and
    // ENFORCE the boot invariant (`locked` XOR a writable overlay). The deprecated
    // `BUSBAR_CONFIG_OVERLAY` env var is honored only when `config.overlay` is unset. The writability
    // probe runs at boot/reload (Strict) but not under `--validate` (Lenient), which must stay
    // side-effect-free.
    let env_overlay = std::env::var(ENV_CONFIG_OVERLAY)
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);
    let probe_fs = matches!(env_mode, config::EnvSubst::Strict);
    let resolution = config::overlay::resolve_backend_with_env(
        &deploy.config,
        config_path,
        env_overlay.as_deref(),
        probe_fs,
    )?;
    let overlay_path = resolution.path;
    let config_locked = resolution.locked;
    let config_read_only = resolution.read_only_backend;

    if safe_mode {
        // `--safe-mode`: boot on the operator-owned base config ALONE — the persisted overlay
        // (API-registered hooks) is quarantined, not deleted. The escape hatch for "an applied
        // hook is harming traffic and re-applies itself every boot".
        diag_warn!(
            SAFE_MODE_OVERLAY_QUARANTINED,
            "SAFE MODE: config overlay NOT merged — running on base config.yaml alone (the \
             overlay file is untouched; boot without --safe-mode to re-apply it)"
        );
        return Ok(LoadedConfig {
            deploy,
            defs,
            providers_path,
            overlay_path,
            config_locked,
            config_read_only,
            overlay_doc: None,
            unset_env_vars,
        });
    }
    // An overlay from a NEWER busbar is refused, not ignored: it is intact and meaningful, so
    // starting without it would run with the operator's API-registered hooks and groups — security
    // gates included — silently absent. `--safe-mode` boots on base config alone without touching
    // the file, so this is a one-flag recovery rather than a brick.
    if let Some(p) = overlay_path.as_ref() {
        if let config::overlay::OverlayReadState::VersionTooNew(v) = config::overlay::read_state(p)
        {
            return Err(format!(
                "config overlay '{}' was written by a newer busbar (overlay version {v}; this                  binary understands {}). Starting without it would silently drop API-registered                  hooks and groups. Upgrade busbar, or boot with --safe-mode to run on config.yaml                  alone (the overlay is left untouched).",
                p.display(),
                config::overlay::OVERLAY_VERSION
            ));
        }
    }
    let overlay_doc = overlay_path.as_ref().and_then(|p| {
        let doc = config::overlay::read(p);
        if let Some(ref d) = doc {
            tracing::info!(
                path = %p.display(),
                hooks = d.hooks.len(),
                "config overlay loaded (merged onto the resolved config after resolve)"
            );
        }
        doc
    });
    Ok(LoadedConfig {
        deploy,
        defs,
        providers_path,
        overlay_path,
        config_locked,
        config_read_only,
        overlay_doc,
        unset_env_vars,
    })
}

/// A queued-but-not-yet-applied governance credential rotation: `build_app_from_config` resolves it
/// but does NOT invoke it (see the call site below for why). `Send` because it is carried across the
/// `spawn_blocking` boundary the admin transaction (`txn.rs`) applies it on.
pub type GovCredentialRotation = Box<dyn FnOnce() + Send>;

#[cold] // boot/admin-only — keeps hot text dense (never inlined into a warm path)
#[inline(never)]
pub fn build_app_from_config(
    cfg: config::RootCfg,
    plugins_cfg: config::PluginsCfg,
    overlay_path: Option<std::path::PathBuf>,
    base_hook_names: std::collections::HashSet<String>,
    base_group_names: std::collections::HashSet<String>,
    config_paths: (Option<std::path::PathBuf>, Option<std::path::PathBuf>),
    prior: Option<&state::App>,
) -> Result<(state::App, Option<GovCredentialRotation>), String> {
    // Install the resolved operational limits process-wide BEFORE any subsystem reads them —
    // running here (not in main) so a config APPLY/RELOAD refreshes them too. The values threaded
    // explicitly (client/store/router/TLS) read `cfg.limits` directly; the deep call-stack sites
    // (translate-body cap, metrics gauge limit, webhook timeout, governance sqlite/sweep, health
    // probe fallbacks, routing policy timeout) read the installed values.
    //
    // …THROUGH A GUARD, because everything below this line is fallible. The install has to come
    // first (the build itself reads these values), but a build that goes on to FAIL must not leave
    // the rejected config's limits installed under the old `App` that keeps serving. The guard
    // restores the previous values on drop unless the build reaches its `Ok`, so "an invalid apply
    // changes nothing" holds for process-wide limits the same way it holds for everything else.
    let limits_guard = limits::InstallGuard::install(&cfg.limits);
    // The config version this App will carry — computed ONCE up front because hook-transport
    // resolution stamps it into every socket configure preamble (the preamble's
    // settings_version must be the REAL version of the settings it delivers, not a hardcoded 0).
    let app_config_version = prior.map_or(0, |p| p.config_version.wrapping_add(1));
    // Semantic validation — the same gate boot has always had, now on the ONE construction path
    // so an apply/reload validates identically and an invalid config changes nothing.
    if let Err(validation_errors) = config_validate::validate(&cfg) {
        return Err(format!(
            "config validation failed:\n  - {}",
            validation_errors.join("\n  - ")
        ));
    }
    // The resolved `export:` block drives the built-in exporters' plugin-route table below. Captured
    // before `cfg`'s fields are consumed by the `App` struct literal.
    let cfg_export = cfg.export.clone();
    let auth_cfg = cfg
        .auth
        .clone()
        .unwrap_or_else(config::AuthCfg::default_none);

    // DECLARATIVE PLUGIN FETCH (`plugins.fetch:`) — download the operator-declared signed tarballs
    // into `plugins.dir` BEFORE preflight scans it. Runs at BOOT and on `POST /plugins/reload` (both
    // reach this construction path), NEVER in `--validate` (that path never calls
    // `build_app_from_config`, preserving its zero-side-effect/no-network contract), and NEVER
    // per-request. `prior.is_none()` is the boot(fatal-on-miss) vs reload(warn-on-miss) discriminator.
    // Signature verification stays the trust gate below; fetch is integrity/cache + delivery only.
    if plugins_cfg.enabled && !plugins_cfg.fetch.is_empty() {
        let specs = plugins_cfg.fetch_specs()?;
        let dir = std::path::Path::new(&plugins_cfg.dir).to_path_buf();
        // Ensure the target dir exists so the atomic rename has a home.
        if let Err(e) = crate::durable::create_dir_all(&dir) {
            return Err(format!(
                "plugins.fetch: cannot create plugins dir '{}': {e}",
                dir.display()
            ));
        }
        let downloader = plugin_fetch_downloader(&cfg.blocked_metadata_hosts);
        let outcomes =
            busbar_plugin_loader::fetch_plugins(&dir, &specs, prior.is_none(), &downloader)
                .map_err(|errs| format!("plugins.fetch failed:\n  - {}", errs.join("\n  - ")))?;
        for outcome in &outcomes {
            match outcome {
                busbar_plugin_loader::FetchOutcome::Cached { filename } => {
                    tracing::info!(filename, "plugins.fetch: cached (pin match, no download)")
                }
                busbar_plugin_loader::FetchOutcome::Fetched { filename } => {
                    tracing::info!(filename, "plugins.fetch: downloaded + verified")
                }
                busbar_plugin_loader::FetchOutcome::Warned { url, error } => {
                    diag_warn!(
                        PLUGINS_FETCH_RELOAD_MISS,
                        url,
                        error,
                        "plugins.fetch: miss on reload; keeping current artifact"
                    )
                }
            }
        }
    }

    // PLUGIN PRE-FLIGHT (the ONE shared pipeline; see the fn doc). Run UP FRONT so the secret
    // resolver - and the store open below - both draw on the same validated registry. A non-memory
    // store, an unresolvable secret plugin, or any invalid tarball fails boot here.
    let plugin_registry = Arc::new(plugins_preflight(
        cfg.store.as_ref(),
        cfg.auth.as_ref(),
        &cfg.identity_providers,
        &cfg.hooks,
        &plugins_cfg,
        &cfg.export,
    )?);

    // Every SECRET REFERENCE whose module is not a built-in (`env`/`file`) must resolve to a loaded
    // `kind: secret` plugin — the deferred half of the check `config_validate::validate` cannot do
    // (it runs before the registry exists). A typo'd module fails boot HERE; the documented vault
    // `api_key: { module: acme-vault }` passes once the plugin is loaded + trusted. This is the boot
    // twin of the `--validate` check, sharing `validate_secret_refs`/`config_validate::secret_refs`.
    validate_secret_refs(&plugin_registry, &cfg)?;

    // The SECRET RESOLVER: built-in env/file resolve inline; any other module delegates to a
    // loaded `kind: secret` plugin via the registry (fail-closed if the plugin subsystem is off or
    // the module is unknown). Shared by provider keys, the admin token, and the TLS listener.
    let secret_resolver = Arc::new(build_secret_resolver(
        plugin_registry.clone(),
        &cfg.secrets,
    )?);

    let mut lanes_data = Vec::new();
    // Validated provider handle for each lane, captured in lockstep with `lanes_data` below. The
    // first loop already resolves `cfg.providers.get(&mc.provider)` (failing loud via `die` on a
    // missing provider), so the lane-build loop reuses that handle instead of re-looking it up —
    // there is no second lookup and no `expect` on the startup path.
    let mut lane_provider_cfgs: Vec<&config::ProviderCfg> = Vec::new();
    let mut by_model = HashMap::new();
    // Per-model configured default_max_tokens (injected at the translation seam for protocols that
    // require max_tokens). Captured here because `cfg.models` is consumed by this loop.
    let mut model_default_max_tokens: std::collections::HashMap<String, Option<u32>> =
        std::collections::HashMap::new();
    // Single source of truth for each provider's resolved API key. The secret-bearing env read
    // happens exactly once per provider here; both the empty-key warning below and the later
    // `Lane.api_key` population reuse this value, so the warning and the captured key can never
    // diverge (and we don't read the same env var twice).
    let mut provider_api_keys: HashMap<String, String> = HashMap::new();
    // Build lanes in a DETERMINISTIC order (sorted by model name) rather than `cfg.models`'
    // HashMap iteration order, which is randomized per process start. Lane index is assigned here
    // (`by_model` → `lanes_data.len()`), so a random iteration order gave each lane a different
    // index every boot — surfacing as non-reproducible `/stats` lane ordering and metric lane-series
    // identity that shifts across restarts (a scrape/dashboard annoyance and a flaky-test source).
    // Sorting makes the whole observable surface stable. (Mirrors the deterministic-resolution fix
    // already applied to `model_context_max` below.)
    // Resolve the COST MODEL from THIS config (rate card + budget groups + flat fee) BEFORE
    // `cfg.models` is consumed below. Rebuilt on every apply/reload - unlike the GovState ledger,
    // which survives the swap - so a rate-card correction reprices every derived figure on the
    // next read (tokens are the truth).
    let cost = Arc::new(crate::cost::CostModel::resolve_parts(
        cfg.rate_card.as_ref(),
        cfg.per_request_fee,
        &cfg.groups,
    ));

    let mut sorted_models: Vec<_> = cfg.models.into_iter().collect();
    sorted_models.sort_by(|a, b| a.0.cmp(&b.0));
    for (model, mc) in sorted_models {
        model_default_max_tokens.insert(model.clone(), mc.default_max_tokens);
        let Some(provider_cfg) = cfg.providers.get(&mc.provider) else {
            return Err(format!(
                "model '{model}' references unknown provider '{}'",
                mc.provider
            ));
        };
        let key = provider_api_keys.entry(mc.provider.clone()).or_insert_with(|| {
            // Resolve the provider credential through its SECRET REFERENCE. An unresolvable
            // secret degrades to the empty key with a loud warning (parity with the old empty
            // env-var posture: keyless local upstreams - ollama/vLLM - are legitimate).
            match secret_resolver.resolve_string(&provider_cfg.api_key) {
                Ok(k) => k,
                Err(e) => {
                    diag_warn!(PROVIDER_API_KEY_UNRESOLVED, provider = %mc.provider, "provider api_key did not resolve: {e}");
                    String::new()
                }
            }
        });
        if key.is_empty() {
            eprintln!(
                "[warn] provider {} api_key ({}) empty",
                mc.provider,
                provider_cfg.api_key.describe()
            );
        }
        let limited = mc.max_requests >= 0;
        // `max_concurrent` is an OPT-IN limiter: omitted (None) = UNBOUNDED. Realize "unbounded" as a
        // semaphore seeded with `Semaphore::MAX_PERMITS` (usize::MAX >> 3) — a lane will never reach
        // 2^60 concurrent in-flight requests, so this never throttles, yet it keeps the entire
        // permit-based dispatch path (which every selection route depends on) intact. A literal
        // usize::MAX would PANIC: `Semaphore::new` asserts `permits <= MAX_PERMITS`. `max` records the
        // same count so /stats `inflight = max - available` stays coherent.
        let max_concurrent = mc
            .max_concurrent
            .unwrap_or(tokio::sync::Semaphore::MAX_PERMITS);
        by_model.insert(model.clone(), lanes_data.len());
        lane_provider_cfgs.push(provider_cfg);
        lanes_data.push(LaneData {
            model: model.clone(),
            provider: mc.provider.clone(),
            max: max_concurrent,
            sem: std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
            limited,
            budget: if limited { mc.max_requests } else { -1 },
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            ok: 0,
            err: 0,
            client_fault: 0,
            upstream_model: mc.upstream_model.clone(),
            attempt_timeout_ms: mc.attempt_timeout_ms,
            reasoning: mc.reasoning.unwrap_or(false),
            prompt_caching: mc.prompt_caching.unwrap_or(false),
        });

        eprintln!(
            "  model {} via {} ({}) max {}{}",
            model,
            mc.provider,
            provider_cfg.base_url.trim_end_matches('/'),
            // Show the operator-facing form: an omitted cap reads "unbounded", not 2^60.
            match mc.max_concurrent {
                Some(n) => n.to_string(),
                None => "unbounded".to_string(),
            },
            // Surface the alias→wire-id indirection at boot so an operator can see this lane sends a
            // different model string upstream than the config key it's filed under.
            match &mc.upstream_model {
                Some(u) => format!(" → upstream {u}"),
                None => String::new(),
            }
        );
    }

    // Build a map from model name to context_max. A model is one lane shared across every pool that
    // names it, so its context_max must be single-valued. Previously the last pool to iterate (in
    // nondeterministic HashMap order) silently won, so a model carrying `context_max: Some(128000)`
    // in one pool and `None` (or a different limit) in another could end up with whichever value the
    // iteration happened to land on — defeating the context-length failover exclusion in proxy engine
    // and losing pool-specific limits without a diagnostic. Resolve it deterministically and fail
    // loud on a genuine conflict instead.
    let model_context_max = resolve_model_context_max(&cfg.pools)?;

    // Every lane, flattened into the NEUTRAL `LaneInput` carrier (1.6.0 money-path Phase 3-4 C):
    // the LLM plane's `build_runtime` reconstructs the concrete `Lane` (egress targets, resolved
    // credential, prebuilt auth) FROM these scalars — the `proxy::build_egress_targets` /
    // `egress_auth::*` calls that used to run here moved in-plane (the allowed plane→core edge), so
    // core names no `Lane`/`EgressTarget`/`CredentialProvider`. This loop keeps only the NEUTRAL work:
    // resolve+validate the protocol name, carry the pre-resolved api-key plaintext, and mirror the
    // provider's config into neutral scalars.
    let mut lane_inputs: Vec<LaneInput> = Vec::new();
    for (idx, ld) in lanes_data.iter().enumerate() {
        // Reuse the provider handle resolved (and validated via `die`) in the lanes_data loop above,
        // captured in lockstep into `lane_provider_cfgs`. No redundant re-lookup / `expect` here.
        let provider_cfg = lane_provider_cfgs[idx];
        let Some(protocol) = crate::proto::lane_protocol_name(&provider_cfg.protocol) else {
            // The "supported:" roster is DERIVED from the registry (`known_protocols()`), not a
            // hand-maintained literal that names the six LLM dialects core no longer owns: the codec
            // protocols are whatever the linked plane crates registered, so a build with the LLM plane
            // compiled out names only what it actually serves (and a build with a seventh dialect names
            // it) — the deletion-test property at the vocabulary level. Empty roster is a real answer.
            return Err(format!(
                "provider '{}' uses unknown protocol '{}' (supported: {})",
                ld.provider,
                provider_cfg.protocol,
                crate::proto::known_protocols().join(", ")
            ));
        };
        // Reuse the single env read captured in the lanes_data loop above (same source of truth as
        // the empty-key warning); no second read of the secret-bearing env var. This PLAINTEXT is
        // carried into the neutral carrier because the plane cannot re-resolve a secret ref.
        let api_key = provider_api_keys
            .get(&ld.provider)
            .cloned()
            .unwrap_or_default();
        // The base URL, trailing-slash-trimmed once here (the plane consumes it verbatim into the
        // egress-target build + SigV4 signed-host derivation).
        let base_url = provider_cfg.base_url.trim_end_matches('/').to_string();
        lane_inputs.push(LaneInput {
            model: ld.model.clone(),
            provider: ld.provider.clone(),
            protocol: protocol.to_string(),
            base_url,
            path: provider_cfg.path.clone(),
            path_base: provider_cfg.path_base.clone(),
            upstream_model: ld.upstream_model.clone(),
            api_key_plaintext: api_key,
            auth_style: auth_style_of(provider_cfg.auth),
            scope: provider_cfg.scope.clone(),
            token_url: provider_cfg.token_url.clone(),
            subject: provider_cfg.subject.clone(),
            error_map: provider_cfg.error_map.clone(),
            health: provider_cfg.health.as_ref().map(health_input_of),
            allow_metadata_hosts: provider_cfg.allow_metadata_hosts.clone(),
            context_max: model_context_max.get(&ld.model).copied().flatten(),
            lane_default_max_tokens: model_default_max_tokens.get(&ld.model).copied().flatten(),
            attempt_timeout_ms: ld.attempt_timeout_ms,
            reasoning: ld.reasoning,
            prompt_caching: ld.prompt_caching,
            max_concurrent: ld.max,
            limited: ld.limited,
            budget: ld.budget,
        });
    }

    // Every pool, flattened into the NEUTRAL `PoolInput` carrier: member (weight/meta) projections
    // plus the pool's neutral `failover`/`affinity`/`on_exhausted`/`upstream_credentials` config. The
    // plane's `build_runtime` rebuilds the `WeightedLane`/`PoolRuntime` tables from these; the pool's
    // ROUTING POLICY / gates / rewrites are NOT carried (they resolve core-side behind
    // `App::resolve_pool_*` — their value is the core-owned `ResolvedPolicy`, which must not cross the
    // downcast). The member `by_model` lookup stays here so an unknown-model pool member fails boot
    // LOUD at the composition root (not deep inside the plane).
    let mut pool_inputs: Vec<PoolInput> = Vec::with_capacity(cfg.pools.len());
    for (name, pool) in &cfg.pools {
        let mut members: Vec<PoolMemberInput> = Vec::with_capacity(pool.members.len());
        for m in pool.members.iter() {
            let Some(&lane_idx) = by_model.get(&m.model) else {
                return Err(format!(
                    "pool '{name}' references unknown model '{}'",
                    m.model
                ));
            };
            members.push(PoolMemberInput {
                model: m.model.clone(),
                lane_idx,
                weight: m.weight, // from config PoolMember.weight (default 1)
                reasoning: m.reasoning,
                attempt_timeout_ms: m.attempt_timeout_ms,
                tier: m.tier.clone(),
                // The routing cost scalar derives from the member's MODEL's rate_card entry — cost
                // lives on no pool member; resolved core-side (the plane has no rate card).
                cost_per_mtok: cfg
                    .rate_card
                    .as_ref()
                    .and_then(|card| card.get(&m.model))
                    .map(crate::config::rate_entry_per_mtok),
                tags: m.tags.clone(),
            });
        }
        if let Some(ref on_exc) = pool.on_exhausted {
            // Same INFO line 1.5.5 logged from `main.rs`'s per-pool `on_exhausted` parse, carried
            // here now that pool construction lives core-side (neutrality: no boot-line drift).
            let mode = on_exc.to_runtime();
            tracing::info!(pool = %name, on_exhausted = ?mode, "pool exhaustion policy");
        }

        pool_inputs.push(PoolInput {
            name: name.clone(),
            members,
            failover: pool.failover.as_ref().map(failover_input_of),
            affinity: pool.affinity.as_ref().map(affinity_input_of),
            on_exhausted: pool
                .on_exhausted
                .as_ref()
                .map(|o| on_exhausted_input_of(&o.to_runtime()))
                .unwrap_or_default(),
            upstream_credentials: pool.upstream_credentials,
            // The pool's `breaker:` block, RESOLVED core-side into the runtime cfg
            // (`store::breaker_cfg_to_runtime` does the config→runtime lowering + ADR-0002 trip
            // defaults) then flattened to the neutral carrier; the plane's `build_runtime`
            // reconstructs it via `BreakerCfg::from_llm`.
            breaker: pool
                .breaker
                .as_ref()
                .map(crate::store::breaker_cfg_to_runtime)
                .map(|b| b.to_llm()),
        });
    }

    eprintln!(
        "busbar: {} models, {} pools",
        lane_inputs.len(),
        pool_inputs.len()
    );
    for p in &pool_inputs {
        let agg: usize = p
            .members
            .iter()
            .map(|m| lane_inputs[m.lane_idx].max_concurrent)
            .sum();
        eprintln!(
            "  pool /{} = [{}] aggregate {}",
            p.name,
            p.members
                .iter()
                .map(|m| lane_inputs[m.lane_idx].model.clone())
                .collect::<Vec<_>>()
                .join(", "),
            agg
        );
    }

    // Loud warning for an empty `auth.chain` (open relay). Not fatal — busbar still starts (useful for
    // local dev) — but operators must not run this in production. NOTE: an ABSENT `auth:` block
    // serde-defaults to an empty chain too (`AuthCfg::default_none`), so a config that merely omits
    // `auth:` silently becomes an open relay. Surface this at ERROR level (not warn — a warn is
    // suppressed under RUST_LOG=error, the very level an operator most likely runs in production)
    // AND unconditionally on stderr, so the open-relay state cannot be masked by log configuration.
    if let Some(banner) = open_relay_banner(auth_cfg.chain.is_empty(), cfg.auth.is_some()) {
        eprintln!("[error] {banner}");
        diag_error!(OPEN_RELAY_NO_AUTH, "{banner}");
    }

    // FAIL-CLOSED: the auth chain resolves every non-builtin `auth.chain` module as a `kind: auth`
    // plugin via the SAME validated registry the store/secret plugins load through. A configured
    // auth plugin that cannot be loaded (missing/untrusted tarball, wrong kind, ABI failure) aborts
    // boot here rather than silently dropping the module and leaving the front door open.
    let auth_mw = Arc::new(
        AuthMiddleware::new(&auth_cfg, &plugin_registry, &secret_resolver)
            .map_err(|e| format!("auth chain construction failed: {e}"))?,
    );
    // ADMIN-plane external auth plugins (1.5.2 admin-plane OIDC): resolve every non-builtin
    // `admin_auth:` entry as a signed `kind: auth` plugin through the SAME validated registry. Runs
    // on boot AND reload (this whole function is `build_app_from_config`, called on both), so a
    // reload can never leave a stale/empty admin chain. FAIL-CLOSED: an unresolvable admin module
    // aborts the build rather than silently disabling the admin plane.
    let admin_modules = Arc::new(
        crate::auth::AdminAuthChain::build(&auth_cfg, &plugin_registry, &secret_resolver)
            .map_err(|e| format!("admin auth chain construction failed: {e}"))?,
    );
    // HOSTED-LOGIN methods (1.5.2): resolve every `auth.methods:` entry as a login-capable
    // `kind: auth` plugin (ABI v2). Also runs on boot AND reload (this whole fn). FAIL-CLOSED: an
    // unresolvable method — or a `browser_login` method backed by a pre-v2 plugin (capability gate)
    // — aborts the build rather than surfacing a 500 at request time.
    let login_methods = Arc::new(
        crate::auth::token::LoginMethods::build(&auth_cfg, &plugin_registry, &secret_resolver)
            .map_err(|e| format!("auth.methods (hosted login) construction failed: {e}"))?,
    );
    // Thread the operator-configured hard-down cooldown + honored-Retry-After ceiling into the store
    // (both default to their historical const at the config layer).
    // Carry-over: an APPLY/RELOAD (prior = Some) restores every surviving lane's learned
    // health state BY STABLE IDENTITY from the prior store; boot (None) starts fresh.
    let store: Arc<dyn crate::store::LaneRuntime> = match prior {
        Some(p) => Arc::new(HealthState::new_with_limits_restored(
            lanes_data.clone(),
            cfg.limits.hard_down_cooldown_secs,
            cfg.limits.max_honored_retry_after_secs,
            &p.store.export_health(),
        )),
        None => Arc::new(HealthState::new_with_limits(
            lanes_data.clone(),
            cfg.limits.hard_down_cooldown_secs,
            cfg.limits.max_honored_retry_after_secs,
        )),
    };

    // The global default failover config, the fallback-pool routing table, and the upstream HTTP
    // client (with its warm-pool carry-over) are all part of the LLM data-plane runtime bundle now —
    // rebuilt IN-PLANE by the LLM plane's `build_runtime` from the neutral `PlaneBuildInput` carrier
    // (1.6.0 money-path Phase 3-4 C). Core no longer names `FailoverCfg`/`UpstreamClients`/the moved
    // egress-client builders here; it carries only the neutral client-affecting scalars below.

    // The client-affecting subset of the resolved limits (timeout, pool sizing, protocol posture).
    // Carried onto `App` so the NEXT apply can compare; the `redirect: none` SSRF posture and every
    // other builder input is a compile-time constant, so this snapshot is exhaustive over what the
    // client build reads from config. The plane's `build_runtime` reuses the prior warm client iff
    // its own copy of these scalars is unchanged.
    // The upstream protocol posture comes from `advanced.upstream_h2_prior_knowledge` /
    // `advanced.upstream_http1_only` in config.yaml (carried on `cfg.limits`). The deprecated
    // `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` / `BUSBAR_UPSTREAM_HTTP1_ONLY` env vars still override
    // those values so an existing pin keeps working across the upgrade; each is read here, at
    // client-build time, and the deprecation warning fires once, on the first build (a reload that
    // reuses the warm client does not repeat it). If both are set, http1-only wins because the
    // plane's client builder applies it last.
    let h2_env = std::env::var_os(ENV_UPSTREAM_H2_PRIOR_KNOWLEDGE);
    if h2_env.is_some() && prior.is_none() {
        diag_warn!(
            DEPRECATED_ENV_VAR_HONORED,
            "{ENV_UPSTREAM_H2_PRIOR_KNOWLEDGE} is DEPRECATED; set \
             `advanced.upstream_h2_prior_knowledge` in config.yaml (honored for now)."
        );
    }
    let h2_prior_knowledge =
        upstream_bool_env_override(h2_env, cfg.limits.upstream_h2_prior_knowledge);
    let http1_env = std::env::var_os(ENV_UPSTREAM_HTTP1_ONLY);
    if http1_env.is_some() && prior.is_none() {
        diag_warn!(
            DEPRECATED_ENV_VAR_HONORED,
            "{ENV_UPSTREAM_HTTP1_ONLY} is DEPRECATED; set `advanced.upstream_http1_only` in \
             config.yaml (honored for now)."
        );
    }
    let http1_only = upstream_bool_env_override(http1_env, cfg.limits.upstream_http1_only);
    let mut new_client_settings = crate::state::UpstreamClientSettings::from_limits(&cfg.limits);
    new_client_settings.upstream_h2_prior_knowledge = h2_prior_knowledge;
    new_client_settings.upstream_http1_only = http1_only;
    let llm_client_settings = ClientSettingsInput {
        upstream_request_timeout_secs: cfg.limits.upstream_request_timeout_secs,
        pool_max_idle_per_host: cfg.limits.pool_max_idle_per_host,
        pool_idle_timeout_secs: cfg.limits.pool_idle_timeout_secs,
        http1_only,
        h2_prior_knowledge,
    };

    // The hook plugin-resolution environment: the validated registry + shared projectors. Every hook
    // `plugin:` ref opens a `DlopenPolicy` through this. Built once and cloned into each resolver and
    // onto `App` (for the control-plane reads + scrape).
    let hook_env = hooks::HookEnv::new(plugin_registry.clone(), secret_resolver.clone());

    // FAIL-CLOSED: resolve every hook's SecretRef settings ONCE, up front, so an unresolvable
    // hook secret aborts boot/reload here — matching the store path (above) and the auth chain
    // (`AuthMiddleware::new`). Without this, a gate whose SecretRef fails to resolve would be
    // silently dropped from the routing chain by `resolve_pool_gates`/`resolve_on_error_chain`
    // (fail-OPEN), letting traffic the gate was configured to restrict/reject flow unfiltered.
    hook_env.preresolve_hook_secrets(&cfg.hooks)?;

    // The store's SecretRefs are resolved only on the BOOT arm (`prior == None`), because the store
    // backend is reused across a hot reload. So a `PUT /config/settings` naming an unresolvable ref
    // returned 200, persisted it, and the NEXT restart died in `resolve_settings` before serving.
    //
    // WARN, never fail: the store is restart-to-apply, so staging a ref whose secret the
    // orchestrator mounts on the next deploy is a legitimate workflow — and `tls` already accepts
    // exactly that. Rejecting here would make the store stricter than the block beside it.
    if let Some(store_cfg) = cfg.store.as_ref() {
        if let Err(e) = config::secret::resolve_settings(&store_cfg.settings, &secret_resolver) {
            diag_warn!(
                STORE_SECRET_REF_UNRESOLVED,
                store = %store_cfg.module,
                error = %e,
                "store settings hold a secret reference that does not resolve here; the store is \
                 restart-to-apply, so THIS WILL FAIL THE NEXT RESTART unless the secret exists then"
            );
        }
    }

    // FAIL-CLOSED (open-time variant): actually OPEN every referenced decision/rewrite gate up
    // front so an `open()`-time failure of a PRESENT plugin aborts boot/reload here — matching the
    // store (`open_store`) and auth (`AuthMiddleware::new`) paths. Without this, a gate whose plugin
    // fails to `open()` (constructor rejecting cfg_json, staging/mmap failure, ABI/kind mismatch
    // observable only on load) is silently `filter_map`-dropped by the resolvers below (fail-OPEN),
    // letting traffic a Reject/restrict/rewrite gate was configured to filter flow unfiltered while
    // boot reports success. A GENUINELY-ABSENT plugin stays the legitimate fail-open skip.
    // `plugins_preflight` is manifest-only (no dlopen) and `preresolve_hook_secrets` only resolves
    // SecretRefs, so neither catches an `open()` failure — this pass does.
    hook_env.preopen_gate_hooks(&cfg.hooks)?;

    // The per-pool runtime bundle (member metadata + resolved failover/affinity/breaker), the
    // any-pool-override fast-path flag, and the per-pool `on_exhausted:` table are all part of the LLM
    // data-plane runtime now — rebuilt IN-PLANE by the LLM plane's `build_runtime` from the neutral
    // `PoolInput` members of the carrier (1.6.0 money-path Phase 3-4 C). The pool ROUTING POLICIES
    // (`resolve_pool_{ordering,gates,rewrites}`) stay resolved-and-read core-side behind the
    // `App::resolve_pool_*` down-facade (their value is the core-owned `ResolvedPolicy`, which must not
    // cross the neutral downcast), so they are NOT resolved here into a plane type either.

    // PLUGIN PRE-FLIGHT: the same fail-closed pipeline `--validate` runs (consistency -> policy ->
    // three-phase scan -> store resolution). Runs on EVERY construction path (boot, apply, reload),
    // so a bad plugin state can never produce a partial App. When plugins are disabled and nothing
    // references one, this is a no-op empty registry.
    // open the governance store + load the virtual-key cache when enabled.
    // Credentials RE-RESOLVED on this apply/reload; the rotation closure is handed back to the
    // caller (see `Ok((app, rotate_gov_credentials))` below) rather than applied here. Resolution
    // itself happens HERE and is FAIL-CLOSED: an `auth.admin_auth` token ref or an `auth.signing_key`
    // that no longer resolves aborts the apply rather than silently leaving the old credential live.
    let mut rotate_gov_credentials: Option<GovCredentialRotation> = None;
    let governance = if let Some(p) = prior {
        // REUSED across applies: the keys + spend/rate state must survive config changes. But the
        // CREDENTIALS on it are config, not state: `GovState` used to freeze the admin-token digest
        // and the signing key at construction, so rotating either SecretRef and reloading had no
        // effect whatsoever — the process kept accepting the boot-time credential for its entire
        // life. Re-resolve both refs against the fresh resolver and swap them
        // into the reused instance.
        //
        // SCOPE: a credential is re-resolved exactly when THIS config DECLARES it — an
        // `admin-tokens` entry in `auth.admin_auth`/`auth.chain` for the admin token, an explicit
        // `auth.signing_key` for the signing key. A config that declares neither is not asserting
        // "no credential"; it simply does not own that credential (the dev signing key is
        // generate-and-persist at BOOT, and re-running that on every reload would churn key
        // material), so the live one stands. REMOVING a declaration therefore still needs a restart
        // — documented, and the narrow case; ROTATING one, the operational path that matters and
        // the one that silently did nothing, now works.
        if let Some(gs) = p.governance.clone() {
            let auth = cfg.auth.as_ref();
            let declares_admin_tokens = auth.is_some_and(|a| {
                a.admin_auth
                    .iter()
                    .chain(a.chain.iter())
                    .any(|e| e.module == crate::config::ADMIN_TOKENS_MODULE)
            });
            // FAIL-CLOSED: a declared ref that no longer resolves ABORTS the apply. The alternative
            // — carry on serving with the old credential — is exactly the defect being fixed.
            let admin_token: Option<Option<busbar_api::Redacted<String>>> = if declares_admin_tokens
            {
                // Declared with no token ref resolves to `None`: the admin API is credential-less
                // BY CONFIGURATION, so fail closed and disable it rather than keep the old secret.
                Some(
                    resolve_admin_token(auth, &secret_resolver)
                        .map_err(|e| format!("{e} (nothing was changed)"))?,
                )
            } else {
                None
            };
            let signer = match auth.and_then(|a| a.signing_key.as_ref()) {
                Some(_) => Some(resolve_signing_key(auth, &secret_resolver)?),
                None => None,
            };
            if admin_token.is_some() || signer.is_some() {
                rotate_gov_credentials = Some(Box::new(move || {
                    if let Some(token) = admin_token {
                        gs.set_admin_token(token.as_ref().map(|r| r.expose_secret().as_str()));
                    }
                    if let Some(signer) = signer {
                        gs.set_signing_key(signer);
                    }
                }));
            }
        }
        p.governance.clone()
    } else {
        // Governance is ALWAYS available (it is inert until an admin token is set and virtual keys are
        // minted). Only the STORE backend is a choice: ephemeral RAM by default, or a store PLUGIN
        // (resolved by alias or canonical name from the validated registry — the engine sees only the
        // returned `dyn Store`, exactly like a compiled-in backend).
        let g = cfg.store.clone().unwrap_or_default();
        // Is a STATEFUL plane (MCP / A2A) actually configured? Those planes carry per-task state that
        // the RAM store drops on restart. "Configured" = any MCP server / A2A agent OR any MCP
        // tool-pool / A2A agent-pool; the pool maps are always typed (present regardless of which
        // planes are compiled in), while the def sections are only typed when their plane is compiled
        // in. A bare `tools:`/`agents:` entry (the common case, no failover pool) is just as stateful
        // as a pooled one, so both are checked. Computed here so the sharper warn below can fire only
        // for a stateful deployment — never for an LLM-only (stateless) one.
        // Data-driven: `tool_defs`/`agent_defs` are always the neutral `Box<dyn PlaneCfg>`; with the
        // owning plane compiled out the section is the raw carrier whose `def_names()` is empty, so
        // these read identically to the former per-feature branches without naming a plane feature.
        let mcp_stateful = !cfg.tool_defs.def_names().is_empty() || !cfg.tool_pools.is_empty();
        let a2a_stateful = !cfg.agent_defs.def_names().is_empty() || !cfg.agent_pools.is_empty();
        let store: Arc<dyn governance::Store> = if g.module
            == crate::config::GOVERNANCE_STORE_MEMORY
        {
            diag_warn!(
                GOVERNANCE_STORE_EPHEMERAL,
                "store: in-memory (ephemeral) - keys, groups' usage, and ledgers reset on \
                     restart; configure a durable store plugin for persistence"
            );
            // SHARPER, CONDITIONAL warn: the generic notice above is about governance state; MCP
            // and A2A task state also lives only in this RAM store. Fire the specific warn (naming
            // the consequence) ONLY when a stateful plane is configured — an LLM-only deploy keeps
            // just the generic notice. Additive to, not a replacement for, the notice above.
            if let Some(msg) = stateful_plane_ephemeral_store_warn(true, mcp_stateful, a2a_stateful)
            {
                diag_warn!(STATEFUL_PLANE_EPHEMERAL_STORE, "{msg}");
            }
            Arc::new(governance::MemoryStore::new())
        } else {
            // Resolve any SecretRef-typed setting (e.g. a `licenseKey`) against the secret
            // store BEFORE the settings cross the ABI (ADR-0010). FAIL-CLOSED: an unresolvable
            // ref refuses the store load rather than handing the plugin a dangling reference.
            let resolved = config::secret::resolve_settings(&g.settings, &secret_resolver)
                .map_err(|e| format!("store '{}' settings: {e}", g.module))?;
            let cfg_json = serde_json::Value::Object(resolved).to_string();
            match plugin_registry.open_store(&g.module, &cfg_json) {
                Ok(s) => Arc::from(s),
                Err(e) => return Err(format!("store '{}' plugin load failed: {e}", g.module)),
            }
        };
        // The operator ADMIN credential: the `admin-tokens` chain entry's `token:` secret ref.
        // FAIL-CLOSED: a configured-but-unresolvable admin token refuses boot (a silently-absent
        // token would lock the admin API while the operator believes it is guarded).
        let admin_token: Option<busbar_api::Redacted<String>> =
            resolve_admin_token(cfg.auth.as_ref(), &secret_resolver)?;
        // The KEY-SIGNING key: resolve `auth.signing_key` (a secret ref) to 32 ed25519 secret
        // bytes. ABSENT => no signer (1.5.1: busbar no longer auto-generates one; config_validate
        // has already failed closed if the `keys` verifier is in the chain). Fleet deployments
        // provide it (shared) so every node verifies the same tokens.
        let signer = resolve_signing_key(cfg.auth.as_ref(), &secret_resolver)?;
        match governance::GovState::new_with_signer(
            store,
            admin_token.as_ref().map(|r| r.expose_secret().clone()),
            signer,
        ) {
            Ok(gs) => {
                let gs = Arc::new(gs);
                // BOOT-ONLY crash-recovery: hydrate the in-memory token-ledger cells (key buckets +
                // budget-group buckets) from the durable store so a restart resumes enforcement from
                // the persisted ledger. A no-op for the empty RAM store.
                // Fail-open: a store error here is FATAL - resuming with empty (reset) budget
                // cells would let a maxed-out key spend its whole cap again. Fail boot loudly.
                if let Err(e) = gs.hydrate_budgets(&cost, crate::store::now()) {
                    return Err(format!(
                        "governance boot: budget hydration failed ({e}); refusing to start with an \
                         unenforced (reset) ledger. Fix the durable store and restart."
                    ));
                }
                // BOOT FAIL-CLOSED: every stored key naming a budget_group must resolve in THIS
                // config (mint validates it; a shared durable store can carry keys minted under a
                // config another node no longer has). A dangling reference is a boot error naming
                // the offender with the paste-ready fix.
                // A store error reading the keys here must NOT be swallowed (the old `if let
                // Ok(keys)` skipped the whole dangling-reference check on error, so a boot-time store
                // blip published a config whose keys were never validated). Propagate it - fail boot.
                let keys = gs.all_keys().map_err(|e| {
                    format!(
                        "governance boot: could not read stored keys to validate budget_group \
                         references ({e}); refusing to start unvalidated. Fix the durable store and \
                         restart."
                    )
                })?;
                for k in &keys {
                    if let Some(group) = k.group.as_deref() {
                        if cost.group_named(group).is_none() {
                            return Err(format!(
                                "virtual key '{}' names group '{group}', which does not exist in the top-level groups block.\n\
                                 Paste this under groups and set real limits:\n\n    {group}:\n      limits:\n        - {{ budget: 0, per: month }}\n",
                                k.id
                            ));
                        }
                    }
                }
                // INERT-KEYS GUARD: a durable store may carry virtual keys minted in a prior run
                // whose data-plane chain no longer names the `keys` verifier — no request then
                // resolves them and their per-key controls are silently bypassed. Surface it LOUD:
                // ERROR level (survives RUST_LOG=error) AND unconditionally on stderr, mirroring the
                // open-relay banner so log config can't mask it. RAM stores can't reach this state,
                // so `key_count` there is 0 (or the store is non-durable) and the banner is None.
                // `all_keys()` failure is non-fatal — treat as 0 keys (the enforcement gate is
                // unaffected; we only lose the advisory). Inertness is now recomputed from CHAIN
                // SHAPE (is `keys` in the running chain?), not the admin token.
                let store_is_durable = g.module != crate::config::GOVERNANCE_STORE_MEMORY;
                let key_count = gs.all_keys().map(|k| k.len()).unwrap_or(0);
                let keys_in_chain = auth_mw.keys_in_chain;
                if let Some(banner) =
                    inert_durable_keys_banner(store_is_durable, key_count, keys_in_chain)
                {
                    eprintln!("[error] {banner}");
                    diag_error!(DURABLE_KEYS_INERT, "{banner}");
                }
                Some(gs)
            }
            Err(e) => return Err(format!("governance init failed: {e}")),
        }
    };

    // Resolve the global rewrite hooks (prompt: rw gates in global_hooks) into priority-ordered
    // transports ONCE. Empty unless the operator configured a rewrite hook — zero cost by default.
    let rewrite_hooks =
        hooks::resolve_rewrite_hooks(&cfg.hooks, &cfg.global_hooks, &hook_env, app_config_version);
    // Resolve the global request-stage tap hooks the same way. Empty unless configured.
    let tap_hooks = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &hook_env,
        app_config_version,
        config::HookStage::Request,
    );
    let tap_hooks_candidate = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &hook_env,
        app_config_version,
        config::HookStage::Candidate,
    );
    let tap_hooks_routing = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &hook_env,
        app_config_version,
        config::HookStage::Routing,
    );
    let tap_hooks_response = hooks::resolve_tap_hooks(
        &cfg.hooks,
        &cfg.global_hooks,
        &hook_env,
        app_config_version,
        config::HookStage::Response,
    );
    // Resolve the global DECISION gates (non-rewrite gates in global_hooks) — fired for a verdict on
    // every request. Empty unless configured.
    let global_gates =
        hooks::resolve_gate_hooks(&cfg.hooks, &cfg.global_hooks, &hook_env, app_config_version);

    // THE PER-POOL ROUTING POLICY / DECISION GATES / REWRITE CHAINS — resolved HERE, core-side, keyed
    // by pool (money-path Phase 3-4 C — the RATIFIED pool-hook facade). They USED to be built into the
    // LLM plane's `PoolRuntime`, but their resolved values (`ResolvedPolicy` / `Arc<dyn RoutingPolicy>`,
    // an Arc over a dlopen plugin) cannot cross the `build_runtime` downcast, so they stay here and the
    // engine reads them through `App::pool_{policy,gates,rewrites}`. Byte-identical to the old inline
    // `PoolRuntime` resolution: the SAME `hooks::resolve_pool_*` calls, same inputs, same order.
    let default_hook = hooks::default_hook_name(&cfg.hooks).map(str::to_string);
    let mut pool_orderings = std::collections::HashMap::new();
    let mut pool_decision_gates = std::collections::HashMap::new();
    let mut pool_rewrite_chains = std::collections::HashMap::new();
    for (pool_name, pool_cfg) in &cfg.pools {
        if let Some(policy) = hooks::resolve_pool_ordering(
            pool_cfg,
            &cfg.hooks,
            &hook_env,
            default_hook.as_deref(),
            app_config_version,
        ) {
            pool_orderings.insert(pool_name.clone(), policy);
        }
        let gates = hooks::resolve_pool_gates(pool_cfg, &cfg.hooks, &hook_env, app_config_version);
        if !gates.is_empty() {
            pool_decision_gates.insert(pool_name.clone(), gates);
        }
        let rewrites =
            hooks::resolve_pool_rewrites(pool_cfg, &cfg.hooks, &hook_env, app_config_version);
        if !rewrites.is_empty() {
            pool_rewrite_chains.insert(pool_name.clone(), rewrites);
        }
    }

    // THE OTHER TWO PLANES' GATES, resolved by the SAME function, from the SAME registry, on the
    // same generation — which is the point. `tools.hooks:` / `agents.hooks:` and the per-entry
    // lists have parsed and validated since 1.5.3 and fired nothing, because nothing resolved them
    // and nothing called them. These two lines and their two firing sites are the whole of what was
    // missing; the grammar, the validation and the cross-plane refusal were already there.
    //
    // Empty on every deployment that attaches nothing, which is every deployment that does not
    // spell the key — so the dispatch paths' lookups cost one hash probe against an empty map.
    // The MCP `tools:` per-server gates read the typed `tools:` registry, which exists only when
    // the plane is compiled in. With `plane-mcp` off there is no registry, so the map is empty.
    // Data-driven: `container_gates()` is a neutral `PlaneCfg` method; with the owning plane compiled
    // out the section is the raw carrier that answers empty containers/section-hooks, so `resolve_
    // container_gates` yields the same empty map the former `#[cfg(not)]` branch built by hand — no
    // plane feature named.
    let mcp_server_gates = {
        let g = cfg.tool_defs.container_gates();
        hooks::resolve_container_gates(
            g.containers
                .iter()
                .map(|(name, hooks)| (name.as_str(), hooks.as_slice())),
            &g.section_hooks,
            &cfg.hooks,
            &hook_env,
            app_config_version,
        )
    };
    let a2a_agent_gates = {
        let g = cfg.agent_defs.container_gates();
        hooks::resolve_container_gates(
            g.containers
                .iter()
                .map(|(name, hooks)| (name.as_str(), hooks.as_slice())),
            &g.section_hooks,
            &cfg.hooks,
            &hook_env,
            app_config_version,
        )
    };
    // THE TAP/TRANSFORM twins of the two gate maps above: each plane's per-container `prompt: rw`
    // rewrite chains, resolved once per generation exactly like the gates. Empty on every deployment
    // that attaches no rewrite hook, so the transform firing sites stay zero-cost / byte-identical.
    let mcp_server_rewrites = {
        let g = cfg.tool_defs.container_gates();
        hooks::resolve_container_rewrites(
            g.containers
                .iter()
                .map(|(name, hooks)| (name.as_str(), hooks.as_slice())),
            &g.section_hooks,
            &cfg.hooks,
            &hook_env,
            app_config_version,
        )
    };
    let a2a_agent_rewrites = {
        let g = cfg.agent_defs.container_gates();
        hooks::resolve_container_rewrites(
            g.containers
                .iter()
                .map(|(name, hooks)| (name.as_str(), hooks.as_slice())),
            &g.section_hooks,
            &cfg.hooks,
            &hook_env,
            app_config_version,
        )
    };

    // EVERY fallible step of THIS build has now succeeded, so `rotate_gov_credentials` (if any) is
    // ready to run. It is NOT invoked here, though: `GovState` is a process-lifetime `Arc` shared
    // with the OLD `App` that is still serving, so invoking it now would mutate the live engine's
    // credentials even though the candidate `App` returned below is only a CANDIDATE — the admin
    // transaction wrapping this call (`txn.rs`) still has a fallible PERSIST step to run, and on a
    // persist failure the transaction discards this candidate and swaps nothing. Firing the
    // rotation here would leave the "nothing was changed" response a lie: the shared `GovState`
    // would already carry the new credential while the old (rejected) `App` keeps serving. The
    // caller is responsible for invoking the returned closure — after its own persist step (if any)
    // has succeeded, never before.

    // The active-probe schedule (live state, carried across an apply only when the lane set is
    // identical) is part of the LLM data-plane runtime now — its lane-indexed deadlines + the
    // prior-runtime carry-over compare move IN-PLANE to the LLM plane's `build_runtime`, which reads
    // the prior generation's runtime through the neutral `PlaneSlots` seam. Core no longer names
    // `health::ProbeSchedule` here.

    // Plugin HTTP routes: the BUILT-IN exporters (`crate::export`) declare their routes
    // into the snapshot — today the `prometheus` exporter's `GET /metrics` when `export.prometheus` is
    // configured. Rebuilt on every config apply. A collision (a future loaded export/hook plugin
    // claiming a built-in's path) is a LOUD build failure naming the owner, never last-writer-wins.
    //
    // The rebuilt TABLE is not the same thing as what the ROUTER serves: each path is registered on
    // the router once, at boot, and an apply swaps only `Arc<App>`. So REMOVING `export.prometheus`
    // takes effect immediately (`plugin_route_dispatch` resolves the owner from the current snapshot
    // and 404s), while ADDING it needs a RESTART. `boot_route_paths` below is what remembers which
    // paths the router actually has, so a config mutation can SAY so instead of
    // reporting success for a route that will keep 404ing.
    let plugin_routes = std::sync::Arc::new(crate::plugin_routes::build_route_table(
        crate::export::route_decls(&cfg_export),
    )?);
    // Seeded ONCE, on a fresh boot (`prior == None`) from the table that is about to be mounted;
    // every rebuild inherits the boot value unchanged. Deliberately NOT recomputed per rebuild — a
    // recomputed set would say every newly declared path is already mounted, which is the exact
    // silent no-op this exists to report.
    let boot_route_paths = prior.map_or_else(
        || std::sync::Arc::new(plugin_routes.paths()),
        |p| p.boot_route_paths.clone(),
    );

    // THE PLANE SLOT MAP (Step 2.3's app-state seam): every registered plane's runtime object for
    // THIS config generation, built ONCE via its own decl's `build` fn and type-erased into
    // `Arc<dyn Any + Send + Sync>`. Built here, ahead of the `App` literal below. Each plane's object
    // lives ONLY in this map now — the typed `App::mcp` / `App::a2a` fields were deleted in the D4
    // step — and every reader downcasts the SAME `Arc` out of the slot rather than building a second
    // one that could disagree. The MCP plane's object is already validated
    // (`McpResource::from_cfg` ran at `RootCfg` construction), so its `build` fn is a wrap, not a
    // second parse; the A2A plane's object is lowered here for the first time, exactly where
    // `A2aPlane::from_config` used to be called directly — it is still lowered ONCE, now through the
    // decl instead of by name, and read from `plane_slots` everywhere below (the dispatch table's
    // admission facts and the registry the re-verification job sweeps).
    let mut plane_slots: std::collections::BTreeMap<
        &'static str,
        Arc<dyn std::any::Any + Send + Sync>,
    > = {
        let ctx = crate::plane::registry::BuildCtx {
            // The MCP resource is TYPE-ERASED here, at the composition root, rather than inside the
            // plane's `build` fn — so the `BuildCtx` seam carries an opaque slot and names no
            // `crate::mcp` type. It is the SAME `Arc` the plane clones into `plane_slots` and
            // `crate::mcp::resource` downcasts back out inside the plane, so the "one lowering, one
            // Arc" invariant holds — the plane's own module is the only reader, through the slot.
            // The endpoint resource is ALREADY validated and erased as `Option<Arc<dyn Any>>` by
            // config resolution, read here through the neutral SECTION-KEYED accessor (the `tools:`
            // plane owns the endpoint door) — so the slot is a CLONE of that one opaque `Arc`, not a
            // re-erasure, and names no plane resource type. `None` when the block is absent or the
            // owning plane is compiled out (resolve produced no resource then).
            mcp_slot: cfg
                .endpoint_resources
                .get(busbar_substrate::plane::config::NAMED_MAP_SECTIONS[2])
                .cloned(),
            // The neutral registry section, erased as `&dyn Any` via `PlaneCfg::as_any` so `BuildCtx`
            // names no `crate::a2a` type; the A2A `build` closure downcasts it back to `AgentsCfg`.
            agent_defs: cfg.agent_defs.as_any(),
            public_url: cfg.public_url.as_deref(),
            // THE PRIOR GENERATION'S SLOTS, so a plane's `build` can CARRY accumulated coordination
            // off its own prior runtime object across this apply (the A2A plane carries its
            // verify-on-call gate and boot-resolved card transports off the prior `A2aPlane`) — the
            // same neutral `&dyn PlaneSlots` the MCP runtime's `build_runtime` receives below.
            prior: prior.map(|p| p as &dyn busbar_substrate::plane_host::PlaneSlots),
        };
        crate::plane::registry::plane_decls()
            .iter()
            .filter_map(|decl| (decl.build)(&ctx).map(|obj| (decl.key, obj)))
            .collect()
    };

    // THE MCP PLANE'S PER-GENERATION RUNTIME, carried in `plane_slots` under its ALWAYS-PRESENT
    // companion key (`runtime_slot_key(<mcp decl key>)`), distinct from the plane's decl key,
    // whose slot is config-conditional and drives the dispatch door. Built ONCE through the plane's
    // own type-erasing `build_runtime` seam (from the neutral `tool_defs` section, erased via
    // `PlaneCfg::as_any`) so this composition names no `crate::mcp` runtime type. It bundles the
    // catalogue snapshot (which takes the next PIN GENERATION on construction, so every config apply —
    // even one that changes nothing about `tools:` — moves the generation and a call admitted under the
    // previous one is refused at dispatch), the `tools:` registry, the fresh connection pool, the
    // CARRIED-ACROSS-APPLY sightings / roots-epochs / sampling-spend and the verify-on-call coalescer
    // (all accumulated evidence, not intent — see `McpRuntime::build`). Composing it beside the `App`
    // keeps the swap atomic: the whole `Arc<App>` is replaced under one lock, so the catalogue and the
    // config that produced it never disagree. With `plane-mcp` off there is no built-in decl, so no
    // slot is inserted and nothing downcasts it (no MCP accessor exists then).
    if let Some((slot_key, runtime_slot)) = crate::plane::registry::plane_decl_for_config_section(
        busbar_substrate::plane::config::NAMED_MAP_SECTIONS[2],
    )
    .and_then(|d| {
        d.build_runtime
            .map(|f| (crate::state::runtime_slot_key(d.key), f))
    })
    .map(|(slot_key, f)| {
        (
            slot_key,
            f(
                cfg.tool_defs.as_any(),
                prior.map(|p| p as &dyn busbar_substrate::plane_host::PlaneSlots),
            ),
        )
    }) {
        plane_slots.insert(slot_key, runtime_slot);
    }

    // THE LLM DATA-PLANE RUNTIME for this config generation — the pool/lane/failover/egress bundle,
    // carried in `plane_slots` under its ALWAYS-PRESENT companion key (`runtime_slot_key(<llm plane
    // key>)`), the SAME opaque slot MCP/A2A ride, now composed through the LLM plane's OWN type-erasing
    // `build_runtime` seam (1.6.0 money-path Phase 3-4 C — THE PIVOT): core populates the neutral
    // `PlaneBuildInput` carrier from the resolved config and hands it across the `&dyn Any` seam; the
    // plane rebuilds its `Lane`/`WeightedLane`/`PoolRuntime`/`NativeRuntime` tables IN-PLANE. Core names
    // no plane runtime type here, exactly as it composes the MCP runtime above.
    //
    // NEUTRAL telemetry label projections (money-path Phase 3-4 B): pool→member-idx list, the
    // direct-model index, and a lane-idx→model resolver — banked into `AppSlots::build` from the neutral
    // carrier's `lane_inputs`/`pool_inputs`/`by_model`, so core's label bank names no `Lane`/`WeightedLane`.
    let ts_pools: Vec<(&str, Vec<usize>)> = pool_inputs
        .iter()
        .map(|p| {
            (
                p.name.as_str(),
                p.members.iter().map(|m| m.lane_idx).collect(),
            )
        })
        .collect();
    let ts_by_model: Vec<(&str, usize)> = by_model
        .iter()
        .map(|(model, &idx)| (model.as_str(), idx))
        .collect();
    let tslots = Arc::new(telemetry::AppSlots::build(
        &ts_pools,
        &ts_by_model,
        |idx| lane_inputs.get(idx).map(|lane| lane.model.as_str()),
        crate::plane::fallback_key(),
    ));

    // Populate the NEUTRAL carrier field-by-field from the already-resolved config (pre-resolved secret
    // plaintexts + rate-card-derived costs + resolved context/tokens are in `lane_inputs`/`pool_inputs`).
    let llm_build_input = PlaneBuildInput {
        lanes: lane_inputs,
        pools: pool_inputs,
        upstream_credentials: cfg.upstream_credentials,
        allow_metadata_hosts: cfg.allow_metadata_hosts.clone(),
        allow_all_metadata: cfg.allow_all_metadata,
        blocked_metadata_hosts: cfg.blocked_metadata_hosts.clone(),
        client_settings: llm_client_settings,
        // The cross-protocol translation seam's GLOBAL fallback max-output-tokens and effort→budget
        // table — LLM-plane vocabulary, carried through the neutral carrier so the plane's
        // `build_runtime` stamps them onto its own `NativeRuntime` (they no longer live on `App`).
        global_default_max_tokens: cfg.limits.default_max_tokens,
        reasoning_budgets: {
            let b = cfg.limits.reasoning_effort_budgets;
            [b.minimal, b.low, b.medium, b.high]
        },
        // The FIXED global-default failover (production has no operator knob for it) — carried so the
        // plane's `build_runtime` sets `NativeRuntime.failover_cfg` identically to the pre-pivot inline
        // lowering, and so the test fixture can override the whole-App deadline.
        default_failover: Some(busbar_substrate::plane_host::FailoverInput {
            timeout_secs: crate::config::DEFAULT_FAILOVER_DEADLINE_SECS,
            exclusions: None,
            max_hops: crate::config::DEFAULT_FAILOVER_CAP,
        }),
    };

    let llm_runtime_key = crate::state::runtime_slot_key(crate::plane::fallback_key());
    // Compose the LLM runtime slot through the fallback plane's OWN `build_runtime` fn-pointer, exactly
    // as the MCP runtime is composed above — passing the neutral carrier erased to `&dyn Any` and the
    // prior generation's snapshot through the neutral `PlaneSlots` seam (for the warm-client /
    // probe-schedule carry-over the plane now owns). GATED on a genuine fallback (LLM) plane existing —
    // NOT merely on `fallback_key()` resolving — because `fallback_key()` degrades to the FIRST
    // registered plane's key when no plane flags itself fallback (the plane suites' dependency-copy of
    // core, which registers only MCP/A2A); writing the slot then would clobber that sibling's runtime.
    // With the LLM plane's `build_runtime` still `None` (pre-M3b) no slot is inserted and
    // `App::llm_runtime` reads the empty default — byte-identical to the featureless zero-plane boot.
    if crate::plane::is_fallback(crate::plane::fallback_key()) {
        if let Some(f) = crate::plane::registry::plane_decl_for(crate::plane::fallback_key())
            .and_then(|d| d.build_runtime)
        {
            let slot = f(
                &llm_build_input as &dyn std::any::Any,
                prior.map(|p| p as &dyn busbar_substrate::plane_host::PlaneSlots),
            );
            plane_slots.insert(llm_runtime_key, slot);
        }
    }

    // THE AUTHORIZATION SERVER, built ONCE, and only when the operator asked for one. Everything
    // this plane costs hangs off this `Option`: absent, nothing below runs, `App::oauth_as` is
    // `None`, `oauth_as::routes::mount` returns the router untouched, and no sweeper exists.
    //
    // The RFC 8707 `allowed_resources` list is busbar's OWN protected resources and nothing else.
    // Left unset, `oauth-as` would mint a token carrying whatever `resource` a client asked for in
    // its `aud`, which any resource server verifying against our JWKS would then honour — so the
    // list is derived here, from the planes this deployment actually serves, rather than configured
    // separately where it could disagree with them.
    let oauth_as_plane = match cfg.oauth_as.as_ref() {
        None => None,
        Some(identity) => {
            let key_material = match identity.signing_key() {
                None => {
                    diag_warn!(
                        OAUTH_AS_EPHEMERAL_SIGNING_KEY,
                        "oauth_as: no signing_key configured, so an EPHEMERAL ES256 key was \
                         generated. Every token this deployment issues stops verifying when the \
                         process restarts. Set `oauth_as.signing_key` for anything but a trial."
                    );
                    None
                }
                Some(reference) => Some(
                    secret_resolver
                        .resolve_string(reference)
                        .map_err(|e| format!("oauth_as.signing_key: {e}"))?,
                ),
            };
            // busbar's OWN protected resource is its MCP endpoint's canonical URI, read back through
            // the mcp plane's `admission` seam — a `PlaneAdmission::audience` IS that canonical URI —
            // so appbuild names no `crate::mcp` resource type. Empty when `mcp:` is absent or the MCP
            // plane is compiled out (no built-in decl, hence no admission, so the deployment protects
            // no MCP audience).
            let protected_resources: Vec<String> = cfg
                .endpoint_resources
                .get(busbar_substrate::plane::config::NAMED_MAP_SECTIONS[2])
                .and_then(|slot| {
                    crate::plane::registry::plane_decl_for_config_section(
                        busbar_substrate::plane::config::NAMED_MAP_SECTIONS[2],
                    )
                    .and_then(|d| (d.admission)(slot.as_ref()))
                })
                .map(|adm| adm.audience)
                .into_iter()
                .collect();
            let plane = crate::oauth_as::plane::AsPlane::build(
                identity.clone(),
                key_material.as_deref(),
                protected_resources,
            )
            .map_err(|e| e.to_string())?;
            let plane = Arc::new(plane);
            // `Storage::sweep_expired` is the only thing that reclaims anything in `oauth-as`, and
            // it runs when it is called and never otherwise. Spawned here, once per generation.
            crate::oauth_as::plane::spawn_sweeper(
                Arc::clone(plane.server()),
                std::time::Duration::from_secs(60),
            );
            Some(plane)
        }
    };

    // The generation's hook CONTENT ceiling, installed once here and read on the hook seam with a
    // single relaxed load — never recomputed per request, and never consulted at all on a
    // deployment with no content-granted hook, because no content projection is built there.
    crate::proxy::set_hook_content_max_bytes(cfg.limits.hook_content_max_bytes);

    let app = App {
        // Telemetry-bank slot table for this generation (built above as a local, BEFORE the
        // config-derived collections moved into the LLM runtime bundle so its `&lanes`/`&pools`/
        // `&by_model` borrows ran first). Identical label sets across applies re-intern to the same
        // slots, so hot-path counters accumulate monotonically across config generations.
        tslots,
        // THE LLM DATA-PLANE RUNTIME'S SLOT KEY (R3/R4 sub-phase B): the bundle itself was composed
        // above into `plane_slots` under this interned key through the LLM plane's `build_runtime`
        // seam; the snapshot names only the `&'static str` key, and `App::llm_runtime` downcasts the
        // slot on the money path. Absent slot (featureless build) reads the empty default.
        llm_runtime_key,
        store,
        // The non-LLM planes' breaker cells: PROCESS-LIFETIME, reused across an apply/reload the
        // way the HTTP client pool and governance state are — a config swap must not un-trip a
        // dead tool server or agent. Boot starts fresh (reliability is never persisted; the
        // store-or-RAM rule).
        // "What is not configured must not be loaded": a config with NO plane content — no mounted
        // plane slot, no `tools:`/`agents:` registration, no `tool_pools:`/`agent_pools:` — gets the
        // INERT handle (empty lane table; see `PlaneBreakers::new_inert` for the ~130 KiB the 8
        // placeholder cells' preallocated windows/stripes otherwise cost every planeless idle
        // process). A PROVISIONED prior is always reused (learned reliability survives every apply,
        // including one that removes the last plane section); an inert prior is upgraded HERE — at
        // apply, boot-only work — the first time plane content appears, losing nothing (an inert
        // handle never recorded anything). Note the `runtime_slot_key(<mcp decl key>)` companion slot is inserted on
        // every MCP-compiled build, so the gate reads the DECL keys (config-conditional), never it.
        plane_breakers: {
            let planes_configured = crate::plane::registry::plane_decls()
                .iter()
                .any(|d| plane_slots.contains_key(d.key))
                || !cfg.tool_defs.def_names().is_empty()
                || !cfg.agent_defs.def_names().is_empty()
                || !cfg.tool_pools.is_empty()
                || !cfg.agent_pools.is_empty();
            match prior {
                Some(p) if p.plane_breakers.is_provisioned() || !planes_configured => {
                    Arc::clone(&p.plane_breakers)
                }
                _ if planes_configured => Arc::new(crate::store::PlaneBreakers::new()),
                _ => Arc::new(crate::store::PlaneBreakers::new_inert()),
            }
        },
        // The neutral per-session substrate: PROCESS-LIFETIME like `plane_breakers`, reused across an
        // apply so a config swap never forgets a live session. Bounded (`SESSION_STORE_CAPACITY`
        // slots, LRU-evicted) and TTL-defaulted so an idle session's state cannot accumulate — the
        // memory-safety bound the substrate is built around.
        session_store: prior.map_or_else(
            || {
                Arc::new(crate::session::SessionStore::new(
                    SESSION_STORE_CAPACITY,
                    Some(SESSION_STORE_TTL_MS),
                ))
            },
            |p| Arc::clone(&p.session_store),
        ),
        // Operator opt-in for the gate's incremental-scan tenant. Env, not config: OFF (the default,
        // and any value that is empty or "0") keeps every gate screening the full projection —
        // byte-identical to 1.5.4 — while an operator can turn it on without a config-schema change.
        incremental_scan: std::env::var_os("BUSBAR_INCREMENTAL_SCAN")
            .is_some_and(|v| !v.is_empty() && v != "0"),
        // The failover pools, resolved-verbatim per generation (the CELLS above are process-
        // lifetime; the pool DECLARATIONS are config like any other).
        tool_pools: cfg.tool_pools.clone(),
        // The GENERIC per-plane failover pool map, keyed by each plane's stable decl key (the A2A
        // relay's `agent_pools:` set; the MCP `tool_pools:` set keeps its own dedicated field above).
        plane_pools: {
            // Keyed by the DECL KEY of the plane that owns the `agents:` section — resolved from the
            // registry, never spelled as a literal — so this composition names no plane. A compiled-out
            // plane has no decl for its section, so nothing is inserted; the pool read treats an absent
            // key identically to the former empty-value entry.
            let mut m = std::collections::BTreeMap::new();
            if let Some(decl) = crate::plane::registry::plane_decl_for_config_section(
                busbar_substrate::plane::config::NAMED_MAP_SECTIONS[3],
            ) {
                m.insert(decl.key, cfg.agent_pools.clone());
            }
            m
        },
        client_settings: new_client_settings,
        auth: auth_mw.clone(),
        rewrite_hooks,
        tap_hooks,
        tap_hooks_candidate,
        tap_hooks_routing,
        tap_hooks_response,
        global_gates,
        // The per-pool routing policy / decision gates / rewrite chains, read by the relocated LLM
        // engine through `App::pool_{policy,gates,rewrites}` (the pool-hook facade).
        pool_orderings,
        pool_decision_gates,
        pool_rewrite_chains,
        // The GENERIC per-plane per-container submission-gate map, keyed by each plane's stable decl
        // key — in place of the former per-plane `mcp_server_gates`/`a2a_agent_gates` fields. Each
        // plane's resolved gate map (built above, empty when its feature is off) goes under its key.
        plane_gates: {
            // Keyed by each owning plane's DECL KEY, resolved from the registry rather than named as a
            // literal: the `tools:` section's plane takes `mcp_server_gates`, the `agents:` section's
            // plane takes `a2a_agent_gates`. A compiled-out plane has no decl for its section, so its
            // (empty) gate map is simply not inserted — byte-identical to the former empty-value entry.
            let mut m = std::collections::BTreeMap::new();
            if let Some(decl) = crate::plane::registry::plane_decl_for_config_section(
                busbar_substrate::plane::config::NAMED_MAP_SECTIONS[2],
            ) {
                m.insert(decl.key, mcp_server_gates);
            }
            if let Some(decl) = crate::plane::registry::plane_decl_for_config_section(
                busbar_substrate::plane::config::NAMED_MAP_SECTIONS[3],
            ) {
                m.insert(decl.key, a2a_agent_gates);
            }
            m
        },
        // THE TAP twin of `plane_gates`, built identically: each plane's rewrite-chain map under its
        // decl key, empty (hence not inserted) for a compiled-out plane.
        plane_rewrites: {
            let mut m = std::collections::BTreeMap::new();
            if let Some(decl) = crate::plane::registry::plane_decl_for_config_section(
                busbar_substrate::plane::config::NAMED_MAP_SECTIONS[2],
            ) {
                m.insert(decl.key, mcp_server_rewrites);
            }
            if let Some(decl) = crate::plane::registry::plane_decl_for_config_section(
                busbar_substrate::plane::config::NAMED_MAP_SECTIONS[3],
            ) {
                m.insert(decl.key, a2a_agent_rewrites);
            }
            m
        },
        hook_env: hook_env.clone(),
        hook_registry: cfg.hooks.clone(),
        requested_signals: hooks::requested_signals(&cfg.hooks),
        any_content_hook: hooks::any_content_hook(&cfg.hooks),
        export_projections: cfg.export.projection_union(),
        global_hooks: cfg.global_hooks.clone(),
        groups_registry: cfg.groups.clone(),
        base_group_names,
        // The two NAMED-DEFINITION maps the generic admin CRUD serves, carried verbatim off the
        // resolved config (the EFFECTIVE base+overlay shape).
        identity_providers: cfg.identity_providers.clone(),
        export_defs: cfg.export_defs.clone(),
        // TYPE-ERASED into `App` so it names no `crate::a2a` config type — the SAME resolved object
        // (a clone, not a reparse), so the admin view and gates are byte-identical. The A2A plane
        // downcasts it back in `crate::a2a::agent_cfg`.
        agent_defs: cfg.agent_defs.clone_arc_any(),
        // THE A2A PLANE, built only when `agents:` defines one, is NOT mirrored into a typed `App`
        // field any more: it lives solely in its `plane_slots` entry (built once by `PlaneDecl::build`),
        // and every reader reaches it through `crate::a2a::runtime(app)`/`runtime_arc(app)`, which
        // downcast that slot inside the a2a module. So there is no `a2a:` initializer here and `App`
        // names no `crate::a2a` type for the runtime object. The A2A verify-on-call GATE and the
        // boot-resolved CARD transports moved ONTO that same `A2aPlane` runtime object too (like MCP's
        // `McpRuntime::verify`): they are carried across this apply INSIDE the plane's `build` (through
        // `carried_a2a_gates`, off `BuildCtx::prior`), so `App` carries no `a2a_verify`/`a2a_cards`
        // field for them either.
        // History + rate windows are Arc-shared across applies (process-lifetime state).
        versions: prior.map_or_else(
            || Arc::new(admin::versions::VersionLog::new()),
            |p| p.versions.clone(),
        ),
        mutation_limiter: prior.map_or_else(
            || Arc::new(admin::rate::MutationLimiter::new()),
            |p| p.mutation_limiter.clone(),
        ),
        idempotency_cache: prior.map_or_else(
            || Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            |p| p.idempotency_cache.clone(),
        ),
        base_hook_names,
        admin_chain: cfg.admin_auth.clone(),
        admin_modules,
        login_methods,
        public_url: cfg.public_url.clone(),
        // The MCP plane, and the dispatch table that governs it, are built from ONE validated
        // object in ONE act: the resource that mounts the ingress is the same resource whose
        // canonical URI becomes the audience the middleware enforces there. Absent `mcp:`, the
        // dispatch table is empty and `admission_for` answers `None` for every path, so the
        // audience check costs one `Option` test on the hot path and changes nothing.
        //
        // THE SECOND CONSUMER. A2A mounts and admits through the very same two verbs, with its own
        // strings and no new code in `plane/` — which is the claim that module's own doc made when
        // it was written for a consumer that did not exist yet. A2A admits only when it has a
        // RECEIVING side (`A2aPlane::admission` answers `None` without a `public_url`), so a
        // delegation-only deployment claims no path and binds no audience.
        // THE DISPATCH TABLE, folded from the registered plane declarations rather than a hardcoded
        // block per plane. Each plane's runtime object is handed to its decl (type-erased as
        // `&dyn Any`), and the decl computes the plane's claims and admission from it — the same
        // strings the hardcoded MCP/A2A blocks used to compute, now stated beside the plane they
        // describe so an extracted plane crate contributes its own door. `build_dispatch` refuses the
        // boot if any plane claims a path but binds no audience (ratchet R2).
        //
        // The slot lookup reads `plane_slots` (built above, once, via each decl's `build` fn) rather
        // than naming `crate::mcp`/`crate::a2a` directly — the CLAIMS and ADMISSION logic, and now
        // the object the two are computed from, are all reached through the decl.
        planes: Arc::new({
            let ref_slots: std::collections::BTreeMap<&'static str, &dyn std::any::Any> =
                plane_slots
                    .iter()
                    .map(|(k, v)| (*k, v.as_ref() as &dyn std::any::Any))
                    .collect();
            crate::plane::registry::build_dispatch(
                crate::plane::registry::plane_decls(),
                &ref_slots,
            )?
        }),
        // THE TYPE-ERASED SLOT MAP ITSELF (Step 2.3). Moved in last: every typed field above that
        // reads a plane's object does so by cloning out of this map first, so `plane_slots` and
        // (e.g.) `mcp`/`a2a` are guaranteed to agree — there is no second `build` call anywhere that
        // could disagree with what is stored here.
        // THE MCP PLANE'S PER-GENERATION RUNTIME (and the verify-on-call coalescer folded into it) is
        // no longer a flat `App` field: it was inserted into `plane_slots` above under
        // `runtime_slot_key(<mcp decl key>)`, through the plane's own `build_runtime` seam. `plane_slots`
        // is moved into `App` on the line just above; the MCP plane reads its runtime back through
        // `crate::mcp::runtime`, which downcasts that slot inside the plane.
        plane_slots,
        oauth_as: oauth_as_plane.clone(),
        // CARRIED ACROSS THE APPLY for the same reason, and it is the same class of mistake: an
        // approval already spent is evidence, not intent, and a config apply that forgot it would
        // hand every outstanding confirmation back to whoever still holds it.
        spent_token_ledger: prior.map_or_else(
            || Arc::new(crate::plane::approvals::SpentTokenLedger::new()),
            |p| p.spent_token_ledger.clone(),
        ),
        // CARRIED ACROSS THE APPLY, and here the reason is sharper than for the two above: the
        // durable sink is attached to this instance once at boot, so rebuilding it on an apply would
        // silently detach it and every later quarantine would stop being written down.
        demotion_record: prior.map_or_else(
            || Arc::new(crate::plane::quarantine::DemotionRecord::new()),
            |p| p.demotion_record.clone(),
        ),
        credential_cache: prior.map_or_else(
            || Arc::new(auth_cache::CredentialCache::new()),
            |p| p.credential_cache.clone(),
        ),
        auth_scope_caps: cfg
            .auth
            .as_ref()
            .map(project_auth_scope_caps)
            .unwrap_or_default(),
        role_bindings: cfg
            .auth
            .as_ref()
            .map(|a| a.role_bindings.clone())
            .unwrap_or_default(),
        config_path: config_paths.0,
        providers_path: config_paths.1,
        overlay_path,
        config_version: app_config_version,
        max_keys_per_principal: cfg.limits.max_keys_per_principal,
        max_auto_provisioned_groups: cfg.limits.max_auto_provisioned_groups,
        governance,
        secret_resolver,
        cost,
        plugins_dir: std::path::PathBuf::from(&plugins_cfg.dir),
        plugins_cfg,
        // Where `auth.key_ttl` is finally READ: the self-serve mint's token lifetime.
        // Config-validate already proved this parses; the fallback keeps a bad value from panicking.
        self_key_ttl_secs: cfg
            .auth
            .as_ref()
            .and_then(|a| a.key_ttl.as_deref())
            .map(|s| admin::parse_duration_secs(s).unwrap_or(admin::DEFAULT_KEY_TTL_SECS))
            .unwrap_or(admin::DEFAULT_KEY_TTL_SECS),
        // Where `auth.policy:` is finally READ: the resolved mint policy (block TTL/mode ceiling +
        // per-role `mint_ceilings`). Config-validate already proved the durations parse; a stray bad
        // value falls back to no cap rather than fabricating a ceiling nobody wrote.
        mint_policy: std::sync::Arc::new(admin::MintPolicy::from_auth(cfg.auth.as_ref())),
        // Arc-shared like `versions`/`mutation_limiter`: a REBUILD carries the SAME counter forward
        // (ids stay monotonic across a config reload) while a fresh boot seeds it once from OS
        // entropy (see `state::seed_request_id_counter`) so restarts don't restamp `0, 1, 2, …`.
        request_id_counter: prior.map_or_else(
            || {
                Arc::new(std::sync::atomic::AtomicU64::new(
                    state::seed_request_id_counter(),
                ))
            },
            |p| p.request_id_counter.clone(),
        ),
        plugin_routes,
        boot_route_paths,
    };
    // PRUNE the verify-on-call gates to the subjects THIS generation still fronts. `flights` and
    // `drift_latch` are per-subject coordination CARRIED across every apply (above); without a prune
    // they leak one dead entry per server/agent an operator ever removed. Done here, on the same
    // carry path, with the live registration set of each plane: a pruned subject is one no delegation
    // can name, so dropping its coalescing state and latch cannot race a verify (fail-closed intact).
    // Each plane prunes its OWN verify-on-call gate through its `retain_verify_gates` seam, so this
    // composition names no `crate::mcp`/`crate::a2a` runtime type. UNCONDITIONAL per the hooks' own
    // contract: when the operator REMOVES a plane's block the live subject set is EMPTY, so retain
    // drops every carried flight/latch instead of leaking one per removed subject. The two hooks touch
    // disjoint gates (each plane's own runtime `verify`), so the registry iteration order is not observable.
    for decl in crate::plane::registry::plane_decls() {
        if let Some(retain) = decl.retain_verify_gates {
            retain(&app);
        }
    }
    // The build reached its end without a single fallible step refusing: KEEP the limits installed
    // at the top. Every earlier `return Err` / `?` drops the guard instead and rolls them back.
    limits_guard.commit();
    Ok((app, rotate_gov_credentials))
}
