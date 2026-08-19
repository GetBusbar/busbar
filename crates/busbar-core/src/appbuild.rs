//! APP CONSTRUCTION — how a `busbar` process's App comes to exist: the environment axes, the
//! boot banners, config load from disk, and `build_app_from_config` (the one function that turns a
//! validated `RootCfg` into a living `App`). Reached from the binary's `run()` AND from the admin
//! plane's config PATCH/reload path (`admin/v1/json/*` re-runs the load pipeline on a live apply),
//! which is why this is core and not bin: a hot reload that called UP into the composition root
//! would be the dependency inversion the core split exists to remove.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::auth::AuthMiddleware;
use crate::preflight::{
    build_secret_resolver, plugin_fetch_downloader, plugins_preflight, resolve_admin_token,
    resolve_signing_key, validate_secret_refs,
};
use crate::proto::ProtocolRegistry;
use crate::router::project_auth_scope_caps;
use crate::state::{App, Lane, WeightedLane};
use crate::store::{HealthState, LaneData};
#[allow(unused_imports)]
use crate::{
    a2a, admin, audit, auth, auth_cache, billing, breaker, catalogue, config, config_validate,
    core_routes, cost, durable, egress_auth, endpoints, eventstream, export, failover, governance,
    handlers, health, hooks, ingress, ir, json, limits, lossless, mcp, media, metrics, net_guard,
    oauth_as, observability, operation, plane, plugin_routes, profile, proto, proxy, sigv4, state,
    store, telemetry, tls, transport, trust,
};

// The upstream-request timeout, pool-idle, and request-body caps that used to live here as `const`s
// are now operator-tunable (`limits.upstream_request_timeout_secs` / `pool_max_idle_per_host` /
// `request_body_max_bytes`), each defaulting to its historical value at the config layer. They are
// threaded from `cfg.limits` into the client builder and router below; the egress translate-body cap
// is COUPLED to `request_body_max_bytes` via `crate::limits::translate_body_max_bytes`.

/// DEPRECATED (1.5.3) environment variable name for the providers.yaml path — migrated to the
/// top-level `providers_file:` key in config.yaml. Still honored for one release (see
/// [`providers_override_from_env`]).
pub const ENV_PROVIDERS: &str = "BUSBAR_PROVIDERS";

/// Environment variable name for the config.yaml path — the one irreducible bootstrap env var.
pub const ENV_CONFIG: &str = "BUSBAR_CONFIG";

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

/// Resolve a boot-time boolean upstream knob under the env→config migration precedence: the DEPRECATED
/// env var, when SET, wins (honored for one release) — `"0"` or empty means OFF, anything else ON; when
/// UNSET, the config value (`advanced.upstream_*`, carried on `cfg.limits`) stands. The deprecation
/// WARN is emitted at the call site (only when the env var is present). Module-level so the precedence
/// is unit-testable without building the whole client; see `tests/tests.rs`.
pub fn upstream_bool_env_override(env: Option<std::ffi::OsString>, config_val: bool) -> bool {
    match env {
        Some(v) => v != "0" && !v.is_empty(),
        None => config_val,
    }
}

/// Everything the DISK half of configuration produces, shared by boot and runtime reload.
pub struct LoadedConfig {
    pub deploy: config::DeployCfg,
    pub defs: HashMap<String, config::ProviderDef>,
    /// The RESOLVED providers-catalog path actually read (1.5.3): `config.providers_file` relative to
    /// the config dir, the deprecated `BUSBAR_PROVIDERS` override, or `providers.yaml` next to the
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

/// `providers_override`: the DEPRECATED `BUSBAR_PROVIDERS` path (Some ⇒ set), or the live
/// providers path a runtime reload wants to re-use. When `None`, the catalog path is resolved from
/// `config.providers_file` (relative to the config dir) or defaults to `providers.yaml` next to the
/// resolved config.yaml (1.5.3).
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
    let deploy: config::DeployCfg = serde_yaml::from_str(&interpolated_config).map_err(|e| {
        format!(
            "config.yaml: invalid YAML: {}",
            config::augment_config_error(e)
        )
    })?;

    // 1.5.3: resolve the providers CATALOG path. Precedence: the explicit override (the deprecated
    // `BUSBAR_PROVIDERS` env var, or a runtime reload re-using its boot path) > `config.providers_file`
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
    let env_overlay = std::env::var("BUSBAR_CONFIG_OVERLAY")
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);
    let probe_fs = matches!(env_mode, config::EnvSubst::Strict);
    let resolution = config::overlay::resolve_backend(
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
        tracing::warn!(
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
                    tracing::warn!(
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
                    tracing::warn!(provider = %mc.provider, "provider api_key did not resolve: {e}");
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

    let registry = ProtocolRegistry::with_builtins();

    // Build a map from model name to context_max. A model is one lane shared across every pool that
    // names it, so its context_max must be single-valued. Previously the last pool to iterate (in
    // nondeterministic HashMap order) silently won, so a model carrying `context_max: Some(128000)`
    // in one pool and `None` (or a different limit) in another could end up with whichever value the
    // iteration happened to land on — defeating the context-length failover exclusion in proxy engine
    // and losing pool-specific limits without a diagnostic. Resolve it deterministically and fail
    // loud on a genuine conflict instead.
    let model_context_max = resolve_model_context_max(&cfg.pools)?;

    let mut lanes = Vec::new();
    for (idx, ld) in lanes_data.iter().enumerate() {
        // Reuse the provider handle resolved (and validated via `die`) in the lanes_data loop above,
        // captured in lockstep into `lane_provider_cfgs`. No redundant re-lookup / `expect` here.
        let provider_cfg = lane_provider_cfgs[idx];
        let Some(protocol) = registry.get(&provider_cfg.protocol) else {
            return Err(format!(
                "provider '{}' uses unknown protocol '{}' (supported: anthropic, openai, gemini, bedrock, responses, cohere)",
                ld.provider, provider_cfg.protocol
            ));
        };
        // Reuse the single env read captured in the lanes_data loop above (same source of truth as
        // the empty-key warning); no second read of the secret-bearing env var.
        let api_key = provider_api_keys
            .get(&ld.provider)
            .cloned()
            .unwrap_or_default();
        // Resolve the outbound credential once. Most auth styles are a simple sync lookup; the OAuth
        // styles parse their credential material here (failing loud on a bad key) and start a
        // background token minter/refresher. `api_key` carries that material.
        //
        // Both OAuth mechanisms vet their token endpoint (oauth `token_url`, jwt-bearer SA `token_uri`)
        // for SSRF against the operator's REAL metadata posture so the boot-time check matches
        // config_validate's validate-time check EXACTLY (validate == apply) and both mechanisms behave
        // identically: the allow-override set is the SAME union config_validate builds (this provider's
        // `allow_metadata_hosts` ∪ the global `security.allow_metadata_hosts`), plus the nuclear
        // `allow_all_metadata` and the operator's extra `blocked_metadata_hosts`. Threading it into
        // jwt-bearer too means a global `blocked_metadata_hosts` deny is enforced on a jwt
        // `token_uri`, and `allow_all_metadata` uniformly disables the guard for both.
        let allow_overrides: Vec<String> = provider_cfg
            .allow_metadata_hosts
            .iter()
            .chain(cfg.allow_metadata_hosts.iter())
            .cloned()
            .collect();
        let ssrf = egress_auth::MetadataSsrfPolicy {
            allow_overrides: &allow_overrides,
            allow_all: cfg.allow_all_metadata,
            blocked_hosts: &cfg.blocked_metadata_hosts,
        };
        let credential = match provider_cfg.auth {
            // `jwt-bearer`: `api_key` is the service-account JSON (inline) or a key-file path. A
            // configured `scope:` overrides the default cloud-platform scope (else `None` → default).
            // A configured `subject:` (RFC 7523 `sub`) is opt-in: `None` (the default, every existing
            // Vertex AI config) omits the claim entirely, unchanged from before this field existed.
            Some(config::ProviderAuth::JwtBearer) => egress_auth::jwt_bearer::build(
                &api_key,
                provider_cfg.scope.as_deref(),
                provider_cfg.subject.as_deref(),
                &ssrf,
            )
            .map_err(|e| format!("provider '{}' (jwt-bearer auth): {e}", ld.provider))?,
            // `oauth-client-credentials`: `api_key` is `client_id:client_secret`; `token_url`+`scope`
            // come from the provider config (required — the config validator also rejects them absent).
            Some(config::ProviderAuth::OAuthClientCredentials) => {
                let token_url = provider_cfg.token_url.as_deref().ok_or_else(|| {
                    format!(
                        "provider '{}' (oauth-client-credentials auth) requires `token_url`",
                        ld.provider
                    )
                })?;
                let scope = provider_cfg.scope.as_deref().ok_or_else(|| {
                    format!(
                        "provider '{}' (oauth-client-credentials auth) requires `scope`",
                        ld.provider
                    )
                })?;
                egress_auth::oauth_client_credentials::build(&api_key, token_url, scope, &ssrf)
                    .map_err(|e| {
                        format!(
                            "provider '{}' (oauth-client-credentials auth): {e}",
                            ld.provider
                        )
                    })?
            }
            _ => egress_auth::resolve(&provider_cfg.protocol, provider_cfg.auth),
        };
        let base_url = provider_cfg.base_url.trim_end_matches('/').to_string();
        lanes.push(Lane {
            model: ld.model.clone(),
            provider: ld.provider.clone(),
            // Precompute the SigV4 signed-host once at boot (pure function of base_url) so the forward
            // path borrows it into SigningContext instead of re-parsing/allocating it per request.
            signing_host: proxy::host_from_base(&base_url),
            base_url,
            api_key: busbar_api::Redacted::new(api_key),
            credential,
            protocol,
            max: ld.max,
            error_map: Arc::new(provider_cfg.error_map.clone()),
            context_max: model_context_max.get(&ld.model).copied().flatten(),
            path: provider_cfg.path.clone(),
            path_base: provider_cfg.path_base.clone(),
            health: provider_cfg.health.clone(),
            upstream_model: ld.upstream_model.clone(),
            attempt_timeout_ms: ld.attempt_timeout_ms,
            reasoning: ld.reasoning,
            prompt_caching: ld.prompt_caching,
            default_max_tokens: model_default_max_tokens.get(&ld.model).copied().flatten(),
        });
    }

    let mut pools = HashMap::new();
    for (name, pool) in &cfg.pools {
        // Wire per-member weights from config into the pool structure.
        // Each pool member has a weight; default is 1 if not specified.
        let mut weighted_members: Vec<WeightedLane> = Vec::with_capacity(pool.members.len());
        for m in pool.members.iter() {
            {
                let Some(&lane_idx) = by_model.get(&m.model) else {
                    return Err(format!(
                        "pool '{name}' references unknown model '{}'",
                        m.model
                    ));
                };
                weighted_members.push(WeightedLane {
                    idx: lane_idx,
                    weight: m.weight, // from config PoolMember.weight (default 1)
                    // Per-member attempt cap: one model, different hang budgets per pool/workload.
                    attempt_timeout_ms: m.attempt_timeout_ms,
                    reasoning: m.reasoning,
                });
            }
        }
        pools.insert(name.clone(), weighted_members);
    }

    eprintln!("busbar: {} models, {} pools", lanes.len(), pools.len());
    for (n, wl_vec) in &pools {
        let agg: usize = wl_vec.iter().map(|wl| lanes[wl.idx].max).sum();
        eprintln!(
            "  pool /{} = [{}] aggregate {}",
            n,
            wl_vec
                .iter()
                .map(|wl| lanes[wl.idx].model.clone())
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
        tracing::error!("{banner}");
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

    // Global default failover config — the fallback for pools that don't set their own. A fixed
    // default (not "whatever pool HashMap iteration happens to yield first", which was
    // nondeterministic across restarts).
    let failover_cfg = Some(crate::config::FailoverCfg {
        timeout_secs: crate::config::DEFAULT_FAILOVER_DEADLINE_SECS,
        exclusions: None,
        max_hops: crate::config::DEFAULT_FAILOVER_CAP,
    });

    // The fallback-pool routing table: on_exhausted `fallback_pool:<name>` looks a pool up here,
    // so it mirrors the pools map (any pool can be a fallback target).
    let fallback_pools = pools.clone();

    // The upstream HTTP client, built ONCE — as N per-thread SHARDS (see `UpstreamClients`): each
    // worker thread keeps its own client/pool, so no request ever crosses another core's pool
    // lock. Constructed before the pool-runtime loop so the webhook routing transport can reuse
    // it (a shard clone shares that shard's connection pool + the `redirect:none` SSRF posture);
    // the sharded set is then moved into `App` below.
    let upstream_client = if let Some(p) = prior {
        // REUSED across applies: the pooled connections + their kept-alive upstream sockets.
        p.client.clone()
    } else {
        // Opt-in HTTP/2 PRIOR-KNOWLEDGE for CLEARTEXT upstreams (no TLS/ALPN to negotiate over):
        // `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE=1` makes the shared client assume h2 without ALPN. This
        // is a PROCESS-WIDE, DEFAULT-OFF switch — production keeps ALPN (safe against h1 upstreams);
        // it exists so a cleartext h2c backend (e.g. the benchmark mock, or an in-mesh h2c service)
        // can exercise multiplexing without TLS. It FORCES h2, so every configured upstream must speak
        // h2c when set — never enable it against a mixed/h1 fleet. Read once at client-build time.
        // 1.5.3: home is `advanced.upstream_h2_prior_knowledge` in config.yaml (carried on
        // `cfg.limits`); the `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` env var overrides it for one release,
        // with a deprecation warn.
        let h2_env = std::env::var_os("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE");
        if h2_env.is_some() {
            tracing::warn!(
                "BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE is DEPRECATED; set \
                 `advanced.upstream_h2_prior_knowledge` in config.yaml (honored for now)."
            );
        }
        let h2_prior_knowledge =
            upstream_bool_env_override(h2_env, cfg.limits.upstream_h2_prior_knowledge);
        // Opt-out ESCAPE HATCH for the ALPN h2 default: `BUSBAR_UPSTREAM_HTTP1_ONLY=1` pins the
        // shared client to HTTP/1.1 (reqwest `.http1_only()`), so ALPN never offers h2 at all. This
        // is a PROCESS-WIDE, DEFAULT-OFF switch — production keeps the ALPN default (h2 where the
        // backend accepts it, h1 otherwise); it exists as an operational rollback lever in case a
        // specific upstream negotiates h2 but misbehaves on it (flow-control stalls, broken
        // keep-alive pings, intermediary bugs) and you need the pre-h2 wire behavior back without a
        // rebuild. Mutually exclusive in spirit with the h2c opt-in above (forcing h1 AND forcing
        // h2 makes no sense); if both are set, http1-only wins because it is applied last. Read
        // once at client-build time. 1.5.3: home is `advanced.upstream_http1_only` in config.yaml
        // (carried on `cfg.limits`); the `BUSBAR_UPSTREAM_HTTP1_ONLY` env var overrides it for one
        // release, with a deprecation warn.
        let http1_env = std::env::var_os("BUSBAR_UPSTREAM_HTTP1_ONLY");
        if http1_env.is_some() {
            tracing::warn!(
                "BUSBAR_UPSTREAM_HTTP1_ONLY is DEPRECATED; set `advanced.upstream_http1_only` in \
                 config.yaml (honored for now)."
            );
        }
        let http1_only = upstream_bool_env_override(http1_env, cfg.limits.upstream_http1_only);
        let shard_count = crate::state::UpstreamClients::shard_count();
        // The per-host idle budget is divided across shards so the TOTAL kept-alive sockets
        // toward any single upstream stay at the configured value (never below 1 per shard).
        let idle_per_host_per_shard = cfg
            .limits
            .pool_max_idle_per_host
            .div_ceil(shard_count)
            .max(1);
        let make_one = || {
            let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(
                cfg.limits.upstream_request_timeout_secs,
            ));
            builder = builder
                // Bound the TCP connect separately from the coarse overall timeout: a stalled SYN would
                // otherwise hang up to the streaming `.timeout()` (minutes) before failover kicks in.
                .connect_timeout(Duration::from_secs(10))
                // Keep idle upstream sockets alive so a middlebox silently dropping a long-idle
                // keep-alive connection is detected proactively, not discovered as a spurious failure on
                // the next request (added latency + a needless failover hop).
                .tcp_keepalive(Duration::from_secs(60))
                // Disable Nagle's algorithm on the EGRESS sockets. Busbar writes a whole request body in
                // one shot and then immediately awaits the response, so Nagle has nothing to coalesce —
                // but on a small body it interacts with the peer's delayed-ACK to hold the final segment
                // for up to ~40 ms waiting for an ACK that only arrives once the peer's timer fires. That
                // manifests as a bimodal tail-latency spike (a native SDK, which also sets TCP_NODELAY,
                // never sees it) and is pure added latency on the request path. Inbound accepted sockets
                // already set this (tls.rs serve loops); this brings the egress leg to parity. `axum`'s
                // own serve() defaults nodelay on; reqwest does NOT, so it must be set explicitly.
                .tcp_nodelay(true)
                // HTTP/2 to the upstream, NEGOTIATED via ALPN (NOT prior-knowledge): over TLS the client
                // offers `h2,http/1.1` and uses whichever the backend accepts, so an h2-capable provider
                // (Anthropic, OpenAI, Vertex, Bedrock all speak h2) multiplexes many concurrent requests
                // over ONE connection — collapsing the per-request connect+TLS handshake and the socket /
                // epoll pressure that caps proxy RPS on a core-bound box — while an HTTP/1-only backend
                // transparently stays on h1. By DEFAULT we do NOT call `.http2_prior_knowledge()` (that
                // would FORCE h2 and break every h1 upstream and a plaintext h1 mock) — it is applied only
                // when the cleartext-h2c opt-in below is set. H2 keep-alive pings keep a multiplexed
                // connection healthy through idle gaps without the h1 trick of holding N sockets open. No
                // behavior change against an h1-only upstream on the default (ALPN) path.
                .http2_keep_alive_interval(Duration::from_secs(30))
                .http2_keep_alive_timeout(Duration::from_secs(10))
                .http2_adaptive_window(true)
                .pool_max_idle_per_host(idle_per_host_per_shard)
                // Idle keep-alive lifetime — EXPLICIT 300s default, replacing reqwest's implicit 90s:
                // the warm working set (amortized TCP+TLS handshakes / h2 sessions) survives
                // inter-burst gaps of a few minutes instead of being reaped and re-paid as cold
                // handshakes when the next burst lands. Safe at 300s because `tcp_keepalive(60s)`
                // above actively validates idle sockets (a silently-dropped connection is caught by
                // the probe, not by a failed request), and bounded by `pool_max_idle_per_host` + OS
                // reclamation. Operator-tunable via `limits.pool_idle_timeout_secs`.
                .pool_idle_timeout(Duration::from_secs(cfg.limits.pool_idle_timeout_secs))
                // SSRF guard: do NOT follow redirects. The startup SSRF blocklist (config_validate.rs
                // ssrf_blocked_host) only vets the configured base_url; it does not see redirect targets.
                // reqwest's default policy follows up to 10 redirects, so a compromised/malicious upstream
                // could 30x-redirect a vetted base_url to an internal address (169.254.169.254 metadata,
                // localhost, RFC1918) and busbar would follow it — forwarding the signed request
                // (x-api-key / SigV4 Authorization on same-host redirects) to the internal target,
                // defeating the blocklist at runtime. Upstream AI provider APIs do not redirect as part of
                // normal operation, so disabling redirect following entirely closes the vector at no cost.
                .redirect(reqwest::redirect::Policy::none());
            // Cleartext h2c opt-in (bench / in-mesh): FORCE h2 without ALPN. Default-off; when set, every
            // upstream must speak h2c. Applied last so it overrides the ALPN default above.
            if h2_prior_knowledge {
                builder = builder.http2_prior_knowledge();
            }
            // HTTP/1-only escape hatch: pin the client to h1 (no ALPN h2 offer). Applied last so it
            // wins over both the ALPN default and the h2c opt-in above.
            if http1_only {
                builder = builder.http1_only();
            }
            builder.build().expect("build upstream HTTP client")
        };
        crate::state::UpstreamClients::build(shard_count, make_one)
    };

    // The `default:` hook (if any) — the base ordering that pools which named none inherit, replacing
    // the compiled-in weighted backstop (everything-is-a-hook model). At most one (validated).
    let default_hook = hooks::default_hook_name(&cfg.hooks).map(str::to_string);
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
            tracing::warn!(
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

    // Per-pool runtime config (failover/exclusions), keyed by pool name.
    let mut pool_runtime = std::collections::HashMap::new();
    for (pool_name, pool_cfg) in &cfg.pools {
        pool_runtime.insert(
            pool_name.clone(),
            state::PoolRuntime {
                failover: pool_cfg.failover.clone(),
                // 1.5.3: the pool's own `upstream_credentials:` OVERRIDES the all-pools
                // `pools.upstream_credentials:` default; `None` inherits it.
                upstream_credentials: pool_cfg.upstream_credentials,
                affinity: pool_cfg.affinity.clone(),
                breaker: pool_cfg.breaker.as_ref().map(store::BreakerCfg::from),
                // Operator-declared member metadata (tier/cost/tags) keyed by lane idx, for the
                // routing Candidate projection. Mirrors the WeightedLane construction's target→lane
                // mapping (by_model). Read only inside the policy arm of the seam.
                members: pool_cfg
                    .members
                    .iter()
                    .filter_map(|m| {
                        by_model.get(&m.model).map(|&idx| {
                            (
                                idx,
                                state::MemberMeta {
                                    tier: m.tier.clone(),
                                    // The routing cost scalar derives from the member's
                                    // MODEL's rate_card entry - cost lives on no pool member.
                                    cost_per_mtok: cfg
                                        .rate_card
                                        .as_ref()
                                        .and_then(|card| card.get(&m.model))
                                        .map(crate::config::rate_entry_per_mtok),
                                    tags: m.tags.clone(),
                                },
                            )
                        })
                    })
                    .collect(),
                // Resolve the routing policy ONCE here. `weighted` (default) ⇒ `None` ⇒ the zero-cost
                // inline SWRR path; a `default:` hook replaces that base for pools that named none; a
                // `kind: hook` plugin base opens a `DlopenPolicy` through the plugin registry.
                policy: hooks::resolve_pool_ordering(
                    pool_cfg,
                    &cfg.hooks,
                    &hook_env,
                    default_hook.as_deref(),
                    app_config_version,
                ),
                // This pool's decision gates, resolved once here (priority carried for the phase-2
                // chain merge). NOT re-resolved on config apply yet — same scope caveat as `policy`.
                gates: hooks::resolve_pool_gates(
                    pool_cfg,
                    &cfg.hooks,
                    &hook_env,
                    app_config_version,
                ),
                rewrite_hooks: hooks::resolve_pool_rewrites(
                    pool_cfg,
                    &cfg.hooks,
                    &hook_env,
                    app_config_version,
                ),
            },
        );
    }

    // Parse on_exhausted configs per pool
    let mut on_exhausted_cfgs = std::collections::HashMap::new();
    for (pool_name, pool_cfg) in &cfg.pools {
        if let Some(ref on_exc) = pool_cfg.on_exhausted {
            // The structured config value maps directly (unknown spellings already failed parse).
            let mode = on_exc.to_runtime();
            tracing::info!(pool = %pool_name, on_exhausted = ?mode, "pool exhaustion policy");
            on_exhausted_cfgs.insert(pool_name.clone(), mode);
        } else {
            // Default to Status503 if not specified
            on_exhausted_cfgs.insert(pool_name.clone(), crate::config::OnExhausted::Status503);
        }
    }

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
        let store: Arc<dyn governance::Store> =
            if g.module == crate::config::GOVERNANCE_STORE_MEMORY {
                tracing::warn!(
                    "store: in-memory (ephemeral) - keys, groups' usage, and ledgers reset on \
                     restart; configure a durable store plugin for persistence"
                );
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
                    tracing::error!("{banner}");
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

    // THE OTHER TWO PLANES' GATES, resolved by the SAME function, from the SAME registry, on the
    // same generation — which is the point. `tools.hooks:` / `agents.hooks:` and the per-entry
    // lists have parsed and validated since 1.5.3 and fired nothing, because nothing resolved them
    // and nothing called them. These two lines and their two firing sites are the whole of what was
    // missing; the grammar, the validation and the cross-plane refusal were already there.
    //
    // Empty on every deployment that attaches nothing, which is every deployment that does not
    // spell the key — so the dispatch paths' lookups cost one hash probe against an empty map.
    let mcp_server_gates = hooks::resolve_container_gates(
        cfg.tool_defs
            .servers
            .iter()
            .map(|(name, def)| (name.as_str(), def.hooks.as_slice())),
        &cfg.tool_defs.all_server_hooks,
        &cfg.hooks,
        &hook_env,
        app_config_version,
    );
    let a2a_agent_gates = hooks::resolve_container_gates(
        cfg.agent_defs
            .agents
            .iter()
            .map(|(name, def)| (name.as_str(), def.hooks.as_slice())),
        &cfg.agent_defs.all_agent_hooks,
        &cfg.hooks,
        &hook_env,
        app_config_version,
    );

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

    // The probe schedule is live state, not config-derived: it carries each lane's next-probe deadline
    // and the prober generation. `App::clone` shares it (Arc), so an in-place mutation swap keeps the
    // phase; a REBUILD must do the same, or a mutation cadence faster than the probe interval —
    // /config/settings meters at 10/min, the default interval is 30s — replaces every generation before
    // its first tick and probing goes dark while still logging that it is enabled. Carried ONLY when the
    // lane set is identical, because deadlines are indexed by lane: a changed lane set makes the old
    // indices mean something else, and a genuine lane change SHOULD re-establish probing.
    //
    // zip ≡ set-equality HERE, not in general: `cfg.models` is a `HashMap<String, ModelCfg>`, so model
    // names are UNIQUE keys, and both lane vectors are built by sorting those keys before reaching this
    // point. Two vectors built from the same unique-key set via the same deterministic sort are
    // identical element-for-element, so an elementwise compare and a set compare accept exactly the
    // same configs. Do NOT reuse this shortcut for a lane source that is not sorted-from-a-unique-key-
    // set: there the zip would start accepting a shifted-index pairing.
    let probe_schedule = match prior {
        Some(p)
            if p.lanes.len() == lanes.len()
                && p.lanes
                    .iter()
                    .zip(lanes.iter())
                    .all(|(a, b)| a.model == b.model && a.provider == b.provider) =>
        {
            p.probe_schedule.clone()
        }
        _ => Arc::new(crate::health::ProbeSchedule::new(lanes.len())),
    };

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

    // THE A2A PLANE, lowered ONCE and read twice below: as the registry the re-verification job
    // sweeps, and as the source of the dispatch table's A2A admission facts. Lowering it twice would
    // let the mounted surface and the registry behind it come from two different readings of one
    // config generation.
    let a2a_plane =
        crate::a2a::plane::A2aPlane::from_config(&cfg.agent_defs, cfg.public_url.as_deref());

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
                    tracing::warn!(
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
            let protected_resources: Vec<String> = cfg
                .mcp
                .as_ref()
                .map(|r| r.canonical_uri().to_string())
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
        // The all-pools `upstream_credentials:` default (1.5.3 — moved off `auth:`).
        upstream_credentials: cfg.upstream_credentials,
        // Telemetry-bank slot table for this generation, registered BEFORE the config-derived
        // collections move into the snapshot. Identical label sets across applies re-intern to the
        // same slots, so hot-path counters accumulate monotonically across config generations.
        tslots: Arc::new(telemetry::AppSlots::build(
            &lanes,
            &pools,
            &by_model,
            crate::plane::Plane::Llm,
        )),
        probe_schedule,
        lanes,
        store,
        // The non-LLM planes' breaker cells: PROCESS-LIFETIME, reused across an apply/reload the
        // way the HTTP client pool and governance state are — a config swap must not un-trip a
        // dead tool server or agent. Boot starts fresh (reliability is never persisted; the
        // store-or-RAM rule).
        plane_breakers: prior.map_or_else(
            || Arc::new(crate::store::PlaneBreakers::new()),
            |p| Arc::clone(&p.plane_breakers),
        ),
        // The failover pools, resolved-verbatim per generation (the CELLS above are process-
        // lifetime; the pool DECLARATIONS are config like any other).
        tool_pools: cfg.tool_pools.clone(),
        agent_pools: cfg.agent_pools.clone(),
        by_model,
        pools,
        client: upstream_client.clone(),
        auth: auth_mw.clone(),
        rewrite_hooks,
        tap_hooks,
        tap_hooks_candidate,
        tap_hooks_routing,
        tap_hooks_response,
        global_gates,
        mcp_server_gates,
        a2a_agent_gates,
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
        agent_defs: cfg.agent_defs.clone(),
        // THE A2A PLANE, built only when `agents:` defines one. A deployment that fronts no agents
        // gets `None` here and nothing downstream: no registry, no re-verification job. Built from
        // THIS generation's config on every apply, deliberately — a registration an operator
        // removed must stop being re-verified, and one whose pin they changed must be judged
        // against the pin they now declare.
        a2a: a2a_plane.clone(),
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
        planes: Arc::new({
            let mut dispatch = crate::plane::PlaneDispatch::default();
            if let Some(r) = cfg.mcp.as_ref() {
                dispatch = dispatch
                    .mount(
                        crate::plane::Plane::Mcp,
                        r.mount_path(),
                        crate::plane::WIRE_JSONRPC,
                    )
                    .admit(crate::plane::Plane::Mcp, r.admission());
            }
            if let Some(admission) = a2a_plane.as_ref().and_then(|p| p.admission()) {
                dispatch = dispatch
                    .mount(
                        crate::plane::Plane::A2a,
                        crate::a2a::serve::MOUNT_PATH,
                        crate::plane::WIRE_JSONRPC,
                    )
                    // THE SECOND BINDING'S PATH, claimed by the same act and for the same reason.
                    // gRPC is served at the path the vendored `a2a.proto` dictates rather than under
                    // the plane's mount, and a claimed path is where `admission_for` finds the RFC
                    // 8707 audience — so leaving it out would not merely mislabel the leg, it would
                    // admit a token minted for some other resource on it.
                    .mount(
                        crate::plane::Plane::A2a,
                        crate::a2a::serve::GRPC_MOUNT_PATH,
                        crate::plane::WIRE_GRPC,
                    )
                    .admit(crate::plane::Plane::A2a, admission);
            }
            dispatch
        }),
        mcp: cfg.mcp.clone().map(Arc::new),
        oauth_as: oauth_as_plane.clone(),
        // THE CATALOGUE SNAPSHOT, built here and only here. It takes the next PIN GENERATION on
        // construction, so every config apply — including one that changes nothing about `tools:` —
        // moves the generation and a call admitted under the previous one is refused at dispatch —
        // an in-flight call cannot outlive the approval it was admitted under, which is the whole
        // point of taking the generation here rather than reading config at dispatch time.
        // Building it beside the `App` is what makes the swap atomic: the
        // whole `Arc<App>` is replaced under one lock, so there is no window in which the catalogue
        // and the config that produced it disagree.
        mcp_catalogue: Arc::new(crate::mcp::catalogue::Catalogue::build(&cfg.tool_defs)),
        mcp_servers: Arc::new(cfg.tool_defs.clone()),
        mcp_pool: Arc::new(crate::mcp::client::pool::McpConnectionPool::new()),
        // CARRIED ACROSS THE APPLY. A sighting is what accumulated, not what the operator intended,
        // so a config apply must not erase it: dropping the observations here would clear a
        // quarantine as a side effect of an unrelated edit.
        mcp_sightings: prior.map_or_else(
            || Arc::new(crate::mcp::client::catalogue::CatalogueCache::new()),
            |p| p.mcp_sightings.clone(),
        ),
        // CARRIED ACROSS THE APPLY for the same reason, and it is the same class of mistake: an
        // approval already spent is evidence, not intent, and a config apply that forgot it would
        // hand every outstanding confirmation back to whoever still holds it.
        plane_approvals: prior.map_or_else(
            || Arc::new(crate::plane::approvals::PlaneApprovals::new()),
            |p| p.plane_approvals.clone(),
        ),
        // CARRIED ACROSS THE APPLY, same class again: an epoch bump is a caller's own announcement
        // that its roots changed, and an apply that reset it would re-validate roots answers the
        // caller disavowed — inside the very TTL window the seal exists to police.
        mcp_roots_epochs: prior.map_or_else(
            || Arc::new(crate::mcp::roots::RootsEpochs::new()),
            |p| p.mcp_roots_epochs.clone(),
        ),
        // CARRIED ACROSS THE APPLY, same class: spend that already happened is evidence, not
        // intent, and an apply that rebuilt this would hand every registered upstream a fresh
        // sampling budget the moment an operator touched an unrelated section of config.
        mcp_sampling_spend: prior.map_or_else(
            || Arc::new(crate::mcp::sampling::SamplingSpend::new()),
            |p| p.mcp_sampling_spend.clone(),
        ),
        // CARRIED ACROSS THE APPLY, and here the reason is sharper than for the two above: the
        // durable sink is attached to this instance once at boot, so rebuilding it on an apply would
        // silently detach it and every later quarantine would stop being written down.
        mcp_demotions: prior.map_or_else(
            || Arc::new(crate::plane::quarantine::PlaneQuarantine::new()),
            |p| p.mcp_demotions.clone(),
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
        failover_cfg,
        pool_runtime,
        fallback_pools,
        on_exhausted_cfgs,
        queued_depth: std::sync::Arc::new(crate::state::QueuedDepth::default()),
        governance,
        secret_resolver,
        cost,
        plugins_dir: std::path::PathBuf::from(&plugins_cfg.dir),
        plugins_cfg,
        default_max_tokens: cfg.limits.default_max_tokens,
        reasoning_effort_budgets: {
            let b = cfg.limits.reasoning_effort_budgets;
            [b.minimal, b.low, b.medium, b.high]
        },
        // Where `auth.key_ttl` is finally READ: the self-serve mint's token lifetime.
        // Config-validate already proved this parses; the fallback keeps a bad value from panicking.
        self_key_ttl_secs: cfg
            .auth
            .as_ref()
            .and_then(|a| a.key_ttl.as_deref())
            .map(|s| admin::parse_duration_secs(s).unwrap_or(admin::DEFAULT_KEY_TTL_SECS))
            .unwrap_or(admin::DEFAULT_KEY_TTL_SECS),
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
    // The build reached its end without a single fallible step refusing: KEEP the limits installed
    // at the top. Every earlier `return Err` / `?` drops the guard instead and rolls them back.
    limits_guard.commit();
    Ok((app, rotate_gov_credentials))
}
