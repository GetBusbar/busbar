use std::collections::HashMap;
use std::future::Future as _;
use std::sync::Arc;

use crate::auth::{open_operator, AuthMiddleware};
use crate::diagnostics::{
    diag_error, diag_warn, DURABLE_KEYS_INERT, GOVERNANCE_STORE_EPHEMERAL, OPEN_RELAY_NO_AUTH,
    PLUGINS_FETCH_RELOAD_MISS, PROVIDER_API_KEY_UNRESOLVABLE, SAFE_MODE_OVERLAY_QUARANTINED,
    STATEFUL_PLANE_EPHEMERAL_STORE, STORE_SECRET_REF_UNRESOLVED,
};
use crate::preflight::{
    build_secret_resolver, resolve_admin_token, resolve_at_rest_keys, resolve_signing_key,
};
use crate::router::project_auth_scope_caps;
use crate::state::App;
use crate::store::{HealthState, LaneData};
#[allow(unused_imports)]
use crate::{
    admin, audit, auth, catalogue, config, config_validate, core_routes, cost, durable, endpoints,
    export, governance, hooks, ingress, ir, json, oauth_as, observability, operation,
    plugin_routes, profile, ratelimit, snapshot, state, store, telemetry, trust,
};
use busbar_kernel::plane_driver::route_input::{
    LaneInput, OnExhaustedInput, PoolInput, PoolMemberInput,
};

pub const ENV_CONFIG: &str = "BUSBAR_CONFIG";

pub const ENV_PROVIDERS: &str = "BUSBAR_PROVIDERS";

pub const ENV_UPSTREAM_H2_PRIOR_KNOWLEDGE: &str = "BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE";

pub const ENV_UPSTREAM_HTTP1_ONLY: &str = "BUSBAR_UPSTREAM_HTTP1_ONLY";

pub fn upstream_bool_env_override(env: Option<std::ffi::OsString>, config_val: bool) -> bool {
    match env {
        Some(v) => v != "0" && !v.is_empty(),
        None => config_val,
    }
}

pub const DEFAULT_CONFIG_PATH: &str = "/etc/busbar/config.yaml";

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

pub fn stateful_plane_ephemeral_store_warn(
    store_is_memory: bool,
    stateful: bool,
) -> Option<&'static str> {
    if store_is_memory && stateful {
        Some(
            "Stateful plane task state will NOT survive a restart — in-flight tasks will break on the next \
             request. Configure a durable store plugin.",
        )
    } else {
        None
    }
}

fn on_exhausted_input_of(o: &config::OnExhausted) -> OnExhaustedInput {
    match o {
        config::OnExhausted::Status503 => OnExhaustedInput::Status503,
        config::OnExhausted::FallbackPool(name) => OnExhaustedInput::FallbackPool(name.clone()),
        config::OnExhausted::LeastBad => OnExhaustedInput::LeastBad,
        config::OnExhausted::Queue { max_ms } => OnExhaustedInput::Queue { max_ms: *max_ms },
    }
}

pub fn resolve_model_context_max(
    pools: &HashMap<String, config::PoolCfg>,
) -> Result<HashMap<String, Option<usize>>, String> {
    let mut resolved: HashMap<String, Option<usize>> = HashMap::new();
    for pool in pools.values() {
        for m in &pool.members {
            match resolved.get(&m.model) {
                None => {
                    resolved.insert(m.model.clone(), m.context_max);
                }
                Some(None) => {
                    resolved.insert(m.model.clone(), m.context_max);
                }
                Some(Some(existing)) => match m.context_max {
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

const SESSION_STORE_CAPACITY: usize = 65_536;

const SESSION_STORE_TTL_MS: u64 = 60 * 60 * 1_000;

pub struct LoadedConfig {
    pub deploy: config::DeployCfg,
    pub defs: HashMap<String, config::ProviderDef>,

    pub providers_path: std::path::PathBuf,

    pub overlay_path: Option<Arc<config::overlay::OverlayStore>>,

    pub config_locked: bool,

    pub config_read_only: bool,

    pub overlay_doc: Option<config::overlay::OverlayDoc>,

    pub unset_env_vars: Vec<String>,
}

#[cold]
#[inline(never)]
pub fn load_config_from_disk(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    safe_mode: bool,
    env_mode: config::EnvSubst,
) -> Result<LoadedConfig, String> {
    load_config_from_disk_judged(
        config_path,
        providers_override,
        safe_mode,
        env_mode,
        &AcceptAll,
    )
}

#[cold]
#[inline(never)]
pub fn load_config_from_disk_judged(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    safe_mode: bool,
    env_mode: config::EnvSubst,
    rules: &dyn RootRules,
) -> Result<LoadedConfig, String> {
    load_config_from_disk_with_document_patch(
        config_path,
        providers_override,
        safe_mode,
        env_mode,
        rules,
        None,
    )
}

/// Compose the durable document layer before the same parser boot uses. The Store anchor is
/// selected from the base configuration before calling this for a persisted patch.
pub fn load_config_from_disk_with_document_patch(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    safe_mode: bool,
    env_mode: config::EnvSubst,
    rules: &dyn RootRules,
    patch: Option<&config::document_patch::DocumentPatch>,
) -> Result<LoadedConfig, String> {
    load_config_from_disk_with_document_patches(
        config_path,
        providers_override,
        safe_mode,
        env_mode,
        rules,
        patch,
        None,
    )
}

/// Compose both operator documents with their durable edits before the shared boot readers.
pub fn load_config_from_disk_with_document_patches(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    safe_mode: bool,
    env_mode: config::EnvSubst,
    rules: &dyn RootRules,
    patch: Option<&config::document_patch::DocumentPatch>,
    providers_patch: Option<&config::document_patch::DocumentPatch>,
) -> Result<LoadedConfig, String> {
    let mut patch = patch.cloned();
    let mut providers_patch = providers_patch.cloned();
    load_config_from_disk_compacting_document_patches(
        config_path,
        providers_override,
        safe_mode,
        env_mode,
        rules,
        DocumentPatchLoad {
            patch: patch.as_mut(),
            providers_patch: providers_patch.as_mut(),
            admission: None,
        },
    )
}

pub struct DocumentPatchLoad<'a> {
    pub patch: Option<&'a mut config::document_patch::DocumentPatch>,
    pub providers_patch: Option<&'a mut config::document_patch::DocumentPatch>,
    pub admission: Option<&'a mut config::document_patch::SourceAdmission>,
}

/// Reuse the exact file/env preprocessing while returning a compacted guarded Store carrier.
/// The admin caller persists these edits only after typed parsing and runtime validation succeed.
pub fn load_config_from_disk_compacting_document_patches(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    safe_mode: bool,
    env_mode: config::EnvSubst,
    rules: &dyn RootRules,
    edits: DocumentPatchLoad<'_>,
) -> Result<LoadedConfig, String> {
    let DocumentPatchLoad {
        patch,
        providers_patch,
        mut admission,
    } = edits;
    let mut unset_env_vars: Vec<String> = Vec::new();

    let raw_config = std::fs::read_to_string(config_path).map_err(|e| {
        format!(
            "cannot read config file '{}': {e} (set {ENV_CONFIG})",
            config_path.display()
        )
    })?;
    let normalized_config =
        rules.normalize_document(ConfigDocument::Deployment, config_path, &raw_config)?;
    let interpolated_config = config::interpolate_env_with(
        normalized_config
            .as_deref()
            .map_or(raw_config.as_str(), String::as_str),
        env_mode,
        &mut unset_env_vars,
    )
    .map_err(|e| format!("config.yaml: {e}"))?;

    if let Some(admission) = admission.as_deref_mut() {
        admission.check_config(&interpolated_config)?;
    }

    if let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&interpolated_config) {
        let markers = config::current_format::detect_legacy_markers(&doc);
        if !markers.is_empty() {
            return Err(format!(
                "config.yaml: {}",
                config::current_format::legacy_config_error(&markers)
            ));
        }

        let keys: Vec<&str> = doc
            .as_mapping()
            .into_iter()
            .flat_map(|m| m.keys())
            .filter_map(serde_yaml::Value::as_str)
            .collect();
        if let Some(refusal) = rules.unloaded_plane_refusal(&keys) {
            return Err(format!("config.yaml: {refusal}"));
        }
    }

    let mut deploy: config::DeployCfg = if let Some(patch) = patch.filter(|_| !safe_mode) {
        *patch = patch.compacted_against_yaml(&interpolated_config)?;
        patch.parse_deploy_yaml_checked(&interpolated_config, |keys| {
            rules.unloaded_plane_refusal(keys).map_or(Ok(()), Err)
        })?
    } else {
        config::deploy_from_yaml_str(&interpolated_config).map_err(|e| {
            format!(
                "config.yaml: invalid YAML: {}",
                config::augment_config_error(e)
            )
        })?
    };

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
            "cannot read providers file '{}': {e} (set `providers_file:` in config.yaml, or --providers)",
            providers_path.display()
        )
    })?;
    let normalized_providers =
        rules.normalize_document(ConfigDocument::Providers, &providers_path, &raw_providers)?;
    let interpolated_providers = config::interpolate_env_with(
        normalized_providers
            .as_deref()
            .map_or(raw_providers.as_str(), String::as_str),
        env_mode,
        &mut unset_env_vars,
    )
    .map_err(|e| format!("providers.yaml: {e}"))?;
    if let Some(admission) = admission {
        admission.check_catalog(&interpolated_providers)?;
    }
    deploy.document_source_fingerprints =
        Some(config::document_patch::SourceFingerprints::from_sources(
            &interpolated_config,
            &interpolated_providers,
        ));
    let defs: HashMap<String, config::ProviderDef> =
        if let Some(patch) = providers_patch.filter(|_| !safe_mode) {
            *patch = patch.compacted_against_yaml(&interpolated_providers)?;
            patch.parse_catalog_yaml(&interpolated_providers)?
        } else {
            config::providers::catalog_from_str(&interpolated_providers)
                .map_err(|e| format!("providers.yaml: invalid YAML: {e}"))?
        };

    let resolution = config::overlay::resolve_backend(&deploy.config);
    let overlay_path = None;
    let config_locked = resolution.locked;
    let config_read_only = false;

    if safe_mode {
        diag_warn!(
            SAFE_MODE_OVERLAY_QUARANTINED,
            "SAFE MODE: config overlay NOT merged — running on base config.yaml alone (the \
             Store overlay is untouched; boot without --safe-mode to re-apply it)"
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

    let overlay_doc = None;
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

pub async fn load_config_from_disk_with_store(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    safe_mode: bool,
    env_mode: config::EnvSubst,
    rules: &dyn RootRules,
    overlay: Option<Arc<config::overlay::OverlayStore>>,
) -> Result<LoadedConfig, String> {
    let mut loaded =
        load_config_from_disk_judged(config_path, providers_override, safe_mode, env_mode, rules)?;
    if !loaded.config_locked {
        let store = overlay.ok_or_else(|| {
            "running config has no Store overlay anchor; restart to bootstrap it".to_string()
        })?;
        if safe_mode {
            loaded.overlay_path = Some(store);
        } else {
            let (reopened, doc) = store.reopen_for_reload_async().await?;
            let mut patched_locked = false;
            if let Some(doc) = doc
                .as_ref()
                .filter(|doc| doc.document_patch.is_some() || doc.providers_patch.is_some())
            {
                loaded = load_config_from_disk_with_document_patches(
                    config_path,
                    providers_override,
                    false,
                    env_mode,
                    rules,
                    doc.document_patch.as_ref(),
                    doc.providers_patch.as_ref(),
                )?;
                patched_locked = loaded.config_locked;
            }
            loaded.overlay_path = (!patched_locked).then_some(reopened);
            loaded.overlay_doc = doc;
        }
    }
    Ok(loaded)
}

pub type GovCredentialRotation = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

async fn rewrap_at_rest(gs: &governance::GovState) {
    let pass = gs
        .rewrap_credentials_async(busbar_kernel::store::now())
        .await;
    if pass.is_err() {
        // Reconcile a lost native rewrap reply before the candidate's readiness
        // barrier. Refresh retries only identity-owned original attempts, then
        // reloads confirmed canonical rows; it never generates another envelope.
        if let Err(error) = gs.refresh_async().await {
            diag_warn!(
                crate::diagnostics::CREDENTIAL_AT_REST_REWRAP_PENDING,
                error = %error,
                "canonical identity refresh remains deferred after credential re-wrap"
            );
        }
    }
    match pass {
        Ok(pass) if pass.pending > 0 => diag_warn!(
            crate::diagnostics::CREDENTIAL_AT_REST_REWRAP_PENDING,
            resealed = pass.resealed,
            pending = pass.pending,
            "{} recoverable credential(s) are still sealed under credentials.at_rest.previous (or \
             stored in the clear): another node holds their re-wrap, or the store keeps no claims. \
             They still authenticate; keep credentials.at_rest.previous configured until a boot \
             or reload re-seals them all",
            pass.pending
        ),
        Ok(pass) if pass.resealed > 0 => tracing::info!(
            resealed = pass.resealed,
            "recoverable credentials re-sealed under credentials.at_rest.key"
        ),
        Ok(_) => {}
        Err(e) => diag_warn!(
            crate::diagnostics::CREDENTIAL_AT_REST_REWRAP_PENDING,
            error = %e,
            "the credential re-wrap pass did not complete; canonical identity reconciliation \
             was attempted before readiness, and remaining work is retried at the next boot or reload"
        ),
    }
}

#[must_use = "an unkept InstalledLimits never publishes the generation's limits"]
pub struct InstalledLimits {
    limits: config::LimitsResolved,
    rates: ResolvedRates,

    configured_card: config::card::CardFields,

    destinations: config::Destinations,

    rules: std::sync::Arc<dyn RootRules>,
}

impl ResolvedRates {
    fn raw(&self) -> crate::rate_apply::RawRates<'_> {
        crate::rate_apply::RawRates {
            lanes: &self.lanes,
            units: &self.units,
            flat_minor: self.flat_minor,
            present: self.present,
            plane_fees: &self.plane_fees,
        }
    }
}

struct ResolvedRates {
    lanes: Vec<(String, busbar_contract::billing::RawTierRates)>,
    units: Vec<(String, String, u64)>,
    flat_minor: i64,
    present: bool,
    plane_fees: config::PlaneFeesMap,
}

impl InstalledLimits {
    pub fn stage_boot(&self) {
        crate::rate_apply::card_applied(&self.configured_card);
    }

    pub async fn prepare_rates(self) -> Result<PreparedLimits, String> {
        let rates = crate::rate_apply::prepare(&self.configured_card, &self.rates.raw()).await?;
        Ok(PreparedLimits {
            installed: self,
            rates,
        })
    }

    pub async fn prepare_rates_for_reload(self) -> Result<PreparedLimits, String> {
        let rates =
            crate::rate_apply::prepare_recovery(&self.configured_card, &self.rates.raw()).await?;
        Ok(PreparedLimits {
            installed: self,
            rates,
        })
    }

    pub async fn prepare_rates_with_origin(self, origin: &str) -> Result<PreparedLimits, String> {
        let rates = crate::rate_apply::prepare_with_origin(
            &self.configured_card,
            &self.rates.raw(),
            origin,
        )
        .await?;
        Ok(PreparedLimits {
            installed: self,
            rates,
        })
    }

    pub async fn prepare_rates_for_reload_with_origin(
        self,
        origin: &str,
    ) -> Result<PreparedLimits, String> {
        let rates = crate::rate_apply::prepare_recovery_with_origin(
            &self.configured_card,
            &self.rates.raw(),
            origin,
        )
        .await?;
        Ok(PreparedLimits {
            installed: self,
            rates,
        })
    }

    pub async fn keep(self) -> Result<(), String> {
        self.prepare_rates()
            .await?
            .confirm_activation()
            .await?
            .keep()
            .notify();
        Ok(())
    }
}

#[must_use = "a prepared generation must be committed to activate its rates and limits"]
pub struct PreparedLimits {
    installed: InstalledLimits,
    rates: Box<dyn crate::rate_apply::PreparedRates>,
}

impl PreparedLimits {
    pub async fn confirm_activation(self) -> Result<ConfirmedLimits, String> {
        let Self { installed, rates } = self;
        Ok(ConfirmedLimits {
            installed,
            rates: rates.confirm_activation().await?,
        })
    }
}

#[must_use = "confirmed rates must be published with their App generation"]
pub struct ConfirmedLimits {
    installed: InstalledLimits,
    rates: Box<dyn crate::rate_apply::RateCommit>,
}

impl ConfirmedLimits {
    pub fn keep(self) -> CommittedLimits {
        let Self {
            installed,
            rates: commit,
        } = self;
        let InstalledLimits {
            limits,
            rates: _,
            configured_card: _,
            destinations,
            rules,
        } = installed;
        commit.commit();
        busbar_kernel::config::limits::publish(&limits);
        CommittedLimits {
            destinations,
            rules,
        }
    }
}

pub struct CommittedLimits {
    destinations: config::Destinations,
    rules: std::sync::Arc<dyn RootRules>,
}

impl CommittedLimits {
    pub fn notify(self) {
        self.rules.destinations_applied(&self.destinations);
    }
}

pub type ConfigProjection = fn(&config::RootCfg) -> std::sync::Arc<dyn std::any::Any + Send + Sync>;

pub(crate) fn plane_is_open_for_build(
    fallback: bool,
    section: &str,
    written: &std::collections::BTreeSet<&'static str>,
    awaiting_restart: &[&str],
) -> bool {
    (fallback || written.contains(section)) && (fallback || !awaiting_restart.contains(&section))
}

/// An authored input document. Historical conversion belongs to the composition root's
/// migration library; the kernel continues to parse only its current format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigDocument {
    Deployment,
    Providers,
}

pub trait RootRules: Send + Sync {
    fn check(&self, cfg: &config::RootCfg) -> Result<(), String>;

    /// Normalize authored bytes before environment expansion. Returning `None` preserves
    /// the exact original document. Converted material remains in wiping custody and must
    /// preserve authored secret references; this hook never publishes a configuration.
    fn normalize_document(
        &self,
        _kind: ConfigDocument,
        _path: &std::path::Path,
        _raw: &str,
    ) -> Result<Option<zeroize::Zeroizing<String>>, String> {
        Ok(None)
    }

    fn check_built(&self, _app: &App) -> Result<(), String> {
        Ok(())
    }

    fn mounted_plugin_paths(&self, _app: &App) -> Option<std::collections::HashSet<String>> {
        None
    }

    fn planes_awaiting_restart(&self, _cfg: &config::RootCfg) -> Vec<&'static str> {
        Vec::new()
    }

    fn destinations_applied(&self, _destinations: &config::Destinations) {}

    /// Move host-owned, single-use admission custody before durable ticket redemption.
    fn claim_ticket_admission(
        &self,
        _identity: &crate::host_services::VerifiedTicketIdentity,
    ) -> crate::host_services::TicketClaimDisposition {
        crate::host_services::TicketClaimDisposition::Ordinary
    }

    fn unloaded_plane_refusal(&self, _keys: &[&str]) -> Option<String> {
        None
    }
}

/// The rules of a build with no composition root's rules to judge by (a tool, a test fixture): it
/// accepts every configuration.
#[derive(Debug, Default, Clone, Copy)]
pub struct AcceptAll;

impl RootRules for AcceptAll {
    fn check(&self, _cfg: &config::RootCfg) -> Result<(), String> {
        Ok(())
    }
}

pub async fn bootstrap_config_store(
    cfg: &config::RootCfg,
    plugins: &config::PluginsCfg,
) -> Result<busbar_contract::persistence::axis::OpenedBackend, String> {
    let (registry, resolver) = bootstrap_store_inputs(cfg, plugins).await?;
    open_config_store(cfg.store.as_ref(), &registry, &resolver).await
}

/// Inspect a configured Store before ordinary OPEN can initialize or select its dataset.
/// Historical transformation is supplied by the composition root, not this projection.
pub async fn prepare_config_store(
    cfg: &config::RootCfg,
    plugins: &config::PluginsCfg,
) -> Result<busbar_contract::persistence::lifecycle::axis::Prepared, String> {
    let (registry, resolver) = bootstrap_store_inputs(cfg, plugins).await?;
    let (door, label, settings) = config_store_inputs(cfg.store.as_ref(), &registry, &resolver)?;
    let axis = crate::preflight::root_rows()
        .store_axis
        .ok_or("no Store axis is installed")?;
    axis()
        .prepare(door, &label, settings.as_bytes())
        .await
        .map_err(|_| format!("Store '{label}' native preparation refused"))
}

async fn bootstrap_store_inputs(
    cfg: &config::RootCfg,
    plugins: &config::PluginsCfg,
) -> Result<
    (
        Arc<dyn busbar_contract::plugin_rows::PluginRows>,
        config::secret::SecretResolver,
    ),
    String,
> {
    // This is a Store-only bootstrap projection. Overlay definitions do not exist yet;
    // the composition root validates the complete effective configuration after recovery.
    config_validate::validate_bootstrap_security(cfg).map_err(|errors| errors.join("; "))?;
    if plugins.enabled && !plugins.fetch.is_empty() {
        fetch_config_plugins(plugins, cfg, true)?;
    }

    let registry = crate::preflight::plugins_preflight(
        cfg.store.as_ref(),
        None,
        &Default::default(),
        &HashMap::new(),
        plugins,
        &Default::default(),
    )?;
    let dependencies = bootstrap_dependency_names(cfg, registry.as_ref());
    validate_bootstrap_artifacts(registry.as_ref(), &dependencies, plugins)?;
    if let Some(admit) = crate::preflight::root_rows().secret_admit {
        admit(&registry, plugins).await?;
    }
    let bootstrap_secrets = cfg
        .secrets
        .iter()
        .filter(|(module, _)| {
            registry
                .resolve(module)
                .is_some_and(|row| row.kind == "secret" && dependencies.contains(&row.name))
        })
        .map(|(module, settings)| (module.clone(), settings.clone()))
        .collect();
    let resolver = build_secret_resolver(registry.clone(), &bootstrap_secrets)?;

    let _admin = resolve_admin_token(cfg.auth.as_ref(), &resolver)?;
    let _signer = resolve_signing_key(cfg.auth.as_ref(), &resolver)?;
    let _at_rest = resolve_at_rest_keys(&cfg.credentials, &resolver)?;
    Ok((registry, resolver))
}

pub fn bootstrap_dependency_names(
    cfg: &config::RootCfg,
    registry: &dyn busbar_contract::plugin_rows::PluginRows,
) -> std::collections::BTreeSet<String> {
    let fields: Vec<_> = cfg.store.as_ref().map_or_else(Vec::new, |store| {
        registry
            .secret_slots(&store.module)
            .into_iter()
            .chain(registry.reference_slots(&store.module))
            .collect()
    });
    bootstrap_dependency_names_from_metadata(cfg, &fields, |module| {
        registry
            .resolve(module)
            .map(|row| row.name)
            .or_else(|| registry.unresolved_reason(module).map(|row| row.name))
            .unwrap_or_else(|| module.to_string())
    })
}

pub fn bootstrap_dependency_names_from_metadata(
    cfg: &config::RootCfg,
    fields: &[String],
    mut canonical: impl FnMut(&str) -> String,
) -> std::collections::BTreeSet<String> {
    let mut modules = std::collections::BTreeSet::new();
    let mut add = |module: &str| {
        modules.insert(canonical(module));
    };
    if let Some(store) = &cfg.store {
        add(&store.module);
        if let Ok(references) = store
            .settings
            .reference_modules(fields, &config::secret::sugars())
        {
            for module in references {
                add(&module);
            }
        }
    }
    if let Some(auth) = &cfg.auth {
        if let Some(reference) = auth.admin_token_ref() {
            if let Some(module) = reference.source_module() {
                add(module);
            }
        }
        if let Some(reference) = &auth.signing_key {
            if let Some(module) = reference.source_module() {
                add(module);
            }
        }
    }
    if let Some(keys) = &cfg.credentials.at_rest {
        if let Some(module) = keys.key.source_module() {
            add(module);
        }
        if let Some(previous) = &keys.previous {
            if let Some(module) = previous.source_module() {
                add(module);
            }
        }
    }
    modules
}

pub fn validate_bootstrap_artifacts(
    registry: &dyn busbar_contract::plugin_rows::PluginRows,
    dependencies: &std::collections::BTreeSet<String>,
    plugins: &config::PluginsCfg,
) -> Result<(), String> {
    for name in dependencies {
        let Some(row) = registry.resolve(name) else {
            continue;
        };
        if row.linked {
            continue;
        }
        let actual = registry.archive_sha256(&row.name);
        validate_bootstrap_archive(&row.name, &row.file, actual.as_deref(), plugins)?;
    }
    Ok(())
}

pub fn validate_bootstrap_archive(
    name: &str,
    file: &str,
    actual: Option<&str>,
    plugins: &config::PluginsCfg,
) -> Result<(), String> {
    let targets = plugins.fetch_targets()?;
    let mut pin: Option<String> = None;
    for target in targets.into_iter().filter(|target| target.filename == file) {
        let Some(hash) = target.sha256 else { continue };
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "plugins.fetch archive pin for '{file}' must be exactly 64 hexadecimal SHA-256 digits"
            ));
        }
        let hash = hash.to_ascii_lowercase();
        if pin.as_ref().is_some_and(|previous| previous != &hash) {
            return Err(format!(
                "plugins.fetch has conflicting archive pins for '{file}'"
            ));
        }
        pin = Some(hash);
    }
    if pin.is_none() || actual != pin.as_deref() {
        return Err(format!(
            "native Store bootstrap dependency '{name}' ({file}) requires its exact archive SHA-256 in the operator's base plugins.fetch entry before it can load; the pin is missing or does not match the retained admitted archive. Install the intended signed artifact and update its base config.yaml fetch pin together; an unread Store-owned pin cannot authorize opening its own bootstrap dependency",
        ));
    }
    Ok(())
}

async fn open_config_store(
    store: Option<&config::StoreCfg>,
    registry: &Arc<dyn busbar_contract::plugin_rows::PluginRows>,
    resolver: &config::secret::SecretResolver,
) -> Result<busbar_contract::persistence::axis::OpenedBackend, String> {
    let (door, label, settings) = config_store_inputs(store, registry, resolver)?;
    let failed = |error: String| format!("store '{label}' plugin load failed: {error}");
    let axis = crate::preflight::root_rows()
        .store_axis
        .ok_or_else(|| failed("no store axis is installed".into()))?;
    axis()
        .open(door, &label, settings.as_bytes())
        .await
        .map_err(failed)
}

fn config_store_inputs(
    store: Option<&config::StoreCfg>,
    registry: &Arc<dyn busbar_contract::plugin_rows::PluginRows>,
    resolver: &config::secret::SecretResolver,
) -> Result<
    (
        busbar_contract::persistence::axis::StoreDoor,
        String,
        zeroize::Zeroizing<String>,
    ),
    String,
> {
    let store = store.ok_or_else(config::store_required)?;
    let row = registry.resolve(&store.module);
    let resolved = if row.as_ref().is_some_and(|row| row.in_process) {
        Default::default()
    } else {
        config::secret::resolve_settings(
            &store.settings,
            &registry.secret_slots(&store.module),
            &registry.reference_slots(&store.module),
            &store.module,
            resolver,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .map_err(|error| format!("store '{}' settings: {error}", store.module))?
    };
    let bytes = resolved.encode().map_err(|error| error.to_string())?;
    let settings = zeroize::Zeroizing::new(
        String::from_utf8(bytes.into_exposed(&crate::seal::lend()))
            .map_err(|_| "settings encoding was not UTF-8")?,
    );
    drop(resolved);
    let failed = |error: String| format!("store '{}' plugin load failed: {error}", store.module);
    let door = registry.store_door(&store.module).map_err(failed)?;
    Ok((door, store.module.clone(), settings))
}

fn fetch_config_plugins(
    plugins: &config::PluginsCfg,
    cfg: &config::RootCfg,
    boot: bool,
) -> Result<(), String> {
    let targets = plugins.fetch_targets()?;
    let dir = std::path::Path::new(&plugins.dir);
    crate::durable::create_dir_all(dir).map_err(|error| {
        format!(
            "plugins.fetch: cannot create plugins dir '{}': {error}",
            dir.display()
        )
    })?;
    let fetch = crate::preflight::root_rows()
        .plugins_fetch
        .ok_or("plugins.fetch failed: no composition root installed the plugins fetch")?;
    let outcomes = fetch(dir, &targets, boot, &cfg.blocked_metadata_hosts)
        .map_err(|errors| format!("plugins.fetch failed: {}", errors.join("; ")))?;
    for outcome in outcomes {
        match outcome {
            crate::preflight::Fetched::Cached { filename } => {
                tracing::info!(filename, "plugins.fetch: cached")
            }
            crate::preflight::Fetched::Fetched { filename } => {
                tracing::info!(filename, "plugins.fetch: downloaded + verified")
            }
            crate::preflight::Fetched::Warned { url, error } => diag_warn!(
                PLUGINS_FETCH_RELOAD_MISS,
                url,
                error,
                "plugins.fetch: miss on reload; keeping current artifact"
            ),
        }
    }
    Ok(())
}

#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub async fn build_app_from_config(
    cfg: config::RootCfg,
    plugins_cfg: config::PluginsCfg,
    overlay_path: Option<Arc<config::overlay::OverlayStore>>,
    base_hook_names: std::collections::HashSet<String>,
    base_group_names: std::collections::HashSet<String>,
    config_paths: (Option<std::path::PathBuf>, Option<std::path::PathBuf>),
    prior: Option<&state::App>,
    rules: &std::sync::Arc<dyn RootRules>,
) -> Result<(state::App, Option<GovCredentialRotation>, InstalledLimits), String> {
    build_app_from_config_with_store(
        cfg,
        plugins_cfg,
        overlay_path,
        base_hook_names,
        base_group_names,
        config_paths,
        prior,
        rules,
        None,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn build_app_from_config_with_store(
    cfg: config::RootCfg,
    plugins_cfg: config::PluginsCfg,
    overlay_path: Option<Arc<config::overlay::OverlayStore>>,
    base_hook_names: std::collections::HashSet<String>,
    base_group_names: std::collections::HashSet<String>,
    config_paths: (Option<std::path::PathBuf>, Option<std::path::PathBuf>),
    prior: Option<&state::App>,
    rules: &Arc<dyn RootRules>,
    boot_store: Option<Arc<crate::persistence::facade::CoreStore>>,
    recover_usage_before_hydration: bool,
) -> Result<(state::App, Option<GovCredentialRotation>, InstalledLimits), String> {
    let limits = cfg.limits.clone();
    let mut future = std::pin::pin!(build_app_native(
        cfg,
        plugins_cfg,
        overlay_path,
        base_hook_names,
        base_group_names,
        config_paths,
        prior,
        rules,
        boot_store,
        recover_usage_before_hydration
    ));
    std::future::poll_fn(move |context| {
        let _scope = config::limits::BuildScope::enter(&limits);
        future.as_mut().poll(context)
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn build_app_native(
    cfg: config::RootCfg,
    plugins_cfg: config::PluginsCfg,
    overlay_path: Option<Arc<config::overlay::OverlayStore>>,
    base_hook_names: std::collections::HashSet<String>,
    base_group_names: std::collections::HashSet<String>,
    config_paths: (Option<std::path::PathBuf>, Option<std::path::PathBuf>),
    prior: Option<&state::App>,
    rules: &Arc<dyn RootRules>,
    boot_store: Option<Arc<crate::persistence::facade::CoreStore>>,
    recover_usage_before_hydration: bool,
) -> Result<(state::App, Option<GovCredentialRotation>, InstalledLimits), String> {
    config::security_policy::check_candidate(prior, &cfg, &plugins_cfg)?;
    let configured_card = config::card::CardFields::of_root(&cfg);
    let configured_view = Arc::new(config::readback::ConfiguredView::from_root(
        &cfg,
        &plugins_cfg,
    ));

    let planes_awaiting_restart = rules.planes_awaiting_restart(&cfg);

    let config_projection = crate::preflight::root_rows()
        .config_projection
        .map(|project| project(&cfg));
    let destinations = cfg.destinations();

    let app_config_version = prior.map_or(0, |p| p.config_version.wrapping_add(1));

    let cfg_export = cfg.export.clone();
    let auth_cfg = cfg
        .auth
        .clone()
        .unwrap_or_else(config::AuthCfg::default_none);

    let fetch = || -> Result<(), String> {
        let targets = plugins_cfg.fetch_targets()?;
        let dir = std::path::Path::new(&plugins_cfg.dir).to_path_buf();

        if let Err(e) = crate::durable::create_dir_all(&dir) {
            return Err(format!(
                "plugins.fetch: cannot create plugins dir '{}': {e}",
                dir.display()
            ));
        }

        let fetch = crate::preflight::root_rows()
            .plugins_fetch
            .ok_or("plugins.fetch failed:\n  - no composition root installed the plugins fetch")?;
        let outcomes = fetch(&dir, &targets, prior.is_none(), &cfg.blocked_metadata_hosts)
            .map_err(|errs| format!("plugins.fetch failed:\n  - {}", errs.join("\n  - ")))?;
        for outcome in &outcomes {
            match outcome {
                crate::preflight::Fetched::Cached { filename } => {
                    tracing::info!(filename, "plugins.fetch: cached (pin match, no download)")
                }
                crate::preflight::Fetched::Fetched { filename } => {
                    tracing::info!(filename, "plugins.fetch: downloaded + verified")
                }
                crate::preflight::Fetched::Warned { url, error } => {
                    diag_warn!(
                        PLUGINS_FETCH_RELOAD_MISS,
                        url,
                        error,
                        "plugins.fetch: miss on reload; keeping current artifact"
                    )
                }
            }
        }
        Ok(())
    };

    let root_rules = |c: &config::RootCfg| rules.check(c);
    let wants_fetch = plugins_cfg.enabled && !plugins_cfg.fetch.is_empty();
    let plugin_registry = config_validate::check(
        &cfg,
        config_validate::Check {
            plugins: &plugins_cfg,
            unset_env_vars: &[],
            root: &root_rules,
            fetch: wants_fetch.then_some(&fetch as &dyn Fn() -> Result<(), String>),
            resolve_builtins: false,
        },
    )
    .map_err(|refused| match refused {
        config_validate::Refusal::Config(errors) => {
            format!("config validation failed:\n  - {}", errors.join("\n  - "))
        }
        config_validate::Refusal::Root(e)
        | config_validate::Refusal::Plugins(e)
        | config_validate::Refusal::Unresolved(e) => e,
    })?;

    if let Some(admit) = crate::preflight::root_rows().secret_admit {
        admit(&plugin_registry, &plugins_cfg).await?;
    }

    let transition_requirements =
        governance::principal_transition::requirements(&cfg, plugin_registry.as_ref())?;

    let secret_resolver = Arc::new(build_secret_resolver(
        plugin_registry.clone(),
        &cfg.secrets,
    )?);

    let mut lanes_data = Vec::new();

    let mut lane_provider_cfgs: Vec<&config::ResolvedProvider> = Vec::new();
    let mut by_model = HashMap::new();

    let mut resolved_providers: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    let cost = crate::cost::CostModel::resolve_parts(
        cfg.rate_card.as_ref(),
        cfg.per_request_fee,
        &cfg.groups,
    );
    let cost = Arc::new(cost.with_plane_fees(&cfg.plane_fees));

    let (mut lanes, mut units) = (Vec::new(), Vec::new());
    for (lane, e) in cfg.rate_card.iter().flatten() {
        lanes.push((lane.clone(), e.raw_tier_rates()));
        for (class, rate) in &e.units {
            units.push((lane.clone(), class.clone(), rate.nanos_per_unit()));
        }
    }
    let resolved_rates = ResolvedRates {
        lanes,
        units,
        flat_minor: cfg.per_request_fee,
        present: cfg.rate_card.is_some(),
        plane_fees: cfg.plane_fees.clone(),
    };
    let mut sorted_models: Vec<_> = cfg.models.into_iter().collect();
    sorted_models.sort_by(|a, b| a.0.cmp(&b.0));
    for (model, mc) in sorted_models {
        let Some(provider_cfg) = cfg.providers.get(&mc.provider) else {
            return Err(format!(
                "model '{model}' references unknown provider '{}'",
                mc.provider
            ));
        };

        if resolved_providers.insert(mc.provider.clone()) && !provider_cfg.api_key.is_none() {
            secret_resolver
                .resolve_string_at_config(
                    &provider_cfg.api_key,
                    &busbar_contract::config_time::ConfigScope::config_time(),
                )
                .map_err(|e| {
                    diag_error!(
                        PROVIDER_API_KEY_UNRESOLVABLE,
                        provider = %mc.provider,
                        reference = %provider_cfg.api_key.describe(),
                        "provider api_key did not resolve: {e}"
                    );
                    format!(
                        "provider '{}' api_key ({}) did not resolve: {e}. A provider \
                         credential that cannot resolve refuses boot; if this upstream takes \
                         NO credential (a local ollama / vLLM), declare it: `api_key: none`",
                        mc.provider,
                        provider_cfg.api_key.describe()
                    )
                })?;
        }
        let limited = mc.max_requests >= 0;

        let max_concurrent = mc
            .max_concurrent
            .unwrap_or(tokio::sync::Semaphore::MAX_PERMITS);
        by_model.insert(model.clone(), lanes_data.len());
        lane_provider_cfgs.push(provider_cfg);
        lanes_data.push(LaneData {
            member: model.clone(),
            route: mc.provider.clone(),
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
        });

        eprintln!(
            "  model {} via {} ({}) max {}{}",
            model,
            mc.provider,
            busbar_kernel_egress::trust::net::strip_userinfo(
                provider_cfg.base_url.trim_end_matches('/')
            ),
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

    resolve_model_context_max(&cfg.pools)?;

    let mut lane_inputs: Vec<LaneInput> = Vec::new();
    for (idx, ld) in lanes_data.iter().enumerate() {
        let provider_cfg = lane_provider_cfgs[idx];

        let providers = crate::plane_driver::dispatch::provider_dialects();
        if !providers.iter().any(|d| *d == provider_cfg.dialect()) {
            return Err(format!(
                "provider '{}' uses unknown protocol '{}' (supported: {})",
                ld.route,
                provider_cfg.dialect(),
                providers.join(", ")
            ));
        }

        let base_url = busbar_kernel_egress::trust::net::strip_userinfo(
            provider_cfg.base_url.trim_end_matches('/'),
        )
        .into_owned();
        lane_inputs.push(LaneInput {
            model: ld.member.clone(),
            provider: ld.route.clone(),
            base_url,
            max_concurrent: ld.max,
        });
    }

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
                lane_idx,
                weight: m.weight,
            });
        }
        if let Some(ref on_exc) = pool.on_exhausted {
            let mode = on_exc.to_runtime();
            tracing::info!(pool = %name, on_exhausted = ?mode, "pool exhaustion policy");
        }

        pool_inputs.push(PoolInput {
            name: name.clone(),
            members,
            on_exhausted: pool
                .on_exhausted
                .as_ref()
                .map(|o| on_exhausted_input_of(&o.to_runtime()))
                .unwrap_or_default(),
        });
    }

    eprintln!(
        "busbar: {} models, {} pools",
        lane_inputs.len(),
        pool_inputs.len()
    );
    for p in &pool_inputs {
        let agg: u128 = p
            .members
            .iter()
            .map(|m| lane_inputs[m.lane_idx].max_concurrent as u128)
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

    if let Some(banner) = open_relay_banner(auth_cfg.chain.is_empty(), cfg.auth.is_some()) {
        eprintln!("[error] {banner}");
        diag_error!(OPEN_RELAY_NO_AUTH, "{banner}");
    }

    let auth_mw = Arc::new(
        AuthMiddleware::new(&auth_cfg, &plugin_registry, &secret_resolver)
            .map_err(|e| format!("auth chain construction failed: {e}"))?,
    );

    let mut admin_modules =
        crate::auth::AdminAuthChain::build(&auth_cfg, &plugin_registry, &secret_resolver)
            .map_err(|e| format!("admin auth chain construction failed: {e}"))?;

    let login_methods = Arc::new(
        crate::auth::login::LoginMethods::build(&auth_cfg, &plugin_registry, &secret_resolver)
            .map_err(|e| format!("auth.methods (hosted login) construction failed: {e}"))?,
    );

    let store: Arc<dyn busbar_kernel::store::LaneRuntime> = match prior {
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

    let mut hook_env = hooks::HookEnv::new(plugin_registry.clone(), secret_resolver.clone())?;

    hook_env.preresolve_hook_secrets(&cfg.hooks)?;
    let hook_route_decls = hook_env.route_decls(&cfg.hooks)?;

    if let Some(store_cfg) = cfg.store.as_ref() {
        if let Err(e) = config::secret::resolve_settings(
            &store_cfg.settings,
            &plugin_registry.secret_slots(&store_cfg.module),
            &plugin_registry.reference_slots(&store_cfg.module),
            &store_cfg.module,
            secret_resolver.as_ref(),
            &busbar_contract::config_time::ConfigScope::config_time(),
        ) {
            diag_warn!(
                STORE_SECRET_REF_UNRESOLVED,
                store = %store_cfg.module,
                error = %e,
                "store settings hold a secret reference that does not resolve here; the store is \
                 restart-to-apply, so THIS WILL FAIL THE NEXT RESTART unless the secret exists then"
            );
        }
    }

    hook_env.preopen_gate_hooks(&cfg.hooks)?;

    let mut rotate_gov_credentials: Option<GovCredentialRotation> = None;

    let mut rotated_digest: Option<Option<String>> = None;
    let governance = if let Some(p) = prior {
        if let Some(gs) = p.governance.clone() {
            let transition_holds = governance::principal_transition::guard_native(
                gs.core_store_handle().map_err(|error| error.to_string())?,
                &governance::principal_transition::store_fingerprint(&cfg.store)?,
                &transition_requirements,
            )
            .await?;
            // This is deny-only state from a completed receipt, never an authority grant.
            gs.install_transition_self_holds(transition_holds);
            let auth = cfg.auth.as_ref();
            let declares_operator = auth.is_some_and(|a| {
                a.admin_auth
                    .iter()
                    .chain(a.chain.iter())
                    .any(|e| crate::config::names_operator(&e.module))
            });

            let admin_token: Option<Option<busbar_contract::redacted::Secret<String>>> =
                if declares_operator {
                    Some(
                        resolve_admin_token(auth, &secret_resolver)
                            .map_err(|e| format!("{e} (nothing was changed)"))?,
                    )
                } else {
                    None
                };
            let hash = |t: &busbar_contract::redacted::Secret<String>| {
                busbar_contract::redacted::sha256_hex(t.expose(&crate::seal::lend()).as_bytes())
            };
            rotated_digest = admin_token.as_ref().map(|t| t.as_ref().map(hash));
            let signer = match auth.and_then(|a| a.signing_key.as_ref()) {
                Some(_) => Some(resolve_signing_key(auth, &secret_resolver)?),
                None => None,
            };

            let at_rest = match cfg.credentials.at_rest {
                Some(_) => resolve_at_rest_keys(&cfg.credentials, &secret_resolver)?,
                None => None,
            };
            if admin_token.is_some() || signer.is_some() || at_rest.is_some() {
                rotate_gov_credentials = Some(Box::pin(async move {
                    if let Some(token) = admin_token {
                        gs.set_admin_token(
                            token
                                .as_ref()
                                .map(|r| r.expose(&crate::seal::lend()).as_str()),
                        );
                    }
                    if let Some(signer) = signer {
                        gs.set_signing_key(signer);
                    }
                    if let Some(keys) = at_rest {
                        gs.set_at_rest_keys(Some(keys));

                        rewrap_at_rest(&gs).await;
                    }
                }));
            }
        }
        p.governance.clone()
    } else {
        cfg.store.as_ref().ok_or_else(config::store_required)?;

        let stateful = cfg.plane_defs.values().any(|d| !d.def_names().is_empty())
            || cfg.plane_pools.values().any(|p| !p.is_empty());

        let core = boot_store.ok_or_else(|| {
            "normal app boot requires the admitted CoreStore from Startup".to_string()
        })?;
        let ephemeral =
            core.info().durability == busbar_contract::persistence::Durability::Ephemeral;
        if ephemeral {
            diag_warn!(
                GOVERNANCE_STORE_EPHEMERAL,
                "store: in-memory (ephemeral) - keys, groups' usage, and ledgers reset on \
                     restart; configure a durable store plugin for persistence"
            );

            if let Some(msg) = stateful_plane_ephemeral_store_warn(true, stateful) {
                diag_warn!(STATEFUL_PLANE_EPHEMERAL_STORE, "{msg}");
            }
        }
        let transition_holds = governance::principal_transition::guard_startup_native(
            core.clone(),
            &governance::principal_transition::store_fingerprint(&cfg.store)?,
            &transition_requirements,
        )
        .await?;

        let admin_token: Option<busbar_contract::redacted::Secret<String>> =
            resolve_admin_token(cfg.auth.as_ref(), &secret_resolver)?;

        let signer = resolve_signing_key(cfg.auth.as_ref(), &secret_resolver)?;

        let at_rest = resolve_at_rest_keys(&cfg.credentials, &secret_resolver)?;
        match governance::GovState::new_with_core(
            core,
            admin_token
                .as_ref()
                .map(|r| r.expose(&crate::seal::lend()).clone()),
            signer,
        )
        .await
        {
            Ok(gs) => {
                gs.install_transition_self_holds(transition_holds);
                let gs = Arc::new(gs);

                if gs.set_at_rest_keys(at_rest) {
                    rewrap_at_rest(&gs).await;
                }

                if !recover_usage_before_hydration {
                    if let Err(e) = gs
                        .hydrate_budgets_async(&cost, busbar_kernel::store::now())
                        .await
                    {
                        return Err(format!(
                            "governance boot: budget hydration failed ({e}); refusing to start with an \
                             unenforced (reset) ledger. Fix the durable store and restart."
                        ));
                    }
                }

                let keys = gs.all_keys_async().await.map_err(|e| {
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

                let key_count = gs.all_keys_async().await.map(|k| k.len()).unwrap_or(0);
                if let Some(banner) =
                    inert_durable_keys_banner(!ephemeral, key_count, auth_mw.keys_in_chain)
                {
                    eprintln!("[error] {banner}");
                    diag_error!(DURABLE_KEYS_INERT, "{banner}");
                }
                Some(gs)
            }
            Err(e) => return Err(format!("governance init failed: {e}")),
        }
    };

    let digest = rotated_digest.unwrap_or_else(|| governance.as_ref()?.admin_token_hash());
    admin_modules.operator = open_operator(&plugin_registry, digest, &cfg.identity_providers)
        .map_err(|e| format!("admin auth chain construction failed: {e}"))?;
    let admin_modules = Arc::new(admin_modules);

    let rewrite_hooks =
        hooks::resolve_rewrite_hooks(&cfg.hooks, &cfg.global_hooks, &hook_env, app_config_version);

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

    let global_gates =
        hooks::resolve_gate_hooks(&cfg.hooks, &cfg.global_hooks, &hook_env, app_config_version);

    let default_hook = hooks::default_hook_name(&cfg.hooks).map(str::to_string);
    let mut pool_orderings = std::collections::HashMap::new();
    let mut pool_decision_gates = std::collections::HashMap::new();
    let mut pool_rewrite_chains = std::collections::HashMap::new();
    for (pool_name, pool_cfg) in &cfg.pools {
        if let Some(policy) = hooks::try_resolve_pool_ordering(
            pool_cfg,
            &cfg.hooks,
            &hook_env,
            default_hook.as_deref(),
            app_config_version,
        )
        .map_err(|e| format!("pool '{pool_name}': {e}"))?
        {
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

    let mut plane_gates = std::collections::BTreeMap::new();
    let mut plane_rewrites = std::collections::BTreeMap::new();
    for (section, defs) in &cfg.plane_defs {
        let Some(decl) = crate::plane_driver::registry::plane_decl_for_config_section(section)
        else {
            continue;
        };
        let g = defs.container_gates();
        let containers = || {
            g.containers
                .iter()
                .map(|(name, hooks)| (name.as_str(), hooks.as_slice()))
        };
        plane_gates.insert(
            decl.key,
            hooks::resolve_container_gates(
                containers(),
                &g.section_hooks,
                &cfg.hooks,
                &hook_env,
                app_config_version,
            ),
        );
        plane_rewrites.insert(
            decl.key,
            hooks::resolve_container_rewrites(
                containers(),
                &g.section_hooks,
                &cfg.hooks,
                &hook_env,
                app_config_version,
            ),
        );
    }

    let (mut route_decls, withheld_public_exports) = crate::export::route_projection(&cfg_export);
    route_decls.extend(hook_route_decls);
    let plugin_routes = std::sync::Arc::new(
        crate::plugin_routes::build_route_table(route_decls)?
            .with_withheld_public_exports(withheld_public_exports),
    );

    let boot_route_paths = prior.map_or_else(
        || std::sync::Arc::new(plugin_routes.paths()),
        |p| p.boot_route_paths.clone(),
    );

    let plane_slots: std::collections::BTreeMap<
        &'static str,
        Arc<dyn std::any::Any + Send + Sync>,
    > = {
        crate::plane_driver::registry::plane_decls()
            .iter()
            .filter(|decl| {
                plane_is_open_for_build(
                    decl.fallback,
                    decl.config_section,
                    &cfg.plane_sections,
                    &planes_awaiting_restart,
                )
            })
            .filter_map(|decl| {
                let ctx = crate::plane_driver::registry::BuildCtx {
                    endpoint_slot: cfg.endpoint_resources.get(decl.config_section).cloned(),

                    plane_defs: &cfg.plane_defs,
                    public_url: cfg.public_url.as_deref(),

                    prior: prior.map(|p| p as &dyn busbar_kernel::plane_driver::slots::PlaneSlots),

                    providers: Some(&cfg.providers),
                };
                (decl.build)(decl, &ctx).map(|obj| (decl.key, obj))
            })
            .collect()
    };

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
        crate::plane_driver::dispatch::fallback_key(),
    ));

    let config_tables = Arc::new(busbar_kernel::plane_driver::route_tables::ConfigTables::of(
        &lane_inputs,
        &pool_inputs,
        &by_model,
        cfg.upstream_credentials,
    ));

    let fallback = crate::plane_driver::dispatch::fallback_decl();
    let fallback_runtime_key = crate::state::runtime_slot_key(fallback.map_or("", |d| d.key));

    let oauth_as_plane = match cfg.oauth_as.as_ref() {
        None => None,
        Some(checked) => {
            let seam = crate::oauth_as::seam::seam().ok_or_else(|| {
                "oauth_as: configured, but the authorization-server plane (busbar-core-oauth2) is not \
                 linked into this binary"
                    .to_string()
            })?;
            let secrets = checked
                .secret_refs
                .iter()
                .map(|(path, reference)| {
                    secret_resolver
                        .resolve_string_at_config(
                            reference,
                            &busbar_contract::config_time::ConfigScope::config_time(),
                        )
                        .map(|value| (path.clone(), value.expose(&crate::seal::lend()).clone()))
                        .map_err(|e| format!("{path}: {e}"))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let protected_resources: Vec<String> = cfg
                .endpoint_resources
                .get(crate::config::plane_sections::EndpointSection::OWNER)
                .and_then(|slot| {
                    crate::plane_driver::registry::plane_decl_for_config_section(
                        crate::config::plane_sections::EndpointSection::OWNER,
                    )
                    .and_then(|d| (d.admission)(slot.as_ref()))
                })
                .map(|adm| adm.audience)
                .into_iter()
                .collect();

            let store = governance
                .as_ref()
                .map(|gs| gs.core_store_handle())
                .transpose()
                .map_err(|error| format!("oauth_as store: {error}"))?;
            Some(
                (seam.build)(
                    checked.block.clone(),
                    secrets,
                    protected_resources,
                    prior.and_then(state::App::oauth_as_any).cloned(),
                    store,
                )
                .await?,
            )
        }
    };

    let limits_resolved = cfg.limits.clone();

    let amendments = match (prior, governance.as_ref()) {
        (Some(p), _) => Arc::clone(&p.amendments),
        (None, Some(g)) => Arc::clone(g.amendments()),
        (None, None) => Arc::new(crate::audit::amend::NodeAmendments::new()),
    };
    if prior.is_none() {
        crate::export::plugin::record_reads_on(&amendments);
    }

    let limits = Some(limits_resolved.clone());

    let serve_tables = prior.map_or_else(crate::plane_driver::serve::ServeTables::default, |p| {
        p.serve_tables.clone()
    });
    let root_rules = std::sync::Arc::clone(rules);
    let plane_sections = Some(cfg.plane_sections.clone());

    let session_store = prior.map_or_else(
        || {
            Arc::new(crate::session::SessionStore::new(
                SESSION_STORE_CAPACITY,
                Some(SESSION_STORE_TTL_MS),
            ))
        },
        |p| Arc::clone(&p.session_store),
    );

    let incremental_scan =
        std::env::var_os("BUSBAR_INCREMENTAL_SCAN").is_some_and(|v| !v.is_empty() && v != "0");

    let plane_pools = cfg
        .plane_pools
        .iter()
        .filter_map(|(section, pools)| {
            crate::plane_driver::registry::plane_decl_for_config_section(section)
                .map(|decl| (decl.key, pools.clone()))
        })
        .collect();
    let auth = auth_mw.clone();

    let hook_env = hook_env.clone();
    let hook_registry = cfg.hooks.clone();
    let requested_signals = hooks::requested_signals(&cfg.hooks);
    let any_content_hook = hooks::any_content_hook(&cfg.hooks);
    let export_projections = cfg.export.projection_union();
    let global_hooks = cfg.global_hooks.clone();
    let groups_registry = cfg.groups.clone();

    let identity_providers = cfg.identity_providers.clone();
    let export_defs = cfg.export_defs.clone();

    let admin = prior.map_or_else(
        || Arc::new(admin::seam::AdminSlot::default()),
        |p| p.admin.clone(),
    );
    let mutation_limiter = prior.map_or_else(
        || Arc::new(ratelimit::MutationLimiter::new()),
        |p| p.mutation_limiter.clone(),
    );
    let admin_chain = cfg.admin_auth.clone();
    let public_url = cfg.public_url.clone();

    let planes = Arc::new({
        let ref_slots: std::collections::BTreeMap<&'static str, &dyn std::any::Any> = plane_slots
            .iter()
            .map(|(k, v)| (*k, v.as_ref() as &dyn std::any::Any))
            .collect();
        crate::plane_driver::registry::build_dispatch(
            crate::plane_driver::registry::plane_decls(),
            &ref_slots,
            auth_mw.keys_in_chain,
        )?
    });

    let oauth_as = oauth_as_plane.clone();

    let demotion_record = prior.map_or_else(
        || Arc::new(crate::trust::demotion::DemotionRecord::new()),
        |p| p.demotion_record.clone(),
    );
    let auth_scope_caps = cfg
        .auth
        .as_ref()
        .map(project_auth_scope_caps)
        .unwrap_or_default();
    let role_bindings = cfg
        .auth
        .as_ref()
        .map(|a| a.role_bindings.clone())
        .unwrap_or_default();
    let config_path = config_paths.0;
    let providers_path = config_paths.1;
    let config_version = app_config_version;
    let max_keys_per_principal = cfg.limits.max_keys_per_principal;
    let max_auto_provisioned_groups = cfg.limits.max_auto_provisioned_groups;
    let plugins_dir = std::path::PathBuf::from(&plugins_cfg.dir);
    let plugin_admission = crate::preflight::root_rows().admission;

    let self_key_ttl_secs = cfg
        .auth
        .as_ref()
        .and_then(|a| a.key_ttl.as_deref())
        .map(|s| {
            config::parse::parse_duration_secs(s)
                .unwrap_or(governance::mint_policy::DEFAULT_KEY_TTL_SECS)
        })
        .unwrap_or(governance::mint_policy::DEFAULT_KEY_TTL_SECS);

    let mint_policy = std::sync::Arc::new(governance::mint_policy::MintPolicy::from_auth(
        cfg.auth.as_ref(),
    ));

    let request_id_counter = prior.map_or_else(
        || {
            Arc::new(std::sync::atomic::AtomicU64::new(
                state::seed_request_id_counter(),
            ))
        },
        |p| p.request_id_counter.clone(),
    );
    let planes_awaiting_restart = planes_awaiting_restart
        .iter()
        .map(|section| (*section).to_string())
        .collect();
    let mut app = App::assemble(
        crate::state::AppParts {
            limits,
            serve_tables,
            root_rules,
            config_projection,
            plane_sections,
            fallback_runtime_key,
            config_tables,
            store,
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
            groups_registry,
            base_group_names,
            identity_providers,
            export_defs,
            admin,
            base_hook_names,
            admin_chain,
            admin_modules,
            public_url,
            planes,
            plane_slots,
            oauth_as,
            demotion_record,
            amendments,
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
        },
        tslots,
        export_projections,
        mutation_limiter,
        login_methods,
    );
    rules.check_built(&app)?;
    if let Some(paths) = rules.mounted_plugin_paths(&app) {
        app.boot_route_paths = Arc::new(paths);
    }

    for decl in crate::plane_driver::registry::plane_decls() {
        if let Some(retain) = decl.retain_verify_gates {
            retain(&app);
        }
    }

    app.configured_view = Some(configured_view);
    // Existing direct builders pass an explicit providers path. The executable replaces this
    // initial default with its actual CLI/env provenance; subsequent generations inherit it.
    if let Some(prior) = prior {
        app.providers_override = prior.providers_override.clone();
    }
    app.config_pending_restart = prior
        .map(|app| app.config_pending_restart.clone())
        .unwrap_or_default();
    Ok((
        app,
        rotate_gov_credentials,
        InstalledLimits {
            limits: limits_resolved,
            rates: resolved_rates,
            configured_card,
            destinations,
            rules: std::sync::Arc::clone(rules),
        },
    ))
}

#[cfg(test)]
#[path = "tests/root_rules_hearing_tests.rs"]
mod root_rules_hearing_tests;

#[cfg(test)]
#[path = "tests/config_store_recovery_tests.rs"]
mod config_store_recovery_tests;
