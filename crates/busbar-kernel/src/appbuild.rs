// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::Arc;

use crate::auth::AuthMiddleware;
use crate::diagnostics::{
    diag_error, diag_warn, DURABLE_KEYS_INERT, GOVERNANCE_STORE_EPHEMERAL, OPEN_RELAY_NO_AUTH,
    PLUGINS_FETCH_RELOAD_MISS, PROVIDER_API_KEY_UNRESOLVABLE, STATEFUL_PLANE_EPHEMERAL_STORE,
    STORE_SECRET_REF_UNRESOLVED,
};
use crate::preflight::resolve_signing_key;
use crate::router::project_auth_scope_caps;
use crate::state::App;
use crate::store::{HealthState, LaneData};
use crate::{admin, config, config_validate, governance, ratelimit, state, telemetry};
use busbar_kernel::plane_driver::route_input::{
    LaneInput, OnExhaustedInput, PoolInput, PoolMemberInput,
};

pub const ENV_CONFIG: &str = "BUSBAR_CONFIG";

pub const DEFAULT_CONFIG_PATH: &str = "/etc/busbar/config.yaml";

/// The explicit open posture (`auth: { chain: [] }`) boots bannered. A configuration with no `auth:`
/// block never reaches here: validation refuses it (#358).
pub fn open_relay_banner(chain_empty: bool) -> Option<&'static str> {
    chain_empty.then_some(
        "auth is DISABLED (auth.chain is empty) — busbar is running as an OPEN RELAY; do not run this in production",
    )
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
    /// Names in the composed source before any typed overlay is applied.
    pub resource_ownership: config::ResourceOwnership,
    pub defs: HashMap<String, config::ProviderDef>,

    pub providers_path: std::path::PathBuf,

    pub overlay_path: Option<Arc<config::overlay::OverlayStore>>,

    pub config_locked: bool,

    pub config_read_only: bool,

    pub overlay_doc: Option<config::overlay::OverlayDoc>,

    pub unset_env_vars: Vec<String>,

    /// config.yaml's operator-backed definitions exactly as read from disk, before any
    /// `document_patch` is composed (OPERATOR-FROM-ADMITTED-AUTH §000.1): the file-policy reference.
    pub operator_reference: config::OperatorFileDefs,
}

impl LoadedConfig {
    /// A disk rebuild's candidate (`POST /config/reload`, `POST /plugins/reload`,
    /// `POST /plugins/rollback`): the overlay's root applied to config.yaml's deploy, then resolved.
    /// A disk rebuild re-reads config.yaml, so config.yaml's operator definitions, before any
    /// patch, become the file-policy reference (OPERATOR-FROM-ADMITTED-AUTH §3.6.1): editing them
    /// and reloading is how the operator credential rotates. Resource ownership was captured before
    /// typed overlays; callers carry those names and merge the resolved hook/group overlay.
    #[cold]
    #[inline(never)]
    pub fn disk_candidate(&mut self) -> Result<config::RootCfg, String> {
        if let Some(doc) = self.overlay_doc.as_ref() {
            self.resource_ownership.validate_named_maps(doc)?;
            config::overlay::apply_root_to_deploy(&mut self.deploy, doc)?;
        }
        let mut cfg = config::resolve(&self.deploy, &self.defs)
            .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))?;
        cfg.operator_file_defs = Some(Arc::new(std::mem::take(&mut self.operator_reference)));
        Ok(cfg)
    }
}

#[cold]
#[inline(never)]
pub fn load_config_from_disk(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    ignore_overlay: bool,
    env_mode: config::EnvSubst,
) -> Result<LoadedConfig, String> {
    load_config_from_disk_judged(
        config_path,
        providers_override,
        ignore_overlay,
        env_mode,
        &AcceptAll,
    )
}

#[cold]
#[inline(never)]
pub fn load_config_from_disk_judged(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    ignore_overlay: bool,
    env_mode: config::EnvSubst,
    rules: &dyn RootRules,
) -> Result<LoadedConfig, String> {
    load_config_from_disk_with_document_patch(
        config_path,
        providers_override,
        ignore_overlay,
        env_mode,
        rules,
        None,
    )
}

/// Compose the durable document layer before the same parser boot uses. The Store anchor is
/// selected from the base configuration before calling this for a persisted patch.
pub(crate) fn load_config_from_disk_with_document_patch(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    ignore_overlay: bool,
    env_mode: config::EnvSubst,
    rules: &dyn RootRules,
    patch: Option<&config::document_patch::DocumentPatch>,
) -> Result<LoadedConfig, String> {
    load_config_from_disk_with_document_patches(
        config_path,
        providers_override,
        ignore_overlay,
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
    ignore_overlay: bool,
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
        ignore_overlay,
        env_mode,
        rules,
        DocumentPatchLoad {
            patch: patch.as_mut(),
            providers_patch: providers_patch.as_mut(),
            admission: None,
        },
    )
}

/// Set once by the binary when it was booted with `--ignore-overlay`.
pub static IGNORE_OVERLAY_FLAG: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether this process was booted with `--ignore-overlay`; a later reload/apply re-merges
/// the Store overlay.
pub fn booted_with_ignore_overlay() -> bool {
    IGNORE_OVERLAY_FLAG.load(std::sync::atomic::Ordering::Relaxed)
}

pub struct DocumentPatchLoad<'a> {
    pub patch: Option<&'a mut config::document_patch::DocumentPatch>,
    pub providers_patch: Option<&'a mut config::document_patch::DocumentPatch>,
    pub admission: Option<&'a mut config::document_patch::SourceAdmission>,
}

/// Reuse the exact file/env preprocessing while returning a compacted guarded Store carrier.
/// The admin caller persists these edits only after typed parsing and runtime validation succeed.
///
/// The read's grammar is its own (SECRET-SHORTHAND-BOOT §3.1): phase 1 over this read's effective
/// `plugins:` block (patch applied, in this read's env mode), never the live secret axis.
pub fn load_config_from_disk_compacting_document_patches(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    ignore_overlay: bool,
    env_mode: config::EnvSubst,
    rules: &dyn RootRules,
    edits: DocumentPatchLoad<'_>,
) -> Result<LoadedConfig, String> {
    let raw = read_config_documents(
        config_path,
        providers_override,
        ignore_overlay,
        env_mode,
        rules,
        edits,
    )?;
    let read = Arc::new(raw.own_read()?);
    raw.typed_prepared(read)
}

/// The deployment document as one read sees it before its typed parse: read, normalized,
/// interpolated in the read's env mode, judged for legacy markers and unloaded plane sections, and
/// with the durable document patch applied. What the read's grammar is computed from
/// ([`RawDocuments::plugins_block`]) and then typed under ([`RawDocuments::typed`]).
pub struct RawDocuments<'a> {
    inputs: ReadInputs<'a>,
    /// The interpolated deployment text as the operator wrote it (no patch): what the source
    /// fingerprints bind.
    source_text: busbar_contract::secure::SecureString,
    /// The effective deployment text: interpolated, with the document patch applied.
    config_text: busbar_contract::secure::SecureString,
    /// Whether `config_text` carries a durable document patch (its parse refusal says so).
    patched: bool,
    /// The keys that patch itself names (DocumentPatch::submitted_keys): the only names its parse
    /// refusal may quote.
    patch_keys: Vec<busbar_contract::secure::SecureString>,
    /// Whether that patch edits `identity-providers`: then config.yaml's operator definitions
    /// (the file-policy reference) are read from `source_text`, not the patched document.
    operator_patched: bool,
    unset_env_vars: Vec<String>,
}

/// What one read was asked for, kept for its providers half.
struct ReadInputs<'a> {
    config_path: &'a std::path::Path,
    providers_override: Option<&'a std::path::Path>,
    ignore_overlay: bool,
    env_mode: config::EnvSubst,
    rules: &'a dyn RootRules,
    providers_patch: Option<&'a mut config::document_patch::DocumentPatch>,
    admission: Option<&'a mut config::document_patch::SourceAdmission>,
}

impl RawDocuments<'_> {
    /// The complete admission of this effective document, before parsing its typed fields.
    pub fn own_read(&self) -> Result<config::grammar::PreparedConfigRead, String> {
        self.read_with_pins(&Default::default())
    }

    fn read_with_pins(
        &self,
        pins: &std::collections::BTreeMap<String, String>,
    ) -> Result<config::grammar::PreparedConfigRead, String> {
        let plugins = self.plugins_block()?;
        config::grammar::prepare_read_for(
            &config::grammar::PhaseOneIn {
                plugins: &plugins,
                dir: std::path::Path::new(&plugins.dir),
                pins,
                fetch: config::grammar::Fetch::None,
            },
            self.inputs.rules,
        )
        .map_err(|refusal| format!("config.yaml: {refusal}"))
    }

    /// Parse and retain the exact image/descriptor owner. No admission is repeated here.
    pub fn typed_prepared(
        self,
        read: Arc<config::grammar::PreparedConfigRead>,
    ) -> Result<LoadedConfig, String> {
        read.check_plugins(&self.plugins_block()?)?;
        let mut loaded = self.typed(read.grammar())?;
        read.attach(&mut loaded.deploy)?;
        Ok(loaded)
    }
    /// The read's effective `plugins:` block, typed without a grammar: it holds no secret
    /// reference (G18). An absent block is the default (`enabled: false`). A document that does not
    /// read as YAML at all has no block here; the typed parse reports it.
    pub fn plugins_block(&self) -> Result<config::PluginsCfg, String> {
        use busbar_contract::yaml::ValueExt as _;
        let Ok(doc) = busbar_contract::yaml::from_str::<busbar_contract::yaml::Value>(
            self.config_text.as_ref(),
        ) else {
            return Ok(config::PluginsCfg::default());
        };
        match doc.get("plugins") {
            None => Ok(config::PluginsCfg::default()),
            Some(block) => busbar_contract::yaml::from_value::<config::PluginsCfg>(block.clone())
                .map_err(|e| format!("config.yaml: plugins: {e}")),
        }
    }

    /// Phase 1 over this read's own block alone: its own directory, no pins, no fetch.
    pub fn own_grammar(&self) -> Result<config::Grammar, String> {
        let plugins = self.plugins_block()?;
        config::grammar::grammar_for(
            &config::grammar::PhaseOneIn::of(&plugins),
            self.inputs.rules,
        )
        .map_err(|refusal| format!("config.yaml: {refusal}"))
    }

    /// The typed read under `grammar`: the deployment document, then the providers catalog it
    /// names. A refused word carries the grammar's report (one line per file not admitted).
    pub fn typed(self, grammar: &config::Grammar) -> Result<LoadedConfig, String> {
        let RawDocuments {
            inputs,
            source_text,
            config_text,
            patched,
            patch_keys,
            operator_patched,
            mut unset_env_vars,
        } = self;
        if let Some(refusal) = process_lifetime_refusal(config_text.as_ref(), grammar, false) {
            return Err(format!("config.yaml: {refusal}"));
        }
        let mut deploy =
            config::deploy_from_yaml_str(config_text.as_ref(), grammar).map_err(|e| {
                grammar.with_report(if patched {
                    patched_parse_refusal(&e.to_string(), &patch_keys)
                } else {
                    format!(
                        "config.yaml: invalid YAML: {}",
                        config::augment_config_error(e)
                    )
                })
            })?;
        // The operator credential's reference is config.yaml as read from disk, before any
        // document_patch (OPERATOR-FROM-ADMITTED-AUTH §000.1).
        let operator_reference = if operator_patched {
            let unpatched =
                config::deploy_from_yaml_str(source_text.as_ref(), grammar).map_err(|e| {
                    grammar.with_report(format!(
                        "config.yaml: invalid YAML: {} (the operator credential is read from \
                         config.yaml before any document_patch)",
                        config::augment_config_error(e)
                    ))
                })?;
            config::OperatorFileDefs::of(&unpatched.identity_providers)
        } else {
            config::OperatorFileDefs::of(&deploy.identity_providers)
        };
        let bound_grammar = deploy.grammar.get().map_err(String::from)?.clone();
        let (defs, providers_path) = typed_rest(
            inputs,
            &source_text,
            &mut deploy,
            &mut unset_env_vars,
            &bound_grammar,
        )?;
        let resolution = config::overlay::resolve_backend(&deploy.config);
        let resource_ownership = config::ResourceOwnership::capture(&deploy);
        Ok(LoadedConfig {
            deploy,
            resource_ownership,
            defs,
            providers_path,
            overlay_path: None,
            config_locked: resolution.locked,
            config_read_only: false,
            overlay_doc: None,
            unset_env_vars,
            operator_reference,
        })
    }
}

/// Read the deployment document up to (not including) its typed parse ([`RawDocuments`]).
pub fn read_config_documents<'a>(
    config_path: &'a std::path::Path,
    providers_override: Option<&'a std::path::Path>,
    ignore_overlay: bool,
    env_mode: config::EnvSubst,
    rules: &'a dyn RootRules,
    edits: DocumentPatchLoad<'a>,
) -> Result<RawDocuments<'a>, String> {
    let DocumentPatchLoad {
        patch,
        providers_patch,
        mut admission,
    } = edits;
    let mut unset_env_vars: Vec<String> = Vec::new();

    // A document the composition root holds (an unstamped boot's planned config.yaml) is read in
    // place of the file, which is then not opened (MIGRATE-ON-BOOT r42 §3 step 2).
    let raw_config = match rules.held_document(config_path) {
        Some(held) => held,
        None => busbar_contract::secure::SecureString::from(
            std::fs::read_to_string(config_path).map_err(|e| {
                format!(
                    "cannot read config file '{}': {e} (set {ENV_CONFIG})",
                    config_path.display()
                )
            })?,
        ),
    };
    let interpolated_config =
        config::interpolate_env_with(&raw_config, env_mode, &mut unset_env_vars)
            .map_err(|e| format!("config.yaml: {e}"))?;

    if let Some(admission) = admission.as_deref_mut() {
        admission.check_config(&interpolated_config)?;
    }

    if let Ok(doc) =
        busbar_contract::yaml::from_str::<busbar_contract::yaml::Value>(&interpolated_config)
    {
        use busbar_contract::yaml::{MappingExt as _, ValueExt as _};
        // Startup unfolds a literal 1.5.5 `cache_write_utok: 0` before this reader; one that still
        // arrives (a runtime edit, or an env-interpolated value) is refused rather than made free.
        // Admin-API zeros live in the overlay patch, applied below, and are not touched.
        if let Some(model) = doc
            .as_mapping()
            .and_then(|root| config::zero_cache_write_models(root).into_iter().next())
        {
            return Err(format!(
                "config.yaml: rate_card.{model}.cache_write_utok: 0 is refused. In a root \
                 rate_card it is the 1.5.5 spelling of 'no separate write tariff' and would make \
                 cache writes free. Remove the key (writes price at input_utok) or set free writes \
                 through the admin API."
            ));
        }

        let keys: Vec<&str> = doc
            .as_mapping()
            .into_iter()
            .flat_map(|m| m.keys())
            .filter_map(busbar_contract::yaml::Value::as_str)
            .collect();
        if let Some(refusal) = rules.unloaded_plane_refusal(&keys) {
            return Err(format!("config.yaml: {refusal}"));
        }
    }

    // The operator credential's reference is config.yaml as read, before any patch (§000.1). Only a
    // patch that edits `identity-providers` can make the composed document's differ.
    let mut operator_patched = false;
    let mut patch_keys = Vec::new();
    let (config_text, patched) = match patch.filter(|_| !ignore_overlay) {
        Some(patch) => {
            *patch = patch.compacted_against_yaml(&interpolated_config)?;
            patch_keys = patch.submitted_keys();
            operator_patched = config::operator_file::touches_identity_providers(patch);
            let text = patch.patched_text(&interpolated_config, |keys| {
                rules.unloaded_plane_refusal(keys).map_or(Ok(()), Err)
            })?;
            (text, true)
        }
        None => (
            busbar_contract::secure::SecureString::from(interpolated_config.as_str()),
            false,
        ),
    };
    Ok(RawDocuments {
        inputs: ReadInputs {
            config_path,
            providers_override,
            ignore_overlay,
            env_mode,
            rules,
            providers_patch,
            admission,
        },
        source_text: busbar_contract::secure::SecureString::from(interpolated_config),
        config_text,
        patched,
        patch_keys,
        operator_patched,
        unset_env_vars,
    })
}

/// The refusal of a patched document's boot parse. Every boot-parse error stays redacted (b381eadf2e),
/// except one: an unknown field whose name is a key the caller's own patch names. That name is the
/// caller's input, not configuration it cannot see, so it is quoted; no value ever is (PM ruling
/// D-REDACT, 2026-11-17).
fn patched_parse_refusal(
    error: &str,
    patch_keys: &[busbar_contract::secure::SecureString],
) -> String {
    const REDACTED: &str = "patched configuration failed boot parsing";
    let Some(rest) = error.split_once("unknown field `").map(|(_, rest)| rest) else {
        return REDACTED.to_owned();
    };
    let Some((name, _)) = rest.split_once('`') else {
        return REDACTED.to_owned();
    };
    if patch_keys.iter().any(|key| key.as_str() == name) {
        format!("{REDACTED}: unknown field `{name}`")
    } else {
        REDACTED.to_owned()
    }
}

/// The providers half of a typed read: the catalog file `deploy` names (or the override), read,
/// normalized and interpolated as the deployment document was, and typed under `grammar`.
fn typed_rest(
    inputs: ReadInputs<'_>,
    source_text: &str,
    deploy: &mut config::DeployCfg,
    unset_env_vars: &mut Vec<String>,
    grammar: &config::Grammar,
) -> Result<(HashMap<String, config::ProviderDef>, std::path::PathBuf), String> {
    let ReadInputs {
        config_path,
        providers_override,
        ignore_overlay,
        env_mode,
        rules,
        providers_patch,
        admission,
    } = inputs;
    // A providers file the operator NAMED (--providers / env, or `providers_file:`) must exist. The
    // default one beside config.yaml is optional: absent means an empty catalog (an admin-only
    // deployment configures no provider). Custody learns of the absence itself, never a stand-in.
    let location = config::providers::CatalogLocation::select(
        config_path,
        providers_override,
        deploy.providers_file.as_deref(),
    );
    let providers_path = location.path.clone();
    // A held catalog (the planned `providers.busbar-1.6.yaml` step 5 creates) is read in place of
    // its file (MIGRATE-ON-BOOT r42 §3 step 2).
    let source = match rules.held_document(&providers_path) {
        Some(held) => config::providers::CatalogSource::Authored(String::from(&*held)),
        None => location.read()?,
    };
    if matches!(source, config::providers::CatalogSource::AbsentDefault) {
        tracing::info!(
            path = %providers_path.display(),
            "no providers file at the default location; running with an empty provider catalog"
        );
    }
    let interpolated_providers =
        config::interpolate_env_with(source.text(), env_mode, unset_env_vars)
            .map_err(|e| format!("providers.yaml: {e}"))?;
    if let Some(admission) = admission {
        admission.check_catalog(&interpolated_providers)?;
    }
    if let Some(refusal) = process_lifetime_refusal(&interpolated_providers, grammar, true) {
        return Err(format!("providers.yaml: {refusal}"));
    }
    deploy.document_source_fingerprints =
        Some(config::document_patch::SourceFingerprints::from_sources(
            source_text,
            &interpolated_providers,
        ));
    let (defs, mut used): (HashMap<String, config::ProviderDef>, config::grammar::Used) =
        if let Some(patch) = providers_patch.filter(|_| !ignore_overlay) {
            *patch = patch.compacted_against_yaml(&interpolated_providers)?;
            patch.parse_catalog_yaml_used(&interpolated_providers, grammar)?
        } else {
            config::providers::catalog_from_str_used(&interpolated_providers, grammar)
                .map_err(|e| grammar.with_report(format!("providers.yaml: invalid YAML: {e}")))?
        };
    // The read's use of its grammar covers both documents (§3.8): the catalog's words and styles,
    // and the deployment's own provider styles.
    used.styles.extend(
        deploy
            .providers
            .values()
            .filter_map(|provider| provider.auth.as_ref())
            .map(|style| style.as_str().to_owned()),
    );
    deploy.grammar.record(&used);
    Ok((defs, providers_path))
}

/// The refusal for a document that writes a process-lifetime item its read does not let count
/// (SECRET-SHORTHAND-BOOT §3.6): a top-level plane section, or a provider's `auth:` style, whose
/// module this process did not register at start, or registered but the read no longer admits.
/// Judged before the typed parse, so the refusal names the module and the cause instead of an
/// unknown field. `catalog`: `text` is a providers catalog (each top-level entry is a provider).
fn process_lifetime_refusal(
    text: &str,
    grammar: &config::Grammar,
    catalog: bool,
) -> Option<String> {
    use busbar_contract::yaml::{MappingExt as _, Value, ValueExt as _};
    if grammar.items.is_empty() {
        return None;
    }
    let doc = busbar_contract::yaml::from_str::<Value>(text).ok()?;
    let root = doc.as_mapping()?;
    let providers = if catalog {
        Some(root)
    } else {
        if let Some(refusal) = root
            .keys()
            .filter_map(Value::as_str)
            .find_map(|key| grammar.item_refusal(config::grammar::ItemKind::Section, key))
        {
            return Some(refusal);
        }
        doc.get("providers").and_then(Value::as_mapping)
    };
    // Bound to a local: the iterator borrows `doc`, which a tail expression's temporary would
    // outlive.
    let found = providers?.values().find_map(|entry| {
        entry
            .get("auth")
            .and_then(Value::as_str)
            .and_then(|style| grammar.item_refusal(config::grammar::ItemKind::Style, style))
    });
    found
}

pub async fn load_config_from_disk_with_store(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    ignore_overlay: bool,
    env_mode: config::EnvSubst,
    rules: &dyn RootRules,
    overlay: Option<Arc<config::overlay::OverlayStore>>,
) -> Result<LoadedConfig, String> {
    let mut loaded = load_config_from_disk_judged(
        config_path,
        providers_override,
        ignore_overlay,
        env_mode,
        rules,
    )?;
    if !loaded.config_locked {
        let store = overlay.ok_or_else(|| {
            "running config has no Store overlay anchor; restart to bootstrap it".to_string()
        })?;
        if ignore_overlay {
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
                // A stored patch from an earlier binary that moves the operator credential is
                // refused at every re-read, as at boot: never applied or dropped silently.
                if let Some(patch) = doc.document_patch.as_ref() {
                    config::operator_file::stored_document_patch(patch, &loaded)?;
                }
                patched_locked = loaded.config_locked;
            }
            loaded.overlay_path = (!patched_locked).then_some(reopened);
            loaded.overlay_doc = doc;
        }
    }
    Ok(loaded)
}

/// THE FIRST HALF OF A RELOAD-CLASS DISK READ (SECRET-SHORTHAND-BOOT §3.11-3.12): `config.yaml`
/// with the Store's durable document patch, and the Store's overlay, read up to (not including)
/// the read's grammar. [`DiskRead::candidate`] is what the authority pre-check judges and what
/// phase 1 fetches and scans for; [`DiskRead::typed`] then reads the documents under the grammar
/// phase 1 gave. Nothing here fetches, scans `plugins.dir` or computes a grammar.
pub struct DiskRead {
    pub candidate: config::security_policy::Candidate,
    /// The reopened Store overlay; `None` when `config.yaml` is locked (nothing to reopen).
    overlay: Option<Arc<config::overlay::OverlayStore>>,
    doc: Option<config::overlay::OverlayDoc>,
}

/// Read `config.yaml` and the Store overlay for a reload-class operation ([`DiskRead`]). `overlay`
/// is the Store to reopen, or why there is none (refused only when `config.yaml` is unlocked). The
/// candidate's grammar-bearing security fields are read under `running`, the serving generation's
/// grammar.
pub async fn read_disk_candidate(
    config_path: &std::path::Path,
    providers_override: Option<&std::path::Path>,
    env_mode: config::EnvSubst,
    rules: &dyn RootRules,
    overlay: Result<Arc<config::overlay::OverlayStore>, String>,
    running: &config::Grammar,
) -> Result<DiskRead, String> {
    let text = |patch: Option<&mut config::document_patch::DocumentPatch>| {
        read_config_documents(
            config_path,
            providers_override,
            false,
            env_mode,
            rules,
            DocumentPatchLoad {
                patch,
                providers_patch: None,
                admission: None,
            },
        )
        .map(|raw| raw.config_text)
    };
    let file = config::security_policy::Candidate::of_yaml(text(None)?.as_ref(), running, None)?;
    if file.locked {
        return Ok(DiskRead {
            candidate: file,
            overlay: None,
            doc: None,
        });
    }
    let (reopened, doc) = overlay?.reopen_for_reload_async().await?;
    let mut patch = doc.as_ref().and_then(|doc| doc.document_patch.clone());
    let effective = match patch.as_mut() {
        Some(patch) => text(Some(patch))?,
        None => text(None)?,
    };
    let candidate =
        config::security_policy::Candidate::of_yaml(effective.as_ref(), running, doc.as_ref())?;
    Ok(DiskRead {
        candidate,
        overlay: Some(reopened),
        doc,
    })
}

impl DiskRead {
    /// Carry the exact admission through the second document read. Changed plugin inputs refuse.
    pub fn typed_prepared(
        self,
        config_path: &std::path::Path,
        providers_override: Option<&std::path::Path>,
        env_mode: config::EnvSubst,
        rules: &dyn RootRules,
        read: Arc<config::grammar::PreparedConfigRead>,
    ) -> Result<LoadedConfig, String> {
        let grammar = read.grammar().clone();
        self.typed_inner(
            config_path,
            providers_override,
            env_mode,
            rules,
            &grammar,
            Some(read),
        )
    }

    /// The documents typed under `grammar` (the read's phase 1), with the Store's durable patches
    /// applied and its overlay attached, as [`load_config_from_disk_with_store`] reads them.
    pub fn typed(
        self,
        config_path: &std::path::Path,
        providers_override: Option<&std::path::Path>,
        env_mode: config::EnvSubst,
        rules: &dyn RootRules,
        grammar: &config::Grammar,
    ) -> Result<LoadedConfig, String> {
        self.typed_inner(
            config_path,
            providers_override,
            env_mode,
            rules,
            grammar,
            None,
        )
    }

    fn typed_inner(
        self,
        config_path: &std::path::Path,
        providers_override: Option<&std::path::Path>,
        env_mode: config::EnvSubst,
        rules: &dyn RootRules,
        grammar: &config::Grammar,
        read: Option<Arc<config::grammar::PreparedConfigRead>>,
    ) -> Result<LoadedConfig, String> {
        let DiskRead {
            overlay, mut doc, ..
        } = self;
        let mut patch = doc.as_ref().and_then(|doc| doc.document_patch.clone());
        let mut providers_patch = doc.as_ref().and_then(|doc| doc.providers_patch.clone());
        let raw = read_config_documents(
            config_path,
            providers_override,
            false,
            env_mode,
            rules,
            DocumentPatchLoad {
                patch: patch.as_mut(),
                providers_patch: providers_patch.as_mut(),
                admission: None,
            },
        )?;
        let mut loaded = match read {
            Some(read) => raw.typed_prepared(read)?,
            None => raw.typed(grammar)?,
        };
        // A stored patch from an earlier binary that moves the operator credential is refused at
        // every re-read, as at boot: never applied or dropped silently.
        if let Some(patch) = doc.as_ref().and_then(|doc| doc.document_patch.as_ref()) {
            config::operator_file::stored_document_patch(patch, &loaded)?;
        }
        if let Some(reopened) = overlay {
            if !loaded.config_locked {
                loaded.overlay_path = Some(reopened);
            }
            loaded.overlay_doc = doc.take();
        }
        Ok(loaded)
    }
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
            "{} recoverable credential(s) are still stored in the clear (written by 1.5.5): \
             another node holds their re-wrap, or the store keeps no claims. \
             They still authenticate; a later boot \
             or reload re-seals them all",
            pass.pending
        ),
        Ok(pass) if pass.resealed > 0 => tracing::info!(
            resealed = pass.resealed,
            "recoverable credentials re-sealed under the key derived from auth.signing_key"
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
    rates: config::card::CardRates,

    configured_card: config::card::CardFields,

    destinations: config::Destinations,

    rules: std::sync::Arc<dyn RootRules>,
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

/// The root's act that completes one candidate once the kernel has built its app.
pub type CandidateFinish = Box<
    dyn for<'a> FnOnce(
            &'a mut App,
        )
            -> busbar_plugin_abi::host_side::caller::BoxFut<'a, Result<(), String>>
        + Send,
>;

/// Root-owned early resolver and late completion of one unpublished candidate.
/// The containing transaction owns this object across awaits; response detachment does not abort it.
pub struct CandidatePreparation {
    secret_resolver: Arc<config::secret::SecretResolver>,
    finish: CandidateFinish,
}

impl CandidatePreparation {
    pub fn new(
        secret_resolver: Arc<config::secret::SecretResolver>,
        finish: CandidateFinish,
    ) -> Self {
        Self {
            secret_resolver,
            finish,
        }
    }

    pub fn secret_resolver(&self) -> Arc<config::secret::SecretResolver> {
        Arc::clone(&self.secret_resolver)
    }

    pub fn finish<'a>(
        self,
        app: &'a mut App,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<'a, Result<(), String>> {
        (self.finish)(app)
    }
}

pub trait RootRules: Send + Sync {
    /// Retain the actual read's native admission. Metadata-only readers need no opaque context.
    fn prepare_read(
        &self,
        input: &config::grammar::PhaseOneIn<'_>,
    ) -> Result<config::grammar::PreparedConfigRead, config::grammar::GrammarRefusal> {
        self.grammar(input)
            .map(config::grammar::PreparedConfigRead::new)
    }

    /// Capture the candidate before its fields move and before any dependent secret resolution.
    /// Native reads must supply a real producer; an absent implementation cannot reuse old ports.
    fn prepare_candidate<'a>(
        &'a self,
        cfg: &'a config::RootCfg,
        _plugins: &'a config::PluginsCfg,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<Option<CandidatePreparation>, String>,
    > {
        Box::pin(async move {
            if cfg
                .grammar
                .prepared()
                .is_some_and(|read| read.has_context() || !read.provider_planes().is_empty())
            {
                Err("the native read has no candidate preparation producer".into())
            } else {
                Ok(None)
            }
        })
    }
    /// Phase one uses this reader's owned process and image admission context.
    fn grammar(
        &self,
        input: &config::grammar::PhaseOneIn<'_>,
    ) -> Result<config::Grammar, config::grammar::GrammarRefusal> {
        if input.plugins.enabled {
            Err(config::grammar::GrammarRefusal(
                "no composition root supplied the config grammar".to_owned(),
            ))
        } else {
            Ok(config::Grammar::empty())
        }
    }
    /// Open the candidate secret plan using this roots complete bootstrap owners. The root
    /// refuses protected boot changes before opening any candidate instance.
    fn secret_resolver<'a>(
        &'a self,
        cfg: &'a config::RootCfg,
        _plugins: &'a config::PluginsCfg,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<Arc<config::secret::SecretResolver>, String>,
    > {
        Box::pin(async move {
            let sugars = generation_sugars(cfg);
            if !cfg.secrets.is_empty() || sugars.iter().next().is_some() {
                return Err("no composition root supplied the candidate secret plan".to_owned());
            }
            Ok(Arc::new(
                config::secret::SecretResolver::builtins_only().with_sources(sugars),
            ))
        })
    }
    fn check(&self, cfg: &config::RootCfg) -> Result<(), String>;

    /// The document this read runs in place of the file at `path`, held in memory by the
    /// composition root (MIGRATE-ON-BOOT r42 §3 step 2): an unstamped boot runs the *planned*
    /// document, which step 5 writes only once every instance has opened. `Some` replaces the read
    /// of the file (it is not opened); the held text is then interpolated and typed exactly as the
    /// file's bytes would be. `None`, every other read, reads the file. The gateway reads only
    /// current bytes: conversion runs in the composition root's migrate seam, before the re-exec.
    fn held_document(
        &self,
        _path: &std::path::Path,
    ) -> Option<busbar_contract::secure::SecureString> {
        None
    }

    /// Complete the exclusively owned candidate's root projections before publication.
    /// Implementations may replace candidate fields; they must not alter shared prior state.
    fn check_built(&self, _app: &mut App) -> Result<(), String> {
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

pub async fn bootstrap_store_inputs(
    cfg: &config::RootCfg,
    plugins: &config::PluginsCfg,
    resolver: &config::secret::SecretResolver,
) -> Result<Arc<dyn busbar_contract::plugin_rows::PluginRows>, String> {
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
    admitted_pin(cfg, registry.as_ref())?;
    let signer = resolve_signing_key(cfg.auth.as_ref(), resolver)?;
    let at_rest = signer
        .as_ref()
        .map(|s| crate::governance::at_rest::AtRestKeys::from_signing_secret(&s.secret_bytes()));
    publish_bootstrap_at_rest(Ok(at_rest.is_some()));
    Ok(registry)
}

/// What core's records step (MIGRATE-ON-BOOT r42 §3 4a, §6 (2) and (4)) seals and verifies with: the
/// at-rest key and the token-signing key the latest store bootstrap resolved, with the secret instances
/// the store boot opened (2a), before the store opened. Taken once, by the step; dropped after it.
pub struct RecordsKeys {
    /// `credentials.at_rest`, `None` when the block is absent.
    pub at_rest: Option<crate::governance::at_rest::AtRestKeys>,
    /// `auth.signing_key`, `None` when it is absent.
    pub signer: Option<crate::governance::signing::TokenSigner>,
}

/// [`RecordsKeys`] from the raw secret bytes a MIN-3 boot's walk resolved (its core secrets), parsed exactly as the
/// store bootstrap parses them.
///
/// # Errors
/// A key that is not 32 bytes (raw or hex).
pub fn records_keys_from(signing_key: Option<&[u8]>) -> Result<RecordsKeys, String> {
    let signer = signing_key
        .map(|bytes| {
            crate::preflight::parse_signing_secret(bytes).map(|secret| {
                crate::governance::signing::TokenSigner::from_secret_bytes(
                    &secret,
                    crate::governance::signing::DEFAULT_KID,
                )
            })
        })
        .transpose()?;
    let at_rest = signer
        .as_ref()
        .map(|s| crate::governance::at_rest::AtRestKeys::from_signing_secret(&s.secret_bytes()));
    Ok(RecordsKeys { at_rest, signer })
}

/// What the latest store bootstrap resolved of `credentials.at_rest`, before the store opened:
/// `Ok(true)` the key resolved, `Ok(false)` no `credentials.at_rest` block, `Err` the resolver's
/// own text. The migration seam's recoverable gate reads it while the store's data step runs
/// (MIGRATE-ON-BOOT §3 step 2 (a)); nothing else does. A MIN-3 boot's walk publishes it after its
/// secret instances opened (2a), before its store opens (2b).
static BOOTSTRAP_AT_REST: std::sync::Mutex<Option<Result<bool, String>>> =
    std::sync::Mutex::new(None);

/// Publishes the at-rest verdict the recoverable gate reads (see `BOOTSTRAP_AT_REST`).
pub fn publish_bootstrap_at_rest(verdict: Result<bool, String>) {
    *BOOTSTRAP_AT_REST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(verdict);
}

/// The latest store bootstrap's at-rest verdict (see `BOOTSTRAP_AT_REST`); `None` before any.
#[must_use]
pub fn bootstrap_at_rest() -> Option<Result<bool, String>> {
    BOOTSTRAP_AT_REST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// The secret shorthand of the generation `cfg` was read under (SECRET-SHORTHAND-BOOT §3.4): what
/// its settings, hooks and references are resolved and judged under, carried by its resolver. A
/// configuration decoded without a grammar (a fixture; every read binds one) admits no word.
fn generation_sugars(cfg: &config::RootCfg) -> busbar_contract::secret_ref::Sugars {
    cfg.grammar()
        .map(|grammar| grammar.sugars.clone())
        .unwrap_or_default()
}

/// THE GRAMMAR PIN after admission (SECRET-SHORTHAND-BOOT §3.8, BUSBAR-3170): every item the
/// configuration used declares the same in the grammar it was read under and in the grammar of the
/// registry admission just put on the axis. It closes the window between the read's scan and
/// admission's: a module replaced in between with a different declaration refuses the build (the
/// old generation keeps serving; at boot the process exits and the next start reads again). A
/// configuration decoded without a grammar has no read to pin; reading it refuses elsewhere.
fn admitted_pin(
    cfg: &config::RootCfg,
    rows: &dyn busbar_contract::plugin_rows::PluginRows,
) -> Result<(), String> {
    let Some(admitted) = crate::preflight::root_rows().admitted_grammar else {
        return Ok(());
    };
    let (Ok(read), Ok(used)) = (cfg.grammar.get(), cfg.grammar.used()) else {
        return Ok(());
    };
    match admitted(rows).map_err(String::from)? {
        Some(now) => {
            let now = if now.secret_binding_required() {
                now.bind_secret_instances(&cfg.secrets)?
            } else {
                now
            };
            config::grammar::pin(read, &now, used, config::grammar::Pin::Admission)
        }
        None => Ok(()),
    }
}

/// THE WRITE-TIME CHECK for a plugin version pin (SECRET-SHORTHAND-BOOT §3.7): a pin written to the
/// Store is applied by every later read, but the next start's first read is `config.yaml`'s own
/// `plugins:` block alone. If the two would judge an item the configuration uses differently, the
/// next restart would refuse (BUSBAR-3170), so the write is refused now, before it is persisted.
/// `used` is what the serving generation's documents use. A document patch cannot move the plugin
/// admission set (the operator file policy refuses `/plugins` paths), so the pins are the only
/// difference to judge.
pub fn pin_write_refusal(
    config_path: &std::path::Path,
    pins: &std::collections::BTreeMap<String, String>,
    used: &config::grammar::Used,
    rules: &dyn RootRules,
) -> Result<(), String> {
    let raw = read_config_documents(
        config_path,
        None,
        false,
        config::EnvSubst::Strict,
        rules,
        DocumentPatchLoad {
            patch: None,
            providers_patch: None,
            admission: None,
        },
    )?;
    let plugins = raw.plugins_block()?;
    let next_start = raw.own_grammar()?;
    let pinned = config::grammar::grammar_for(
        &config::grammar::PhaseOneIn {
            plugins: &plugins,
            dir: std::path::Path::new(&plugins.dir),
            pins,
            fetch: config::grammar::Fetch::None,
        },
        rules,
    )
    .map_err(|refusal| format!("config.yaml: {refusal}"))?;
    config::grammar::pin(&next_start, &pinned, used, config::grammar::Pin::NextBoot)
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

/// The `module` each of core's own secret references names (IF §11.2 `boot_plan`: the admin token, the signing
/// key), in that order, each once. This is what `Registry::boot_plan_with_core` is fed so the
/// secret instances core itself resolves from open in 2a, before the store.
pub fn core_secret_modules(cfg: &config::RootCfg) -> Vec<String> {
    let mut modules: Vec<String> = Vec::new();
    let mut add = |reference: &busbar_contract::secret_ref::SecretRef| {
        if let Some(module) = reference.source_module() {
            if !modules.iter().any(|seen| seen == module) {
                modules.push(module.to_owned());
            }
        }
    };
    if let Some(auth) = &cfg.auth {
        if let Some(reference) = auth.operator_token_ref() {
            add(reference);
        }
        if let Some(reference) = &auth.signing_key {
            add(reference);
        }
    }
    modules
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
        // The store's settings are read under the grammar its document was read under, not the
        // live axis: bootstrap admission has not run yet (SECRET-SHORTHAND-BOOT F7).
        let references = cfg
            .grammar()
            .map_err(String::from)
            .and_then(|grammar| store.settings.reference_modules(fields, &grammar.sugars));
        if let Ok(references) = references {
            for module in references {
                add(&module);
            }
        }
    }
    for module in core_secret_modules(cfg) {
        add(&module);
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

/// The store's configured instance name: its config section key.
pub const STORE_INSTANCE: &str = "store";

/// The limits of an instance as the registry takes them: every number 0 (the kind's default; there is no `limits`
/// key, and the plugin's settled LIMITS answer is applied in memory at its open), `accept` from the instance's
/// `insecure_transport` (TRANSPORT-SECURITY-POLICY §4), empty (verified TLS only) when none is stated.
pub fn instance_limits(
    cfg: &config::RootCfg,
    section: &str,
    name: &str,
) -> busbar_plugin_abi::host_side::caller::InstanceLimits {
    limits_of(&cfg.min3.insecure_transport, section, name)
}

/// [`instance_limits`] over the parsed acceptances alone (`RootCfg::min3.insecure_transport`). A plane
/// instance is keyed (`<instance>`, `<instance>`): its section word is its instance name.
pub fn limits_of(
    accepted: &config::min3::InsecureTransportMap,
    section: &str,
    name: &str,
) -> busbar_plugin_abi::host_side::caller::InstanceLimits {
    let key: (Box<str>, Box<str>) = (Box::from(section), Box::from(name));
    let mut limits = busbar_plugin_abi::host_side::caller::InstanceLimits::default();
    // TRANSPORT-SECURITY-POLICY §4: the instance's `insecure_transport`, absent = verified TLS only.
    if let Some(accepted) = accepted.get(&key) {
        limits.accept = accepted.accept;
    }
    limits
}

/// The 1.5.5 `plugins.fetch` refusal: a header line, then one `  - ` bullet per failed target.
fn plugins_fetch_refusal<S: AsRef<str>>(errors: &[S]) -> String {
    let mut out = String::from("plugins.fetch failed:");
    for error in errors {
        out.push_str("\n  - ");
        out.push_str(error.as_ref());
    }
    out
}

fn fetch_config_plugins(
    plugins: &config::PluginsCfg,
    cfg: &config::RootCfg,
    boot: bool,
) -> Result<(), String> {
    fetch_plugins(plugins, &cfg.blocked_metadata_hosts, boot)
}

/// A reload-class read's phase 1 fetch (SECRET-SHORTHAND-BOOT §3.14): `plugins.fetch` downloaded
/// into `plugins.dir` before the read scans it, so a reload can use a newly fetched module's word.
/// A miss keeps the current artifact (warned), as the build's own reload fetch does. The caller runs
/// the authority pre-check first, and runs this outside the plugin scan gate.
pub fn fetch_for_read(
    plugins: &config::PluginsCfg,
    blocked_metadata_hosts: &[String],
) -> Result<(), String> {
    if !plugins.enabled || plugins.fetch.is_empty() {
        return Ok(());
    }
    fetch_plugins(plugins, blocked_metadata_hosts, false)
}

fn fetch_plugins(
    plugins: &config::PluginsCfg,
    blocked_metadata_hosts: &[String],
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
    let fetch = crate::preflight::root_rows().plugins_fetch.ok_or_else(|| {
        plugins_fetch_refusal(&["no composition root installed the plugins fetch"])
    })?;
    let outcomes = fetch(dir, &targets, boot, blocked_metadata_hosts)
        .map_err(|errors| plugins_fetch_refusal(&errors))?;
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
    Box::pin(build_app_from_config_with_store(
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
    ))
    .await
}

pub async fn build_app_from_config_with_store(
    mut cfg: config::RootCfg,
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
    // The live recorder's allocated budget belongs to the retained generation. A config
    // candidate can request another declaration, but changing that allocation needs restart.
    if let Some(limits) = prior.and_then(|app| app.limits.as_ref()) {
        cfg.limits.key_gauge_limit = limits.key_gauge_limit;
    }
    let limits = cfg.limits.clone();
    in_build_scope(
        limits,
        Box::pin(build_app_native(
            cfg,
            plugins_cfg,
            overlay_path,
            base_hook_names,
            base_group_names,
            config_paths,
            prior,
            rules,
            boot_store,
            recover_usage_before_hydration,
            None,
            None,
        )),
    )
    .await
}

/// The startup continuation's construction of the first application on the admitted boot Store.
/// `judged` is the semantic pass's one result when boot already judged this exact effective
/// configuration (the fresh-instance principal transition judges it before it writes its Store
/// baseline); construction consumes it instead of judging the configuration a second time.
pub struct BootBuild<'a> {
    pub cfg: config::RootCfg,
    pub judged: Option<config_validate::Judged>,
    pub plugins_cfg: config::PluginsCfg,
    pub overlay_path: Option<Arc<config::overlay::OverlayStore>>,
    pub base_hook_names: std::collections::HashSet<String>,
    pub base_group_names: std::collections::HashSet<String>,
    pub config_paths: (Option<std::path::PathBuf>, Option<std::path::PathBuf>),
    pub rules: &'a Arc<dyn RootRules>,
    pub boot_store: Arc<crate::persistence::facade::CoreStore>,
    /// The fully opened S5 secret view; application construction never reopens it.
    pub secret_resolver: Arc<config::secret::SecretResolver>,
}

pub async fn build_boot_app(
    boot: BootBuild<'_>,
) -> Result<(state::App, Option<GovCredentialRotation>, InstalledLimits), String> {
    let limits = boot.cfg.limits.clone();
    in_build_scope(
        limits,
        Box::pin(build_app_native(
            boot.cfg,
            boot.plugins_cfg,
            boot.overlay_path,
            boot.base_hook_names,
            boot.base_group_names,
            boot.config_paths,
            None,
            boot.rules,
            Some(boot.boot_store),
            true,
            boot.judged,
            Some(boot.secret_resolver),
        )),
    )
    .await
}

async fn in_build_scope<T>(
    limits: config::LimitsResolved,
    future: impl std::future::Future<Output = T>,
) -> T {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(move |context| {
        let _scope = config::limits::BuildScope::enter(&limits);
        future.as_mut().poll(context)
    })
    .await
}

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
    judged: Option<config_validate::Judged>,
    opened_secrets: Option<Arc<config::secret::SecretResolver>>,
) -> Result<(state::App, Option<GovCredentialRotation>, InstalledLimits), String> {
    if let Some(read) = cfg.grammar.prepared() {
        read.check_plugins(&plugins_cfg)?;
    }
    config::security_policy::check_candidate(prior, &cfg, &plugins_cfg)?;
    // The operator file-policy reference (§3.6.1): a disk read sets it on the candidate; every
    // other build carries the running generation's unchanged.
    let operator_file_defs = cfg
        .operator_file_defs
        .clone()
        .or_else(|| prior.map(|p| Arc::clone(&p.operator_file_defs)))
        .unwrap_or_default();
    let configured_card = config::card::CardFields::of_root(&cfg);
    let grammar = cfg.grammar.clone();
    let restart_candidate = config::restart::Root::capture(&cfg, &plugins_cfg);
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

        let fetch = crate::preflight::root_rows().plugins_fetch.ok_or_else(|| {
            plugins_fetch_refusal(&["no composition root installed the plugins fetch"])
        })?;
        let outcomes = fetch(&dir, &targets, prior.is_none(), &cfg.blocked_metadata_hosts)
            .map_err(|errs| plugins_fetch_refusal(&errs))?;
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
    let plugin_registry = config_validate::check_with(
        &cfg,
        judged,
        config_validate::Check {
            plugins: &plugins_cfg,
            unset_env_vars: &[],
            root: &root_rules,
            fetch: wants_fetch.then_some(&fetch as &dyn Fn() -> Result<(), String>),
            resolve_builtins: false,
            secret_axis: config::secret::live_axis(),
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

    admitted_pin(&cfg, plugin_registry.as_ref())?;

    // The protected resources are the audiences of the recognized plane instances whose admitted
    // images serve HTTP routes (r3 section 2.3); the grammar carries that judgement. Taken here,
    // while `cfg` is whole.
    let protected_resources: Vec<String> =
        config::recognizer::plane_audiences(&cfg.instance_sections(), |instance| {
            cfg.grammar()
                .is_ok_and(|grammar| grammar.serves_http(instance))
        });

    let transition_requirements =
        governance::principal_transition::requirements(&cfg, plugin_registry.as_ref())?;

    let publication_generation = config::generation::reserve(prior).await?;
    // Only build_boot_app supplies opened_secrets: its retained root preparation owns
    // the exact already-opened bootstrap prefix and ServingReady. Full initial native
    // completion remains after NodeBook confirms the boot generation. Every runtime
    // rebuild instead requires its real early/late candidate producer here.
    let preparation = if opened_secrets.is_some() {
        if prior.is_some() || boot_store.is_none() {
            return Err("initial secret ownership requires the admitted boot Store".into());
        }
        None
    } else {
        rules.prepare_candidate(&cfg, &plugins_cfg).await?
    };
    let prepared_resolver = preparation
        .as_ref()
        .map(|preparation| preparation.secret_resolver());
    let secret_resolver = match (prepared_resolver, opened_secrets) {
        (Some(resolver), opened) => {
            if opened.is_some_and(|opened| !Arc::ptr_eq(&opened, &resolver)) {
                return Err("the candidate resolver differs from its opened secret owner".into());
            }
            resolver
        }
        (None, Some(resolver)) => resolver,
        (None, None) => rules.secret_resolver(&cfg, &plugins_cfg).await?,
    };

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
    let resolved_rates = config::card::CardRates {
        lanes,
        units,
        flat_minor: cfg.per_request_fee,
        present: cfg.rate_card.is_some(),
        plane_fees: cfg.plane_fees.clone(),
    };
    // #359 SEC-L1: a root listener served in the clear under its acceptance is bannered and audited
    // (before `cfg.models` moves out below).
    crate::config::listener_acceptance::announce(&cfg);
    let plaintext_listeners: Vec<&'static str> = crate::config::listener_acceptance::accepted(&cfg)
        .into_iter()
        .map(|(listener, _)| listener.setting)
        .collect();

    let llm_configured = !cfg.providers.is_empty() || !cfg.models.is_empty();
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

    let supported = supported_provider_dialects(grammar.prepared().map(|read| &**read));
    let mut lane_inputs: Vec<LaneInput> = Vec::new();
    for (idx, ld) in lanes_data.iter().enumerate() {
        let provider_cfg = lane_provider_cfgs[idx];

        if let Some(refusal) =
            provider_protocol_refusal(&supported, &ld.route, provider_cfg.dialect())
        {
            return Err(refusal);
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

    if let Some(banner) = open_relay_banner(auth_cfg.chain.is_empty()) {
        eprintln!("[error] {banner}");
        diag_error!(OPEN_RELAY_NO_AUTH, "{banner}");
    }

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

    let mut rotate_gov_credentials: Option<GovCredentialRotation> = None;

    let governance = if let Some(p) = prior {
        if let Some(gs) = p.governance.clone() {
            let transition_holds = governance::principal_transition::guard_native(
                gs.core_store_handle().map_err(|error| error.to_string())?,
                &{
                    let seal = crate::seal::acquire();
                    let fingerprint = governance::principal_transition::store_fingerprint(
                        &cfg.store.as_ref().map(|store| store.authoring(&seal)),
                    )?;
                    fingerprint
                },
                &transition_requirements,
            )
            .await?;
            // This is deny-only state from a completed receipt, never an authority grant.
            gs.install_transition_self_holds(transition_holds);
            let auth = cfg.auth.as_ref();
            let signer = match auth.and_then(|a| a.signing_key.as_ref()) {
                Some(_) => Some(resolve_signing_key(auth, &secret_resolver)?),
                None => None,
            };
            if signer.is_some() {
                rotate_gov_credentials = Some(Box::pin(async move {
                    if let Some(signer) = signer {
                        let sealed = signer.is_some();
                        gs.set_signing_key(signer);
                        if sealed {
                            rewrap_at_rest(&gs).await;
                        }
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
            &{
                let seal = crate::seal::acquire();
                let fingerprint = governance::principal_transition::store_fingerprint(
                    &cfg.store.as_ref().map(|store| store.authoring(&seal)),
                )?;
                fingerprint
            },
            &transition_requirements,
        )
        .await?;

        let signer = resolve_signing_key(cfg.auth.as_ref(), &secret_resolver)?;
        let sealed = signer.is_some();

        // The operator credential is the operator row's own instance (OPERATOR-FROM-ADMITTED-AUTH
        // §3.8): core holds no operator token digest.
        match governance::GovState::new_with_core(core, None, signer).await {
            Ok(gs) => {
                gs.install_transition_self_holds(transition_holds);
                let gs = Arc::new(gs);

                if sealed {
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
                if let Some(banner) = inert_durable_keys_banner(
                    !ephemeral,
                    key_count,
                    auth_cfg
                        .chain
                        .iter()
                        .any(|entry| entry.module == config::KEYS_MODULE),
                ) {
                    eprintln!("[error] {banner}");
                    diag_error!(DURABLE_KEYS_INERT, "{banner}");
                }
                Some(gs)
            }
            Err(e) => return Err(format!("governance init failed: {e}")),
        }
    };

    // Construct serving consumers only after the complete Store governance owner exists.
    // One instance per identity provider for this build, shared by every role that names it
    // (WASTE-AUTH-SECRETS W1): the chain, admin_auth and the hosted login methods look it up.
    // Carried across builds (W2): an instance whose inputs are unchanged and that reports
    // `reusable()` is handed over from the prior App, not opened again.
    let mut auth_instances = crate::auth::instances::AuthInstances::carrying(
        prior.map(|p| Arc::clone(&p.auth_instances)),
    );
    let open_auth_axis = || crate::preflight::auth_axis(plugin_registry.clone());
    let auth_mw = Arc::new(
        AuthMiddleware::build_on(
            &auth_cfg,
            plugin_registry.as_ref(),
            &secret_resolver,
            &mut auth_instances,
            &open_auth_axis,
        )
        .map_err(|e| format!("auth chain construction failed: {e}"))?,
    );

    let admin_modules = crate::auth::AdminAuthChain::build_on(
        &auth_cfg,
        plugin_registry.as_ref(),
        &secret_resolver,
        &mut auth_instances,
        &open_auth_axis,
    )
    .map_err(|e| format!("admin auth chain construction failed: {e}"))?;

    let login_methods = Arc::new(
        crate::auth::login::LoginMethods::build_on(
            &auth_cfg,
            plugin_registry.as_ref(),
            &secret_resolver,
            &mut auth_instances,
            &open_auth_axis,
        )
        .map_err(|e| format!("auth.methods (hosted login) construction failed: {e}"))?,
    );
    let auth_instances = auth_instances.sealed();

    if prior.is_none() {
        accepted_operator(&auth_cfg, &admin_modules.operator);
    }
    let admin_modules = Arc::new(admin_modules);

    let route_decls =
        crate::export::route_projection(&cfg_export, prior.map(|app| app.exports.as_ref()));
    let plugin_routes = std::sync::Arc::new(crate::plugin_routes::build_route_table(route_decls)?);

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
    let mut tslots = telemetry::AppSlots::build(
        &ts_pools,
        &ts_by_model,
        |idx| lane_inputs.get(idx).map(|lane| lane.model.as_str()),
        crate::plane_driver::dispatch::fallback_key(),
    );
    tslots.attach_lane_durations(
        |idx| lane_inputs.get(idx).map(|lane| lane.model.as_str()),
        |idx| lane_inputs.get(idx).map(|lane| lane.provider.as_str()),
        crate::telemetry::max_lane_series(),
    );
    let tslots = Arc::new(tslots);

    let config_tables = Arc::new(busbar_kernel::plane_driver::route_tables::ConfigTables::of(
        &lane_inputs,
        &pool_inputs,
        &by_model,
        cfg.upstream_credentials,
        llm_configured,
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

            let store = governance
                .as_ref()
                .ok_or_else(config::store_required)?
                .core_store_handle()
                .map_err(|error| format!("oauth_as store: {error}"))?;
            Some(
                (seam.build)(
                    checked.block.clone(),
                    secrets,
                    protected_resources,
                    prior.and_then(state::App::oauth_as_any).cloned(),
                    store,
                    checked.admin_origin.clone(),
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

    let plugin_registry = plugin_registry.clone();
    let hook_registry = cfg.hooks.clone();
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
    let login_guard = prior.map_or_else(
        || Arc::new(crate::auth::login_limits::LoginGuard::default()),
        |p| p.login_guard.clone(),
    );
    login_guard.configure(cfg.login_limits.clone());
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
    let mut planes_awaiting_restart: Vec<String> = planes_awaiting_restart
        .iter()
        .map(|section| (*section).to_string())
        .collect();
    // A used plane section or auth style whose file was replaced in place keeps serving under the
    // running image; the new image takes effect at the next restart (SECRET-SHORTHAND-BOOT §3.6).
    if let (Ok(grammar), Ok(used)) = (cfg.grammar.get(), cfg.grammar.used()) {
        for item in grammar.replaced() {
            let entry = match item.kind {
                config::grammar::ItemKind::Section if used.sections.contains(&item.name) => {
                    item.name.clone()
                }
                config::grammar::ItemKind::Style if used.styles.contains(&item.name) => {
                    format!("auth style {}", item.name)
                }
                _ => continue,
            };
            if !planes_awaiting_restart.contains(&entry) {
                planes_awaiting_restart.push(entry);
            }
        }
        planes_awaiting_restart.sort();
    }
    let mut app = App::assemble(
        crate::state::AppParts {
            limits,
            serve_tables,
            port_seats: prior.map(|app| app.port_seats.clone()).unwrap_or_default(),
            exports: prior
                .map(|app| Arc::clone(&app.exports))
                .unwrap_or_default(),
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
            plugin_registry,
            hook_registry,
            global_hooks,
            groups_registry,
            base_group_names,
            identity_providers,
            export_defs,
            admin,
            base_hook_names,
            admin_chain,
            admin_modules,
            auth_instances,
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
        login_guard,
    );
    if let Some(prior) = prior {
        app.config_generation = Arc::clone(&prior.config_generation);
    }
    app.publication_generation = publication_generation;
    app.selected_predecessor = prior.and_then(|prior| prior.selected_policy.clone());
    app.configured_view = Some(configured_view);
    app.operator_file_defs = operator_file_defs;
    app.grammar = grammar;
    app.plaintext_listeners = plaintext_listeners;
    if let Some(preparation) = preparation {
        preparation.finish(&mut app).await?;
    }
    rules.check_built(&mut app)?;
    if let Some(paths) = rules.mounted_plugin_paths(&app) {
        app.boot_route_paths = Arc::new(paths);
    }

    for decl in crate::plane_driver::registry::plane_decls() {
        if let Some(retain) = decl.retain_verify_gates {
            retain(&app);
        }
    }

    // Existing direct builders pass an explicit providers path. The executable replaces this
    // initial default with its actual CLI/env provenance; subsequent generations inherit it.
    if let Some(prior) = prior {
        app.providers_override.clone_from(&prior.providers_override);
    }
    app.config_pending_restart = prior
        .map(|app| app.config_pending_restart.clone())
        .unwrap_or_default();
    // Export membership is restart-only: recompute its markers against the retained boot
    // instances, so a reverted or withdrawn candidate cannot leave a stale requirement.
    app.config_pending_restart
        .retain(|path| !path.starts_with("export."));
    app.boot_restart_root = prior.and_then(|app| app.boot_restart_root.clone());
    app.boot_restart_source = prior.and_then(|app| app.boot_restart_source.clone());
    if let Some(boot) = &app.boot_restart_root {
        app.config_pending_restart
            .extend(restart_candidate.changed(boot));
    } else {
        app.boot_restart_root = Some(Arc::new(restart_candidate));
    }
    if let Some(prior) = prior {
        app.config_pending_restart
            .extend(crate::plugin_routes::paths_awaiting_restart(
                &app.plugin_routes,
                &prior.plugin_routes,
                &app.boot_route_paths,
            ));
        let exports: std::collections::BTreeSet<_> = app
            .export_defs
            .keys()
            .chain(app.exports.sinks.iter().map(|sink| &sink.name))
            .cloned()
            .collect();
        for name in exports {
            if crate::export::plugin::requires_restart(
                &app.exports,
                &name,
                app.export_defs.get(&name),
                app.grammar.read_context().as_deref(),
            ) {
                app.config_pending_restart.push(format!("export.{name}"));
            }
        }
    }
    app.config_pending_restart.sort();
    app.config_pending_restart.dedup();
    app.require_if_match = cfg
        .auth
        .as_ref()
        .and_then(|a| a.require_if_match)
        .unwrap_or(false);
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

#[cfg(test)]
#[path = "tests/plugins_fetch_refusal_tests.rs"]
mod plugins_fetch_refusal_tests;

#[cfg(test)]
#[path = "tests/provider_protocol_tests.rs"]
mod provider_protocol_tests;

/// The dialects a provider's `protocol` may name in this build: those the registered planes list.
fn supported_provider_dialects(_read: Option<&config::grammar::PreparedConfigRead>) -> Vec<&str> {
    crate::plane_driver::dispatch::provider_dialects()
}

/// A lane whose provider names a protocol outside `supported` is refused, naming the supported ones.
fn provider_protocol_refusal(supported: &[&str], provider: &str, protocol: &str) -> Option<String> {
    if supported.contains(&protocol) {
        return None;
    }
    Some(format!(
        "provider '{provider}' uses unknown protocol '{protocol}' (supported: {})",
        supported.join(", ")
    ))
}

/// The boot's `auth.operator.accepted` rows (OPERATOR-FROM-ADMITTED-AUTH §3.10): one per
/// operator-backed admin provider whose instance opened, naming the operator row that backs it.
fn accepted_operator(auth: &config::AuthCfg, operator: &crate::auth::Operator) {
    let Ok(Ok(Some(claim))) = busbar_kernel_identity::operator::judged().map(|j| j.words.as_ref())
    else {
        return;
    };
    for entry in auth
        .admin_auth
        .iter()
        .filter(|e| operator.instance(&e.name).is_some())
    {
        crate::audit::auditlog::record_operator(
            crate::audit::auditlog::OperatorAudit::Accepted,
            &entry.name,
            &format!(
                "{} {} {} {}",
                claim.canonical, claim.version, claim.signer, claim.principal
            ),
        );
    }
}
