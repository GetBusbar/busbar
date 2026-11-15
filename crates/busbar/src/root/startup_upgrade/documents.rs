// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Original authored bytes stay in custody across bootstrap and source-proven conversion.
use busbar_contract::crypto::Sha256;
use busbar_contract::secure::{SecureString, SecureVec};
use busbar_contract::yaml::ValueExt as _;
use busbar_kernel::{
    appbuild::{ConfigDocument, RootRules},
    config,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use zeroize::Zeroize;

struct Document {
    kind: ConfigDocument,
    original: SecureString,
    converted: Option<SecureString>,
    published: bool,
    requires_released_source: bool,
    restored_transform: Option<[u8; 32]>,
    runtime_only: bool,
    /// An unnamed default file that is absent ([`config::providers::CatalogSource::AbsentDefault`]):
    /// its empty form is both original and target, and its file is never inspected as present,
    /// published or created.
    absent: bool,
}

/// Complete document inventory, including unchanged documents. Debug is deliberately absent.
pub(crate) struct Publication {
    pub path: PathBuf,
    pub original: SecureVec,
    pub converted: SecureVec,
    pub original_digest: [u8; 32],
    pub target_digest: [u8; 32],
    pub transform_id: [u8; 32],
    pub locked: bool,
    /// The intent binds that this document's file is absent; one that appears is a changed source.
    pub absent: bool,
}

/// A protected artifact to materialize only after its native/Store intent is Applied.
/// Raw material is never included in logs, fingerprints or diagnostic formatting.
pub(crate) struct SecretPublication {
    pub config_path: PathBuf,
    pub site: String,
    pub settings_path: Vec<String>,
    pub bytes: SecureVec,
    pub path: PathBuf,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Phase {
    #[default]
    Structural,
    Released(
        [u8; 32],
        busbar_contract::persistence::lifecycle::DocumentSemantics,
    ),
    Current,
}
#[derive(Default)]
struct State {
    documents: BTreeMap<PathBuf, Document>,
    secrets: BTreeMap<PathBuf, SecretPublication>,
    phase: Phase,
    revision: u64,
    locked: bool,
    source_binding: Option<[u8; 32]>,
    source_profile: Option<busbar_contract::persistence::lifecycle::DocumentSemantics>,
    config_proofs: BTreeMap<[u8; 32], busbar_migrations::config::HistoricalShape>,
    secret_binding: Option<[u8; 32]>,
    /// The decisions behind the last refused deployment normalization, wiped on drop.
    debt: Option<Vec<SecureString>>,
}
#[derive(Default)]
pub(crate) struct Documents {
    state: Mutex<State>,
    environment: Mutex<BTreeMap<String, Option<SecureString>>>,
    /// Startup conversion notices raised before the log is installed, replayed by
    /// [`Documents::replay_notices`] so none is silently dropped.
    notices: Mutex<Vec<String>>,
}

impl Documents {
    /// Report a startup conversion notice (an authored key and fixed text, never a value) at WARN:
    /// now when the log is installed, else held for [`Documents::replay_notices`].
    pub(crate) fn notice(&self, notice: &str) {
        if tracing::dispatcher::has_been_set() {
            tracing::warn!(change = %notice, "startup converted a 1.5.5 configuration value");
        } else if let Ok(mut held) = self.notices.lock() {
            held.push(notice.to_owned());
        }
    }

    /// Log every notice held from before the log was installed. Called once logging starts.
    pub(crate) fn replay_notices(&self) {
        let held = self
            .notices
            .lock()
            .map(|mut held| std::mem::take(&mut *held))
            .unwrap_or_default();
        for notice in held {
            tracing::warn!(change = %notice, "startup converted a 1.5.5 configuration value");
        }
    }

    fn captured_env(&self, key: &str) -> Option<String> {
        let mut captured = self
            .environment
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        captured
            .entry(key.to_owned())
            .or_insert_with(|| std::env::var(key).ok().map(SecureString::from))
            .as_ref()
            .map(|value| value.as_str().to_owned())
    }

    pub(crate) fn normalize(
        self: &Arc<Self>,
        kind: ConfigDocument,
        path: &Path,
        raw: &str,
    ) -> Result<Option<SecureString>, String> {
        let (phase, revision, original) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "configuration custody failed")?;
            if state.phase == Phase::Current {
                if let Some(entry) = state.documents.get(path) {
                    if entry.kind != kind {
                        return Err(
                            "one file cannot be deployment and provider configuration".into()
                        );
                    }
                    if raw == entry.original.as_str() {
                        let converted = entry
                            .converted
                            .as_ref()
                            .ok_or("completed configuration is missing its retained output")?;
                        return Ok((converted.as_str() != raw).then(|| converted.clone()));
                    }
                }
                // New runtime edits must satisfy the real current reader. The frozen
                // startup source proof does not establish their historical semantics.
                return Ok(None);
            } else {
                let entry = state
                    .documents
                    .entry(path.to_owned())
                    .or_insert_with(|| Document {
                        kind,
                        original: SecureString::from(raw),
                        converted: None,
                        published: false,
                        requires_released_source: false,
                        restored_transform: None,
                        runtime_only: false,
                        absent: false,
                    });
                if entry.kind != kind {
                    return Err("one file cannot be deployment and provider configuration".into());
                }
                // A file that appeared where this startup retained an absent default is changed.
                if entry.absent
                    || (raw != entry.original.as_str()
                        && !(entry.published
                            && entry.converted.as_ref().is_some_and(|v| v.as_str() == raw)))
                {
                    return Err("configuration changed during startup migration".into());
                }
                if let Some(converted) = &entry.converted {
                    return Ok((converted.as_str() != raw).then(|| converted.clone()));
                }
                let original = entry.original.clone();
                (state.phase, state.revision, original)
            }
        };
        // No custody mutex is held across plugin callbacks, catalogue staging or I/O.
        let mut detected_locked = false;
        let mut runtime_only = false;
        let (converted, requires_released_source) = match kind {
            ConfigDocument::Deployment => {
                let mut unset = Vec::new();
                let detection = SecureString::from(
                    config::interpolate_env_lookup(
                        &original,
                        config::EnvSubst::Lenient,
                        &mut unset,
                        |key| self.captured_env(key),
                    )
                    .map_err(|_| "configuration detection interpolation refused")?,
                );
                detected_locked =
                    busbar_contract::yaml::from_str::<busbar_contract::yaml::Value>(&detection)
                        .ok()
                        .and_then(|doc| match doc.get("config")?.get("locked")? {
                            busbar_contract::yaml::Value::Bool(locked) => Some(*locked),
                            _ => None,
                        })
                        .unwrap_or(false);
                // OPERATOR-FROM-ADMITTED-AUTH §3.4.1: a deferred start binds the operator from
                // pass 1's converted `plugins:` view (a fresh host, the same inputs) before pass 2.
                if crate::root::boot::plugins_block_is_historical()
                    && busbar_kernel_identity::operator::judged().is_err()
                {
                    let pass1 = crate::root::config_migrate::RootHost::for_startup_document(
                        &original,
                        &detection,
                        path,
                        self.clone(),
                    )?;
                    crate::root::auth_bindings::bind_from_upgraded_view(&original, &pass1)
                        .map_err(|_| {
                            "the startup upgrade could not bind the operator credential from its \
                             converted plugins: view"
                        })?;
                }
                let host = crate::root::config_migrate::RootHost::for_startup_document(
                    &original,
                    &detection,
                    path,
                    self.clone(),
                )?;
                let authored_profile =
                    busbar_migrations::config::recognize_authored_schema(&original)
                        .map_err(|_| "historical configuration grammar detection refused")?;
                let mut output = if let Some(proof) = authored_profile {
                    busbar_migrations::config::normalize_historical_config(&proof, &original, &host)
                } else if let Phase::Released(_, profile) = phase {
                    busbar_migrations::config::normalize_supported_source(profile, &original, &host)
                } else {
                    busbar_migrations::config::normalize_authored_with_detection(
                        &original,
                        Some(&detection),
                        &host,
                    )
                }
                .map_err(|_| {
                    "supported configuration normalization refused the authored document"
                })?;
                runtime_only = host.runtime_only();
                let debt = output.todos.len();
                // Only the decision paths leave in the refusal text: never a reason or a value.
                let decisions = output.decision_paths().join(", ");
                // Change lines may quote interpolated values and are zeroized; a notice holds only
                // an authored key and fixed text, so the operator sees it at WARN.
                for notice in &output.notices {
                    self.notice(notice);
                }
                output.changes.zeroize();
                output.warnings.zeroize();
                if debt != 0 {
                    output.yaml.zeroize();
                    // The reasons stay in custody for the boot refusal to explain itself.
                    let todos: Vec<SecureString> =
                        output.todos.drain(..).map(SecureString::from).collect();
                    if let Ok(mut state) = self.state.lock() {
                        state.debt = Some(todos);
                    }
                    return Err(debt_refusal(debt, &decisions));
                }
                output.todos.zeroize();
                (SecureString::from(output.yaml), false)
            }
            ConfigDocument::Providers => {
                let mut unset = Vec::new();
                let detection = SecureString::from(
                    config::interpolate_env_lookup(
                        &original,
                        config::EnvSubst::Lenient,
                        &mut unset,
                        |key| self.captured_env(key),
                    )
                    .map_err(|_| "providers detection interpolation refused")?,
                );
                if config::providers::catalog_from_str(&detection).is_ok() {
                    (original.clone(), false)
                } else {
                    let output = busbar_migrations::config::migrate_catalog::migrate_catalog(
                        &original,
                        "providers configuration",
                    )
                    .map_err(|_| "providers normalization refused the authored document")?;
                    match output {
                        Some(mut output) => {
                            output.changes.zeroize();
                            (SecureString::from(output.yaml), true)
                        }
                        None => (original.clone(), false),
                    }
                }
            }
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        if state.phase != phase || state.revision != revision {
            return Err("configuration phase changed during normalization".into());
        }
        state.locked |= detected_locked;
        if kind == ConfigDocument::Deployment {
            if let Ok(doc) =
                busbar_contract::yaml::from_str::<busbar_contract::yaml::Value>(&converted)
            {
                state.locked |= doc
                    .get("config")
                    .and_then(|c| c.get("locked"))
                    .and_then(|locked| match locked {
                        busbar_contract::yaml::Value::Bool(locked) => Some(*locked),
                        _ => None,
                    })
                    .unwrap_or(false);
            }
        }
        let entry = state
            .documents
            .get_mut(path)
            .ok_or("configuration custody disappeared")?;
        if entry.original.as_str() != original.as_str() {
            return Err("configuration custody changed".into());
        }
        let answer = (converted.as_str() != raw).then(|| converted.clone());
        entry.runtime_only = runtime_only;
        entry.converted = Some(converted);
        entry.requires_released_source = requires_released_source;
        Ok(answer)
    }

    /// Retain an unnamed default document the loader found absent
    /// ([`config::providers::CatalogSource::AbsentDefault`]). Its empty form is original and
    /// target alike, so planning, the fingerprint, the intent and the commit all see one
    /// unchanged document whose file stays absent. A file that existed earlier in this startup,
    /// or appears later, is a changed source.
    pub(crate) fn absent(&self, kind: ConfigDocument, path: &Path) -> Result<(), String> {
        if kind != ConfigDocument::Providers {
            return Err("only the default provider catalog may be absent".into());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        if state.phase == Phase::Current {
            // A runtime reload of an absent default reads the empty catalog: a current input.
            return Ok(());
        }
        let empty = SecureString::from(config::providers::CatalogSource::AbsentDefault.text());
        let entry = state
            .documents
            .entry(path.to_owned())
            .or_insert_with(|| Document {
                kind,
                original: empty.clone(),
                converted: Some(empty.clone()),
                published: false,
                requires_released_source: false,
                restored_transform: None,
                runtime_only: false,
                absent: true,
            });
        if entry.kind != kind {
            return Err("one file cannot be deployment and provider configuration".into());
        }
        if !entry.absent {
            return Err("configuration changed during startup migration".into());
        }
        entry.converted = Some(empty);
        Ok(())
    }

    /// The unresolved decisions behind the last refused deployment normalization. Taken once:
    /// a second call returns `None`.
    pub(crate) fn take_debt(&self) -> Option<Vec<SecureString>> {
        self.state.lock().ok()?.debt.take()
    }

    /// The migration owner alone constructs this proof from actual native inspection.
    /// Frozen settings semantics follow the admitted native profile, without inventing a release.
    pub(crate) fn enter_released_source(
        &self,
        proof: &busbar_migrations::ReleasedSourceProof,
    ) -> Result<(), String> {
        let source = proof.source();
        let mut binding = Sha256::new();
        binding.update(b"busbar.startup.config-source.1\0");
        binding.update(&source.native_anchor[..]);
        binding.update(&source.dataset.0[..]);
        binding.update(&source.catalogue_digest[..]);
        binding.update(&source.layout_digest[..]);
        if let Some(format) = source.format {
            binding.update(&format.owner[..]);
            binding.update(&format.physical.to_be_bytes());
            binding.update(&format.logical.to_be_bytes());
            binding.update(&format.codec.to_be_bytes());
        }
        binding.update(&proof.reader().decoder_digest()[..]);
        binding.update(&[match proof.documents() {
            busbar_contract::persistence::lifecycle::DocumentSemantics::Historical => 0,
            busbar_contract::persistence::lifecycle::DocumentSemantics::Current => 1,
        }]);
        self.enter_released_binding(binding.finish(), proof.documents())
    }

    /// Phase entry is wired below to the migration coordinator's opaque source proof.
    fn enter_released_binding(
        &self,
        binding: [u8; 32],
        profile: busbar_contract::persistence::lifecycle::DocumentSemantics,
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        match state.phase {
            Phase::Released(existing, existing_profile)
                if existing == binding && existing_profile == profile =>
            {
                return Ok(());
            }
            Phase::Structural => {}
            _ => {
                return Err(
                    "configuration source phase cannot change its established binding".into(),
                );
            }
        }
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or("configuration phase exhausted")?;
        state.phase = Phase::Released(binding, profile);
        state.source_binding = Some(binding);
        state.source_profile = Some(profile);
        for entry in state
            .documents
            .values_mut()
            .filter(|entry| !entry.published && entry.restored_transform.is_none() && !entry.absent)
        {
            entry.converted = None;
            entry.requires_released_source = false;
        }
        Ok(())
    }

    /// Close historical conversion after validated adoption; subsequent reloads are current inputs.
    pub(crate) fn finish_upgrade(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        if state.phase == Phase::Current {
            return Ok(());
        }
        if state
            .documents
            .values()
            .any(|entry| entry.converted.is_none())
        {
            return Err("configuration phase has not reloaded every original source".into());
        }
        if !has_historical_semantics(&state)
            && state
                .documents
                .values()
                .any(|entry| entry.requires_released_source)
        {
            return Err(
                "configuration conversion still requires released-source provenance".into(),
            );
        }
        let revision = state
            .revision
            .checked_add(1)
            .ok_or("configuration phase exhausted")?;
        state.phase = Phase::Current;
        self.environment
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        state.secret_binding = Some(secret_fingerprint(&state.secrets));
        state.secrets.clear();
        state.revision = revision;
        Ok(())
    }

    pub(crate) fn admit_config_profile(
        &self,
        proof: &busbar_migrations::config::HistoricalConfigProof,
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        if state.phase == Phase::Current {
            return Err(
                "completed startup cannot acquire new historical settings authority".into(),
            );
        }
        state.config_proofs.insert(proof.binding(), proof.shape());
        Ok(())
    }

    /// Interpolate retained normalization output under only this startup's captured references.
    pub(crate) fn interpolate_captured(&self, raw: &str) -> Result<SecureString, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        if state.phase == Phase::Current {
            return Err("historical environment custody is closed".into());
        }
        drop(state);
        config::interpolate_env_lookup(raw, config::EnvSubst::Strict, &mut Vec::new(), |key| {
            self.captured_env(key)
        })
        .map(SecureString::from)
        .map_err(|_| "captured configuration interpolation refused".into())
    }

    /// The exact frozen authored deployment and a detection view under this startup's
    /// captured environment. Neither may be replaced by a re-read of a partially published file.
    pub(crate) fn original_deployment(
        &self,
        path: &Path,
    ) -> Result<(SecureString, SecureString), String> {
        let authored = {
            let state = self
                .state
                .lock()
                .map_err(|_| "configuration custody failed")?;
            if state.phase == Phase::Current {
                return Err("historical deployment custody is closed".into());
            }
            let document = state
                .documents
                .get(path)
                .ok_or("deployment is outside startup custody")?;
            if document.kind != ConfigDocument::Deployment {
                return Err("requested source is not deployment configuration".into());
            }
            document.original.clone()
        };
        let detection = SecureString::from(
            config::interpolate_env_lookup(
                &authored,
                config::EnvSubst::Lenient,
                &mut Vec::new(),
                |key| self.captured_env(key),
            )
            .map_err(|_| "captured deployment detection interpolation refused")?,
        );
        Ok((authored, detection))
    }

    /// Compare every Store field after reversing only secret representation changes
    /// bound to this exact retained document and its protected artifact intents.
    pub(crate) fn bootstrap_equivalent(
        &self,
        original: &Option<config::StoreCfg>,
        target: &Option<config::StoreCfg>,
        config_path: &Path,
    ) -> Result<bool, String> {
        let sources =
            busbar_contract::secret::SecretAxis::sugars(crate::root::linked::secret_rows());
        self.bootstrap_equivalent_with_sources(original, target, config_path, &sources)
    }

    fn bootstrap_equivalent_with_sources(
        &self,
        original: &Option<config::StoreCfg>,
        target: &Option<config::StoreCfg>,
        config_path: &Path,
        sources: &busbar_contract::secret_ref::Sugars,
    ) -> Result<bool, String> {
        let (Some(original), Some(target)) = (original, target) else {
            return Ok(original.is_none() && target.is_none());
        };
        let (authored, detection) = self.original_deployment(config_path)?;
        let templates = busbar_migrations::config::templates::ResolvedTemplates::from_yaml(
            &authored, &detection,
        )?;
        let authored: busbar_contract::yaml::Value = busbar_contract::yaml::from_str(&authored)
            .map_err(|_| "retained Store source is invalid")?;
        let mut target = target.clone();
        let state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        let mut settings =
            serde_json::to_value(target.settings.authoring(&busbar_kernel::seal::acquire()))
                .map_err(|_| "Store comparison settings encoding failed")?;
        for secret in state
            .secrets
            .values()
            .filter(|secret| secret.config_path == config_path && secret.site == "store.settings")
        {
            let Some(slot) = json_slot_mut(&mut settings, &secret.settings_path) else {
                continue;
            };
            let expected = sources.reference_for_role(
                busbar_contract::abi::mechanism::door::SUGAR_ROLE_PATH,
                secret
                    .path
                    .to_str()
                    .ok_or("staged Store credential path is not UTF-8")?,
            )?;
            if serde_json::from_value::<busbar_contract::secret_ref::SecretRef>(slot.clone())
                .ok()
                .as_ref()
                != Some(&expected)
            {
                continue;
            }
            let value = std::str::from_utf8(&secret.bytes)
                .map_err(|_| "staged Store credential is not text")?;
            *slot = serde_json::Value::String(value.to_owned());
        }
        // Env refs are admitted only at the identical authored scalar path. The
        // captured YAML scalar, never a new environment read, supplies its value.
        fn env_refs(
            target: &mut serde_json::Value,
            authored: &busbar_contract::yaml::Value,
            templates: &busbar_migrations::config::templates::ResolvedTemplates,
            sources: &busbar_contract::secret_ref::Sugars,
        ) -> Result<(), String> {
            if let Some(text) = authored.as_str() {
                if text.contains("${")
                    && serde_json::from_value::<busbar_contract::secret_ref::SecretRef>(
                        target.clone(),
                    )
                    .ok()
                        == Some(busbar_contract::secret_ref::SecretRef::template(
                            text, sources,
                        )?)
                {
                    if let Some(value) = templates.scalar(text)? {
                        *target = value;
                    }
                    return Ok(());
                }
                if let Some(variable) = text
                    .strip_prefix("${")
                    .and_then(|text| text.strip_suffix('}'))
                    .filter(|text| !text.is_empty() && !text.contains(['{', '}']))
                {
                    if serde_json::from_value::<busbar_contract::secret_ref::SecretRef>(
                        target.clone(),
                    )
                    .ok()
                        == Some(sources.reference_for_role(
                            busbar_contract::abi::mechanism::door::SUGAR_ROLE_FILL,
                            variable,
                        )?)
                    {
                        if let Some(value) = templates.scalar(text)? {
                            *target = value;
                        }
                    }
                }
                return Ok(());
            }
            if let Some(values) = target.as_object_mut() {
                for (key, value) in values {
                    if let Some(source) = authored.get(key) {
                        env_refs(value, source, templates, sources)?;
                    }
                }
            }
            Ok(())
        }
        if let Some(source) = authored
            .get("store")
            .and_then(|store| store.get("settings"))
        {
            env_refs(&mut settings, source, &templates, sources)?;
        }
        target.settings = settings
            .as_object_mut()
            .map(std::mem::take)
            .ok_or("Store comparison settings are invalid")?
            .into();
        let original = serde_json::to_value(original.authoring(&busbar_kernel::seal::acquire()))
            .map_err(|_| "Store comparison encoding failed")?;
        let target = serde_json::to_value(target.authoring(&busbar_kernel::seal::acquire()))
            .map_err(|_| "Store comparison encoding failed")?;
        Ok(original == target)
    }

    /// The retained provider source: its path, and its authored text unless the default file is
    /// absent (`None`, read as [`config::providers::CatalogSource::AbsentDefault`]).
    pub(crate) fn original_provider(
        &self,
    ) -> Result<Option<(PathBuf, Option<SecureString>)>, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        let mut entries = state
            .documents
            .iter()
            .filter(|(_, entry)| entry.kind == ConfigDocument::Providers);
        let Some((path, entry)) = entries.next() else {
            return Ok(None);
        };
        if entries.next().is_some() {
            return Err("startup provider source is ambiguous".into());
        }
        Ok(Some((
            path.clone(),
            (!entry.absent).then(|| entry.original.clone()),
        )))
    }

    pub(crate) fn stage_catalog(
        &self,
        path: &Path,
        raw: &str,
        converted: &str,
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        if !has_historical_semantics(&state) {
            return Err("catalog conversion requires historical config or native semantics".into());
        }
        let entry = state
            .documents
            .entry(path.to_owned())
            .or_insert_with(|| Document {
                kind: ConfigDocument::Providers,
                original: SecureString::from(raw),
                converted: None,
                published: false,
                requires_released_source: true,
                restored_transform: None,
                runtime_only: false,
                absent: false,
            });
        if entry.kind != ConfigDocument::Providers || entry.absent || entry.original.as_str() != raw
        {
            return Err("providers source changed during conversion".into());
        }
        if entry
            .converted
            .as_ref()
            .is_some_and(|current| current.as_str() != converted)
        {
            return Err("providers conversion target changed within one source phase".into());
        }
        entry.converted = Some(SecureString::from(converted));
        entry.requires_released_source = true;
        Ok(())
    }

    pub(crate) fn stage_secret(&self, secret: SecretPublication) -> Result<String, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        if state.source_profile.is_none() && state.config_proofs.is_empty() {
            return Err(
                "credential staging requires historical config or settings evidence".into(),
            );
        }
        let path = secret
            .path
            .to_str()
            .ok_or("credential artifact path must be UTF-8")?
            .to_owned();
        if let Some(existing) = state.secrets.get(&secret.path) {
            if existing.config_path != secret.config_path
                || existing.site != secret.site
                || existing.settings_path != secret.settings_path
                || existing.bytes.as_slice() != secret.bytes.as_slice()
            {
                return Err("credential artifact intent changed".into());
            }
        } else {
            state.secrets.insert(secret.path.clone(), secret);
        }
        Ok(path)
    }

    pub(crate) fn pending_secrets(&self) -> Result<Vec<SecretPublication>, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        Ok(state
            .secrets
            .values()
            .map(|s| SecretPublication {
                config_path: s.config_path.clone(),
                site: s.site.clone(),
                settings_path: s.settings_path.clone(),
                bytes: s.bytes.clone(),
                path: s.path.clone(),
            })
            .collect())
    }

    /// Restore only an inventory authenticated by the real checkpoint owner.
    /// A disk file may be its protected original or exact target after a partial publish.
    pub(crate) fn restore_from_checkpoint(
        &self,
        input: super::document_commit::RestoredDocuments<'_>,
    ) -> Result<(), String> {
        let (observed, phase, revision) = {
            let state = self
                .state
                .lock()
                .map_err(|_| "configuration custody failed")?;
            let observed: BTreeMap<_, _> = state
                .documents
                .iter()
                .map(|(path, entry)| {
                    let runtime = entry
                        .runtime_only
                        .then(|| (entry.original.clone(), entry.converted.as_ref().cloned()));
                    (path.clone(), (entry.kind, runtime, entry.absent))
                })
                .collect();
            (observed, state.phase, state.revision)
        };
        let mut restored = BTreeMap::new();
        let mut locked = false;
        for publication in input.publications() {
            let (kind, runtime, absent) = observed
                .get(&publication.path)
                .ok_or("checkpoint names an unobserved configuration source")?;
            let kind = *kind;
            // A retained absence and a file that is there now (or the reverse) are different sources.
            if publication.absent != *absent {
                return Err(
                    "configuration changed outside the protected publication checkpoint".into(),
                );
            }
            let original_digest: [u8; 32] =
                busbar_contract::crypto::sha256(publication.original.as_slice());
            let target_digest: [u8; 32] =
                busbar_contract::crypto::sha256(publication.converted.as_slice());
            if original_digest != publication.original_digest
                || target_digest != publication.target_digest
            {
                return Err(
                    "checkpoint configuration bytes do not match their protected digests".into(),
                );
            }
            let current = match std::fs::read(&publication.path) {
                Ok(bytes) => Some(SecureVec::from(bytes)),
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && (publication.absent || input.recoverable_missing(&publication.path)) =>
                {
                    None
                }
                Err(_) => return Err("checkpoint configuration source could not be read".into()),
            };
            if current.as_ref().is_some_and(|bytes| {
                publication.absent
                    || (bytes.as_slice() != publication.original.as_slice()
                        && bytes.as_slice() != publication.converted.as_slice())
            }) {
                return Err(
                    "configuration changed outside the protected publication checkpoint".into(),
                );
            }
            let original = SecureString::from(
                std::str::from_utf8(&publication.original)
                    .map_err(|_| "checkpoint source is not UTF-8")?,
            );
            let mut converted = SecureString::from(
                std::str::from_utf8(&publication.converted)
                    .map_err(|_| "checkpoint target is not UTF-8")?,
            );
            let published = current
                .as_ref()
                .is_some_and(|bytes| bytes.as_slice() == publication.converted.as_slice());
            let mut runtime_only = false;
            if publication.original.as_slice() == publication.converted.as_slice() {
                if let Some((authored, Some(current))) = runtime {
                    if authored.as_str() == original.as_str() {
                        converted = current.clone();
                        runtime_only = true;
                    }
                }
            }
            locked |= publication.locked;
            if restored
                .insert(
                    publication.path.clone(),
                    Document {
                        kind,
                        original,
                        converted: Some(converted),
                        published,
                        requires_released_source: matches!(phase, Phase::Released(_, _))
                            && kind == ConfigDocument::Providers
                            && !publication.absent,
                        restored_transform: Some(publication.transform_id),
                        runtime_only,
                        absent: publication.absent,
                    },
                )
                .is_some()
            {
                return Err("checkpoint repeats a configuration source".into());
            }
        }
        if restored.len() != observed.len() {
            return Err("checkpoint does not bind every observed configuration source".into());
        }
        let mut secrets = BTreeMap::new();
        for secret in input.secrets() {
            let expected = crate::root::loader::migration_secrets::externalized_path(
                &secret.config_path,
                &secret.site,
                &secret.settings_path,
            )?;
            if expected != secret.path || secrets.contains_key(&secret.path) {
                return Err("checkpoint credential artifact identity is invalid".into());
            }
            secrets.insert(
                secret.path.clone(),
                SecretPublication {
                    config_path: secret.config_path.clone(),
                    site: secret.site.clone(),
                    settings_path: secret.settings_path.clone(),
                    bytes: secret.bytes.clone(),
                    path: secret.path.clone(),
                },
            );
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        if state.phase != phase
            || state.revision != revision
            || state.documents.len() != observed.len()
        {
            return Err("configuration phase changed during checkpoint recovery".into());
        }
        state.revision = state
            .revision
            .checked_add(1)
            .ok_or("configuration phase exhausted")?;
        state.documents = restored;
        state.secrets = secrets;
        state.secret_binding = None;
        state.locked |= locked;
        Ok(())
    }

    pub(crate) fn pending(&self) -> Result<Vec<Publication>, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        let mut outputs = Vec::with_capacity(state.documents.len());
        for (path, entry) in &state.documents {
            let converted = entry
                .converted
                .as_ref()
                .ok_or("configuration phase must reload every original source before checkpoint")?;
            if entry.requires_released_source && !has_historical_semantics(&state) {
                return Err(
                    "provider conversion requires verified released Store provenance".into(),
                );
            }
            let converted = if entry.runtime_only {
                &entry.original
            } else {
                converted
            };
            let original_digest: [u8; 32] =
                busbar_contract::crypto::sha256(entry.original.as_bytes());
            let target_digest: [u8; 32] = busbar_contract::crypto::sha256(converted.as_bytes());
            let transform_id = entry.restored_transform.unwrap_or_else(|| {
                document_transform(
                    path,
                    entry.kind,
                    original_digest,
                    target_digest,
                    state.source_binding,
                    entry.absent,
                )
            });
            outputs.push(Publication {
                path: path.clone(),
                original: SecureVec::from(entry.original.as_bytes()),
                converted: SecureVec::from(converted.as_bytes()),
                original_digest,
                target_digest,
                transform_id,
                locked: state.locked,
                absent: entry.absent,
            });
        }
        Ok(outputs)
    }

    /// Record a completed native publication of this exact retained document pair.
    pub(crate) fn mark_published(&self, publication: &Publication) -> Result<(), String> {
        let expected = self
            .pending()?
            .into_iter()
            .find(|entry| entry.path == publication.path)
            .ok_or("published document is outside the retained inventory")?;
        if expected.transform_id != publication.transform_id {
            return Err("published document does not match the retained transform".into());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        let entry = state
            .documents
            .get_mut(&publication.path)
            .ok_or("published source custody disappeared")?;
        let actual_original: [u8; 32] = busbar_contract::crypto::sha256(entry.original.as_bytes());
        if actual_original != publication.original_digest
            || entry.converted.as_ref().is_none_or(|target| {
                let target = if entry.runtime_only {
                    &entry.original
                } else {
                    target
                };
                busbar_contract::crypto::sha256(target.as_bytes()) != publication.target_digest
            })
        {
            return Err("published source changed during native publication".into());
        }
        entry.published = true;
        Ok(())
    }

    pub(crate) fn fingerprint(&self) -> Result<[u8; 32], String> {
        let outputs = self.pending()?;
        let mut hash = Sha256::new();
        hash.update(b"busbar.startup.documents.2\0");
        for output in outputs {
            hash.update(&output.transform_id[..]);
            hash.update(&[u8::from(output.locked)]);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        hash.update(
            &state
                .secret_binding
                .unwrap_or_else(|| secret_fingerprint(&state.secrets))[..],
        );
        Ok(hash.finish())
    }
}

/// The startup refusal for unresolved migration decisions: their count and the configuration
/// paths they concern (`decisions`, from [`busbar_migrations::config::migrate::MigrateOutput::decision_paths`]).
fn debt_refusal(debt: usize, decisions: &str) -> String {
    format!(
        "configuration migration requires {debt} unresolved configuration decision(s) at: {decisions}"
    )
}

fn json_slot_mut<'a>(
    mut value: &'a mut serde_json::Value,
    path: &[String],
) -> Option<&'a mut serde_json::Value> {
    for component in path {
        value = value.as_object_mut()?.get_mut(component)?;
    }
    Some(value)
}

fn has_historical_semantics(state: &State) -> bool {
    state.source_profile
        == Some(busbar_contract::persistence::lifecycle::DocumentSemantics::Historical)
        || state
            .config_proofs
            .values()
            .any(|shape| *shape == busbar_migrations::config::HistoricalShape::RootGrammar)
}

fn document_transform(
    path: &Path,
    kind: ConfigDocument,
    original: [u8; 32],
    target: [u8; 32],
    source: Option<[u8; 32]>,
    absent: bool,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"busbar.startup.document-transform.1\0");
    hash.update(path.as_os_str().as_encoded_bytes());
    hash.update(&original[..]);
    hash.update(&target[..]);
    hash.update(&[u8::from(kind == ConfigDocument::Providers)]);
    if let Some(binding) = source {
        hash.update(&binding[..]);
    }
    // An absent default and an authored file holding the same empty text are different sources,
    // so the fingerprint and intent tell them apart. Present documents keep their transform.
    if absent {
        hash.update(b"\0absent-default");
    }
    hash.finish()
}

fn secret_fingerprint(secrets: &BTreeMap<PathBuf, SecretPublication>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"busbar.startup.credential-artifacts.1\0");
    for secret in secrets.values() {
        for part in [
            secret.config_path.as_os_str().as_encoded_bytes(),
            secret.path.as_os_str().as_encoded_bytes(),
            secret.site.as_bytes(),
        ] {
            hash.update(&(part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        hash.update(&(secret.settings_path.len() as u64).to_be_bytes());
        for part in &secret.settings_path {
            hash.update(&(part.len() as u64).to_be_bytes());
            hash.update(part.as_bytes());
        }
        hash.update(&busbar_contract::crypto::sha256(secret.bytes.as_slice())[..]);
    }
    hash.finish()
}

pub(crate) struct BootstrapRules(pub Arc<Documents>);
impl RootRules for BootstrapRules {
    fn check(&self, _: &config::RootCfg) -> Result<(), String> {
        Ok(())
    }
    fn normalize_document(
        &self,
        kind: ConfigDocument,
        path: &Path,
        raw: &str,
    ) -> Result<Option<SecureString>, String> {
        self.0.normalize(kind, path, raw)
    }
    fn absent_document(&self, kind: ConfigDocument, path: &Path) -> Result<(), String> {
        self.0.absent(kind, path)
    }
}

/// The boot refusal text for a deployment document left with migration debt.
///
/// `diagnosis` is `--validate`'s judgement of the same file's unmigrated bytes. Only its
/// plugin-preflight class names the condition behind the debt (a named plugin that is not
/// present), so only that class replaces the decision list; every other outcome prints the
/// decisions themselves.
pub(crate) fn explain_debt(
    todos: &[impl AsRef<str>],
    diagnosis: Option<&crate::root::cli::ValidateRefusal>,
    config: &Path,
) -> String {
    if let Some(crate::root::cli::ValidateRefusal::Check(
        busbar_kernel::config_validate::Refusal::Plugins(text),
    )) = diagnosis
    {
        return text.clone();
    }
    let mut detail = format!(
        "configuration migration requires {} unresolved configuration decision(s):\n",
        todos.len()
    );
    for todo in todos {
        detail.push_str("  * ");
        detail.push_str(todo.as_ref());
        detail.push('\n');
    }
    let config = config.display();
    detail.push_str(&format!(
        "Decide each item in {config}, then boot again (busbar --migrate-config {config} shows \
         the converted document)."
    ));
    detail
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::abi::mechanism::door::{
        REWRITE_SUGAR, REWRITE_SUGAR_ROLE, SUGAR_ROLE_FILL, SUGAR_ROLE_PATH,
    };

    fn fixture_sources() -> busbar_contract::secret_ref::Sugars {
        let mut sources = busbar_contract::secret_ref::Sugars::default();
        for (word, owner, role) in [
            ("lookup", "fixture-lookup", SUGAR_ROLE_FILL),
            ("artifact", "fixture-artifact", SUGAR_ROLE_PATH),
        ] {
            sources
                .declare(
                    owner,
                    &[
                        (REWRITE_SUGAR, word.into(), "slot".into()),
                        (REWRITE_SUGAR_ROLE, word.into(), role.into()),
                    ],
                )
                .unwrap();
        }
        sources
    }

    fn source_document(
        sources: &busbar_contract::secret_ref::Sugars,
        role: &str,
        value: &str,
    ) -> serde_json::Value {
        let reference = sources.reference_for_role(role, value).unwrap();
        serde_json::to_value(reference.authoring(&busbar_kernel::seal::acquire())).unwrap()
    }

    fn edit_store(store: &mut Option<config::StoreCfg>, edits: serde_json::Value) {
        let store = store.as_mut().unwrap();
        store.settings = store
            .settings
            .edit(&serde_json::from_value(edits).unwrap(), &[])
            .unwrap();
    }

    const CONFIG: &str = "store: {module: custom}\nconfig: {locked: true}\n";

    #[test]
    fn a_migration_debt_refusal_names_its_decision_paths() {
        assert_eq!(
            debt_refusal(2, "export.hook.settings, export.trace.settings"),
            "configuration migration requires 2 unresolved configuration decision(s) at: \
             export.hook.settings, export.trace.settings"
        );
    }

    #[test]
    fn unchanged_documents_are_retained_and_completion_keeps_the_fingerprint() {
        let docs = Arc::new(Documents::default());
        assert!(docs
            .normalize(ConfigDocument::Deployment, Path::new("config.yaml"), CONFIG)
            .unwrap()
            .is_none());
        assert!(docs
            .normalize(
                ConfigDocument::Providers,
                Path::new("providers.yaml"),
                "{}\n"
            )
            .unwrap()
            .is_none());
        let inventory = docs.pending().unwrap();
        assert_eq!(inventory.len(), 2);
        assert!(inventory
            .iter()
            .all(|entry| entry.original_digest == entry.target_digest && entry.locked));
        let fingerprint = docs.fingerprint().unwrap();
        docs.finish_upgrade().unwrap();
        assert_eq!(docs.fingerprint().unwrap(), fingerprint);
        assert!(docs
            .normalize(
                ConfigDocument::Deployment,
                Path::new("config.yaml"),
                "store: {module: other}\n"
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn proven_source_invalidates_outputs_and_retains_every_original() {
        let docs = Arc::new(Documents::default());
        docs.normalize(ConfigDocument::Deployment, Path::new("config.yaml"), CONFIG)
            .unwrap();
        docs.normalize(
            ConfigDocument::Providers,
            Path::new("providers.yaml"),
            "{}\n",
        )
        .unwrap();
        docs.enter_released_binding(
            [7; 32],
            busbar_contract::persistence::lifecycle::DocumentSemantics::Historical,
        )
        .unwrap();
        assert!(
            docs.pending().is_err(),
            "every original must be reloaded in the new phase"
        );
        let state = docs.state.lock().unwrap();
        assert_eq!(state.documents.len(), 2);
        assert_eq!(
            state.documents[Path::new("config.yaml")].original.as_str(),
            CONFIG
        );
        assert!(state
            .documents
            .values()
            .all(|entry| entry.converted.is_none()));
    }

    #[test]
    fn concurrent_source_edits_are_refused_before_publication() {
        let docs = Arc::new(Documents::default());
        docs.normalize(ConfigDocument::Deployment, Path::new("config.yaml"), CONFIG)
            .unwrap();
        assert!(docs
            .normalize(
                ConfigDocument::Deployment,
                Path::new("config.yaml"),
                "store: {module: changed}\n"
            )
            .is_err());
    }

    #[test]
    fn store_comparison_reverses_only_exact_document_bound_secret_intents() {
        let docs = Arc::new(Documents::default());
        let sources = fixture_sources();
        let path = Path::new("config.yaml");
        let raw = "store: {module: custom, settings: {password: historical, database: original}}\n";
        docs.normalize(ConfigDocument::Deployment, path, raw)
            .unwrap();
        docs.enter_released_binding(
            [7; 32],
            busbar_contract::persistence::lifecycle::DocumentSemantics::Historical,
        )
        .unwrap();
        docs.stage_secret(SecretPublication {
            config_path: path.into(),
            site: "store.settings".into(),
            settings_path: vec!["password".into()],
            bytes: SecureVec::from(b"historical".as_slice()),
            path: "/private/exact.secret".into(),
        })
        .unwrap();
        let original = Some(config::StoreCfg {
            module: "custom".into(),
            settings: serde_json::from_value(
                serde_json::json!({"password":"historical", "database":"original"}),
            )
            .unwrap(),
        });
        let mut target = original.clone();
        edit_store(
            &mut target,
            serde_json::json!({"password": source_document(&sources, SUGAR_ROLE_PATH, "/private/exact.secret")}),
        );
        assert!(docs
            .bootstrap_equivalent_with_sources(&original, &target, path, &sources)
            .unwrap());
        edit_store(&mut target, serde_json::json!({"database": "different"}));
        assert!(!docs
            .bootstrap_equivalent_with_sources(&original, &target, path, &sources)
            .unwrap());
        edit_store(&mut target, serde_json::json!({"database": "original"}));
        edit_store(
            &mut target,
            serde_json::json!({"password": source_document(&sources, SUGAR_ROLE_PATH, "/private/other.secret")}),
        );
        assert!(!docs
            .bootstrap_equivalent_with_sources(&original, &target, path, &sources)
            .unwrap());
        assert!(docs
            .bootstrap_equivalent_with_sources(
                &original,
                &target,
                Path::new("other.yaml"),
                &sources
            )
            .is_err());
    }

    #[test]
    fn store_comparison_uses_captured_authored_env_binding_without_reading_files() {
        let docs = Arc::new(Documents::default());
        let sources = fixture_sources();
        docs.environment.lock().unwrap().insert(
            "CAPTURED_STORE_SECRET".into(),
            Some(SecureString::from("captured")),
        );
        let path = Path::new("env.yaml");
        let raw = "store: {module: custom, settings: {password: '${CAPTURED_STORE_SECRET}'}}\n";
        docs.normalize(ConfigDocument::Deployment, path, raw)
            .unwrap();
        let original = Some(config::StoreCfg {
            module: "custom".into(),
            settings: serde_json::from_value(serde_json::json!({"password":"captured"})).unwrap(),
        });
        let mut target = original.clone();
        edit_store(
            &mut target,
            serde_json::json!({"password": source_document(&sources, SUGAR_ROLE_FILL, "CAPTURED_STORE_SECRET")}),
        );
        assert!(docs
            .bootstrap_equivalent_with_sources(&original, &target, path, &sources)
            .unwrap());
        edit_store(
            &mut target,
            serde_json::json!({"password": source_document(&sources, SUGAR_ROLE_FILL, "OTHER_SECRET")}),
        );
        assert!(!docs
            .bootstrap_equivalent_with_sources(&original, &target, path, &sources)
            .unwrap());
        docs.finish_upgrade().unwrap();
        assert!(docs.environment.lock().unwrap().is_empty());
        assert!(docs.original_deployment(path).is_err());
    }

    #[test]
    fn runtime_conversions_preserve_authored_publication_and_reloads() {
        let docs = Arc::new(Documents::default());
        let path = Path::new("config.yaml");
        docs.normalize(ConfigDocument::Deployment, path, CONFIG)
            .unwrap();
        let runtime = "store: {module: custom}\nadvanced: {worker_threads: 4}\n";
        {
            let mut state = docs.state.lock().unwrap();
            let entry = state.documents.get_mut(path).unwrap();
            entry.converted = Some(SecureString::from(runtime));
            entry.runtime_only = true;
        }
        let publication = docs.pending().unwrap().remove(0);
        assert_eq!(publication.original.as_slice(), CONFIG.as_bytes());
        assert_eq!(publication.converted.as_slice(), CONFIG.as_bytes());
        docs.mark_published(&publication).unwrap();
        docs.finish_upgrade().unwrap();
        assert_eq!(
            docs.normalize(ConfigDocument::Deployment, path, CONFIG)
                .unwrap()
                .unwrap()
                .as_str(),
            runtime
        );
    }

    #[test]
    fn secret_intents_are_retained_exactly_without_filesystem_writes() {
        let docs = Documents::default();
        docs.enter_released_binding(
            [9; 32],
            busbar_contract::persistence::lifecycle::DocumentSemantics::Historical,
        )
        .unwrap();
        let secret = |bytes: &[u8]| SecretPublication {
            config_path: "config.yaml".into(),
            site: "auth:test".into(),
            settings_path: vec!["token".into()],
            bytes: SecureVec::from(bytes),
            path: "private/credential.secret".into(),
        };
        docs.stage_secret(secret(b"same bytes")).unwrap();
        docs.stage_secret(secret(b"same bytes")).unwrap();
        assert!(docs.stage_secret(secret(b"different bytes")).is_err());
        assert_eq!(docs.pending_secrets().unwrap().len(), 1);
        let before = docs.fingerprint().unwrap();
        docs.finish_upgrade().unwrap();
        assert_eq!(before, docs.fingerprint().unwrap());
        assert!(docs.pending_secrets().unwrap().is_empty());
    }
}

#[cfg(test)]
#[path = "../tests/startup_debt.rs"]
mod startup_debt;
