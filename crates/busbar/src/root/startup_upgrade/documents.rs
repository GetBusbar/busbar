// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Original authored bytes stay in custody across bootstrap and source-proven conversion.
use busbar_kernel::{
    appbuild::{ConfigDocument, RootRules},
    config,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use zeroize::{Zeroize, Zeroizing};

struct Document {
    kind: ConfigDocument,
    original: Zeroizing<String>,
    converted: Option<Zeroizing<String>>,
    published: bool,
    requires_released_source: bool,
    restored_transform: Option<[u8; 32]>,
    runtime_only: bool,
}

/// Complete document inventory, including unchanged documents. Debug is deliberately absent.
pub struct Publication {
    pub path: PathBuf,
    pub original: Zeroizing<Vec<u8>>,
    pub converted: Zeroizing<Vec<u8>>,
    pub original_digest: [u8; 32],
    pub target_digest: [u8; 32],
    pub transform_id: [u8; 32],
    pub locked: bool,
}

/// A protected artifact to materialize only after its native/Store intent is Applied.
/// Raw material is never included in logs, fingerprints or diagnostic formatting.
pub struct SecretPublication {
    pub config_path: PathBuf,
    pub site: String,
    pub settings_path: Vec<String>,
    pub bytes: Zeroizing<Vec<u8>>,
    pub path: PathBuf,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Phase {
    #[default]
    Structural,
    Released([u8; 32], busbar_migrations::ReleasedProfile),
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
    source_profile: Option<busbar_migrations::ReleasedProfile>,
    config_proofs: BTreeMap<[u8; 32], busbar_migrations::config::HistoricalShape>,
    secret_binding: Option<[u8; 32]>,
}
#[derive(Default)]
pub struct Documents {
    state: Mutex<State>,
    environment: Mutex<BTreeMap<String, Option<Zeroizing<String>>>>,
}

impl Documents {
    fn captured_env(&self, key: &str) -> Option<String> {
        let mut captured = self
            .environment
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        captured
            .entry(key.to_owned())
            .or_insert_with(|| std::env::var(key).ok().map(Zeroizing::new))
            .as_ref()
            .map(|value| value.to_string())
    }

    pub fn normalize(
        self: &Arc<Self>,
        kind: ConfigDocument,
        path: &Path,
        raw: &str,
    ) -> Result<Option<Zeroizing<String>>, String> {
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
                        return Ok((converted.as_str() != raw)
                            .then(|| Zeroizing::new(converted.to_string())));
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
                        original: Zeroizing::new(raw.to_owned()),
                        converted: None,
                        published: false,
                        requires_released_source: false,
                        restored_transform: None,
                        runtime_only: false,
                    });
                if entry.kind != kind {
                    return Err("one file cannot be deployment and provider configuration".into());
                }
                if raw != entry.original.as_str()
                    && !(entry.published
                        && entry.converted.as_ref().is_some_and(|v| v.as_str() == raw))
                {
                    return Err("configuration changed during startup migration".into());
                }
                if let Some(converted) = &entry.converted {
                    return Ok(
                        (converted.as_str() != raw).then(|| Zeroizing::new(converted.to_string()))
                    );
                }
                let original = Zeroizing::new(entry.original.to_string());
                (state.phase, state.revision, original)
            }
        };
        // No custody mutex is held across plugin callbacks, catalogue staging or I/O.
        let mut detected_locked = false;
        let mut runtime_only = false;
        let (converted, requires_released_source) = match kind {
            ConfigDocument::Deployment => {
                let mut unset = Vec::new();
                let detection = Zeroizing::new(
                    config::interpolate_env_lookup(
                        &original,
                        config::EnvSubst::Lenient,
                        &mut unset,
                        |key| self.captured_env(key),
                    )
                    .map_err(|_| "configuration detection interpolation refused")?,
                );
                detected_locked = serde_yaml::from_str::<serde_yaml::Value>(&detection)
                    .ok()
                    .and_then(|doc| doc.get("config")?.get("locked")?.as_bool())
                    .unwrap_or(false);
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
                output.changes.zeroize();
                output.todos.zeroize();
                output.warnings.zeroize();
                if debt != 0 {
                    output.yaml.zeroize();
                    return Err(format!(
                        "configuration migration requires {debt} unresolved configuration decision(s)"
                    ));
                }
                (Zeroizing::new(output.yaml), false)
            }
            ConfigDocument::Providers => {
                let mut unset = Vec::new();
                let detection = Zeroizing::new(
                    config::interpolate_env_lookup(
                        &original,
                        config::EnvSubst::Lenient,
                        &mut unset,
                        |key| self.captured_env(key),
                    )
                    .map_err(|_| "providers detection interpolation refused")?,
                );
                if config::providers::catalog_from_str(&detection).is_ok() {
                    (Zeroizing::new(original.to_string()), false)
                } else {
                    let output = busbar_migrations::config::migrate_catalog::migrate_catalog(
                        &original,
                        "providers configuration",
                    )
                    .map_err(|_| "providers normalization refused the authored document")?;
                    match output {
                        Some(mut output) => {
                            output.changes.zeroize();
                            (Zeroizing::new(output.yaml), true)
                        }
                        None => (Zeroizing::new(original.to_string()), false),
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
            if let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&converted) {
                state.locked |= doc
                    .get("config")
                    .and_then(|c| c.get("locked"))
                    .and_then(serde_yaml::Value::as_bool)
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
        let answer = (converted.as_str() != raw).then(|| Zeroizing::new(converted.to_string()));
        entry.runtime_only = runtime_only;
        entry.converted = Some(converted);
        entry.requires_released_source = requires_released_source;
        Ok(answer)
    }

    /// The migration owner alone constructs this proof from actual native inspection.
    /// Frozen settings semantics follow the admitted native profile, without inventing a release.
    pub fn enter_released_source(
        &self,
        proof: &busbar_migrations::ReleasedSourceProof,
    ) -> Result<(), String> {
        let source = proof.source();
        let mut binding = Sha256::new();
        binding.update(b"busbar.startup.config-source.1\0");
        binding.update(source.native_anchor);
        binding.update(source.dataset.0);
        binding.update(source.catalogue_digest);
        binding.update(source.layout_digest);
        if let Some(format) = source.format {
            binding.update(format.owner);
            binding.update(format.physical.to_be_bytes());
            binding.update(format.logical.to_be_bytes());
            binding.update(format.codec.to_be_bytes());
        }
        self.enter_released_binding(binding.finalize().into(), proof.profile())
    }

    /// Phase entry is wired below to the migration coordinator's opaque source proof.
    fn enter_released_binding(
        &self,
        binding: [u8; 32],
        profile: busbar_migrations::ReleasedProfile,
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
            .filter(|entry| !entry.published && entry.restored_transform.is_none())
        {
            entry.converted = None;
            entry.requires_released_source = false;
        }
        Ok(())
    }

    /// Close historical conversion after validated adoption; subsequent reloads are current inputs.
    pub fn finish_upgrade(&self) -> Result<(), String> {
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

    pub fn admit_config_profile(
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

    pub fn native_source_established(&self) -> Result<bool, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        Ok(state.source_profile.is_some())
    }

    /// Interpolate retained normalization output under only this startup's captured references.
    pub fn interpolate_captured(&self, raw: &str) -> Result<Zeroizing<String>, String> {
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
        .map(Zeroizing::new)
        .map_err(|_| "captured configuration interpolation refused".into())
    }

    /// The exact frozen authored deployment and a detection view under this startup's
    /// captured environment. Neither may be replaced by a re-read of a partially published file.
    pub fn original_deployment(
        &self,
        path: &Path,
    ) -> Result<(Zeroizing<String>, Zeroizing<String>), String> {
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
            Zeroizing::new(document.original.to_string())
        };
        let detection = Zeroizing::new(
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
    pub fn bootstrap_equivalent(
        &self,
        original: &Option<config::StoreCfg>,
        target: &Option<config::StoreCfg>,
        config_path: &Path,
    ) -> Result<bool, String> {
        let (Some(original), Some(target)) = (original, target) else {
            return Ok(original.is_none() && target.is_none());
        };
        let (authored, detection) = self.original_deployment(config_path)?;
        let templates = busbar_migrations::config::templates::ResolvedTemplates::from_yaml(
            &authored, &detection,
        )?;
        let authored: serde_yaml::Value =
            serde_yaml::from_str(&authored).map_err(|_| "retained Store source is invalid")?;
        let mut target = target.clone();
        let state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        let mut settings = serde_json::Value::Object(std::mem::take(&mut target.settings));
        for secret in state
            .secrets
            .values()
            .filter(|secret| secret.config_path == config_path && secret.site == "store.settings")
        {
            let Some(slot) = json_slot_mut(&mut settings, &secret.settings_path) else {
                continue;
            };
            let expected = busbar_contract::secret_ref::SecretRef::file(
                secret
                    .path
                    .to_str()
                    .ok_or("staged Store credential path is not UTF-8")?,
            );
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
            authored: &serde_yaml::Value,
            templates: &busbar_migrations::config::templates::ResolvedTemplates,
        ) -> Result<(), String> {
            if let Some(text) = authored.as_str() {
                if text.contains("${")
                    && serde_json::from_value::<busbar_contract::secret_ref::SecretRef>(
                        target.clone(),
                    )
                    .ok()
                        == Some(busbar_contract::secret_ref::SecretRef::template(text))
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
                        == Some(busbar_contract::secret_ref::SecretRef::env(variable))
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
                        env_refs(value, source, templates)?;
                    }
                }
            }
            Ok(())
        }
        if let Some(source) = authored
            .get("store")
            .and_then(|store| store.get("settings"))
        {
            env_refs(&mut settings, source, &templates)?;
        }
        target.settings = settings
            .as_object_mut()
            .map(std::mem::take)
            .ok_or("Store comparison settings are invalid")?;
        let original =
            serde_json::to_value(original).map_err(|_| "Store comparison encoding failed")?;
        let target =
            serde_json::to_value(target).map_err(|_| "Store comparison encoding failed")?;
        Ok(original == target)
    }

    pub fn original_provider(&self) -> Result<Option<(PathBuf, Zeroizing<String>)>, String> {
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
            Zeroizing::new(entry.original.to_string()),
        )))
    }

    pub fn stage_catalog(&self, path: &Path, raw: &str, converted: &str) -> Result<(), String> {
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
                original: Zeroizing::new(raw.to_owned()),
                converted: None,
                published: false,
                requires_released_source: true,
                restored_transform: None,
                runtime_only: false,
            });
        if entry.kind != ConfigDocument::Providers || entry.original.as_str() != raw {
            return Err("providers source changed during conversion".into());
        }
        if entry
            .converted
            .as_ref()
            .is_some_and(|current| current.as_str() != converted)
        {
            return Err("providers conversion target changed within one source phase".into());
        }
        entry.converted = Some(Zeroizing::new(converted.to_owned()));
        entry.requires_released_source = true;
        Ok(())
    }

    pub fn stage_secret(&self, secret: SecretPublication) -> Result<String, String> {
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

    pub fn pending_secrets(&self) -> Result<Vec<SecretPublication>, String> {
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
                bytes: Zeroizing::new(s.bytes.to_vec()),
                path: s.path.clone(),
            })
            .collect())
    }

    /// Restore only an inventory authenticated by the real checkpoint owner.
    /// A disk file may be its protected original or exact target after a partial publish.
    pub fn restore_from_checkpoint(
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
                    let runtime = entry.runtime_only.then(|| {
                        (
                            Zeroizing::new(entry.original.to_string()),
                            entry
                                .converted
                                .as_ref()
                                .map(|value| Zeroizing::new(value.to_string())),
                        )
                    });
                    (path.clone(), (entry.kind, runtime))
                })
                .collect();
            (observed, state.phase, state.revision)
        };
        let mut restored = BTreeMap::new();
        let mut locked = false;
        for publication in input.publications() {
            let (kind, runtime) = observed
                .get(&publication.path)
                .ok_or("checkpoint names an unobserved configuration source")?;
            let kind = *kind;
            let original_digest: [u8; 32] = Sha256::digest(publication.original.as_slice()).into();
            let target_digest: [u8; 32] = Sha256::digest(publication.converted.as_slice()).into();
            if original_digest != publication.original_digest
                || target_digest != publication.target_digest
            {
                return Err(
                    "checkpoint configuration bytes do not match their protected digests".into(),
                );
            }
            let current = match std::fs::read(&publication.path) {
                Ok(bytes) => Some(Zeroizing::new(bytes)),
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && input.recoverable_missing(&publication.path) =>
                {
                    None
                }
                Err(_) => return Err("checkpoint configuration source could not be read".into()),
            };
            if current.as_ref().is_some_and(|bytes| {
                bytes.as_slice() != publication.original.as_slice()
                    && bytes.as_slice() != publication.converted.as_slice()
            }) {
                return Err(
                    "configuration changed outside the protected publication checkpoint".into(),
                );
            }
            let original = Zeroizing::new(
                std::str::from_utf8(&publication.original)
                    .map_err(|_| "checkpoint source is not UTF-8")?
                    .to_owned(),
            );
            let mut converted = Zeroizing::new(
                std::str::from_utf8(&publication.converted)
                    .map_err(|_| "checkpoint target is not UTF-8")?
                    .to_owned(),
            );
            let published = current
                .as_ref()
                .is_some_and(|bytes| bytes.as_slice() == publication.converted.as_slice());
            let mut runtime_only = false;
            if publication.original == publication.converted {
                if let Some((authored, Some(current))) = runtime {
                    if authored.as_str() == original.as_str() {
                        converted = Zeroizing::new(current.to_string());
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
                            && kind == ConfigDocument::Providers,
                        restored_transform: Some(publication.transform_id),
                        runtime_only,
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
                    bytes: Zeroizing::new(secret.bytes.to_vec()),
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

    pub fn pending(&self) -> Result<Vec<Publication>, String> {
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
            let original_digest: [u8; 32] = Sha256::digest(entry.original.as_bytes()).into();
            let target_digest: [u8; 32] = Sha256::digest(converted.as_bytes()).into();
            let transform_id = entry.restored_transform.unwrap_or_else(|| {
                document_transform(
                    path,
                    entry.kind,
                    original_digest,
                    target_digest,
                    state.source_binding,
                )
            });
            outputs.push(Publication {
                path: path.clone(),
                original: Zeroizing::new(entry.original.as_bytes().to_vec()),
                converted: Zeroizing::new(converted.as_bytes().to_vec()),
                original_digest,
                target_digest,
                transform_id,
                locked: state.locked,
            });
        }
        Ok(outputs)
    }

    /// Record a completed native publication of this exact retained document pair.
    pub fn mark_published(&self, publication: &Publication) -> Result<(), String> {
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
        let actual_original: [u8; 32] = Sha256::digest(entry.original.as_bytes()).into();
        if actual_original != publication.original_digest
            || entry.converted.as_ref().is_none_or(|target| {
                let target = if entry.runtime_only {
                    &entry.original
                } else {
                    target
                };
                <[u8; 32]>::from(Sha256::digest(target.as_bytes())) != publication.target_digest
            })
        {
            return Err("published source changed during native publication".into());
        }
        entry.published = true;
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<[u8; 32], String> {
        let outputs = self.pending()?;
        let mut hash = Sha256::new();
        hash.update(b"busbar.startup.documents.2\0");
        for output in outputs {
            hash.update(output.transform_id);
            hash.update([u8::from(output.locked)]);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| "configuration custody failed")?;
        hash.update(
            state
                .secret_binding
                .unwrap_or_else(|| secret_fingerprint(&state.secrets)),
        );
        Ok(hash.finalize().into())
    }
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
    use busbar_migrations::ReleasedProfile;
    matches!(
        state.source_profile,
        Some(
            ReleasedProfile::Sqlite6
                | ReleasedProfile::Postgres6
                | ReleasedProfile::Mysql3
                | ReleasedProfile::Valkey6
        )
    ) || state
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
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"busbar.startup.document-transform.1\0");
    hash.update(path.as_os_str().as_encoded_bytes());
    hash.update(original);
    hash.update(target);
    hash.update([u8::from(kind == ConfigDocument::Providers)]);
    if let Some(binding) = source {
        hash.update(binding);
    }
    hash.finalize().into()
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
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        hash.update((secret.settings_path.len() as u64).to_be_bytes());
        for part in &secret.settings_path {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part.as_bytes());
        }
        hash.update(Sha256::digest(secret.bytes.as_slice()));
    }
    hash.finalize().into()
}

pub struct BootstrapRules(pub Arc<Documents>);
impl RootRules for BootstrapRules {
    fn check(&self, _: &config::RootCfg) -> Result<(), String> {
        Ok(())
    }
    fn normalize_document(
        &self,
        kind: ConfigDocument,
        path: &Path,
        raw: &str,
    ) -> Result<Option<Zeroizing<String>>, String> {
        self.0.normalize(kind, path, raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const CONFIG: &str = "store: {module: custom}\nconfig: {locked: true}\n";

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
        docs.enter_released_binding([7; 32], busbar_migrations::ReleasedProfile::Sqlite6)
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
        let path = Path::new("config.yaml");
        let raw = "store: {module: custom, settings: {password: historical, database: original}}\n";
        docs.normalize(ConfigDocument::Deployment, path, raw)
            .unwrap();
        docs.enter_released_binding([7; 32], busbar_migrations::ReleasedProfile::Sqlite6)
            .unwrap();
        docs.stage_secret(SecretPublication {
            config_path: path.into(),
            site: "store.settings".into(),
            settings_path: vec!["password".into()],
            bytes: Zeroizing::new(b"historical".to_vec()),
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
        target.as_mut().unwrap().settings.insert(
            "password".into(),
            serde_json::json!({"file":"/private/exact.secret"}),
        );
        assert!(docs.bootstrap_equivalent(&original, &target, path).unwrap());
        target
            .as_mut()
            .unwrap()
            .settings
            .insert("database".into(), "different".into());
        assert!(!docs.bootstrap_equivalent(&original, &target, path).unwrap());
        target
            .as_mut()
            .unwrap()
            .settings
            .insert("database".into(), "original".into());
        target.as_mut().unwrap().settings.insert(
            "password".into(),
            serde_json::json!({"file":"/private/other.secret"}),
        );
        assert!(!docs.bootstrap_equivalent(&original, &target, path).unwrap());
        assert!(docs
            .bootstrap_equivalent(&original, &target, Path::new("other.yaml"))
            .is_err());
    }

    #[test]
    fn store_comparison_uses_captured_authored_env_binding_without_reading_files() {
        let docs = Arc::new(Documents::default());
        docs.environment.lock().unwrap().insert(
            "CAPTURED_STORE_SECRET".into(),
            Some(Zeroizing::new("captured".into())),
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
        target.as_mut().unwrap().settings.insert(
            "password".into(),
            serde_json::json!({"env":"CAPTURED_STORE_SECRET"}),
        );
        assert!(docs.bootstrap_equivalent(&original, &target, path).unwrap());
        target
            .as_mut()
            .unwrap()
            .settings
            .insert("password".into(), serde_json::json!({"env":"OTHER_SECRET"}));
        assert!(!docs.bootstrap_equivalent(&original, &target, path).unwrap());
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
            entry.converted = Some(Zeroizing::new(runtime.into()));
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
        docs.enter_released_binding([9; 32], busbar_migrations::ReleasedProfile::Postgres6)
            .unwrap();
        let secret = |bytes: &[u8]| SecretPublication {
            config_path: "config.yaml".into(),
            site: "auth:test".into(),
            settings_path: vec!["token".into()],
            bytes: Zeroizing::new(bytes.to_vec()),
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
