// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Complete admitted plane authority inventory for frozen-source migration.
//! Source rows cannot add owners or declare collection relationships.

use busbar_contract::crypto::Sha256;
use std::collections::BTreeSet;

use busbar_contract::yaml::{MappingExt, ValueExt};
use busbar_contract::{
    abi::{
        mechanism::{self, call::BLOB_OCTETS, rendering, KindCode},
        plane::{collections, CollectionMode},
    },
    records::Retention,
};
use busbar_kernel::{config::RootCfg, persistence::import_target::records::history::HistoryMode};
use busbar_migrations::{
    legacy::{
        archive::Scope,
        transform::{Collection, HistoryBinding, RecordBinding, TokenBinding},
    },
    routes::{AdmittedStatement, Bindings, DeclarationInventory},
};

/// Resolve before native source capture/claim. `discover_planes` must already have
/// retained the admitted manifest inventory; this function never loads a library,
/// opens a Store or constructs an application/runtime.
pub(crate) fn inventory() -> Result<DeclarationInventory, String> {
    let candidates = crate::root::boot::DOOR_CANDIDATES
        .get()
        .ok_or("migration: admitted plane inventory is not initialized")?;
    // The initial bootstrap config excludes Store overlay plane selections. Keep
    // every admitted declaration: record rows carry a reversible historical
    // instance scope, while ambiguous history/token owners require the effective
    // frozen overlay in the compiled transform before they can be selected.
    let mut inventory = candidates.clone();
    inventory.sort_by(|a, b| a.name.cmp(&b.name));

    let mut bindings = Bindings::default();
    let mut statements = Vec::new();
    let mut owners = BTreeSet::new();

    for candidate in inventory {
        if !owners.insert(candidate.name.clone()) {
            return Err(format!(
                "migration: plane '{}' has more than one admitted declaration",
                candidate.name
            ));
        }
        let statement = rendering::read(&candidate.stated)
            .map_err(|error| format!("migration: plane '{}': {error:?}", candidate.name))?;
        if candidate.kind != KindCode::Plane
            || statement.kind != KindCode::Plane as u32
            || statement.name != candidate.name
            || statement.mechanism_version != mechanism::MECHANISM_VERSION
            || statement.kind_abi != KindCode::Plane.abi_version()
            || statement.kind_tail_size == 0
        {
            return Err(format!(
                "migration: plane '{}' does not declare the current plane ABI",
                candidate.name
            ));
        }
        statements.push(AdmittedStatement {
            owner: candidate.name.clone(),
            statement_sha256: busbar_contract::crypto::sha256(&candidate.stated),
            kind: statement.kind,
            kind_abi: statement.kind_abi,
            layout_fingerprint: candidate.kind.layout_fingerprint(),
        });
        let records = rendering::read_plane_records(&statement.kind_tail, statement.kind_tail_size)
            .map_err(|error| format!("migration: plane '{}': {error:?}", candidate.name))?;
        let collections =
            collections::from_extensions(&statement.extensions.bytes, records.kinds.len() as u64)
                .map_err(|_| {
                format!(
                    "migration: plane '{}' has invalid collections",
                    candidate.name
                )
            })?;
        if mechanism::extensions::get(
            &statement.extensions.bytes,
            collections::EXT_RECORD_COLLECTIONS,
        )
        .is_some()
            && (statement.extensions.fmt != BLOB_OCTETS || statement.extensions.flags != 0)
        {
            return Err(format!(
                "migration: plane '{}' has invalid collection extension framing",
                candidate.name
            ));
        }
        // load_planes binds every plane under its canonical admitted name, even
        // when configuration selects it through a verb, alias or owned section.
        let owner = candidate.name;
        for kind in &records.kinds {
            bindings.records.push(RecordBinding {
                schema: kind.clone(),
                instance: owner.clone(),
                // This selects the normal instance-authorized namespace, not a
                // confidentiality class. Both this owner and import TargetRow
                // retain Secret<Vec<u8>> for every payload, including opaque
                // ciphertext. Core-private schemas use separate compiled routes.
                private: false,
                // Historical host records used record_key(instance, key): a BE u16
                // instance length + exact instance bytes. This is a compiled
                // historical host framing rule, never inferred from source keys.
                source_scope: Scope::Instance,
            });
            bindings.tokens.push(TokenBinding {
                source_kind: kind.clone(),
                instance: owner.clone(),
                kind: kind.clone(),
            });
        }
        if !records.chains.is_empty() {
            bindings.records.push(RecordBinding {
                schema: busbar_kernel::host_chains::CHAIN_LIFE_SCHEMA
                    .as_str()
                    .to_string(),
                instance: owner.clone(),
                private: false,
                source_scope: Scope::Instance,
            });
        }
        let mut declared = Vec::new();
        for collection in collections {
            let kind = &records.kinds[collection.kind as usize];
            let retention = records
                .retentions
                .iter()
                .find(|row| row.kind == collection.kind)
                .map(|row| Retention::from_code(row.rule).expect("validated retention code"))
                .unwrap_or_default();
            declared.push(Collection {
                kind: kind.clone(),
                mode: match collection.mode {
                    CollectionMode::Upsert => HistoryMode::Upsert,
                    CollectionMode::Append => HistoryMode::Append,
                },
                retention,
                parent: collection
                    .parent
                    .map(|parent| records.kinds[parent as usize].clone()),
            });
        }
        if !declared.is_empty() {
            bindings.histories.push(HistoryBinding {
                owner,
                collections: declared,
            });
        }
    }
    Ok(DeclarationInventory {
        bindings,
        statements,
    })
}

/// The source and its declarations are already admitted. This resolver reads only
/// the frozen archive and retained authored documents; it never opens a Store/App.
pub(crate) struct Resolver {
    documents: std::sync::Arc<super::documents::Documents>,
    config_path: std::path::PathBuf,
    providers_override: Option<std::path::PathBuf>,
    ignore_overlay: bool,
    value_budget: usize,
    bindings: Bindings,
    owners: BTreeSet<String>,
}

impl Resolver {
    pub(crate) fn new(
        documents: std::sync::Arc<super::documents::Documents>,
        config_path: std::path::PathBuf,
        providers_override: Option<std::path::PathBuf>,
        ignore_overlay: bool,
        index_budget: usize,
        value_budget: usize,
        inventory: &DeclarationInventory,
    ) -> Result<Self, busbar_migrations::Error> {
        let bindings = busbar_migrations::routes::dormant_safe_bindings(inventory, index_budget)?;
        Ok(Self {
            documents,
            config_path,
            providers_override,
            ignore_overlay,
            value_budget,
            bindings,
            owners: inventory
                .statements
                .iter()
                .map(|statement| statement.owner.clone())
                .collect(),
        })
    }

    fn effective(
        &self,
        doc: Option<&busbar_kernel::config::overlay::OverlayDoc>,
    ) -> Result<RootCfg, String> {
        use busbar_kernel::{
            appbuild::{ConfigDocument, RootRules},
            config,
        };
        let rules = super::documents::BootstrapRules(self.documents.clone());
        let (raw, _) = self.documents.original_deployment(&self.config_path)?;
        let normalized =
            rules.normalize_document(ConfigDocument::Deployment, &self.config_path, &raw)?;
        let input = self.documents.interpolate_captured(
            normalized
                .as_ref()
                .map_or(raw.as_str(), |text| text.as_str()),
        )?;
        if let Ok(document) =
            busbar_contract::yaml::from_str::<busbar_contract::yaml::Value>(&input)
        {
            let keys: Vec<&str> = document
                .as_mapping()
                .into_iter()
                .flat_map(|mapping| mapping.keys())
                .filter_map(busbar_contract::yaml::Value::as_str)
                .collect();
            if rules.unloaded_plane_refusal(&keys).is_some() {
                return Err("retained deployment selects an unloaded plane".into());
            }
        }
        // The retained document is read under its own grammar: phase 1 over its effective `plugins:`
        // block (SECRET-SHORTHAND-BOOT §3.5), never the live secret axis.
        let effective = match doc
            .and_then(|doc| doc.document_patch.as_ref())
            .filter(|_| !self.ignore_overlay)
        {
            Some(patch) => patch
                .compacted_against_yaml(&input)?
                .patched_text(&input, |keys| {
                    rules.unloaded_plane_refusal(keys).map_or(Ok(()), Err)
                })?,
            None => busbar_contract::secure::SecureString::from(&*input),
        };
        let grammar = crate::root::boot::grammar_of_text(&effective)?;
        let mut deploy = config::deploy_from_yaml_str(&effective, &grammar)
            .map_err(|_| "retained deployment parsing refused")?;
        let selected = config::providers::CatalogLocation::select(
            &self.config_path,
            self.providers_override.as_deref(),
            deploy.providers_file.as_deref(),
        );
        let (provider_path, raw_providers) = self
            .documents
            .original_provider()?
            .ok_or("retained provider source is absent")?;
        if provider_path != selected.path {
            return Err("retained provider source binding changed".into());
        }
        let providers = match raw_providers {
            Some(raw_providers) => {
                let providers = rules.normalize_document(
                    ConfigDocument::Providers,
                    &provider_path,
                    &raw_providers,
                )?;
                self.documents.interpolate_captured(
                    providers
                        .as_ref()
                        .map_or(raw_providers.as_str(), |text| text.as_str()),
                )?
            }
            // Only an unnamed default may be absent; the loader refuses a named missing file.
            None if selected.named => {
                return Err("retained provider source binding changed".into());
            }
            None => {
                rules.absent_document(ConfigDocument::Providers, &provider_path)?;
                self.documents
                    .interpolate_captured(config::providers::CatalogSource::AbsentDefault.text())?
            }
        };
        deploy.document_source_fingerprints = Some(
            config::document_patch::SourceFingerprints::from_sources(&input, &providers),
        );
        let defs = match doc
            .and_then(|doc| doc.providers_patch.as_ref())
            .filter(|_| !self.ignore_overlay)
        {
            Some(patch) => patch
                .compacted_against_yaml(&providers)?
                .parse_catalog_yaml(&providers, &grammar)?,
            None => config::providers::catalog_from_str(&providers, &grammar)
                .map_err(|_| "retained provider parsing refused")?,
        };
        if let Some(doc) = doc.filter(|_| !self.ignore_overlay) {
            // The ordinary merge reports malformed named definitions diagnostically.
            // Frozen migration must instead refuse before any definition is skipped.
            for section in config::named_map::NamedMapSection::sections() {
                if let Some(entries) = doc.named_maps.get(section.key()) {
                    for (name, value) in entries {
                        section
                            .insert(&mut deploy, name, value)
                            .map_err(|_| "frozen named definition parsing refused")?;
                    }
                }
            }
            config::overlay::apply_root_to_deploy(&mut deploy, doc)
                .map_err(|_| "frozen named definition parsing refused")?;
        }
        let mut cfg = config::resolve(&deploy, &defs)
            .map_err(|_| "frozen effective configuration resolution refused")?;
        if let Some(doc) = doc.filter(|_| !self.ignore_overlay) {
            config::overlay::merge_into(&mut cfg, doc.clone());
        }
        Ok(cfg)
    }
}

impl busbar_migrations::FrozenBindingResolver for Resolver {
    fn resolve(
        &self,
        source: &busbar_migrations::Identity,
        rows: &mut dyn busbar_migrations::archive_source::ArchiveRows,
    ) -> Result<busbar_migrations::FrozenResolution, busbar_migrations::Error> {
        use busbar_migrations::{
            legacy::overlay::{frozen_overlay_from_facts, PreparedOverlay},
            Error,
        };
        let original = frozen_overlay_from_facts(rows, source, self.value_budget)?;
        let mut converted = None;
        let overlay = if let Some(original) = original {
            let seal = busbar_kernel::seal::lend();
            #[derive(serde::Deserialize)]
            struct Version {
                #[serde(default = "legacy_version")]
                version: u32,
            }
            fn legacy_version() -> u32 {
                1
            }
            let raw = original.bytes().expose(&seal);
            let version: Version = serde_json::from_slice(raw).map_err(|_| Error::Corrupt)?;
            let doc = match version.version {
                1 => {
                    let (authored, detection) = self
                        .documents
                        .original_deployment(&self.config_path)
                        .map_err(|_| Error::Corrupt)?;
                    let host = crate::root::config_migrate::RootHost::for_frozen_overlay(
                        &authored,
                        &detection,
                        &self.config_path,
                        self.documents.clone(),
                    )
                    .map_err(|_| Error::Corrupt)?;
                    let mut converted =
                        busbar_migrations::config::migrate_overlay::migrate_overlay_with(
                            raw, &host,
                        )
                        .map_err(|_| Error::Corrupt)?;
                    // Change lines may quote resolved values and are zeroized; a notice holds only
                    // an authored key and fixed text, so the operator sees it at WARN.
                    for notice in &converted.notices {
                        self.documents.notice(notice);
                    }
                    zeroize::Zeroize::zeroize(&mut converted.changes);
                    converted.doc
                }
                version if version == busbar_kernel::config::overlay::OVERLAY_VERSION => {
                    serde_json::from_slice(raw).map_err(|_| Error::Corrupt)?
                }
                _ => return Err(Error::MissingCapability),
            };
            let mut output = ProtectedJson {
                bytes: busbar_contract::secure::SecureVec::new(),
                budget: self.value_budget,
            };
            serde_json::to_writer(&mut output, &doc.authoring(&busbar_kernel::seal::acquire()))
                .map_err(|_| Error::Bounds)?;
            converted = Some(std::sync::Arc::new(PreparedOverlay::prepare(
                original,
                busbar_contract::Secret::new(output.bytes.into_vec()),
                conversion_digest(),
                self.value_budget,
            )?));
            Some(doc)
        } else {
            None
        };
        let cfg = self
            .effective(overlay.as_ref())
            .map_err(|_| Error::Corrupt)?;
        let mut roots: BTreeSet<String> = cfg
            .plane_sections
            .iter()
            .map(|section| (*section).to_owned())
            .collect();
        roots.extend(
            crate::root::door_steps::kernel_sections(&cfg)
                .map_err(|_| Error::Corrupt)?
                .keys()
                .map(|section| (*section).to_owned()),
        );
        let uses = crate::root::loader::boot::Uses {
            roots,
            ..Default::default()
        };
        let candidates = crate::root::boot::DOOR_CANDIDATES
            .get()
            .ok_or(Error::MissingCapability)?;
        for selected in crate::root::loader::boot::used_planes(&uses, candidates) {
            if !self.owners.contains(&selected.name) {
                return Err(Error::MissingCapability);
            }
        }
        Ok(busbar_migrations::FrozenResolution {
            bindings: self.bindings.clone(),
            overlay: converted,
        })
    }
}

struct ProtectedJson {
    bytes: busbar_contract::secure::SecureVec,
    budget: usize,
}
impl std::io::Write for ProtectedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= self.budget)
            .ok_or_else(|| std::io::Error::other("frozen overlay encoding budget exceeded"))?;
        // Grows into a fresh block and wipes the old one (LINT-RULES LR-117).
        self.bytes
            .extend(bytes)
            .map_err(|_| std::io::Error::other("frozen overlay encoding allocation refused"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn conversion_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    for source in [
        include_bytes!("bindings.rs").as_slice(),
        include_bytes!("documents.rs").as_slice(),
        include_bytes!("../config_migrate.rs").as_slice(),
        include_bytes!("../../../../busbar-migrations/src/config/mod.rs").as_slice(),
        include_bytes!("../../../../busbar-migrations/src/config/migrate.rs").as_slice(),
        include_bytes!("../../../../busbar-migrations/src/config/migrate_1_6.rs").as_slice(),
        include_bytes!("../../../../busbar-migrations/src/config/migrate_overlay.rs").as_slice(),
        include_bytes!("../../../../busbar-migrations/src/config/overlay_legacy.rs").as_slice(),
        include_bytes!("../../../../busbar-migrations/src/config/migrate_plugins.rs").as_slice(),
        include_bytes!("../../../../busbar-migrations/src/config/migrate_credentials.rs")
            .as_slice(),
        include_bytes!("../../../../busbar-migrations/src/config/migrate_catalog.rs").as_slice(),
        include_bytes!("../../../../busbar-migrations/src/config/provenance.rs").as_slice(),
        include_bytes!("../../../../busbar-migrations/src/config/templates.rs").as_slice(),
        include_bytes!("../../../../busbar-migrations/src/config/former_names.rs").as_slice(),
        include_bytes!("../../../../busbar-migrations/src/config/retired.rs").as_slice(),
        include_bytes!("../../../../busbar-migrations/src/config/migration_table.rs").as_slice(),
        include_bytes!("../../../../busbar-migrations/src/config/migrate_export.rs").as_slice(),
    ] {
        hash.update(&(source.len() as u64).to_be_bytes());
        hash.update(source);
    }
    for (key, value) in busbar_migrations::config::migration_table::rows() {
        hash.update(&(key.len() as u64).to_be_bytes());
        hash.update(key.as_bytes());
        hash.update(&(value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.finish()
}
