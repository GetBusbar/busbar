// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Early native candidate custody, retained unchanged through later Hook and plane opens.
//!
//! The read context supplies its exact admitted image leases. The bootstrap owner supplies only
//! protected, already-open Secret sources; neither a previous App nor its serving Registry is kept.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::secret_ref::Sugars;
use busbar_kernel::config::secret::SecretResolver;
use busbar_kernel::config::{Grammar, RootCfg, SecretModuleCfg};
use busbar_kernel::plugin_config::{Binder, ConfigBinder};
use busbar_plugin_loader::instance::Registry;
use busbar_plugin_loader::process::ProcessResources;
use tokio::runtime::Handle;

use super::boot::images::{BootImages, FileImages};
use super::boot::inputs::BootInstances;
use super::secret_custody::BootSecrets;

/// Fixed process bootstrap authority. Secret ports retain their original invocation owners;
/// preparing a candidate only gives those immutable source leases a fresh binder view.
pub(crate) struct BootstrapSecrets {
    prefix: Arc<BootSecrets>,
    images: Arc<BootImages>,
    instances: Arc<BootInstances>,
    runtime: Handle,
}

impl BootstrapSecrets {
    pub(crate) fn new(
        prefix: Arc<BootSecrets>,
        images: Arc<BootImages>,
        instances: Arc<BootInstances>,
        runtime: Handle,
    ) -> Self {
        Self {
            prefix,
            images,
            instances,
            runtime,
        }
    }
}

/// One candidate's early resolver and late opening authority. The lifecycle preparation keeps
/// this same value until completion or refusal; accessors never replace any of its owners.
pub(crate) struct CandidateSecrets {
    binder: Arc<dyn ConfigBinder>,
    prefix: Arc<BootSecrets>,
    registry: Arc<Registry>,
    resolver: Arc<SecretResolver>,
    sugars: Sugars,
}

impl CandidateSecrets {
    pub(crate) fn prepare(
        bootstrap: &BootstrapSecrets,
        images: &FileImages,
        cfg: &RootCfg,
        process: &ProcessResources,
    ) -> Result<Self, String> {
        // Refuse protected changes and mismatched read metadata before creating candidate owners.
        bootstrap.images.check(images).map_err(|error| error.0)?;
        bootstrap.instances.check(cfg)?;
        let grammar = bound_read_grammar(
            &images.grammar,
            &cfg.secrets,
            cfg.grammar().map_err(|error| error.0)?,
        )?;
        let binder = new_binder(&grammar);
        let prefix = bootstrap.prefix.with_binder(Arc::clone(&binder));
        let registry = Arc::new(Registry::new(
            images.images.clone(),
            Arc::clone(&binder),
            Arc::clone(process.ids()),
        ));
        let resolver = prefix.resolver(bootstrap.runtime.clone(), grammar.sugars.clone());
        Ok(Self {
            binder,
            prefix,
            registry,
            resolver,
            sugars: grammar.sugars,
        })
    }

    pub(crate) fn binder(&self) -> &Arc<dyn ConfigBinder> {
        &self.binder
    }

    pub(crate) fn prefix(&self) -> &Arc<BootSecrets> {
        &self.prefix
    }

    pub(crate) fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    pub(crate) fn resolver(&self) -> &Arc<SecretResolver> {
        &self.resolver
    }

    pub(crate) fn sugars(&self) -> &Sugars {
        &self.sugars
    }
}

/// The single binder construction used by bootstrap and serving candidate owners. The grammar
/// already contains canonical explicit and implicit instance names from the document reader.
pub(crate) fn new_binder(grammar: &Grammar) -> Arc<dyn ConfigBinder> {
    Arc::new(Binder::new(
        Arc::new(grammar.sugars.clone()),
        reference_schemas(grammar),
    ))
}

/// Reference schemas retain the configured or implicit instance name used by the binder.
pub(crate) fn reference_schemas(grammar: &Grammar) -> Vec<(Arc<str>, Box<str>)> {
    grammar
        .secret_instances
        .iter()
        .map(|(name, source)| {
            (
                Arc::from(name.as_str()),
                Box::from(source.ref_schema.as_str()),
            )
        })
        .collect()
}

fn bound_read_grammar(
    read: &Grammar,
    configured: &BTreeMap<String, SecretModuleCfg>,
    typed: &Grammar,
) -> Result<Grammar, String> {
    // Use the document reader's canonical instance binding, including shorthand alias rules.
    let bound = read.bind_secret_instances(configured)?;
    if !bound.same_authority(typed) {
        return Err("native candidate grammar does not belong to its admitted image read".into());
    }
    Ok(bound)
}

#[cfg(test)]
#[path = "min3_candidate_secrets/tests.rs"]
mod tests;
