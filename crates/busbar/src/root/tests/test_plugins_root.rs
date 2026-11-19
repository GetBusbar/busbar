// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The root's fixture plugins: the shared `test_plugins.rs` (which the distribution's own test crates also
//! include, so it names nothing inside this binary) plus the fixtures that open the application Store through
//! the composition root (`root::min3_boot`, `root::door_steps`, `root::auth_bindings`) or read the binary's
//! linked table (`crate::LINKED`). Those exist only in this crate's unit tests.

pub(crate) use crate::test_common::plugins::*;

use busbar_plugin_loader::sign::sha256_hex;
use std::path::Path;

/// Creation provenance owned only by the provisioner of a new fixture database.
/// May cross construction stages, but must be initialized before any serving starts.
pub(crate) struct FreshApplicationStore {
    opened: std::sync::Arc<busbar_kernel::persistence::facade::CoreStore>,
    rules: std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>,
    evidence_sha256: String,
    store_sha256: String,
}

impl FreshApplicationStore {
    pub(crate) fn rules(&self) -> std::sync::Arc<dyn busbar_kernel::appbuild::RootRules> {
        self.rules.clone()
    }

    pub fn opened(&self) -> std::sync::Arc<busbar_kernel::persistence::facade::CoreStore> {
        self.opened.clone()
    }

    /// Commit only the public witness of this provisioner's genuine exclusive Store creation.
    /// This does not initialize an authentication format or grant any runtime quota.
    pub(crate) async fn commit_creation_witness(
        &self,
    ) -> Result<busbar_kernel::host_record_bootstrap::StoreWitness, String> {
        use busbar_kernel::persistence::scoped::{Outcome, ScopedStore};
        let schema = "test.fixture.principal-creation";
        let owner = ScopedStore::host_private(
            self.opened.clone(),
            "busbar.fixture.principal-creation",
            [schema],
        )
        .map_err(|error| format!("fixture creation owner: {error:?}"))?;
        let outcome = owner
            .put(
                schema,
                b"namespace",
                busbar_contract::Secret::new(self.evidence_sha256.as_bytes().to_vec()),
            )
            .await
            .map_err(|error| format!("fixture creation witness: {error:?}"))?;
        if outcome != Outcome::Applied {
            return Err(format!(
                "fixture creation witness not confirmed: {outcome:?}"
            ));
        }
        Ok(busbar_kernel::host_record_bootstrap::StoreWitness {
            schema: schema.into(),
            key_hex: hex::encode(b"namespace"),
            value_hex: hex::encode(self.evidence_sha256.as_bytes()),
        })
    }

    pub(crate) async fn initialize_principal_format(
        self,
        cfg: &busbar_kernel::config::RootCfg,
        plugins: &busbar_kernel::config::PluginsCfg,
    ) -> Result<crate::root::min3_boot::fixture::Admitted, String> {
        use busbar_kernel::governance::principal_transition as transition;
        let seal = busbar_kernel::seal::acquire();
        let store_sha256 =
            transition::store_fingerprint(&cfg.store.as_ref().map(|store| store.authoring(&seal)))?;
        if store_sha256 != self.store_sha256 {
            return Err(
                "new fixture Store configuration changed before baseline initialization".into(),
            );
        }
        let registry = busbar_kernel::plugins_preflight(
            cfg.store.as_ref(),
            cfg.auth.as_ref(),
            &cfg.identity_providers,
            &cfg.hooks,
            plugins,
            &cfg.export,
        )?;
        let requirements = transition::requirements(cfg, registry.as_ref())?;
        assert!(
            requirements.iter().any(|r| !r.format.is_empty()),
            "this explicit fixture initializer is for admitted marked-auth deployments"
        );
        let witness = self.commit_creation_witness().await?;
        let receipt = transition::FreshNamespace {
            version: 2,
            witness_binding: Some(transition::WitnessBinding {
                instance: "busbar.fixture.principal-creation".into(),
                private: true,
                source_scope: transition::WitnessScope::Unscoped,
            }),
            store_config_sha256: store_sha256.clone(),
            requirements: requirements.clone(),
            witness: Some(witness),
            ephemeral_instance: false,
            exclusive_instance: false,
            creation_evidence_sha256: self.evidence_sha256,
            newly_created_namespace: true,
            sender_quiesced: true,
            backend_quiesced: true,
            actor: "isolated application fixture provisioner".into(),
            reason: "exclusive new database file; construction only, serving not activated".into(),
        };
        transition::initialize_fresh(&receipt, self.opened.clone(), &store_sha256, &requirements)
            .await?;
        Ok(crate::root::min3_boot::fixture::Admitted {
            core: self.opened,
            rules: self.rules,
        })
    }
}

/// Exclusively create the actual database before its first Store open.
/// A retained App or an already existing database cannot supply this provenance.
pub(crate) async fn provision_fresh_application_store(
    cfg: &busbar_kernel::config::RootCfg,
    plugins: &busbar_kernel::config::PluginsCfg,
    directory: &Path,
) -> Result<FreshApplicationStore, String> {
    provision_fresh_application_store_with_backend(cfg, plugins, directory, |backend| backend).await
}

pub(crate) async fn provision_fresh_application_store_with_backend(
    cfg: &busbar_kernel::config::RootCfg,
    plugins: &busbar_kernel::config::PluginsCfg,
    directory: &Path,
    decorate: impl FnOnce(
        std::sync::Arc<dyn busbar_contract::persistence::PersistenceBackend>,
    ) -> std::sync::Arc<dyn busbar_contract::persistence::PersistenceBackend>,
) -> Result<FreshApplicationStore, String> {
    let store = cfg
        .store
        .as_ref()
        .expect("the fixture explicitly selects its Store");
    assert_eq!(
        busbar_contract::json::to_value(&store.settings.authoring(&busbar_kernel::seal::acquire()))
            .expect("the authorized fixture Store settings serialize"),
        application_store_settings(directory),
        "the fixture owns the exact configured application database path"
    );
    let database = directory.join("application.sqlite");
    for suffix in ["application.sqlite-wal", "application.sqlite-shm"] {
        assert!(
            !directory.join(suffix).exists(),
            "no retained database sidecar belongs to this new fixture"
        );
    }
    // Exclusive filesystem creation is the provisioner's evidence, not an empty Store scan.
    drop(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&database)
            .expect("the fixture exclusively creates its database file before opening the Store"),
    );
    let evidence = busbar_contract::json::to_vec(&busbar_contract::json::json!({
        "database": database, "creation": "exclusive create_new before Store open",
        "fixture": directory, "sender_quiesced": true, "backend_quiesced": true,
    }))
    .expect("fixture creation evidence serializes");
    std::fs::write(
        directory.join("principal-creation-evidence.json"),
        &evidence,
    )
    .expect("retain the actual fixture creation evidence");
    let evidence_sha256 = sha256_hex(&evidence);
    let crate::root::min3_boot::fixture::Fixture { backend, rules, .. } =
        crate::root::min3_boot::fixture::open(
            cfg,
            plugins,
            std::sync::Arc::new(crate::root::door_steps::Rules::default()),
        )
        .await?;
    let opened = core_over(decorate(backend)).await;
    let seal = busbar_kernel::seal::acquire();
    let store_sha256 = busbar_kernel::governance::principal_transition::store_fingerprint(
        &cfg.store.as_ref().map(|store| store.authoring(&seal)),
    )?;
    Ok(FreshApplicationStore {
        opened,
        rules,
        evidence_sha256,
        store_sha256,
    })
}

/// Provision and initialize a genuinely new SQLite fixture before normal app startup.
/// Call only for the first open in a new scratch directory; retained fixtures reopen normally.
pub(crate) async fn bootstrap_fresh_application_store(
    cfg: &busbar_kernel::config::RootCfg,
    plugins: &busbar_kernel::config::PluginsCfg,
    directory: &Path,
) -> Result<crate::root::min3_boot::fixture::Admitted, String> {
    provision_fresh_application_store(cfg, plugins, directory)
        .await?
        .initialize_principal_format(cfg, plugins)
        .await
}

/// The identity of the store this build links: a MIN-3 image on `LINKED.images` (WP3: the door `stores` axis is
/// retired). The build links one store, the default ephemeral one.
pub fn linked_store_module() -> &'static str {
    static NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NAME.get_or_init(|| {
        crate::LINKED
            .images
            .iter()
            .find_map(|row| {
                let admitted = (row.admit)().ok()?;
                (admitted.kind() == busbar_plugin_abi::types::KindCode::Store)
                    .then(|| admitted.identity().to_owned())
            })
            .expect("the build links a store image")
    })
    .as_str()
}

/// The start stage's native image prepare for a process with no `plugins:` block, once per test
/// process, as `main`'s `register_root` runs it (`boot::images::publish_start`) before any
/// configuration is read: the linked images' secret words, hook facts, scope kinds and operator
/// claims are published. Without it the test process has no native secret word (a `{file: …}`
/// reference read under the linked grammar is refused BUSBAR-3170 at admission) and no operator
/// claim (the operator binding judges none).
pub(crate) fn publish_linked_start() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let process = crate::root::boot::images::process().expect("the process plugin resources");
        let plugins = busbar_kernel::config::PluginsCfg {
            enabled: false,
            ..Default::default()
        };
        let prepared = crate::root::boot::images::prepare(
            &process,
            &busbar_kernel::config::grammar::PhaseOneIn::of(&plugins),
        )
        .map_err(|refusal| refusal.0)
        .expect("the linked images prepare as the start stage prepares them");
        prepared.publish_secrets();
        prepared.publish_hooks();
        prepared.publish_scope_kinds();
        prepared.publish_operator();
    });
}

/// Bind the linked first-party operator credential for this test process, through the production
/// process-start binding, and return the provider key configuration names it by. The start stage's
/// publication runs first, as it does in `main`.
pub fn bind_operator() -> &'static str {
    publish_linked_start();
    busbar_kernel::preflight::install_operator(crate::root::auth_bindings::operator_binding());
    busbar_kernel::config::operator_provider()
}
