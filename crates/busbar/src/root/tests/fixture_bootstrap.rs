// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Actual S5/Store ownership for application fixtures, before native storage admission.
use super::*;
use busbar_kernel::appbuild::RootRules;
use busbar_kernel::config::secret::SecretResolver;
use std::sync::OnceLock;

#[path = "fixture_transport.rs"]
mod transport;

struct Process {
    /// The process's one loader resources (`boot::images::process`): a process installs its plugin
    /// sinks once (a02080fd43), so the fixture shares the start stage's set rather than making a second.
    resources: Arc<busbar_plugin_loader::process::ProcessResources>,
    io: crate::root::boot::process::ProcessIo,
}

fn process() -> Result<&'static Process, String> {
    static PROCESS: OnceLock<Result<Process, String>> = OnceLock::new();
    PROCESS
        .get_or_init(|| {
            Ok(Process {
                resources: crate::root::boot::images::process()?,
                io: crate::root::boot::process::ProcessIo::new()?,
            })
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// The test process's one loader resources, shared by every fixture in it.
pub(crate) fn resources() -> Result<&'static busbar_plugin_loader::process::ProcessResources, String>
{
    process().map(|process| &*process.resources)
}

pub(crate) fn grammar(plugins: &PluginsCfg) -> Result<busbar_kernel::config::Grammar, String> {
    super::super::boot::images::fixture(&process()?.resources, plugins).map(|images| images.grammar)
}

pub(crate) struct Owners {
    built: Built,
    prefix: Arc<BootSecrets>,
    resolver: Arc<SecretResolver>,
    instances: crate::root::boot::inputs::BootInstances,
    images: crate::root::boot::images::BootImages,
}

pub(crate) struct Fixture {
    pub(crate) backend: busbar_contract::persistence::axis::OpenedBackend,
    pub(crate) rules: Arc<dyn RootRules>,
    /// The native image and secret owners the opened backend came from: a caller that takes the
    /// backend apart keeps them (`owners: _owners`) for as long as it uses it.
    pub(crate) owners: Arc<Owners>,
}

pub(crate) struct Admitted {
    pub(crate) core: Arc<busbar_kernel::persistence::facade::CoreStore>,
    pub(crate) rules: Arc<dyn RootRules>,
}

impl Fixture {
    pub(crate) async fn admit(self) -> Admitted {
        self.admit_serving().await.0
    }

    /// Admit the exact backend once, retaining its native image and secret owners for serving.
    pub(crate) async fn admit_serving(self) -> (Admitted, ServingFixture) {
        let core = crate::root::real_store::core_over(self.backend).await;
        let serving = ServingFixture {
            owners: self.owners,
            core: Arc::clone(&core),
        };
        (
            Admitted {
                core,
                rules: self.rules,
            },
            serving,
        )
    }
}

pub(crate) struct ServingFixture {
    owners: Arc<Owners>,
    core: Arc<busbar_kernel::persistence::facade::CoreStore>,
}

/// Open the real configured Store over the exact admitted S5 prefix used by its App reader.
pub(crate) async fn open(
    cfg: &RootCfg,
    plugins: &PluginsCfg,
    policy: Arc<dyn RootRules>,
) -> Result<Fixture, String> {
    let process = process()?;
    let images = super::super::boot::images::fixture(&process.resources, plugins)?;
    let protected = images.protect(cfg)?;
    let built = build(
        &process.resources,
        Guard::from_config(&cfg.destinations())?,
        cfg,
        images.images.clone(),
    )?;
    let configured = configured(cfg, &[])?;
    let specs = specifications(&configured, cfg.public_url.as_deref(), false);
    let mut core_modules = busbar_kernel::appbuild::core_secret_modules(cfg);
    core_modules.extend(
        configured
            .iter()
            .filter(|instance| instance.kind == KindCode::Secret)
            .map(|instance| instance.name.clone()),
    );
    core_modules.sort();
    core_modules.dedup();
    let roots: Vec<_> = core_modules.iter().map(String::as_str).collect();
    let plan = built
        .registry
        .boot_plan_with_core(&specs, &built.sugars, &roots)
        .map_err(|error| format!("{error:?}"))?;
    let startup = Arc::default();
    let deployment = deployment_read(startup);
    let steps = BootstrapSteps {
        registry: &built.registry,
        instances: &specs,
        deployment: &*deployment,
        store_seal: Arc::new(|| Box::new(busbar_kernel::seal::lend())),
        secrets: Mutex::new(Arc::clone(&built.secrets)),
        built: &built,
        at_rest: cfg.auth.as_ref().and_then(|auth| auth.signing_key.clone()),
    };
    for (index, phase) in &plan.steps {
        if *phase == busbar_plugin_loader::instance::BootPhase::StoreSecrets {
            steps
                .open(*index)
                .await
                .map_err(|error| format!("{error:?}"))?;
        }
    }
    let prefix = steps.prefix();
    let resolver = prefix.resolver(process.io.handle(), built.sugars.clone());
    let opener = super::super::boot::store::RegistryStore {
        registry: Arc::clone(&built.registry),
        needs: built.bootstrap_needs_for(Arc::clone(&prefix)),
        refs: prefix.refs(),
        seal: Arc::new(|| Box::new(busbar_kernel::seal::lend())),
    };
    let backend =
        super::super::boot::store::bootstrap_config_store(cfg, plugins, &opener, &resolver).await?;
    drop(steps);
    let owners = Arc::new(Owners {
        built,
        prefix,
        resolver,
        instances: crate::root::boot::inputs::BootInstances::capture(cfg),
        images: protected,
    });
    Ok(Fixture {
        owners: Arc::clone(&owners),
        backend: Arc::new(Backend {
            inner: backend,
            _owners: Arc::clone(&owners),
        }),
        rules: Arc::new(Reader {
            owner: ReaderOwner::Boot(owners),
            policy,
        }),
    })
}

enum ReaderOwner {
    Boot(Arc<Owners>),
    Carried(Arc<dyn RootRules>),
}

struct Reader {
    owner: ReaderOwner,
    policy: Arc<dyn RootRules>,
}

/// Carry a prior fixture's opened secret view while applying the candidate's explicit policy.
pub(crate) fn carry(reader: Arc<dyn RootRules>, policy: Arc<dyn RootRules>) -> Arc<dyn RootRules> {
    Arc::new(Reader {
        owner: ReaderOwner::Carried(reader),
        policy,
    })
}

impl RootRules for Reader {
    fn grammar(
        &self,
        input: &busbar_kernel::config::grammar::PhaseOneIn<'_>,
    ) -> Result<busbar_kernel::config::Grammar, busbar_kernel::config::GrammarRefusal> {
        let owners = match &self.owner {
            ReaderOwner::Boot(owners) => owners,
            ReaderOwner::Carried(reader) => return reader.grammar(input),
        };
        let refused = busbar_kernel::config::GrammarRefusal;
        let mut plugins = input.plugins.clone();
        plugins.dir = input.dir.to_string_lossy().into_owned();
        for (name, version) in input.pins {
            plugins.min_versions.insert(name.clone(), version.clone());
            plugins
                .first_party_floors
                .insert(name.clone(), version.clone());
        }
        let candidate =
            crate::root::boot::images::fixture(&process().map_err(refused)?.resources, &plugins)
                .map_err(refused)?;
        owners.images.check(&candidate)?;
        Ok(candidate.grammar)
    }
    fn secret_resolver<'a>(
        &'a self,
        cfg: &'a RootCfg,
        plugins: &'a PluginsCfg,
    ) -> BoxFut<'a, Result<Arc<SecretResolver>, String>> {
        Box::pin(async move {
            match &self.owner {
                ReaderOwner::Boot(owners) => {
                    owners.instances.check(cfg)?;
                    Ok(Arc::clone(&owners.resolver))
                }
                ReaderOwner::Carried(reader) => reader.secret_resolver(cfg, plugins).await,
            }
        })
    }
    fn check(&self, cfg: &RootCfg) -> Result<(), String> {
        self.policy.check(cfg)
    }
    fn held_document(
        &self,
        path: &std::path::Path,
    ) -> Option<busbar_contract::secure::SecureString> {
        self.policy.held_document(path)
    }
    fn check_built(&self, app: &mut busbar_kernel::state::App) -> Result<(), String> {
        self.policy.check_built(app)
    }
    fn mounted_plugin_paths(
        &self,
        app: &busbar_kernel::state::App,
    ) -> Option<std::collections::HashSet<String>> {
        self.policy.mounted_plugin_paths(app)
    }
    fn planes_awaiting_restart(&self, cfg: &RootCfg) -> Vec<&'static str> {
        self.policy.planes_awaiting_restart(cfg)
    }
    fn destinations_applied(&self, destinations: &busbar_kernel::config::Destinations) {
        self.policy.destinations_applied(destinations)
    }
    fn claim_ticket_admission(
        &self,
        identity: &busbar_kernel::host_services::VerifiedTicketIdentity,
    ) -> busbar_kernel::host_services::TicketClaimDisposition {
        self.policy.claim_ticket_admission(identity)
    }
    fn unloaded_plane_refusal(&self, keys: &[&str]) -> Option<String> {
        self.policy.unloaded_plane_refusal(keys)
    }
}

struct Backend {
    inner: busbar_contract::persistence::axis::OpenedBackend,
    _owners: Arc<Owners>,
}

impl busbar_contract::persistence::PersistenceBackend for Backend {
    fn info(&self) -> busbar_contract::persistence::BackendInfo {
        self.inner.info()
    }
    fn read(
        &self,
        request: Arc<busbar_contract::persistence::Read>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ReadResult> {
        self.inner.read(request)
    }
    fn scan(
        &self,
        request: Arc<busbar_contract::persistence::Scan>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Page> {
        self.inner.scan(request)
    }
    fn commit(
        &self,
        candidate: busbar_contract::persistence::PreparedCandidate,
        key: busbar_contract::persistence::CommitKey,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Decision> {
        self.inner.commit(candidate, key)
    }
    fn clock(
        &self,
        dataset: busbar_contract::persistence::DatasetId,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
    {
        self.inner.clock(dataset)
    }
}

#[path = "native_export_lifecycle.rs"]
mod native_export_lifecycle;
#[tokio::test]
async fn admitted_initial_store_build_retains_its_resolver_and_runtime_requires_a_candidate() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct MissingRuntime {
        inner: Arc<dyn RootRules>,
        calls: Arc<AtomicUsize>,
    }
    impl RootRules for MissingRuntime {
        fn grammar(
            &self,
            input: &busbar_kernel::config::grammar::PhaseOneIn<'_>,
        ) -> Result<busbar_kernel::config::Grammar, busbar_kernel::config::GrammarRefusal> {
            self.inner.grammar(input)
        }
        fn check(&self, cfg: &RootCfg) -> Result<(), String> {
            self.inner.check(cfg)
        }
        fn prepare_candidate<'a>(
            &'a self,
            _: &'a RootCfg,
            _: &'a PluginsCfg,
        ) -> BoxFut<'a, Result<Option<busbar_kernel::appbuild::CandidatePreparation>, String>>
        {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async { Err("native fixture has no serving candidate owner".into()) })
        }
    }

    #[cfg(distribution_root)]
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let directory = crate::root::test_plugins::scratch("initial-runtime-candidate-boundary");
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    let module = manifest.name.clone();
    let library = std::fs::read(library_path).expect("actual Store image reads");
    std::fs::write(
        directory.join("store.tar.gz"),
        crate::root::test_plugins::signed(
            &crate::root::test_plugins::key(0x5a),
            manifest,
            &library,
        ),
    )
    .expect("stage signed actual Store");
    crate::root::linked::register_stores();
    busbar_kernel::preflight::install_operator(crate::root::auth_bindings::operator_binding());
    let plugins = crate::root::test_plugins::trusted_config(&directory);
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {}, "auth": {"chain": []},
        "store": {"module": module, "settings": crate::root::test_plugins::application_store_settings(&directory)},
    }), &crate::root::boot::axis_test_grammar()).expect("actual Store deployment parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("actual Store deployment resolves");
    let admitted =
        crate::root::test_plugins::bootstrap_fresh_application_store(&cfg, &plugins, &directory)
            .await
            .expect("actual signed Store is provisioned and admitted once");
    let resolver = admitted
        .rules
        .secret_resolver(&cfg, &plugins)
        .await
        .expect("same admitted bootstrap secret owner");
    let calls = Arc::new(AtomicUsize::new(0));
    let rules: Arc<dyn RootRules> = Arc::new(MissingRuntime {
        inner: admitted.rules,
        calls: Arc::clone(&calls),
    });
    let (app, rotate, limits) =
        busbar_kernel::appbuild::build_boot_app(busbar_kernel::appbuild::BootBuild {
            cfg,
            judged: None,
            plugins_cfg: plugins.clone(),
            overlay_path: None,
            base_hook_names: Default::default(),
            base_group_names: Default::default(),
            config_paths: (None, None),
            rules: &rules,
            boot_store: Arc::clone(&admitted.core),
            secret_resolver: Arc::clone(&resolver),
        })
        .await
        .expect("owned initial build does not attempt runtime OPEN before NodeBook");
    assert_eq!(calls.load(Ordering::Acquire), 0);
    assert!(Arc::ptr_eq(&app.secret_resolver, &resolver));
    assert_eq!(
        app.prepared_generation(),
        None,
        "initial native finish awaits confirmed boot identity"
    );
    if let Some(rotate) = rotate {
        rotate.await;
    }
    drop(limits);
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    let before = app.config_generation.load(Ordering::Acquire);
    let runtime = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(cfg),
        plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        Some(&app),
        &rules,
        Some(Arc::clone(&admitted.core)),
        false,
    )
    .await;
    assert_eq!(
        runtime
            .err()
            .expect("missing real runtime producer refuses"),
        "native fixture has no serving candidate owner"
    );
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_eq!(app.config_generation.load(Ordering::Acquire), before);
    drop(app);
    drop(rules);
    drop(admitted.core);
    drop(resolver);
    std::fs::remove_dir_all(directory).expect("remove finished actual Store fixture");
}
