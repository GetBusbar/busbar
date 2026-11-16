// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Actual S5/Store ownership for application fixtures, before native storage admission.
use super::*;
use busbar_kernel::appbuild::RootRules;
use busbar_kernel::config::secret::SecretResolver;

struct Process {
    resources: busbar_plugin_loader::process::ProcessResources,
    io: crate::root::boot::process::ProcessIo,
}

fn process() -> Result<&'static Process, String> {
    static PROCESS: OnceLock<Result<Process, String>> = OnceLock::new();
    PROCESS
        .get_or_init(|| {
            Ok(Process {
                resources: busbar_plugin_loader::process::ProcessResources::new()?,
                io: crate::root::boot::process::ProcessIo::new()?,
            })
        })
        .as_ref()
        .map_err(Clone::clone)
}

pub(crate) fn grammar(plugins: &PluginsCfg) -> Result<busbar_kernel::config::Grammar, String> {
    super::super::boot::images::fixture(&process()?.resources, plugins).map(|images| images.grammar)
}

struct Owners {
    _registry: Arc<MinRegistry>,
    resolver: Arc<SecretResolver>,
    instances: crate::root::boot::inputs::BootInstances,
    images: crate::root::boot::images::BootImages,
}

pub(crate) struct Fixture {
    pub(crate) backend: busbar_contract::persistence::axis::OpenedBackend,
    pub(crate) rules: Arc<dyn RootRules>,
}

pub(crate) struct Admitted {
    pub(crate) core: Arc<busbar_kernel::persistence::facade::CoreStore>,
    pub(crate) rules: Arc<dyn RootRules>,
}

impl Fixture {
    pub(crate) async fn admit(self) -> Admitted {
        Admitted {
            core: crate::root::real_store::core_over(self.backend).await,
            rules: self.rules,
        }
    }
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
        images.images,
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
    let owners = Arc::new(Owners {
        _registry: Arc::clone(&built.registry),
        resolver,
        instances: crate::root::boot::inputs::BootInstances::capture(cfg),
        images: protected,
    });
    Ok(Fixture {
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
    fn check_built(&self, app: &busbar_kernel::state::App) -> Result<(), String> {
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
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Decision> {
        self.inner.commit(candidate)
    }
    fn clock(
        &self,
        dataset: busbar_contract::persistence::DatasetId,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
    {
        self.inner.clock(dataset)
    }
}
