// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Actual S5/Store ownership for application fixtures, before native storage admission.
use super::*;
use busbar_kernel::appbuild::RootRules;
use busbar_kernel::config::secret::SecretResolver;
use std::sync::OnceLock;

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
    built: Built,
    prefix: Arc<BootSecrets>,
    planes: Vec<PlaneImage>,
    resolver: Arc<SecretResolver>,
    instances: crate::root::boot::inputs::BootInstances,
    images: crate::root::boot::images::BootImages,
}

pub(crate) struct Fixture {
    pub(crate) backend: busbar_contract::persistence::axis::OpenedBackend,
    pub(crate) rules: Arc<dyn RootRules>,
    owners: Arc<Owners>,
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

pub(crate) struct PlaneFixture {
    pub(crate) seat: PortSeat,
    pub(crate) workers: crate::root::boot::workers::PreparedWorkers,
    _owners: Arc<Owners>,
    _prefix: Arc<BootSecrets>,
    records: Records,
    directory: Directory,
    hook_specs: Vec<Configured>,
    public_url: Option<String>,
}

pub(crate) struct HookFixture {
    pub(crate) who: Namespace,
    pub(crate) port: Arc<dyn busbar_ports::hook::HookPort>,
    pub(crate) described: busbar_plugin_loader::instance::Described,
    pub(crate) limits: busbar_plugin_abi::host_side::caller::InstanceLimits,
}

impl PlaneFixture {
    /// Open the candidate's actual hooks over the plane's same Registry, secret prefix, Store
    /// and directory owners. The hook pipeline receives the admitted immutable describe records,
    /// including D_WORD; no legacy HookCalls adapter or synthetic capability grant is involved.
    pub(crate) async fn hooks(
        &self,
    ) -> Result<std::collections::BTreeMap<String, HookFixture>, String> {
        let built = &self._owners.built;
        let needs = built.needs_for(
            Arc::clone(&self._prefix),
            Arc::clone(&self.records),
            Arc::clone(&self.directory),
        );
        let refs = self._prefix.refs();
        let specs = specifications(&self.hook_specs, self.public_url.as_deref(), false);
        let mut opened = std::collections::BTreeMap::new();
        for (_, spec) in specs {
            let prepared = built
                .registry
                .reserve(&spec)
                .map_err(|why| format!("{why:?}"))?;
            let described = built
                .registry
                .described(prepared.identity())
                .ok_or("native hook reservation lost its admitted description")?;
            let who = Namespace {
                plugin: Arc::from(prepared.identity()),
                name: Arc::from(prepared.name()),
                instance: prepared.id(),
                slot: prepared.slot(),
            };
            let port = built
                .registry
                .open_hook_reserved(prepared, &needs, &refs)
                .await
                .map_err(|why| format!("{why:?}"))?;
            opened.insert(
                spec.name.to_owned(),
                HookFixture {
                    who,
                    port,
                    described,
                    limits: spec.limits,
                },
            );
        }
        Ok(opened)
    }
}

impl ServingFixture {
    /// Open one actual admitted plane through the production S8 composer. The caller must build
    /// its App over `admit_serving`'s core and pass complete services from root::serve::compose.
    /// Workers remain dormant until the caller has published its routes and AppHandle.
    pub(crate) async fn plane(
        &self,
        cfg: &RootCfg,
        instance: &str,
        app: &busbar_kernel::state::App,
        services: Arc<KernelServices>,
    ) -> Result<PlaneFixture, String> {
        let store = app
            .governance
            .as_ref()
            .ok_or("native fixture needs actual governance")?
            .core_store_handle()
            .map_err(|why| why.to_string())?;
        if !Arc::ptr_eq(&store, &self.core) {
            return Err("native fixture App uses a different Store attachment".into());
        }
        self.owners.instances.check(cfg)?;
        if !cfg.min3.provisioning.is_empty() {
            return Err("native plane fixture needs the complete Auth provisioning plan".into());
        }
        let image = self
            .owners
            .planes
            .iter()
            .find(|image| {
                (if image.alias.is_empty() {
                    image.identity.as_str()
                } else {
                    image.alias.as_str()
                }) == instance
            })
            .ok_or_else(|| format!("native fixture has no admitted plane {instance}"))?;
        let built = &self.owners.built;
        let prefix = Arc::clone(&self.owners.prefix);
        let core = Arc::new(core_secrets_of(cfg, &prefix).await?);
        let mut instances = plane_instances(
            std::slice::from_ref(image),
            &super::super::door_steps::raw_sections(cfg),
        )?;
        let declared = declared_planes(&built.registry, &mut instances)?;
        let specs = specifications(&instances, cfg.public_url.as_deref(), false);
        let records = Arc::new(StoreRecords::new(Arc::clone(&store)));
        let provisioning = super::super::provisioning::prepare(
            Arc::clone(&store),
            Arc::new(LogEvents),
            Vec::new(),
        )
        .await?;
        let directory = Arc::clone(&provisioning.directory);
        let shared = Arc::new(Shared::new(
            Arc::clone(&records),
            Arc::new(StorePushQueue::new(
                Arc::clone(&store),
                Arc::new(RetryPolicyImpl::default()),
            )),
            store,
            busbar_kernel::plane_driver::port_work::governed_binder(
                app.governance.clone(),
                app.role_bindings.clone(),
            ),
        ));
        let steps = Steps {
            registry: &built.registry,
            instances: &specs,
            services: Some(services),
            seats: Mutex::default(),
            shared: Arc::clone(&shared),
            directory: provisioning.directory,
            core,
            secrets: Arc::clone(&prefix),
            built,
            seat: SeatShared {
                upstreams: declared
                    .into_iter()
                    .map(|(name, split)| (name, Arc::new(split.definitions)))
                    .collect(),
                signals: Arc::clone(&shared.signals),
                secrets: Arc::new(SpawnCustody(Arc::clone(&prefix))),
                kernel: Arc::new(Kernel::new()),
                table: ConnTable::installed(),
            },
            probes: Mutex::default(),
        };
        let (_, spec) = specs
            .first()
            .ok_or("native fixture lost its plane specification")?;
        let prepared = built
            .registry
            .reserve(spec)
            .map_err(|why| format!("{why:?}"))?;
        steps
            .open_plane(spec, prepared)
            .await
            .map_err(|why| format!("{why:?}"))?;
        let seat = steps
            .seats
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .ok_or("native fixture opened no plane seat")?;
        let mut workers = super::super::boot::workers::PreparedWorkers::new();
        workers.push(provisioning.refresh.run());
        for probe in steps
            .probes
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
        {
            workers.push(probe);
        }
        let ticking = seat.clone();
        workers.push(async move { ticking.tick_task(shared.push.clone()).await });
        let seal = busbar_kernel::seal::lend();
        let hook_specs = cfg
            .hooks
            .iter()
            .map(|(name, hook)| {
                Ok(Configured {
                    kind: KindCode::Hook,
                    identity: hook.module.clone(),
                    name: name.clone(),
                    config: hook
                        .settings
                        .encode()
                        .map_err(|why| format!("hooks.{name}: {why}"))?
                        .into_exposed(&seal),
                    limits: busbar_kernel::appbuild::instance_limits(cfg, "hooks", name),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(PlaneFixture {
            seat,
            workers,
            _owners: Arc::clone(&self.owners),
            _prefix: prefix,
            records,
            directory,
            hook_specs,
            public_url: cfg.public_url.clone(),
        })
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
    let planes = images
        .aliases
        .iter()
        .filter(|(identity, _)| {
            images
                .images
                .described(identity)
                .is_some_and(|facts| facts.kind == KindCode::Plane)
        })
        .map(|(identity, alias)| PlaneImage {
            identity: identity.clone(),
            alias: alias.clone(),
        })
        .collect();
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
    drop(steps);
    let owners = Arc::new(Owners {
        built,
        prefix,
        planes,
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
