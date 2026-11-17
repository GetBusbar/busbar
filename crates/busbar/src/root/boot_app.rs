// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The boot's configuration reader and its one application build (MIGRATE-ON-BOOT r42 §3 step 2).
//!
//! [`ConfigRules`] are the rules every boot read of config.yaml and its providers catalog runs under:
//! an unstamped boot reads the document the migrate seam planned in memory ([`crate::root::migrate::held`]),
//! every other read reads the file. The gateway reads only current bytes: conversion runs in the seam, before
//! the re-exec. [`BootApp`] builds the one `App` over the store admission the boot holds and retains the
//! build and its readiness checks until the boot adopts the ready candidate.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use busbar_contract::crypto::Sha256;
use busbar_contract::secure::SecureString;
use busbar_kernel::{
    appbuild::{self, ConfirmedLimits, InstalledLimits, RootRules},
    config::{self, overlay::OverlayStore, DeployCfg, PluginsCfg, ProviderDef, RootCfg},
    persistence::{
        facade::{CoreStore, WriterAuthority},
        startup::Startup,
    },
    state::App,
};
use tokio::{
    sync::{watch, Mutex},
    task::JoinHandle,
};

use crate::root::{durability::NodeBook, linked::Compose};

/// The rules of the boot's configuration reads: the held plan in place of config.yaml (and of the planned
/// providers catalog) on an unstamped boot, the file otherwise. The build judges the configuration itself.
pub(crate) struct ConfigRules {
    pub(crate) process: Arc<busbar_plugin_loader::process::ProcessResources>,
}

impl RootRules for ConfigRules {
    fn prepare_read(
        &self,
        input: &config::grammar::PhaseOneIn<'_>,
    ) -> Result<config::grammar::PreparedConfigRead, config::GrammarRefusal> {
        crate::root::boot::images::prepare(&self.process, input)?.prepared_read(input)
    }

    fn grammar(
        &self,
        input: &config::grammar::PhaseOneIn<'_>,
    ) -> Result<config::Grammar, config::GrammarRefusal> {
        crate::root::boot::phase_one(&self.process, input)
    }
    fn check(&self, _: &RootCfg) -> Result<(), String> {
        Ok(())
    }
    fn held_document(&self, path: &Path) -> Option<SecureString> {
        crate::root::migrate::held(path)
    }
}

/// Reads after the bootstrap Store opens must preserve the images and inputs that opened it.
pub(crate) struct ProtectedRules {
    pub(crate) reader: ConfigRules,
    pub(crate) images: crate::root::boot::images::BootImages,
    pub(crate) instances: Arc<crate::root::boot::inputs::BootInstances>,
}

impl ProtectedRules {
    /// Root owns the exact effective admission through typed parsing and later instance opens.
    pub(crate) fn read_under_store(
        &self,
        config_path: &Path,
        providers: Option<&Path>,
        doc: &config::overlay::OverlayDoc,
    ) -> Result<
        (
            appbuild::LoadedConfig,
            crate::root::boot::images::FileImages,
        ),
        String,
    > {
        let mut patch = doc.document_patch.clone();
        let mut providers_patch = doc.providers_patch.clone();
        let raw = appbuild::read_config_documents(
            config_path,
            providers,
            false,
            config::EnvSubst::Strict,
            self,
            appbuild::DocumentPatchLoad {
                patch: patch.as_mut(),
                providers_patch: providers_patch.as_mut(),
                admission: None,
            },
        )?;
        let plugins = raw.plugins_block()?;
        let input = config::grammar::PhaseOneIn {
            plugins: &plugins,
            dir: Path::new(&plugins.dir),
            pins: &doc.plugin_versions,
            fetch: config::grammar::Fetch::None,
        };
        let images = crate::root::boot::images::prepare(&self.reader.process, &input)
            .map_err(|error| error.0)?;
        self.images.check(&images).map_err(|error| error.0)?;
        let read = images.prepared_read(&input).map_err(|error| error.0)?;
        let loaded = raw.typed_prepared(Arc::new(read))?;
        Ok((loaded, images))
    }
}

impl RootRules for ProtectedRules {
    fn prepare_read(
        &self,
        input: &config::grammar::PhaseOneIn<'_>,
    ) -> Result<config::grammar::PreparedConfigRead, config::GrammarRefusal> {
        let candidate = crate::root::boot::images::prepare(&self.reader.process, input)?;
        self.images.check(&candidate)?;
        candidate.prepared_read(input)
    }

    fn grammar(
        &self,
        input: &config::grammar::PhaseOneIn<'_>,
    ) -> Result<config::Grammar, config::GrammarRefusal> {
        let candidate = crate::root::boot::images::prepare(&self.reader.process, input)?;
        self.images.check(&candidate)?;
        Ok(candidate.grammar)
    }

    fn check(&self, cfg: &RootCfg) -> Result<(), String> {
        self.instances.check(cfg)
    }

    fn held_document(&self, path: &Path) -> Option<SecureString> {
        self.reader.held_document(path)
    }
}

/// THE STORE BOOTSTRAP: the non-serving projection of the deployment the store opens under, before the
/// effective configuration resolves. The deployment is current bytes (the seam converted any 1.5.5 shape
/// before this read), so it is the kernel's projection with nothing narrowed.
pub(crate) fn store_bootstrap(deploy: &DeployCfg) -> Result<RootCfg, Vec<String>> {
    config::bootstrap::resolve_store_bootstrap(deploy)
}

pub(crate) struct Preparation {
    pub secret_resolver: Arc<config::secret::SecretResolver>,
    pub startup: Startup,
    pub config: RootCfg,
    /// The semantic pass's one result when boot already judged `config` (the fresh-instance
    /// principal transition); construction consumes it instead of judging again.
    pub judged: Option<busbar_kernel::config_validate::Judged>,
    pub plugins: PluginsCfg,
    pub overlay: Option<Arc<OverlayStore>>,
    pub deploy: DeployCfg,
    pub definitions: HashMap<String, ProviderDef>,
    pub base_hook_names: HashSet<String>,
    pub base_group_names: HashSet<String>,
    pub config_path: PathBuf,
    pub providers_path: PathBuf,
    pub providers_override: Option<PathBuf>,
    pub rules: Arc<dyn RootRules>,
    pub shutdown_rx: watch::Receiver<bool>,
    pub shutdown_tx: watch::Sender<bool>,
}

/// Moving this value into serving transfers the actual validated owners.
/// No field is rebuilt or reopened after readiness is validated.
pub(crate) struct ReadyCandidate {
    pub startup: Startup,
    pub core: Arc<CoreStore>,
    pub app: Arc<App>,
    pub book: NodeBook,
    pub limits: ConfirmedLimits,
    pub node_lease_task: Option<JoinHandle<Result<(), String>>>,
    pub deploy: DeployCfg,
    pub overlay: Option<Arc<OverlayStore>>,
    pub configuration_fingerprint: [u8; 32],
}

/// A failed preparation keeps every owner it has constructed. This type cannot
/// be adopted as a serving candidate; disposal owns the real shutdown path.
pub(crate) struct PreparationFailure {
    reason: String,
    pub startup: Option<Startup>,
    pub app: Option<Arc<App>>,
    pub book: Option<NodeBook>,
    pub limits: Option<InstalledLimits>,
    pub node_lease_task: Option<JoinHandle<Result<(), String>>>,
    pub book_failure: Option<Box<crate::root::boot::BookFailure>>,
}
impl PreparationFailure {
    fn new(startup: Startup) -> Self {
        Self {
            reason: String::new(),
            startup: Some(startup),
            app: None,
            book: None,
            limits: None,
            node_lease_task: None,
            book_failure: None,
        }
    }
    fn refused(mut self, reason: impl Into<String>) -> Box<Self> {
        self.reason = reason.into();
        if let Some(task) = &self.node_lease_task {
            task.abort();
        }
        Box::new(self)
    }
    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }
}
impl Drop for PreparationFailure {
    fn drop(&mut self) {
        if let Some(task) = &self.node_lease_task {
            task.abort();
        }
    }
}
impl std::fmt::Display for PreparationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}
impl std::fmt::Debug for PreparationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparationFailure([retained owners])")
    }
}
impl std::error::Error for PreparationFailure {}

/// The one application-building segment of the boot.
/// Call through [`BootApp`] so cancellation retains this future.
pub(crate) async fn prepare(input: Preparation) -> Result<ReadyCandidate, Box<PreparationFailure>> {
    // The retained future may be polled by a task other than its creator. Scope its execution,
    // including appbuild's Secret/Store work before BookPreparation installs measurement custody.
    Box::pin(crate::root::measurements::maintenance(prepare_inner(input))).await
}

async fn prepare_inner(input: Preparation) -> Result<ReadyCandidate, Box<PreparationFailure>> {
    let Preparation {
        secret_resolver,
        startup,
        config,
        judged,
        plugins,
        overlay,
        deploy,
        definitions,
        base_hook_names,
        base_group_names,
        config_path,
        providers_path,
        providers_override,
        rules,
        shutdown_rx,
        shutdown_tx,
    } = input;
    let mut failed = PreparationFailure::new(startup);
    let Some(core) = failed.startup.as_ref().and_then(Startup::store) else {
        return Err(failed.refused("startup preparation requires admitted persistence"));
    };
    if overlay.as_ref().is_some_and(|overlay| {
        !overlay
            .core_store_handle()
            .is_ok_and(|owner| Arc::ptr_eq(&owner, &core))
    }) {
        return Err(failed.refused("startup overlay belongs to another persistence owner"));
    }
    let Some(source) = deploy.document_source_fingerprints else {
        return Err(failed.refused("startup configuration source fingerprints are missing"));
    };
    let mut configuration_binding = Sha256::new();
    configuration_binding.update(b"busbar.startup-configuration.v1\0");
    configuration_binding.update(&source.binding_digest()[..]);
    let configuration_fingerprint = configuration_binding.finish();
    if *shutdown_rx.borrow() {
        return Err(failed.refused("startup was stopped before application preparation"));
    }
    for on_config in crate::ROOT_UNITS.iter().filter_map(|unit| unit.on_config) {
        on_config(&config.limits);
    }
    let composes: Vec<Compose> = crate::LINKED
        .compose
        .iter()
        .filter_map(|capture| capture(&config))
        .collect();
    let Some(store) = config.store.as_ref() else {
        return Err(failed.refused(config::store_required()));
    };
    let store_module = store.module.clone();
    let (mut app, rotation, limits) =
        match Box::pin(appbuild::build_boot_app(appbuild::BootBuild {
            secret_resolver,
            cfg: config,
            judged,
            plugins_cfg: plugins,
            overlay_path: overlay.clone(),
            base_hook_names,
            base_group_names,
            config_paths: (Some(config_path), Some(providers_path)),
            rules: &rules,
            boot_store: core.clone(),
        }))
        .await
        {
            Ok(built) => built,
            Err(reason) => return Err(failed.refused(reason)),
        };
    if rotation.is_some() {
        failed.app = Some(Arc::new(app));
        failed.limits = Some(limits);
        return Err(failed.refused("initial startup unexpectedly prepared a credential rotation"));
    }
    app.providers_override = providers_override;
    config::readback::ConfiguredView::capture_documents(&mut app, &deploy, &definitions);
    limits.stage_boot();
    let app = Arc::new(app);
    failed.app = Some(app.clone());
    failed.limits = Some(limits);
    match Box::pin(crate::root::boot::book_with_lease_watch(
        &app,
        &store_module,
        shutdown_rx,
        shutdown_tx,
    ))
    .await
    {
        Ok((book, node_lease_task)) => {
            failed.book = Some(book);
            failed.node_lease_task = node_lease_task;
        }
        Err(book_failure) => {
            let reason = book_failure.reason().to_owned();
            failed.book_failure = Some(Box::new(book_failure));
            return Err(failed.refused(reason));
        }
    }
    for compose in composes {
        compose(&*app.secret_resolver);
    }
    busbar_kernel::admin::seam::record_boot(&app);
    if let Err(reason) = busbar_kernel::boot::hydrate_all(&app).await {
        return Err(failed.refused(reason));
    }
    let installed = failed.limits.take().expect("retained configured limits");
    let prepared = match installed.prepare_rates().await {
        Ok(prepared) => prepared,
        Err(reason) => return Err(failed.refused(reason)),
    };
    let limits = match prepared.confirm_activation().await {
        Ok(confirmed) => confirmed,
        Err(reason) => return Err(failed.refused(reason)),
    };
    Ok(ReadyCandidate {
        startup: failed.startup.take().expect("retained admitted startup"),
        core,
        app,
        book: failed.book.take().expect("retained native book"),
        limits,
        node_lease_task: failed.node_lease_task.take(),
        deploy,
        overlay,
        configuration_fingerprint,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Reopening,
    Hydrating,
    Validating,
    Ready,
}

type Preparing =
    Pin<Box<dyn Future<Output = Result<ReadyCandidate, Box<PreparationFailure>>> + Send>>;
#[derive(Clone, Copy)]
struct Readiness {
    digest: [u8; 32],
    authority: WriterAuthority,
}
#[derive(Clone, Copy)]
enum ValidationError {
    Retryable(&'static str),
    Permanent(&'static str),
}
type Validating = Pin<Box<dyn Future<Output = Result<Readiness, ValidationError>> + Send>>;

struct State {
    phase: Phase,
    preparing: Option<Preparing>,
    candidate: Option<Arc<Mutex<ReadyCandidate>>>,
    validating: Option<Validating>,
    receipt: Option<Readiness>,
    failure: Option<String>,
    failed_preparation: Option<Box<PreparationFailure>>,
    pending_reason: Option<&'static str>,
    taken: bool,
}

impl Drop for State {
    fn drop(&mut self) {
        // Drop a suspended validator before inspecting its locked candidate.
        self.validating = None;
        self.preparing = None;
        if let Some(candidate) = &self.candidate {
            if let Ok(candidate) = candidate.try_lock() {
                if let Some(task) = &candidate.node_lease_task {
                    task.abort();
                }
            }
        }
    }
}

/// Owns both pending futures and their candidate. A bounded-out caller cannot
/// restart application construction or initialize the global owners a second time.
pub(crate) struct BootApp {
    state: Mutex<State>,
}

impl BootApp {
    /// The boot's one application build over its store admission: the MIN-3 walk's (its store's own open
    /// converted its data; core's records step ran after admission) or the old ABI's current dataset.
    pub(crate) fn new(input: Preparation) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                phase: Phase::Reopening,
                preparing: Some(Box::pin(prepare(input))),
                candidate: None,
                validating: None,
                receipt: None,
                failure: None,
                failed_preparation: None,
                pending_reason: None,
                taken: false,
            }),
        })
    }
    #[cfg(test)]
    pub(crate) async fn phase(&self) -> Phase {
        self.state.lock().await.phase
    }

    #[cfg(test)]
    pub(crate) async fn pending_reason(&self) -> Option<&'static str> {
        self.state.lock().await.pending_reason
    }

    /// One bounded wait. Timeout leaves the same future in custody for the next call.
    pub(crate) async fn readiness(&self) -> Result<Option<[u8; 32]>, String> {
        let mut state = self.state.lock().await;
        if state.taken {
            return Err("startup candidate was already adopted".into());
        }
        if let Some(failure) = &state.failure {
            return Err(failure.clone());
        }
        if let Some(receipt) = state.receipt {
            return Ok(Some(receipt.digest));
        }
        if state.preparing.is_some() {
            state.phase = Phase::Hydrating;
            let result = tokio::time::timeout(
                Duration::from_secs(30),
                state
                    .preparing
                    .as_mut()
                    .expect("retained preparation")
                    .as_mut(),
            )
            .await;
            match result {
                Err(_) => return Ok(None),
                Ok(Err(error)) => {
                    state.preparing = None;
                    let reason = error.reason().to_owned();
                    state.failure = Some(reason.clone());
                    state.failed_preparation = Some(error);
                    return Err(reason);
                }
                Ok(Ok(candidate)) => {
                    state.preparing = None;
                    state.candidate = Some(Arc::new(Mutex::new(candidate)));
                }
            }
        }
        if state.validating.is_none() {
            let candidate = state
                .candidate
                .as_ref()
                .ok_or("startup candidate missing")?
                .clone();
            state.validating = Some(Box::pin(async move {
                let mut candidate = candidate.lock().await;
                loop {
                    match Box::pin(crate::root::measurements::maintenance(validate(
                        &mut candidate,
                    )))
                    .await
                    {
                        Err(ValidationError::Retryable(_)) => {
                            // The same validator and serving candidate retain custody while
                            // their typed native owners resolve the original operations.
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        result => return result,
                    }
                }
            }));
        }
        state.phase = Phase::Validating;
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            state
                .validating
                .as_mut()
                .expect("retained validation")
                .as_mut(),
        )
        .await;
        match result {
            Err(_) => Ok(None),
            Ok(Err(ValidationError::Retryable(reason))) => {
                state.validating = None;
                state.pending_reason = Some(reason);
                Ok(None)
            }
            Ok(Err(ValidationError::Permanent(reason))) => {
                state.validating = None;
                if let Some(candidate) = &state.candidate {
                    if let Some(task) = &candidate.lock().await.node_lease_task {
                        task.abort();
                    }
                }
                state.failure = Some(reason.into());
                Err(reason.into())
            }
            Ok(Ok(receipt)) => {
                state.validating = None;
                state.receipt = Some(receipt);
                state.pending_reason = None;
                state.phase = Phase::Ready;
                Ok(Some(receipt.digest))
            }
        }
    }
    /// The ready candidate, once [`Self::readiness`] answered: checked live again, and handed over once.
    pub(crate) async fn take(&self) -> Result<Option<ReadyCandidate>, String> {
        let mut state = self.state.lock().await;
        if state.taken {
            return Err("startup candidate was already adopted".into());
        }
        if let Some(failure) = &state.failure {
            return Err(failure.clone());
        }
        let receipt = state
            .receipt
            .ok_or("startup candidate has no readiness receipt")?;
        let candidate = state
            .candidate
            .as_ref()
            .ok_or("startup candidate missing")?
            .clone();
        let checked = {
            let candidate = candidate.lock().await;
            check_live(&candidate).and_then(|()| {
                let authority = candidate.core.authority().map_err(|_| {
                    ValidationError::Permanent("candidate authority observation refused")
                })?;
                if authority != receipt.authority {
                    return Err(ValidationError::Permanent(
                        "candidate writer changed after readiness validation",
                    ));
                }
                Ok(())
            })
        };
        drop(candidate);
        match checked {
            Ok(()) => {}
            Err(ValidationError::Retryable(reason)) => {
                state.pending_reason = Some(reason);
                return Ok(None);
            }
            Err(ValidationError::Permanent(reason)) => {
                if let Some(candidate) = &state.candidate {
                    if let Some(task) = &candidate.lock().await.node_lease_task {
                        task.abort();
                    }
                }
                state.failure = Some(reason.into());
                return Err(reason.into());
            }
        }
        let candidate = state.candidate.take().ok_or("startup candidate missing")?;
        let candidate = match Arc::try_unwrap(candidate) {
            Ok(candidate) => candidate.into_inner(),
            Err(candidate) => {
                state.candidate = Some(candidate);
                state.pending_reason = Some("startup candidate validator remains active");
                return Ok(None);
            }
        };
        state.taken = true;
        state.phase = Phase::Ready;
        Ok(Some(candidate))
    }
}

fn check_owners(candidate: &ReadyCandidate) -> Result<(), ValidationError> {
    use ValidationError::Permanent;
    let admitted = candidate
        .startup
        .store()
        .ok_or(Permanent("candidate startup is not admitted"))?;
    let book_journal = candidate
        .book
        .durability
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .runtime_journal();
    if !Arc::ptr_eq(&admitted, &candidate.core)
        || !Arc::ptr_eq(&candidate.book.runtime_journal, &book_journal)
        || !candidate.book.runtime_journal.is_bound_to(&candidate.core)
    {
        return Err(Permanent("candidate persistence owners do not match"));
    }
    if candidate
        .node_lease_task
        .as_ref()
        .is_some_and(JoinHandle::is_finished)
    {
        return Err(Permanent(
            "candidate node lease task ended before publication",
        ));
    }
    let governance = candidate
        .app
        .governance
        .as_ref()
        .ok_or(Permanent("candidate governance is missing"))?;
    if !Arc::ptr_eq(
        &governance
            .core_store_handle()
            .map_err(|_| Permanent("candidate governance observation refused"))?,
        &candidate.core,
    ) {
        return Err(Permanent("candidate governance owner does not match"));
    }
    for overlay in [
        candidate.overlay.as_ref(),
        candidate.app.overlay_path.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if !overlay
            .core_store_handle()
            .is_ok_and(|store| Arc::ptr_eq(&store, &candidate.core))
        {
            return Err(Permanent("candidate overlay owner does not match"));
        }
    }
    let prices = crate::root::kernel::ROOT_CARD
        .card_store()
        .ok_or(Permanent("candidate prices were not hydrated"))?;
    if !prices.is_bound_to(&candidate.core) {
        return Err(Permanent("candidate price owner does not match"));
    }
    Ok(())
}

fn check_live(candidate: &ReadyCandidate) -> Result<(), ValidationError> {
    use ValidationError::{Permanent, Retryable};
    check_owners(candidate)?;
    if candidate.book.runtime_journal.pending_records() != 0
        || candidate
            .core
            .pending_operations()
            .map_err(|_| Permanent("candidate pending state observation refused"))?
            != 0
    {
        return Err(Retryable("candidate native originals remain pending"));
    }
    let governance = candidate
        .app
        .governance
        .as_ref()
        .ok_or(Permanent("candidate governance is missing"))?;
    let prices = crate::root::kernel::ROOT_CARD
        .card_store()
        .ok_or(Permanent("candidate prices were not hydrated"))?;
    if governance.has_unsettled_persistence() || prices.has_unconfirmed_operations() {
        return Err(Retryable("candidate semantic recovery remains pending"));
    }
    Ok(())
}

async fn validate(candidate: &mut ReadyCandidate) -> Result<Readiness, ValidationError> {
    use ValidationError::Permanent;
    check_owners(candidate)?;
    let governance = candidate
        .app
        .governance
        .as_ref()
        .ok_or(Permanent("candidate governance is missing"))?;
    governance
        .resume_correction_verdicts(&candidate.app.cost)
        .await
        .map_err(|_| Permanent("candidate correction recovery refused"))?;
    governance
        .flush_unit_checkpoints()
        .await
        .map_err(|_| Permanent("candidate checkpoint recovery refused"))?;
    let _ = governance.settle_ticket_operations().await;
    let _ = governance.flush_budgets().await;
    let _ = governance.flush_metering().await;
    let prices = crate::root::kernel::ROOT_CARD
        .card_store()
        .ok_or(Permanent("candidate prices were not hydrated"))?;
    prices
        .retry_pending()
        .await
        .map_err(|_| Permanent("candidate price recovery refused"))?;
    prices
        .rescan(None)
        .await
        .map_err(|_| Permanent("candidate price observation refused"))?;
    candidate
        .app
        .demotion_record
        .snapshot()
        .await
        .map_err(|_| Permanent("candidate trust observation refused"))?;
    busbar_kernel::audit::auditlog::flush_pending()
        .await
        .map_err(|_| Permanent("candidate audit flush refused"))?;
    candidate
        .book
        .runtime_journal
        .flush()
        .await
        .map_err(|error| {
            use busbar_contract::persistence::Failure;
            use busbar_kernel::persistence::journal::runtime::RuntimeError;
            match error {
                RuntimeError::Pending
                | RuntimeError::Backend(
                    Failure::Unknown | Failure::Unavailable | Failure::Overloaded,
                ) => ValidationError::Retryable("candidate journal original remains pending"),
                _ => Permanent("candidate journal flush refused"),
            }
        })?;
    let chain = candidate
        .book
        .durability
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .chain_at();
    let records = chain
        .read()
        .await
        .map_err(|_| Permanent("candidate journal observation refused"))?
        .map_err(|_| Permanent("candidate journal verification refused"))?;
    let identity = candidate
        .core
        .identity()
        .snapshot()
        .await
        .map_err(|_| Permanent("candidate identity observation refused"))?;
    let price_snapshot = candidate.core.prices().snapshot().await.map_err(|error| {
        use busbar_contract::persistence::Failure;
        use busbar_kernel::governance::persistence::prices::Error;
        match error {
            Error::Backend(
                Failure::Unknown | Failure::Unavailable | Failure::Overloaded | Failure::StaleScan,
            ) => ValidationError::Retryable("candidate price verification remains pending"),
            _ => Permanent("candidate price verification refused"),
        }
    })?;
    let now = busbar_kernel::store::now();
    for credential in &identity.credentials {
        if !credential.meta.is_live(now)
            || credential.meta.secret_form != busbar_contract::records::SecretForm::Recoverable
        {
            continue;
        }
        let (key, _) = governance
            .lookup_credential(&credential.meta.kind, &credential.meta.public_id)
            .ok_or(Permanent("candidate live credential is not hydrated"))?;
        if key.enabled
            && !key.expires_at.is_some_and(|expiry| now > expiry)
            && !governance.is_revoked_at(&key.id, now)
            && !governance
                .credential_secret(&credential.meta.kind, &credential.meta.public_id, now)
                .1
        {
            return Err(Permanent("candidate live credential cannot be opened"));
        }
    }
    check_live(candidate)?;
    let authority = candidate
        .core
        .authority()
        .map_err(|_| Permanent("candidate writer observation refused"))?;
    let mut proof = Sha256::new();
    proof.update(b"busbar.startup-readiness.v1\0");
    proof.update(&candidate.core.info().dataset.0[..]);
    proof.update(&candidate.core.info().atomic_domain[..]);
    proof.update(&candidate.core.info().clock_authority[..]);
    proof.update(&candidate.core.info().physical_version.to_le_bytes());
    proof.update(&candidate.configuration_fingerprint[..]);
    proof.update(&authority.writer[..]);
    proof.update(&authority.writer_epoch.to_le_bytes());
    proof.update(&authority.execution_epoch.to_le_bytes());
    proof.update(&identity.revision.to_le_bytes());
    if let Some(head) = price_snapshot.head {
        proof.update(head.to_string().as_bytes());
    }
    for record in records {
        proof.update(&record.node.to_le_bytes());
        proof.update(&record.node_seq.to_le_bytes());
        proof.update(&record.hash[..]);
    }
    Ok(Readiness {
        digest: proof.finish(),
        authority,
    })
}
