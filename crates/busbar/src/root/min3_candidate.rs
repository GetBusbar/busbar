// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native lifetime custody attached to the exact published App.
//!
//! Physical slots retain request dispatchers, but the complete owner also retains the
//! invocation registrations and opened ports which authorize those dispatchers.

use std::sync::{Arc, Mutex};

use super::boot::workers::{PreparedWorkers, RunningWorkers};

pub(crate) struct NativeGeneration {
    pub(crate) native: Arc<super::min3_boot::Booted>,
    /// Retained, never read: the services own the invocation registrations and opened ports
    /// that authorize the slot dispatchers, for exactly this generation's lifetime.
    _services: Arc<super::serve::Services>,
    prepared: Mutex<Option<PreparedWorkers>>,
}

impl std::fmt::Debug for NativeGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeGeneration")
            .field("config_version", &self.native.config_version)
            .finish_non_exhaustive()
    }
}

/// Retain the real initial owners after native boot and before App publication.
/// Initial workers keep their existing explicit shutdown owner in main.
pub(crate) fn install_initial(
    app: &mut busbar_kernel::state::App,
    native: Arc<super::min3_boot::Booted>,
    services: Arc<super::serve::Services>,
) -> Result<(), String> {
    install(app, native, services, None)
}

/// Runtime preparation retains inert work until the existing publication callback.
pub(crate) fn install_prepared(
    app: &mut busbar_kernel::state::App,
    native: Arc<super::min3_boot::Booted>,
    services: Arc<super::serve::Services>,
    workers: PreparedWorkers,
) -> Result<(), String> {
    if app.prepared_generation().is_none() {
        return Err("native workers have no reserved publication generation".into());
    }
    install(app, native, services, Some(workers))
}

fn install(
    app: &mut busbar_kernel::state::App,
    native: Arc<super::min3_boot::Booted>,
    services: Arc<super::serve::Services>,
    workers: Option<PreparedWorkers>,
) -> Result<(), String> {
    if native.config_version != app.config_version {
        return Err("native generation belongs to another configuration".into());
    }
    let kernel = services
        .kernel()
        .ok_or("native generation requires actual serving services")?;
    if native
        .seats
        .iter()
        .any(|seat| !Arc::ptr_eq(seat.driver.core(), &kernel))
    {
        return Err("native generation services differ from its admitted plane services".into());
    }
    let mut config = app
        .config_projection
        .as_ref()
        .and_then(|value| value.downcast_ref::<super::door_steps::DoorConfig>())
        .ok_or("native generation has no root configuration projection")?
        .clone();
    if config.native_generation.is_some() {
        return Err("native generation already installed on candidate".into());
    }
    config.native_generation = Some(Arc::new(NativeGeneration {
        native,
        _services: services,
        prepared: Mutex::new(workers),
    }));
    app.config_projection = Some(Arc::new(config));
    Ok(())
}

/// Lookup never substitutes the boot generation for an incomplete candidate.
pub(crate) fn generation(app: &busbar_kernel::state::App) -> Result<Arc<NativeGeneration>, String> {
    app.config_projection
        .as_ref()
        .and_then(|value| value.downcast_ref::<super::door_steps::DoorConfig>())
        .and_then(|config| config.native_generation.clone())
        .ok_or_else(|| "App has no complete native generation owner".into())
}

impl NativeGeneration {
    pub(crate) fn has_prepared_workers(&self) -> bool {
        self.prepared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }
}

struct RunningGeneration {
    // Registrations remain alive until the original worker handles have joined.
    generation: Arc<NativeGeneration>,
    workers: RunningWorkers,
}

struct WorkerState {
    active: Option<RunningGeneration>,
    stopped: bool,
    failure: Option<String>,
}

type Retirement = tokio::task::JoinHandle<Result<(), String>>;

/// Process-owned worker custody uses the existing serialized publication callbacks.
/// It retains no App and no chain of predecessor generations.
pub(crate) struct Workers {
    state: Mutex<WorkerState>,
    retiring: tokio::sync::Mutex<Option<Retirement>>,
}

impl Workers {
    pub(crate) fn start(
        app: &busbar_kernel::state::App,
        workers: PreparedWorkers,
    ) -> Result<Arc<Self>, String> {
        let generation = generation(app)?;
        Ok(Arc::new(Self {
            state: Mutex::new(WorkerState {
                active: Some(RunningGeneration {
                    generation,
                    workers: workers.start(),
                }),
                stopped: false,
                failure: None,
            }),
            retiring: tokio::sync::Mutex::new(None),
        }))
    }

    /// A controller with no generation running: what a post-serve fixture that served no native
    /// generation drains (f94371980d made PostServe hold the controller, not bare workers).
    #[cfg(test)]
    pub(crate) fn idle() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(WorkerState {
                active: None,
                stopped: false,
                failure: None,
            }),
            retiring: tokio::sync::Mutex::new(None),
        })
    }

    pub(crate) fn bind(self: &Arc<Self>, app: &busbar_kernel::state::AppHandle) {
        let owner = Arc::clone(self);
        app.on_apply(Box::new(move |next| owner.activate(next)));
        let owner = Arc::clone(self);
        app.on_apply_async(Box::new(move |_| {
            let owner = Arc::clone(&owner);
            Box::pin(async move { owner.join_retired().await })
        }));
    }

    fn retire(running: RunningGeneration) -> Retirement {
        running.workers.request_stop();
        tokio::spawn(async move {
            let RunningGeneration {
                generation,
                workers,
            } = running;
            let result = workers.stop().await;
            drop(generation);
            result
        })
    }

    fn activate(&self, app: &busbar_kernel::state::App) {
        let next = generation(app).expect("native publication passed complete-owner checks");
        let workers = next
            .prepared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("native publication retained dormant workers");
        // AppHandle holds its application lock through both callback phases.
        let mut retiring = self
            .retiring
            .try_lock()
            .expect("previous native retirement completed before publication");
        assert!(retiring.is_none(), "native retirement was not joined");
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(!state.stopped, "native publication after worker shutdown");
        if let Some(prior) = state.active.take() {
            *retiring = Some(Self::retire(prior));
        }
        state.active = Some(RunningGeneration {
            generation: next,
            workers: workers.start(),
        });
    }

    async fn join_retired(&self) {
        let mut retiring = self.retiring.lock().await;
        let Some(join) = retiring.as_mut() else {
            return;
        };
        // Await by reference: detaching this waiter keeps the original join owned here.
        let result = join.await;
        retiring.take();
        let failure = match result {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error),
            Err(error) => Some(error.to_string()),
        };
        if let Some(error) = failure {
            tracing::error!(%error, "native generation workers failed retirement");
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .failure
                .get_or_insert(error);
        }
    }

    pub(crate) async fn stop(&self) -> Result<(), String> {
        self.join_retired().await;
        {
            let mut retiring = self.retiring.lock().await;
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.stopped = true;
            if let Some(active) = state.active.take() {
                *retiring = Some(Self::retire(active));
            }
        }
        self.join_retired().await;
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &state.failure {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

/// Immutable runtime producer. Only fixed bootstrap/physical authority is shared;
/// each preparation creates its own read-bound registry, secret prefix and serving services.
pub(crate) struct Factory {
    process: Arc<busbar_plugin_loader::process::ProcessResources>,
    bootstrap: Arc<super::min3_boot::BootstrapSources>,
    core: Arc<busbar_kernel::persistence::facade::CoreStore>,
    transports: super::min3_boot::TransportSources,
    listeners: Arc<super::min3_listener_plan::NativeListenerPlan>,
    node: Arc<super::plane_node::Node>,
    observers: Arc<super::export_observer::ExportObservers>,
    boot_has_exports: bool,
}

impl Factory {
    pub(crate) fn new(
        process: Arc<busbar_plugin_loader::process::ProcessResources>,
        bootstrap: Arc<super::min3_boot::BootstrapSources>,
        core: Arc<busbar_kernel::persistence::facade::CoreStore>,
        native: &super::min3_boot::Booted,
        listeners: Arc<super::min3_listener_plan::NativeListenerPlan>,
        node: Arc<super::plane_node::Node>,
        observers: Arc<super::export_observer::ExportObservers>,
    ) -> Arc<Self> {
        Arc::new(Self {
            process,
            bootstrap,
            core,
            transports: native.transport_sources.clone(),
            listeners,
            node,
            observers,
            boot_has_exports: native.has_exports(),
        })
    }

    pub(crate) fn prepare<'a>(
        self: &'a Arc<Self>,
        cfg: &'a busbar_kernel::config::RootCfg,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<Option<busbar_kernel::appbuild::CandidatePreparation>, String>,
    > {
        Box::pin(async move {
            // The required desired-versus-boot export evidence and aggregate CHECK
            // producer are not supplied by this native request-side construction.
            // Never reopen an immutable export or silently relabel its boot backend.
            if self.boot_has_exports || !cfg.export_defs.is_empty() {
                return Err(
                    "native export reload requires its retained boot-evidence producer".into(),
                );
            }
            let dest = super::connector::guard_for(&cfg.destinations())?;
            let ready = self
                .bootstrap
                .prepare_next(&self.process, cfg, dest.guard().clone(), &self.transports)
                .await?;
            let candidate = Candidate {
                owner: Arc::clone(self),
                ready,
                dest,
            };
            Ok(Some(busbar_kernel::appbuild::CandidatePreparation::new(
                candidate.ready.resolver(),
                Box::new(move |app| candidate.finish(app)),
            )))
        })
    }
}

struct Candidate {
    owner: Arc<Factory>,
    ready: super::min3_boot::ServingReady,
    dest: Arc<dyn busbar_kernel::host_services::DestJudge>,
}

impl Candidate {
    fn finish<'a>(
        self,
        app: &'a mut busbar_kernel::state::App,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            let Self { owner, ready, dest } = self;
            let epoch = app
                .prepared_generation()
                .ok_or("native candidate has no durable publication reservation")?;
            let planes: Vec<_> = busbar_kernel::plane_driver::registry::plane_decls()
                .iter()
                .map(|plane| &plane.declaration)
                .collect();
            let services = super::serve::compose(dest, app, Arc::clone(&owner.core), &planes);
            let observations = owner.observers.reserve(ready.export_names())?;
            let (_, mut workers, _exports, native, selected) = super::min3_boot::finish_with_store(
                ready,
                Arc::clone(&owner.core),
                None,
                services.kernel(),
                busbar_kernel::plane_driver::port_work::governed_binder(
                    app.governance.clone(),
                    app.role_bindings.clone(),
                ),
                Some(super::min3_boot::ServingEnvironment::new(app)),
                &observations,
            )
            .await?;
            if !Arc::ptr_eq(&app.secret_resolver, &native.resolver) {
                return Err("native completion changed its early secret resolver".into());
            }
            app.prepare_selected_policy(selected)?;
            let served = native_served(Arc::clone(&native), app, &owner.node);
            let owners = super::min3_physical::SlotOwners {
                auth: Arc::clone(&native.auth),
                epoch,
                inventories: Arc::clone(&native.inventories),
                keys: owner.node.kernel_and_keys().1,
                core: super::min3_listener_plan::core_lines(app, &served).into(),
            };
            super::door_steps::prepare_native_candidate(&owner.listeners, app, &served, &owners)?;
            services.prepare_workers(&mut workers);
            install_prepared(app, native, services, workers)
        })
    }
}

fn native_served(
    native: Arc<super::min3_boot::Booted>,
    app: &busbar_kernel::state::App,
    node: &Arc<super::plane_node::Node>,
) -> super::serve::Served {
    let mut served = super::serve::Served {
        ports: native.seats.clone(),
        native: Some(native),
        tables: app.serve_tables.clone(),
        ..Default::default()
    };
    if let Some(governance) = &app.governance {
        let post = Arc::new(super::plane_node::NodeEndPost::new(Arc::clone(node)));
        let money = Arc::new(busbar_kernel::plane_driver::PlaneMoney::new(
            Arc::clone(governance),
            Arc::clone(&post) as Arc<dyn busbar_kernel::plane_driver::EndPost>,
        ));
        served.billing = Some(
            busbar_kernel::plane_driver::port_billing::PortBilling::new(
                money,
                Arc::clone(governance),
                node.kernel_and_keys().1,
                Arc::new(busbar_kernel::plane_driver::CoreAudit),
            )
            .with_journal(Arc::clone(&post) as Arc<dyn busbar_kernel::plane_driver::HookJournal>),
        );
        served.post = Some(post);
    }
    served
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn detaching_retirement_wait_keeps_original_join_owned() {
        let release = Arc::new(tokio::sync::Notify::new());
        let entered = Arc::new(tokio::sync::Notify::new());
        let task_release = Arc::clone(&release);
        let task_entered = Arc::clone(&entered);
        let (finished, mut observed) = tokio::sync::oneshot::channel();
        let join = tokio::spawn(async move {
            task_entered.notify_one();
            task_release.notified().await;
            let _ = finished.send(());
            Ok(())
        });
        let owner = Arc::new(Workers {
            state: Mutex::new(WorkerState {
                active: None,
                stopped: false,
                failure: None,
            }),
            retiring: tokio::sync::Mutex::new(Some(join)),
        });
        entered.notified().await;
        let waiting = Arc::clone(&owner);
        let waiter = tokio::spawn(async move { waiting.join_retired().await });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if owner.retiring.try_lock().is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the waiter acquired the real retirement custody");
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(owner.retiring.lock().await.is_some());
        assert!(matches!(
            observed.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        release.notify_one();
        owner.stop().await.expect("the original retirement joins");
        observed.await.expect("the original task completed");
        assert!(owner.retiring.lock().await.is_none());
    }

    #[tokio::test]
    async fn retirement_failure_prevents_successful_shutdown() {
        let owner = Workers {
            state: Mutex::new(WorkerState {
                active: None,
                stopped: false,
                failure: None,
            }),
            retiring: tokio::sync::Mutex::new(Some(tokio::spawn(async {
                Err("original worker failed".to_owned())
            }))),
        };
        owner.join_retired().await;
        assert_eq!(owner.stop().await.unwrap_err(), "original worker failed");
        assert_eq!(owner.stop().await.unwrap_err(), "original worker failed");
    }
}
