// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Complete, independently retained native bootstrap and serving network owners.

use super::judge::Judge;
use super::net::ConnectorIo;
use super::observations::Observations;
use super::tlsconf::Configs;
use crate::guard::{FrozenGuard, Resolve, Resolved};
use crate::hostio::HostIo;
use crate::proxy::ProxyChoice;
use crate::tls::store::TrustStore;
use busbar_kernel::config::tls::ProxyResolution;
use std::sync::Arc;

/// Shared resolver adapter; no process resolver lookup is performed by a retained owner.
#[derive(Clone)]
pub struct SharedResolver(pub Arc<dyn Resolve>);
impl Resolve for SharedResolver {
    fn resolve(&self, host: &str, done: Resolved) {
        self.0.resolve(host, done);
    }
}

/// All inputs are supplied before any native secret/store instance opens.
pub struct NetworkInputs {
    /// S0 runtime, retained for registration, timers and HTTP connection drivers.
    pub runtime: tokio::runtime::Handle,
    /// Exact stage policy, frozen after own-listener publication.
    pub guard: FrozenGuard,
    /// Explicit resolver shared by this generation.
    pub resolver: Arc<dyn Resolve>,
    /// Validated, fully resolved operator TLS policy for this stage.
    pub trust: Arc<TrustStore>,
    /// Already resolved configured proxy/environment choice; None means direct.
    pub proxy: Option<Arc<ProxyChoice>>,
    /// Explicit local-versus-proxy target resolution policy.
    pub resolution: ProxyResolution,
    /// Bounded pre-store writer retained for this owner's full life.
    pub observations: Arc<Observations>,
}

pub(super) struct State {
    pub runtime: tokio::runtime::Handle,
    pub configs: Configs,
    pub guard: FrozenGuard,
    pub resolver: SharedResolver,
    pub proxy: Option<Arc<ProxyChoice>>,
    pub resolution: ProxyResolution,
    pub observations: Arc<Observations>,
    pub host_io: Arc<HostIo>,
    maintenance: tokio::task::JoinHandle<()>,
}

impl State {
    fn new(inputs: NetworkInputs) -> Arc<Self> {
        let trust = Arc::clone(&inputs.trust);
        let maintenance = inputs.runtime.spawn(async move {
            loop {
                tokio::time::sleep(crate::tls::store::SWEEP_EVERY).await;
                trust.sweep(std::time::SystemTime::now());
            }
        });
        Arc::new(Self {
            host_io: Arc::new(HostIo::new_on(inputs.runtime.clone())),
            runtime: inputs.runtime,
            configs: Configs::new(inputs.trust),
            guard: inputs.guard,
            resolver: SharedResolver(inputs.resolver),
            proxy: inputs.proxy,
            resolution: inputs.resolution,
            observations: inputs.observations,
            maintenance,
        })
    }

    fn judge(&self) -> Judge<SharedResolver> {
        Judge::observed(
            self.guard.clone(),
            self.resolver.clone(),
            self.proxy.clone(),
            self.resolution,
            Arc::clone(&self.observations),
        )
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.maintenance.abort();
    }
}

/// Complete file-era networking. Cloned Needs retain this owner across S7 publication.
#[derive(Clone)]
pub struct BootstrapConnector(Arc<State>);
impl BootstrapConnector {
    /// Consume complete file-era inputs; no policy is installed after construction.
    #[must_use]
    pub fn new(inputs: NetworkInputs) -> Self {
        Self(State::new(inputs))
    }
    /// Native I/O sharing this exact network owner.
    #[must_use]
    pub fn io(&self) -> ConnectorIo {
        ConnectorIo::from_state(Arc::clone(&self.0))
    }
    /// A judge sharing this exact frozen policy and resolver.
    #[must_use]
    pub fn judge(&self) -> Judge<SharedResolver> {
        self.0.judge()
    }
    /// Native host I/O on this stage's explicit runtime.
    #[must_use]
    pub fn host_io(&self) -> Arc<HostIo> {
        Arc::clone(&self.0.host_io)
    }
}

/// Effective-config networking. It never mutates or borrows the bootstrap owner's state.
#[derive(Clone)]
pub struct ServingConnector(Arc<State>);
impl ServingConnector {
    /// Consume complete effective inputs in a separate owner.
    #[must_use]
    pub fn new(inputs: NetworkInputs) -> Self {
        Self(State::new(inputs))
    }
    /// Native I/O sharing this exact network owner.
    #[must_use]
    pub fn io(&self) -> ConnectorIo {
        ConnectorIo::from_state(Arc::clone(&self.0))
    }
    /// A judge sharing this exact frozen policy and resolver.
    #[must_use]
    pub fn judge(&self) -> Judge<SharedResolver> {
        self.0.judge()
    }
    /// Native host I/O on this stage's explicit runtime.
    #[must_use]
    pub fn host_io(&self) -> Arc<HostIo> {
        Arc::clone(&self.0.host_io)
    }
}
