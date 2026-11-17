// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The actual admitted transport arm of the existing native Store fixture.

use super::*;
use busbar_ports::transport::TransportPort;

/// Retain this owner until every listener and connection using `port` has retired.
/// Start the prepared workers only after publishing the complete physical routes.
pub(crate) struct TransportFixture {
    pub(crate) port: Arc<dyn TransportPort>,
    pub(crate) holds: Arc<busbar_kernel::directory::Holds>,
    pub(crate) workers: crate::root::boot::workers::PreparedWorkers,
    _owners: Arc<Owners>,
    _needs: Arc<Needs>,
}

impl ServingFixture {
    /// Open a real transport image already admitted by this fixture's bootstrap.
    /// Its serving Needs use the same native CoreStore and immutable secret prefix.
    pub(crate) async fn transport(
        &self,
        cfg: &RootCfg,
        identity: &str,
    ) -> Result<TransportFixture, String> {
        self.owners.instances.check(cfg)?;
        let built = &self.owners.built;
        let described = built
            .registry
            .described(identity)
            .ok_or_else(|| format!("fixture has no admitted transport {identity}"))?;
        if described.kind != KindCode::Transport {
            return Err(format!("fixture image {identity} is not a transport"));
        }
        let configured =
            super::super::transports::configured(cfg, &built.registry, &[identity.to_owned()])?;
        let specs = specifications(&configured, cfg.public_url.as_deref(), false);
        let (_, spec) = specs
            .first()
            .ok_or("transport fixture lost its specification")?;
        let prepared = built
            .registry
            .reserve(spec)
            .map_err(|error| format!("{error:?}"))?;
        let provisioning = crate::root::provisioning::prepare(
            Arc::clone(&self.core),
            Arc::new(LogEvents),
            Vec::new(),
        )
        .await?;
        let holds = Arc::clone(&provisioning.holds);
        let needs = built.needs_for(
            Arc::clone(&self.owners.prefix),
            Arc::new(StoreRecords::new(Arc::clone(&self.core))),
            provisioning.directory,
        );
        let refs = self.owners.prefix.refs();
        let port = built
            .registry
            .open_transport_reserved(prepared, &needs, &refs)
            .await
            .map_err(|error| format!("{error:?}"))?;
        let mut workers = crate::root::boot::workers::PreparedWorkers::new();
        workers.push(provisioning.refresh.run());
        Ok(TransportFixture {
            port,
            holds,
            workers,
            _owners: Arc::clone(&self.owners),
            _needs: needs,
        })
    }
}
