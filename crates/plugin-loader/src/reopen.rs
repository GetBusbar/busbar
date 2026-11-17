// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Type erasure is cold and per instance: the ABI Needs trait uses RPITIT, so it cannot
//! be stored as a trait object. Retain its concrete Arc without boxing hot Need calls.
use crate::chains::OwnedSpec;
use crate::instance::{OpenError, OpenedPort, Registry, StoreSeal};
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::types::KindCode;
use std::sync::Arc;

pub(crate) trait Reopener: Send + Sync {
    fn open<'a>(
        &'a self,
        registry: &'a Registry,
        spec: OwnedSpec,
        kind: KindCode,
    ) -> BoxFut<'a, Result<OpenedPort, OpenError>>;
}

pub(crate) struct BoundNeeds<N: Needs> {
    pub needs: Arc<N>,
    pub refs: Arc<dyn busbar_ports::binder::RefSource>,
    pub seal: Option<StoreSeal>,
}

impl<N: Needs> Reopener for BoundNeeds<N> {
    fn open<'a>(
        &'a self,
        registry: &'a Registry,
        owned: OwnedSpec,
        kind: KindCode,
    ) -> BoxFut<'a, Result<OpenedPort, OpenError>> {
        Box::pin(async move {
            let spec = owned.spec();
            Ok(match kind {
                KindCode::Store => OpenedPort::Store(
                    registry
                        .open_store(
                            &spec,
                            &self.needs,
                            &self.refs,
                            self.seal.clone().ok_or_else(|| {
                                OpenError::Unknown("store reopen missing seal".into())
                            })?,
                        )
                        .await?,
                ),
                KindCode::Secret => {
                    OpenedPort::Secret(registry.open_secret(&spec, &self.needs, &self.refs).await?)
                }
                KindCode::Auth => {
                    OpenedPort::Auth(registry.open_auth(&spec, &self.needs, &self.refs).await?)
                }
                KindCode::Hook => {
                    OpenedPort::Hook(registry.open_hook(&spec, &self.needs, &self.refs).await?)
                }
                KindCode::Export => {
                    OpenedPort::Export(registry.open_export(&spec, &self.needs, &self.refs).await?)
                }
                KindCode::Plane => {
                    OpenedPort::Plane(registry.open_plane(&spec, &self.needs, &self.refs).await?)
                }
                KindCode::Transport => OpenedPort::Transport(
                    registry
                        .open_transport(&spec, &self.needs, &self.refs)
                        .await?,
                ),
            })
        })
    }
}
