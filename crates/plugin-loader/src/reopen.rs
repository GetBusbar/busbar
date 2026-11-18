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

pub(crate) type Reopen = Arc<
    dyn for<'a> Fn(&'a Registry, OwnedSpec, KindCode) -> BoxFut<'a, Result<OpenedPort, OpenError>>
        + Send
        + Sync,
>;

/// Run the stored reopen function. It is called by value of the parameter, never through a field, so the
/// entry machinery's hop scan (ci/hop) sees no raw field call.
pub(crate) fn reopen<'a>(
    opener: &Reopen,
    registry: &'a Registry,
    owned: OwnedSpec,
    kind: KindCode,
) -> BoxFut<'a, Result<OpenedPort, OpenError>> {
    opener(registry, owned, kind)
}

/// Reopens under exactly these Needs. Cold and per instance: no Need call is boxed.
pub(crate) fn bound<N: Needs>(
    needs: Arc<N>,
    refs: Arc<dyn busbar_ports::binder::RefSource>,
    seal: Option<StoreSeal>,
) -> Reopen {
    Arc::new(move |registry, owned, kind| {
        let (needs, refs, seal) = (Arc::clone(&needs), Arc::clone(&refs), seal.clone());
        Box::pin(async move {
            let spec = owned.spec();
            Ok(match kind {
                KindCode::Store => OpenedPort::Store(
                    registry
                        .open_store(
                            &spec,
                            &needs,
                            &refs,
                            seal.ok_or_else(|| {
                                OpenError::Unknown("store reopen missing seal".into())
                            })?,
                        )
                        .await?,
                ),
                KindCode::Secret => {
                    OpenedPort::Secret(registry.open_secret(&spec, &needs, &refs).await?)
                }
                KindCode::Auth => OpenedPort::Auth(registry.open_auth(&spec, &needs, &refs).await?),
                KindCode::Hook => OpenedPort::Hook(registry.open_hook(&spec, &needs, &refs).await?),
                KindCode::Export => {
                    OpenedPort::Export(registry.open_export(&spec, &needs, &refs).await?)
                }
                KindCode::Plane => {
                    OpenedPort::Plane(registry.open_plane(&spec, &needs, &refs).await?)
                }
                KindCode::Transport => {
                    OpenedPort::Transport(registry.open_transport(&spec, &needs, &refs).await?)
                }
            })
        })
    })
}
