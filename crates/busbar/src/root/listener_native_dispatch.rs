// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Dispatch only the route selected by the original physical request.

use std::sync::Arc;

use axum::body::Body;
use busbar_contract::route::RouteAuth;
use busbar_core_connector::framed_stream::session::{Feed, RegisterResponse};
use busbar_kernel::inbound::http_projection::HttpProjection;
use busbar_kernel::inbound::native::{PhysicalAdminExecution, PhysicalRefusalCarrier, RouteTarget};
use tokio::sync::mpsc;
use tower::ServiceExt;

use super::delivery::{CompletedResponse, RegisteredResponse, ResponseAuthority};
use super::{data, InputError, NativeListener, ReadyInput};
use crate::root::durability::response_intent::ResponseConnection;
use crate::root::plane_node::{NativeNodeHandle, Node};

impl From<InputError> for data::DataPrepareError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}
impl From<busbar_kernel::inbound::native::ArrivalRefusal> for data::DataPrepareError {
    fn from(error: busbar_kernel::inbound::native::ArrivalRefusal) -> Self {
        Self::Input(error.into())
    }
}

/// An unrouted request has no route, so no chain and no carriers: its refusal is recorded
/// R_AUTH_REQUIRED (the bytes are those of every unauthenticated answer).
const NO_CARRIERS: &[Box<str>] = &[];

pub(super) struct Prepared {
    response: axum::response::Response,
    registered: RegisteredResponse,
    settlement: Option<data::DataSettlement>,
}

impl Prepared {
    pub(super) fn native_node_handle(&self) -> Option<NativeNodeHandle> {
        self.settlement
            .as_ref()
            .and_then(data::DataSettlement::native_node_handle)
    }
    pub(super) async fn send(self, feeds: &mpsc::Sender<Feed>, node: &Node) -> CompletedResponse {
        let mut completed = self.registered.send_http(self.response, feeds, node).await;
        // The completion keeps the original physical execution and input retirement guard until
        // the same Task's selected monetary terminal has consumed the genuine delivery receipt.
        if let Some(settlement) = self.settlement {
            if let Err(error) = settlement
                .finish(&completed.delivery, &completed.snapshot)
                .await
            {
                completed.result = Err(error);
            }
        }
        completed
    }
}

pub(super) async fn prepare(
    ready: ReadyInput,
    native: Arc<NativeListener>,
    node: Arc<Node>,
    connection: Arc<ResponseConnection>,
    registrations: mpsc::Sender<RegisterResponse>,
) -> Result<Prepared, data::DataPrepareError> {
    let binding = ready.request.binding().clone();
    let deadline = binding.deadline().ok_or(InputError::Invalid)?.into();
    let upgrade_request = crate::root::min3_physical::is_upgrade(binding.route());
    let data_request =
        matches!(binding.route().target(), RouteTarget::Plane(_)) && !upgrade_request;
    let work = async {
        let (response, authority, settlement) = match binding.route().target() {
            RouteTarget::Plane(_) if upgrade_request => {
                let slot =
                    (native.select)(binding.app(), &native.slot).ok_or(InputError::Invalid)?;
                let (response, refusal) = super::upgrade::prepare(ready.request, slot).await?;
                (response, ResponseAuthority::Refused(refusal), None)
            }
            RouteTarget::Plane(_) => {
                let slot =
                    (native.select)(binding.app(), &native.slot).ok_or(InputError::Invalid)?;
                // Lend the same HEAD-created physical owner to Node before Task admission.
                // Node retains it independently through registration and audit failures.
                let prepared =
                    data::prepare(ready.request, slot, node, ready.owner.clone()).await?;
                (
                    prepared.response,
                    match prepared.authority {
                        data::DataAuthority::Executing(owner) => ResponseAuthority::Data(owner),
                        data::DataAuthority::Refused(owner) => ResponseAuthority::Refused(owner),
                    },
                    prepared.settlement,
                )
            }
            RouteTarget::Core(RouteAuth::None) => {
                let owner = Arc::new(ready.request.complete_public()?);
                let response = owner.http_response().await?;
                (response, ResponseAuthority::Public(owner), None)
            }
            RouteTarget::Core(RouteAuth::Admin) => {
                let router = native.admin.clone().ok_or(InputError::Invalid)?;
                let snapshot = binding.snapshot().map_err(|_| InputError::Capacity)?;
                let mut request = HttpProjection::from_snapshot(snapshot.clone())
                    .map_err(|_| InputError::Capacity)?
                    .into_request(Body::from(snapshot.body_bytes()));
                request.extensions_mut().insert(binding.app().clone());
                request.extensions_mut().insert(ready.request.into_admin()?);
                let mut response = router
                    .oneshot(request)
                    .await
                    .unwrap_or_else(|never| match never {});
                let refused = response.extensions_mut().remove::<PhysicalRefusalCarrier>();
                let authority = match (
                    response.extensions().get::<Arc<PhysicalAdminExecution>>(),
                    refused,
                ) {
                    (Some(owner), None) if Arc::ptr_eq(owner.binding(), &binding) => {
                        ResponseAuthority::Admin(owner.clone())
                    }
                    (None, Some(carrier)) => {
                        let owner = carrier.take()?;
                        if !Arc::ptr_eq(owner.binding(), &binding) {
                            return Err(InputError::Invalid.into());
                        }
                        ResponseAuthority::Refused(owner)
                    }
                    (Some(_), _) => return Err(InputError::Invalid.into()),
                    // A raw request binding is not output authority. A denied walk needs its
                    // own consumed physical refusal owner before it can register a response.
                    (None, None) => {
                        return Err(InputError::Delivery(
                            busbar_contract::response_delivery::ResponseStop::Integrity,
                        )
                        .into())
                    }
                };
                (response, authority, None)
            }
            RouteTarget::Unrouted => {
                // No route matched: answered exactly as an unauthenticated request on a route is.
                let response = super::unauthenticated_response(&binding, NO_CARRIERS)?;
                let refusal = ready.request.refuse_unrouted()?;
                (response, ResponseAuthority::Refused(refusal), None)
            }
            RouteTarget::Core(_) => return Err(InputError::Invalid.into()),
        };
        let registered = match RegisteredResponse::register(
            &connection,
            &registrations,
            authority,
            ready.owner,
            deadline,
        )
        .await
        {
            Ok(registered) => registered,
            Err(error) => {
                // Release the unpublished receiver before joining a bounded producer that may
                // be waiting to send into it. No registered delivery receipt is invented here.
                drop(response);
                if let Some(settlement) = settlement {
                    let handle = settlement.native_node_handle();
                    let error = settlement
                        .registration_failed()
                        .await
                        .err()
                        .unwrap_or(error);
                    return Err(match handle {
                        Some(handle) => data::DataPrepareError::HeldNode { error, handle },
                        None => data::DataPrepareError::Input(error),
                    });
                }
                return Err(error.into());
            }
        };
        Ok(Prepared {
            response,
            registered,
            settlement,
        })
    };
    if data_request {
        // DATA owns the plane session and monetary state. Its producer observes the
        // original cancellation/deadline and joins that work; dropping this await would detach it.
        return work.await;
    }
    tokio::select! {
        result = work => result,
        () = binding.cancelled() => Err(InputError::Delivery(busbar_contract::response_delivery::ResponseStop::Cancelled).into()),
        () = tokio::time::sleep_until(deadline) => Err(InputError::Delivery(busbar_contract::response_delivery::ResponseStop::Deadline).into()),
    }
}
