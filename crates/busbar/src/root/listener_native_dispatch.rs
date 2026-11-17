// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Dispatch only the route selected by the original physical request.

use std::sync::Arc;

use axum::body::Body;
use busbar_contract::abi::mechanism::route::RouteAuth;
use busbar_core_connector::framed_stream::session::{Feed, RegisterResponse};
use busbar_kernel::inbound::http_projection::HttpProjection;
use busbar_kernel::inbound::native::{PhysicalAdminExecution, RouteTarget};
use tokio::sync::mpsc;
use tower::ServiceExt;

use super::delivery::{CompletedResponse, RegisteredResponse, ResponseAuthority};
use super::{data, InputError, NativeListener, ReadyInput};
use crate::root::durability::response_intent::ResponseConnection;
use crate::root::plane_node::Node;

pub(super) struct Prepared {
    response: axum::response::Response,
    registered: RegisteredResponse,
    settlement: Option<data::DataSettlement>,
}

impl Prepared {
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
) -> Result<Prepared, InputError> {
    let binding = ready.request.binding().clone();
    let deadline = binding.deadline().ok_or(InputError::Invalid)?.into();
    let data_request = matches!(binding.route().target(), RouteTarget::Plane(_));
    let work = async {
        let (response, authority, settlement) = match binding.route().target() {
            RouteTarget::Plane(_) => {
                let slot =
                    (native.select)(binding.app(), &native.slot).ok_or(InputError::Invalid)?;
                let prepared = data::prepare(ready.request, slot, node).await?;
                (
                    prepared.response,
                    ResponseAuthority::Data(prepared.authority),
                    Some(prepared.settlement),
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
                let response = router
                    .oneshot(request)
                    .await
                    .unwrap_or_else(|never| match never {});
                let authority = match response.extensions().get::<Arc<PhysicalAdminExecution>>() {
                    Some(owner) if Arc::ptr_eq(owner.binding(), &binding) => {
                        ResponseAuthority::Admin(owner.clone())
                    }
                    Some(_) => return Err(InputError::Invalid),
                    // A raw request binding is not output authority. A denied walk needs its
                    // own consumed physical refusal owner before it can register a response.
                    None => {
                        return Err(InputError::Delivery(
                            busbar_contract::response_delivery::ResponseStop::Integrity,
                        ))
                    }
                };
                (response, authority, None)
            }
            RouteTarget::Core(_) => return Err(InputError::Invalid),
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
                    settlement.registration_failed().await?;
                }
                return Err(error);
            }
        };
        Ok(Prepared {
            response,
            registered,
            settlement,
        })
    };
    if data_request {
        // DATA owns real blocking callbacks and monetary state. Its producer observes the
        // original cancellation/deadline and joins that work; dropping this await would detach it.
        return work.await;
    }
    tokio::select! {
        result = work => result,
        () = binding.cancelled() => Err(InputError::Delivery(busbar_contract::response_delivery::ResponseStop::Cancelled)),
        () = tokio::time::sleep_until(deadline) => Err(InputError::Delivery(busbar_contract::response_delivery::ResponseStop::Deadline)),
    }
}
