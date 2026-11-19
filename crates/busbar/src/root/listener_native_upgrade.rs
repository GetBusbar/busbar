// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A native ROUTE_UPGRADE request (§12.27): the route's auth chain on the head first, then core's
//! answer before any 101 (400 or 501, rendered by the plane, through the same response registration
//! as every other answer). A denied request is cancelled, as a denied DATA request is.

use std::sync::Arc;

use axum::response::Response;
use busbar_kernel::inbound::native::{CompletingPhysicalRequest, PhysicalRefusal, RouteTarget};

use super::InputError;
use crate::root::min3_physical::NativeSlot;
use crate::root::port_mount::{self, UpgradeStep};

pub(super) async fn prepare(
    mut request: CompletingPhysicalRequest,
    slot: Arc<NativeSlot>,
) -> Result<(Response, PhysicalRefusal), InputError> {
    let binding = request.binding().clone();
    let RouteTarget::Plane(target) = binding.route().target() else {
        return Err(InputError::Invalid);
    };
    let route = slot
        .upgrade_for(&binding)
        .map_err(|_| InputError::Invalid)?;
    let routes = binding
        .prepared()
        .data()
        .ok_or(InputError::Invalid)?
        .downcast::<crate::root::serve::DataRoutes>()
        .map_err(|_| InputError::Invalid)?;
    let seat = routes
        .served
        .ports
        .iter()
        .find(|seat| seat.driver.caller().same_incarnation(target.caller()))
        .cloned()
        .ok_or(InputError::Invalid)?;
    let deadline = binding.deadline().ok_or(InputError::Invalid)?;
    let request_id = binding.invocation().request_id().get();
    let preparation = request
        .begin_data_preparation()
        .map_err(|_| InputError::Invalid)?;
    // Auth before anything that tells the caller about this route: an anonymous caller learns
    // nothing a denied request on any gated route would not tell it (`port_mount::UpgradeStep`).
    let authorization = route
        .authorize(
            preparation,
            busbar_ports::CallCx {
                deadline,
                request_id,
                stack: Default::default(),
            },
        )
        .await
        .map_err(|_| InputError::Invalid)?;
    let head = Arc::clone(authorization.snapshot());
    let asks = port_mount::asks_websocket(head.headers());
    let refusal = match port_mount::upgrade_step(asks, slot.websocket()) {
        UpgradeStep::Refuse(refusal) => refusal,
        // Fail closed: a slot never carries a websocket instance while it mounts upgrade routes
        // (listener-plan assembly refuses that candidate until the hand-over adopter is linked).
        UpgradeStep::HandOver(carrier) => {
            tracing::error!(
                instance = %carrier.instance,
                "an upgrade request reached a websocket instance with no linked hand-over; refused"
            );
            return Err(InputError::Invalid);
        }
    };
    let items = port_mount::upgrade_refusal_items(
        &seat,
        target.mounted().route,
        &head,
        request_id,
        refusal,
    );
    let response = super::data::refusal_response(items, &head.request().storage())?;
    let physical = request.refuse_upgrade(authorization)?;
    Ok((response, physical))
}
