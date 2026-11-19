// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A native ROUTE_UPGRADE request (§12.27): the route's auth chain on the head first, then core's
//! answer before any 101 (400 or 501, rendered by the plane, through the same response registration
//! as every other answer). A denied request gets the listener's one unauthenticated answer.

use std::sync::Arc;

use axum::response::Response;
use busbar_kernel::auth::admission_table::Refusal;
use busbar_kernel::auth::native_upgrade::UpgradeRefused;
use busbar_kernel::inbound::native::{
    CompletingPhysicalRequest, PhysicalRefusal, PhysicalUpgrade, RouteTarget, StreamOwner,
};

use super::handover::{Adopted, HandOver, UpgradeAdopter};
use super::{answer, InputError};
use crate::root::min3_physical::NativeSlot;
use crate::root::plane_node::Node;
use crate::root::port_mount::{self, UpgradeStep};

/// What an upgrade request was answered with, and the authority that answer is written under.
pub(super) enum Upgraded {
    /// Refused before any 101: core's answer, under the refusal's own custody.
    Refused(Response, PhysicalRefusal),
    /// Handed over: the adopter's answer (the 101, or the plane's own answer before one), under
    /// the consumed request.
    Executing(Response, Arc<PhysicalUpgrade>),
}

pub(super) async fn prepare(
    mut request: CompletingPhysicalRequest,
    slot: Arc<NativeSlot>,
    adopter: Option<Arc<dyn UpgradeAdopter>>,
    stream: Arc<StreamOwner>,
    node: Arc<Node>,
) -> Result<Upgraded, InputError> {
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
    let authorization = match route
        .authorize(
            preparation,
            busbar_ports::CallCx {
                deadline,
                request_id,
                stack: Default::default(),
            },
        )
        .await
    {
        Ok(authorization) => authorization,
        // A denial gets the listener's one unauthenticated answer; any other failure none.
        Err(refused @ UpgradeRefused::Denied { .. }) => {
            let reason = refused.reason();
            let refusal = reason
                .refusal(answer::presented(&binding, route.withheld()))
                .ok_or(InputError::Invalid)?;
            let response = answer::core(&binding, refusal, reason.after_verification(), "", None)?;
            let physical = request.refuse_upgrade_denied(refused)?;
            return Ok(Upgraded::Refused(response, physical));
        }
        Err(UpgradeRefused::Failed(_)) => return Err(InputError::Invalid),
    };
    let head = Arc::clone(authorization.snapshot());
    let asks = port_mount::asks_websocket(head.headers());
    let withheld = Arc::clone(authorization.withheld());
    let render = |refusal: Refusal| {
        answer::route(
            &binding,
            refusal,
            true,
            "",
            None,
            Some(answer::Renderer {
                seat: &seat,
                route: target.mounted().route,
                head: &head,
                withheld: &withheld,
                request_id,
            }),
        )
    };
    // The upgrade request is judged before anything is counted against the key (the decision's
    // order): a request that does not ask to switch is 400, a listener with no websocket carrier
    // or no linked hand-over is 501. Each is answered; none drops the request.
    let carrier = match port_mount::upgrade_step(asks, slot.websocket()) {
        UpgradeStep::Refuse(refusal) => {
            let row = if asks {
                Refusal::NoUpgradeTransport
            } else {
                Refusal::NotAnUpgrade
            };
            debug_assert_eq!(refusal.status, row.row(true).status);
            let response = render(row)?;
            let physical = request.refuse_upgrade(authorization)?;
            return Ok(Upgraded::Refused(response, physical));
        }
        UpgradeStep::HandOver(carrier) => carrier,
    };
    let Some(adopter) = adopter else {
        let response = render(Refusal::NoUpgradeTransport)?;
        let physical = request.refuse_upgrade(authorization)?;
        return Ok(Upgraded::Refused(response, physical));
    };
    // Consumed once: Completing becomes Executing, and only the adopter can answer from here.
    let upgrade = Arc::new(request.complete_upgrade(authorization)?);
    let adopted = adopter
        .hand_over(
            carrier,
            HandOver {
                upgrade: Arc::clone(&upgrade),
                seat,
                route: target.mounted().route,
                withheld,
                stream,
                node,
            },
        )
        .await?;
    Ok(match adopted {
        Adopted::Switched(response) | Adopted::Answered(response) => {
            Upgraded::Executing(response, upgrade)
        }
    })
}
