// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A native ROUTE_UPGRADE request (§12.27; owner decision 18: the WebSocket hand-over is built for
//! 1.6.0).
//!
//! AN UPGRADE REQUEST IS ADMITTED BY THE SAME ADMISSION AS ANY REQUEST. It is a data request whose
//! answer may be a 101: the route's chain verifies the caller on the head (a denied request gets
//! the listener's one unauthenticated answer), the governed key, its replay claim and its scope
//! are judged, the unit is opened and its money admitted before the plane's FORWARD is walked.
//! Nothing here verifies, opens or admits anything: [`prepare`] hands the request to the data
//! path ([`super::data::prepare_for`]) with the two things an upgrade adds to it:
//!
//! 1. core's own refusals before any 101 ([`judge`]), answered only to a verified caller and
//!    rendered by the route's plane: 400 for a request that does not ask to switch to websocket,
//!    501 when the listener has no transport that can carry it;
//! 2. the caller's side of the session ([`super::handover::UpgradePipe`]): the plane's answer is
//!    HTTP's until it commits with RESPOND(101), which it does only as its answer to a far end
//!    that accepted the upstream handshake. A budget refusal, a scope refusal, a far end that
//!    cannot be dialled or refuses, an exhausted walk: each is an ordinary HTTP answer BEFORE any
//!    101, never a 101 followed by a close.
//!
//! After the 101 the connection is handed to the websocket transport ([`super::handover::adopt`],
//! called by the connection's supervisor when the HTTP transport answers UPGRADE) and the session
//! is relayed message by message through the plane (`busbar_kernel::plane_driver::port_duplex`),
//! which is what meters it. The unit settles when the answer's delivery ends, on every path: the
//! data path's own settlement, with the session's last stated usage.
//!
//! A ROUTE WHOSE DATA ADMISSION IS NOT BOUND (a build in which the admission table still mounts
//! upgrade routes on the upgrade-only chain, [`unadmitted`]) is never served without a unit: its
//! caller is verified as before and then refused 501, clearly, before any 101.

use std::sync::Arc;

use busbar_kernel::auth::admission_table::Refusal;
use busbar_kernel::auth::native_upgrade::UpgradeRefused;
use busbar_kernel::inbound::native::{CompletingPhysicalRequest, RouteTarget, StreamOwner};

use super::data::{DataAuthority, DataPrepareError, DataResponse};
use super::handover::{UpgradeAdopter, ADOPTED_STREAM};
use super::{answer, InputError};
use crate::root::min3_boot::transports::ServedTransport;
use crate::root::min3_physical::NativeSlot;
use crate::root::plane_node::Node;
use crate::root::port_mount::{self, UpgradeStep};

/// What an upgrade request adds to the data path's preparation.
pub(super) struct UpgradeRequest {
    /// The listener's admitted websocket transport, if it has one.
    pub(super) websocket: Option<ServedTransport>,
}

/// What core does with a verified upgrade request before any 101 (§12.27 steps 1 and 2).
pub(super) struct UpgradeTerms {
    /// Core's refusal: answered only to a verified caller, rendered by the route's plane.
    pub(super) refused: Option<Refusal>,
    /// The websocket transport the connection is handed to; `None` exactly when refused.
    pub(super) carrier: Option<ServedTransport>,
}

/// Judges a verified upgrade request: `asks` = its head asks to switch to websocket, `websocket`
/// = the listener's admitted websocket transport, `stream` = the stream it arrived on.
///
/// The order is the decision's: a request that does not ask to switch is 400 whatever the
/// listener has; one the listener cannot carry is 501. Both are judged before anything is counted
/// against the key (the data path answers them before it completes the request's admission).
///
/// A request that is not its connection's first is refused 501 as well: the adopting session
/// serves the upgraded answer as its stream 1, and the delivery entry of an answer on any other
/// stream cannot be renamed yet (delivery evidence E.5). Refusing it here is before the unit, the
/// dial and the 101; switching it would be a 101 that the adopt step then has to cut.
pub(super) fn judge(asks: bool, websocket: Option<&ServedTransport>, stream: u64) -> UpgradeTerms {
    let refused = |row| UpgradeTerms {
        refused: Some(row),
        carrier: None,
    };
    match port_mount::upgrade_step(asks, websocket) {
        UpgradeStep::Refuse(_) if !asks => refused(Refusal::NotAnUpgrade),
        UpgradeStep::Refuse(_) => refused(Refusal::NoUpgradeTransport),
        UpgradeStep::HandOver(_) if stream != ADOPTED_STREAM => {
            refused(Refusal::NoUpgradeTransport)
        }
        UpgradeStep::HandOver(carrier) => UpgradeTerms {
            refused: None,
            carrier: Some(carrier.clone()),
        },
    }
}

/// Serves one upgrade request. The answer and its authority are the data path's own: a refusal
/// under the refusal's custody, or the executing request with its settlement (the unit's one
/// terminal, driven when the answer's delivery ends).
///
/// `adopter` is not consulted: the carrier of a hand-over is the listener's own admitted websocket
/// transport ([`NativeSlot::websocket`]), and the adopt step is the connection supervisor's.
pub(super) async fn prepare(
    request: CompletingPhysicalRequest,
    slot: Arc<NativeSlot>,
    adopter: Option<Arc<dyn UpgradeAdopter>>,
    stream: Arc<StreamOwner>,
    node: Arc<Node>,
) -> Result<DataResponse, DataPrepareError> {
    drop(adopter);
    let binding = request.binding().clone();
    if slot.data_for(&binding).is_err() {
        // No data admission is bound for this route: it cannot be given a unit, so it is not
        // handed over.
        return unadmitted(request, slot)
            .await
            .map_err(DataPrepareError::Input);
    }
    let websocket = slot.websocket().cloned();
    super::data::prepare_for(
        request,
        slot,
        node,
        stream,
        Some(UpgradeRequest { websocket }),
    )
    .await
}

/// An upgrade request on a route with no data admission bound: the route's own chain on the head
/// (a denial gets the listener's one unauthenticated answer), then core's refusal before any 101.
/// It is never handed over: 400 when it does not ask to switch, else 501.
async fn unadmitted(
    mut request: CompletingPhysicalRequest,
    slot: Arc<NativeSlot>,
) -> Result<DataResponse, InputError> {
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
            return Ok(DataResponse {
                response,
                authority: DataAuthority::Refused(physical),
                settlement: None,
            });
        }
        Err(UpgradeRefused::Failed(_)) => return Err(InputError::Invalid),
    };
    let head = Arc::clone(authorization.snapshot());
    let withheld = Arc::clone(authorization.withheld());
    let row = if port_mount::asks_websocket(head.headers()) {
        Refusal::NoUpgradeTransport
    } else {
        Refusal::NotAnUpgrade
    };
    let response = answer::route(
        &binding,
        row,
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
    )?;
    let physical = request.refuse_upgrade(authorization)?;
    Ok(DataResponse {
        response,
        authority: DataAuthority::Refused(physical),
        settlement: None,
    })
}

#[cfg(test)]
#[path = "tests/listener_native_upgrade.rs"]
mod tests;
