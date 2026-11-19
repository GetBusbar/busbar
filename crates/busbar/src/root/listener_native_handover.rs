// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hand-over of an admitted upgrade request (§12.27 steps 2 to 5): the one seam between
//! admission, which is the listener's, and the carrier that takes the stream, which is the
//! websocket transport's. Admission's part ends here: everything through money happened on the
//! HTTP head, the request is consumed once into a [`PhysicalUpgrade`], and what the adopter is
//! handed can produce a 101 and nothing else.

use std::sync::Arc;

use axum::response::Response;
use busbar_kernel::inbound::native::{PhysicalUpgrade, StreamOwner};
use busbar_kernel::plane_driver::port::PortSeat;

use super::InputError;
use crate::root::min3_boot::transports::ServedTransport;
use crate::root::plane_node::Node;

/// Everything an adopter needs, and the only things it may use.
pub(crate) struct HandOver {
    /// The consumed request: the charged head, the verified identity, the governed key and the
    /// plane route. Dropping it cancels the request.
    pub(crate) upgrade: Arc<PhysicalUpgrade>,
    /// The route's plane seat: the adopter calls its `request` on the head with an empty body.
    pub(crate) seat: PortSeat,
    pub(crate) route: u32,
    /// The carriers the route's chain read: withheld from the plane on the hand-over's `request`.
    pub(crate) withheld: Arc<[Box<str>]>,
    /// The stream the upgrade arrived on. The adopter renames it at hand-over, so an upgrade on a
    /// request that is not its connection's first does not collide with the adopted stream.
    pub(crate) stream: Arc<StreamOwner>,
    /// The node that owns the request's unit: money is admitted through it before the plane is
    /// called, exactly as a data request's is.
    pub(crate) node: Arc<Node>,
}

/// What the adopter answered on the HTTP head.
pub(crate) enum Adopted {
    /// The plane committed with RESPOND(101): the response carries the 101 head and the plane's
    /// pairs, and the session continues on the adopted stream, begun with CONN_UPGRADED.
    Switched(Response),
    /// The plane answered something else before any 101 (its own client error): written as an
    /// ordinary response; the stream is not adopted.
    Answered(Response),
}

/// The carrier side of the hand-over. One implementation, linked by the websocket transport's
/// adapter; the listener holds it as `NativeListener::adopter`.
///
/// The contract an implementation keeps:
/// 1. open the request's unit and admit its money through `node` before calling the plane (scope,
///    limits and the unit are judged on the head: a refusal there is `Adopted::Answered`);
/// 2. call the plane's `request` once on `upgrade`'s head with an empty body, `withheld` withheld;
/// 3. on RESPOND(101), `begin` `carrier` with CONN_UPGRADED and the head, H_STATUS(101) and the
///    plane's PAIR*, on `stream` renamed for the adopted connection;
/// 4. settle the unit once, when the adopted session ends.
#[async_trait::async_trait]
pub(crate) trait UpgradeAdopter: Send + Sync {
    async fn hand_over(
        &self,
        carrier: &ServedTransport,
        hand_over: HandOver,
    ) -> Result<Adopted, InputError>;
}
