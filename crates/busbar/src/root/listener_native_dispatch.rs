// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Dispatch only the route selected by the original physical request, by its admission.
//!
//! One `match` over the route's [`Admission`] with no catch-all arm: an admission with no code
//! here does not compile, so "no native path admits this class" is not a state the listener can
//! be in. Each arm lives in its own file of the family, side by side:
//!
//! | admission | file | authority of a served answer |
//! |---|---|---|
//! | walk, selected, principal-only with a unit | `listener_native_data.rs` | `Data` (after money) |
//! | catalog, principal-only free, public, optional | `listener_native_unbilled.rs` | `Unbilled` |
//! | upgrade | `listener_native_upgrade.rs`, `listener_native_handover.rs` | `Upgrade` |
//! | operator | the admin router, below | `Admin` |
//! | no route | `listener_native_unrouted.rs` | (a refusal) |
//!
//! Every refusal is written by `listener_native_answer.rs` from the one refusal table.

use std::sync::Arc;

use axum::body::Body;
use busbar_contract::route::RouteAuth;
use busbar_core_connector::framed_stream::session::{Feed, RegisterResponse};
use busbar_kernel::auth::admission_table::Admission;
use busbar_kernel::inbound::http_projection::HttpProjection;
use busbar_kernel::inbound::native::{PhysicalAdminExecution, PhysicalRefusalCarrier, RouteTarget};
use tokio::sync::mpsc;
use tower::ServiceExt;

use super::delivery::{CompletedResponse, RegisteredResponse, ResponseAuthority};
use super::unbilled::{UnbilledAuthority, UnbilledResponse, UnbilledWork};
use super::upgrade::Upgraded;
use super::{answer, data, InputError, NativeListener, ReadyInput};
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

/// What must be finished after the response has gone.
enum Settlement {
    /// A request that reached money: its unit is settled once, by what the client was answered.
    Data(data::DataSettlement),
    /// A session that opened no unit: its task is joined.
    Unbilled(UnbilledWork),
}

pub(super) struct Prepared {
    response: axum::response::Response,
    registered: RegisteredResponse,
    settlement: Option<Settlement>,
}

impl Prepared {
    pub(super) fn native_node_handle(&self) -> Option<NativeNodeHandle> {
        match self.settlement.as_ref()? {
            Settlement::Data(settlement) => settlement.native_node_handle(),
            Settlement::Unbilled(_) => None,
        }
    }
    pub(super) async fn send(self, feeds: &mpsc::Sender<Feed>, node: &Node) -> CompletedResponse {
        let mut completed = self.registered.send_http(self.response, feeds, node).await;
        match self.settlement {
            // The completion keeps the original physical execution and input retirement guard
            // until the same Task's selected monetary terminal has consumed the genuine delivery
            // receipt.
            Some(Settlement::Data(settlement)) => {
                if let Err(error) = settlement
                    .finish(&completed.delivery, &completed.snapshot)
                    .await
                {
                    completed.result = Err(error);
                }
            }
            Some(Settlement::Unbilled(work)) => work.finish().await,
            None => {}
        }
        completed
    }
}

/// The admission of the request's route, as its bound completion states it. A plane route with
/// no bound completion is one whose record admits nobody in particular (public) or is an upgrade:
/// those are told apart by the route's own declaration.
fn admission_of(
    native: &NativeListener,
    binding: &busbar_kernel::inbound::native::RequestBinding,
) -> Result<Admission, InputError> {
    let RouteTarget::Plane(target) = binding.route().target() else {
        return Err(InputError::Invalid);
    };
    if crate::root::min3_physical::is_upgrade(binding.route()) {
        return Ok(Admission::Upgrade);
    }
    let slot = (native.select)(binding.app(), &native.slot).ok_or(InputError::Invalid)?;
    if let Ok(route) = slot.data_for(binding) {
        return Ok(route.route_admission());
    }
    // No completion was bound: the only routes mounted without one verify nobody.
    if target.mounted().auth == busbar_plugin_abi::plane::AUTH_PUBLIC {
        Ok(Admission::Public)
    } else {
        Err(InputError::Invalid)
    }
}

type Answered = (
    axum::response::Response,
    ResponseAuthority,
    Option<Settlement>,
);

fn unbilled(served: UnbilledResponse) -> Answered {
    let UnbilledResponse {
        response,
        authority,
        work,
    } = served;
    (
        response,
        match authority {
            UnbilledAuthority::Served(owner) => ResponseAuthority::Unbilled(owner),
            UnbilledAuthority::Refused(owner) => ResponseAuthority::Refused(owner),
        },
        Some(Settlement::Unbilled(work)),
    )
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
    let admission = match binding.route().target() {
        RouteTarget::Plane(_) => Some(admission_of(&native, &binding)?),
        RouteTarget::Core(_) | RouteTarget::Unrouted => None,
    };
    // A request that reaches money owns a plane session and monetary state: its producer
    // observes the original cancellation and deadline and joins that work.
    let joins_its_own_work = matches!(
        admission,
        Some(
            Admission::Walk
                | Admission::Selected
                | Admission::PrincipalOnly
                | Admission::Catalog
                | Admission::Optional
                | Admission::Public
                | Admission::Upgrade
        )
    );
    let work = async {
        let (response, authority, settlement): Answered =
            match (binding.route().target(), admission) {
                (RouteTarget::Plane(_), Some(admission)) => {
                    let slot =
                        (native.select)(binding.app(), &native.slot).ok_or(InputError::Invalid)?;
                    match admission {
                        // Money moves (or the walk judges scope): the data path.
                        Admission::Walk | Admission::Selected | Admission::PrincipalOnly => {
                            let route = slot.data_for(&binding).map_err(|_| InputError::Invalid)?;
                            if route.billed() {
                                // Lend the same HEAD-created physical owner to Node before Task
                                // admission. Node retains it independently through registration and
                                // audit failures.
                                let prepared =
                                    data::prepare(ready.request, slot, node, ready.owner.clone())
                                        .await?;
                                (
                                    prepared.response,
                                    match prepared.authority {
                                        data::DataAuthority::Executing(owner) => {
                                            ResponseAuthority::Data(owner)
                                        }
                                        data::DataAuthority::Refused(owner) => {
                                            ResponseAuthority::Refused(owner)
                                        }
                                    },
                                    prepared.settlement.map(Settlement::Data),
                                )
                            } else {
                                unbilled(
                                    super::unbilled::prepare_verified(ready.request, route).await?,
                                )
                            }
                        }
                        Admission::Catalog => {
                            let route = slot.data_for(&binding).map_err(|_| InputError::Invalid)?;
                            unbilled(super::unbilled::prepare_verified(ready.request, route).await?)
                        }
                        Admission::Optional => {
                            let route = slot.data_for(&binding).map_err(|_| InputError::Invalid)?;
                            // The chain runs only when a credential is presented.
                            if answer::presented(&binding, route.withheld()) {
                                unbilled(
                                    super::unbilled::prepare_verified(ready.request, route).await?,
                                )
                            } else {
                                unbilled(super::unbilled::prepare_unverified(ready.request).await?)
                            }
                        }
                        Admission::Public => {
                            unbilled(super::unbilled::prepare_unverified(ready.request).await?)
                        }
                        Admission::Upgrade => {
                            match super::upgrade::prepare(
                                ready.request,
                                slot,
                                native.adopter.clone(),
                                ready.owner.clone(),
                                node,
                            )
                            .await?
                            {
                                Upgraded::Refused(response, refusal) => {
                                    (response, ResponseAuthority::Refused(refusal), None)
                                }
                                Upgraded::Executing(response, owner) => {
                                    (response, ResponseAuthority::Upgrade(owner), None)
                                }
                            }
                        }
                        // A ticket and a sender's signature are verified by core's ticket book and
                        // the route's signature verifier. Neither has a native verifier yet, so the
                        // plan mounts no such route (`NotMounted::NoSignatureVerifier`, and a
                        // ticket-only route has no chain to bind); one that arrives here is answered
                        // is the engine's fault and is never served.
                        Admission::Ticket | Admission::SignedIngress => {
                            return Err(InputError::Invalid.into())
                        }
                        // A plane's admin routes are mounted on the admin door, and an internal
                        // route on no listener: neither is a data listener's route.
                        Admission::Operator | Admission::Internal => {
                            return Err(InputError::Invalid.into())
                        }
                    }
                }
                (RouteTarget::Plane(_), None) => return Err(InputError::Invalid.into()),
                (RouteTarget::Core(RouteAuth::None), _) => {
                    let owner = Arc::new(ready.request.complete_public()?);
                    let response = owner.http_response().await?;
                    (response, ResponseAuthority::Public(owner), None)
                }
                (RouteTarget::Core(RouteAuth::Admin), _) => {
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
                (RouteTarget::Unrouted, _) => {
                    // No route matched: the data chain judges the caller. 404 or 405 to a verified
                    // one; the one unverified answer, identical to a real route's, to anyone else.
                    let slot = (native.select)(binding.app(), &native.slot);
                    let (response, refusal) = super::unrouted::prepare(ready.request, slot).await?;
                    (response, ResponseAuthority::Refused(refusal), None)
                }
                (RouteTarget::Core(_), _) => return Err(InputError::Invalid.into()),
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
                return Err(match settlement {
                    Some(Settlement::Data(settlement)) => {
                        let handle = settlement.native_node_handle();
                        let error = settlement
                            .registration_failed()
                            .await
                            .err()
                            .unwrap_or(error);
                        match handle {
                            Some(handle) => data::DataPrepareError::HeldNode { error, handle },
                            None => data::DataPrepareError::Input(error),
                        }
                    }
                    Some(Settlement::Unbilled(work)) => {
                        work.finish().await;
                        data::DataPrepareError::Input(error)
                    }
                    None => data::DataPrepareError::Input(error),
                });
            }
        };
        Ok(Prepared {
            response,
            registered,
            settlement,
        })
    };
    if joins_its_own_work {
        // Dropping this await would detach a plane session from the request that owns it.
        return work.await;
    }
    tokio::select! {
        result = work => result,
        () = binding.cancelled() => Err(InputError::Delivery(busbar_contract::response_delivery::ResponseStop::Cancelled).into()),
        () = tokio::time::sleep_until(deadline) => Err(InputError::Delivery(busbar_contract::response_delivery::ResponseStop::Deadline).into()),
    }
}
