// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Dispatch only the route selected by the original physical request, by its admission.
//!
//! One `match` over the sequence the admission table gives the route (`admission_table::plan`:
//! how the caller is verified, what a served answer is built from), with no catch-all arm over
//! both: a sequence with no code
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
use busbar_kernel::auth::admission_table::{plan, Admission, Authority, VerifyBy};
use busbar_kernel::auth::route_record::Money;
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

/// The answer to a plane request its own input refused. A route that verifies runs its chain on
/// the head first: a denial is the one 401 (or 503, 409) exactly as on a served request, and only
/// a verified caller is told the row, rendered by the route's plane. A route that verifies
/// nobody is answered the row by core.
async fn input_refused(
    mut request: busbar_kernel::inbound::native::CompletingPhysicalRequest,
    slot: &crate::root::min3_physical::NativeSlot,
    admission: Admission,
    refusal: busbar_kernel::auth::admission_table::Refusal,
) -> Result<Answered, InputError> {
    let binding = request.binding().clone();
    let verified_route = match admission {
        Admission::Walk | Admission::Selected | Admission::PrincipalOnly | Admission::Catalog => {
            true
        }
        Admission::Optional => {
            let route = slot.data_for(&binding).map_err(|_| InputError::Invalid)?;
            answer::presented(&binding, route.withheld())
        }
        Admission::Public => false,
        // An upgrade request carries no body to refuse; the rest are not a data listener's.
        Admission::Upgrade
        | Admission::Ticket
        | Admission::SignedIngress
        | Admission::Operator
        | Admission::Internal => return Err(InputError::Invalid),
    };
    if !verified_route {
        let response = answer::core(&binding, refusal, false, "", None)?;
        let owner = Arc::new(request.complete_unverified()?);
        return Ok((response, ResponseAuthority::Unbilled(owner), None));
    }
    let route = slot.data_for(&binding).map_err(|_| InputError::Invalid)?;
    let (seat, _) = super::unbilled::seat_of(&binding)?;
    let deadline = binding.deadline().ok_or(InputError::Invalid)?;
    let preparation = request
        .begin_data_preparation()
        .map_err(|_| InputError::Invalid)?;
    let failed = match route
        .prepare(
            preparation,
            busbar_ports::CallCx {
                deadline,
                request_id: binding.invocation().request_id().get(),
                stack: Default::default(),
            },
        )
        .await
    {
        Ok(pending) => pending.refuse_input(refusal),
        Err(failed) => failed,
    };
    let (response, physical) = data::refuse_prepared(request, failed, &route, &seat)?;
    Ok((response, ResponseAuthority::Refused(physical), None))
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
                // Step 0: the gateway is full or draining. Answered before any route, caller
                // or unit is looked at, on every route and on none; the connection is kept.
                _ if matches!(
                    ready.refused,
                    Some(
                        busbar_kernel::auth::admission_table::Refusal::GatewayFull
                            | busbar_kernel::auth::admission_table::Refusal::Draining
                    )
                ) =>
                {
                    let refusal = ready.refused.ok_or(InputError::Invalid)?;
                    let response = answer::core(&binding, refusal, false, "", None)?;
                    let owner = ready.request.refuse_at_gate()?;
                    (response, ResponseAuthority::Gate(owner), None)
                }
                // The request's own input refused it (a body over the cap, request trailers).
                // Its caller is judged as for any request, so an unverified one still receives
                // the one 401; a verified one is answered the row. Nothing is served.
                (RouteTarget::Plane(_), Some(admission)) if ready.refused.is_some() => {
                    let refusal = ready.refused.ok_or(InputError::Invalid)?;
                    let slot =
                        (native.select)(binding.app(), &native.slot).ok_or(InputError::Invalid)?;
                    input_refused(ready.request, &slot, admission, refusal).await?
                }
                // A core route's own input refusal has no custody to answer under yet: the
                // request ends as it did before (the connection is stopped).
                (RouteTarget::Core(_), _) if ready.refused.is_some() => {
                    return Err(match ready.refused {
                        Some(busbar_kernel::auth::admission_table::Refusal::BodyTooLarge) => {
                            InputError::TooLarge
                        }
                        _ => InputError::Trailers,
                    }
                    .into())
                }
                (RouteTarget::Plane(_), Some(admission)) => {
                    let slot =
                        (native.select)(binding.app(), &native.slot).ok_or(InputError::Invalid)?;
                    // The sequence is the table's (`admission_table::plan`): how the caller is
                    // verified and what a served answer is built from are read from it, so the
                    // listener holds no order of its own and cannot drift from the truth table.
                    let money = match slot.data_for(&binding) {
                        Ok(route) if route.billed() => Money::Unit,
                        _ => Money::None,
                    };
                    let Some(sequence) = plan(admission, money) else {
                        // An internal route is on no listener.
                        return Err(InputError::Invalid.into());
                    };
                    match (sequence.verify, sequence.serves) {
                        // Money moves: the data path. The unit is opened before the plane is
                        // called; scope, limits and money are admitted there or at its FORWARD.
                        (VerifyBy::Chain, Authority::Billed | Authority::Walk) => {
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
                        }
                        // Verified and not billed: a catalog, a principal's route that moves no
                        // money.
                        (VerifyBy::Chain, Authority::Unbilled | Authority::Catalog) => {
                            let route = slot.data_for(&binding).map_err(|_| InputError::Invalid)?;
                            unbilled(super::unbilled::prepare_verified(ready.request, route).await?)
                        }
                        (VerifyBy::Chain, Authority::Upgrade) => {
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
                        // The chain runs only when a credential is presented.
                        (VerifyBy::ChainIfPresented, _) => {
                            let route = slot.data_for(&binding).map_err(|_| InputError::Invalid)?;
                            if answer::presented(&binding, route.withheld()) {
                                unbilled(
                                    super::unbilled::prepare_verified(ready.request, route).await?,
                                )
                            } else {
                                unbilled(super::unbilled::prepare_unverified(ready.request).await?)
                            }
                        }
                        // Nobody is verified and no credential is read.
                        (VerifyBy::Nobody, _) => {
                            unbilled(super::unbilled::prepare_unverified(ready.request).await?)
                        }
                        // A ticket and a sender's signature have no native verifier yet, so the
                        // plan mounts no such route; one that arrives here is the engine's
                        // fault and is never served.
                        (VerifyBy::TicketOrChain | VerifyBy::Signature, _) => {
                            return Err(InputError::Invalid.into())
                        }
                        // A plane's admin routes are mounted on the admin door.
                        (VerifyBy::AdminChain, _) => return Err(InputError::Invalid.into()),
                        // The chain verified a caller for an authority the chain does not
                        // grant: the table and this match disagree, and nothing is served.
                        (VerifyBy::Chain, Authority::Public | Authority::Operator) => {
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
                (RouteTarget::Core(RouteAuth::Key), _) => {
                    // `/stats` and a plugin's own keyed route: the data chain verifies the
                    // caller, the handler filters by the verified key, no unit is opened.
                    let slot = (native.select)(binding.app(), &native.slot);
                    match super::corekey::prepare(ready.request, slot).await? {
                        super::corekey::KeyAnswered::Served(response, owner) => {
                            (response, ResponseAuthority::CoreKey(owner), None)
                        }
                        super::corekey::KeyAnswered::Refused(response, owner) => {
                            (response, ResponseAuthority::CoreKeyRefused(owner), None)
                        }
                    }
                }
                (RouteTarget::Unrouted, _) => {
                    // No route matched: the data chain judges the caller. 404 or 405 to a verified
                    // one; the one unverified answer, identical to a real route's, to anyone else.
                    let slot = (native.select)(binding.app(), &native.slot);
                    let (response, refusal) = super::unrouted::prepare(ready.request, slot).await?;
                    (response, ResponseAuthority::Refused(refusal), None)
                }
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
