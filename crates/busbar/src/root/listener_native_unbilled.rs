// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plane routes whose record says money none: a catalog (core's list of what the key may see,
//! rendered by the plane), a principal-only route that moves no money, a public route, and an
//! optional route. The caller is verified where the record asks for it; the answer is recorded;
//! no unit is opened and no limit is counted.

use std::sync::Arc;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use busbar_kernel::auth::admission_table::Admission;
use busbar_kernel::auth::native_data::NativeDataRoute;
use busbar_kernel::inbound::native::{
    CompletingPhysicalRequest, PhysicalRefusal, PhysicalUnbilledExecution, RouteTarget,
};
use busbar_kernel::plane_driver::dispatch::LaneQualifier;
use busbar_kernel::plane_driver::port::{HttpHead, HttpIn, PortSeat, ServeError, ServeIn, Served};
use busbar_kernel::plane_driver::port_auth::{Credentials, Principal, Subject};
use tokio::task::JoinHandle;

use super::data::{self, ClientPipe};
use super::InputError;

/// What the listener holds until the response has gone: the session's task. It is joined, never
/// dropped: dropping a JoinHandle cannot establish that the session stopped.
pub(super) struct UnbilledWork(Option<JoinHandle<Result<Served, ServeError>>>);

impl UnbilledWork {
    pub(super) async fn finish(self) {
        if let Some(work) = self.0 {
            let _ = work.await;
        }
    }
}

pub(super) enum UnbilledAuthority {
    Served(Arc<PhysicalUnbilledExecution>),
    Refused(PhysicalRefusal),
}

pub(super) struct UnbilledResponse {
    pub(super) response: Response,
    pub(super) authority: UnbilledAuthority,
    pub(super) work: UnbilledWork,
}

pub(super) fn seat_of(
    binding: &busbar_kernel::inbound::native::RequestBinding,
) -> Result<(PortSeat, u32), InputError> {
    let RouteTarget::Plane(target) = binding.route().target() else {
        return Err(InputError::Invalid);
    };
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
    Ok((seat, target.mounted().route))
}

/// A verified request on a route that moves no money (catalog, principal-only), or an optional
/// route's request that presents a credential.
pub(super) async fn prepare_verified(
    mut request: CompletingPhysicalRequest,
    route: Arc<NativeDataRoute>,
) -> Result<UnbilledResponse, InputError> {
    let binding = request.binding().clone();
    let (seat, route_id) = seat_of(&binding)?;
    let deadline = binding.deadline().ok_or(InputError::Invalid)?;
    let preparation = request
        .begin_data_preparation()
        .map_err(|_| InputError::Invalid)?;
    let cx = busbar_ports::CallCx {
        deadline,
        request_id: binding.invocation().request_id().get(),
        stack: Default::default(),
    };
    // Steps 2 and 3: the route's chain on the head, then key policy and the replay claim.
    let pending = match route.prepare(preparation, cx).await {
        Ok(pending) => pending,
        Err(failed) => return refused(request, failed, &route, &seat),
    };
    let authorization = match pending.complete().await {
        Ok(authorization) => authorization,
        Err(failed) => return refused(request, failed, &route, &seat),
    };
    // Step 5 on a catalog: core builds the list of what this key may see; the plane only
    // renders it. A restricted key sees its own pools' names and no others.
    let models = if route.route_admission() == Admission::Catalog {
        busbar_kernel::endpoints::catalog_names(
            binding.app(),
            &busbar_kernel::governance::GovCtx {
                key: Some(Arc::clone(authorization.key())),
            },
            &LaneQualifier::default(),
        )
    } else {
        Vec::new()
    };
    let principal = Principal::Verified(Subject::Identity(authorization.identity().clone()));
    let snapshot = Arc::clone(authorization.snapshot());
    let withheld = Arc::clone(route.withheld());
    let owner = Arc::new(request.complete_unbilled(authorization)?);
    serve(owner, seat, route_id, snapshot, withheld, principal, models).await
}

/// A request on a route whose record admits a caller that presents nothing: a public route, or an
/// optional route with no credential on the head. No chain runs and no credential is read.
pub(super) async fn prepare_unverified(
    request: CompletingPhysicalRequest,
) -> Result<UnbilledResponse, InputError> {
    let binding = request.binding().clone();
    let (seat, route_id) = seat_of(&binding)?;
    let snapshot = binding.snapshot().map_err(|_| InputError::Capacity)?;
    let owner = Arc::new(request.complete_unverified()?);
    // Nothing a caller presents on such a route reaches the plane as a credential: the
    // carriers every data route withholds are withheld here too.
    let withheld: Arc<[Box<str>]> = Arc::from(vec![Box::<str>::from("authorization")]);
    serve(
        owner,
        seat,
        route_id,
        snapshot,
        withheld,
        Principal::Anonymous,
        Vec::new(),
    )
    .await
}

/// A signed route's request whose signature verified over its exact bytes and whose replay claim
/// was won (`NativeSignedRoute::admit`). The request the plane is handed is the owner's own
/// verified request: the body is taken from the value verification returned and from nowhere
/// else, so nothing is parsed that was not verified. The sender is no principal (it earned no
/// key): the plane is told the request is signed, and is given no identity and no credential.
pub(super) async fn serve_signed(
    owner: PhysicalUnbilledExecution,
    route: &busbar_kernel::auth::native_signed_route::NativeSignedRoute,
) -> Result<UnbilledResponse, InputError> {
    let owner = Arc::new(owner);
    let binding = owner.binding().clone();
    let (seat, route_id) = seat_of(&binding)?;
    let verified = Arc::clone(owner.signed_request().ok_or(InputError::Invalid)?);
    serve(
        owner,
        seat,
        route_id,
        verified,
        Arc::clone(route.withheld()),
        Principal::Anonymous,
        Vec::new(),
    )
    .await
}

fn refused(
    request: CompletingPhysicalRequest,
    failed: busbar_kernel::auth::native_data::DataPreparationFailed,
    route: &NativeDataRoute,
    seat: &PortSeat,
) -> Result<UnbilledResponse, InputError> {
    let (response, refusal) = data::refuse_prepared(request, failed, route, seat)?;
    Ok(UnbilledResponse {
        response,
        authority: UnbilledAuthority::Refused(refusal),
        work: UnbilledWork(None),
    })
}

async fn serve(
    owner: Arc<PhysicalUnbilledExecution>,
    seat: PortSeat,
    route: u32,
    snapshot: Arc<busbar_kernel::inbound::request_snapshot::ChargedRequestSnapshot>,
    withheld: Arc<[Box<str>]>,
    principal: Principal,
    models: Vec<String>,
) -> Result<UnbilledResponse, InputError> {
    let binding = owner.binding().clone();
    let deadline = binding.deadline().ok_or(InputError::Invalid)?;
    let lease = snapshot.request().clone();
    let now_s = snapshot.now_s();
    let source = lease.storage().clone();
    let mut http = HttpIn::new(
        HttpHead::Snapshot(Arc::clone(&snapshot)),
        snapshot.body_bytes(),
        binding.invocation().request_id().get(),
    );
    // The plane is given the request minus the carriers the route's chain read, and the verified
    // identity, never the credential.
    http.withhold(withheld);
    let (pipe, producer) = ClientPipe::open(source.clone());
    let executing = Arc::clone(&owner);
    let mut work = tokio::spawn(async move {
        let served = if executing.check_executing().is_ok() {
            seat.driver
                .serve(ServeIn {
                    request: lease,
                    admission: None,
                    invocation: None,
                    route,
                    http,
                    creds: Credentials {
                        bearer: None,
                        principal,
                        operator: false,
                        // Signed exactly when the owner holds the request a signature
                        // verified (`complete_signed`); no other owner can say so.
                        signed: executing.signed_request().map(|_| true),
                    },
                    audience: seat.audience.as_deref().unwrap_or_default(),
                    now_s,
                    // No unit: the route's record says money none. A plane that forwards
                    // upstream from such a route has no unit to forward under and is refused
                    // by the walk.
                    unit: None,
                    upstream: None,
                    client: Some(producer.sink()),
                    carrier: seat.carrier.clone(),
                    intents: seat.intents.clone(),
                    models,
                })
                .await
        } else {
            Err(ServeError::NoRoute)
        };
        producer.close();
        served
    });
    let mut pipe = pipe;
    let head = tokio::select! {
        biased;
        head = &mut pipe.head => Some(head),
        () = binding.cancelled() => None,
        () = tokio::time::sleep_until(deadline.into()) => None,
    };
    let Some(head) = head else {
        // No response was published: close the receivers, then join the session's task.
        drop(pipe);
        let _ = work.await;
        return Err(InputError::Invalid);
    };
    let (response, work) = match head {
        Ok(head) => (pipe.response(head), Some(work)),
        Err(_) => {
            drop(pipe);
            match (&mut work).await.ok().and_then(Result::ok) {
                // The plane refused it (its own client error), already rendered.
                Some(Served::Refused(refused)) => {
                    (data::refusal_response(refused.items, &source)?, None)
                }
                _ => {
                    let mut response = Response::new(Body::empty());
                    *response.status_mut() = StatusCode::BAD_GATEWAY;
                    (response, None)
                }
            }
        }
    };
    Ok(UnbilledResponse {
        response,
        authority: UnbilledAuthority::Served(owner),
        work: UnbilledWork(work),
    })
}
