// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The retained native DATA request drives one Task and settles its original monetary owner.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use busbar_contract::response_delivery::{DeliverySnapshot, DeliveryTerminal};
use busbar_contract::storage::{StorageCredit, StorageSource};
use busbar_kernel::auth::native_data::{NativeDataAllocation, NativeDataPending};
use busbar_kernel::inbound::native::{CompletingPhysicalRequest, RouteTarget, StreamOwner};
use busbar_kernel::plane_driver::port::{
    HttpHead, HttpIn, NativeServed, NativeTaskRetirement, ServeError, ServeIn, Served,
};
use busbar_kernel::plane_driver::port_admission::AdmittedUnit;
use busbar_kernel::plane_driver::port_auth::{Credentials, Principal};
use busbar_kernel::plane_driver::port_billing::{end_of, NativeOrdinaryTerminalSlot, PortBilling};
use busbar_kernel::plane_driver::port_session::{ClientSink, ToClient};
use busbar_kernel::plane_driver::{FeeRefund, HeadFields, NativeAdmissionError};
use bytes::Bytes;
use http_body::Frame;
use tokio::sync::{mpsc, oneshot};

use super::{InputError, RegisteredDelivery};
use crate::root::min3_physical::NativeSlot;
use crate::root::plane_node::{NativeNodeHandle, Node};

pub(super) enum DataPrepareError {
    Input(InputError),
    HeldNode {
        error: InputError,
        handle: NativeNodeHandle,
    },
}

pub(super) enum DataAuthority {
    Executing(Arc<NativeDataPending>),
    Refused(busbar_kernel::inbound::native::PhysicalRefusal),
}

pub(super) struct DataResponse {
    pub(super) response: Response,
    pub(super) authority: DataAuthority,
    pub(super) settlement: Option<DataSettlement>,
}

pub(super) struct DataSettlement {
    authority: Arc<NativeDataPending>,
    billing: PortBilling,
    work: Option<tokio::task::JoinHandle<Result<NativeServed, ServeError>>>,
    retirement: Option<NativeTaskRetirement>,
    ran: bool,
    status: u16,
    node: NativeNodeHandle,
    ordinary: Arc<NativeOrdinaryTerminalSlot>,
}

impl DataSettlement {
    pub(super) fn native_node_handle(&self) -> Option<NativeNodeHandle> {
        Some(self.node.clone())
    }

    /// Elect the original terminal intent in the Node-owned slot, then attempt its one
    /// transfer. A failed transfer retains the intent and Open; the Node pulse retries it.
    /// Neither step is a receipt: the Node entry stays until the checkpoint R confirms.
    fn ordinary_terminal(
        &self,
        request: &busbar_kernel::plane_driver::request_admission::AdmittedRequest,
        end: busbar_kernel::plane_driver::UnitEnd,
    ) -> Result<(), InputError> {
        self.ordinary
            .request_terminal(request, end)
            .map_err(|_| InputError::Invalid)?;
        let _ = self.billing.drive_ordinary_terminal(&self.ordinary);
        Ok(())
    }

    /// Registration never exposed a response feed. The caller first drops the unpublished
    /// body so its blocked producer can stop, then retains this join through actual retirement.
    pub(super) async fn registration_failed(mut self) -> Result<(), InputError> {
        let failed = if let Some(work) = self.work.take() {
            match work.await {
                Ok(Ok(served)) => {
                    let (served, retirement) = served.into_parts();
                    self.ran = matches!(served, Served::Ran(_));
                    self.retirement = Some(retirement);
                    false
                }
                Ok(Err(_)) | Err(_) => {
                    self.ran = false;
                    true
                }
            }
        } else {
            false
        };
        // Never registered: W04's carrier receipt is the physical half of this terminal.
        self.node.unregistered(self.ran, failed)?;
        let admitted = self.authority.admitted().ok_or(InputError::Invalid)?;
        if admitted.selected.is_some() {
            return Err(InputError::Invalid);
        }
        let mut end = end_of(502, self.ran);
        end.cut = true;
        self.ordinary_terminal(&admitted.request, end)?;
        if failed {
            Err(InputError::Invalid)
        } else {
            Ok(())
        }
    }

    pub(super) async fn finish(
        mut self,
        delivery: &RegisteredDelivery,
        snapshot: &DeliverySnapshot,
    ) -> Result<(), InputError> {
        let work_failed = if let Some(work) = self.work.take() {
            match work.await {
                Ok(Ok(served)) => {
                    let (served, retirement) = served.into_parts();
                    self.ran = matches!(served, Served::Ran(_));
                    self.retirement = Some(retirement);
                    false
                }
                Ok(Err(_)) | Err(_) => {
                    self.ran = false;
                    true
                }
            }
        } else {
            false
        };
        if snapshot.terminal.is_none() || delivery.reader().snapshot() != *snapshot {
            return Err(InputError::Invalid);
        }
        let admitted = self.authority.admitted().ok_or(InputError::Invalid)?;
        let original = delivery.admission().ok_or(InputError::Invalid)?;
        if !original.same_admission(&admitted.request) {
            return Err(InputError::Invalid);
        }
        // r2: the ACK-created loan is authority only when its reader key is its stored key and
        // that key names this same original unit.
        if delivery.reader().key() != delivery.key() || delivery.key().unit != Some(original.unit())
        {
            return Err(InputError::Invalid);
        }
        let mut end = end_of(u32::from(self.status), self.ran);
        end.cut = matches!(snapshot.terminal, Some(DeliveryTerminal::Failed(_)));
        // Delivered output retired at delivery: the verified snapshot is the physical proof.
        self.node.delivered(snapshot, self.ran, work_failed)?;
        // This first cohort uses the adopted ordinary DATA callback. Selected activation
        // requires its finite route ceiling and actual Node audit admission producer.
        if admitted.selected.is_some() {
            return Err(InputError::Invalid);
        }
        self.ordinary_terminal(original, end)?;
        if work_failed {
            Err(InputError::Invalid)
        } else {
            Ok(())
        }
    }
}

struct ChargedBytes {
    bytes: Vec<u8>,
    _credit: StorageCredit,
}
impl AsRef<[u8]> for ChargedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

struct RefusalBody {
    items: std::vec::IntoIter<ToClient>,
    credit: StorageCredit,
    source: StorageSource,
    trailer_credit: Option<StorageCredit>,
    trailers: bool,
    ended: bool,
}
impl http_body::Body for RefusalBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        let result = match self.items.next() {
            Some(ToClient::Body(bytes)) if !self.trailers => self
                .credit
                .split(bytes.capacity())
                .map(|credit| {
                    Frame::data(Bytes::from_owner(ChargedBytes {
                        bytes,
                        _credit: credit,
                    }))
                })
                .map_err(|_| ()),
            Some(ToClient::Trailers(values)) if !self.trailers => {
                match fields(&self.source, values) {
                    Ok((headers, credit)) => {
                        self.trailers = true;
                        self.trailer_credit = Some(credit);
                        Ok(Frame::trailers(headers))
                    }
                    Err(()) => Err(()),
                }
            }
            Some(ToClient::End) if self.items.as_slice().is_empty() => {
                self.ended = true;
                return Poll::Ready(None);
            }
            _ => Err(()),
        };
        match result {
            Ok(frame) => Poll::Ready(Some(Ok(frame))),
            Err(()) => {
                self.ended = true;
                Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "native refusal producer ended without valid END",
                ))))
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.ended
    }
}

pub(super) fn refusal_response(
    items: Vec<ToClient>,
    source: &StorageSource,
) -> Result<Response, InputError> {
    let mut extent = items
        .capacity()
        .checked_mul(std::mem::size_of::<ToClient>())
        .ok_or(InputError::Capacity)?;
    for item in &items {
        let bytes = match item {
            ToClient::Head { fields, .. } | ToClient::Trailers(fields) => fields.iter().try_fold(
                fields
                    .capacity()
                    .checked_mul(std::mem::size_of::<(Vec<u8>, Vec<u8>)>())
                    .ok_or(InputError::Capacity)?,
                |sum, (name, value)| {
                    sum.checked_add(name.capacity())
                        .and_then(|sum| sum.checked_add(value.capacity()))
                        .ok_or(InputError::Capacity)
                },
            )?,
            ToClient::Body(bytes) | ToClient::Msg { bytes, .. } => bytes.capacity(),
            ToClient::End => 0,
        };
        extent = extent.checked_add(bytes).ok_or(InputError::Capacity)?;
    }
    let credit = source
        .try_reserve(extent)
        .map_err(|_| InputError::Capacity)?;
    let mut items = items.into_iter();
    let Some(ToClient::Head {
        status,
        fields: values,
    }) = items.next()
    else {
        return Err(InputError::Invalid);
    };
    let (headers, head_credit) = fields(source, values).map_err(|_| InputError::Capacity)?;
    let status = StatusCode::from_u16(status).map_err(|_| InputError::Invalid)?;
    let mut response = Response::new(Body::new(RefusalBody {
        items,
        credit,
        source: source.clone(),
        trailer_credit: None,
        trailers: false,
        ended: false,
    }));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response.extensions_mut().insert(Arc::new(head_credit));
    Ok(response)
}

struct BodyItem {
    frame: Frame<Bytes>,
    trailers: Option<StorageCredit>,
}

struct DataBody {
    receiver: mpsc::Receiver<BodyItem>,
    ended: Arc<std::sync::atomic::AtomicBool>,
    trailer_credit: Option<StorageCredit>,
    failed: bool,
}
impl http_body::Body for DataBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        match self.receiver.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(item)) => {
                if item.trailers.is_some() {
                    self.trailer_credit = item.trailers;
                }
                Poll::Ready(Some(Ok(item.frame)))
            }
            Poll::Ready(None) if self.ended.load(std::sync::atomic::Ordering::Acquire) => {
                Poll::Ready(None)
            }
            Poll::Ready(None) => {
                self.failed = true;
                Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "native DATA producer ended without END",
                ))))
            }
        }
    }
}

type Head = (u16, HeaderMap, Arc<StorageCredit>);
struct SinkState {
    head: Option<oneshot::Sender<Head>>,
    /// The bounded `mpsc(1)` to the response body, polled for room by the session's own task: at most one body
    /// item in flight, and the session waits (it is not a thread that blocks) until the body has taken it.
    body: Option<tokio_util::sync::PollSender<BodyItem>>,
    trailers: bool,
}
struct Sink {
    source: StorageSource,
    state: Mutex<SinkState>,
    ended: Arc<std::sync::atomic::AtomicBool>,
}

fn fields(source: &StorageSource, fields: HeadFields) -> Result<(HeaderMap, StorageCredit), ()> {
    use axum::http::header::{HeaderMapPlan, ProjectionError};
    let plan = HeaderMapPlan::for_values(fields.len()).map_err(|_| ())?;
    let credit = source
        .try_reserve(plan.allocation_bytes())
        .map_err(|_| ())?;
    let map = HeaderMap::try_from_plan(
        plan,
        fields.into_iter().map(|(mut name, value)| {
            let name_credit = source
                .try_reserve(name.capacity())
                .map_err(|_| ProjectionError::Capacity)?;
            let value_credit = source
                .try_reserve(value.capacity())
                .map_err(|_| ProjectionError::Capacity)?;
            name.make_ascii_lowercase();
            let name = HeaderName::from_lowercase_shared(Bytes::from_owner(ChargedBytes {
                bytes: name,
                _credit: name_credit,
            }))
            .map_err(|_| ProjectionError::InvalidField)?;
            let value = HeaderValue::from_maybe_shared(Bytes::from_owner(ChargedBytes {
                bytes: value,
                _credit: value_credit,
            }))
            .map_err(|_| ProjectionError::InvalidField)?;
            Ok((name, value))
        }),
    )
    .map_err(|_| ())?;
    Ok((map, credit))
}

impl Sink {
    /// One item, whose body room (if it needs any) is already reserved.
    fn put(&self, state: &mut SinkState, item: ToClient) -> Result<(), ()> {
        match item {
            ToClient::Head {
                status,
                fields: values,
            } => {
                let (headers, credit) = fields(&self.source, values)?;
                state
                    .head
                    .take()
                    .ok_or(())?
                    .send((status, headers, Arc::new(credit)))
                    .map_err(|_| ())?;
            }
            ToClient::Body(bytes) => {
                let credit = self.source.try_reserve(bytes.capacity()).map_err(|_| ())?;
                let bytes = Bytes::from_owner(ChargedBytes {
                    bytes,
                    _credit: credit,
                });
                state
                    .body
                    .as_mut()
                    .ok_or(())?
                    .send_item(BodyItem {
                        frame: Frame::data(bytes),
                        trailers: None,
                    })
                    .map_err(|_| ())?;
            }
            ToClient::Trailers(values) => {
                let (headers, credit) = fields(&self.source, values)?;
                state.trailers = true;
                state
                    .body
                    .as_mut()
                    .ok_or(())?
                    .send_item(BodyItem {
                        frame: Frame::trailers(headers),
                        trailers: Some(credit),
                    })
                    .map_err(|_| ())?;
            }
            ToClient::End => {
                self.ended.store(true, std::sync::atomic::Ordering::Release);
                state.body.take();
            }
            ToClient::Msg { .. } => return Err(()),
        }
        Ok(())
    }
}

impl ClientSink for Sink {
    fn poll_items(&self, cx: &mut Context<'_>, items: &mut Vec<ToClient>) -> Poll<bool> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while let Some(next) = items.first() {
            if matches!(next, ToClient::Body(_) | ToClient::Trailers(_)) {
                if state.head.is_some() || state.trailers {
                    state.body.take();
                    return Poll::Ready(false);
                }
                // The body's one slot: wait (this task's waker is kept) until the response body took the last item.
                let Some(body) = state.body.as_mut() else {
                    return Poll::Ready(false);
                };
                match body.poll_reserve(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(_)) => {
                        state.body.take();
                        return Poll::Ready(false);
                    }
                    Poll::Ready(Ok(())) => {}
                }
            }
            let item = items.remove(0);
            if self.put(&mut state, item).is_err() {
                state.body.take();
                return Poll::Ready(false);
            }
        }
        Poll::Ready(true)
    }
}

/// A DATA request its route's chain denied (credential, policy or replay) is answered with the
/// listener's one unauthenticated refusal under the denial's own custody. Any other failure (an
/// unavailable verifier, a deadline, a foreign input) grants no answer: the request is cancelled.
fn denied(
    request: CompletingPhysicalRequest,
    failed: busbar_kernel::auth::native_data::DataPreparationFailed,
    carriers: &[Box<str>],
) -> Result<DataResponse, DataPrepareError> {
    let busbar_kernel::auth::native_data::DataPreparationFailed::Denied(denial) = failed else {
        return Err(DataPrepareError::Input(InputError::Invalid));
    };
    let response = super::unauthenticated_response(request.binding(), carriers)?;
    let refusal = request.refuse_data(denial).map_err(InputError::from)?;
    Ok(DataResponse {
        response,
        authority: DataAuthority::Refused(refusal),
        settlement: None,
    })
}

pub(super) async fn prepare(
    mut request: CompletingPhysicalRequest,
    slot: Arc<NativeSlot>,
    node: Arc<Node>,
    stream_owner: Arc<StreamOwner>,
) -> Result<DataResponse, DataPrepareError> {
    let binding = request.binding().clone();
    let routes = binding
        .prepared()
        .data()
        .ok_or(InputError::Invalid)?
        .downcast::<crate::root::serve::DataRoutes>()
        .map_err(|_| InputError::Invalid)?;
    let original_node = routes.post.node().ok_or(InputError::Invalid)?;
    if !Arc::ptr_eq(&original_node, &node) {
        return Err(DataPrepareError::Input(InputError::Invalid));
    }
    let RouteTarget::Plane(target) = binding.route().target() else {
        return Err(DataPrepareError::Input(InputError::Invalid));
    };
    let route = target.mounted().route;
    let seat = routes
        .served
        .ports
        .iter()
        .find(|seat| seat.driver.caller().same_incarnation(target.caller()))
        .cloned()
        .ok_or(InputError::Invalid)?;
    let billing = routes.served.billing.clone().ok_or(InputError::Invalid)?;
    let data_route = slot.data_for(&binding).map_err(|_| InputError::Invalid)?;
    let deadline = binding.deadline().ok_or(InputError::Invalid)?;
    let preparation = request
        .begin_data_preparation()
        .map_err(|_| InputError::Invalid)?;
    // Auth first: the route's chain verifies the credential before anything of the request is
    // lent to the plane.
    let pending = match data_route
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
        Ok(pending) => pending,
        Err(failed) => return denied(request, failed, data_route.withheld()),
    };
    // Only a verified request is lent to a selecting route's plane (a direct call on this
    // request's thread, its credential carriers withheld). A route that selects nothing is
    // admitted through the plane's own `request`.
    let pending = if data_route.selects() {
        let port = seat.driver.port();
        match pending.select(|frozen, withheld| {
            busbar_kernel::resource_admission::select_resources(&*port, frozen, withheld)
        }) {
            Ok(pending) => pending,
            Err(failed) => return denied(request, failed, data_route.withheld()),
        }
    } else {
        pending
    };
    let authorization = match pending.complete().await {
        Ok(authorization) => authorization,
        Err(failed) => return denied(request, failed, data_route.withheld()),
    };
    let authorized = request
        .complete(authorization)
        .map_err(|_| InputError::Invalid)?;
    let mut allocation =
        NativeDataAllocation::register(authorized).map_err(|_| InputError::Invalid)?;
    let classes = seat.driver.usage_classes();
    let (native_node, unit, ordinary) = node
        .install_native(
            &mut allocation,
            stream_owner,
            routes.post.clone(),
            &billing,
            classes.clone(),
        )
        .map_err(|(error, handle)| match handle {
            Some(handle) => DataPrepareError::HeldNode { error, handle },
            None => DataPrepareError::Input(error),
        })?;
    let result: Result<DataResponse, InputError> = async {
        let callback_billing = billing.clone();
        let callback_slot = ordinary.clone();
        let callback_node = node.clone();
        let journal = unit.journal.clone();
        let pending = Arc::new(
            allocation
                .into_pending_runtime(&seat, journal, move |receipt| {
                    use busbar_kernel::refusal::RefusalMap;
                    callback_node.money_gate()?;
                    let unavailable = || {
                        busbar_kernel::refusal::CoreRefusals::new()
                            .for_core(route, busbar_plugin_abi::fail::refused::R_NO_ROUTE)
                    };
                    let request = callback_billing
                        .admit_existing_ordinary(
                            receipt.begin().map_err(|_| unavailable())?,
                            &callback_slot,
                            classes,
                            FeeRefund::PlaneFeeUnits(Arc::from([])),
                            busbar_kernel::config::groups::ExhaustionMode::FinishUnit,
                        )
                        .map_err(|error| match error {
                            NativeAdmissionError::Blocked(blocked) => {
                                crate::root::port_mount::blocked_client(&blocked).0
                            }
                            _ => unavailable(),
                        })?;
                    let rollback = callback_billing
                        .admission_rollback(&request)
                        .map_err(|_| unavailable())?;
                    AdmittedUnit::ordinary(request, unit, rollback).map_err(|_| unavailable())
                })
                .map_err(|_| InputError::Invalid)?,
        );
        native_node.bind_pending(pending.clone())?;
        let snapshot = pending.snapshot();
        let header_extent = snapshot
            .headers()
            .try_fold(0usize, |sum, (name, value)| {
                sum.checked_add(std::mem::size_of::<(String, Vec<u8>)>())?
                    .checked_add(name.len())?
                    .checked_add(value.len())
            })
            .ok_or(InputError::Capacity)?;
        let header_credit = snapshot
            .request()
            .storage()
            .try_reserve(header_extent)
            .map_err(|_| InputError::Capacity)?;
        // The DATA request's head is its charged snapshot, shared, not copied.
        let http = HttpIn::new(
            HttpHead::Snapshot(Arc::clone(snapshot)),
            snapshot.body_bytes(),
            binding.invocation().request_id().get(),
        );
        let lease = snapshot.request().clone();
        let now_s = snapshot.now_s();
        let (head_tx, mut head_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::channel(1);
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sink = Arc::new(Sink {
            source: lease.storage().clone(),
            state: Mutex::new(SinkState {
                head: Some(head_tx),
                body: Some(tokio_util::sync::PollSender::new(body_tx)),
                trailers: false,
            }),
            ended: ended.clone(),
        });
        let authority = pending.clone();
        let response_source = lease.storage().clone();
        let mut work = tokio::spawn(async move {
            let _header_credit = header_credit;
            let served = seat
                .driver
                .serve_admitted(
                    ServeIn {
                        request: lease,
                        admission: None,
                        invocation: None,
                        route,
                        http,
                        creds: Credentials {
                            bearer: None,
                            principal: Principal::Anonymous,
                            operator: false,
                            signed: None,
                        },
                        audience: seat.audience.as_deref().unwrap_or_default(),
                        now_s,
                        unit: None,
                        upstream: seat.upstream.clone(),
                        client: Some(sink.clone()),
                        carrier: seat.carrier.clone(),
                        intents: seat.intents.clone(),
                        models: Vec::new(),
                    },
                    authority,
                )
                .await;
            // Closing an unfinished producer reports a body error; Drop never manufactures END.
            let mut state = sink
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.head.take();
            state.body.take();
            served
        });
        // The listener retains this future until completion. On cancellation we close the
        // unpublished response receivers, then join the session's task before settling.
        // Dropping a JoinHandle cannot establish that an upstream effect stopped.
        let head = tokio::select! {
            biased;
            head = &mut head_rx => Some(head),
            () = binding.cancelled() => None,
            () = tokio::time::sleep_until(deadline.into()) => None,
        };
        let Some(head) = head else {
            drop(head_rx);
            drop(body_rx);
            let ran = work
                .await
                .ok()
                .and_then(Result::ok)
                .is_some_and(|served| matches!(served.into_parts().0, Served::Ran(_)));
            // No response was published: freeze the original terminal for the Node join.
            native_node.unregistered(ran, false)?;
            if let Some(admitted) = pending.admitted() {
                // Record the original intent; the Node-owned slot transfers the exact Open.
                ordinary
                    .request_terminal(&admitted.request, end_of(502, ran))
                    .map_err(|_| InputError::Invalid)?;
                let _ = billing.drive_ordinary_terminal(&ordinary);
            }
            return Err(InputError::Invalid);
        };
        let mut output_authority = None;
        let (response, status, ran, work, retirement) = match head {
            Ok((status, headers, credit)) => {
                let mut response = Response::new(Body::new(DataBody {
                    receiver: body_rx,
                    ended,
                    trailer_credit: None,
                    failed: false,
                }));
                let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
                *response.status_mut() = status;
                *response.headers_mut() = headers;
                response.extensions_mut().insert(credit);
                (response, status.as_u16(), false, Some(work), None)
            }
            Err(_) => {
                let result = (&mut work)
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .map(NativeServed::into_parts);
                match result {
                    Some((Served::Refused(refused), retirement)) => {
                        let response = refusal_response(refused.items, &response_source)?;
                        let status = response.status().as_u16();
                        let physical = retirement.refuse().map_err(|_| InputError::Invalid)?;
                        output_authority = Some(DataAuthority::Refused(physical));
                        (response, status, false, None, None)
                    }
                    result => {
                        let (ran, retirement) = match result {
                            Some((served, retirement)) => {
                                (matches!(served, Served::Ran(_)), Some(retirement))
                            }
                            None => (false, None),
                        };
                        let mut response = Response::new(Body::empty());
                        *response.status_mut() = StatusCode::BAD_GATEWAY;
                        (response, 502, ran, None, retirement)
                    }
                }
            }
        };
        if output_authority.is_none() && pending.execution().is_none() {
            return Err(InputError::Invalid);
        }
        Ok(DataResponse {
            response,
            authority: output_authority
                .unwrap_or_else(|| DataAuthority::Executing(pending.clone())),
            settlement: Some(DataSettlement {
                authority: pending,
                billing,
                work,
                retirement,
                ran,
                status,
                node: native_node.clone(),
                ordinary: ordinary.clone(),
            }),
        })
    }
    .await;
    result.map_err(|error| DataPrepareError::HeldNode {
        error,
        handle: native_node,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn source() -> StorageSource {
        busbar_kernel::limits::process_admission::ProcessAdmission::new(0)
            .connection_storage(busbar_kernel::limits::process_admission::AdmissionClass::Data)
    }

    #[tokio::test]
    async fn native_data_stream_retains_body_and_trailers_until_actual_end() {
        let (head_tx, head_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::channel(1);
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sink = Sink {
            source: source(),
            state: Mutex::new(SinkState {
                head: Some(head_tx),
                body: Some(tokio_util::sync::PollSender::new(body_tx)),
                trailers: false,
            }),
            ended: ended.clone(),
        };
        // The producer is a task on this same runtime: it waits for the body's one slot, it does not block.
        let producer = tokio::spawn(async move {
            let mut items = vec![
                ToClient::Head {
                    status: 200,
                    fields: Vec::new(),
                },
                ToClient::Body(b"payload".to_vec()),
                ToClient::Trailers(vec![(b"x-checksum".to_vec(), b"value".to_vec())]),
                ToClient::End,
            ];
            std::future::poll_fn(|cx| sink.poll_items(cx, &mut items)).await
        });
        assert_eq!(head_rx.await.unwrap().0, 200);
        let mut body = DataBody {
            receiver: body_rx,
            ended,
            trailer_credit: None,
            failed: false,
        };
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "payload"
        );
        let trailers = body
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_trailers()
            .unwrap();
        assert_eq!(trailers["x-checksum"], "value");
        assert!(body.frame().await.is_none());
        assert!(producer.await.unwrap());
    }

    #[tokio::test]
    async fn native_data_producer_drop_is_an_error_not_eof() {
        let (sender, receiver) = mpsc::channel(1);
        let mut body = DataBody {
            receiver,
            ended: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            trailer_credit: None,
            failed: false,
        };
        drop(sender);
        assert_eq!(
            body.frame().await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}
