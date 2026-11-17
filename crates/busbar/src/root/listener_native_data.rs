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
use busbar_kernel::inbound::native::{CompletingPhysicalRequest, RouteTarget};
use busbar_kernel::plane_driver::port::{HttpIn, ServeIn, Served};
use busbar_kernel::plane_driver::port_admission::AdmittedUnit;
use busbar_kernel::plane_driver::port_auth::{Credentials, Principal};
use busbar_kernel::plane_driver::port_billing::{end_of, PortBilling};
use busbar_kernel::plane_driver::port_session::{ClientSink, ToClient};
use busbar_kernel::plane_driver::{FeeRefund, HeadFields, NativeAdmissionError};
use busbar_kernel::resource_admission::FrozenRequest;
use bytes::Bytes;
use http_body::Frame;
use tokio::sync::{mpsc, oneshot};

use super::{InputError, RegisteredDelivery};
use crate::root::min3_physical::NativeSlot;
use crate::root::plane_node::Node;

pub(super) struct DataResponse {
    pub(super) response: Response,
    pub(super) authority: Arc<NativeDataPending>,
    pub(super) settlement: DataSettlement,
}

pub(super) struct DataSettlement {
    authority: Arc<NativeDataPending>,
    billing: PortBilling,
    work: Option<tokio::task::JoinHandle<bool>>,
    ran: bool,
    status: u16,
}

impl DataSettlement {
    /// Registration never exposed a response feed. The caller first drops the unpublished
    /// body so its blocked producer can stop, then retains this join through actual retirement.
    pub(super) async fn registration_failed(mut self) -> Result<(), InputError> {
        let failed = if let Some(work) = self.work.take() {
            match work.await {
                Ok(ran) => {
                    self.ran = ran;
                    false
                }
                Err(_) => {
                    self.ran = false;
                    true
                }
            }
        } else {
            false
        };
        let admitted = self.authority.admitted().ok_or(InputError::Invalid)?;
        if admitted.selected.is_some() {
            return Err(InputError::Invalid);
        }
        let mut end = end_of(502, self.ran);
        end.cut = true;
        self.billing
            .settle_admitted(&admitted.request, end)
            .map_err(|_| InputError::Invalid)?;
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
                Ok(ran) => {
                    self.ran = ran;
                    false
                }
                Err(_) => {
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
        let mut end = end_of(u32::from(self.status), self.ran);
        end.cut = matches!(snapshot.terminal, Some(DeliveryTerminal::Failed(_)));
        // This first cohort uses the adopted ordinary DATA callback. Selected activation
        // requires its finite route ceiling and actual Node audit admission producer.
        if admitted.selected.is_some() {
            return Err(InputError::Invalid);
        }
        self.billing
            .settle_admitted(original, end)
            .map_err(|_| InputError::Invalid)?;
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
    body: Option<mpsc::Sender<BodyItem>>,
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

impl ClientSink for Sink {
    fn items(&self, items: Vec<ToClient>) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for item in items {
            let result = (|| -> Result<(), ()> {
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
                        if state.head.is_some() || state.trailers {
                            return Err(());
                        }
                        let credit = self.source.try_reserve(bytes.capacity()).map_err(|_| ())?;
                        let bytes = Bytes::from_owner(ChargedBytes {
                            bytes,
                            _credit: credit,
                        });
                        state
                            .body
                            .as_ref()
                            .ok_or(())?
                            .blocking_send(BodyItem {
                                frame: Frame::data(bytes),
                                trailers: None,
                            })
                            .map_err(|_| ())?;
                    }
                    ToClient::Trailers(values) => {
                        if state.head.is_some() || state.trailers {
                            return Err(());
                        }
                        let (headers, credit) = fields(&self.source, values)?;
                        state.trailers = true;
                        state
                            .body
                            .as_ref()
                            .ok_or(())?
                            .blocking_send(BodyItem {
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
            })();
            if result.is_err() {
                state.body.take();
                return false;
            }
        }
        true
    }
}

pub(super) async fn prepare(
    request: CompletingPhysicalRequest,
    slot: Arc<NativeSlot>,
    node: Arc<Node>,
) -> Result<DataResponse, InputError> {
    let binding = request.binding().clone();
    let routes = binding
        .prepared()
        .data()
        .ok_or(InputError::Invalid)?
        .downcast::<crate::root::serve::DataRoutes>()
        .map_err(|_| InputError::Invalid)?;
    if !Arc::ptr_eq(routes.post.node(), &node) {
        return Err(InputError::Invalid);
    }
    let RouteTarget::Plane(target) = binding.route().target() else {
        return Err(InputError::Invalid);
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
    let original = binding.snapshot().map_err(|_| InputError::Capacity)?;
    let frozen = FrozenRequest::from_snapshot(binding.invocation(), route, original);
    let port = seat.driver.port();
    let (frozen, selection) = tokio::task::spawn_blocking(move || {
        let selection = frozen.with_selection_input(|input, body| {
            port.resource_facts(
                busbar_plugin_abi::plane::RESOURCE_SELECT,
                input,
                body,
                busbar_plugin_abi::resource_admission::MAX_SELECTION_BYTES,
            )
        });
        (frozen, selection)
    })
    .await
    .map_err(|_| InputError::Invalid)?;
    let selection = selection
        .map_err(|_| InputError::Invalid)?
        .map_err(|_| InputError::Invalid)?;
    let selected = data_route
        .inventory()
        .select_wire(frozen, target.mounted(), &selection)
        .map_err(|_| InputError::Invalid)?;
    let deadline = binding.deadline().ok_or(InputError::Invalid)?;
    let authorized = data_route
        .prepare(
            request,
            selected,
            busbar_ports::CallCx {
                deadline,
                request_id: binding.invocation().request_id().get(),
                stack: Default::default(),
            },
        )
        .await
        .map_err(|_| InputError::Invalid)?
        .complete()
        .await
        .map_err(|_| InputError::Invalid)?;
    let allocation = NativeDataAllocation::register(authorized).map_err(|_| InputError::Invalid)?;
    let classes = seat.driver.usage_classes();
    let unit = billing
        .allocated_data(&allocation, classes.clone())
        .map_err(|_| InputError::Invalid)?;
    let callback_billing = billing.clone();
    let journal = unit.journal.clone();
    let pending = Arc::new(
        allocation
            .into_pending_runtime(&seat, journal, move |receipt| {
                use busbar_kernel::refusal::RefusalMap;
                let unavailable = || {
                    busbar_kernel::refusal::CoreRefusals::new()
                        .for_core(route, busbar_plugin_abi::fail::refused::R_NO_ROUTE)
                };
                let request = callback_billing
                    .admit_existing(
                        receipt.begin().map_err(|_| unavailable())?,
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
    let http = HttpIn {
        method: snapshot.method().to_owned(),
        path: snapshot.path().to_owned(),
        query: snapshot.query().to_owned(),
        headers: snapshot
            .headers()
            .map(|(name, value)| (name.to_owned(), value.to_vec()))
            .collect(),
        body: snapshot.body_bytes(),
        request_id: binding.invocation().request_id().get(),
    };
    let lease = snapshot.request().clone();
    let now_s = snapshot.now_s();
    let (head_tx, mut head_rx) = oneshot::channel();
    let (body_tx, body_rx) = mpsc::channel(1);
    let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sink = Arc::new(Sink {
        source: lease.storage().clone(),
        state: Mutex::new(SinkState {
            head: Some(head_tx),
            body: Some(body_tx),
            trailers: false,
        }),
        ended: ended.clone(),
    });
    let authority = pending.clone();
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
                    principal: None,
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
        let ran = matches!(served, Ok(Served::Ran(_)));
        // Closing an unfinished producer reports a body error; Drop never manufactures END.
        let mut state = sink
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.head.take();
        state.body.take();
        ran
    });
    // The listener retains this future until completion. On cancellation we close the
    // unpublished response receivers, then join the actual blocking Task before settling.
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
        let ran = work.await.unwrap_or(false);
        if let Some(admitted) = pending.admitted() {
            billing
                .settle_admitted(&admitted.request, end_of(502, ran))
                .map_err(|_| InputError::Invalid)?;
        }
        return Err(InputError::Invalid);
    };
    let (response, status, ran, work) = match head {
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
            (response, status.as_u16(), false, Some(work))
        }
        Err(_) => {
            let ran = (&mut work).await.unwrap_or(false);
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::BAD_GATEWAY;
            (response, 502, ran, None)
        }
    };
    if pending.execution().is_none() {
        return Err(InputError::Invalid);
    }
    Ok(DataResponse {
        response,
        authority: pending.clone(),
        settlement: DataSettlement {
            authority: pending,
            billing,
            work,
            ran,
            status,
        },
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
                body: Some(body_tx),
                trailers: false,
            }),
            ended: ended.clone(),
        };
        let producer = tokio::task::spawn_blocking(move || {
            sink.items(vec![
                ToClient::Head {
                    status: 200,
                    fields: Vec::new(),
                },
                ToClient::Body(b"payload".to_vec()),
                ToClient::Trailers(vec![(b"x-checksum".to_vec(), b"value".to_vec())]),
                ToClient::End,
            ])
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
