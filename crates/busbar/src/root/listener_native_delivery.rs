// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The actual registration receipt, execution owner and final publication stay joined.

use std::sync::Arc;

use busbar_contract::response_delivery::{DeliverySnapshot, ResponseKey, ResponseStop};
use busbar_core_connector::framed_stream::session::{Feed, Payload, Piece, RegisterResponse};
use busbar_core_connector::response_delivery::{DeliveryInput, DeliveryWatch, ResponseHandles};
use busbar_kernel::auth::native_data::NativeDataPending;
use busbar_kernel::inbound::native::{
    PhysicalAdminExecution, PhysicalPublicExecution, PhysicalRefusal, RequestBinding, StreamOwner,
};
use busbar_kernel::plane_driver::request_admission::AdmittedRequest;
use busbar_plugin_abi::transport::{E_BODY, E_END, E_HEAD, E_TRAILERS};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use super::response::ResponsePieces;
use super::InputError;
use crate::root::durability::response_intent::{
    ResponseConnection, ResponseDisposition, ResponseFinalizer, ResponsePlan,
};
use crate::root::plane_node::Node;

/// Root chooses the explicit response class; a missing DATA execution can never become None-unit.
pub(super) enum ResponseAuthority {
    Data(Arc<NativeDataPending>),
    Admin(Arc<PhysicalAdminExecution>),
    Public(Arc<PhysicalPublicExecution>),
    /// A plane route answered with no unit: verified and not billed, or admitted with nobody to
    /// verify (`busbar_kernel::inbound::native::PhysicalUnbilledExecution`).
    Unbilled(Arc<busbar_kernel::inbound::native::PhysicalUnbilledExecution>),
    /// An upgrade request handed over: the 101, or the plane's own answer before one.
    Upgrade(Arc<busbar_kernel::inbound::native::PhysicalUpgrade>),
    Refused(PhysicalRefusal),
}
impl ResponseAuthority {
    fn binding(&self) -> &Arc<RequestBinding> {
        match self {
            Self::Data(owner) => owner.binding(),
            Self::Admin(owner) => owner.binding(),
            Self::Public(owner) => owner.binding(),
            Self::Unbilled(owner) => owner.binding(),
            Self::Upgrade(owner) => owner.binding(),
            Self::Refused(owner) => owner.binding(),
        }
    }
    fn admission(&self) -> Result<Option<AdmittedRequest>, InputError> {
        match self {
            Self::Data(owner) => owner
                .execution()
                .map(|execution| Some(execution.money().clone()))
                .ok_or(InputError::Delivery(ResponseStop::Integrity)),
            Self::Admin(_)
            | Self::Public(_)
            | Self::Unbilled(_)
            | Self::Upgrade(_)
            | Self::Refused(_) => Ok(None),
        }
    }
}

/// A single loan source for terminal billing. Construction is private to the actual response ACK
/// path below; callers cannot combine an expected numeric key with an unrelated reader/admission.
pub(crate) struct RegisteredDelivery {
    key: ResponseKey,
    watch: DeliveryWatch,
    admission: Option<AdmittedRequest>,
}
impl RegisteredDelivery {
    pub(crate) fn key(&self) -> ResponseKey {
        self.key
    }
    pub(crate) fn reader(&self) -> &DeliveryWatch {
        &self.watch
    }
    pub(crate) fn admission(&self) -> Option<&AdmittedRequest> {
        self.admission.as_ref()
    }
}

pub(super) struct RegisteredResponse {
    delivery: RegisteredDelivery,
    plan: ResponsePlan,
    finalizer: Arc<ResponseFinalizer>,
    authority: ResponseAuthority,
    owner: Arc<StreamOwner>,
    deadline: Instant,
    retirement: RetireInput,
}

struct RegistrationAck {
    receiver: oneshot::Receiver<Result<ResponseHandles, ResponseStop>>,
}
impl Drop for RegistrationAck {
    fn drop(&mut self) {
        // Close before draining: a concurrent successful send can no longer race between a
        // failed try_recv and receiver drop, abandoning a live response without its handles.
        self.receiver.close();
        if let Ok(Ok(handles)) = self.receiver.try_recv() {
            handles.cancel.cancel(ResponseStop::Cancelled);
            handles.input.retired();
        }
    }
}
struct RetireInput(DeliveryInput);
impl Drop for RetireInput {
    fn drop(&mut self) {
        self.0.retired();
    }
}

/// Returned even for stopped output: settlement still needs the original admission and physical
/// owners. The connection retires its matching input slot only after consuming this completion.
pub(super) struct CompletedResponse {
    pub(super) delivery: RegisteredDelivery,
    pub(super) snapshot: DeliverySnapshot,
    pub(super) owner: Arc<StreamOwner>,
    pub(super) result: Result<(), InputError>,
    _authority: ResponseAuthority,
    _finalizer: Arc<ResponseFinalizer>,
    _retirement: RetireInput,
}

impl RegisteredResponse {
    /// Called in original host-head order, before exposing any response piece or finalizer.
    pub(super) async fn register(
        connection: &ResponseConnection,
        registrations: &mpsc::Sender<RegisterResponse>,
        authority: ResponseAuthority,
        owner: Arc<StreamOwner>,
        deadline: Instant,
    ) -> Result<Self, InputError> {
        let binding = authority.binding();
        if !binding.owns_stream(&owner) {
            return Err(InputError::Delivery(ResponseStop::Integrity));
        }
        let admission = authority.admission()?;
        let unit = match &authority {
            ResponseAuthority::Refused(owner) => owner.unit(),
            _ => admission.as_ref().map(AdmittedRequest::unit),
        };
        let key = connection
            .key(binding.stream(), unit)
            .map_err(InputError::FinalIntent)?;
        let (ack, admitted) = oneshot::channel();
        let mut admitted = RegistrationAck { receiver: admitted };
        tokio::time::timeout_at(
            deadline,
            registrations.send(RegisterResponse { key, admitted: ack }),
        )
        .await
        .map_err(|_| InputError::Delivery(ResponseStop::Deadline))?
        .map_err(|_| InputError::Delivery(ResponseStop::CarrierRetired))?;
        let handles = tokio::time::timeout_at(deadline, &mut admitted.receiver)
            .await
            .map_err(|_| InputError::Delivery(ResponseStop::Deadline))?
            .map_err(|_| InputError::Delivery(ResponseStop::CarrierRetired))?
            .map_err(InputError::Delivery)?;
        // ResponseConnection verifies original journal node/incarnation/generation and the ACK's
        // complete private-cell key. No independent expected-key parameter is exposed to billing.
        let (plan, finalizer) = connection
            .admit(key, handles, deadline)
            .map_err(InputError::FinalIntent)?;
        // The finalizer's admitted scope must be the very key this request registered.
        if finalizer.key() != key {
            return Err(InputError::Delivery(ResponseStop::Integrity));
        }
        let watch = finalizer.watch();
        let retirement = RetireInput(finalizer.input());
        Ok(Self {
            delivery: RegisteredDelivery {
                key,
                watch,
                admission,
            },
            plan,
            finalizer,
            authority,
            owner,
            deadline,
            retirement,
        })
    }

    /// Own this future in the connection's supervisor. Dropping a request waiter must not detach
    /// the response's journal operation, body producer or physical execution owner.
    pub(super) async fn send_http(
        self,
        response: axum::response::Response,
        feeds: &mpsc::Sender<Feed>,
        node: &Node,
    ) -> CompletedResponse {
        let Self {
            delivery,
            plan,
            finalizer,
            authority,
            owner,
            deadline,
            retirement,
        } = self;
        let binding = authority.binding().clone();
        let input = finalizer.input();
        let source = binding.request().storage();
        let (send, pieces) = mpsc::channel(1);
        let run = async {
            let mut response = ResponsePieces::new(response, source.clone())?;
            if let Some(admin) = response.take_admin() {
                if !Arc::ptr_eq(admin.binding(), &binding) {
                    return Err(InputError::Delivery(ResponseStop::Integrity));
                }
                // This must be the same final execution already retained by registration.
                if !matches!(&authority, ResponseAuthority::Admin(original) if Arc::ptr_eq(original, &admin))
                {
                    return Err(InputError::Delivery(ResponseStop::Integrity));
                }
            }
            feeds
                .send(Feed {
                    stream: delivery.key.stream,
                    pieces,
                    opened: None,
                })
                .await
                .map_err(|_| InputError::Delivery(ResponseStop::CarrierRetired))?;
            let mut plan = plan;
            while let Some(piece) = response.next().await? {
                match piece.piece {
                    E_HEAD => plan.record_head(Some(response.status())),
                    E_BODY => plan.record_body(),
                    E_TRAILERS => plan.record_trailers(),
                    _ => return Err(InputError::Delivery(ResponseStop::Integrity)),
                }
                .map_err(InputError::FinalIntent)?;
                send.send(piece)
                    .await
                    .map_err(|_| InputError::Delivery(ResponseStop::CarrierRetired))?;
            }
            if !response.eof() {
                return Err(InputError::Delivery(ResponseStop::Integrity));
            }
            input.reader_eof();
            let stamp = node
                .response_intent_stamp(finalizer.journal())
                .map_err(|_| InputError::Delivery(ResponseStop::Integrity))?;
            let intent = plan
                .freeze(
                    ResponseDisposition::End {
                        status: Some(response.status()),
                    },
                    stamp,
                )
                .map_err(InputError::FinalIntent)?;
            // Confirmation runs while E_END is blocked behind held output. Neither path bypasses
            // prior body pieces, and both stay owned by this supervisor until they finish.
            let confirm = async {
                let result = finalizer
                    .finalize(intent)
                    .await
                    .map(|_| ())
                    .map_err(InputError::FinalIntent);
                if result.is_err() {
                    finalizer.cancel().cancel(ResponseStop::Cancelled);
                }
                result
            };
            let end = async {
                let bytes = Payload::copy(&source, &[]).map_err(|_| InputError::Capacity)?;
                let result = send
                    .send(Piece {
                        piece: E_END,
                        arg: 0,
                        bytes,
                    })
                    .await
                    .map_err(|_| InputError::Delivery(ResponseStop::CarrierRetired));
                if result.is_ok() {
                    input.producer_ended();
                } else {
                    finalizer.cancel().cancel(ResponseStop::Cancelled);
                }
                result
            };
            let (confirmed, ended) = tokio::join!(confirm, end);
            confirmed?;
            ended
        };
        let result = tokio::select! {
            result = run => result,
            _ = binding.cancelled() => Err(InputError::Delivery(ResponseStop::Cancelled)),
            _ = tokio::time::sleep_until(deadline) => Err(InputError::Delivery(ResponseStop::Deadline)),
        };
        // The selected branch has dropped/joined this sole reader and piece producer; no Drop is
        // reported as successful EOF. A stopped producer uses the separate retired observation.
        drop(send);
        if result.is_err() {
            finalizer.cancel().cancel(ResponseStop::Cancelled);
            input.retired();
        }
        let snapshot = delivery.watch.terminal().await;
        CompletedResponse {
            delivery,
            snapshot,
            owner,
            result,
            _authority: authority,
            _finalizer: finalizer,
            _retirement: retirement,
        }
    }
}

#[cfg(test)]
#[path = "tests/listener_native_delivery.rs"]
mod tests;
