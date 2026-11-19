// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The actual registration receipt, execution owner and final publication stay joined.

use std::sync::Arc;

use busbar_contract::response_delivery::{DeliverySnapshot, ResponseKey, ResponseStop};
use busbar_core_connector::framed_stream::session::{Feed, Payload, Piece, RegisterResponse};
use busbar_core_connector::hold::{Hold, Piece as HoldPiece};
use busbar_core_connector::response_delivery::{DeliveryInput, DeliveryWatch, ResponseHandles};
use busbar_kernel::auth::native_data::NativeDataPending;
use busbar_kernel::inbound::native::{
    PhysicalAdminExecution, PhysicalPublicExecution, PhysicalRefusal, RequestBinding, StreamOwner,
};
use busbar_kernel::plane_driver::request_admission::AdmittedRequest;
use busbar_plugin_abi::transport::{E_BODY, E_END, E_HEAD, E_TRAILERS, SH_END_STREAM};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use super::response::ResponsePieces;
use super::InputError;
use crate::root::durability::response_intent::{
    ResponseConnection, ResponseDisposition, ResponseFinalizer, ResponsePlan, ResponseRecord,
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
    /// A core route that requires a key, served to the caller the data chain verified.
    CoreKey(Arc<busbar_kernel::inbound::native::PhysicalKeyExecution>),
    /// A core keyed route refused: the one unverified answer, or the verifier's 503.
    CoreKeyRefused(busbar_kernel::inbound::native::PhysicalKeyRefusal),
    /// Refused at the gate (the gateway is full or draining): step 0, nothing judged.
    Gate(busbar_kernel::inbound::native::PhysicalGateRefusal),
    Refused(PhysicalRefusal),
}
impl ResponseAuthority {
    fn binding(&self) -> &Arc<RequestBinding> {
        match self {
            Self::Data(owner) => owner.binding(),
            Self::Admin(owner) => owner.binding(),
            Self::Public(owner) => owner.binding(),
            Self::Unbilled(owner) => owner.binding(),
            Self::CoreKey(owner) => owner.binding(),
            Self::CoreKeyRefused(owner) => owner.binding(),
            Self::Gate(owner) => owner.binding(),
            Self::Refused(owner) => owner.binding(),
        }
    }
    /// WHAT THIS RESPONSE RECORDS (design 2, A5, A7): a health check or public answer nothing; an
    /// administrative answer nothing here (its admin unit records it); a refusal with no unit one
    /// count on its core; a metered answer nothing on its path, its unit's line following after
    /// delivery, unless `advanced.wait_for_commit` makes it hand a line over and wait for it.
    fn record(
        &self,
        node: &Node,
        admission: Option<&AdmittedRequest>,
    ) -> Result<ResponseRecord, InputError> {
        Ok(match (self, admission) {
            (Self::Refused(owner), _) => match owner.counted() {
                Some((step, reason)) => ResponseRecord::Counted {
                    listener: owner.binding().slot().into(),
                    step,
                    reason,
                },
                None => ResponseRecord::Nothing,
            },
            // The flag is a field of the generation this request was admitted under.
            (Self::Data(owner), Some(admission)) if owner.binding().app().wait_for_commit() => {
                ResponseRecord::Committed(Box::new(
                    node.response_line(admission)
                        .map_err(|_| InputError::Capacity)?,
                ))
            }
            _ => ResponseRecord::Nothing,
        })
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
            | Self::CoreKey(_)
            | Self::CoreKeyRefused(_)
            | Self::Gate(_)
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
    /// THE ONE DECISION "this answer waits for its record", made once at registration: the answer
    /// records a line whose commit its release awaits ([`ResponseRecord::Committed`], which only
    /// `advanced.wait_for_commit` on a metered answer produces). The finalizer waits for that
    /// commit and the hold withholds the answer's last piece until it returns; both follow this
    /// one fact, so neither can wait while the other does not.
    waits_for_record: bool,
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
        node: &Node,
    ) -> Result<Self, InputError> {
        let binding = authority.binding();
        if !binding.owns_stream(&owner) {
            return Err(InputError::Delivery(ResponseStop::Integrity));
        }
        let admission = authority.admission()?;
        let record = authority.record(node, admission.as_ref())?;
        let waits_for_record = matches!(record, ResponseRecord::Committed(_));
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
            .admit(key, handles, deadline, record)
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
            waits_for_record,
        })
    }

    /// Own this future in the connection's supervisor. Dropping a request waiter must not detach
    /// the response's journal operation, body producer or physical execution owner.
    pub(super) async fn send_http(
        self,
        response: axum::response::Response,
        feeds: &mpsc::Sender<Feed>,
    ) -> CompletedResponse {
        let Self {
            delivery,
            plan,
            finalizer,
            authority,
            owner,
            deadline,
            retirement,
            waits_for_record,
        } = self;
        let binding = authority.binding().clone();
        let input = finalizer.input();
        let source = binding.request().storage();
        let (send, pieces) = mpsc::channel(1);
        // The body length the answer's head states exactly, if it states one: a caller knows such an answer
        // is complete at its last byte, so that byte is what a held answer withholds.
        let stated_len = response
            .headers()
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
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
            // THE HOLD IS THE ENGINE'S. When an answer must wait for its record (`advanced.wait_for_commit`
            // on a metered answer: the decision registration made, `waits_for_record`), the piece that
            // completes it is not given to the transport until the record is in: the end; the trailers
            // with it; the body piece that reaches a length the head stated; a head that is the whole
            // answer. An answer that records no line has nothing to wait for and withholds nothing,
            // whatever the setting; with the setting off the path is exactly the unheld one. Nothing is
            // parked in the connection's byte pipe, so other answers on it keep flowing.
            let mut hold = Hold::new(waits_for_record);
            let mut withheld: Vec<Piece> = Vec::new();
            while let Some(piece) = response.next().await? {
                let completes = match piece.piece {
                    E_HEAD => {
                        plan.record_head(Some(response.status()))
                            .map_err(InputError::FinalIntent)?;
                        hold.withholds(HoldPiece::Head {
                            ends: piece.arg & SH_END_STREAM != 0,
                            stated_len,
                        })
                    }
                    E_BODY => {
                        plan.record_body().map_err(InputError::FinalIntent)?;
                        hold.withholds(HoldPiece::Body(piece.bytes.as_slice().len() as u64))
                    }
                    E_TRAILERS => {
                        plan.record_trailers().map_err(InputError::FinalIntent)?;
                        hold.withholds(HoldPiece::Trailers)
                    }
                    _ => return Err(InputError::Delivery(ResponseStop::Integrity)),
                };
                if completes {
                    withheld.push(piece);
                    continue;
                }
                send.send(piece)
                    .await
                    .map_err(|_| InputError::Delivery(ResponseStop::CarrierRetired))?;
            }
            if !response.eof() {
                return Err(InputError::Delivery(ResponseStop::Integrity));
            }
            input.reader_eof();
            let intent = plan
                .freeze(ResponseDisposition::End {
                    status: Some(response.status()),
                })
                .map_err(InputError::FinalIntent)?;
            // Release waits for a commit only under `advanced.wait_for_commit`; then the completing
            // piece is withheld until it has. Neither path bypasses prior body pieces, and both stay
            // owned by this supervisor until they finish.
            let waits = hold.withholds(HoldPiece::End);
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
                // What was withheld goes first, in the order it was withheld, then the end.
                for piece in withheld {
                    if send.send(piece).await.is_err() {
                        finalizer.cancel().cancel(ResponseStop::Cancelled);
                        return Err(InputError::Delivery(ResponseStop::CarrierRetired));
                    }
                }
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
            if waits {
                // The record first; only then does the transport get the piece that completes the answer.
                // A record that is refused ends the answer without its end: the caller sees it cut.
                confirm.await?;
                hold.committed();
                end.await
            } else {
                // Nothing waits: the end goes at once and the record is confirmed beside it.
                let (confirmed, ended) = tokio::join!(confirm, end);
                confirmed?;
                ended
            }
        };
        // The request's deadline (`limits.request_timeout`) bounds the WHOLE answer, an upgraded
        // one included: a WebSocket session is closed (1000) when it passes. The owner decided an
        // upgraded session is bounded by its plane's ceiling, not by this; it stays until the
        // request's effect gate (`NativeDataEffectGate`, `Phase::Executing`) follows the same
        // bound, else a session would be relayed past the time its usage can be stated
        // (ENGINE-OPEN-3).
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
