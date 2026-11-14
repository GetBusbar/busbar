// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Governed dispatch from a sealed transport admission to opaque plane frames.

use super::*;
use busbar_core_connector::framed_stream::FramedStream;
use busbar_kernel::auth::AdmittedContext;
use busbar_kernel::inbound::RequestAdmission;
use busbar_kernel::plane_routes::{FramedSession, SessionPipe};

pub(crate) trait Output: SessionCaller + Stated + Send + Sync + 'static {
    fn trailers(&self, fields: HeadFields);
    /// A complete response with no body or later trailers.
    fn complete_head(&self, status: u32, fields: HeadFields) {
        self.head(status, fields);
    }
    fn write_owned(&self, bytes: Bytes) -> impl std::future::Future<Output = bool> + Send {
        async move { self.write(&bytes).await }
    }
}

pub(super) struct Whole {
    pub(super) status: u32,
    pub(super) fields: HeadFields,
    pub(super) body: Bytes,
}
impl Whole {
    pub(super) fn failed() -> Self {
        Self {
            status: refusal_status(ReasonCode::PlanePanic),
            fields: Vec::new(),
            body: Bytes::new(),
        }
    }
}
impl From<Rendered> for Whole {
    fn from(rendered: Rendered) -> Self {
        Self {
            status: rendered.status,
            fields: rendered.fields,
            body: Bytes::from(rendered.body),
        }
    }
}

impl DataRoutes {
    pub(super) fn inbound_audit_kind(&self, line: u32) -> OpClassId {
        self.guests
            .lines()
            .get(line as usize)
            .and_then(|line| {
                let busbar_kernel::guest::Claimant::Plane(instance) = &line.claimant else {
                    return None;
                };
                let (plane, _) = self.of_line.get(&(instance.clone(), line.route.rung))?;
                Some(self.live[*plane].facts.audit_kind)
            })
            .unwrap_or(OpClassId::new("inbound"))
    }

    fn admitted_claim(&self, admission: &RequestAdmission) -> Option<DoorClaim> {
        let line = admission.selected_line();
        let busbar_kernel::guest::Claimant::Plane(instance) = &line.claimant else {
            return None;
        };
        // Verify membership in this pinned dispatcher without rematching the caller's path.
        self.guests
            .lines()
            .iter()
            .any(|candidate| candidate == line)
            .then_some(())?;
        self.of_line
            .get(&(instance.clone(), line.route.rung))
            .copied()
    }

    pub(crate) fn refusal(
        &self,
        admission: &RequestAdmission,
        reason: ReasonCode,
    ) -> Option<Rendered> {
        admission.refuse(busbar_contract::caps::StepName::Decode, reason);
        let (plane, _) = self.admitted_claim(admission)?;
        let head = admission.head();
        let target = target_of(head);
        Some(self.served.planes[plane].driver.refuse_unitless(
            reason,
            admission.selected_line().dialect,
            &target,
        ))
    }

    /// Render the physical arrival cap through the already sealed claimant. This does not
    /// start execution, read a body, or rematch the request against another plane.
    pub(crate) fn capacity_refusal(&self, admission: &RequestAdmission) -> Option<Rendered> {
        let (plane, _) = self.admitted_claim(admission)?;
        self.served.planes[plane].driver.refuse_kernel(
            ReasonCode::InFlightCap,
            503,
            "The gateway is at capacity. Please retry shortly.",
            admission.selected_line().dialect,
            &target_of(admission.head()),
        )
    }

    pub(crate) fn auth_completion(&self, admission: &RequestAdmission, status: u32) {
        if let Some((plane, _)) = self.admitted_claim(admission) {
            self.auth_completion_for(
                &admission.app(),
                plane,
                admission.selected_line().dialect,
                status,
            );
        }
    }

    fn auth_completion_for(
        &self,
        app: &Arc<busbar_kernel::state::App>,
        plane: usize,
        dialect: u32,
        status: u32,
    ) {
        if let Some(dialect) = self.served.planes[plane].dialects.get(dialect as usize) {
            // The legacy tap projection has a 16-bit optional status. Do not discard the
            // completion or truncate an opaque 32-bit producer code to fit that projection.
            busbar_kernel::auth::auth_completion_taps(app, dialect, u16::try_from(status).ok());
        }
    }

    /// Render a pre-admission refusal through the exact sealed claimant, without a path rematch.
    pub fn refuse_line(
        &self,
        app: &Arc<busbar_kernel::state::App>,
        refusal: &busbar_kernel::plane_routes::KernelRefusal<'_>,
    ) -> Option<Rendered> {
        let line = refusal.selected_line?;
        if !self
            .guests
            .lines()
            .iter()
            .any(|candidate| candidate == line)
        {
            return None;
        }
        let busbar_kernel::guest::Claimant::Plane(instance) = &line.claimant else {
            return None;
        };
        let (plane, _) = *self.of_line.get(&(instance.clone(), line.route.rung))?;
        if refusal.reason == ReasonCode::Unauthenticated {
            self.auth_completion_for(app, plane, line.dialect, u32::from(refusal.status));
            return Some(self.served.planes[plane].driver.refuse_unitless(
                refusal.reason,
                line.dialect,
                refusal.target.as_bytes(),
            ));
        }
        self.served.planes[plane].driver.refuse_kernel(
            refusal.reason,
            u32::from(refusal.status),
            refusal.text,
            line.dialect,
            refusal.target.as_bytes(),
        )
    }

    fn neutral_arrival(
        &self,
        plane: usize,
        claim: u32,
        context: AdmittedContext,
        body: Bytes,
    ) -> (SessionDoor, Arrival) {
        let AdmittedContext {
            app,
            mut head,
            gov,
            consumed,
            ..
        } = context;
        // The served head is this request's own copy: its fields move into the arrival rather
        // than being copied again (SINGLE-PATH SP-A2). A field the arrival does not keep is wiped
        // here, as the head's own drop would have wiped it.
        let target = target_of(&head);
        let arrival = Arrival {
            claim,
            method: std::mem::take(&mut head.method).into_bytes(),
            target,
            fields: std::mem::take(&mut head.fields)
                .into_iter()
                .filter_map(|(name, mut value)| {
                    if keep_arrival_field(name.as_bytes()) {
                        Some((name.into_bytes(), value))
                    } else {
                        zeroize::Zeroize::zeroize(&mut value);
                        None
                    }
                })
                .collect(),
            body,
        };
        let principal = match gov.key() {
            Some(key) => PrincipalId::new(key.id.as_str()),
            None => PrincipalId::new(AuthPrincipal(None).actor_id()),
        };
        let pools_plane = self.served.planes[plane].live.served_facts.section
            == busbar_contract::section::RESERVED_POOLS_KEY;
        let open = (pools_plane && app.auth.is_open())
            || self.served.planes[plane]
                .snapshot
                .claims
                .get(claim as usize)
                .is_some_and(|claim| claim.flags & CLAIM_OPEN != 0);
        let door = SessionDoor {
            admission: None,
            plane,
            app,
            principal,
            key: gov.key.clone(),
            open,
            credential: consumed
                .caller
                .as_ref()
                .map(busbar_kernel::auth::CallerCredential::lend),
            ticket: consumed.ticket,
            host_ticket_admission: consumed.host_ticket_admission,
        };
        (door, arrival)
    }

    async fn complete_unmetered<C: Output>(
        &self,
        plane: usize,
        admission: &RequestAdmission,
        context: &AdmittedContext,
        caller: &C,
        rendered: Rendered,
    ) {
        if rendered.body.is_empty() {
            caller.complete_head(rendered.status, rendered.fields);
        } else {
            caller.head(rendered.status, rendered.fields);
        }
        if !rendered.body.is_empty() && !caller.write(&rendered.body).await {
            admission.refuse(
                busbar_contract::caps::StepName::Encode,
                ReasonCode::ClientGone,
            );
            return;
        }
        if admission.begin_execution() {
            let principal = context.gov.key().map_or_else(
                || PrincipalId::new(AuthPrincipal(None).actor_id()),
                |key| PrincipalId::new(key.id.as_str()),
            );
            self.post.node().unmetered_inbound(
                admission.unit_key(),
                self.live[plane].facts.audit_kind,
                &principal,
                busbar_contract::caps::Outcome::Completed,
            );
        }
    }

    /// The same teller driver, money seam, hooks and NodeEndPost as the compatibility adapter.
    /// The admitted line selects the handler; no URL or method is parsed as HTTP here.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn serve_admitted<C: Output>(
        self: Arc<Self>,
        admission: &RequestAdmission,
        context: AdmittedContext,
        body: Bytes,
        scheme: u8,
        slot: FramedSession,
        caller: Arc<C>,
    ) -> Option<SessionPipe> {
        let (plane, claim) = self.admitted_claim(admission)?;
        use tracing::Instrument as _;
        let field = |name: &str| {
            context
                .head
                .fields
                .iter()
                .find(|(field, _)| field.eq_ignore_ascii_case(name))
                .and_then(|(_, value)| std::str::from_utf8(value).ok())
                .or_else(|| {
                    context
                        .consumed_fields
                        .iter()
                        .find(|(field, _)| field == name)
                        .map(|(_, scheme)| scheme.as_str())
                })
        };
        let span =
            self.entries[plane].open(claim, &context.head.method, &context.head.target, field);
        self.serve_admitted_inner(
            admission,
            (plane, claim),
            context,
            body,
            scheme,
            slot,
            caller,
        )
        .instrument(span)
        .await
    }

    /// The same teller driver, money seam, hooks and NodeEndPost as the compatibility adapter.
    /// The admitted line selects the handler; no URL or method is parsed as HTTP here.
    #[allow(clippy::too_many_arguments)]
    async fn serve_admitted_inner<C: Output>(
        self: Arc<Self>,
        admission: &RequestAdmission,
        // `serve_admitted`'s claim of the selected line, looked up once (SINGLE-PATH SP-A1).
        (plane, claim): DoorClaim,
        context: AdmittedContext,
        body: Bytes,
        scheme: u8,
        slot: FramedSession,
        caller: Arc<C>,
    ) -> Option<SessionPipe> {
        if let Some(document) = resource_documents(&self.served).get(&(plane, claim)) {
            let rendered = busbar_kernel::ingress::protocol::metadata_rendered(
                &busbar_kernel::ingress::protocol::Metadata {
                    resource: std::borrow::Cow::Borrowed(&document.resource),
                    authorization_servers: &document.authorization_servers,
                    scopes_supported: &document.scopes_supported,
                },
            );
            self.complete_unmetered(plane, admission, &context, &*caller, rendered)
                .await;
            return None;
        }
        let catalog = self.served.planes[plane]
            .snapshot
            .claims
            .get(claim as usize)
            .is_some_and(|claim| claim.flags & busbar_contract::abi::plane::CLAIM_CATALOG != 0);
        if catalog {
            let names = busbar_kernel::endpoints::catalog_names(
                &context.app,
                &context.gov,
                &self.served.planes[plane].facts.plane,
            );
            let head = &context.head;
            let fields: HeadFields = head
                .fields
                .iter()
                .filter(|(name, _)| keep_arrival_field(name.as_bytes()))
                .map(|(n, v)| (n.as_bytes().to_vec(), v.clone()))
                .collect();
            if let Some(rendered) = self.served.planes[plane].driver.catalog_unitless(
                head.method.as_bytes(),
                &target_of(head),
                &fields,
                &names,
            ) {
                self.complete_unmetered(plane, admission, &context, &*caller, rendered)
                    .await;
            }
            return None;
        }
        let (mut door, mut arrival) = self.neutral_arrival(plane, claim, context, body);
        door.admission = Some(admission.clone());
        if admission.selected_line().upgrade.is_some() {
            if !slot.admit().await {
                if let Some(rendered) = self.refusal(admission, ReasonCode::DecodeFailed) {
                    render(&*caller, rendered).await;
                }
                return None;
            }
            let (from_caller, from_rx) = mpsc::channel(SESSION_QUEUE);
            let (to_tx, to_caller) = mpsc::channel(SESSION_QUEUE);
            let pipe_caller = PipeCaller {
                from: tokio::sync::Mutex::new(from_rx),
                to: to_tx,
            };
            let (verdict, said) = oneshot::channel();
            busbar_kernel::detached::spawn_detached(Arc::clone(&self).session(
                door,
                ClosingCaller::new(pipe_caller),
                arrival,
                verdict,
                Attach::switched(),
            ));
            return match said.await {
                Ok(Ok(())) => Some(SessionPipe {
                    from_caller,
                    to_caller,
                }),
                Ok(Err(Some(rendered))) => {
                    render(&*caller, rendered).await;
                    None
                }
                _ => None,
            };
        }
        let framed = self.served.planes[plane]
            .snapshot
            .claims
            .get(claim as usize)
            .and_then(|claim| {
                self.framer_for(&claim.carrier)
                    .map(|door| (door, claim.carrier.clone()))
            });
        if let Some((framer, carrier)) = framed {
            if framer.facts().datagram {
                let response = Arc::clone(&self)
                    .open_datagram_neutral((framer, carrier), door, arrival)
                    .await;
                if response.body.is_empty() {
                    caller.complete_head(response.status, response.fields);
                } else {
                    caller.head(response.status, response.fields);
                    let _ = caller.write_owned(response.body).await;
                }
                return None;
            }
            if let Some(framer) = framed_by(&carrier, |_| Some(Arc::clone(&framer))) {
                let fields: Vec<_> = arrival
                    .fields
                    .iter()
                    .map(|(n, v)| (String::from_utf8_lossy(n).into_owned(), v.clone()))
                    .collect();
                let target = String::from_utf8_lossy(&arrival.target);
                match FramedStream::open_neutral(framer, &carrier, &target, &fields, scheme) {
                    Ok(mut stream) => match stream.ingest(&arrival.body, true) {
                        Ok(messages) => {
                            arrival.body = Bytes::from(messages.concat());
                            let framed = FramedOutput::new(
                                Arc::clone(&caller),
                                stream,
                                arrival.body.clone(),
                            );
                            if let Some(rendered) = self.drive_neutral(door, arrival, &framed).await
                            {
                                framed.refused(rendered).await;
                            }
                            if framed.stated().is_some() {
                                framed.close();
                            }
                        }
                        Err(_) => {
                            admission.refuse(
                                busbar_contract::caps::StepName::Decode,
                                ReasonCode::DecodeFailed,
                            );
                            if let Ok(closing) = stream.refuse_response(
                                &[],
                                refusal_status(ReasonCode::DecodeFailed),
                                false,
                            ) {
                                caller.complete_head(
                                    closing.status.unwrap_or_else(|| {
                                        refusal_status(ReasonCode::DecodeFailed)
                                    }),
                                    closing.fields,
                                );
                            }
                        }
                    },
                    Err(_) => {
                        if let Some(rendered) = self.refusal(admission, ReasonCode::DecodeFailed) {
                            render(&*caller, rendered).await;
                        }
                    }
                }
                return None;
            }
        }
        if let Some(rendered) = self.drive_neutral(door, arrival, &*caller).await {
            render(&*caller, rendered).await;
        }
        None
    }

    async fn drive_neutral<C: SessionCaller + Stated + Send + Sync>(
        &self,
        door: SessionDoor,
        arrival: Arrival,
        caller: &C,
    ) -> Option<Rendered> {
        let SessionDoor {
            admission,
            plane,
            app,
            principal,
            key,
            open,
            credential,
            ticket,
            host_ticket_admission,
        } = door;
        self.drive(
            plane,
            app,
            (principal, key, credential, ticket, host_ticket_admission),
            open,
            caller,
            arrival,
            None,
            admission.as_ref(),
        )
        .await
    }
}

fn target_of(head: &busbar_kernel::inbound::Head) -> Vec<u8> {
    let mut target = head.target.as_bytes().to_vec();
    if let Some(query) = &head.query {
        target.push(b'?');
        target.extend_from_slice(query.as_bytes());
    }
    target
}

pub(crate) async fn render<C: Output>(caller: &C, rendered: Rendered) {
    if rendered.body.is_empty() {
        caller.complete_head(rendered.status, rendered.fields);
    } else {
        caller.head(rendered.status, rendered.fields);
        let _ = caller.write(&rendered.body).await;
    }
}

struct FramedOutput<C> {
    inner: Arc<C>,
    stream: serve_framed::Shared,
    opening: HeadFields,
    body: Mutex<Option<Bytes>>,
}

impl<C: Output> FramedOutput<C> {
    fn new(inner: Arc<C>, stream: FramedStream, body: Bytes) -> Self {
        let opening = stream.opening_fields().to_vec();
        Self {
            inner,
            stream: serve_framed::shared(stream),
            opening,
            body: Mutex::new(Some(body)),
        }
    }

    fn close(&self) {
        let inner = Arc::clone(&self.inner);
        serve_framed::close_with(&self.stream, move |stream| {
            if let Ok(closing) = stream.close_response() {
                inner.trailers(closing.fields);
            }
        });
    }

    fn finish(&self, status: u32, message: &[u8], details: &[u8]) {
        let inner = Arc::clone(&self.inner);
        let (message, details) = (message.to_vec(), details.to_vec());
        serve_framed::close_with(&self.stream, move |mut stream| {
            if let Ok(closing) = stream.finish_response(status, &message, &details) {
                inner.trailers(closing.fields);
            }
        });
    }

    async fn refused(&self, rendered: Rendered) {
        let stream = serve_framed::lock(&self.stream).stream.take();
        if let Some(mut stream) = stream {
            if let Ok(closing) = stream.refuse_response(
                &rendered.body,
                rendered.status,
                self.inner.stated().is_some(),
            ) {
                if self.inner.stated().is_some() {
                    self.inner.trailers(closing.fields);
                } else {
                    self.inner
                        .complete_head(closing.status.unwrap_or(rendered.status), closing.fields);
                }
            }
        }
    }

    async fn framed(&self, bytes: &[u8], ends: bool) -> bool {
        let stream = {
            let mut slot = serve_framed::lock(&self.stream);
            let stream = slot.stream.take();
            slot.out = stream.is_some();
            stream
        };
        let Some(mut stream) = stream else {
            return false;
        };
        let wire = stream.emit(bytes, ends);
        serve_framed::returned(
            &self.stream,
            stream,
            wire.as_ref().err().map(|_| ReasonCode::ClientGone),
        );
        match wire {
            Ok(wire) if wire.is_empty() => true,
            Ok(wire) => self.inner.write(&wire).await,
            Err(_) => false,
        }
    }
}

impl<C: Output> CallerEnd for FramedOutput<C> {
    async fn stopped(&self) -> ReasonCode {
        serve_framed::stopped(&self.stream).await
    }

    fn head(&self, status: u32, mut fields: HeadFields) {
        fields.extend(self.opening.iter().cloned());
        fields.retain(|(name, _)| !name.eq_ignore_ascii_case(b"content-length"));
        self.inner.head(status, fields);
    }
    async fn write(&self, bytes: &[u8]) -> bool {
        self.framed(bytes, true).await
    }
    async fn write_piece(&self, bytes: &[u8], _text: bool, end: bool) -> bool {
        if bytes.is_empty() && !end {
            return true;
        }
        self.framed(bytes, end).await
    }
    fn final_status(&self, status: u32, message: &[u8], details: &[u8]) {
        self.finish(status, message, details);
    }
}
impl<C: Output> SessionCaller for FramedOutput<C> {
    async fn read(&self) -> Option<Vec<u8>> {
        let body = self
            .body
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        body.map(|body| body.to_vec())
    }
}
impl<C: Output> Stated for FramedOutput<C> {
    fn stated(&self) -> Option<u32> {
        self.inner.stated()
    }
    fn ended(&self, outcome: Option<busbar_contract::caps::Outcome>) {
        let Some(reason) = outcome.and_then(serve_framed::cut_reason) else {
            return;
        };
        if self.inner.stated().is_none() {
            return;
        }
        let inner = Arc::clone(&self.inner);
        serve_framed::close_with(&self.stream, move |mut stream| {
            if let Ok(closing) = stream.refuse_response(&[], refusal_status(reason), true) {
                inner.trailers(closing.fields);
            }
        });
    }
}
