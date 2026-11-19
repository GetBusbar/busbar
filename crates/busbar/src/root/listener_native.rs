// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native listener ownership over the selected TransportPort and canonical physical routes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::secure::SecureVec;
use busbar_contract::transport::wire::{ConnectionIo, ConnectionSecurity, SecuredIo};
use busbar_core_connector::framed_stream::session::{Inbound, TransportConn};
use busbar_core_connector::response_delivery::DeliveryLedger;
use busbar_kernel::inbound::native::{
    AcceptedConnection, ArrivalRefusal, CompletingPhysicalRequest, PhysicalConnection,
    PhysicalListener, PhysicalRequest, StreamOwner,
};
use busbar_kernel::inbound::Head;
use busbar_kernel::limits::process_admission::{
    AdmissionClass, ByteCredit, ProcessAdmission, RequestLease,
};
use busbar_plugin_abi::records::{tag, Records};
use busbar_ports::transport::{ConnIn, TransportPort};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

#[path = "listener_native_answer.rs"]
mod answer;
#[path = "listener_native_corekey.rs"]
mod corekey;
#[path = "listener_native_data.rs"]
mod data;
#[path = "listener_native_delivery.rs"]
mod delivery;
#[path = "listener_native_dispatch.rs"]
mod dispatch;
#[path = "listener_native_handover.rs"]
mod handover;
#[path = "listener_native_response.rs"]
mod response;
#[path = "listener_native_serve.rs"]
mod serving;
#[path = "listener_native_unbilled.rs"]
mod unbilled;
#[path = "listener_native_unrouted.rs"]
mod unrouted;
#[path = "listener_native_upgrade.rs"]
mod upgrade;
pub(crate) use delivery::RegisteredDelivery;
pub(crate) use handover::{Adopted, HandOver, UpgradeAdopter};
pub(crate) use serving::{serve_admitted, NativeCarrierRetired};

pub(crate) type SelectNativeSlot = Arc<
    dyn Fn(&busbar_kernel::state::App, &str) -> Option<Arc<super::min3_physical::NativeSlot>>
        + Send
        + Sync,
>;

/// Whether a request's head can be verified at all: `true` when its route requires a credential
/// and the head presents none its chain could read. Such a request is answered on its head; the
/// screen judges nothing else, and a head that presents any credential is verified by the chain
/// as before.
pub(crate) type HeadScreen =
    Arc<dyn Fn(&busbar_kernel::inbound::native::RequestBinding) -> bool + Send + Sync>;

pub(crate) struct NativeLimits {
    pub(crate) max_connections: usize,
    pub(crate) body_bytes: usize,
    pub(crate) stall_ms: Option<u32>,
    pub(crate) handshake_timeout: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) write_timeout: Duration,
    pub(crate) drain_grace: Duration,
}

/// The selected native supplier and physical authority are captured together before accepting IO.
pub(crate) struct NativeListener {
    slot: Box<str>,
    port: Arc<dyn TransportPort>,
    physical: PhysicalListener,
    budget: Arc<ProcessAdmission>,
    class: AdmissionClass,
    limits: NativeLimits,
    select: SelectNativeSlot,
    admin: Option<axum::Router>,
    /// The carrier side of an upgrade's hand-over (`listener_native_handover.rs`). `None`: no
    /// websocket transport is linked, and an admitted upgrade request is answered 501.
    adopter: Option<Arc<dyn UpgradeAdopter>>,
}

pub(crate) struct OpenedConnection {
    pub(crate) ingress: NativeIngress,
    pub(crate) conn: TransportConn,
    pub(crate) io: Compat<SecuredIo>,
    pub(crate) progress: Arc<dyn busbar_contract::response_delivery::CarrierProgressReader>,
    pub(crate) delivery: DeliveryLedger,
}

/// What admits a native listener's requests: the process budget and the class they are counted under.
pub(crate) struct NativeAdmission {
    pub(crate) budget: Arc<ProcessAdmission>,
    pub(crate) class: AdmissionClass,
}

impl NativeListener {
    pub(crate) fn new(
        handle: Arc<busbar_kernel::state::AppHandle>,
        slot: Box<str>,
        port: Arc<dyn TransportPort>,
        admission: NativeAdmission,
        select: SelectNativeSlot,
        limits: NativeLimits,
        admin: Option<axum::Router>,
    ) -> Result<Self, InputError> {
        use busbar_plugin_abi::transport::{FB_DATAGRAM, FB_SERVER, FB_WIRE_PROVENANCE};
        let NativeAdmission { budget, class } = admission;
        if !port
            .listener_slots()
            .iter()
            .any(|name| name.as_ref() == slot.as_ref())
            || port.facts() & (FB_SERVER | FB_WIRE_PROVENANCE) != (FB_SERVER | FB_WIRE_PROVENANCE)
            || port.facts() & FB_DATAGRAM != 0
            || limits.max_connections == 0
        {
            return Err(InputError::Invalid);
        }
        let select_physical = select.clone();
        let physical = PhysicalListener::new(
            handle,
            slot.clone(),
            port.clone(),
            class,
            Arc::new(move |app, slot| {
                select_physical(app, slot).map(|selected| selected.prepared().clone())
            }),
        )
        .map_err(|error| InputError::Arrival(ArrivalRefusal::Binding(error)))?;
        Ok(Self {
            slot,
            port,
            physical,
            budget,
            class,
            limits,
            select,
            admin,
            adopter: None,
        })
    }

    /// The screen every connection of this listener judges its heads with.
    fn head_screen(&self) -> HeadScreen {
        let (select, slot) = (self.select.clone(), self.slot.clone());
        Arc::new(move |binding| {
            if !matches!(
                binding.route().target(),
                busbar_kernel::inbound::native::RouteTarget::Plane(_)
            ) {
                return false;
            }
            let Some(slot) = select(binding.app(), &slot) else {
                return false;
            };
            let Ok(route) = slot.data_for(binding) else {
                return false;
            };
            route.requires_credential() && !answer::presented(binding, route.withheld())
        })
    }

    /// Link the carrier side of an upgrade's hand-over. Called once, at assembly, by the listener
    /// plan when the candidate's websocket transport is admitted on this slot.
    pub(crate) fn with_adopter(mut self, adopter: Arc<dyn UpgradeAdopter>) -> Self {
        self.adopter = Some(adopter);
        self
    }

    /// Observe the actual unbuffered socket before security wrapping and preserve its trusted
    /// storage origin through the handshake, callback copies and physical request facts.
    pub(crate) async fn accepted(
        &self,
        stream: tokio::net::TcpStream,
        security: Option<&dyn ConnectionSecurity>,
    ) -> Result<OpenedConnection, InputError> {
        let peer = Address::capture(stream.peer_addr().map_err(InputError::Io)?)?;
        let local = Address::capture(stream.local_addr().map_err(InputError::Io)?)?;
        let storage = self.budget.connection_storage(self.class);
        let raw = busbar_core_connector::raw_progress::tcp(stream);
        let progress = raw.progress();
        let raw = ConnectionIo {
            io: Box::new(raw.compat()),
            progress,
            storage,
        };
        let secured = match security {
            None => SecuredIo::anonymous(raw),
            Some(security) => {
                tokio::time::timeout(self.limits.handshake_timeout, security.wrap(raw))
                    .await
                    .map_err(|_| InputError::Io(std::io::ErrorKind::TimedOut.into()))?
                    .map_err(InputError::Io)?
            }
        };
        self.open(secured, peer.as_str(), local.as_str())
    }

    fn open(
        &self,
        mut io: SecuredIo,
        peer: &str,
        local: &str,
    ) -> Result<OpenedConnection, InputError> {
        let alpn = io.tls_handshake.as_ref().and_then(|info| info.alpn());
        let alpn = alpn
            .map(std::str::from_utf8)
            .transpose()
            .map_err(|_| InputError::Invalid)?;
        if alpn.is_some_and(|protocol| {
            !self
                .port
                .alpn(busbar_plugin_abi::transport::ROLE_SERVER)
                .iter()
                .any(|offered| offered.as_ref() == protocol)
        }) {
            return Err(InputError::Invalid);
        }
        let sni = io
            .tls_handshake
            .as_ref()
            .and_then(|info| info.server_name())
            .unwrap_or("");
        // The wrap's charged certificate moves into the facts; the transport is lent it there.
        let facts = AcceptedConnection::capture_secured(
            io.tls_handshake.as_ref(),
            std::mem::take(&mut io.peer_certificate),
            &io.storage,
            peer,
            local,
        )
        .map_err(|_| InputError::Capacity)?;
        let ingress = NativeIngress::new(
            self.physical.connect(facts),
            self.budget.clone(),
            self.class,
            self.limits.body_bytes,
            Some(self.head_screen()),
        );
        // Empty: its arrays and its wake cell are made with the first response (allocation ruling).
        let delivery = DeliveryLedger::default();
        let conn = TransportConn::begin(
            self.port.clone(),
            &ConnIn {
                role: busbar_plugin_abi::transport::ROLE_SERVER,
                flags: busbar_plugin_abi::transport::CONN_ACCEPT,
                alpn: alpn.unwrap_or(""),
                sni,
                peer,
                local,
                tls_peer_cert: ingress.connection.facts().peer_certificate(),
                leftover: &[],
                head: &[],
                local_fingerprint: "",
                // The host clock the plugin's Host::mono_ns and WAKE_AT are stated on.
                mono_ns: busbar_plugin_abi::host_side::host_vt::vt::mono(),
            },
            self.limits.stall_ms,
            Instant::now(),
            io.storage.clone(),
        )
        .map_err(InputError::Transport)?;
        let progress = io.progress.clone();
        Ok(OpenedConnection {
            ingress,
            conn,
            io: io.compat(),
            progress,
            delivery,
        })
    }
}

// SocketAddr formatting has a fixed maximum extent; avoid an uncharged temporary String.
struct Address {
    bytes: [u8; 64],
    len: usize,
}
impl Address {
    fn capture(address: std::net::SocketAddr) -> Result<Self, InputError> {
        use std::fmt::Write;
        let mut value = Self {
            bytes: [0; 64],
            len: 0,
        };
        write!(&mut value, "{address}").map_err(|_| InputError::Invalid)?;
        Ok(value)
    }
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).expect("SocketAddr is ASCII")
    }
}
impl std::fmt::Write for Address {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let end = self
            .len
            .checked_add(value.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or(std::fmt::Error)?;
        self.bytes[self.len..end].copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

const PLAINTEXT_WINDOW: usize = 256 * 1024;

#[derive(Debug)]
pub(crate) enum InputError {
    Invalid,
    Capacity,
    TooLarge,
    /// The request carried trailers: refused 400 (the snapshot has no trailer authority field,
    /// and a trailer is never reinterpreted as a head field).
    Trailers,
    Arrival(ArrivalRefusal),
    Io(std::io::Error),
    Transport(busbar_core_connector::framed_stream::session::Ended),
    Body(axum::Error),
    FinalIntent(super::durability::response_intent::FinalIntentError),
    Delivery(busbar_contract::response_delivery::ResponseStop),
}

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => f.write_str("invalid native listener input"),
            Self::Capacity => f.write_str("native listener capacity exhausted"),
            Self::TooLarge => f.write_str("native request exceeds its body limit"),
            Self::Trailers => f.write_str("native request carried trailers"),
            Self::Arrival(reason) => write!(f, "native physical arrival refused: {reason:?}"),
            Self::Io(error) => write!(f, "native carrier failed: {error}"),
            Self::Transport(reason) => write!(f, "native transport ended: {reason:?}"),
            Self::Body(error) => write!(f, "native response body failed: {error}"),
            Self::FinalIntent(error) => write!(f, "native response intent failed: {error}"),
            Self::Delivery(reason) => write!(f, "native response delivery stopped: {reason:?}"),
        }
    }
}
impl std::error::Error for InputError {}

impl InputError {
    /// The row of the refusal table an input failure is answered by, where it is the request's
    /// own doing: a full gateway (row 1), a body over the cap (row 6), request trailers (row 8).
    /// `None`: the connection's failure, or the engine's; there is no client to answer. The
    /// supervisor answers a row on the request's own stream and keeps the connection (an
    /// HTTP/2 connection's other streams are untouched); it stops the connection only on `None`.
    pub(crate) fn refusal(&self) -> Option<busbar_kernel::auth::admission_table::Refusal> {
        use busbar_kernel::auth::admission_table::Refusal;
        match self {
            Self::Capacity => Some(Refusal::GatewayFull),
            Self::TooLarge => Some(Refusal::BodyTooLarge),
            Self::Trailers => Some(Refusal::Trailers),
            Self::Invalid
            | Self::Arrival(_)
            | Self::Io(_)
            | Self::Transport(_)
            | Self::Body(_)
            | Self::FinalIntent(_)
            | Self::Delivery(_) => None,
        }
    }
}

impl From<ArrivalRefusal> for InputError {
    fn from(error: ArrivalRefusal) -> Self {
        Self::Arrival(error)
    }
}

struct InputSlot {
    stream: u64,
    deadline: Option<Instant>,
    body_started: tokio::time::Instant,
    body_deadline: Instant,
    pending: Option<PhysicalRequest>,
    body: Option<InputBody>,
    // The same owner also accompanies completion. A reset can still reach it after input EOS.
    owner: Arc<StreamOwner>,
    node: Option<crate::root::plane_node::NativeNodeHandle>,
    carrier_reported: bool,
    /// The request's own input refused it (a body over the cap, request trailers): the rest of
    /// its body is discarded unbuffered, and at its end the request is answered with this row
    /// instead of being served. The connection, and its other streams, are untouched.
    refused: Option<busbar_kernel::auth::admission_table::Refusal>,
    /// The request was answered on its head ([`HeadScreen`]): its input was completed empty,
    /// and whatever body its client still sends is discarded as it arrives.
    answered_at_head: bool,
}
impl InputSlot {
    fn next_deadline(&self) -> Option<Instant> {
        if self.pending.is_some() {
            Some(
                self.deadline
                    .map_or(self.body_deadline, |at| at.min(self.body_deadline)),
            )
        } else {
            self.deadline
        }
    }
    fn body_bounds_exceeded(&self) -> bool {
        let elapsed = u64::try_from(self.body_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let bytes = self.body.as_ref().map_or(0, |body| body.bytes.len() as u64);
        crate::root::listener::check_body_bounds(0, elapsed, bytes).is_some()
    }
}

pub(crate) struct ReadyInput {
    pub(crate) request: CompletingPhysicalRequest,
    pub(crate) owner: Arc<StreamOwner>,
    /// The request's own input refused it ([`InputError::refusal`]): dispatch verifies the caller
    /// as for any request, then answers this row. `None`: serve it.
    pub(crate) refused: Option<busbar_kernel::auth::admission_table::Refusal>,
}

/// The actual native stream event consumer. EOF completes input only; the physical owner stays
/// in this connection until the response lifecycle retires, or the real connection is dropped.
///
/// Its input slots start empty and grow with the requests (allocation ruling): no fixed capacity
/// and no refusal of its own. What bounds them is each head's own admission (`try_enter`).
pub(crate) struct NativeIngress {
    connection: PhysicalConnection,
    budget: Arc<ProcessAdmission>,
    class: AdmissionClass,
    slots: Vec<InputSlot>,
    last_head: u64,
    body_limit: usize,
    /// Whether a head can be verified at all ([`HeadScreen`]). `None`: every head is taken whole.
    screen: Option<HeadScreen>,
}

impl NativeIngress {
    pub(crate) fn new(
        connection: PhysicalConnection,
        budget: Arc<ProcessAdmission>,
        class: AdmissionClass,
        body_limit: usize,
        screen: Option<HeadScreen>,
    ) -> Self {
        Self {
            connection,
            budget,
            class,
            slots: Vec::new(),
            last_head: 0,
            body_limit,
            screen,
        }
    }

    pub(crate) fn accept(
        &mut self,
        input: Inbound,
        deadline: Option<Instant>,
    ) -> Result<Option<ReadyInput>, InputError> {
        match input {
            Inbound::Head {
                stream,
                end_stream,
                head,
            } => {
                let body_started = tokio::time::Instant::now();
                let total_deadline = Instant::now()
                    .checked_add(crate::root::listener::total_body_deadline())
                    .ok_or(InputError::Capacity)?;
                // Host stream identities are monotone and never recycled, including refused heads.
                if stream <= self.last_head {
                    return Err(InputError::Invalid);
                }
                self.last_head = stream;
                let request = self
                    .budget
                    .try_enter(self.class)
                    .map_err(|_| InputError::Capacity)?;
                let DecodedHead {
                    head: decoded,
                    credit,
                } = decode_head(head.as_slice(), &request)?;
                let (pending, owner) =
                    self.connection
                        .head(stream, decoded, request.clone(), deadline)?;
                // PhysicalRequest now holds its own full head backing reservation.
                drop(credit);
                let body = InputBody::new(&request)?;
                // A head that presents no credential its route could read cannot be verified:
                // it is answered now, on the head, and none of its body is taken into memory.
                let unverifiable = !end_stream
                    && self
                        .screen
                        .as_ref()
                        .is_some_and(|screen| screen(pending.binding()));
                self.slots.push(InputSlot {
                    stream,
                    deadline,
                    body_started,
                    body_deadline: total_deadline,
                    pending: Some(pending),
                    body: Some(body),
                    owner: Arc::new(owner),
                    node: None,
                    carrier_reported: false,
                    refused: unverifiable.then_some(
                        busbar_kernel::auth::admission_table::Refusal::Unverified {
                            presented: false,
                        },
                    ),
                    answered_at_head: unverifiable,
                });
                if end_stream || unverifiable {
                    self.end(stream).map(Some)
                } else {
                    Ok(None)
                }
            }
            Inbound::Body {
                stream,
                flags,
                bytes,
            } => {
                if flags != 0 {
                    return Err(InputError::Invalid);
                }
                let slot = self
                    .slots
                    .iter_mut()
                    .find(|slot| slot.stream == stream)
                    .ok_or(InputError::Invalid)?;
                if slot.answered_at_head {
                    return Ok(None);
                }
                let pending = slot.pending.as_ref().ok_or(InputError::Invalid)?;
                pending.binding().check_live()?;
                let limit = pending
                    .binding()
                    .app()
                    .limits
                    .as_ref()
                    .map_or(self.body_limit, |limits| limits.request_body_max_bytes);
                // A request its own input already refused takes no more of its body into memory.
                if slot.refused.is_some() {
                    return Ok(None);
                }
                let request = pending.binding().request().clone();
                match slot.body.as_mut().ok_or(InputError::Invalid)?.append(
                    &request,
                    bytes.as_slice(),
                    limit,
                ) {
                    Ok(()) => {}
                    // Over the cap: what was read is released now, the rest is discarded as it
                    // arrives, and the request is answered 413 at its end (refusal row 6).
                    Err(InputError::TooLarge) => {
                        slot.body = Some(InputBody::new(&request)?);
                        slot.refused = InputError::TooLarge.refusal();
                        return Ok(None);
                    }
                    Err(error) => return Err(error),
                }
                if slot.body_bounds_exceeded() {
                    self.connection.cancel(&slot.owner);
                    slot.pending.take();
                    slot.body.take();
                    return Err(InputError::Delivery(
                        busbar_contract::response_delivery::ResponseStop::Deadline,
                    ));
                }
                Ok(None)
            }
            Inbound::End(stream) => {
                // A request answered on its head completed its input then.
                if self
                    .slots
                    .iter()
                    .any(|slot| slot.stream == stream && slot.answered_at_head)
                {
                    return Ok(None);
                }
                self.end(stream).map(Some)
            }
            Inbound::Reset { stream, .. } | Inbound::Stalled(stream) => {
                let slot = self
                    .slots
                    .iter_mut()
                    .find(|slot| slot.stream == stream)
                    .ok_or(InputError::Invalid)?;
                self.connection.cancel(&slot.owner);
                slot.pending.take();
                slot.body.take();
                Ok(None)
            }
            // The immutable request snapshot currently has no trailer authority field. Do not
            // silently discard or reinterpret trailer credentials as original head fields.
            // The request is answered 400 at its end (refusal row 8); its connection is kept.
            Inbound::Trailers { stream, .. } => {
                let slot = self
                    .slots
                    .iter_mut()
                    .find(|slot| slot.stream == stream)
                    .ok_or(InputError::Invalid)?;
                if slot.answered_at_head {
                    return Ok(None);
                }
                if slot.refused.is_none() {
                    slot.refused = InputError::Trailers.refusal();
                }
                Ok(None)
            }
        }
    }

    fn end(&mut self, stream: u64) -> Result<ReadyInput, InputError> {
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.stream == stream)
            .ok_or(InputError::Invalid)?;
        if slot.body_bounds_exceeded() {
            self.connection.cancel(&slot.owner);
            slot.pending.take();
            slot.body.take();
            return Err(InputError::Delivery(
                busbar_contract::response_delivery::ResponseStop::Deadline,
            ));
        }
        let pending = slot.pending.take().ok_or(InputError::Invalid)?;
        let InputBody { bytes, credit } = slot.body.take().ok_or(InputError::Invalid)?;
        let request = pending.finish_input(bytes, credit)?.begin_completion()?;
        Ok(ReadyInput {
            request,
            owner: Arc::clone(&slot.owner),
            refused: slot.refused.take(),
        })
    }

    /// Called only after the corresponding writer and input lifecycle have actually retired.
    pub(crate) fn retire(&mut self, owner: &Arc<StreamOwner>) -> Result<(), InputError> {
        let index = self
            .slots
            .iter()
            .position(|slot| Arc::ptr_eq(&slot.owner, owner))
            .ok_or(InputError::Invalid)?;
        self.slots.swap_remove(index);
        Ok(())
    }
}

struct DecodedHead {
    head: Head,
    // Retain the provisional full allocation until PhysicalConnection::head reserves its owner.
    credit: ByteCredit,
}

fn add(left: usize, right: usize) -> Result<usize, InputError> {
    left.checked_add(right).ok_or(InputError::Capacity)
}

fn text_copy(text: &str) -> Result<String, InputError> {
    let mut copied = String::new();
    copied
        .try_reserve_exact(text.len())
        .map_err(|_| InputError::Capacity)?;
    if copied.capacity() > text.len() {
        return Err(InputError::Capacity);
    }
    copied.push_str(text);
    Ok(copied)
}

fn value_copy(value: &[u8]) -> Result<Vec<u8>, InputError> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(value.len())
        .map_err(|_| InputError::Capacity)?;
    if copied.capacity() > value.len() {
        return Err(InputError::Capacity);
    }
    copied.extend_from_slice(value);
    Ok(copied)
}

/// Validate borrowed records and quote every destination allocation before copying any field.
fn decode_head(bytes: &[u8], request: &RequestLease) -> Result<DecodedHead, InputError> {
    let (mut method, mut path, mut authority, mut scheme) = (None, None, None, None);
    let mut fields = 0usize;
    let mut field_bytes = 0usize;
    for record in Records::new(bytes) {
        let record = record.map_err(|_| InputError::Invalid)?;
        match record.tag {
            tag::H_METHOD | tag::H_PATH | tag::H_AUTHORITY | tag::H_SCHEME => {
                let text = record.text().map_err(|_| InputError::Invalid)?;
                let destination = match record.tag {
                    tag::H_METHOD => &mut method,
                    tag::H_PATH => &mut path,
                    tag::H_AUTHORITY => &mut authority,
                    _ => &mut scheme,
                };
                if destination.replace(text).is_some() {
                    return Err(InputError::Invalid);
                }
            }
            tag::PAIR => {
                let (name, value) = record.pair().map_err(|_| InputError::Invalid)?;
                fields = add(fields, 1)?;
                field_bytes = add(add(field_bytes, name.len())?, value.len())?;
            }
            _ => return Err(InputError::Invalid),
        }
    }
    let method = method
        .filter(|method| !method.is_empty())
        .ok_or(InputError::Invalid)?;
    let path = path
        .filter(|path| !path.is_empty())
        .ok_or(InputError::Invalid)?;
    let (path, query) = path
        .split_once('?')
        .map_or((path, None), |(path, query)| (path, Some(query)));
    let authority = authority.unwrap_or_default();
    let descriptors = fields
        .checked_mul(std::mem::size_of::<(String, Vec<u8>)>())
        .ok_or(InputError::Capacity)?;
    let extent = add(
        add(
            add(
                add(add(method.len(), path.len())?, query.map_or(0, str::len))?,
                authority.len(),
            )?,
            field_bytes,
        )?,
        descriptors,
    )?;
    let credit = request
        .try_reserve(extent)
        .map_err(|_| InputError::Capacity)?;
    let mut head = Head::default();
    head.method = text_copy(method)?;
    head.target = text_copy(path)?;
    head.query = query.map(text_copy).transpose()?;
    head.authority = text_copy(authority)?;
    head.fields
        .try_reserve_exact(fields)
        .map_err(|_| InputError::Capacity)?;
    if head.fields.capacity() > fields {
        return Err(InputError::Capacity);
    }
    for record in Records::new(bytes) {
        let record = record.map_err(|_| InputError::Invalid)?;
        if record.tag == tag::PAIR {
            let (name, value) = record.pair().map_err(|_| InputError::Invalid)?;
            head.fields.push((text_copy(name)?, value_copy(value)?));
        }
    }
    // H_SCHEME is validated text only; physical security comes from the accepted socket.
    Ok(DecodedHead { head, credit })
}

struct InputBody {
    bytes: SecureVec,
    credit: ByteCredit,
}
impl InputBody {
    fn new(request: &RequestLease) -> Result<Self, InputError> {
        let credit = request.try_reserve(0).map_err(|_| InputError::Capacity)?;
        Ok(Self {
            bytes: SecureVec::new(),
            credit,
        })
    }
    fn append(
        &mut self,
        request: &RequestLease,
        bytes: &[u8],
        max: usize,
    ) -> Result<(), InputError> {
        if !self.credit.request().same_request(request) {
            return Err(InputError::Invalid);
        }
        let length = add(self.bytes.len(), bytes.len())?;
        if length > max {
            return Err(InputError::TooLarge);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        // Full replacement overlaps the old request allocation and the original callback owner.
        let credit = request
            .try_reserve(length)
            .map_err(|_| InputError::Capacity)?;
        let mut replacement = SecureVec::with_capacity(length).map_err(|_| InputError::Capacity)?;
        if replacement.capacity() > length {
            return Err(InputError::Capacity);
        }
        replacement
            .extend(self.bytes.as_slice())
            .map_err(|_| InputError::Capacity)?;
        replacement
            .extend(bytes)
            .map_err(|_| InputError::Capacity)?;
        let old_bytes = std::mem::replace(&mut self.bytes, replacement);
        let old_credit = std::mem::replace(&mut self.credit, credit);
        drop(old_bytes);
        drop(old_credit);
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/listener_native.rs"]
mod tests;
