// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_plugin_abi::records::{Reply, Writer};

fn request_budget(bytes: u32) -> (Arc<ProcessAdmission>, RequestLease) {
    let budget = ProcessAdmission::with_limits(2, bytes, 0);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    (budget, request)
}

#[test]
fn native_head_preserves_empty_query_duplicates_and_charges_before_copy() {
    let mut wire = Reply::new();
    wire.put_text(tag::H_METHOD, "POST").unwrap();
    wire.put_text(tag::H_PATH, "/one?").unwrap();
    wire.put_text(tag::H_AUTHORITY, "example.test").unwrap();
    wire.put_pair(tag::PAIR, "x-order", b"first").unwrap();
    wire.put_pair(tag::PAIR, "x-order", b"second").unwrap();
    let (budget, request) = request_budget(4096);
    let decoded = decode_head(wire.as_bytes(), &request).unwrap();
    assert_eq!(decoded.head.query.as_deref(), Some(""));
    assert_eq!(decoded.head.target, "/one");
    assert_eq!(decoded.head.fields.len(), 2);
    assert_eq!(decoded.head.fields[1].1, b"second");
    let held = decoded.credit.len();
    assert!(held >= 2 * std::mem::size_of::<(String, Vec<u8>)>());
    assert_eq!(budget.used(), (held, held));
    drop(decoded);
    assert_eq!(budget.used(), (0, 0));
    let (small, request) = request_budget(1);
    assert!(decode_head(wire.as_bytes(), &request).is_err());
    assert_eq!(small.used(), (0, 0));
}

#[test]
fn native_head_rejects_duplicate_identity_before_retaining_any_fields() {
    let mut wire = Reply::new();
    wire.put_text(tag::H_METHOD, "GET").unwrap();
    wire.put_text(tag::H_METHOD, "POST").unwrap();
    wire.put_text(tag::H_PATH, "/").unwrap();
    let (budget, request) = request_budget(4096);
    assert!(decode_head(wire.as_bytes(), &request).is_err());
    assert_eq!(budget.used(), (0, 0));
}

#[test]
fn native_input_window_is_not_a_total_body_limit_and_replacement_overlaps() {
    let (budget, request) = request_budget(2 * 1024 * 1024);
    let mut body = InputBody::new(&request).unwrap();
    let chunk = vec![7; PLAINTEXT_WINDOW];
    body.append(&request, &chunk, 1024 * 1024).unwrap();
    body.append(&request, &chunk, 1024 * 1024).unwrap();
    assert_eq!(body.bytes.len(), 2 * PLAINTEXT_WINDOW);
    assert_eq!(budget.used().0 as usize, 2 * PLAINTEXT_WINDOW);
    assert!(body.credit.request().same_request(&request));
    drop(body);
    assert_eq!(budget.used(), (0, 0));
    let (small, request) = request_budget(10);
    let mut body = InputBody::new(&request).unwrap();
    body.append(&request, b"123456", 64).unwrap();
    assert!(body.append(&request, b"7", 64).is_err());
    assert_eq!(body.bytes.as_slice(), b"123456");
    assert_eq!(small.used(), (6, 6));
}

pub(super) async fn ingress_fixture() -> (NativeIngress, busbar_contract::storage::StorageSource) {
    use busbar_kernel::inbound::native::{AcceptedConnection, PhysicalListener};
    busbar_core_admin::install();
    let app = crate::root::min3_auth::tests::physical_app().await;
    let transport = crate::root::min3_boot::transports::tests::framer(&["http"]);
    let slot =
        crate::root::min3_physical::assemble_admin_slot(&app, "admin_listen", transport.clone())
            .unwrap();
    let listener = PhysicalListener::new(
        Arc::new(busbar_kernel::state::AppHandle::new(app)),
        "admin_listen".into(),
        transport,
        AdmissionClass::Operator,
        Arc::new(move |_, name| (name == slot.slot()).then(|| slot.prepared().clone())),
    )
    .unwrap();
    let budget = ProcessAdmission::with_limits(256, 32 * 1024 * 1024, 32 * 1024 * 1024);
    let source = budget.connection_storage(AdmissionClass::Operator);
    let facts =
        AcceptedConnection::capture(&source, "192.0.2.1", "192.0.2.2", "http/1.1", &[]).unwrap();
    (
        NativeIngress::new(
            listener.connect(facts),
            budget,
            AdmissionClass::Operator,
            1024 * 1024,
            None,
        ),
        source,
    )
}

pub(super) fn public_head(
    source: &busbar_contract::storage::StorageSource,
    stream: u64,
    end_stream: bool,
) -> Inbound {
    let mut wire = Reply::new();
    wire.put_text(tag::H_METHOD, "GET").unwrap();
    wire.put_text(tag::H_PATH, busbar_kernel::auth::HEALTHZ_PATH)
        .unwrap();
    Inbound::Head {
        stream,
        end_stream,
        head: busbar_core_connector::framed_stream::session::Payload::copy(source, wire.as_bytes())
            .unwrap(),
    }
}

#[tokio::test]
async fn native_input_eof_keeps_reset_bound_to_the_original_physical_owner() {
    let (mut ingress, source) = ingress_fixture().await;
    assert!(ingress
        .accept(public_head(&source, 1, false), None)
        .unwrap()
        .is_none());
    let ready = ingress.accept(Inbound::End(1), None).unwrap().unwrap();
    let binding = ready.request.binding().clone();
    assert!(binding.owns_stream(&ready.owner));
    let (mut other, other_source) = ingress_fixture().await;
    let other_ready = other
        .accept(public_head(&other_source, 1, true), None)
        .unwrap()
        .unwrap();
    assert!(
        !binding.owns_stream(&other_ready.owner),
        "equal stream numbers are not physical identity"
    );
    assert!(binding.check_live().is_ok());
    assert!(Arc::ptr_eq(&ingress.slots[0].owner, &ready.owner));
    let execution = ready.request.complete_public().unwrap();
    assert!(execution.check_executing().is_ok());
    ingress
        .accept(Inbound::Reset { stream: 1, code: 0 }, None)
        .unwrap();
    assert!(execution.check_executing().is_err());
    ingress.retire(&ready.owner).unwrap();
    assert!(ingress.accept(public_head(&source, 1, true), None).is_err());
}

#[tokio::test]
async fn native_root_input_slots_and_ledger_have_no_fixed_shape() {
    // Owner's allocation ruling: no fixed capacity and no refusal of their own. Past the old shape
    // of 200, every head is taken; what bounds them is each request's admission.
    let (mut ingress, source) = ingress_fixture().await;
    assert_eq!(
        ingress.slots.capacity(),
        0,
        "nothing made before the first head"
    );
    let mut ready = Vec::new();
    for stream in 1..=210u64 {
        ready.push(
            ingress
                .accept(public_head(&source, stream, true), None)
                .unwrap()
                .unwrap(),
        );
    }
    ingress.retire(&ready.remove(0).owner).unwrap();
    assert!(ingress
        .accept(public_head(&source, 211, true), None)
        .unwrap()
        .is_some());

    use busbar_contract::response_delivery::ResponseKey;
    let mut ledger = busbar_core_connector::response_delivery::DeliveryLedger::default();
    let mut handles = Vec::new();
    let key = |stream| ResponseKey {
        node: 1,
        incarnation: 1,
        unit: None,
        connection_generation: 1,
        stream,
    };
    for stream in 1..=210u64 {
        handles.push(ledger.admit(key(stream)).unwrap());
    }
    assert!(ledger.admit(key(210)).is_err(), "an id is never reused");
}

#[tokio::test]
async fn completed_public_request_dispatches_its_original_core_route_and_observes_reset() {
    let (mut ingress, source) = ingress_fixture().await;
    let ready = ingress
        .accept(public_head(&source, 1, true), None)
        .unwrap()
        .unwrap();
    let execution = ready.request.complete_public().unwrap();
    let response = execution.http_response().await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
        "ok"
    );
    ingress
        .accept(Inbound::Reset { stream: 1, code: 0 }, None)
        .unwrap();
    assert!(matches!(
        execution.http_response().await,
        Err(ArrivalRefusal::Cancelled)
    ));
    ingress.retire(&ready.owner).unwrap();
}

struct ObservedBegin {
    inner: Arc<dyn TransportPort>,
    slots: [Box<str>; 1],
    seen: std::sync::Mutex<Option<(String, String, u64)>>,
}
impl TransportPort for ObservedBegin {
    fn listener_slots(&self) -> &[Box<str>] {
        &self.slots
    }
    fn alpn(&self, role: u32) -> &[Box<str>] {
        self.inner.alpn(role)
    }
    fn defaults(&self, role: u32) -> &[(Box<str>, Box<str>)] {
        self.inner.defaults(role)
    }
    fn protocols(&self) -> &[Box<str>] {
        self.inner.protocols()
    }
    fn facts(&self) -> u64 {
        busbar_plugin_abi::transport::FB_SERVER | busbar_plugin_abi::transport::FB_WIRE_PROVENANCE
    }
    fn begin(
        &self,
        input: &ConnIn<'_>,
        sink: &mut dyn FnMut(busbar_ports::transport::TransportOut<'_>),
    ) -> Result<busbar_ports::transport::TransportSession, busbar_ports::PortError> {
        assert_eq!(input.role, busbar_plugin_abi::transport::ROLE_SERVER);
        assert_eq!(input.flags, busbar_plugin_abi::transport::CONN_ACCEPT);
        assert!(input.alpn.is_empty() && input.sni.is_empty() && input.tls_peer_cert.is_empty());
        assert!(
            input.head.is_empty()
                && input.leftover.is_empty()
                && input.local_fingerprint.is_empty()
        );
        *self.seen.lock().unwrap() =
            Some((input.peer.to_owned(), input.local.to_owned(), input.mono_ns));
        self.inner.begin(input, sink)
    }
    fn ingest(
        &self,
        s: &mut busbar_ports::transport::TransportSession,
        bytes: &[u8],
        sink: &mut dyn FnMut(busbar_ports::transport::TransportOut<'_>),
    ) -> Result<(), busbar_ports::PortError> {
        self.inner.ingest(s, bytes, sink)
    }
    fn emit(
        &self,
        s: &mut busbar_ports::transport::TransportSession,
        stream: u64,
        piece: u32,
        arg: u32,
        bytes: &[u8],
        sink: &mut dyn FnMut(busbar_ports::transport::TransportOut<'_>),
    ) -> Result<(), busbar_ports::PortError> {
        self.inner.emit(s, stream, piece, arg, bytes, sink)
    }
    fn timer(
        &self,
        s: &mut busbar_ports::transport::TransportSession,
        sink: &mut dyn FnMut(busbar_ports::transport::TransportOut<'_>),
    ) -> Result<(), busbar_ports::PortError> {
        self.inner.timer(s, sink)
    }
    fn datagram(
        &self,
        s: &mut busbar_ports::transport::TransportSession,
        path: u32,
        secured: bool,
        bytes: &[u8],
        sink: &mut dyn FnMut(busbar_ports::transport::TransportOut<'_>),
    ) -> Result<(), busbar_ports::PortError> {
        self.inner.datagram(s, path, secured, bytes, sink)
    }
    fn event(
        &self,
        s: &mut busbar_ports::transport::TransportSession,
        event: busbar_ports::transport::TransportEvent<'_>,
        sink: &mut dyn FnMut(busbar_ports::transport::TransportOut<'_>),
    ) -> Result<(), busbar_ports::PortError> {
        self.inner.event(s, event, sink)
    }
}

#[tokio::test]
async fn actual_tcp_accept_passes_real_socket_facts_and_host_clock_to_native_begin() {
    // The host clock's zero point is this process's first reading of it, taken here, before any
    // other clock in the process starts: a begin stated on another zero point is then 50 ms off.
    let _ = busbar_plugin_abi::host_side::host_vt::vt::mono();
    std::thread::sleep(Duration::from_millis(50));
    busbar_core_admin::install();
    let app = crate::root::min3_auth::tests::physical_app().await;
    let port = Arc::new(ObservedBegin {
        inner: crate::root::min3_boot::transports::tests::framer(&["http"]),
        slots: ["admin_listen".into()],
        seen: Default::default(),
    });
    let slot = crate::root::min3_physical::assemble_admin_slot(&app, "admin_listen", port.clone())
        .unwrap();
    let budget = ProcessAdmission::with_limits(2, 16 * 1024 * 1024, 16 * 1024 * 1024);
    let native = NativeListener::new(
        Arc::new(busbar_kernel::state::AppHandle::new(app)),
        "admin_listen".into(),
        port.clone(),
        crate::root::listener_native::NativeAdmission {
            budget: budget.clone(),
            class: AdmissionClass::Operator,
        },
        Arc::new(move |_, name| (name == slot.slot()).then(|| slot.clone())),
        NativeLimits {
            max_connections: 2,
            body_bytes: 1024,
            stall_ms: None,
            handshake_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            drain_grace: Duration::from_secs(5),
        },
        None,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_address = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(server_address)
        .await
        .unwrap();
    let client_address = client.local_addr().unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    // ConnInfo.mono_ns is on the clock the plugin's Host::mono_ns and its WAKE_AT are on.
    let before = busbar_plugin_abi::host_side::host_vt::vt::mono();
    assert!(matches!(
        native.accepted(stream, None).await,
        Err(InputError::Transport(_))
    ));
    let after = busbar_plugin_abi::host_side::host_vt::vt::mono();
    let seen = port.seen.lock().unwrap().take().unwrap();
    assert_eq!(seen.0, client_address.to_string());
    assert_eq!(seen.1, server_address.to_string());
    assert!((before..=after).contains(&seen.2));
    // The deliberate begin refusal leaves neither connection backing nor request count retained.
    assert_eq!(budget.used(), (0, 0));
}

fn payload(
    source: &busbar_contract::storage::StorageSource,
    bytes: &[u8],
) -> busbar_core_connector::framed_stream::session::Payload {
    busbar_core_connector::framed_stream::session::Payload::copy(source, bytes).unwrap()
}

/// A head that declares a body, with one extra field.
fn head_with(
    source: &busbar_contract::storage::StorageSource,
    stream: u64,
    name: &str,
    value: &[u8],
) -> Inbound {
    let mut wire = Reply::new();
    wire.put_text(tag::H_METHOD, "POST").unwrap();
    wire.put_text(tag::H_PATH, busbar_kernel::auth::HEALTHZ_PATH)
        .unwrap();
    wire.put_pair(tag::PAIR, name, value).unwrap();
    Inbound::Head {
        stream,
        end_stream: false,
        head: payload(source, wire.as_bytes()),
    }
}

/// REFUSAL ROW 8: request trailers no longer end the connection. The request is completed at its
/// end and carries the row it is answered by; every other stream of the connection goes on.
#[tokio::test]
async fn request_trailers_are_answered_and_the_connection_is_kept() {
    use busbar_kernel::auth::admission_table::Refusal;
    let (mut ingress, source) = ingress_fixture().await;
    assert!(ingress
        .accept(public_head(&source, 1, false), None)
        .unwrap()
        .is_none());
    let trailers = Inbound::Trailers {
        stream: 1,
        pairs: payload(&source, &[]),
    };
    assert!(
        ingress.accept(trailers, None).unwrap().is_none(),
        "trailers are not a connection error"
    );
    let ready = ingress.accept(Inbound::End(1), None).unwrap().unwrap();
    assert_eq!(ready.refused, Some(Refusal::Trailers));
    // A second request on the same connection is taken as usual.
    let next = ingress
        .accept(public_head(&source, 2, true), None)
        .unwrap()
        .unwrap();
    assert_eq!(next.refused, None);
}

/// The body cap a request on `stream` is read under: the app's configured one, else the
/// listener's (what `NativeIngress::accept` computes for each body piece).
fn effective_cap(ingress: &NativeIngress, stream: u64) -> usize {
    let slot = ingress
        .slots
        .iter()
        .find(|slot| slot.stream == stream)
        .expect("the stream's slot");
    slot.pending
        .as_ref()
        .expect("input not yet complete")
        .binding()
        .app()
        .limits
        .as_ref()
        .map_or(ingress.body_limit, |limits| limits.request_body_max_bytes)
}

/// REFUSAL ROW 6: a body that runs past the cap is not a connection error. What was read is
/// released, the rest is discarded as it arrives, and the request is completed at its end
/// carrying the row it is answered by.
#[tokio::test]
async fn a_body_over_the_cap_is_answered_and_nothing_past_the_cap_is_kept() {
    use busbar_kernel::auth::admission_table::Refusal;
    let (mut ingress, source) = ingress_fixture().await;
    ingress.body_limit = 8;
    assert!(ingress
        .accept(public_head(&source, 1, false), None)
        .unwrap()
        .is_none());
    let cap = effective_cap(&ingress, 1);
    assert!(
        cap <= 4096,
        "the fixture app configures a {cap}-byte body cap; this test sends cap + 1 bytes and \
         needs a small one (`limits.request_body_max_bytes`) in `physical_app`"
    );
    let body = |bytes: &[u8]| Inbound::Body {
        stream: 1,
        flags: 0,
        bytes: payload(&source, bytes),
    };
    assert!(ingress
        .accept(body(&vec![b'1'; cap]), None)
        .unwrap()
        .is_none());
    assert!(
        ingress.accept(body(b"9"), None).unwrap().is_none(),
        "over the cap is not a connection error"
    );
    assert!(ingress.accept(body(&[b'x'; 4096]), None).unwrap().is_none());
    let slot = ingress.slots.iter().find(|slot| slot.stream == 1).unwrap();
    assert_eq!(slot.refused, Some(Refusal::BodyTooLarge));
    assert_eq!(
        slot.body.as_ref().map(|body| body.bytes.len()),
        Some(0),
        "nothing of a refused body is held"
    );
    let ready = ingress.accept(Inbound::End(1), None).unwrap().unwrap();
    assert_eq!(ready.refused, Some(Refusal::BodyTooLarge));
}

/// REFUSAL ROW 6, unread: a declared length over the cap completes the request on its head.
/// Body bytes its client still sends are discarded and its end is not a second completion.
#[tokio::test]
async fn a_declared_length_over_the_cap_is_refused_on_the_head() {
    use busbar_kernel::auth::admission_table::Refusal;
    let (mut ingress, source) = ingress_fixture().await;
    ingress.body_limit = 8;
    // A first request tells the cap this connection's requests are read under.
    assert!(ingress
        .accept(public_head(&source, 1, false), None)
        .unwrap()
        .is_none());
    let cap = effective_cap(&ingress, 1);
    let over = (cap as u64 + 1).to_string();
    let ready = ingress
        .accept(
            head_with(&source, 2, "content-length", over.as_bytes()),
            None,
        )
        .unwrap()
        .expect("completed on the head");
    assert_eq!(ready.refused, Some(Refusal::BodyTooLarge));
    let late = Inbound::Body {
        stream: 2,
        flags: 0,
        bytes: payload(&source, b"123456789"),
    };
    assert!(ingress.accept(late, None).unwrap().is_none());
    assert!(ingress.accept(Inbound::End(2), None).unwrap().is_none());
    // At the cap exactly, the request is taken as usual.
    let at = cap.to_string();
    assert!(ingress
        .accept(head_with(&source, 3, "content-length", at.as_bytes()), None)
        .unwrap()
        .is_none());
}
