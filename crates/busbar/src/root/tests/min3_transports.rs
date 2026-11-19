// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W2-SW-TRANSPORT: the transport arm of the MIN-3 boot. The open itself is the walk's generic
//! `Registry::open_transport` (an ffi handle, run by the image suite); these are the seams the boot builds around
//! it: the settings each instance is opened with, the ports the walk hands back, and the D_PROTOCOL table.

use busbar_ports::transport::{ConnIn, TransportEvent, TransportOut, TransportSession};
use busbar_ports::PortError;

use super::*;

/// A framer that declares `protocols` and answers nothing (the table reads only `protocols`).
struct Framer {
    protocols: Box<[Box<str>]>,
    slots: Box<[Box<str>]>,
    alpn: Box<[Box<str>]>,
    facts: u64,
}

pub(crate) fn framer(protocols: &[&str]) -> Arc<dyn TransportPort> {
    Arc::new(Framer {
        protocols: protocols.iter().map(|p| Box::from(*p)).collect(),
        slots: Box::default(),
        alpn: Box::default(),
        facts: 0,
    })
}

fn unanswered() -> PortError {
    PortError::Refused {
        code: 0,
        text: Box::from("a table test framer begins no session"),
        error: None,
    }
}

impl TransportPort for Framer {
    fn listener_slots(&self) -> &[Box<str>] {
        &self.slots
    }
    fn alpn(&self, role: u32) -> &[Box<str>] {
        if role == busbar_plugin_abi::transport::ROLE_SERVER {
            &self.alpn
        } else {
            &[]
        }
    }
    fn defaults(&self, _: u32) -> &[(Box<str>, Box<str>)] {
        &[]
    }
    fn protocols(&self) -> &[Box<str>] {
        &self.protocols
    }
    fn facts(&self) -> u64 {
        self.facts
    }
    fn begin(
        &self,
        _: &ConnIn<'_>,
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<TransportSession, PortError> {
        Err(unanswered())
    }
    fn ingest(
        &self,
        _: &mut TransportSession,
        _: &[u8],
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Err(unanswered())
    }
    fn emit(
        &self,
        _: &mut TransportSession,
        _: u64,
        _: u32,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Err(unanswered())
    }
    fn timer(
        &self,
        _: &mut TransportSession,
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Err(unanswered())
    }
    fn datagram(
        &self,
        _: &mut TransportSession,
        _: u32,
        _: bool,
        _: &[u8],
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Err(unanswered())
    }
    fn event(
        &self,
        _: &mut TransportSession,
        _: TransportEvent<'_>,
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Err(unanswered())
    }
}

fn served(instance: &str, protocols: &[&str]) -> ServedTransport {
    ServedTransport {
        instance: Arc::from(instance),
        port: framer(protocols),
    }
}

fn limits() -> LimitsResolved {
    LimitsResolved {
        upstream_h2_prior_knowledge: true,
        upstream_http1_only: false,
        request_body_max_bytes: 1_048_576,
        upstream_request_timeout_secs: 45,
        ..LimitsResolved::default()
    }
}

fn text(bag: &[u8]) -> &str {
    core::str::from_utf8(bag).expect("the settings bag is UTF-8 JSON")
}

#[test]
fn each_instance_is_dealt_the_deployment_value_of_every_core_path_its_schema_names() {
    let http = r#"{"type":"object","additionalProperties":false,"properties":{
        "advanced.upstream_h2_prior_knowledge":{"type":"boolean"},
        "advanced.upstream_http1_only":{"type":"boolean"},
        "limits.upstream_request_timeout_secs":{"type":"integer"},
        "limits.request_body_max_bytes":{"type":"integer"}}}"#;
    let bag = settings(&limits(), Some(http)).expect("a schema naming the four paths is dealt");
    assert_eq!(
        text(&bag),
        r#"{"advanced.upstream_h2_prior_knowledge":true,"advanced.upstream_http1_only":false,"limits.request_body_max_bytes":1048576,"limits.upstream_request_timeout_secs":45}"#
    );
    let ws =
        r#"{"type":"object","properties":{"limits.request_body_max_bytes":{"type":"integer"}}}"#;
    let bag = settings(&limits(), Some(ws)).expect("a schema naming one path is dealt that one");
    assert_eq!(
        text(&bag),
        r#"{"limits.request_body_max_bytes":1048576}"#,
        "a path the schema does not name is never sent: the framer's grammar refuses unknown keys"
    );
}

#[test]
fn a_path_core_does_not_deal_keeps_the_plugins_default_and_no_schema_is_the_empty_bag() {
    let own = r#"{"type":"object","properties":{"frame_limit":{"type":"integer"}}}"#;
    assert_eq!(text(&settings(&limits(), Some(own)).unwrap()), "{}");
    assert_eq!(text(&settings(&limits(), None).unwrap()), "{}");
    assert_eq!(
        text(&settings(&limits(), Some(r#"{"type":"object"}"#)).unwrap()),
        "{}"
    );
}

#[test]
fn a_schema_that_is_not_an_object_refuses_the_boot() {
    assert!(settings(&limits(), Some("[]")).is_err());
    assert!(settings(&limits(), Some("not json")).is_err());
    assert!(settings(&limits(), Some(r#"{"properties":[]}"#)).is_err());
}

#[test]
fn the_walk_hands_back_each_opened_transport_under_its_instance_name_and_nothing_else() {
    let port = framer(&["websocket"]);
    let config: &[u8] = b"{}";
    let spec = |name: &'static str| InstanceSpec {
        store_migration: None,
        purpose: busbar_plugin_loader::instance::OpenPurpose::Canonical,
        identity: name,
        name,
        config_json: config,
        limits: Default::default(),
        public_url: None,
        caller_upstreams: &[],
    };
    let specs = [
        (KindCode::Plane, spec("plane-a")),
        (KindCode::Transport, spec("transport-ws")),
        (KindCode::Transport, spec("transport-http")),
    ];
    let walked = [
        (0, BootPhase::Rest, None),
        (
            1,
            BootPhase::Rest,
            Some(OpenedPort::Transport(Arc::clone(&port))),
        ),
        (2, BootPhase::Rest, None),
        (9, BootPhase::Rest, Some(OpenedPort::Transport(framer(&[])))),
    ];
    let served = opened(&walked, &specs);
    assert_eq!(served.len(), 1, "a plan index naming no spec is not served");
    assert_eq!(&*served[0].instance, "transport-ws");
    assert!(Arc::ptr_eq(&served[0].port, &port));
}

#[test]
fn an_upgrade_finds_the_one_instance_declaring_its_protocol() {
    let table = table(vec![
        served("transport-http", &[]),
        served("transport-ws", &["websocket"]),
    ])
    .expect("one instance per protocol");
    assert_eq!(
        declaring(&table, "WebSocket").map(|one| &*one.instance),
        Some("transport-ws"),
        "a protocol is compared ASCII case-insensitively"
    );
    assert!(
        declaring(&table, "grpc").is_none(),
        "none declares grpc: 501"
    );
}

#[test]
fn two_instances_declaring_one_protocol_refuse_the_boot_naming_both() {
    let refused = table(vec![
        served("transport-ws", &["websocket"]),
        served("transport-http", &[]),
        served("ws-fork", &["WEBSOCKET"]),
    ])
    .err()
    .expect("two instances answering one upgrade protocol");
    assert!(
        refused.contains("`transport-ws`") && refused.contains("`ws-fork`"),
        "{refused}"
    );
}

/// An opened instance with these describe facts (roles) and nothing declared: the carrier table's fixture.
pub(crate) fn with_facts(instance: &str, facts: u64) -> ServedTransport {
    ServedTransport {
        instance: Arc::from(instance),
        port: Arc::new(Framer {
            protocols: Box::default(),
            slots: Box::default(),
            alpn: Box::default(),
            facts,
        }),
    }
}

pub(crate) fn initial(instance: &str, slots: &[&str]) -> ServedTransport {
    ServedTransport {
        instance: Arc::from(instance),
        port: Arc::new(Framer {
            protocols: Box::default(),
            slots: slots.iter().map(|slot| Box::from(*slot)).collect(),
            alpn: Box::new([Box::from("h2"), Box::from("http/1.1")]),
            facts: busbar_plugin_abi::transport::FB_SERVER,
        }),
    }
}

#[test]
fn native_initial_binding_selects_the_exact_declaring_instance_and_server_offer() {
    use crate::root::min3_framers::NativeFramers;
    let one = initial("independent-publisher", &["listen", "future_slot"]);
    let port = Arc::clone(&one.port);
    let framers = NativeFramers::new(vec![served("upgrade-only", &["listen"]), one]);
    let selected = framers.for_slot("listen").expect("explicit supplier");
    assert_eq!(selected.instance.as_ref(), "independent-publisher");
    assert!(Arc::ptr_eq(&selected.port, &port));
    assert_eq!(
        selected
            .port
            .alpn(busbar_plugin_abi::transport::ROLE_SERVER),
        [Box::<str>::from("h2"), Box::from("http/1.1")]
    );
    assert!(framers.for_slot("Listen").is_err(), "slots are exact");
}

#[test]
fn missing_and_duplicate_native_initial_suppliers_refuse_without_order_fallback() {
    use crate::root::min3_framers::NativeFramers;
    assert!(NativeFramers::new(vec![
        initial("server-only", &[]),
        served("protocol-only", &["listen"])
    ])
    .for_slot("listen")
    .is_err());
    for names in [["first", "second"], ["second", "first"]] {
        let framers = NativeFramers::new(
            names
                .into_iter()
                .map(|name| initial(name, &["listen"]))
                .collect(),
        );
        let error = framers
            .for_slot("listen")
            .err()
            .expect("ambiguous slot refused");
        assert!(error.contains("`first`") && error.contains("`second`"));
    }
}

#[test]
fn replacing_native_framers_keeps_the_selected_old_generation_alive() {
    use crate::root::min3_framers::NativeFramers;
    let old = initial("old-supplier", &["listen"]);
    let weak = Arc::downgrade(&old.port);
    let current = NativeFramers::new(vec![old]);
    let accepted = current.clone();
    drop(current);
    let replacement = NativeFramers::new(vec![initial("new-supplier", &["listen"])]);
    assert_eq!(
        accepted
            .for_slot("listen")
            .expect("old generation")
            .instance
            .as_ref(),
        "old-supplier"
    );
    assert_eq!(
        replacement
            .for_slot("listen")
            .expect("new generation")
            .instance
            .as_ref(),
        "new-supplier"
    );
    assert!(weak.upgrade().is_some());
    drop(accepted);
    assert!(weak.upgrade().is_none());
}
