//! Tests for `transports.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_unit_transport_key::AccessPurpose;
use std::collections::HashMap;
use std::sync::Mutex;

/// A secret source over an in-memory map. The deployment's real resolver is the secret plugin;
/// what matters for these tests is that it is A source and the unit reads through it.
struct MapSource(HashMap<String, Vec<u8>>);

impl SecretSource for MapSource {
    fn resolve(&self, location: &str) -> Result<Vec<u8>, String> {
        self.0
            .get(location)
            .cloned()
            .ok_or_else(|| format!("no such secret: {location}"))
    }
}

/// A journal that keeps what it was told, so a test can assert what was read and why.
#[derive(Default)]
struct RecordingJournal(Mutex<Vec<(String, AccessPurpose)>>);

impl AccessJournal for RecordingJournal {
    fn record_access(&self, location: &str, purpose: AccessPurpose) {
        self.0
            .lock()
            .expect("journal lock")
            .push((location.to_string(), purpose));
    }
}

/// A sink that records which slot each config landed in, standing in for the TLS transport.
#[derive(Default)]
struct RecordingSink {
    server: Mutex<Vec<u64>>,
    client: Mutex<Vec<u64>>,
}

impl TlsConfigSink for RecordingSink {
    fn register_server_config(&self, slot: u64, _cfg: Arc<rustls::ServerConfig>) {
        self.server.lock().expect("sink lock").push(slot);
    }

    fn register_client_config(&self, slot: u64, _cfg: Arc<rustls::ClientConfig>) {
        self.client.lock().expect("sink lock").push(slot);
    }
}

/// A fresh self-signed keypair, as PEM, plus the client trust store that trusts exactly it.
fn self_signed() -> (Vec<u8>, Vec<u8>, Arc<rustls::ClientConfig>) {
    busbar_unit_transport_key::install_crypto_provider();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("a self-signed pair");
    let cert_pem = cert.pem().into_bytes();
    let key_pem = signing_key.serialize_pem().into_bytes();

    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for der in rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem) {
        roots.add(der.expect("a certificate")).expect("a root");
    }
    let client = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    (cert_pem, key_pem, client)
}

fn two_listeners(cert: &str, key: &str) -> Vec<ListenerConfig> {
    vec![
        ListenerConfig {
            role: ListenerRole::Data,
            bind: "127.0.0.1:0".into(),
            tls: Some(TlsMaterialRefs {
                cert: cert.into(),
                key: key.into(),
                client_ca: None,
            }),
            fingerprint: "data-listener",
        },
        ListenerConfig {
            role: ListenerRole::Admin,
            bind: "127.0.0.1:0".into(),
            tls: Some(TlsMaterialRefs {
                cert: cert.into(),
                key: key.into(),
                client_ca: None,
            }),
            fingerprint: "operator-listener",
        },
    ]
}

/// Slots are stable and named. The administrative listener is slot 1 on every node, so a
/// journal entry naming a slot means the same thing on the next boot and on the next node.
#[test]
fn the_slot_allocation_is_fixed_and_stable() {
    assert_eq!(ListenerRole::Data.slot_index(), 0);
    assert_eq!(ListenerRole::Admin.slot_index(), 1);
    assert_eq!(ListenerRole::Additional(0).slot_index(), 2);
    assert_eq!(ListenerRole::Additional(3).slot_index(), 5);
}

/// The whole path, on a real self-signed pair: two listeners provisioned, two configs landing
/// in their own slots, and the handles carrying those slots back.
#[test]
fn two_listeners_provision_into_their_own_slots() {
    let (cert_pem, key_pem, _) = self_signed();
    let source = MapSource(HashMap::from([
        ("cert-ref".to_string(), cert_pem),
        ("key-ref".to_string(), key_pem),
    ]));
    let journal = RecordingJournal::default();
    let sink = RecordingSink::default();
    let token = crate::root::kernel::new_kernel().transport_key_token();

    let listeners = two_listeners("cert-ref", "key-ref");
    let provisioned = provision_servers(&listeners, &source, &journal, &sink, &token)
        .expect("a self-signed pair resolves and parses");

    assert_eq!(provisioned.len(), 2);
    assert_eq!(provisioned[0].handle.slot(), 0);
    assert_eq!(provisioned[1].handle.slot(), 1);
    assert_eq!(*sink.server.lock().expect("sink lock"), vec![0, 1]);
}

/// Every secret actually read gets an access entry, naming WHY it was read. That is what makes
/// "the secret plugin is read here and nowhere else" a thing anybody can check afterwards.
#[test]
fn every_secret_read_is_journaled_with_its_purpose() {
    let (cert_pem, key_pem, _) = self_signed();
    let source = MapSource(HashMap::from([
        ("cert-ref".to_string(), cert_pem),
        ("key-ref".to_string(), key_pem),
    ]));
    let journal = RecordingJournal::default();
    let sink = RecordingSink::default();
    let token = crate::root::kernel::new_kernel().transport_key_token();

    provision_servers(
        &two_listeners("cert-ref", "key-ref"),
        &source,
        &journal,
        &sink,
        &token,
    )
    .expect("a self-signed pair resolves and parses");

    let entries = journal.0.lock().expect("journal lock").clone();
    // Two listeners, each reading a certificate and a key, and neither reading a client CA
    // because neither declared mutual TLS.
    assert_eq!(entries.len(), 4);
    assert_eq!(
        entries
            .iter()
            .filter(|(_, p)| *p == AccessPurpose::Cert)
            .count(),
        2
    );
    assert_eq!(
        entries
            .iter()
            .filter(|(_, p)| *p == AccessPurpose::Key)
            .count(),
        2
    );
    assert!(entries
        .iter()
        .all(|(loc, _)| loc == "cert-ref" || loc == "key-ref"));
}

/// A listener with no configured material is not a failure and reads no secret: a listener
/// behind a terminating proxy has nothing of its own to resolve. It still gets a handle, so the
/// transport is bound the same way either side of that choice.
#[test]
fn a_plain_listener_reads_no_secret_and_still_gets_a_handle() {
    let source = MapSource(HashMap::new());
    let journal = RecordingJournal::default();
    let sink = RecordingSink::default();
    let token = crate::root::kernel::new_kernel().transport_key_token();

    let listeners = vec![ListenerConfig {
        role: ListenerRole::Data,
        bind: "127.0.0.1:0".into(),
        tls: None,
        fingerprint: "plain-listener",
    }];
    let provisioned = provision_servers(&listeners, &source, &journal, &sink, &token)
        .expect("a plain listener needs nothing resolved");

    assert_eq!(provisioned.len(), 1);
    assert_eq!(provisioned[0].handle.slot(), 0);
    assert!(journal.0.lock().expect("journal lock").is_empty());
    assert!(sink.server.lock().expect("sink lock").is_empty());
}

/// A material reference the source cannot resolve is an error the operator sees, and the
/// message names the SOURCE rather than anything about the bytes it failed to produce.
#[test]
fn an_unresolvable_reference_names_the_source_and_not_the_bytes() {
    let source = MapSource(HashMap::new());
    let journal = RecordingJournal::default();
    let sink = RecordingSink::default();
    let token = crate::root::kernel::new_kernel().transport_key_token();

    let err = provision_servers(
        &two_listeners("missing-cert", "missing-key"),
        &source,
        &journal,
        &sink,
        &token,
    )
    .expect_err("nothing resolves");
    assert!(err.contains("missing-cert"), "the message names the source");
}

/// The dial side: a client config lands in its slot, and nothing is journaled, because a public
/// root store is not a secret.
#[test]
fn the_dial_side_registers_a_config_and_journals_nothing() {
    let (_, _, client_cfg) = self_signed();
    let sink = RecordingSink::default();
    let token = crate::root::kernel::new_kernel().transport_key_token();

    let handle = provision_dial(
        &sink,
        &token,
        ListenerRole::Data,
        "upstream-roots",
        client_cfg,
    );

    assert_eq!(handle.slot(), 0);
    assert_eq!(*sink.client.lock().expect("sink lock"), vec![0]);
}

/// The whole seam, against the real TLS transport rather than a recording double: the material
/// is resolved through the secret source, lands in the transport's own slot, and the listener
/// binds against the handle. Before this existed the only thing that ever registered a config
/// was the transport's own tests, so a production listener had no key at all.
#[test]
fn a_listener_binds_through_the_transport_it_was_provisioned_into() {
    let (cert_pem, key_pem, _) = self_signed();
    let source = MapSource(HashMap::from([
        ("cert-ref".to_string(), cert_pem),
        ("key-ref".to_string(), key_pem),
    ]));
    let journal = RecordingJournal::default();
    let tls = busbar_transport_tls::TlsTransport::new();
    let token = crate::root::kernel::new_kernel().transport_key_token();

    let listeners = vec![ListenerConfig {
        role: ListenerRole::Data,
        bind: "127.0.0.1:0".into(),
        tls: Some(TlsMaterialRefs {
            cert: "cert-ref".into(),
            key: "key-ref".into(),
            client_ca: None,
        }),
        fingerprint: "data-listener",
    }];
    let provisioned = provision_servers(&listeners, &source, &journal, &tls, &token)
        .expect("a self-signed pair resolves and parses");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let bound = runtime
        .block_on(listen_all(&tls, &provisioned, 1024))
        .expect("the listener binds against its own slot");
    assert_eq!(bound.len(), 1);
}

/// The view a transport is handed answers the one question it may ask and refuses the rest. A
/// transport that could read arbitrary configuration keys would be a transport that could learn
/// what a plane or a unit is for.
#[test]
fn the_listener_view_offers_the_address_and_nothing_else() {
    let view = ListenerView::new("127.0.0.1:8080", 1024);
    assert_eq!(view.bind(), Some("127.0.0.1:8080"));
    assert_eq!(view.get_str("cert"), None);
    assert_eq!(view.get_int("port"), None);
    assert_eq!(view.get_bool("tls"), None);
}

/// And the one key it DOES answer is the message ceiling, because a transport that assembles a
/// message before anything above it can see a byte has no other place to learn the number.
///
/// The `ws` transport reads this at `listen`. A view that answered `None` for it would leave
/// the ceiling at the WebSocket library's own default — 64 MiB, a number this project never
/// chose — while the operator's configuration said something four orders of magnitude smaller,
/// and every other listener on the node honoured it. That is not a refusal to disclose: it is a
/// limit the node states everywhere else silently not applying here.
#[cfg(feature = "plane-voice")]
#[test]
fn the_listener_view_answers_the_operators_message_ceiling() {
    const CAP: usize = 1024;
    let view = ListenerView::new("127.0.0.1:8080", CAP);
    assert_eq!(
        view.get_int(MESSAGE_MAX_BYTES_KEY),
        Some(CAP as i64),
        "a transport that asks for the operator's cap must be told it, not left on a default"
    );
    // Still nothing else. The ceiling is one answer, not an opening.
    assert_eq!(view.get_int("limits.request_body_max_bytes.other"), None);
    assert_eq!(view.get_int("port"), None);
    assert_eq!(view.bind(), Some("127.0.0.1:8080"));
}

/// The handle carries a slot and a fingerprint, and its debug output says as much rather than
/// printing anything derived from what was resolved.
#[test]
fn the_handle_carries_no_material() {
    let token = crate::root::kernel::new_kernel().transport_key_token();
    let handle = busbar_unit_transport_key::issue_handle(&token, 1, "operator-listener");
    let rendered = format!("{handle:?}");
    assert!(
        rendered.contains("no material"),
        "the handle's debug output should say it carries none: {rendered}"
    );
}

// ── the driver, over a real plane ───────────────────────────────────────────────────────────────

/// The whole driver, assembled the way a listener is handed one.
///
/// Gated on the plane feature as well as the root one because the fixture NAMES a plane, and a
/// build without that plane has no bytes for it to mean. The driver itself names none: what the
/// test hands it is a `&dyn Plane`, and that is the property the assertions below turn on.
#[cfg(all(feature = "root-admin", feature = "plane-a2a"))]
mod driver {
    use busbar_contract::transport::surface::{Answering, Bar};
    use busbar_contract::transport::{Arrival, Outcome, UnitDriver};

    use crate::root::kernel::ProductionUnits;
    use crate::root::transports::LoopDriver;

    /// The facts an HTTP mount publishes for a posted document, in the order it publishes them.
    const FACTS: &[(&str, &str)] = &[
        ("path", "/a2a"),
        ("method", "POST"),
        ("peer", "203.0.113.9:52000"),
    ];

    const CHAIN: &[&str] = &["tcp", "http"];

    /// Everything a listener holds, in one value, so a test reads like a composition and not like a
    /// constructor.
    struct Node {
        kernel: busbar_kernel::teller::Kernel,
        units: ProductionUnits,
        gauge: busbar_kernel::slice::ConcurrencyGauge,
        canary: busbar_caps::Canary,
    }

    impl Node {
        fn new() -> Self {
            Node {
                kernel: crate::root::kernel::new_kernel(),
                units: ProductionUnits::admin_only(std::sync::Arc::new(
                    crate::root::units_admin::RefusingDispatch,
                )),
                gauge: busbar_kernel::slice::ConcurrencyGauge::new(),
                canary: busbar_caps::Canary::new(),
            }
        }

        fn driver<'n>(&'n self, plane: &'n dyn busbar_contract::Plane) -> LoopDriver<'n> {
            LoopDriver::new(&self.kernel, &self.units, &self.gauge, &self.canary, plane)
        }
    }

    fn arrival<'a>(
        body: &'a [u8],
        operation: Option<&'a busbar_contract::transport::surface::Operation>,
    ) -> Arrival<'a> {
        Arrival {
            facts: FACTS,
            body,
            transport: "http",
            chain: CHAIN,
            operation,
            bar: Bar::Credential,
        }
    }

    /// THE BYTES THAT LEAVE ARE THE PLANE'S.
    ///
    /// The driver used to answer every arrival with nothing at all, because it could not build a
    /// context to ask a plane with. It can now, and what comes back is the plane's own refusal
    /// document — carrying the CALLER'S OWN request identifier, which is the part that proves the
    /// plane read the arriving bytes rather than being handed a shape the driver made up.
    ///
    /// The ending is the loop's. This root composes no A2A steps yet, so the unit really does end
    /// at the first step, and what is asserted is that the outcome the transport frames is the one
    /// the loop reached.
    #[test]
    fn the_driver_answers_with_the_planes_own_bytes() {
        let node = Node::new();
        let plane = busbar_plane_a2a::A2aPlane::EMPTY;
        let driver = node.driver(&plane);
        let body = br#"{"jsonrpc":"2.0","id":"req-7","method":"message/send","params":{}}"#;
        let answer = driver.drive(arrival(body, None), &busbar_plane_a2a::surface::SURFACE);

        let rendered = String::from_utf8(answer.body.clone()).expect("the plane wrote text");
        assert!(
            rendered.contains("\"jsonrpc\""),
            "the answer is this plane's own envelope: {rendered}"
        );
        assert!(
            rendered.contains("req-7"),
            "the plane read the caller's identifier off the arriving bytes: {rendered}"
        );
        assert!(
            rendered.contains("\"error\""),
            "a unit this root composes no steps for is refused, and the plane renders the \
             refusal: {rendered}"
        );
        assert_eq!(
            answer.outcome,
            Outcome::NotFound,
            "the loop refused at its first step for want of a destination, and that is the word \
             the transport frames"
        );
    }

    /// A body this plane cannot read still gets this plane's answer, and no identifier is invented
    /// for it.
    ///
    /// The two halves matter separately. The plane is still asked — a refusal document is the
    /// plane's to write whether or not it could read the request — and the identifier it would have
    /// echoed is absent, because there was no draft to read one off. A driver that carried a draft
    /// forward from a failed decode would be answering a caller about a request it never sent.
    #[test]
    fn an_unreadable_body_is_answered_without_an_invented_identifier() {
        let node = Node::new();
        let plane = busbar_plane_a2a::A2aPlane::EMPTY;
        let driver = node.driver(&plane);
        let answer = driver.drive(
            arrival(b"not a document", None),
            &busbar_plane_a2a::surface::SURFACE,
        );
        let rendered = String::from_utf8(answer.body.clone()).expect("the plane wrote text");
        assert!(
            rendered.contains("\"error\""),
            "the plane renders the refusal: {rendered}"
        );
        assert!(
            !rendered.contains("req-7"),
            "no draft, so no identifier is echoed: {rendered}"
        );
    }

    /// The media type and the answer's shape come off the DECLARATION, and are absent where the
    /// arrival addressed a mount rather than a route.
    ///
    /// Absent is the honest answer and not a gap: no declaration named a media type for a document
    /// mount, because on a document mount it is the plane that names the operation, out of bytes
    /// the transport does not read. A driver that guessed one would put a content type on an answer
    /// nobody declared.
    #[test]
    fn the_frame_around_the_bytes_is_the_declarations() {
        let node = Node::new();
        let plane = busbar_plane_a2a::A2aPlane::EMPTY;
        let driver = node.driver(&plane);

        let unaddressed = driver.drive(arrival(b"{}", None), &busbar_plane_a2a::surface::SURFACE);
        assert_eq!(unaddressed.media, "");
        assert_eq!(unaddressed.answering, Answering::Unary);

        let operation = busbar_plane_a2a::surface::SURFACE
            .operations
            .first()
            .expect("the plane declares at least one operation");
        let addressed = driver.drive(
            arrival(b"{}", Some(operation)),
            &busbar_plane_a2a::surface::SURFACE,
        );
        assert_eq!(
            addressed.media, operation.response_media,
            "the media type is the one the declaration names for this operation's answer"
        );
        assert_eq!(addressed.answering, operation.answering);
    }

    /// Two arrivals are two units, and nothing is carried between them.
    ///
    /// One driver serves every connection a listener accepts. A per-unit value that survived its
    /// unit — the arena above all — would be one connection's bytes reachable from another's, so
    /// the same request twice has to reach the same ending twice.
    #[test]
    fn each_arrival_is_its_own_unit() {
        let node = Node::new();
        let plane = busbar_plane_a2a::A2aPlane::EMPTY;
        let driver = node.driver(&plane);
        let body = br#"{"jsonrpc":"2.0","id":"req-7","method":"message/send","params":{}}"#;
        let first = driver.drive(arrival(body, None), &busbar_plane_a2a::surface::SURFACE);
        let second = driver.drive(arrival(body, None), &busbar_plane_a2a::surface::SURFACE);
        assert_eq!(first, second);
    }
}

// ── the seam: what the driver walks an arrival against ──────────────────────────────────────────

/// THE ONE SEAM between the driver and a plane's units, driven both ways.
///
/// The driver used to hold the node's units by name. It holds a `&dyn PlaneLeg` now, and these
/// tests are what says the widening is real rather than cosmetic: a leg written here, over units
/// this file spells, reaches the loop through the same call the node's own units reach it through,
/// and the ending it produces is what the transport frames.
///
/// The fixture is deliberately NOT the A2A leg. A test that could only be written against one plane
/// would be a test of that plane; what is under test is the seam, so the leg is a leg and nothing
/// else, and the property it proves holds for every leg that ever mounts.
#[cfg(all(feature = "root-admin", feature = "plane-a2a"))]
mod leg {
    use busbar_caps::{
        Admission, Admit, AdmitToken, Approve, Arrival as ArrivalStep, Audit, Authenticate,
        Authenticated, Decision, Decode, Encode, Hold, Meter, Outcome, PrincipalId, ReasonCode,
        Refusal, Route, StepName, UnitToken, Usage, UsageToken, VerifiedDestination, Verify,
    };
    use busbar_contract::transport::{Arrival, UnitDriver};
    use busbar_kernel::teller::{AccrualMeter, Evidence, UnitCtx, Units};
    use std::sync::Mutex;

    use crate::root::transports::{LoopDriver, PlaneLeg};

    /// A leg whose units run every step, note that they ran, and refuse at one named step.
    ///
    /// The step names are the assertion. A refusal is not only "the unit ended badly" — it is "the
    /// unit ended THERE", and a loop that ran the meter after a verify that refused would be
    /// charging for a destination it had just said was unreachable. So the log is what is read, and
    /// the ending is read beside it.
    #[derive(Default)]
    struct Noting {
        ran: Mutex<Vec<StepName>>,
        refuse_at: Option<(StepName, ReasonCode)>,
    }

    impl Noting {
        /// A leg that refuses nothing.
        fn passing() -> Self {
            Noting::default()
        }

        /// A leg whose named step answers with a refusal.
        fn refusing_at(step: StepName, reason: ReasonCode) -> Self {
            Noting {
                ran: Mutex::new(Vec::new()),
                refuse_at: Some((step, reason)),
            }
        }

        fn note(&self, step: StepName) {
            self.ran.lock().expect("a test lock").push(step);
        }

        fn refusal(&self, step: StepName) -> Option<Refusal> {
            self.refuse_at
                .as_ref()
                .filter(|(at, _)| *at == step)
                .map(|(_, reason)| Refusal::new(*reason))
        }

        fn ran(&self) -> Vec<StepName> {
            self.ran.lock().expect("a test lock").clone()
        }
    }

    macro_rules! step {
        ($self:ident, $token:ident, $marker:ty, $name:expr, $facts:expr) => {{
            $self.note($name);
            match $self.refusal($name) {
                Some(refusal) => Decision::<$marker>::refuse($token, refusal),
                None => Decision::<$marker>::proceed($token, $facts),
            }
        }};
    }

    impl Units for Noting {
        fn arrival(&self, token: &UnitToken<ArrivalStep>, _ctx: &UnitCtx) -> Decision<ArrivalStep> {
            step!(
                self,
                token,
                ArrivalStep,
                StepName::Arrival,
                busbar_caps::ArrivalRecord {
                    source: "203.0.113.9:52000".into(),
                    port: 52_000,
                    alpn: None,
                    sni: None,
                    peer_cert: None,
                    transport_chain: vec!["http"],
                }
            )
        }

        fn decode(&self, token: &UnitToken<Decode>, _ctx: &UnitCtx) -> Decision<Decode> {
            step!(
                self,
                token,
                Decode,
                StepName::Decode,
                busbar_caps::OpClassId::new("seam")
            )
        }

        fn authenticate(
            &self,
            token: &UnitToken<Authenticate>,
            _ctx: &UnitCtx,
        ) -> Decision<Authenticate> {
            step!(
                self,
                token,
                Authenticate,
                StepName::Authenticate,
                Authenticated::Principal(PrincipalId::new("caller"))
            )
        }

        fn verify(
            &self,
            token: &UnitToken<Verify>,
            trust: &busbar_caps::TrustToken,
            _ctx: &UnitCtx,
            _principal: &PrincipalId,
        ) -> Decision<Verify> {
            self.note(StepName::Verify);
            match self.refusal(StepName::Verify) {
                Some(refusal) => Decision::refuse(token, refusal),
                None => Decision::proceed(
                    token,
                    vec![VerifiedDestination::seal(
                        trust,
                        busbar_caps::LaneId::new("seam:lane"),
                    )],
                ),
            }
        }

        fn approve(
            &self,
            token: &UnitToken<Approve>,
            _ctx: &UnitCtx,
            _principal: &PrincipalId,
            _destinations: &[VerifiedDestination],
        ) -> Decision<Approve> {
            step!(
                self,
                token,
                Approve,
                StepName::Approve,
                busbar_caps::ScopeFacts::default()
            )
        }

        fn admit(
            &self,
            token: &UnitToken<Admit>,
            admit: &AdmitToken<Admit>,
            _ctx: &UnitCtx,
            principal: &PrincipalId,
            _destinations: &[VerifiedDestination],
            _leases: &busbar_kernel::slice::GroupLeaseSlip,
        ) -> Decision<Admit> {
            step!(
                self,
                token,
                Admit,
                StepName::Admit,
                Admission::Own(Hold::open(admit, principal.clone(), 0))
            )
        }

        fn route(
            &self,
            token: &UnitToken<Route>,
            _ctx: &UnitCtx,
            _meter: &AccrualMeter,
        ) -> Decision<Route> {
            step!(
                self,
                token,
                Route,
                StepName::Route,
                busbar_caps::RoutePlan::default()
            )
        }

        fn meter(
            &self,
            token: &UnitToken<Meter>,
            usage: &UsageToken,
            _ctx: &UnitCtx,
            _provisional: &Outcome,
        ) -> Decision<Meter> {
            step!(
                self,
                token,
                Meter,
                StepName::Meter,
                Usage::report(usage, Vec::new()).expect("an empty report is within the bound")
            )
        }

        fn audit(
            &self,
            token: &UnitToken<Audit>,
            _ctx: &UnitCtx,
            _outcome: &Outcome,
        ) -> Decision<Audit> {
            self.note(StepName::Audit);
            Decision::proceed(token, audit_facts())
        }

        fn audit_refused(
            &self,
            token: &UnitToken<Audit>,
            _ctx: &UnitCtx,
            _refusal: &Refusal,
        ) -> Decision<Audit> {
            self.note(StepName::Audit);
            Decision::proceed(token, audit_facts())
        }

        fn encode(
            &self,
            token: &UnitToken<Encode>,
            _ctx: &UnitCtx,
            _outcome: &Outcome,
        ) -> Decision<Encode> {
            step!(
                self,
                token,
                Encode,
                StepName::Encode,
                busbar_caps::Frame {
                    direction: busbar_contract::Direction::Outbound,
                    stream: busbar_contract::StreamId(0),
                    bytes: busbar_contract::SlabBytes::new(std::sync::Arc::from(&b"{}"[..])),
                    meta: busbar_contract::FrameMeta::default(),
                }
            )
        }

        fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
            Evidence::default()
        }
    }

    fn audit_facts() -> busbar_caps::AuditFacts {
        busbar_caps::AuditFacts {
            op_class: busbar_caps::OpClassId::new("seam"),
            finish: busbar_contract::FinishClass::Complete,
        }
    }

    /// Everything a listener holds, minus the units — those are the leg's.
    struct Node {
        kernel: busbar_kernel::teller::Kernel,
        gauge: busbar_kernel::slice::ConcurrencyGauge,
        canary: busbar_caps::Canary,
    }

    impl Node {
        fn new() -> Self {
            Node {
                kernel: crate::root::kernel::new_kernel(),
                gauge: busbar_kernel::slice::ConcurrencyGauge::new(),
                canary: busbar_caps::Canary::new(),
            }
        }

        fn driver<'n>(
            &'n self,
            leg: &'n dyn PlaneLeg,
            plane: &'n dyn busbar_contract::Plane,
        ) -> LoopDriver<'n> {
            LoopDriver::new(&self.kernel, leg, &self.gauge, &self.canary, plane)
        }
    }

    const FACTS: &[(&str, &str)] = &[("path", "/seam"), ("method", "POST")];
    const CHAIN: &[&str] = &["tcp", "http"];

    fn arrival(body: &[u8]) -> Arrival<'_> {
        Arrival {
            facts: FACTS,
            body,
            transport: "http",
            chain: CHAIN,
            operation: None,
            bar: busbar_contract::transport::surface::Bar::Credential,
        }
    }

    /// A LEG WHOSE STEP ANSWER IS REFUSE ENDS THE UNIT AS REFUSED.
    ///
    /// The point of the seam is that the leg DECIDES and the driver reports. So a leg that refuses
    /// at Approve — the caller's credential was accepted and does not cover this — must produce a
    /// unit that ended refused at Approve, and the driver must frame that as forbidden rather than
    /// as anything of its own. A driver that reached its own verdict would answer the same word for
    /// a leg that passed, which is the failure this pins.
    #[test]
    fn a_leg_that_refuses_a_step_ends_the_unit_refused_at_that_step() {
        let node = Node::new();
        let plane = busbar_plane_a2a::A2aPlane::EMPTY;
        let leg = Noting::refusing_at(StepName::Approve, ReasonCode::ScopeDenied);
        let driver = node.driver(&leg, &plane);
        let answer = driver.drive(arrival(b"{}"), &busbar_plane_a2a::surface::SURFACE);
        assert_eq!(
            answer.outcome,
            busbar_contract::transport::Outcome::Forbidden,
            "the leg refused at Approve and the transport frames the leg's word, not the driver's"
        );
        let ran = leg.ran();
        assert!(
            ran.contains(&StepName::Approve),
            "the refusing step ran: {ran:?}"
        );
        assert!(
            !ran.contains(&StepName::Admit) && !ran.contains(&StepName::Route),
            "nothing after the refusal ran: {ran:?}"
        );
        assert!(
            ran.contains(&StepName::Audit),
            "and it still left through the refused audit door: {ran:?}"
        );
    }

    /// A UNIT WHOSE DESTINATION IS UNREACHABLE NEVER REACHES THE METER.
    ///
    /// The Verify step is where a plane says where a unit may go, and a draft whose destination the
    /// plane calls unreachable is refused there. What must be true after that refusal is that
    /// NOTHING PRICED IT: the meter step is what folds a usage report, and a unit that had no
    /// destination consumed nothing, so a meter that ran would be pricing a hop that never happened.
    ///
    /// This is the money property of the seam and it is asserted on the log rather than on a figure,
    /// because a figure of zero is what a meter that ran and found nothing also reports — and those
    /// two are not the same fact.
    #[test]
    fn an_unreachable_destination_never_reaches_the_meter() {
        let node = Node::new();
        let plane = busbar_plane_a2a::A2aPlane::EMPTY;
        let leg = Noting::refusing_at(StepName::Verify, ReasonCode::NoDestination);
        let driver = node.driver(&leg, &plane);
        let answer = driver.drive(arrival(b"{}"), &busbar_plane_a2a::surface::SURFACE);
        assert_eq!(
            answer.outcome,
            busbar_contract::transport::Outcome::Forbidden,
            "a unit refused at Verify is told its credential was accepted and does not cover this \
             — the step decides the word, never the reason, which is the split `outcome_of` keeps"
        );
        let ran = leg.ran();
        assert!(
            !ran.contains(&StepName::Meter),
            "the meter never ran for a unit that reached nowhere: {ran:?}"
        );
        assert!(
            !ran.contains(&StepName::Route),
            "and neither did the route step: {ran:?}"
        );
    }

    /// A LEG THAT PASSES EVERY STEP COMPLETES, AND ANSWERS WITH WHAT ITS OWN ENCODE STEP WROTE.
    ///
    /// The other half of the same seam. Without this the two refusal tests above would pass against
    /// a driver that refused everything, which is exactly the driver the widening replaced.
    #[test]
    fn a_leg_that_passes_every_step_completes_with_its_own_bytes() {
        let node = Node::new();
        let plane = busbar_plane_a2a::A2aPlane::EMPTY;
        let leg = Noting::passing();
        let driver = node.driver(&leg, &plane);
        let answer = driver.drive(arrival(b"{}"), &busbar_plane_a2a::surface::SURFACE);
        assert_eq!(
            answer.outcome,
            busbar_contract::transport::Outcome::Completed,
            "every step passed, so the unit completed"
        );
        assert_eq!(
            answer.body, b"{}",
            "the bytes that leave are the ones the leg's own Encode step wrote"
        );
        let ran = leg.ran();
        assert!(
            ran.contains(&StepName::Meter) && ran.contains(&StepName::Encode),
            "the whole chain ran: {ran:?}"
        );
    }

    /// THE NODE'S OWN UNITS ARE A LEG WITHOUT BEING TOLD SO.
    ///
    /// The blanket implementation is the compatibility half of the widening, and this is what says
    /// it holds: `ProductionUnits` is passed where a `&dyn PlaneLeg` is expected, with no adapter
    /// written at the call site, and the ending is the one it always produced.
    #[test]
    fn the_nodes_own_units_are_a_leg_with_no_adapter() {
        let node = Node::new();
        let units = crate::root::kernel::ProductionUnits::admin_only(std::sync::Arc::new(
            crate::root::units_admin::RefusingDispatch,
        ));
        let plane = busbar_plane_a2a::A2aPlane::EMPTY;
        let driver = node.driver(&units, &plane);
        let answer = driver.drive(arrival(b"{}"), &busbar_plane_a2a::surface::SURFACE);
        assert_eq!(
            answer.outcome,
            busbar_contract::transport::Outcome::NotFound,
            "a unit on a plane this root composes no steps for is refused for want of a destination"
        );
    }
}
