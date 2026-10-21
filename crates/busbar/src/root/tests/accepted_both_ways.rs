// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ACCEPTED DATA DOOR ANSWERS ALIKE, BOTH WAYS (status row 192 C; `BUSBAR-1.6.0.md`
//! l.475-484 and l.896-906: the connector owns every listener, bound to one transport; customer
//! bytes stay 1.5.5's).
//!
//! One corpus of requests, sent over real sockets to listeners bound in this process over one data
//! router, one generation and one guest list:
//!
//! * through the data listener's framer LINKED and through the same framer's dropped-in `cdylib`
//!   (found by its facts, never by its name), each listener bound framed and served by the accepted
//!   data door: the bytes are equal;
//! * through the hand-up (each socket handed up to the kernel's hyper loop, the old path) and
//!   through the linked framer (the new path): the bytes are equal.
//!
//! The `date` field's value is masked; every other byte is compared, the status line first.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use busbar_core_connector::compose::Via;
use busbar_core_connector::framer::FramerDoor;
use busbar_core_connector::listen::{AcceptLimits, Listening};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The router's body cap in these cells.
const CAP: usize = 1 << 20;

/// How long one exchange may take before what was read is compared.
const EXCHANGE_BOUND: Duration = Duration::from_secs(20);

/// One served generation: the data router, its handle, the connector the listeners bind through,
/// and the carrier they ride.
struct Rig {
    router: axum::Router,
    handle: Arc<busbar_kernel::state::AppHandle>,
    connector: Arc<busbar_core_connector::Connector>,
    via: Via,
}

/// The rig: a test app's data router with no door plane, the data listener's list of the kernel's
/// own lines and its residual line staged and published for the inbound auth handle, and a
/// connector over this build's linked transport doors on the process's dispatcher.
fn rig() -> Rig {
    let app = busbar_kernel::test_support::TestApp::new().build();
    let (router, _admin, handle) = busbar_kernel::build_split_routers_serving_doors(
        Arc::clone(&app),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        CAP,
        0,
        false,
    );
    crate::root::serve::stage_lines(
        &[],
        &busbar_kernel::base_data_core_lines(&app),
        &busbar_kernel::base_data_plugin_lines(&app),
        &[],
        &[],
    )
    .expect("the data listener's lines seal");
    let dispatcher = crate::root::doors::dispatcher();
    crate::root::connector::install_io(dispatcher);
    let _ = crate::root::inbound::install(dispatcher);
    crate::root::inbound::publish(&handle.load()).expect("the generation is published");
    let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
        block_private_addresses: false,
        ..Default::default()
    })
    .expect("the guard");
    let connector = busbar_core_connector::process::build(
        || {
            crate::root::connector::entries(
                crate::LINKED_TRANSPORT_DOORS,
                &busbar_contract::transport::TransportSettings::default(),
            )
        },
        judge,
        &[],
        Arc::new(|_, _| {}),
        busbar_core_connector::pool::PoolPosture::NONE,
    )
    .expect("the connector builds");
    let via = connector
        .address_via()
        .expect("a linked carrier serves the data address");
    Rig {
        router,
        handle,
        connector,
        via,
    }
}

impl Rig {
    /// The data listener's framer among this build's linked transports, found by its facts.
    fn linked_framer(&self) -> Arc<dyn FramerDoor> {
        let claims = crate::root::serve::transport_claims(crate::LINKED.transports, &[]);
        crate::root::boot::data_door_framer(claims, |c| self.connector.framer_for(c))
            .expect("this build links the data listener's framer")
    }

    /// The same framer's dropped-in `cdylib`, found by its facts beside this test binary, loaded
    /// on the process's dispatcher and opened as a dropped-in transport is.
    fn dropped_framer(&self, linked: &dyn FramerDoor) -> Arc<dyn FramerDoor> {
        let key = linked
            .facts()
            .claims
            .first()
            .copied()
            .expect("the framer states its own claim");
        let path = crate::root::test_plugins::framer_cdylib_claiming(key).unwrap_or_else(|| {
            crate::root::test_plugins::missing(
                "data listener framer's dropped-in",
                crate::root::test_plugins::BUILD_PINNED,
            )
        });
        let stated = crate::root::loader::dispatch::rendering_of_library(&path)
            .expect("the library reads")
            .expect("the library states its Statement");
        let plugin = crate::root::loader::dispatch::load_dropped::<
            crate::root::loader::dispatch::kinds::transport::Transport,
        >(&path, &stated, crate::root::doors::bind())
        .expect("the dropped-in framer binds");
        crate::root::doors::served(
            plugin,
            &busbar_contract::transport::TransportSettings::default(),
            None,
        )
        .expect("the dropped-in framer opens")
        .0
    }

    /// A data listener bound FRAMED over `framer`, lending its owner's guest list, served by the
    /// accepted data door: where it listens.
    fn framed(&self, framer: Arc<dyn FramerDoor>) -> SocketAddr {
        let owner = crate::root::doors::owner_of(framer.as_ref()).expect("the framer's instance");
        crate::root::inbound::serve_under(owner).expect("the listener's table installs");
        let door = Arc::new(super::DataDoor {
            routes: None,
            router: self.router.clone(),
            handle: Arc::clone(&self.handle),
            owner,
            secured: false,
            server_timing: false,
            framer_for: Arc::new(|_: &str| -> Option<Arc<dyn FramerDoor>> { None }),
        });
        let listener = Listening::bind(
            Some(framer),
            &self.via,
            "127.0.0.1:0",
            None,
            Vec::new(),
            AcceptLimits::uncapped(),
        )
        .expect("the framed listener binds")
        .lending(crate::root::inbound::book(owner));
        let at = listener.local_addr();
        drop(tokio::task::spawn_local(super::serve_door(
            listener,
            Some(self.via.clone()),
            door,
            std::future::pending::<()>(),
            None,
        )));
        at
    }

    /// A data listener whose sockets are HANDED UP to the kernel's hyper loop (the old path):
    /// where it listens.
    fn handed_up(&self) -> SocketAddr {
        let listener =
            Listening::bind_stream(Some(&self.via), "127.0.0.1:0", AcceptLimits::uncapped())
                .expect("the stream listener binds");
        let at = listener.local_addr();
        drop(tokio::task::spawn_local(
            crate::root::listener::serve_admitted(
                listener,
                self.router.clone(),
                None,
                std::future::pending::<()>(),
                None,
            ),
        ));
        at
    }
}

/// One exchange as the caller's socket saw it: `request` written (a write the server cut short is
/// part of the exchange), everything read until the server closed, the `date` value masked.
async fn exchange(at: SocketAddr, request: Vec<u8>) -> Vec<u8> {
    let stream = tokio::net::TcpStream::connect(at)
        .await
        .expect("the listener accepts");
    let (mut read, mut write) = stream.into_split();
    let writer = tokio::spawn(async move {
        let _ = write.write_all(&request).await;
        write
    });
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(EXCHANGE_BOUND, read.read_to_end(&mut answer)).await;
    drop(writer.await);
    masked(&answer)
}

/// `bytes` with every `date` field's value masked.
fn masked(bytes: &[u8]) -> Vec<u8> {
    const FIELD: &[u8] = b"\r\ndate: ";
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some(at) = rest
        .windows(FIELD.len())
        .position(|w| w.eq_ignore_ascii_case(FIELD))
    {
        out.extend_from_slice(&rest[..at + FIELD.len()]);
        out.extend_from_slice(b"<date>");
        rest = &rest[at + FIELD.len()..];
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(rest.len());
        rest = &rest[end..];
    }
    out.extend_from_slice(rest);
    out
}

/// The version a request line states: the one the data listener's wire speaks to a client that
/// asks for nothing else, spelled by the version type itself.
fn version() -> String {
    format!("{:?}", axum::http::Version::HTTP_11)
}

/// A request with no body, closing the connection after its answer.
fn get(method: &str, path: &str) -> Vec<u8> {
    let version = version();
    format!("{method} {path} {version}\r\nHost: door.test\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

/// A request carrying `body` as `content-type`.
fn post(path: &str, content_type: &str, accept: &str, body: &[u8]) -> Vec<u8> {
    let version = version();
    let mut request = format!(
        "POST {path} {version}\r\nHost: door.test\r\nContent-Type: {content_type}\r\n\
         Accept: {accept}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

/// THE CORPUS, by shape: each case's name and its request bytes.
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let healthz = busbar_kernel::auth::HEALTHZ_PATH;
    let whole = br#"{"model":"door-model","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#;
    let version = version();
    let mut pipelined = format!("GET {healthz} {version}\r\nHost: door.test\r\n\r\n").into_bytes();
    pipelined.extend_from_slice(&get("GET", healthz));
    vec![
        ("probe__get", get("GET", healthz)),
        ("probe__head", get("HEAD", healthz)),
        ("chat__options", get("OPTIONS", "/v1/chat/completions")),
        ("unknown__path", get("GET", "/v1/unknown/suffix")),
        (
            "body__oversize",
            post("/v1/messages", "application/json", "*/*", &vec![b'x'; CAP + 4096]),
        ),
        ("credential__absent", get("GET", "/stats")),
        (
            "post__whole",
            post("/v1/messages", "application/json", "application/json", whole),
        ),
        (
            "post__event_stream",
            post(
                "/v1/messages",
                "application/json",
                busbar_contract::protocol::TEXT_EVENT_STREAM,
                br#"{"model":"door-model","max_tokens":8,"stream":true,"messages":[]}"#,
            ),
        ),
        ("pipelined__two", pipelined),
        ("api__root", get("GET", "/api")),
        ("api__prefix", get("GET", "/api/v1/admin/keys")),
    ]
}

/// One request over h2 by prior knowledge: the status, the head fields but `date` in order,
/// and the body.
async fn prior_knowledge(at: SocketAddr, path: &str) -> (u16, Vec<(String, Vec<u8>)>, Vec<u8>) {
    use http_body_util::BodyExt as _;
    let stream = tokio::net::TcpStream::connect(at)
        .await
        .expect("the listener accepts");
    let (mut send, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .expect("the h2 preface is answered");
    drop(tokio::task::spawn_local(conn));
    let scheme = axum::http::uri::Scheme::HTTP;
    let request = hyper::Request::get(format!("{scheme}://{at}{path}"))
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .expect("a request");
    let response = tokio::time::timeout(EXCHANGE_BOUND, send.send_request(request))
        .await
        .expect("answered in time")
        .expect("answered");
    let status = response.status().as_u16();
    let fields = response
        .headers()
        .iter()
        .filter(|(name, _)| name.as_str() != "date")
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("the body")
        .to_bytes()
        .to_vec();
    (status, fields, body)
}

/// Every case of the corpus answered at `left` and at `right`, byte for byte (the `date` value
/// masked), each answer a whole status line and never nothing; and the same request over h2
/// by prior knowledge, its status, fields and body.
async fn alike(left: SocketAddr, right: SocketAddr, sides: &str) {
    for (case, request) in corpus() {
        let l = exchange(left, request.clone()).await;
        let r = exchange(right, request).await;
        assert!(
            l.starts_with(format!("{} ", version()).as_bytes()),
            "{case}: {sides}: the first answers with a status line: {:?}",
            String::from_utf8_lossy(&l)
        );
        assert_eq!(
            String::from_utf8_lossy(&l),
            String::from_utf8_lossy(&r),
            "{case}: {sides}: the answers differ"
        );
    }
    let healthz = busbar_kernel::auth::HEALTHZ_PATH;
    assert_eq!(
        prior_knowledge(left, healthz).await,
        prior_knowledge(right, healthz).await,
        "prior_knowledge__probe: {sides}: the answers differ"
    );
}

/// THE DATA DOOR ANSWERS ALIKE THROUGH THE LINKED AND THE DROPPED-IN FRAMER (#3 OWNER-LOCKED: a
/// transport is swappable, compiled in OR dropped in): two data listeners over one generation, each
/// bound framed, one to the data listener's framer linked into this build and one to the same
/// framer's `cdylib` dlopened, answer the corpus with the same bytes.
#[tokio::test(flavor = "current_thread")]
async fn the_data_door_answers_alike_through_the_linked_and_the_dropped_in_framer() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let rig = rig();
            let linked = rig.linked_framer();
            let dropped = rig.dropped_framer(linked.as_ref());
            let through_linked = rig.framed(linked);
            let through_dropped = rig.framed(dropped);
            alike(through_linked, through_dropped, "linked and dropped in").await;
        })
        .await;
}

/// THE DATA DOOR ANSWERS ALIKE HANDED UP AND FRAMED (the switch's two arms, in one process): a data
/// listener whose sockets are handed up to the kernel's hyper loop and one bound to the data
/// listener's framer, over one generation, answer the corpus with the same bytes.
#[tokio::test(flavor = "current_thread")]
async fn the_data_door_answers_alike_handed_up_and_framed() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let rig = rig();
            let handed_up = rig.handed_up();
            let framed = rig.framed(rig.linked_framer());
            alike(handed_up, framed, "handed up and framed").await;
        })
        .await;
}
