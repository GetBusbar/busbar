// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ACCEPTED DATA DOOR ANSWERS ALIKE, BOTH WAYS (status row 192 C; `BUSBAR-1.6.0.md`
//! l.475-484 and l.896-906: the connector owns every listener, bound to one transport; customer
//! bytes stay 1.5.5's).
//!
//! One corpus of requests, sent over real sockets to listeners bound in this process over one data
//! router, one generation and one guest list, the test plane's door composed on it (its claims are
//! neutral: `/call/local-whole` answers whole, `/call/local-events` an event stream, each through
//! `DataRoutes::drive`):
//!
//! * through the data listener's framer LINKED and through the same framer's dropped-in `cdylib`
//!   (found by its facts, never by its name), each listener bound framed and served by the accepted
//!   data door: the bytes are equal;
//! * through the hand-up (each socket handed up to the kernel's hyper loop, the old path) and
//!   through the linked framer (the new path): the bytes are equal.
//!
//! The `date` field's value is masked; every other byte is compared, the status line first. Beside
//! the corpus: a request holds ONE admission slot on either path, an over-cap answer keeps 1.5.5's
//! connection handling, and a data request verified by a dropped-in token-verifying auth plugin is
//! answered alike.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use busbar_core_connector::compose::Via;
use busbar_core_connector::framer::FramerDoor;
use busbar_core_connector::listen::{AcceptLimits, Listening};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec};
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::planes_tests::{bound, composed_services, Published, PUBLISHING};
use super::{compose_planes, door_mounts};
use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
use crate::root::plane_node::{Node, NodeEndPost};

/// The router's body cap in these cells.
const CAP: usize = 1 << 20;

/// How long one exchange may take before what was read is compared.
const EXCHANGE_BOUND: Duration = Duration::from_secs(20);

/// The test plane's section: one entry, one pool over it.
const SECTION: &str = "m: {}\npools: {p: {members: [m]}}";

/// The audience the dropped-in auth plugin's tokens are bound to.
const AUDIENCE: &str = "api://doors-alike";

/// Who verifies a data request's credential in a rig.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Chain {
    /// The kernel's own signed-key verifier: the caller presents a minted key.
    Keys,
    /// A dropped-in token-verifying `kind: auth` plugin, against a local issuer.
    Verifier,
}

/// One served generation: the data router as the hand-up serves it and the same router without
/// its admission cap (what the framed door calls), their handle, the door planes' routes, the
/// connector the listeners bind through and the carrier they ride, and the credential a caller
/// presents.
struct Rig {
    router: axum::Router,
    ungated: axum::Router,
    handle: Arc<busbar_kernel::state::AppHandle>,
    routes: Option<Arc<super::DataRoutes>>,
    connector: Arc<busbar_core_connector::Connector>,
    via: Via,
    token: String,
    _published: Published,
}

/// THE LOCAL ISSUER, one per test process: an ES256 key whose JWKS is served only to a need trusting
/// its certificate, through the stand-in connection table the auth axis reaches it by.
fn issuer() -> &'static busbar_test_kit::test_issuer::Issuer {
    static ONE: std::sync::OnceLock<busbar_test_kit::test_issuer::Issuer> =
        std::sync::OnceLock::new();
    ONE.get_or_init(|| {
        let scheme = axum::http::uri::Scheme::HTTPS;
        let url = format!("{scheme}://issuer.doors-alike.invalid");
        let issuer = busbar_test_kit::test_issuer::Issuer::start(&url, "doors-alike");
        let conns = busbar_test_kit::https_conns::HttpsConns::new();
        conns.serve_issuer(&issuer);
        busbar_plugin_loader::auth_axis::stand_in_conns(Arc::new(conns));
        issuer
    })
}

/// The chain name the dropped-in verifier is configured under.
const VERIFIER: &str = "door-verifier";

/// The role the issuer's tokens carry, bound so an identified caller earns a grant.
const ROLE: &str = "platform";

/// THE DROPPED-IN VERIFIER'S CHAIN: the token-verifying auth plugin's `cdylib` (found by its role,
/// `crate::root::test_plugins::token_verifier_cdylib_path`), packed first-party into a plugins
/// directory, admitted by the preflight and opened as the data chain's one position; its role bound.
fn verifier_app() -> busbar_kernel::test_support::TestApp {
    let lib_path = crate::root::test_plugins::token_verifier_cdylib_path().unwrap_or_else(|| {
        crate::root::test_plugins::missing(
            "token-verifying auth",
            crate::root::test_plugins::BUILD_PINNED,
        )
    });
    let lib = std::fs::read(&lib_path).expect("the verifier's library reads");
    let dir = crate::root::test_plugins::scratch("doors-alike-verifier");
    let mut m = crate::root::test_plugins::manifest("auth", "door-idp", "acme");
    m.alias = VERIFIER.into();
    m.version = "1.5.0".into();
    m.statement = crate::root::loader::dispatch::rendering_of_library(&lib_path)
        .expect("the verifier states its door")
        .map(hex::encode);
    m.publisher = crate::root::loader::sign::FIRST_PARTY_PUBLISHER.into();
    // The test build's release key (`tests/common/root_install.rs`), the first-party key the scan
    // trusts: the kernel's test kit names no loader, so the root's own fixture scans the directory
    // as boot does and its auth axis opens the dropped-in row.
    let release = crate::root::test_plugins::key(0x5a);
    let tarball = crate::root::test_plugins::signed(&release, m, &lib);
    std::fs::write(dir.join("verifier.tar.gz"), tarball).expect("the tarball is written");
    let mut entry = busbar_kernel::config::AuthChainEntry::bare(VERIFIER);
    entry.settings = issuer().settings(AUDIENCE);
    let cfg = busbar_kernel::config::AuthCfg {
        chain: vec![entry],
        ..busbar_kernel::config::AuthCfg::default_none()
    };
    let registry: Arc<dyn busbar_contract::plugin_rows::PluginRows> =
        Arc::new(crate::root::test_plugins::boot_with(
            &dir,
            &crate::root::test_plugins::release_policy(&release),
        ));
    busbar_kernel::test_support::install_root_auth_axis(verifier_axis);
    let auth = busbar_kernel::auth::AuthMiddleware::new(
        &cfg,
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the verifier opens");
    let mut roles = busbar_kernel::config::RoleBindings::default();
    roles
        .entry(VERIFIER.to_string())
        .or_default()
        .entry(ROLE.to_string())
        .or_default();
    busbar_kernel::test_support::TestApp::new()
        .auth(Arc::new(auth))
        .role_bindings(roles)
}

/// The auth axis the verifier opens on: the loader's own over the scanned registry, on a
/// dispatcher of its own, as the integration tests' root install opens a dropped-in auth row
/// (`tests/common/root_install.rs`), the kernel's seal lent.
fn verifier_axis(
    rows: Arc<dyn busbar_contract::plugin_rows::PluginRows>,
) -> Arc<dyn busbar_contract::auth_calls::AuthAxis> {
    // Rows the loader did not build (the kit's linked stand-in) are no dropped-in row's: none.
    let registry = crate::root::loader::rows::registry_arc(rows)
        .unwrap_or_else(|| Arc::new(crate::root::loader::PluginRegistry::empty()));
    crate::root::loader::auth_axis::stand_in(registry, busbar_kernel::seal::lend())
}

/// The rig over the test plane composed as `instance`, its data chain `chain`, the router's
/// admission cap `max_inbound` (`0` = none): the data listener's lines (the plane's claims, the
/// kernel's own routes and the residual line) staged and published for the inbound auth handle, a
/// connector over this build's linked transport doors on the process's dispatcher.
fn rig(instance: &'static str, chain: Chain, max_inbound: usize) -> Rig {
    let services = composed_services();
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::clone(&services) as Arc<dyn busbar_contract::services::HostServices>,
    ));
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let plane = bound(instance, &dispatcher);
    let signer = TokenSigner::from_secret_bytes(&[11u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer))
            .expect("governance"),
    );
    let cost = CostModel::flat(1);
    let spec = NewKeySpec {
        name: "door".to_string(),
        ..Default::default()
    };
    let (_key, minted) = gov
        .mint_signed(spec, 4_000_000_000, 1_700_000_000)
        .expect("mint");
    gov.hydrate_budgets(&cost, 0).expect("hydrate");
    let book = Arc::new(std::sync::Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_kernel_wal::NullShipper::new()),
            Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal opens"),
    ));
    let node = Arc::new(Node::new());
    node.bind_book(book);
    let post = Arc::new(NodeEndPost::new(node));
    let money = Arc::new(PlaneMoney::new(
        Arc::clone(&gov),
        Arc::clone(&post) as Arc<dyn EndPost>,
    ));
    let mut sections = BTreeMap::new();
    sections.insert("test_plane", serde_yaml::from_str(SECTION).expect("yaml"));
    let mut served = compose_planes(
        &[(instance.to_string(), plane)],
        &dispatcher,
        &services,
        &sections,
        None,
        &move || Arc::clone(&money),
        None,
        None,
    )
    .expect("the test plane composes");
    served.post = Some(post);
    // The framer of the test plane's framed claim: the neutral frame door, dropped in.
    served.framers = Some(super::money_tests::neutral_framers());
    let (app, token) = match chain {
        Chain::Keys => (
            busbar_kernel::test_support::TestApp::new().keys_chain(),
            minted.expose(&busbar_kernel::seal::lend()).clone(),
        ),
        Chain::Verifier => (verifier_app(), issuer().mint("caller", &[ROLE], AUDIENCE)),
    };
    let app = app.governance(Arc::clone(&gov)).cost(cost).build();
    let provider = match chain {
        Chain::Keys => busbar_kernel::config::KEYS_MODULE,
        Chain::Verifier => VERIFIER,
    };
    let data_chain = vec![(provider.to_string(), app.auth.position_points(provider))];
    let mounts = door_mounts(
        served,
        || crate::root::kernel::ROOT_CARD.pin(),
        &data_chain,
        &busbar_kernel::base_data_core_lines(&app),
        &busbar_kernel::base_data_plugin_lines(&app),
        &super::upgrade_carriers(crate::LINKED.transports, &[]),
        &super::transport_offers(crate::LINKED.transports, &[]),
    )
    .expect("the data listener's lines seal");
    let routes = crate::root::accepted::staged_routes();
    let routers = busbar_kernel::build_data_routers(
        app,
        mounts.routes,
        mounts.sessions,
        mounts.refusals,
        CAP,
        max_inbound,
        false,
    );
    if let Some(refuse) = mounts.refuse_by_path {
        routers.handle.bind_door_refuser(refuse);
    }
    let doors = crate::root::doors::dispatcher();
    crate::root::connector::install_io(doors);
    let _ = crate::root::inbound::install(doors);
    crate::root::inbound::publish(&routers.handle.load()).expect("the generation is published");
    let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
        block_private_addresses: false,
        ..Default::default()
    })
    .expect("the guard");
    let connector = busbar_core_connector::process::build_with_secrets(
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
        busbar_kernel::config::secret::resolve_linked_string_at_config,
    )
    .expect("the connector builds");
    let via = connector
        .address_via()
        .expect("a linked carrier serves the data address");
    Rig {
        router: routers.data,
        ungated: routers.ungated,
        handle: routers.handle,
        routes,
        connector,
        via,
        token,
        _published: Published(instance),
    }
}

impl Rig {
    /// The data listener's framer among this build's linked transports, found by its facts.
    fn linked_framer(&self) -> Arc<dyn FramerDoor> {
        let claims = super::transport_claims(crate::LINKED.transports, &[]);
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
        )
        .expect("the dropped-in framer opens")
        .0
    }

    /// The instance identity `framer`'s guest list is installed under, entered.
    fn owner(framer: &dyn FramerDoor) -> u64 {
        let owner = crate::root::doors::owner_of(framer).expect("the framer's instance");
        crate::root::inbound::serve_under(owner).expect("the listener's table installs");
        owner
    }

    /// A data listener bound FRAMED over `framer` (its owner `owner`), lending its owner's guest
    /// list, served by the accepted data door over the router WITHOUT its admission cap: where it
    /// listens.
    fn framed_as(&self, framer: Arc<dyn FramerDoor>, owner: u64) -> SocketAddr {
        let door = Arc::new(crate::root::accepted::DataDoor::over(
            self.routes.clone(),
            self.ungated.clone(),
            Arc::clone(&self.handle),
            owner,
        ));
        let listener = Listening::bind(
            Some(framer),
            &self.via,
            "127.0.0.1:0",
            None,
            busbar_core_connector::tls::server_alpn(),
            AcceptLimits::uncapped(),
        )
        .expect("the framed listener binds")
        .lending(crate::root::inbound::book(owner));
        let at = listener.local_addr();
        drop(tokio::task::spawn_local(crate::root::accepted::serve_door(
            listener,
            Some(self.via.clone()),
            door,
            std::future::pending::<()>(),
            None,
        )));
        at
    }

    /// [`Rig::framed_as`] under `framer`'s own instance.
    fn framed(&self, framer: Arc<dyn FramerDoor>) -> SocketAddr {
        let owner = Self::owner(framer.as_ref());
        self.framed_as(framer, owner)
    }

    /// A data listener whose sockets are HANDED UP to the kernel's hyper loop (the old path), the
    /// router WITH its admission cap: where it listens.
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

/// What the connection did after its answer: whether the server closed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum After {
    Closed,
    Open,
}

/// ONE ANSWER, its connection left as the server left it: `request` written, read until the first
/// final answer is whole (an interim `100` before it read with it), the `date` value masked; then
/// whether the server closed the connection within a second.
async fn answered(at: SocketAddr, request: Vec<u8>) -> (Vec<u8>, After) {
    let stream = tokio::net::TcpStream::connect(at)
        .await
        .expect("the listener accepts");
    let (mut read, mut write) = stream.into_split();
    let writer = tokio::spawn(async move {
        let _ = write.write_all(&request).await;
        write
    });
    let mut answer = Vec::new();
    let mut chunk = [0_u8; 16 * 1024];
    let read_whole = async {
        loop {
            if whole_final(&answer) {
                return true;
            }
            match read.read(&mut chunk).await {
                Ok(0) | Err(_) => return false,
                Ok(n) => answer.extend_from_slice(&chunk[..n]),
            }
        }
    };
    let whole = tokio::time::timeout(EXCHANGE_BOUND, read_whole)
        .await
        .unwrap_or(false);
    let after = if whole {
        match tokio::time::timeout(Duration::from_secs(1), read.read(&mut chunk)).await {
            Ok(Ok(0) | Err(_)) => After::Closed,
            _ => After::Open,
        }
    } else {
        After::Closed
    };
    drop(writer);
    (masked(&answer), after)
}

/// Whether `bytes` hold a whole final answer: past any interim `1xx` answers, a head and the body
/// its `content-length` states.
fn whole_final(bytes: &[u8]) -> bool {
    let mut rest = bytes;
    loop {
        let Some(end) = rest.windows(4).position(|w| w == b"\r\n\r\n") else {
            return false;
        };
        let head = String::from_utf8_lossy(&rest[..end]).to_ascii_lowercase();
        let body = &rest[end + 4..];
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        if (100..200).contains(&status) {
            rest = body;
            continue;
        }
        let length = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        return body.len() >= length;
    }
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

/// A request with no body and the head lines `lines` (each ending its own line), closing the
/// connection after its answer.
fn get(method: &str, path: &str, lines: &str) -> Vec<u8> {
    let version = version();
    format!("{method} {path} {version}\r\nHost: door.test\r\n{lines}Connection: close\r\n\r\n")
        .into_bytes()
}

/// A request carrying `body` as `content-type`, the head lines `lines` before its own; `close` =
/// it asks the connection closed after its answer.
fn post(path: &str, lines: &str, content_type: &str, body: &[u8], close: bool) -> Vec<u8> {
    let version = version();
    let close = if close { "Connection: close\r\n" } else { "" };
    let mut request = format!(
        "POST {path} {version}\r\nHost: door.test\r\n{lines}Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n{close}\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

/// A request's head on `path` (with the head lines `lines`) stating a body of 64 bytes, and its
/// first few: the caller never sends the rest.
fn partial(path: &str, lines: &str) -> Vec<u8> {
    let version = version();
    let mut head = format!(
        "POST {path} {version}\r\nHost: door.test\r\n{lines}Content-Type: text/plain\r\n\
         Content-Length: 64\r\n\r\n"
    )
    .into_bytes();
    head.extend_from_slice(b"partial");
    head
}

/// The credential line a caller presents `token` on.
fn bearer(token: &str) -> String {
    format!("Authorization: Bearer {token}\r\n")
}

/// THE CORPUS, by shape: each case's name and its request bytes, `token` the caller's credential.
fn corpus(token: &str) -> Vec<(&'static str, Vec<u8>)> {
    let healthz = busbar_kernel::auth::HEALTHZ_PATH;
    let keyed = bearer(token);
    let json = "application/json";
    let whole =
        br#"{"model":"door-model","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#;
    let version = version();
    let mut pipelined = format!("GET {healthz} {version}\r\nHost: door.test\r\n\r\n").into_bytes();
    pipelined.extend_from_slice(&get("GET", healthz, ""));
    let over = vec![b'x'; CAP + 4096];
    vec![
        ("probe__get", get("GET", healthz, "")),
        ("probe__head", get("HEAD", healthz, "")),
        ("chat__options", get("OPTIONS", "/v1/chat/completions", "")),
        ("unknown__path", get("GET", "/v1/unknown/suffix", "")),
        (
            "body__oversize",
            post("/v1/messages", "", json, &over, true),
        ),
        (
            "body__oversize_keyed",
            post("/v1/messages", &keyed, json, &over, true),
        ),
        (
            "plane__oversize_keyed",
            post("/call/local-whole", &keyed, json, &over, true),
        ),
        ("credential__absent", get("GET", "/stats", "")),
        ("credential__keyed", get("GET", "/stats", &keyed)),
        (
            "post__whole",
            post("/v1/messages", &keyed, json, whole, true),
        ),
        (
            "plane__whole",
            post("/call/local-whole", &keyed, "text/plain", b"ping", true),
        ),
        (
            "plane__event_stream",
            post("/call/local-events", &keyed, "text/plain", b"ping", true),
        ),
        (
            "plane__credential_absent",
            post("/call/local-whole", "", "text/plain", b"ping", true),
        ),
        ("pipelined__two", pipelined),
        ("api__root", get("GET", "/api", "")),
        ("api__prefix", get("GET", "/api/v1/admin/keys", "")),
    ]
}

/// One request over h2 by prior knowledge: the status, the head fields but `date` in order, and
/// the body.
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

/// Every case of `corpus` answered at `left` and at `right`, byte for byte (the `date` value
/// masked), each answer a whole status line and never nothing; and the probe over h2 by prior
/// knowledge, its status, fields and body.
async fn alike(left: SocketAddr, right: SocketAddr, corpus: Vec<(&str, Vec<u8>)>, sides: &str) {
    for (case, request) in corpus {
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
    let _one = PUBLISHING.lock().await;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let rig = rig("accepted-linked-dropped", Chain::Keys, 0);
            let linked = rig.linked_framer();
            let dropped = rig.dropped_framer(linked.as_ref());
            let through_linked = rig.framed(linked);
            let through_dropped = rig.framed(dropped);
            let corpus = corpus(&rig.token);
            alike(
                through_linked,
                through_dropped,
                corpus,
                "linked and dropped in",
            )
            .await;
        })
        .await;
}

/// THE DATA DOOR ANSWERS ALIKE HANDED UP AND FRAMED (the switch's two arms, in one process): a data
/// listener whose sockets are handed up to the kernel's hyper loop and one bound to the data
/// listener's framer, over one generation, answer the corpus with the same bytes.
#[tokio::test(flavor = "current_thread")]
async fn the_data_door_answers_alike_handed_up_and_framed() {
    let _one = PUBLISHING.lock().await;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let rig = rig("accepted-handed-framed", Chain::Keys, 0);
            let handed_up = rig.handed_up();
            let framed = rig.framed(rig.linked_framer());
            let corpus = corpus(&rig.token);
            alike(handed_up, framed, corpus, "handed up and framed").await;
        })
        .await;
}

/// The 1.5.5 golden cells of the over-cap family (`testing/shadow-oracle/golden/1.5.5/cells`,
/// read only, by their family's prefix): each answered `413`, its head fields' names.
fn golden_over_cap_fields() -> Vec<Vec<String>> {
    let dir = format!(
        "{}/../../testing/shadow-oracle/golden/1.5.5/cells",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{dir}: {e}")) {
        let path = entry.expect("an entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.contains(".crosscut__413__") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a cell reads");
        let cell: serde_json::Value = serde_json::from_str(&text).expect("a cell is JSON");
        if cell["status"] != 413 {
            continue;
        }
        let names = cell["headers"]
            .as_object()
            .map(|h| h.keys().cloned().collect())
            .unwrap_or_default();
        found.push(names);
    }
    found
}

/// AN OVER-CAP ANSWER KEEPS 1.5.5's CONNECTION HANDLING (status row 192 C): a body past the cap,
/// sent as a client sends a large body (`Expect: 100-continue`, the connection kept alive), is
/// answered by the hand-up and by the framed door with the same bytes, interim answer included, and
/// the connection is left the same way (closed, or kept). The answer states no `connection` field,
/// as no 1.5.5 over-cap golden does.
#[tokio::test(flavor = "current_thread")]
async fn an_over_cap_answer_keeps_the_1_5_5_connection_handling_on_both_paths() {
    let _one = PUBLISHING.lock().await;
    let goldens = golden_over_cap_fields();
    assert!(!goldens.is_empty(), "the over-cap goldens are read");
    for names in &goldens {
        assert!(
            !names.iter().any(|n| n == "connection"),
            "a 1.5.5 over-cap answer states no connection field: {names:?}"
        );
    }
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let rig = rig("accepted-over-cap", Chain::Keys, 0);
            let handed_up = rig.handed_up();
            let framed = rig.framed(rig.linked_framer());
            let keyed = format!("{}Expect: 100-continue\r\n", bearer(&rig.token));
            let over = vec![b'x'; CAP + 4096];
            for (case, path) in [("residual", "/v1/messages"), ("plane", "/call/local-whole")] {
                let request = post(path, &keyed, "application/json", &over, false);
                let (l, l_after) = answered(handed_up, request.clone()).await;
                let (r, r_after) = answered(framed, request).await;
                let text = String::from_utf8_lossy(&l).to_ascii_lowercase();
                assert!(
                    text.contains(" 413 "),
                    "{case}: the hand-up answers the over-cap body 413: {text}"
                );
                assert!(
                    !text.contains("\r\nconnection:"),
                    "{case}: no connection field, as 1.5.5: {text}"
                );
                assert_eq!(
                    String::from_utf8_lossy(&l),
                    String::from_utf8_lossy(&r),
                    "{case}: the over-cap answers differ"
                );
                assert_eq!(l_after, r_after, "{case}: the connection is left alike");
            }
        })
        .await;
}

/// A request through `router` whose body never ends, in flight on its own task; the sender that
/// would end it, held.
fn held(
    router: &axum::Router,
    token: &str,
) -> tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::convert::Infallible>> {
    use hyper::service::Service as _;
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let body = axum::body::Body::from_stream(futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|piece| (piece, rx))
    }));
    let request = axum::http::Request::post("/call/local-whole")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(body)
        .expect("a request");
    let service = hyper_util::service::TowerToHyperService::new(router.clone());
    drop(tokio::task::spawn_local(async move {
        let _ = service.call(request).await;
    }));
    tx
}

/// The status `router` answers the probe with now.
async fn probe(router: &axum::Router) -> u16 {
    use hyper::service::Service as _;
    let request = axum::http::Request::get(busbar_kernel::auth::HEALTHZ_PATH)
        .body(axum::body::Body::empty())
        .expect("a request");
    let service = hyper_util::service::TowerToHyperService::new(router.clone());
    service
        .call(request)
        .await
        .map_or(0, |r| r.status().as_u16())
}

/// Whether `answer` is the at-capacity 503 a full gate sheds an arrival with, its words once.
fn shed_once(answer: &[u8]) -> bool {
    let text = String::from_utf8_lossy(answer);
    text.contains(" 503 ") && text.matches("\"overloaded\"").count() == 1
}

/// A REQUEST HOLDS ONE ADMISSION SLOT ON EITHER PATH (1.5.5: one outermost cap, one slot a
/// request). The framed door calls the data router WITHOUT its admission cap (the request took its
/// slot at the kernel's inbound gate): with the router's cap at one slot, a request held in flight
/// through the ungated router leaves the probe served, where the capped router sheds it. And end to
/// end, with one slot on each path's gate, a request held in flight makes the next arrival shed with
/// the at-capacity 503, its bytes alike on both paths and the answer once; the held request let
/// go, its slot comes back.
#[tokio::test(flavor = "current_thread")]
async fn a_request_holds_one_admission_slot_on_either_path() {
    let _one = PUBLISHING.lock().await;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let rig = rig("accepted-admission", Chain::Keys, 1);
            // The router the framed door calls holds no slot of its own.
            let capped = held(&rig.router, &rig.token);
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(probe(&rig.router).await, 503, "the capped router is full");
            drop(capped);
            let ungated = held(&rig.ungated, &rig.token);
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(
                probe(&rig.ungated).await,
                200,
                "a request through the ungated router holds no slot of its own"
            );
            drop(ungated);
            // End to end: one slot on each path's gate.
            let handed_up = rig.handed_up();
            let linked = rig.linked_framer();
            let owner = Rig::owner(linked.as_ref());
            crate::root::inbound::reinstall_gated(owner, 1).expect("a one-slot gate");
            let framed = rig.framed_as(linked, owner);
            let healthz = busbar_kernel::auth::HEALTHZ_PATH;
            let mut answers = Vec::new();
            for at in [handed_up, framed] {
                // The head states a body the caller never finishes sending.
                let open = partial("/call/local-whole", &bearer(&rig.token));
                let mut stream = tokio::net::TcpStream::connect(at)
                    .await
                    .expect("the listener accepts");
                stream.write_all(&open).await.expect("the head is sent");
                tokio::time::sleep(Duration::from_millis(300)).await;
                let shed = exchange(at, get("GET", healthz, "")).await;
                assert!(
                    shed_once(&shed),
                    "a full gate sheds with the at-capacity 503, once: {}",
                    String::from_utf8_lossy(&shed)
                );
                answers.push(shed);
                drop(stream);
                let mut served = false;
                for _ in 0..50 {
                    let again = exchange(at, get("GET", healthz, "")).await;
                    if String::from_utf8_lossy(&again).contains(" 200 ") {
                        served = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                assert!(served, "the held request let go, its slot comes back");
            }
            assert_eq!(
                String::from_utf8_lossy(&answers[0]),
                String::from_utf8_lossy(&answers[1]),
                "the shed answers differ"
            );
        })
        .await;
}

/// A DATA REQUEST VERIFIED BY A DROPPED-IN AUTH PLUGIN IS ANSWERED ALIKE: the data chain's one
/// position a token-verifying `kind: auth` plugin (its `cdylib` dropped in, its role bound), a
/// caller presenting the local issuer's signed token on the test plane's claim and on the kernel's
/// own route, and one presenting none, are answered with the same bytes handed up and framed.
#[tokio::test(flavor = "current_thread")]
async fn a_data_request_verified_by_a_dropped_in_auth_plugin_is_answered_alike() {
    let _one = PUBLISHING.lock().await;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let rig = rig("accepted-verified", Chain::Verifier, 0);
            let handed_up = rig.handed_up();
            let framed = rig.framed(rig.linked_framer());
            let token = bearer(&rig.token);
            let corpus = vec![
                (
                    "verified__plane_whole",
                    post("/call/local-whole", &token, "text/plain", b"ping", true),
                ),
                (
                    "verified__plane_event_stream",
                    post("/call/local-events", &token, "text/plain", b"ping", true),
                ),
                ("verified__kernel_route", get("GET", "/stats", &token)),
                (
                    "verified__credential_absent",
                    post("/call/local-whole", "", "text/plain", b"ping", true),
                ),
            ];
            alike(handed_up, framed, corpus, "handed up and framed, verified").await;
        })
        .await;
}

/// One answer on an h2 connection: the status, the head fields but `date` in order, and the body;
/// or the failure the stream ended with, by its kind.
type H2Answer = Result<(u16, Vec<(String, Vec<u8>)>, Vec<u8>), String>;

/// `request` sent on `send`, its answer read whole.
async fn h2_answer(
    send: &mut hyper::client::conn::http2::SendRequest<http_body_util::Full<bytes::Bytes>>,
    request: hyper::Request<http_body_util::Full<bytes::Bytes>>,
) -> H2Answer {
    use http_body_util::BodyExt as _;
    let response = tokio::time::timeout(EXCHANGE_BOUND, send.send_request(request))
        .await
        .map_err(|_| "no answer in time".to_string())?
        .map_err(|e| format!("the stream failed: {}", e.is_canceled()))?;
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
        .map_err(|_| "the body failed".to_string())?
        .to_bytes()
        .to_vec();
    Ok((status, fields, body))
}

/// ON ONE h2 CONNECTION at `at`: a stream carrying a body past the cap and a concurrent probe,
/// then a third request on the same connection: each answer.
async fn h2_over_cap(at: SocketAddr, token: &str) -> Vec<H2Answer> {
    let stream = tokio::net::TcpStream::connect(at)
        .await
        .expect("the listener accepts");
    let (send, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .expect("the h2 preface is answered");
    drop(tokio::task::spawn_local(conn));
    let scheme = axum::http::uri::Scheme::HTTP;
    let request = |method: &str, path: &str, body: Vec<u8>| {
        hyper::Request::builder()
            .method(method)
            .uri(format!("{scheme}://{at}{path}"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "text/plain")
            .body(http_body_util::Full::new(bytes::Bytes::from(body)))
            .expect("a request")
    };
    let over = request("POST", "/call/local-whole", vec![b'x'; CAP + 4096]);
    let probe = request("GET", busbar_kernel::auth::HEALTHZ_PATH, Vec::new());
    let (mut a, mut b) = (send.clone(), send.clone());
    let (over, probe) = tokio::join!(h2_answer(&mut a, over), h2_answer(&mut b, probe));
    // The connection outlives the over-cap stream: a third request on it is answered.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut c = send;
    let after = h2_answer(
        &mut c,
        request("POST", "/call/local-whole", b"ping".to_vec()),
    )
    .await;
    vec![over, probe, after]
}

/// AN OVER-CAP STREAM ENDS ON ITS OWN ON h2 (1.5.5's hyper: the stream answered and reset, the
/// connection and its other streams kept): on one h2 connection, a stream carrying a body past the
/// cap is answered `413`, a concurrent probe completes with its whole answer, and a request made on
/// the same connection afterwards is answered, its bytes alike handed up and framed.
#[tokio::test(flavor = "current_thread")]
async fn an_over_cap_stream_ends_on_its_own_on_h2_and_the_connection_serves_on() {
    let _one = PUBLISHING.lock().await;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let rig = rig("accepted-over-cap-h2", Chain::Keys, 0);
            let handed_up = rig.handed_up();
            let framed = rig.framed(rig.linked_framer());
            let left = h2_over_cap(handed_up, &rig.token).await;
            let right = h2_over_cap(framed, &rig.token).await;
            let status = |a: &H2Answer| a.as_ref().map(|(s, _, _)| *s).ok();
            assert_eq!(
                status(&left[0]),
                Some(413),
                "the over-cap stream: {:?}",
                left[0]
            );
            assert_eq!(status(&left[1]), Some(200), "the probe: {:?}", left[1]);
            assert_eq!(
                status(&left[2]),
                Some(200),
                "the request after: {:?}",
                left[2]
            );
            for (case, (l, r)) in ["over_cap", "probe", "after"]
                .iter()
                .zip(left.iter().zip(right.iter()))
            {
                assert_eq!(l, r, "h2__{case}: the answers differ handed up and framed");
            }
        })
        .await;
}

/// One framed claim's answer over h2: the status, the head fields but `date` in order, the body and
/// the closing block (the trailers), each field as `(name, value)`.
type Closed = (u16, Vec<(String, Vec<u8>)>, Vec<u8>, Vec<(String, Vec<u8>)>);

/// `body` POSTed to the framed claim `path` over h2 by prior knowledge at `at`: its answer and its
/// closing block.
async fn framed_over_h2(at: SocketAddr, path: &str, body: &'static [u8]) -> Closed {
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
    let request = hyper::Request::post(format!("{scheme}://{at}{path}"))
        .body(http_body_util::Full::new(bytes::Bytes::from_static(body)))
        .expect("a request");
    let response = tokio::time::timeout(EXCHANGE_BOUND, send.send_request(request))
        .await
        .expect("answered in time")
        .expect("answered");
    let fields = |h: &axum::http::HeaderMap| -> Vec<(String, Vec<u8>)> {
        h.iter()
            .filter(|(name, _)| name.as_str() != "date")
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect()
    };
    let status = response.status().as_u16();
    let head = fields(response.headers());
    let collected = response.into_body().collect().await.expect("the body");
    let closing = collected.trailers().map(fields).unwrap_or_default();
    (status, head, collected.to_bytes().to_vec(), closing)
}

/// A FRAMED CLAIM'S CLOSING BLOCK IS NEVER SURFACED ON THE DATA LISTENER (`BUSBAR-1.6.0.md`
/// l.731-732, no trailer piece on the transport ABI; l.4794, the caller output drops trailers, as
/// 1.5.5's did): the test plane's framed claim, framed by its own framer (the neutral frame door,
/// dropped in), answers its messages, and no trailer field reaches the caller, over h1 (chunked,
/// the caller asking for trailers) and over h2, handed up and framed alike.
#[tokio::test(flavor = "current_thread")]
async fn a_framed_claims_closing_block_is_never_surfaced_on_the_data_listener() {
    let _one = PUBLISHING.lock().await;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let rig = rig("accepted-framed-claim", Chain::Keys, 0);
            let handed_up = rig.handed_up();
            let framed = rig.framed(rig.linked_framer());
            let messages: &'static [u8] = b"\x02hi\x03abc";
            for path in ["/framed/status", "/framed/ok"] {
                // h2: the answer and its body, and no trailer field.
                let left = framed_over_h2(handed_up, path, messages).await;
                let right = framed_over_h2(framed, path, messages).await;
                assert!(
                    !left.2.is_empty(),
                    "{path}: the framed answer's body arrives"
                );
                assert!(
                    left.3.is_empty() && right.3.is_empty(),
                    "{path}: no trailer field on h2: {:?} / {:?}",
                    left.3,
                    right.3
                );
                assert_eq!(left, right, "{path}: the h2 answers differ");
                // h1, chunked, the caller asking for trailers.
                let request = post(
                    path,
                    "TE: trailers\r\n",
                    "application/octet-stream",
                    messages,
                    true,
                );
                let l = exchange(handed_up, request.clone()).await;
                let r = exchange(framed, request).await;
                let text = String::from_utf8_lossy(&l).to_ascii_lowercase();
                assert!(text.contains(" 200 "), "{path}: the h1 answer: {text}");
                for name in ["frame-status", "frame-message", "frame-details"] {
                    assert!(!text.contains(name), "{path}: no {name} on h1: {text}");
                }
                if text.contains("transfer-encoding: chunked") {
                    assert!(
                        text.ends_with("\r\n0\r\n\r\n"),
                        "{path}: the last chunk carries no trailer field: {text:?}"
                    );
                }
                assert_eq!(
                    String::from_utf8_lossy(&l),
                    String::from_utf8_lossy(&r),
                    "{path}: the h1 answers differ"
                );
            }
        })
        .await;
}

/// AN ABSOLUTE-FORM h1 REQUEST LEFT UNREAD CLOSES ITS CONNECTION ON BOTH PATHS (1.5.5's hyper:
/// an h1 request whose body the handler left unread closes the connection after its answer,
/// whatever form its target takes): a request naming its target in absolute form, its body past the
/// cap, is answered alike handed up and framed, and its connection is closed on both. Naming an
/// authority in the head makes no h1 connection a multiplexed one.
#[tokio::test(flavor = "current_thread")]
async fn an_absolute_form_over_cap_request_closes_its_connection_on_both_paths() {
    let _one = PUBLISHING.lock().await;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let rig = rig("accepted-absolute-form", Chain::Keys, 0);
            let handed_up = rig.handed_up();
            let framed = rig.framed(rig.linked_framer());
            let scheme = axum::http::uri::Scheme::HTTP;
            let target = format!("{scheme}://door.test/call/local-whole");
            let keyed = bearer(&rig.token);
            let over = vec![b'x'; CAP + 4096];
            let request = post(&target, &keyed, "application/json", &over, false);
            let (l, l_after) = answered(handed_up, request.clone()).await;
            let (r, r_after) = answered(framed, request).await;
            let text = String::from_utf8_lossy(&l).to_ascii_lowercase();
            assert!(
                text.contains(" 413 "),
                "the over-cap body is answered 413: {text}"
            );
            assert_eq!(l_after, After::Closed, "the hand-up closes the connection");
            assert_eq!(
                String::from_utf8_lossy(&l),
                String::from_utf8_lossy(&r),
                "the absolute-form answers differ"
            );
            assert_eq!(
                r_after,
                After::Closed,
                "the framed door closes the connection"
            );
        })
        .await;
}
