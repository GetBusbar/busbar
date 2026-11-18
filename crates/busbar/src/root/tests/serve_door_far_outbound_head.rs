// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-R2: one upstream attempt copies its outbound head once. The kernel's far end
//! builds the head (the request's own fields and the framer's defaults) and the connector keeps
//! that very head for the dial; neither copies it again. Counted by the dev-only stage probe
//! (`Derive::OutboundHead`) on the actual far end over the actual connector, and the bytes the
//! upstream receives are the ones a table that only lends the head (every open before) sends.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_contract::abi::transport::FAULT_NONE;
use busbar_contract::caps::Route;
use busbar_contract::conn::{
    ConnError, ConnId, Conns, HeadDefaults, InstanceId, LocatedTarget, NeedId, OpenDesc, Piece,
    PollConns, Ticket,
};
use busbar_contract::stage_probe::{Derive, Scope};
use busbar_contract::transport::trust::EgressTrust;
use busbar_contract::transport::{ConnFacts, TransportSettings};
use busbar_core_connector::registry::Transports;
use busbar_core_connector::{process, Connector, DEFAULT_CLASS};
use busbar_kernel::config::Destinations;
use busbar_kernel::plane_driver::{
    Egress, FarEnd as _, MemberRoute, OutboundRequest, Pick, UnitRoute, DEFAULT_ERROR_BODY_MAX,
};
use busbar_kernel::test_hooks::tokens::pass;
use busbar_kernel_egress::ports::DestinationId;
use busbar_kernel_egress::{Failover, Member, OnExhausted, Pool, WeightedFloor};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{Book, Free, Quiet, Wall};

const OWNER: InstanceId = InstanceId(7);
const NEED: NeedId = NeedId(0);
const POOL: &str = "outbound-head";

/// An HTTP/1.1 upstream that keeps every request it receives, byte for byte, and answers each
/// `200 ok`.
async fn recording_far_end() -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = l.local_addr().expect("its address").port();
    let heard = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::clone(&heard);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let keep = Arc::clone(&keep);
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut buf = vec![0_u8; 4096];
                loop {
                    if let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&got[..at]).to_ascii_lowercase();
                        let length = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if got.len() >= at + 4 + length {
                            let request: Vec<u8> = got.drain(..at + 4 + length).collect();
                            keep.lock().expect("heard").push(request);
                            let answer = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";
                            if s.write_all(answer).await.is_err() {
                                return;
                            }
                            continue;
                        }
                    }
                    match s.read(&mut buf[..]).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
            });
        }
    });
    (port, heard)
}

/// The linked connector, its request/response need declared for `OWNER`.
fn connector() -> Connector {
    let settings = TransportSettings::default();
    let dest = crate::root::connector::guard_for(&Destinations {
        block_private_addresses: false,
        ..Destinations::default()
    })
    .expect("the guard");
    let view = Transports::new(
        crate::root::connector::entries(crate::LINKED_TRANSPORT_DOORS, &settings)
            .expect("the linked doors open"),
    )
    .expect("the view");
    let tls = busbar_core_connector::tls::client::build_client_config(&EgressTrust::default())
        .expect("the trust");
    let c = Connector::serving(
        view,
        process::judge(dest, &[]),
        Some(Arc::new(tls)),
        Arc::new(|_, _| {}),
    )
    .pooling(crate::root::connector::pool_posture(&settings));
    c.declare_need(
        OWNER,
        NEED,
        busbar_core_admin::admin_codec::claims::TRANSPORT,
        DEFAULT_CLASS,
    )
    .expect("the request/response framer's door serves the need");
    c
}

/// The same connector behind a table that forwards every call the far end makes but keeps no
/// head of its own: its open lends the head the far end built, as every open did before.
struct Lending(Arc<Connector>);

impl Conns for Lending {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.0.open(caller, need, desc)
    }
    fn open_with_security(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
    ) -> Result<ConnId, ConnError> {
        self.0
            .open_with_security(caller, need, desc, require_secure)
    }
    fn open_located(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        located: Option<&Arc<LocatedTarget>>,
    ) -> Result<ConnId, ConnError> {
        self.0
            .open_located(caller, need, desc, require_secure, located)
    }
    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, ConnError> {
        self.0.write(caller, conn, bytes, end, text)
    }
    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        ticket: Ticket,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.0.read(caller, conn, ticket, buf)
    }
    fn wait(&self, caller: InstanceId, set: &[ConnId], ticket: Ticket) -> Result<usize, ConnError> {
        self.0.wait(caller, set, ticket)
    }
    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.0.facts(caller, conn)
    }
    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.0.close(caller, conn)
    }
}

impl PollConns for Lending {
    fn poll_read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Piece, ConnError>> {
        self.0.poll_read(caller, conn, cx, buf)
    }
    fn head_defaults(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        timeout_ms: u64,
    ) -> Result<HeadDefaults, ConnError> {
        self.0.head_defaults(owner, need, target, timeout_ms)
    }
    fn locate_head(
        &self,
        owner: InstanceId,
        need: NeedId,
        target: &str,
        timeout_ms: u64,
    ) -> Result<(HeadDefaults, Option<Arc<LocatedTarget>>), ConnError> {
        self.0.locate_head(owner, need, target, timeout_ms)
    }
}

fn egress_over(conns: Arc<dyn PollConns>, port: u16) -> Egress {
    let destination = DestinationId::new(1);
    Egress {
        caller: OWNER,
        conns,
        breaker: busbar_kernel::plane_driver::fixed_breaker(Arc::new(Book::default())),
        capacity: Arc::new(Free),
        clock: Arc::new(Wall),
        journal: Arc::new(Quiet),
        telemetry: Arc::new(Quiet),
        pools: foldhash::HashMap::from_iter([(busbar_contract::kept::Text::fixed(POOL), {
            let mut pool = Pool::new(POOL.to_owned(), vec![Member::new(destination, "e", 1)]);
            pool.set_failover(Failover {
                timeout_secs: 30,
                max_hops: 1,
                exclusions: Vec::new(),
            });
            pool.on_exhausted = OnExhausted::Status503;
            pool.floor = WeightedFloor::new();
            pool
        })]),
        routes: foldhash::HashMap::from_iter([(
            destination,
            MemberRoute {
                ride_anchors: Vec::new(),
                connection_required: false,
                need: NEED,
                base_url: format!("http://127.0.0.1:{port}/"),
                auth: None,
                provider: busbar_contract::kept::Text::fixed("e"),
                keep: Default::default(),
                rides: Vec::new(),
                anchors: Default::default(),
                spelled: Vec::new(),
            },
        )]),
        stream_ceiling_secs: 600,
        stated_ceiling_secs: 0,
        error_body_max: DEFAULT_ERROR_BODY_MAX,
    }
}

fn request() -> OutboundRequest {
    OutboundRequest {
        text: false,
        member: busbar_contract::kept::Text::EMPTY,
        pool: busbar_contract::kept::Text::EMPTY,
        attempt_no: 1,
        verb: b"POST".to_vec(),
        target: b"/v1/chat/completions".to_vec(),
        fields: vec![
            (b"content-type".to_vec(), b"application/json".to_vec()),
            (b"x-trace".to_vec(), b"abc".to_vec()),
        ],
        body: b"{\"model\":\"m\"}".to_vec(),
        need: 0,
    }
}

/// One attempt through the kernel's far end over `conns`, read to its last piece. Returns the
/// answer's status and body, and how often the attempt copied its outbound head.
async fn attempt(conns: Arc<dyn PollConns>, port: u16) -> ((Option<u32>, Vec<u8>), u32) {
    let egress = egress_over(conns, port);
    let t = pass::<Route>();
    let far = egress.unit(UnitRoute {
        pool: busbar_contract::kept::Text::fixed(POOL),
        // The far end is a plaintext loopback server: its plane instance carries
        // `insecure_transport.accept: plaintext` (SEC-2, #297 model A; loopback is not exempt).
        accept: busbar_plugin_abi::host_side::caller::Accept(
            busbar_plugin_abi::host_side::caller::Accept::PLAINTEXT,
        ),
        ..UnitRoute::default()
    });
    let scope = Scope::open();
    assert!(matches!(far.member(&t, 1).await, Pick::Member { .. }));
    assert!(far.send(&t, request()).await, "the attempt is sent");
    let (mut status, mut body) = (None, Vec::new());
    loop {
        let piece = tokio::time::timeout(Duration::from_secs(10), far.next(&t))
            .await
            .expect("the upstream answers")
            .expect("a piece through the last");
        far.judged(&t, FAULT_NONE);
        status = status.or(piece.status.map(|(code, _)| code));
        body.extend_from_slice(&piece.bytes);
        if piece.last {
            break;
        }
    }
    ((status, body), scope.count(Derive::OutboundHead))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn outbound_head_copied_once() {
    let (port, heard) = recording_far_end().await;
    let connector = Arc::new(connector());
    let answered = (Some(200), b"ok".to_vec());

    let (owned, owned_copies) = attempt(Arc::clone(&connector) as Arc<dyn PollConns>, port).await;
    assert_eq!(owned, answered, "the upstream answers the attempt");
    assert_eq!(
        owned_copies, 1,
        "the far end builds the outbound head once and the connector keeps that head for the dial"
    );

    let (lent, lent_copies) = attempt(Arc::new(Lending(Arc::clone(&connector))), port).await;
    assert_eq!(lent, answered, "the upstream answers the lent attempt");
    assert_eq!(
        lent_copies, 2,
        "control: a table that only lends the head copies it again, as every open did before"
    );

    let heard = heard.lock().expect("heard").clone();
    assert_eq!(heard.len(), 2, "each attempt reached the upstream once");
    assert_eq!(
        heard[0], heard[1],
        "the head the connector kept sends the upstream the very bytes the lent head sends"
    );
    let sent = String::from_utf8_lossy(&heard[0]).to_ascii_lowercase();
    assert!(
        sent.contains("\r\nx-trace: abc\r\n") && sent.ends_with("{\"model\":\"m\"}"),
        "the request's own field and body reach the upstream: {sent}"
    );
}
