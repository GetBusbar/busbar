// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The connection table's native entry where no framer session is needed: the boot hand-over, the open's refusal
//! of a carrier no image carries, a failed dial, and the per-core idle set (reuse, a far end that closes an idle
//! connection, the posture's timeout, no read buffer held while idle). The exchange itself (open, read, reuse, a
//! reset mid-body) needs the linked http image's session and is proved through the default distribution
//! (`dist/default/tests/native_dial_conns.rs`).

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_DEFAULT};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::conn::{
    ConnError, Conns, DeclaredConns, InstanceId, NeedId, NeedRefusal, OpenDesc, PollConns,
};
use busbar_plugin_abi::plane::{CARRIER_HTTP, CARRIER_WEBSOCKET};
use busbar_ports::transport::{
    ConnIn, TransportEvent, TransportOut, TransportPort, TransportSession,
};
use busbar_ports::PortError;

use super::native_conns::Idle;
use super::native_dial::{locate, NativeCarrier, NativeConnection, NativeDial};
use super::pool::{PoolKey, PoolPosture};
use crate::{Connector, Judged, Verdict};

const OWNER: InstanceId = InstanceId(7);
const NEED: NeedId = NeedId(3);

/// A transport port no session is begun on: these tests never send a head.
struct Unbegun;

fn unbegun() -> PortError {
    PortError::Refused {
        code: 0,
        text: Box::from("no session is begun in these tests"),
        error: None,
    }
}

impl TransportPort for Unbegun {
    fn alpn(&self, _: u32) -> &[Box<str>] {
        &[]
    }
    fn defaults(&self, _: u32) -> &[(Box<str>, Box<str>)] {
        &[]
    }
    fn protocols(&self) -> &[Box<str>] {
        &[]
    }
    fn listener_slots(&self) -> &[Box<str>] {
        &[]
    }
    fn facts(&self) -> u64 {
        busbar_plugin_abi::transport::FB_CLIENT
    }
    fn begin(
        &self,
        _: &ConnIn<'_>,
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<TransportSession, PortError> {
        Err(unbegun())
    }
    fn ingest(
        &self,
        _: &mut TransportSession,
        _: &[u8],
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Err(unbegun())
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
        Err(unbegun())
    }
    fn timer(
        &self,
        _: &mut TransportSession,
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Err(unbegun())
    }
    fn datagram(
        &self,
        _: &mut TransportSession,
        _: u32,
        _: bool,
        _: &[u8],
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Err(unbegun())
    }
    fn event(
        &self,
        _: &mut TransportSession,
        _: TransportEvent<'_>,
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        Err(unbegun())
    }
}

fn carrier(carrier: u32) -> NativeCarrier {
    NativeCarrier {
        instance: Arc::from("unbegun"),
        port: Arc::new(Unbegun),
        carrier,
        stall_ms: None,
    }
}

fn storage() -> busbar_contract::storage::StorageSource {
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    ProcessAdmission::new(0).connection_storage(AdmissionClass::Data)
}

fn loopback(target: &str, _: u32, _: Judged) -> Option<Result<SocketAddr, Verdict>> {
    Some(
        target
            .parse::<SocketAddr>()
            .ok()
            .filter(|address| address.ip().is_loopback())
            .ok_or(busbar_contract::abi::host::service::DEST_UNRESOLVABLE),
    )
}

/// A connector with no old transport entry (so `http` is served natively), judging loopback literals only.
fn connector() -> Connector {
    Connector::serving(
        crate::registry::Transports::default(),
        Arc::new(loopback),
        None,
        Arc::new(|_, _| {}),
    )
}

fn need() -> ReadNeed {
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_DEFAULT,
        transport: "http".into(),
        auth: String::new(),
        target_from: String::new(),
        trust_from: String::new(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
        keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
        keep_response_headers: Vec::new(),
        deny_response_headers: Vec::new(),
    }
}

fn desc(target: &str) -> OpenDesc<'_> {
    OpenDesc {
        target,
        method: b"GET",
        head_target: b"/",
        timeout_ms: 5_000,
        plaintext_accepted: true,
        ..OpenDesc::default()
    }
}

#[test]
fn the_carriers_are_handed_over_once() {
    let connector = connector();
    assert!(!connector.carries_natively());
    connector
        .carry_natively(vec![carrier(CARRIER_HTTP)], storage())
        .expect("the first hand-over");
    assert!(connector.carries_natively());
    assert!(
        connector
            .carry_natively(vec![carrier(CARRIER_HTTP)], storage())
            .is_err(),
        "a second hand-over is refused"
    );
}

#[test]
fn a_need_no_old_entry_serves_is_declared_natively_and_framed() {
    let connector = connector();
    DeclaredConns::declare(&connector, OWNER, NEED, &need(), None, None)
        .expect("http is a scheme core dials natively");
    assert!(connector.native_need(OWNER, NEED).is_some());
    assert!(connector.framed(OWNER, NEED));
    let mut unknown = need();
    unknown.transport = "gopher".into();
    assert_eq!(
        DeclaredConns::declare(&connector, OWNER, NeedId(4), &unknown, None, None),
        Err(ConnError::Refused),
        "a scheme neither an old entry nor core's table serves is refused at declare"
    );
}

#[test]
fn an_open_whose_carrier_no_image_carries_is_refused_naming_why() {
    let connector = connector();
    connector
        .carry_natively(vec![carrier(CARRIER_WEBSOCKET)], storage())
        .unwrap();
    DeclaredConns::declare(&connector, OWNER, NEED, &need(), None, None).unwrap();
    assert_eq!(
        connector.open(OWNER, NEED, &desc("http://127.0.0.1:9/v1")),
        Err(ConnError::Refused)
    );
    assert_eq!(
        connector.refusal(OWNER, NEED),
        Some(NeedRefusal::Policy(super::refusal_text::NO_CARRIER))
    );
    assert!(
        connector
            .head_defaults(OWNER, NEED, "http://127.0.0.1:9/v1", 0)
            .is_err(),
        "no head is completed for a carrier no image carries"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_dial_answers_its_reader_a_fault_with_the_connect_stage() {
    // A port nothing listens on: bound, then let go.
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let connector = connector();
    connector
        .carry_natively(vec![carrier(CARRIER_HTTP)], storage())
        .unwrap();
    DeclaredConns::declare(&connector, OWNER, NEED, &need(), None, None).unwrap();
    let target = format!("http://{closed}/v1");
    let conn = match connector.open(OWNER, NEED, &desc(&target)) {
        Ok(conn) => conn,
        // The refusal came at once (the socket refused synchronously): that is the failed dial too.
        Err(error) => {
            assert!(matches!(error, ConnError::Fault | ConnError::Refused));
            return;
        }
    };
    let mut buf = [0_u8; 64];
    let read = tokio::time::timeout(
        Duration::from_secs(10),
        std::future::poll_fn(|cx| connector.poll_read(OWNER, conn, cx, &mut buf)),
    )
    .await
    .expect("a refused connect is answered, never waited on forever");
    assert_eq!(read.map(|_| ()), Err(ConnError::Fault));
    let cause = connector
        .failure_cause(OWNER, conn)
        .expect("the failed dial keeps its cause");
    assert_eq!(cause.stage, super::native_dial::stage::CONNECT);
    assert!(!cause.outbound, "a refused connect is no local fault");
    connector.close(OWNER, conn).unwrap();
}

/// A plain connection to `addr`, connected (open, nothing queued) and so reusable, with no session begun.
async fn connected(addr: SocketAddr) -> NativeConnection {
    let mut conn = NativeConnection::dial(
        carrier(CARRIER_HTTP),
        NativeDial {
            located: locate(&format!("http://{addr}/")).unwrap(),
            addr,
            also: Vec::new(),
            tls: None,
            anchors: None,
            open_timeout: Duration::from_secs(5),
            storage: storage(),
            tunnel: None,
        },
    )
    .expect("the connect begins");
    std::future::poll_fn(|cx| conn.poll_flushed(cx))
        .await
        .expect("the connect lands");
    conn
}

/// A key as one connector's pools seal it (one hasher for every key, as in a connector).
fn key(owner: u64) -> PoolKey {
    static POOLS: std::sync::OnceLock<crate::pool::Pools> = std::sync::OnceLock::new();
    let pools = POOLS.get_or_init(|| crate::pool::Pools::new(PoolPosture::NONE));
    pools.keyed(PoolKey {
        owner: InstanceId(owner),
        need: NEED,
        door: 1,
        authority: "127.0.0.1:1".into(),
        secure: false,
        name: None,
        class: (0, 0),
        reach: false,
        anchored_as: None,
        trust: None,
        sealed: None,
        hash: 0,
    })
}

const POSTURE: PoolPosture = PoolPosture {
    max_idle_per_host: 2,
    idle_timeout: Duration::from_secs(60),
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_connection_is_lent_again_only_on_its_own_core_and_holds_no_read_buffer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let conn = connected(addr).await;
    let (_far, _) = listener.accept().unwrap();
    // Idle: no stream, nothing queued for the socket, no inbox: what `reusable` states.
    assert!(
        conn.reusable(),
        "a landed connection with no exchange is reusable"
    );
    let idle = Idle::default();
    let now = Instant::now();
    idle.put(0, key(1), conn, now, POSTURE);
    assert!(
        idle.take(1, &key(1), now, POSTURE).is_none(),
        "another core is never lent this core's connection"
    );
    assert!(
        idle.take(0, &key(2), now, POSTURE).is_none(),
        "another key is never lent it"
    );
    let lent = idle
        .take(0, &key(1), now, POSTURE)
        .expect("its own core is lent it");
    assert!(lent.reusable(), "lent idle, it still holds nothing");
    assert!(
        idle.take(0, &key(1), now, POSTURE).is_none(),
        "lent once, it is no longer idle"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_end_that_closes_an_idle_connection_is_never_lent_it() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let conn = connected(addr).await;
    let (far, _) = listener.accept().unwrap();
    let idle = Idle::default();
    idle.put(0, key(1), conn, Instant::now(), POSTURE);
    drop(far);
    // Once the reactor has seen the far end's FIN, the lend's one look at the socket lets the closed connection go.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        idle.take(0, &key(1), Instant::now(), POSTURE).is_none(),
        "a connection its far end closed is closed, not lent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_connection_past_the_posture_timeout_is_closed_not_lent() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let conn = connected(addr).await;
    let (_far, _) = listener.accept().unwrap();
    let idle = Idle::default();
    let then = Instant::now();
    idle.put(0, key(1), conn, then, POSTURE);
    assert!(idle
        .take(0, &key(1), then + POSTURE.idle_timeout, POSTURE)
        .is_none());
    // Past the per-key bound, a connection is closed instead of kept.
    let mut far_ends = Vec::new();
    for _ in 0..3 {
        idle.put(0, key(3), connected(addr).await, then, POSTURE);
        far_ends.push(listener.accept().unwrap());
    }
    let mut kept = 0;
    while idle.take(0, &key(3), then, POSTURE).is_some() {
        kept += 1;
    }
    assert_eq!(kept, POSTURE.max_idle_per_host);
}

#[test]
fn an_idle_set_with_nothing_kept_made_nothing() {
    // No per-core table exists until a connection is kept.
    let idle = Idle::default();
    assert!(idle.cores.get().is_none());
}

/// A need whose declaration is refused is not served: a re-declaration refused (here: a target carrying a userinfo)
/// leaves no earlier native record behind, so an open of that need is refused and nothing is dialled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_declaration_leaves_no_need_to_open() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let connector = connector();
    connector
        .carry_natively(vec![carrier(CARRIER_HTTP)], storage())
        .unwrap();
    DeclaredConns::declare(&connector, OWNER, NEED, &need(), None, None)
        .expect("the first declaration is served");
    let credentialed = format!("http://user:secret@{addr}/v1");
    assert_eq!(
        DeclaredConns::declare(&connector, OWNER, NEED, &need(), Some(&credentialed), None),
        Err(ConnError::Refused),
        "a target carrying a userinfo is refused at declare"
    );
    let target = format!("http://{addr}/v1");
    assert_eq!(
        connector.open(OWNER, NEED, &desc(&target)).map(|_| ()),
        Err(ConnError::Refused),
        "the refused need is not opened"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        listener.accept().is_err(),
        "nothing was dialled for the refused need"
    );
}
