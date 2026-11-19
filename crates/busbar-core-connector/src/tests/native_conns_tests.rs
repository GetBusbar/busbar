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
    ConnIn, EmitParts, TransportEvent, TransportOut, TransportPort, TransportSession,
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
        _: u64,
        _: EmitParts<'_>,
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

/// A connector serving `http` natively, judging loopback literals only.
fn connector() -> Connector {
    Connector::serving(Arc::new(loopback), None, Arc::new(|_, _| {}))
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
    // An entry that carries no messages states no kind and no close code, failed or not.
    assert_eq!(connector.message_text(OWNER, conn), None);
    assert_eq!(connector.close_code(OWNER, conn), None);
    connector.close(OWNER, conn).unwrap();
    // Nor does an entry that is gone.
    assert_eq!(connector.message_text(OWNER, conn), None);
    assert_eq!(connector.close_code(OWNER, conn), None);
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
    // The stated figure is the deployment's, divided across the cores (v1.5.5's rule), at least one per core.
    assert_eq!(
        kept,
        crate::outbound::lend::idle_bound(POSTURE.max_idle_per_host, super::pool::shard_count())
    );
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

// POOL ISOLATION, JUDGED ADDRESS SETS AND THE PROGRAM REFUSAL (P095-3): what a line, a binding and a dial are
// never lent across, and what is refused before anything is dialled or spawned.

/// How many connections `listener` was handed within `wait` (each let go at once).
fn accepted(listener: &TcpListener, wait: Duration) -> usize {
    listener.set_nonblocking(true).unwrap();
    let until = Instant::now() + wait;
    let mut count = 0;
    loop {
        match listener.accept() {
            Ok(_) => count += 1,
            Err(_) if Instant::now() < until => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => return count,
        }
    }
}

/// A judge that answers a loopback literal at once, refuses any other literal as a metadata host, and pends a
/// name until the test answers it; it keeps every destination it was asked.
#[derive(Default)]
struct Pending {
    asked: std::sync::Mutex<Vec<String>>,
    pended: std::sync::Mutex<Vec<(String, Judged)>>,
}

impl Pending {
    /// Answer the pended judgement of `dest`.
    fn answer(&self, dest: &str, verdict: Result<SocketAddr, Verdict>) {
        let done = {
            let mut pended = self.pended.lock().unwrap();
            let at = pended
                .iter()
                .position(|(asked, _)| asked == dest)
                .expect("the name's judgement pended");
            pended.remove(at).1
        };
        done(verdict);
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

/// A connector judging through `judge`, carrying `http` on a port no session is begun on.
fn judged_by(judge: &Arc<Pending>) -> Connector {
    let judge = Arc::clone(judge);
    let connector = Connector::serving(
        Arc::new(
            move |dest: &str, _: u32, done: Judged| -> Option<Result<SocketAddr, Verdict>> {
                judge.asked.lock().unwrap().push(dest.to_owned());
                match dest.parse::<SocketAddr>() {
                    Ok(addr) if addr.ip().is_loopback() => Some(Ok(addr)),
                    Ok(_) => Some(Err(busbar_contract::abi::host::service::DEST_METADATA)),
                    Err(_) => {
                        judge.pended.lock().unwrap().push((dest.to_owned(), done));
                        None
                    }
                }
            },
        ),
        None,
        Arc::new(|_, _| {}),
    );
    connector
}

/// A read of `conn` that does not wait: `Pending` while the judgement or the dial has not answered.
fn read_now(
    connector: &Connector,
    conn: busbar_contract::conn::ConnId,
) -> std::task::Poll<Result<busbar_contract::conn::Piece, ConnError>> {
    let mut buf = [0_u8; 64];
    connector.poll_read(
        OWNER,
        conn,
        &mut std::task::Context::from_waker(std::task::Waker::noop()),
        &mut buf,
    )
}

/// Whether the exchange of `conn` would go back to an idle set (it holds a pool key).
fn keyed_for_the_pool(connector: &Connector, conn: busbar_contract::conn::ConnId) -> bool {
    let (_, held) = connector.slab.get(OWNER, conn).expect("the entry");
    let native = held.native.as_ref().expect("a native entry");
    let exchange = native
        .begin(std::task::Waker::noop())
        .expect("no other call has the exchange");
    let keyed = exchange.key.is_some();
    native.end(exchange);
    keyed
}

/// A program whose spawn would leave `marker` behind.
fn touching(marker: &std::path::Path) -> busbar_contract::conn::Program {
    busbar_contract::conn::Program {
        command: "/usr/bin/touch".to_owned(),
        cwd: Some("/".to_owned()),
        args: vec![marker.display().to_string()],
        env: vec![("PROGRAM_MODE".to_owned(), "serve".to_owned())],
        env_refs: Vec::new(),
    }
}

/// Every program need is refused at declare, whatever the operator wrote down for it (one program, a program per
/// member, a program carried over from a predecessor instance), with the unserved-scheme refusal kept for it; no
/// program is ever spawned, and no earlier native record of the same need survives to be opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_program_need_is_refused_unless_the_operator_declared_it_as_written() {
    let marker = std::env::temp_dir().join(format!(
        "busbar-p095-program-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let program = touching(&marker);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let connector = connector();
    connector
        .carry_natively(vec![carrier(CARRIER_HTTP)], storage())
        .unwrap();
    let unserved = Some(NeedRefusal::Policy(super::refusal_text::UNSERVED));

    assert_eq!(
        DeclaredConns::declare_program(&connector, OWNER, NeedId(4), &need(), &program),
        Err(ConnError::Refused),
        "a program need is refused at declare"
    );
    assert_eq!(connector.refusal(OWNER, NeedId(4)), unserved);
    let members = vec![
        ("alpha".to_owned(), program.clone()),
        ("beta".to_owned(), program.clone()),
    ];
    assert_eq!(
        DeclaredConns::declare_member_programs(&connector, OWNER, NeedId(5), &need(), &members),
        Err(ConnError::Refused),
        "a program per member is refused at declare"
    );
    assert_eq!(connector.refusal(OWNER, NeedId(5)), unserved);
    assert_eq!(
        DeclaredConns::declare_member_programs_from(
            &connector,
            InstanceId(6),
            OWNER,
            NeedId(6),
            &need(),
            &members
        ),
        Err(ConnError::Refused),
        "a predecessor's member programs are refused at declare"
    );
    assert_eq!(connector.refusal(OWNER, NeedId(6)), unserved);

    // A need first served natively, then declared again as a program: the refusal leaves no native record.
    DeclaredConns::declare(&connector, OWNER, NEED, &need(), None, None)
        .expect("the first declaration is served");
    assert_eq!(
        DeclaredConns::declare_program(&connector, OWNER, NEED, &need(), &program),
        Err(ConnError::Refused)
    );
    assert_eq!(connector.refusal(OWNER, NEED), unserved);
    assert!(
        connector.native_need(OWNER, NEED).is_none(),
        "the refused program need keeps no native record"
    );
    let target = format!("http://{addr}/v1");
    for need in [NEED, NeedId(4), NeedId(5), NeedId(6)] {
        assert!(
            connector.open(OWNER, need, &desc(&target)).is_err(),
            "a program need is never opened"
        );
    }
    assert_eq!(
        accepted(&listener, Duration::from_millis(200)),
        0,
        "nothing was dialled for a program need"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!marker.exists(), "no program was spawned");
}

/// An auth instance that is never asked for fields here: the bindings are told apart by their handles.
struct Unasked;

struct Unanswered;

impl std::future::Future for Unanswered {
    type Output = busbar_contract::auth_calls::Fields;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Ready(busbar_contract::auth_calls::Fields::Failed)
    }
}

impl busbar_contract::auth_calls::Fielding for Unanswered {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::Fields> {
        Some(busbar_contract::auth_calls::Fields::Failed)
    }
}

impl busbar_contract::auth_calls::OutboundAuth for Unasked {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Err("never opened in these tests".to_owned())
    }
    fn fields_now(
        &self,
        _: u64,
        _: &busbar_contract::auth_calls::FieldsRequest,
    ) -> Option<busbar_contract::auth_calls::Fields> {
        None
    }
    fn fields(
        &self,
        _: u64,
        _: busbar_contract::auth_calls::FieldsRequest,
        _: u64,
    ) -> Box<dyn busbar_contract::auth_calls::Fielding> {
        Box::new(Unanswered)
    }
}

fn binding(handle: u64) -> busbar_contract::conn::ConnAuth {
    busbar_contract::conn::ConnAuth {
        auth: Arc::new(Unasked),
        handle,
        style_flags: 0,
        points: busbar_contract::route::AuthPoints(0),
        passthrough: false,
        lender: None,
        per_request: None,
    }
}

/// The handle of the binding a request of `member` to `target` is authenticated with, if any.
fn bound(connector: &Connector, need: NeedId, member: &str, target: &str) -> Option<u64> {
    DeclaredConns::auth_of(connector, OWNER, need, member, target).map(|auth| auth.handle)
}

const ORIGIN: &str = "https://api.example:8443";

#[test]
fn members_sharing_an_origin_each_answer_their_own_binding_and_never_a_neighbours() {
    let connector = connector();
    DeclaredConns::bind_auth(&connector, OWNER, NEED, "alpha", ORIGIN, binding(1));
    DeclaredConns::bind_auth(&connector, OWNER, NEED, "beta", ORIGIN, binding(2));
    let target = "https://api.example:8443/v1/chat?stream=1";
    assert_eq!(bound(&connector, NEED, "alpha", target), Some(1));
    assert_eq!(bound(&connector, NEED, "beta", target), Some(2));
    assert_eq!(
        bound(&connector, NEED, "gamma", target),
        None,
        "a member bound nowhere borrows no neighbour's binding at the origin"
    );
    assert_eq!(
        bound(&connector, NEED, "alpha", "https://api.example:9443/v1/chat"),
        None,
        "a member's binding is its origin's alone"
    );
    assert_eq!(
        bound(&connector, NeedId(4), "alpha", target),
        None,
        "nor another need's"
    );
    assert_eq!(
        DeclaredConns::auth_of(&connector, InstanceId(8), NEED, "alpha", target).map(|a| a.handle),
        None,
        "nor another instance's"
    );
    // A neighbour bound again leaves every other member's binding as it was.
    DeclaredConns::bind_auth(&connector, OWNER, NEED, "beta", ORIGIN, binding(3));
    assert_eq!(bound(&connector, NEED, "alpha", target), Some(1));
    assert_eq!(bound(&connector, NEED, "beta", target), Some(3));
}

#[test]
fn a_request_naming_no_member_gets_no_binding_even_from_the_one_member_at_its_origin() {
    let connector = connector();
    DeclaredConns::bind_auth(&connector, OWNER, NEED, "alpha", ORIGIN, binding(1));
    let target = "https://api.example:8443/v1/chat";
    assert_eq!(bound(&connector, NEED, "alpha", target), Some(1));
    assert_eq!(
        bound(&connector, NEED, "", target),
        None,
        "a request naming no member is authenticated as nobody, even with one member bound at its origin"
    );
}

/// A key with every field fixed but the ones a test varies, before the pools seal it.
fn unsealed() -> PoolKey {
    PoolKey {
        owner: OWNER,
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
    }
}

/// `key` sealed by `pools`, then forced onto `like`'s hash: only `Eq` tells the two apart.
fn colliding(pools: &crate::pool::Pools, key: PoolKey, like: &PoolKey) -> PoolKey {
    let mut key = pools.keyed(key);
    key.hash = like.hash;
    key
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pooled_line_is_never_lent_to_another_need_or_instance() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pools = crate::pool::Pools::new(PoolPosture::NONE);
    let trusted = |config: rustls::ClientConfig| Some(crate::pool::Same::of(Arc::new(config)));
    let config = || {
        crate::tls::client::build_client_config(
            &busbar_contract::transport::trust::EgressTrust::default(),
        )
        .expect("a client config")
    };
    let sealed = || {
        Some(crate::pool::Same::of(Arc::new(
            crate::tls::client::Sealed::default(),
        )))
    };
    let base = PoolKey {
        trust: trusted(config()),
        sealed: sealed(),
        ..unsealed()
    };
    let lined = pools.keyed(base.clone());
    let others = [
        ("another need", PoolKey { need: NeedId(4), ..base.clone() }),
        ("another instance", PoolKey { owner: InstanceId(8), ..base.clone() }),
        ("another trust", PoolKey { trust: trusted(config()), ..base.clone() }),
        ("another seal", PoolKey { sealed: sealed(), ..base.clone() }),
    ];
    let mut far_ends = Vec::new();
    for (what, other) in others {
        let other = colliding(&pools, other, &lined);
        let idle = Idle::default();
        let now = Instant::now();
        idle.put(0, lined.clone(), connected(addr).await, now, POSTURE);
        far_ends.push(listener.accept().unwrap());
        assert!(
            idle.take(0, &other, now, POSTURE).is_none(),
            "a line is never lent to {what}, whose key hashes alike"
        );
        idle.put(0, other.clone(), connected(addr).await, now, POSTURE);
        far_ends.push(listener.accept().unwrap());
        assert!(idle.take(0, &other, now, POSTURE).is_some());
        assert!(
            idle.take(0, &other, now, POSTURE).is_none(),
            "{what} was lent its own line only"
        );
        assert!(
            idle.take(0, &lined, now, POSTURE).is_some(),
            "the line is still kept for its own key"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pool_key_collision_never_lends() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pools = crate::pool::Pools::new(PoolPosture::NONE);
    let first = pools.keyed(unsealed());
    let second = colliding(
        &pools,
        PoolKey {
            authority: "127.0.0.1:2".into(),
            ..unsealed()
        },
        &first,
    );
    assert_eq!(first.hash, second.hash, "the two keys collide");
    let idle = Idle::default();
    let now = Instant::now();
    let mut far_ends = Vec::new();
    idle.put(0, first.clone(), connected(addr).await, now, POSTURE);
    far_ends.push(listener.accept().unwrap());
    assert!(
        idle.take(0, &second, now, POSTURE).is_none(),
        "a colliding key is never lent the other's line"
    );
    idle.put(0, second.clone(), connected(addr).await, now, POSTURE);
    far_ends.push(listener.accept().unwrap());
    assert!(idle.take(0, &second, now, POSTURE).is_some());
    assert!(idle.take(0, &second, now, POSTURE).is_none());
    assert!(idle.take(0, &first, now, POSTURE).is_some());
    assert!(idle.take(0, &first, now, POSTURE).is_none());
}

/// A pooling connector carrying `http`, with the need declared.
fn pooling_with(judge: &Arc<Pending>) -> Connector {
    let connector = judged_by(judge).pooling(POSTURE);
    connector
        .carry_natively(vec![carrier(CARRIER_HTTP)], storage())
        .unwrap();
    DeclaredConns::declare(&connector, OWNER, NEED, &need(), None, None).unwrap();
    connector
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_judged_address_set_pins_the_dial() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let judge = Arc::new(Pending::default());
    let connector = pooling_with(&judge);
    let within = [addr.ip()];
    let literal = format!("http://{addr}/v1");
    let pinned = OpenDesc {
        within: &within,
        ..desc(&literal)
    };
    let conn = connector
        .open(OWNER, NEED, &pinned)
        .expect("an address in the set is dialled");
    assert_eq!(
        accepted(&listener, Duration::from_secs(5)),
        1,
        "the dial landed"
    );
    assert!(
        !keyed_for_the_pool(&connector, conn),
        "a pinned open's line is never pooled"
    );
    let unpinned = connector.open(OWNER, NEED, &desc(&literal)).unwrap();
    assert!(
        keyed_for_the_pool(&connector, unpinned),
        "the same open with no set is pooled"
    );
    accepted(&listener, Duration::from_secs(5));

    // A name whose judged address is in the set lands too.
    let named = format!("http://pinned.test:{}/v1", addr.port());
    let conn = connector
        .open(
            OWNER,
            NEED,
            &OpenDesc {
                within: &within,
                ..desc(&named)
            },
        )
        .expect("the judgement pends");
    judge.answer(&format!("pinned.test:{}", addr.port()), Ok(addr));
    let (_, held) = connector.slab.get(OWNER, conn).unwrap();
    let native = held.native.as_ref().unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match connector.landed_native(native, std::task::Waker::noop()) {
            Ok(()) => break,
            Err(ConnError::Pending) if Instant::now() < until => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            other => panic!("the pinned name's dial lands, not {other:?}"),
        }
    }
    assert_eq!(accepted(&listener, Duration::from_secs(5)), 1);
    assert!(!keyed_for_the_pool(&connector, conn));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rebound_name_is_refused_before_its_bytes_leave() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let judge = Arc::new(Pending::default());
    let connector = pooling_with(&judge);
    // The set the open was judged against; the name later answers an address outside it.
    let within = [std::net::IpAddr::from([127, 0, 0, 2])];
    let named = format!("http://rebound.test:{}/v1", addr.port());
    let conn = connector
        .open(
            OWNER,
            NEED,
            &OpenDesc {
                within: &within,
                body: busbar_contract::conn::Bytes::from_static(b"the request body"),
                ..desc(&named)
            },
        )
        .expect("the judgement pends");
    assert!(read_now(&connector, conn).is_pending());
    assert_eq!(
        Conns::write(&connector, OWNER, conn, b"more", false, false),
        Err(ConnError::Pending),
        "a write while the name is judged is held"
    );
    judge.answer(&format!("rebound.test:{}", addr.port()), Ok(addr));
    assert_eq!(
        read_now(&connector, conn).map(|read| read.map(|_| ())),
        std::task::Poll::Ready(Err(ConnError::Refused)),
        "an address outside the set refuses the open"
    );
    assert_eq!(
        read_now(&connector, conn).map(|read| read.map(|_| ())),
        std::task::Poll::Ready(Err(ConnError::Refused)),
        "the refusal stays"
    );
    assert_eq!(
        Conns::write(&connector, OWNER, conn, b"more", false, false),
        Err(ConnError::Refused)
    );
    // A literal outside the set is refused at the open.
    let literal = format!("http://{addr}/v1");
    assert_eq!(
        connector
            .open(
                OWNER,
                NEED,
                &OpenDesc {
                    within: &within,
                    ..desc(&literal)
                }
            )
            .map(|_| ()),
        Err(ConnError::Refused)
    );
    assert_eq!(
        accepted(&listener, Duration::from_millis(200)),
        0,
        "nothing was dialled: no byte left"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_framed_operator_infrastructure_need_without_a_declared_target_is_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let connector = connector();
    connector
        .carry_natively(vec![carrier(CARRIER_HTTP)], storage())
        .unwrap();
    let infrastructure = ReadNeed {
        egress_class: busbar_contract::abi::host::conn::connector::EGRESS_OPERATOR_INFRASTRUCTURE,
        ..need()
    };
    // Served first as an ordinary need, then declared again as untargeted operator infrastructure.
    DeclaredConns::declare(&connector, OWNER, NEED, &need(), None, None).unwrap();
    assert_eq!(
        DeclaredConns::declare(&connector, OWNER, NEED, &infrastructure, None, None),
        Err(ConnError::Refused),
        "operator infrastructure names its target"
    );
    assert_eq!(
        DeclaredConns::declare(&connector, OWNER, NeedId(4), &infrastructure, None, None),
        Err(ConnError::Refused)
    );
    let code = busbar_kernel::diagnostics::PLUGIN_DECLARES_RETIRED_ABI_VALUE.code;
    {
        let flagged = connector.flagged.lock().unwrap();
        assert!(flagged.contains(&(OWNER, code)), "the shape is flagged");
        assert_eq!(
            flagged.len(),
            1,
            "the instance is flagged once, however often it declares the shape"
        );
    }
    for need in [NEED, NeedId(4)] {
        assert!(connector.native_need(OWNER, need).is_none());
        assert!(connector.open(OWNER, need, &desc(&format!("http://{addr}/v1"))).is_err());
    }
    assert_eq!(accepted(&listener, Duration::from_millis(200)), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn program_constraint_fields_never_reach_a_network_open() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let connector = connector();
    connector
        .carry_natively(vec![carrier(CARRIER_HTTP)], storage())
        .unwrap();
    DeclaredConns::declare(&connector, OWNER, NEED, &need(), None, None).unwrap();
    let target = format!("http://{addr}/v1");
    let instance = busbar_contract::conn::PROGRAM_EXPECT_INSTANCE_FIELD.to_ascii_uppercase();
    let generation = format!(" {} ", busbar_contract::conn::PROGRAM_EXPECT_GENERATION_FIELD);
    for field in [instance.as_str(), generation.as_str()] {
        let fields = [("accept", b"*/*".as_slice()), (field, b"7".as_slice())];
        assert_eq!(
            connector
                .open(
                    OWNER,
                    NEED,
                    &OpenDesc {
                        fields: &fields,
                        ..desc(&target)
                    }
                )
                .map(|_| ()),
            Err(ConnError::Refused),
            "a field only a member program reads refuses the open ({field:?})"
        );
    }
    assert_eq!(
        accepted(&listener, Duration::from_millis(200)),
        0,
        "nothing reached a network open"
    );
    connector
        .open(OWNER, NEED, &desc(&target))
        .expect("the same open without the field dials");
    assert_eq!(accepted(&listener, Duration::from_secs(5)), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_target_the_guard_refuses_never_reaches_the_proxy() {
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let judge = Arc::new(Pending::default());
    let connector = judged_by(&judge).proxying(Some(crate::proxy::test_config(
        "127.0.0.1",
        proxy_port,
        None,
        "",
    )));
    connector
        .carry_natively(vec![carrier(CARRIER_HTTP)], storage())
        .unwrap();
    DeclaredConns::declare(&connector, OWNER, NEED, &need(), None, None).unwrap();
    let proxy_endpoint = format!("127.0.0.1:{proxy_port}");

    // Refused at once (a metadata host): the proxy is neither judged nor dialled.
    assert_eq!(
        connector
            .open(OWNER, NEED, &desc("http://169.254.169.254/latest/meta-data"))
            .map(|_| ()),
        Err(ConnError::Refused)
    );
    assert!(
        !judge.asked().contains(&proxy_endpoint),
        "a target refused at once never consults the proxy"
    );

    // Refused once its name is judged (an internal address): both judgements were asked, the proxy is never
    // asked for a tunnel.
    let conn = connector
        .open(OWNER, NEED, &desc("http://internal.test/v1"))
        .expect("the target's judgement pends");
    assert!(read_now(&connector, conn).is_pending());
    judge.answer(
        "internal.test:80",
        Err(busbar_contract::abi::host::service::DEST_INTERNAL),
    );
    assert_eq!(
        read_now(&connector, conn).map(|read| read.map(|_| ())),
        std::task::Poll::Ready(Err(ConnError::Refused)),
        "the guard's refusal is the open's answer"
    );
    assert_eq!(
        accepted(&proxy, Duration::from_millis(200)),
        0,
        "the proxy was never asked for a tunnel"
    );
}
