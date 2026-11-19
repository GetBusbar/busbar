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

/// THE DECLARE/OPEN REFUSAL FIXTURE: a native need's refusals at declare and at open, each answered before the
/// judge or any dial runs; the pin a config-targeted need is declared with; the admission of a pinned target.
mod declare_open_refusals {
    use super::*;

    use std::sync::Mutex;

    use busbar_contract::abi::host::conn::connector::{
        EGRESS_LOOPBACK_ALLOWED, EGRESS_OPEN_WEB, EGRESS_OPERATOR_INFRASTRUCTURE, EGRESS_PROVIDER,
    };
    use busbar_contract::conn::Bytes;
    use busbar_contract::services::codes::{DEST_INTERNAL, DEST_METADATA};

    use crate::conns::refusal_text;
    use crate::DialJudge;

    /// A second owner, whose authority the host does not hold.
    const OTHER: InstanceId = InstanceId(8);

    /// How long a refused open is given to have dialled anyway (as the tests above wait).
    const SETTLE: Duration = Duration::from_millis(200);

    /// How long an admitted open's connect is given to land at its far end.
    const LANDS: Duration = Duration::from_secs(10);

    /// The fixture judge: it writes down every authority it is asked to judge and the class it is asked in. A
    /// loopback literal (the tests' far ends) is admitted, except in `restricted`, a class whose rule refuses an
    /// internal address; every other target is judged by the connector's own literal guard (a metadata address
    /// refused in every class, a private one per the class's rule).
    struct Recording {
        guard: crate::conns::LiteralsOnly,
        restricted: Option<u32>,
        asked: Mutex<Vec<(String, u32)>>,
    }

    impl Recording {
        fn new(restricted: Option<u32>) -> Arc<Self> {
            Arc::new(Self {
                guard: crate::conns::LiteralsOnly(crate::conns::guard::Guard::default()),
                restricted,
                asked: Mutex::new(Vec::new()),
            })
        }

        fn asked(&self) -> Vec<(String, u32)> {
            self.asked.lock().expect("asked").clone()
        }

        fn count(&self) -> usize {
            self.asked.lock().expect("asked").len()
        }
    }

    impl DialJudge for Recording {
        fn judge_dial(
            &self,
            dest: &str,
            class: u32,
            done: Judged,
        ) -> Option<Result<SocketAddr, Verdict>> {
            self.asked
                .lock()
                .expect("asked")
                .push((dest.to_owned(), class));
            match crate::conns::socket::address_of(dest) {
                Some(addr) if addr.ip().is_loopback() => Some(if self.restricted == Some(class) {
                    Err(DEST_INTERNAL)
                } else {
                    Ok(addr)
                }),
                _ => self.guard.judge_dial(dest, class, done),
            }
        }
    }

    /// A connector judging through `judge`, keeping no idle connection (every admitted open dials), its `http`
    /// carrier handed over, and its owner carrying `insecure_transport.accept: plaintext` (SEC-2: the tests' far
    /// ends are plaintext loopback; `open-web` never admits plaintext whatever the owner accepts).
    fn judged_by(judge: &Arc<Recording>) -> Connector {
        let connector = Connector::serving(
            Arc::clone(judge) as Arc<dyn DialJudge>,
            None,
            Arc::new(|_, _| {}),
        )
        .pooling(PoolPosture::NONE);
        connector
            .carry_natively(vec![carrier(CARRIER_HTTP)], storage())
            .expect("the hand-over");
        DeclaredConns::accept_plaintext(&connector, OWNER);
        connector
    }

    /// A listening far end that has not been dialled.
    fn far_end() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a far end");
        listener.set_nonblocking(true).expect("non-blocking");
        let addr = listener.local_addr().expect("its address");
        (listener, addr)
    }

    /// Whether `listener` is handed a connection within `wait`.
    fn dialled(listener: &TcpListener, wait: Duration) -> bool {
        let until = Instant::now() + wait;
        loop {
            if listener.accept().is_ok() {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// An outbound `http` need in `class` whose target its config names (`target_from`).
    fn pinned(class: u32) -> ReadNeed {
        ReadNeed {
            egress_class: class,
            target_from: "settings.url".into(),
            ..need()
        }
    }

    fn declare(
        connector: &Connector,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
    ) -> Result<(), ConnError> {
        DeclaredConns::declare(connector, OWNER, need, spec, target, None)
    }

    /// An auth instance's token request to `far` with `fields`.
    fn token<'a>(far: &'a str, fields: &'a [(&'a str, &'a [u8])]) -> OpenDesc<'a> {
        OpenDesc {
            fields,
            method: b"POST",
            head_target: b"/token",
            body: Bytes::from_static(b"grant_type=authorization_code"),
            ..desc(far)
        }
    }

    /// The open of `need` at `desc`, its connection id dropped.
    fn open(
        connector: &Connector,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<(), ConnError> {
        connector.open(owner, need, desc).map(drop)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actual_secure_and_undeclared_refusals_happen_before_any_destination_open() {
        let (listener, addr) = far_end();
        let judge = Recording::new(None);
        let connector = judged_by(&judge);
        declare(&connector, NEED, &need(), None).expect("a default-class need");
        let open_web = NeedId(5);
        let open_web_need = ReadNeed {
            egress_class: EGRESS_OPEN_WEB,
            ..need()
        };
        declare(&connector, open_web, &open_web_need, None).expect("an open-web need");
        let target = format!("http://{addr}/v1");

        assert_eq!(
            DeclaredConns::open_request(&connector, OWNER, NEED, &desc(&target), true, 5_000)
                .map(drop),
            Err(ConnError::AuthRefused),
            "an auth that must be delivered secured is refused a plaintext target"
        );
        assert_eq!(
            open(&connector, OWNER, NeedId(9), &desc(&target)),
            Err(ConnError::UndeclaredNeed),
            "an undeclared need"
        );
        let refused_head = OpenDesc {
            head_target: b"/v1\0",
            ..desc(&target)
        };
        assert_eq!(
            open(&connector, OWNER, NEED, &refused_head),
            Err(ConnError::Refused),
            "a refused head"
        );
        assert_eq!(
            open(&connector, OWNER, open_web, &desc(&target)),
            Err(ConnError::Refused),
            "a plaintext target in a class that requires security"
        );
        assert_eq!(
            connector.refusal(OWNER, open_web),
            Some(NeedRefusal::Policy(refusal_text::PLAINTEXT))
        );
        assert_eq!(judge.count(), 0, "no refusal reached the judge");
        assert!(!dialled(&listener, SETTLE), "no refusal dialled");

        let conn = connector
            .open(OWNER, NEED, &desc(&target))
            .expect("the admitted open");
        assert_eq!(
            judge.asked(),
            vec![(addr.to_string(), EGRESS_DEFAULT)],
            "an admitted target crosses the judge exactly once"
        );
        assert!(dialled(&listener, LANDS), "and is dialled");
        connector.close(OWNER, conn).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_need_in_a_restricted_class_is_refused_a_target_that_class_forbids() {
        let (listener, addr) = far_end();
        let judge = Recording::new(Some(EGRESS_PROVIDER));
        let connector = judged_by(&judge);
        let restricted = NeedId(4);
        declare(&connector, NEED, &need(), None).expect("the default-class need");
        let provider = ReadNeed {
            egress_class: EGRESS_PROVIDER,
            ..need()
        };
        declare(&connector, restricted, &provider, None).expect("the restricted need");
        let target = format!("http://{addr}/v1");

        assert_eq!(
            open(&connector, OWNER, restricted, &desc(&target)),
            Err(ConnError::Refused),
            "the restricted need is judged under its own class"
        );
        assert_eq!(
            connector.refusal(OWNER, restricted),
            Some(NeedRefusal::Policy(crate::conns::verdict_text(
                DEST_INTERNAL
            )))
        );
        assert!(
            !dialled(&listener, SETTLE),
            "the refused need dialled nothing"
        );

        let conn = connector
            .open(OWNER, NEED, &desc(&target))
            .expect("the default-class need opens the same target");
        assert!(dialled(&listener, LANDS));
        connector.close(OWNER, conn).unwrap();
        let authority = addr.to_string();
        assert_eq!(
            judge.asked(),
            vec![
                (authority.clone(), EGRESS_PROVIDER),
                (authority, EGRESS_DEFAULT)
            ],
            "each need was judged once, under its own class"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_config_targeted_need_dialing_elsewhere_is_refused() {
        let (listener, addr) = far_end();
        let (other_listener, other) = far_end();
        let judge = Recording::new(None);
        let connector = judged_by(&judge);
        let declared = format!("http://{addr}/v1");
        declare(&connector, NEED, &pinned(EGRESS_DEFAULT), Some(&declared))
            .expect("the config target is admitted");
        let judged_at_declare = judge.count();

        for (elsewhere, what) in [
            (
                format!("http://127.0.0.2:{}/v1", addr.port()),
                "another host",
            ),
            (
                format!("http://127.0.0.1:{}/v1", other.port()),
                "another port",
            ),
            (format!("https://{addr}/v1"), "the same authority secured"),
        ] {
            assert_eq!(
                open(&connector, OWNER, NEED, &desc(&elsewhere)),
                Err(ConnError::Refused),
                "{what}"
            );
        }
        assert_eq!(
            judge.count(),
            judged_at_declare,
            "a target off the pin is refused before the judge"
        );
        assert!(
            !dialled(&other_listener, SETTLE),
            "another port is never dialled"
        );
        assert!(!dialled(&listener, SETTLE));

        let conn = connector
            .open(OWNER, NEED, &desc(&declared))
            .expect("the declared target opens");
        assert!(dialled(&listener, LANDS));
        connector.close(OWNER, conn).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fill_declared_need_is_pinned_to_its_resolved_target() {
        let (first_listener, first) = far_end();
        let (moved_listener, moved) = far_end();
        let judge = Recording::new(None);
        let connector = judged_by(&judge);
        let spec = pinned(EGRESS_DEFAULT);
        let first = format!("http://{first}/v1");
        let moved = format!("http://{moved}/v1");

        declare(&connector, NEED, &spec, Some(&first)).expect("the resolved target");
        assert_eq!(
            open(&connector, OWNER, NEED, &desc(&moved)),
            Err(ConnError::Refused),
            "a target other than the pin"
        );
        assert!(!dialled(&moved_listener, SETTLE));
        let conn = connector
            .open(OWNER, NEED, &desc(&first))
            .expect("the resolved target opens");
        assert!(dialled(&first_listener, LANDS));
        connector.close(OWNER, conn).unwrap();

        declare(&connector, NEED, &spec, Some(&moved)).expect("the re-declaration");
        assert_eq!(
            connector
                .native_need(OWNER, NEED)
                .and_then(|n| n.declared_target.clone())
                .as_deref(),
            Some(moved.as_str()),
            "the re-declaration moved the pin"
        );
        assert_eq!(
            open(&connector, OWNER, NEED, &desc(&first)),
            Err(ConnError::Refused),
            "the old pin"
        );
        assert!(
            !dialled(&first_listener, SETTLE),
            "the old pin is not dialled"
        );
        let conn = connector
            .open(OWNER, NEED, &desc(&moved))
            .expect("the re-declared target opens");
        assert!(dialled(&moved_listener, LANDS));
        connector.close(OWNER, conn).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fill_declared_need_whose_target_resolved_to_nothing_is_refused() {
        let (listener, addr) = far_end();
        let judge = Recording::new(None);
        let connector = judged_by(&judge);
        let spec = ReadNeed {
            target_from: "settings.upstream".into(),
            ..need()
        };
        let resolved = format!("http://{addr}/v1");

        // Never resolved: refused at declare, unjudged.
        let never = NeedId(6);
        assert_eq!(
            declare(&connector, never, &spec, None),
            Err(ConnError::Refused)
        );
        assert_eq!(
            connector.refusal(OWNER, never),
            Some(NeedRefusal::Policy(refusal_text::UNRESOLVED))
        );
        assert_eq!(judge.count(), 0, "a need resolved to nothing is not judged");

        // Resolved once, then to nothing: the earlier pin does not survive.
        declare(&connector, NEED, &spec, Some(&resolved)).expect("the resolved target");
        assert_eq!(
            declare(&connector, NEED, &spec, None),
            Err(ConnError::Refused)
        );
        assert_eq!(
            DeclaredConns::declared(&connector, OWNER, NEED),
            Some(Err(ConnError::Refused)),
            "the refusal is the answer kept"
        );
        assert_eq!(
            connector.refusal(OWNER, NEED),
            Some(NeedRefusal::Policy(refusal_text::UNRESOLVED))
        );
        assert!(connector.native_need(OWNER, NEED).is_none());
        let judged = judge.count();
        for target in [resolved.as_str(), ""] {
            assert_eq!(
                open(&connector, OWNER, NEED, &desc(target)),
                Err(ConnError::Refused),
                "{target:?}"
            );
            assert_eq!(
                open(&connector, OWNER, never, &desc(target)),
                Err(ConnError::UndeclaredNeed),
                "{target:?}: a need never admitted is not declared"
            );
        }
        assert_eq!(judge.count(), judged, "the refused needs reach no judge");
        assert!(!dialled(&listener, SETTLE), "and nothing is dialled");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_head_carrying_nul_or_its_own_framing_is_refused_before_any_dial() {
        let (listener, addr) = far_end();
        let judge = Recording::new(None);
        let connector = judged_by(&judge);
        declare(&connector, NEED, &need(), None).expect("the need");
        let far = format!("http://{addr}/v1");
        let nul_target = format!("http://{addr}/v1\0");
        let crlf_target = format!("http://{addr}/v1\r\nX: y");
        let refused: &[(&str, OpenDesc<'_>)] = &[
            ("NUL in the target", desc(&nul_target)),
            ("CRLF in the target", desc(&crlf_target)),
            (
                "NUL in the method",
                OpenDesc {
                    method: b"PO\0ST",
                    ..desc(&far)
                },
            ),
            (
                "CR in the method",
                OpenDesc {
                    method: b"POST\r",
                    ..desc(&far)
                },
            ),
            (
                "NUL in the request target",
                OpenDesc {
                    head_target: b"/v1/\0traces",
                    ..desc(&far)
                },
            ),
            (
                "CRLF in the request target",
                OpenDesc {
                    head_target: b"/v1\r\nX: y",
                    ..desc(&far)
                },
            ),
            (
                "NUL in a field name",
                OpenDesc {
                    fields: &[("x-\0nul", b"v".as_slice())],
                    ..desc(&far)
                },
            ),
            (
                "LF in a field name",
                OpenDesc {
                    fields: &[("Bad\nName", b"v".as_slice())],
                    ..desc(&far)
                },
            ),
            (
                "NUL in a field value",
                OpenDesc {
                    fields: &[("x-nul", b"a\0b".as_slice())],
                    ..desc(&far)
                },
            ),
            (
                "CRLF in a field value",
                OpenDesc {
                    fields: &[("x-evil", b"a\r\nInjected: 1".as_slice())],
                    ..desc(&far)
                },
            ),
            (
                "the caller's own content-length",
                OpenDesc {
                    fields: &[
                        ("authorization", b"Bearer abc.def".as_slice()),
                        ("content-length", b"5".as_slice()),
                    ],
                    body: Bytes::from_static(b"token"),
                    ..desc(&far)
                },
            ),
            (
                "the caller's own Content-Length",
                OpenDesc {
                    fields: &[("Content-Length", b"0".as_slice())],
                    ..desc(&far)
                },
            ),
            (
                "the caller's own transfer-encoding",
                OpenDesc {
                    fields: &[("Transfer-Encoding", b"chunked".as_slice())],
                    body: Bytes::from_static(b"token"),
                    ..desc(&far)
                },
            ),
            (
                "the caller's own TRANSFER-ENCODING",
                OpenDesc {
                    fields: &[("TRANSFER-ENCODING", b"identity".as_slice())],
                    ..desc(&far)
                },
            ),
            (
                "a padded framing field name",
                OpenDesc {
                    fields: &[(" content-length", b"0".as_slice())],
                    ..desc(&far)
                },
            ),
        ];
        for (why, refused) in refused {
            assert_eq!(
                open(&connector, OWNER, NEED, refused),
                Err(ConnError::Refused),
                "{why}"
            );
        }
        assert_eq!(judge.count(), 0, "a refused head reaches no judge");
        assert!(!dialled(&listener, SETTLE), "a refused head dials nothing");

        let conn = connector
            .open(
                OWNER,
                NEED,
                &OpenDesc {
                    fields: &[("authorization", b"Bearer abc.def".as_slice())],
                    method: b"POST",
                    head_target: b"/v1/traces",
                    body: Bytes::from_static(b"token"),
                    ..desc(&far)
                },
            )
            .expect("a clean head opens");
        assert_eq!(judge.count(), 1);
        assert!(dialled(&listener, LANDS));
        connector.close(OWNER, conn).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_auth_instances_own_host_field_is_refused_before_any_dial() {
        let (listener, addr) = far_end();
        let judge = Recording::new(None);
        let connector = judged_by(&judge);
        DeclaredConns::hold_authority(&connector, OWNER);
        for owner in [OWNER, OTHER] {
            DeclaredConns::declare(&connector, owner, NEED, &need(), None, None).expect("the need");
        }
        let far = format!("http://{addr}/token");
        let far = far.as_str();
        for host in ["host", "Host", "HOST", " host"] {
            let fields: &[(&str, &[u8])] = &[
                (
                    "content-type",
                    b"application/x-www-form-urlencoded".as_slice(),
                ),
                (host, b"idp.example.com".as_slice()),
            ];
            assert_eq!(
                open(&connector, OWNER, NEED, &token(far, fields)),
                Err(ConnError::Refused),
                "the auth instance's own {host:?} field"
            );
        }
        assert_eq!(judge.count(), 0, "a refused head reaches no judge");
        assert!(!dialled(&listener, SETTLE), "a refused head dials nothing");

        let conn = connector
            .open(
                OWNER,
                NEED,
                &token(
                    far,
                    &[(
                        "content-type",
                        b"application/x-www-form-urlencoded".as_slice(),
                    )],
                ),
            )
            .expect("the auth instance's clean head opens");
        assert!(dialled(&listener, LANDS));
        connector.close(OWNER, conn).unwrap();

        let conn = connector
            .open(
                OTHER,
                NEED,
                &token(far, &[("host", b"upstream.example.com".as_slice())]),
            )
            .expect("an owner whose authority is not held states its own host field");
        assert!(dialled(&listener, LANDS));
        connector.close(OTHER, conn).unwrap();
        assert_eq!(judge.count(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_settings_derived_target_is_declared_without_its_userinfo() {
        const USER: &str = "the-user";
        const SECRET: &str = "s3cret-pw";
        let (listener, addr) = far_end();
        let judge = Recording::new(None);
        let connector = judged_by(&judge);
        let mut said: Vec<String> = Vec::new();
        for (credentialed, cleared) in [
            (
                format!("http://{USER}:{SECRET}@{addr}/v1/traces"),
                format!("http://{addr}/v1/traces"),
            ),
            (format!("http://{USER}@{addr}"), format!("http://{addr}")),
        ] {
            assert_eq!(
                declare(
                    &connector,
                    NEED,
                    &pinned(EGRESS_DEFAULT),
                    Some(&credentialed)
                ),
                Ok(()),
                "a settings-derived target is declared"
            );
            assert_eq!(
                connector
                    .native_need(OWNER, NEED)
                    .and_then(|n| n.declared_target.clone())
                    .as_deref(),
                Some(cleared.as_str()),
                "pinned without its userinfo"
            );
            said.push(format!(
                "{:?} {:?}",
                connector.refusal(OWNER, NEED),
                DeclaredConns::declared(&connector, OWNER, NEED)
            ));
            let conn = connector
                .open(OWNER, NEED, &desc(""))
                .expect("the cleared target opens");
            assert!(dialled(&listener, LANDS), "at the stripped authority");
            connector.close(OWNER, conn).unwrap();
        }
        assert!(
            judge
                .asked()
                .iter()
                .all(|(authority, _)| *authority == addr.to_string()),
            "only the stripped authority was judged: {:?}",
            judge.asked()
        );
        said.push(format!("{:?}", judge.asked()));

        // A target the plugin's own settings did not derive keeps its userinfo, and is refused for it.
        let named = NeedId(4);
        let credentialed = format!("http://{USER}:{SECRET}@{addr}/v1");
        assert_eq!(
            declare(&connector, named, &need(), Some(&credentialed)),
            Err(ConnError::Refused)
        );
        assert_eq!(
            connector.refusal(OWNER, named),
            Some(NeedRefusal::Policy(refusal_text::CREDENTIALED))
        );
        said.push(format!("{:?}", connector.refusal(OWNER, named)));
        for line in &said {
            assert!(
                !line.contains(SECRET) && !line.contains(USER),
                "the dropped userinfo was repeated: {line}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pinned_carrier_need_uses_the_same_authority_as_its_dial() {
        let (listener, addr) = far_end();
        let judge = Recording::new(None);
        let connector = judged_by(&judge);
        let authority = addr.to_string();
        for (id, pin) in [
            (NeedId(10), format!("http://{addr}")),
            (NeedId(11), format!("http://{addr}/v1/traces")),
        ] {
            let before = judge.count();
            assert_eq!(
                declare(&connector, id, &pinned(EGRESS_DEFAULT), Some(&pin)),
                Ok(())
            );
            assert_eq!(DeclaredConns::declared(&connector, OWNER, id), Some(Ok(())));
            let conn = connector
                .open(OWNER, id, &desc(""))
                .expect("the pinned need opens");
            assert!(dialled(&listener, LANDS), "{pin}");
            connector.close(OWNER, conn).unwrap();
            assert_eq!(
                judge.asked()[before..].to_vec(),
                vec![
                    (authority.clone(), EGRESS_OPERATOR_INFRASTRUCTURE),
                    (authority.clone(), EGRESS_OPERATOR_INFRASTRUCTURE)
                ],
                "{pin}: the declare judged the authority its dial was judged at, in the same class"
            );
        }

        let before = judge.count();
        for (id, pin, class, why) in [
            (
                NeedId(12),
                authority.clone(),
                EGRESS_DEFAULT,
                NeedRefusal::Policy(refusal_text::UNLOCATED),
            ),
            (
                NeedId(13),
                "http://169.254.169.254:80".to_owned(),
                EGRESS_DEFAULT,
                NeedRefusal::Policy(crate::conns::verdict_text(DEST_METADATA)),
            ),
            (
                NeedId(14),
                format!("http://{addr}"),
                EGRESS_OPEN_WEB,
                NeedRefusal::Policy(refusal_text::PLAINTEXT),
            ),
        ] {
            assert_eq!(
                declare(&connector, id, &pinned(class), Some(&pin)),
                Err(ConnError::Refused),
                "{pin}"
            );
            assert_eq!(
                DeclaredConns::declared(&connector, OWNER, id),
                Some(Err(ConnError::Refused))
            );
            assert_eq!(connector.refusal(OWNER, id), Some(why), "{pin}");
            assert!(connector.native_need(OWNER, id).is_none());
            assert_eq!(
                open(&connector, OWNER, id, &desc("")),
                Err(ConnError::Refused),
                "{pin}"
            );
        }
        assert_eq!(
            judge.asked()[before..].to_vec(),
            vec![(
                "169.254.169.254:80".to_owned(),
                EGRESS_OPERATOR_INFRASTRUCTURE
            )],
            "only the metadata pin needed the judge to refuse it"
        );
        assert!(!dialled(&listener, SETTLE), "a refused pin dials nothing");
    }

    #[test]
    fn an_open_web_need_pinned_to_a_plaintext_target_is_refused_at_declare() {
        let judge = Recording::new(None);
        let connector = judged_by(&judge);
        let spec = pinned(EGRESS_OPEN_WEB);
        for (id, pin) in [
            (NeedId(0), "http://127.0.0.1:4318"),
            (NeedId(1), "http://localhost:4318"),
            (NeedId(2), "http://collector.example/v1/traces"),
        ] {
            assert_eq!(
                declare(&connector, id, &spec, Some(pin)),
                Err(ConnError::Refused),
                "{pin}"
            );
            assert_eq!(
                DeclaredConns::declared(&connector, OWNER, id),
                Some(Err(ConnError::Refused)),
                "{pin}: the admission the plugin reads"
            );
            assert_eq!(
                connector.refusal(OWNER, id),
                Some(NeedRefusal::Policy(refusal_text::PLAINTEXT)),
                "{pin}"
            );
            assert_eq!(
                open(&connector, OWNER, id, &desc(pin)),
                Err(ConnError::Refused),
                "{pin}"
            );
        }
        assert_eq!(
            judge.count(),
            0,
            "the owner's plaintext acceptance notwithstanding, refused before any judgement"
        );
    }

    #[test]
    fn a_pinned_target_every_dial_would_admit_is_admitted_at_declare() {
        let judge = Recording::new(None);
        let connector = judged_by(&judge);
        let secure = pinned(EGRESS_OPEN_WEB);
        for (id, pin) in [
            (NeedId(0), "https://collector.example:443"),
            (NeedId(1), "https://1.1.1.1:443/v1/traces"),
        ] {
            assert_eq!(declare(&connector, id, &secure, Some(pin)), Ok(()), "{pin}");
            assert_eq!(
                DeclaredConns::declared(&connector, OWNER, id),
                Some(Ok(())),
                "{pin}"
            );
            assert_eq!(connector.refusal(OWNER, id), None, "{pin}");
            assert_eq!(
                connector
                    .native_need(OWNER, id)
                    .and_then(|n| n.declared_target.clone())
                    .as_deref(),
                Some(pin)
            );
        }
        let plain = pinned(EGRESS_DEFAULT);
        assert_eq!(
            declare(&connector, NeedId(2), &plain, Some("http://127.0.0.1:4318")),
            Ok(())
        );
        assert_eq!(
            DeclaredConns::declared(&connector, OWNER, NeedId(2)),
            Some(Ok(()))
        );
        assert_eq!(
            judge.asked(),
            vec![
                ("1.1.1.1:443".to_owned(), EGRESS_OPEN_WEB),
                ("127.0.0.1:4318".to_owned(), EGRESS_OPERATOR_INFRASTRUCTURE)
            ],
            "a literal is judged as its dial judges it; a name is resolved only at its dial"
        );
    }

    #[test]
    fn an_open_web_need_pinned_to_a_private_literal_is_refused_at_declare() {
        let judge = Recording::new(None);
        let connector = judged_by(&judge);
        let spec = pinned(EGRESS_OPEN_WEB);
        for (id, pin) in [
            (NeedId(0), "https://10.0.0.5:443"),
            (NeedId(1), "https://192.168.1.5/v1"),
        ] {
            assert_eq!(
                declare(&connector, id, &spec, Some(pin)),
                Err(ConnError::Refused),
                "{pin}"
            );
            assert_eq!(
                DeclaredConns::declared(&connector, OWNER, id),
                Some(Err(ConnError::Refused))
            );
            assert_eq!(
                connector.refusal(OWNER, id),
                Some(NeedRefusal::Policy(crate::conns::verdict_text(
                    DEST_INTERNAL
                ))),
                "{pin}"
            );
            assert!(connector.native_need(OWNER, id).is_none(), "{pin}");
        }
    }

    #[test]
    fn a_pinned_metadata_literal_is_refused_at_declare() {
        let judge = Recording::new(None);
        let connector = judged_by(&judge);
        let mut id = 0;
        for class in [
            EGRESS_DEFAULT,
            EGRESS_PROVIDER,
            EGRESS_OPERATOR_INFRASTRUCTURE,
            EGRESS_OPEN_WEB,
            EGRESS_LOOPBACK_ALLOWED,
        ] {
            for pin in [
                "https://169.254.169.254:443",
                "https://169.254.169.254/latest",
            ] {
                id += 1;
                let need = NeedId(id);
                assert_eq!(
                    declare(&connector, need, &pinned(class), Some(pin)),
                    Err(ConnError::Refused),
                    "class {class}: {pin}"
                );
                assert_eq!(
                    DeclaredConns::declared(&connector, OWNER, need),
                    Some(Err(ConnError::Refused))
                );
                assert_eq!(
                    connector.refusal(OWNER, need),
                    Some(NeedRefusal::Policy(crate::conns::verdict_text(
                        DEST_METADATA
                    ))),
                    "class {class}: {pin}"
                );
                assert!(connector.native_need(OWNER, need).is_none());
            }
        }
    }
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
    Connector::serving(
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
    )
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
        bound(
            &connector,
            NEED,
            "alpha",
            "https://api.example:9443/v1/chat"
        ),
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
        (
            "another need",
            PoolKey {
                need: NeedId(4),
                ..base.clone()
            },
        ),
        (
            "another instance",
            PoolKey {
                owner: InstanceId(8),
                ..base.clone()
            },
        ),
        (
            "another trust",
            PoolKey {
                trust: trusted(config()),
                ..base.clone()
            },
        ),
        (
            "another seal",
            PoolKey {
                sealed: sealed(),
                ..base.clone()
            },
        ),
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
        assert!(connector
            .open(OWNER, need, &desc(&format!("http://{addr}/v1")))
            .is_err());
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
    let generation = format!(
        " {} ",
        busbar_contract::conn::PROGRAM_EXPECT_GENERATION_FIELD
    );
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
            .open(
                OWNER,
                NEED,
                &desc("http://169.254.169.254/latest/meta-data")
            )
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

/// THE `Connector::anchor` FIXTURE (P095-1): anchors sealed per destination and per registration, held to a real
/// TLS handshake against a far end on loopback. What these prove ends where a transport session begins: the
/// connection's security (the key pin, the identity presented, the trust a line was verified under, the reach a
/// registration holds) is settled before a request byte could leave, so no session is needed here. A line is kept
/// for the next exchange when its answer was read whole; the session that reads it is the linked http image's, so
/// the pooled tests mark the exchange answered (`Exchange::ended`) and close it through the connection table's own
/// close, which keeps it exactly as a whole answer would.
mod anchor_seals {
    use std::io::Read as _;
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::task::Waker;

    use busbar_contract::abi::host::conn::connector::EGRESS_PROVIDER;
    use busbar_contract::conn::{Bytes, ConnId, NO_TICKET};
    use busbar_contract::crypto::testing::rcgen;
    use busbar_contract::transport::trust::{Anchors, ClientIdentity, EgressTrust};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use super::*;

    /// Another instance, which declared nothing.
    const OTHER: InstanceId = InstanceId(8);
    /// `OWNER`'s plaintext need (`NEED` is its secure one).
    const PLAIN: NeedId = NeedId(4);

    const POOLED: PoolPosture = PoolPosture {
        max_idle_per_host: 8,
        idle_timeout: Duration::from_secs(60),
    };

    /// A private root, under a subject no other root of this process carries.
    struct Pki {
        params: rcgen::CertificateParams,
        key: rcgen::KeyPair,
        der: Vec<u8>,
        pem: String,
    }

    /// A leaf a [`Pki`] signed: its certificate, its key (PKCS#8 DER) and its key pin.
    struct Leaf {
        der: Vec<u8>,
        key: Vec<u8>,
        pin: String,
    }

    impl Pki {
        fn new() -> Self {
            static ROOTS: AtomicUsize = AtomicUsize::new(0);
            let n = ROOTS.fetch_add(1, Ordering::Relaxed);
            let key = rcgen::KeyPair::generate().expect("a root key");
            let mut params =
                rcgen::CertificateParams::new(Vec::<String>::new()).expect("root params");
            params.distinguished_name.push(
                rcgen::DnType::CommonName,
                format!("anchor seal test root {n}"),
            );
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let cert = params.self_signed(&key).expect("the root");
            Self {
                der: cert.der().to_vec(),
                pem: cert.pem(),
                params,
                key,
            }
        }

        fn leaf(&self, name: &str) -> Leaf {
            let key = rcgen::KeyPair::generate().expect("a leaf key");
            let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
            let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
                .expect("leaf params")
                .signed_by(&key, &issuer)
                .expect("the leaf");
            Leaf {
                der: cert.der().to_vec(),
                key: key.serialize_der(),
                pin: busbar_contract::transport::trust::key_pin(&key.subject_public_key_info()),
            }
        }

        /// The connector's trust: the public roots and this root.
        fn trust(&self) -> EgressTrust {
            EgressTrust {
                extra_anchors: vec![self.der.clone()],
                ..EgressTrust::default()
            }
        }
    }

    fn identity(leaf: &Leaf) -> ClientIdentity {
        ClientIdentity {
            cert_chain: vec![leaf.der.clone()],
            private_key: leaf.key.clone().into(),
        }
    }

    fn pinned(leaf: &Leaf) -> Anchors {
        Anchors {
            key_pin: Some(leaf.pin.clone()),
            ..Anchors::default()
        }
    }

    /// What a TLS far end met on one connection, in the order it accepted them.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Met {
        /// The handshake completed; the client certificate presented, if any.
        Secured { presented: Option<Vec<u8>> },
        /// The handshake failed.
        Refused,
    }

    /// A far end on loopback: its URL, what it met, how many connections it accepted and how many
    /// application bytes reached it.
    struct FarEnd {
        target: String,
        met: Arc<Mutex<Vec<Met>>>,
        accepted: Arc<AtomicUsize>,
        app_bytes: Arc<AtomicUsize>,
    }

    impl FarEnd {
        /// What it met, once `count` connections were met (or ten seconds passed).
        async fn meetings(&self, count: usize) -> Vec<Met> {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let met = self.met.lock().expect("meetings").clone();
                if met.len() >= count || Instant::now() >= deadline {
                    return met;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        /// The connections it accepted, once at least `count` were (or ten seconds passed).
        async fn accepted(&self, count: usize) -> usize {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let accepted = self.accepted.load(Ordering::SeqCst);
                if accepted >= count || Instant::now() >= deadline {
                    return accepted;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        fn app_bytes(&self) -> usize {
            self.app_bytes.load(Ordering::SeqCst)
        }
    }

    /// Accept on a loopback port, counting, handing each connection to `each` on its own thread.
    fn listening(
        scheme: &str,
        each: impl Fn(TcpStream, Arc<Mutex<Vec<Met>>>, Arc<AtomicUsize>) + Send + Sync + 'static,
    ) -> FarEnd {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        let host = if scheme == "https" {
            "localhost"
        } else {
            "127.0.0.1"
        };
        let far = FarEnd {
            target: format!("{scheme}://{host}:{port}/v1"),
            met: Arc::default(),
            accepted: Arc::default(),
            app_bytes: Arc::default(),
        };
        let (met, accepted, app_bytes) = (
            Arc::clone(&far.met),
            Arc::clone(&far.accepted),
            Arc::clone(&far.app_bytes),
        );
        let each = Arc::new(each);
        std::thread::spawn(move || {
            for tcp in listener.incoming() {
                let Ok(tcp) = tcp else { return };
                accepted.fetch_add(1, Ordering::SeqCst);
                let (each, met, app_bytes) =
                    (Arc::clone(&each), Arc::clone(&met), Arc::clone(&app_bytes));
                std::thread::spawn(move || each(tcp, met, app_bytes));
            }
        });
        far
    }

    /// A plaintext far end that holds each connection open and counts what it reads.
    fn plain_far_end() -> FarEnd {
        listening("http", |mut tcp, _, app_bytes| {
            let mut buf = [0_u8; 256];
            while let Ok(n @ 1..) = tcp.read(&mut buf) {
                app_bytes.fetch_add(n, Ordering::SeqCst);
            }
        })
    }

    /// A TLS far end serving `leaf` as `localhost`, asking for a client certificate under `asks`
    /// (and taking a connection that presents none), holding each connection open after its
    /// handshake and counting the application bytes it reads.
    fn tls_far_end(leaf: &Leaf, asks: Option<&Pki>) -> FarEnd {
        let chain = vec![CertificateDer::from(leaf.der.clone())];
        let key = PrivateKeyDer::try_from(leaf.key.clone()).expect("the leaf's key");
        let verifier = asks.map(|pki| {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(CertificateDer::from(pki.der.clone()))
                .expect("the client root");
            busbar_contract::crypto::tls::client_verifier(Arc::new(roots), |b| {
                b.allow_unauthenticated()
            })
            .expect("a client verifier")
        });
        let config = busbar_contract::crypto::tls::server_config(|builder| {
            let builder = match verifier {
                Some(verifier) => builder.with_client_cert_verifier(verifier),
                None => builder.with_no_client_auth(),
            };
            builder.with_single_cert(chain, key)
        })
        .expect("a server config");
        listening("https", move |mut tcp, met, app_bytes| {
            let Ok(mut tls) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                return;
            };
            while tls.is_handshaking() {
                if tls.complete_io(&mut tcp).is_err() {
                    met.lock().expect("meetings").push(Met::Refused);
                    return;
                }
            }
            let presented = tls
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|leaf| leaf.to_vec());
            met.lock()
                .expect("meetings")
                .push(Met::Secured { presented });
            let mut stream = rustls::Stream::new(&mut tls, &mut tcp);
            let mut buf = [0_u8; 256];
            while let Ok(n @ 1..) = stream.read(&mut buf) {
                app_bytes.fetch_add(n, Ordering::SeqCst);
            }
        })
    }

    /// `localhost:<port>` is loopback; an IP literal is judged as [`loopback`] judges it.
    fn named_loopback(
        target: &str,
        class: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, Verdict>> {
        match target
            .strip_prefix("localhost:")
            .and_then(|port| port.parse::<u16>().ok())
        {
            Some(port) => Some(Ok(SocketAddr::from(([127, 0, 0, 1], port)))),
            None => loopback(target, class, done),
        }
    }

    /// A connector trusting `trust` (with its policy known when `known`: member roots can be sealed
    /// on it; otherwise its client config is opaque), keeping lines under `posture`, carrying http
    /// natively, with `OWNER`'s secure `NEED` and plaintext `PLAIN` declared.
    fn anchoring(trust: EgressTrust, known: bool, posture: PoolPosture) -> Connector {
        let c = if known {
            Connector::serving_with_trust(Arc::new(named_loopback), trust, Arc::new(|_, _| {}))
                .expect("a usable trust")
        } else {
            let config =
                crate::tls::client::build_client_config(&trust).expect("a usable client config");
            Connector::serving(
                Arc::new(named_loopback),
                Some(Arc::new(config)),
                Arc::new(|_, _| {}),
            )
        }
        .pooling(posture);
        c.carry_natively(vec![carrier(CARRIER_HTTP)], storage())
            .expect("the carriers");
        DeclaredConns::declare(&c, OWNER, NEED, &secure_need(), None, None).expect("declared");
        DeclaredConns::declare(&c, OWNER, PLAIN, &need(), None, None).expect("declared");
        c
    }

    fn secure_need() -> ReadNeed {
        ReadNeed {
            transport: "https".into(),
            ..need()
        }
    }

    /// `owner`'s open of `need` at `target` naming `member`, with a five-byte body.
    fn open_as(
        c: &Connector,
        (owner, need): (InstanceId, NeedId),
        target: &str,
        member: &str,
    ) -> Result<ConnId, ConnError> {
        c.open(
            owner,
            need,
            &OpenDesc {
                member,
                body: Bytes::from_static(b"first"),
                ..desc(target)
            },
        )
    }

    /// Drive `conn`'s dial until it has landed (dialled, secured, nothing queued) or failed.
    async fn land(c: &Connector, owner: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match DeclaredConns::landed(c, owner, conn, NO_TICKET) {
                Err(ConnError::Pending) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                landed => return landed,
            }
        }
    }

    /// Open as `member` and land: the facts of the landed connection, or why it did not land.
    async fn landed_as(
        c: &Connector,
        target: &str,
        member: &str,
    ) -> Result<busbar_contract::transport::ConnFacts, ConnError> {
        let conn = open_as(c, (OWNER, NEED), target, member)?;
        let landed = land(c, OWNER, conn).await;
        let facts = landed.and_then(|()| c.facts(OWNER, conn));
        c.close(OWNER, conn).expect("closed");
        facts
    }

    /// Whether `conn`'s exchange rides a kept line (lent from the idle set), not one dialled for it.
    fn lent(c: &Connector, conn: ConnId) -> bool {
        let (_, held) = c.slab.get(OWNER, conn).expect("held");
        let native = held.native.as_ref().expect("a native entry");
        let exchange = native.begin(Waker::noop()).expect("the exchange is in");
        let kept = exchange.kept;
        native.end(exchange);
        kept
    }

    /// `conn`'s answer read whole (what the http session states at its end), then the connection
    /// table's close, which keeps the line for the next exchange to the same key.
    fn answered_and_closed(c: &Connector, conn: ConnId) {
        {
            let (_, held) = c.slab.get(OWNER, conn).expect("held");
            let native = held.native.as_ref().expect("a native entry");
            let mut exchange = native.begin(Waker::noop()).expect("the exchange is in");
            exchange.ended = true;
            native.end(exchange);
        }
        c.close(OWNER, conn).expect("closed");
    }

    #[tokio::test]
    async fn prepared_request_tls_facts_precede_application_bytes_on_same_connection() {
        let pki = Pki::new();
        let leaf = pki.leaf("localhost");
        let far = tls_far_end(&leaf, None);
        let c = anchoring(pki.trust(), false, PoolPosture::NONE);
        assert_eq!(
            DeclaredConns::prepare_request(&c, OWNER, NEED, &desc(&far.target), 0),
            Err(ConnError::Refused),
            "a native need prepares nothing apart from its open"
        );
        let conn = open_as(&c, (OWNER, NEED), &far.target, "").expect("opens");
        land(&c, OWNER, conn)
            .await
            .expect("the handshake completes");
        let facts = c.facts(OWNER, conn).expect("the landed connection's facts");
        assert_eq!(facts.sni.as_deref(), Some("localhost"));
        assert_eq!(
            facts.peer_key_pin.as_deref(),
            Some(leaf.pin.as_str()),
            "the key of the handshake that completed"
        );
        assert!(!facts.client_identity);
        assert_eq!(
            far.meetings(1).await,
            vec![Met::Secured { presented: None }]
        );
        assert_eq!(
            far.app_bytes(),
            0,
            "the facts are read before any application byte"
        );
        assert_eq!(
            c.facts(OWNER, conn),
            Ok(facts),
            "the same connection states the same facts"
        );
        c.close(OWNER, conn).expect("closed");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            far.accepted.load(Ordering::SeqCst),
            1,
            "one connection: the refused prepare and the facts dialled no other"
        );
        assert_eq!(far.app_bytes(), 0);
    }

    #[tokio::test]
    async fn a_far_end_serving_the_pinned_key_is_reached_and_its_key_is_the_facts() {
        let pki = Pki::new();
        let leaf = pki.leaf("localhost");
        let far = tls_far_end(&leaf, None);
        let c = anchoring(pki.trust(), false, PoolPosture::NONE);
        let anchors = Anchors {
            key_pin: Some(format!(" {} ", leaf.pin)),
            ..Anchors::default()
        };
        c.anchor(OWNER, NEED, "", &far.target, &anchors)
            .expect("sealed");
        let facts = landed_as(&c, &far.target, "")
            .await
            .expect("the far end serving the pinned key is reached");
        assert_eq!(facts.peer_key_pin.as_deref(), Some(leaf.pin.as_str()));
        assert!(!facts.client_identity);
        assert_eq!(
            far.meetings(1).await,
            vec![Met::Secured { presented: None }]
        );

        // Twin: the same far end, the seal naming another key of the same root, is refused.
        c.anchor(
            OWNER,
            NEED,
            "",
            &far.target,
            &pinned(&pki.leaf("localhost")),
        )
        .expect("sealed again");
        assert!(
            landed_as(&c, &far.target, "").await.is_err(),
            "held to the pin, not to the chain"
        );
        assert_eq!(far.app_bytes(), 0);
    }

    #[tokio::test]
    async fn two_registrations_at_one_authority_each_present_their_own_identity() {
        let pki = Pki::new();
        let server = pki.leaf("localhost");
        let planner = pki.leaf("planner.client");
        let auditor = pki.leaf("auditor.client");
        let far = tls_far_end(&server, Some(&pki));
        let c = anchoring(pki.trust(), false, PoolPosture::NONE);
        c.anchor(
            OWNER,
            NEED,
            "planner",
            &far.target,
            &Anchors {
                key_pin: Some(server.pin.clone()),
                client_identity: Some(identity(&planner)),
                ..Anchors::default()
            },
        )
        .expect("sealed");
        c.anchor(
            OWNER,
            NEED,
            "auditor",
            &far.target,
            &Anchors {
                client_identity: Some(identity(&auditor)),
                ..Anchors::default()
            },
        )
        .expect("sealed");
        c.anchor(OWNER, NEED, "bare", &far.target, &Anchors::default())
            .expect("sealed");

        for (n, (member, own)) in [
            ("planner", Some(&planner)),
            ("auditor", Some(&auditor)),
            ("bare", None),
            ("planner", Some(&planner)),
        ]
        .into_iter()
        .enumerate()
        {
            let facts = landed_as(&c, &far.target, member)
                .await
                .unwrap_or_else(|e| panic!("{member} lands: {e:?}"));
            assert_eq!(facts.client_identity, own.is_some(), "{member}");
            assert_eq!(
                far.meetings(n + 1).await.get(n),
                Some(&Met::Secured {
                    presented: own.map(|leaf| leaf.der.clone())
                }),
                "{member} presents its own identity, and one holding none presents none"
            );
        }
        assert_eq!(far.app_bytes(), 0);
    }

    #[tokio::test]
    async fn a_pinned_destination_over_plaintext_is_refused_and_a_bad_identity_refuses_the_seal() {
        let pki = Pki::new();
        let leaf = pki.leaf("localhost");
        let plain = plain_far_end();
        let c = anchoring(pki.trust(), false, PoolPosture::NONE);

        // Control: unsealed, the plaintext open (its opener accepting plaintext) is dialled.
        let conn = open_as(&c, (OWNER, PLAIN), &plain.target, "").expect("opens");
        assert_eq!(plain.accepted(1).await, 1, "the unsealed open dials");
        c.close(OWNER, conn).expect("closed");

        c.anchor(OWNER, PLAIN, "", &plain.target, &pinned(&leaf))
            .expect("sealed");
        assert_eq!(
            open_as(&c, (OWNER, PLAIN), &plain.target, "").map(|_| ()),
            Err(ConnError::Refused),
            "a pin has no key to hold over plaintext: the open is refused, whatever the opener accepts"
        );
        let bad = Anchors {
            client_identity: Some(ClientIdentity {
                cert_chain: vec![leaf.der.clone()],
                private_key: b"not a key".to_vec().into(),
            }),
            ..Anchors::default()
        };
        let secure = "https://localhost:443/v1";
        assert_eq!(
            c.anchor(OWNER, NEED, "", secure, &bad),
            Err(ConnError::Refused),
            "an identity that does not parse refuses the seal"
        );
        assert_eq!(
            c.anchor(OWNER, NEED, "planner", secure, &bad),
            Err(ConnError::Refused)
        );
        for member in ["", "planner"] {
            assert_eq!(
                c.anchor(OTHER, NEED, member, &plain.target, &pinned(&leaf)),
                Err(ConnError::Refused),
                "another owner's need is never sealed ({member:?})"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            plain.accepted.load(Ordering::SeqCst),
            1,
            "nothing was dialled for a refusal"
        );
    }

    #[tokio::test]
    async fn a_pooled_line_is_never_lent_once_its_destination_is_sealed_again() {
        let pki = Pki::new();
        let served = pki.leaf("localhost");
        let other = pki.leaf("localhost");
        let far = tls_far_end(&served, None);
        let c = anchoring(pki.trust(), false, POOLED);
        c.anchor(OWNER, NEED, "", &far.target, &pinned(&served))
            .expect("sealed");

        let first = open_as(&c, (OWNER, NEED), &far.target, "").expect("opens");
        assert!(!lent(&c, first), "nothing is kept yet: dialled");
        land(&c, OWNER, first).await.expect("lands");
        answered_and_closed(&c, first);

        // Control: under the same seal the kept line is lent.
        let again = open_as(&c, (OWNER, NEED), &far.target, "").expect("opens");
        assert!(lent(&c, again), "the same seal rides its kept line");
        land(&c, OWNER, again).await.expect("lands");
        assert_eq!(
            c.facts(OWNER, again).map(|f| f.peer_key_pin),
            Ok(Some(served.pin.clone()))
        );
        answered_and_closed(&c, again);
        assert_eq!(far.accepted.load(Ordering::SeqCst), 1, "one line so far");

        c.anchor(OWNER, NEED, "", &far.target, &pinned(&other))
            .expect("sealed again");
        let resealed = open_as(&c, (OWNER, NEED), &far.target, "").expect("opens");
        assert!(
            !lent(&c, resealed),
            "the line the old seal verified is never lent under the new one"
        );
        assert!(
            land(&c, OWNER, resealed).await.is_err(),
            "the open is held to the new pin, which the far end does not serve"
        );
        assert!(far.accepted(2).await >= 2, "it dialled afresh");
        c.close(OWNER, resealed).expect("closed");
        assert_eq!(far.app_bytes(), 0);
    }

    #[tokio::test]
    async fn a_pooled_line_is_never_lent_once_its_need_trusts_another_operator_ca() {
        let pki = Pki::new();
        let another = Pki::new();
        let far = tls_far_end(&pki.leaf("localhost"), None);
        // The connector's own trust is the public roots alone: only the need's CA verifies the far end.
        let c = anchoring(EgressTrust::default(), false, POOLED);
        let declare = |pem: &str| {
            let need = ReadNeed {
                trust_from: "settings.ca".into(),
                ..secure_need()
            };
            DeclaredConns::declare(&c, OWNER, NEED, &need, None, Some(pem))
        };
        declare(&pki.pem).expect("declared under its CA");

        let first = open_as(&c, (OWNER, NEED), &far.target, "").expect("opens");
        land(&c, OWNER, first)
            .await
            .expect("the need's CA verifies the far end");
        answered_and_closed(&c, first);
        let again = open_as(&c, (OWNER, NEED), &far.target, "").expect("opens");
        assert!(
            lent(&c, again),
            "control: under the same CA the kept line is lent"
        );
        land(&c, OWNER, again).await.expect("lands");
        answered_and_closed(&c, again);
        assert_eq!(far.accepted.load(Ordering::SeqCst), 1);

        declare(&another.pem).expect("declared again under another CA");
        let moved = open_as(&c, (OWNER, NEED), &far.target, "").expect("opens");
        assert!(
            !lent(&c, moved),
            "the line the old CA verified is never lent under the new one"
        );
        assert!(
            land(&c, OWNER, moved).await.is_err(),
            "the open is held to the need's new CA, which did not sign the far end"
        );
        assert!(far.accepted(2).await >= 2, "it dialled afresh");
        c.close(OWNER, moved).expect("closed");
        assert_eq!(far.app_bytes(), 0);
    }

    #[tokio::test]
    async fn member_ca_public_connector_opens_only_its_sealed_member() {
        let base = Pki::new();
        let member = Pki::new();
        let leaf = member.leaf("localhost");
        let far = tls_far_end(&leaf, None);
        let c = anchoring(base.trust(), true, PoolPosture::NONE);
        c.anchor(
            OWNER,
            NEED,
            "member",
            &far.target,
            &Anchors {
                extra_anchors: vec![member.der.clone()],
                key_pin: Some(leaf.pin.clone()),
                ..Anchors::default()
            },
        )
        .expect("the member's root is sealed on the known policy");
        c.anchor(OWNER, NEED, "sibling", &far.target, &Anchors::default())
            .expect("sealed");

        let facts = landed_as(&c, &far.target, "member")
            .await
            .expect("the member's own root verifies its far end");
        assert_eq!(facts.peer_key_pin.as_deref(), Some(leaf.pin.as_str()));
        assert_eq!(
            far.meetings(1).await,
            vec![Met::Secured { presented: None }]
        );
        assert!(
            landed_as(&c, &far.target, "sibling").await.is_err(),
            "another registration at the authority is not lent the member's root"
        );
        assert_eq!(far.meetings(2).await.get(1), Some(&Met::Refused));
        assert_eq!(
            open_as(&c, (OWNER, NEED), &far.target, "").map(|_| ()),
            Err(ConnError::Refused),
            "nor is an open naming no registration"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(far.accepted.load(Ordering::SeqCst), 2);
        assert_eq!(far.app_bytes(), 0);
    }

    #[tokio::test]
    async fn member_ca_fails_closed_for_plaintext_and_opaque_base() {
        let pki = Pki::new();
        let roots = Anchors {
            extra_anchors: vec![pki.der.clone()],
            ..Anchors::default()
        };
        let secure = "https://localhost:443/v1";

        // An opaque base (a client config whose policy is not known) cannot carry a member root.
        let opaque = anchoring(pki.trust(), false, PoolPosture::NONE);
        for member in ["member", ""] {
            assert_eq!(
                opaque.anchor(OWNER, NEED, member, secure, &roots),
                Err(ConnError::Refused),
                "opaque base ({member:?})"
            );
        }

        let c = anchoring(pki.trust(), true, PoolPosture::NONE);
        // A target that names no locatable authority (the (None, false) arm).
        for target in ["localhost:443", "gopher://localhost/x", ""] {
            assert_eq!(
                c.anchor(OWNER, NEED, "member", target, &roots),
                Err(ConnError::Refused),
                "no locatable authority ({target:?})"
            );
        }

        // Plaintext: the member's root has no handshake to verify, so its open is refused.
        let plain = plain_far_end();
        let control = open_as(&c, (OWNER, PLAIN), &plain.target, "member").expect("opens");
        assert_eq!(plain.accepted(1).await, 1, "control: unsealed, it dials");
        c.close(OWNER, control).expect("closed");
        c.anchor(OWNER, PLAIN, "member", &plain.target, &roots)
            .expect("sealed");
        assert_eq!(
            open_as(&c, (OWNER, PLAIN), &plain.target, "member").map(|_| ()),
            Err(ConnError::Refused),
            "a member root over plaintext fails closed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(plain.accepted.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_registration_holding_no_anchors_never_borrows_one_sealed_after_it() {
        let pki = Pki::new();
        let server = pki.leaf("localhost");
        let planner = pki.leaf("planner.client");
        let far = tls_far_end(&server, Some(&pki));
        let c = anchoring(pki.trust(), false, PoolPosture::NONE);
        c.anchor(OWNER, NEED, "bare", &far.target, &Anchors::default())
            .expect("sealed");
        c.anchor(
            OWNER,
            NEED,
            "planner",
            &far.target,
            &Anchors {
                key_pin: Some(server.pin.clone()),
                client_identity: Some(identity(&planner)),
                ..Anchors::default()
            },
        )
        .expect("sealed after it");

        let bare = landed_as(&c, &far.target, "bare")
            .await
            .expect("the bare registration dials under the default trust");
        assert!(!bare.client_identity);
        assert_eq!(
            far.meetings(1).await,
            vec![Met::Secured { presented: None }],
            "it never borrows the identity sealed after it"
        );
        let own = landed_as(&c, &far.target, "planner").await.expect("lands");
        assert!(own.client_identity);
        assert_eq!(
            far.meetings(2).await.get(1),
            Some(&Met::Secured {
                presented: Some(planner.der.clone())
            })
        );
    }

    #[tokio::test]
    async fn an_open_naming_no_registration_is_refused_where_the_registrations_at_its_authority_disagree(
    ) {
        let pki = Pki::new();
        let server = pki.leaf("localhost");
        let planner = pki.leaf("planner.client");
        let far = tls_far_end(&server, Some(&pki));
        let c = anchoring(pki.trust(), false, PoolPosture::NONE);
        c.anchor(
            OWNER,
            NEED,
            "planner",
            &far.target,
            &Anchors {
                key_pin: Some(server.pin.clone()),
                client_identity: Some(identity(&planner)),
                ..Anchors::default()
            },
        )
        .expect("sealed");
        landed_as(&c, &far.target, "")
            .await
            .expect("control: one registration at the authority is the destination's anchors");
        assert_eq!(far.meetings(1).await.len(), 1);

        c.anchor(OWNER, NEED, "bare", &far.target, &Anchors::default())
            .expect("sealed");
        assert_eq!(
            open_as(&c, (OWNER, NEED), &far.target, "").map(|_| ()),
            Err(ConnError::Refused),
            "two registrations disagree: an open naming neither is refused"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            far.accepted.load(Ordering::SeqCst),
            1,
            "nothing was dialled for the refusal"
        );
        landed_as(&c, &far.target, "planner")
            .await
            .expect("a named registration still opens under its own seal");
    }

    #[tokio::test]
    async fn a_registrations_private_reach_admits_its_own_opens_and_nothing_else() {
        let far = plain_far_end();
        let strict = Arc::new(crate::conns::LiteralsOnly(
            crate::conns::guard::Guard::default(),
        ));
        let c = Connector::serving(strict, None, Arc::new(|_, _| {}));
        c.carry_natively(vec![carrier(CARRIER_HTTP)], storage())
            .expect("the carriers");
        let provider = ReadNeed {
            egress_class: EGRESS_PROVIDER,
            ..need()
        };
        for n in [NEED, PLAIN] {
            DeclaredConns::declare(&c, OWNER, n, &provider, None, None).expect("declared");
        }
        let open = |need: NeedId, target: &str, member: &str| {
            open_as(&c, (OWNER, need), target, member).map(|conn| {
                c.close(OWNER, conn).expect("closed");
            })
        };
        let reach = Anchors {
            private_reach: true,
            ..Anchors::default()
        };
        assert_eq!(
            open(NEED, &far.target, "inside"),
            Err(ConnError::Refused),
            "no reach yet: the guard refuses the private address"
        );
        assert_eq!(
            c.anchor(OWNER, NEED, "", &far.target, &reach),
            Err(ConnError::Refused),
            "a reach is a registration's, never a destination's"
        );
        c.anchor(OWNER, NEED, "inside", &far.target, &reach)
            .expect("sealed");
        c.anchor(OWNER, NEED, "outside", &far.target, &Anchors::default())
            .expect("sealed");
        assert_eq!(
            open(NEED, &far.target, "inside"),
            Ok(()),
            "the registration's own open reaches"
        );
        assert_eq!(far.accepted(1).await, 1);
        for (need, target, member, why) in [
            (
                NEED,
                "http://127.0.0.1:1/v1",
                "inside",
                "another port on the same host",
            ),
            (
                NEED,
                far.target.as_str(),
                "outside",
                "another registration at the authority",
            ),
            (
                NEED,
                far.target.as_str(),
                "",
                "an open naming no registration",
            ),
            (
                PLAIN,
                far.target.as_str(),
                "inside",
                "the same member name on another need",
            ),
        ] {
            assert_eq!(open(need, target, member), Err(ConnError::Refused), "{why}");
        }
        assert_eq!(
            c.seal_reach(OWNER, NEED, "inside", &far.target, false),
            Ok(())
        );
        assert_eq!(
            open(NEED, &far.target, "inside"),
            Err(ConnError::Refused),
            "a withdrawn reach admits nothing"
        );
        assert_eq!(
            c.seal_reach(OWNER, NEED, "inside", &far.target, true),
            Ok(())
        );
        assert_eq!(open(NEED, &far.target, "inside"), Ok(()));
        assert_eq!(far.accepted(2).await, 2);
        let metadata = "http://169.254.169.254:80/latest";
        c.anchor(OWNER, NEED, "inside", metadata, &reach)
            .expect("sealed");
        assert_eq!(
            open(NEED, metadata, "inside"),
            Err(ConnError::Refused),
            "a reach never admits cloud metadata"
        );
        assert_eq!(
            open(NEED, &far.target, "inside"),
            Err(ConnError::Refused),
            "the registration's reach moved with its seal"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(far.accepted.load(Ordering::SeqCst), 2);
    }
}
