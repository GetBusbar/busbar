// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! K9: what the boot composes into a MIN-3 plane seat from the configured upstreams. The plane is an ffi handle, so
//! the seat's request path runs in the image suite (W2-SW-PLANE e2e); these are the seams the boot builds: the
//! seat's walk and carrier over the shared upstream table, its needs on the connection table, the transport
//! acceptance it is held to, and the process-tree containment of a stdio child.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::task::{Context, Poll};

use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{ConnError, ConnId, Conns, Piece, PollConns, Ticket};
use busbar_contract::json::{json, JsonValueTrait as _};
use busbar_contract::transport::trust::Anchors;
use busbar_contract::transport::ConnFacts;
use busbar_kernel::channels::carrier::Wires;
use busbar_kernel::channels::ChannelReq;
use busbar_kernel::upstreams::{ProgramPin, StdioCommand, UpstreamTls};
use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::plane::CARRIER_STDIO;
use busbar_plugin_abi::records::Records;
use busbar_ports::plane::{PlaneIn, PlaneOut, PlaneSession, RouteInfo, TargetIn, UsageClass};
use busbar_ports::{CallCx, PortError};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use super::*;

fn refused() -> PortError {
    PortError::Refused {
        code: 1,
        text: "no".into(),
        error: None,
    }
}

/// A plane that states nothing and answers nothing (no FB_PROBES).
struct Quiet;

impl PlanePort for Quiet {
    fn routes(&self) -> &[RouteInfo] {
        &[]
    }
    fn dialects(&self) -> &[Box<str>] {
        &[]
    }
    fn usage_classes(&self) -> &[UsageClass] {
        &[]
    }
    fn facts(&self) -> u64 {
        0
    }
    fn tick_s(&self) -> Option<u64> {
        None
    }
    fn admin_openapi(&self) -> Option<&str> {
        None
    }
    fn charge(&self, _: FaultReason) {}
    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        Err(refused())
    }
    fn upstream(
        &self,
        _: &mut PlaneSession,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn piece(
        &self,
        _: &mut PlaneSession,
        _: u32,
        _: u32,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn rewrite(
        &self,
        _: &mut PlaneSession,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn end(&self, _: PlaneSession, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        Err(refused())
    }
    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn probe(
        &self,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        Err(refused())
    }
    fn demux(&self, _: &str, _: &[u8], _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        Err(refused())
    }
    fn admin<'a>(
        &'a self,
        _: CallCx,
        _: u32,
        _: &'a [u8],
    ) -> BoxFut<'a, Result<Vec<u8>, PortError>> {
        Box::pin(async move { Err(refused()) })
    }
}

/// A connection table that records the needs declared on it and the anchors sealed, and opens nothing.
#[derive(Default)]
struct Table {
    declared: Mutex<Vec<(InstanceId, NeedId, String)>>,
    anchored: Mutex<Vec<(NeedId, String, Option<String>)>>,
}

impl Conns for Table {
    fn open(&self, _: InstanceId, _: NeedId, _: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
        Err(ConnError::Refused)
    }
    fn write(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        Err(ConnError::Refused)
    }
    fn read(&self, _: InstanceId, _: ConnId, _: Ticket, _: &mut [u8]) -> Result<Piece, ConnError> {
        Err(ConnError::Refused)
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
        Err(ConnError::Refused)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Ok(ConnFacts::default())
    }
    fn close(&self, _: InstanceId, _: ConnId) -> Result<(), ConnError> {
        Ok(())
    }
}

impl PollConns for Table {
    fn poll_read(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &mut Context<'_>,
        _: &mut [u8],
    ) -> Poll<Result<Piece, ConnError>> {
        Poll::Ready(Err(ConnError::Refused))
    }
    fn anchor(
        &self,
        _: InstanceId,
        need: NeedId,
        _: &str,
        target: &str,
        anchors: &Anchors,
    ) -> Result<(), ConnError> {
        self.anchored
            .lock()
            .unwrap()
            .push((need, target.to_owned(), anchors.key_pin.clone()));
        Ok(())
    }
}

impl DeclaredConns for Table {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        assert!(
            target.is_none(),
            "no target is pinned: the guard judges every dial"
        );
        self.declared
            .lock()
            .unwrap()
            .push((owner, need, spec.transport.clone()));
        Ok(())
    }
    fn declared(&self, _: InstanceId, _: NeedId) -> Option<Result<(), ConnError>> {
        None
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
}

/// Every reference resolves to the same value.
struct Fixed;

impl SpawnSecrets for Fixed {
    fn resolve<'a>(&'a self, _: &'a SecretRef) -> BoxFut<'a, Option<String>> {
        Box::pin(core::future::ready(Some("value".to_owned())))
    }
}

const PIN_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn upstreams() -> Arc<ConfiguredUpstreams> {
    let section = json!({
        "alpha": {"url": "https://alpha.example/v1", "tls": {"pin_spki": [PIN_HEX]}},
        "beta": {"url": "http://beta.internal:8080"},
        "files": {"command": {"argv": ["/opt/mcp/files"]}},
    });
    Arc::new(
        ConfiguredUpstreams::from_config(
            section.as_object().expect("a map"),
            &BTreeMap::new(),
            &busbar_kernel::plugin_config::upstream_anchor,
        )
        .expect("the upstreams type"),
    )
}

fn shared(table: Option<ConnTable>) -> SeatShared {
    SeatShared {
        upstreams: BTreeMap::from([("mcp".to_owned(), upstreams())]),
        signals: SignalRegistry::new(),
        secrets: Arc::new(Fixed),
        kernel: Arc::new(Kernel::new()),
        table,
    }
}

fn who(instance: u64) -> Namespace {
    Namespace {
        plugin: "plane-mcp".into(),
        name: "mcp".into(),
        instance,
        slot: 0,
    }
}

#[test]
fn a_seat_owner_is_its_own_never_a_dispatch_handle_or_the_root() {
    let owner = seat_owner(7);
    assert_ne!(owner, InstanceId(0));
    assert!(owner.0 >= 1 << 40, "above every 24-bit dispatch handle id");
    assert_ne!(seat_owner(7), seat_owner(8));
    assert!(
        seat_owner(u64::MAX).0 < u64::MAX - 3,
        "below the connector's own test owners"
    );
}

#[test]
fn an_upstream_need_rides_its_url_scheme_with_no_target_pinned() {
    let need = upstream_need("HTTPS://alpha.example/v1");
    assert_eq!(need.transport, "https");
    assert!(need.target_from.is_empty() && need.trust_from.is_empty());
    assert_eq!(need.direction, DIRECTION_OUTBOUND);
    assert_eq!(upstream_need("http://beta.internal").transport, "http");
}

#[test]
fn verified_tls_is_the_default_and_each_acceptance_admits_only_what_it_names() {
    let none = Accept::default();
    assert!(admitted(none, "https://alpha.example/v1"));
    assert!(!admitted(none, "http://beta.internal:8080/x"));
    assert!(admitted(
        Accept(Accept::PLAINTEXT),
        "http://beta.internal:8080/x"
    ));
    assert!(admitted(
        Accept(Accept::UNVERIFIED_TLS),
        "https://alpha.example/v1"
    ));
    assert!(!admitted(
        Accept(Accept::UNVERIFIED_TLS),
        "http://beta.internal:8080/x"
    ));
    assert_eq!(accept_words(none), Vec::<&str>::new());
    assert_eq!(
        accept_words(Accept(Accept::PLAINTEXT | Accept::UNVERIFIED_TLS)),
        ["plaintext", "unverified_tls"]
    );
}

#[test]
fn an_acceptance_is_audited_and_none_is_silent() {
    let pool = SeatPool::of("mcp", &upstreams()).expect("the seat's pool");
    assert!(!audit_acceptance("mcp", Accept::default(), &pool));
    assert!(audit_acceptance("mcp", Accept(Accept::PLAINTEXT), &pool));
}

#[tokio::test]
async fn a_seat_with_configured_upstreams_is_composed_with_its_walk_and_its_carrier() {
    let table = Arc::new(Table::default());
    let conns = ConnTable {
        declared: Arc::clone(&table) as Arc<dyn DeclaredConns>,
        conns: Arc::clone(&table) as Arc<dyn PollConns>,
    };
    let wiring = compose(
        &shared(Some(conns)),
        "mcp",
        Accept::default(),
        &who(7),
        Arc::new(Quiet),
        Handle::current(),
    )
    .expect("the seat composes");
    assert!(wiring.upstream.is_some(), "a FORWARD has a walk to run");
    assert!(
        wiring.probes.is_none(),
        "a plane that states no FB_PROBES is never probed"
    );
    assert_eq!(
        *table.declared.lock().unwrap(),
        [
            (seat_owner(7), NeedId(0), "https".to_owned()),
            (seat_owner(7), NeedId(1), "http".to_owned()),
        ],
        "one need per network upstream, on the seat's own owner"
    );
    let anchored = table.anchored.lock().unwrap().clone();
    assert_eq!(
        anchored.len(),
        2,
        "each member seals its own trust and private-reach policy"
    );
    assert_eq!(anchored[0].0, NeedId(0));
    assert!(anchored[0]
        .2
        .as_deref()
        .is_some_and(|pin| pin.starts_with("sha256/")));

    // The carrier reads the same table: a CHANNEL to a configured upstream finds it, any other name does not.
    let session = wiring.carrier.session();
    session.map.point("files");
    assert!(session.map.of(0).is_some_and(|def| def.command.is_some()));
    session.map.point("ghost");
    assert!(session.map.of(0).is_none());
}

#[test]
fn each_registration_carries_only_its_own_private_reach_into_the_seat() {
    let split = busbar_kernel::upstreams::declared(
        "p",
        &json!({"members": {
            "allowed": {"url":"https://shared.internal", "allow_private":true},
            "denied": {"url":"https://shared.internal"}
        }}),
        &["/members/*"],
        &busbar_kernel::plugin_config::upstream_anchor,
    )
    .unwrap();
    let pool = SeatPool::of("p", &split.definitions).unwrap();
    for member in &pool.members {
        let route = &pool.routes[&member.destination];
        assert_eq!(
            route.anchors.private_reach,
            member.upstream.as_ref() == "allowed"
        );
    }
}

#[tokio::test]
async fn a_seat_with_no_connection_table_still_gets_its_carrier_and_walks_nothing() {
    let wiring = compose(
        &shared(None),
        "mcp",
        Accept::default(),
        &who(3),
        Arc::new(Quiet),
        Handle::current(),
    )
    .expect("the seat composes");
    assert!(wiring.upstream.is_none());
    assert!(wiring.probes.is_none());
    let session = wiring.carrier.session();
    session.map.point("alpha");
    assert!(session.map.of(0).is_some());
}

fn stdio(argv: &[&str]) -> UpstreamDef {
    UpstreamDef {
        allow_private: false,
        name: "files".into(),
        url: None,
        command: Some(StdioCommand {
            argv: argv.iter().map(|arg| Box::<str>::from(*arg)).collect(),
            env: Vec::new(),
            cwd: None,
            pin: ProgramPin::Unpinned,
            idle_s: 300,
        }),
        tls: UpstreamTls {
            pin_spki: Vec::new(),
            client_identity: None,
            trust: None,
        },
        auth: None,
    }
}

fn channel() -> ChannelReq<'static> {
    ChannelReq {
        exchange: 1,
        carrier: CARRIER_STDIO,
        flags: 0,
        framing: 0,
        key: "k",
        subject: None,
        head: Records::new(&[]),
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_contained_stdio_channel_opens_and_carries_bytes_both_ways() {
    let wires = ProcessWires::new(Arc::new(Fixed), None).spawning(Arc::new(ContainedSpawn));
    let up = stdio(&["/bin/cat"]);
    let req = channel();
    let wire = wires.open(&up, &req).await.expect("the child starts");
    let mut write = wire.write.expect("a stdio wire takes writes");
    let mut read = wire.read;
    write.write_all(b"ping\n").await.expect("written");
    write.flush().await.expect("flushed");
    let mut got = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), read.read_exact(&mut got))
        .await
        .expect("the child answers in time")
        .expect("read");
    assert_eq!(&got, b"ping\n");
    drop(wire.hold);
}

/// Whether `pid` is a live process (a zombie is not: it has ended and waits to be reaped).
#[cfg(target_os = "linux")]
fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.trim_start().chars().next())
            .is_some_and(|state| state != 'Z' && state != 'X')
    })
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_stdio_child_s_whole_process_tree_stops_with_its_generation() {
    let wires = ProcessWires::new(Arc::new(Fixed), None).spawning(Arc::new(ContainedSpawn));
    // The child forks a grandchild and reports its pid; `exec` keeps the child itself alive on its stdin.
    let up = stdio(&["/bin/sh", "-c", "/bin/sleep 300 & echo $!; exec /bin/cat"]);
    let req = channel();
    let wire = wires.open(&up, &req).await.expect("the child starts");
    let mut line = String::new();
    let mut reader = BufReader::new(wire.read);
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("the child reports in time")
        .expect("read");
    let pid: u32 = line.trim().parse().expect("a pid");
    assert!(alive(pid), "the grandchild runs while the generation lives");
    drop(wire.write);
    drop(wire.hold);
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(pid) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        !alive(pid),
        "a process the child started outlived its generation"
    );
}
