// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "../../../crates/busbar-kernel/tests/common/mod.rs"]
mod common;

#[path = "fixtures/plane_driver_test_plane.rs"]
#[allow(dead_code)]
mod plane;

#[path = "../../../crates/busbar-kernel/tests/support/plane_driver_cases.rs"]
mod cases;

#[path = "../../../crates/busbar/src/root/tests/test_plugins.rs"]
mod fixture_plugins;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::Outcome as AbiOutcome;
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpenOut};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, PlaneOpenIn, PlaneOpenOut, UnitCount,
    FROM_FAR_END,
};
use busbar_contract::caps::OpClassId;
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    PieceKind,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::ConnFacts;
use busbar_kernel::host_services::KernelServices;
use busbar_kernel::plane_driver::{refusal_status, BufferCaps, DriverConfig, PlaneDriver};
use busbar_plugin_loader::dispatch::{
    conn_services::ticket_of,
    in_head,
    kinds::plane::{OwnedSnapshot, Plane},
    load_dropped, load_linked, now_ns as dispatch_now, out_head,
    plane_calls::PlaneInstance,
    rendering_of, Bind, ConnTable, Diagnostic, DispatchConfig, Dispatcher, Dropped, EnvelopeSink,
    Frame, LinkedRow, Metric, NoSink, Plugin, NO_BLOB,
};

pub(crate) fn now_ns() -> u64 {
    dispatch_now()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Way {
    Linked,
    Dropped,
}

fn dropped_path() -> std::path::PathBuf {
    let name = "plane_driver_test_plane";
    let exe = std::env::current_exe().expect("the test binary's path");
    let path = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("the test binary sits in target/<profile>/deps")
        .join("examples")
        .join(format!(
            "{}{name}{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        ));
    if !path.exists() {
        fixture_plugins::missing(name, fixture_plugins::BUILD_BUSBAR_EXAMPLES);
    }
    path
}

pub(crate) fn ways() -> Vec<Way> {
    vec![Way::Linked, Way::Dropped]
}

fn load(way: Way, dispatcher: &Dispatcher) -> Arc<Plugin<Plane>> {
    load_with(way, dispatcher, Arc::new(NoSink))
}

fn load_with(way: Way, dispatcher: &Dispatcher, sink: Arc<dyn EnvelopeSink>) -> Arc<Plugin<Plane>> {
    load_open(way, dispatcher, sink, ConnTable::Probe).0
}

fn load_over(
    way: Way,
    dispatcher: &Dispatcher,
    sink: Arc<dyn EnvelopeSink>,
    conns: Option<Arc<dyn DeclaredConns>>,
) -> Arc<Plugin<Plane>> {
    let conns = conns.map_or(ConnTable::Probe, ConnTable::Host);
    load_open(way, dispatcher, sink, conns).0
}

fn load_open(
    way: Way,
    dispatcher: &Dispatcher,
    sink: Arc<dyn EnvelopeSink>,
    conns: ConnTable,
) -> (Arc<Plugin<Plane>>, OwnedSnapshot) {
    load_open_capped(way, dispatcher, sink, conns, 64)
}

fn load_open_capped(
    way: Way,
    dispatcher: &Dispatcher,
    sink: Arc<dyn EnvelopeSink>,
    conns: ConnTable,
    cap: u32,
) -> (Arc<Plugin<Plane>>, OwnedSnapshot) {
    let bind = Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: cap,
        sink,
        dispatcher: dispatcher.adopter(),
        conns,
    };
    let plugin = match way {
        Way::Linked => {
            let row = LinkedRow::of(plane::door).expect("the plane states its Statement");
            load_linked::<Plane>(&row, bind).expect("the linked door loads")
        }
        Way::Dropped => {
            let stated = rendering_of(plane::door).expect("the plane renders its Statement");
            let path = dropped_path();
            load_dropped::<Plane>(&path, &stated, bind).expect("the dropped door loads")
        }
    };
    let mut open = Frame::new(
        PlaneOpenIn {
            open: OpenIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: NO_BLOB,
                secrets: std::ptr::null(),
                secrets_len: 0,
                generation: 1,
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            public_url: busbar_contract::abi::mechanism::call::AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            owned: NO_BLOB,
            providers: std::ptr::null(),
            providers_len: 0,
        },
        PlaneOpenOut {
            open: OpenOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
                err_len: 0,
            },
            snapshot: std::ptr::null(),
        },
    );
    let (called, snapshot) = plugin.open(&mut open);
    assert_eq!(called.outcome, AbiOutcome::Ready);
    (Arc::new(plugin), snapshot.expect("the snapshot is copied"))
}

fn stats(plugin: &Plugin<Plane>) -> [u64; cases::stat::COUNT] {
    let mut units = [UnitCount {
        class: 0,
        source: 0,
        amount: 0,
    }; 8];
    let target = b"/stats";
    let mut frame = Frame::new(
        ArriveIn {
            head: in_head(),
            unit: 0,
            claim: 0,
            _reserved: 0,
            target: busbar_contract::abi::mechanism::call::AbiStr {
                ptr: target.as_ptr(),
                len: target.len(),
            },
            fields: std::ptr::null(),
            fields_len: 0,
            body: NO_BLOB,
            units_buf: units.as_mut_ptr(),
            units_cap: units.len(),
            method: busbar_contract::abi::mechanism::call::AbiStr {
                ptr: b"POST".as_ptr(),
                len: 4,
            },
        },
        ArriveOut {
            head: out_head(),
            op_class: 0,
            principal_need: 0,
            dialect: 0,
            units_written: 0,
            units_needed: 0,
            refusal: 0,
            refusal_status: 0,
            refusal_flags: 0,
            correlation: 0,
            cancels: 0,
            pool: busbar_contract::abi::mechanism::call::AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            route: 0,
            route_flags: 0,
            _route_reserved: [0; 6],
            affinity: busbar_contract::abi::mechanism::call::AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            trust_counterparty: busbar_contract::abi::mechanism::call::AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            trust_item: busbar_contract::abi::mechanism::call::AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            trust_digest: busbar_contract::abi::mechanism::call::AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
        },
    );
    assert_eq!(
        plugin.call(slot::ARRIVE, &mut frame).outcome,
        AbiOutcome::Ready
    );
    let mut out = [0; cases::stat::COUNT];
    for (k, v) in out.iter_mut().enumerate() {
        *v = units[k].amount;
    }
    out
}

pub(crate) struct Rig {
    plugin: Arc<Plugin<Plane>>,
    pub(crate) driver: PlaneDriver,
    pub(crate) book: Arc<cases::Book>,
}

impl Rig {
    pub(crate) fn stats(&self) -> [u64; cases::stat::COUNT] {
        stats(&self.plugin)
    }

    fn sessions(&self) -> [u64; plane::SESSIONS] {
        let all = arrive_at(&self.plugin, "/sessions");
        let mut out = [0; plane::SESSIONS];
        out.copy_from_slice(&all[..plane::SESSIONS]);
        out
    }
}

pub(crate) fn rig(way: Way, caps: BufferCaps, book: cases::Book) -> Rig {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        ..DispatchConfig::default()
    }));
    let plugin = load(way, &dispatcher);
    let book = Arc::new(book);
    let calls = Arc::new(PlaneInstance::new(Arc::clone(&plugin), dispatcher, 1));
    let refusal_statuses = calls.refusal_statuses();
    assert_eq!(
        refusal_statuses,
        cases::statuses(),
        "{way:?}: the tail's statuses, as the loader read them"
    );
    let driver = PlaneDriver::new(
        calls,
        DriverConfig {
            caps,
            op_classes: vec![OpClassId::new("call")],
            status_of: refusal_status,
            refusal_statuses,
            caller_refs: None,
        },
        book.clone(),
        services(),
        ("test_plane", &serde_yaml::Value::Null),
    )
    .expect("the instance is admitted");
    Rig {
        plugin,
        driver,
        book,
    }
}

/// The envelope gauges the host accepted, by family.
#[derive(Default)]
struct Gauges(Mutex<Vec<(u32, f64)>>);

impl EnvelopeSink for Gauges {
    fn metric(&self, m: Metric<'_>) {
        self.0.lock().unwrap().push((m.family, m.value));
    }
    fn diag(&self, _: Diagnostic<'_>) {}
    fn dropped(&self, _: Dropped) {}
}

#[test]
fn a_plane_driven_through_its_driver_ticket_answers_under_its_own_frame() {
    for way in ways() {
        let dispatcher = Dispatcher::new(DispatchConfig::default());
        let gauges = Arc::new(Gauges::default());
        let plugin = load_with(way, &dispatcher, gauges.clone());
        let t = dispatcher.driver(&*plugin, 0).expect("a driver ticket");
        wake(&plugin, t);
        let until = Instant::now() + Duration::from_secs(5);
        while gauges.0.lock().unwrap().is_empty() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(stats(&plugin)[cases::stat::DRIVES], 1, "{way:?}: drive ran");
        assert_eq!(
            *gauges.0.lock().unwrap(),
            vec![(0, 1.0)],
            "{way:?}: the drive answer passed its check and its envelope was read"
        );
    }
}

fn wake(plugin: &Plugin<Plane>, t: busbar_contract::abi::mechanism::ticket::Ticket) {
    arrive_at(plugin, &format!("/wake:{}:{}", t.slot, t.generation));
}

fn arrive_at(plugin: &Plugin<Plane>, target: &str) -> [u64; 16] {
    let target = target.as_bytes().to_vec();
    let mut units = [UnitCount {
        class: 0,
        source: 0,
        amount: 0,
    }; 16];
    let mut frame = Frame::new(
        ArriveIn {
            head: in_head(),
            unit: 0,
            claim: 0,
            _reserved: 0,
            target: busbar_contract::abi::mechanism::call::AbiStr {
                ptr: target.as_ptr(),
                len: target.len(),
            },
            fields: std::ptr::null(),
            fields_len: 0,
            body: NO_BLOB,
            units_buf: units.as_mut_ptr(),
            units_cap: units.len(),
            method: busbar_contract::abi::mechanism::call::AbiStr {
                ptr: b"POST".as_ptr(),
                len: 4,
            },
        },
        zero_arrive_out(),
    );
    assert_eq!(
        plugin.call(slot::ARRIVE, &mut frame).outcome,
        AbiOutcome::Ready
    );
    units.map(|u| u.amount)
}

fn zero_arrive_out() -> ArriveOut {
    ArriveOut {
        head: out_head(),
        op_class: 0,
        principal_need: 0,
        dialect: 0,
        units_written: 0,
        units_needed: 0,
        refusal: 0,
        refusal_status: 0,
        refusal_flags: 0,
        correlation: 0,
        cancels: 0,
        pool: busbar_contract::abi::mechanism::call::AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        route: 0,
        route_flags: 0,
        _route_reserved: [0; 6],
        affinity: busbar_contract::abi::mechanism::call::AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        trust_counterparty: busbar_contract::abi::mechanism::call::AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        trust_item: busbar_contract::abi::mechanism::call::AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        trust_digest: busbar_contract::abi::mechanism::call::AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
    }
}

fn ticked(plugin: &Plugin<Plane>) -> [u64; plane::TICKED] {
    let all = arrive_at(plugin, "/ticks");
    let mut out = [0; plane::TICKED];
    out.copy_from_slice(&all[..plane::TICKED]);
    out
}

fn driver_of(plugin: &Arc<Plugin<Plane>>, dispatcher: Arc<Dispatcher>) -> PlaneDriver {
    let calls = Arc::new(PlaneInstance::new(Arc::clone(plugin), dispatcher, 0));
    let refusal_statuses = calls.refusal_statuses();
    PlaneDriver::new(
        calls,
        DriverConfig {
            caps: BufferCaps::default(),
            op_classes: vec![OpClassId::new("call")],
            status_of: refusal_status,
            refusal_statuses,
            caller_refs: None,
        },
        Arc::new(cases::Book::default()),
        services(),
        ("test_plane", &serde_yaml::Value::Null),
    )
    .expect("the instance is admitted")
}

fn services() -> Arc<KernelServices> {
    Arc::new(KernelServices::new())
}

fn until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[tokio::test]
async fn the_kernel_ticks_a_plane_on_its_driver_ticket_at_each_next_tick() {
    for way in ways() {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let plugin = load(way, &dispatcher);
        arrive_at(&plugin, "/tick-every:20");
        let driver = driver_of(&plugin, dispatcher.clone());
        let ran = tokio::time::timeout(Duration::from_millis(150), driver.ticks()).await;
        assert!(
            ran.is_err(),
            "{way:?}: a plane that asks again is ticked again"
        );
        let t = ticked(&plugin);
        assert!(
            t[plane::Ticked::Ticks as usize] >= 3,
            "{way:?}: ticks {t:?}"
        );
        assert_eq!(
            t[plane::Ticked::Early as usize],
            0,
            "{way:?}: a tick before its time"
        );
        assert_ne!(
            t[plane::Ticked::Ticket as usize],
            0,
            "{way:?}: tick crossed on a ticket"
        );
        assert_eq!(
            plugin.inflight(),
            0,
            "{way:?}: a tick holds no max_inflight slot"
        );
    }
}

#[tokio::test]
async fn no_tick_follows_a_tick_that_asks_for_none() {
    for way in ways() {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let plugin = load(way, &dispatcher);
        let driver = driver_of(&plugin, dispatcher.clone());
        parks_after_one_tick(&driver).await;
        assert_eq!(ticked(&plugin)[plane::Ticked::Ticks as usize], 1, "{way:?}");
    }
}

async fn parks_after_one_tick(driver: &PlaneDriver) {
    let run = tokio::time::timeout(Duration::from_millis(300), driver.ticks()).await;
    assert!(run.is_err(), "the schedule parks on an answer of 0");
}

#[tokio::test]
async fn a_wake_of_the_driver_ticket_runs_drive_then_ticks_again() {
    for way in ways() {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let plugin = load(way, &dispatcher);
        let driver = driver_of(&plugin, dispatcher.clone());
        let waker = async {
            let ticks = || ticked(&plugin)[plane::Ticked::Ticks as usize];
            while ticks() < 1 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            let ticket = ticked(&plugin)[plane::Ticked::Ticket as usize];
            tokio::time::sleep(Duration::from_millis(60)).await;
            assert_eq!(ticks(), 1, "{way:?}: no tick without a wake");
            wake(&plugin, ticket_of(ticket));
            while ticks() < 2 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            assert!(
                stats(&plugin)[cases::stat::DRIVES] >= 1,
                "{way:?}: drive ran before the tick"
            );
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                () = driver.ticks() => panic!("{way:?}: the schedule ended at 0"),
                () = waker => {}
            }
        })
        .await
        .expect("the wake ticked again");
    }
}

/// A connection table whose read pends (interest under the caller's ticket) until bytes are put:
/// for that one connection (`ready`), or for whichever reads next (`bytes`).
#[derive(Default)]
struct Far {
    slab: ConnSlab<()>,
    bytes: Mutex<Option<Vec<u8>>>,
    /// Bytes for one connection's next read.
    ready: Mutex<std::collections::HashMap<ConnId, Vec<u8>>>,
    waiting: Mutex<Vec<u64>>,
    /// Connections opened (each ESTABLISH that ran).
    opened: Mutex<u32>,
    /// Each connection opened, in order.
    ids: Mutex<Vec<ConnId>>,
}

impl DeclaredConns for Far {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        _: &ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        self.slab.declare(owner, need);
        Ok(())
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }

    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
}

impl Conns for Far {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        _: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need)?;
        *self.opened.lock().unwrap() += 1;
        let id = self.slab.insert(caller, need, ())?;
        self.ids.lock().unwrap().push(id);
        Ok(id)
    }
    fn write(
        &self,
        c: InstanceId,
        id: ConnId,
        b: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        self.slab.get(c, id).map(|_| b.len())
    }
    fn read(&self, c: InstanceId, id: ConnId, t: u64, buf: &mut [u8]) -> Result<Piece, ConnError> {
        self.slab.get(c, id)?;
        let mine = self.ready.lock().unwrap().remove(&id);
        let Some(bytes) = mine.or_else(|| self.bytes.lock().unwrap().take()) else {
            self.waiting.lock().unwrap().push(t);
            return Err(ConnError::Pending);
        };
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(Piece {
            kind: PieceKind::Body,
            stream: StreamId(0),
            len: bytes.len(),
            end: true,
            status: None,
            status_code: None,
            status_namespace: None,
            retry_after_secs: None,
            fault: None,
            reason: None,
            declared_len: None,
        })
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Pending)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, c: InstanceId, id: ConnId) -> Result<(), ConnError> {
        self.slab.remove(c, id).map(|_| ())
    }
}

#[tokio::test]
async fn a_read_inside_tick_pends_on_the_driver_ticket_and_resumes_through_drive() {
    for way in ways() {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let far = Arc::new(Far::default());
        let plugin = load_over(way, &dispatcher, Arc::new(NoSink), Some(far.clone()));
        arrive_at(&plugin, "/tick-read");
        let driver = driver_of(&plugin, dispatcher.clone());
        parks_after_one_tick(&driver).await;
        let t = ticked(&plugin);
        assert_eq!(
            t[plane::Ticked::ReadPended as usize],
            1,
            "{way:?}: the read pended: {t:?}"
        );
        let waiting = far.waiting.lock().unwrap().clone();
        let ticket = t[plane::Ticked::Ticket as usize];
        assert_eq!(
            waiting,
            vec![ticket],
            "{way:?}: interest under the driver ticket"
        );
        *far.bytes.lock().unwrap() = Some(b"hello".to_vec());

        wake(&plugin, ticket_of(ticket));
        until("drive read the bytes", || {
            ticked(&plugin)[plane::Ticked::DriveRead as usize] == 5
        });
        assert!(
            stats(&plugin)[cases::stat::DRIVES] >= 1,
            "{way:?}: drive ran"
        );
    }
}

#[tokio::test]
async fn a_tick_forgets_what_the_last_cycle_kept_on_the_driver_ticket() {
    for way in ways() {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let far = Arc::new(Far::default());
        let plugin = load_over(way, &dispatcher, Arc::new(NoSink), Some(far.clone()));
        let driver = driver_of(&plugin, dispatcher.clone());
        for round in 1..=2 {
            arrive_at(&plugin, "/tick-read");
            parks_after_one_tick(&driver).await;

            *far.bytes.lock().unwrap() = Some(vec![b'x'; round]);
            let ticket = ticked(&plugin)[plane::Ticked::Ticket as usize];
            wake(&plugin, ticket_of(ticket));
            until("drive read the bytes", || {
                ticked(&plugin)[plane::Ticked::DriveRead as usize] == round as u64
            });
        }
        assert_eq!(
            *far.opened.lock().unwrap(),
            2,
            "{way:?}: each tick's ESTABLISH ran"
        );
        assert!(
            dispatcher.stats().driver_kept_high >= 1,
            "{way:?}: the first cycle's kept ESTABLISH answer is counted"
        );
    }
}

async fn eventually(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

async fn beside_ticks(
    way: Way,
    driver: &PlaneDriver,
    script: impl std::future::Future<Output = ()>,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            () = driver.ticks() => panic!("{way:?}: the schedule ended"),
            () = script => {}
        }
    })
    .await
    .expect("the script finished");
}

#[tokio::test]
async fn a_tick_keeps_every_held_exchange_and_the_second_completes_while_the_first_pends() {
    for way in ways() {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let far = Arc::new(Far::default());
        let plugin = load_over(way, &dispatcher, Arc::new(NoSink), Some(far.clone()));
        let driver = driver_of(&plugin, dispatcher.clone());
        let t = |c: plane::Ticked| ticked(&plugin)[c as usize];
        let opened = || *far.opened.lock().unwrap();
        arrive_at(&plugin, "/tick-hold");
        let script = async {
            eventually("the first exchange pends inside the first tick", || {
                t(plane::Ticked::HoldStarted) == 1 && !far.waiting.lock().unwrap().is_empty()
            })
            .await;
            let ticket = ticket_of(t(plane::Ticked::Ticket));
            arrive_at(&plugin, "/tick-hold");
            wake(&plugin, ticket);
            eventually(
                "the re-polled tick starts a second exchange beside the first",
                || t(plane::Ticked::HoldStarted) == 2 && opened() == 2,
            )
            .await;
            let (first, second) = {
                let ids = far.ids.lock().unwrap();
                (ids[0], ids[1])
            };
            far.ready.lock().unwrap().insert(second, b"second".to_vec());
            wake(&plugin, ticket);
            eventually("the second exchange completes", || {
                t(plane::Ticked::HoldDone) & 0b10 != 0
            })
            .await;
            assert_eq!(
                t(plane::Ticked::HoldDone),
                0b10,
                "{way:?}: the second completed while the first stays pending"
            );
            far.ready.lock().unwrap().insert(first, b"first".to_vec());
            wake(&plugin, ticket);
            eventually("the first exchange, still held, completes", || {
                t(plane::Ticked::HoldDone) == 0b11
            })
            .await;
            assert_eq!(
                opened(),
                2,
                "{way:?}: each exchange dialled once; the held one's kept answer survived the ticks"
            );
        };
        beside_ticks(way, &driver, script).await;
    }
}

fn load_capped(way: Way, dispatcher: &Dispatcher, far: &Arc<Far>, cap: u32) -> Arc<Plugin<Plane>> {
    let conns: Arc<dyn DeclaredConns> = far.clone();
    let (plugin, _) = load_open_capped(
        way,
        dispatcher,
        Arc::new(NoSink),
        ConnTable::Host(conns),
        cap,
    );
    assert_eq!(plugin.max_inflight(), cap, "{way:?}: the host's clamp");
    plugin
}

#[tokio::test]
async fn a_tick_that_reuses_a_held_handle_is_faulted_not_answered_the_held_answer() {
    for way in ways() {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let far = Arc::new(Far::default());
        let plugin = load_over(way, &dispatcher, Arc::new(NoSink), Some(far.clone()));
        let driver = driver_of(&plugin, dispatcher.clone());
        let t = |c: plane::Ticked| ticked(&plugin)[c as usize];
        let opened = || *far.opened.lock().unwrap();
        arrive_at(&plugin, "/tick-hold");
        let script = async {
            eventually("the first exchange is held", || {
                t(plane::Ticked::HoldStarted) == 1 && !far.waiting.lock().unwrap().is_empty()
            })
            .await;
            let ticket = ticket_of(t(plane::Ticked::Ticket));
            arrive_at(&plugin, "/tick-hold");
            arrive_at(&plugin, "/tick-reuse");
            wake(&plugin, ticket);
            eventually("the re-polled tick starts the reusing exchange", || {
                t(plane::Ticked::HoldStarted) == 2
            })
            .await;
            assert_eq!(
                (t(plane::Ticked::HoldFaulted), t(plane::Ticked::HoldDone)),
                (1, 0),
                "{way:?}: the reused handle is answered FAULT, not the held exchange's answer"
            );
            assert_eq!(opened(), 1, "{way:?}: nothing ran under the reused handle");
            let first = far.ids.lock().unwrap()[0];
            far.ready.lock().unwrap().insert(first, b"first".to_vec());
            wake(&plugin, ticket);
            eventually("the held exchange completes on its own connection", || {
                t(plane::Ticked::HoldDone) == 0b01
            })
            .await;
        };
        beside_ticks(way, &driver, script).await;
    }
}

#[tokio::test]
async fn the_held_set_on_a_driver_ticket_is_bounded_by_max_inflight_and_frees_per_exchange() {
    for way in ways() {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let far = Arc::new(Far::default());
        let plugin = load_capped(way, &dispatcher, &far, 2);
        let driver = driver_of(&plugin, dispatcher.clone());
        let t = |c: plane::Ticked| ticked(&plugin)[c as usize];
        let drives = || stats(&plugin)[cases::stat::DRIVES];
        for _ in 0..3 {
            arrive_at(&plugin, "/tick-hold");
        }
        let script = async {
            eventually("the first exchange is held", || {
                t(plane::Ticked::HoldStarted) == 1
            })
            .await;
            let ticket = ticket_of(t(plane::Ticked::Ticket));
            wake(&plugin, ticket);
            eventually("a second exchange is held beside it", || {
                t(plane::Ticked::HoldStarted) == 2
            })
            .await;
            let ticks = t(plane::Ticked::Ticks);
            let seen = drives();
            wake(&plugin, ticket);
            eventually("the wake's drive ran", || drives() > seen).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                (t(plane::Ticked::HoldStarted), t(plane::Ticked::Ticks)),
                (2, ticks),
                "{way:?}: at the cap the tick is parked, not crossed"
            );
            let second = far.ids.lock().unwrap()[1];
            far.ready.lock().unwrap().insert(second, b"second".to_vec());
            wake(&plugin, ticket);
            eventually(
                "one exchange ended: the parked tick starts the third",
                || t(plane::Ticked::HoldStarted) == 3,
            )
            .await;
            assert_eq!(
                t(plane::Ticked::HoldDone),
                0b010,
                "{way:?}: the third started while the first still pends"
            );
        };
        beside_ticks(way, &driver, script).await;
    }
}

#[tokio::test]
async fn a_tick_parked_at_the_cap_runs_when_a_slot_frees_without_a_poke() {
    for way in ways() {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let far = Arc::new(Far::default());
        let plugin = load_capped(way, &dispatcher, &far, 2);
        let drv = dispatcher.driver(&*plugin, 0).expect("a driver ticket");
        let t = |c: plane::Ticked| ticked(&plugin)[c as usize];
        for _ in 0..3 {
            arrive_at(&plugin, "/tick-hold");
        }
        for k in 1..=2 {
            let done = dispatcher
                .tick(&*plugin, drv, now_ns())
                .wait(Duration::from_secs(5))
                .expect("a held set under its cap answers the tick");
            assert_eq!(
                done.outcome,
                AbiOutcome::Pending,
                "{way:?}: exchange {k} is held"
            );
        }
        let parked = dispatcher.tick(&*plugin, drv, now_ns());
        assert!(
            parked.wait(Duration::from_millis(200)).is_none(),
            "{way:?}: at the cap the tick is parked, unanswered"
        );
        assert_eq!(t(plane::Ticked::HoldStarted), 2, "{way:?}: not crossed");
        let first = far.ids.lock().unwrap()[0];
        far.ready.lock().unwrap().insert(first, b"first".to_vec());

        wake(&plugin, drv);
        let done = parked
            .wait(Duration::from_secs(5))
            .expect("the freed slot woke the parked tick");
        assert_eq!(
            done.outcome,
            AbiOutcome::Pending,
            "{way:?}: it crossed and holds the third exchange"
        );
        assert_eq!(
            t(plane::Ticked::HoldStarted),
            3,
            "{way:?}: the third started"
        );
        assert_eq!(
            t(plane::Ticked::HoldDone),
            0b001,
            "{way:?}: the second still pends"
        );
    }
}

#[test]
fn the_crossing_is_under_a_microsecond() {
    for way in ways() {
        let dispatcher = Dispatcher::new(DispatchConfig::default());
        let plugin = load(way, &dispatcher);
        let mut reply = vec![0u8; 64];
        let mut units = vec![
            UnitCount {
                class: 0,
                source: 0,
                amount: 0
            };
            4
        ];
        let mut frame = Frame::new(
            OnPieceIn {
                head: in_head(),
                unit: 0,
                from: FROM_FAR_END,
                flags: 0,
                stream: 0,
                bytes: NO_BLOB,
                status_code: 0,
                status_class: 0,
                reply_buf: reply.as_mut_ptr(),
                reply_cap: reply.len(),
                units_buf: units.as_mut_ptr(),
                units_cap: units.len(),
                records_buf: std::ptr::null_mut(),
                records_cap: 0,
                fields_buf: std::ptr::null_mut(),
                fields_cap: 0,
                arena_buf: std::ptr::null_mut(),
                arena_cap: 0,
                member: busbar_contract::abi::mechanism::call::AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
                attempt_no: 0,
                _reserved: 0,
                pool: busbar_contract::abi::mechanism::call::AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
                caller_ref: busbar_contract::abi::mechanism::call::AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
                claim: 0,
                dialect: 0,
                head_fields: std::ptr::null(),
                head_fields_len: 0,
                passthrough: 0,
                reason: 0,
            },
            zero_piece_out(),
        );

        stats(&plugin);
        const BATCH: u32 = 1_000;
        let mut samples = Vec::new();
        for _ in 0..300 {
            let t = Instant::now();
            for _ in 0..BATCH {
                let c = plugin.call(slot::ON_PIECE, &mut frame);
                assert_eq!(c.outcome, AbiOutcome::Ready);
            }
            samples.push(t.elapsed().as_nanos() as f64 / f64::from(BATCH));
        }
        samples.sort_by(f64::total_cmp);
        let (p50, p99) = (
            samples[samples.len() / 2],
            samples[samples.len() * 99 / 100],
        );
        println!("{way:?}: on_piece crossing p50 {p50:.0} ns, p99 {p99:.0} ns");
        if !cfg!(debug_assertions) {
            assert!(
                p50 < 1_000.0 && p99 < 1_000.0,
                "{way:?}: p50 {p50} ns, p99 {p99} ns"
            );
        }
    }
}

fn zero_piece_out() -> OnPieceOut {
    let span = busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 };
    OnPieceOut {
        head: out_head(),
        emitted: 0,
        more: 0,
        flags: 0,
        reply_status: 0,
        fields_written: 0,
        fields_needed: 0,
        units_written: 0,
        units_needed: 0,
        records_written: 0,
        records_needed: 0,
        verdict: 0,
        arena_written: 0,
        arena_needed: 0,
        verb: span,
        target: span,
        need: 0,
        fault: 0,
        tap_fault: 0,
        _fault_reserved: [0; 2],
        lane: span,
        final_status: 0,
        _final_reserved: 0,
        final_message: span,
        final_details: span,
        metric_pool: span,
        metric_lane: span,
        wait_member: span,
        fault_reason: span,
    }
}

fn serve_table(
    way: Way,
    instance: &str,
) -> (
    Arc<Plugin<Plane>>,
    busbar_kernel::plane_driver::serve::ServeTable,
) {
    use busbar_kernel::plane_driver::serve::{ServeRoute, ServeTable};
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        ..DispatchConfig::default()
    }));
    let (plugin, snapshot) = load_open(way, &dispatcher, Arc::new(NoSink), ConnTable::Probe);
    let routes = snapshot
        .admin_routes
        .iter()
        .map(|r| ServeRoute {
            verb: r.verb.clone(),
            target: r.target.clone(),
            flags: r.flags,
            audit_verb: r.audit_verb.clone(),
        })
        .collect();
    let table = ServeTable {
        instance: instance.to_string(),
        audit_kind: "testkind".to_string(),
        calls: Arc::new(PlaneInstance::new(Arc::clone(&plugin), dispatcher, 1)),
        caps: BufferCaps::default(),
        routes,
        records: None,
    };
    (plugin, table)
}

fn admin(
    tables: &busbar_kernel::plane_driver::serve::ServeTables,
    method: &str,
    path: &str,
    body: &str,
) -> Option<(u16, String)> {
    let req = axum::http::Request::builder()
        .method(method)
        .uri(format!("{}{path}", busbar_kernel::api::ADMIN_PREFIX))
        .header("authorization", "Bearer operator-secret")
        .header("cookie", "session=secret")
        .header("proxy-authorization", "Basic secret")
        .header("x-trace", "t-1")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    rt.block_on(async {
        let resp = tables.answer(req).await?;
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("the body");
        Some((status, String::from_utf8_lossy(&bytes).into_owned()))
    })
}

fn rows(resource: &str) -> Vec<String> {
    busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(0, busbar_kernel::audit_ring::MAX_AUDIT_ENTRIES, None, None)
        .into_iter()
        .rev()
        .filter(|e| e.action == "testkind.act" && e.resource == resource)
        .map(|e| e.outcome)
        .collect()
}

#[test]
fn a_declared_admin_route_reaches_serve_and_an_undeclared_one_is_refused() {
    use busbar_kernel::plane_driver::serve::{serve, ServeTables, Unserved};
    let _one = PUBLISHED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    crate::dist_root_install::install();
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: memory}\nauth: {chain: [], admin_auth: []}\nproviders: {}\nmodels: {}\n",
    )
    .expect("the admin-route deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the admin-route deployment resolves");
    let store = crate::root::real_store::store();
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(crate::root::door_steps::Rules::default());
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(busbar_contract::store_calls::OpenedStore {
            records: store.clone(),
            calls: Some(store),
        }),
    )
    .expect("the product builds the admin-route deployment");
    limits.keep().expect("the admin-route limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    busbar_kernel::audit::auditlog::register_test_audit_stream(&app);
    for way in ways() {
        let item = format!("{way:?}").to_lowercase();
        let act = format!("/items/{item}/act");

        let tables = ServeTables::default();
        assert_eq!(admin(&tables, "POST", &act, "go"), None, "{way:?}");
        let (_plugin, table) = serve_table(way, "the-instance");
        let calls = table.calls.clone();
        assert_eq!(table.routes.len(), 2, "{way:?}: both routes are copied");
        tables
            .publish(table.clone(), &[])
            .expect("the instance publishes");

        let served = admin(&tables, "POST", &act, "go").expect("a declared route is served");
        assert_eq!(
            served,
            (200, format!("served {act} fields=x-trace")),
            "{way:?}: the plane serves it, and sees no credential"
        );
        let resource = format!("testkind:{item}");
        assert_eq!(rows(&resource), ["applied"], "{way:?}");
        let malformed = admin(&tables, "POST", &act, "malformed");
        assert_eq!(malformed.map(|r| r.0), Some(400), "{way:?}");
        assert_eq!(
            rows(&resource),
            ["applied"],
            "{way:?}: a malformed body is not audited"
        );
        let disagree = admin(&tables, "POST", &act, "disagree");
        assert_eq!(disagree.map(|r| r.0), Some(400), "{way:?}");
        assert_eq!(rows(&resource), ["applied", "rejected"], "{way:?}");

        assert_eq!(
            admin(&tables, "POST", &format!("/items/{item}/other"), "go"),
            None
        );
        assert_eq!(
            admin(&tables, "POST", &format!("/items/{item}/hook"), "go"),
            None
        );
        assert_eq!(
            admin(&tables, "GET", &act, "").map(|r| r.0),
            Some(405),
            "{way:?}"
        );

        assert_eq!(
            admin(&tables, "POST", &act, "short").map(|r| r.0),
            Some(200),
            "{way:?}"
        );
        assert_eq!(
            admin(&tables, "POST", &act, "short-twice").map(|r| r.0),
            Some(502)
        );
        assert_eq!(
            admin(&tables, "POST", &act, "bad-audit").map(|r| r.0),
            Some(502)
        );
        assert_eq!(rows(&resource).len(), 3, "{way:?}: a FAULT writes no row");

        let past = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime")
            .block_on(serve(
                &*calls,
                BufferCaps::default(),
                2,
                2,
                b"/x",
                Vec::new(),
                "".into(),
            ));
        assert_eq!(past, Err(Unserved::NoRoute), "{way:?}");

        let other = busbar_kernel::plane_driver::serve::ServeTable {
            instance: "another".to_string(),
            ..table.clone()
        };
        let refused = tables
            .publish(other, &[])
            .expect_err("an overlapping instance is refused");
        assert_eq!(refused.with, "the-instance", "{way:?}");
        let kernel = [("POST", "/items/{id}/act")];
        let refused = tables
            .publish(table.clone(), &kernel)
            .expect_err("a kernel route is never shadowed");
        assert_eq!(refused.with, "kernel", "{way:?}");
        tables
            .publish(table, &[])
            .expect("a refresh of the same instance publishes");

        tables.withdraw("the-instance");
        assert_eq!(
            admin(&tables, "POST", &act, "go"),
            None,
            "{way:?}: withdrawn, nothing mounts"
        );
    }
}

static PUBLISHED: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn a_public_route_is_served_by_the_planes_serve_without_a_credential() {
    use busbar_kernel::plane_driver::serve::ServeTables;
    let _one = PUBLISHED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for way in ways() {
        let item = format!("{way:?}").to_lowercase();
        let (_plugin, table) = serve_table(way, "the-public-instance");
        let tables = ServeTables::default();
        tables.publish(table, &[]).expect("the instance publishes");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "Bearer someone".parse().unwrap());
        headers.insert("cookie", "session=secret".parse().unwrap());
        headers.insert("x-trace", "t-1".parse().unwrap());
        let call = |method: &str, path: &str| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime");
            rt.block_on(async {
                let resp = tables
                    .answer_public(method, path, path, &headers, axum::body::Bytes::from("go"))
                    .await;
                let status = resp.status().as_u16();
                let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .expect("a body");
                (status, String::from_utf8_lossy(&body).into_owned())
            })
        };
        let hook = format!("/items/{item}/hook");
        assert_eq!(
            call("POST", &hook),
            (200, format!("public {hook} fields=x-trace")),
            "{way:?}: served by the plane, no credential crossed"
        );
        assert_eq!(call("GET", &hook).0, 404, "{way:?}: another verb");
        assert_eq!(
            call("POST", &format!("/items/{item}/act")).0,
            404,
            "{way:?}: the admin route is not public"
        );
        assert_eq!(call("POST", "/nowhere").0, 404, "{way:?}");
        tables.withdraw("the-public-instance");
        assert_eq!(call("POST", &hook).0, 404, "{way:?}: withdrawn");
    }
}

#[test]
fn a_public_route_carrying_its_own_token_is_lent_authorization_and_nothing_else() {
    use busbar_contract::abi::plane::{ROUTE_CARRIES_OWN_TOKEN, ROUTE_PUBLIC};
    use busbar_kernel::plane_driver::serve::ServeTables;
    let _one = PUBLISHED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for way in ways() {
        let item = format!("{way:?}").to_lowercase();
        let (_plugin, mut table) = serve_table(way, "the-token-instance");
        for route in &mut table.routes {
            if route.flags & ROUTE_PUBLIC != 0 {
                route.flags |= ROUTE_CARRIES_OWN_TOKEN;
            }
        }
        let tables = ServeTables::default();
        tables.publish(table, &[]).expect("the instance publishes");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "Bearer own-token".parse().unwrap());
        headers.insert("cookie", "session=secret".parse().unwrap());
        headers.insert("proxy-authorization", "Basic secret".parse().unwrap());
        headers.insert("x-trace", "t-1".parse().unwrap());
        let hook = format!("/items/{item}/hook");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let (status, body) = rt.block_on(async {
            let resp = tables
                .answer_public(
                    "POST",
                    &hook,
                    &hook,
                    &headers,
                    axum::body::Bytes::from("go"),
                )
                .await;
            let status = resp.status().as_u16();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .expect("a body");
            (status, String::from_utf8_lossy(&body).into_owned())
        });
        tables.withdraw("the-token-instance");
        assert_eq!(
            (status, body),
            (200, format!("public {hook} fields=authorization,x-trace")),
            "{way:?}: the plane's own token crossed, and no other credential field"
        );
    }
}

/// One line of a session caller's script.
#[derive(Debug, Clone, Copy)]
enum Line {
    /// Send this piece.
    Send(&'static [u8]),
    /// Wait until the plane has written this to the caller.
    Hear(&'static str),
    /// Never send another piece (the caller holds the session open).
    Hold,
}

struct Scripted {
    script: Mutex<std::collections::VecDeque<Line>>,
    heard: Mutex<Vec<u8>>,
}

impl Scripted {
    fn new<const N: usize>(lines: [Line; N]) -> Self {
        Scripted {
            script: Mutex::new(lines.into_iter().collect()),
            heard: Mutex::new(Vec::new()),
        }
    }

    fn heard(&self) -> String {
        String::from_utf8_lossy(&self.heard.lock().unwrap()).into_owned()
    }
}

impl busbar_kernel::plane_driver::CallerEnd for Scripted {
    fn head(&self, _status: u32, _fields: Vec<(Vec<u8>, Vec<u8>)>) {}

    async fn write(&self, bytes: &[u8]) -> bool {
        self.heard.lock().unwrap().extend_from_slice(bytes);
        true
    }
}

impl busbar_kernel::plane_driver::SessionCaller for Scripted {
    async fn read(&self) -> Option<Vec<u8>> {
        loop {
            let front = self.script.lock().unwrap().front().copied();
            match front {
                None => return None,
                Some(Line::Send(piece)) => {
                    self.script.lock().unwrap().pop_front();
                    return Some(piece.to_vec());
                }
                Some(Line::Hear(text)) if self.heard().contains(text) => {
                    self.script.lock().unwrap().pop_front();
                }
                Some(Line::Hear(_)) => tokio::time::sleep(Duration::from_millis(2)).await,
                Some(Line::Hold) => std::future::pending::<()>().await,
            }
        }
    }
}

async fn session(
    r: &Rig,
    far: &cases::Far,
    caller: &Scripted,
    key: u64,
) -> Result<(), busbar_contract::caps::ReasonCode> {
    session_on(&r.driver, far, caller, cases::arrival("/call", b""), key).await
}

async fn session_on<F, C>(
    driver: &PlaneDriver,
    far: &F,
    caller: &C,
    arrival: busbar_kernel::plane_driver::Arrival,
    key: u64,
) -> Result<(), busbar_contract::caps::ReasonCode>
where
    F: busbar_kernel::plane_driver::FarEnd,
    C: busbar_kernel::plane_driver::SessionCaller,
{
    use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
    use busbar_kernel::teller::{open_unit, AccrualMeter, Kernel, Run, SessionOpen};
    let steps = common::TestUnits::passing();
    let units = driver.unit(&steps, far, caller, arrival, 0);
    let kernel = Kernel::new();
    let (gauge, canary, leases, meter) = (
        ConcurrencyGauge::new(),
        busbar_kernel::canary::Canary::new(),
        LeaseCell::new(),
        AccrualMeter::new(),
    );
    let cell = common::cell(&kernel);
    let run = Run {
        cell: &cell,
        parent: None,
        leases: &leases,
        gauge: &gauge,
        canary: &canary,
        meter: &meter,
        taps: None,
    };
    let ctx = common::ctx(key);
    let SessionOpen::Admitted {
        route,
        destinations,
    } = open_unit(&kernel, &units, &ctx, run).await
    else {
        panic!("the session is admitted");
    };
    units.session(&route, &ctx, &destinations).await
}

const SEALED: &str = "fixture-lane";

#[tokio::test]
async fn a_duplex_session_answers_its_caller_and_cleans_up_once() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), cases::Book::default());
        let far = cases::Far::new(&[SEALED], &[b"x"]);
        let caller = Scripted::new([Line::Send(b"hi"), Line::Hear("echo:hi")]);
        let ended = tokio::time::timeout(Duration::from_secs(5), session(&r, &far, &caller, 31))
            .await
            .expect("the session ends with its caller");
        assert_eq!(ended, Ok(()), "{way:?}");
        assert_eq!(caller.heard(), "echo:hi", "{way:?}");
        assert_eq!(r.stats()[cases::stat::UNIT], 31, "{way:?}: the unit's key");
        assert_eq!(
            r.sessions()[plane::Sessions::Tickets as usize],
            1,
            "{way:?}: the caller's pieces crossed on one ticket"
        );
        assert!(far.sent().is_empty(), "{way:?}: no turn, no far end");
        assert_eq!(
            r.book
                .sessions_ended
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "{way:?}: one cleanup"
        );
        assert_eq!(
            r.stats()[cases::stat::CANCELS],
            0,
            "{way:?}: nothing to cancel"
        );
    }
}

#[tokio::test]
async fn unsolicited_output_reaches_the_caller_through_the_instances_one_driver_ticket() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), cases::Book::default());

        parks_after_one_tick(&r.driver).await;
        let far = cases::Far::new(&[SEALED], &[b"x"]);
        let caller = Scripted::new([Line::Send(b"push:hello"), Line::Hear("hello")]);
        let ended = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                biased;
                ended = session(&r, &far, &caller, 32) => ended,
                () = r.driver.drives() => Err(busbar_contract::caps::ReasonCode::TaskLost),
            }
        })
        .await
        .expect("the session's unsolicited output was collected");
        assert_eq!(ended, Ok(()), "{way:?}");
        assert_eq!(caller.heard(), "hello", "{way:?}");
        let s = r.sessions();
        assert_eq!(s[plane::Sessions::Collects as usize], 1, "{way:?}");
        assert_eq!(
            s[plane::Sessions::Tickets as usize],
            1,
            "{way:?}: collected on the session's caller-side ticket"
        );
        assert!(r.stats()[cases::stat::DRIVES] >= 1, "{way:?}: drive ran");
    }
}

#[tokio::test]
async fn a_turn_leg_walks_inside_the_destination_set_sealed_at_the_open() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), cases::Book::default());
        let far = cases::Far::new(&["outsider", SEALED], &[b"pong"]);
        let caller = Scripted::new([Line::Send(b"far:ping"), Line::Hear("far-said:pong")]);
        let ended = tokio::time::timeout(Duration::from_secs(5), session(&r, &far, &caller, 33))
            .await
            .expect("the turn's answer reached the caller");
        assert_eq!(ended, Ok(()), "{way:?}");
        assert_eq!(caller.heard(), "far-said:pong", "{way:?}");
        let sent = far.sent();
        assert_eq!(sent.len(), 1, "{way:?}: one send");
        assert_eq!(sent[0].member, SEALED, "{way:?}: inside the sealed set");
        assert_eq!(
            sent[0].attempt_no, 2,
            "{way:?}: the outsider was the first pick"
        );
        assert_eq!(sent[0].verb, b"POST", "{way:?}");
        assert_eq!(sent[0].target, b"/far/turn", "{way:?}");
        assert_eq!(sent[0].body, b"ping", "{way:?}");
        let s = r.sessions();
        assert_eq!(
            s[plane::Sessions::Attempts as usize],
            1,
            "{way:?}: only the sealed member was crossed"
        );
        assert_eq!(
            s[plane::Sessions::Tickets as usize],
            2,
            "{way:?}: one ticket per side"
        );
    }
}

#[tokio::test]
async fn a_held_far_end_takes_every_turn_while_its_socket_stays_open() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), cases::Book::default());
        let far = cases::Far::held(&["outsider", SEALED]);
        let caller = Scripted::new([
            Line::Send(b"far:one"),
            Line::Hear("far-said:re:one"),
            Line::Send(b"far:two"),
            Line::Hear("far-said:re:two"),
        ]);
        let ended = tokio::time::timeout(Duration::from_secs(5), session(&r, &far, &caller, 36))
            .await
            .expect("frame two reached the held far end and its answer reached the caller");
        assert_eq!(ended, Ok(()), "{way:?}");
        assert_eq!(
            caller.heard(),
            "far-said:hellofar-said:re:onefar-said:re:two",
            "{way:?}: the far end's frames as they arrived"
        );
        let sent = far.sent();
        assert_eq!(sent.len(), 1, "{way:?}: ONE dial for the session");
        assert_eq!(sent[0].member, SEALED, "{way:?}: inside the sealed set");
        assert_eq!(sent[0].body, b"one", "{way:?}: the dial carries frame one");
        assert_eq!(
            far.written(),
            vec![(b"two".to_vec(), true)],
            "{way:?}: frame two went into the open socket"
        );
        assert_eq!(
            r.sessions()[plane::Sessions::Tickets as usize],
            2,
            "{way:?}: one ticket per side"
        );
        assert_eq!(
            r.book
                .sessions_ended
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "{way:?}: one cleanup"
        );
        assert_eq!(
            r.stats()[cases::stat::CANCELS],
            0,
            "{way:?}: nothing cancelled"
        );
    }
}

#[tokio::test]
async fn a_far_end_that_hangs_up_ends_the_session_with_its_caller() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), cases::Book::default());
        let far = cases::Far::held(&[SEALED]);
        let caller = Scripted::new([
            Line::Send(b"far:one"),
            Line::Hear("far-said:re:one"),
            Line::Send(b"far:bye"),
            Line::Hold,
        ]);
        let ended = tokio::time::timeout(Duration::from_secs(5), session(&r, &far, &caller, 37))
            .await
            .expect("the far end's hang-up ended the session");
        assert_eq!(ended, Ok(()), "{way:?}");
        assert!(
            caller.heard().contains("far-said:re:bye"),
            "{way:?}: {}",
            caller.heard()
        );
        assert_eq!(far.sent().len(), 1, "{way:?}");
        assert_eq!(far.written(), vec![(b"bye".to_vec(), true)], "{way:?}");
        assert_eq!(
            r.book
                .sessions_ended
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "{way:?}: one cleanup"
        );
        assert_eq!(
            r.stats()[cases::stat::CANCELS],
            0,
            "{way:?}: nothing cancelled"
        );
    }
}

#[tokio::test]
async fn a_dropped_session_cleans_up_exactly_once() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), cases::Book::default());
        let far = cases::Far::new(&[SEALED], &[b"x"]);
        let caller = Scripted::new([Line::Send(b"hi"), Line::Hold]);
        let held =
            tokio::time::timeout(Duration::from_millis(300), session(&r, &far, &caller, 34)).await;
        assert!(held.is_err(), "{way:?}: the session was still open");
        assert_eq!(caller.heard(), "echo:hi", "{way:?}");
        let ended = || {
            r.book
                .sessions_ended
                .load(std::sync::atomic::Ordering::SeqCst)
        };
        assert_eq!(ended(), 1, "{way:?}: the dropped session's one cleanup");
        assert_eq!(r.driver.buried(), 2, "{way:?}: one ticket per side, buried");
        r.driver.sweep();
        assert_eq!(r.driver.buried(), 0, "{way:?}");
        assert_eq!(
            r.stats()[cases::stat::CANCELS],
            2,
            "{way:?}: each side cancelled once"
        );
        r.driver.sweep();
        assert_eq!(ended(), 1, "{way:?}: and never again");
        assert_eq!(r.stats()[cases::stat::CANCELS], 2, "{way:?}");
    }
}

struct Unstated;

impl busbar_kernel::plane_driver::MoneySeam for Unstated {
    fn checkpoint(
        &self,
        _: &busbar_kernel::teller::UnitCtx,
        _: &[UnitCount],
    ) -> busbar_kernel::plane_driver::Checkpoint {
        busbar_kernel::plane_driver::Checkpoint::Continue
    }
    fn cancelled(
        &self,
        _: &busbar_kernel::teller::UnitCtx,
        _: &busbar_kernel::plane_driver::CancelBill,
    ) {
    }
    fn abandoned(&self, _: &busbar_kernel::teller::UnitCtx, _: busbar_kernel::teller::Ended) {}
}

#[tokio::test]
async fn a_session_is_refused_while_its_money_is_unstated() {
    for way in ways() {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig {
            workers: 2,
            ..DispatchConfig::default()
        }));
        let plugin = load(way, &dispatcher);
        let calls = Arc::new(PlaneInstance::new(Arc::clone(&plugin), dispatcher, 1));
        let refusal_statuses = calls.refusal_statuses();
        let driver = PlaneDriver::new(
            calls,
            DriverConfig {
                caps: BufferCaps::default(),
                op_classes: vec![OpClassId::new("call")],
                status_of: refusal_status,
                refusal_statuses,
                caller_refs: None,
            },
            Arc::new(Unstated),
            services(),
            ("test_plane", &serde_yaml::Value::Null),
        )
        .expect("the instance is admitted");
        let r = Rig {
            plugin,
            driver,
            book: Arc::new(cases::Book::default()),
        };
        let far = cases::Far::new(&[SEALED], &[b"x"]);
        let caller = Scripted::new([Line::Send(b"hi")]);
        let ended = session(&r, &far, &caller, 35).await;
        assert_eq!(
            ended,
            Err(busbar_contract::caps::ReasonCode::Unpriced),
            "{way:?}"
        );
        assert_eq!(
            r.stats()[cases::stat::ON_PIECES],
            0,
            "{way:?}: no piece crossed"
        );
        assert_eq!(caller.heard(), "", "{way:?}");
    }
}
