// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE DRIVER, BOTH WAYS (`BUSBAR-1.6.0.md` Part 3, §12). One test plane, LINKED (its door
//! compiled into this test) and DROPPED (its `cdylib`, dlopened), each loaded through the one
//! path, handed to the kernel's plane driver as the contract's `PlaneCalls`, and driven by the one
//! loop (`run_unit_async` / `open_unit`) through every case in `plane_driver_cases.rs`. Beside
//! them: a plane's `drive` through the dispatcher's own driver ticket, the crossing's cost, and
//! the duplex session (K6) the driver pumps after `open_unit` admitted it.

#[path = "../../busbar-kernel/tests/common/mod.rs"]
mod common;

#[path = "fixtures/plane_driver_test_plane.rs"]
#[allow(dead_code)]
mod plane;

#[path = "../../busbar-kernel/tests/support/plane_driver_cases.rs"]
mod cases;

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
    rendering_of, Bind, Diagnostic, DispatchConfig, Dispatcher, Dropped, EnvelopeSink, Frame,
    LinkedRow, Metric, NoSink, Plugin, NO_BLOB,
};

/// The dispatcher's clock, the one a unit's deadline is on.
pub(crate) fn now_ns() -> u64 {
    dispatch_now()
}

// ── the doors ────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Way {
    Linked,
    Dropped,
}

/// The example `cdylib` beside this test binary. Under CI a missing artifact is a failure.
fn dropped_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.parent()?.join("examples").join(format!(
        "{}plane_driver_test_plane{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    let found = path.exists().then_some(path);
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the plane_driver_test_plane example cdylib is not built under CI"
    );
    found
}

/// The doors this run can reach: both, or only the linked one where the example is not built.
pub(crate) fn ways() -> Vec<Way> {
    let mut ways = vec![Way::Linked];
    if dropped_path().is_some() {
        ways.push(Way::Dropped);
    }
    ways
}

/// Load and open the test plane through `way`, adopted by `dispatcher`.
fn load(way: Way, dispatcher: &Dispatcher) -> Plugin<Plane> {
    load_with(way, dispatcher, Arc::new(NoSink))
}

/// [`load`], with the #85 envelope going to `sink`.
fn load_with(way: Way, dispatcher: &Dispatcher, sink: Arc<dyn EnvelopeSink>) -> Plugin<Plane> {
    load_open(way, dispatcher, sink, None).0
}

/// [`load_with`], its need declared on `conns` when given.
fn load_over(
    way: Way,
    dispatcher: &Dispatcher,
    sink: Arc<dyn EnvelopeSink>,
    conns: Option<Arc<dyn DeclaredConns>>,
) -> Plugin<Plane> {
    load_open(way, dispatcher, sink, conns).0
}

/// [`load_over`], and the first generation's snapshot as the host copied it.
fn load_open(
    way: Way,
    dispatcher: &Dispatcher,
    sink: Arc<dyn EnvelopeSink>,
    conns: Option<Arc<dyn DeclaredConns>>,
) -> (Plugin<Plane>, OwnedSnapshot) {
    let bind = Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
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
            let path = dropped_path().expect("the example is built");
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
    (plugin, snapshot.expect("the snapshot is copied"))
}

/// The plane's own counters, read through `arrive` on `/stats`.
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
            _reserved: 0,
            correlation: 0,
            cancels: 0,
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

// ── the rig the cases run on ─────────────────────────────────────────────────────────────────────

pub(crate) struct Rig {
    plugin: Plugin<Plane>,
    pub(crate) driver: PlaneDriver,
    pub(crate) book: Arc<cases::Book>,
}

impl Rig {
    pub(crate) fn stats(&self) -> [u64; cases::stat::COUNT] {
        stats(&self.plugin)
    }

    /// The plane's session counters (`/sessions`), in [`plane::Sessions`] order.
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
    let calls = Arc::new(PlaneInstance::new(plugin.clone(), dispatcher, 1));
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

// ── the plane's driver ticket ────────────────────────────────────────────────────────────────────

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

/// A plane's `drive`, run by the dispatcher's own driver ticket, crosses with the plane's
/// `PlaneDriveIn`/`PlaneDriveOut` and is judged by the plane's `check_drive`: its answer is
/// accepted (its envelope reaches the host). With the lifecycle's bare `DriveIn`/`OutHead` frame
/// every plane `drive` was FAULT, its envelope never read.
#[test]
fn a_plane_driven_through_its_driver_ticket_answers_under_its_own_frame() {
    for way in ways() {
        let dispatcher = Dispatcher::new(DispatchConfig::default());
        let gauges = Arc::new(Gauges::default());
        let plugin = load_with(way, &dispatcher, gauges.clone());
        let t = dispatcher.driver(&plugin, 0).expect("a driver ticket");
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

/// Wake ticket `t` through the plane (only a plugin holds the host's wake).
fn wake(plugin: &Plugin<Plane>, t: busbar_contract::abi::mechanism::ticket::Ticket) {
    arrive_at(plugin, &format!("/wake:{}:{}", t.slot, t.generation));
}

/// One `arrive` on `target`, READY.
fn arrive_at(plugin: &Plugin<Plane>, target: &str) -> [u64; 8] {
    let target = target.as_bytes().to_vec();
    let mut units = [UnitCount {
        class: 0,
        source: 0,
        amount: 0,
    }; 8];
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
        _reserved: 0,
        correlation: 0,
        cancels: 0,
    }
}

// ── the instance's driver ticket: tick and drive ────────────────────────────────────────────────

/// The plane's tick counters (`/ticks`).
fn ticked(plugin: &Plugin<Plane>) -> [u64; plane::TICKED] {
    let all = arrive_at(plugin, "/ticks");
    let mut out = [0; plane::TICKED];
    out.copy_from_slice(&all[..plane::TICKED]);
    out
}

/// The kernel's driver of `plugin`'s instance, on the dispatcher's one worker (worker 0).
fn driver_of(plugin: &Plugin<Plane>, dispatcher: Arc<Dispatcher>) -> PlaneDriver {
    let calls = Arc::new(PlaneInstance::new(plugin.clone(), dispatcher, 0));
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

/// The kernel's host services, with no egress class and no store.
fn services() -> Arc<KernelServices> {
    Arc::new(KernelServices::new())
}

/// Wait up to 5 s for `done`.
fn until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// THE KERNEL TICKS A PLANE INSTANCE (spec :3288, B.3.7): at once, then at each `next_tick_ns` it
/// answered, never before it, on the instance's driver ticket (the head carries it); dropping the
/// driver ends the schedule. RED before K-TICK: nothing ever called `tick`.
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

/// A plane that answers `next_tick_ns = 0` is ticked once and never again.
#[tokio::test]
async fn no_tick_follows_a_tick_that_asks_for_none() {
    for way in ways() {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let plugin = load(way, &dispatcher);
        let driver = driver_of(&plugin, dispatcher.clone());
        tokio::time::timeout(Duration::from_secs(5), driver.ticks())
            .await
            .expect("the schedule ends at next_tick_ns = 0");
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(ticked(&plugin)[plane::Ticked::Ticks as usize], 1, "{way:?}");
    }
}

/// A connection table whose read pends (interest under the caller's ticket) until bytes are put.
#[derive(Default)]
struct Far {
    slab: ConnSlab<()>,
    bytes: Mutex<Option<Vec<u8>>>,
    waiting: Mutex<Vec<u64>>,
    /// Connections opened (each ESTABLISH that ran).
    opened: Mutex<u32>,
}

impl DeclaredConns for Far {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        _: &ReadNeed,
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
        self.slab.insert(caller, need, ())
    }
    fn write(&self, c: InstanceId, id: ConnId, b: &[u8], _: bool) -> Result<usize, ConnError> {
        self.slab.get(c, id).map(|_| b.len())
    }
    fn read(&self, c: InstanceId, id: ConnId, t: u64, buf: &mut [u8]) -> Result<Piece, ConnError> {
        self.slab.get(c, id)?;
        let Some(bytes) = self.bytes.lock().unwrap().take() else {
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
            reason: None,
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

/// A HOP INSIDE `tick` PENDS AND RESUMES THROUGH `drive` (ARCHITECT S7-TICK; spec :3314-3316):
/// the plane ESTABLISHes its need (READY: the table holds the dial) and READs it inside `tick`; the
/// read is PENDING on the instance's driver ticket, not refused for want of one, and `tick` answers
/// PENDING, which ends it (a driver ticket's op is never resumed: what pended goes on through
/// `drive`); the table's wake on that ticket calls `drive`, whose read on the driver ticket gets the
/// bytes. RED before K-TICK: no `tick` ran, so nothing pended; with a PENDING tick held open, the
/// schedule never ends.
#[tokio::test]
async fn a_read_inside_tick_pends_on_the_driver_ticket_and_resumes_through_drive() {
    for way in ways() {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let far = Arc::new(Far::default());
        let plugin = load_over(way, &dispatcher, Arc::new(NoSink), Some(far.clone()));
        arrive_at(&plugin, "/tick-read");
        let driver = driver_of(&plugin, dispatcher.clone());
        tokio::time::timeout(Duration::from_secs(5), driver.ticks())
            .await
            .expect("one tick");
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
        // The table's readiness wake, on the ticket it registered.
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

/// EACH TICK STARTS A NEW CYCLE ON THE DRIVER TICKET (ARCHITECT S7-TICK (iii)): the services'
/// kept answers under the driver ticket are forgotten when the next tick starts, so the second
/// tick's ESTABLISH (handle 1 again) runs afresh instead of answering the first tick's stream; the
/// cycle's kept count reaches the dispatcher's high-water gauge. RED before: the driver ticket is
/// never recycled, the second ESTABLISH replayed the first one's answer (one connection opened) and
/// the kept answers grew without bound.
#[tokio::test]
async fn a_tick_forgets_what_the_last_cycle_kept_on_the_driver_ticket() {
    for way in ways() {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let far = Arc::new(Far::default());
        let plugin = load_over(way, &dispatcher, Arc::new(NoSink), Some(far.clone()));
        let driver = driver_of(&plugin, dispatcher.clone());
        for _ in 0..2 {
            arrive_at(&plugin, "/tick-read");
            tokio::time::timeout(Duration::from_secs(5), driver.ticks())
                .await
                .expect("one tick");
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

// ── the crossing's cost ──────────────────────────────────────────────────────────────────────────

/// One `on_piece` crossing (host→plane, through the table, its answer judged by the kind's check),
/// p50 and p99 over batches, per door. The budget (under 1 µs) is asserted in release builds; a
/// debug build prints the figures only.
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
                _reserved_tail: 0,
            },
            zero_piece_out(),
        );
        // Unit 0 arrives first (its `arrive` on `/stats`), so the plane holds its head.
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
    }
}

// ── the plane's `serve` op on the admin table (B.9; ARCHITECT C2c S5 Q1-Q6) ─────────────────────

/// The test plane's admin table, as the composition root publishes an open instance's snapshot.
fn serve_table(
    way: Way,
    instance: &str,
) -> (
    Plugin<Plane>,
    busbar_kernel::plane_driver::serve::ServeTable,
) {
    use busbar_kernel::plane_driver::serve::{ServeRoute, ServeTable};
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        ..DispatchConfig::default()
    }));
    let (plugin, snapshot) = load_open(way, &dispatcher, Arc::new(NoSink), None);
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
        calls: Arc::new(PlaneInstance::new(plugin.clone(), dispatcher, 1)),
        caps: BufferCaps::default(),
        routes,
    };
    (plugin, table)
}

/// One admin request through the admin router's fallback: its status and body, or `None` when no
/// published instance names the path (the router's own `404`).
fn admin(method: &str, path: &str, body: &str) -> Option<(u16, String)> {
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
        let resp = busbar_kernel::plane_driver::serve::answer(req).await?;
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("the body");
        Some((status, String::from_utf8_lossy(&bytes).into_owned()))
    })
}

/// The audit rows written for `resource` under the test plane's audit verb.
fn rows(resource: &str) -> Vec<String> {
    busbar_kernel::audit_ring::AUDIT
        .export()
        .into_iter()
        .filter(|e| e.action == "testkind.act" && e.resource == resource)
        .map(|e| e.outcome)
        .collect()
}

/// A DECLARED ADMIN ROUTE REACHES `serve`, AND NOTHING ELSE DOES, both ways. The plane is handed
/// the request's own head fields without a credential, answers with its own status, fields
/// and body, and reports the audit row the kernel writes under the route's audit word:
/// 1.5.5's two `400`s, one unaudited (a malformed body), one audited `rejected` (a disagreement).
/// An undeclared path, a public route and an unpublished instance are the router's `404`; a
/// declared path under another verb is the admin `405`; an index past the snapshot never crosses;
/// a short answer is re-called once, and a second short answer or an unknown audit code is `502`.
/// A route that overlaps another instance's, or a kernel route, is refused at publish.
#[test]
fn a_declared_admin_route_reaches_serve_and_an_undeclared_one_is_refused() {
    use busbar_kernel::plane_driver::serve::{publish, serve, withdraw, Unserved};
    for way in ways() {
        let item = format!("{way:?}").to_lowercase();
        let act = format!("/items/{item}/act");
        // Unpublished: nothing mounts.
        assert_eq!(admin("POST", &act, "go"), None, "{way:?}");
        let (_plugin, table) = serve_table(way, "the-instance");
        let calls = table.calls.clone();
        assert_eq!(table.routes.len(), 2, "{way:?}: both routes are copied");
        publish(table.clone(), &[]).expect("the instance publishes");

        let served = admin("POST", &act, "go").expect("a declared route is served");
        assert_eq!(
            served,
            (200, format!("served {act} fields=x-trace")),
            "{way:?}: the plane serves it, and sees no credential"
        );
        let resource = format!("testkind:{item}");
        assert_eq!(rows(&resource), ["applied"], "{way:?}");
        let malformed = admin("POST", &act, "malformed");
        assert_eq!(malformed.map(|r| r.0), Some(400), "{way:?}");
        assert_eq!(
            rows(&resource),
            ["applied"],
            "{way:?}: a malformed body is not audited"
        );
        let disagree = admin("POST", &act, "disagree");
        assert_eq!(disagree.map(|r| r.0), Some(400), "{way:?}");
        assert_eq!(rows(&resource), ["applied", "rejected"], "{way:?}");

        assert_eq!(admin("POST", &format!("/items/{item}/other"), "go"), None);
        assert_eq!(admin("POST", &format!("/items/{item}/hook"), "go"), None);
        assert_eq!(admin("GET", &act, "").map(|r| r.0), Some(405), "{way:?}");

        assert_eq!(
            admin("POST", &act, "short").map(|r| r.0),
            Some(200),
            "{way:?}"
        );
        assert_eq!(admin("POST", &act, "short-twice").map(|r| r.0), Some(502));
        assert_eq!(admin("POST", &act, "bad-audit").map(|r| r.0), Some(502));
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
        let refused = publish(other, &[]).expect_err("an overlapping instance is refused");
        assert_eq!(refused.with, "the-instance", "{way:?}");
        let kernel = [("POST", "/items/{id}/act")];
        let refused =
            publish(table.clone(), &kernel).expect_err("a kernel route is never shadowed");
        assert_eq!(refused.with, "kernel", "{way:?}");
        publish(table, &[]).expect("a refresh of the same instance publishes");

        withdraw("the-instance");
        assert_eq!(
            admin("POST", &act, "go"),
            None,
            "{way:?}: withdrawn, nothing mounts"
        );
    }
}

// ── duplex sessions (K6) ─────────────────────────────────────────────────────────────────────────

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

/// A session's caller: it sends its script's pieces, waits where the script says, and keeps what
/// the plane wrote to it. Its side ends when the script does.
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
    /// Cancel-safe: a line leaves the script only once it is answered.
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

/// Open a session on `r`'s driver through the one loop's opener (unit `key`, its stream), then pump
/// it under the admission it handed back.
async fn session(
    r: &Rig,
    far: &cases::Far,
    caller: &Scripted,
    key: u64,
) -> Result<(), busbar_contract::caps::ReasonCode> {
    use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
    use busbar_kernel::teller::{open_unit, AccrualMeter, Kernel, Run, SessionOpen};
    let steps = common::TestUnits::passing();
    let units = r
        .driver
        .unit(&steps, far, caller, cases::arrival("/call", b""), 0);
    let kernel = Kernel::new();
    let (gauge, canary, leases, meter) = (
        ConcurrencyGauge::new(),
        busbar_contract::caps::Canary::new(),
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
    };
    let ctx = common::ctx(key);
    let SessionOpen::Admitted {
        route,
        destinations,
    } = open_unit(&kernel, &units, &ctx, run)
    else {
        panic!("the session is admitted");
    };
    units.session(&route, &ctx, &destinations).await
}

/// The lane the test steps' Verify seals: the one destination a session's turns may reach.
const SEALED: &str = "fixture-lane";

/// A DUPLEX SESSION, both ways (K6): the caller's pieces cross on the session's caller-side
/// ticket, under the unit's stream, and the plane's answers reach the caller; the caller's last
/// piece ends it, and its one cleanup runs once. Nothing reaches the far end without a turn.
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

/// UNSOLICITED OUTPUT (R-B), both ways: the plane holds output for a session and wakes the
/// instance's ONE driver ticket; its `drive` names the session, the driver wakes it, and the
/// session collects the output (`FROM_KERNEL`, no bytes) on its own caller-side ticket, so the
/// caller hears it. No ticket of the session's own is a driver ticket. RED without the fan-out
/// (`PlaneDriver::drives`, or the loader handing `drive`'s names on): the caller never hears it.
#[tokio::test]
async fn unsolicited_output_reaches_the_caller_through_the_instances_one_driver_ticket() {
    for way in ways() {
        let r = rig(way, BufferCaps::default(), cases::Book::default());
        // The plane learns its driver ticket from its first tick.
        tokio::time::timeout(Duration::from_secs(5), r.driver.ticks())
            .await
            .expect("one tick");
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

/// A TURN LEG IS A ROUTE WALK under the session's one admission, inside the destination set
/// sealed at the open, both ways: the caller's piece the plane binds for the far end is walked on
/// the session's far-side ticket; the walk's member outside the sealed set is passed over without
/// a crossing, and the far end's answer reaches the caller. RED without the sealed-set check: the
/// first attempt goes to the outsider.
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

/// CLEANUP RUNS EXACTLY ONCE when the session's caller drops it mid-flight, both ways: the guard
/// runs the session's cleanup once, its two tickets are buried (nothing crosses inside a `Drop`),
/// and the sweep cancels each once; nothing runs it again.
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

/// A money seam that states no session money.
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

/// THE SESSION MONEY GUARD (K6-4 not landed): under a money seam that states no session money a
/// session is refused at its open as `Unpriced`, before any ticket is minted or piece crosses.
#[tokio::test]
async fn a_session_is_refused_while_its_money_is_unstated() {
    for way in ways() {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig {
            workers: 2,
            ..DispatchConfig::default()
        }));
        let plugin = load(way, &dispatcher);
        let calls = Arc::new(PlaneInstance::new(plugin.clone(), dispatcher, 1));
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
