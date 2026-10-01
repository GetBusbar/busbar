// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE DRIVER, BOTH WAYS (`BUSBAR-1.6.0.md` Part 3, §12). One test plane, LINKED (its door
//! compiled into this test) and DROPPED (its `cdylib`, dlopened), each loaded through the one
//! path, handed to the kernel's plane driver as the contract's `PlaneCalls`, and driven by the one
//! loop (`run_unit_async` / `open_unit`) through every case in `plane_driver_cases.rs`. Beside
//! them: a plane's `drive` through the dispatcher's own driver ticket, and the crossing's cost.

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
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, PlaneOpenIn, PlaneOpenOut, UnitCount,
    FROM_FAR_END,
};
use busbar_contract::caps::OpClassId;
use busbar_kernel::plane_driver::{refusal_status, BufferCaps, DriverConfig, PlaneDriver};
use busbar_plugin_loader::dispatch::{
    in_head, kinds::plane::Plane, load_dropped, load_linked, now_ns as dispatch_now, out_head, rendering_of,
    plane_calls::PlaneInstance, Bind, Diagnostic, DispatchConfig, Dispatcher, Dropped,
    EnvelopeSink, Frame, LinkedRow, Metric, NoSink, Plugin, NO_BLOB,
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
    let bind = Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink,
        dispatcher: dispatcher.adopter(),
        conns: None,
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
            },
            snapshot: std::ptr::null(),
        },
    );
    assert_eq!(
        plugin.call(life::OPEN, &mut open).outcome,
        AbiOutcome::Ready
    );
    plugin
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
    );
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
    let target = format!("/wake:{}:{}", t.slot, t.generation).into_bytes();
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
