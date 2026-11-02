// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::dispatch_test_plugin as plug;
use busbar_contract::abi::mechanism::call::{Blob, DeadlineClass, OutHead, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::check::{fault, Fault, Rule};
use busbar_contract::abi::mechanism::door::{Door, DoorParts, KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    slot, OpenIn, OpenOut, OpsHead, RefreshIn, TickIn, TickOut, ValidateIn, LIFECYCLE_SLOTS,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, MECHANISM_VERSION};

use crate::dispatch::load::validate_door;
use crate::dispatch::{
    in_head, load_dropped, load_linked, now_ns, out_head, Bind, Budgets, Diagnostic,
    DispatchConfig, Dispatcher, Dropped, EnvelopeSink, Frame, Kind, LinkedRow, LoadError,
    ManifestFacts, Metric, Plugin, NO_BLOB,
};

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod unload_witness {
    use std::mem::ManuallyDrop;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::sync::Arc;
    use std::time::Duration;

    use libloading::Library;

    const REENTRANT_CHILD: &str = "BUSBAR_UNLOAD_REENTRANT_CHILD";

    pub(crate) struct Unloaded {
        pub(crate) thread: std::thread::ThreadId,
        pub(crate) permanent: bool,
        pub(crate) reentered: bool,

        dispatcher: Option<ManuallyDrop<Arc<super::Dispatcher>>>,
    }

    impl Unloaded {
        pub(super) fn release_dispatcher_on_caller(self) {
            if let Some(dispatcher) = self.dispatcher {
                drop(ManuallyDrop::into_inner(dispatcher));
            }
        }
    }

    struct Context {
        sender: Sender<Unloaded>,
        dispatcher: Option<Arc<super::Dispatcher>>,
    }

    extern "C" fn witnessed_unload(context: usize) {
        // SAFETY: `UnloadWitness::new` transfers exactly this Box to the fixture, whose finalizer
        // takes its callback once. No other code consumes the pointer after successful registration.
        let Context { sender, dispatcher } = *unsafe { Box::from_raw(context as *mut Context) };

        let reentered = dispatcher.as_ref().is_some_and(|d| {
            if let Some(ticket) = d.mint(0) {
                d.recycle(ticket);
                true
            } else {
                false
            }
        });
        let observed = Unloaded {
            thread: std::thread::current().id(),
            permanent: crate::ffi_thread::on_permanent_worker(),
            reentered,
            dispatcher: dispatcher.map(ManuallyDrop::new),
        };

        let _ = sender.send(observed);
    }

    pub(crate) struct UnloadWitness {
        dir: PathBuf,
        path: PathBuf,
        unloaded: Receiver<Unloaded>,
    }

    impl UnloadWitness {
        pub(crate) fn new() -> (Self, Library) {
            Self::with_dispatcher(None)
        }

        pub(super) fn reentrant(dispatcher: Arc<super::Dispatcher>) -> (Self, Library) {
            Self::with_dispatcher(Some(dispatcher))
        }

        fn with_dispatcher(dispatcher: Option<Arc<super::Dispatcher>>) -> (Self, Library) {
            let dir = unique_dir();
            let (sender, unloaded) = mpsc::channel();
            let path = dir.join(crate::plugin_library_filename("dispatch_test_plugin"));
            let witness = Self {
                dir,
                path,
                unloaded,
            };
            std::fs::copy(
                crate::dispatch_tests::example_cdylib("dispatch_test_plugin"),
                &witness.path,
            )
            .expect("copy this test's existing dropped fixture");
            let lib =
                crate::dlopen_on_worker(witness.path.as_os_str()).expect("load the copied image");
            type Arm = extern "C" fn(extern "C" fn(usize), usize) -> bool;
            // SAFETY: the existing fixture exports exactly this registration function. `lib` remains
            // live through the call; neither the Symbol nor a plugin function pointer escapes it.
            let arm = unsafe { lib.get::<Arm>(b"busbar_test_arm_unload\0") }
                .expect("the dropped fixture exports its finalizer witness");
            let context = Box::into_raw(Box::new(Context { sender, dispatcher })) as usize;
            let armed = crate::ffi_thread::on_plugin_thread(|| arm(witnessed_unload, context))
                .expect("fixture registration does not panic");
            if !armed {
                // SAFETY: a refused registration retains no pointer; this caller still owns the Box.
                drop(unsafe { Box::from_raw(context as *mut Context) });
            }
            assert!(armed, "a new copied image has no previous witness");
            (witness, lib)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.path
        }

        pub(crate) fn finished(&self) -> Unloaded {
            self.unloaded
                .recv_timeout(Duration::from_secs(5))
                .expect("this image's actual finalizer must report its unload")
        }

        pub(crate) fn is_pending(&self) -> bool {
            matches!(self.unloaded.try_recv(), Err(mpsc::TryRecvError::Empty))
        }
    }

    impl Drop for UnloadWitness {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn unique_dir() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);

        let parent = if std::env::var_os(REENTRANT_CHILD).is_some() {
            std::env::current_dir().expect("the isolated child's parent-owned directory")
        } else {
            std::env::temp_dir()
        };
        loop {
            let dir = parent.join(format!(
                "busbar-unload-witness-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => return dir,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create unique fixture directory: {e}"),
            }
        }
    }

    struct ChildCase {
        child: Option<std::process::Child>,
        dir: PathBuf,
    }

    impl Drop for ChildCase {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    pub(super) fn assert_reentrant_child(test: &str, child_body: fn()) {
        const FINISHED: &str = "unload-reentrant-progress-finished";
        if std::env::var_os(REENTRANT_CHILD).is_some() {
            child_body();
            println!("{FINISHED}");
            return;
        }
        let mut case = ChildCase {
            child: None,
            dir: unique_dir(),
        };
        let stdout = case.dir.join("stdout");
        let stderr = case.dir.join("stderr");
        case.child = Some(
            std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args(["--exact", test, "--test-threads=1", "--nocapture"])
                .env(REENTRANT_CHILD, "1")
                .current_dir(&case.dir)
                .stdout(std::fs::File::create(&stdout).expect("capture stdout"))
                .stderr(std::fs::File::create(&stderr).expect("capture stderr"))
                .spawn()
                .expect("run isolated finalizer reentrancy case"),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = case.child.as_mut().unwrap().try_wait().expect("poll child") {
                case.child.take().unwrap().wait().expect("reap child");
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "finalizer reentrancy child did not finish"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let stdout = std::fs::read_to_string(stdout).expect("read stdout");
        let stderr = std::fs::read_to_string(stderr).expect("read stderr");
        assert!(
            status.success() && stdout.contains(FINISHED),
            "finalizer reentrancy child status {status}; stdout: {stdout}; stderr: {stderr}"
        );
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(crate) use unload_witness::UnloadWitness;

/// The test kind's context: the Statement's `max_inflight`, as bound.
#[derive(Debug, PartialEq, Eq)]
struct TestContext(u32);

pub(crate) struct TestKind;
impl Kind for TestKind {
    const CODE: KindCode = plug::KIND;
    type Ops = OpsHead;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn context(
        st: &busbar_contract::abi::mechanism::door::Statement,
    ) -> Result<Option<Box<crate::dispatch::Context>>, String> {
        Ok(Some(Box::new(TestContext(st.max_inflight))))
    }

    fn check(a: &crate::dispatch::Answer) -> Result<(), Fault> {
        if a.context::<TestContext>() != Some(&TestContext(2)) {
            return Err(fault(Rule::Missing, "test.context"));
        }
        if a.slot == TICK && a.out::<TickOut>()?.next_tick_ns == plug::KIND_REJECTS {
            return Err(fault(Rule::Contradiction, "tick.next_tick_ns"));
        }
        Ok(())
    }

    fn short(a: &crate::dispatch::Answer) -> bool {
        a.slot == TICK
            && a.out::<TickOut>()
                .is_ok_and(|o| o.next_tick_ns == plug::SHORT)
    }
}

/// The #85 envelope as the host received it: one line per entry, and the plugin's report gauges
/// (families 2..=5) by family.
#[derive(Default)]
struct Recorder {
    lines: Mutex<Vec<String>>,
    gauges: Mutex<BTreeMap<u32, u32>>,
}
impl EnvelopeSink for Recorder {
    fn metric(&self, m: Metric<'_>) {
        if m.family >= plug::GAUGE_INVOCATIONS {
            self.gauges.lock().unwrap().insert(m.family, m.value as u32);
            return;
        }
        let labels: Vec<String> = m
            .labels
            .iter()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .collect();
        self.lines.lock().unwrap().push(format!(
            "  metric f={} k={} v={} {labels:?}",
            m.family, m.kind, m.value
        ));
    }
    fn diag(&self, d: Diagnostic<'_>) {
        self.lines.lock().unwrap().push(format!(
            "  diag id={} sev={} {}",
            d.id,
            d.severity,
            String::from_utf8_lossy(d.text)
        ));
    }
    fn dropped(&self, why: Dropped) {
        self.lines
            .lock()
            .unwrap()
            .push(format!("  dropped {why:?}"));
    }
}
impl Recorder {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut self.lines.lock().unwrap())
    }
    fn gauge(&self, family: u32) -> u32 {
        self.gauges
            .lock()
            .unwrap()
            .get(&family)
            .copied()
            .unwrap_or(0)
    }
}

fn bind(sink: Arc<Recorder>) -> Bind {
    Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink,
        dispatcher: crate::dispatch::Adopter::unwatched(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    }
}

fn facts() -> ManifestFacts {
    ManifestFacts {
        mechanism_version: MECHANISM_VERSION,
        kind: plug::KIND,
        kind_abi: plug::KIND.abi_version(),
    }
}

fn stated() -> Vec<u8> {
    crate::dispatch::load::rendering_of_raw(plug::busbar_plugin_door)
        .expect("the door renders its Statement")
}

#[test]
fn raw_door_rendering_refuses_null_optional_blob_payloads() {
    static CELL: LinkedSlot = LinkedSlot::new();
    extern "C" fn door() -> *const Door {
        CELL.get()
    }
    for schema in [false, true] {
        let install = |ptr, len| {
            let mut parts = plug::door().parts();
            // SAFETY: the fixture's real door owns a complete static Statement.
            let mut st = unsafe { parts.statement.read_unaligned() };
            let field = if schema {
                &mut st.settings_schema
            } else {
                &mut st.extensions
            };
            *field = Blob {
                ptr,
                len,
                fmt: BLOB_OCTETS,
                flags: 0,
            };
            parts.statement = Box::leak(Box::new(st));

            assert!(crate::dispatch::load::statement(&parts).is_ok());
            // SAFETY: all backing is static or leaked; the malformed NULL blob is never read.
            CELL.set(unsafe { Door::__from_parts(parts) });
        };
        for len in [1, 5] {
            install(std::ptr::null(), len);
            assert!(matches!(
                crate::dispatch::load::rendering_of_raw(door),
                Err(LoadError::Rendering(_))
            ));
        }
        install(std::ptr::null(), 0);
        let empty = crate::dispatch::load::rendering_of_raw(door).unwrap();
        install(b"".as_ptr(), 0);
        assert_eq!(
            crate::dispatch::load::rendering_of_raw(door).unwrap(),
            empty
        );
        busbar_contract::abi::mechanism::rendering::read(&empty).unwrap();
    }
}

#[test]
fn statement_reading_calls_the_door_on_a_permanent_worker() {
    extern "C" fn worker_only_door() -> *const Door {
        if crate::ffi_thread::on_permanent_worker() {
            plug::busbar_plugin_door()
        } else {
            std::ptr::null()
        }
    }
    assert!(!crate::ffi_thread::on_permanent_worker());
    assert!(crate::dispatch::load::statement_of(worker_only_door).is_ok());
    crate::ffi_thread::on_plugin_thread(|| {
        assert!(crate::dispatch::load::statement_of(worker_only_door).is_ok());
    })
    .unwrap();
}

fn stated_with(f: ManifestFacts) -> Vec<u8> {
    let mut b = stated();
    b[8..12].copy_from_slice(&f.mechanism_version.to_le_bytes());
    b[12..16].copy_from_slice(&(f.kind as u32).to_le_bytes());
    b[16..20].copy_from_slice(&f.kind_abi.to_le_bytes());
    b
}

#[test]
fn a_plugin_handle_is_not_clone() {
    trait NotClone<A> {
        fn verdict() -> &'static str {
            "a Plugin is not Clone"
        }
    }
    impl<T: ?Sized> NotClone<()> for T {}
    #[allow(dead_code)]
    struct WhenClone;
    impl<T: Clone> NotClone<WhenClone> for T {}
    assert_eq!(
        <Plugin<TestKind> as NotClone<_>>::verdict(),
        "a Plugin is not Clone"
    );
}

fn row() -> LinkedRow {
    LinkedRow::of_raw(plug::busbar_plugin_door).expect("the linked row states its Statement")
}

fn linked(sink: Arc<Recorder>) -> Plugin<TestKind> {
    load_linked::<TestKind>(&row(), bind(sink)).expect("the linked door loads")
}

pub(crate) fn example_cdylib(name: &str) -> std::path::PathBuf {
    crate::both_ways::example_cdylib(name)
}

fn dropped_path() -> std::path::PathBuf {
    example_cdylib("dispatch_test_plugin")
}

fn dropped(sink: Arc<Recorder>) -> Plugin<TestKind> {
    let path = dropped_path();
    load_dropped::<TestKind>(&path, &stated(), bind(sink)).expect("the dropped door loads")
}

fn frame(mode: &'static [u8]) -> Frame<TickIn, TickOut> {
    let mut head = in_head();
    head.extensions = Blob {
        ptr: mode.as_ptr(),
        len: mode.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    Frame::new(
        TickIn {
            head,
            now_ns: now_ns(),
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 0,
        },
    )
}

fn answer(byte: u8) -> &'static [u8] {
    Box::leak(format!("answer:{byte}").into_bytes().into_boxed_slice())
}

fn arm(t: Ticket) -> &'static [u8] {
    Box::leak(
        format!("arm:{}:{}", t.slot, t.generation)
            .into_bytes()
            .into_boxed_slice(),
    )
}

const TICK: u32 = slot::TICK;

fn text(e: &Option<Vec<u8>>) -> String {
    e.as_ref()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default()
}

fn count<K: Kind>(p: &Plugin<K>, sink: &Recorder) -> (u32, u32, u32) {
    assert_eq!(
        p.call(TICK, &mut frame(plug::COUNT)).outcome,
        Outcome::Ready
    );
    (
        sink.gauge(plug::GAUGE_INVOCATIONS),
        sink.gauge(plug::GAUGE_CANCELS),
        sink.gauge(plug::GAUGE_DRIVES),
    )
}

fn open_frame() -> Frame<OpenIn, OpenOut> {
    Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: NO_BLOB,
            secrets: std::ptr::null(),
            secrets_len: 0,
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    )
}

const WAIT: Duration = Duration::from_secs(10);

fn open(d: &Dispatcher, p: &Plugin<TestKind>, worker: u32) -> Outcome {
    let t = d.mint(worker).expect("a ticket");
    let done = d
        .submit(p, t, slot::OPEN, open_frame(), DeadlineClass::Call, 0)
        .wait(WAIT)
        .expect("open answers");
    d.recycle(t);
    done.outcome
}

fn run_child(test: &str) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().expect("the test binary's path"))
        .args([test, "--test-threads=1", "--nocapture"])
        .env(CHILD_ENV, "1")
        .output()
        .expect("run the child")
}

const CHILD_ENV: &str = "BUSBAR_DISPATCH_CHILD";

pub(crate) fn assert_child_passes(test: &str, what: &str, child: fn()) {
    if std::env::var_os(CHILD_ENV).is_some() {
        child();
        return;
    }
    let out = run_child(test);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{what}: the child ended {:?}\n{stdout}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn until(what: &str, f: impl Fn() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < WAIT, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn config() -> DispatchConfig {
    DispatchConfig {
        workers: 2,
        budgets: Budgets {
            call: Duration::from_millis(400),
            ..Budgets::default()
        },
        watchdog_period: Duration::from_millis(20),
        ..DispatchConfig::default()
    }
}

fn script(load: &dyn Fn(Arc<Recorder>) -> Plugin<TestKind>) -> Vec<String> {
    let sink = Arc::new(Recorder::default());
    let p = load(sink.clone());
    let d = Dispatcher::new(config());
    let mut out = Vec::new();
    let mut say = |line: String, sink: &Recorder| {
        out.push(line);
        out.extend(sink.take());
    };

    say(format!("load max_inflight={}", p.max_inflight()), &sink);
    let mut v = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: NO_BLOB,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    say(
        format!("validate {:?}", p.call(slot::VALIDATE, &mut v).outcome),
        &sink,
    );
    let before = p.call(TICK, &mut frame(answer(1))).outcome;
    say(format!("answer before open {before:?}"), &sink);
    say(
        format!("open {:?} is_open={}", open(&d, &p, 0), p.is_open()),
        &sink,
    );
    say(format!("open again {:?}", open(&d, &p, 0)), &sink);

    for arg in [1, 3, 4, 2, 0] {
        let c = p.call(TICK, &mut frame(answer(arg)));
        say(
            format!("answer {arg} -> {:?} {:?}", c.outcome, text(&c.error)),
            &sink,
        );
    }
    for (name, mode) in [("mismatch", plug::MISMATCH), ("unknown", plug::UNKNOWN)] {
        let c = p.call(TICK, &mut frame(mode));
        say(format!("answer {name} -> {:?}", c.outcome), &sink);
    }

    for (name, mode) in [
        ("after", plug::PEND_AFTER),
        ("before", plug::PEND_BEFORE),
        ("spurious", plug::PEND_SPURIOUS),
        ("stale", plug::PEND_STALE),
        ("timer", plug::PEND_TIMER),
    ] {
        let stale0 = d.stats().stale_wakes;
        let t = d.mint(1).expect("a ticket");
        let done = d
            .submit(
                &p,
                t,
                TICK,
                frame(mode),
                DeadlineClass::Call,
                now_ns() + 5_000_000_000,
            )
            .wait(WAIT)
            .expect("pend answers");
        d.recycle(t);
        let f = done.frame.expect("the frame comes back");
        say(
            format!(
                "pend {name} -> {:?} resume={} invocations={} early={} stale_wakes+{}",
                done.outcome,
                f.input.head.flags,
                sink.gauge(plug::GAUGE_INVOCATIONS),
                sink.gauge(plug::GAUGE_EARLY),
                d.stats().stale_wakes - stale0
            ),
            &sink,
        );
    }

    let t = d.mint(1).expect("a ticket");
    let done = d
        .submit(
            &p,
            t,
            TICK,
            frame(plug::PEND_HOLD),
            DeadlineClass::Call,
            now_ns() + 50_000_000,
        )
        .wait(WAIT)
        .expect("the deadline answers");
    d.recycle(t);
    say(
        format!(
            "deadline -> {:?} cancels={}",
            done.outcome,
            count(&p, &sink).1
        ),
        &sink,
    );
    let t = d.mint(0).expect("a ticket");
    let reply = d.submit(
        &p,
        t,
        TICK,
        frame(plug::PEND_HOLD),
        DeadlineClass::Stream,
        0,
    );
    until("the held op", || d.is_pending(t));
    d.drop_client(t);
    let done = reply.wait(WAIT).expect("the drop answers");
    d.recycle(t);
    say(
        format!(
            "client drop -> {:?} cancels={}",
            done.outcome,
            count(&p, &sink).1
        ),
        &sink,
    );

    let calls0 = count(&p, &sink).0;
    let (a, b, c) = (d.mint(0).unwrap(), d.mint(1).unwrap(), d.mint(0).unwrap());
    let ra = d.submit(&p, a, TICK, frame(plug::PEND_HOLD), DeadlineClass::Call, 0);
    let rb = d.submit(&p, b, TICK, frame(plug::PEND_HOLD), DeadlineClass::Call, 0);
    let rc = d.submit(&p, c, TICK, frame(plug::PEND_HOLD), DeadlineClass::Call, 0);
    let over = rc.wait(WAIT).expect("over the cap answers at once").outcome;
    let none_over = p.call(TICK, &mut frame(plug::COUNT)).outcome;
    until("two held ops", || d.is_pending(a) && d.is_pending(b));
    d.drop_client(a);
    let da = ra.wait(WAIT).expect("a answers").outcome;
    let kick = p.call(TICK, &mut frame(plug::KICK)).outcome;
    let db = rb.wait(WAIT).expect("b answers").outcome;
    for t in [a, b, c] {
        d.recycle(t);
    }
    say(
        format!(
            "max_inflight: third {over:?}, ticket-less {none_over:?}, dropped {da:?}, kick {kick:?}, kicked {db:?}, calls+{}",
            count(&p, &sink).0 - calls0
        ),
        &sink,
    );

    let (cancels0, late0) = (count(&p, &sink).1, d.stats().write_behind_late);
    let w = d.mint(1).expect("a ticket");
    let rw = d.submit(
        &p,
        w,
        TICK,
        frame(plug::PEND_HOLD),
        DeadlineClass::WriteBehind,
        now_ns() + 50_000_000,
    );
    let dw = rw.wait(WAIT).expect("the caller stops waiting");
    d.drop_client(w);
    let drained = d.drain(&p, Duration::from_secs(2));
    let rt = d.mint(0).expect("a ticket");
    let refresh = d
        .submit(
            &p,
            rt,
            slot::REFRESH,
            Frame::new(
                RefreshIn {
                    head: in_head(),
                    generation: 2,
                    settings: NO_BLOB,
                    secrets: std::ptr::null(),
                    secrets_len: 0,
                },
                out_head(),
            ),
            DeadlineClass::Call,
            0,
        )
        .wait(WAIT)
        .expect("refresh answers")
        .outcome;
    d.recycle(rt);
    let kick = p.call(TICK, &mut frame(plug::KICK)).outcome;
    until("the late write-behind", || {
        d.stats().write_behind_late > late0
    });
    d.recycle(w);
    say(
        format!(
            "write_behind -> {:?} detached={} drained={drained} refresh={refresh:?} kick={kick:?} cancels+{} late+{}",
            dw.outcome,
            dw.detached,
            count(&p, &sink).1 - cancels0,
            d.stats().write_behind_late - late0
        ),
        &sink,
    );

    let drv = d.driver(&p, 0).expect("a driver ticket");
    let armed = p.call(TICK, &mut frame(arm(drv))).outcome;

    until("three drives", || count(&p, &sink).2 >= 3);
    say(
        format!(
            "driver armed={armed:?} drives={} inflight={}",
            count(&p, &sink).2,
            p.inflight()
        ),
        &sink,
    );
    d.recycle(drv);

    let held = d.mint(1).expect("a ticket");
    let rh = d.submit(
        &p,
        held,
        TICK,
        frame(plug::PEND_HOLD),
        DeadlineClass::Call,
        0,
    );
    let hung = d.mint(1).expect("a ticket");
    let rg = d.submit(
        &p,
        hung,
        TICK,
        frame(b"hang:script"),
        DeadlineClass::Call,
        0,
    );
    let (dh, dg) = (
        rh.wait(WAIT).expect("held answers"),
        rg.wait(WAIT).expect("hung answers"),
    );
    let after = p.call(TICK, &mut frame(answer(1))).outcome;
    let stale = d
        .submit(
            &p,
            held,
            TICK,
            frame(plug::PEND_HOLD),
            DeadlineClass::Call,
            0,
        )
        .wait(WAIT)
        .expect("a stale ticket answers")
        .outcome;
    let p2 = load(sink.clone());
    let fresh = d.mint(1).expect("the fresh worker mints");
    let fresh_stale = crate::dispatch::handle::ticket_count(
        d.ticket_key(),
        1,
        crate::dispatch::ticket::decode(fresh.slot).1,
        fresh.generation,
    ) > 1;
    d.recycle(fresh);
    let opened2 = open(&d, &p2, 1);
    let unhang = p2.call(TICK, &mut frame(b"unhang:script")).outcome;
    say(
        format!(
            "watchdog: hung={:?} frame={} held={:?} faulted={} after={after:?} stale_ticket={stale:?} inflight={} replaced={} fresh_generation_bumped={fresh_stale} next_instance_open={opened2:?} unhang={unhang:?}",
            dg.outcome,
            dg.frame.is_some(),
            dh.outcome,
            p.is_faulted(),
            p.inflight(),
            d.stats().replacements,
        ),
        &sink,
    );
    let t = d.mint(0).expect("a ticket");
    let closed = d
        .submit(
            &p2,
            t,
            slot::CLOSE,
            Frame::new(in_head(), out_head()),
            DeadlineClass::Call,
            0,
        )
        .wait(WAIT)
        .expect("close answers")
        .outcome;
    d.recycle(t);
    say(format!("close {closed:?} is_open={}", p2.is_open()), &sink);
    out
}

const EXPECTED: &[&str] = &[
    "load max_inflight=2",
    "validate Ready",
    "answer before open Refused",
    "open Ready is_open=true",
    "open again Refused",
    "answer 1 -> Ready \"\"",
    "  metric f=0 k=0 v=1 [\"answer\"]",
    "  dropped FamilyOutOfRange(9)",
    "  dropped NonFinite(1)",
    "  dropped KindMismatch { family: 1, kind: 0 }",
    "  metric f=1 k=1 v=7.5 []",
    "  diag id=0 sev=1 answered",
    "  dropped DiagOutOfRange(5)",
    "answer 3 -> Failed \"answer failed\"",
    "  metric f=0 k=0 v=1 [\"answer\"]",
    "  dropped FamilyOutOfRange(9)",
    "  dropped NonFinite(1)",
    "  dropped KindMismatch { family: 1, kind: 0 }",
    "  metric f=1 k=1 v=7.5 []",
    "  diag id=0 sev=1 answered",
    "  dropped DiagOutOfRange(5)",
    "answer 4 -> Refused \"answer refused\"",
    "  metric f=0 k=0 v=1 [\"answer\"]",
    "  dropped FamilyOutOfRange(9)",
    "  dropped NonFinite(1)",
    "  dropped KindMismatch { family: 1, kind: 0 }",
    "  metric f=1 k=1 v=7.5 []",
    "  diag id=0 sev=1 answered",
    "  dropped DiagOutOfRange(5)",
    "answer 2 -> Fault \"\"",
    "answer 0 -> Fault \"\"",
    "answer mismatch -> Fault",
    "answer unknown -> Fault",
    "pend after -> Ready resume=1 invocations=2 early=0 stale_wakes+0",
    "pend before -> Ready resume=1 invocations=2 early=0 stale_wakes+0",
    "pend spurious -> Ready resume=1 invocations=3 early=1 stale_wakes+0",
    "pend stale -> Ready resume=1 invocations=2 early=0 stale_wakes+2",
    "pend timer -> Ready resume=1 invocations=2 early=0 stale_wakes+0",
    "deadline -> Failed cancels=1",
    "client drop -> Failed cancels=2",
    "max_inflight: third Refused, ticket-less Refused, dropped Failed, kick Ready, kicked Ready, calls+3",
    "write_behind -> Failed detached=true drained=true refresh=Ready kick=Ready cancels+0 late+1",
    "driver armed=Ready drives=3 inflight=0",
    "watchdog: hung=Fault frame=false held=Fault faulted=true after=Fault stale_ticket=Fault inflight=0 replaced=1 fresh_generation_bumped=true next_instance_open=Ready unhang=Ready",
    "close Ready is_open=false",
];

#[test]
fn one_script_linked_and_dropped_is_byte_identical() {
    let linked_run = script(&|s| linked(s));
    let dropped_run = script(&|s| dropped(s));
    assert_eq!(linked_run, dropped_run, "LINKED and DROPPED diverge");
    assert_eq!(
        linked_run, EXPECTED,
        "the transcript is not what the mechanism requires"
    );
}

fn quiet() -> Arc<Recorder> {
    Arc::new(Recorder::default())
}

fn opened(d: &Dispatcher) -> (Plugin<TestKind>, Arc<Recorder>) {
    let sink = quiet();
    let p = linked(sink.clone());
    assert_eq!(open(d, &p, 0), Outcome::Ready);
    (p, sink)
}

#[test]
fn red_an_open_reason_longer_than_the_buffer_lent_is_fault() {
    let p = linked(quiet());
    let mut f = open_frame();
    let settings = b"overlong:open";
    f.input.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let c = p.call(slot::OPEN, &mut f);
    assert_eq!(c.outcome, Outcome::Fault);
    assert_eq!(c.error, None);
    assert!(!p.is_open());
}

/// The C ABI, spelled once for the restated doors below and every other test slot in the crate
/// (`crate::dispatch_tests::c_abi!`): each spelling of its literal is a Law 0 hit (the scan reads
/// it as a secret instance's id).
macro_rules! c_abi {
    ($($(#[$m:meta])* fn $name:ident($($arg:tt: $t:ty),* $(,)?) -> $ret:ty $body:block)*) => {
        $($(#[$m])* extern "C" fn $name($($arg: $t),*) -> $ret $body)*
    };
}
pub(crate) use c_abi;

mod open_faults_on_its_resume {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use busbar_contract::abi::mechanism::call::{DeadlineClass, InHead, Op, Outcome, RawOutcome};
    use busbar_contract::abi::mechanism::door::Door;
    use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpsHead};
    use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket, WakeFn};

    use super::{
        bind, close_frame, config, crossings, frame, open_frame, plug, quiet, until, TestKind,
        TICK, WAIT,
    };
    use crate::dispatch::{load_linked, Dispatcher, LinkedRow};

    static REAL: Mutex<Option<OpsHead>> = Mutex::new(None);
    static SLOT: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());

    static FREED: AtomicUsize = AtomicUsize::new(0);

    static STALE: AtomicU32 = AtomicU32::new(0);

    static WAKE: Mutex<Option<(WakeFn, HostCtx, Ticket)>> = Mutex::new(None);

    fn real() -> OpsHead {
        REAL.lock().unwrap().expect("the door was restated")
    }

    fn freed(instance: *mut c_void) -> bool {
        !instance.is_null() && instance as usize == FREED.load(Ordering::SeqCst)
    }

    c_abi! {
        /// Fresh: the real `open` mints the box, then the op answers PENDING without a wake (the
        /// test wakes it). Resumed on the box: the box is freed and the op answers FAULT.
        fn open(
            instance: *mut c_void,
            input: *const c_void,
            out: *mut c_void,
        ) -> RawOutcome {
            let ops = real();
            if !instance.is_null() {
                let close: Op = ops.close.expect("the test plugin closes");
                // SAFETY: the resumed OPEN still owns its live half-open fixture instance. CLOSE
                // reads/writes only the initialized head prefixes of these exclusive OPEN frames.
                unsafe { close(instance, input, out) };
                FREED.store(instance as usize, Ordering::SeqCst);
                return RawOutcome::of(Outcome::Fault);
            }
            let open: Op = ops.open.expect("the test plugin opens");
            // SAFETY: forward the original first OPEN's instance and complete host frames to
            // their original fixture slot; its input loans remain live for the complete crossing.
            let opened = unsafe { open(instance, input, out) };
            if opened != RawOutcome::of(Outcome::Ready) {
                return opened;
            }
            // SAFETY: the host hands `open` an `OpenIn` (leading with its head) and an `OpenOut`.
            unsafe {
                let ticket = (*input.cast::<InHead>()).ticket;
                let tables = &*(*input.cast::<OpenIn>()).host;
                let wake = tables.wake.expect("the host hands a wake");
                *WAKE.lock().unwrap() = Some((wake, tables.ctx, ticket));
                (*out.cast::<busbar_contract::abi::mechanism::call::OutHead>()).outcome =
                    RawOutcome::of(Outcome::Pending);
            }
            RawOutcome::of(Outcome::Pending)
        }

        /// The real `close`, unless it is handed the freed box.
        fn close(
            instance: *mut c_void,
            input: *const c_void,
            out: *mut c_void,
        ) -> RawOutcome {
            if freed(instance) {
                STALE.fetch_add(1, Ordering::SeqCst);
                return RawOutcome::of(Outcome::Fault);
            }
            // SAFETY: the freed-instance guard passed; these are this live instance's original
            // CLOSE frames, kept initialized and exclusive until the fixture crossing returns.
            unsafe { real().close.expect("the test plugin closes")(instance, input, out) }
        }

        /// The real `tick`, unless it is handed the freed box.
        fn tick(
            instance: *mut c_void,
            input: *const c_void,
            out: *mut c_void,
        ) -> RawOutcome {
            if freed(instance) {
                STALE.fetch_add(1, Ordering::SeqCst);
                return RawOutcome::of(Outcome::Fault);
            }
            // SAFETY: the freed-instance guard passed; forward this live instance's exact TICK
            // frames and their nested loans unchanged through their original fixture slot.
            unsafe { real().tick.expect("the test plugin ticks")(instance, input, out) }
        }

        fn door() -> *const Door {
            let have = SLOT.load(Ordering::SeqCst);
            if !have.is_null() {
                return have;
            }
            // SAFETY: the test plugin's door and its lifecycle table are `'static`.
            let real: Door = unsafe { plug::busbar_plugin_door().read_unaligned() };
            // SAFETY: as above.
            let ops: OpsHead = unsafe { real.ops().read_unaligned() };
            *REAL.lock().unwrap() = Some(ops);
            let ops: &'static OpsHead = Box::leak(Box::new(OpsHead {
                open: Some(open),
                close: Some(close),
                tick: Some(tick),
                ..ops
            }));
            let door = Box::into_raw(Box::new(unsafe { Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts { ops, ..real.parts() }) }));
            SLOT.store(door, Ordering::SeqCst);
            door
        }
    }

    #[test]
    fn red_an_open_that_faults_on_its_resume_leaves_no_instance() {
        let d = Dispatcher::new(config());
        let row = LinkedRow::of_raw(door).expect("the restated door states itself");
        let p = load_linked::<TestKind>(&row, bind(quiet())).expect("it loads");

        let t = d.mint(0).expect("a ticket");
        let reply = d.submit(&p, t, slot::OPEN, open_frame(), DeadlineClass::Call, 0);
        until("the open pends", || d.is_pending(t));

        let open_in_flight = p.is_open();
        let other = d.mint(1).expect("a ticket");
        let ticked_in_flight = d
            .submit(&p, other, TICK, frame(plug::COUNT), DeadlineClass::Call, 0)
            .wait(WAIT)
            .expect("the tick answers")
            .outcome;

        let (wake, ctx, ticket) = WAKE.lock().unwrap().take().expect("the open pended");
        wake(ctx, ticket);
        let opened = reply.wait(WAIT).expect("the open answers");
        assert_eq!(opened.outcome, Outcome::Fault);
        assert_ne!(FREED.load(Ordering::SeqCst), 0, "the resume freed the box");
        d.recycle(t);
        assert!(
            !p.is_open(),
            "an open that FAULTed on its resume is not open"
        );

        let before = crossings(&p);
        let closed = d
            .submit(
                &p,
                other,
                slot::CLOSE,
                close_frame(),
                DeadlineClass::Call,
                0,
            )
            .wait(WAIT)
            .expect("the close answers");
        assert_eq!(closed.outcome, Outcome::Refused, "nothing is open to close");
        let ticked = d
            .submit(&p, other, TICK, frame(plug::COUNT), DeadlineClass::Call, 0)
            .wait(WAIT)
            .expect("the tick answers");
        assert_eq!(ticked.outcome, Outcome::Refused, "nothing is open to tick");
        assert_eq!(
            p.call(slot::CLOSE, &mut close_frame()).outcome,
            Outcome::Refused
        );
        assert_eq!(
            crossings(&p),
            before,
            "nothing crossed after the failed open"
        );
        assert_eq!(
            STALE.load(Ordering::SeqCst),
            0,
            "the freed box never reached the plugin"
        );
        d.recycle(other);
        assert!(!open_in_flight, "an open in flight is not open");
        assert_eq!(
            ticked_in_flight,
            Outcome::Refused,
            "a non-lifecycle op is refused while the open is in flight"
        );
    }
}

mod open_left_live_is_closed {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicPtr, AtomicU32, AtomicU8, Ordering};
    use std::sync::Mutex;

    use busbar_contract::abi::mechanism::call::{DeadlineClass, Op, OutHead, Outcome, RawOutcome};
    use busbar_contract::abi::mechanism::door::Door;
    use busbar_contract::abi::mechanism::lifecycle::{slot, OpsHead};
    use busbar_contract::abi::mechanism::ticket::Ticket;

    use super::{bind, close_frame, config, open_frame, plug, quiet, until, TestKind, WAIT};
    use crate::dispatch::{load_linked, now_ns, Dispatcher, LinkedRow, Plugin};

    static SERIAL: Mutex<()> = Mutex::new(());

    static REAL: Mutex<Option<OpsHead>> = Mutex::new(None);
    static SLOT: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());

    static LIVE: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    static STALE: AtomicU32 = AtomicU32::new(0);

    static MODE: AtomicU8 = AtomicU8::new(PEND);

    const PEND: u8 = 0;

    const MISMATCH: u8 = 1;

    fn real() -> OpsHead {
        REAL.lock().unwrap().expect("the door was restated")
    }

    fn opened_minus_closed() -> usize {
        LIVE.lock().unwrap().len()
    }

    c_abi! {
        /// The real `open` mints a box (counted), then the op answers as [`MODE`] says.
        fn open(
            instance: *mut c_void,
            input: *const c_void,
            out: *mut c_void,
        ) -> RawOutcome {
            // SAFETY: the dispatcher supplied this first OPEN's permitted instance and complete
            // exclusive host frames; forward all still-live loans to their original fixture slot.
            let opened = unsafe { real().open.expect("the test plugin opens")(instance, input, out) };
            if opened != RawOutcome::of(Outcome::Ready) {
                return opened;
            }
            // SAFETY: the host hands `open` an `OpenOut`, leading with its head.
            unsafe {
                let o = &mut *out.cast::<busbar_contract::abi::mechanism::lifecycle::OpenOut>();
                LIVE.lock().unwrap().push(o.instance as usize);
                if MODE.load(Ordering::SeqCst) == MISMATCH {
                    o.head.outcome = RawOutcome::of(Outcome::Failed);
                    return RawOutcome::of(Outcome::Ready);
                }
                o.head.outcome = RawOutcome::of(Outcome::Pending);
            }
            RawOutcome::of(Outcome::Pending)
        }

        /// The real `close` of a live box (counted); any other box is never touched.
        fn close(
            instance: *mut c_void,
            input: *const c_void,
            out: *mut c_void,
        ) -> RawOutcome {
            let mut live = LIVE.lock().unwrap();
            let Some(at) = live.iter().position(|b| *b == instance as usize) else {
                STALE.fetch_add(1, Ordering::SeqCst);
                // SAFETY: the host's `out`, leading with its head.
                unsafe { (*out.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Ready) };
                return RawOutcome::of(Outcome::Ready);
            };
            live.swap_remove(at);
            let close: Op = real().close.expect("the test plugin closes");
            // SAFETY: LIVE admitted this exact fixture instance and retires it only here. Its CLOSE
            // frames remain initialized and exclusive through the original slot's final access.
            unsafe { close(instance, input, out) }
        }

        fn door() -> *const Door {
            let have = SLOT.load(Ordering::SeqCst);
            if !have.is_null() {
                return have;
            }
            // SAFETY: the test plugin's door and its lifecycle table are `'static`.
            let real: Door = unsafe { plug::busbar_plugin_door().read_unaligned() };
            // SAFETY: as above.
            let ops: OpsHead = unsafe { real.ops().read_unaligned() };
            *REAL.lock().unwrap() = Some(ops);
            let ops: &'static OpsHead = Box::leak(Box::new(OpsHead {
                open: Some(open),
                close: Some(close),
                ..ops
            }));
            let door = Box::into_raw(Box::new(unsafe { Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts { ops, ..real.parts() }) }));
            SLOT.store(door, Ordering::SeqCst);
            door
        }
    }

    #[test]
    fn red_an_open_the_host_judged_fault_is_closed_never_leaked() {
        let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let d = Dispatcher::new(config());
        let row = LinkedRow::of_raw(door).expect("the restated door states itself");

        MODE.store(PEND, Ordering::SeqCst);
        let p = load_linked::<TestKind>(&row, bind(quiet())).expect("it loads");
        assert_eq!(
            p.call(slot::OPEN, &mut open_frame()).outcome,
            Outcome::Fault
        );
        assert_eq!(
            opened_minus_closed(),
            0,
            "the host closes the live box of a PENDING it judged FAULT"
        );
        assert!(!p.is_open());
        assert_eq!(
            p.call(slot::CLOSE, &mut close_frame()).outcome,
            Outcome::Refused,
            "nothing is left to close"
        );

        MODE.store(MISMATCH, Ordering::SeqCst);
        let p = load_linked::<TestKind>(&row, bind(quiet())).expect("it loads");
        let t = d.mint(0).expect("a ticket");
        let done = d
            .submit(&p, t, slot::OPEN, open_frame(), DeadlineClass::Call, 0)
            .wait(WAIT)
            .expect("the open answers");
        d.recycle(t);
        assert_eq!(done.outcome, Outcome::Fault);
        assert_eq!(
            opened_minus_closed(),
            0,
            "the host closes the live box of a READY it judged FAULT"
        );
        assert!(!p.is_open());
        assert_eq!(
            p.call(slot::CLOSE, &mut close_frame()).outcome,
            Outcome::Refused,
            "nothing is left to close"
        );
        assert_eq!(STALE.load(Ordering::SeqCst), 0, "no box is closed twice");
    }

    fn pended(d: &Dispatcher) -> (Plugin<TestKind>, Ticket) {
        MODE.store(PEND, Ordering::SeqCst);
        let row = LinkedRow::of_raw(door).expect("the restated door states itself");
        let p = load_linked::<TestKind>(&row, bind(quiet())).expect("it loads");
        let t = d.mint(0).expect("a ticket");
        (p, t)
    }

    #[test]
    fn red_a_cancelled_pended_open_is_closed_once() {
        let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let d = Dispatcher::new(config());

        let (p, t) = pended(&d);
        let deadline = now_ns() + 50_000_000;
        let done = d
            .submit(
                &p,
                t,
                slot::OPEN,
                open_frame(),
                DeadlineClass::Call,
                deadline,
            )
            .wait(WAIT)
            .expect("the cancelled open answers");
        d.recycle(t);
        assert_eq!(done.outcome, Outcome::Failed, "the kind's timeout outcome");
        assert_eq!(
            opened_minus_closed(),
            0,
            "the host closes the half-open box of an open it cancelled at its deadline"
        );
        assert!(!p.is_open());

        let (p, t) = pended(&d);
        let reply = d.submit(&p, t, slot::OPEN, open_frame(), DeadlineClass::Call, 0);
        until("the open pends", || d.is_pending(t));
        d.drop_client(t);
        let done = reply.wait(WAIT).expect("the dropped open answers");
        d.recycle(t);
        assert_eq!(done.outcome, Outcome::Failed, "the kind's timeout outcome");
        assert_eq!(
            opened_minus_closed(),
            0,
            "the host closes the half-open box of an open whose client went away"
        );
        assert!(!p.is_open());
        assert_eq!(STALE.load(Ordering::SeqCst), 0, "no box is closed twice");
    }

    #[test]
    fn red_a_late_close_after_the_auto_close_is_refused_never_double_freed() {
        let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let d = Dispatcher::new(config());
        let (p, t) = pended(&d);
        let deadline = now_ns() + 50_000_000;
        let done = d
            .submit(
                &p,
                t,
                slot::OPEN,
                open_frame(),
                DeadlineClass::Call,
                deadline,
            )
            .wait(WAIT)
            .expect("the cancelled open answers");
        d.recycle(t);
        assert_eq!(done.outcome, Outcome::Failed);
        let stale = STALE.load(Ordering::SeqCst);

        let t = d.mint(1).expect("a ticket");
        let closed = d
            .submit(&p, t, slot::CLOSE, close_frame(), DeadlineClass::Call, 0)
            .wait(WAIT)
            .expect("the close answers");
        d.recycle(t);
        assert_eq!(
            closed.outcome,
            Outcome::Refused,
            "the host already closed the box"
        );
        assert_eq!(
            p.call(slot::CLOSE, &mut close_frame()).outcome,
            Outcome::Refused
        );
        assert_eq!(
            STALE.load(Ordering::SeqCst),
            stale,
            "the box is never closed twice"
        );
        assert_eq!(opened_minus_closed(), 0);
        assert!(!p.is_open());
    }
}

#[test]
fn red_outcome_mismatch_unknown_byte_and_pending_on_none_are_fault() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    for mode in [
        plug::MISMATCH,
        plug::UNKNOWN,
        answer(2),
        answer(0),
        answer(5),
    ] {
        let c = p.call(TICK, &mut frame(mode));
        assert_eq!(
            c.outcome,
            Outcome::Fault,
            "{}",
            String::from_utf8_lossy(mode)
        );
    }

    assert_eq!(p.call(TICK, &mut frame(answer(1))).outcome, Outcome::Ready);
}

#[test]
fn red_over_max_inflight_is_refused_without_a_call() {
    let d = Dispatcher::new(config());
    let (p, sink) = opened(&d);
    let calls0 = count(&p, &sink).0;
    let (a, b, c) = (d.mint(0).unwrap(), d.mint(0).unwrap(), d.mint(1).unwrap());
    let ra = d.submit(&p, a, TICK, frame(plug::PEND_HOLD), DeadlineClass::Call, 0);
    let rb = d.submit(&p, b, TICK, frame(plug::PEND_HOLD), DeadlineClass::Call, 0);
    let rc = d.submit(&p, c, TICK, frame(plug::PEND_HOLD), DeadlineClass::Call, 0);
    assert_eq!(rc.wait(WAIT).unwrap().outcome, Outcome::Refused);
    until("two held ops", || d.is_pending(a) && d.is_pending(b));
    d.drop_client(a);
    assert_eq!(ra.wait(WAIT).unwrap().outcome, Outcome::Failed);
    assert_eq!(p.call(TICK, &mut frame(plug::KICK)).outcome, Outcome::Ready);
    assert_eq!(rb.wait(WAIT).unwrap().outcome, Outcome::Ready);
    assert_eq!(
        count(&p, &sink).0 - calls0,
        3,
        "the refused op was never called"
    );
    assert_eq!(p.inflight(), 0);
}

#[test]
fn red_a_stale_generation_wake_is_dropped() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    let old = d.mint(0).unwrap();
    d.recycle(old);

    let t = loop {
        let t = d.mint(0).unwrap();
        if t.slot == old.slot {
            break t;
        }
    };

    let idx = crate::dispatch::ticket::decode(t.slot).1;
    assert_eq!(
        crate::dispatch::handle::ticket_count(d.ticket_key(), 0, idx, t.generation),
        crate::dispatch::handle::ticket_count(d.ticket_key(), 0, idx, old.generation) + 1
    );
    assert_ne!(t.generation, old.generation);
    let reply = d.submit(&p, t, TICK, frame(plug::PEND_HOLD), DeadlineClass::Call, 0);
    until("the held op", || d.is_pending(t));
    let stale0 = d.stats().stale_wakes;
    let crossings0 = p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst);

    crate::dispatch::plugin::with_crossing(Some(&*p.inner), || {
        crate::dispatch::ticket::host_wake(p.inner.ctx(), old);
    });
    until("the stale wake is counted", || {
        d.stats().stale_wakes > stale0
    });

    assert!(
        !p.is_faulted(),
        "a stale wake for a generation the host minted was judged a forgery"
    );

    assert_eq!(
        p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst),
        crossings0,
        "a stale wake resumed an op"
    );
    d.drop_client(t);
    assert_eq!(reply.wait(WAIT).unwrap().outcome, Outcome::Failed);
}

#[test]
fn red_a_reload_drain_does_not_wait_on_a_pending_write_behind() {
    let d = Dispatcher::new(config());
    let (p, sink) = opened(&d);
    let w = d.mint(0).unwrap();
    let rw = d.submit(
        &p,
        w,
        TICK,
        frame(plug::PEND_HOLD),
        DeadlineClass::WriteBehind,
        0,
    );
    until("the write-behind pends", || d.is_pending(w));
    d.drop_client(w);
    assert!(
        d.drain(&p, Duration::from_secs(1)),
        "the drain waited on a WriteBehind op"
    );

    let t = d.mint(1).unwrap();
    let rt = d.submit(&p, t, TICK, frame(plug::PEND_HOLD), DeadlineClass::Call, 0);
    until("the call pends", || d.is_pending(t));
    assert!(
        !d.drain(&p, Duration::from_millis(100)),
        "a pending Call op must hold the drain"
    );

    d.drop_client(t);
    assert_eq!(rt.wait(WAIT).unwrap().outcome, Outcome::Failed);
    assert!(d.drain(&p, Duration::from_secs(1)));
    assert_eq!(p.call(TICK, &mut frame(plug::KICK)).outcome, Outcome::Ready);
    assert_eq!(
        rw.wait(WAIT).unwrap().outcome,
        Outcome::Ready,
        "the write-behind was never cancelled"
    );
    assert_eq!(count(&p, &sink).1, 1, "one cancel: the Call op's");
}

#[test]
fn red_every_door_refusal() {
    // SAFETY: the real door is `'static`.
    let real: Door = unsafe { *plug::busbar_plugin_door() };
    let ops: OpsHead = unsafe { *real.ops() };
    let st = unsafe { *real.statement() };
    let leak_ops = |o: OpsHead| Box::leak(Box::new(o)) as *const OpsHead;
    let with = |f: &dyn Fn(&mut DoorParts)| {
        let mut d = real.parts();
        f(&mut d);
        // SAFETY: a copy of the real door with one field wrong, which the loader reads only
        // through its checks (the refusal under test).
        validate_door::<TestKind>(Box::leak(Box::new(unsafe { Door::__from_parts(d) }))).err()
    };
    assert!(validate_door::<TestKind>(&real).is_ok(), "the GREEN twin");
    assert_eq!(
        validate_door::<TestKind>(std::ptr::null()).err(),
        Some(LoadError::NullDoor)
    );
    assert_eq!(
        with(&|d| d.magic = u64::from_le_bytes(*b"BUSPLANE")),
        Some(LoadError::Magic(u64::from_le_bytes(*b"BUSPLANE")))
    );
    assert_ne!(DOOR_MAGIC, u64::from_le_bytes(*b"BUSPLANE"));
    for v in [MECHANISM_VERSION - 1, MECHANISM_VERSION + 1] {
        assert_eq!(
            with(&|d| d.mechanism_version = v),
            Some(LoadError::Mechanism {
                door: v,
                host: MECHANISM_VERSION
            })
        );
    }
    let abi = plug::KIND.abi_version();
    for v in [abi - 1, abi + 1] {
        assert_eq!(
            with(&|d| d.kind_abi = v),
            Some(LoadError::KindAbi {
                kind: plug::KIND,
                door: v,
                host: abi
            })
        );
    }
    assert_eq!(with(&|d| d.kind = 99), Some(LoadError::UnknownKind(99)));
    let other_kind = *KindCode::ALL.iter().find(|k| **k != plug::KIND).unwrap();
    assert_eq!(
        with(&|d| d.kind = other_kind as u32),
        Some(LoadError::WrongKind {
            door: other_kind,
            want: plug::KIND
        })
    );
    assert!(matches!(
        with(&|d| d.size = 8),
        Some(LoadError::DoorSize { .. })
    ));
    assert_eq!(
        with(&|d| d.ops = std::ptr::null()),
        Some(LoadError::NullOps)
    );
    for n in [LIFECYCLE_SLOTS - 1, LIFECYCLE_SLOTS + 1] {
        let p = leak_ops(OpsHead { slots: n, ..ops });
        assert_eq!(
            with(&|d| d.ops = p),
            Some(LoadError::TableSlots {
                door: n,
                host: LIFECYCLE_SLOTS
            })
        );
    }
    let p = leak_ops(OpsHead {
        size: ops.size + 8,
        ..ops
    });
    assert!(matches!(
        with(&|d| d.ops = p),
        Some(LoadError::TableSize { .. })
    ));
    let p = leak_ops(OpsHead {
        cancel: None,
        ..ops
    });
    assert_eq!(
        with(&|d| d.ops = p),
        Some(LoadError::NullSlot(slot::CANCEL))
    );
    let p = leak_ops(OpsHead { close: None, ..ops });
    assert_eq!(with(&|d| d.ops = p), Some(LoadError::NullSlot(slot::CLOSE)));
    assert_eq!(
        with(&|d| d.statement = std::ptr::null()),
        Some(LoadError::NullStatement)
    );
    let other = Box::leak(Box::new(Statement {
        kind_abi: abi + 1,
        ..st
    }));
    assert_eq!(
        with(&|d| d.statement = other),
        Some(LoadError::StatementDisagrees("kind_abi"))
    );
    let tail = Box::leak(Box::new(KindTailHead {
        size: 4,
        _reserved: 0,
    }));
    let short = Box::leak(Box::new(Statement {
        kind_tail: tail,
        ..st
    }));
    assert!(matches!(
        with(&|d| d.statement = short),
        Some(LoadError::KindTail(_))
    ));
    let tail = Box::leak(Box::new(KindTailHead {
        size: 8,
        _reserved: 0,
    }));
    let fine = Box::leak(Box::new(Statement {
        kind_tail: tail,
        ..st
    }));
    assert!(
        with(&|d| d.statement = fine).is_none(),
        "a well-formed kind tail loads"
    );

    let unknown_mark = Box::leak(Box::new(Statement {
        marks: 1 << 20,
        ..st
    }));
    assert_eq!(
        with(&|d| d.statement = unknown_mark),
        Some(LoadError::BadStatement(
            "statement.marks breaks UnknownCode".into()
        ))
    );
    let null_needs = Box::leak(Box::new(Statement { needs_len: 1, ..st }));
    assert_eq!(
        with(&|d| d.statement = null_needs),
        Some(LoadError::BadStatement(
            "statement.needs breaks NullWithCount".into()
        ))
    );
    let rewrite: &'static [busbar_contract::abi::mechanism::door::Rewrite] =
        Box::leak(Box::new([busbar_contract::abi::mechanism::door::Rewrite {
            class: 9,
            _reserved: 0,
            from: busbar_contract::abi::sdk::door::abi_str("x"),
            to: busbar_contract::abi::sdk::door::abi_str(""),
        }]));
    let bad_rewrite = Box::leak(Box::new(Statement {
        rewrites: rewrite.as_ptr(),
        rewrites_len: 1,
        ..st
    }));
    assert_eq!(
        with(&|d| d.statement = bad_rewrite),
        Some(LoadError::BadStatement(
            "rewrite.class breaks UnknownCode".into()
        ))
    );
    let marked = Box::leak(Box::new(Statement {
        marks: busbar_contract::abi::mechanism::door::MARK_ONE_INSTANCE,
        ..st
    }));
    assert!(
        with(&|d| d.statement = marked).is_none(),
        "a known mark loads"
    );
}

pub(crate) extern "C" fn null_door() -> *const Door {
    std::ptr::null()
}

#[test]
fn red_both_origins_refuse_the_same_way() {
    let null_row = LinkedRow {
        statement: stated(),
        door: null_door,
    };
    assert_eq!(
        load_linked::<TestKind>(&null_row, bind(quiet())).err(),
        Some(LoadError::NullDoor)
    );
    assert_eq!(
        LinkedRow::of_raw(null_door).err(),
        Some(LoadError::NullDoor)
    );

    let nowhere = std::path::Path::new("/nonexistent/libnothing.so");
    for v in [MECHANISM_VERSION - 1, MECHANISM_VERSION + 1] {
        let f = ManifestFacts {
            mechanism_version: v,
            ..facts()
        };
        assert_eq!(
            load_dropped::<TestKind>(nowhere, &stated_with(f), bind(quiet())).err(),
            Some(LoadError::ManifestMechanism {
                stated: v,
                host: MECHANISM_VERSION
            })
        );
    }
    let f = ManifestFacts {
        kind_abi: plug::KIND.abi_version() + 1,
        ..facts()
    };
    assert!(matches!(
        load_dropped::<TestKind>(nowhere, &stated_with(f), bind(quiet())).err(),
        Some(LoadError::ManifestKindAbi { .. })
    ));
    let other = *KindCode::ALL.iter().find(|k| **k != plug::KIND).unwrap();
    let f = ManifestFacts {
        kind: other,
        ..facts()
    };
    assert_eq!(
        load_dropped::<TestKind>(nowhere, &stated_with(f), bind(quiet())).err(),
        Some(LoadError::ManifestKind {
            stated: other,
            want: plug::KIND
        })
    );
    assert!(matches!(
        load_dropped::<TestKind>(nowhere, &stated(), bind(quiet())).err(),
        Some(LoadError::Open(_))
    ));

    assert!(matches!(
        load_dropped::<TestKind>(nowhere, b"{}", bind(quiet())).err(),
        Some(LoadError::Rendering(_))
    ));

    #[cfg(target_os = "macos")]
    let libc = "/usr/lib/libSystem.B.dylib";
    #[cfg(all(unix, not(target_os = "macos")))]
    let libc = "libc.so.6";
    #[cfg(unix)]
    assert!(matches!(
        load_dropped::<TestKind>(std::path::Path::new(libc), &stated(), bind(quiet())).err(),
        Some(LoadError::NoDoor(_))
    ));
}

#[test]
fn red_a_statement_other_than_the_stated_one_is_refused_at_admit() {
    assert_eq!(facts(), ManifestFacts::read(&stated()).unwrap());
    let mut lying = stated();
    let max_inflight_at = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len()
        + 3 * std::mem::size_of::<u32>();
    lying[max_inflight_at] ^= 1;
    let lying_row = LinkedRow {
        statement: lying.clone(),
        door: plug::busbar_plugin_door,
    };
    assert_eq!(
        load_linked::<TestKind>(&lying_row, bind(quiet())).err(),
        Some(LoadError::StatementMismatch)
    );
    let mut short = stated();
    short.pop();
    let short_row = LinkedRow {
        statement: short,
        door: plug::busbar_plugin_door,
    };
    assert!(matches!(
        load_linked::<TestKind>(&short_row, bind(quiet())).err(),
        Some(LoadError::Rendering(_))
    ));
    assert!(load_linked::<TestKind>(&row(), bind(quiet())).is_ok());
    let path = dropped_path();
    assert_eq!(
        load_dropped::<TestKind>(&path, &lying, bind(quiet())).err(),
        Some(LoadError::StatementMismatch)
    );
    assert!(load_dropped::<TestKind>(&path, &stated(), bind(quiet())).is_ok());
}

#[test]
fn malformed_or_obsolete_manifest_facts_are_refused_before_any_door_or_library_opens() {
    use busbar_contract::abi::mechanism::rendering::{
        RENDERING_MAGIC, RENDERING_MAGIC_TAIL_SIZE_ONLY, RENDERING_MAGIC_WITHOUT_NEED_RETENTION,
    };
    static ENTERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    extern "C" fn must_not_enter() -> *const Door {
        ENTERED.store(true, std::sync::atomic::Ordering::SeqCst);
        plug::busbar_plugin_door()
    }
    let control = stated();
    assert!(ManifestFacts::read(&control).is_ok());
    let mut malformed = Vec::new();
    for cut in 0..control.len() {
        malformed.push(control[..cut].to_vec());
    }

    {
        use busbar_contract::abi::host::conn::connector::{KEEP_ALL_EXCEPT_DENIED, KEEP_NAMED};
        use busbar_contract::abi::sdk::door::{abi_str, statement};
        const NAME: &str = "x-admission-count-control";
        const NAMES: &[busbar_contract::abi::mechanism::call::AbiStr] = &[abi_str(NAME)];
        for mode in [KEEP_NAMED, KEEP_ALL_EXCEPT_DENIED] {
            let mut need = crate::needs_restated::need(abi_str("tcp"));
            need.keep_mode = mode;
            let need = if mode == KEEP_NAMED {
                need.with_keep_response_headers(NAMES)
            } else {
                need.with_deny_response_headers(NAMES)
            };
            let st = Statement {
                kind: plug::KIND as u32,
                kind_abi: plug::KIND.abi_version(),
                needs: &need,
                needs_len: 1,
                ..statement("retention-count", "1", 1)
            };
            // SAFETY: the Statement and its Need live for rendering, with static names.
            let mut huge =
                unsafe { busbar_contract::abi::mechanism::rendering::render(&st) }.unwrap();
            assert!(ManifestFacts::read(&huge).is_ok());
            let name_at = huge
                .windows(NAME.len())
                .position(|b| b == NAME.as_bytes())
                .unwrap();
            let count_at = name_at - 2 * std::mem::size_of::<u32>();
            huge[count_at..count_at + std::mem::size_of::<u32>()]
                .copy_from_slice(&u32::MAX.to_le_bytes());
            malformed.push(huge);
        }
    }
    for magic in [
        RENDERING_MAGIC_TAIL_SIZE_ONLY,
        RENDERING_MAGIC_WITHOUT_NEED_RETENTION,
    ] {
        let mut old = control.clone();
        old[..magic.len()].copy_from_slice(magic);
        let Some(LoadError::Rendering(why)) = ManifestFacts::read(&old).err() else {
            panic!("old renderings must refuse before admission");
        };
        assert!(why.contains("repack the plugin"));
        malformed.push(old);
    }
    let mut padded = control.clone();
    padded.push(0);
    malformed.push(padded);
    let mut foreign = control.clone();
    foreign[..RENDERING_MAGIC.len()].fill(0);
    malformed.push(foreign);
    for statement in malformed {
        assert!(matches!(
            ManifestFacts::read(&statement),
            Err(LoadError::Rendering(_))
        ));
        assert!(matches!(
            load_dropped::<TestKind>(
                std::path::Path::new("/nonexistent/libnothing.so"),
                &statement,
                bind(quiet())
            ),
            Err(LoadError::Rendering(_))
        ));
        let row = LinkedRow {
            statement,
            door: must_not_enter,
        };
        assert!(matches!(
            load_linked::<TestKind>(&row, bind(quiet())),
            Err(LoadError::Rendering(_))
        ));
        assert!(!ENTERED.load(std::sync::atomic::Ordering::SeqCst));
    }
}

#[test]
fn the_pack_time_rendering_of_a_library_is_its_door_s() {
    assert_eq!(
        crate::dispatch::rendering_of_library(&dropped_path()).unwrap(),
        Some(stated())
    );
    #[cfg(target_os = "macos")]
    let libc = "/usr/lib/libSystem.B.dylib";
    #[cfg(all(unix, not(target_os = "macos")))]
    let libc = "libc.so.6";
    #[cfg(unix)]
    assert_eq!(
        crate::dispatch::rendering_of_library(std::path::Path::new(libc)).unwrap(),
        None
    );
}

fn panic_child(origin: &str) {
    let p = if origin == "dropped" {
        dropped(quiet())
    } else {
        linked(quiet())
    };
    let d = Dispatcher::new(config());
    assert_eq!(open(&d, &p, 0), Outcome::Ready);
    let _ = p.call(TICK, &mut frame(plug::PANIC));

    std::process::exit(0);
}

#[test]
fn red_a_panic_in_a_hand_written_slot_aborts() {
    if let Ok(origin) = std::env::var("BUSBAR_M1_PANIC_CHILD") {
        panic_child(&origin);
    }

    dropped_path();
    for origin in ["linked", "dropped"] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "dispatch_tests::red_a_panic_in_a_hand_written_slot_aborts",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("BUSBAR_M1_PANIC_CHILD", origin)
            .output()
            .expect("run the child")
            .status;
        assert!(
            !status.success(),
            "{origin}: the child survived a panic across extern \"C\""
        );
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                status.signal(),
                Some(libc::SIGABRT),
                "{origin}: not an abort: {status:?}"
            );
        }
    }
}

#[test]
fn outhead_is_prefilled_as_fault() {
    let h: OutHead = out_head();
    assert_eq!(h.outcome.outcome(), Outcome::Fault);
}

#[test]
fn red_an_answer_that_fails_validation_is_fault() {
    let d = Dispatcher::new(config());
    let (p, sink) = opened(&d);
    for mode in [plug::OVERSIZE, plug::BAD_TEXT, plug::BAD_ENVELOPE] {
        let c = p.call(TICK, &mut frame(mode));
        assert_eq!(
            c.outcome,
            Outcome::Fault,
            "{}",
            String::from_utf8_lossy(mode)
        );
        assert_eq!(c.error, None, "nothing is read through a rejected answer");
    }
    assert!(
        sink.take().is_empty(),
        "no envelope is ingested from a rejected answer"
    );
}

#[test]
fn red_the_kinds_validator_refuses_an_answer_as_fault() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    assert_eq!(
        p.call(TICK, &mut frame(plug::REJECTED)).outcome,
        Outcome::Fault
    );

    assert_eq!(p.call(TICK, &mut frame(answer(1))).outcome, Outcome::Ready);
}

#[test]
fn red_one_recall_a_second_short_answer_is_fault() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    let t = d.mint(0).unwrap();
    let ask = |mode| {
        d.submit(&p, t, TICK, frame(mode), DeadlineClass::Call, 0)
            .wait(WAIT)
            .unwrap()
            .outcome
    };
    assert_eq!(
        ask(plug::SHORT_ANSWER),
        Outcome::Failed,
        "the first short answer earns one re-call"
    );
    assert_eq!(
        ask(plug::SHORT_ANSWER),
        Outcome::Fault,
        "short again on the re-call is FAULT"
    );
    assert_eq!(
        ask(plug::SHORT_ANSWER),
        Outcome::Failed,
        "a fresh op may be short once more"
    );
    assert_eq!(
        ask(answer(1)),
        Outcome::Ready,
        "the re-call that fits is READY"
    );
    d.recycle(t);
}

fn door_with(f: impl Fn(&mut DoorParts)) -> Option<LoadError> {
    let mut d = plug::door().parts();
    f(&mut d);
    // SAFETY: a copy of the real door with one field wrong, which the loader reads only through
    // its checks (the refusal under test).
    validate_door::<TestKind>(Box::leak(Box::new(unsafe { Door::__from_parts(d) }))).err()
}

#[test]
fn red_refuses_an_older_door() {
    let (m, k) = (MECHANISM_VERSION, plug::KIND.abi_version());
    assert_eq!(
        door_with(|d| d.mechanism_version = m - 1),
        Some(LoadError::Mechanism {
            door: m - 1,
            host: m
        })
    );
    assert_eq!(
        door_with(|d| d.kind_abi = k - 1),
        Some(LoadError::KindAbi {
            kind: plug::KIND,
            door: k - 1,
            host: k
        })
    );
}

#[test]
fn red_refuses_a_newer_door() {
    let (m, k) = (MECHANISM_VERSION, plug::KIND.abi_version());
    assert_eq!(
        door_with(|d| d.mechanism_version = m + 1),
        Some(LoadError::Mechanism {
            door: m + 1,
            host: m
        })
    );
    assert_eq!(
        door_with(|d| d.kind_abi = k + 1),
        Some(LoadError::KindAbi {
            kind: plug::KIND,
            door: k + 1,
            host: k
        })
    );
}

#[test]
fn red_refuses_a_wrong_magic() {
    let retired = u64::from_le_bytes(*b"BUSPLANE");
    assert_eq!(
        door_with(|d| d.magic = retired),
        Some(LoadError::Magic(retired))
    );
    assert_eq!(
        door_with(|_| {}),
        None,
        "the GREEN twin: the real door loads"
    );
}

fn crossings(p: &Plugin<TestKind>) -> u64 {
    p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst)
}

fn close_frame() -> Frame<busbar_contract::abi::mechanism::call::InHead, OutHead> {
    Frame::new(in_head(), out_head())
}

#[test]
fn red_close_is_refused_while_an_op_is_in_flight() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    let t = d.mint(0).unwrap();
    let held = d.submit(&p, t, TICK, frame(plug::PEND_HOLD), DeadlineClass::Call, 0);
    until("the held op", || d.is_pending(t));
    let n = crossings(&p);
    assert_eq!(
        p.call(slot::CLOSE, &mut close_frame()).outcome,
        Outcome::Refused
    );
    let c = d.mint(1).unwrap();
    let ticketed = d.submit(&p, c, slot::CLOSE, close_frame(), DeadlineClass::Call, 0);
    assert_eq!(ticketed.wait(WAIT).unwrap().outcome, Outcome::Refused);
    assert_eq!(crossings(&p), n, "a refused close never crossed");
    assert!(p.is_open());

    d.drop_client(t);
    assert_eq!(held.wait(WAIT).unwrap().outcome, Outcome::Failed);
    assert_eq!(
        p.call(slot::CLOSE, &mut close_frame()).outcome,
        Outcome::Ready
    );
    assert!(!p.is_open());
}

#[test]
fn red_after_close_a_late_wake_and_every_op_fault_without_crossing() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    let drv = d.driver(&p, 0).unwrap();
    assert_eq!(
        p.call(slot::CLOSE, &mut close_frame()).outcome,
        Outcome::Ready
    );
    let n = crossings(&p);

    crate::dispatch::ticket::host_wake(p.inner.ctx(), drv);
    let t = d.mint(0).unwrap();
    let after = d.submit(&p, t, TICK, frame(answer(1)), DeadlineClass::Call, 0);
    assert_eq!(after.wait(WAIT).unwrap().outcome, Outcome::Fault);
    assert_eq!(p.call(TICK, &mut frame(answer(1))).outcome, Outcome::Fault);
    assert_eq!(crossings(&p), n, "nothing crossed into a closed instance");
}

#[test]
fn red_a_close_that_faults_leaves_the_instance_closed() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    assert_eq!(
        p.call(TICK, &mut frame(plug::CLOSE_FAULTS)).outcome,
        Outcome::Ready
    );
    assert_eq!(
        p.call(slot::CLOSE, &mut close_frame()).outcome,
        Outcome::Fault
    );
    assert!(!p.is_open(), "a faulted close leaves no instance pointer");
    let n = crossings(&p);
    assert_eq!(p.call(TICK, &mut frame(answer(1))).outcome, Outcome::Fault);
    assert_eq!(
        p.call(slot::CLOSE, &mut close_frame()).outcome,
        Outcome::Fault
    );
    assert_eq!(crossings(&p), n, "nothing crossed into the freed instance");
}

#[test]
fn red_text_is_capped_before_any_slice_is_made() {
    use crate::dispatch::plugin::{str_bytes, MAX_TEXT};
    use busbar_contract::abi::mechanism::call::AbiStr;
    let bytes = b"x";
    let huge = AbiStr {
        ptr: bytes.as_ptr(),
        len: isize::MAX as usize + 1,
    };
    assert_eq!(str_bytes(huge), None, "no slice of isize::MAX + 1 bytes");
    let over = AbiStr {
        ptr: bytes.as_ptr(),
        len: MAX_TEXT + 1,
    };
    assert_eq!(str_bytes(over), None);
    let null = AbiStr {
        ptr: std::ptr::null(),
        len: 3,
    };
    assert_eq!(str_bytes(null), None);
    assert_eq!(
        str_bytes(AbiStr {
            ptr: bytes.as_ptr(),
            len: 1
        }),
        Some(&b"x"[..])
    );

    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    let c = p.call(TICK, &mut frame(plug::HUGE_TEXT));
    assert_eq!((c.outcome, c.error), (Outcome::Fault, None));
}

#[test]
fn red_a_hung_ticketless_call_faults_its_instance() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    let (p2, _s2) = opened(&d);

    let p = Arc::new(p);
    let hung = Arc::clone(&p);
    let caller =
        std::thread::spawn(move || hung.call(TICK, &mut frame(b"hang:ticketless")).outcome);
    until("the watchdog faults the instance", || p.is_faulted());
    assert!(!p2.is_faulted(), "only the hung instance");
    assert_eq!(
        d.stats().quarantined,
        1,
        "bb_plugin_quarantined_total counts the quarantine (the default N is the first breach)"
    );
    assert_eq!(p.call(TICK, &mut frame(answer(1))).outcome, Outcome::Fault);
    assert_eq!(
        p2.call(TICK, &mut frame(b"unhang:ticketless")).outcome,
        Outcome::Ready
    );
    caller.join().unwrap();
}

#[test]
fn an_older_ticketless_call_is_counted_when_its_longer_budget_expires() {
    let d = Dispatcher::new(DispatchConfig {
        quarantine_after: 2,
        ..config()
    });
    let (p, _) = opened(&d);
    let (release, _) = opened(&d);
    let p = Arc::new(p);
    let long = Arc::clone(&p);
    let first = std::thread::spawn(move || {
        let settings = b"hang:older-watch-budget";
        let mut f = Frame::new(
            ValidateIn {
                head: in_head(),
                settings: Blob {
                    ptr: settings.as_ptr(),
                    len: settings.len(),
                    fmt: BLOB_OCTETS,
                    flags: 0,
                },
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            out_head(),
        );
        long.call(slot::VALIDATE, &mut f).outcome
    });
    until("the earlier validation crossing", || {
        p.inner.lock_calls().len() == 1
    });
    let older = *p.inner.lock_calls().keys().next().unwrap();
    let short = Arc::clone(&p);
    let second = std::thread::spawn(move || {
        short
            .call(TICK, &mut frame(b"hang:newer-watch-budget"))
            .outcome
    });
    until("both ticketless crossings", || {
        p.inner.lock_calls().len() == 2
    });
    {
        let mut calls = p.inner.lock_calls();
        let newer = *calls.keys().find(|&&id| id != older).unwrap();
        calls.get_mut(&newer).unwrap().0 = Instant::now() - Duration::from_secs(1);
    }
    let deadline = Instant::now() + WAIT;
    while p.inner.breaches.load(std::sync::atomic::Ordering::Acquire) == 0
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(2));
    }
    let first_count = p.inner.breaches.load(std::sync::atomic::Ordering::Acquire);
    p.inner.lock_calls().get_mut(&older).unwrap().0 = Instant::now() - Duration::from_secs(60);
    let deadline = Instant::now() + WAIT;
    while !p.is_faulted() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    let counted = p.inner.breaches.load(std::sync::atomic::Ordering::Acquire);
    let faulted = p.is_faulted();

    release.call(TICK, &mut frame(b"unhang:older-watch-budget"));
    release.call(TICK, &mut frame(b"unhang:newer-watch-budget"));
    first.join().unwrap();
    second.join().unwrap();
    assert_eq!(first_count, 1, "the later short-budget call breaches first");
    assert_eq!(counted, 2, "the earlier call still owns its later breach");
    assert!(faulted, "the two distinct breaches quarantine the instance");
}

#[test]
fn red_an_instance_is_quarantined_on_its_nth_breach_and_not_before() {
    let d = Dispatcher::new(DispatchConfig {
        quarantine_after: 2,
        ..config()
    });
    let (p, _sink) = opened(&d);
    let p = Arc::new(p);
    let (p2, _s2) = opened(&d);
    let breaches = || p.inner.breaches.load(std::sync::atomic::Ordering::SeqCst);

    let hung = Arc::clone(&p);
    let first =
        std::thread::spawn(move || hung.call(TICK, &mut frame(b"hang:quarantine-n-1")).outcome);
    until("the watchdog counts the first breach", || breaches() == 1);

    std::thread::sleep(Duration::from_millis(120));
    assert_eq!(breaches(), 1, "a hung call is one breach, not one per scan");
    assert!(!p.is_faulted(), "one breach of two quarantines nothing");
    assert_eq!(d.stats().quarantined, 0);
    assert_eq!(
        p2.call(TICK, &mut frame(b"unhang:quarantine-n-1")).outcome,
        Outcome::Ready
    );
    first.join().unwrap();
    assert_eq!(
        p.call(TICK, &mut frame(answer(1))).outcome,
        Outcome::Ready,
        "below N the instance keeps serving"
    );

    let hung = Arc::clone(&p);
    let second =
        std::thread::spawn(move || hung.call(TICK, &mut frame(b"hang:quarantine-n-2")).outcome);
    until("the second breach quarantines the instance", || {
        p.is_faulted()
    });
    assert_eq!(breaches(), 2);
    assert_eq!(d.stats().quarantined, 1, "bb_plugin_quarantined_total");
    assert_eq!(p.call(TICK, &mut frame(answer(1))).outcome, Outcome::Fault);
    assert!(!p2.is_faulted(), "only the breaching instance");
    assert_eq!(
        p2.call(TICK, &mut frame(b"unhang:quarantine-n-2")).outcome,
        Outcome::Ready
    );
    second.join().unwrap();
}

#[test]
fn cancel_carries_the_disposition_and_a_fault_on_cancel_is_fault() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    for (mode, want) in [
        (&b"pend:hold:0"[..], (Outcome::Failed, Some(0))),
        (&b"pend:hold:1"[..], (Outcome::Failed, Some(1))),
        (&b"pend:hold:2"[..], (Outcome::Failed, Some(2))),
        (&b"pend:hold:f"[..], (Outcome::Fault, None)),
    ] {
        let t = d.mint(0).unwrap();
        let r = d.submit(&p, t, TICK, frame(mode), DeadlineClass::Call, 0);
        until("the held op", || d.is_pending(t));
        d.drop_client(t);
        let done = r.wait(WAIT).unwrap();
        assert_eq!(
            (done.outcome, done.disposition),
            want,
            "{}",
            String::from_utf8_lossy(mode)
        );
        d.recycle(t);
    }
}

#[test]
fn red_the_host_zeroes_the_whole_out_before_a_crossing() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);

    let mut f = frame(plug::SILENT);
    f.out.head.outcome = busbar_contract::abi::mechanism::call::RawOutcome::of(Outcome::Ready);
    f.out.head.lease = 0xBAD;
    f.out.next_tick_ns = 0xBAD;
    let c = p.call(TICK, &mut f);
    assert_eq!(c.outcome, Outcome::Fault);
    assert_eq!(f.out.next_tick_ns, 0, "the tail was zeroed too");
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn recycling_the_last_driver_releases_its_own_image_on_a_permanent_worker() {
    let caller = std::thread::current().id();
    let (witness, registration) = UnloadWitness::new();
    let d = Dispatcher::new(config());
    let p = load_dropped::<TestKind>(witness.path(), &stated(), bind(quiet()))
        .expect("this test's independently owned image loads");
    crate::dlclose_on_worker(registration);
    assert_eq!(open(&d, &p, 0), Outcome::Ready);
    let drv = d.driver(&p, 0).unwrap();
    let gone = std::sync::Arc::downgrade(&p.inner);
    let mut close: Frame<busbar_contract::abi::mechanism::call::InHead, OutHead> =
        Frame::new(in_head(), out_head());
    assert_eq!(p.call(slot::CLOSE, &mut close).outcome, Outcome::Ready);

    drop(p);
    assert!(
        witness.is_pending(),
        "the driver's reference retains its image"
    );
    d.recycle(drv);
    let unloaded = witness.finished();
    assert_eq!(gone.strong_count(), 0, "the driver's instance was released");
    assert_ne!(unloaded.thread, caller);
    assert!(unloaded.permanent);
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn recycling_a_driver_allows_its_finalizer_to_mint_on_the_same_worker() {
    unload_witness::assert_reentrant_child(
        "dispatch_tests::recycling_a_driver_allows_its_finalizer_to_mint_on_the_same_worker",
        || {
            let d = Arc::new(Dispatcher::new(config()));
            let (witness, registration) = UnloadWitness::reentrant(Arc::clone(&d));
            let p = load_dropped::<TestKind>(witness.path(), &stated(), bind(quiet()))
                .expect("this child's owned image loads");
            crate::dlclose_on_worker(registration);
            assert_eq!(open(&d, &p, 0), Outcome::Ready);
            let driver = d.driver(&p, 0).expect("a driver on worker zero");
            let gone = Arc::downgrade(&p.inner);
            let mut close: Frame<busbar_contract::abi::mechanism::call::InHead, OutHead> =
                Frame::new(in_head(), out_head());
            assert_eq!(p.call(slot::CLOSE, &mut close).outcome, Outcome::Ready);
            drop(p);
            assert!(witness.is_pending(), "driver still retains this image");
            d.recycle(driver);
            let unloaded = witness.finished();
            assert_eq!(gone.strong_count(), 0);
            assert!(unloaded.permanent);
            assert!(
                unloaded.reentered,
                "actual finalizer minted and recycled a ticket on worker zero"
            );

            unloaded.release_dispatcher_on_caller();
            drop(d);
        },
    );
}

#[test]
fn red_a_hanging_unload_faults_no_innocent_instance() {
    use crate::dispatch::load::reap;
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);

    let (release, hold) = std::sync::mpsc::channel::<()>();
    let (entered, inside) = std::sync::mpsc::channel::<String>();
    reap(Box::new(move || {
        let _ = entered.send(
            std::thread::current()
                .name()
                .unwrap_or_default()
                .to_string(),
        );
        let _ = hold.recv();
    }));
    let reaper = inside
        .recv_timeout(WAIT)
        .expect("the reaper runs the unload");
    assert_eq!(reaper, crate::dispatch::load::REAPER_THREAD);

    std::thread::sleep(config().budgets.call * 2);
    assert!(!p.is_faulted());
    assert_eq!(p.call(TICK, &mut frame(answer(1))).outcome, Outcome::Ready);
    let t = d.mint(0).unwrap();
    let r = d.submit(&p, t, TICK, frame(answer(1)), DeadlineClass::Call, 0);
    assert_eq!(r.wait(WAIT).unwrap().outcome, Outcome::Ready);
    assert_eq!(d.stats().replacements, 0, "no worker was replaced");
    release.send(()).unwrap();
}

#[test]
fn red_a_hanging_unload_holds_back_no_other_unload() {
    use crate::dispatch::load::reap;
    let (release, hold) = std::sync::mpsc::channel::<()>();
    let (entered, inside) = std::sync::mpsc::channel::<()>();
    reap(Box::new(move || {
        let _ = entered.send(());
        let _ = hold.recv();
    }));
    inside
        .recv_timeout(WAIT)
        .expect("the first unload runs, and hangs");
    let (ran, next) = std::sync::mpsc::channel::<String>();
    reap(Box::new(move || {
        let name = std::thread::current()
            .name()
            .unwrap_or_default()
            .to_string();
        let _ = ran.send(name);
    }));
    let got = next.recv_timeout(WAIT);
    release.send(()).unwrap();
    assert_eq!(
        got.as_deref(),
        Ok(crate::dispatch::load::REAPER_THREAD),
        "the second unload ran on a reaper while the first hung"
    );
}

#[test]
fn red_a_hung_unload_is_warned_of_and_counted_live() {
    use crate::dispatch::load::{reap_within, HUNG_WARNED};
    use std::sync::atomic::Ordering::SeqCst;
    let d = Dispatcher::new(config());
    let warned0 = HUNG_WARNED.load(SeqCst);
    let (release, hold) = std::sync::mpsc::channel::<()>();
    let (entered, inside) = std::sync::mpsc::channel::<()>();
    let (returned, back) = std::sync::mpsc::channel::<()>();
    reap_within(
        Box::new(move || {
            let _ = entered.send(());
            let _ = hold.recv();
            let _ = returned.send(());
        }),
        Duration::from_millis(1),
    );
    inside
        .recv_timeout(WAIT)
        .expect("the unload runs, and hangs");
    assert!(
        d.stats().live_reapers >= 1,
        "a hung unload's reaper is counted live"
    );
    until("the watch warned of the hung unload", || {
        HUNG_WARNED.load(SeqCst) > warned0
    });
    release.send(()).unwrap();
    back.recv_timeout(WAIT)
        .expect("the released unload returns");
}

#[test]
fn red_a_ticketless_short_answer_is_re_called_once() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    let first = p.call(TICK, &mut frame(plug::SHORT_ANSWER));
    assert_eq!(first.outcome, Outcome::Failed);
    let token = first.recall.expect("a short answer earns one re-call");

    let again = p.recall(token, TICK, &mut frame(plug::SHORT_ANSWER));
    assert_eq!(
        again.outcome,
        Outcome::Fault,
        "short again on the re-call is FAULT"
    );
    assert!(again.recall.is_none());

    let token = p.call(TICK, &mut frame(plug::SHORT_ANSWER)).recall.unwrap();
    assert_eq!(
        p.recall(token, TICK, &mut frame(answer(1))).outcome,
        Outcome::Ready
    );

    let (other, _s) = opened(&d);
    let token = p.call(TICK, &mut frame(plug::SHORT_ANSWER)).recall.unwrap();
    assert_eq!(
        other.recall(token, TICK, &mut frame(answer(1))).outcome,
        Outcome::Refused
    );
    assert!(
        p.call(TICK, &mut frame(answer(1))).recall.is_none(),
        "only a short answer earns one"
    );

    let t = d.mint(0).unwrap();
    let done = d
        .submit(
            &p,
            t,
            TICK,
            frame(plug::SHORT_ANSWER),
            DeadlineClass::Call,
            0,
        )
        .wait(WAIT)
        .unwrap();
    assert!(done.short);
    d.recycle(t);
}

#[test]
fn red_a_hung_ticketless_open_is_watched_from_bind() {
    let d = Dispatcher::new(DispatchConfig {
        budgets: Budgets {
            lifecycle: Duration::from_millis(400),
            ..config().budgets
        },
        ..config()
    });
    let sink = quiet();
    let p = load_linked::<TestKind>(
        &row(),
        Bind {
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::NoNeeds,
            ..bind(sink)
        },
    )
    .unwrap();
    let p = Arc::new(p);
    let hung = Arc::clone(&p);
    let caller = std::thread::spawn(move || {
        let mut f = open_frame();
        let settings = b"hang:open";
        f.input.settings = busbar_contract::abi::mechanism::call::Blob {
            ptr: settings.as_ptr(),
            len: settings.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        hung.call(slot::OPEN, &mut f).outcome
    });

    until("the watchdog faults the hung open", || p.is_faulted());
    let (other, _s) = opened(&d);
    assert_eq!(
        other.call(TICK, &mut frame(b"unhang:open")).outcome,
        Outcome::Ready
    );
    caller.join().unwrap();
}

#[test]
fn red_close_is_refused_while_a_drive_is_mid_crossing() {
    let d = Dispatcher::new(DispatchConfig {
        budgets: Budgets {
            connection: Duration::from_secs(30),
            ..config().budgets
        },
        ..config()
    });
    let (p, _sink) = opened(&d);

    let (other, _s) = opened(&d);
    let drv = d.driver(&p, 0).unwrap();
    assert_eq!(
        p.call(TICK, &mut frame(plug::DRIVE_HANGS)).outcome,
        Outcome::Ready
    );
    crate::dispatch::ticket::host_wake(p.inner.ctx(), drv);
    until("the drive is inside its crossing", || {
        p.call(TICK, &mut frame(plug::DRIVE_ENTERED)).outcome == Outcome::Ready
    });

    assert_eq!(p.inflight(), 0);
    let n = crossings(&p);
    assert_eq!(
        p.call(slot::CLOSE, &mut close_frame()).outcome,
        Outcome::Refused
    );
    assert_eq!(crossings(&p), n, "the refused close never crossed");
    assert!(p.is_open());
    assert_eq!(
        other.call(TICK, &mut frame(b"unhang:drive")).outcome,
        Outcome::Ready
    );

    until("close after the drive", || {
        p.call(slot::CLOSE, &mut close_frame()).outcome == Outcome::Ready
    });
    assert!(!p.is_open());
}

#[test]
fn red_a_wake_behind_a_scheduled_tick_on_a_driver_ticket_still_drives() {
    let d = Dispatcher::new(DispatchConfig {
        budgets: Budgets {
            call: Duration::from_secs(30),
            ..config().budgets
        },
        ..config()
    });
    let (p, sink) = opened(&d);
    let (other, _s) = opened(&d);
    let drv = d.driver(&p, 0).unwrap();

    let wedge = d.mint(0).unwrap();
    let wedged = d.submit(
        &other,
        wedge,
        TICK,
        frame(b"hang:latched-wake"),
        DeadlineClass::Call,
        0,
    );
    let ticked = d.submit(&p, drv, TICK, frame(answer(1)), DeadlineClass::Call, 0);
    crate::dispatch::ticket::host_wake(p.inner.ctx(), drv);
    assert_eq!(
        p.call(TICK, &mut frame(b"unhang:latched-wake")).outcome,
        Outcome::Ready
    );
    assert_eq!(wedged.wait(WAIT).unwrap().outcome, Outcome::Ready);
    assert_eq!(ticked.wait(WAIT).unwrap().outcome, Outcome::Ready);
    until("the wake owed behind the tick drives", || {
        count(&p, &sink).2 >= 1
    });
    d.recycle(wedge);
    d.recycle(drv);
}

#[test]
fn red_a_kind_check_judges_every_outcome_in_its_bound_context() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);

    assert_eq!(
        p.call(TICK, &mut frame(plug::REJECTED_REFUSED)).outcome,
        Outcome::Fault
    );

    assert_eq!(
        p.call(TICK, &mut frame(answer(4))).outcome,
        Outcome::Refused
    );

    assert_eq!(p.call(TICK, &mut frame(answer(1))).outcome, Outcome::Ready);
}

fn one_thread() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime")
}

#[test]
fn an_await_on_a_one_thread_runtime_completes() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    let rt = one_thread();

    let t = d.mint(0).unwrap();
    let reply = d.submit(&p, t, TICK, frame(plug::PEND_AFTER), DeadlineClass::Call, 0);
    let done = rt.block_on(async {
        tokio::time::timeout(WAIT, reply)
            .await
            .expect("the awaited reply completes")
    });
    assert_eq!(done.outcome, Outcome::Ready);

    let (a, b) = (d.mint(0).unwrap(), d.mint(1).unwrap());
    let ra = d.submit(&p, a, TICK, frame(plug::PEND_AFTER), DeadlineClass::Call, 0);
    let rb = d.submit(
        &p,
        b,
        TICK,
        frame(plug::PEND_BEFORE),
        DeadlineClass::Call,
        0,
    );
    let (da, db) = rt
        .block_on(async { tokio::time::timeout(WAIT, async { (ra.await, rb.await) }).await })
        .expect("both complete");
    assert_eq!((da.outcome, db.outcome), (Outcome::Ready, Outcome::Ready));

    let c = d.mint(1).unwrap();
    let rc = d.submit(&p, c, TICK, frame(answer(1)), DeadlineClass::Call, 0);
    assert_eq!(rc.wait(WAIT).unwrap().outcome, Outcome::Ready);
}

#[test]
fn red_dropping_a_pending_reply_cancels_and_a_late_wake_is_a_no_op() {
    let d = Dispatcher::new(config());
    let (p, sink) = opened(&d);
    let rt = one_thread();
    let t = d.mint(0).unwrap();
    let reply = d.submit(&p, t, TICK, frame(plug::PEND_HOLD), DeadlineClass::Call, 0);

    let polled = rt.block_on(async {
        tokio::time::timeout(Duration::from_millis(20), reply)
            .await
            .is_err()
    });
    assert!(
        polled,
        "the held op is still pending when its future is dropped"
    );
    until("the dropped reply's op is cancelled", || {
        count(&p, &sink).1 == 1
    });
    until("the ticket is idle", || !d.is_pending(t));

    let n = p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst);
    crate::dispatch::ticket::host_wake(p.inner.ctx(), t);
    let probe = d.mint(0).unwrap();
    assert_eq!(
        d.submit(&p, probe, TICK, frame(answer(1)), DeadlineClass::Call, 0)
            .wait(WAIT)
            .unwrap()
            .outcome,
        Outcome::Ready
    );

    assert_eq!(
        p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst),
        n + 1
    );

    let w = d.mint(1).unwrap();
    d.submit(&p, w, TICK, frame(plug::PEND_HOLD), DeadlineClass::Call, 0)
        .detach();
    until("the detached op pends", || d.is_pending(w));
    assert_eq!(count(&p, &sink).1, 1, "a detached reply cancels nothing");
    assert_eq!(p.call(TICK, &mut frame(plug::KICK)).outcome, Outcome::Ready);
    until("the detached op completes", || !d.is_pending(w));
}

struct LentMode {
    bytes: Vec<u8>,
    dropped: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for LentMode {
    fn drop(&mut self) {
        self.dropped
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn lent_frame(lent: &LentMode) -> Frame<TickIn, TickOut> {
    let mut f = frame(b"");
    f.input.head.extensions = Blob {
        ptr: lent.bytes.as_ptr(),
        len: lent.bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    f
}

fn lent(mode: &[u8]) -> (Arc<LentMode>, Arc<std::sync::atomic::AtomicBool>) {
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let lent = Arc::new(LentMode {
        bytes: mode.to_vec(),
        dropped: dropped.clone(),
    });
    (lent, dropped)
}

#[test]
fn red_a_dropped_reply_keeps_its_lent_memory_until_the_crossing_returns() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    let (owner, dropped) = lent(b"hang:lent");
    let t = d.mint(0).unwrap();
    let reply = d.submit_lent(
        &p,
        t,
        TICK,
        lent_frame(&owner),
        DeadlineClass::Call,
        0,
        owner.clone(),
    );
    until("the op is inside its crossing", || {
        p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst) > 1
    });
    drop(reply);
    drop(owner);

    until("the watchdog replaced the hung worker", || {
        d.stats().replacements == 1
    });
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        !dropped.load(std::sync::atomic::Ordering::SeqCst),
        "the lent memory must outlive a crossing that has not returned"
    );

    let (p2, _) = opened(&d);
    assert_eq!(
        p2.call(TICK, &mut frame(b"unhang:lent")).outcome,
        Outcome::Ready
    );
    until("the lent memory goes once the crossing returned", || {
        dropped.load(std::sync::atomic::Ordering::SeqCst)
    });
}

#[test]
fn a_dropped_pending_reply_keeps_its_lent_memory_until_the_cancel() {
    let d = Dispatcher::new(config());
    let (p, sink) = opened(&d);
    let (owner, dropped) = lent(plug::PEND_HOLD);
    let t = d.mint(0).unwrap();
    let reply = d.submit_lent(
        &p,
        t,
        TICK,
        lent_frame(&owner),
        DeadlineClass::Call,
        0,
        owner.clone(),
    );
    until("the op pends", || d.is_pending(t));
    drop(owner);
    assert!(
        !dropped.load(std::sync::atomic::Ordering::SeqCst),
        "a pending op holds its lent memory"
    );
    drop(reply);
    until("the dropped reply's op is cancelled", || {
        count(&p, &sink).1 == 1
    });
    until("the lent memory goes after the cancel", || {
        dropped.load(std::sync::atomic::Ordering::SeqCst)
    });
}

#[test]
fn bind_states_the_caller_to_the_host_services() {
    let p = linked(quiet());
    let caller = p.inner.wake.caller.get().expect("bind states a caller");
    assert_eq!(&*caller.instance, "the-instance");
    assert_eq!(&*caller.plugin, p.inner.name());
    assert_eq!(caller.kind, p.inner.kind);
}

#[test]
fn two_instances_of_one_plugin_are_two_callers() {
    let first = linked(quiet());
    let second = load_linked::<TestKind>(
        &row(),
        Bind {
            instance: Arc::from("the-second"),
            ..bind(quiet())
        },
    )
    .expect("the linked door loads twice");
    let (a, b) = (
        first.inner.wake.caller.get().unwrap(),
        second.inner.wake.caller.get().unwrap(),
    );
    assert_eq!(a.plugin, b.plugin);
    assert_ne!(a.instance, b.instance);
}

#[test]
fn a_transport_tail_with_a_row_per_claimed_name_is_admitted_and_no_other() {
    use busbar_contract::abi::mechanism::call::AbiStr;
    use busbar_contract::abi::transport::{Claim, TransportTail};
    const NAMES: &[AbiStr] = &[
        busbar_contract::abi::sdk::door::abi_str("tele"),
        busbar_contract::abi::sdk::door::abi_str("teles"),
    ];
    // SAFETY: an all-zero Claim is a valid row (no strings, no lists).
    let row: &'static Claim = Box::leak(Box::new(unsafe { std::mem::zeroed::<Claim>() }));
    // SAFETY: an all-zero TransportTail is a valid value; its size, piece and rows are set below.
    let mut t: TransportTail = unsafe { std::mem::zeroed() };
    t.head.size = std::mem::size_of::<TransportTail>() as u32;
    t.frame_piece_size = std::mem::size_of::<busbar_contract::abi::transport::FramePiece>() as u32;
    t.claim_rows = row;
    t.claim_rows_len = 1;
    let tail = (Box::leak(Box::new(t)) as *const TransportTail).cast::<KindTailHead>();
    let st = |names: usize, kind: KindCode| Statement {
        kind: kind as u32,
        kind_tail: tail,
        claims: NAMES.as_ptr(),
        claims_len: names,
        ..busbar_contract::abi::sdk::door::statement("sockets", "1.0.0", 1)
    };
    assert!(crate::dispatch::load::kind_tail(&st(1, KindCode::Transport)).is_ok());
    assert!(matches!(
        crate::dispatch::load::kind_tail(&st(2, KindCode::Transport)),
        Err(LoadError::KindTail(why)) if why.contains("tail.claim_rows")
    ));

    assert!(crate::dispatch::load::kind_tail(&st(0, KindCode::Hook)).is_ok());

    let untailed = Statement {
        kind_tail: std::ptr::null(),
        ..st(1, KindCode::Transport)
    };
    assert!(matches!(
        crate::dispatch::load::kind_tail(&untailed),
        Err(LoadError::KindTail(_))
    ));
}

#[test]
fn a_transport_built_against_another_frame_piece_is_refused_at_load() {
    use busbar_contract::abi::mechanism::call::AbiStr;
    use busbar_contract::abi::transport::{Claim, FramePiece, TransportTail, FRAME_PIECE_SIZE};
    const NAMES: &[AbiStr] = &[busbar_contract::abi::sdk::door::abi_str("tele")];
    let host = std::mem::size_of::<FramePiece>() as u32;
    assert_eq!(
        host, FRAME_PIECE_SIZE,
        "the contract states the host's piece"
    );
    // SAFETY: an all-zero Claim is a valid row (no strings, no lists).
    let row: &'static Claim = Box::leak(Box::new(unsafe { std::mem::zeroed::<Claim>() }));
    let tail = |size: usize, piece: u32| {
        // SAFETY: an all-zero TransportTail is a valid value; its size, piece and rows are set.
        let mut t: TransportTail = unsafe { std::mem::zeroed() };
        t.head.size = size as u32;
        t.frame_piece_size = piece;
        t.claim_rows = row;
        t.claim_rows_len = 1;
        (Box::leak(Box::new(t)) as *const TransportTail).cast::<KindTailHead>()
    };

    let load = |kind_tail: *const KindTailHead| {
        let st: &'static Statement = Box::leak(Box::new(Statement {
            size: std::mem::size_of::<Statement>() as u32,
            kind: KindCode::Transport as u32,
            kind_abi: KindCode::Transport.abi_version(),
            kind_tail,
            claims: NAMES.as_ptr(),
            claims_len: NAMES.len(),
            ..busbar_contract::abi::sdk::door::statement("sockets", "1.0.0", 1)
        }));
        let door = DoorParts {
            magic: DOOR_MAGIC,
            mechanism_version: MECHANISM_VERSION,
            size: std::mem::size_of::<Door>() as u32,
            kind: KindCode::Transport as u32,
            kind_abi: KindCode::Transport.abi_version(),
            statement: st,
            ops: std::ptr::null(),
            ready: None,
            layout: KindCode::Transport.layout_fingerprint(),
        };
        crate::dispatch::load::statement(&door).map(|_| ())
    };
    let whole = std::mem::size_of::<TransportTail>();

    assert_eq!(load(tail(whole, host)), Ok(()), "the host's piece loads");

    let refused = load(tail(whole, 40)).expect_err("a 40-byte piece is refused");
    assert_eq!(
        refused,
        LoadError::FramePieceSize {
            plugin: "sockets".into(),
            stated: 40,
            host,
        }
    );
    let said = refused.to_string();
    assert!(
        said.contains("'sockets'")
            && said.contains("40-byte")
            && said.contains(&format!("{host}-byte"))
            && said.contains("rebuild against this busbar-contract"),
        "{said}"
    );

    let before = std::mem::offset_of!(TransportTail, frame_piece_size);
    assert_eq!(
        load(tail(before, host)),
        Err(LoadError::FramePieceSize {
            plugin: "sockets".into(),
            stated: 0,
            host,
        }),
        "a tail that predates the piece size is refused, never read past its end"
    );
}

#[test]
fn a_plane_built_against_another_answer_layout_is_refused_at_load() {
    use busbar_contract::abi::plane::{PlaneTail, ANSWER_LAYOUT};
    let host = ANSWER_LAYOUT;
    let tail = |size: usize, layout: u32| {
        // SAFETY: an all-zero PlaneTail is a valid value; its size and layout are set.
        let mut t: PlaneTail = unsafe { std::mem::zeroed() };
        t.head.size = size as u32;
        t.answer_layout = layout;
        (Box::leak(Box::new(t)) as *const PlaneTail).cast::<KindTailHead>()
    };

    let load = |kind_tail: *const KindTailHead| {
        let st: &'static Statement = Box::leak(Box::new(Statement {
            size: std::mem::size_of::<Statement>() as u32,
            kind: KindCode::Plane as u32,
            kind_abi: KindCode::Plane.abi_version(),
            kind_tail,
            ..busbar_contract::abi::sdk::door::statement("tools", "1.0.0", 1)
        }));
        let door = DoorParts {
            magic: DOOR_MAGIC,
            mechanism_version: MECHANISM_VERSION,
            size: std::mem::size_of::<Door>() as u32,
            kind: KindCode::Plane as u32,
            kind_abi: KindCode::Plane.abi_version(),
            statement: st,
            ops: std::ptr::null(),
            ready: None,
            layout: KindCode::Plane.layout_fingerprint(),
        };
        crate::dispatch::load::statement(&door).map(|_| ())
    };
    let whole = std::mem::size_of::<PlaneTail>();

    assert_eq!(load(tail(whole, host)), Ok(()), "the host's layout loads");

    for other in [host - 1, host + 1] {
        let refused = load(tail(whole, other)).expect_err("another answer layout is refused");
        assert_eq!(
            refused,
            LoadError::PlaneLayout {
                plugin: "tools".into(),
                stated: other,
                host,
            }
        );
        let said = refused.to_string();
        assert!(
            said.contains("'tools'")
                && said.contains(&format!("plane layout {other}"))
                && said.contains(&format!("plane layout {host}"))
                && said.contains("rebuild against this busbar-contract"),
            "{said}"
        );
    }

    let before = std::mem::offset_of!(PlaneTail, answer_layout);
    assert_eq!(
        load(tail(before, host)),
        Err(LoadError::PlaneLayout {
            plugin: "tools".into(),
            stated: 0,
            host,
        }),
        "a tail that predates the answer layout is refused, never read past its end"
    );
}

#[test]
fn a_dispatcher_built_and_first_submitted_inside_a_runtime_runs_in_no_runtime_until_one_is_installed(
) {
    let control = one_thread();
    let d = {
        let _inside = control.enter();
        let d = Dispatcher::new(config());
        let (p, _sink) = opened(&d);
        assert_eq!(p.call(TICK, &mut frame(answer(1))).outcome, Outcome::Ready);
        d
    };
    assert!(
        d.installed_runtime().is_none(),
        "the workers were bound to the submitter's runtime"
    );
    let io = one_thread();
    assert!(
        d.install_runtime(io.handle().clone()),
        "the first install holds"
    );
    assert!(
        !d.install_runtime(control.handle().clone()),
        "a second install is ignored"
    );
    assert!(d.installed_runtime().is_some());
}

#[test]
fn a_forged_context_quarantines_the_instance_that_forged_it() {
    let d = Dispatcher::new(config());
    let honest = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &honest, 0), Outcome::Ready);
    assert_eq!(
        honest.call(TICK, &mut frame(plug::COUNT)).outcome,
        Outcome::Ready
    );
    assert!(!honest.is_faulted(), "an honest instance was faulted");

    let forger = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &forger, 0), Outcome::Ready);
    assert_eq!(
        forger.call(TICK, &mut frame(plug::FORGE)).outcome,
        Outcome::Fault,
        "the forging op answered other than FAULT"
    );
    assert!(
        forger.is_faulted(),
        "the forging instance was not quarantined"
    );
    assert_eq!(
        forger.call(TICK, &mut frame(plug::COUNT)).outcome,
        Outcome::Fault,
        "a quarantined instance was called again"
    );
    let latch = crate::dispatch::handle::Latch::new();
    assert!(
        crate::dispatch::handle::resolve_in(forger.inner.ctx(), &latch, None).is_none(),
        "the quarantined instance's own handle still names it"
    );
    assert_eq!(
        latch.forged(),
        0,
        "a revoked handle was counted as a forgery"
    );
    assert!(
        !honest.is_faulted(),
        "the quarantine reached another instance"
    );
    assert!(crate::dispatch::handle::resolve_in(honest.inner.ctx(), &latch, None).is_some());
}

#[test]
fn inside_a_crossing_another_instances_handle_quarantines_the_crossing() {
    let d = Dispatcher::new(config());
    let crossing = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &crossing, 0), Outcome::Ready);
    let other = linked(Arc::new(Recorder::default()));
    let (own_ctx, other_ctx) = (crossing.inner.ctx(), other.inner.ctx());

    other.inner.revoke();
    let latch = crate::dispatch::handle::Latch::new();
    let (own, theirs) = crate::dispatch::plugin::with_crossing(Some(&*crossing.inner), || {
        let own = crate::dispatch::handle::resolve_in(
            own_ctx,
            &latch,
            crate::dispatch::plugin::crossing_wake(),
        )
        .is_some();
        let theirs = crate::dispatch::handle::resolve_in(
            other_ctx,
            &latch,
            crate::dispatch::plugin::crossing_wake(),
        )
        .is_some();
        (own, theirs)
    });
    assert!(own, "the crossing's own handle was refused");
    assert!(
        !theirs,
        "another instance's handle resolved inside a crossing"
    );
    assert_eq!(latch.forged(), 1, "the forgery was not counted");
    assert_eq!(
        latch.unattributed(),
        0,
        "an attributed forgery moved the latch"
    );
    assert!(
        crossing.is_faulted(),
        "the crossing instance was not quarantined"
    );
}

#[test]
fn a_forgery_inside_an_inline_slot_leaves_the_outer_crossing_alone() {
    let d = Dispatcher::new(config());
    let outer = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &outer, 0), Outcome::Ready);
    let forged = busbar_contract::abi::mechanism::ticket::HostCtx {
        handle: outer.inner.ctx().handle ^ (1 << crate::dispatch::handle::HANDLE_ID_BITS),
    };
    let latch = crate::dispatch::handle::Latch::new();
    let restored = crate::dispatch::plugin::with_crossing(Some(&*outer.inner), || {
        crate::dispatch::plugin::without_crossing(|| {
            assert!(crate::dispatch::plugin::crossing_wake().is_none());
            assert!(crate::dispatch::handle::resolve_in(
                forged,
                &latch,
                crate::dispatch::plugin::crossing_wake(),
            )
            .is_none());
        });
        crate::dispatch::plugin::crossing_wake().is_some_and(|w| std::ptr::eq(w, outer.inner.wake))
    });
    assert!(restored, "the outer crossing's mark was not restored");
    assert!(
        !outer.is_faulted(),
        "the outer instance was quarantined for an inline forgery"
    );
    assert_eq!(
        latch.unattributed(),
        1,
        "the unattributed forgery was not counted"
    );
}

#[test]
fn a_closed_a_dropped_and_a_watchdog_faulted_instance_name_nothing() {
    let d = Dispatcher::new(config());
    let latch = crate::dispatch::handle::Latch::new();
    let resolves = |ctx| crate::dispatch::handle::resolve_in(ctx, &latch, None).is_some();

    let closed = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &closed, 0), Outcome::Ready);
    let ctx = closed.inner.ctx();
    assert!(resolves(ctx));
    let t = d.mint(0).expect("a ticket");
    let _ = d
        .submit(
            &closed,
            t,
            slot::CLOSE,
            Frame::new(in_head(), out_head()),
            DeadlineClass::Call,
            0,
        )
        .wait(WAIT);
    d.recycle(t);
    assert!(!resolves(ctx), "a closed instance's handle still names it");

    let dropped = linked(Arc::new(Recorder::default()));
    let ctx = dropped.inner.ctx();
    assert!(resolves(ctx));
    drop(dropped);
    assert!(!resolves(ctx), "a dropped instance's handle still names it");

    let hung = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &hung, 1), Outcome::Ready);
    let ctx = hung.inner.ctx();
    let t = d.mint(1).expect("a ticket");
    let reply = d.submit(
        &hung,
        t,
        TICK,
        frame(b"hang:revoked"),
        DeadlineClass::Call,
        0,
    );
    until("the watchdog faults the hung instance", || {
        hung.is_faulted()
    });
    assert!(
        !resolves(ctx),
        "a watchdog-faulted instance's handle still names it"
    );
    let releaser = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &releaser, 0), Outcome::Ready);
    let _ = releaser.call(TICK, &mut frame(b"unhang:revoked"));
    let _ = reply.wait(WAIT);

    assert_eq!(
        latch.forged(),
        0,
        "a revoked handle was counted as a forgery"
    );
}

#[test]
fn a_ticketless_hang_faulted_by_the_watchdog_revokes_the_handle() {
    let d = Dispatcher::new(config());
    let bind_adopted = || Bind {
        dispatcher: d.adopter(),
        ..bind(Arc::new(Recorder::default()))
    };
    let hung = load_linked::<TestKind>(&row(), bind_adopted()).expect("the linked door loads");
    assert_eq!(open(&d, &hung, 0), Outcome::Ready);
    let ctx = hung.inner.ctx();
    let latch = crate::dispatch::handle::Latch::new();
    assert!(crate::dispatch::handle::resolve_in(ctx, &latch, None).is_some());
    std::thread::scope(|scope| {
        let caller = scope.spawn(|| {
            hung.call(TICK, &mut frame(b"hang:ticketless-revoke"))
                .outcome
        });
        until("the watchdog faults the ticket-less hang", || {
            hung.is_faulted()
        });
        assert!(
            crate::dispatch::handle::resolve_in(ctx, &latch, None).is_none(),
            "a watchdog-faulted instance's handle still names it"
        );
        let releaser =
            load_linked::<TestKind>(&row(), bind_adopted()).expect("the linked door loads");
        assert_eq!(open(&d, &releaser, 0), Outcome::Ready);
        let _ = releaser.call(TICK, &mut frame(b"unhang:ticketless-revoke"));
        let _ = caller.join();
    });
    assert_eq!(
        latch.forged(),
        0,
        "a revoked handle was counted as a forgery"
    );
}

#[test]
fn a_boot_whose_entropy_fails_is_refused() {
    crate::dispatch::handle::ENTROPY_FAILS.with(|f| f.set(true));
    let refused = Dispatcher::try_new(config());
    let bound = load_linked::<TestKind>(&row(), bind(Arc::new(Recorder::default())));
    crate::dispatch::handle::ENTROPY_FAILS.with(|f| f.set(false));
    assert!(
        matches!(refused, Err(LoadError::Entropy(_))),
        "a failing entropy source did not refuse the boot"
    );
    assert!(
        matches!(bound, Err(LoadError::Entropy(_))),
        "a failing entropy source did not refuse the bind"
    );
}

#[test]
fn a_forged_ticket_generation_quarantines_the_instance_that_woke_it() {
    let d = Dispatcher::new(config());
    let honest = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &honest, 0), Outcome::Ready);
    let forger = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &forger, 0), Outcome::Ready);
    let t = d.mint(0).expect("a ticket");
    let _ = d
        .submit(
            &forger,
            t,
            TICK,
            frame(plug::FORGE_TICKET),
            DeadlineClass::Call,
            0,
        )
        .wait(WAIT);
    d.recycle(t);
    until("the forger is quarantined", || forger.is_faulted());
    let latch = crate::dispatch::handle::Latch::new();
    assert!(crate::dispatch::handle::resolve_in(forger.inner.ctx(), &latch, None).is_none());
    assert_eq!(
        forger.call(TICK, &mut frame(plug::COUNT)).outcome,
        Outcome::Fault
    );
    assert!(
        !honest.is_faulted(),
        "the quarantine reached another instance"
    );
}

fn forged_generation(t: Ticket) -> Ticket {
    Ticket {
        slot: t.slot,
        generation: t.generation ^ 0x5a5a_5a5a,
    }
}

#[test]
fn red_a_completion_fired_in_another_crossing_quarantines_its_supplier() {
    use crate::dispatch::services::{serve, Ran, Stored};
    use busbar_contract::abi::host::service::{op, ServiceHead};
    use busbar_contract::abi::mechanism::ticket::CompletionHandle;

    let d = Dispatcher::new(config());
    let supplier = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &supplier, 0), Outcome::Ready);
    let bystander = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &bystander, 0), Outcome::Ready);
    let t = d.mint(0).expect("a ticket");
    let head = ServiceHead {
        size: 0,
        op: op::RECORDS_GET,
        handle: CompletionHandle {
            ticket: forged_generation(t),
            seq: 0,
            _reserved: 0,
        },
    };
    let waking = crate::dispatch::ticket::Waking::of(supplier.inner.wake)
        .expect("the supplier is bound to the dispatcher");
    let held = Mutex::new(None);
    // SAFETY: no buffers; the service pends.
    let pended = unsafe {
        serve(&d.service_store(), &waking, &head, 0, None, |c| {
            *held.lock().unwrap() = c;
            Ran::Later
        })
    };
    assert_eq!(pended.outcome, Outcome::Pending);
    let completer = held.lock().unwrap().take().expect("the call's completer");
    crate::dispatch::plugin::with_crossing(Some(&*bystander.inner), || {
        completer.complete(Stored::ready(1));
    });
    until("the supplier is quarantined", || supplier.is_faulted());
    assert!(
        !bystander.is_faulted(),
        "the instance whose crossing the completion fired in was blamed"
    );
    d.recycle(t);
}

#[test]
fn red_an_off_crossing_forged_ticket_counts_toward_the_latch() {
    let d = Dispatcher::new(config());
    let latch: &'static crate::dispatch::handle::Latch =
        Box::leak(Box::new(crate::dispatch::handle::Latch::new()));
    d.judge_against(latch);
    let honest = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &honest, 0), Outcome::Ready);
    let forger = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &forger, 0), Outcome::Ready);
    let t = d.mint(0).expect("a ticket");

    (d.conn_waker())(
        busbar_contract::conn::InstanceId(0),
        crate::dispatch::conn_services::conn_ticket(forged_generation(t)),
    );
    until("the host's forged wake is counted", || {
        latch.unattributed() == 1
    });
    assert!(
        !honest.is_faulted() && !forger.is_faulted(),
        "the host's own wake blamed an instance"
    );

    crate::dispatch::ticket::host_wake(forger.inner.ctx(), forged_generation(t));
    until("the supplier is quarantined", || forger.is_faulted());
    assert_eq!(
        (latch.forged(), latch.unattributed()),
        (2, 1),
        "a supplied forged ticket was counted toward the latch"
    );
    assert!(
        !honest.is_faulted(),
        "the quarantine reached another instance"
    );
    d.recycle(t);
}

fn own_latch(d: &Dispatcher) -> &'static crate::dispatch::handle::Latch {
    let latch: &'static crate::dispatch::handle::Latch =
        Box::leak(Box::new(crate::dispatch::handle::Latch::new()));
    d.judge_against(latch);
    latch
}

#[test]
fn red_a_guessed_inline_ticket_quarantines_its_supplier() {
    use crate::dispatch::inline::INLINE_WORKER;
    use crate::dispatch::ticket::encode;
    let d = Dispatcher::new(config());
    let latch = own_latch(&d);
    let held = d.inline_ticket().expect("an inline ticket");
    let live = held.ticket();
    assert!(
        (1..=1024).all(|g| g != live.generation),
        "a held inline ticket's generation is a small counter"
    );
    let guesser = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &guesser, 0), Outcome::Ready);
    let prober = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &prober, 0), Outcome::Ready);
    crate::dispatch::ticket::host_wake(
        guesser.inner.ctx(),
        Ticket {
            slot: live.slot,
            generation: 1,
        },
    );
    assert!(
        guesser.is_faulted(),
        "a guessed inline generation was not judged a forgery"
    );
    assert!(
        !prober.is_faulted(),
        "the quarantine reached another instance"
    );
    assert_eq!((latch.forged(), latch.unattributed()), (1, 0));

    crate::dispatch::ticket::host_wake(
        prober.inner.ctx(),
        Ticket {
            slot: encode(INLINE_WORKER, 999),
            generation: 1,
        },
    );
    assert!(
        prober.is_faulted(),
        "a wake for an inline slot never used was not a forgery"
    );
    assert_eq!((latch.forged(), latch.unattributed()), (2, 0));
    drop(held);
}

#[test]
fn red_an_op_whose_dial_frames_inside_its_crossing_pends_and_resumes_ready() {
    let d = Dispatcher::new(config());
    let (plane, _) = opened(&d);
    let (framer, _) = opened(&d);
    let t = d.mint(0).expect("a ticket");
    let serving = d.submit(
        &plane,
        t,
        TICK,
        frame(plug::PEND_HOLD),
        DeadlineClass::Call,
        0,
    );
    until("the op waits on its dial", || d.is_pending(t));

    let side = d.inline_ticket().expect("an inline ticket");
    let begun = crate::dispatch::plugin::with_crossing(Some(&*plane.inner), || {
        framer.call_inline(side.ticket(), false, TICK, &mut frame(plug::COUNT))
    });
    assert_eq!(begun.outcome, Outcome::Ready, "the framing's begin");
    assert!(
        !plane.is_faulted(),
        "the host's own framing of the dial quarantined the instance it was nested in"
    );
    assert!(!framer.is_faulted(), "the framer was quarantined");

    assert_eq!(
        plane.call(TICK, &mut frame(plug::KICK)).outcome,
        Outcome::Ready
    );
    let done = serving.wait(WAIT).expect("the op answers");
    assert_eq!(done.outcome, Outcome::Ready, "the resumed op");
    drop(side);
    d.recycle(t);
}

#[test]
fn red_an_inline_slot_whose_counter_is_spent_is_retired() {
    let d = Dispatcher::new(config());
    let latch = own_latch(&d);
    let waker = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &waker, 0), Outcome::Ready);
    let held = d.inline_ticket().expect("an inline ticket");
    let seeded = d.inline_tickets().seed_count(held.ticket(), u32::MAX - 1);
    drop(held);
    let last = d.inline_ticket().expect("an inline ticket");
    assert_eq!(
        last.ticket().slot,
        seeded.slot,
        "the slot's last count is handed out"
    );
    let last_ticket = last.ticket();
    drop(last);
    let mut kept = Vec::new();
    for _ in 0..8 {
        let fresh = d.inline_ticket().expect("a fresh inline slot");
        assert_ne!(
            fresh.ticket().slot,
            seeded.slot,
            "a retired inline slot was handed out again"
        );
        kept.push(fresh);
    }
    for late in [seeded, last_ticket] {
        crate::dispatch::ticket::host_wake(waker.inner.ctx(), late);
    }
    assert!(
        !waker.is_faulted(),
        "a late wake for a minted inline generation was judged a forgery"
    );
    assert_eq!(latch.forged(), 0);
}

/// A task waker that counts its wakes.
#[derive(Default)]
struct Counted(std::sync::atomic::AtomicUsize);

impl std::task::Wake for Counted {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Counted {
    fn woken(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[test]
fn red_an_io_held_waker_fired_after_recycle_does_not_wake_the_new_task() {
    let d = Dispatcher::new(config());
    let old_task = Arc::new(Counted::default());
    let held = d.inline_ticket().expect("an inline ticket");
    held.register(&std::task::Waker::from(old_task.clone()));
    let io_held = d
        .inline_tickets()
        .waker_of(held.ticket())
        .expect("the held ticket's waker");
    drop(held);
    let new_task = Arc::new(Counted::default());
    let next = d.inline_ticket().expect("the slot again");
    next.register(&std::task::Waker::from(new_task.clone()));
    io_held.wake_by_ref();
    io_held.wake();
    assert_eq!(
        new_task.woken(),
        0,
        "a stale I/O waker woke the next connection's task"
    );
    assert_eq!(old_task.woken(), 0, "a recycled ticket's task was woken");
    d.inline_tickets()
        .waker_of(next.ticket())
        .expect("the new ticket's waker")
        .wake();
    assert_eq!(
        new_task.woken(),
        1,
        "the new generation's own waker did not wake its task"
    );
}

#[test]
fn red_a_wake_interleaved_with_recycle_and_re_mint_does_not_reach_the_new_task() {
    let d = Dispatcher::new(config());
    let held = d.inline_ticket().expect("an inline ticket");
    let old = held.ticket();
    let new_task = Arc::new(Counted::default());
    let next: Arc<Mutex<Option<crate::dispatch::InlineTicket>>> = Arc::default();
    let (tickets, task, slot) = (d.inline_tickets_arc(), new_task.clone(), next.clone());
    crate::dispatch::inline::BETWEEN_LOOKUP_AND_WAKE.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            drop(held);
            let t = tickets.mint().expect("the slot again");
            t.register(&std::task::Waker::from(task));
            *slot.lock().unwrap() = Some(t);
        }));
    });
    let judged = d.inline_tickets().wake(old);
    assert_eq!(judged, crate::dispatch::inline::Judged::Stale);
    let re_minted = next
        .lock()
        .unwrap()
        .take()
        .expect("the hook re-minted the slot");
    assert_eq!(
        re_minted.ticket().slot,
        old.slot,
        "the race re-minted another slot"
    );
    assert_eq!(
        new_task.woken(),
        0,
        "a wake for the recycled generation woke the new task"
    );
}

#[test]
fn red_a_wake_for_a_worker_the_dispatcher_does_not_run_is_a_forgery() {
    let d = Dispatcher::new(config());
    let latch = own_latch(&d);
    let forger = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &forger, 0), Outcome::Ready);
    crate::dispatch::ticket::host_wake(
        forger.inner.ctx(),
        Ticket {
            slot: crate::dispatch::ticket::encode(d.workers(), 0),
            generation: 1,
        },
    );
    assert!(
        forger.is_faulted(),
        "a wake for a worker no one runs was not a forgery"
    );
    assert_eq!((latch.forged(), latch.unattributed()), (1, 0));
}

#[test]
fn red_a_slot_whose_counter_is_spent_is_retired() {
    let d = Dispatcher::new(config());
    let latch: &'static crate::dispatch::handle::Latch =
        Box::leak(Box::new(crate::dispatch::handle::Latch::new()));
    d.judge_against(latch);
    let t = d.mint(0).expect("a ticket");
    let t = d.seed_count(t, u32::MAX - 1);
    d.recycle(t);
    until("the recycle lands", || d.slot_state(t).1);
    let last = d.mint(0).expect("a ticket");
    assert_eq!(last.slot, t.slot, "the slot's last count is handed out");
    assert_eq!(d.slot_state(last).2, u32::MAX);
    d.recycle(last);
    until("the last recycle lands", || !d.slot_state(last).0);
    let (_, free, count) = d.slot_state(last);
    assert!(!free, "a spent slot went back on the free list");
    assert_eq!(count, u32::MAX, "a spent counter wrapped");
    for _ in 0..8 {
        let n = d.mint(0).expect("a fresh slot");
        assert_ne!(n.slot, last.slot, "a retired slot was handed out again");
    }
    let stale0 = d.stats().stale_wakes;
    (d.conn_waker())(
        busbar_contract::conn::InstanceId(0),
        crate::dispatch::conn_services::conn_ticket(last),
    );
    until("the late wake is counted", || {
        d.stats().stale_wakes > stale0
    });
    assert_eq!(
        latch.forged(),
        0,
        "a retired slot's own generation was judged a forgery"
    );
}

struct LinkedSlot(std::sync::atomic::AtomicPtr<Door>);

impl LinkedSlot {
    const fn new() -> Self {
        Self(std::sync::atomic::AtomicPtr::new(std::ptr::null_mut()))
    }
    fn set(&self, d: Door) {
        self.0.store(
            Box::into_raw(Box::new(d)),
            std::sync::atomic::Ordering::SeqCst,
        );
    }
    fn get(&self) -> *const Door {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

static LINKED_ABI: LinkedSlot = LinkedSlot::new();
static LINKED_PIECE: LinkedSlot = LinkedSlot::new();
static LINKED_LAYOUT: LinkedSlot = LinkedSlot::new();

extern "C" fn linked_cell<const I: usize>() -> *const Door {
    [&LINKED_ABI, &LINKED_PIECE, &LINKED_LAYOUT][I].get()
}

extern "C" fn sealed_cell<const I: usize>() -> &'static Door {
    // SAFETY: every test sets its cell, to a door built through the contract's `unsafe`
    // constructor and leaked, before it calls this.
    unsafe { &*linked_cell::<I>() }
}

extern "C" fn ready_slot(
    _: *mut std::ffi::c_void,
    _: *const std::ffi::c_void,
    _: *mut std::ffi::c_void,
) -> busbar_contract::abi::mechanism::call::RawOutcome {
    busbar_contract::abi::mechanism::call::RawOutcome::of(Outcome::Ready)
}

fn whole_table<K: Kind>() -> *const busbar_contract::abi::mechanism::lifecycle::OpsHead {
    use busbar_contract::abi::mechanism::lifecycle::OpsHead;
    let size = crate::dispatch::host_table_size::<K>();
    let slots = crate::dispatch::host_slots::<K>();
    let words: &'static mut [u64] =
        Box::leak(vec![0u64; (size as usize).div_ceil(8)].into_boxed_slice());
    let head = words.as_mut_ptr().cast::<OpsHead>();
    // SAFETY: the buffer is `size` bytes (rounded up) of zeros, 8-aligned, leaked for the process; the
    // head and every slot lie inside it.
    unsafe {
        std::ptr::addr_of_mut!((*head).size).write(size);
        std::ptr::addr_of_mut!((*head).slots).write(slots);
        let first = head
            .cast::<u8>()
            .add(std::mem::offset_of!(OpsHead, validate))
            .cast::<Option<busbar_contract::abi::mechanism::call::Op>>();
        for i in 0..slots as usize {
            first.add(i).write(Some(
                ready_slot as busbar_contract::abi::mechanism::call::Op,
            ));
        }
    }
    head
}

fn door_over<K: Kind>(kind: KindCode, statement: Statement) -> Door {
    // SAFETY: the Statement is leaked for the process, and every slot of the table answers READY
    // under the call convention.
    unsafe {
        Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
            magic: DOOR_MAGIC,
            mechanism_version: MECHANISM_VERSION,
            size: std::mem::size_of::<Door>() as u32,
            kind: kind as u32,
            kind_abi: kind.abi_version(),
            statement: Box::leak(Box::new(statement)),
            ops: whole_table::<K>(),
            ready: None,
            layout: kind.layout_fingerprint(),
        })
    }
}

#[test]
fn open_linked_refuses_another_kind_abi_as_the_dropped_in_door_is_refused() {
    let abi = plug::KIND.abi_version();
    for v in [abi - 1, abi + 1] {
        let mut d = plug::door().parts();
        d.kind_abi = v;
        // SAFETY: the real door's own `'static` Statement and table, at another kind ABI.
        LINKED_ABI.set(unsafe { Door::__from_parts(d) });
        let door: busbar_contract::abi::sdk::door::RawDoorFn = linked_cell::<0>;
        // SAFETY: the cell's door function answers a `'static` door (a restated real door).
        let linked = unsafe { crate::dispatch::load::open_linked(door) }
            .expect_err("a linked door at another kind ABI is refused");

        assert_eq!(
            crate::dispatch::load::admit_linked(sealed_cell::<0>)
                .expect_err("the safe entry refuses it alike"),
            linked
        );
        let Err(dropped) = crate::dispatch::load::validate::<TestKind>(door) else {
            panic!("the dropped-in door at another kind ABI is refused");
        };
        assert_eq!(linked, dropped, "the same refusal, both ways");
        assert_eq!(
            linked,
            LoadError::KindAbi {
                kind: plug::KIND,
                door: v,
                host: abi
            }
        );
        assert_eq!(linked.to_string(), dropped.to_string());
    }
}

#[test]
fn open_linked_refuses_another_layout_as_the_dropped_in_door_is_refused() {
    use crate::dispatch::kinds::{plane::Plane, transport::Transport};
    use busbar_contract::abi::mechanism::call::AbiStr;
    use busbar_contract::abi::plane::{PlaneTail, ANSWER_LAYOUT};
    use busbar_contract::abi::transport::{Claim, FramePiece, TransportTail};
    const NAMES: &[AbiStr] = &[busbar_contract::abi::sdk::door::abi_str("tele")];
    // SAFETY: an all-zero Claim is a valid row (no strings, no lists).
    let row: &'static Claim = Box::leak(Box::new(unsafe { std::mem::zeroed::<Claim>() }));
    let piece_door = |piece: u32| {
        // SAFETY: an all-zero TransportTail is a valid value; its size, piece and rows are set.
        let mut t: TransportTail = unsafe { std::mem::zeroed() };
        t.head.size = std::mem::size_of::<TransportTail>() as u32;
        t.frame_piece_size = piece;
        t.claim_rows = row;
        t.claim_rows_len = 1;
        let tail = (Box::leak(Box::new(t)) as *const TransportTail).cast::<KindTailHead>();
        door_over::<Transport>(
            KindCode::Transport,
            Statement {
                size: std::mem::size_of::<Statement>() as u32,
                kind: KindCode::Transport as u32,
                kind_abi: KindCode::Transport.abi_version(),
                kind_tail: tail,
                claims: NAMES.as_ptr(),
                claims_len: NAMES.len(),
                ..busbar_contract::abi::sdk::door::statement("sockets", "1.0.0", 1)
            },
        )
    };
    let layout_door = |layout: u32| {
        // SAFETY: an all-zero PlaneTail is a valid value; its size and layout are set.
        let mut t: PlaneTail = unsafe { std::mem::zeroed() };
        t.head.size = std::mem::size_of::<PlaneTail>() as u32;
        t.answer_layout = layout;
        let tail = (Box::leak(Box::new(t)) as *const PlaneTail).cast::<KindTailHead>();
        door_over::<Plane>(
            KindCode::Plane,
            Statement {
                size: std::mem::size_of::<Statement>() as u32,
                kind: KindCode::Plane as u32,
                kind_abi: KindCode::Plane.abi_version(),
                kind_tail: tail,
                ..busbar_contract::abi::sdk::door::statement("tools", "1.0.0", 1)
            },
        )
    };
    let piece = std::mem::size_of::<FramePiece>() as u32;
    let piece_cell: busbar_contract::abi::sdk::door::RawDoorFn = linked_cell::<1>;
    let layout_cell: busbar_contract::abi::sdk::door::RawDoorFn = linked_cell::<2>;

    LINKED_PIECE.set(piece_door(piece));
    // SAFETY: the cell answers a `'static` door built above.
    assert!(unsafe { crate::dispatch::load::open_linked(piece_cell) }.is_ok());
    LINKED_LAYOUT.set(layout_door(ANSWER_LAYOUT));
    // SAFETY: as above.
    assert!(unsafe { crate::dispatch::load::open_linked(layout_cell) }.is_ok());

    LINKED_PIECE.set(piece_door(piece - 8));
    // SAFETY: as above.
    let linked = unsafe { crate::dispatch::load::open_linked(piece_cell) }
        .expect_err("a linked transport at another piece is refused");
    let Err(dropped) = crate::dispatch::load::validate::<Transport>(piece_cell) else {
        panic!("the dropped-in transport at another piece is refused");
    };
    assert_eq!(linked, dropped, "the same refusal, both ways");
    assert_eq!(
        linked,
        LoadError::FramePieceSize {
            plugin: "sockets".into(),
            stated: piece - 8,
            host: piece,
        }
    );

    LINKED_LAYOUT.set(layout_door(ANSWER_LAYOUT + 1));
    // SAFETY: as above.
    let linked = unsafe { crate::dispatch::load::open_linked(layout_cell) }
        .expect_err("a linked plane at another layout is refused");
    let Err(dropped) = crate::dispatch::load::validate::<Plane>(layout_cell) else {
        panic!("the dropped-in plane at another layout is refused");
    };
    assert_eq!(linked, dropped, "the same refusal, both ways");
    assert_eq!(
        linked,
        LoadError::PlaneLayout {
            plugin: "tools".into(),
            stated: ANSWER_LAYOUT + 1,
            host: ANSWER_LAYOUT,
        }
    );
}

fn another_layout_is_refused<K: Kind>(kind: KindCode) {
    let host = kind.layout_fingerprint();
    let own = door_over::<K>(
        kind,
        Statement {
            size: std::mem::size_of::<Statement>() as u32,
            kind: kind as u32,
            kind_abi: kind.abi_version(),
            ..busbar_contract::abi::sdk::door::statement("laid", "1.0.0", 1)
        },
    );
    assert_eq!(
        own.layout(),
        host,
        "{kind:?}: the door states the host's fingerprint"
    );
    assert!(
        !matches!(
            validate_door::<K>(&own).map(|_| ()),
            Err(LoadError::KindLayout { .. })
        ),
        "{kind:?}: a door at the host's fingerprint is not refused for its layout"
    );
    for stated in [host ^ 1, 0] {
        // SAFETY: the door's own parts, its layout word restated.
        let other = unsafe {
            Door::__from_parts(DoorParts {
                layout: stated,
                ..own.parts()
            })
        };
        let refused = validate_door::<K>(&other)
            .map(|_| ())
            .expect_err("a door at another layout is refused");
        assert_eq!(
            refused,
            LoadError::KindLayout {
                plugin: "laid".into(),
                kind,
                stated,
                host,
            },
            "{kind:?} at {stated:#018x}"
        );
    }
}

#[test]
fn a_store_door_built_against_another_layout_is_refused() {
    another_layout_is_refused::<crate::dispatch::kinds::store::Store>(KindCode::Store);
}

#[test]
fn a_secret_door_built_against_another_layout_is_refused() {
    another_layout_is_refused::<crate::dispatch::kinds::secret::Secret>(KindCode::Secret);
}

#[test]
fn an_auth_door_built_against_another_layout_is_refused() {
    another_layout_is_refused::<crate::dispatch::kinds::auth::Auth>(KindCode::Auth);
}

#[test]
fn a_hook_door_built_against_another_layout_is_refused() {
    another_layout_is_refused::<crate::dispatch::kinds::hook::Hook>(KindCode::Hook);
}

#[test]
fn an_export_door_built_against_another_layout_is_refused() {
    another_layout_is_refused::<crate::dispatch::kinds::export::Export>(KindCode::Export);
}

#[test]
fn a_plane_door_built_against_another_layout_is_refused() {
    another_layout_is_refused::<crate::dispatch::kinds::plane::Plane>(KindCode::Plane);
}

#[test]
fn a_transport_door_built_against_another_layout_is_refused() {
    another_layout_is_refused::<crate::dispatch::kinds::transport::Transport>(KindCode::Transport);
}

static CANCEL_NAMED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);

struct UnitKind;

impl Kind for UnitKind {
    const CODE: KindCode = plug::KIND;
    type Ops = OpsHead;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn context(
        st: &busbar_contract::abi::mechanism::door::Statement,
    ) -> Result<Option<Box<crate::dispatch::Context>>, String> {
        <TestKind as Kind>::context(st)
    }

    fn check(a: &crate::dispatch::Answer) -> Result<(), Fault> {
        <TestKind as Kind>::check(a)
    }

    fn short(a: &crate::dispatch::Answer) -> bool {
        <TestKind as Kind>::short(a)
    }

    fn unit_of(
        s: u32,
        input: *const busbar_contract::abi::mechanism::call::InHead,
        in_size: usize,
    ) -> Option<u64> {
        // SAFETY: the dispatcher's own `in` of `in_size` bytes, read only when it holds a whole
        // `TickIn`.
        (s == TICK && in_size >= std::mem::size_of::<TickIn>())
            .then(|| unsafe { input.cast::<TickIn>().read_unaligned() }.now_ns)
    }

    fn cancel_frame() -> Box<dyn crate::dispatch::CancelFrame> {
        Box::new(Naming(crate::dispatch::cancel_frame(Ticket::NONE)))
    }
}

struct Naming(
    Frame<
        busbar_contract::abi::mechanism::lifecycle::CancelIn,
        busbar_contract::abi::mechanism::lifecycle::CancelOut,
    >,
);

impl crate::dispatch::CancelFrame for Naming {
    fn prepare(
        &mut self,
        ticket: Ticket,
        class: u8,
    ) -> (
        *mut busbar_contract::abi::mechanism::call::InHead,
        *mut OutHead,
        u32,
    ) {
        crate::dispatch::CancelFrame::prepare(&mut self.0, ticket, class)
    }

    fn disposition(&self) -> u32 {
        crate::dispatch::CancelFrame::disposition(&self.0)
    }

    fn name_unit(&mut self, unit: u64) {
        CANCEL_NAMED.store(unit, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn red_a_client_drop_cancel_names_the_unit_its_op_serves() {
    let d = Dispatcher::new(config());
    let p = load_linked::<UnitKind>(&row(), bind(quiet())).expect("the linked door loads");
    let t = d.mint(0).expect("a ticket");
    let opened = d
        .submit(&p, t, slot::OPEN, open_frame(), DeadlineClass::Call, 0)
        .wait(WAIT)
        .expect("open answers");
    d.recycle(t);
    assert_eq!(opened.outcome, Outcome::Ready);
    let t = d.mint(0).expect("a ticket");
    let held = frame(plug::PEND_HOLD);
    let unit = held.input.now_ns;
    assert_ne!(unit, 0);
    let reply = d.submit(&p, t, TICK, held, DeadlineClass::Call, 0);
    until("the held op", || d.is_pending(t));
    d.drop_client(t);
    let done = reply.wait(WAIT).expect("the drop answers");
    d.recycle(t);
    assert_eq!(done.outcome, Outcome::Failed, "the kind's timeout outcome");
    assert_eq!(
        CANCEL_NAMED.load(std::sync::atomic::Ordering::SeqCst),
        unit,
        "the client-drop cancel named the unit its op serves"
    );
}

#[test]
fn red_close_is_refused_while_an_admitted_units_op_is_in_flight() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    let t = d.mint(0).unwrap();
    let held = d.submit_unit(
        &p,
        t,
        TICK,
        frame(plug::PEND_HOLD),
        DeadlineClass::Stream,
        0,
        Arc::new(()),
    );
    until("the unit's held op", || d.is_pending(t));
    let n = crossings(&p);
    assert_eq!(
        p.call(slot::CLOSE, &mut close_frame()).outcome,
        Outcome::Refused,
        "close crossed while a unit's op was in flight"
    );
    let c = d.mint(1).unwrap();
    let ticketed = d.submit(&p, c, slot::CLOSE, close_frame(), DeadlineClass::Call, 0);
    assert_eq!(ticketed.wait(WAIT).unwrap().outcome, Outcome::Refused);
    assert_eq!(crossings(&p), n, "a refused close never crossed");
    assert!(p.is_open());
    d.drop_client(t);
    let _ = held.wait(WAIT).unwrap();
    assert_eq!(
        p.call(slot::CLOSE, &mut close_frame()).outcome,
        Outcome::Ready
    );
    assert!(!p.is_open());
}

#[test]
fn red_a_replaced_workers_pending_op_of_a_healthy_instance_is_cancelled_before_its_memory_goes() {
    use crate::dispatch::framing_context;

    type ScopeIdentity = (u64, u64, u64, u64);
    static CANCEL_SCOPES: Mutex<Vec<Option<ScopeIdentity>>> = Mutex::new(Vec::new());

    struct ScopeKind;
    impl Kind for ScopeKind {
        const CODE: KindCode = TestKind::CODE;
        type Ops = OpsHead;
        const TIMEOUT: Outcome = TestKind::TIMEOUT;

        fn context(st: &Statement) -> Result<Option<Box<crate::dispatch::Context>>, String> {
            TestKind::context(st)
        }

        fn check(a: &crate::dispatch::Answer) -> Result<(), Fault> {
            if a.slot == slot::CANCEL {
                let identity = framing_context::current().map(|scope| {
                    (
                        scope.owner(),
                        scope.leg(),
                        scope.listener(),
                        scope.connection(),
                    )
                });
                CANCEL_SCOPES.lock().unwrap().push(identity);
            }
            TestKind::check(a)
        }

        fn short(a: &crate::dispatch::Answer) -> bool {
            TestKind::short(a)
        }
    }

    let d = Dispatcher::new(config());
    let sink = quiet();
    let healthy =
        load_linked::<ScopeKind>(&row(), bind(sink.clone())).expect("the linked door loads");
    let opening = d.mint(0).unwrap();
    assert_eq!(
        d.submit(
            &healthy,
            opening,
            slot::OPEN,
            open_frame(),
            DeadlineClass::Call,
            0
        )
        .wait(WAIT)
        .expect("open answers")
        .outcome,
        Outcome::Ready
    );
    d.recycle(opening);
    let context = d
        .framing_context(healthy.instance().0, 71, 0)
        .expect("host scope");
    let scope: Arc<dyn busbar_contract::framing_scope::FramingScope> = context.clone();
    let (owner, dropped) = lent(plug::PEND_HOLD);
    let t = d.mint(0).unwrap();
    let held = framing_context::with_context(Some(scope), || {
        d.submit_lent(
            &healthy,
            t,
            TICK,
            lent_frame(&owner),
            DeadlineClass::Call,
            0,
            owner.clone(),
        )
    });
    let caller_scope_restored = framing_context::current().is_none();
    drop(owner);
    until("the healthy op pends", || d.is_pending(t));
    let (wedger, _) = opened(&d);
    let h = d.mint(0).unwrap();
    let hung = d.submit(
        &wedger,
        h,
        TICK,
        frame(b"hang:orphan"),
        DeadlineClass::Call,
        0,
    );
    until("the watchdog replaced the wedged worker", || {
        d.stats().replacements == 1
    });
    until("the healthy instance's orphaned op is cancelled", || {
        count(&healthy, &sink).1 >= 1
    });
    assert_eq!(held.wait(WAIT).unwrap().outcome, Outcome::Fault);
    until("the orphan's lent memory goes after its cancel", || {
        dropped.load(std::sync::atomic::Ordering::SeqCst)
    });

    let (releaser, _) = opened(&d);
    assert_eq!(
        releaser.call(TICK, &mut frame(b"unhang:orphan")).outcome,
        Outcome::Ready
    );
    drop(hung);
    assert!(
        caller_scope_restored,
        "submission restores the caller's Scope"
    );
    assert_eq!(
        *CANCEL_SCOPES.lock().unwrap(),
        vec![Some((
            healthy.instance().0,
            context.leg(),
            71,
            context.connection(),
        ))],
        "orphan CANCEL retains its operation's Scope across the outer FFI hop"
    );
}

#[test]
fn red_an_inline_tickets_kept_results_go_at_its_next_op_and_with_the_ticket() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    let side = d.inline_ticket().expect("an inline ticket");
    let t = side.ticket();
    d.services().keep(t, 0);
    let _ = p.call_inline(t, true, TICK, &mut frame(answer(1)));
    assert_eq!(d.services().held(), 1, "a resume reads what its op kept");
    let _ = p.call_inline(t, false, TICK, &mut frame(answer(1)));
    assert_eq!(
        d.services().held(),
        0,
        "a new op on an inline ticket redeems the last op's kept results"
    );
    d.services().keep(t, 0);
    drop(side);
    assert_eq!(
        d.services().held(),
        0,
        "a dropped inline ticket's kept results outlive it"
    );
}

#[test]
fn a_path_both_secret_and_reference_capable_is_refused_at_load() {
    use busbar_contract::abi::mechanism::extensions::{
        encode, statement_blob, EXT_REFERENCE_FIELDS,
    };
    // SAFETY: the real door is `'static`.
    let real: Door = unsafe { *plug::busbar_plugin_door() };
    let st = unsafe { *real.statement() };
    let refs: &'static [busbar_contract::abi::mechanism::call::AbiStr] = Box::leak(Box::new([
        busbar_contract::abi::sdk::door::abi_str("token"),
        busbar_contract::abi::sdk::door::abi_str("url"),
    ]));
    let with = |reference: &[u8]| {
        let ext: &'static [u8] =
            Box::leak(encode(&[(EXT_REFERENCE_FIELDS, reference)]).into_boxed_slice());
        let stated: &'static Statement = Box::leak(Box::new(Statement {
            secret_refs: refs.as_ptr(),
            secret_refs_len: refs.len(),
            extensions: statement_blob(ext),
            ..st
        }));
        let mut d = real.parts();
        d.statement = stated;
        // SAFETY: a copy of the real door with its Statement replaced by a `'static` one.
        validate_door::<TestKind>(Box::leak(Box::new(unsafe { Door::__from_parts(d) }))).err()
    };
    assert_eq!(
        with(br#"["base", "endpoint.*"]"#),
        None,
        "distinct lists load"
    );
    let Some(LoadError::BadStatement(why)) = with(br#"["base", "url"]"#) else {
        panic!("a path in both lists is refused");
    };
    assert!(why.contains("url"), "{why}");
    assert!(
        matches!(with(br#"{"url": true}"#), Some(LoadError::BadStatement(_))),
        "a malformed list is refused"
    );
}
