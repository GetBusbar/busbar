// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE DISPATCHER, BOTH WAYS.** One test plugin LINKED (its
//! `rlib`'s door, through [`load_linked`]) and DROPPED (its `cdylib`, through [`load_dropped`]),
//! driven by ONE script, and the two transcripts compared byte for byte — and against the
//! transcript the mechanism's rules require.
//!
//! The script walks every rule: each outcome, outcome authority (a mismatched mirror, an unknown
//! byte, PENDING on NONE: all FAULT), the #85 envelope ingest, PENDING + wake (after, before —
//! latched —, spurious, stale generations, `wake_at_ns`), a Call deadline and a client drop (both
//! `cancel` then the timeout outcome), `max_inflight` (REFUSED without a call), a WriteBehind op
//! (never cancelled, detached at its deadline, a reload drain that does not wait on it, a late
//! completion), a driver ticket, and a hung op (the watchdog faults the instance, every ticket on
//! its worker FAULTs, a fresh worker serves the next instance).
//!
//! RED ARMS, kept: each rule also has its own test below, the door refusals included, and a panic
//! in a hand-written slot is shown to ABORT the process (in a subprocess).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::dispatch_test_plugin as plug;
use busbar_contract::abi::mechanism::call::{Blob, DeadlineClass, OutHead, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::check::{fault, Fault, Rule};
use busbar_contract::abi::mechanism::door::{Door, KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    slot, OpenIn, OpenOut, OpsHead, RefreshIn, TickIn, TickOut, ValidateIn, LIFECYCLE_SLOTS,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, MECHANISM_VERSION};

use crate::dispatch::load::validate_door;
use crate::dispatch::{
    in_head, load_dropped, load_linked, now_ns, out_head, rendering_of, Bind, Budgets, Diagnostic,
    DispatchConfig, Dispatcher, Dropped, EnvelopeSink, Frame, Kind, LinkedRow, LoadError,
    ManifestFacts, Metric, Plugin, NO_BLOB,
};

/// The test kind's context: the Statement's `max_inflight`, as bound.
#[derive(Debug, PartialEq, Eq)]
struct TestContext(u32);

/// The test plugin's kind, as the dispatcher sees it: its code, the lifecycle skeleton for a table
/// (a test kind with no ops of its own), FAILED on a timeout.
pub(crate) struct TestKind;
impl Kind for TestKind {
    const CODE: KindCode = plug::KIND;
    type Ops = OpsHead;
    const TIMEOUT: Outcome = Outcome::Failed;

    /// The test kind's context: a marker built from the Statement at bind.
    fn context(
        st: &busbar_contract::abi::mechanism::door::Statement,
    ) -> Result<Option<Box<crate::dispatch::Context>>, String> {
        Ok(Some(Box::new(TestContext(st.max_inflight))))
    }

    /// The test kind's `check_tick`: refuses [`plug::KIND_REJECTS`] on any outcome, and an answer
    /// judged without the instance's context.
    fn check(a: &crate::dispatch::Answer) -> Result<(), Fault> {
        if a.context::<TestContext>() != Some(&TestContext(2)) {
            return Err(fault(Rule::Missing, "test.context"));
        }
        if a.slot == TICK && a.out::<TickOut>()?.next_tick_ns == plug::KIND_REJECTS {
            return Err(fault(Rule::Contradiction, "tick.next_tick_ns"));
        }
        Ok(())
    }

    /// The test kind's short answer: `tick` FAILED with [`plug::SHORT`].
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

/// The plugin's Statement rendering, as its signed manifest states it: rendered from the linked
/// `rlib`'s door, the same crate the `cdylib` is built from.
fn stated() -> Vec<u8> {
    rendering_of(plug::busbar_plugin_door).expect("the door renders its Statement")
}

/// [`stated`] with its head facts replaced by `f`.
fn stated_with(f: ManifestFacts) -> Vec<u8> {
    let mut b = stated();
    b[8..12].copy_from_slice(&f.mechanism_version.to_le_bytes());
    b[12..16].copy_from_slice(&(f.kind as u32).to_le_bytes());
    b[16..20].copy_from_slice(&f.kind_abi.to_le_bytes());
    b
}

/// RED (THE DESIGN C.1, `BUSBAR-1.6.0.md` l.3868: "`Plugin<K>` is `!Clone`"): a loaded plugin's
/// handle cannot be copied; a holder that shares the instance shares an `Arc<Plugin<K>>`. The
/// probe below is AMBIGUOUS, and so does not compile, exactly when `Plugin<K>` implements `Clone`
/// (both impls of `NotClone` apply); with no `Clone` impl only the first applies.
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
    LinkedRow::of(plug::busbar_plugin_door).expect("the linked row states its Statement")
}

fn linked(sink: Arc<Recorder>) -> Plugin<TestKind> {
    load_linked::<TestKind>(&row(), bind(sink)).expect("the linked door loads")
}

/// The example `cdylib` `name` in this target dir; absent, a hard failure naming the command that
/// builds it, never a skip.
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

/// A `tick` frame whose extensions blob names the test op.
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

/// `answer:<byte>`.
fn answer(byte: u8) -> &'static [u8] {
    Box::leak(format!("answer:{byte}").into_bytes().into_boxed_slice())
}

/// `arm:<slot>:<generation>`.
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

/// A ticket-less `count`: `(invocations, cancels, drives)`, as the plugin's gauges reported them.
fn count(p: &Plugin<TestKind>, sink: &Recorder) -> (u32, u32, u32) {
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

/// `open` on a fresh ticket of `worker`.
fn open(d: &Dispatcher, p: &Plugin<TestKind>, worker: u32) -> Outcome {
    let t = d.mint(worker).expect("a ticket");
    let done = d
        .submit(p, t, slot::OPEN, open_frame(), DeadlineClass::Call, 0)
        .wait(WAIT)
        .expect("open answers");
    d.recycle(t);
    done.outcome
}

/// Run the ignored test `child` of this test binary in a child process, with `CHILD_ENV` set, and
/// answer how it ended: a range read past its buffer kills the child, never the test run.
pub(crate) fn run_child(child: &str) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().expect("the test binary's path"))
        .args([child, "--ignored", "--test-threads=1", "--nocapture"])
        .env(CHILD_ENV, "1")
        .output()
        .expect("run the child")
}

/// Set in a child [`run_child`] runs; an ignored child test run without it refuses to run.
pub(crate) const CHILD_ENV: &str = "BUSBAR_DISPATCH_CHILD";

/// Assert the child test `child` ran and passed (exit 0), naming how it ended otherwise.
pub(crate) fn assert_child_passes(child: &str, what: &str) {
    let out = run_child(child);
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

/// THE SCRIPT. `load` makes a fresh instance of the same origin (the watchdog step needs a second).
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

    // Each outcome, ticket-less; PENDING on NONE is a FAULT.
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

    // PENDING, and every kind of wake.
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

    // A Call deadline, then a client drop: `cancel`, then the kind's timeout outcome.
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

    // max_inflight: over the cap, REFUSED without a call.
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

    // WriteBehind: never cancelled; detached at its deadline; a drain does not wait on it.
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

    // A driver ticket: three wakes, three drives, outside max_inflight.
    let drv = d.driver(&p, 0).expect("a driver ticket");
    let armed = p.call(TICK, &mut frame(arm(drv))).outcome;
    // The plugin issues exactly three wakes, each only after the previous drive ran, and a wake
    // is at most one drive: three is final the moment it is seen.
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

    // The watchdog: a hung op faults its instance and replaces its worker.
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

/// The transcript the mechanism's rules require.
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

/// THE BOTH-WAYS PROOF: the same script, LINKED and DROPPED, byte-identical, and what the rules say.
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

// ── RED ARMS ─────────────────────────────────────────────────────────────────────────────────────

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
    ($($(#[$m:meta])* fn $name:ident($($arg:ident: $t:ty),* $(,)?) -> $ret:ty $body:block)*) => {
        $($(#[$m])* extern "C" fn $name($($arg: $t),*) -> $ret $body)*
    };
}
pub(crate) use c_abi;

/// RED (loader-PL1 #6): an `open` that PENDS and then answers FAULT on its RESUME leaves no
/// instance published (THE DESIGN §11.13; [`Plugin::is_open`]: "`open` answered READY"). The
/// restated `open` mints its box and pends; while it is in flight the instance is not open and a
/// non-lifecycle op is refused. Resumed, it frees the box (as the SDK frees a half-open box on any
/// outcome but READY/PENDING) and answers FAULT: the instance is not open, and neither a `close`
/// nor a `tick` ever hands the plugin the freed pointer.
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
    /// The box the resumed `open` freed.
    static FREED: AtomicUsize = AtomicUsize::new(0);
    /// Crossings that were handed the freed box.
    static STALE: AtomicU32 = AtomicU32::new(0);
    /// The pended `open`'s wake, its context and its ticket.
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
                close(instance, input, out);
                FREED.store(instance as usize, Ordering::SeqCst);
                return RawOutcome::of(Outcome::Fault);
            }
            let open: Op = ops.open.expect("the test plugin opens");
            let opened = open(instance, input, out);
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
            real().close.expect("the test plugin closes")(instance, input, out)
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
            real().tick.expect("the test plugin ticks")(instance, input, out)
        }

        fn door() -> *const Door {
            let have = SLOT.load(Ordering::SeqCst);
            if !have.is_null() {
                return have;
            }
            // SAFETY: the test plugin's door and its lifecycle table are `'static`.
            let real: Door = unsafe { plug::busbar_plugin_door().read_unaligned() };
            // SAFETY: as above.
            let ops: OpsHead = unsafe { real.ops.read_unaligned() };
            *REAL.lock().unwrap() = Some(ops);
            let ops: &'static OpsHead = Box::leak(Box::new(OpsHead {
                open: Some(open),
                close: Some(close),
                tick: Some(tick),
                ..ops
            }));
            let door = Box::into_raw(Box::new(Door { ops, ..real }));
            SLOT.store(door, Ordering::SeqCst);
            door
        }
    }

    #[test]
    fn red_an_open_that_faults_on_its_resume_leaves_no_instance() {
        let d = Dispatcher::new(config());
        let row = LinkedRow::of(door).expect("the restated door states itself");
        let p = load_linked::<TestKind>(&row, bind(quiet())).expect("it loads");

        let t = d.mint(0).expect("a ticket");
        let reply = d.submit(&p, t, slot::OPEN, open_frame(), DeadlineClass::Call, 0);
        until("the open pends", || d.is_pending(t));
        // While it is in flight (asserted last, so the FAULT arm below is the one a regression
        // names first).
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

/// RED (loader-PL1 #6, no leak): an `open` that leaves the plugin holding a live box it will never
/// be asked to close — one the plugin answered READY or PENDING but the host judged FAULT (a
/// PENDING on a ticket-less crossing; a READY whose mirror disagrees), or a pended one the host
/// cancelled (a deadline, a client drop). The host closes the box once the open is over: a
/// counting plugin's instances opened minus closed is 0, nothing is published as open, a late
/// caller's `close` is refused, and no box is ever closed twice. The tests share the counting
/// door, so they run one at a time ([`SERIAL`]).
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

    /// One test at a time over the shared counts.
    static SERIAL: Mutex<()> = Mutex::new(());

    static REAL: Mutex<Option<OpsHead>> = Mutex::new(None);
    static SLOT: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
    /// The boxes the plugin minted and has not closed.
    static LIVE: Mutex<Vec<usize>> = Mutex::new(Vec::new());
    /// `close`s handed a box that is not live (closed twice, or never minted).
    static STALE: AtomicU32 = AtomicU32::new(0);
    /// How the restated `open` answers once it minted its box.
    static MODE: AtomicU8 = AtomicU8::new(PEND);
    /// PENDING (the host FAULTs it on a ticket-less crossing).
    const PEND: u8 = 0;
    /// READY, with a mirror that says FAILED (the host FAULTs the disagreement).
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
            let opened = real().open.expect("the test plugin opens")(instance, input, out);
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
            close(instance, input, out)
        }

        fn door() -> *const Door {
            let have = SLOT.load(Ordering::SeqCst);
            if !have.is_null() {
                return have;
            }
            // SAFETY: the test plugin's door and its lifecycle table are `'static`.
            let real: Door = unsafe { plug::busbar_plugin_door().read_unaligned() };
            // SAFETY: as above.
            let ops: OpsHead = unsafe { real.ops.read_unaligned() };
            *REAL.lock().unwrap() = Some(ops);
            let ops: &'static OpsHead = Box::leak(Box::new(OpsHead {
                open: Some(open),
                close: Some(close),
                ..ops
            }));
            let door = Box::into_raw(Box::new(Door { ops, ..real }));
            SLOT.store(door, Ordering::SeqCst);
            door
        }
    }

    #[test]
    fn red_an_open_the_host_judged_fault_is_closed_never_leaked() {
        let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let d = Dispatcher::new(config());
        let row = LinkedRow::of(door).expect("the restated door states itself");

        // A ticket-less `open` that answers PENDING: the host FAULTs it.
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

        // A ticketed `open` that answers READY under a mirror that disagrees: the host FAULTs it.
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

    /// A ticketed `open` that pends (no wake comes), ended by the host: `cancel` then `close`.
    fn pended(d: &Dispatcher) -> (Plugin<TestKind>, Ticket) {
        MODE.store(PEND, Ordering::SeqCst);
        let row = LinkedRow::of(door).expect("the restated door states itself");
        let p = load_linked::<TestKind>(&row, bind(quiet())).expect("it loads");
        let t = d.mint(0).expect("a ticket");
        (p, t)
    }

    #[test]
    fn red_a_cancelled_pended_open_is_closed_once() {
        let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let d = Dispatcher::new(config());

        // Its deadline passes while it pends: the host cancels it.
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

        // Its client goes away while it pends: the host cancels it.
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

        // The caller that never got an instance closes anyway, on a ticket and without one.
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
    // The GREEN twin: the same op answering honestly is READY.
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
    // The slot comes back once the recycle landed, one generation on.
    let t = loop {
        let t = d.mint(0).unwrap();
        if t.slot == old.slot {
            break t;
        }
    };
    // One mint on: the generation is the slot's next COUNT, permuted (#74), never the next integer.
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
    // Woken from INSIDE a crossing of `p`, so a forgery would have someone to quarantine.
    crate::dispatch::plugin::with_crossing(Some(&*p.inner), || {
        crate::dispatch::ticket::host_wake(p.inner.ctx(), old);
    });
    until("the stale wake is counted", || {
        d.stats().stale_wakes > stale0
    });
    // A generation the slot really minted is a late wake, not a forgery (#74): the instance that
    // woke it is not quarantined.
    assert!(
        !p.is_faulted(),
        "a stale wake for a generation the host minted was judged a forgery"
    );
    // The wake was processed (counted) and resumed nothing: no crossing happened.
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
    // The RED twin: a Call-class op holds the drain.
    let t = d.mint(1).unwrap();
    let rt = d.submit(&p, t, TICK, frame(plug::PEND_HOLD), DeadlineClass::Call, 0);
    until("the call pends", || d.is_pending(t));
    assert!(
        !d.drain(&p, Duration::from_millis(100)),
        "a pending Call op must hold the drain"
    );
    // Its client drop cancels it (the one cancel); the WriteBehind op's did not.
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

/// Every door refusal, on copies of the real door with one field wrong.
#[test]
fn red_every_door_refusal() {
    // SAFETY: the real door is `'static`.
    let real: Door = unsafe { *plug::busbar_plugin_door() };
    let ops: OpsHead = unsafe { *real.ops };
    let st = unsafe { *real.statement };
    let leak_ops = |o: OpsHead| Box::leak(Box::new(o)) as *const OpsHead;
    let with = |f: &dyn Fn(&mut Door)| {
        let mut d = real;
        f(&mut d);
        validate_door::<TestKind>(Box::leak(Box::new(d))).err()
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
    // THE STATEMENT'S LISTS (the design's One Statement): marks, rewrites, sections, needs and
    // answers are judged at load, the same for either origin.
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

/// A door that states nothing: a linked row whose load fails (`LoadError::NullDoor`).
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
    assert_eq!(LinkedRow::of(null_door).err(), Some(LoadError::NullDoor));
    // The manifest's mechanism is checked BEFORE dlopen: a path that does not exist is never opened.
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
    // A manifest that states no rendering head is refused before dlopen, too.
    assert!(matches!(
        load_dropped::<TestKind>(nowhere, b"{}", bind(quiet())).err(),
        Some(LoadError::Rendering(_))
    ));
    // A library that is not a 1.6.0 plugin exports no door: the platform's C library.
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

/// RED, BOTH ORIGINS: a Statement other than the one the manifest (or the compiled-in row) states
/// is refused at admit, naming the repack; the same rendering is admitted.
#[test]
fn red_a_statement_other_than_the_stated_one_is_refused_at_admit() {
    assert_eq!(facts(), ManifestFacts::read(&stated()).unwrap());
    let mut lying = stated();
    let last = lying.len() - 1;
    lying[last] ^= 1;
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
    assert_eq!(
        load_linked::<TestKind>(&short_row, bind(quiet())).err(),
        Some(LoadError::StatementMismatch)
    );
    assert!(load_linked::<TestKind>(&row(), bind(quiet())).is_ok());
    let path = dropped_path();
    assert_eq!(
        load_dropped::<TestKind>(&path, &lying, bind(quiet())).err(),
        Some(LoadError::StatementMismatch)
    );
    assert!(load_dropped::<TestKind>(&path, &stated(), bind(quiet())).is_ok());
}

/// THE PACK-TIME RENDERING: the dropped `cdylib`'s own door renders the same Statement the linked
/// `rlib`'s door does (what the pack tool signs); a library with no door states none.
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

/// The child half of the abort test: runs only when its parent sets the variable. Ignored so the
/// default run never counts it as a pass: alone it proves nothing, and run without the variable it
/// fails (status row 114).
#[test]
#[ignore = "child process of red_a_panic_in_a_hand_written_slot_aborts, which runs it with --ignored"]
fn panic_child() {
    let Ok(origin) = std::env::var("BUSBAR_M1_PANIC_CHILD") else {
        panic!("panic_child is the child half of red_a_panic_in_a_hand_written_slot_aborts");
    };
    let p = if origin == "dropped" {
        dropped(quiet())
    } else {
        linked(quiet())
    };
    let d = Dispatcher::new(config());
    assert_eq!(open(&d, &p, 0), Outcome::Ready);
    let _ = p.call(TICK, &mut frame(plug::PANIC));
    // Unreachable: the panic escapes a C-ABI slot and the process aborts.
    std::process::exit(0);
}

/// A panic that escapes a hand-written slot ABORTS the process — in both origins.
#[test]
fn red_a_panic_in_a_hand_written_slot_aborts() {
    // An absent dropped door fails here, naming its build command, not in the child.
    dropped_path();
    for origin in ["linked", "dropped"] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "dispatch_tests::panic_child",
                "--ignored",
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

// ── VALIDATE EVERY ANSWER: one RED arm per check ────────────────────────────────────────

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
    // The GREEN twin: the same op with an answer the validator accepts.
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

// ── EXACT VERSIONS: older, newer and a wrong magic are each refused ─────────────────────────────

fn door_with(f: impl Fn(&mut Door)) -> Option<LoadError> {
    // SAFETY: the real door is `'static`.
    let mut d = unsafe { *plug::busbar_plugin_door() };
    f(&mut d);
    validate_door::<TestKind>(Box::leak(Box::new(d))).err()
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

// ── CLOSE, TEXT CAPS, THE WATCHDOG, UNLOADS, CANCEL DISPOSITIONS ──────────────────────────────────────────────────────────────

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
    // The GREEN twin: with nothing in flight, close crosses and closes.
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
    // A late wake on the driver, then a ticketed op on the same worker: the worker handles its
    // messages in order, so when the op answers the wake has been handled.
    crate::dispatch::ticket::host_wake(p.inner.ctx(), drv);
    let t = d.mint(0).unwrap();
    let after = d.submit(&p, t, TICK, frame(answer(1)), DeadlineClass::Call, 0);
    assert_eq!(after.wait(WAIT).unwrap().outcome, Outcome::Fault);
    assert_eq!(p.call(TICK, &mut frame(answer(1))).outcome, Outcome::Fault);
    assert_eq!(crossings(&p), n, "nothing crossed into a closed instance");
}

#[test]
fn red_a_close_that_faults_leaves_the_instance_closed() {
    // C1 M5 (c), the loader's backstop: a door whose `close` freed its instance and then answered
    // FAULT. The host treats the instance as closed: nothing crosses into it again, a second
    // `close` included (it would free the memory twice).
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
    // Through a crossing: the answer is FAULT and nothing is read.
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
    // One instance, shared with the hung caller (a `Plugin` is `!Clone`).
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

/// THE DESIGN A.8: "on a breach of the threshold, N times, the instance is quarantined". With
/// N = 2 the first breach is counted ONCE (however many scans see the call hung), the instance
/// keeps serving, and nothing is quarantined; the second breach quarantines it, counts
/// `bb_plugin_quarantined_total`, and every new call is FAULT without a crossing.
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
    // Several scans pass while the call stays hung; it is still one breach.
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
    // The caller's `out` holds garbage that reads as a READY mirror; a plugin that returns READY
    // without writing the mirror must still be FAULT, which only a zeroed `out` makes it.
    let mut f = frame(plug::SILENT);
    f.out.head.outcome = busbar_contract::abi::mechanism::call::RawOutcome::of(Outcome::Ready);
    f.out.head.lease = 0xBAD;
    f.out.next_tick_ns = 0xBAD;
    let c = p.call(TICK, &mut f);
    assert_eq!(c.outcome, Outcome::Fault);
    assert_eq!(f.out.next_tick_ns, 0, "the tail was zeroed too");
}

#[test]
fn an_unload_runs_on_the_reaper_never_under_a_worker_lock() {
    use crate::dispatch::load::UNLOADS;
    use std::sync::atomic::Ordering::SeqCst;
    let d = Dispatcher::new(config());
    let p = dropped(quiet());
    assert_eq!(open(&d, &p, 0), Outcome::Ready);
    let drv = d.driver(&p, 0).unwrap();
    let gone = std::sync::Arc::downgrade(&p.inner);
    let unloads0 = UNLOADS.load(SeqCst);
    // The driver holds the last reference; a recycle drops it on the worker, under its lock. The
    // unload is handed to the reaper, which runs it after (and apart from) the worker.
    drop(p);
    d.recycle(drv);
    until("the instance is gone", || gone.strong_count() == 0);
    until("the reaper unloaded the library", || {
        UNLOADS.load(SeqCst) > unloads0
    });
}

#[test]
fn red_a_hanging_unload_faults_no_innocent_instance() {
    use crate::dispatch::load::reap;
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    // An unload that hangs: it wedges only the reaper.
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
    // Past every budget of the test config, the innocent instance still crosses and is not faulted.
    std::thread::sleep(config().budgets.call * 2);
    assert!(!p.is_faulted());
    assert_eq!(p.call(TICK, &mut frame(answer(1))).outcome, Outcome::Ready);
    let t = d.mint(0).unwrap();
    let r = d.submit(&p, t, TICK, frame(answer(1)), DeadlineClass::Call, 0);
    assert_eq!(r.wait(WAIT).unwrap().outcome, Outcome::Ready);
    assert_eq!(d.stats().replacements, 0, "no worker was replaced");
    release.send(()).unwrap();
}

/// A HANGING UNLOAD HOLDS BACK NO OTHER UNLOAD: while one library's `.fini_array` hangs, the next
/// unload still runs, on a reaper of its own. RED on a single shared reaper thread: the second
/// unload queues behind the wedged one and never runs while it hangs (this is also why a test that
/// wedges the reaper starved `an_unload_runs_on_the_reaper_never_under_a_worker_lock` whenever the
/// two ran together).
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

/// A HUNG UNLOAD IS OBSERVABLE: past its bound the watch warns of it, and while it hangs its reaper
/// is counted live in the dispatcher's stats. RED without the
/// watch and the count: nothing reports the hang.
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
    // The token is spent here; a second `recall` with it does not compile (the `Recall` doc test).
    let again = p.recall(token, TICK, &mut frame(plug::SHORT_ANSWER));
    assert_eq!(
        again.outcome,
        Outcome::Fault,
        "short again on the re-call is FAULT"
    );
    assert!(again.recall.is_none());
    // A fresh short answer, re-called with an answer that fits: READY.
    let token = p.call(TICK, &mut frame(plug::SHORT_ANSWER)).recall.unwrap();
    assert_eq!(
        p.recall(token, TICK, &mut frame(answer(1))).outcome,
        Outcome::Ready
    );
    // A token is bound to its instance and op.
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
    // Ticketed: the reply says short; the dispatcher enforces the one re-call on the ticket.
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
    // No submit ever reached the dispatcher: the instance was adopted at bind.
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
    // Opened before the drive wedges worker 0 (its crossing holds that worker).
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
    // A drive holds no max_inflight unit: only the crossing gate refuses the close.
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
    // Once the drive returns, the gate opens and close crosses.
    until("close after the drive", || {
        p.call(slot::CLOSE, &mut close_frame()).outcome == Outcome::Ready
    });
    assert!(!p.is_open());
}

#[test]
fn red_a_kind_check_judges_every_outcome_in_its_bound_context() {
    let d = Dispatcher::new(config());
    let (p, _sink) = opened(&d);
    // REFUSED is judged too: the test kind's rule fires on it.
    assert_eq!(
        p.call(TICK, &mut frame(plug::REJECTED_REFUSED)).outcome,
        Outcome::Fault
    );
    // The GREEN twin: an honest REFUSED answer stays REFUSED.
    assert_eq!(
        p.call(TICK, &mut frame(answer(4))).outcome,
        Outcome::Refused
    );
    // Every crossing carried the context built from the Statement at bind (the check FAULTs
    // without it), so every READY above and in the whole suite proves it arrived.
    assert_eq!(p.call(TICK, &mut frame(answer(1))).outcome, Outcome::Ready);
}

// ── THE ASYNC COMPLETION ─────────────────────────────────────────────────────────────────────────

/// A runtime with ONE thread: an await that blocked it would deadlock.
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
    // A pend that completes only on a wake from another thread, awaited on the one thread.
    let t = d.mint(0).unwrap();
    let reply = d.submit(&p, t, TICK, frame(plug::PEND_AFTER), DeadlineClass::Call, 0);
    let done = rt.block_on(async {
        tokio::time::timeout(WAIT, reply)
            .await
            .expect("the awaited reply completes")
    });
    assert_eq!(done.outcome, Outcome::Ready);
    // Two ops awaited together on the one thread, each answered by a worker.
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
    // The sync path reads the same slot.
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
    // Poll it once on the one thread (it registers its waker and pends), then drop the future.
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
    // A wake after the drop: nothing crosses.
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
    // The probe crossed once; the late wake resumed nothing.
    assert_eq!(
        p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst),
        n + 1
    );
    // The GREEN twin: a detached reply is not a client drop.
    let w = d.mint(1).unwrap();
    d.submit(&p, w, TICK, frame(plug::PEND_HOLD), DeadlineClass::Call, 0)
        .detach();
    until("the detached op pends", || d.is_pending(w));
    assert_eq!(count(&p, &sink).1, 1, "a detached reply cancels nothing");
    assert_eq!(p.call(TICK, &mut frame(plug::KICK)).outcome, Outcome::Ready);
    until("the detached op completes", || !d.is_pending(w));
}

/// Host-lent memory whose drop the test can see: the bytes a `tick` frame's extensions blob points
/// at, owned here and nowhere else but the dispatcher's job.
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

/// A `tick` frame over `lent`'s bytes (NOT `'static`: the pointer is only as good as `lent`).
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

/// RED (ARCHITECT ruling 2026-09-29, every kind): the caller DROPS its `Reply` while the plugin is
/// still inside a crossing reading host-lent memory (`hang:<key>` re-reads its key from the lent
/// blob every 5ms until released), and drops its own owner too. The memory must live until the
/// crossing RETURNS — through the watchdog tripping and replacing the worker meanwhile — and go
/// once it has. Without the dispatcher holding the owner, the memory is freed at the caller's drop,
/// under a plugin still reading it.
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
    // Past the watchdog's 400ms budget: the instance is faulted and the worker replaced, while the
    // hung thread still reads the lent blob.
    until("the watchdog replaced the hung worker", || {
        d.stats().replacements == 1
    });
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        !dropped.load(std::sync::atomic::Ordering::SeqCst),
        "the lent memory must outlive a crossing that has not returned"
    );
    // Release the hang from a second instance (the first is faulted); the crossing returns.
    let (p2, _) = opened(&d);
    assert_eq!(
        p2.call(TICK, &mut frame(b"unhang:lent")).outcome,
        Outcome::Ready
    );
    until("the lent memory goes once the crossing returned", || {
        dropped.load(std::sync::atomic::Ordering::SeqCst)
    });
}

/// The PENDING twin: a dropped `Reply` on a pending op cancels it; the lent memory lives through
/// the `cancel` and goes after it, never at the caller's drop.
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

/// Bind states the instance to the host services by the host's label for it, beside the plugin's
/// Statement name and its kind; the kernel keys every per-instance fact by the label.
#[test]
fn bind_states_the_caller_to_the_host_services() {
    let p = linked(quiet());
    let caller = p.inner.wake.caller.get().expect("bind states a caller");
    assert_eq!(&*caller.instance, "the-instance");
    assert_eq!(&*caller.plugin, p.inner.name());
    assert_eq!(caller.kind, p.inner.kind);
}

/// Two instances of one plugin share its Statement name and are two callers: each is known by its
/// own label.
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

/// THE ONE SOURCE OF CLAIM NAMES, AT ADMIT (ARCHITECT ruling 2026-09-29 (A)): a transport's
/// Statement names its claimed schemes and its tail carries one row per name. RED: a transport
/// Statement naming two schemes over a tail with one row is refused at admit; one name over one
/// row, and a non-transport Statement's tail, pass.
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
    // A kind with no tail rule at admit (a plane's states its answer layout, judged below in
    // `a_plane_built_against_another_answer_layout_is_refused_at_load`).
    assert!(crate::dispatch::load::kind_tail(&st(0, KindCode::Hook)).is_ok());
    // A transport naming claims with no tail at all has no rows: refused, not skipped.
    let untailed = Statement {
        kind_tail: std::ptr::null(),
        ..st(1, KindCode::Transport)
    };
    assert!(matches!(
        crate::dispatch::load::kind_tail(&untailed),
        Err(LoadError::KindTail(_))
    ));
}

/// THE PIECE STRIDE AT LOAD (busbar #1032): a framer writes `FramerSink::pieces` at its own
/// `FramePiece` size, and the host reads them at its own. RED: a transport whose tail states a
/// piece size other than the host's (the 40-byte piece before #1032), or none (a tail that
/// predates the word), is refused at load, naming the plugin, both sizes and the rebuild. GREEN:
/// the host's size loads.
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
    // Through the load path's own Statement read (`validate`, the pack tool's rendering and
    // `statement_of` all go through it), on a transport door.
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
        let door = Door {
            magic: DOOR_MAGIC,
            mechanism_version: MECHANISM_VERSION,
            size: std::mem::size_of::<Door>() as u32,
            kind: KindCode::Transport as u32,
            kind_abi: KindCode::Transport.abi_version(),
            statement: st,
            ops: std::ptr::null(),
            ready: None,
        };
        crate::dispatch::load::statement(&door).map(|_| ())
    };
    let whole = std::mem::size_of::<TransportTail>();

    // GREEN: the host's piece loads.
    assert_eq!(load(tail(whole, host)), Ok(()), "the host's piece loads");

    // RED: the piece before #1032, read at the wrong stride, is refused.
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

    // RED: a tail that stops short of the word (built before it) states no piece: refused the same.
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

/// THE PLANE'S ANSWER LAYOUT AT LOAD: a plane writes every `out` at its own layout (`OnPieceOut`
/// grew 240 -> 248 bytes and `ArriveOut`'s padding became `refusal_flags` under plane ABI v1), and
/// the host reads them at its own. RED: a plane whose tail states another `ANSWER_LAYOUT` than the
/// host's, or none (a tail that predates the word), is refused at load, naming the plugin, both
/// layouts and the rebuild. GREEN: the host's layout loads.
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
    // Through the load path's own Statement read (`validate`, the pack tool's rendering and
    // `statement_of` all go through it), on a plane door.
    let load = |kind_tail: *const KindTailHead| {
        let st: &'static Statement = Box::leak(Box::new(Statement {
            size: std::mem::size_of::<Statement>() as u32,
            kind: KindCode::Plane as u32,
            kind_abi: KindCode::Plane.abi_version(),
            kind_tail,
            ..busbar_contract::abi::sdk::door::statement("tools", "1.0.0", 1)
        }));
        let door = Door {
            magic: DOOR_MAGIC,
            mechanism_version: MECHANISM_VERSION,
            size: std::mem::size_of::<Door>() as u32,
            kind: KindCode::Plane as u32,
            kind_abi: KindCode::Plane.abi_version(),
            statement: st,
            ops: std::ptr::null(),
            ready: None,
        };
        crate::dispatch::load::statement(&door).map(|_| ())
    };
    let whole = std::mem::size_of::<PlaneTail>();

    // GREEN: the host's layout loads.
    assert_eq!(load(tail(whole, host)), Ok(()), "the host's layout loads");

    // RED: a plane built against another contract's answers is refused, older and newer alike.
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

    // RED: a tail that stops short of the word (built before it) states no layout: refused the
    // same, never read past its end.
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

// ── THE WORKERS' RUNTIME ─────────────────────────────────────────────────────────────────────────

/// RED: the runtime the workers run their crossings inside is INSTALLED, never captured: a
/// dispatcher built, and first submitted to, inside a runtime nobody drives (the control runtime,
/// whose thread then waits synchronously on the op) does not bind its workers to that runtime; the
/// one the host installs does, and a second install is ignored.
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

/// #74, ONE GUESS: an instance that hands the host's `wake` a context the host did not mint, from
/// inside its own crossing, is quarantined (N = 1). The crossing is a `tick`, a lifecycle op, so
/// this is the FFI-worker path: the mark travels with the crossing onto the plugin thread. The
/// forging op ITSELF answers FAULT (its answer is not judged and its envelope not read), the
/// instance is faulted and its every later op is FAULT without a crossing, and its own handle is
/// REVOKED. The control: an instance that only hands back its own context is never faulted.
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

/// #74, IN A REAL CROSSING: another instance's handle is a forgery, revoked or not, and quarantines
/// the instance crossing; the latch does not move (the forgery had someone to blame). Driven under
/// `with_crossing` with a real instance, as a crossing states it.
#[test]
fn inside_a_crossing_another_instances_handle_quarantines_the_crossing() {
    let d = Dispatcher::new(config());
    let crossing = linked(Arc::new(Recorder::default()));
    assert_eq!(open(&d, &crossing, 0), Outcome::Ready);
    let other = linked(Arc::new(Recorder::default()));
    let (own_ctx, other_ctx) = (crossing.inner.ctx(), other.inner.ctx());
    // The other instance revoked first: a revoked handle of ANOTHER instance is still a forgery.
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

/// #74, THE INLINE HOT-LANE SLOT: a call into plugin code that is no mechanism crossing, nested in
/// one, runs with the mark nulled. A forgery made inside it blames no one (the outer instance stays
/// unquarantined, the latch counts it) and the outer crossing's mark is restored after it.
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

/// #74, REVOCATION: a closed instance's handle, a dropped one's and a watchdog-faulted one's name
/// nothing, and none of the three is counted as a forgery (their tags are the host's own).
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

/// #74, REVOCATION ON THE WATCHDOG'S TICKET-LESS PATH: an instance adopted by the dispatcher whose
/// ticket-less call hangs past its budget is faulted by the watchdog (`ticketless`), and its handle
/// names nothing from then on, with no forgery counted.
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
        let caller = scope.spawn(|| hung.call(TICK, &mut frame(b"hang:ticketless")).outcome);
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
        let _ = releaser.call(TICK, &mut frame(b"unhang:ticketless"));
        let _ = caller.join();
    });
    assert_eq!(
        latch.forged(),
        0,
        "a revoked handle was counted as a forgery"
    );
}

/// #74, THE KEY AT BOOT: a loader boot whose OS random source cannot answer is refused
/// (`LoadError::Entropy`), the dispatcher never built; there is no fallback key. Driven through the
/// test seam, which makes this thread's draw a fresh one against a failing source.
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

/// #74, THE TICKET HALF: a wake for a generation the host never minted is a FORGERY. The generation
/// is a keyed permutation of the slot's counter, so the worker names the mint it would be by the
/// inverse and finds none; the instance whose context woke it (its supplier) is quarantined (its
/// handle revoked, every later op FAULT). The control: an honest instance stays unfaulted.
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

/// A generation of `t`'s slot the host never minted, but for a 1-in-2^32 chance.
fn forged_generation(t: Ticket) -> Ticket {
    Ticket {
        slot: t.slot,
        generation: t.generation ^ 0x5a5a_5a5a,
    }
}

/// RED (#74, ATTRIBUTION CARRIED, NEVER READ OFF THE THREAD): instance A takes a service call on a
/// forged ticket; its completion fires from inside instance B's crossing. The completer carries A
/// as the ticket's supplier, so A is quarantined and B, the crossing the wake happened to fire in,
/// is not. A wake that read the thread's crossing would blame B.
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

/// RED (#74, NO ONE TO BLAME): a forged generation the HOST wakes for itself (the connector's
/// readiness under the root's own identity, which no instance's context named) counts toward the
/// latch and quarantines no one; a plugin's own wake from its own thread, outside any crossing,
/// names its supplier and quarantines it, the latch unmoved. Judged against this test's own latch.
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

    // The root's own identity on the connector: no instance supplied the ticket.
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

/// A test latch of the test's own, judged against by `d`.
fn own_latch(d: &Dispatcher) -> &'static crate::dispatch::handle::Latch {
    let latch: &'static crate::dispatch::handle::Latch =
        Box::leak(Box::new(crate::dispatch::handle::Latch::new()));
    d.judge_against(latch);
    latch
}

/// RED (#74, INLINE TICKETS): an inline ticket's generation is the keyed permutation of its slot's
/// counter, as a worker slot's, so a plugin that guesses `encode(INLINE_WORKER, i)` with a small
/// generation (what the plain counter from 1 handed out) does not hit a held ticket, and its miss is
/// a FORGERY: the supplier is quarantined, the latch unmoved. A guess at an inline slot no ticket
/// ever used is a forgery too.
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

/// RED (THE PLANE `serve` THAT DIALS): an op that must wait on an outbound dial answers PENDING
/// (Ready|Pending(wake), BUSBAR-1.6.0.md line 1282); the dial's framing crosses the FRAMER on an
/// inline ticket of its own, nested INSIDE the op's instance's crossing (its connection service
/// drives the connector on its thread), and the framer's new op starts a new epoch of that ticket's
/// stored results. That bookkeeping is the host's own: it blames neither instance, so the wake
/// resumes the op and it answers READY. Before the fix the host resolved the framer's context as if
/// a plugin had handed it inside the outer crossing: "another instance's handle", a forgery, and
/// the outer instance was quarantined, so its resumed op answered FAULT.
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
    // The dial is framed: the framer's `begin` on its own inline ticket, inside the op's crossing.
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
    // The dial completes: the wake resumes the op, which answers READY.
    assert_eq!(
        plane.call(TICK, &mut frame(plug::KICK)).outcome,
        Outcome::Ready
    );
    let done = serving.wait(WAIT).expect("the op answers");
    assert_eq!(done.outcome, Outcome::Ready, "the resumed op");
    drop(side);
    d.recycle(t);
}

/// RED (#74, INLINE WRAP AND LATE WAKES): an inline slot whose counter is spent is RETIRED, never
/// handed out again, and a late wake for a generation it really minted is not a forgery.
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

/// RED (#74, A HELD WAKER OUTLIVES ITS GENERATION): the host's I/O holds the waker of an inline
/// ticket's task (`waker_of`, what `io.*` registers with the reactor); the connection ends, the slot
/// is recycled and re-minted to a new connection whose task registers. The old readiness then fires:
/// it wakes NEITHER task (the old one's waker went with its generation, the new one's is not its
/// to wake). The control: the new generation's own waker wakes the new task.
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

/// RED (#74, A WAKE RACING A RECYCLE): a wake for an inline ticket looks the slot up; between that
/// lookup and the wake (the test hook), the ticket is dropped and the slot re-minted to a new task.
/// The wake checks the generation and takes the waker in one section, so it reaches no task: it is
/// a late wake of a generation the slot minted, not a forgery. A check made outside the section
/// would wake the new task.
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

/// RED (#74, A WORKER THE DISPATCHER DOES NOT RUN): a wake for `encode(n, 0)`, `n` past the
/// dispatcher's workers and short of the inline worker, names a slot nothing minted: a forgery,
/// blamed on its supplier, not merely a stale wake.
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

/// RED (#74, COUNTER WRAP): a slot whose mint counter is spent is RETIRED, never handed out again:
/// a counter that wrapped would re-mint generations the slot already handed out, and a plugin that
/// kept one would wake the slot's next op. Seeded one short of `u32::MAX`; the slot's last mint is
/// at `u32::MAX`; after it the worker takes fresh slots, and a wake on the retired slot's last
/// generation is a late wake, not a forgery.
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

// ── the client-drop `cancel` names the unit its op serves ──────────────────────────────────────

/// The unit the last client-drop `cancel` of a [`UnitKind`] op named.
static CANCEL_NAMED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);

/// The test kind, its ops serving a unit: a `tick`'s `now_ns` stands for the unit key its `in`
/// carries (as a plane's `OnPieceIn::unit` does), and its `cancel` frame records the unit it is
/// told to name (as a plane's `PlaneCancelIn::unit`).
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

/// The lifecycle's `cancel` frame, recording the unit it is told to name.
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

/// RED (plane reviews, close once): the client-drop path's `cancel` of an op in flight names the
/// unit the op serves, read off the op's own `in` (`Kind::unit_of`), so a plane that keys its units
/// from `arrive` frees that unit by its key (`PlaneCancelIn::unit`). Before the fix the frame was
/// never told it and a plane's `cancel` carried `unit: 0`.
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

/// RED (audit loader-src PL1#7; THE DESIGN `docs/design/BUSBAR-1.6.0.md` §11.13 M1, l.1652-1653:
/// "`close` is refused while units are in flight"): an admitted unit's op (a plane's `on_piece` or
/// `serve`, [`Dispatcher::submit_unit`]) holds no `max_inflight` unit, yet while one is in flight
/// `close` is REFUSED and never crosses, called or submitted. RED: the unit op left `inflight` at 0,
/// so `close` took every unit and closed the instance under a pending unit, whose resume then
/// answered FAULT and cut a stream already answered to its caller. The GREEN twin: once the unit's
/// op has ended, `close` crosses and closes.
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

/// RED (audit loader-src PL1#8; THE DESIGN `docs/design/BUSBAR-1.6.0.md` l.324-325: "The memory a
/// call lends a plugin lives until that call completes, abandoned or not, for every kind"): when
/// one plugin wedges a worker and the watchdog replaces it, a HEALTHY instance's op that was
/// PENDING on that worker is sent `cancel` before its frame and lent memory go, so the plugin
/// learns its op ended (a store op's checked-out connection is released on `cancel`). Its caller is
/// answered FAULT, and the lent memory goes only after the `cancel`. RED: the replacement dropped
/// the op with no `cancel`, and the plugin was never told.
#[test]
fn red_a_replaced_workers_pending_op_of_a_healthy_instance_is_cancelled_before_its_memory_goes() {
    let d = Dispatcher::new(config());
    let (healthy, sink) = opened(&d);
    let (owner, dropped) = lent(plug::PEND_HOLD);
    let t = d.mint(0).unwrap();
    let held = d.submit_lent(
        &healthy,
        t,
        TICK,
        lent_frame(&owner),
        DeadlineClass::Call,
        0,
        owner.clone(),
    );
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
    // Release the hang from a third instance (the wedger is faulted).
    let (releaser, _) = opened(&d);
    assert_eq!(
        releaser.call(TICK, &mut frame(b"unhang:orphan")).outcome,
        Outcome::Ready
    );
    drop(hung);
}

/// RED (audit loader-src PL1#6; THE DESIGN `docs/design/BUSBAR-1.6.0.md` §11.12, "the host never
/// runs a service twice", and l.1509, "a late wake cannot resume a slot the host has since recycled
/// to a different call"): the results an op on an INLINE ticket kept are that op's own. A resume
/// reads them; the next NEW op on the ticket, whose handles count from 0 again, starts with none,
/// and a dropped inline ticket takes them with it. RED: nothing forgot an inline ticket's results,
/// so the next op on a carrier's connection side redeemed the last op's answer on its handle 0 (the
/// same random bytes, a stale verdict), and the entries outlived the ticket.
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
