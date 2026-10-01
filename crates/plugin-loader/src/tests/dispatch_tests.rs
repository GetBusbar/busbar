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
    in_head, load_dropped, load_linked, now_ns, out_head, Bind, Budgets, Diagnostic,
    DispatchConfig, Dispatcher, Dropped, EnvelopeSink, Frame, Kind, LoadError, ManifestFacts,
    Metric, Plugin, Redeem, NO_BLOB,
};

/// The test kind's context: the Statement's `max_inflight`, as bound.
#[derive(Debug, PartialEq, Eq)]
struct TestContext(u32);

/// The test plugin's kind, as the dispatcher sees it: its code, the lifecycle skeleton for a table
/// (a test kind with no ops of its own), FAILED on a timeout.
struct TestKind;
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
    }
}

fn facts() -> ManifestFacts {
    ManifestFacts {
        mechanism_version: MECHANISM_VERSION,
        kind: plug::KIND,
        kind_abi: plug::KIND.abi_version(),
    }
}

fn linked(sink: Arc<Recorder>) -> Plugin<TestKind> {
    load_linked::<TestKind>(plug::busbar_plugin_door, bind(sink)).expect("the linked door loads")
}

/// The example `cdylib` `name` in this target dir (`cargo test` builds examples). Under CI a
/// missing artifact is a failure, never a skip.
pub(crate) fn example_cdylib(name: &str) -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile = exe.parent()?.parent()?;
    let path = profile.join("examples").join(format!(
        "{}{name}{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    let found = path.exists().then_some(path);
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the {name} example cdylib is not built under CI; a both-ways proof must not skip"
    );
    found
}

fn dropped_path() -> Option<std::path::PathBuf> {
    example_cdylib("dispatch_test_plugin")
}

fn dropped(sink: Arc<Recorder>) -> Option<Plugin<TestKind>> {
    let path = dropped_path()?;
    Some(load_dropped::<TestKind>(&path, &facts(), bind(sink)).expect("the dropped door loads"))
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
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
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
    let fresh_stale = fresh.generation > 1;
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
    let Some(_) = dropped_path() else {
        return;
    };
    let linked_run = script(&|s| linked(s));
    let dropped_run = script(&|s| dropped(s).expect("the dropped door"));
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
    assert_eq!(t.generation, old.generation + 1);
    let reply = d.submit(&p, t, TICK, frame(plug::PEND_HOLD), DeadlineClass::Call, 0);
    until("the held op", || d.is_pending(t));
    let stale0 = d.stats().stale_wakes;
    let crossings0 = p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst);
    crate::dispatch::ticket::host_wake(p.inner.ctx(), old);
    until("the stale wake is counted", || {
        d.stats().stale_wakes > stale0
    });
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

#[test]
fn completion_handles_store_the_result_and_never_run_twice() {
    let d = Dispatcher::new(config());
    let t = d.mint(0).unwrap();
    let c = d.completions();
    assert!(
        c.issue(Ticket::NONE).is_none(),
        "a ticket-less call has no service to wait for"
    );
    let h = c.issue(t).unwrap();
    let runs = std::sync::atomic::AtomicU32::new(0);
    runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(c.redeem(h), Redeem::Waiting);
    assert!(c.complete(h, b"row".to_vec()));
    assert!(!c.complete(h, b"again".to_vec()), "a handle completes once");
    assert_eq!(c.redeem(h), Redeem::Ready(b"row".to_vec()));
    assert_eq!(c.redeem(h), Redeem::Ready(b"row".to_vec()));
    assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(c.issue(t).unwrap().seq, 1);
    d.recycle(t);
    until("the recycle forgets the handles", || {
        c.redeem(h) == Redeem::Unknown
    });
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
}

extern "C" fn null_door() -> *const Door {
    std::ptr::null()
}

#[test]
fn red_both_origins_refuse_the_same_way() {
    assert_eq!(
        load_linked::<TestKind>(null_door, bind(quiet())).err(),
        Some(LoadError::NullDoor)
    );
    // The manifest's mechanism is checked BEFORE dlopen: a path that does not exist is never opened.
    let nowhere = std::path::Path::new("/nonexistent/libnothing.so");
    for v in [MECHANISM_VERSION - 1, MECHANISM_VERSION + 1] {
        let f = ManifestFacts {
            mechanism_version: v,
            ..facts()
        };
        assert_eq!(
            load_dropped::<TestKind>(nowhere, &f, bind(quiet())).err(),
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
        load_dropped::<TestKind>(nowhere, &f, bind(quiet())).err(),
        Some(LoadError::ManifestKindAbi { .. })
    ));
    let other = *KindCode::ALL.iter().find(|k| **k != plug::KIND).unwrap();
    let f = ManifestFacts {
        kind: other,
        ..facts()
    };
    assert_eq!(
        load_dropped::<TestKind>(nowhere, &f, bind(quiet())).err(),
        Some(LoadError::ManifestKind {
            stated: other,
            want: plug::KIND
        })
    );
    assert!(matches!(
        load_dropped::<TestKind>(nowhere, &facts(), bind(quiet())).err(),
        Some(LoadError::Open(_))
    ));
    // A library that is not a 1.6.0 plugin exports no door: the platform's C library.
    #[cfg(target_os = "macos")]
    let libc = "/usr/lib/libSystem.B.dylib";
    #[cfg(all(unix, not(target_os = "macos")))]
    let libc = "libc.so.6";
    #[cfg(unix)]
    assert!(matches!(
        load_dropped::<TestKind>(std::path::Path::new(libc), &facts(), bind(quiet())).err(),
        Some(LoadError::NoDoor(_))
    ));
}

/// The child half of the abort test: runs only when its parent sets the variable.
#[test]
fn panic_child() {
    let Ok(origin) = std::env::var("BUSBAR_M1_PANIC_CHILD") else {
        return;
    };
    let p = if origin == "dropped" {
        dropped(quiet()).expect("the dropped door")
    } else {
        linked(quiet())
    };
    let d = Dispatcher::new(config());
    assert_eq!(open(&d, &p, 0), Outcome::Ready);
    let _ = p.call(TICK, &mut frame(plug::PANIC));
    // Unreachable: the panic escapes an `extern "C"` slot and the process aborts.
    std::process::exit(0);
}

/// A panic that escapes a hand-written slot ABORTS the process — in both origins.
#[test]
fn red_a_panic_in_a_hand_written_slot_aborts() {
    let origins: &[&str] = if dropped_path().is_some() {
        &["linked", "dropped"]
    } else {
        &["linked"]
    };
    for origin in origins {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "dispatch_tests::panic_child",
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
    let hung = p.clone();
    let caller =
        std::thread::spawn(move || hung.call(TICK, &mut frame(b"hang:ticketless")).outcome);
    until("the watchdog faults the instance", || p.is_faulted());
    assert!(!p2.is_faulted(), "only the hung instance");
    assert_eq!(p.call(TICK, &mut frame(answer(1))).outcome, Outcome::Fault);
    assert_eq!(
        p2.call(TICK, &mut frame(b"unhang:ticketless")).outcome,
        Outcome::Ready
    );
    caller.join().unwrap();
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
    if dropped_path().is_none() {
        return;
    }
    let d = Dispatcher::new(config());
    let p = dropped(quiet()).expect("the dropped door");
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
        plug::busbar_plugin_door,
        Bind {
            dispatcher: d.adopter(),
            ..bind(sink)
        },
    )
    .unwrap();
    let hung = p.clone();
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
        plug::busbar_plugin_door,
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
