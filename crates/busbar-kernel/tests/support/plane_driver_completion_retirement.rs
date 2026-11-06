// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::plane::{self, Ops};
use busbar_contract::plane_calls::{Cancelled, Retirement};
use busbar_kernel::plane_driver::{CancelBill, Checkpoint, MoneySeam};
use busbar_kernel::teller::{Ended, UnitCtx};
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::plane_calls::PlaneInstance;
use busbar_plugin_loader::dispatch::{
    self, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink,
};

#[allow(dead_code)]
#[path = "../../../../dist/default/tests/fixtures/plane_driver_test_plane.rs"]
mod fixture;

#[derive(Default)]
struct Control {
    pieces: AtomicU64,
    cancels: AtomicU64,
    far_pending: AtomicBool,
    primary_crossed: AtomicBool,
    primary_seen: AtomicBool,
    sibling_seen: AtomicBool,
    allow_primary: AtomicBool,
    allow_sibling: AtomicBool,
    allow_settled: AtomicBool,
    wakers: Mutex<Vec<Waker>>,
}

fn controls() -> &'static Mutex<HashMap<usize, Arc<Control>>> {
    static CONTROLS: OnceLock<Mutex<HashMap<usize, Arc<Control>>>> = OnceLock::new();
    CONTROLS.get_or_init(Mutex::default)
}

extern "C" fn piece(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    let c = controls()
        .lock()
        .unwrap()
        .get(&(instance as usize))
        .unwrap()
        .clone();
    // SAFETY: exact initialized ON_PIECE frames, with buffers retained by the real dispatcher.
    let (i, o) = unsafe { (&*input.cast::<OnPieceIn>(), &mut *out.cast::<OnPieceOut>()) };
    c.pieces.fetch_add(1, Ordering::SeqCst);
    let outcome = match i.from {
        FROM_CALLER if i.flags & PIECE_LAST != 0 => {
            o.flags = EMIT_DONE;
            // One primary-owned cumulative report exercises the real kernel checkpoint path.
            assert!(i.units_cap >= 1);
            unsafe {
                i.units_buf.write(UnitCount {
                    class: 0,
                    source: UNITS_REPORTED,
                    amount: 1,
                });
            }
            o.units_written = 1;
            assert!(i.records_cap >= 1 && i.arena_cap >= 17);
            unsafe {
                std::ptr::copy_nonoverlapping(b"thing.callthing:x".as_ptr(), i.arena_buf, 17);
                i.records_buf.write(RecordWrite {
                    kind: AUDIT_APPLIED,
                    op: RECORD_AUDIT,
                    key: Span { offset: 0, len: 10 },
                    value: Span { offset: 10, len: 7 },
                });
            }
            o.records_written = 1;
            o.arena_written = 17;
            c.primary_crossed.store(true, Ordering::SeqCst);
            Outcome::Ready
        }
        FROM_CALLER => {
            let (verb, target) = (b"GET", b"/open");
            assert!(i.arena_cap >= verb.len() + target.len());
            unsafe {
                std::ptr::copy_nonoverlapping(verb.as_ptr(), i.arena_buf, verb.len());
                std::ptr::copy_nonoverlapping(
                    target.as_ptr(),
                    i.arena_buf.add(verb.len()),
                    target.len(),
                );
            }
            o.verb = Span {
                offset: 0,
                len: verb.len() as u32,
            };
            o.target = Span {
                offset: verb.len() as u32,
                len: target.len() as u32,
            };
            o.arena_written = (verb.len() + target.len()) as u64;
            o.flags = EMIT_TO_FAR_END;
            Outcome::Ready
        }
        FROM_FAR_END => {
            c.far_pending.store(true, Ordering::SeqCst);
            Outcome::Pending
        }
        _ => Outcome::Ready,
    };
    o.head.outcome = RawOutcome::of(outcome);
    RawOutcome::of(outcome)
}

extern "C" fn cancel(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    controls()
        .lock()
        .unwrap()
        .get(&(instance as usize))
        .unwrap()
        .cancels
        .fetch_add(1, Ordering::SeqCst);
    // SAFETY: forward the exact borrowed cancel frames to the fixture that owns the instance.
    unsafe { ((*fixture::door().parts().ops).cancel.unwrap())(instance, input, out) }
}

extern "C" fn door() -> &'static Door {
    static ADDRESS: OnceLock<usize> = OnceLock::new();
    let address = *ADDRESS.get_or_init(|| {
        let real = fixture::door().parts();
        // SAFETY: preserve the existing fixture's full descriptor and lifecycle; replace one typed slot.
        let mut ops = unsafe { *real.ops.cast::<Ops>() };
        ops.on_piece = Some(piece);
        ops.head.cancel = Some(cancel);
        let ops = Box::leak(Box::new(ops));
        let door = unsafe {
            Door::__from_parts(DoorParts {
                ops: &ops.head,
                ..real
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    unsafe { &*(address as *const Door) }
}

struct GatedFlight {
    inner: Box<dyn PieceInFlight>,
    control: Arc<Control>,
    primary: bool,
}
impl Future for GatedFlight {
    type Output = Answered;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Answered> {
        let allowed = if self.primary {
            &self.control.allow_primary
        } else {
            &self.control.allow_sibling
        };
        if !allowed.load(Ordering::SeqCst) {
            self.control.wakers.lock().unwrap().push(cx.waker().clone());
            return Poll::Pending;
        }
        let answer = Pin::new(&mut *self.inner).poll(cx);
        if answer.is_ready() {
            if self.primary {
                self.control.primary_seen.store(true, Ordering::SeqCst);
            } else if self.inner.retirement() == Some(Retirement::UnitCompleted) {
                self.control.sibling_seen.store(true, Ordering::SeqCst);
            }
        }
        answer
    }
}
impl PieceInFlight for GatedFlight {
    fn settled(&mut self) -> Option<Answered> {
        if self.control.allow_settled.load(Ordering::SeqCst) {
            self.inner.settled()
        } else {
            None
        }
    }
    fn retirement(&self) -> Option<Retirement> {
        self.inner.retirement()
    }
    fn out(&self) -> Option<OnPieceOut> {
        self.inner.out()
    }
    fn cancel_writes(&self) -> Vec<busbar_contract::plane_calls::CancelWrite> {
        self.inner.cancel_writes()
    }
}

struct Calls {
    metadata: Double,
    actual: PlaneInstance,
    control: Arc<Control>,
}
impl PlaneCalls for Calls {
    fn now_ns(&self) -> u64 {
        self.actual.now_ns()
    }
    fn arrive(
        &self,
        i: &mut ArriveIn,
        o: &mut ArriveOut,
        g: Grow<'_, ArriveIn, ArriveOut>,
    ) -> Outcome {
        let outcome = self.metadata.arrive(i, o, g);
        if outcome == Outcome::Ready {
            o.route = ROUTE_POOL;
            o.pool = AbiStr::over(b"fixture-lane");
        }
        outcome
    }
    fn arrived_pool(&self, o: &ArriveOut) -> Option<Vec<u8>> {
        self.metadata.arrived_pool(o)
    }
    fn refusal(
        &self,
        i: &mut RefusalIn,
        o: &mut RefusalOut,
        g: Grow<'_, RefusalIn, RefusalOut>,
    ) -> Outcome {
        self.metadata.refusal(i, o, g)
    }
    fn project(
        &self,
        i: &mut ProjectIn,
        o: &mut ProjectOut,
        g: Grow<'_, ProjectIn, ProjectOut>,
    ) -> Outcome {
        self.metadata.project(i, o, g)
    }
    fn cancel(&self, t: Ticket, u: u64) -> Option<Cancelled> {
        self.actual.cancel(t, u)
    }
    fn cancel_unit(
        &self,
        t: Ticket,
        u: u64,
    ) -> Pin<Box<dyn Future<Output = Option<Cancelled>> + Send>> {
        self.actual.cancel_unit(t, u)
    }
    fn bind_unit(&self, t: Ticket, u: u64) {
        self.actual.bind_unit(t, u);
    }
    fn mint(&self) -> Option<Ticket> {
        self.actual.mint()
    }
    fn mint_beside(&self, t: Ticket) -> Option<Ticket> {
        self.actual.mint_beside(t)
    }
    fn recycle(&self, t: Ticket) {
        self.actual.recycle(t);
    }
    fn declared(&self) -> InstanceDecl {
        self.metadata.declared()
    }
    fn driver(&self) -> Option<Ticket> {
        None
    }
    fn tick(&self, _: Ticket, _: u64) -> Pin<Box<dyn Future<Output = Option<u64>> + Send>> {
        Box::pin(std::future::ready(None))
    }
    fn ready(&self) -> Pin<Box<dyn Future<Output = Vec<u64>> + Send>> {
        Box::pin(std::future::pending())
    }
    fn drop_client(&self, t: Ticket) {
        self.actual.drop_client(t);
    }
    fn on_piece(
        &self,
        t: Ticket,
        i: OnPieceIn,
        o: OnPieceOut,
        lent: Lent,
    ) -> Box<dyn PieceInFlight> {
        let primary = i.from == FROM_CALLER && i.flags & PIECE_LAST != 0;
        let gated = primary || i.from == FROM_FAR_END;
        let inner = self.actual.on_piece(t, i, o, lent);
        if gated {
            Box::new(GatedFlight {
                inner,
                control: self.control.clone(),
                primary,
            })
        } else {
            inner
        }
    }
    fn serve(&self, t: Ticket, i: ServeIn, o: ServeOut, lent: Lent) -> Box<dyn ServeInFlight> {
        self.actual.serve(t, i, o, lent)
    }
}

#[derive(Default)]
struct Money {
    cut: bool,
    checkpoints: AtomicU64,
    closes: AtomicU64,
    bills: Mutex<Vec<CancelBill>>,
}
impl MoneySeam for Money {
    fn checkpoint(&self, _: &UnitCtx, units: &[UnitCount]) -> Checkpoint {
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].amount, 1);
        self.checkpoints.fetch_add(1, Ordering::SeqCst);
        if self.cut {
            Checkpoint::Cut
        } else {
            Checkpoint::Continue
        }
    }
    fn cancelled(&self, _: &UnitCtx, bill: &CancelBill) {
        self.bills.lock().unwrap().push(bill.clone());
    }
    fn abandoned(&self, _: &UnitCtx, _: Ended) {}
    fn session_opened(&self, _: &UnitCtx) -> Result<(), busbar_contract::caps::ReasonCode> {
        Ok(())
    }
    fn session_ended(&self, _: &UnitCtx) {
        self.closes.fetch_add(1, Ordering::SeqCst);
    }
}

fn calls() -> (Arc<Calls>, Arc<Control>, usize) {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let p = dispatch::load_linked::<Plane>(
        &LinkedRow::of(door).unwrap(),
        Bind {
            instance: "completion-retirement".into(),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::Probe,
        },
    )
    .unwrap();
    // SAFETY: OPEN frames have zero-valid pointer, integer and span fields.
    let (mut input, mut out): (plane::PlaneOpenIn, plane::PlaneOpenOut) =
        unsafe { std::mem::zeroed() };
    input.open.head = dispatch::in_head();
    input.open.generation = 1;
    out.open.head = dispatch::out_head();
    let mut open = Frame::new(input, out);
    assert_eq!(
        p.call(
            busbar_contract::abi::mechanism::lifecycle::slot::OPEN,
            &mut open
        )
        .outcome,
        Outcome::Ready
    );
    let instance = open.out.open.instance as usize;
    let control = Arc::new(Control::default());
    controls().lock().unwrap().insert(instance, control.clone());
    (
        Arc::new(Calls {
            metadata: Double::default(),
            actual: PlaneInstance::new(p, d, 0),
            control: control.clone(),
        }),
        control,
        instance,
    )
}

fn release(c: &Control, primary: bool) {
    if primary {
        c.allow_primary.store(true, Ordering::SeqCst);
    } else {
        c.allow_sibling.store(true, Ordering::SeqCst);
    }
    for waker in std::mem::take(&mut *c.wakers.lock().unwrap()) {
        waker.wake();
    }
}

async fn advance_until<F: Future>(running: &mut Pin<Box<F>>, predicate: impl Fn() -> bool) {
    tokio::time::timeout(
        Duration::from_secs(10),
        std::future::poll_fn(|cx| {
            assert!(running.as_mut().poll(cx).is_pending());
            if predicate() {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }),
    )
    .await
    .expect("dispatcher reached the explicit scheduling gate");
}

#[tokio::test]
async fn completion_retirement_preserves_primary_settlement_in_both_orders() {
    for (sibling_first, cut) in [(true, false), (true, true), (false, false), (false, true)] {
        let (calls, c, instance) = calls();
        let money = Arc::new(Money {
            cut,
            ..Money::default()
        });
        let rows = Arc::new(AuditRows::default());
        let driver = PlaneDriver::new(
            calls,
            DriverConfig {
                caps: BufferCaps::default(),
                op_classes: vec![OpClassId::new("call")],
                status_of: refusal_status,
                refusal_statuses: cases::statuses(),
                caller_refs: None,
            },
            money.clone(),
            services(),
            ("test_plane", &serde_yaml::Value::Null),
        )
        .unwrap()
        .with_audit(rows.clone());
        let (send, receive) = tokio::sync::mpsc::unbounded_channel();
        let caller = session_input_cases::OwnedCaller(tokio::sync::Mutex::new(receive));
        let steps = common::TestUnits::passing();
        let far = cases::Far::held(&["fixture-lane"]);
        let units = driver.unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);
        let mut running = Box::pin(session_input_cases::drive(&units));
        advance_until(&mut running, || c.far_pending.load(Ordering::SeqCst)).await;
        drop(send);
        advance_until(&mut running, || c.primary_crossed.load(Ordering::SeqCst)).await;
        release(&c, !sibling_first);
        advance_until(&mut running, || {
            if sibling_first {
                c.sibling_seen.load(Ordering::SeqCst)
            } else {
                c.primary_seen.load(Ordering::SeqCst)
            }
        })
        .await;
        if sibling_first {
            assert_eq!(money.checkpoints.load(Ordering::SeqCst), 0);
        }
        release(&c, sibling_first);
        let outcome = tokio::time::timeout(Duration::from_secs(10), running)
            .await
            .unwrap();
        if cut {
            assert!(
                matches!(
                    outcome,
                    busbar_contract::caps::Outcome::Failed(
                        _,
                        busbar_contract::caps::ReasonCode::OverBudget
                    )
                ),
                "{outcome:?}"
            );
        } else {
            assert_eq!(outcome, busbar_contract::caps::Outcome::Completed);
        }
        assert!(c.primary_seen.load(Ordering::SeqCst));
        assert!(c.sibling_seen.load(Ordering::SeqCst));
        assert_eq!(money.checkpoints.load(Ordering::SeqCst), 1);
        assert_eq!(money.closes.load(Ordering::SeqCst), 1);
        assert_eq!(c.cancels.load(Ordering::SeqCst), 0);
        assert_eq!(rows.0.lock().unwrap().len(), 1);
        assert_eq!(rows.0.lock().unwrap()[0].0, "thing.call");
        driver.sweep();
        assert_eq!(driver.buried(), 0);
        assert_eq!(driver.owed_closes(), 0);
        assert_eq!(money.checkpoints.load(Ordering::SeqCst), 1);
        drop(units);
        drop(driver);
        controls().lock().unwrap().remove(&instance);
    }
}

#[tokio::test]
async fn completion_retirement_dropped_before_consumption_sweeps_without_duplicate_bill() {
    let (calls, c, instance) = calls();
    let money = Arc::new(Money::default());
    let rows = Arc::new(AuditRows::default());
    let driver = PlaneDriver::new(
        calls,
        DriverConfig {
            caps: BufferCaps::default(),
            op_classes: vec![OpClassId::new("call")],
            status_of: refusal_status,
            refusal_statuses: cases::statuses(),
            caller_refs: None,
        },
        money.clone(),
        services(),
        ("test_plane", &serde_yaml::Value::Null),
    )
    .unwrap()
    .with_audit(rows.clone());
    let (send, receive) = tokio::sync::mpsc::unbounded_channel();
    let caller = session_input_cases::OwnedCaller(tokio::sync::Mutex::new(receive));
    let steps = common::TestUnits::passing();
    let far = cases::Far::held(&["fixture-lane"]);
    let units = driver.unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);
    let mut running = Box::pin(session_input_cases::drive(&units));
    advance_until(&mut running, || c.far_pending.load(Ordering::SeqCst)).await;
    drop(send);
    advance_until(&mut running, || c.primary_crossed.load(Ordering::SeqCst)).await;
    // Neither kernel leg consumed its result. Hide settled() until both flights are buried,
    // then let the real sweeper observe the primary and host-retired sibling together.
    assert!(!c.primary_seen.load(Ordering::SeqCst));
    assert!(!c.sibling_seen.load(Ordering::SeqCst));
    drop(running);
    drop(units);
    assert_eq!(driver.buried(), 2);
    c.allow_settled.store(true, Ordering::SeqCst);
    for _ in 0..4 {
        driver.sweep();
    }
    assert_eq!(driver.buried(), 0);
    assert_eq!(driver.owed_closes(), 0);
    assert_eq!(c.cancels.load(Ordering::SeqCst), 0);
    assert_eq!(money.checkpoints.load(Ordering::SeqCst), 0);
    assert_eq!(money.bills.lock().unwrap().len(), 1);
    assert_eq!(
        money.bills.lock().unwrap()[0].cause,
        busbar_contract::caps::ReasonCode::ClientGone
    );
    assert_eq!(money.closes.load(Ordering::SeqCst), 1);
    assert!(rows.0.lock().unwrap().is_empty());
    driver.sweep();
    assert_eq!(money.bills.lock().unwrap().len(), 1);
    drop(driver);
    controls().lock().unwrap().remove(&instance);
}
