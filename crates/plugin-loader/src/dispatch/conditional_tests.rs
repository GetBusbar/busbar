// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::super::{in_head, out_head, Answer};
use super::*;
use busbar_contract::abi::sdk::{
    plane::conditional::{ConditionalCandidate, RecordMutation, RecordPredicate, Request},
    store::conditional::{Decision, Expected},
};
use busbar_contract::abi::{
    mechanism::{
        call::{RawOutcome, FLAG_RESUME},
        lifecycle::{TickIn, TickOut},
    },
    plane::{OnPieceIn, OnPieceOut, ServeIn, ServeOut},
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

type Completion = Box<dyn FnOnce(ConditionalResult) + Send>;
#[derive(Default)]
struct Provider {
    accepted: Mutex<Vec<(ConditionalCandidate, Completion)>>,
}
impl crate::services_double::ServicesDouble for Arc<Provider> {
    fn observe_chain_life(
        &self,
        _: &busbar_contract::services::Caller,
        _: u32,
        _: &[u8],
        done: Box<dyn FnOnce(Result<Expected, &'static str>) + Send>,
    ) -> Result<(), &'static str> {
        done(Ok(Expected::Bytes(7_u64.to_le_bytes().to_vec())));
        Ok(())
    }
    fn supports_record_transactions(&self) -> bool {
        true
    }
    fn conditional_record_transaction(
        &self,
        _: &busbar_contract::services::Caller,
        _: Option<u64>,
        candidate: ConditionalCandidate,
        acked: Completion,
    ) -> Result<(), &'static str> {
        self.accepted.lock().unwrap().push((candidate, acked));
        Ok(())
    }
}
struct Route {
    store: Arc<super::super::services::ServiceStore>,
    provider: crate::services_double::Double<Arc<Provider>>,
    wakes: AtomicUsize,
    tickets: Mutex<Vec<Ticket>>,
}
impl super::super::ticket::WakeRoute for Route {
    fn wake(&self, ticket: Ticket, _: Option<&'static InstanceWake>) {
        self.tickets.lock().unwrap().push(ticket);
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
    fn services(&self) -> Option<super::super::services::Served<'_>> {
        Some(super::super::services::Served {
            store: &self.store,
            provider: &self.provider,
        })
    }
}
fn candidate(id: u64) -> ConditionalCandidate {
    ConditionalCandidate {
        correlation: id,
        predicates: vec![RecordPredicate {
            kind: 0,
            key: b"row".to_vec(),
            expected: Expected::Absent,
        }],
        mutations: vec![RecordMutation::Put {
            kind: 0,
            key: b"row".to_vec(),
            value: b"value".to_vec(),
        }],
        chains: Vec::new(),
    }
}
fn rig() -> (Arc<Route>, &'static InstanceWake, InHead) {
    let route = Arc::new(Route {
        store: Arc::default(),
        provider: crate::services_double::Double(Arc::new(Provider::default())),
        wakes: AtomicUsize::new(0),
        tickets: Mutex::new(Vec::new()),
    });
    let dynamic: Arc<dyn super::super::ticket::WakeRoute> = route.clone();
    let wake = Box::leak(Box::<InstanceWake>::default());
    assert!(wake.route.set(Arc::downgrade(&dynamic)).is_ok());
    assert!(wake
        .caller
        .set(busbar_contract::services::Caller {
            instance: "conditional".into(),
            plugin: "fixture".into(),
            kind: KindCode::Plane
        })
        .is_ok());
    let mut input = in_head();
    input.ticket = Ticket {
        slot: 1,
        generation: 8,
    };
    (route, wake, input)
}
fn request(wake: &'static InstanceWake, input: &mut InHead, unit: Option<u64>, id: u64) -> Request {
    // SAFETY: the local input and its empty original blob remain live until loan drop.
    let loan = unsafe { prepare(wake, true, slot::TICK, input, unit) }
        .unwrap()
        .unwrap();
    let bytes = unsafe { super::super::validate::lent(input.extensions.ptr, input.extensions.len) }
        .unwrap();
    let request = Request {
        capability: wire::read_capability(bytes).unwrap().unwrap(),
        candidate: candidate(id),
    };
    drop(loan);
    request
}
fn tick_answer(
    wake: &'static InstanceWake,
    input: &InHead,
    unit: Option<u64>,
    request: &Request,
    outcome: Outcome,
) -> Result<bool, ()> {
    let bytes = wire::encode_request(request).unwrap();
    let i = TickIn {
        head: *input,
        now_ns: 0,
    };
    let mut o = TickOut {
        head: out_head(),
        next_tick_ns: 0,
    };
    o.head.outcome = RawOutcome::of(outcome);
    o.head.extensions = Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    // SAFETY: both complete frames and the extension bytes live for the call.
    let a = unsafe {
        Answer::new(
            slot::TICK,
            outcome,
            &i.head,
            std::mem::size_of_val(&i),
            &o.head,
            std::mem::size_of_val(&o),
        )
    };
    unsafe { answer(wake, KindCode::Plane, input.ticket, unit, &o.head, &a) }
}
fn complete(route: &Route, decision: Result<Decision, ConditionalFailure>) {
    let (candidate, acked) = route.provider.accepted.lock().unwrap().remove(0);
    acked(ConditionalResult {
        correlation: candidate.correlation,
        decision,
    });
}
#[test]
fn copied_candidate_exact_replay_and_receipt_survive_resume_short_and_lease_disposal() {
    let (route, wake, mut input) = rig();
    route.store.held.track(input.ticket);
    let mut request = request(wake, &mut input, None, 1);
    assert_eq!(
        tick_answer(wake, &input, None, &request, Outcome::Pending),
        Ok(true)
    );
    assert_eq!(
        tick_answer(wake, &input, None, &request, Outcome::Pending),
        Ok(true)
    );
    assert_eq!(route.provider.accepted.lock().unwrap().len(), 1);
    assert_eq!(route.store.held.held(input.ticket), 1);
    let original = request.clone();
    request.candidate.mutations.clear();
    assert_eq!(
        tick_answer(wake, &input, None, &request, Outcome::Pending),
        Err(())
    );
    assert!(!route
        .store
        .conditional_output_allowed(caller(wake), input.ticket, None));
    complete(&route, Ok(Decision::Applied));
    assert!(!route
        .store
        .conditional_output_allowed(caller(wake), input.ticket, None));
    for flags in [FLAG_RESUME, FLAG_RESUME, 0] {
        input.flags = flags;
        let loan = unsafe { prepare(wake, true, slot::DRIVE, &mut input, None) }.unwrap();
        let bytes =
            unsafe { super::super::validate::lent(input.extensions.ptr, input.extensions.len) }
                .unwrap();
        assert_eq!(
            wire::read_result(bytes, &original)
                .unwrap()
                .unwrap()
                .decision,
            Ok(Decision::Applied)
        );
        drop(loan);
        assert_eq!(input.extensions.len, 0);
    }
    assert!(route
        .store
        .conditional_output_allowed(caller(wake), input.ticket, None));
    assert_eq!(route.wakes.load(Ordering::SeqCst), 1);
}
#[test]
fn conflict_can_replan_but_unknown_cannot_and_cancel_retains_late_delivery() {
    for indeterminate in [false, true] {
        let (route, wake, mut input) = rig();
        let first = request(wake, &mut input, Some(7), 1);
        assert_eq!(
            tick_answer(wake, &input, Some(7), &first, Outcome::Pending),
            Ok(true)
        );
        complete(
            &route,
            if indeterminate {
                Err(ConditionalFailure::Indeterminate)
            } else {
                Ok(Decision::ConditionConflict)
            },
        );
        let next = request(wake, &mut input, Some(7), 2);
        assert_eq!(
            tick_answer(wake, &input, Some(7), &next, Outcome::Pending),
            if indeterminate { Err(()) } else { Ok(true) }
        );
        if !indeterminate {
            route.store.conditional_cancel(caller(wake), input.ticket);
            complete(&route, Ok(Decision::Applied));
            assert_eq!(route.wakes.load(Ordering::SeqCst), 2);
            let (kept, _) = route.store.settlement_input(caller(wake)).unwrap();
            assert_eq!(*kept, next);
        }
    }
}
#[test]
fn stale_ticket_epoch_unit_and_instance_never_receive_another_result() {
    let (route, wake, mut input) = rig();
    let first = request(wake, &mut input, Some(7), 1);
    assert_eq!(
        tick_answer(wake, &input, Some(8), &first, Outcome::Pending),
        Err(())
    );
    assert_eq!(
        tick_answer(wake, &input, Some(7), &first, Outcome::Pending),
        Ok(true)
    );
    route.store.forget(input.ticket);
    let next = request(wake, &mut input, Some(7), 1);
    assert_ne!(first.capability.epoch, next.capability.epoch);
    complete(&route, Ok(Decision::Applied));
    assert_eq!(route.wakes.load(Ordering::SeqCst), 1);
    let (kept, receipt) = route.store.settlement_input(caller(wake)).unwrap();
    assert_eq!(*kept, first);
    assert!(wire::read_result(&receipt, &next).is_err());
    assert_eq!(
        tick_answer(wake, &input, Some(7), &first, Outcome::Pending),
        Err(())
    );
}
#[test]
fn pending_intent_cannot_carry_serve_reply_piece_records_or_short_output() {
    let (route, wake, mut input) = rig();
    let req = request(wake, &mut input, None, 1);
    let bytes = wire::encode_request(&req).unwrap();
    for mode in 0..4 {
        let i: ServeIn = unsafe { std::mem::zeroed() };
        let mut o: ServeOut = unsafe { std::mem::zeroed() };
        o.head = out_head();
        o.head.extensions = Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        match mode {
            0 => o.reply_written = 1,
            1 => o.records_written = 1,
            2 => o.reply_needed = 1,
            _ => o.status = 200,
        }
        let a = unsafe {
            Answer::new(
                busbar_contract::abi::plane::slot::SERVE,
                Outcome::Pending,
                &i.head,
                std::mem::size_of_val(&i),
                &o.head,
                std::mem::size_of_val(&o),
            )
        };
        assert_eq!(
            unsafe { answer(wake, KindCode::Plane, input.ticket, None, &o.head, &a) },
            Err(())
        );
    }
    let i: OnPieceIn = unsafe { std::mem::zeroed() };
    let mut o: OnPieceOut = unsafe { std::mem::zeroed() };
    o.head = out_head();
    o.head.extensions = Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    o.records_written = 1;
    let a = unsafe {
        Answer::new(
            busbar_contract::abi::plane::slot::ON_PIECE,
            Outcome::Pending,
            &i.head,
            std::mem::size_of_val(&i),
            &o.head,
            std::mem::size_of_val(&o),
        )
    };
    assert_eq!(
        unsafe { answer(wake, KindCode::Plane, input.ticket, None, &o.head, &a) },
        Err(())
    );
    assert_eq!(
        tick_answer(wake, &input, None, &req, Outcome::Failed),
        Err(())
    );
    assert!(route.provider.accepted.lock().unwrap().is_empty());
}
#[test]
fn old_plane_without_optin_keeps_its_exact_input_and_ordinary_output() {
    let (_route, wake, mut input) = rig();
    let original = input.extensions;
    assert!(
        unsafe { prepare(wake, false, slot::TICK, &mut input, None) }
            .unwrap()
            .is_none()
    );
    assert_eq!(input.extensions.ptr, original.ptr);
    let i = TickIn {
        head: input,
        now_ns: 0,
    };
    let o = TickOut {
        head: out_head(),
        next_tick_ns: 10,
    };
    let a = unsafe {
        Answer::new(
            slot::TICK,
            Outcome::Ready,
            &i.head,
            std::mem::size_of_val(&i),
            &o.head,
            std::mem::size_of_val(&o),
        )
    };
    assert_eq!(
        unsafe { answer(wake, KindCode::Plane, input.ticket, None, &o.head, &a) },
        Ok(false)
    );
}

#[derive(Default)]
struct PluginState {
    snapshot: Option<Box<busbar_contract::abi::plane::PlaneSnapshot>>,
    request: Option<Request>,
    leases: std::collections::HashMap<u64, Vec<u8>>,
    released: AtomicUsize,
    observed: Mutex<Vec<(u32, bool)>>,
    shorted: bool,
    outcome_only_driver: bool,
    settlement_seen: AtomicUsize,
    settlement_confirmed: AtomicUsize,
}
crate::dispatch_tests::c_abi! {
    fn opened(_: *mut std::ffi::c_void,input:*const std::ffi::c_void,out:*mut std::ffi::c_void)->RawOutcome {
        let (i,o)=unsafe{(&*input.cast::<busbar_contract::abi::plane::PlaneOpenIn>(),&mut *out.cast::<busbar_contract::abi::plane::PlaneOpenOut>())};
        let mut state=Box::<PluginState>::default();
        let mut snapshot:Box<busbar_contract::abi::plane::PlaneSnapshot>=Box::new(unsafe{std::mem::zeroed()});
        snapshot.size=std::mem::size_of_val(&*snapshot) as u32;snapshot.generation=i.open.generation;
        o.snapshot=&*snapshot;state.snapshot=Some(snapshot);o.open.instance=Box::into_raw(state).cast();o.open.head.outcome=RawOutcome::of(Outcome::Ready);RawOutcome::of(Outcome::Ready)
    }
    fn closed(instance:*mut std::ffi::c_void,_:*const std::ffi::c_void,out:*mut std::ffi::c_void)->RawOutcome {
        unsafe{drop(Box::from_raw(instance.cast::<PluginState>()));(*out.cast::<OutHead>()).outcome=RawOutcome::of(Outcome::Ready);}
        RawOutcome::of(Outcome::Ready)
    }
    fn empty(_: *mut std::ffi::c_void,_:*const std::ffi::c_void,out:*mut std::ffi::c_void)->RawOutcome {
        unsafe{(*out.cast::<OutHead>()).outcome=RawOutcome::of(Outcome::Ready);}RawOutcome::of(Outcome::Ready)
    }
    fn released(instance:*mut std::ffi::c_void,input:*const std::ffi::c_void,out:*mut std::ffi::c_void)->RawOutcome {
        let state=unsafe{&mut *instance.cast::<PluginState>()};
        let lease=unsafe{(*input.cast::<busbar_contract::abi::mechanism::lifecycle::ReleaseIn>()).lease};
        let mut bytes=state.leases.remove(&lease).expect("lease released once");bytes.fill(0xA5);state.released.fetch_add(1,Ordering::SeqCst);
        unsafe{(*out.cast::<OutHead>()).outcome=RawOutcome::of(Outcome::Ready);}RawOutcome::of(Outcome::Ready)
    }
    fn crossed(instance:*mut std::ffi::c_void,input:*const std::ffi::c_void,out:*mut std::ffi::c_void)->RawOutcome {
        let (state,i,o)=unsafe{(&mut *instance.cast::<PluginState>(),&*input.cast::<InHead>(),&mut *out.cast::<OutHead>())};
        let bytes=unsafe{super::super::validate::lent(i.extensions.ptr,i.extensions.len)}.unwrap();
        if state.outcome_only_driver && matches!(i.op, slot::TICK | slot::DRIVE) {
            let outcome = if let Some(receipt) = wire::read_settlement(bytes).unwrap() {
                assert!(receipt.matches(state.request.as_ref().expect("original commit retained")).unwrap());
                assert_eq!(receipt.result.decision, Ok(Decision::Applied));
                state.settlement_seen.fetch_add(1, Ordering::SeqCst);
                let bytes = wire::encode_settlement_ack(&receipt);
                o.extensions=Blob{ptr:bytes.as_ptr(),len:bytes.len(),fmt:BLOB_OCTETS,flags:0};
                o.lease=2; assert!(state.leases.insert(2,bytes).is_none());
                Outcome::Pending
            } else {
                if state.settlement_seen.load(Ordering::SeqCst) != 0 { state.settlement_confirmed.fetch_add(1, Ordering::SeqCst); }
                Outcome::Ready
            };
            o.outcome=RawOutcome::of(outcome);return RawOutcome::of(outcome);
        }
        let capability=wire::read_capability(bytes).unwrap().expect("negotiated host");
        let request=state.request.get_or_insert_with(||Request{capability,candidate:candidate(1)});
        let outcome=if let Some(result)=wire::read_result(bytes,request).unwrap() {
            assert_eq!(result.decision,Ok(Decision::Applied));
            state.observed.lock().unwrap().push((i.op,i.flags&FLAG_RESUME!=0));
            if i.op==busbar_contract::abi::plane::slot::SERVE && !state.shorted {
                state.shorted=true;unsafe{(*out.cast::<ServeOut>()).reply_needed=1;}Outcome::Failed
            } else {
                if i.op==busbar_contract::abi::plane::slot::SERVE {unsafe{(*out.cast::<ServeOut>()).status=200;}}
                Outcome::Ready
            }
        } else {
            let bytes=wire::encode_request(request).unwrap();o.extensions=Blob{ptr:bytes.as_ptr(),len:bytes.len(),fmt:BLOB_OCTETS,flags:0};o.lease=1;state.leases.insert(1,bytes);Outcome::Pending
        };
        o.outcome=RawOutcome::of(outcome);RawOutcome::of(outcome)
    }
    fn door()->&'static busbar_contract::abi::mechanism::door::Door {
        static ADDRESS:std::sync::OnceLock<usize>=std::sync::OnceLock::new();
        let ptr=*ADDRESS.get_or_init(||{
            use busbar_contract::abi::mechanism::door::{Door,DoorParts};
            let real=crate::plane_door_plugin::door().parts();
            let mut ops=unsafe{*real.ops.cast::<busbar_contract::abi::plane::Ops>()};
            ops.head.open=Some(opened);ops.head.close=Some(closed);ops.head.retire=Some(empty);ops.head.cancel=Some(empty);ops.head.release=Some(released);ops.head.tick=Some(crossed);ops.head.drive=Some(crossed);ops.serve=Some(crossed);
            let ops=Box::leak(Box::new(ops));let mut statement=unsafe{*real.statement};
            let bytes=wire::statement(&[]).unwrap().into_boxed_slice();let bytes=Box::leak(bytes);
            statement.extensions=Blob{ptr:bytes.as_ptr(),len:bytes.len(),fmt:BLOB_OCTETS,flags:0};
            let statement=Box::leak(Box::new(statement));
            let door=unsafe{Door::__from_parts(DoorParts{ops:std::ptr::from_ref(ops).cast(),statement,..real})};Box::into_raw(Box::new(door)) as usize
        });unsafe{&*(ptr as *const busbar_contract::abi::mechanism::door::Door)}
    }
}
fn plane_rig() -> (
    Arc<super::super::Dispatcher>,
    super::super::Plugin<super::super::kinds::plane::Plane>,
    Arc<Provider>,
    *const PluginState,
) {
    use super::super::{
        kinds::plane::Plane, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink,
    };
    let provider = Arc::new(Provider::default());
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(crate::services_double::Double(provider.clone())),
    ));
    let plugin = super::super::load_linked::<Plane>(
        &LinkedRow::of(door).unwrap(),
        Bind {
            instance: "conditional-plane".into(),
            max_inflight_cap: 2,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .unwrap();
    let mut input: busbar_contract::abi::plane::PlaneOpenIn = unsafe { std::mem::zeroed() };
    let mut out: busbar_contract::abi::plane::PlaneOpenOut = unsafe { std::mem::zeroed() };
    input.open.head = in_head();
    input.open.generation = 1;
    out.open.head = out_head();
    let mut frame = Frame::new(input, out);
    assert_eq!(plugin.call(slot::OPEN, &mut frame).outcome, Outcome::Ready);
    let state = frame.out.open.instance.cast::<PluginState>();
    (dispatcher, plugin, provider, state)
}
#[test]
fn actual_dispatch_serve_waits_for_applied_releases_pending_lease_and_retains_short_receipt() {
    use super::super::Frame;
    use busbar_contract::abi::mechanism::call::DeadlineClass;
    let (dispatcher, plugin, provider, state) = plane_rig();
    let ticket = dispatcher.mint(0).unwrap();
    let frame = || {
        let mut i: ServeIn = unsafe { std::mem::zeroed() };
        let mut o: ServeOut = unsafe { std::mem::zeroed() };
        i.head = in_head();
        o.head = out_head();
        Frame::new(i, o)
    };
    let reply = dispatcher.submit(
        &plugin,
        ticket,
        busbar_contract::abi::plane::slot::SERVE,
        frame(),
        DeadlineClass::Call,
        0,
    );
    let start = std::time::Instant::now();
    while provider.accepted.lock().unwrap().is_empty() {
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
        std::thread::yield_now();
    }
    assert!(
        reply.wait(std::time::Duration::ZERO).is_none(),
        "no serve answer before commit acknowledgement"
    );
    let (candidate, acked) = provider.accepted.lock().unwrap().remove(0);
    acked(ConditionalResult {
        correlation: candidate.correlation,
        decision: Ok(Decision::Applied),
    });
    let done = reply.wait(std::time::Duration::from_secs(10)).unwrap();
    assert_eq!(done.outcome, Outcome::Failed);
    assert!(done.short);
    let done = dispatcher
        .submit(
            &plugin,
            ticket,
            busbar_contract::abi::plane::slot::SERVE,
            frame(),
            DeadlineClass::Call,
            0,
        )
        .wait(std::time::Duration::from_secs(10))
        .unwrap();
    assert_eq!(done.outcome, Outcome::Ready);
    let state = unsafe { &*state };
    assert_eq!(state.released.load(Ordering::SeqCst), 1);
    assert_eq!(state.observed.lock().unwrap().len(), 2);
    assert!(provider.accepted.lock().unwrap().is_empty());
    dispatcher.recycle(ticket);
}

#[test]
fn actual_plane_tick_holds_driver_epoch_until_drive_receipt() {
    use busbar_contract::plane_calls::PlaneCalls;
    let (dispatcher, plugin, provider, state) = plane_rig();
    let instance = super::super::plane_calls::PlaneInstance::new(plugin, dispatcher.clone(), 0);
    let ticket = instance.driver().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    assert_eq!(runtime.block_on(instance.tick(ticket, 0)), Some(0));
    assert_eq!(unsafe { &*state }.released.load(Ordering::SeqCst), 1);
    let (candidate, acked) = provider.accepted.lock().unwrap().remove(0);
    acked(ConditionalResult {
        correlation: candidate.correlation,
        decision: Ok(Decision::Applied),
    });
    let start = std::time::Instant::now();
    loop {
        let observed = unsafe { &*state }.observed.lock().unwrap();
        if let Some((operation, _)) = observed.first() {
            assert_eq!(*operation, slot::DRIVE);
            break;
        }
        drop(observed);
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
        std::thread::yield_now();
    }
    instance.recycle(ticket);
}

#[test]
fn cancel_before_submission_invalidates_the_already_issued_capability() {
    let (route, wake, mut input) = rig();
    let request = request(wake, &mut input, None, 1);
    route.store.conditional_cancel(caller(wake), input.ticket);
    assert_eq!(
        tick_answer(wake, &input, None, &request, Outcome::Pending),
        Err(())
    );
    assert!(route.provider.accepted.lock().unwrap().is_empty());
}

#[test]
fn observed_life_remains_bound_and_held_through_fresh_read_then_commit() {
    let (route, wake, mut input) = rig();
    route.store.held.track(input.ticket);
    let capability = request(wake, &mut input, None, 1).capability;
    let observation = wire::Observation {
        capability,
        correlation: 1,
        kind: 0,
        scope: b"scope".to_vec(),
    };
    let bytes = wire::encode_observation(&observation).unwrap();
    let i = TickIn {
        head: input,
        now_ns: 0,
    };
    let mut o = TickOut {
        head: out_head(),
        next_tick_ns: 0,
    };
    o.head.extensions = Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let a = unsafe {
        Answer::new(
            slot::TICK,
            Outcome::Pending,
            &i.head,
            std::mem::size_of_val(&i),
            &o.head,
            std::mem::size_of_val(&o),
        )
    };
    assert_eq!(
        unsafe { answer(wake, KindCode::Plane, input.ticket, None, &o.head, &a) },
        Ok(true)
    );
    let loan = unsafe { prepare(wake, true, slot::DRIVE, &mut input, None) }.unwrap();
    let bytes = unsafe { super::super::validate::lent(input.extensions.ptr, input.extensions.len) }
        .unwrap();
    let observed = observation
        .observed(wire::read_observed(bytes, &observation).unwrap().unwrap())
        .unwrap();
    let mut forged = observation.clone();
    forged.scope = b"other".to_vec();
    assert!(wire::read_observed(bytes, &forged).is_err());
    drop(loan);
    assert_eq!(
        route.store.held.held(input.ticket),
        1,
        "receipt consumption must not end the driver's epoch before its fresh GET"
    );
    let next = request(wake, &mut input, None, 2);
    assert_eq!(next.capability, capability);
    assert_eq!(observed.life, Expected::Bytes(7_u64.to_le_bytes().to_vec()));
    assert_eq!(
        tick_answer(wake, &input, None, &next, Outcome::Pending),
        Ok(true)
    );
    assert_eq!(route.store.held.held(input.ticket), 1);
    complete(&route, Ok(Decision::Applied));
}

#[test]
fn unreadable_legacy_blobs_stay_ignored_but_negotiated_blobs_refuse_before_slicing() {
    let (route, wake, mut input) = rig();
    let detached = Box::leak(Box::<InstanceWake>::default());
    let over = busbar_contract::abi::mechanism::check::HARD_MAX_BYTES as usize + 1;
    let oversized = Blob {
        ptr: std::ptr::NonNull::<u8>::dangling().as_ptr(),
        len: over,
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let null = Blob {
        ptr: std::ptr::null(),
        len: 1,
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    for legacy_wake in [detached as &'static InstanceWake, wake] {
        for blob in [oversized, null] {
            let i = TickIn {
                head: input,
                now_ns: 0,
            };
            let mut o = TickOut {
                head: out_head(),
                next_tick_ns: 0,
            };
            o.head.extensions = blob;
            // SAFETY: only the valid frame is borrowed. The fabricated blob must never be read.
            let a = unsafe {
                Answer::new(
                    slot::TICK,
                    Outcome::Ready,
                    &i.head,
                    std::mem::size_of_val(&i),
                    &o.head,
                    std::mem::size_of_val(&o),
                )
            };
            assert_eq!(
                unsafe {
                    answer(
                        legacy_wake,
                        KindCode::Plane,
                        input.ticket,
                        None,
                        &o.head,
                        &a,
                    )
                },
                Ok(false)
            );
        }
    }
    let request = request(wake, &mut input, None, 1);
    input.extensions = oversized;
    assert!(unsafe { prepare(wake, true, slot::TICK, &mut input, None) }.is_err());
    assert!(
        unsafe { prepare(wake, false, slot::TICK, &mut input, None) }
            .unwrap()
            .is_none()
    );
    for blob in [oversized, null] {
        let i = TickIn {
            head: input,
            now_ns: 0,
        };
        let mut o = TickOut {
            head: out_head(),
            next_tick_ns: 0,
        };
        o.head.extensions = blob;
        let a = unsafe {
            Answer::new(
                slot::TICK,
                Outcome::Pending,
                &i.head,
                std::mem::size_of_val(&i),
                &o.head,
                std::mem::size_of_val(&o),
            )
        };
        assert_eq!(
            unsafe { answer(wake, KindCode::Plane, input.ticket, None, &o.head, &a) },
            Err(())
        );
    }
    assert!(route.provider.accepted.lock().unwrap().is_empty());
    assert_eq!(request.capability.ticket, input.ticket);
}

#[test]
fn cancellation_preserves_submitted_completion_and_wakes_known_driver() {
    let (route, wake, mut origin) = rig();
    let commit = request(wake, &mut origin, None, 70);
    assert_eq!(
        tick_answer(wake, &origin, None, &commit, Outcome::Pending),
        Ok(true)
    );
    let mut driver = in_head();
    driver.ticket = Ticket {
        slot: 2,
        generation: 9,
    };
    let _ = request(wake, &mut driver, None, 1);
    route.store.conditional_cancel(caller(wake), origin.ticket);
    complete(&route, Ok(Decision::Applied));
    assert_eq!(
        route.wakes.load(Ordering::SeqCst),
        1,
        "a canceled submitted commit must wake the live outcome driver"
    );
    assert_eq!(
        tick_answer(wake, &origin, None, &commit, Outcome::Pending),
        Err(())
    );
}

#[test]
fn ticket_forget_preserves_submitted_completion_and_wakes_known_driver() {
    let (route, wake, mut origin) = rig();
    let commit = request(wake, &mut origin, None, 71);
    assert_eq!(
        tick_answer(wake, &origin, None, &commit, Outcome::Pending),
        Ok(true)
    );
    let mut driver = in_head();
    driver.ticket = Ticket {
        slot: 2,
        generation: 9,
    };
    let _ = request(wake, &mut driver, None, 1);
    route.store.forget(origin.ticket);
    complete(&route, Ok(Decision::Applied));
    assert_eq!(
        route.wakes.load(Ordering::SeqCst),
        1,
        "forget must retire normal authority without discarding the submitted outcome"
    );
    assert_eq!(
        tick_answer(wake, &origin, None, &commit, Outcome::Pending),
        Err(())
    );
}

fn settlement(wake: &'static InstanceWake, input: &mut InHead) -> Option<wire::Settlement> {
    let loan = unsafe { prepare(wake, true, slot::DRIVE, input, None) }.unwrap();
    let bytes = unsafe { super::super::validate::lent(input.extensions.ptr, input.extensions.len) }
        .unwrap();
    let result = wire::read_settlement(bytes).unwrap();
    drop(loan);
    result
}
fn ack_answer(
    wake: &'static InstanceWake,
    input: &InHead,
    bytes: &[u8],
    outcome: Outcome,
) -> Result<bool, ()> {
    let i = TickIn {
        head: *input,
        now_ns: 0,
    };
    let mut o = TickOut {
        head: out_head(),
        next_tick_ns: 0,
    };
    o.head.outcome = RawOutcome::of(outcome);
    o.head.extensions = Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let a = unsafe {
        Answer::new(
            slot::TICK,
            outcome,
            &i.head,
            std::mem::size_of_val(&i),
            &o.head,
            std::mem::size_of_val(&o),
        )
    };
    unsafe { answer(wake, KindCode::Plane, input.ticket, None, &o.head, &a) }
}
fn driver() -> InHead {
    let mut input = in_head();
    input.ticket = Ticket {
        slot: 22,
        generation: 10,
    };
    input
}

#[test]
fn canceled_commit_settles_exact_original_after_cancel_or_forget_in_both_result_orders() {
    for forget in [false, true] {
        for before in [false, true] {
            let (route, wake, mut origin) = rig();
            let commit = request(wake, &mut origin, Some(7), 81);
            assert_eq!(
                tick_answer(wake, &origin, Some(7), &commit, Outcome::Pending),
                Ok(true)
            );
            let mut driver = driver();
            assert!(settlement(wake, &mut driver).is_none());
            if before {
                complete(&route, Ok(Decision::Applied));
            }
            route.tickets.lock().unwrap().clear();
            if forget {
                route.store.forget(origin.ticket);
            } else {
                route.store.conditional_cancel(caller(wake), origin.ticket);
            }
            if !before {
                complete(&route, Ok(Decision::Applied));
            }
            assert_eq!(*route.tickets.lock().unwrap(), vec![driver.ticket]);
            let receipt = settlement(wake, &mut driver).unwrap();
            assert!(receipt.matches(&commit).unwrap());
            assert_eq!(receipt.result.decision, Ok(Decision::Applied));
            let ack = wire::encode_settlement_ack(&receipt);
            assert_eq!(ack_answer(wake, &driver, &ack, Outcome::Pending), Ok(true));
            assert!(
                settlement(wake, &mut driver).is_none(),
                "absence confirms successful ACK consumption"
            );
            assert_eq!(
                ack_answer(wake, &driver, &ack, Outcome::Pending),
                Ok(true),
                "duplicate ACK is harmless"
            );
            assert_eq!(
                tick_answer(wake, &origin, Some(7), &commit, Outcome::Pending),
                Err(())
            );
            if !forget {
                assert!(!route.store.conditional_output_allowed(
                    caller(wake),
                    origin.ticket,
                    Some(7)
                ));
            }
            assert!(route.provider.accepted.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn failed_ack_keeps_sticky_receipt_even_when_another_canceled_commit_completes() {
    let (route, wake, mut origin) = rig();
    let first = request(wake, &mut origin, None, 90);
    assert_eq!(
        tick_answer(wake, &origin, None, &first, Outcome::Pending),
        Ok(true)
    );
    let mut second_input = in_head();
    second_input.ticket = Ticket {
        slot: 3,
        generation: 8,
    };
    let second = request(wake, &mut second_input, None, 91);
    assert_eq!(
        tick_answer(wake, &second_input, None, &second, Outcome::Pending),
        Ok(true)
    );
    let mut driver = driver();
    assert!(settlement(wake, &mut driver).is_none());
    route.store.conditional_cancel(caller(wake), origin.ticket);
    route
        .store
        .conditional_cancel(caller(wake), second_input.ticket);
    complete(&route, Ok(Decision::Applied));
    let first_receipt = settlement(wake, &mut driver).unwrap();
    let ack = wire::encode_settlement_ack(&first_receipt);
    assert_eq!(ack_answer(wake, &driver, &ack, Outcome::Failed), Ok(true));
    complete(&route, Ok(Decision::ConditionConflict));
    assert_eq!(settlement(wake, &mut driver), Some(first_receipt.clone()));
    assert_eq!(ack_answer(wake, &driver, &ack, Outcome::Pending), Ok(true));
    let next = settlement(wake, &mut driver).unwrap();
    assert!(next.matches(&second).unwrap());
    assert_eq!(next.result.decision, Ok(Decision::ConditionConflict));
    assert_eq!(ack_answer(wake, &driver, &ack, Outcome::Pending), Ok(true));
    assert_eq!(settlement(wake, &mut driver), Some(next));
}

#[test]
fn settlement_ack_checks_original_instance_generation_epoch_correlation_and_digest() {
    let (route, wake, mut origin) = rig();
    let commit = request(wake, &mut origin, None, 92);
    assert_eq!(
        tick_answer(wake, &origin, None, &commit, Outcome::Pending),
        Ok(true)
    );
    route.store.conditional_cancel(caller(wake), origin.ticket);
    complete(&route, Ok(Decision::Applied));
    let exact = wire::read_settlement(
        &wire::encode_settlement(
            &commit,
            &ConditionalResult {
                correlation: 92,
                decision: Ok(Decision::Applied),
            },
        )
        .unwrap(),
    )
    .unwrap()
    .unwrap();
    let ack = wire::read_settlement_ack(&wire::encode_settlement_ack(&exact))
        .unwrap()
        .unwrap();
    assert_eq!(
        route.store.settlement_ack(caller(wake), &ack, true),
        Err(()),
        "unlent ACK cannot consume"
    );
    let mut driver = driver();
    let receipt = settlement(wake, &mut driver).unwrap();
    let (_other_route, other, _) = rig();
    assert_eq!(
        route.store.settlement_ack(caller(other), &ack, true),
        Err(())
    );
    for field in 0..5 {
        let mut changed = receipt.clone();
        match field {
            0 => changed.capability.ticket.generation += 1,
            1 => changed.capability.epoch += 1,
            2 => changed.result.correlation += 1,
            3 => changed.request_digest[0] ^= 1,
            _ => changed.capability.ticket.slot += 1,
        }
        let bytes = wire::encode_settlement_ack(&changed);
        let _ = ack_answer(wake, &driver, &bytes, Outcome::Pending);
        assert_eq!(
            settlement(wake, &mut driver),
            Some(receipt.clone()),
            "a changed identity never consumes the original"
        );
    }
    let mut mixed = wire::encode_settlement_ack(&receipt);
    mixed.extend_from_slice(&wire::encode_request(&commit).unwrap());
    assert_eq!(ack_answer(wake, &driver, &mixed, Outcome::Pending), Err(()));
    assert_eq!(settlement(wake, &mut driver), Some(receipt));
}

#[test]
fn new_ticket_generation_and_current_epoch_do_not_steal_old_settlement() {
    let (route, wake, mut origin) = rig();
    let old = request(wake, &mut origin, None, 93);
    assert_eq!(
        tick_answer(wake, &origin, None, &old, Outcome::Pending),
        Ok(true)
    );
    route
        .store
        .forget_worker(super::super::ticket::decode(origin.ticket.slot).0);
    let next_epoch = request(wake, &mut origin, None, 93);
    assert_ne!(old.capability.epoch, next_epoch.capability.epoch);
    origin.ticket.generation += 1;
    let next_generation = request(wake, &mut origin, None, 93);
    assert_ne!(old.capability.ticket, next_generation.capability.ticket);
    let mut driver = driver();
    assert!(settlement(wake, &mut driver).is_none());
    complete(&route, Ok(Decision::Applied));
    let receipt = settlement(wake, &mut driver).unwrap();
    assert!(receipt.matches(&old).unwrap());
    assert!(!receipt.matches(&next_epoch).unwrap());
    assert!(!receipt.matches(&next_generation).unwrap());
    assert_eq!(route.provider.accepted.lock().unwrap().len(), 0);
}

#[test]
fn indeterminate_is_never_applied_and_teardown_drops_only_plugin_settlement_custody() {
    for complete_first in [false, true] {
        let (route, wake, mut origin) = rig();
        let commit = request(wake, &mut origin, None, 94);
        assert_eq!(
            tick_answer(wake, &origin, None, &commit, Outcome::Pending),
            Ok(true)
        );
        route.store.conditional_cancel(caller(wake), origin.ticket);
        let mut driver = driver();
        if complete_first {
            complete(&route, Err(ConditionalFailure::Indeterminate));
            let receipt = settlement(wake, &mut driver).unwrap();
            assert_eq!(
                receipt.result.decision,
                Err(ConditionalFailure::Indeterminate)
            );
            assert!(!route
                .store
                .conditional_output_allowed(caller(wake), origin.ticket, None));
        }
        route.store.conditional_teardown(caller(wake));
        if !complete_first {
            complete(&route, Ok(Decision::Applied));
        }
        assert!(route.store.settlement_input(caller(wake)).is_none());
        assert!(route.provider.accepted.lock().unwrap().is_empty());
    }
}

#[test]
fn result_before_first_driver_tick_is_delivered_without_reviving_canceled_origin() {
    let (route, wake, mut origin) = rig();
    let commit = request(wake, &mut origin, None, 95);
    *wake.conditional_driver.lock().unwrap() = None;
    assert_eq!(
        tick_answer(wake, &origin, None, &commit, Outcome::Pending),
        Ok(true)
    );
    route.store.conditional_cancel(caller(wake), origin.ticket);
    complete(&route, Ok(Decision::Applied));
    assert_eq!(route.wakes.load(Ordering::SeqCst), 0);
    let mut driver = driver();
    let receipt = settlement(wake, &mut driver).unwrap();
    assert!(receipt.matches(&commit).unwrap());
    wake.revoked.store(true, Ordering::Release);
    route.tickets.lock().unwrap().clear();
    wake_driver(wake);
    assert!(route.tickets.lock().unwrap().is_empty());
    assert!(
        unsafe { prepare(wake, true, slot::DRIVE, &mut driver, None) }
            .unwrap()
            .is_none()
    );
}

#[test]
fn actual_canceled_serve_settles_on_idle_driver_without_new_tick_or_resubmission() {
    use super::super::Frame;
    use busbar_contract::abi::mechanism::call::DeadlineClass;
    use busbar_contract::plane_calls::PlaneCalls;
    let (dispatcher, plugin, provider, state) = plane_rig();

    unsafe {
        (*state.cast_mut()).outcome_only_driver = true;
    }
    let plugin = Arc::new(plugin);
    let instance =
        super::super::plane_calls::PlaneInstance::new(plugin.clone(), dispatcher.clone(), 0);
    let driver = instance.driver().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    assert_eq!(runtime.block_on(instance.tick(driver, 0)), Some(0));
    let origin = dispatcher.mint(0).unwrap();
    let mut input: ServeIn = unsafe { std::mem::zeroed() };
    let mut output: ServeOut = unsafe { std::mem::zeroed() };
    input.head = in_head();
    output.head = out_head();
    let reply = dispatcher.submit(
        &plugin,
        origin,
        busbar_contract::abi::plane::slot::SERVE,
        Frame::new(input, output),
        DeadlineClass::Call,
        0,
    );
    let start = std::time::Instant::now();
    while provider.accepted.lock().unwrap().is_empty() {
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
        std::thread::yield_now();
    }
    dispatcher.drop_client(origin);
    let canceled = reply.wait(std::time::Duration::from_secs(10)).unwrap();
    assert_ne!(canceled.outcome, Outcome::Ready);
    dispatcher.recycle(origin);
    let (candidate, done) = provider.accepted.lock().unwrap().remove(0);
    done(ConditionalResult {
        correlation: candidate.correlation,
        decision: Ok(Decision::Applied),
    });
    let start = std::time::Instant::now();
    while unsafe { &*state }
        .settlement_confirmed
        .load(Ordering::SeqCst)
        == 0
    {
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
        std::thread::yield_now();
    }
    assert_eq!(unsafe { &*state }.settlement_seen.load(Ordering::SeqCst), 1);
    assert!(provider.accepted.lock().unwrap().is_empty());
    instance.recycle(driver);
}

#[test]
fn forget_late_applied_ack_removes_retired_owner_but_preserves_live_current_state() {
    for new_state in [false, true] {
        let (route, wake, mut origin) = rig();
        let commit = request(wake, &mut origin, None, 100);
        assert_eq!(
            tick_answer(wake, &origin, None, &commit, Outcome::Pending),
            Ok(true)
        );
        route.store.forget(origin.ticket);
        if new_state {
            route.store.keep(origin.ticket, 1);
        }
        assert!(route.store.conditional_ticket_kept(origin.ticket));
        complete(&route, Ok(Decision::Applied));
        let mut driver = driver();
        let receipt = settlement(wake, &mut driver).unwrap();
        assert_eq!(
            ack_answer(
                wake,
                &driver,
                &wire::encode_settlement_ack(&receipt),
                Outcome::Pending
            ),
            Ok(true)
        );
        assert_eq!(
            route.store.conditional_ticket_kept(origin.ticket),
            new_state
        );
        assert_eq!(route.store.held(), usize::from(new_state));
    }
}

#[test]
fn teardown_prunes_empty_owners_and_preserves_other_callers_and_ordinary_work() {
    let (route, wake, mut origin) = rig();
    let commit = request(wake, &mut origin, None, 101);
    assert_eq!(
        tick_answer(wake, &origin, None, &commit, Outcome::Pending),
        Ok(true)
    );
    route.store.forget(origin.ticket);
    complete(&route, Ok(Decision::Applied));
    let ordinary = Ticket {
        slot: 41,
        generation: 2,
    };
    route.store.keep(ordinary, 7);
    let other_ticket = Ticket {
        slot: 42,
        generation: 2,
    };
    let (_other_route, other, _) = rig();
    route
        .store
        .conditional_input(caller(other), other_ticket, None)
        .unwrap();
    route.store.conditional_teardown(caller(wake));
    assert!(!route.store.conditional_ticket_kept(origin.ticket));
    assert!(route.store.conditional_ticket_kept(ordinary));
    assert!(route.store.conditional_ticket_kept(other_ticket));
    assert_eq!(route.store.held(), 1);
    route.store.conditional_teardown(caller(other));
    assert!(!route.store.conditional_ticket_kept(other_ticket));
    assert!(route.store.conditional_ticket_kept(ordinary));
}

#[test]
fn oldest_ready_epoch_is_selected_after_sticky_ack_despite_new_completed_arrivals() {
    let (route, wake, _) = rig();
    let mut commits = Vec::new();
    for id in 0..3 {
        let mut input = in_head();
        input.ticket = Ticket {
            slot: 50 + id as u32,
            generation: 3,
        };
        let commit = request(wake, &mut input, None, 110 + id);
        assert_eq!(
            tick_answer(wake, &input, None, &commit, Outcome::Pending),
            Ok(true)
        );
        route.store.forget(input.ticket);
        complete(&route, Ok(Decision::Applied));
        commits.push(commit);
    }
    let mut driver = driver();
    let first = settlement(wake, &mut driver).unwrap();
    assert!(first.matches(&commits[0]).unwrap());
    let mut newest = in_head();
    newest.ticket = Ticket {
        slot: 1,
        generation: 99,
    };
    let new = request(wake, &mut newest, None, 999);
    assert_eq!(
        tick_answer(wake, &newest, None, &new, Outcome::Pending),
        Ok(true)
    );
    route.store.forget(newest.ticket);
    complete(&route, Ok(Decision::Applied));
    assert_eq!(settlement(wake, &mut driver), Some(first));
    commits.push(new);
    for original in commits {
        let receipt = settlement(wake, &mut driver).unwrap();
        assert!(receipt.matches(&original).unwrap());
        assert_eq!(
            ack_answer(
                wake,
                &driver,
                &wire::encode_settlement_ack(&receipt),
                Outcome::Pending
            ),
            Ok(true)
        );
        assert!(!route
            .store
            .conditional_ticket_kept(original.capability.ticket));
    }
    assert!(settlement(wake, &mut driver).is_none());
}

#[test]
fn refused_terminal_output_retires_submitted_commit_without_losing_late_applied() {
    let (route, wake, mut origin) = rig();
    let commit = request(wake, &mut origin, None, 120);
    assert_eq!(
        tick_answer(wake, &origin, None, &commit, Outcome::Pending),
        Ok(true)
    );
    assert_eq!(ack_answer(wake, &origin, &[], Outcome::Refused), Ok(false));
    route.store.forget(origin.ticket);
    complete(&route, Ok(Decision::Applied));
    let receipt = settlement(wake, &mut driver()).unwrap();
    assert!(receipt.matches(&commit).unwrap());
    assert_eq!(receipt.result.decision, Ok(Decision::Applied));
}

#[test]
fn actual_bound_instance_drop_and_quarantine_release_completed_retired_owners() {
    use super::super::{Adopter, Bind, ConnTable, LinkedRow, NoSink};
    for quarantine in [false, true] {
        let (route, _, mut origin) = rig();
        let plugin = super::super::load_linked::<super::super::kinds::plane::Plane>(
            &LinkedRow::of(door).unwrap(),
            Bind {
                instance: "settlement-teardown".into(),
                max_inflight_cap: 2,
                sink: Arc::new(NoSink),
                dispatcher: Adopter::unwatched(),
                conns: ConnTable::NoNeeds,
            },
        )
        .unwrap();
        let wake = plugin.inner.wake;
        let dynamic: Arc<dyn super::super::ticket::WakeRoute> = route.clone();
        assert!(wake.route.set(Arc::downgrade(&dynamic)).is_ok());
        let commit = request(wake, &mut origin, None, 121);
        assert_eq!(
            tick_answer(wake, &origin, None, &commit, Outcome::Pending),
            Ok(true)
        );
        route.store.forget(origin.ticket);
        complete(&route, Ok(Decision::Applied));
        assert!(route.store.conditional_ticket_kept(origin.ticket));
        if quarantine {
            super::super::plugin::quarantine(wake, "settlement teardown source control");
        } else {
            drop(plugin);
        }
        assert!(wake.revoked.load(Ordering::Acquire));
        assert!(route.store.settlement_input(caller(wake)).is_none());
        assert!(!route.store.conditional_ticket_kept(origin.ticket));
    }
}

#[test]
fn legacy_refusal_and_cancel_do_not_guard_ordinary_service_state() {
    let (route, wake, input) = rig();
    route.store.keep(input.ticket, 1);
    assert!(!route
        .store
        .conditional_negotiated(caller(wake), input.ticket));
    assert_eq!(ack_answer(wake, &input, &[], Outcome::Refused), Ok(false));
    route.store.conditional_cancel(caller(wake), input.ticket);
    assert!(!route
        .store
        .conditional_negotiated(caller(wake), input.ticket));
    assert!(route
        .store
        .conditional_output_allowed(caller(wake), input.ticket, None));
    assert_eq!(ack_answer(wake, &input, &[], Outcome::Ready), Ok(false));
    assert_eq!(route.store.held(), 1);
}
