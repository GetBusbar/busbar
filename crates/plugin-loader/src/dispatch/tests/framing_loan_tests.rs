// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::dispatch::auth_handle::{
    AuthCallAsk, AuthDone, AuthRan, HandInAsk, RefusalBytes, RefuseAsk, UnitSecret,
};
use busbar_contract::abi::host::service::UnitRef;
use busbar_contract::abi::transport::guest_policy::Policy;

#[derive(Default)]
struct Host {
    granted: Mutex<HashSet<u64>>,
    ended: Mutex<Vec<u64>>,
    scope: Mutex<Weak<FramingContext>>,
    cancel_on_open: Mutex<Option<Ticket>>,
}

impl AuthHandleHost for Host {
    fn unit_secret(&self, _: u64, _: u64) -> Option<UnitSecret> {
        None
    }
    fn auth_call(&self, _: AuthCallAsk, _: AuthDone) -> AuthRan {
        panic!("unexpected auth")
    }
    fn hand_in(&self, _: HandInAsk) -> Result<(u32, UnitRef), &'static str> {
        Err("unexpected hand-in")
    }
    fn refuse(&self, _: RefuseAsk) -> Result<RefusalBytes, &'static str> {
        Err("unexpected refusal")
    }
    fn stream_open(
        &self,
        _: u64,
        listener: u64,
        _: u64,
        stream: u64,
    ) -> Result<StreamPolicy, &'static str> {
        self.granted.lock().unwrap().insert(stream);
        let cancel = self.cancel_on_open.lock().unwrap().take();
        let scope = self.scope.lock().unwrap().upgrade();
        if let (Some(ticket), Some(scope)) = (cancel, scope) {
            scope.operation_finished(ticket, true);
        }
        Ok(StreamPolicy {
            policy: Arc::new(Policy {
                listener,
                generation: 3,
                lines: Vec::new(),
            }),
            full: Arc::from(b"full".as_slice()),
            current: Arc::from(b"current".as_slice()),
        })
    }
    fn stream_ended(&self, _: u64, _: u64, stream: u64) {
        if let Some(scope) = self.scope.lock().unwrap().upgrade() {
            assert!(
                scope.state.try_lock().is_ok(),
                "callback ran under context state guard"
            );
            assert!(
                scope.streams.try_lock().is_ok(),
                "callback ran under stream guard"
            );
        }
        self.granted.lock().unwrap().remove(&stream);
        self.ended.lock().unwrap().push(stream);
    }
    fn framing_ended(&self, _: u64) {}
}

fn ready() -> (Arc<Host>, Arc<FramingContext>) {
    let host = Arc::new(Host::default());
    let erased: Arc<dyn AuthHandleHost> = host.clone();
    let scope = FramingContext::new(7, 71, 0, Some(Arc::downgrade(&erased))).unwrap();
    *host.scope.lock().unwrap() = Arc::downgrade(&scope);
    scope.confirm(21).unwrap();
    (host, scope)
}

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 1,
    }
}
fn open(scope: &FramingContext, ticket: Ticket, stream: u64) {
    scope
        .open_stream(
            ticket,
            Open {
                stream,
                known_generation: 3,
            },
        )
        .unwrap();
}

#[test]
fn only_a_new_host_grant_progresses_its_own_operation_once() {
    let (host, scope) = ready();
    let first = ticket(1);
    let sibling = ticket(2);
    for stream in 0..70 {
        open(&scope, first, stream);
        assert!(!scope.take_control_progress(sibling));
        assert!(scope.take_control_progress(first));
        assert!(!scope.take_control_progress(first));
        open(&scope, first, stream);
        assert!(
            !scope.take_control_progress(first),
            "a cached/repeated loan is not progress"
        );
    }
    assert_eq!(host.granted.lock().unwrap().len(), 70);
    scope.operation_finished(first, false);
    assert!(!scope.take_control_progress(first));
    assert_eq!(
        host.granted.lock().unwrap().len(),
        70,
        "body-waiting streams retain their policy"
    );
}

#[test]
fn cancelling_a_pending_operation_revokes_only_its_unadmitted_streams() {
    let (host, scope) = ready();
    let pending = ticket(1);
    let sibling = ticket(2);
    open(&scope, pending, 5);
    scope.operation_done(pending);
    scope.claim_stream_operation(pending, 5, 3).unwrap();
    open(&scope, sibling, 7);
    scope.admit_stream(7);
    scope.operation_finished(pending, true);
    assert_eq!(*host.ended.lock().unwrap(), [5]);
    assert_eq!(scope.policy_generation(5, false), None);
    assert!(scope.operation_reply(pending).is_none());
    assert!(!scope.take_control_progress(pending));
    assert!(scope
        .open_stream(
            pending,
            Open {
                stream: 9,
                known_generation: 3
            }
        )
        .is_err());
    assert!(scope.claim_stream_operation(pending, 5, 3).is_err());
    scope.operation_finished(sibling, true);
    assert_eq!(
        *host.ended.lock().unwrap(),
        [5],
        "an admitted stream survives emit cancellation"
    );
    assert_eq!(scope.policy_generation(7, false), Some(3));
}

#[test]
fn completed_tickets_do_not_own_body_waiting_streams_but_later_auth_reclaims_them() {
    let (host, scope) = ready();
    let reused = ticket(1);
    let later = ticket(2);
    open(&scope, reused, 5);
    scope.operation_finished(reused, false);
    scope.operation_started(reused);
    open(&scope, reused, 7);
    scope.operation_finished(reused, true);
    assert_eq!(*host.ended.lock().unwrap(), [7]);
    assert_eq!(scope.policy_generation(5, false), Some(3));
    assert!(scope.claim_stream_operation(later, 5, 4).is_err());
    scope.claim_stream_operation(later, 5, 3).unwrap();
    assert!(scope.claim_stream_operation(ticket(3), 5, 3).is_err());
    scope.operation_finished(later, true);
    assert_eq!(*host.ended.lock().unwrap(), [7, 5]);
    scope.operation_started(reused);
    open(&scope, reused, 9);
    assert!(scope.take_control_progress(reused));
}

#[test]
fn cancellation_while_the_host_grants_cannot_resurrect_a_stream_or_progress_receipt() {
    let (host, scope) = ready();
    let operation = ticket(1);
    *host.cancel_on_open.lock().unwrap() = Some(operation);
    assert!(scope
        .open_stream(
            operation,
            Open {
                stream: 5,
                known_generation: 3
            }
        )
        .is_err());
    assert!(host.granted.lock().unwrap().is_empty());
    assert_eq!(*host.ended.lock().unwrap(), [5]);
    assert_eq!(scope.policy_generation(5, false), None);
    assert!(!scope.take_control_progress(operation));
    assert!(scope.operation_reply(operation).is_none());
}

mod typed_transport_cancellation {
    use super::*;
    use crate::dispatch::kinds::transport::Transport;
    use crate::dispatch::{
        in_head, load_linked, out_head, Bind, ConnTable, DispatchConfig, Dispatcher, Frame,
        LinkedRow, NoSink, Plugin, Reply, NO_BLOB,
    };
    use busbar_contract::abi::mechanism::call::{DeadlineClass, Op, Outcome, RawOutcome};
    use busbar_contract::abi::mechanism::door::{Door, DoorParts};
    use busbar_contract::abi::mechanism::lifecycle::{slot as life, CancelIn, OpenIn, OpenOut};
    use busbar_contract::abi::sdk::door::{blank_in, blank_out, RawDoorFn};
    use busbar_contract::abi::transport::{self, AdoptIn, BeginIn, EmitIn, FramerOut};
    use std::ffi::c_void;
    use std::future::Future;
    use std::mem::size_of;
    use std::pin::Pin;
    use std::sync::atomic::AtomicBool;
    use std::sync::OnceLock;
    use std::task::{Context, Wake, Waker};
    use std::time::{Duration, Instant};

    const WAIT: Duration = Duration::from_secs(10);

    struct Product {
        door: usize,
        cancel: Op,
        _library: libloading::Library,
    }

    fn product() -> &'static Product {
        static PRODUCT: OnceLock<Product> = OnceLock::new();
        PRODUCT.get_or_init(|| {
            let path = std::env::var_os("BUSBAR_TEST_HTTP_CDYLIB")
                .expect("BUSBAR_TEST_HTTP_CDYLIB names the actual HTTP transport library");
            let library = crate::dlopen_on_worker(&path).expect("the product HTTP library opens");
            // SAFETY: this is the mechanism's door symbol; the process-held library owns it.
            let raw = unsafe {
                *library
                    .get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
                    .expect("the product HTTP library exports its door")
            };
            crate::dispatch::load::validate::<Transport>(raw)
                .expect("the genuine product descriptor has the complete Transport table");
            let real = crate::ffi_thread::on_plugin_thread(|| {
                // SAFETY: the actual product library owns this door for the process lifetime.
                unsafe { &*raw() }.parts()
            })
            .expect("the product descriptor reads on its FFI thread");
            // SAFETY: the genuine descriptor has the transport ABI table; the normal loader
            // below validates its Statement, layout and table before any operation is submitted.
            let mut ops = unsafe { *real.ops.cast::<transport::Ops>() };
            let cancel = ops.head.cancel.expect("the product transport serves CANCEL");
            ops.adopt = Some(pending_adopt);
            ops.emit = Some(pending_commit);
            ops.head.cancel = Some(observed_cancel);
            let ops = Box::leak(Box::new(ops));
            // SAFETY: all original descriptor data and code remain process-held. The only
            // replaced kind callbacks inject Pending and never manufacture a protocol answer.
            let door = unsafe {
                Door::__from_parts(DoorParts {
                    ops: &ops.head,
                    ..real
                })
            };
            Product {
                door: Box::into_raw(Box::new(door)) as usize,
                cancel,
                _library: library,
            }
        })
    }

    #[derive(Default)]
    struct Control {
        calls: AtomicU64,
        cancel_entries: AtomicU64,
        cancel_completions: AtomicU64,
        release_cancel: AtomicBool,
        input: Mutex<Option<(u32, Ticket, usize, usize, usize)>>,
    }

    fn controls() -> &'static Mutex<HashMap<usize, Arc<Control>>> {
        static CONTROLS: OnceLock<Mutex<HashMap<usize, Arc<Control>>>> = OnceLock::new();
        CONTROLS.get_or_init(Mutex::default)
    }

    fn control(instance: *mut c_void) -> Arc<Control> {
        controls().lock().unwrap().get(&(instance as usize)).unwrap().clone()
    }

    fn pending(
        instance: *mut c_void,
        slot: u32,
        ticket: Ticket,
        frame: usize,
        bytes: *const u8,
        len: usize,
    ) {
        let control = control(instance);
        control.calls.fetch_add(1, Ordering::SeqCst);
        let mut input = control.input.lock().unwrap();
        let identity = (slot, ticket, frame, bytes as usize, len);
        if let Some(original) = *input {
            assert_eq!(identity, original, "a recall must keep the exact typed frame and loan");
        } else {
            *input = Some(identity);
        }
    }

    crate::dispatch_tests::c_abi! {
        fn fault_door() -> &'static Door {
            // SAFETY: product() retains the descriptor and its library for the process lifetime.
            unsafe { &*(product().door as *const Door) }
        }
        fn pending_adopt(instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
            // SAFETY: the actual Transport dispatcher supplies the named typed ADOPT frame.
            let (input, output) = unsafe { (&*input.cast::<AdoptIn>(), &mut *out.cast::<FramerOut>()) };
            assert_eq!(input.head.size as usize, size_of::<AdoptIn>());
            pending(instance, transport::slot::ADOPT, input.head.ticket, input as *const AdoptIn as usize, input.leftover, input.leftover_len);
            output.head.outcome = RawOutcome::of(Outcome::Pending);
            RawOutcome::of(Outcome::Pending)
        }
        fn pending_commit(instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
            // SAFETY: the actual Transport dispatcher supplies the named typed upgrade EMIT frame.
            let (input, output) = unsafe { (&*input.cast::<EmitIn>(), &mut *out.cast::<FramerOut>()) };
            assert_eq!(input.head.size as usize, size_of::<EmitIn>());
            pending(instance, transport::slot::EMIT, input.head.ticket, input as *const EmitIn as usize, input.bytes, input.len);
            output.head.outcome = RawOutcome::of(Outcome::Pending);
            RawOutcome::of(Outcome::Pending)
        }
        fn observed_cancel(instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
            let control = control(instance);
            // SAFETY: the actual Transport lifecycle supplies CancelIn and its original output.
            let cancel = unsafe { &*input.cast::<CancelIn>() };
            assert_eq!(cancel.ticket, control.input.lock().unwrap().unwrap().1);
            control.cancel_entries.fetch_add(1, Ordering::SeqCst);
            until(|| control.release_cancel.load(Ordering::Acquire));
            let (_, _, _, bytes, len) = control.input.lock().unwrap().unwrap();
            // SAFETY: the test retains an independent safety owner even if dispatcher custody
            // fails; strong counts independently assert the dispatcher's original loan remains.
            assert_eq!(unsafe { std::slice::from_raw_parts(bytes as *const u8, len) }, b"original framing loan");
            let outcome = (product().cancel)(instance, input, out);
            control.cancel_completions.fetch_add(1, Ordering::SeqCst);
            outcome
        }
    }

    fn until(mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !ready() {
            assert!(Instant::now() < deadline, "the transport cancellation did not progress");
            std::thread::yield_now();
        }
    }

    struct Release(Arc<Control>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.release_cancel.store(true, Ordering::Release);
        }
    }

    struct NoWake;
    impl Wake for NoWake {
        fn wake(self: Arc<Self>) {}
    }

    fn rig() -> (Dispatcher, Plugin<Transport>, usize, Arc<Control>, Arc<FramingContext>, u64) {
        let dispatcher = Dispatcher::new(DispatchConfig::default());
        let plugin = load_linked::<Transport>(
            &LinkedRow::of(fault_door).expect("the genuine transport Statement renders"),
            Bind {
                instance: "typed-framing-loan-negative".into(),
                max_inflight_cap: 4,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .expect("actual Transport admission validates the held product descriptor");
        let mut opening = Frame::new(
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
        );
        assert_eq!(plugin.call(life::OPEN, &mut opening).outcome, Outcome::Ready);
        let scope = dispatcher.framing_context(plugin.instance().0, 0, 0).unwrap();
        let mut input: BeginIn = blank_in();
        input.side = transport::SIDE_DIAL;
        input.scheme = busbar_contract::abi::host::service::SCHEME_PLAIN;
        input.target = busbar_contract::abi::mechanism::call::AbiStr {
            ptr: b"http://127.0.0.1/".as_ptr(),
            len: b"http://127.0.0.1/".len(),
        };
        let mut beginning = Frame::new(input, blank_out::<FramerOut>());
        let begun = with_context(Some(scope.clone()), || plugin.call(transport::slot::BEGIN, &mut beginning));
        assert_eq!(begun.outcome, Outcome::Ready, "the actual product begins the source framing");
        assert_ne!(beginning.out.framing, 0);
        scope.confirm(beginning.out.framing).unwrap();
        let instance = opening.out.instance as usize;
        let control = Arc::new(Control::default());
        assert!(controls().lock().unwrap().insert(instance, control.clone()).is_none());
        (dispatcher, plugin, instance, control, scope, beginning.out.framing)
    }

    fn cancelled<I: crate::dispatch::InFrame>(
        dispatcher: &Dispatcher,
        plugin: &Plugin<Transport>,
        control: &Arc<Control>,
        ticket: Ticket,
        mut reply: Reply<I, FramerOut>,
        loan: &Arc<Vec<u8>>,
        slot: u32,
    ) {
        let release = Release(control.clone());
        until(|| control.calls.load(Ordering::SeqCst) == 1);
        let waker = Waker::from(Arc::new(NoWake));
        assert!(Pin::new(&mut reply)
            .poll(&mut Context::from_waker(&waker))
            .is_pending());
        assert_eq!(control.input.lock().unwrap().unwrap().0, slot);
        assert_eq!(control.cancel_entries.load(Ordering::SeqCst), 0);
        assert!(Arc::strong_count(loan) > 1, "Pending retains the original payload loan");
        drop(reply);
        until(|| control.cancel_entries.load(Ordering::SeqCst) == 1);
        assert_eq!(control.cancel_completions.load(Ordering::SeqCst), 0);
        assert!(Arc::strong_count(loan) > 1, "CANCEL still borrows the original payload");
        drop(release);
        until(|| control.cancel_completions.load(Ordering::SeqCst) == 1);
        assert!(dispatcher.retirement_barrier(ticket, WAIT));
        assert_eq!(Arc::strong_count(loan), 1, "only retirement releases dispatcher custody");
        let waking = crate::dispatch::ticket::Waking::of(plugin.inner.wake).unwrap();
        waking.wake(ticket);
        waking.wake(ticket);
        assert!(dispatcher.retirement_barrier(ticket, WAIT));
        assert_eq!(control.calls.load(Ordering::SeqCst), 1, "late wakes never recall ADOPT or EMIT");
        assert_eq!(control.cancel_entries.load(Ordering::SeqCst), 1);
        assert_eq!(control.cancel_completions.load(Ordering::SeqCst), 1);
        dispatcher.recycle(ticket);
    }

    #[test]
    fn pending_typed_adopt_keeps_its_original_loan_until_cancel_retirement() {
        let (dispatcher, plugin, instance, control, scope, _) = rig();
        let ticket = dispatcher.mint(0).unwrap();
        let loan = Arc::new(b"original framing loan".to_vec());
        let mut input: AdoptIn = blank_in();
        input.side = transport::SIDE_ACCEPT;
        input.leftover = loan.as_ptr();
        input.leftover_len = loan.len();
        let reply = with_context(Some(scope), || dispatcher.submit_lent(
            &plugin, ticket, transport::slot::ADOPT, Frame::new(input, blank_out::<FramerOut>()),
            DeadlineClass::Call, 0, loan.clone(),
        ));
        cancelled(&dispatcher, &plugin, &control, ticket, reply, &loan, transport::slot::ADOPT);
        controls().lock().unwrap().remove(&instance);
    }

    #[test]
    fn pending_typed_upgrade_commit_keeps_its_original_loan_until_cancel_retirement() {
        let (dispatcher, plugin, instance, control, scope, framing) = rig();
        let ticket = dispatcher.mint(0).unwrap();
        let loan = Arc::new(b"original framing loan".to_vec());
        let mut input: EmitIn = blank_in();
        input.framing = framing;
        input.stream = 5;
        input.bytes = loan.as_ptr();
        input.len = loan.len();
        input.end_of_frame = 1;
        input.status = 101;
        let reply = with_context(Some(scope), || dispatcher.submit_lent(
            &plugin, ticket, transport::slot::EMIT, Frame::new(input, blank_out::<FramerOut>()),
            DeadlineClass::Call, 0, loan.clone(),
        ));
        cancelled(&dispatcher, &plugin, &control, ticket, reply, &loan, transport::slot::EMIT);
        controls().lock().unwrap().remove(&instance);
    }
}
