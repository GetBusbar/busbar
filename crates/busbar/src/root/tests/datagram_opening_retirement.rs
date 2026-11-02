// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Instant;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::blank_in;
use busbar_contract::abi::transport::EmitIn;
use busbar_core_connector::datagram::Pairing;
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};
use busbar_core_connector::publication::{Memory, Messages};
use busbar_core_connector::udp::{bind, ReadyPort};
use busbar_core_connector::Connector;
use busbar_kernel::config::limits::{BuildScope, LimitsResolved};
use busbar_kernel::plane_driver::{CallerEnd, SessionCaller};
use busbar_test_kit::root_door_fixtures::datagram_order::Recording;

use super::{lock, CallerLeg, ClaimDoor, Joining, Opened};

#[derive(Clone, Copy)]
enum Preparation {
    Accepted,
    NoDescription,
    Refused,
    Panicked,
}

type Callback = Arc<dyn Fn() + Send + Sync>;

struct OpeningFramer {
    recording: Arc<Recording>,
    preparation: Preparation,
    settled: AtomicBool,
    finishes: AtomicUsize,
    on_finish: Mutex<Option<Callback>>,
}

impl OpeningFramer {
    fn new(preparation: Preparation) -> Arc<Self> {
        let recording = Recording::new();
        recording.echo_emits();
        Arc::new(Self {
            recording,
            preparation,
            settled: AtomicBool::new(false),
            finishes: AtomicUsize::new(0),
            on_finish: Mutex::new(None),
        })
    }
}

impl FramerDoor for OpeningFramer {
    fn facts(&self) -> &DoorFacts {
        self.recording.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Ingest(input, out) if !self.settled.swap(true, Ordering::SeqCst) => {
                let crossed = self.recording.cross(Call::Ingest(&mut *input, &mut *out));
                match self.preparation {
                    Preparation::NoDescription => return crossed,
                    Preparation::Refused => {
                        return Crossed {
                            outcome: Outcome::Refused,
                            error: None,
                        };
                    }
                    Preparation::Panicked => panic!("opening preparation panicked"),
                    Preparation::Accepted => {}
                }
                let frame_len = out.yielded.frame_len;
                assert!(input.sink.pieces_cap >= 2);
                let mut echo: EmitIn = blank_in();
                echo.framing = input.framing;
                echo.bytes = b"host".as_ptr();
                echo.len = 4;
                echo.end_of_frame = 1;
                echo.sink = input.sink;
                self.recording.cross(Call::Emit(&mut echo, &mut *out));
                echo.stream = 1;
                echo.sink.pieces = echo.sink.pieces.wrapping_add(1);
                echo.sink.pieces_cap -= 1;
                self.recording.cross(Call::Emit(&mut echo, &mut *out));
                out.yielded.frame_len = frame_len;
                out.yielded.pieces_len = 2;
                crossed
            }
            Call::Finish(input, out) => {
                self.finishes.fetch_add(1, Ordering::SeqCst);
                let callback = lock(&self.on_finish).clone();
                if let Some(callback) = callback {
                    callback();
                }
                self.recording.cross(Call::Finish(input, out))
            }
            call => self.recording.cross(call),
        }
    }
}

fn door() -> Arc<ClaimDoor> {
    ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap())
}

fn open(door: &Arc<ClaimDoor>, framer: &Arc<OpeningFramer>) -> Result<Opened, String> {
    let limits = LimitsResolved {
        datagram_line_memory_bytes: Some(
            4 * busbar_core_connector::test_support::datagram_output_reservation_bytes(),
        ),
        ..LimitsResolved::default()
    };
    let _scope = BuildScope::enter(&limits);
    Opened::open(door, Arc::clone(framer) as Arc<dyn FramerDoor>, b"offer")
}

fn only_joining(opened: Opened) -> Joining {
    let Opened {
        description,
        caller,
        head,
        joining,
    } = opened;
    drop((description, caller, head));
    joining
}

struct Observed {
    leg: Weak<CallerLeg>,
    pairing: Weak<Pairing>,
    messages: Weak<Messages>,
    memory: Arc<Memory>,
}

impl Observed {
    fn new(opened: &Opened) -> Self {
        let pairing = lock(&opened.caller.leg.pairing).clone().unwrap();
        let memory = pairing.memory_account();
        assert!(memory.used() > 0, "the actual opening has charged custody");
        assert_eq!(opened.description.bytes, b"host");
        Self {
            leg: Arc::downgrade(&opened.caller.leg),
            pairing: Arc::downgrade(&pairing),
            messages: Arc::downgrade(&opened.caller.from),
            memory,
        }
    }

    fn retired(&self, framer: &OpeningFramer) {
        assert!(self.leg.upgrade().is_none(), "the caller cycle retired");
        assert!(self.pairing.upgrade().is_none(), "the pairing retired");
        assert!(
            self.messages.upgrade().is_none(),
            "the opening queue retired"
        );
        assert_eq!(self.memory.used(), 0, "all opening custody retired");
        assert_eq!(framer.finishes.load(Ordering::SeqCst), 1);
    }
}

fn assert_host_unlocked(door: &ClaimDoor, leg: &CallerLeg) {
    assert!(door.legs.try_lock().is_ok());
    assert!(leg.id.try_lock().is_ok());
    assert!(leg.pairing.try_lock().is_ok());
    assert!(leg.outbound.try_lock().is_ok());
    assert!(leg.to_session.try_lock().is_ok());
}

#[tokio::test]
async fn dropping_an_accepted_opening_retires_its_cycle_queue_and_custody_once() {
    let door = door();
    let framer = OpeningFramer::new(Preparation::Accepted);
    let opened = open(&door, &framer).unwrap();
    let observed = Observed::new(&opened);
    drop(opened);
    observed.retired(&framer);
    assert!(lock(&door.legs).is_empty());
    assert!(door.assocs.is_empty());
    door.close();
    assert_eq!(framer.finishes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn refusal_retires_the_opening_when_the_last_admission_holder_drops() {
    let door = door();
    let framer = OpeningFramer::new(Preparation::Accepted);
    let opened = open(&door, &framer).unwrap();
    let observed = Observed::new(&opened);
    let joining = only_joining(opened);
    let opening = Arc::new(Mutex::new(Some(joining)));
    let admitted = Arc::clone(&opening);
    let refused = move || drop(admitted);
    drop(opening);
    assert!(observed.pairing.upgrade().is_some());
    refused();
    observed.retired(&framer);
    assert!(lock(&door.legs).is_empty());
    assert!(door.assocs.is_empty());
    door.close();
}

#[tokio::test]
async fn cancelling_before_or_after_first_poll_retires_the_accepted_opening() {
    for first_poll in [false, true] {
        let door = door();
        let framer = OpeningFramer::new(Preparation::Accepted);
        let opened = open(&door, &framer).unwrap();
        let observed = Observed::new(&opened);
        let mut cancelled = Box::pin(async move {
            let opening = opened;
            std::future::pending::<()>().await;
            drop(opening);
        });
        if first_poll {
            let wake = Waker::noop();
            assert!(cancelled
                .as_mut()
                .poll(&mut Context::from_waker(wake))
                .is_pending());
        }
        drop(cancelled);
        observed.retired(&framer);
        door.close();
    }
}

#[tokio::test]
async fn preparation_errors_and_unwinding_finish_the_actual_framing_once() {
    for preparation in [
        Preparation::NoDescription,
        Preparation::Refused,
        Preparation::Panicked,
    ] {
        let door = door();
        let framer = OpeningFramer::new(preparation);
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| open(&door, &framer)));
        match preparation {
            Preparation::Panicked => assert!(result.is_err()),
            _ => assert!(result.unwrap().is_err()),
        }
        assert_eq!(framer.finishes.load(Ordering::SeqCst), 1);
        assert!(lock(&door.legs).is_empty());
        door.close();
    }
}

#[tokio::test]
async fn a_book_refusal_retires_the_already_joined_association_outside_host_locks() {
    let door = door();
    let framer = OpeningFramer::new(Preparation::Accepted);
    let opened = open(&door, &framer).unwrap();
    let observed = Observed::new(&opened);
    let weak_door = Arc::downgrade(&door);
    let weak_leg = observed.leg.clone();
    let weak_pairing = observed.pairing.clone();
    *lock(&framer.on_finish) = Some(Arc::new(move || {
        let door = weak_door.upgrade().unwrap();
        let leg = weak_leg.upgrade().unwrap();
        assert_host_unlocked(&door, &leg);
        let pairing = weak_pairing.upgrade().unwrap();
        assert!(pairing.closed());
        pairing.close();
    }));
    let joining = only_joining(opened);
    let connector = Connector::new();
    let refusal = joining.admit_into(0, &connector).unwrap_err();
    assert!(refusal.starts_with("the session book refused"));
    observed.retired(&framer);
    assert!(lock(&door.legs).is_empty());
    assert!(door.assocs.is_empty());
    door.close();
}

#[tokio::test]
async fn a_duplicate_book_key_retires_only_the_second_joined_opening() {
    let connector = Connector::new();
    let first_door = door();
    let first_framer = OpeningFramer::new(Preparation::Accepted);
    let first = open(&first_door, &first_framer).unwrap();
    let first_observed = Observed::new(&first);
    only_joining(first).admit_into(1, &connector).unwrap();

    let second_door = door();
    let second_framer = OpeningFramer::new(Preparation::Accepted);
    let second = open(&second_door, &second_framer).unwrap();
    let second_observed = Observed::new(&second);
    let refused = only_joining(second).admit_into(1, &connector).unwrap_err();
    assert!(refused.starts_with("the session book refused"));
    second_observed.retired(&second_framer);
    assert!(lock(&second_door.legs).is_empty());
    assert!(second_door.assocs.is_empty());
    assert!(!first_observed.pairing.upgrade().unwrap().closed());
    assert_eq!(first_framer.finishes.load(Ordering::SeqCst), 0);
    connector.unpair(1);
    first_observed.retired(&first_framer);
    first_door.close();
    second_door.close();
}

#[tokio::test]
async fn a_door_refusal_closes_only_the_refused_opening() {
    let door = door();
    let connector = Connector::new();
    let accepted = OpeningFramer::new(Preparation::Accepted);
    let first = open(&door, &accepted).unwrap();
    let first_observed = Observed::new(&first);
    let joining = only_joining(first);
    joining.admit_into(1, &connector).unwrap();
    let refused = OpeningFramer::new(Preparation::Accepted);
    let second = open(&door, &refused).unwrap();
    let observed = Observed::new(&second);
    let joining = only_joining(second);
    let refusal = joining.admit_into(2, &connector).unwrap_err();
    assert!(refusal.starts_with("the claim door refused"));
    observed.retired(&refused);
    assert!(!first_observed.pairing.upgrade().unwrap().closed());
    assert_eq!(accepted.finishes.load(Ordering::SeqCst), 0);
    connector.unpair(1);
    first_observed.retired(&accepted);
    door.close();
}

struct ReentrantWake(Callback);

impl Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
        (self.0)();
    }
}

#[tokio::test]
async fn successful_admission_keeps_serving_until_explicit_retirement_and_wakes_without_locks() {
    let door = door();
    let connector = Arc::new(Connector::new());
    let framer = OpeningFramer::new(Preparation::Accepted);
    let opened = open(&door, &framer).unwrap();
    let observed = Observed::new(&opened);
    let Opened {
        caller,
        description,
        head,
        joining,
    } = opened;
    let holder = Arc::new(Mutex::new(Some(joining)));
    let joining = lock(&holder).take().unwrap();
    joining.admit_into(1, &connector).unwrap();
    drop(holder);
    assert!(!observed.pairing.upgrade().unwrap().closed());
    assert_eq!(framer.finishes.load(Ordering::SeqCst), 0);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        assert_eq!(caller.read().await, Some(Vec::new()));
        assert_eq!(caller.read().await, Some(b"host".to_vec()));
        caller.leg.take(
            vec![super::tests::got(1, b"label: messages\r\n", true)],
            Instant::now(),
        );
        assert!(caller.write(b"served").await);
        assert_eq!(caller.read().await, Some(b"served".to_vec()));
    })
    .await
    .expect("the admitted association serves its opening and later output");
    assert_eq!(framer.recording.emitted().last().unwrap(), b"served");

    let weak_door = Arc::downgrade(&door);
    let weak_leg = observed.leg.clone();
    let weak_pairing = observed.pairing.clone();
    let weak_connector = Arc::downgrade(&connector);
    let wakes = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&wakes);
    let wake = Waker::from(Arc::new(ReentrantWake(Arc::new(move || {
        assert_host_unlocked(&weak_door.upgrade().unwrap(), &weak_leg.upgrade().unwrap());
        let pairing = weak_pairing.upgrade().unwrap();
        assert!(pairing.closed());
        pairing.close();
        weak_connector.upgrade().unwrap().unpair(1);
        count.fetch_add(1, Ordering::SeqCst);
    }))));
    assert!(matches!(
        caller.from.poll_recv(&mut Context::from_waker(&wake)),
        Poll::Pending
    ));
    connector.unpair(1);
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    assert_eq!(framer.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(caller.read().await, None);
    assert!(!caller.write(b"retired").await);
    drop((caller, description, head));
    observed.retired(&framer);
    connector.unpair(1);
    assert!(lock(&door.legs).is_empty());
    assert!(door.assocs.is_empty());
    door.close();
}
