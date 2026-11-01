// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A datagram session's caller leg: its channel messages are the session's pieces, what the plane
//! writes before the channel opens waits for it, and a plane that falls behind its caller ends the
//! session (its pairing closes, the leg with it).

use std::sync::Arc;
use std::time::Instant;

use busbar_core_connector::datagram::Pairing;
use busbar_core_connector::framer::Got;
use busbar_core_connector::udp::{bind, ReadyPort};
use tokio::sync::mpsc;

use super::{lock, CallerLeg, ClaimDoor, ClaimDoors, CALLER_QUEUE};

fn got(stream: u64, bytes: &[u8], fields: bool) -> Got {
    Got {
        stream,
        bytes: bytes.to_vec(),
        end_of_frame: true,
        status_code: None,
        handoff: false,
        status_class: 0,
        fault: 0,
        retry_after_secs: None,
        declared_len: None,
        fields,
        text: false,
        reason: None,
        failed: false,
        end: false,
    }
}

fn leg(
    capacity: usize,
) -> (
    Arc<ClaimDoor>,
    Arc<CallerLeg>,
    Arc<Pairing>,
    mpsc::Receiver<Vec<u8>>,
) {
    let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let (tx, rx) = mpsc::channel(capacity);
    let leg = CallerLeg::new(&door, tx);
    let pairing = Pairing::new(
        Arc::clone(&leg) as Arc<dyn busbar_core_connector::datagram::LegSink>,
        door.local(),
    );
    *lock(&leg.pairing) = Some(Arc::clone(&pairing));
    (door, leg, pairing, rx)
}

#[tokio::test]
async fn a_channels_messages_are_the_sessions_pieces_and_early_writes_wait_for_the_channel() {
    let (door, leg, pairing, mut rx) = leg(8);
    let framer = busbar_test_kit::root_door_fixtures::datagram_order::Recording::new();
    join_recording(&door, &leg, &framer);
    let mut doors = ClaimDoors::default();
    doors.insert("dg", Arc::clone(&door));
    assert!(doors.get("dg").is_some() && doors.get("other").is_none());
    let now = Instant::now();
    // Written before the channel opened: held, not lost.
    assert!(leg.write(b"early", true).await);
    assert_eq!(lock(&leg.outbound).held.len(), 1);
    leg.take(
        vec![
            got(0, b"description", false),
            got(1, b"label: events\r\n", true),
            got(1, b"{\"type\":\"x\"}", false),
        ],
        now,
    );
    let caller = caller_for(Arc::clone(&leg));
    assert!(busbar_kernel::plane_driver::CallerEnd::write(&caller, b"after opening").await);
    assert_eq!(
        lock(&leg.outbound).channel,
        Some(1),
        "the first channel is the session's"
    );
    assert!(
        lock(&leg.outbound).held.is_empty(),
        "released onto the channel"
    );
    assert_eq!(rx.recv().await.unwrap(), b"{\"type\":\"x\"}");
    assert!(rx.try_recv().is_err(), "the description is never a piece");
    assert!(!pairing.closed());
}

/// RED: a plane that does not keep up with its caller ends the session: the pairing closes and
/// the caller's queue with it.
#[tokio::test]
async fn a_plane_that_falls_behind_its_caller_ends_the_session() {
    let (_door, leg, pairing, mut rx) = leg(2);
    let now = Instant::now();
    let mut pieces = vec![got(1, b"label: events\r\n", true)];
    pieces.extend((0..3).map(|_| got(1, b"m", false)));
    leg.take(pieces, now);
    assert!(pairing.closed(), "the third message found the queue full");
    assert!(lock(&leg.to_session).is_none());
    assert_eq!(rx.recv().await.unwrap(), b"m");
    assert_eq!(rx.recv().await.unwrap(), b"m");
    assert!(rx.recv().await.is_none(), "the session's caller side ended");
}

/// Up to the caller queue's bound, what the plane writes before the far end opens a channel waits
/// for it and is released onto it once the channel opens; the session stands (THE DESIGN l.758-765:
/// application data waits). The green twin of the test below; RED before the fix: none, it passes
/// before and after.
#[tokio::test]
async fn early_writes_up_to_the_bound_wait_for_the_channel() {
    let (door, leg, pairing, _rx) = leg(8);
    let framer = busbar_test_kit::root_door_fixtures::datagram_order::Recording::new();
    join_recording(&door, &leg, &framer);
    let now = Instant::now();
    for _ in 0..CALLER_QUEUE {
        assert!(leg.write(b"early", false).await);
    }
    assert_eq!(lock(&leg.outbound).held.len(), CALLER_QUEUE);
    assert!(!pairing.closed());
    leg.take(vec![got(1, b"label: events\r\n", true)], now);
    let caller = caller_for(Arc::clone(&leg));
    assert!(busbar_kernel::plane_driver::CallerEnd::write(&caller, b"after opening").await);
    assert!(
        lock(&leg.outbound).held.is_empty(),
        "released onto the channel"
    );
    assert!(!pairing.closed());
}

/// What the plane writes before the far end opens a channel is held to the same bound as what the
/// caller sends the plane: the write past it is refused and ends the session (its pairing closes,
/// the leg and what it held with it), as a plane that falls behind its caller does; a far end that
/// never opens a channel cannot grow the host's memory for the session's whole life (THE DESIGN
/// l.758-765; l.2221 #38(c): every collection has a ceiling). RED before the fix: the held queue had
/// no bound, so the write past it was accepted and held, the session stood, and a closed leg went
/// on holding writes.
#[tokio::test]
async fn a_plane_that_writes_past_the_bound_before_the_channel_opens_ends_the_session() {
    let (_door, leg, pairing, mut rx) = leg(8);
    for _ in 0..CALLER_QUEUE {
        assert!(leg.write(b"early", false).await);
    }
    assert!(
        !leg.write(b"one too many", false).await,
        "the write past the bound is refused"
    );
    assert!(pairing.closed(), "the session ended");
    assert!(
        lock(&leg.outbound).held.is_empty(),
        "what it held went with it"
    );
    assert!(lock(&leg.to_session).is_none());
    assert!(rx.recv().await.is_none(), "the session's caller side ended");
    assert!(
        !leg.write(b"after", false).await,
        "a closed leg takes no write"
    );
    assert!(lock(&leg.outbound).held.is_empty(), "nor holds one");
}

/// A door that states only its facts.
struct Stated(busbar_core_connector::framer::DoorFacts);

impl busbar_core_connector::framer::FramerDoor for Stated {
    fn facts(&self) -> &busbar_core_connector::framer::DoorFacts {
        &self.0
    }
    fn cross(
        &self,
        _call: busbar_core_connector::framer::Call<'_>,
    ) -> busbar_core_connector::framer::Crossed {
        busbar_core_connector::framer::Crossed {
            outcome: busbar_contract::abi::mechanism::call::Outcome::Refused,
            error: None,
        }
    }
}

fn stated(
    name: &'static str,
    datagram: bool,
) -> Arc<dyn busbar_core_connector::framer::FramerDoor> {
    Arc::new(Stated(busbar_core_connector::framer::DoorFacts {
        name: name.into(),
        claims: vec![name],
        role: busbar_contract::abi::transport::ROLE_FRAMER,
        composes_over: Vec::new(),
        ported: false,
        status_rows: Vec::new(),
        duplex: vec![name],
        datagram,
    }))
}

fn need(transport: &str, listen: &str) -> crate::root::loader::boot::InboundBind {
    crate::root::loader::boot::InboundBind {
        owner: crate::root::loader::boot::BindOwner::Need {
            instance: "streams".into(),
            kind: busbar_contract::abi::mechanism::KindCode::Plane,
            need: 0,
        },
        transport: transport.into(),
        at: format!("streams.{transport}"),
        listen: listen.parse().unwrap(),
        tls: None,
        max_conns: 1024,
    }
}

fn framers(scheme: &str) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>> {
    match scheme {
        "dg" => Some(stated("dg", true)),
        "lp" => Some(stated("lp", false)),
        _ => None,
    }
}

/// Ruling (d): a claim door is bound for every inbound listener whose transport a datagram framer
/// answers, on its `{listen}` address, and for no other listener. RED arms: a wildcard address
/// (no candidate to advertise) and a second door for one claim are refused, naming the setting.
#[tokio::test]
async fn boot_binds_a_claim_door_for_each_datagram_listener_and_no_other() {
    let root = crate::root::loader::boot::InboundBind {
        owner: crate::root::loader::boot::BindOwner::Root,
        transport: String::new(),
        at: "listen".into(),
        listen: "127.0.0.1:0".parse().unwrap(),
        tls: None,
        max_conns: u64::MAX,
    };
    let doors = ClaimDoors::bind(
        &[root, need("lp", "127.0.0.1:0"), need("dg", "127.0.0.1:0")],
        framers,
    )
    .expect("the claim doors bind");
    let dg = doors
        .get("dg")
        .expect("the datagram listener is a claim door");
    assert_eq!(dg.local().ip(), std::net::IpAddr::from([127, 0, 0, 1]));
    assert_ne!(dg.local().port(), 0, "bound");
    assert!(
        doors.get("lp").is_none(),
        "a stream listener is no claim door"
    );
    assert!(
        doors.get("").is_none(),
        "the root's own listener is no claim door"
    );

    let wild = ClaimDoors::bind(&[need("dg", "0.0.0.0:0")], framers).expect_err("a wildcard");
    assert!(wild.contains("streams.dg.listen"), "{wild}");
    let twice = ClaimDoors::bind(
        &[need("dg", "127.0.0.1:0"), need("dg", "127.0.0.1:0")],
        framers,
    )
    .expect_err("one claim, two doors");
    assert!(twice.contains("a second claim door"), "{twice}");
}

/// A datagram session's open answers under the head its plane states on the session's first
/// crossing: the plane's status and its fields, `location` among
/// them, as it stated them.
#[tokio::test]
async fn the_open_answers_under_the_head_the_plane_states() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let location = (b"location".to_vec(), b"/v1/calls/c_0123abcd".to_vec());
    tx.send((201, vec![location.clone()])).unwrap();
    let head = super::plane_head(rx, std::time::Duration::from_secs(5)).await;
    assert_eq!(head, Some((201, vec![location])));
}

/// RED: a plane that states no head within the open's bound, or whose session ends first, answers
/// nothing: the open is refused, never a bare 201.
#[tokio::test]
async fn a_plane_that_states_no_head_in_time_answers_nothing() {
    let (_held, rx) = tokio::sync::oneshot::channel::<(u32, super::HeadFields)>();
    let started = Instant::now();
    assert_eq!(
        super::plane_head(rx, std::time::Duration::from_millis(50)).await,
        None
    );
    assert!(started.elapsed() >= std::time::Duration::from_millis(50));
    let (dropped, rx) = tokio::sync::oneshot::channel::<(u32, super::HeadFields)>();
    drop(dropped);
    assert_eq!(
        super::plane_head(rx, std::time::Duration::from_secs(5)).await,
        None
    );
}

/// The session's caller side opens with one empty piece, before the caller's first message: the
/// plane crosses the session once before the open is answered.
#[tokio::test]
async fn the_caller_side_opens_with_one_empty_piece() {
    use busbar_kernel::plane_driver::SessionCaller;
    let (_door, leg, _pairing, _rx) = leg(8);
    let (to, from) = mpsc::channel(8);
    let (head, _rx) = tokio::sync::oneshot::channel();
    let caller = super::DatagramCaller {
        leg,
        from: tokio::sync::Mutex::new(from),
        head: std::sync::Mutex::new(Some(head)),
        stated: std::sync::atomic::AtomicU32::new(0),
        opened: std::sync::atomic::AtomicBool::new(false),
    };
    to.send(b"{\"type\":\"x\"}".to_vec()).await.unwrap();
    assert_eq!(caller.read().await, Some(Vec::new()), "the open");
    assert_eq!(caller.read().await, Some(b"{\"type\":\"x\"}".to_vec()));
    drop(to);
    assert_eq!(caller.read().await, None);
}

#[tokio::test]
async fn a_reentrant_write_cannot_overtake_the_early_messages_being_released() {
    use busbar_core_connector::datagram::DatagramFraming;
    use busbar_core_connector::framer::FramerDoor;
    use busbar_test_kit::root_door_fixtures::datagram_order::Recording;

    let (door, leg, pairing, _rx) = leg(8);
    let framer = Recording::new();
    let now = Instant::now();
    let (mut framing, _) =
        DatagramFraming::accept_minted(Arc::clone(&framer) as Arc<dyn FramerDoor>, door.local())
            .expect("begin");
    framing.rendezvous(b"offer", now).expect("valid terms");
    door.join(framing, &leg).expect("join");
    let weak = Arc::downgrade(&leg);
    let (written, third) = tokio::sync::oneshot::channel();
    let written = std::sync::Mutex::new(Some(written));
    framer.observe(Arc::new(move |bytes| {
        if bytes == b"first" {
            let leg = weak.upgrade().unwrap();
            let written = written.lock().unwrap().take().unwrap();
            tokio::spawn(async move {
                let _ = written.send(leg.write(b"third", false).await);
            });
        }
    }));
    assert!(leg.write(b"first", false).await);
    assert!(leg.write(b"second", false).await);
    leg.take(vec![got(1, b"label: events\r\n", true)], now);
    assert!(third.await.unwrap());
    assert_eq!(
        framer.emitted(),
        vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
    );
    assert!(!pairing.closed());
    pairing.close();
}

#[tokio::test]
async fn a_closed_leg_with_an_open_channel_refuses_further_writes() {
    let (_door, leg, pairing, _rx) = leg(8);
    let now = Instant::now();
    leg.take(vec![got(1, b"label: events\r\n", true)], now);
    pairing.close();
    assert!(!leg.write(b"after close", false).await);
}

const SESSION_CHANNEL: u64 = 1;
const FRAMER_PARK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

fn caller_for(leg: Arc<CallerLeg>) -> super::DatagramCaller {
    let (_to, from) = mpsc::channel(8);
    let (head, _answer) = tokio::sync::oneshot::channel();
    super::DatagramCaller {
        leg,
        from: tokio::sync::Mutex::new(from),
        head: std::sync::Mutex::new(Some(head)),
        stated: std::sync::atomic::AtomicU32::new(0),
        opened: std::sync::atomic::AtomicBool::new(false),
    }
}

fn join_recording(
    door: &Arc<ClaimDoor>,
    leg: &Arc<CallerLeg>,
    framer: &Arc<busbar_test_kit::root_door_fixtures::datagram_order::Recording>,
) -> u64 {
    use busbar_core_connector::datagram::DatagramFraming;
    use busbar_core_connector::framer::FramerDoor;
    let (mut framing, _) =
        DatagramFraming::accept_minted(Arc::clone(framer) as Arc<dyn FramerDoor>, door.local())
            .expect("begin");
    framing.rendezvous(b"offer", Instant::now()).expect("terms");
    door.join(framing, leg).expect("join")
}

#[derive(Default)]
struct WriteWake(std::sync::atomic::AtomicUsize);

impl std::task::Wake for WriteWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Worker registration belongs to the serving thread, never the publishing callback thread.
/// A separate current-thread reactor also lets cancellation precede every task's first poll.
struct ControlledDoor {
    door: Arc<ClaimDoor>,
    leg: Arc<CallerLeg>,
    pairing: Arc<Pairing>,
    _rx: mpsc::Receiver<Vec<u8>>,
    framer: Arc<busbar_test_kit::root_door_fixtures::datagram_order::Recording>,
    id: u64,
    tracker: Arc<busbar_kernel::detached::DetachedTasks>,
    shutdown: tokio::sync::watch::Sender<bool>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ControlledDoor {
    fn new(poll_tasks: bool) -> Self {
        let tracker = busbar_kernel::detached::DetachedTasks::new();
        let serving_tracker = Arc::clone(&tracker);
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (ready, fixture) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            busbar_kernel::detached::set_worker_detached(serving_tracker);
            busbar_kernel::detached::set_worker_shutdown(shutdown_rx);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            {
                let _entered = runtime.enter();
                let (door, leg, pairing, rx) = leg(8);
                let framer = busbar_test_kit::root_door_fixtures::datagram_order::Recording::new();
                let id = join_recording(&door, &leg, &framer);
                assert!(ready.send((door, leg, pairing, rx, framer, id)).is_ok());
            }
            if poll_tasks {
                runtime.block_on(async {
                    let _ = stopped.await;
                });
            } else {
                let _ = stopped.blocking_recv();
            }
            // Dropping this reactor cancels even futures it never polled.
            drop(runtime);
        });
        let (door, leg, pairing, rx, framer, id) = fixture
            .recv_timeout(FRAMER_PARK_WAIT)
            .expect("serving reactor ready");
        Self {
            door,
            leg,
            pairing,
            _rx: rx,
            framer,
            id,
            tracker,
            shutdown,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    fn publish_channel(&self) {
        let leg = Arc::clone(&self.leg);
        std::thread::spawn(move || {
            assert!(tokio::runtime::Handle::try_current().is_err());
            assert!(busbar_kernel::detached::worker_detached().is_none());
            assert!(busbar_kernel::detached::worker_shutdown().is_none());
            leg.take(
                vec![got(SESSION_CHANNEL, b"label: events\r\n", true)],
                Instant::now(),
            );
        })
        .join()
        .unwrap();
    }

    fn assert_tracked(&self) {
        use std::future::Future;
        let wake = std::task::Waker::from(Arc::new(WriteWake::default()));
        let mut cx = std::task::Context::from_waker(&wake);
        assert!(Box::pin(self.tracker.drained())
            .as_mut()
            .poll(&mut cx)
            .is_pending());
    }

    fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

impl Drop for ControlledDoor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[tokio::test]
async fn ordinary_thread_publication_uses_the_serving_tracker_and_reactor_in_fifo_order() {
    use busbar_kernel::plane_driver::CallerEnd;

    let mut control = ControlledDoor::new(true);
    control.assert_tracked(); // The port's receive loop itself owns shutdown custody.
    let caller = caller_for(Arc::clone(&control.leg));
    assert!(CallerEnd::write(&caller, b"first").await);
    assert!(CallerEnd::write_text(&caller, b"second").await);
    control.publish_channel();
    assert!(
        tokio::time::timeout(FRAMER_PARK_WAIT, CallerEnd::write(&caller, b"last"),)
            .await
            .unwrap()
    );
    let emitted = control.framer.emitted();
    control.shutdown.send(true).unwrap();
    tokio::time::timeout(FRAMER_PARK_WAIT, control.tracker.drained())
        .await
        .expect("tracked port and early drainer retired");
    control.stop();

    assert_eq!(
        emitted,
        vec![b"first".to_vec(), b"second".to_vec(), b"last".to_vec()]
    );
    assert!(control.pairing.closed());
    assert!(!CallerEnd::write(&caller, b"after shutdown").await);
}

#[tokio::test]
async fn shutdown_retires_a_blocked_accepted_drainer_and_wakes_the_later_writer() {
    use busbar_kernel::plane_driver::CallerEnd;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    let mut control = ControlledDoor::new(true);
    let caller = caller_for(Arc::clone(&control.leg));
    assert!(CallerEnd::write(&caller, b"first").await);
    assert!(CallerEnd::write(&caller, b"second").await);
    let (entered, inside) = std::sync::mpsc::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let resume = std::sync::Mutex::new(resume);
    control.framer.observe(Arc::new(move |bytes| {
        if bytes == b"occupied" {
            entered.send(()).unwrap();
            resume.lock().unwrap().recv().unwrap();
        }
    }));
    let holder = {
        let door = Arc::clone(&control.door);
        let id = control.id;
        std::thread::spawn(move || {
            door.emit(
                id,
                SESSION_CHANNEL,
                b"occupied",
                true,
                false,
                Instant::now(),
            )
        })
    };
    inside
        .recv_timeout(FRAMER_PARK_WAIT)
        .expect("framer borrowed");
    control.publish_channel();
    let parked = tokio::time::timeout(FRAMER_PARK_WAIT, async {
        loop {
            // Rendezvous with the real pending Emit: its first accepted item has left the queue.
            if lock(&control.leg.outbound).held.len() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let wake = Arc::new(WriteWake::default());
    let waker = Waker::from(Arc::clone(&wake));
    let mut cx = Context::from_waker(&waker);
    let mut later = Box::pin(CallerEnd::write(&caller, b"never accepted"));
    let before = later.as_mut().poll(&mut cx);
    control.shutdown.send(true).unwrap();
    // Shutdown must finish independently of the ordinary thread still borrowing the framer.
    let drained = tokio::time::timeout(FRAMER_PARK_WAIT, control.tracker.drained()).await;
    let after = later.as_mut().poll(&mut cx);
    let notified = wake.0.load(std::sync::atomic::Ordering::SeqCst);
    release.send(()).unwrap();
    let _ = holder.join().unwrap();
    control.stop();

    assert!(
        parked.is_ok(),
        "first accepted message waited for the borrowed framer"
    );
    assert!(
        drained.is_ok(),
        "accepted drainer is tracked and shutdown-aware"
    );
    assert!(before.is_pending());
    assert!(notified > 0);
    assert_eq!(after, Poll::Ready(false));
    assert!(control.pairing.closed());
    assert!(lock(&control.leg.outbound).held.is_empty());
    assert!(!lock(&control.leg.outbound).draining);
    assert_eq!(control.framer.emitted(), vec![b"occupied".to_vec()]);
}

#[tokio::test]
async fn unpolled_runtime_cancellation_releases_accepted_drainer_custody() {
    use busbar_kernel::plane_driver::CallerEnd;

    let mut control = ControlledDoor::new(false);
    let caller = caller_for(Arc::clone(&control.leg));
    assert!(CallerEnd::write(&caller, b"first").await);
    assert!(CallerEnd::write(&caller, b"second").await);
    control.publish_channel();
    control.assert_tracked(); // Synchronous reservations, although neither task has been polled.
    assert!(lock(&control.leg.outbound).draining);
    assert_eq!(lock(&control.leg.outbound).held.len(), 2);
    control.stop();
    tokio::time::timeout(FRAMER_PARK_WAIT, control.tracker.drained())
        .await
        .expect("unpolled task reservations released");

    assert!(control.pairing.closed());
    assert!(lock(&control.leg.outbound).held.is_empty());
    assert!(!lock(&control.leg.outbound).draining);
    assert!(control.framer.emitted().is_empty());
    assert!(!CallerEnd::write(&caller, b"after cancellation").await);
}

#[tokio::test]
async fn admission_finishing_after_shutdown_retires_its_new_pairing_and_association() {
    let mut control = ControlledDoor::new(true);
    control.shutdown.send(true).unwrap();
    tokio::time::timeout(FRAMER_PARK_WAIT, control.tracker.drained())
        .await
        .expect("serving loop retired");
    let (tx, mut rx) = mpsc::channel(8);
    let leg = CallerLeg::new(&control.door, tx);
    let pairing = Pairing::new(
        Arc::clone(&leg) as Arc<dyn busbar_core_connector::datagram::LegSink>,
        control.door.local(),
    );
    *lock(&leg.pairing) = Some(Arc::clone(&pairing));
    let framer = busbar_test_kit::root_door_fixtures::datagram_order::Recording::new();
    join_recording(&control.door, &leg, &framer);
    control.stop();

    assert!(pairing.closed());
    assert!(control.door.assocs.is_empty());
    assert!(lock(&control.door.legs).is_empty());
    assert!(!leg.write(b"after shutdown", false).await);
    assert!(rx.recv().await.is_none());
}

#[tokio::test]
async fn session_delivery_and_close_allow_the_receiver_waker_to_reenter_the_leg() {
    struct Reenter {
        leg: std::sync::Weak<CallerLeg>,
        locked: std::sync::atomic::AtomicBool,
        wakes: std::sync::atomic::AtomicUsize,
    }
    impl std::task::Wake for Reenter {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let leg = self.leg.upgrade().unwrap();
            if leg.to_session.try_lock().is_err() || leg.outbound.try_lock().is_err() {
                self.locked.store(true, std::sync::atomic::Ordering::SeqCst);
                return;
            }
            // A real receiver wake can synchronously end the session that published it.
            leg.failed();
        }
    }

    for deliver in [true, false] {
        let (_door, leg, pairing, mut rx) = leg(8);
        let wake = Arc::new(Reenter {
            leg: Arc::downgrade(&leg),
            locked: std::sync::atomic::AtomicBool::new(false),
            wakes: std::sync::atomic::AtomicUsize::new(0),
        });
        let waker = std::task::Waker::from(Arc::clone(&wake));
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(rx.poll_recv(&mut cx).is_pending());
        if deliver {
            leg.take(vec![got(SESSION_CHANNEL, b"piece", false)], Instant::now());
        } else {
            pairing.close();
        }
        assert!(wake.wakes.load(std::sync::atomic::Ordering::SeqCst) > 0);
        assert!(!wake.locked.load(std::sync::atomic::Ordering::SeqCst));
        assert!(pairing.closed());
        if deliver {
            assert_eq!(rx.try_recv().unwrap(), b"piece");
        }
        assert!(rx.recv().await.is_none());
    }
}

#[tokio::test]
async fn early_drain_wakes_the_next_writer_after_cancel_without_overtaking_accepted_messages() {
    use busbar_kernel::plane_driver::CallerEnd;
    use busbar_test_kit::root_door_fixtures::datagram_order::Recording;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    let (door, leg, pairing, _rx) = leg(8);
    let framer = Recording::new();
    join_recording(&door, &leg, &framer);
    let caller = Arc::new(caller_for(Arc::clone(&leg)));
    assert!(CallerEnd::write(&*caller, b"first").await);
    assert!(CallerEnd::write(&*caller, b"second").await);
    let (queued, pending) = tokio::sync::oneshot::channel();
    let queued = std::sync::Mutex::new(Some(queued));
    framer.observe(Arc::new(move |bytes| {
        if bytes != b"first" {
            return;
        }
        let wake = Arc::new(WriteWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut cx = Context::from_waker(&waker);
        let mut cancelled = Box::pin(CallerEnd::write(&*caller, b"cancelled during drain"));
        let cancelled_poll = cancelled.as_mut().poll(&mut cx);
        let later = Arc::clone(&caller);
        let mut later = Box::pin(async move { CallerEnd::write(&*later, b"last").await });
        let later_poll = later.as_mut().poll(&mut cx);
        drop(cancelled);
        let later_retry = if later_poll.is_pending() {
            later.as_mut().poll(&mut cx)
        } else {
            later_poll
        };
        // Both waits are registered during the actual first Emit crossing. The later
        // writer must hear the drainer finish even though its predecessor was cancelled.
        let _ = queued.lock().unwrap().take().unwrap().send((
            cancelled_poll,
            later_poll,
            later_retry,
            later,
            wake,
        ));
    }));
    let opened = {
        let leg = Arc::clone(&leg);
        std::thread::spawn(move || {
            leg.take(
                vec![got(SESSION_CHANNEL, b"label: events\r\n", true)],
                Instant::now(),
            );
        })
    };
    if let Err(panic) = opened.join() {
        pairing.close();
        std::panic::resume_unwind(panic);
    }
    let (cancelled_poll, later_poll, later_retry, later, wake) = pending.await.unwrap();
    let notified = wake.0.load(std::sync::atomic::Ordering::SeqCst);
    let accepted = match later_retry {
        Poll::Ready(ok) => ok,
        Poll::Pending => later.await,
    };
    let emitted = framer.emitted();
    pairing.close();

    assert!(cancelled_poll.is_pending() && later_poll.is_pending() && later_retry.is_pending());
    assert!(
        notified > 0,
        "finishing the early queue wakes the surviving writer"
    );
    assert!(accepted);
    assert_eq!(
        emitted,
        vec![b"first".to_vec(), b"second".to_vec(), b"last".to_vec()]
    );
}

#[tokio::test]
async fn busy_caller_writes_wait_without_accepting_cancelled_bytes_and_other_associations_progress()
{
    use busbar_kernel::plane_driver::CallerEnd;
    use busbar_test_kit::root_door_fixtures::datagram_order::Recording;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    let (door, leg, pairing, _rx) = leg(8);
    let framer = Recording::new();
    let id = join_recording(&door, &leg, &framer);
    leg.take(
        vec![got(SESSION_CHANNEL, b"label: events\r\n", true)],
        Instant::now(),
    );
    tokio::task::yield_now().await;
    let caller = caller_for(Arc::clone(&leg));
    let (tx, _rx_b) = mpsc::channel(8);
    let leg_b = CallerLeg::new(&door, tx);
    let framer_b = Recording::with_user(b"otherfrag");
    let id_b = join_recording(&door, &leg_b, &framer_b);
    let (entered, inside) = std::sync::mpsc::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let resume = std::sync::Mutex::new(resume);
    framer.observe(Arc::new(move |bytes| {
        if bytes == b"occupied" {
            entered.send(()).unwrap();
            resume.lock().unwrap().recv().unwrap();
        }
    }));
    let holder = {
        let door = Arc::clone(&door);
        std::thread::spawn(move || {
            door.emit(
                id,
                SESSION_CHANNEL,
                b"occupied",
                true,
                false,
                Instant::now(),
            )
        })
    };
    inside.recv_timeout(FRAMER_PARK_WAIT).expect("parked emit");
    let wake = Arc::new(WriteWake::default());
    let waker = Waker::from(Arc::clone(&wake));
    let mut cx = Context::from_waker(&waker);
    let mut active_cancelled = Box::pin(CallerEnd::write(&caller, b"cancelled active waiter"));
    let active_cancel_poll = active_cancelled.as_mut().poll(&mut cx);
    let mut first = Box::pin(CallerEnd::write(&caller, b"first"));
    let first_poll = first.as_mut().poll(&mut cx);
    let mut cancelled = Box::pin(CallerEnd::write(&caller, b"cancelled"));
    let cancel_poll = cancelled.as_mut().poll(&mut cx);
    let mut last = Box::pin(CallerEnd::write_text(&caller, b"last"));
    let last_poll = last.as_mut().poll(&mut cx);
    drop(active_cancelled);
    let first_retry = if first_poll.is_pending() {
        first.as_mut().poll(&mut cx)
    } else {
        first_poll
    };
    let first_repeated = if first_retry.is_pending() {
        first.as_mut().poll(&mut cx)
    } else {
        first_retry
    };
    drop(cancelled);
    let other = door.emit(
        id_b,
        SESSION_CHANNEL,
        b"healthy",
        true,
        false,
        Instant::now(),
    );
    let other_bytes = framer_b.emitted();
    release.send(()).unwrap();
    let held = holder.join().unwrap();
    let notified = wake.0.load(std::sync::atomic::Ordering::SeqCst);
    let first_result = match first_poll {
        Poll::Ready(ok) => ok,
        Poll::Pending => first.await,
    };
    let last_result = match last_poll {
        Poll::Ready(ok) => ok,
        Poll::Pending => last.await,
    };
    let emitted = framer.emitted();
    pairing.close();
    door.leave(id_b);

    assert!(active_cancel_poll.is_pending());
    assert!(first_poll.is_pending() && cancel_poll.is_pending() && last_poll.is_pending());
    assert!(first_retry.is_pending() && first_repeated.is_pending());
    assert!(other && held && first_result && last_result);
    assert_eq!(other_bytes, vec![b"healthy".to_vec()]);
    assert!(notified > 0, "availability wakes the pending writer");
    assert_eq!(
        emitted,
        vec![b"occupied".to_vec(), b"first".to_vec(), b"last".to_vec()]
    );
}

#[tokio::test]
async fn closing_a_busy_caller_wakes_the_unaccepted_write_without_emitting_it() {
    use busbar_kernel::plane_driver::CallerEnd;
    use busbar_test_kit::root_door_fixtures::datagram_order::Recording;
    use std::future::Future;
    use std::task::{Context, Waker};

    let (door, leg, pairing, _rx) = leg(8);
    let framer = Recording::new();
    let id = join_recording(&door, &leg, &framer);
    leg.take(
        vec![got(SESSION_CHANNEL, b"label: events\r\n", true)],
        Instant::now(),
    );
    tokio::task::yield_now().await;
    let caller = caller_for(leg);
    let (entered, inside) = std::sync::mpsc::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let resume = std::sync::Mutex::new(resume);
    framer.observe(Arc::new(move |bytes| {
        if bytes == b"occupied" {
            entered.send(()).unwrap();
            resume.lock().unwrap().recv().unwrap();
        }
    }));
    let holder = {
        let door = Arc::clone(&door);
        std::thread::spawn(move || {
            door.emit(
                id,
                SESSION_CHANNEL,
                b"occupied",
                true,
                false,
                Instant::now(),
            )
        })
    };
    inside.recv_timeout(FRAMER_PARK_WAIT).expect("parked emit");
    let wake = Arc::new(WriteWake::default());
    let waker = Waker::from(Arc::clone(&wake));
    let mut cx = Context::from_waker(&waker);
    let mut write = Box::pin(CallerEnd::write(&caller, b"never accepted"));
    let before = write.as_mut().poll(&mut cx);
    let mut queued = Box::pin(CallerEnd::write(&caller, b"also never accepted"));
    let queued_before = queued.as_mut().poll(&mut cx);
    pairing.close();
    let notified = wake.0.load(std::sync::atomic::Ordering::SeqCst);
    let after = if before.is_pending() {
        write.as_mut().poll(&mut cx)
    } else {
        before
    };
    let queued_after = if queued_before.is_pending() {
        queued.as_mut().poll(&mut cx)
    } else {
        queued_before
    };
    drop(write);
    drop(queued);
    release.send(()).unwrap();
    let _ = holder.join().unwrap();
    assert!(before.is_pending());
    assert!(notified > 0, "close wakes without waiting for the framer");
    assert_eq!(after, std::task::Poll::Ready(false));
    assert!(queued_before.is_pending());
    assert_eq!(queued_after, std::task::Poll::Ready(false));
    assert_eq!(framer.emitted(), vec![b"occupied".to_vec()]);
}

#[tokio::test]
async fn caller_write_publishes_the_framers_emitted_channel_output_once() {
    use busbar_kernel::plane_driver::CallerEnd;
    use busbar_test_kit::root_door_fixtures::datagram_order::Recording;
    let (door, leg, pairing, mut rx) = leg(8);
    let framer = Recording::new();
    join_recording(&door, &leg, &framer);
    framer.echo_emits();
    leg.take(
        vec![got(SESSION_CHANNEL, b"label: events\r\n", true)],
        Instant::now(),
    );
    let caller = caller_for(leg);
    assert!(CallerEnd::write(&caller, b"echo").await);
    let received = rx.try_recv();
    let extra = rx.try_recv();
    pairing.close();
    assert_eq!(received.unwrap(), b"echo");
    assert!(extra.is_err());
}

#[tokio::test]
async fn a_bridged_line_emit_delivers_its_callers_channel_output_once() {
    use busbar_core_connector::datagram::{Across, Leg, LegSink};
    use busbar_test_kit::root_door_fixtures::datagram_order::Recording;

    struct Upstream;
    impl LegSink for Upstream {
        fn line(&self, _: Across, _: Instant) {}
        fn close(&self) {}
    }
    const CALLER_LINE: u64 = 11;
    const UPSTREAM_LINE: u64 = 21;

    let (door, leg, pairing, mut rx) = leg(8);
    let framer = Recording::new();
    join_recording(&door, &leg, &framer);
    framer.echo_emits_on(SESSION_CHANNEL);
    let now = Instant::now();
    pairing.sort(
        Leg::Caller,
        vec![got(CALLER_LINE, b"kind: audio\r\n", true)],
        now,
    );
    pairing.sort(
        Leg::Upstream,
        vec![got(UPSTREAM_LINE, b"kind: audio\r\n", true)],
        now,
    );
    pairing.attach(Arc::new(Upstream)).unwrap();
    leg.take(vec![got(SESSION_CHANNEL, b"label: events\r\n", true)], now);
    let session = pairing.sort(
        Leg::Upstream,
        vec![got(UPSTREAM_LINE, b"line frame", false)],
        now,
    );
    let received = rx.try_recv();
    let extra = rx.try_recv();
    pairing.close();

    assert!(
        session.is_empty(),
        "the LINE stays out of the upstream session"
    );
    assert_eq!(framer.emitted(), vec![b"line frame".to_vec()]);
    assert_eq!(received.unwrap(), b"line frame");
    assert!(extra.is_err());
}

#[tokio::test]
async fn a_line_queued_during_application_emit_delivers_its_own_output_in_order() {
    use busbar_core_connector::datagram::{Across, Leg, LegSink};
    use busbar_kernel::plane_driver::CallerEnd;
    use busbar_test_kit::root_door_fixtures::datagram_order::Recording;

    struct Upstream;
    impl LegSink for Upstream {
        fn line(&self, _: Across, _: Instant) {}
        fn close(&self) {}
    }
    const CALLER_LINE: u64 = 11;
    const UPSTREAM_LINE: u64 = 21;

    let (door, leg, pairing, mut rx) = leg(8);
    let framer = Recording::new();
    join_recording(&door, &leg, &framer);
    framer.echo_emits_on(SESSION_CHANNEL);
    let now = Instant::now();
    pairing.sort(
        Leg::Caller,
        vec![got(CALLER_LINE, b"kind: audio\r\n", true)],
        now,
    );
    pairing.sort(
        Leg::Upstream,
        vec![got(UPSTREAM_LINE, b"kind: audio\r\n", true)],
        now,
    );
    pairing.attach(Arc::new(Upstream)).unwrap();
    leg.take(vec![got(SESSION_CHANNEL, b"label: events\r\n", true)], now);
    let source = Arc::downgrade(&pairing);
    framer.observe(Arc::new(move |bytes| {
        if bytes == b"application" {
            source.upgrade().unwrap().sort(
                Leg::Upstream,
                vec![got(UPSTREAM_LINE, b"queued line", false)],
                Instant::now(),
            );
        }
    }));
    let caller = caller_for(leg);
    let accepted = CallerEnd::write(&caller, b"application").await;
    let application = rx.try_recv();
    let line = rx.try_recv();
    let extra = rx.try_recv();
    pairing.close();

    assert!(accepted);
    assert_eq!(
        framer.emitted(),
        vec![b"application".to_vec(), b"queued line".to_vec()]
    );
    assert_eq!(application.unwrap(), b"application");
    assert_eq!(line.unwrap(), b"queued line");
    assert!(extra.is_err());
}

#[tokio::test]
async fn refusal_of_an_accepted_early_message_closes_before_later_messages_cross() {
    use busbar_kernel::plane_driver::CallerEnd;
    use busbar_test_kit::root_door_fixtures::datagram_order::Recording;

    let (door, leg, pairing, _rx) = leg(8);
    let framer = Recording::new();
    join_recording(&door, &leg, &framer);
    let caller = caller_for(Arc::clone(&leg));
    assert!(CallerEnd::write(&caller, b"first accepted").await);
    assert!(CallerEnd::write(&caller, b"later accepted").await);
    framer.refuse_emits();
    leg.take(
        vec![got(SESSION_CHANNEL, b"label: events\r\n", true)],
        Instant::now(),
    );
    // This live write waits behind the early drainer, so its result also observes
    // completion of the already accepted messages without a timed assertion.
    let later = CallerEnd::write(&caller, b"after refusal").await;
    let closed = pairing.closed();
    let emitted = framer.emitted();
    pairing.close();

    assert!(closed, "accepted custody failure ends the session");
    assert!(!later);
    assert_eq!(emitted, vec![b"first accepted".to_vec()]);
}
