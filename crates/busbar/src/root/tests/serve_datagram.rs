// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Instant;

use busbar_core_connector::datagram::Pairing;
use busbar_core_connector::framer::Got;
use busbar_core_connector::publication::{Custody, Message, Messages};
use busbar_core_connector::udp::{bind, ReadyPort};
use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission, RequestLease};

use super::{lock, CallerLeg, ClaimDoor, CALLER_QUEUE};

fn request() -> RequestLease {
    ProcessAdmission::new(0)
        .try_enter(AdmissionClass::Data)
        .unwrap()
}

pub(super) fn got(stream: u64, bytes: &[u8], fields: bool) -> Got {
    Got {
        stream,
        bytes: bytes.to_vec(),
        end_of_frame: true,
        status_code: None,
        status_namespace: None,
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

fn leg(capacity: usize) -> (Arc<ClaimDoor>, Arc<CallerLeg>, Arc<Pairing>, Arc<Messages>) {
    let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let rx = Messages::new(capacity);
    let tx = Arc::clone(&rx);
    let leg = CallerLeg::new(&door, tx, request());
    let pairing = Pairing::new(
        Arc::clone(&leg) as Arc<dyn busbar_core_connector::datagram::LegSink>,
        door.local(),
    );
    *lock(&leg.pairing) = Some(Arc::clone(&pairing));
    (door, leg, pairing, rx)
}

const SESSION_CHANNEL: u64 = 1;

#[tokio::test]
async fn association_capacity_is_per_claim_and_released_on_close() {
    let (door, first, _, _) = leg(1);
    let mut held = Vec::new();
    for _ in 0..super::DATAGRAM_ASSOCIATIONS_PER_CLAIM {
        let member = CallerLeg::new(&door, Messages::new(1), request());
        assert!(door.reserve(&member).is_ok());
        held.push(member);
    }
    assert!(door.reserve(&first).is_err());
    use busbar_core_connector::datagram::LegSink;
    held.pop().unwrap().close();
    assert!(door.reserve(&first).is_ok());
    first.close();
    for member in held {
        member.close();
    }
    assert_eq!(
        door.capacity.available_permits(),
        super::DATAGRAM_ASSOCIATIONS_PER_CLAIM
    );
}

#[tokio::test]
async fn expired_association_closes_even_without_a_plugin_deadline() {
    let (door, leg, pairing, _) = leg(1);
    door.reserve(&leg).unwrap();
    lock(&door.legs).insert(1, Arc::clone(&leg));
    leg.bind(1);
    door.expire(Instant::now() + super::DATAGRAM_ASSOCIATION_LIFETIME);
    assert!(pairing.closed());
    assert!(lock(&door.legs).is_empty());
    assert_eq!(
        door.capacity.available_permits(),
        super::DATAGRAM_ASSOCIATIONS_PER_CLAIM
    );
}

#[tokio::test]
async fn a_plane_that_falls_behind_its_caller_ends_the_session() {
    let (_door, leg, pairing, rx) = leg(2);
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

#[tokio::test]
async fn a_plane_that_writes_past_the_bound_before_the_channel_opens_ends_the_session() {
    let (_door, leg, pairing, rx) = leg(8);
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

#[tokio::test]
async fn the_open_answers_under_the_head_the_plane_states() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let location = (b"location".to_vec(), b"/v1/calls/c_0123abcd".to_vec());
    tx.send((201, vec![location.clone()])).unwrap();
    let head = super::plane_head(rx, std::time::Duration::from_secs(5)).await;
    assert_eq!(head, Some((201, vec![location])));
}

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

#[tokio::test]
async fn the_caller_side_opens_with_one_empty_piece() {
    use busbar_kernel::plane_driver::SessionCaller;
    let (_door, leg, _pairing, _rx) = leg(8);
    let from = Messages::new(8);
    let to = Arc::clone(&from);
    let (head, _rx) = tokio::sync::oneshot::channel();
    let caller = super::DatagramCaller {
        leg,
        from,
        head: std::sync::Mutex::new(Some(head)),
        stated: std::sync::atomic::AtomicU32::new(0),
        opened: std::sync::atomic::AtomicBool::new(false),
    };
    to.send(Message {
        bytes: b"{\"type\":\"x\"}".to_vec(),
        end: true,
        consumed: 0,
        custody: Custody::default().reader(),
    })
    .unwrap();
    assert_eq!(
        caller.read_owned().await.unwrap().bytes,
        Vec::<u8>::new(),
        "the open"
    );
    assert_eq!(
        caller.read_owned().await.unwrap().bytes,
        b"{\"type\":\"x\"}".to_vec()
    );
    to.close();
    assert!(caller.read_owned().await.is_none());
}

#[tokio::test]
async fn a_closed_leg_with_an_open_channel_refuses_further_writes() {
    let (_door, leg, pairing, _rx) = leg(8);
    let now = Instant::now();
    leg.take(vec![got(1, b"label: events\r\n", true)], now);
    pairing.close();
    assert!(!leg.write(b"after close", false).await);
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

            leg.failed();
        }
    }

    for deliver in [true, false] {
        let (_door, leg, pairing, rx) = leg(8);
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

struct ExhaustionDiagnostic(Arc<std::sync::atomic::AtomicUsize>);

impl tracing::Subscriber for ExhaustionDiagnostic {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Reason<'a>(&'a std::sync::atomic::AtomicUsize);
        impl tracing::field::Visit for Reason<'_> {
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "reason" && value == "resource_exhausted" {
                    self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
        event.record(&mut Reason(&self.0));
    }
}

#[tokio::test]
async fn configured_exhaustion_reports_one_clear_operator_error_and_takes_no_preaccept_bytes() {
    use busbar_kernel::plane_driver::CallerEnd;
    let diagnostics = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dispatch = tracing::Dispatch::new(ExhaustionDiagnostic(Arc::clone(&diagnostics)));
    let _subscriber = tracing::dispatcher::set_default(&dispatch);
    let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let leg = CallerLeg::new(&door, Messages::new(8), request());
    let pairing = Pairing::with_memory_limit(
        Arc::clone(&leg) as Arc<dyn busbar_core_connector::datagram::LegSink>,
        door.local(),
        Some(1),
    );
    *lock(&leg.pairing) = Some(Arc::clone(&pairing));
    let (head, _answer) = tokio::sync::oneshot::channel();
    let caller = super::DatagramCaller {
        leg,
        from: Messages::new(8),
        head: std::sync::Mutex::new(Some(head)),
        stated: std::sync::atomic::AtomicU32::new(0),
        opened: std::sync::atomic::AtomicBool::new(false),
    };
    assert!(!CallerEnd::write(&caller, b"unaccepted").await);
    assert!(!CallerEnd::write(&caller, b"also unaccepted").await);
    assert_eq!(diagnostics.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        pairing.publication_outcome().failure.as_deref(),
        Some(busbar_core_connector::datagram::LINE_MEMORY_EXHAUSTED)
    );
    assert_eq!(pairing.publication_outcome().original_bytes, 0);
    assert!(pairing.closed());
}

#[tokio::test]
async fn queued_datagram_payload_retains_the_opening_request_until_last_owned_read() {
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    use busbar_kernel::plane_driver::SessionCaller;
    let budget = ProcessAdmission::new(2);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let from = Messages::new(2);
    let leg = CallerLeg::new(&door, Arc::clone(&from), request.clone());
    let pairing = Pairing::new(
        Arc::clone(&leg) as Arc<dyn busbar_core_connector::datagram::LegSink>,
        door.local(),
    );
    *lock(&leg.pairing) = Some(Arc::clone(&pairing));
    leg.take(vec![got(1, b"data", false)], Instant::now());
    let remaining = request.try_reserve(224 * 1024 * 1024 - 4).unwrap();
    assert!(
        request.try_reserve(1).is_err(),
        "the queue is charged before any receiver reads"
    );
    let (head, _) = tokio::sync::oneshot::channel();
    let caller = super::DatagramCaller {
        leg,
        from,
        head: std::sync::Mutex::new(Some(head)),
        stated: std::sync::atomic::AtomicU32::new(0),
        opened: std::sync::atomic::AtomicBool::new(true),
    };
    assert!(
        caller.read().await.is_none(),
        "bare reads cannot strip custody or dequeue"
    );
    let input = caller.read_owned().await.unwrap();
    assert_eq!(input.bytes, b"data");
    pairing.close();
    drop(caller);
    drop(pairing);
    drop(request);
    drop(remaining);
    assert!(
        budget.try_enter(AdmissionClass::Data).is_err(),
        "transport teardown does not retire retained input"
    );
    assert!(
        budget.try_enter(AdmissionClass::Operator).is_ok(),
        "Data never takes the recovery floor"
    );
    drop(input);
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

#[tokio::test]
async fn a_kept_description_and_its_bytes_aliases_retain_the_opening_admission() {
    let budget = ProcessAdmission::new(2);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let leg = CallerLeg::new(&door, Messages::new(1), request.clone());
    let description = leg
        .take_batch_keeping(
            busbar_core_connector::datagram::SessionBatch {
                pieces: vec![got(0, b"description", false)],
                custody: Custody::default(),
                owners: Vec::new(),
                producer: busbar_core_connector::publication::ProducerCustody::default(),
            },
            Instant::now(),
            Some(0),
        )
        .unwrap()
        .unwrap();
    let remaining = request
        .try_reserve(224 * 1024 * 1024 - b"description".len())
        .unwrap();
    assert!(
        request.try_reserve(1).is_err(),
        "description bytes are charged before handoff"
    );
    let bytes = description.into_bytes();
    let alias = bytes.slice(1..);
    assert_eq!(bytes.as_ref(), b"description");
    drop(bytes);
    drop(leg);
    drop(remaining);
    drop(request);
    assert!(
        budget.try_enter(AdmissionClass::Data).is_err(),
        "the retained response description still owns its opening request"
    );
    drop(alias);
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

#[tokio::test]
async fn process_byte_exhaustion_refuses_datagram_retention_before_queueing() {
    let budget = ProcessAdmission::new(2);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let full = request.try_reserve(224 * 1024 * 1024).unwrap();
    let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let from = Messages::new(1);
    let leg = CallerLeg::new(&door, Arc::clone(&from), request.clone());
    let pairing = Pairing::new(
        Arc::clone(&leg) as Arc<dyn busbar_core_connector::datagram::LegSink>,
        door.local(),
    );
    *lock(&leg.pairing) = Some(Arc::clone(&pairing));
    leg.take(vec![got(1, b"refused", false)], Instant::now());
    assert!(pairing.closed());
    assert!(
        from.recv().await.is_none(),
        "the uncharged payload never enters the receiver queue"
    );
    let operator = budget.try_enter(AdmissionClass::Operator).unwrap();
    assert!(operator.try_reserve(32 * 1024 * 1024).is_ok());
    drop(full);
    assert!(
        request.try_reserve(224 * 1024 * 1024).is_ok(),
        "the refused payload leaked no credit"
    );
}
