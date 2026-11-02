// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use busbar_contract::conn::{ConnError, Piece, PieceKind};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::WireStatusClass;
use busbar_core_connector::datagram::{DatagramFraming, LegSink, Pairing, LINE_MEMORY_EXHAUSTED};
use busbar_core_connector::framer::{FramerDoor, FRAME_CAP};
use busbar_core_connector::publication::{Message, Messages};
use busbar_core_connector::test_support::{datagram_output_reservation_bytes, DatagramSession};
use busbar_core_connector::udp::{bind, ReadyPort};
use busbar_test_kit::root_door_fixtures::datagram_feedback::{Branching, Terminals};

use super::{lock, CallerLeg, ClaimDoor};

const CALLER_LINE: u64 = 11;
const UPSTREAM_LINE: u64 = 21;
const CALLER_CHANNEL: u64 = 12;
const UPSTREAM_CHANNEL: u64 = 22;
const COMPLETION_WAIT: Duration = Duration::from_secs(5);

struct Quiet;
impl Wake for Quiet {
    fn wake(self: Arc<Self>) {}
}
fn waker() -> Waker {
    Waker::from(Arc::new(Quiet))
}

fn exchange_piece(kind: PieceKind, len: usize) -> Piece {
    Piece {
        kind,
        stream: StreamId(0),
        len,
        end: true,
        status: (kind == PieceKind::Fields).then_some(WireStatusClass::Success),
        status_code: None,
        status_namespace: None,
        retry_after_secs: None,
        fault: None,
        reason: None,
        declared_len: None,
    }
}

struct ActualPair {
    door: Arc<ClaimDoor>,
    caller: Arc<CallerLeg>,
    pair: Arc<Pairing>,
    caller_rx: Arc<Messages>,
    upstream: DatagramSession,
    a: Arc<Branching>,
    b: Arc<Branching>,
}

impl ActualPair {
    fn new(limit: Option<usize>, per_batch: usize, terminals: Terminals) -> Self {
        let door = ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
        let caller_rx = Messages::new(1024);
        let caller = CallerLeg::new(&door, Arc::clone(&caller_rx));
        let pair = Pairing::with_memory_limit(
            Arc::clone(&caller) as Arc<dyn LegSink>,
            door.local(),
            limit,
        );
        *lock(&caller.pairing) = Some(Arc::clone(&pair));
        let a = Branching::new(
            CALLER_LINE,
            CALLER_CHANNEL,
            b"callerfrag",
            per_batch,
            terminals,
        );
        let (mut framing, _) =
            DatagramFraming::accept_minted(Arc::clone(&a) as Arc<dyn FramerDoor>, door.local())
                .unwrap();
        let initial = framing.rendezvous(b"caller offer", Instant::now()).unwrap();
        door.join(framing, &caller).unwrap();

        caller.yielded_batch(initial, Instant::now());
        let port = ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap();
        let b = Branching::new(
            UPSTREAM_LINE,
            UPSTREAM_CHANNEL,
            b"upstreamfrag",
            per_batch,
            terminals,
        );
        let (framing, _) = DatagramFraming::accept_minted(
            Arc::clone(&b) as Arc<dyn FramerDoor>,
            port.local_addr(),
        )
        .unwrap();
        let upstream = DatagramSession::new(framing, port, Arc::clone(&pair));
        assert!(upstream
            .exchanged(exchange_piece(PieceKind::Fields, 0), &[])
            .unwrap()
            .is_some());
        assert!(upstream
            .exchanged(exchange_piece(PieceKind::Body, 6), b"answer")
            .unwrap()
            .is_none());
        assert!(upstream
            .exchanged(exchange_piece(PieceKind::Completion, 0), &[])
            .unwrap()
            .is_none());
        Self {
            door,
            caller,
            pair,
            caller_rx,
            upstream,
            a,
            b,
        }
    }

    async fn published(&self) -> busbar_core_connector::datagram::PublicationOutcome {
        tokio::time::timeout(COMPLETION_WAIT, self.pair.published())
            .await
            .expect("finite actual-pair publication completes or explicitly fails")
    }

    fn caller_messages(&self) -> Vec<Vec<u8>> {
        let mut messages = Vec::new();
        while let Ok(message) = self.caller_rx.try_recv() {
            messages.push(message.bytes);
        }
        messages
    }

    fn upstream_messages(&self) -> Vec<Vec<u8>> {
        let mut messages = Vec::new();
        let mut bytes = vec![0; FRAME_CAP];
        loop {
            match self.upstream.read(&waker(), &mut bytes) {
                Ok(piece) => {
                    assert!(piece.end, "this buffer holds one complete fixture terminal");
                    messages.push(bytes[..piece.len].to_vec());
                }
                Err(ConnError::Pending) => return messages,
                other => panic!("unexpected terminal reader outcome: {other:?}"),
            }
        }
    }
}

impl Drop for ActualPair {
    fn drop(&mut self) {
        self.upstream.close();
        self.door.close();
    }
}

fn expected_paths(depth: u8, prefix: &[u8]) -> Vec<Vec<u8>> {
    (0..1_usize << depth)
        .map(|path| {
            let mut bytes = prefix.to_vec();
            bytes.extend((0..depth).rev().map(|bit| ((path >> bit) & 1) as u8));
            bytes
        })
        .collect()
}

async fn complete_feedback(limit: Option<usize>, depth: u8, per_batch: usize) {
    let actual = ActualPair::new(limit, per_batch, Terminals::Paths);
    assert_eq!(actual.pair.memory_account().limit(), limit);

    let prefix = if per_batch == 1 {
        vec![b'r'; FRAME_CAP / 2]
    } else {
        b"root".to_vec()
    };
    let mut token = vec![depth];
    token.extend_from_slice(&prefix);
    assert!(
        tokio::time::timeout(COMPLETION_WAIT, actual.caller.write(&token, false))
            .await
            .unwrap()
    );
    let outcome = actual.published().await;
    assert!(outcome.failure.is_none(), "{outcome:?}");
    assert_eq!(outcome.original_bytes, token.len() as u64);
    assert_eq!(outcome.original_handed_bytes, token.len() as u64);
    assert_eq!(outcome.original_cancelled_bytes, 0);
    assert_eq!(outcome.accepted_frames, (1_u64 << (depth + 1)) - 2);
    assert_eq!(outcome.handed_frames, outcome.accepted_frames);
    assert_eq!(outcome.cancelled_frames, 0);
    let (mut terminals, other) = if depth % 2 == 0 {
        (actual.caller_messages(), actual.upstream_messages())
    } else {
        (actual.upstream_messages(), actual.caller_messages())
    };
    terminals.sort();
    assert_eq!(terminals, expected_paths(depth, &prefix));
    assert!(other.is_empty());
    assert_eq!(
        actual.a.emitted().len() + actual.b.emitted().len(),
        (1_usize << (depth + 1)) - 1
    );
    assert!(!actual.pair.closed());
    if per_batch == 1 {
        assert!(actual.a.recalls() + actual.b.recalls() > 0);
    }
    actual.upstream.close();
    assert_eq!(actual.a.finishes(), 1);
    assert_eq!(actual.b.finishes(), 1);
}

#[tokio::test]
async fn unlimited_actual_pair_completes_distinct_finite_feedback_in_both_directions() {
    complete_feedback(None, 4, 2).await;
    complete_feedback(None, 5, 2).await;
}

#[tokio::test]
async fn configured_ample_actual_pair_preserves_paths_and_same_operation_recalls() {
    let ample = datagram_output_reservation_bytes() + 128 * FRAME_CAP;
    complete_feedback(Some(ample), 4, 1).await;
    complete_feedback(Some(ample), 5, 2).await;
}

#[tokio::test]
async fn an_idle_upstream_reader_releases_crossing_credit_before_the_callers_next_episode() {
    let actual = ActualPair::new(
        Some(datagram_output_reservation_bytes() + 4 * FRAME_CAP),
        2,
        Terminals::Paths,
    );
    for prefix in [b'a', b'b'] {
        let token = [3, prefix];
        assert!(
            tokio::time::timeout(COMPLETION_WAIT, actual.caller.write(&token, false))
                .await
                .expect("the other leg can reserve its next real crossing")
        );
        let outcome = actual.published().await;
        assert!(outcome.failure.is_none(), "{outcome:?}");
        let mut received = actual.upstream_messages();
        received.sort();
        assert_eq!(received, expected_paths(3, &[prefix]));
        assert!(actual.caller_messages().is_empty());

        let wake = waker();
        assert!(!actual.upstream.ready(&wake));
        assert_eq!(
            actual.upstream.read(&wake, &mut [0; 8]),
            Err(ConnError::Pending)
        );
        assert!(!actual.pair.closed());
        assert_eq!(
            actual
                .a
                .emitted()
                .iter()
                .filter(|bytes| bytes.as_slice() == token)
                .count(),
            1,
            "each independent accepted source crosses exactly once"
        );
    }
    let outcome = actual.published().await;
    assert_eq!(outcome.original_bytes, 4);
    assert_eq!(outcome.original_handed_bytes, 4);
    assert_eq!(outcome.original_cancelled_bytes, 0);
    assert_eq!(outcome.accepted_frames, 28);
    assert_eq!(outcome.handed_frames, 28);
    assert_eq!(outcome.cancelled_frames, 0);
    assert_eq!(actual.a.emitted().len() + actual.b.emitted().len(), 30);
}

#[tokio::test]
async fn a_caller_waits_before_accepting_input_until_actual_upstream_readers_release_credit() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct CreditWake(AtomicUsize);
    impl Wake for CreditWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    const EPISODES: usize = 256;
    const MESSAGES: usize = 2 * EPISODES;
    const PAYLOAD_BYTES: usize = MESSAGES * FRAME_CAP;
    const METADATA_HEADROOM: usize = 32 * FRAME_CAP;
    let crossing = datagram_output_reservation_bytes();
    let limit = crossing + PAYLOAD_BYTES + METADATA_HEADROOM;

    assert!(2 * PAYLOAD_BYTES > limit);
    let actual = ActualPair::new(
        Some(limit),
        2,
        Terminals::OverlapAndEmpty {
            payload_bytes: FRAME_CAP,
            empty_pieces: 0,
        },
    );
    for _ in 0..EPISODES {
        assert_eq!(actual.upstream.write(&[0], true, false), Ok(1));
        assert!(actual.published().await.failure.is_none());
    }

    let before = actual.published().await;
    assert_eq!(before.original_bytes, EPISODES as u64);
    assert_eq!(before.original_handed_bytes, EPISODES as u64);
    assert!(before.failure.is_none());
    assert_eq!(actual.b.emitted(), vec![vec![0]; EPISODES]);
    assert!(actual.a.emitted().is_empty());
    assert!(actual.caller_messages().is_empty());
    actual.a.consume_without_output();
    let input = vec![b'i'; PAYLOAD_BYTES];
    let wakes = Arc::new(CreditWake::default());
    let wake = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&wake);
    let mut writing = Box::pin(actual.caller.write(&input, false));
    assert!(writing.as_mut().poll(&mut cx).is_pending());
    assert!(writing.as_mut().poll(&mut cx).is_pending());
    assert_eq!(
        actual.pair.publication_outcome(),
        before,
        "Pending accepts none"
    );
    assert!(
        actual.a.emitted().is_empty(),
        "no fresh Emit crossed before credit"
    );
    assert!(!actual.pair.closed());
    let registered = wakes.0.load(Ordering::SeqCst);

    let mut bytes = vec![0; FRAME_CAP];
    for _ in 0..MESSAGES {
        let piece = actual.upstream.read(&waker(), &mut bytes).unwrap();
        assert_eq!(piece.len, FRAME_CAP);
        assert!(piece.end);
        assert!(bytes.iter().all(|byte| *byte == b'x'));
    }
    assert_eq!(
        actual.upstream.read(&waker(), &mut bytes),
        Err(ConnError::Pending)
    );
    assert!(
        wakes.0.load(Ordering::SeqCst) > registered,
        "actual reader retirement wakes the unaccepted writer"
    );
    assert_eq!(actual.pair.publication_outcome(), before);
    assert!(tokio::time::timeout(COMPLETION_WAIT, writing)
        .await
        .expect("the same unaccepted write resumes after real reader consumption"));
    let outcome = actual.published().await;
    assert!(outcome.failure.is_none(), "{outcome:?}");
    assert_eq!(outcome.original_bytes, EPISODES as u64 + input.len() as u64);
    assert_eq!(outcome.original_handed_bytes, outcome.original_bytes);
    assert_eq!(outcome.original_cancelled_bytes, 0);
    assert_eq!(actual.a.emitted(), vec![input]);
    assert_eq!(actual.b.emitted(), vec![vec![0]; EPISODES]);
    assert!(actual.caller_messages().is_empty());
    assert_eq!(
        actual.upstream.read(&waker(), &mut bytes),
        Err(ConnError::Pending)
    );
    assert!(!actual.pair.closed());
}

#[tokio::test]
async fn a_callers_own_unread_output_cannot_keep_its_unaccepted_write_waiting() {
    const EPISODES: usize = 256;
    const MESSAGES: usize = 2 * EPISODES;
    const PAYLOAD_BYTES: usize = MESSAGES * FRAME_CAP;
    let limit = datagram_output_reservation_bytes() + PAYLOAD_BYTES + 32 * FRAME_CAP;
    assert!(2 * PAYLOAD_BYTES > limit);
    let actual = ActualPair::new(
        Some(limit),
        2,
        Terminals::OverlapAndEmpty {
            payload_bytes: FRAME_CAP,
            empty_pieces: 0,
        },
    );
    for _ in 0..EPISODES {
        assert!(
            tokio::time::timeout(COMPLETION_WAIT, actual.caller.write(&[0], false))
                .await
                .expect("each finite seed publishes its two real caller messages")
        );
        assert!(actual.published().await.failure.is_none());
    }
    let before = actual.published().await;
    assert_eq!(before.original_bytes, EPISODES as u64);
    assert_eq!(before.original_handed_bytes, EPISODES as u64);
    actual.a.consume_without_output();
    let input = vec![b'i'; PAYLOAD_BYTES];

    assert!(
        !tokio::time::timeout(COMPLETION_WAIT, actual.caller.write(&input, false))
            .await
            .expect("own unread output causes explicit preaccept failure")
    );
    let outcome = actual.published().await;
    assert_eq!(outcome.failure.as_deref(), Some(LINE_MEMORY_EXHAUSTED));
    assert_eq!(outcome.original_bytes, before.original_bytes);
    assert_eq!(outcome.original_handed_bytes, before.original_handed_bytes);
    assert_eq!(outcome.original_cancelled_bytes, 0);
    assert_eq!(outcome.original_uncertain_bytes, 0);
    assert_eq!(outcome.accepted_frames, 0);
    assert_eq!(actual.a.emitted(), vec![vec![0]; EPISODES]);
    assert!(actual.b.emitted().is_empty());
    assert!(actual.pair.closed());

    for _ in 0..MESSAGES {
        let message = actual
            .caller_rx
            .try_recv()
            .expect("accepted caller message retained");
        assert!(message.end);
        assert_eq!(message.bytes.len(), FRAME_CAP);
        assert!(message.bytes.iter().all(|byte| *byte == b'x'));
    }
    assert!(actual.caller_rx.try_recv().is_err());
    assert_eq!(actual.a.finishes(), 1);
    assert_eq!(actual.b.finishes(), 1);
}

#[tokio::test]
async fn accepted_feedback_exhausts_instead_of_waiting_for_its_own_queued_reader_chunks() {
    let limit = datagram_output_reservation_bytes() + 4 * FRAME_CAP;
    let actual = ActualPair::new(
        Some(limit),
        2,
        Terminals::OverlapAndEmpty {
            payload_bytes: FRAME_CAP,
            empty_pieces: 0,
        },
    );
    assert!(
        tokio::time::timeout(COMPLETION_WAIT, actual.caller.write(&[0], false))
            .await
            .expect("finite seed completes before the expanding episode")
    );
    assert!(actual.published().await.failure.is_none());

    let mut token = vec![b'p'; FRAME_CAP / 4];
    token[0] = 10;
    assert!(
        !tokio::time::timeout(COMPLETION_WAIT, actual.caller.write(&token, false))
            .await
            .expect("queued-only reader custody cannot stall accepted feedback forever")
    );
    let outcome = actual.published().await;
    assert_eq!(outcome.failure.as_deref(), Some(LINE_MEMORY_EXHAUSTED));
    assert_eq!(outcome.original_bytes, 1 + token.len() as u64);
    assert_eq!(outcome.original_handed_bytes, outcome.original_bytes);
    assert_eq!(outcome.original_cancelled_bytes, 0);
    assert_eq!(outcome.original_uncertain_bytes, 0);
    assert!(outcome.handed_frames > 0);
    assert!(outcome.cancelled_frames > 0);
    assert_eq!(
        outcome.accepted_frames,
        outcome.handed_frames + outcome.cancelled_frames
    );
    assert_eq!(
        outcome.accepted_bytes,
        outcome.handed_bytes + outcome.cancelled_bytes
    );
    assert_eq!(
        outcome.uncertain_frames, 0,
        "credit refusal makes no uncertain crossing"
    );
    assert_eq!(outcome.uncertain_bytes, 0);
    let emitted: Vec<_> = actual
        .a
        .emitted()
        .into_iter()
        .chain(actual.b.emitted())
        .filter(|bytes| bytes.as_slice() != [0])
        .collect();
    assert_eq!(emitted.len() as u64, 1 + outcome.handed_frames);
    assert_eq!(outcome.accepted_frames, 2 * emitted.len() as u64);
    let unique: std::collections::BTreeSet<_> = emitted.iter().collect();
    assert_eq!(
        unique.len(),
        emitted.len(),
        "no accepted finite-tree node is replayed"
    );
    drop(unique);
    for bytes in emitted {
        let path_len = bytes.len() - token.len();
        assert!(path_len < 10, "resource failure precedes terminal leaves");
        assert_eq!(bytes[0], 10 - path_len as u8);
        assert_eq!(&bytes[1..token.len()], &token[1..]);
        assert!(bytes[token.len()..].iter().all(|bit| *bit <= 1));
    }
    assert!(actual.pair.closed());
    for _ in 0..2 {
        let message = actual
            .caller_rx
            .try_recv()
            .expect("old accepted chunk remains readable");
        assert_eq!(message.bytes, vec![b'x'; FRAME_CAP]);
        assert!(message.end);
    }
    assert!(actual.caller_rx.try_recv().is_err());
    assert_eq!(actual.a.finishes(), 1);
    assert_eq!(actual.b.finishes(), 1);
}

#[tokio::test]
async fn configured_frontier_exhaustion_reports_real_partial_publication_and_isolates_the_pair() {
    let limit = datagram_output_reservation_bytes() + 4 * FRAME_CAP;
    let actual = ActualPair::new(Some(limit), 2, Terminals::Paths);

    let mut token = vec![b'p'; FRAME_CAP / 4];
    token[0] = 10;
    assert!(
        !tokio::time::timeout(COMPLETION_WAIT, actual.caller.write(&token, false))
            .await
            .unwrap()
    );
    let outcome = actual.published().await;
    assert_eq!(outcome.failure.as_deref(), Some(LINE_MEMORY_EXHAUSTED));
    assert!(actual.pair.closed());
    assert_eq!(outcome.original_bytes, token.len() as u64);
    assert_eq!(outcome.original_handed_bytes, token.len() as u64);
    assert_eq!(
        outcome.original_cancelled_bytes, 0,
        "taken input cannot be relabelled untaken"
    );
    assert!(
        outcome.handed_frames > 0,
        "real destination Emits preceded exhaustion"
    );
    assert!(
        outcome.cancelled_frames > 0,
        "unresolved LINE custody is explicit"
    );
    assert_eq!(
        outcome.accepted_frames,
        outcome.handed_frames + outcome.cancelled_frames
    );
    assert_eq!(
        outcome.accepted_bytes,
        outcome.handed_bytes + outcome.cancelled_bytes
    );
    assert_eq!(
        actual
            .a
            .emitted()
            .iter()
            .filter(|bytes| **bytes == token)
            .count(),
        1
    );
    assert!(
        !actual
            .caller
            .write(b"never replay accepted bytes", false)
            .await
    );
    assert!(matches!(
        actual.upstream.read(&waker(), &mut [0; 8]),
        Err(ConnError::Fault)
    ));
    assert!(actual.pair.memory_account().used() <= limit);
    assert!(actual.caller_messages().is_empty());
    assert_eq!(actual.a.finishes(), 1);
    assert_eq!(actual.b.finishes(), 1);
    complete_feedback(Some(limit), 3, 2).await;
}

#[tokio::test]
async fn real_upstream_accepts_one_source_job_and_pending_takes_no_second_input() {
    let actual = ActualPair::new(None, 2, Terminals::Paths);
    let first = [4, b'a'];
    let second = [4, b'b'];
    assert_eq!(actual.upstream.write(&first, true, false), Ok(first.len()));
    assert_eq!(
        actual.upstream.write(&second, true, false),
        Err(ConnError::Pending)
    );
    assert_eq!(
        actual.pair.publication_outcome().original_bytes,
        first.len() as u64
    );
    assert!(actual.published().await.failure.is_none());
    assert_eq!(
        actual.upstream.write(&second, true, false),
        Ok(second.len())
    );
    let outcome = actual.published().await;
    assert!(outcome.failure.is_none());
    assert_eq!(outcome.original_bytes, (first.len() + second.len()) as u64);
    let mut received = actual.upstream_messages();
    received.sort();
    let mut expected = expected_paths(4, b"a");
    expected.extend(expected_paths(4, b"b"));
    assert_eq!(received, expected);
    assert!(actual.caller_messages().is_empty());
    assert_eq!(
        actual
            .b
            .emitted()
            .iter()
            .filter(|bytes| bytes.as_slice() == first)
            .count(),
        1
    );
    assert_eq!(
        actual
            .b
            .emitted()
            .iter()
            .filter(|bytes| bytes.as_slice() == second)
            .count(),
        1
    );
}

#[tokio::test]
async fn overlapping_payloads_and_empty_metadata_remain_charged_until_real_reader_consumption() {
    for payload_bytes in [FRAME_CAP / 2, 0] {
        const EMPTY_PIECES: usize = 32;
        let actual = ActualPair::new(
            Some(datagram_output_reservation_bytes() + 8 * FRAME_CAP),
            2,
            Terminals::OverlapAndEmpty {
                payload_bytes,
                empty_pieces: EMPTY_PIECES,
            },
        );
        let memory = actual.pair.memory_account();
        let baseline = memory.used();
        assert_eq!(actual.upstream.write(&[0], true, false), Ok(1));
        assert!(actual.published().await.failure.is_none());
        let retained = memory.used();

        let minimum = 2 * payload_bytes + (EMPTY_PIECES + 2) * std::mem::size_of::<Message>();
        assert!(
            retained >= baseline + minimum,
            "retained={retained}, baseline={baseline}, minimum={minimum}"
        );
        if payload_bytes > 0 {
            let mut prefix = vec![0; payload_bytes / 2];
            let first = actual.upstream.read(&waker(), &mut prefix).unwrap();
            assert_eq!(first.len, prefix.len());
            assert!(!first.end);
            assert!(prefix.iter().all(|byte| *byte == b'x'));
            assert_eq!(
                memory.used(),
                retained,
                "partial read retains the whole allocation"
            );
            let last = actual.upstream.read(&waker(), &mut prefix).unwrap();
            assert!(last.end);
            assert_eq!(last.len, prefix.len());
            assert!(
                memory.used() < retained,
                "last byte releases this reader's allocation"
            );
        }
        let messages = actual.upstream_messages();
        let nonempty = messages
            .iter()
            .filter(|message| !message.is_empty())
            .count();
        assert_eq!(nonempty, usize::from(payload_bytes > 0));
        assert_eq!(
            messages.iter().filter(|message| message.is_empty()).count(),
            EMPTY_PIECES + if payload_bytes == 0 { 2 } else { 0 }
        );
        assert!(memory.used() < retained);
        actual.upstream.close();
        assert_eq!(
            memory.used(),
            0,
            "teardown releases both actual associations' remaining custody"
        );
    }
}

#[tokio::test]
async fn cancelling_an_accepted_actual_caller_write_cancels_without_crossing_or_replaying_it() {
    let actual = ActualPair::new(
        Some(datagram_output_reservation_bytes() + 8 * FRAME_CAP),
        1,
        Terminals::Paths,
    );
    let token = [4, b'c'];
    let wake = waker();
    let mut cx = Context::from_waker(&wake);
    let mut writing = Box::pin(actual.caller.write(&token, false));
    assert!(writing.as_mut().poll(&mut cx).is_pending());
    assert_eq!(
        actual.pair.publication_outcome().original_bytes,
        token.len() as u64
    );
    let mut queued = Box::pin(actual.caller.write(b"unaccepted", false));
    assert!(queued.as_mut().poll(&mut cx).is_pending());
    drop(writing);
    assert_eq!(queued.as_mut().poll(&mut cx), Poll::Ready(false));
    drop(queued);
    let outcome = actual.published().await;
    assert!(outcome.failure.is_some());
    assert_eq!(outcome.original_handed_bytes, 0);
    assert_eq!(outcome.original_cancelled_bytes, token.len() as u64);
    assert!(actual.a.emitted().is_empty() && actual.b.emitted().is_empty());
    assert!(actual.pair.closed());
    assert_eq!(actual.a.finishes(), 1);
    assert_eq!(actual.b.finishes(), 1);
    assert_eq!(actual.pair.memory_account().used(), 0);
}

#[tokio::test]
async fn claim_door_shutdown_retires_an_accepted_actual_pair_before_the_actor_first_poll() {
    let actual = ActualPair::new(
        Some(datagram_output_reservation_bytes() + 8 * FRAME_CAP),
        1,
        Terminals::Paths,
    );
    let wake = waker();
    let mut cx = Context::from_waker(&wake);
    let mut writing = Box::pin(actual.caller.write(&[3, b's'], false));
    assert!(writing.as_mut().poll(&mut cx).is_pending());
    assert_eq!(actual.pair.publication_outcome().original_bytes, 2);
    actual.door.close();
    assert_eq!(writing.as_mut().poll(&mut cx), Poll::Ready(false));
    drop(writing);
    let outcome = actual.published().await;
    assert!(outcome.failure.is_some());
    assert_eq!(outcome.original_handed_bytes, 0);
    assert_eq!(outcome.original_cancelled_bytes, 2);
    assert!(actual.a.emitted().is_empty() && actual.b.emitted().is_empty());
    assert!(actual.pair.closed());
    assert_eq!(actual.a.finishes(), 1);
    assert_eq!(actual.b.finishes(), 1);
    assert_eq!(actual.pair.memory_account().used(), 0);
}
