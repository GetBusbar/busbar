// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The upstream leg's reads: a channel message longer than the reader's buffer; every channel
//! message reaches the reader.

use std::collections::VecDeque;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use super::{take_ready, Messages};

fn ready_messages(pieces: &[(&[u8], bool)]) -> Messages {
    let mut messages = Messages::default();
    for (bytes, end) in pieces {
        messages.push_back(crate::publication::Message {
            bytes: bytes.to_vec(),
            end: *end,
            consumed: 0,
            custody: crate::publication::Custody::default().reader(),
        });
    }
    messages
}

fn drain_messages(ready: &Mutex<Messages>) -> Vec<(Vec<u8>, bool)> {
    let mut messages = std::mem::take(&mut *ready.lock().unwrap());
    let mut result = Vec::new();
    while let Some(message) = messages.pop_front() {
        assert_eq!(message.consumed, 0);
        result.push((message.bytes, message.end));
    }
    result
}

thread_local! {
    static AFTER_READY_POP: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

pub(super) fn after_ready_pop() {
    let hook = AFTER_READY_POP.with(|hook| hook.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[test]
fn a_concurrent_reader_gets_the_partial_messages_suffix_before_the_next_message() {
    let ready = Arc::new(Mutex::new(ready_messages(&[
        (b"abcd", true),
        (b"ef", true),
    ])));
    let other = Arc::clone(&ready);
    let reader = Arc::new(Mutex::new(None));
    let spawned = Arc::clone(&reader);
    AFTER_READY_POP.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            // Select the same boundary on both versions. If pop released the mutex, force the
            // second read to finish before the first can put its suffix back. With atomic pop
            // and suffix retention, the second read waits for the first to release its guard.
            let unlocked = other.try_lock().is_ok();
            let (finished, done) = mpsc::channel();
            *spawned.lock().unwrap() = Some(std::thread::spawn(move || {
                let mut buf = [0; 2];
                let got = take_ready(&other, &mut buf).map(|(n, end)| (buf[..n].to_vec(), end));
                let _ = finished.send(());
                got
            }));
            if unlocked {
                done.recv().unwrap();
            }
        }));
    });
    let mut buf = [0; 2];
    let first = take_ready(&ready, &mut buf).map(|(n, end)| (buf[..n].to_vec(), end));
    let second = reader.lock().unwrap().take().unwrap().join().unwrap();
    let third = take_ready(&ready, &mut buf).map(|(n, end)| (buf[..n].to_vec(), end));
    assert_eq!(first, Some((b"ab".to_vec(), false)));
    assert_eq!(second, Some((b"cd".to_vec(), true)));
    assert_eq!(third, Some((b"ef".to_vec(), true)));
    assert_eq!(take_ready(&ready, &mut buf), None);
}

/// RED (THE DESIGN §5: a plugin's slow I/O answers not-ready, "no blocking thread exists"): a
/// channel message longer than the reader's buffer is read in parts, its rest kept first in line.
/// Put back while the queue's lock was still held (the lock taken for the pop lives through the
/// whole `if let`), the read locked the queue a second time on the same thread and never answered,
/// wedging the worker that drove it.
#[test]
fn a_message_longer_than_the_readers_buffer_is_read_in_parts_and_never_wedges_the_reader() {
    let ready = Arc::new(Mutex::new(ready_messages(&[(b"abcd", true)])));
    let (answer, answered) = mpsc::channel();
    let queue = Arc::clone(&ready);
    std::thread::spawn(move || {
        let mut buf = [0_u8; 2];
        let first = take_ready(&queue, &mut buf).map(|(n, end)| (buf[..n].to_vec(), end));
        let second = take_ready(&queue, &mut buf).map(|(n, end)| (buf[..n].to_vec(), end));
        let _ = answer.send((first, second));
    });
    assert_eq!(
        answered.recv_timeout(Duration::from_secs(5)),
        Ok((Some((b"ab".to_vec(), false)), Some((b"cd".to_vec(), true)))),
        "the message is read in two parts, the end on the last"
    );
}

/// A caller leg that takes nothing (the pairing's line frames are not under test here).
struct NoLeg;

impl crate::datagram::LegSink for NoLeg {
    fn line(&self, _: crate::datagram::Across, _: std::time::Instant) {}
    fn close(&self) {}
}

/// One channel message on stream `3`, whole.
fn message(bytes: &[u8]) -> crate::framer::Got {
    crate::framer::Got {
        stream: 3,
        bytes: bytes.to_vec(),
        end_of_frame: true,
        status_code: None,
        handoff: false,
        status_class: 0,
        fault: 0,
        retry_after_secs: None,
        declared_len: None,
        fields: false,
        text: false,
        reason: None,
        failed: false,
        end: false,
    }
}

/// RED (THE DESIGN §5: reads are back-pressured, nothing is lost silently on
/// a reliable stream; `busbar_contract::abi::transport`, "an EMPTY piece is an empty frame (a
/// wire's empty message)"): every channel message the leg's association yields reaches the
/// reader, in order: an EMPTY message is relayed as an empty message, and a reader that has fallen
/// past the leg's queue bound loses nothing (the leg stops draining its port instead). The leg
/// dropped both, with no failure, flag or count.
#[test]
fn every_channel_message_reaches_the_reader_empty_ones_and_past_the_bound() {
    crate::support::worker().block_on(async {
        let port = crate::udp::ReadyPort::open(crate::udp::bind("127.0.0.1:0").unwrap()).unwrap();
        let leg = super::UpstreamLeg {
            framing: Mutex::default(),
            pairing: std::sync::Weak::new(),
            port,
            ready: Mutex::new(Messages::default()),
            channel: Mutex::new(None),
            recv: Mutex::new(Vec::new()),
            timer: Mutex::new(None),
        };
        let pairing =
            crate::datagram::Pairing::new(Arc::new(NoLeg), "127.0.0.1:1".parse().unwrap());
        let now = std::time::Instant::now();
        let _ = leg.take(
            &pairing,
            crate::framer::Yielded {
                pieces: vec![message(b""), message(b"x")],
                ..Default::default()
            },
            now,
        );
        let mut buf = [0_u8; 4];
        assert_eq!(
            take_ready(&leg.ready, &mut buf),
            Some((0, true)),
            "the empty message, as an empty message"
        );
        assert_eq!(take_ready(&leg.ready, &mut buf), Some((1, true)));
        let past = super::MAX_READY + 5;
        let _ = leg.take(
            &pairing,
            crate::framer::Yielded {
                pieces: (0..past).map(|_| message(b"m")).collect(),
                ..Default::default()
            },
            now,
        );
        assert_eq!(
            leg.ready.lock().unwrap().len(),
            past,
            "nothing past the bound is dropped"
        );
    });
}

/// A datagram framer that answers every op with nothing (its `begin` naming framing `1`), and whose
/// `emit` HANGS once armed: it says it is inside the crossing, then does not come back until the
/// test lets it. Every crossing is recorded with the thread it ran on.
struct Hanging {
    facts: crate::framer::DoorFacts,
    gate: Mutex<Option<(mpsc::Sender<std::thread::ThreadId>, mpsc::Receiver<()>)>>,
    crossed: Mutex<Vec<(&'static str, std::thread::ThreadId)>>,
}

impl crate::framer::FramerDoor for Hanging {
    fn facts(&self) -> &crate::framer::DoorFacts {
        &self.facts
    }

    fn cross(&self, call: crate::framer::Call<'_>) -> crate::framer::Crossed {
        use crate::framer::Call;
        let op = match call {
            Call::Begin(_, o) => {
                o.framing = 1;
                "begin"
            }
            Call::Emit(..) => "emit",
            Call::Finish(..) => "finish",
            _ => "other",
        };
        self.crossed
            .lock()
            .unwrap()
            .push((op, std::thread::current().id()));
        if op == "emit" {
            let gate = self.gate.lock().unwrap().take();
            if let Some((entered, release)) = gate {
                entered.send(std::thread::current().id()).unwrap();
                release.recv().unwrap();
            }
        }
        crate::framer::Crossed {
            outcome: busbar_contract::abi::mechanism::call::Outcome::Ready,
            error: None,
        }
    }
}

/// RED before the leg's association was driven under no lock (`BUSBAR-1.6.0.md` §11: no plugin
/// code runs under a host lock): its mutex was held across every framer crossing, so the session's
/// close beside a hung line-frame emit waited on the plugin for as long as it hung. Now a second
/// line frame and the close both return while the emit still hangs, and the holder finishes the
/// association on its own thread as it brings it back.
#[test]
fn a_close_beside_a_hung_datagram_emit_never_waits_and_the_holder_finishes_it() {
    use crate::datagram::{Across, LegSink as _};
    let rt = crate::support::worker();
    let handle = rt.handle().clone();
    rt.block_on(async {
        let door = Arc::new(Hanging {
            facts: crate::framer::DoorFacts {
                name: "hanging".into(),
                claims: vec!["hanging"],
                role: busbar_contract::abi::transport::ROLE_FRAMER,
                composes_over: Vec::new(),
                ported: false,
                status_rows: Vec::new(),
                duplex: Vec::new(),
                datagram: true,
            },
            gate: Mutex::new(None),
            crossed: Mutex::new(Vec::new()),
        });
        let (framing, _) = crate::datagram::DatagramFraming::accept_minted(
            Arc::clone(&door) as Arc<dyn crate::framer::FramerDoor>,
            "127.0.0.1:9".parse().unwrap(),
        )
        .expect("the association begins");
        let port = crate::udp::ReadyPort::open(crate::udp::bind("127.0.0.1:0").unwrap()).unwrap();
        let pairing =
            crate::datagram::Pairing::new(Arc::new(NoLeg), "127.0.0.1:1".parse().unwrap());
        let dialled = Arc::new(super::Dialled::new(framing, port, pairing, None));
        dialled
            .pairing
            .attach(Arc::clone(&dialled.leg) as Arc<dyn crate::datagram::LegSink>)
            .unwrap();
        let frame = |b: &[u8]| Across {
            stream: 1,
            bytes: b.to_vec(),
            end_of_frame: true,
        };

        let (entered_tx, entered) = mpsc::channel();
        let (release, held_back) = mpsc::channel();
        *door.gate.lock().unwrap() = Some((entered_tx, held_back));
        let holding = Arc::clone(&dialled);
        let on = handle.clone();
        let first = frame(b"first");
        let holder = std::thread::spawn(move || {
            let _rt = on.enter();
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            let _ = holding
                .leg
                .poll_line(&mut cx, Some(&first), false, std::time::Instant::now());
        });
        let owner = entered
            .recv_timeout(Duration::from_secs(10))
            .expect("the line frame reaches the framer");

        let (done_tx, done) = mpsc::channel();
        let closing = Arc::clone(&dialled);
        let second = frame(b"second");
        let closer = std::thread::spawn(move || {
            closing.leg.line(second, std::time::Instant::now());
            closing.close();
            done_tx.send(()).unwrap();
        });
        done.recv_timeout(Duration::from_secs(5))
            .expect("a line frame and a close beside a hung emit returned while it still hangs");
        let finished_early = door
            .crossed
            .lock()
            .unwrap()
            .iter()
            .any(|(op, _)| *op == "finish");
        assert!(
            !finished_early,
            "the close was handed to the holder: nothing crossed beside its hung emit"
        );

        release.send(()).unwrap();
        holder.join().unwrap();
        closer.join().unwrap();
        let crossed = door.crossed.lock().unwrap().clone();
        let emit = crossed
            .iter()
            .rposition(|(op, _)| *op == "emit")
            .expect("the emit crossed");
        assert_eq!(
            crossed[emit + 1..].to_vec(),
            vec![("finish", owner)],
            "the holder finished the association as it brought it back, on its own thread, and \
             the closed leg emitted nothing more"
        );
    });
}

/// The caller observes LINE feedback without knowing what its frame contains.
#[derive(Default)]
struct ReturnedLines(
    Mutex<Vec<crate::datagram::Across>>,
    Mutex<Option<Box<dyn FnOnce() + Send>>>,
    Mutex<std::sync::Weak<crate::datagram::Pairing>>,
);

impl crate::datagram::LegSink for ReturnedLines {
    fn line(&self, frame: crate::datagram::Across, _: std::time::Instant) {
        self.0.lock().unwrap().push(frame);
        let hook = self.1.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }

    fn close(&self) {}

    fn pairing(&self) -> Option<Arc<crate::datagram::Pairing>> {
        self.2.lock().unwrap().upgrade()
    }
}

/// A finite Emit answer with a channel head, LINE feedback, and more channel messages than the
/// actual host sink can hold. Recalls retain their output but receive no application bytes.
struct LineOutputs {
    facts: crate::framer::DoorFacts,
    pending: Mutex<VecDeque<(u64, Vec<u8>, u16)>>,
    calls: Mutex<Vec<(usize, bool, bool)>>,
    inputs: Mutex<Vec<Vec<u8>>>,
    count: std::sync::atomic::AtomicUsize,
    finished: std::sync::atomic::AtomicUsize,
    during_emit: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    feedback_count: std::sync::atomic::AtomicUsize,
    timer_mode: bool,
    timer_left: std::sync::atomic::AtomicUsize,
    timer_calls: std::sync::atomic::AtomicUsize,
}

#[allow(unsafe_code)]
impl crate::framer::FramerDoor for LineOutputs {
    fn facts(&self) -> &crate::framer::DoorFacts {
        &self.facts
    }

    fn cross(&self, call: crate::framer::Call<'_>) -> crate::framer::Crossed {
        use busbar_contract::abi::transport::{
            FramePiece, EMIT_TEXT, PIECE_END_OF_FRAME, PIECE_FIELDS, YIELD_MORE,
        };
        match call {
            crate::framer::Call::Begin(_, out) => {
                out.framing = 1;
                if self.timer_mode {
                    out.yielded.flags = busbar_contract::abi::transport::YIELD_HAS_DEADLINE;
                    out.yielded.next_deadline_ns = 0;
                }
            }
            crate::framer::Call::Emit(input, out) => {
                self.calls.lock().unwrap().push((
                    input.len,
                    input.end_of_frame != 0,
                    input.flags & EMIT_TEXT != 0,
                ));
                let hook = self.during_emit.lock().unwrap().take();
                if let Some(hook) = hook {
                    hook();
                }
                let mut pending = self.pending.lock().unwrap();
                if input.len != 0 {
                    // SAFETY: the host owns this initialized input loan for this crossing.
                    self.inputs.lock().unwrap().push(unsafe {
                        std::slice::from_raw_parts(input.bytes, input.len).to_vec()
                    });
                    assert!(pending.is_empty(), "new input before the same-op recall");
                    let count = input.sink.pieces_cap + 1;
                    self.count.store(count, std::sync::atomic::Ordering::SeqCst);
                    pending.push_back((3, b"label: channel\r\n".to_vec(), PIECE_FIELDS));
                    for _ in 0..self
                        .feedback_count
                        .load(std::sync::atomic::Ordering::SeqCst)
                    {
                        pending.push_back((20, b"feedback".to_vec(), 0));
                    }
                    for index in 0..count {
                        pending.push_back((3, index.to_string().into_bytes(), 0));
                    }
                }
                let mut used = 0;
                let mut written = 0;
                while written < input.sink.pieces_cap {
                    let Some((stream, bytes, flags)) = pending.front() else {
                        break;
                    };
                    if used + bytes.len() > input.sink.frame_cap {
                        break;
                    }
                    // SAFETY: both host loans were capacity-checked; every span names bytes
                    // initialized on this crossing and copied by the host before the next one.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            input.sink.frame.add(used),
                            bytes.len(),
                        );
                        input.sink.pieces.add(written).write(FramePiece {
                            stream: *stream,
                            offset: used as u64,
                            len: bytes.len() as u64,
                            flags: *flags | PIECE_END_OF_FRAME,
                            ..FramePiece::ZERO
                        });
                    }
                    used += bytes.len();
                    written += 1;
                    pending.pop_front();
                }
                out.yielded.frame_len = used as u64;
                out.yielded.pieces_len = written as u32;
                if !pending.is_empty() {
                    out.yielded.flags = YIELD_MORE;
                }
            }
            crate::framer::Call::Timer(input, out) if self.timer_mode => {
                use std::sync::atomic::Ordering;
                let left = if self.timer_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    let count = input.sink.pieces_cap + 1;
                    self.count.store(count, Ordering::SeqCst);
                    count
                } else {
                    self.timer_left.load(Ordering::SeqCst)
                };
                let bytes = b"timer";
                let written = left
                    .min(input.sink.pieces_cap)
                    .min(input.sink.frame_cap / bytes.len());
                for index in 0..written {
                    // SAFETY: both loans were checked above; spans name initialized payload.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            input.sink.frame.add(index * bytes.len()),
                            bytes.len(),
                        );
                        input.sink.pieces.add(index).write(FramePiece {
                            stream: 3,
                            offset: (index * bytes.len()) as u64,
                            len: bytes.len() as u64,
                            flags: PIECE_END_OF_FRAME,
                            ..FramePiece::ZERO
                        });
                    }
                }
                self.timer_left.store(left - written, Ordering::SeqCst);
                out.yielded.frame_len = (written * bytes.len()) as u64;
                out.yielded.pieces_len = written as u32;
                if left > written {
                    out.yielded.flags = YIELD_MORE;
                }
            }
            crate::framer::Call::Finish(..) => {
                self.finished
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            _ => {}
        }
        crate::framer::Crossed {
            outcome: busbar_contract::abi::mechanism::call::Outcome::Ready,
            error: None,
        }
    }
}

fn line_outputs() -> (Arc<super::Dialled>, Arc<LineOutputs>, Arc<ReturnedLines>) {
    line_outputs_with_limit(None)
}

fn line_outputs_with_limit(
    limit: Option<usize>,
) -> (Arc<super::Dialled>, Arc<LineOutputs>, Arc<ReturnedLines>) {
    line_outputs_settings(limit, false)
}

fn line_outputs_settings(
    limit: Option<usize>,
    timer_mode: bool,
) -> (Arc<super::Dialled>, Arc<LineOutputs>, Arc<ReturnedLines>) {
    let door = Arc::new(LineOutputs {
        facts: crate::framer::DoorFacts {
            name: "line-output".into(),
            claims: vec!["line-output"],
            role: busbar_contract::abi::transport::ROLE_FRAMER,
            composes_over: Vec::new(),
            ported: false,
            status_rows: Vec::new(),
            duplex: Vec::new(),
            datagram: true,
        },
        pending: Mutex::default(),
        calls: Mutex::default(),
        inputs: Mutex::default(),
        count: std::sync::atomic::AtomicUsize::new(0),
        finished: std::sync::atomic::AtomicUsize::new(0),
        during_emit: Mutex::new(None),
        feedback_count: std::sync::atomic::AtomicUsize::new(1),
        timer_mode,
        timer_left: std::sync::atomic::AtomicUsize::new(0),
        timer_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let (framing, _) = crate::datagram::DatagramFraming::accept_minted(
        Arc::clone(&door) as Arc<dyn crate::framer::FramerDoor>,
        "127.0.0.1:9".parse().unwrap(),
    )
    .unwrap();
    let caller = Arc::new(ReturnedLines::default());
    let pairing = crate::datagram::Pairing::with_memory_limit(
        Arc::clone(&caller) as Arc<dyn crate::datagram::LegSink>,
        "127.0.0.1:1".parse().unwrap(),
        limit,
    );
    *caller.2.lock().unwrap() = Arc::downgrade(&pairing);
    let now = std::time::Instant::now();
    for (leg, stream) in [
        (crate::datagram::Leg::Caller, 10),
        (crate::datagram::Leg::Upstream, 20),
    ] {
        let mut head = message(b"kind: opaque\r\n");
        head.stream = stream;
        head.fields = true;
        pairing.sort(leg, vec![head], now);
    }
    let port = crate::udp::ReadyPort::open(crate::udp::bind("127.0.0.1:0").unwrap()).unwrap();
    let dialled = Arc::new(super::Dialled::new(framing, port, pairing, None));
    dialled
        .pairing
        .attach(Arc::clone(&dialled.leg) as Arc<dyn crate::datagram::LegSink>)
        .unwrap();
    *dialled.phase.lock().unwrap() = super::Phase::Running;
    (dialled, door, caller)
}

fn incoming_line() -> crate::datagram::Across {
    crate::datagram::Across {
        stream: 20,
        bytes: b"request".to_vec(),
        end_of_frame: true,
    }
}

#[test]
fn a_successful_line_emit_publishes_its_channel_head_messages_and_line_feedback_in_order() {
    use crate::datagram::LegSink as _;
    crate::support::worker().block_on(async {
        let (dialled, door, caller) = line_outputs();
        dialled.leg.line(incoming_line(), std::time::Instant::now());
        assert!(dialled.pairing.published().await.failure.is_none());
        let count = door.count.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(*dialled.leg.channel.lock().unwrap(), Some(3));
        let delivered = drain_messages(&dialled.leg.ready);
        assert_eq!(
            delivered,
            (0..count)
                .map(|i| (i.to_string().into_bytes(), true))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            *caller.0.lock().unwrap(),
            vec![crate::datagram::Across {
                stream: 10,
                bytes: b"feedback".to_vec(),
                end_of_frame: true,
            }]
        );
        let calls = door.calls.lock().unwrap();
        assert_eq!(calls[0], (b"request".len(), true, false));
        assert!(calls.len() > 1);
        assert!(calls[1..].iter().all(|call| *call == (0, false, false)));
    });
}

#[test]
fn a_line_handed_to_the_active_holder_publishes_after_the_holders_older_output() {
    use crate::datagram::LegSink as _;
    crate::support::worker().block_on(async {
        let (dialled, door, caller) = line_outputs();
        let leg = Arc::downgrade(&dialled.leg);
        *door.during_emit.lock().unwrap() = Some(Box::new(move || {
            leg.upgrade()
                .unwrap()
                .line(incoming_line(), std::time::Instant::now());
        }));
        dialled.leg.line(incoming_line(), std::time::Instant::now());
        assert!(dialled.pairing.published().await.failure.is_none());
        let count = door.count.load(std::sync::atomic::Ordering::SeqCst);
        let delivered = drain_messages(&dialled.leg.ready);
        let expected: Vec<_> = (0..count)
            .map(|i| (i.to_string().into_bytes(), true))
            .collect();
        assert_eq!(delivered, [expected.clone(), expected].concat());
        assert_eq!(caller.0.lock().unwrap().len(), 2);
    });
}

#[test]
fn a_line_emit_wakes_an_already_pending_reader_after_publishing_its_output() {
    use crate::datagram::LegSink as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct ReadWake {
        count: AtomicUsize,
        leg: std::sync::Weak<super::UpstreamLeg>,
    }
    impl std::task::Wake for ReadWake {
        fn wake(self: Arc<Self>) {
            if let Some(leg) = self.leg.upgrade() {
                assert!(leg.framing.try_lock().is_ok());
                assert!(leg.ready.try_lock().is_ok());
                assert!(leg.channel.try_lock().is_ok());
            }
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }
    crate::support::worker().block_on(async {
        let (dialled, _, _) = line_outputs();
        let woke = Arc::new(ReadWake {
            count: AtomicUsize::new(0),
            leg: Arc::downgrade(&dialled.leg),
        });
        let waker = std::task::Waker::from(Arc::clone(&woke));
        let mut buf = [0; 16];
        assert_eq!(
            dialled.read(&waker, &mut buf),
            Err(crate::ConnError::Pending)
        );
        let before = woke.count.load(Ordering::SeqCst);
        assert_eq!(before, 0, "an idle drive must not wake itself repeatedly");
        dialled.leg.line(incoming_line(), std::time::Instant::now());
        assert!(dialled.pairing.published().await.failure.is_none());
        assert!(woke.count.load(Ordering::SeqCst) > before);
        let piece = dialled.read(&waker, &mut buf).unwrap();
        assert_eq!(&buf[..piece.len], b"0");
        assert!(piece.end);
    });
}

#[test]
fn an_unwinding_queued_line_publication_keeps_its_framing_guard_until_finish() {
    use crate::datagram::LegSink as _;
    crate::support::worker().block_on(async {
        let (dialled, door, caller) = line_outputs();
        *caller.1.lock().unwrap() = Some(Box::new(|| panic!("publication unwinds")));
        dialled.leg.line(incoming_line(), std::time::Instant::now());
        assert!(dialled.pairing.published().await.failure.is_some());
        let held = dialled.leg.framing.lock().unwrap();
        assert!(held.closing);
        assert!(!held.out);
        assert!(held.framing.is_none());
        drop(held);
        assert_eq!(door.finished.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(dialled);
        assert_eq!(door.finished.load(std::sync::atomic::Ordering::SeqCst), 1);
    });
}

#[test]
fn a_close_during_queued_line_publication_prevents_later_lines_from_crossing() {
    use crate::datagram::LegSink as _;
    crate::support::worker().block_on(async {
        let (dialled, door, caller) = line_outputs();
        let closing = Arc::downgrade(&dialled);
        *caller.1.lock().unwrap() = Some(Box::new(move || closing.upgrade().unwrap().close()));
        dialled.leg.turn(
            (),
            |()| panic!("the association starts at home"),
            |()| panic!("the association starts open"),
            |_, ()| {
                dialled.leg.line(incoming_line(), std::time::Instant::now());
                dialled.leg.line(incoming_line(), std::time::Instant::now());
            },
        );
        dialled.pairing.published().await;
        let calls = door.calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|call| call.0 != 0).count(), 1);
        assert_eq!(door.finished.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(dialled.leg.ready.lock().unwrap().is_empty());
    });
}

struct LatestReadWake {
    woke: Arc<std::sync::atomic::AtomicUsize>,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
    leg: std::sync::Weak<super::UpstreamLeg>,
}

impl std::task::Wake for LatestReadWake {
    fn wake(self: Arc<Self>) {
        if let Some(leg) = self.leg.upgrade() {
            assert!(leg.framing.try_lock().is_ok());
            assert!(leg.ready.try_lock().is_ok());
        }
        self.woke.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for LatestReadWake {
    fn drop(&mut self) {
        if let Some(leg) = self.leg.upgrade() {
            assert!(
                leg.framing.try_lock().is_ok(),
                "waker dropped under the handoff"
            );
            assert!(
                leg.ready.try_lock().is_ok(),
                "waker dropped under the ready queue"
            );
        }
        self.dropped
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn replacing_quiet_read_contexts_releases_old_wakers_without_waking_them() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    crate::support::worker().block_on(async {
        let (dialled, _, _) = line_outputs();
        let woke = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut contexts = Vec::new();
        let mut buf = [0; 16];
        for _ in 0..128 {
            let reader = Arc::new(LatestReadWake {
                woke: Arc::clone(&woke),
                dropped: Arc::clone(&dropped),
                leg: Arc::downgrade(&dialled.leg),
            });
            contexts.push(Arc::downgrade(&reader));
            let waker = std::task::Waker::from(reader);
            assert_eq!(
                dialled.read(&waker, &mut buf),
                Err(crate::ConnError::Pending)
            );
        }
        assert_eq!(
            woke.load(Ordering::SeqCst),
            0,
            "no replacement self-wake loop"
        );
        assert_eq!(contexts.iter().filter(|w| w.upgrade().is_some()).count(), 1);
        assert_eq!(dropped.load(Ordering::SeqCst), contexts.len() - 1);
    });
}

#[test]
fn line_publication_wakes_only_the_latest_read_context_as_the_stream_and_reactor_do() {
    use crate::datagram::LegSink as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    crate::support::worker().block_on(async {
        let (dialled, _, _) = line_outputs();
        let first = Arc::new(AtomicUsize::new(0));
        let latest = Arc::new(AtomicUsize::new(0));
        let mut buf = [0; 16];
        for count in [&first, &latest] {
            let waker = std::task::Waker::from(Arc::new(LatestReadWake {
                woke: Arc::clone(count),
                dropped: Arc::new(AtomicUsize::new(0)),
                leg: Arc::downgrade(&dialled.leg),
            }));
            assert_eq!(
                dialled.read(&waker, &mut buf),
                Err(crate::ConnError::Pending)
            );
        }
        assert_eq!(first.load(Ordering::SeqCst), 0);
        assert_eq!(latest.load(Ordering::SeqCst), 0);
        dialled.leg.line(incoming_line(), std::time::Instant::now());
        assert!(dialled.pairing.published().await.failure.is_none());
        assert_eq!(first.load(Ordering::SeqCst), 0);
        assert!(latest.load(Ordering::SeqCst) > 0);
    });
}

#[test]
fn the_latest_pending_read_is_woken_on_close_and_on_a_queued_publication_unwind() {
    use crate::datagram::LegSink as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    for unwind in [false, true] {
        crate::support::worker().block_on(async {
            let (dialled, _, caller) = line_outputs();
            let woke = Arc::new(AtomicUsize::new(0));
            let waker = std::task::Waker::from(Arc::new(LatestReadWake {
                woke: Arc::clone(&woke),
                dropped: Arc::new(AtomicUsize::new(0)),
                leg: Arc::downgrade(&dialled.leg),
            }));
            let mut buf = [0; 16];
            assert_eq!(
                dialled.read(&waker, &mut buf),
                Err(crate::ConnError::Pending)
            );
            assert_eq!(woke.load(Ordering::SeqCst), 0);
            if unwind {
                *caller.1.lock().unwrap() = Some(Box::new(|| panic!("publication unwinds")));
                dialled.leg.line(incoming_line(), std::time::Instant::now());
                assert!(dialled.pairing.published().await.failure.is_some());
            } else {
                dialled.close();
            }
            assert!(woke.load(Ordering::SeqCst) > 0);
        });
    }
}

#[test]
fn a_busy_line_takes_no_input_and_resumes_exactly_once_after_the_holder_returns() {
    use crate::datagram::{Leg, LegSink as _, LineStep};
    use std::task::{Context, Poll, Waker};
    use std::time::Instant;

    let runtime = crate::support::worker();
    let handle = runtime.handle().clone();
    runtime.block_on(async {
        let (dialled, door, _) = line_outputs();
        let (entered_tx, entered) = mpsc::channel();
        let (release, held_back) = mpsc::channel();
        *door.during_emit.lock().unwrap() = Some(Box::new(move || {
            entered_tx.send(()).unwrap();
            held_back.recv().unwrap();
        }));
        let first = Arc::clone(&dialled);
        let holder = std::thread::spawn(move || {
            let _entered = handle.enter();
            let mut cx = Context::from_waker(Waker::noop());
            first
                .leg
                .poll_line(&mut cx, Some(&incoming_line()), false, Instant::now())
        });
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        let woke = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(LatestReadWake {
            woke: Arc::clone(&woke),
            dropped: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            leg: Arc::downgrade(&dialled.leg),
        }));
        let mut cx = Context::from_waker(&waker);
        let mut second = incoming_line();
        second.bytes = b"second".to_vec();
        assert!(matches!(
            dialled
                .leg
                .poll_line(&mut cx, Some(&second), true, Instant::now()),
            Poll::Pending
        ));
        assert_eq!(door.calls.lock().unwrap().len(), 1);
        release.send(()).unwrap();
        let Poll::Ready(Ok(LineStep::Batch {
            yielded,
            accepted: true,
        })) = holder.join().unwrap()
        else {
            panic!("the first crossing must take its input once");
        };
        assert!(woke.load(std::sync::atomic::Ordering::SeqCst) > 0);
        assert!(!dialled.leg.framing.lock().unwrap().out);
        let batch = dialled
            .pairing
            .publish(Leg::Upstream, yielded, Instant::now());
        dialled.leg.channels(batch, Instant::now()).unwrap();
        assert_eq!(
            door.calls.lock().unwrap().len(),
            1,
            "MORE is not eagerly accumulated"
        );
        let ready = dialled.leg.ready.lock().unwrap().len();
        assert!(ready > 0 && ready < door.count.load(std::sync::atomic::Ordering::SeqCst));
        assert!(dialled.pairing.published().await.failure.is_none());
        let Poll::Ready(Ok(LineStep::Batch {
            yielded,
            accepted: true,
        })) = dialled
            .leg
            .poll_line(&mut cx, Some(&second), true, Instant::now())
        else {
            panic!("the unaccepted frame must now cross");
        };
        let batch = dialled
            .pairing
            .publish(Leg::Upstream, yielded, Instant::now());
        dialled.leg.channels(batch, Instant::now()).unwrap();
        assert!(dialled.pairing.published().await.failure.is_none());
        assert_eq!(
            *door.inputs.lock().unwrap(),
            vec![b"request".to_vec(), b"second".to_vec()]
        );
        let calls = door.calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|call| call.0 != 0).count(), 2);
        assert!(calls
            .iter()
            .filter(|call| call.0 == 0)
            .all(|call| *call == (0, false, false)));
    });
}

#[test]
fn a_charged_channel_keeps_its_original_allocation_until_consumption_or_close() {
    use crate::datagram::LegSink as _;
    for cancel in [false, true] {
        crate::support::worker().block_on(async {
            let (dialled, _, _) = line_outputs_with_limit(Some(usize::MAX));
            let memory = dialled.pairing.memory_account();
            dialled.leg.line(incoming_line(), std::time::Instant::now());
            assert!(dialled.pairing.published().await.failure.is_none());
            let mut buf = [0; 16];
            // Find a real multi-byte CHANNEL piece from the scripted MORE output.
            loop {
                let multi = dialled
                    .leg
                    .ready
                    .lock()
                    .unwrap()
                    .first
                    .as_ref()
                    .unwrap()
                    .message
                    .bytes
                    .len()
                    > 1;
                if multi {
                    break;
                }
                take_ready(&dialled.leg.ready, &mut buf).unwrap();
            }
            let before = memory.used();
            assert!(before > 0);
            let pointer = dialled
                .leg
                .ready
                .lock()
                .unwrap()
                .first
                .as_ref()
                .unwrap()
                .message
                .bytes
                .as_ptr();
            assert_eq!(
                take_ready(&dialled.leg.ready, &mut buf[..1]),
                Some((1, false))
            );
            {
                let ready = dialled.leg.ready.lock().unwrap();
                let message = &ready.first.as_ref().unwrap().message;
                assert_eq!(message.bytes.as_ptr(), pointer);
                assert_eq!(message.consumed, 1);
            }
            assert_eq!(
                memory.used(),
                before,
                "a copied suffix must not retire the original lease"
            );
            if cancel {
                dialled.close();
            } else {
                while take_ready(&dialled.leg.ready, &mut buf).is_some() {}
            }
            assert!(
                memory.used() < before,
                "consumption or cancellation retires reader storage"
            );
            assert!(dialled.leg.ready.lock().unwrap().is_empty());
            // Persistent channel descriptions and framer metadata stay charged until their
            // actual owners retire too; they are not reader payload.
            dialled.close();
            drop(dialled);
            assert_eq!(memory.used(), 0);
        });
    }
}

#[test]
fn ordinary_timer_more_output_uses_charged_reader_custody_and_same_op_recalls() {
    crate::support::worker().block_on(async {
        let (dialled, door, _) = line_outputs_settings(Some(usize::MAX), true);
        let mut buf = [0; 2];
        let piece = dialled.read(std::task::Waker::noop(), &mut buf).unwrap();
        assert_eq!(&buf[..piece.len], b"ti");
        assert!(!piece.end);
        assert!(dialled.pairing.memory_account().used() > 0);
        let memory = dialled.pairing.memory_account();
        assert!(!dialled.leg.framing.lock().unwrap().out);
        assert!(dialled.pairing.published().await.failure.is_none());
        assert!(door.timer_calls.load(std::sync::atomic::Ordering::SeqCst) > 1);
        assert!(
            door.inputs.lock().unwrap().is_empty(),
            "Timer continuation must never become Emit"
        );
        let mut received = b"ti".to_vec();
        while let Some((n, _)) = take_ready(&dialled.leg.ready, &mut buf) {
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(
            received,
            b"timer".repeat(door.count.load(std::sync::atomic::Ordering::SeqCst))
        );
        dialled.close();
        drop(dialled);
        assert_eq!(memory.used(), 0);
    });
}

#[test]
fn accepted_application_writes_remain_bounded_until_actual_emission() {
    crate::support::worker().block_on(async {
        let (dialled, door, _) = line_outputs_with_limit(Some(usize::MAX));
        *dialled.leg.channel.lock().unwrap() = Some(3);
        assert_eq!(dialled.write(b"prefix-", false, false), Ok(7));
        assert_eq!(dialled.write(b"tail", true, true), Ok(4));
        assert_eq!(
            dialled.write(b"unaccepted", false, false),
            Err(crate::ConnError::Pending)
        );
        assert!(
            door.inputs.lock().unwrap().is_empty(),
            "acceptance is not completed emission"
        );
        let outcome = dialled.pairing.published().await;
        assert!(outcome.failure.is_none());
        assert_eq!(outcome.original_bytes, 11);
        assert_eq!(outcome.original_handed_bytes, 11);
        assert_eq!(outcome.original_cancelled_bytes, 0);
        assert_eq!(*door.inputs.lock().unwrap(), vec![b"prefix-tail".to_vec()]);
        assert_eq!(door.calls.lock().unwrap()[0], (11, true, true));
        assert_eq!(dialled.write(b"next", false, false), Ok(4));
        let memory = dialled.pairing.memory_account();
        dialled.close();
        drop(dialled);
        assert_eq!(memory.used(), 0);
    });
}

#[test]
fn a_publication_completion_wake_can_admit_the_next_episode_before_the_old_task_retires() {
    use std::future::Future;
    struct NextWrite {
        dialled: std::sync::Weak<super::Dialled>,
        result: Mutex<Option<Result<usize, crate::ConnError>>>,
        fired: tokio::sync::Notify,
    }
    impl std::task::Wake for NextWrite {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            let mut result = self.result.lock().unwrap();
            if result.is_none() {
                *result = Some(self.dialled.upgrade().unwrap().write(b"next", true, false));
            }
            drop(result);
            self.fired.notify_one();
        }
    }
    crate::support::worker().block_on(async {
        let (dialled, door, _) = line_outputs();
        *dialled.leg.channel.lock().unwrap() = Some(3);
        assert_eq!(dialled.write(b"first", true, false), Ok(5));
        let next = Arc::new(NextWrite {
            dialled: Arc::downgrade(&dialled),
            result: Mutex::new(None),
            fired: tokio::sync::Notify::new(),
        });
        let waker = std::task::Waker::from(Arc::clone(&next));
        let mut context = std::task::Context::from_waker(&waker);
        let mut first = Box::pin(dialled.pairing.published());
        assert!(first.as_mut().poll(&mut context).is_pending());
        // Notify invokes this waker synchronously after the first actor declares quiescence,
        // while its completed future still owns its cancellation guard.
        tokio::time::timeout(Duration::from_secs(5), next.fired.notified())
            .await
            .expect("the first publication reached actual quiescence");
        drop(first);
        assert_eq!(*next.result.lock().unwrap(), Some(Ok(4)));
        let outcome = dialled.pairing.published().await;
        assert!(outcome.failure.is_none());
        assert_eq!(outcome.original_bytes, 9);
        assert_eq!(outcome.original_handed_bytes, 9);
        assert_eq!(outcome.original_cancelled_bytes, 0);
        assert_eq!(
            *door.inputs.lock().unwrap(),
            vec![b"first".to_vec(), b"next".to_vec()]
        );
        assert!(!dialled.pairing.closed());
        dialled.close();
    });
}

#[test]
fn a_busy_final_write_preserves_the_prefix_and_waits_for_real_progress_without_self_waking() {
    crate::support::worker().block_on(async {
        let (dialled, door, _) = line_outputs_with_limit(Some(usize::MAX));
        *dialled.leg.channel.lock().unwrap() = Some(3);
        assert_eq!(dialled.write(b"accepted-", false, false), Ok(9));
        let woke = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = std::task::Waker::from(Arc::new(LatestReadWake {
            woke: Arc::clone(&woke),
            dropped: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            leg: Arc::downgrade(&dialled.leg),
        }));
        dialled.leg.wait_ready(&waker);
        dialled.leg.turn(
            (),
            |()| panic!("the real association starts at home"),
            |()| panic!("the real association starts open"),
            |_, ()| {
                assert_eq!(
                    dialled.write(b"tail", true, false),
                    Err(crate::ConnError::Pending)
                );
                assert_eq!(
                    dialled.gather.lock().unwrap().bytes.as_slice(),
                    b"accepted-"
                );
                assert_eq!(woke.load(std::sync::atomic::Ordering::SeqCst), 0);
                assert!(door.inputs.lock().unwrap().is_empty());
            },
        );
        assert_eq!(woke.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(dialled.write(b"tail", true, false), Ok(4));
        assert!(dialled.pairing.published().await.failure.is_none());
        assert_eq!(
            *door.inputs.lock().unwrap(),
            vec![b"accepted-tail".to_vec()]
        );
    });
}

#[test]
fn shutdown_before_the_first_actor_poll_cancels_accepted_input_without_replaying_it() {
    crate::support::worker().block_on(async {
        let (dialled, door, _) = line_outputs_with_limit(Some(usize::MAX));
        *dialled.leg.channel.lock().unwrap() = Some(3);
        assert_eq!(dialled.write(b"accepted", true, false), Ok(8));
        dialled.close();
        let outcome = dialled.pairing.published().await;
        assert!(outcome.failure.is_some());
        assert_eq!(outcome.original_bytes, 8);
        assert_eq!(outcome.original_handed_bytes, 0);
        assert_eq!(outcome.original_cancelled_bytes, 8);
        assert_eq!(outcome.handed_frames, 0);
        assert!(door.inputs.lock().unwrap().is_empty());
        assert!(!dialled.gather.lock().unwrap().writing);
        assert_eq!(dialled.pairing.memory_account().used(), 0);
        assert_eq!(
            dialled.write(b"accepted", true, false),
            Err(crate::ConnError::Closed)
        );
    });
}

#[test]
fn a_configured_preaccept_refusal_never_tells_the_framer_it_took_application_bytes() {
    use crate::datagram::{LegSink as _, LineStep};
    crate::support::worker().block_on(async {
        let (dialled, door, _) = line_outputs_with_limit(Some(1));
        *dialled.leg.channel.lock().unwrap() = Some(3);
        let woke = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = std::task::Waker::from(Arc::new(LatestReadWake {
            woke: Arc::clone(&woke),
            dropped: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            leg: Arc::downgrade(&dialled.leg),
        }));
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(matches!(
            dialled.leg.poll_line(
                &mut cx,
                Some(&incoming_line()),
                false,
                std::time::Instant::now()
            ),
            std::task::Poll::Ready(Ok(LineStep::Credit))
        ));
        assert_eq!(
            woke.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "unavailable credit is not progress"
        );
        assert_eq!(
            dialled.write(b"unaccepted", true, false),
            Err(crate::ConnError::Fault)
        );
        assert!(dialled.pairing.closed());
        assert!(door.calls.lock().unwrap().is_empty());
        let outcome = dialled.pairing.publication_outcome();
        assert_eq!(outcome.original_bytes, 0);
        assert!(outcome.failure.is_some());
        assert_eq!(dialled.pairing.memory_account().used(), 0);
    });
}

#[test]
fn closing_after_partial_feedback_preserves_accepted_handed_and_cancelled_truth() {
    crate::support::worker().block_on(async {
        let (dialled, door, caller) = line_outputs_with_limit(Some(usize::MAX));
        door.feedback_count
            .store(2, std::sync::atomic::Ordering::SeqCst);
        *dialled.leg.channel.lock().unwrap() = Some(3);
        let closing = Arc::downgrade(&dialled);
        *caller.1.lock().unwrap() = Some(Box::new(move || closing.upgrade().unwrap().close()));
        assert_eq!(dialled.write(b"accepted", true, false), Ok(8));
        let outcome = dialled.pairing.published().await;
        assert!(outcome.failure.is_some());
        assert_eq!(outcome.original_bytes, 8);
        assert_eq!(outcome.original_handed_bytes, 8);
        assert_eq!(outcome.original_cancelled_bytes, 0);
        assert_eq!(outcome.accepted_frames, 2);
        assert_eq!(outcome.handed_frames, 1);
        assert_eq!(outcome.cancelled_frames, 1);
        assert_eq!(outcome.handed_bytes, b"feedback".len() as u64);
        assert_eq!(outcome.cancelled_bytes, b"feedback".len() as u64);
        assert_eq!(*door.inputs.lock().unwrap(), vec![b"accepted".to_vec()]);
        assert_eq!(caller.0.lock().unwrap().len(), 1);
        assert!(dialled.leg.ready.lock().unwrap().is_empty());
    });
}
