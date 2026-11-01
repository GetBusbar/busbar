// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The upstream leg's reads: a channel message longer than the reader's buffer; every channel
//! message reaches the reader.

use std::collections::VecDeque;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use super::take_ready;

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
    let ready = Arc::new(Mutex::new(VecDeque::from([
        (b"abcd".to_vec(), true),
        (b"ef".to_vec(), true),
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
    let ready = Arc::new(Mutex::new(VecDeque::from([(b"abcd".to_vec(), true)])));
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
            port,
            ready: Mutex::new(VecDeque::new()),
            channel: Mutex::new(None),
            recv: Mutex::new(Vec::new()),
            timer: Mutex::new(None),
        };
        let pairing =
            crate::datagram::Pairing::new(Arc::new(NoLeg), "127.0.0.1:1".parse().unwrap());
        let now = std::time::Instant::now();
        let _ = leg.take(&pairing, vec![message(b""), message(b"x")], now);
        let mut buf = [0_u8; 4];
        assert_eq!(
            take_ready(&leg.ready, &mut buf),
            Some((0, true)),
            "the empty message, as an empty message"
        );
        assert_eq!(take_ready(&leg.ready, &mut buf), Some((1, true)));
        let past = super::MAX_READY + 5;
        let _ = leg.take(&pairing, (0..past).map(|_| message(b"m")).collect(), now);
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
            holding.leg.line(first, std::time::Instant::now());
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
struct ReturnedLines(Mutex<Vec<crate::datagram::Across>>);

impl crate::datagram::LegSink for ReturnedLines {
    fn line(&self, frame: crate::datagram::Across, _: std::time::Instant) {
        self.0.lock().unwrap().push(frame);
    }

    fn close(&self) {}
}

/// A finite Emit answer with a channel head, LINE feedback, and more channel messages than the
/// actual host sink can hold. Recalls retain their output but receive no application bytes.
struct LineOutputs {
    facts: crate::framer::DoorFacts,
    pending: Mutex<VecDeque<(u64, Vec<u8>, u32)>>,
    calls: Mutex<Vec<(usize, bool, bool)>>,
    count: std::sync::atomic::AtomicUsize,
    during_emit: Mutex<Option<Box<dyn FnOnce() + Send>>>,
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
            crate::framer::Call::Begin(_, out) => out.framing = 1,
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
                    assert!(pending.is_empty(), "new input before the same-op recall");
                    let count = input.sink.pieces_cap + 1;
                    self.count.store(count, std::sync::atomic::Ordering::SeqCst);
                    pending.push_back((3, b"label: channel\r\n".to_vec(), PIECE_FIELDS));
                    pending.push_back((20, b"feedback".to_vec(), 0));
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
            _ => {}
        }
        crate::framer::Crossed {
            outcome: busbar_contract::abi::mechanism::call::Outcome::Ready,
            error: None,
        }
    }
}

fn line_outputs() -> (Arc<super::Dialled>, Arc<LineOutputs>, Arc<ReturnedLines>) {
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
        count: std::sync::atomic::AtomicUsize::new(0),
        during_emit: Mutex::new(None),
    });
    let (framing, _) = crate::datagram::DatagramFraming::accept_minted(
        Arc::clone(&door) as Arc<dyn crate::framer::FramerDoor>,
        "127.0.0.1:9".parse().unwrap(),
    )
    .unwrap();
    let caller = Arc::new(ReturnedLines::default());
    let pairing = crate::datagram::Pairing::new(
        Arc::clone(&caller) as Arc<dyn crate::datagram::LegSink>,
        "127.0.0.1:1".parse().unwrap(),
    );
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
        let count = door.count.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(*dialled.leg.channel.lock().unwrap(), Some(3));
        let delivered: Vec<_> = dialled.leg.ready.lock().unwrap().drain(..).collect();
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
        let count = door.count.load(std::sync::atomic::Ordering::SeqCst);
        let delivered: Vec<_> = dialled.leg.ready.lock().unwrap().drain(..).collect();
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
    struct ReadWake(AtomicUsize);
    impl std::task::Wake for ReadWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    crate::support::worker().block_on(async {
        let (dialled, _, _) = line_outputs();
        let woke = Arc::new(ReadWake(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(Arc::clone(&woke));
        let mut buf = [0; 16];
        assert_eq!(
            dialled.read(&waker, &mut buf),
            Err(crate::ConnError::Pending)
        );
        let before = woke.0.load(Ordering::SeqCst);
        dialled.leg.line(incoming_line(), std::time::Instant::now());
        assert!(woke.0.load(Ordering::SeqCst) > before);
        let piece = dialled.read(&waker, &mut buf).unwrap();
        assert_eq!(&buf[..piece.len], b"0");
        assert!(piece.end);
    });
}
