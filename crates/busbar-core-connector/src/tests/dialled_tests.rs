// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The upstream leg's reads: a channel message longer than the reader's buffer; every channel
//! message reaches the reader.

use std::collections::VecDeque;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use super::take_ready;

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
