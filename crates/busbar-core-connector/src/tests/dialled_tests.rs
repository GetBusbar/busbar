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
            framing: Mutex::new(None),
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
