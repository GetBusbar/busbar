// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::carrier::{Carry, Side};
use crate::framer::{Call, Crossed, DoorFacts, FramerDoor, Refused};
use crate::support::{AuthHost, AuthTicket};
use busbar_contract::abi::mechanism::{call::Outcome, ticket::Ticket};
use busbar_contract::framing_scope::FramingScope;
use busbar_plugin_loader::dispatch::framing_context::FramingContext;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::task::{Context, Poll};

/// A finite, immediately readable carrier: no socket timing can hide an excessive read.
struct Input {
    inner: TestDoor,
    read: AtomicUsize,
    written: AtomicUsize,
    total: usize,
}
impl FramerDoor for Input {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }
    fn side(&self) -> Option<Box<dyn Side>> {
        self.inner.side()
    }
    fn carry(&self, _: &dyn Side, _: bool, call: Carry<'_>) -> Crossed {
        let mut outcome = Outcome::Ready;
        match call {
            Carry::Read(i, o) => {
                let read = self.read.load(Ordering::SeqCst);
                let n = i.cap.min(self.total - read);
                if n == 0 {
                    outcome = Outcome::Pending;
                } else {
                    // SAFETY: the connector lends exactly cap initialized, writable bytes.
                    unsafe { std::slice::from_raw_parts_mut(i.buf, n) }.fill(b'x');
                    o.len = n as u64;
                    self.read.fetch_add(n, Ordering::SeqCst);
                }
            }
            Carry::Write(i, o) => {
                o.len = i.len as u64;
                self.written.fetch_add(i.len, Ordering::SeqCst);
            }
            _ => {}
        }
        Crossed {
            outcome,
            error: None,
        }
    }
}

/// Pending auth retains input while fresh tickets still deliver a sibling. The real loader's
/// per-leg metadata is used here; the HTTP door test separately exercises the wire report.
struct Holding {
    inner: TestDoor,
    scope: Arc<FramingContext>,
    auth: Arc<AuthHost>,
    next: AtomicU32,
    started: AtomicBool,
    admitted: AtomicBool,
    sibling: AtomicBool,
    split_input: bool,
    retained: Mutex<Vec<u8>>,
    timers: AtomicUsize,
}
impl FramerDoor for Holding {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn framing_context(&self, _: u64, _: u64) -> Result<Option<Arc<dyn FramingScope>>, Refused> {
        Ok(Some(self.scope.clone()))
    }
    fn framing_side(&self) -> Option<Box<dyn Side>> {
        Some(Box::new(AuthTicket {
            ticket: Ticket {
                slot: self.next.fetch_add(1, Ordering::SeqCst),
                generation: 1,
            },
            host: self.auth.clone(),
        }))
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        if matches!(&call, Call::Timer(..)) {
            self.timers.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.cross(call)
    }
    fn cross_on(&self, side: &dyn Side, resume: bool, call: Call<'_>) -> Crossed {
        let Call::Ingest(i, o) = call else {
            return self.cross(call);
        };
        let mut outcome = Outcome::Ready;
        if resume {
            assert_eq!(i.len, 0, "resuming never takes the input twice");
            if self.auth.call(side.ticket(), 0).is_none() {
                outcome = Outcome::Pending;
            } else {
                self.admitted.store(true, Ordering::SeqCst);
                self.retained.lock().unwrap().clear();
                crate::support::pieces_on_lanes(&i.sink, o, b"1");
            }
        } else if !self.admitted.load(Ordering::SeqCst) {
            let input = crate::support::lent(i.bytes, i.len);
            let first = !self.started.swap(true, Ordering::SeqCst);
            let split = if self.split_input && !first {
                input.len() / 2
            } else {
                0
            };
            self.retained
                .lock()
                .unwrap()
                .extend_from_slice(&input[split..]);
            if split != 0 {
                // SAFETY: these bytes and one piece fit the connector's lent sink.
                unsafe {
                    std::ptr::copy_nonoverlapping(input.as_ptr(), i.sink.frame, split);
                    i.sink
                        .pieces
                        .write(busbar_contract::abi::transport::FramePiece {
                            stream: 3,
                            offset: 0,
                            len: split as u64,
                            code: 0,
                            status_class: 0,
                            flags: 0,
                            fault: 0,
                            retry_after_secs: 0,
                            declared_len: 0,
                        });
                }
                o.yielded.frame_len = split as u64;
                o.yielded.pieces_len = 1;
            }
            if first {
                assert!(self.auth.call(side.ticket(), 0).is_none());
                outcome = Outcome::Pending;
            } else if !self.split_input && !self.sibling.swap(true, Ordering::SeqCst) {
                crate::support::pieces_on_lanes(&i.sink, o, b"3");
            }
        }
        self.scope
            .set_retained_input(self.retained.lock().unwrap().len() as u64);
        Crossed {
            outcome,
            error: None,
        }
    }
}

#[test]
fn pending_auth_retained_input_stops_reads_but_resumes_siblings_timers_and_writes() {
    worker().block_on(async {
        let input = Arc::new(Input {
            inner: TestDoor::new("input", &["input"], &[], Knobs::default()),
            read: AtomicUsize::new(0),
            written: AtomicUsize::new(0),
            total: 4 * RECEIVE_BUFFER_BYTES,
        });
        let holding = Arc::new(Holding {
            inner: TestDoor::identity("holding"),
            scope: FramingContext::new(7, 0, 0, None).unwrap(),
            auth: Arc::new(AuthHost::default()),
            next: AtomicU32::new(10),
            started: AtomicBool::new(false),
            admitted: AtomicBool::new(false),
            sibling: AtomicBool::new(false),
            split_input: false,
            retained: Mutex::new(Vec::new()),
            timers: AtomicUsize::new(0),
        });
        let carried = crate::carrier::Carried::accepted(
            input.clone(),
            Arc::new(crate::hostio::HostIo::new()),
            1,
            None,
        )
        .unwrap();
        let mut conn = Connection::accepted(
            Some(holding.clone()),
            carried,
            &Accept {
                tls: None,
                alpn: Vec::new(),
                handshake_timeout: Duration::from_secs(5),
            },
            None,
        )
        .unwrap();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(Ok(Some(sibling))) = conn.poll_piece(&mut cx) else {
            panic!("a fresh ticket must deliver the sibling while auth waits");
        };
        assert_eq!(sibling.stream, 3);
        assert!(conn.poll_piece(&mut cx).is_pending());
        let read = input.read.load(Ordering::SeqCst);
        assert!(
            (RECEIVE_BUFFER_BYTES..RECEIVE_BUFFER_BYTES + READ_CHUNK).contains(&read),
            "private input must stop socket reads at the existing bound: {read}"
        );
        assert!(conn.poll_piece(&mut cx).is_pending());
        assert_eq!(input.read.load(Ordering::SeqCst), read);
        conn.framer_deadline = Some(Instant::now());
        assert!(conn.poll_piece(&mut cx).is_pending());
        assert_eq!(holding.timers.load(Ordering::SeqCst), 1);
        conn.write(b"reply", false, false, &mut cx).unwrap();
        assert!(
            input.written.load(Ordering::SeqCst) > 0,
            "pressure does not hold writes"
        );
        holding.auth.complete(1);
        let Poll::Ready(Ok(Some(admitted))) = conn.poll_piece(&mut cx) else {
            panic!("stored auth completion must resume at receive pressure");
        };
        assert_eq!(admitted.stream, 1);
        assert_eq!(holding.auth.calls(), 1, "resume reuses the first dispatch");
        assert!(conn.poll_piece(&mut cx).is_pending());
        assert_eq!(
            input.read.load(Ordering::SeqCst),
            input.total,
            "draining retained input restores read progress"
        );
    });
}

#[test]
fn line_parked_pieces_and_framer_input_share_one_receive_allowance() {
    worker().block_on(async {
        let input = Arc::new(Input {
            inner: TestDoor::new("input", &["input"], &[], Knobs::default()),
            read: AtomicUsize::new(0),
            written: AtomicUsize::new(0),
            total: 4 * RECEIVE_BUFFER_BYTES,
        });
        let holding = Arc::new(Holding {
            inner: TestDoor::identity("holding"),
            scope: FramingContext::new(7, 0, 0, None).unwrap(),
            auth: Arc::new(AuthHost::default()),
            next: AtomicU32::new(10),
            started: AtomicBool::new(false),
            admitted: AtomicBool::new(false),
            sibling: AtomicBool::new(false),
            split_input: true,
            retained: Mutex::new(Vec::new()),
            timers: AtomicUsize::new(0),
        });
        let carried = crate::carrier::Carried::accepted(
            input.clone(),
            Arc::new(crate::hostio::HostIo::new()),
            1,
            None,
        )
        .unwrap();
        let conn = Connection::accepted(
            Some(holding.clone()),
            carried,
            &Accept {
                tls: None,
                alpn: Vec::new(),
                handshake_timeout: Duration::from_secs(5),
            },
            None,
        )
        .unwrap();
        let line = crate::line::Line::new(conn);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(Ok(Some(piece))) = line.poll_piece(crate::line::EVERY, &mut cx) else {
            panic!("the sibling's pieces remain readable");
        };
        assert_eq!(piece.stream, 3);
        let read = input.read.load(Ordering::SeqCst);
        assert!(
            (RECEIVE_BUFFER_BYTES..RECEIVE_BUFFER_BYTES + READ_CHUNK).contains(&read),
            "parking pieces must not create a second receive allowance: {read}"
        );
        holding.auth.complete(1);
        let mut admitted = false;
        for _ in 0..512 {
            match line.poll_piece(crate::line::EVERY, &mut cx) {
                Poll::Ready(Ok(Some(piece))) => admitted |= piece.stream == 1,
                Poll::Pending => break,
                other => panic!("unexpected line answer: {other:?}"),
            }
        }
        assert!(
            admitted,
            "draining parked pieces permits auth completion and progress"
        );
        assert_eq!(input.read.load(Ordering::SeqCst), input.total);
        assert_eq!(holding.auth.calls(), 1);
    });
}
