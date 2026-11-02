// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::transport::{
    FramePiece, FrameSpan, FramerOut, FramerSink, HeadSlots, PIECE_END, PIECE_END_OF_FRAME,
    PIECE_FIELDS, PIECE_HAS_CODE, ROLE_FRAMER, STATUS_SUCCESS, YIELD_ENDED, YIELD_MORE,
};
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};

pub const SESSION_ACCEPT_WIRE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\n\r\n";
pub const SESSION_REFUSE_WIRE: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\ncontent-length: 12\r\n\r\nstage denied";
const SESSION_FINISH_WIRE: &[u8] = b"SESSION-CLOSE";

#[derive(Default)]
struct Gate {
    released: AtomicBool,
    wake: Mutex<Option<std::task::Waker>>,
}

struct Side {
    ticket: Ticket,
    gate: Arc<Gate>,
}

impl busbar_core_connector::carrier::Side for Side {
    fn ticket(&self) -> Ticket {
        self.ticket
    }

    fn register(&self, waker: &std::task::Waker) {
        let next = waker.clone();
        let retired = { self.gate.wake.lock().unwrap().replace(next) };
        drop(retired);
    }
}

/// Owned response data retained for inspection, never a pointer into a crossing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Emitted {
    pub stream: u64,
    pub status: u32,
    pub bytes: Vec<u8>,
    pub end: bool,
}

pub struct Mux {
    facts: DoorFacts,
    session: bool,
    refuse_adopt: bool,
    pending_adopt: bool,
    pending_adopt_refused: bool,
    pending_commit: bool,
    adoption_released: AtomicBool,
    commit_released: AtomicBool,
    commit_active: AtomicBool,
    adoption_ticket: Mutex<Option<Ticket>>,
    commit_ticket: Mutex<Option<Ticket>>,
    adoption_entered: tokio::sync::Notify,
    commit_entered: tokio::sync::Notify,
    commit_done: tokio::sync::Notify,
    adoption_resumes: AtomicU32,
    commit_attempts: AtomicU32,
    cancellations: AtomicU32,
    message_attempts: AtomicU32,
    message_done: tokio::sync::Notify,
    response_started: AtomicBool,
    response_done: tokio::sync::Notify,
    responses: Mutex<Vec<Emitted>>,
    finishes: AtomicU32,
    accepted_head_pending: AtomicBool,
    committed_heads: AtomicU32,
    gate: Arc<Gate>,
    entered: tokio::sync::Notify,
    second_done: tokio::sync::Notify,
    held: Mutex<Option<Emitted>>,
    emitted: Mutex<Vec<Emitted>>,
    next: AtomicU32,
}

impl Default for Mux {
    fn default() -> Self {
        Self {
            session: false,
            refuse_adopt: false,
            pending_adopt: false,
            pending_adopt_refused: false,
            pending_commit: false,
            adoption_released: AtomicBool::new(false),
            commit_released: AtomicBool::new(false),
            commit_active: AtomicBool::new(false),
            adoption_ticket: Mutex::new(None),
            commit_ticket: Mutex::new(None),
            adoption_entered: tokio::sync::Notify::new(),
            commit_entered: tokio::sync::Notify::new(),
            commit_done: tokio::sync::Notify::new(),
            adoption_resumes: AtomicU32::new(0),
            commit_attempts: AtomicU32::new(0),
            cancellations: AtomicU32::new(0),
            message_attempts: AtomicU32::new(0),
            message_done: tokio::sync::Notify::new(),
            response_started: AtomicBool::new(false),
            response_done: tokio::sync::Notify::new(),
            responses: Mutex::new(Vec::new()),
            finishes: AtomicU32::new(0),
            accepted_head_pending: AtomicBool::new(false),
            committed_heads: AtomicU32::new(0),
            facts: DoorFacts {
                name: "test-pending-mux".into(),
                claims: vec!["http"],
                role: ROLE_FRAMER,
                composes_over: Vec::new(),
                ported: false,
                status_rows: Vec::new(),
                duplex: Vec::new(),
                datagram: false,
            },
            gate: Arc::new(Gate::default()),
            entered: tokio::sync::Notify::new(),
            second_done: tokio::sync::Notify::new(),
            held: Mutex::new(None),
            emitted: Mutex::new(Vec::new()),
            next: AtomicU32::new(1),
        }
    }
}

impl Mux {
    pub fn with_session() -> Self {
        let mut fixture = Self {
            session: true,
            ..Self::default()
        };
        fixture.facts.claims.push("ws");
        fixture
    }

    pub fn with_refused_session() -> Self {
        Self {
            refuse_adopt: true,
            ..Self::with_session()
        }
    }

    pub fn with_pending_adoption(refused: bool) -> Self {
        Self {
            pending_adopt: true,
            pending_adopt_refused: refused,
            ..Self::with_session()
        }
    }

    pub fn with_pending_commit() -> Self {
        Self {
            pending_commit: true,
            ..Self::with_session()
        }
    }

    pub async fn wait_for_adoption_pending(&self) {
        self.adoption_entered.notified().await;
    }
    pub async fn wait_for_commit_pending(&self) {
        self.commit_entered.notified().await;
    }
    pub async fn wait_for_commit(&self) {
        self.commit_done.notified().await;
    }

    pub fn release_adoption(&self) {
        self.adoption_released.store(true, Ordering::SeqCst);
        self.wake();
    }
    pub fn release_commit(&self) {
        self.commit_released.store(true, Ordering::SeqCst);
        self.wake();
    }
    pub fn adopted_resumes(&self) -> u32 {
        self.adoption_resumes.load(Ordering::SeqCst)
    }
    pub fn commit_attempts(&self) -> u32 {
        self.commit_attempts.load(Ordering::SeqCst)
    }
    pub fn cancellations(&self) -> u32 {
        self.cancellations.load(Ordering::SeqCst)
    }

    pub fn message_attempts(&self) -> u32 {
        self.message_attempts.load(Ordering::SeqCst)
    }
    pub async fn wait_for_message(&self) {
        self.message_done.notified().await;
    }

    pub fn responses(&self) -> Vec<Emitted> {
        self.responses.lock().unwrap().clone()
    }

    pub fn session_finishes(&self) -> u32 {
        self.finishes.load(Ordering::SeqCst)
    }

    pub async fn wait_for_response_end(&self) {
        self.response_done.notified().await;
    }

    pub async fn wait_for_head(&self) {
        self.entered.notified().await;
    }

    pub async fn wait_for_second(&self) {
        self.second_done.notified().await;
    }

    pub fn release(&self) {
        self.gate.released.store(true, Ordering::SeqCst);
        self.wake();
    }

    fn wake(&self) {
        let wake = { self.gate.wake.lock().unwrap().take() };
        if let Some(wake) = wake {
            wake.wake();
        }
    }

    pub fn committed_heads(&self) -> u32 {
        self.committed_heads.load(Ordering::SeqCst)
    }

    pub fn emitted(&self) -> Vec<Emitted> {
        self.emitted.lock().unwrap().clone()
    }
}

fn copied(ptr: *const u8, len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    // SAFETY: the crossing lends `len` bytes for this call. Only the owned copy survives it.
    unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
}

fn request(stream: u64, sink: &FramerSink, out: &mut FramerOut) {
    let path: &[u8] = if stream == 1 { b"/first" } else { b"/second" };
    assert!(sink.frame_cap >= 3 + path.len() && sink.heads_cap >= 1 && sink.pieces_cap >= 1);
    // SAFETY: the three sink buffers have been checked above; only this crossing uses them.
    unsafe {
        std::ptr::copy_nonoverlapping(b"GET".as_ptr(), sink.frame, 3);
        std::ptr::copy_nonoverlapping(path.as_ptr(), sink.frame.add(3), path.len());
        sink.heads.write(HeadSlots {
            stream,
            method: FrameSpan { offset: 0, len: 3 },
            target: FrameSpan {
                offset: 3,
                len: path.len() as u64,
            },
            ..HeadSlots::default()
        });
        sink.pieces.write(FramePiece {
            stream,
            flags: PIECE_FIELDS | PIECE_END_OF_FRAME | PIECE_END,
            ..FramePiece::default()
        });
    }
    out.yielded.frame_len = (3 + path.len()) as u64;
    out.yielded.heads_len = 1;
    out.yielded.pieces_len = 1;
}

fn wire(bytes: &[u8], sink: &FramerSink, out: &mut FramerOut) {
    if bytes.is_empty() {
        return;
    }
    assert!(
        sink.wire_cap >= bytes.len(),
        "the fixture response fits the bounded host wire loan"
    );
    // SAFETY: the exclusively loaned wire buffer covers the bounded bytes above.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), sink.wire, bytes.len()) };
    out.yielded.wire_len = bytes.len() as u64;
}

/// Adoption reports either typed session acceptance or its complete refused wire response.
/// Accepted bytes remain provisional until the actor commits the plane's result.
fn stage_head(sink: &FramerSink, out: &mut FramerOut, refused: bool) -> bool {
    let bytes = if refused {
        SESSION_REFUSE_WIRE
    } else {
        SESSION_ACCEPT_WIRE
    };
    if sink.wire_cap < bytes.len() || (!refused && sink.pieces_cap == 0) {
        out.yielded.flags = YIELD_MORE;
        return false;
    }
    wire(bytes, sink, out);
    if refused {
        out.yielded.flags = YIELD_ENDED;
        return true;
    }
    // SAFETY: the piece array has room for one entry, exclusively loaned for this crossing.
    unsafe {
        sink.pieces.write(FramePiece {
            stream: 1,
            code: 101,
            status_class: STATUS_SUCCESS,
            flags: PIECE_FIELDS | PIECE_END_OF_FRAME | PIECE_HAS_CODE,
            ..FramePiece::default()
        });
    }
    out.yielded.pieces_len = 1;
    true
}

impl FramerDoor for Mux {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }
    fn accepts(&self) -> bool {
        true
    }
    fn instance(&self) -> Option<u64> {
        Some(0x5eee)
    }

    fn framing_side(&self) -> Option<Box<dyn busbar_core_connector::carrier::Side>> {
        Some(Box::new(Side {
            ticket: Ticket {
                slot: self.next.fetch_add(1, Ordering::SeqCst),
                generation: 1,
            },
            gate: Arc::clone(&self.gate),
        }))
    }

    fn carry(
        &self,
        side: &dyn busbar_core_connector::carrier::Side,
        _: bool,
        call: busbar_core_connector::carrier::Carry<'_>,
    ) -> Crossed {
        match call {
            busbar_core_connector::carrier::Carry::Cancel(input, out) => {
                assert_eq!(
                    input.ticket,
                    side.ticket(),
                    "cancel retains its parked operation ticket"
                );
                self.cancellations.fetch_add(1, Ordering::SeqCst);
                out.disposition = busbar_contract::abi::mechanism::lifecycle::cancel::ABORTED;
                Crossed {
                    outcome: Outcome::Ready,
                    error: None,
                }
            }
            _ => Crossed {
                outcome: Outcome::Refused,
                error: Some(b"not this fixture's carrier op".to_vec()),
            },
        }
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        self.cross_on(
            &Side {
                ticket: Ticket {
                    slot: 0,
                    generation: 1,
                },
                gate: Arc::clone(&self.gate),
            },
            false,
            call,
        )
    }

    fn cross_on(
        &self,
        side: &dyn busbar_core_connector::carrier::Side,
        resume: bool,
        call: Call<'_>,
    ) -> Crossed {
        let ready = Crossed {
            outcome: Outcome::Ready,
            error: None,
        };
        match call {
            Call::Begin(_, out) => out.framing = 1,
            Call::Ingest(input, out) => {
                if self.session
                    && input.framing == 2
                    && self.accepted_head_pending.load(Ordering::SeqCst)
                {
                    if stage_head(&input.sink, out, self.refuse_adopt) {
                        self.accepted_head_pending.store(false, Ordering::SeqCst);
                    }
                    return ready;
                }
                let bytes = copied(input.bytes, input.len);
                assert!(bytes.len() <= 1, "send one stream opener at a time");
                if let Some(&byte) = bytes.first() {
                    assert!(byte == b'1' || byte == b'3');
                    request(u64::from(byte - b'0'), &input.sink, out);
                }
            }
            Call::Emit(input, out) => {
                if self.session
                    && input.status == 101
                    && input.len == 0
                    && (input.end_of_frame != 0
                        || (resume && self.commit_active.load(Ordering::SeqCst)))
                {
                    if resume {
                        assert_eq!(
                            *self.commit_ticket.lock().unwrap(),
                            Some(side.ticket()),
                            "commit resumes on its original ticket"
                        );
                    } else {
                        *self.commit_ticket.lock().unwrap() = Some(side.ticket());
                    }
                    if !resume {
                        self.commit_attempts.fetch_add(1, Ordering::SeqCst);
                    }
                    if self.pending_commit && !self.commit_released.load(Ordering::SeqCst) {
                        self.commit_active.store(true, Ordering::SeqCst);
                        if !resume {
                            self.commit_entered.notify_one();
                        }
                        return Crossed {
                            outcome: Outcome::Pending,
                            error: None,
                        };
                    }
                    self.commit_active.store(false, Ordering::SeqCst);
                    self.committed_heads.fetch_add(1, Ordering::SeqCst);
                    self.commit_done.notify_one();
                    return ready;
                }
                if self.session
                    && (input.status >= 200 || self.response_started.load(Ordering::SeqCst))
                {
                    self.response_started.store(true, Ordering::SeqCst);
                    let value = Emitted {
                        stream: input.stream,
                        status: input.status,
                        bytes: copied(input.bytes, input.len),
                        end: input.end_of_frame != 0,
                    };
                    wire(&value.bytes, &input.sink, out);
                    let done = value.end;
                    self.responses.lock().unwrap().push(value);
                    if done {
                        self.response_done.notify_one();
                    }
                    return ready;
                }
                if !resume {
                    self.message_attempts.fetch_add(1, Ordering::SeqCst);
                }
                let value = if resume {
                    if !self.gate.released.load(Ordering::SeqCst) {
                        return Crossed {
                            outcome: Outcome::Pending,
                            error: None,
                        };
                    }
                    self.held
                        .lock()
                        .unwrap()
                        .take()
                        .expect("owned pending head")
                } else {
                    let value = Emitted {
                        stream: input.stream,
                        status: input.status,
                        bytes: copied(input.bytes, input.len),
                        end: input.end_of_frame != 0,
                    };
                    if input.stream == 1
                        && ((self.session
                            && input.framing == 2
                            && !self.gate.released.load(Ordering::SeqCst))
                            || (!self.session && input.status != 0))
                    {
                        *self.held.lock().unwrap() = Some(value);
                        self.entered.notify_one();
                        return Crossed {
                            outcome: Outcome::Pending,
                            error: None,
                        };
                    }
                    value
                };
                let second_done = value.stream == 3 && value.status == 0 && value.end;
                self.emitted.lock().unwrap().push(value);
                self.message_done.notify_one();
                if second_done {
                    self.second_done.notify_one();
                }
            }
            Call::Detach(_, _) if self.session => {}
            Call::Adopt(input, out) if self.session => {
                if resume {
                    self.adoption_resumes.fetch_add(1, Ordering::SeqCst);
                }
                if self.pending_adopt {
                    if resume {
                        assert_eq!(
                            *self.adoption_ticket.lock().unwrap(),
                            Some(side.ticket()),
                            "adoption resumes on its original ticket"
                        );
                    } else {
                        *self.adoption_ticket.lock().unwrap() = Some(side.ticket());
                    }
                    if !self.adoption_released.load(Ordering::SeqCst) {
                        if !resume {
                            self.adoption_entered.notify_one();
                        }
                        return Crossed {
                            outcome: Outcome::Pending,
                            error: None,
                        };
                    }
                    if self.pending_adopt_refused {
                        return Crossed {
                            outcome: Outcome::Refused,
                            error: Some(b"the pending session adoption refused".to_vec()),
                        };
                    }
                }
                out.framing = 2;
                self.accepted_head_pending.store(
                    !stage_head(&input.sink, out, self.refuse_adopt),
                    Ordering::SeqCst,
                );
            }
            Call::Finish(input, out) if self.session && input.framing == 2 => {
                self.finishes.fetch_add(1, Ordering::SeqCst);
                wire(SESSION_FINISH_WIRE, &input.sink, out);
                out.yielded.flags = YIELD_ENDED;
            }
            Call::Locate(_, _) | Call::Timer(_, _) | Call::Refuse(_, _) | Call::Finish(_, _) => {}
            Call::Encode(_, _) | Call::Detach(_, _) | Call::Adopt(_, _) => {
                return Crossed {
                    outcome: Outcome::Refused,
                    error: Some(b"not this fixture's".to_vec()),
                }
            }
        }
        ready
    }
}

#[cfg(test)]
mod waker_tests {
    use super::*;
    use busbar_core_connector::carrier::Side as _;
    use std::task::{Wake, Waker};
    struct Reentrant(Arc<Gate>);
    impl Wake for Reentrant {
        fn wake(self: Arc<Self>) {
            assert!(self.0.wake.try_lock().is_ok());
        }
    }
    impl Drop for Reentrant {
        fn drop(&mut self) {
            assert!(self.0.wake.try_lock().is_ok());
        }
    }
    #[test]
    fn replacement_and_release_retire_after_unlocking() {
        let fixture = Mux::default();
        let gate = Arc::clone(&fixture.gate);
        let side = Side {
            ticket: busbar_contract::abi::mechanism::ticket::Ticket::NONE,
            gate: Arc::clone(&gate),
        };
        let old = Waker::from(Arc::new(Reentrant(Arc::clone(&gate))));
        side.register(&old);
        drop(old);
        let next = Waker::from(Arc::new(Reentrant(Arc::clone(&gate))));
        side.register(&next);
        drop(next);
        fixture.release();
    }
}
