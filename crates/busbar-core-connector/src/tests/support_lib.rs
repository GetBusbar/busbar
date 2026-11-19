// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LIB TESTS' VIEW OF THE TEST TRANSPORT ENTRY: everything in `support.rs` (which the
//! integration targets and examples include by path, and which stays free of what only the lib's
//! own tests use) plus the lib-only observers and doubles: the allocation and wipe observers, the
//! builder variants, the auth double and the pending door, and the multiplexing helpers.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Waker;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::transport::{FramePiece, FramerOut, FramerSink};
use busbar_contract::transport::codes::{PIECE_END_OF_FRAME, PIECE_WRITABLE};

// `base` was written against `super::{carrier, compose, framer, hostio}`; these keep those paths.
use super::{carrier, compose, framer, hostio};
use carrier::{Carry, Side};
use framer::{Call, Crossed, DoorFacts, FramerDoor};

#[path = "support.rs"]
mod base;
pub(crate) use base::*;

use base::raw;

#[derive(Clone, Copy, Default)]
struct WipeWatch {
    pointer: usize,
    len: usize,
    second: usize,
    second_len: usize,
    first_result: Option<bool>,
    second_result: Option<bool>,
}

struct YieldedWireWatch {
    pointer: usize,
    initialized: usize,
    wiped: Option<bool>,
}

thread_local! {
    static WIPE_WATCH: std::cell::Cell<WipeWatch> = const { std::cell::Cell::new(WipeWatch {
        pointer: 0, len: 0, second: 0, second_len: 0, first_result: None, second_result: None,
    }) };
    static YIELDED_WIRE_WATCH: std::cell::RefCell<Option<Vec<YieldedWireWatch>>> = const {
        std::cell::RefCell::new(None)
    };
    /// Heap allocations made on this thread (`alloc`; `alloc_zeroed` and `realloc` go through it).
    static ALLOCATIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many heap allocations `run` makes on the calling thread.
pub fn allocations_during<T>(run: impl FnOnce() -> T) -> (T, u64) {
    let before = ALLOCATIONS.with(std::cell::Cell::get);
    let result = run();
    let after = ALLOCATIONS.with(std::cell::Cell::get);
    (result, after.wrapping_sub(before))
}

/// THE RELEASE PROOFS (owner's ruling on allocation, addendum): the bytes the process holds through this
/// allocator now, on every thread. Under nextest each test is its own process, so a test reads its own.
static HELD_BYTES: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

/// Bytes held now (see [`HELD_BYTES`]).
pub fn held_bytes() -> isize {
    HELD_BYTES.load(std::sync::atomic::Ordering::Relaxed)
}

struct ObservingAllocator;

#[global_allocator]
static OBSERVING_ALLOCATOR: ObservingAllocator = ObservingAllocator;

// SAFETY: every allocation is delegated unchanged to System. The observer reads live allocated
// bytes immediately before the matching System deallocation, on the observing test's thread.
unsafe impl std::alloc::GlobalAlloc for ObservingAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get().wrapping_add(1)));
        // SAFETY: the caller supplied GlobalAlloc's layout.
        let pointer = unsafe { std::alloc::GlobalAlloc::alloc(&std::alloc::System, layout) };
        if !pointer.is_null() {
            HELD_BYTES.fetch_add(
                isize::try_from(layout.size()).unwrap_or(isize::MAX),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        let _ = YIELDED_WIRE_WATCH.try_with(|watch| {
            let Ok(mut state) = watch.try_borrow_mut() else {
                return;
            };
            let Some(watched) = state.as_mut() else {
                return;
            };
            for allocation in watched.iter_mut().filter(|allocation| {
                allocation.pointer == pointer as usize && allocation.wiped.is_none()
            }) {
                // SAFETY: the live Yielded owner registered only its initialized prefix. This
                // current allocation pointer remains valid until System deallocates it below.
                allocation.wiped = Some(
                    allocation.initialized <= layout.size()
                        && unsafe { std::slice::from_raw_parts(pointer, allocation.initialized) }
                            .iter()
                            .all(|byte| *byte == 0),
                );
            }
        });
        let _ = WIPE_WATCH.try_with(|watch| {
            let mut state = watch.get();
            if state.pointer == pointer as usize || state.second == pointer as usize {
                let len = if state.pointer == pointer as usize {
                    state.len
                } else {
                    state.second_len
                };
                // SAFETY: the owner supplied this allocation's initialized prefix, and this
                // deallocation pointer still owns the live allocation until System receives it.
                let wiped = len <= layout.size()
                    && unsafe { std::slice::from_raw_parts(pointer, len) }
                        .iter()
                        .all(|byte| *byte == 0);
                if state.pointer == pointer as usize {
                    state.first_result = Some(wiped);
                    state.pointer = 0;
                }
                if state.second == pointer as usize {
                    state.second_result = Some(wiped);
                    state.second = 0;
                    state.second_len = 0;
                }
                watch.set(state);
            }
        });
        HELD_BYTES.fetch_sub(
            isize::try_from(layout.size()).unwrap_or(isize::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        // SAFETY: the caller returned the allocation and original layout to its allocator.
        unsafe { std::alloc::GlobalAlloc::dealloc(&std::alloc::System, pointer, layout) };
    }
}

/// Record the actual live owner, never an allocation selected by size or contents.
pub fn watch_yielded_wire(wire: &[u8]) {
    if wire.is_empty() {
        return;
    }
    YIELDED_WIRE_WATCH.with(|watch| {
        let mut state = watch.borrow_mut();
        let Some(watched) = state.as_mut() else {
            return;
        };
        if let Some(allocation) = watched.iter_mut().find(|allocation| {
            allocation.pointer == wire.as_ptr() as usize && allocation.wiped.is_none()
        }) {
            allocation.initialized = wire.len();
        } else {
            watched.push(YieldedWireWatch {
                pointer: wire.as_ptr() as usize,
                initialized: wire.len(),
                wiped: None,
            });
        }
    });
}

/// Observe all wire allocations through their actual retirement, including MORE growth/merges.
pub fn observe_yielded_wires<T>(run: impl FnOnce() -> T) -> (T, Vec<Option<bool>>) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            YIELDED_WIRE_WATCH.with(|watch| {
                drop(watch.borrow_mut().take());
            });
        }
    }
    YIELDED_WIRE_WATCH.with(|watch| {
        assert!(watch.borrow().is_none(), "nested yielded-wire observation");
        *watch.borrow_mut() = Some(Vec::new());
    });
    let _reset = Reset;
    let result = run();
    let allocations = YIELDED_WIRE_WATCH.with(|watch| watch.borrow_mut().take().unwrap());
    (
        result,
        allocations
            .into_iter()
            .map(|allocation| allocation.wiped)
            .collect(),
    )
}

/// Observe real destruction of an owner's initialized buffer and any explicitly lent encode copy.
pub fn observe_wipe<T>(
    pointer: *const u8,
    len: usize,
    run: impl FnOnce() -> T,
) -> (T, Option<bool>, Option<bool>) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            WIPE_WATCH.with(|watch| watch.set(WipeWatch::default()));
        }
    }
    WIPE_WATCH.with(|watch| {
        watch.set(WipeWatch {
            pointer: pointer as usize,
            len,
            ..WipeWatch::default()
        })
    });
    let _reset = Reset;
    let result = run();
    let state = WIPE_WATCH.with(std::cell::Cell::get);
    (result, state.first_result, state.second_result)
}

/// Arm an existing observation after the fixture initializes the framer's wire scratch.
pub fn watch_scratch(pointer: *const u8, len: usize) {
    WIPE_WATCH.with(|watch| {
        watch.set(WipeWatch {
            pointer: pointer as usize,
            len,
            ..WipeWatch::default()
        })
    });
}

/// The encode owner lends only its initialized output, without inferring ownership from capacity.
pub fn watch_encoded_wire(wire: &[u8]) {
    WIPE_WATCH.with(|watch| {
        let mut state = watch.get();
        if state.pointer != 0 && !wire.is_empty() {
            state.second = wire.as_ptr() as usize;
            state.second_len = wire.len();
            watch.set(state);
        }
    });
}

impl TestDoor {
    /// Use this fixture's host I/O for carrier crossings.
    pub fn with_host_io(mut self, io: Arc<super::hostio::HostIo>) -> Self {
        self.io = Some(io);
        self
    }

    /// The same entry, stating `role` (`ROLE_CARRIER` | `ROLE_FRAMER`).
    #[must_use]
    pub fn with_role(mut self, role: u32) -> Self {
        self.facts.role = role;
        self.facts.ported = role == busbar_contract::transport::codes::ROLE_CARRIER;
        self
    }

    pub fn without_dialing(mut self) -> Self {
        self.facts.dials = false;
        self
    }

    /// The same entry, its claim serving no port (a carrier reached by a path or a program).
    #[must_use]
    pub fn unported(mut self) -> Self {
        self.facts.ported = false;
        self
    }

    /// The same entry, its claim reading a port whatever its role (a framer stating one is still no
    #[must_use]
    pub fn with_port(mut self) -> Self {
        self.facts.ported = true;
        self
    }

    /// How many crossings of `op` there were.
    pub fn count(&self, op: &str) -> usize {
        self.crossings
            .lock()
            .unwrap()
            .iter()
            .filter(|o| **o == op)
            .count()
    }
}

/// THE HOST'S AUTH SERVICE, doubled as the mechanism keeps it: a call runs ONCE per handle
/// `(ticket, seq)` and stores its result; a not-ready call answers NOT_READY and its completion
/// wakes the ticket; a re-issued handle reads the stored result; a NEW op on the ticket forgets the
/// ticket's results (its handles count from 0 again), so only a resume reads them.
#[derive(Default)]
pub struct AuthHost {
    /// `None` = running, `Some` = the stored answer.
    pub stored: Mutex<HashMap<(Ticket, u32), Option<u64>>>,
    /// How many times the auth itself ran.
    pub real_calls: std::sync::atomic::AtomicUsize,
    /// The waker the ticket's holder registered last.
    pub waker: Mutex<Option<Waker>>,
}

impl AuthHost {
    /// A new op starts on `t`: its stored results are forgotten.
    pub fn new_op(&self, t: Ticket) {
        self.stored.lock().unwrap().retain(|(k, _), _| *k != t);
    }

    /// `auth.call` on `(t, seq)`: `Some` = READY with the stored answer, `None` = NOT_READY.
    pub fn call(&self, t: Ticket, seq: u32) -> Option<u64> {
        let mut m = self.stored.lock().unwrap();
        if let Some(r) = m.get(&(t, seq)) {
            return *r;
        }
        self.real_calls.fetch_add(1, Ordering::SeqCst);
        m.insert((t, seq), None);
        None
    }

    /// The auth answers: every running call stores `answer`, and the ticket's wake fires.
    pub fn complete(&self, answer: u64) {
        for v in self.stored.lock().unwrap().values_mut() {
            v.get_or_insert(answer);
        }
        if let Some(w) = self.waker.lock().unwrap().take() {
            w.wake();
        }
    }

    /// How many times the auth itself ran.
    pub fn calls(&self) -> usize {
        self.real_calls.load(Ordering::SeqCst)
    }
}

/// A framing's ticket, its registered waker held by the auth double.
pub struct AuthTicket {
    /// The ticket.
    pub ticket: Ticket,
    /// The auth double whose completions wake it.
    pub host: Arc<AuthHost>,
}

impl Side for AuthTicket {
    fn ticket(&self) -> Ticket {
        self.ticket
    }

    fn register(&self, waker: &Waker) {
        *self.host.waker.lock().unwrap() = Some(waker.clone());
    }
}

/// One `emit` crossing as a [`PendingDoor`] saw it first: its stream, the opening body length it
pub type EmitSeen = (u64, u64, u32);

/// A TICKETED TEST ENTRY WHOSE AUTH MAY PEND: the test entry `inner`, its framings on tickets of
pub struct PendingDoor {
    /// The entry the ops land on.
    pub inner: TestDoor,
    /// The auth double.
    pub host: Arc<AuthHost>,
    /// The stream whose head emit calls the auth.
    pub pend: u64,
    /// The adoption itself waits on the host before installing the framing.
    pub pend_adopt: bool,
    next: AtomicU32,
    taken: Mutex<HashMap<Ticket, Vec<u8>>>,
    /// Every fresh `emit` crossing that carried bytes, in order.
    pub emitted: Mutex<Vec<EmitSeen>>,
    /// Every `begin` crossing's binding (`BeginIn::points`, `BeginIn::auth`), in order.
    pub begun: Mutex<Vec<(u32, busbar_contract::abi::host::service::AuthRef)>>,
    /// The ticket every crossing on a ticket ran on, with whether it was a resume, in order.
    pub on: Mutex<Vec<(&'static str, Ticket, bool)>>,
}

impl PendingDoor {
    /// `inner`, its emits on stream `pend` calling the auth.
    pub fn new(inner: TestDoor, pend: u64) -> Self {
        Self {
            inner,
            host: Arc::new(AuthHost::default()),
            pend,
            pend_adopt: false,
            next: AtomicU32::new(100),
            taken: Mutex::new(HashMap::new()),
            emitted: Mutex::new(Vec::new()),
            begun: Mutex::new(Vec::new()),
            on: Mutex::new(Vec::new()),
        }
    }
}

impl FramerDoor for PendingDoor {
    fn io_owner(&self) -> Option<u64> {
        self.inner.io_owner()
    }
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn seals_values(&self) -> bool {
        self.inner.seals_values()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }

    fn carry(&self, _side: &dyn Side, _resume: bool, _call: Carry<'_>) -> Crossed {
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }

    fn framing_side(&self) -> Option<Box<dyn Side>> {
        Some(Box::new(AuthTicket {
            ticket: Ticket {
                slot: self.next.fetch_add(1, Ordering::SeqCst),
                generation: 1,
            },
            host: Arc::clone(&self.host),
        }))
    }

    fn cross_on(&self, side: &dyn Side, resume: bool, call: Call<'_>) -> Crossed {
        let t = side.ticket();
        let op = match &call {
            Call::Begin(..) => "begin",
            Call::Adopt(..) => "adopt",
            Call::Ingest(..) => "ingest",
            Call::Emit(..) => "emit",
            _ => "other",
        };
        self.on.lock().unwrap().push((op, t, resume));
        match call {
            Call::Begin(i, o) => {
                self.begun.lock().unwrap().push((i.points, i.auth));
                self.inner.cross(Call::Begin(i, o))
            }
            Call::Adopt(i, o) if self.pend_adopt => {
                if !resume {
                    self.host.new_op(t);
                    self.taken
                        .lock()
                        .unwrap()
                        .insert(t, raw(i.leftover, i.leftover_len).to_vec());
                } else {
                    assert_eq!(
                        i.leftover_len, 0,
                        "adopt resumes with no new leftover bytes"
                    );
                }
                if self.host.call(t, 0).is_none() {
                    return Crossed {
                        outcome: Outcome::Pending,
                        error: None,
                    };
                }
                let bytes = self.taken.lock().unwrap().remove(&t).unwrap_or_default();
                i.leftover = bytes.as_ptr();
                i.leftover_len = bytes.len();
                self.inner.cross(Call::Adopt(i, o))
            }
            Call::Emit(i, o) => {
                if !resume && i.len != 0 {
                    self.emitted
                        .lock()
                        .unwrap()
                        .push((i.stream, i.body_len, i.body_len_known));
                }
                if i.stream != self.pend {
                    return self.inner.cross(Call::Emit(i, o));
                }
                if !resume {
                    self.host.new_op(t);
                    self.taken
                        .lock()
                        .unwrap()
                        .insert(t, raw(i.bytes, i.len).to_vec());
                }
                if self.host.call(t, 0).is_none() {
                    return Crossed {
                        outcome: Outcome::Pending,
                        error: None,
                    };
                }
                let bytes = self.taken.lock().unwrap().remove(&t).unwrap_or_default();
                i.bytes = bytes.as_ptr();
                i.len = bytes.len();
                i.end_of_frame = 1;
                self.inner.cross(Call::Emit(i, o))
            }
            other => self.inner.cross(other),
        }
    }
}

/// The host's bytes an op lent (`ptr`, `len`), copied.
pub fn lent(ptr: *const u8, len: usize) -> Vec<u8> {
    raw(ptr, len).to_vec()
}

/// A MULTIPLEXING framer's answer: one piece per byte of `lane_bytes`, on the stream the byte names
pub fn pieces_on_lanes(sink: &FramerSink, o: &mut FramerOut, lane_bytes: &[u8]) {
    for (n, &b) in lane_bytes.iter().enumerate() {
        // SAFETY: the host's buffers; a test's few pieces fit them.
        unsafe {
            sink.frame.add(n).write(b);
            sink.pieces.add(n).write(FramePiece {
                stream: u64::from(b - b'0'),
                offset: n as u64,
                len: 1,
                code: 0,
                status_class: 0,
                flags: PIECE_END_OF_FRAME,
                fault: 0,
                retry_after_secs: 0,
                declared_len: 0,
            });
        }
    }
    o.yielded.frame_len = lane_bytes.len() as u64;
    o.yielded.pieces_len = lane_bytes.len() as u32;
}

pub fn writable_on_lane(sink: &FramerSink, out: &mut FramerOut, stream: u64) {
    // SAFETY: the host's buffers offer room for one zero-length signal piece.
    unsafe {
        sink.pieces.write(FramePiece {
            stream,
            offset: 0,
            len: 0,
            code: 0,
            status_class: 0,
            flags: PIECE_WRITABLE,
            fault: 0,
            retry_after_secs: 0,
            declared_len: 0,
        });
    }
    out.yielded.pieces_len = 1;
}
