// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::host::service::UnitRef;
use busbar_contract::abi::transport::guest_policy::{Open, Policy};
use busbar_contract::framing_scope::FramingScope;
use busbar_plugin_loader::dispatch::auth_handle::{
    AuthCallAsk, AuthDone, AuthHandleHost, AuthRan, HandInAsk, RefusalBytes, RefuseAsk,
    StreamPolicy, UnitSecret,
};
use busbar_plugin_loader::dispatch::framing_context::FramingContext;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

#[derive(Default)]
struct LoanHost {
    live: Mutex<HashSet<u64>>,
}

impl AuthHandleHost for LoanHost {
    fn unit_secret(&self, _: u64, _: u64) -> Option<UnitSecret> {
        None
    }
    fn auth_call(&self, _: AuthCallAsk, _: AuthDone) -> AuthRan {
        panic!("unexpected auth")
    }
    fn hand_in(&self, _: HandInAsk) -> Result<(u32, UnitRef), &'static str> {
        Err("unexpected hand-in")
    }
    fn refuse(&self, _: RefuseAsk) -> Result<RefusalBytes, &'static str> {
        Err("unexpected refusal")
    }
    fn stream_open(
        &self,
        _: u64,
        listener: u64,
        _: u64,
        stream: u64,
    ) -> Result<StreamPolicy, &'static str> {
        self.live.lock().unwrap().insert(stream);
        Ok(StreamPolicy {
            policy: Arc::new(Policy {
                listener,
                generation: 3,
                lines: Vec::new(),
            }),
            full: Arc::from(b"full".as_slice()),
            current: Arc::from(b"current".as_slice()),
        })
    }
    fn stream_ended(&self, _: u64, _: u64, stream: u64) {
        self.live.lock().unwrap().remove(&stream);
    }
    fn framing_ended(&self, _: u64) {
        self.live.lock().unwrap().clear();
    }
}

#[derive(Clone, Copy)]
enum Loans {
    Distinct,
    Repeated,
    Sibling,
    None,
}

/// A real loader policy context with no head/body output, just trusted stream grants.
struct LoanDoor {
    inner: TestDoor,
    host: Arc<LoanHost>,
    scope: Arc<FramingContext>,
    calls: AtomicUsize,
    loans: Loans,
    pending_at: Option<usize>,
    malformed_at: Option<usize>,
    limit: usize,
    scratch_until: usize,
    pending_after: Option<usize>,
    timer: bool,
    cancels: AtomicUsize,
}

impl LoanDoor {
    fn new(loans: Loans, pending_at: Option<usize>, malformed_at: Option<usize>) -> Arc<Self> {
        let host = Arc::new(LoanHost::default());
        let erased: Arc<dyn AuthHandleHost> = host.clone();
        let scope = FramingContext::new(7, 71, 0, Some(Arc::downgrade(&erased))).unwrap();
        Arc::new(Self {
            inner: TestDoor::identity("t"),
            host,
            scope,
            loans,
            pending_at,
            malformed_at,
            calls: AtomicUsize::new(0),
            limit: 70,
            scratch_until: 0,
            pending_after: None,
            timer: false,
            cancels: AtomicUsize::new(0),
        })
    }

    fn begin(self: &Arc<Self>) -> Framing {
        Framing::begin_ticketed(
            self.clone(),
            SIDE_ACCEPT,
            "t",
            &Established::plain_for_test(),
            &[],
        )
        .unwrap()
        .0
    }

    #[allow(unsafe_code)]
    fn answer(&self, operation: Ticket, sink: FramerSink, out: &mut FramerOut) -> Crossed {
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        if index == self.limit {
            return Crossed {
                outcome: Outcome::Ready,
                error: None,
            };
        }
        let ticket = if matches!(self.loans, Loans::Sibling) {
            Ticket {
                slot: 99,
                generation: 1,
            }
        } else {
            operation
        };
        if !matches!(self.loans, Loans::None) {
            let stream = if matches!(self.loans, Loans::Repeated) {
                5
            } else {
                index as u64
            };
            self.scope
                .open_stream(
                    ticket,
                    Open {
                        stream,
                        known_generation: 3,
                    },
                )
                .unwrap();
        }
        out.yielded.flags = YIELD_MORE;
        if index < self.scratch_until {
            // SAFETY: the fixture initializes precisely the host's lent frame buffer.
            unsafe {
                std::ptr::write_bytes(sink.frame, b'x', sink.frame_cap);
            }
            out.yielded.frame_len = sink.frame_cap as u64;
        }
        if self.malformed_at == Some(index) {
            out.yielded.frame_len = u64::MAX;
        }
        Crossed {
            outcome: if self.pending_at == Some(index)
                || self.pending_after.is_some_and(|at| index >= at)
            {
                Outcome::Pending
            } else {
                Outcome::Ready
            },
            error: None,
        }
    }
}

impl FramerDoor for LoanDoor {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn carry(
        &self,
        side: &dyn crate::carrier::Side,
        _: bool,
        call: crate::carrier::Carry<'_>,
    ) -> Crossed {
        let crate::carrier::Carry::Cancel(input, _) = call else {
            panic!("the framer only carries cancellation");
        };
        assert_eq!(input.ticket, side.ticket());
        self.cancels.fetch_add(1, Ordering::SeqCst);
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }
    fn framing_context(&self, _: u64, _: u64) -> Result<Option<Arc<dyn FramingScope>>, Refused> {
        Ok(Some(self.scope.clone()))
    }
    fn framing_side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        Some(Box::new(AuthTicket {
            ticket: Ticket {
                slot: 7,
                generation: 1,
            },
            host: Arc::new(AuthHost::default()),
        }))
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Begin(_, out) => out.framing = 21,
            Call::Timer(input, out) if self.timer => {
                return self.answer(Ticket::NONE, input.sink, out)
            }
            _ => {}
        }
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }
    fn cross_on(&self, side: &dyn crate::carrier::Side, _: bool, call: Call<'_>) -> Crossed {
        let Call::Ingest(input, out) = call else {
            return self.cross(call);
        };
        self.answer(side.ticket(), input.sink, out)
    }
}

#[test]
fn seventy_distinct_body_waiting_stream_loans_are_control_progress_without_output() {
    for pending_at in [None, Some(32)] {
        let door = LoanDoor::new(Loans::Distinct, pending_at, None);
        let mut framing = door.begin();
        let output = framing.ingest(b"seventy incomplete heads", false).unwrap();
        assert_eq!(output, Yielded::default());
        if pending_at.is_some() {
            assert!(framing.parked());
            assert!(matches!(
                framing.poll_parked(&mut noop_cx()),
                std::task::Poll::Ready(Ok(_))
            ));
        }
        assert_eq!(door.host.live.lock().unwrap().len(), 70);
        assert_eq!(door.calls.load(Ordering::SeqCst), 71);
    }
}

#[test]
fn repeated_loans_sibling_progress_and_plain_more_still_hit_the_same_stall_limit() {
    for loans in [Loans::Repeated, Loans::Sibling, Loans::None] {
        let door = LoanDoor::new(loans, None, None);
        let mut framing = door.begin();
        let error = framing.ingest(b"heads", false).unwrap_err();
        assert_eq!(error.outcome, Outcome::Fault);
        assert!(door.calls.load(Ordering::SeqCst) < 71);
    }
}

#[test]
fn pending_cannot_reset_an_operations_existing_no_progress_stalls() {
    let door = LoanDoor::new(Loans::None, Some(32), None);
    let mut framing = door.begin();
    framing.ingest(b"heads", false).unwrap();
    assert!(framing.parked());
    assert!(matches!(
        framing.poll_parked(&mut noop_cx()),
        std::task::Poll::Ready(Err(_))
    ));
}

#[test]
fn a_pending_cancel_or_invalid_output_revokes_the_operations_unpublished_loans() {
    let door = LoanDoor::new(Loans::Distinct, Some(2), None);
    let mut framing = door.begin();
    framing.ingest(b"heads", false).unwrap();
    assert!(framing.parked());
    assert_eq!(door.host.live.lock().unwrap().len(), 3);
    framing.cancel_parked();
    assert!(door.host.live.lock().unwrap().is_empty());

    let door = LoanDoor::new(Loans::Distinct, None, Some(2));
    let mut framing = door.begin();
    assert!(framing.ingest(b"heads", false).is_err());
    assert!(door.host.live.lock().unwrap().is_empty());
}

#[test]
fn control_only_more_and_pending_progress_share_the_operations_existing_byte_budget() {
    use std::mem::size_of;
    // Spend most of the existing budget on initialized scratch, then grant streams with no
    // payload at all. The remaining grants exceed the byte budget without a new numeric cap.
    let prefix = MORE_BYTES as usize / FRAME_CAP - 1;
    let limit = prefix + FRAME_CAP / size_of::<Open>() + MORE_STALLS;
    for (timer, pending) in [(false, false), (true, false), (false, true)] {
        let mut door = LoanDoor::new(Loans::Distinct, None, None);
        let configured = Arc::get_mut(&mut door).unwrap();
        configured.limit = limit;
        configured.scratch_until = prefix;
        configured.timer = timer;
        configured.pending_after = pending.then_some(prefix);
        let mut framing = door.begin();
        let result = if timer {
            framing.timer()
        } else {
            framing.ingest(b"heads", false)
        };
        let error = if pending {
            assert!(result.is_ok());
            let mut failure = None;
            for _ in prefix..=limit {
                match framing.poll_parked(&mut noop_cx()) {
                    std::task::Poll::Ready(Err(error)) => {
                        failure = Some(error);
                        break;
                    }
                    std::task::Poll::Ready(Ok(_)) => break,
                    std::task::Poll::Pending => {}
                }
            }
            failure.expect("new control progress while Pending must consume the same budget")
        } else {
            result.expect_err("control-only MORE must consume the same budget")
        };
        assert_eq!(error.outcome, Outcome::Fault);
        assert!(door.calls.load(Ordering::SeqCst) <= limit);
        assert_eq!(door.cancels.load(Ordering::SeqCst), usize::from(pending));
        assert!(
            door.host.live.lock().unwrap().is_empty(),
            "failed operations revoke their unpublished grants"
        );
    }
}
