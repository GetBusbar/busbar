// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ordinary checks of the production completion-retirement ABI boundary. These
//! do not replace the autonomous DispatcherDrive/answer-lease integration cases.

use super::*;
use crate::dispatch::ticket::WakeRoute;
use crate::dispatch::{completion_retirement, in_head, out_head};
use busbar_contract::abi::mechanism::call::BLOB_OCTETS;
use busbar_contract::abi::mechanism::lifecycle::slot;
use busbar_contract::abi::sdk::completion_retirement::{self as wire, Handle};
use std::sync::atomic::AtomicUsize;

struct Route {
    store: Arc<ServiceStore>,
    wakes: AtomicUsize,
}
impl WakeRoute for Route {
    fn store(&self) -> Option<Arc<ServiceStore>> {
        Some(self.store.clone())
    }
    fn wake(&self, _: Ticket, _: Option<&'static InstanceWake>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

fn completed() -> (Arc<Route>, &'static InstanceWake, Capability) {
    let store = Arc::new(ServiceStore::default());
    let wake = Box::leak(Box::<InstanceWake>::default());
    let ticket = Ticket {
        slot: 31,
        generation: 7,
    };
    store.held.track(ticket);
    let caller = std::ptr::from_ref(wake) as usize;
    let cap = store
        .retirement_input(caller, HostCtx { handle: 9 }, ticket)
        .unwrap();
    store.lock(ticket).get_mut(&ticket).unwrap().entries.insert(
        Issue { caller, seq: 4 },
        (
            Bound { op: 1, req: 3 },
            Entry::Done {
                invocation: 101,
                stored: Stored::ready(1),
                shorts: 0,
                delivered: true,
            },
        ),
    );
    let handle = CompletionHandle {
        ticket,
        seq: 4,
        ..CompletionHandle::ZERO
    };
    assert!(store.held.call(caller, Domain::Host, handle));
    store.held.answered(caller, Domain::Host, handle, false);
    let route = Arc::new(Route {
        store,
        wakes: AtomicUsize::new(0),
    });
    let dynamic: Arc<dyn WakeRoute> = route.clone();
    assert!(wake.route.set(Arc::downgrade(&dynamic)).is_ok());
    (route, wake, cap)
}

fn ack(capability: Capability) -> Acknowledgement {
    Acknowledgement {
        capability,
        handles: vec![Handle {
            domain: Domain::Host,
            seq: 4,
        }],
    }
}

#[test]
fn a_ready_or_pending_ack_retires_the_delivered_result_and_wakes_confirmation() {
    for outcome in [Outcome::Ready, Outcome::Pending] {
        let (route, wake, cap) = completed();
        let mut input = in_head();
        input.ticket = cap.ticket;
        input.host = cap.owner;
        // SAFETY: this stack-owned input remains live until the guard is dropped.
        let loan = unsafe { completion_retirement::prepare(wake, slot::DRIVE, &mut input) }
            .expect("the production input boundary accepts its tracked driver")
            .expect("the actual held result lends its capability");
        let bytes = wire::append_ack(&[], &ack(cap)).unwrap();
        let mut head = out_head();
        head.extensions = Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        // SAFETY: the complete answer bytes remain borrowed through this call.
        assert_eq!(
            unsafe {
                completion_retirement::answer(wake, slot::DRIVE, outcome, &head, Some(&loan))
            },
            Ok(())
        );
        assert_eq!(route.store.held(), 0);
        assert_eq!(route.wakes.load(Ordering::SeqCst), 1);
        let next = route
            .store
            .retirement_input(std::ptr::from_ref(wake) as usize, cap.owner, cap.ticket)
            .unwrap();
        assert_ne!(next.nonce, cap.nonce);
        assert_eq!(next.acknowledged, wire::ack_digest(&ack(cap)).unwrap());
        drop(loan);
        assert_eq!(
            input.extensions.len, 0,
            "input loan restores the original extensions"
        );
    }
}

#[test]
fn rejected_ack_boundaries_preserve_the_original_result_without_waking_confirmation() {
    for case in [
        "failed",
        "refused",
        "fault",
        "owner",
        "nonce",
        "epoch",
        "truncated",
        "format",
        "cancel",
    ] {
        let (route, wake, cap) = completed();
        let mut input = in_head();
        input.ticket = cap.ticket;
        input.host = cap.owner;
        // SAFETY: the initialized host input remains in this scope for its loan.
        let loan = unsafe { completion_retirement::prepare(wake, slot::DRIVE, &mut input) }
            .unwrap()
            .unwrap();
        let mut candidate = cap;
        match case {
            "owner" => candidate.owner.handle += 1,
            "nonce" => candidate.nonce += 1,
            "epoch" => candidate.epoch += 1,
            _ => {}
        }
        let mut bytes = wire::append_ack(&[], &ack(candidate)).unwrap();
        if case == "truncated" {
            bytes.pop();
        }
        let mut head = out_head();
        head.extensions = Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: if case == "format" { 0 } else { BLOB_OCTETS },
            flags: 0,
        };
        let outcome = match case {
            "failed" => Outcome::Failed,
            "refused" => Outcome::Refused,
            "fault" => Outcome::Fault,
            _ => Outcome::Ready,
        };
        let operation = if case == "cancel" {
            slot::CANCEL
        } else {
            slot::DRIVE
        };
        // SAFETY: deliberately invalid wire metadata is backed by live allocated bytes.
        assert_eq!(
            unsafe { completion_retirement::answer(wake, operation, outcome, &head, Some(&loan)) },
            Err(()),
            "{case}"
        );
        assert_eq!(
            route.store.held(),
            1,
            "{case}: rejected ACK cannot consume custody"
        );
        assert_eq!(route.wakes.load(Ordering::SeqCst), 0, "{case}");
    }
}

#[test]
fn an_ack_without_its_lent_driver_capability_cannot_retire_the_result() {
    let (route, wake, cap) = completed();
    let bytes = wire::append_ack(&[], &ack(cap)).unwrap();
    let mut head = out_head();
    head.extensions = Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    // SAFETY: complete wire bytes remain borrowed through the boundary call.
    assert_eq!(
        unsafe { completion_retirement::answer(wake, slot::DRIVE, Outcome::Ready, &head, None) },
        Err(())
    );
    assert_eq!(route.store.held(), 1);
    assert_eq!(route.wakes.load(Ordering::SeqCst), 0);
}
