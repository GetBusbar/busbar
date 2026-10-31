// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::dispatch::auth_handle::{
    AuthCallAsk, AuthDone, AuthRan, HandInAsk, RefusalBytes, RefuseAsk, UnitSecret,
};
use busbar_contract::abi::host::service::UnitRef;
use busbar_contract::abi::transport::guest_policy::Policy;

#[derive(Default)]
struct Host {
    granted: Mutex<HashSet<u64>>,
    ended: Mutex<Vec<u64>>,
    scope: Mutex<Weak<FramingContext>>,
    cancel_on_open: Mutex<Option<Ticket>>,
}

impl AuthHandleHost for Host {
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
        self.granted.lock().unwrap().insert(stream);
        let cancel = self.cancel_on_open.lock().unwrap().take();
        let scope = self.scope.lock().unwrap().upgrade();
        if let (Some(ticket), Some(scope)) = (cancel, scope) {
            scope.operation_finished(ticket, true);
        }
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
        if let Some(scope) = self.scope.lock().unwrap().upgrade() {
            assert!(
                scope.state.try_lock().is_ok(),
                "callback ran under context state guard"
            );
            assert!(
                scope.streams.try_lock().is_ok(),
                "callback ran under stream guard"
            );
        }
        self.granted.lock().unwrap().remove(&stream);
        self.ended.lock().unwrap().push(stream);
    }
    fn framing_ended(&self, _: u64) {}
}

fn ready() -> (Arc<Host>, Arc<FramingContext>) {
    let host = Arc::new(Host::default());
    let erased: Arc<dyn AuthHandleHost> = host.clone();
    let scope = FramingContext::new(7, 71, 0, Some(Arc::downgrade(&erased))).unwrap();
    *host.scope.lock().unwrap() = Arc::downgrade(&scope);
    scope.confirm(21).unwrap();
    (host, scope)
}

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 1,
    }
}
fn open(scope: &FramingContext, ticket: Ticket, stream: u64) {
    scope
        .open_stream(
            ticket,
            Open {
                stream,
                known_generation: 3,
            },
        )
        .unwrap();
}

#[test]
fn only_a_new_host_grant_progresses_its_own_operation_once() {
    let (host, scope) = ready();
    let first = ticket(1);
    let sibling = ticket(2);
    for stream in 0..70 {
        open(&scope, first, stream);
        assert!(!scope.take_control_progress(sibling));
        assert!(scope.take_control_progress(first));
        assert!(!scope.take_control_progress(first));
        open(&scope, first, stream);
        assert!(
            !scope.take_control_progress(first),
            "a cached/repeated loan is not progress"
        );
    }
    assert_eq!(host.granted.lock().unwrap().len(), 70);
    scope.operation_finished(first, false);
    assert!(!scope.take_control_progress(first));
    assert_eq!(
        host.granted.lock().unwrap().len(),
        70,
        "body-waiting streams retain their policy"
    );
}

#[test]
fn cancelling_a_pending_operation_revokes_only_its_unadmitted_streams() {
    let (host, scope) = ready();
    let pending = ticket(1);
    let sibling = ticket(2);
    open(&scope, pending, 5);
    scope.operation_done(pending);
    scope.claim_stream_operation(pending, 5, 3).unwrap();
    open(&scope, sibling, 7);
    scope.admit_stream(7);
    scope.operation_finished(pending, true);
    assert_eq!(*host.ended.lock().unwrap(), [5]);
    assert_eq!(scope.policy_generation(5, false), None);
    assert!(scope.operation_reply(pending).is_none());
    assert!(!scope.take_control_progress(pending));
    assert!(scope
        .open_stream(
            pending,
            Open {
                stream: 9,
                known_generation: 3
            }
        )
        .is_err());
    assert!(scope.claim_stream_operation(pending, 5, 3).is_err());
    scope.operation_finished(sibling, true);
    assert_eq!(
        *host.ended.lock().unwrap(),
        [5],
        "an admitted stream survives emit cancellation"
    );
    assert_eq!(scope.policy_generation(7, false), Some(3));
}

#[test]
fn completed_tickets_do_not_own_body_waiting_streams_but_later_auth_reclaims_them() {
    let (host, scope) = ready();
    let reused = ticket(1);
    let later = ticket(2);
    open(&scope, reused, 5);
    scope.operation_finished(reused, false);
    scope.operation_started(reused);
    open(&scope, reused, 7);
    scope.operation_finished(reused, true);
    assert_eq!(*host.ended.lock().unwrap(), [7]);
    assert_eq!(scope.policy_generation(5, false), Some(3));
    assert!(scope.claim_stream_operation(later, 5, 4).is_err());
    scope.claim_stream_operation(later, 5, 3).unwrap();
    assert!(scope.claim_stream_operation(ticket(3), 5, 3).is_err());
    scope.operation_finished(later, true);
    assert_eq!(*host.ended.lock().unwrap(), [7, 5]);
    scope.operation_started(reused);
    open(&scope, reused, 9);
    assert!(scope.take_control_progress(reused));
}

#[test]
fn cancellation_while_the_host_grants_cannot_resurrect_a_stream_or_progress_receipt() {
    let (host, scope) = ready();
    let operation = ticket(1);
    *host.cancel_on_open.lock().unwrap() = Some(operation);
    assert!(scope
        .open_stream(
            operation,
            Open {
                stream: 5,
                known_generation: 3
            }
        )
        .is_err());
    assert!(host.granted.lock().unwrap().is_empty());
    assert_eq!(*host.ended.lock().unwrap(), [5]);
    assert_eq!(scope.policy_generation(5, false), None);
    assert!(!scope.take_control_progress(operation));
    assert!(scope.operation_reply(operation).is_none());
}
