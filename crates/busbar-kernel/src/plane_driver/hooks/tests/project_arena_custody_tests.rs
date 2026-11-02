// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::cell::RefCell;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::task::{Context, Poll, Waker};

use super::ProjectBufs;

const PAYLOAD: &[u8] = b"private-project-arena-payload";

struct Payload {
    address: usize,
    initialized: usize,
    observed: bool,
    wiped: bool,
}

#[derive(Default)]
struct Scope {
    active: bool,
    payloads: Vec<Payload>,
}

thread_local! {
    static SCOPE: RefCell<Scope> = RefCell::new(Scope::default());
}

pub(super) struct ObservedArena {
    bytes: Vec<u8>,
    registration: Option<usize>,
}

impl From<Vec<u8>> for ObservedArena {
    fn from(bytes: Vec<u8>) -> Self {
        let registration = SCOPE.with(|scope| {
            let mut scope = scope.borrow_mut();
            if !scope.active {
                return None;
            }
            let index = scope.payloads.len();
            scope.payloads.push(Payload {
                address: bytes.as_ptr() as usize,
                initialized: bytes.len(),
                observed: false,
                wiped: false,
            });
            Some(index)
        });
        Self {
            bytes,
            registration,
        }
    }
}

impl Deref for ObservedArena {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.bytes
    }
}

impl DerefMut for ObservedArena {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }
}

impl zeroize::Zeroize for ObservedArena {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(self.bytes.as_mut_slice());
    }
}

impl Drop for ObservedArena {
    fn drop(&mut self) {
        let Some(index) = self.registration else {
            return;
        };
        let _ = SCOPE.try_with(|scope| {
            let Ok(mut scope) = scope.try_borrow_mut() else {
                return;
            };
            if !scope.active {
                return;
            }
            let Some(payload) = scope.payloads.get_mut(index) else {
                return;
            };
            payload.observed = true;
            payload.wiped = payload.address == self.bytes.as_ptr() as usize
                && payload.initialized <= self.bytes.len()
                && self.bytes[..payload.initialized]
                    .iter()
                    .all(|byte| *byte == 0);
        });
    }
}

struct Probe;

impl Probe {
    fn start() -> Self {
        SCOPE.with(|scope| {
            let mut scope = scope.borrow_mut();
            assert!(!scope.active);
            *scope = Scope {
                active: true,
                ..Default::default()
            };
        });
        Self
    }

    fn counts(&self) -> (usize, usize, usize) {
        SCOPE.with(|scope| {
            let scope = scope.borrow();
            (
                scope.payloads.len(),
                scope
                    .payloads
                    .iter()
                    .filter(|payload| payload.observed)
                    .count(),
                scope
                    .payloads
                    .iter()
                    .filter(|payload| payload.wiped)
                    .count(),
            )
        })
    }

    fn finish(self) {
        let (registered, observed, wiped) = self.counts();
        assert!(registered != 0);
        assert_eq!(
            observed, registered,
            "every registered owner must be released"
        );
        assert_eq!(wiped, registered, "an initialized arena was freed unwiped");
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        SCOPE.with(|scope| *scope.borrow_mut() = Scope::default());
    }
}

fn buffers() -> ProjectBufs {
    ProjectBufs {
        signals: Vec::new(),
        messages: Vec::new(),
        arena: PAYLOAD.to_vec().into(),
    }
}

fn returned(_buffers: ProjectBufs, fail: bool) -> Result<(), ()> {
    if fail {
        Err(())
    } else {
        Ok(())
    }
}

#[test]
fn the_passive_owner_distinguishes_unwiped_and_zeroizing_destruction() {
    let probe = Probe::start();
    let plain = ObservedArena::from(PAYLOAD.to_vec());
    drop(plain);
    assert_eq!(probe.counts(), (1, 1, 0), "the observer itself never wipes");
    drop(probe);

    let probe = Probe::start();
    let held = zeroize::Zeroizing::new(ObservedArena::from(PAYLOAD.to_vec()));
    drop(held);
    probe.finish();
}

#[test]
fn project_buffers_wipe_their_initialized_arena_on_success_error_cancel_and_drop() {
    for exit in [
        "success",
        "error",
        "cancel",
        "drop",
        "replace",
        "transfer",
        "overwrite",
    ] {
        let probe = Probe::start();
        let mut buffers = buffers();
        assert_eq!(probe.counts(), (1, 0, 0));
        match exit {
            "cancel" => {
                let mut pending = Box::pin(async move {
                    let buffers = buffers;
                    std::future::pending::<()>().await;
                    drop(buffers);
                });
                assert_eq!(
                    pending
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Pending
                );
                assert_eq!(probe.counts(), (1, 0, 0));
                drop(pending);
            }
            "drop" => drop(buffers),
            "replace" => {
                buffers.arena = PAYLOAD.to_vec().into();
                assert_eq!(probe.counts(), (2, 1, 1));
                assert_eq!(&buffers.arena[..], PAYLOAD);
                drop(buffers);
                assert_eq!(probe.counts(), (2, 2, 2));
            }
            "transfer" => {
                let final_owner = buffers;
                assert_eq!(probe.counts(), (1, 0, 0));
                drop(final_owner);
            }
            "overwrite" => {
                buffers.arena[..].fill(b'x');
                drop(buffers);
            }
            _ => assert_eq!(returned(buffers, exit == "error").is_err(), exit == "error"),
        }
        probe.finish();
    }
}

#[test]
fn short_growth_wipes_the_retired_arena_and_preserves_its_prefix() {
    let probe = Probe::start();
    let mut buffers = buffers();
    let original = buffers.arena.as_ptr();
    buffers.arena.grow(PAYLOAD.len());
    buffers.arena.grow(PAYLOAD.len() - 1);
    assert_eq!(buffers.arena.as_ptr(), original);
    assert_eq!(probe.counts(), (1, 0, 0));
    let needed = PAYLOAD.len() * 2;
    buffers.arena.grow(needed);
    assert_ne!(buffers.arena.as_ptr(), original);
    assert_eq!(
        probe.counts(),
        (2, 1, 1),
        "the old SHORT allocation was wiped"
    );
    assert_eq!(buffers.arena.len(), needed);
    assert_eq!(&buffers.arena[..PAYLOAD.len()], PAYLOAD);
    assert!(buffers.arena[PAYLOAD.len()..].iter().all(|byte| *byte == 0));
    drop(buffers);
    assert_eq!(probe.counts(), (2, 2, 2));
    probe.finish();
}
