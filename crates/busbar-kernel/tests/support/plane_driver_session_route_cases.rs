// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-R4: a session states its route once. The kernel copies a far-bound frame's
//! verb, target and fields only until the session has dialed; after that only the frame's body
//! and text reach the far end, and "the plane emitted far-bound" decides whether a frame is
//! written. Counted by the dev-only stage probes (`busbar_contract::stage_probe`).

use super::session_input_cases::{drive, OwnedCaller};
use super::*;
use busbar_contract::stage_probe::{Derive, Scope};
use busbar_kernel::plane_driver::SessionInput;

const FRAMES: usize = 100;

fn frame(bytes: Vec<u8>) -> SessionInput {
    SessionInput {
        bytes,
        custody: None,
    }
}

/// Poll the session on this thread (where the scope is current) until `far` has `n` writes.
async fn written(running: &mut Pin<Box<impl Future>>, far: &cases::Far, n: usize) {
    for _ in 0..(n * 64 + 64) {
        std::future::poll_fn(|cx| {
            assert!(running.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        if far.written().len() >= n {
            return;
        }
    }
    panic!("the session wrote {} of {n} frames", far.written().len());
}

#[tokio::test]
async fn session_route_stated_once() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    r.plane.sessions.server_first.store(true, Ordering::SeqCst);
    r.plane.sessions.restates.store(true, Ordering::SeqCst);
    let (send, receive) = tokio::sync::mpsc::unbounded_channel();
    let caller = OwnedCaller(tokio::sync::Mutex::new(receive));
    let (steps, far) = (
        common::TestUnits::passing(),
        cases::Far::held(&["fixture-lane"]),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);

    let scope = Scope::open();
    let mut running = Box::pin(drive(&units));
    for k in 0..FRAMES {
        assert!(send.send(frame(format!("piece:{k}").into_bytes())).is_ok());
    }
    written(&mut running, &far, FRAMES).await;

    let sent = far.sent();
    assert_eq!(sent.len(), 1, "one dial for the whole session");
    assert_eq!(sent[0].verb, b"GET");
    assert_eq!(sent[0].target, b"/open");
    let expected: Vec<_> = (0..FRAMES)
        .map(|k| (format!("piece:{k}").into_bytes(), true))
        .collect();
    assert_eq!(
        far.written(),
        expected,
        "every frame's body is written, in order"
    );
    assert_eq!(
        scope.count(Derive::SessionRoute),
        1,
        "the route is copied for the dial only, never for a frame of the dialed session"
    );
    drop(send);
    assert_eq!(running.await, busbar_contract::caps::Outcome::Completed);
}

#[tokio::test]
async fn a_dialed_session_writes_an_empty_frame_that_states_no_route() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    r.plane.sessions.server_first.store(true, Ordering::SeqCst);
    let (send, receive) = tokio::sync::mpsc::unbounded_channel();
    let caller = OwnedCaller(tokio::sync::Mutex::new(receive));
    let (steps, far) = (
        common::TestUnits::passing(),
        cases::Far::held(&["fixture-lane"]),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/session", b""), 0);
    let mut running = Box::pin(drive(&units));
    assert!(send.send(frame(Vec::new())).is_ok());
    assert!(send.send(frame(b"piece:1".to_vec())).is_ok());
    written(&mut running, &far, 2).await;

    assert_eq!(far.sent().len(), 1, "one dial for the whole session");
    assert_eq!(
        far.written(),
        vec![(Vec::new(), true), (b"piece:1".to_vec(), true)],
        "a far-bound empty binary frame of a dialed session is written, not dropped"
    );
    drop(send);
    assert_eq!(running.await, busbar_contract::caps::Outcome::Completed);
}
