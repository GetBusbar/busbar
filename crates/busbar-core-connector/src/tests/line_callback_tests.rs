// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::callback_waker::Probe;

#[test]
fn every_busy_line_poll_owns_raw_wakers_before_taking_state() {
    let line = Arc::new(Line {
        state: Mutex::new(State {
            conn: None,
            closing: false,
            seen: Seen::default(),
            opening: Default::default(),
            refused: Default::default(),
            missed: Vec::new(),
            parked: Default::default(),
            held: Default::default(),
            next: 3,
        }),
        fan: Arc::default(),
        dialled: true,
        users: AtomicUsize::new(1),
        tainted: AtomicBool::new(false),
    });
    let weak = Arc::downgrade(&line);
    let probe = Probe::new(move || {
        weak.upgrade().is_some_and(|line| {
            line.state.try_lock().is_err() || line.fan.waiting.try_lock().is_err()
        })
    });
    let waker = probe.waker();
    let mut cx = Context::from_waker(&waker);
    assert!(line.poll_piece(EXCHANGE_STREAM, &mut cx).is_pending());
    assert!(line.poll_ready(EXCHANGE_STREAM, &mut cx).is_pending());
    assert!(line.poll_landed(EXCHANGE_STREAM, &mut cx).is_pending());
    assert!(matches!(
        line.emit_waking(EXCHANGE_STREAM, b"x", true, false, Some(&waker)),
        Err(Failure::Pending)
    ));
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
    );
    assert!(line
        .upgrade_secure(
            &config,
            "example.com",
            std::time::Duration::from_secs(1),
            false,
            &mut cx
        )
        .is_pending());
    let missed = { std::mem::take(&mut line.state().missed) };
    assert_eq!(
        missed.len(),
        1,
        "all polls for this task retain one wake target"
    );
    wake(missed);
    line.fan.forget(EXCHANGE_STREAM);
    assert!(probe.clones.load(Ordering::SeqCst) >= 5);
    assert_eq!(probe.wakes.load(Ordering::SeqCst), 1);
    assert!(probe.drops.load(Ordering::SeqCst) > 0);
    probe.assert_unlocked();
}
