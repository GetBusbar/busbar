// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::callback_waker::Probe;
use busbar_contract::conn::PollConns;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll, Waker};

fn observed(member: &Arc<super::super::Member>) -> Arc<Probe> {
    let weak = Arc::downgrade(member);
    let driver = std::thread::current().id();
    Probe::new(move || {
        // A reactor callback on another thread may coincide with a legal guarded publication.
        // This witness checks callbacks invoked on the thread actually making that publication.
        std::thread::current().id() == driver
            && weak.upgrade().is_some_and(|member| {
                member.state.try_lock().is_err() || member.fan.wakers.try_lock().is_err()
            })
    })
}

#[test]
fn public_program_reads_replace_and_remove_raw_waiters_after_both_locks() {
    worker().block_on(async {
        let c = connector();
        declare(&c, &[("mute", sh("cat >/dev/null", &[]))]).unwrap();
        let id = open(&c, "mute", b"").unwrap();
        generation(&c, id).await;
        let held = c.slab.get(OWNER, id).unwrap().1;
        let (member, lease) = held.lease.as_ref().unwrap();
        let first = observed(member);
        let second = observed(member);
        let a = first.waker();
        let b = second.waker();
        assert_eq!(member.ready(*lease, &a), Ok(false));
        assert_eq!(member.ready(*lease, &b), Ok(false));
        assert!(c
            .poll_read(OWNER, id, &mut Context::from_waker(&a), &mut [0; 1])
            .is_pending());
        assert!(c
            .poll_read(OWNER, id, &mut Context::from_waker(&b), &mut [0; 1])
            .is_pending());
        assert!(first.clones.load(Ordering::SeqCst) > 0);
        assert!(
            first.drops.load(Ordering::SeqCst) > 0,
            "replacement retires the old registration"
        );
        c.close(OWNER, id).unwrap();
        assert!(
            second.drops.load(Ordering::SeqCst) > 0,
            "close retires the stored registration"
        );
        first.assert_unlocked();
        second.assert_unlocked();
        member.retire();
    });
}

#[test]
fn a_program_connection_return_notifies_the_actual_busy_reader_after_unlocking() {
    worker().block_on(async {
        let c = connector();
        declare(&c, &[("mute", sh("cat >/dev/null", &[]))]).unwrap();
        let id = open(&c, "mute", b"").unwrap();
        generation(&c, id).await;
        let held = c.slab.get(OWNER, id).unwrap().1;
        let (member, _) = held.lease.as_ref().unwrap();
        let probe = observed(member);
        let waker = probe.waker();
        // Hold the connection as a carrier crossing does; the public read must file its waiter.
        let conn = { member.lock().live.as_mut().unwrap().conn.take().unwrap() };
        assert!(c
            .poll_read(OWNER, id, &mut Context::from_waker(&waker), &mut [0; 1])
            .is_pending());
        assert_eq!(member.lock().missed.len(), 1);
        member.lock().live.as_mut().unwrap().conn = Some(conn);
        let before = probe.wakes.load(Ordering::SeqCst);
        // This actual write hands the connection out and back through Member::crossing.
        assert_eq!(c.write(OWNER, id, b"x", false, false), Ok(1));
        assert!(probe.wakes.load(Ordering::SeqCst) > before);
        assert!(member.lock().missed.is_empty());
        probe.assert_unlocked();
        c.close(OWNER, id).unwrap();
        member.retire();
    });
}

#[test]
fn public_program_reads_publish_frames_and_eof_after_unlocking() {
    worker().block_on(async {
        let c = connector();
        declare(&c, &[("once", sh("read l; printf '%s\\n' \"$l\"", &[]))]).unwrap();
        let id = open(&c, "once", b"").unwrap();
        generation(&c, id).await;
        let held = c.slab.get(OWNER, id).unwrap().1;
        let (member, _) = held.lease.as_ref().unwrap();
        let probe = observed(member);
        let waker = probe.waker();
        assert!(c
            .poll_read(OWNER, id, &mut Context::from_waker(&waker), &mut [0; 64])
            .is_pending());
        assert_eq!(c.write(OWNER, id, b"answer\n", false, false), Ok(7));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut body = Vec::new();
        loop {
            let mut buf = [0; 64];
            match c.poll_read(OWNER, id, &mut Context::from_waker(&waker), &mut buf) {
                Poll::Ready(Ok(piece)) if piece.kind == PieceKind::Body => {
                    body.extend_from_slice(&buf[..piece.len])
                }
                Poll::Ready(Ok(piece)) if piece.kind == PieceKind::Completion => break,
                Poll::Ready(Ok(_)) => {}
                Poll::Pending if std::time::Instant::now() < deadline => {
                    tokio::task::yield_now().await
                }
                other => panic!("program did not deliver its body and end: {other:?}"),
            }
        }
        assert_eq!(body, b"answer\n");
        assert!(probe.wakes.load(Ordering::SeqCst) > 0);
        probe.assert_unlocked();
        c.close(OWNER, id).unwrap();
        member.retire();
    });
}

#[test]
fn draining_or_closing_a_backlogged_program_lease_notifies_after_unlocking() {
    worker().block_on(async {
        let c = connector();
        declare(&c, &[("mute", sh("cat >/dev/null", &[]))]).unwrap();
        let first = open(&c, "mute", b"").unwrap();
        let second = open(&c, "mute", b"").unwrap();
        generation(&c, first).await;
        generation(&c, second).await;
        let held = c.slab.get(OWNER, first).unwrap().1;
        let (member, lease) = held.lease.as_ref().unwrap();
        let second_held = c.slab.get(OWNER, second).unwrap().1;
        let second_lease = second_held.lease.as_ref().unwrap().1;
        let probe = observed(member);
        let waker = probe.waker();
        {
            let mut st = member.lock();
            let inbox = st.leases.get_mut(lease).unwrap();
            inbox
                .pieces
                .push_back((vec![b'x'; crate::compose::RECEIVE_BUFFER_BYTES], true));
            inbox.queued = crate::compose::RECEIVE_BUFFER_BYTES;
        }
        assert_eq!(member.ready(second_lease, &waker), Ok(false));
        assert!(c
            .poll_read(OWNER, second, &mut Context::from_waker(&waker), &mut [0; 1])
            .is_pending());
        let before = probe.wakes.load(Ordering::SeqCst);
        assert!(c
            .poll_read(OWNER, first, &mut Context::from_waker(&waker), &mut [0; 1])
            .is_ready());
        assert!(
            probe.wakes.load(Ordering::SeqCst) > before,
            "draining releases the generation cap"
        );
        {
            let mut st = member.lock();
            let inbox = st.leases.get_mut(lease).unwrap();
            inbox.pieces.push_back((vec![b'x'], true));
            inbox.queued += 1;
        }
        assert!(c
            .poll_read(OWNER, second, &mut Context::from_waker(&waker), &mut [0; 1])
            .is_pending());
        let before = probe.wakes.load(Ordering::SeqCst);
        c.close(OWNER, first).unwrap();
        assert!(
            probe.wakes.load(Ordering::SeqCst) > before,
            "closing releases the generation cap"
        );
        probe.assert_unlocked();
        c.close(OWNER, second).unwrap();
        member.retire();
    });
}

#[test]
fn unwinding_a_program_drive_notifies_its_public_reader_after_unlocking() {
    worker().block_on(async {
        let c = connector();
        declare(&c, &[("mute", sh("cat >/dev/null", &[]))]).unwrap();
        let id = open(&c, "mute", b"").unwrap();
        generation(&c, id).await;
        let held = c.slab.get(OWNER, id).unwrap().1;
        let (member, _) = held.lease.as_ref().unwrap();
        let probe = observed(member);
        let waker = probe.waker();
        assert!(c
            .poll_read(OWNER, id, &mut Context::from_waker(&waker), &mut [0; 1])
            .is_pending());
        let missed = Arc::new(Waker::noop().clone());
        let generation = member.lock().generation;
        let before = probe.wakes.load(Ordering::SeqCst);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            member.crossing::<()>(member.lock(), generation, &missed, |_| {
                std::panic::resume_unwind(Box::new("the program drive unwound"))
            });
        }));
        assert!(unwound.is_err());
        assert!(probe.wakes.load(Ordering::SeqCst) > before);
        assert!(matches!(
            c.poll_read(OWNER, id, &mut Context::from_waker(&waker), &mut [0; 1]),
            Poll::Ready(Err(ConnError::Closed))
        ));
        probe.assert_unlocked();
        c.close(OWNER, id).unwrap();
        member.retire();
    });
}
