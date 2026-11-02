// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An association that ends while an incremental producer has it out must resolve every waiter

use super::*;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use super::super::{Answered, PortAssociations};

#[derive(Default)]
struct Woken(AtomicUsize);

impl Wake for Woken {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn counting() -> (Arc<Woken>, Waker) {
    let woken = Arc::new(Woken::default());
    let waker = Waker::from(Arc::clone(&woken));
    (woken, waker)
}

fn woken(w: &Woken) -> usize {
    w.0.load(Ordering::SeqCst)
}

/// A port with association `a` (a framer that fails its first clear-lane datagram when

fn port_with(fail_clear: bool) -> (Arc<PortAssociations>, Arc<Scripted>, u64, u64) {
    let da = scripted(Knobs {
        fail_clear,
        ..Knobs::default()
    });
    let db = scripted_as(Knobs::default(), (B_UFRAG, B_PWD));
    let port = Arc::new(PortAssociations::new());
    let a = port.add(settled(da.clone())).unwrap();
    let b = port.add(settled(db)).unwrap();
    let none = |_: SocketAddr, _: &[u8]| {};
    let answered = port.datagram(
        p("203.0.113.2:2000"),
        &check(B_UFRAG, FAR_UFRAG, B_PWD, 2),
        Instant::now(),
        &none,
    );
    assert!(matches!(answered.as_slice(), [(id, Ok(_))] if *id == b));
    (port, da, a, b)
}

/// Hold association `a` out in a framer crossing on its own thread: its incremental producer

fn produce(
    port: &Arc<PortAssociations>,
    door: &Scripted,
) -> (
    std::thread::JoinHandle<Answered>,
    std::sync::mpsc::Sender<()>,
) {
    let (entered, release) = park(door, Parks::Ingest);
    let producer = {
        let port = Arc::clone(port);
        std::thread::spawn(move || {
            let none = |_: SocketAddr, _: &[u8]| {};
            port.datagram_incremental(
                p("203.0.113.1:1000"),
                &check(HOST_UFRAG, FAR_UFRAG, HOST_PWD, 1),
                Instant::now(),
                &none,
            )
        })
    };
    entered
        .recv_timeout(Duration::from_secs(5))
        .expect("the producer is parked in its crossing");
    (producer, release)
}

#[test]
fn a_failed_incremental_producer_closes_and_wakes_its_parked_waiters_and_spares_the_sibling() {
    let (port, door, a, b) = port_with(true);
    let none = |_: SocketAddr, _: &[u8]| {};
    let now = Instant::now();
    let (producer, release) = produce(&port, &door);

    let (first_woke, first_waker) = counting();
    let (queued_woke, queued_waker) = counting();
    let (line_woke, line_waker) = counting();
    let mut first = Box::pin(port.emission_ready(a));
    assert!(first
        .as_mut()
        .poll(&mut Context::from_waker(&first_waker))
        .is_pending());
    let mut queued = Box::pin(port.emission_ready(a));
    assert!(queued
        .as_mut()
        .poll(&mut Context::from_waker(&queued_waker))
        .is_pending());
    assert!(port
        .poll_line(
            a,
            &mut Context::from_waker(&line_waker),
            None,
            false,
            now,
            &none
        )
        .is_pending());
    assert_eq!(
        (woken(&first_woke), woken(&queued_woke), woken(&line_woke)),
        (0, 0, 0),
        "nothing resolved while the producer is still crossing"
    );

    release.send(()).unwrap();
    let answered = producer.join().unwrap();
    assert!(matches!(answered.as_slice(), [(id, Err(_))] if *id == a));

    assert!(woken(&first_woke) > 0, "emission_ready waiter was woken");
    assert!(woken(&queued_woke) > 0, "order-queued waiter was woken");
    assert!(woken(&line_woke) > 0, "poll_line waiter was woken");
    assert!(matches!(
        first.as_mut().poll(&mut Context::from_waker(&first_waker)),
        Poll::Ready(None)
    ));
    assert!(matches!(
        queued
            .as_mut()
            .poll(&mut Context::from_waker(&queued_waker)),
        Poll::Ready(None)
    ));
    assert!(matches!(
        port.poll_line(
            a,
            &mut Context::from_waker(&line_waker),
            None,
            false,
            now,
            &none
        ),
        Poll::Ready(Err(_))
    ));
    port.remove(a);
    assert!(
        !port.emit(a, 1, b"late", true, false, now, &none).0,
        "the failed association takes no more writes"
    );

    assert_eq!(port.len(), 1);
    assert!(port.emit(b, 1, b"m", true, false, now, &none).0);
    let mut sibling = Box::pin(port.emission_ready(b));
    let (_, sibling_waker) = counting();
    assert!(matches!(
        sibling
            .as_mut()
            .poll(&mut Context::from_waker(&sibling_waker)),
        Poll::Ready(Some(_))
    ));
}

#[test]
fn an_association_removed_during_its_incremental_producer_resolves_its_waiters_and_spares_the_sibling(
) {
    let (port, door, a, b) = port_with(false);
    let none = |_: SocketAddr, _: &[u8]| {};
    let now = Instant::now();
    let (producer, release) = produce(&port, &door);

    let (ready_woke, ready_waker) = counting();
    let (line_woke, line_waker) = counting();
    let mut ready = Box::pin(port.emission_ready(a));
    assert!(ready
        .as_mut()
        .poll(&mut Context::from_waker(&ready_waker))
        .is_pending());
    assert!(port
        .poll_line(
            a,
            &mut Context::from_waker(&line_waker),
            None,
            false,
            now,
            &none
        )
        .is_pending());

    port.remove(a);
    assert!(woken(&ready_woke) > 0 && woken(&line_woke) > 0);
    assert!(matches!(
        ready.as_mut().poll(&mut Context::from_waker(&ready_waker)),
        Poll::Ready(None)
    ));
    assert!(matches!(
        port.poll_line(
            a,
            &mut Context::from_waker(&line_waker),
            None,
            false,
            now,
            &none
        ),
        Poll::Ready(Err(_))
    ));

    release.send(()).unwrap();
    let answered = producer.join().unwrap();
    assert!(matches!(answered.as_slice(), [(id, _)] if *id == a));
    assert_eq!(port.len(), 1, "only the sibling remains");
    assert!(port.emit(b, 1, b"m", true, false, now, &none).0);
}
