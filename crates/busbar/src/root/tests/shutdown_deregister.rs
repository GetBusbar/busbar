// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::governance::drain::{ShutdownIntent, ShutdownRequest, DRAIN_TIMEOUT};
use tokio::sync::{broadcast, watch};

struct Lifecycle {
    drain: ShutdownDrain,
    request: ShutdownRequest,
    safety: watch::Sender<bool>,
    workers: watch::Receiver<bool>,
    listeners: broadcast::Receiver<()>,
    refresh_stops: Arc<AtomicU64>,
}

impl Lifecycle {
    fn start(delay: Duration, first: ShutdownIntent, unsafe_before_start: bool) -> Self {
        let drain = ShutdownDrain::new(DrainClock::new(DRAIN_TIMEOUT));
        drain.request_shutdown(first);
        let (safety, safety_rx) = watch::channel(unsafe_before_start);
        let (workers_tx, workers) = watch::channel(false);
        let (listeners_tx, listeners) = broadcast::channel(8);
        let refresh_stops = Arc::new(AtomicU64::new(0));
        let stopped = Arc::clone(&refresh_stops);
        let request = drain.start_deregister_with(
            delay,
            Arc::new(busbar_kernel::endpoints::ProbeState::new(None)),
            ShutdownSignals {
                safety: safety_rx,
                support: safety.clone(),
                workers: workers_tx,
                listeners: listeners_tx,
            },
            move || {
                stopped.fetch_add(1, Ordering::SeqCst);
            },
        );
        Self {
            drain,
            request,
            safety,
            workers,
            listeners,
            refresh_stops,
        }
    }

    fn still_serving(&mut self) {
        assert!(self.drain.clock().armed_at().is_none());
        assert!(!*self.workers.borrow());
        assert!(self.listeners.try_recv().is_err());
        assert_eq!(self.refresh_stops.load(Ordering::SeqCst), 0);
    }

    fn draining(&mut self, at: Instant) {
        assert_eq!(self.drain.clock().armed_at(), Some(at + DRAIN_TIMEOUT));
        assert!(*self.workers.borrow());
        self.listeners
            .try_recv()
            .expect("one shared listener transition");
        assert!(self.listeners.try_recv().is_err());
        assert_eq!(self.refresh_stops.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn operator_delay_is_fixed_and_preserves_the_full_drain_budget() {
    let mut lifecycle = Lifecycle::start(Duration::from_secs(5), ShutdownIntent::Serving, false);
    lifecycle.request.request(ShutdownIntent::Operator);
    tokio::task::yield_now().await;
    let start = Instant::now();
    lifecycle.still_serving();
    tokio::time::advance(Duration::from_secs(4)).await;
    lifecycle.request.request(ShutdownIntent::Operator);
    tokio::task::yield_now().await;
    lifecycle.still_serving();
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    lifecycle.draining(start + Duration::from_secs(5));
    lifecycle.request.request(ShutdownIntent::Operator);
    lifecycle.safety.send_replace(true);
    tokio::task::yield_now().await;
    assert!(lifecycle.listeners.try_recv().is_err());
    assert_eq!(lifecycle.refresh_stops.load(Ordering::SeqCst), 1);
    assert!(!lifecycle.drain.clock().expired());
    lifecycle.request.request(ShutdownIntent::Force);
    tokio::task::yield_now().await;
    assert!(lifecycle.drain.clock().expired());
}

#[tokio::test(start_paused = true)]
async fn safety_and_force_bypass_propagation_even_before_coordinator_publication() {
    for first in [
        ShutdownIntent::Safety,
        ShutdownIntent::Force,
        ShutdownIntent::Serving,
    ] {
        let now = Instant::now();
        let mut lifecycle = Lifecycle::start(
            Duration::from_secs(300),
            first,
            first == ShutdownIntent::Serving,
        );
        tokio::task::yield_now().await;
        lifecycle.draining(now);
        assert_eq!(
            lifecycle.drain.clock().expired(),
            first == ShutdownIntent::Force
        );
        lifecycle.request.request(ShutdownIntent::Operator);
        lifecycle.request.request(ShutdownIntent::Force);
        tokio::task::yield_now().await;
        assert!(lifecycle.drain.clock().expired());
        lifecycle.drain.clock().arm(Instant::now() + DRAIN_TIMEOUT);
        assert!(
            lifecycle.drain.clock().expired(),
            "arming never clears force"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn safety_during_deregistration_keeps_the_full_twenty_seconds() {
    let mut lifecycle = Lifecycle::start(Duration::from_secs(300), ShutdownIntent::Operator, false);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    lifecycle.safety.send_replace(true);
    tokio::task::yield_now().await;
    lifecycle.draining(Instant::now());
    assert!(!lifecycle.drain.clock().expired());
    lifecycle.request.request(ShutdownIntent::Force);
}

#[tokio::test(start_paused = true)]
async fn zero_and_maximum_delays_are_exact_and_force_during_delay_is_sticky() {
    for delay in [Duration::ZERO, Duration::from_secs(300)] {
        let now = Instant::now();
        let mut lifecycle = Lifecycle::start(delay, ShutdownIntent::Operator, false);
        tokio::task::yield_now().await;
        if !delay.is_zero() {
            tokio::time::advance(delay - Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            lifecycle.still_serving();
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
        lifecycle.draining(now + delay);
        lifecycle.request.request(ShutdownIntent::Force);
    }
    let mut lifecycle = Lifecycle::start(Duration::from_secs(5), ShutdownIntent::Operator, false);
    tokio::task::yield_now().await;
    lifecycle.still_serving();
    lifecycle.request.request(ShutdownIntent::Force);
    lifecycle.request.request(ShutdownIntent::Safety);
    lifecycle.request.request(ShutdownIntent::Operator);
    tokio::task::yield_now().await;
    lifecycle.draining(Instant::now());
    assert!(lifecycle.drain.clock().expired());
}

#[test]
fn concurrent_intent_publication_cannot_erase_force() {
    let request = ShutdownRequest::default();
    std::thread::scope(|scope| {
        for level in [
            ShutdownIntent::Operator,
            ShutdownIntent::Safety,
            ShutdownIntent::Force,
        ] {
            let request = &request;
            scope.spawn(move || {
                for _ in 0..100 {
                    request.request(level);
                }
            });
        }
    });
    assert_eq!(*request.subscribe().borrow(), ShutdownIntent::Force);
}

/// The native listener keeps serving while the shutdown intent propagates, stops when the
/// workers signal fires, and a listener started after that signal observes it at once.
#[cfg(unix)]
#[tokio::test]
async fn native_listener_serves_during_propagation_and_a_late_listener_observes_stop() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    crate::tests::native_listener::with_real_server(Some, |server| async move {
        let mut lifecycle =
            Lifecycle::start(Duration::from_secs(30), ShutdownIntent::Serving, false);
        let stop = lifecycle.workers.clone();
        let (address, serving) = server.spawn(busbar_kernel::detached::shutdown_fired(Some(stop)));
        lifecycle.request.request(ShutdownIntent::Operator);
        tokio::task::yield_now().await;
        let mut peer = tokio::net::TcpStream::connect(address).await.unwrap();
        peer.write_all(
            format!(
                "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                busbar_kernel::auth::LIVEZ_PATH
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), peer.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 200") && response.ends_with("ok"),
            "the native listener still serves during propagation: {response}"
        );
        lifecycle.still_serving();
        lifecycle.request.request(ShutdownIntent::Safety);
        tokio::time::timeout(Duration::from_secs(2), serving)
            .await
            .unwrap()
            .unwrap();
        assert!(*lifecycle.workers.borrow());
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
        let (_, late) = server.spawn(busbar_kernel::detached::shutdown_fired(Some(
            lifecycle.workers.clone(),
        )));
        tokio::time::timeout(Duration::from_secs(2), late)
            .await
            .unwrap()
            .unwrap();
        lifecycle.request.request(ShutdownIntent::Force);
    })
    .await
    .expect("the actual declared supplier serves the fixture");
}
