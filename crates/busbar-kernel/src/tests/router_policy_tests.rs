// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The router's layer policies as plain functions (row 192 C), pinned at the seam the router's
//! layers and the accepted path share: the panic boundary, the `Server-Timing` field, the activity
//! tick and the ingress finish.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::*;

/// A future that panics on its first poll.
struct PanicsOnPoll;

impl Future for PanicsOnPoll {
    type Output = u32;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<u32> {
        panic!("a handler panicked on its poll");
    }
}

/// A future that waits once, then answers with the panic-hook depth it was polled at.
struct DepthOnSecondPoll(bool);

impl Future for DepthOnSecondPoll {
    type Output = u32;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u32> {
        if self.0 {
            Poll::Ready(REQUEST_PANIC_DEPTH.with(std::cell::Cell::get))
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// THE PANIC BOUNDARY: a future that finishes answers its output, polled with the depth marker
/// held (one boundary deep) and left at zero after; a panic at the start or at a poll answers its
/// payload, the message whole, and the marker is left at zero.
#[tokio::test]
async fn the_panic_boundary_answers_the_output_or_the_payload() {
    install_request_panic_hook();
    let depth = || REQUEST_PANIC_DEPTH.with(std::cell::Cell::get);
    let answered = catch_request_panic(|| DepthOnSecondPoll(false)).await;
    assert_eq!(
        answered.ok(),
        Some(1),
        "polled one boundary deep, across a wait"
    );
    assert_eq!(depth(), 0);
    let Err(payload) = catch_request_panic(|| PanicsOnPoll).await else {
        panic!("a panic on a poll is caught");
    };
    assert_eq!(
        panic_payload_message(payload.as_ref()),
        "a handler panicked on its poll"
    );
    assert_eq!(depth(), 0);
    let Err(payload) = catch_request_panic(|| -> std::future::Ready<u32> {
        panic!("{}", String::from("a handler panicked at its start"))
    })
    .await
    else {
        panic!("a panic at the start is caught");
    };
    assert_eq!(
        panic_payload_message(payload.as_ref()),
        "a handler panicked at its start"
    );
    assert_eq!(depth(), 0);
}

/// THE `Server-Timing` VALUE: `busbar;dur=` and the gateway's own milliseconds to three places,
/// the upstream round-trip taken off (saturating), the whole time with no upstream.
#[test]
fn the_server_timing_value_is_the_gateways_own_milliseconds() {
    assert_eq!(server_timing_value(1090, 1000), "busbar;dur=0.090");
    assert_eq!(server_timing_value(57, NO_UPSTREAM_RTT), "busbar;dur=0.057");
    assert_eq!(server_timing_value(500, 800), "busbar;dur=0.000");
    assert_eq!(server_timing_value(1_234_567, 0), "busbar;dur=1234.567");
    let (name, value) =
        server_timing_field(std::time::Instant::now(), NO_UPSTREAM_RTT).expect("a field");
    assert_eq!(name.as_str(), HEADER_SERVER_TIMING);
    let value = value.to_str().expect("ascii");
    let ms = value.strip_prefix("busbar;dur=").expect("the busbar entry");
    assert_eq!(ms.split('.').nth(1).map(str::len), Some(3), "{value}");
}

/// ONE TICK per request entered.
#[test]
fn the_activity_tick_is_one_per_request() {
    use std::sync::atomic::Ordering;
    // Other requests may tick beside this one: the tick is at least one, and wraps.
    let before = REQUEST_ACTIVITY_TICKS.load(Ordering::Relaxed);
    request_activity();
    let after = REQUEST_ACTIVITY_TICKS.load(Ordering::Relaxed);
    assert!(after.wrapping_sub(before) >= 1);
}

/// THE INGRESS FINISH: a path no mounted plane labels emits nothing (the fallback plane labels
/// its own requests from its handler).
#[test]
fn the_ingress_finish_passes_over_an_unlabelled_path() {
    let app = crate::test_support::TestApp::new().build();
    assert!(!crate::ingress::observe::finish(
        &app,
        crate::auth::HEALTHZ_PATH,
        200,
        std::time::Duration::from_millis(3),
    ));
}
