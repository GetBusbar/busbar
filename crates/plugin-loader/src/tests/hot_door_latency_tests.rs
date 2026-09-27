// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOT DOOR'S ADDED LATENCY, MEASURED (#30: the HOT lane's per-request crossing stays under
//! 1 µs). Per request, for the example plane LINKED and DROPPED IN:
//!
//! * `plane` — the plane's own `dispatch` over a work item built once (head, reply channel, the
//!   dispatch's handles current): the plane's work and its six host calls, nothing of the door;
//! * `door` — [`ServedPlane::answer`], the whole door: the work item, the reply channel, the emit
//!   sink, the current-dispatch handles and the reply read back. `door - plane` is the #30 crossing;
//! * `inline` / `hop` — the door driven from a tokio worker, inline on the worker or through
//!   `spawn_blocking` (the thread hop the root's answer took before the plane stated whether its
//!   dispatch blocks). `hop - inline` is what the hop adds.
//!
//! Timing is meaningful only in an optimized build, so the measurement is `#[ignore]`d and run as
//! `cargo test --release -p busbar-plugin-loader --lib hot_door_latency -- --ignored --nocapture`;
//! it asserts the crossing's p50 is under 1µs and prints every figure.

use crate::carrier::{Current, RequestHead};
use busbar_contract::abi::hot::host::{HostCtx, PlaneHostVtable};
use busbar_contract::abi::hot::pod::StatusClass;
use busbar_contract::abi::hot::{EmitHandle, EmitKind, InboundHandle, WorkItem};
use busbar_plugin_example_plane::PLANE_DECL as LINKED;
use std::time::Instant;

/// The conformance suite's host: `EMPTY` plus the six slots the example plane calls, each answering
/// at once (a counter bump), so what is timed is the door and the plane, not a host.
fn instant_host() -> &'static PlaneHostVtable {
    Box::leak(Box::new(super::tests::test_host::vtable()))
}

const WARM: usize = 2_000;
const SAMPLES: usize = 50_000;

/// p50 and p99 of `samples`, in nanoseconds.
fn percentiles(mut samples: Vec<u64>) -> (u64, u64) {
    samples.sort_unstable();
    (
        samples[samples.len() / 2],
        samples[samples.len() * 99 / 100],
    )
}

/// Time `f` once per sample, after a warm-up.
fn timed(mut f: impl FnMut()) -> (u64, u64) {
    for _ in 0..WARM {
        f();
    }
    let samples = (0..SAMPLES)
        .map(|_| {
            let at = Instant::now();
            f();
            at.elapsed().as_nanos() as u64
        })
        .collect();
    percentiles(samples)
}

const HEADERS: [(&[u8], &[u8]); 3] = [
    (b"content-type", b"application/json"),
    (b"accept", b"*/*"),
    (b"user-agent", b"bench"),
];

fn head() -> RequestHead<'static> {
    RequestHead {
        method: b"POST",
        path: b"/example",
        query: b"",
        headers: &HEADERS,
    }
}

/// The figures for one door: `(plane, door, inline, hop)`, each `(p50, p99)` ns.
type Figures = [(u64, u64); 4];

fn measure(plane: &'static crate::DynPlane, host: &'static PlaneHostVtable) -> Figures {
    let served: &'static crate::ServedPlane = Box::leak(Box::new(
        plane
            .serve(
                host,
                br#"{"greeting":"hi"}"#,
                Some("https://gw.example.com"),
            )
            .expect("builds"),
    ));
    let inbound = b"{\"ping\":1}";
    let head = head();

    // The plane alone: one work item, built once, its handles current for every call.
    let mut reply = vec![0u8; crate::MAX_PLANE_REPLY_LEN];
    let mut written = 0usize;
    let mut work = WorkItem::new(
        InboundHandle::finite_buffer(inbound),
        EmitHandle::new(EmitKind::Reply, 1),
    )
    .with_host(host, HostCtx::NULL)
    .with_reply(&mut reply, &mut written);
    work.head = core::ptr::from_ref(&head).cast();
    work.head_read = Some(crate::carrier::head_read);
    let current = Current::enter(work.head, 1);
    let alone = timed(|| {
        // SAFETY: the state `serve` built, and a work item whose borrows outlive the call.
        let class = unsafe { plane.dispatch(served.raw.ptr, &work) };
        assert_eq!(class, StatusClass::Ok);
    });
    drop(current);

    let door = timed(|| {
        let reply = served.answer(host, HostCtx::NULL, Some(&head), inbound, None);
        assert_eq!(reply.class, StatusClass::Ok);
    });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    let run = |hop: bool| -> (u64, u64) {
        rt.block_on(async move {
            let one = || async move {
                let at = Instant::now();
                let class = if hop {
                    tokio::task::spawn_blocking(move || {
                        served
                            .answer(host, HostCtx::NULL, Some(&self::head()), inbound, None)
                            .class
                    })
                    .await
                    .expect("joins")
                } else {
                    served
                        .answer(host, HostCtx::NULL, Some(&self::head()), inbound, None)
                        .class
                };
                assert_eq!(class, StatusClass::Ok);
                at.elapsed().as_nanos() as u64
            };
            for _ in 0..WARM {
                one().await;
            }
            let mut samples = Vec::with_capacity(SAMPLES);
            for _ in 0..SAMPLES {
                samples.push(one().await);
            }
            percentiles(samples)
        })
    };
    let inline = run(false);
    let hop = run(true);
    [alone, door, inline, hop]
}

#[test]
#[ignore = "timing: run in release with --ignored (see the module docs)"]
fn hot_door_latency() {
    let host = instant_host();
    let linked: &'static crate::DynPlane = Box::leak(Box::new(
        crate::link_plane(&LINKED, "linked").expect("links"),
    ));
    let mut rows = vec![("linked", measure(linked, host))];
    if let Some(lib) = super::tests::plane_example_cdylib() {
        let dropped: &'static crate::DynPlane =
            Box::leak(Box::new(crate::load_plane(&lib).expect("loads")));
        rows.push(("dropped", measure(dropped, host)));
    }
    for (door, [plane, answer, inline, hop]) in &rows {
        eprintln!(
            "{door:8} plane p50/p99 {}/{} ns · door {}/{} · crossing (door-plane) {}/{} · \
             inline {}/{} · hop {}/{} · hop added {}/{}",
            plane.0,
            plane.1,
            answer.0,
            answer.1,
            answer.0.saturating_sub(plane.0),
            answer.1.saturating_sub(plane.1),
            inline.0,
            inline.1,
            hop.0,
            hop.1,
            hop.0.saturating_sub(inline.0),
            hop.1.saturating_sub(inline.1),
        );
        assert!(
            answer.0.saturating_sub(plane.0) < 1_000,
            "{door}: the #30 crossing's p50 is {} ns, over 1µs",
            answer.0.saturating_sub(plane.0)
        );
    }
}
