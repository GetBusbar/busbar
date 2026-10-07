// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RELEASE TIMING GATE ON THE DOOR (ignored by default; the release engine's
//! `test:timing-gate-release` step runs it explicitly in release mode: `cargo test -p busbar
//! --release --locked timing_gate -- --ignored`). A warm-up and then a measured batch through the
//! door serving the `pools` map (the data router, the kernel's walk, a real loopback far end that
//! answers at once), gated at the previous engine's DELIBERATELY GENEROUS bounds: the real added
//! overhead is microseconds, so the gate trips only on a gross hot-path regression (sync I/O, a
//! sleep, a whole-body walk on the request path), never on runner noise. Fine-grained overhead
//! numbers stay the external latency bench's job.

use super::hook_seat_tests::{far_end_answering, rig, RigOpts};
use super::planes_tests::{Published as Withdrawn, PUBLISHING as ONE_PUBLISHER};

/// An openai chat completion, answered at once.
const SERVED: &str = r#"{"id":"chatcmpl-1","object":"chat.completion","created":0,"model":"m0","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

/// The hot path's p50 and p99 full-request latency stay under the gate's bounds (25 ms, 250 ms)
/// over 500 measured requests after 100 warm-up ones, every one of them a 200.
///
/// Ports legacy `engine/tests/ingress_integration_tests.rs::timing_gate_hot_path_p50_p99`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "timing gate: run explicitly (release engine: cargo test --release -- --ignored timing_gate)"]
async fn timing_gate_hot_path_p50_p99() {
    const WARMUP: usize = 100;
    const MEASURED: usize = 500;
    const P50_MAX_MS: u128 = 25;
    const P99_MAX_MS: u128 = 250;

    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-timing-gate";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;

    let mut samples: Vec<u128> = Vec::with_capacity(MEASURED);
    for i in 0..(WARMUP + MEASURED) {
        let start = std::time::Instant::now();
        let (status, _, _) = rig.chat().await;
        assert_eq!(
            status, 200,
            "request {i} failed: the gate measures 200s only"
        );
        if i >= WARMUP {
            samples.push(start.elapsed().as_millis());
        }
    }
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2];
    let p99 = samples[samples.len() * 99 / 100];
    assert!(
        p50 <= P50_MAX_MS,
        "hot-path p50 {p50}ms exceeded the {P50_MAX_MS}ms gate: a gross regression (the real \
         overhead is microseconds; check for sync I/O or sleeps on the request path)"
    );
    assert!(
        p99 <= P99_MAX_MS,
        "hot-path p99 {p99}ms exceeded the {P99_MAX_MS}ms gate: a gross regression"
    );
    assert_eq!(
        far.served(),
        WARMUP + MEASURED,
        "every request reached the far end"
    );
}
