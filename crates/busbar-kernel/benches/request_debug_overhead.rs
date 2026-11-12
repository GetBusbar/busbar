// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DEBUG LOGGING COST INSTRUMENT: what the forward path's per-request instrumentation costs at
//! each log level, under the console layer boot installs (a `fmt` layer, target off, behind a
//! per-layer `Targets` filter), writing to a sink so only the subscriber's own work is measured.
//!
//! * `off_info_*` — the default (`RUST_LOG` unset): the budget is no measurable difference from
//!   the release before the per-request summary existed.
//! * `on_summary_*` — `RUST_LOG=info,busbar::request=debug`: the one summary event per request.
//! * `on_debug_*` — `RUST_LOG=debug`: the summary plus the request-path spans.
//!
//! `_1` is one attempt; `_2` is a failover and its retry.
//!
//! ```text
//! cargo bench -p busbar-kernel --features test-support --bench request_debug_overhead
//! ```

use std::hint::black_box;
use std::sync::Mutex;

use criterion::{criterion_group, criterion_main, Criterion};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::Layer as _;

fn console(filter: Targets) -> impl tracing::Subscriber + Send + Sync {
    tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::sink)
            .with_target(false)
            .with_filter(filter),
    )
}

fn levels(c: &mut Criterion) {
    let downgraded = Mutex::new(None);
    let live = Mutex::new((3_u64, false));
    let settings = [
        ("off_info", Targets::new().with_default(LevelFilter::INFO)),
        (
            "on_summary",
            Targets::new()
                .with_default(LevelFilter::INFO)
                .with_target("busbar::request", LevelFilter::DEBUG),
        ),
        ("on_debug", Targets::new().with_default(LevelFilter::DEBUG)),
    ];
    for (name, filter) in settings {
        tracing::subscriber::with_default(console(filter), || {
            tracing::callsite::rebuild_interest_cache();
            for attempts in [1_u32, 2] {
                c.bench_function(&format!("{name}_{attempts}"), |b| {
                    b.iter(|| {
                        busbar_kernel::plane_driver::forward_instrumentation(
                            black_box(attempts),
                            black_box(b"gpt-4o"),
                            &downgraded,
                            &live,
                        );
                    });
                });
            }
        });
    }
}

criterion_group!(benches, levels);
criterion_main!(benches);
