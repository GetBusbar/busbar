// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/hook.rs`.
//!
//! OWNER 2026-10-03 (NO TEST PLUGINS): the `DlopenPolicy` drives over the deleted
//! `busbar-hook-test-plugin` cdylib are gone with it (QUESTIONS CONF-SUITE-DEL); what stays is the
//! host-side half no plugin is needed for.

/// **RED, KEPT: the level a cold plugin is told is the HOST's, not the process's.** A door plugin's
/// call capture registers a dispatcher that keeps every level, and it lives as long as its thread.
/// `LevelFilter::current()` is the maximum over every registered dispatcher, so while any capture
/// lived (a door plugin on another worker, or a sibling test in parallel) it read TRACE, and a cold
/// plugin was told to send its debug and trace records to a host set to WARN. This holds a capture
/// alive on another thread, deterministically, and asks for the level under a WARN host.
#[test]
fn a_live_door_capture_does_not_raise_the_level_a_cold_plugin_is_told() {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let _capture = busbar_contract::abi::sdk::capture::CaptureSlot::new();
        ready_tx.send(()).expect("the test waits");
        let _ = done_rx.recv();
    });
    ready_rx.recv().expect("the capture is alive");
    struct Warn;
    impl tracing::Subscriber for Warn {
        fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
            *m.level() <= tracing::Level::WARN
        }
        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::WARN)
        }
        fn new_span(&self, _a: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _s: &tracing::span::Id, _v: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _s: &tracing::span::Id, _f: &tracing::span::Id) {}
        fn event(&self, _e: &tracing::Event<'_>) {}
        fn enter(&self, _s: &tracing::span::Id) {}
        fn exit(&self, _s: &tracing::span::Id) {}
    }
    let told = tracing::subscriber::with_default(Warn, crate::hostlog::host_max_level);
    done_tx.send(()).expect("the holder waits");
    holder.join().expect("the holder ends");
    assert_eq!(
        told,
        busbar_contract::abi::cold::log_level::WARN,
        "a WARN host must tell a cold plugin WARN, whatever other dispatcher is alive"
    );
}
