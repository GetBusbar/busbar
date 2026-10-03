// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tracing` capture the moved store-adapter tests assert silence with, carried from
//! `busbar-plugin-loader`'s `src/tests/abi2_store_ops_tests.rs` (where it stays for its own tests).

use std::sync::{Arc, Mutex};

/// Every `tracing` event that fired on this thread while a subscriber built from this was
/// installed, rendered as `LEVEL message field=value ...`.
#[derive(Clone, Default)]
pub(super) struct EventLog(Arc<Mutex<Vec<String>>>);

impl EventLog {
    pub(super) fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl tracing::Subscriber for EventLog {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Render(String);
        impl tracing::field::Visit for Render {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={:?}", field.name(), value));
            }
        }
        let mut r = Render(format!("{}", event.metadata().level()));
        event.record(&mut r);
        self.0.lock().unwrap_or_else(|p| p.into_inner()).push(r.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}
