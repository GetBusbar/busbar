// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A `tracing::Layer` that records the messages (and other structured fields) of WARN-and-ABOVE
//! events (WARN, ERROR), so a test can assert a particular `tracing::warn!`/`tracing::error!` fired
//! without a global subscriber.
//!
//! Driving idiom (unchanged from the four call sites this replaces):
//! ```ignore
//! use tracing_subscriber::layer::SubscriberExt as _;
//! let cap = WarnCapture::default();
//! let subscriber = tracing_subscriber::registry().with(cap.clone());
//! tracing::subscriber::with_default(subscriber, || { /* code under test */ });
//! assert!(cap.contains("expected substring"));
//! ```
//! `tracing::subscriber::with_default` installs a THREAD-LOCAL subscriber: the code under test
//! must run synchronously on the same thread as the closure (a `new_current_thread` runtime
//! driven with `block_on` INSIDE the closure, never a multi-threaded runtime or an HTTP
//! round-trip), or the capture comes back empty.

#[derive(Clone, Default)]
pub struct WarnCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl WarnCapture {
    /// Every WARN message recorded so far, each as `"{message} {field}={value} ..."`.
    pub fn messages(&self) -> Vec<String> {
        self.0.lock().map(|m| m.clone()).unwrap_or_default()
    }

    /// True when some captured WARN message contains `needle`.
    pub fn contains(&self, needle: &str) -> bool {
        self.messages().iter().any(|m| m.contains(needle))
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() > tracing::Level::WARN {
            // `tracing::Level` orders ERROR < WARN < INFO < ... (lower = more severe), so this
            // admits WARN and ERROR and still excludes INFO/DEBUG/TRACE.
            return;
        }
        // Capture the rendered `message` AND every other field (e.g. a structured `pool`/`hook`
        // name on a diagnostic) so a test can assert on a field value, not just the static
        // message text. Fields are flattened into one `key=value` string per event.
        #[derive(Default)]
        struct Vis {
            message: String,
            fields: String,
        }
        impl Vis {
            fn record(&mut self, field: &tracing::field::Field, rendered: String) {
                if field.name() == "message" {
                    self.message = rendered;
                } else {
                    if !self.fields.is_empty() {
                        self.fields.push(' ');
                    }
                    self.fields
                        .push_str(&format!("{}={}", field.name(), rendered));
                }
            }
        }
        impl tracing::field::Visit for Vis {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.record(field, format!("{value:?}"));
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.record(field, value.to_string());
            }
        }
        let mut vis = Vis::default();
        event.record(&mut vis);
        if let Ok(mut msgs) = self.0.lock() {
            msgs.push(format!("{} {}", vis.message, vis.fields));
        }
    }
}
