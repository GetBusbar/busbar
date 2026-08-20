// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A `tracing::Layer` that records the messages (and other structured fields) of WARN-and-ABOVE
//! events (WARN, ERROR) by default, so a test can assert a particular `diag_warn!`/`diag_error!`
//! fired without a global subscriber. [`WarnCapture::capturing_debug`] lowers the threshold to
//! DEBUG for a diagnostic that was reclassified benign and now emits at `diag_debug!`.
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

#[derive(Clone)]
pub struct WarnCapture {
    messages: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// The least-severe level admitted. `WARN` (the default) captures WARN+ERROR; `DEBUG` captures
    /// DEBUG-and-above — used by tests of a diagnostic that was reclassified benign and now emits at
    /// `diag_debug!`, so the log-content coverage is preserved rather than deleted.
    max_level: tracing::Level,
}

impl Default for WarnCapture {
    fn default() -> Self {
        Self {
            messages: std::sync::Arc::default(),
            max_level: tracing::Level::WARN,
        }
    }
}

impl WarnCapture {
    /// A capture that admits DEBUG-and-above (DEBUG, INFO, WARN, ERROR), for asserting on a
    /// benign-recurring diagnostic that emits at `diag_debug!`.
    pub fn capturing_debug() -> Self {
        Self {
            messages: std::sync::Arc::default(),
            max_level: tracing::Level::DEBUG,
        }
    }

    /// Every captured message recorded so far, each as `"{message} {field}={value} ..."`.
    pub fn messages(&self) -> Vec<String> {
        self.messages.lock().map(|m| m.clone()).unwrap_or_default()
    }

    /// True when some captured WARN message contains `needle`.
    pub fn contains(&self, needle: &str) -> bool {
        self.messages().iter().any(|m| m.contains(needle))
    }

    /// How many captured WARN/ERROR messages contain `needle`. The regression guard for the
    /// log-spam class: a warn-once latch or a per-tick aggregation asserts this stays at 1 across
    /// repeated ticks / many keys, where the unguarded code would have produced N.
    pub fn count(&self, needle: &str) -> usize {
        self.messages()
            .iter()
            .filter(|m| m.contains(needle))
            .count()
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() > self.max_level {
            // `tracing::Level` orders ERROR < WARN < INFO < ... (lower = more severe), so a WARN
            // threshold admits WARN+ERROR and excludes INFO/DEBUG/TRACE; a DEBUG threshold admits
            // everything down to DEBUG.
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
        if let Ok(mut msgs) = self.messages.lock() {
            msgs.push(format!("{} {}", vis.message, vis.fields));
        }
    }
}
