// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DEBUG LOGGING SWITCH, end to end through a real subscriber: the console filter boot
//! installs (`RUST_LOG`), the per-request `request finished` summary, and what each setting lets
//! through. One process, one global subscriber, one test: `tracing` caches callsite interest
//! process-wide, so these assertions run alone and switch the filter through a reload handle,
//! exactly as a filter change rebuilds interest in a live process.

use std::sync::{Arc, Mutex};

use busbar_kernel::observability::console_filter;
use busbar_kernel::observability::request::{
    enabled, finished, AttemptNote, Summary, Trail, TARGET,
};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::Layer as _;

/// One recorded field: its name, how the subscriber was handed it, and its rendering.
type Recorded = (&'static str, &'static str, String);

/// One delivered event: its target and its fields.
type Delivered = (String, Vec<Recorded>);

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<Delivered>>>);

impl Events {
    fn take(&self) -> Vec<Delivered> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

struct Kinds<'a>(&'a mut Vec<Recorded>);

impl tracing::field::Visit for Kinds<'_> {
    fn record_u64(&mut self, f: &tracing::field::Field, v: u64) {
        self.0.push((f.name(), "u64", v.to_string()));
    }
    fn record_bool(&mut self, f: &tracing::field::Field, v: bool) {
        self.0.push((f.name(), "bool", v.to_string()));
    }
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        self.0.push((f.name(), "str", v.to_string()));
    }
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        self.0.push((f.name(), "fmt", format!("{v:?}")));
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Events {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut fields = Vec::new();
        event.record(&mut Kinds(&mut fields));
        self.0
            .lock()
            .unwrap()
            .push((event.metadata().target().to_string(), fields));
    }
}

/// A `Display` that counts its renderings: proof a field is never formatted while off.
struct Counted(Arc<std::sync::atomic::AtomicUsize>);

impl std::fmt::Display for Counted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        f.write_str("counted")
    }
}

fn note(lane: &str, provider: &str, status: u32, us: u64, outcome: &'static str) -> AttemptNote {
    AttemptNote {
        lane: lane.into(),
        provider: provider.into(),
        status,
        elapsed_us: us,
        outcome,
        failover: None,
    }
}

fn two_attempts() -> Vec<AttemptNote> {
    vec![
        AttemptNote {
            failover: Some("rate_limited"),
            ..note("openai-east", "openai", 429, 112_400, "retry")
        },
        note("claude", "anthropic", 200, 840_000, "complete"),
    ]
}

fn summary(attempts: &[AttemptNote]) -> Summary<'_> {
    Summary {
        request_id: Some(0x51f3),
        unit_id: 42,
        plane: "llm",
        ingress: Some("openai"),
        op: Some("chat"),
        requested: Some("gpt-4o"),
        pool: Some("gpt-4o"),
        key_id: Some("vk_0a1b"),
        governance: "admitted",
        lane: Some("claude"),
        provider: Some("anthropic"),
        outcome: "completed",
        walk: Some("done"),
        status: 200,
        attempts,
        latency_us: 958_123,
        ..Summary::default()
    }
}

fn get<'f>(fields: &'f [Recorded], name: &str) -> Option<(&'static str, &'f str)> {
    fields
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, kind, v)| (*kind, v.as_str()))
}

#[test]
fn the_request_summary_is_free_when_off_and_complete_when_on() {
    let events = Events::default();
    let (filter, handle) =
        tracing_subscriber::reload::Layer::new(console_filter(None).expect("the default"));
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(events.clone().with_filter(filter)),
    )
    .expect("this test owns the process's subscriber");
    let set = |rust_log: Option<&str>| {
        handle
            .reload(console_filter(rust_log).expect("a valid filter"))
            .expect("the filter reloads");
    };

    // OFF (unset RUST_LOG): nothing started, nothing computed, nothing delivered.
    let renders = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    assert!(!enabled(), "the summary is off at the default level");
    assert!(
        Trail::start().is_none(),
        "no trail: no allocation and no clock read"
    );
    finished(&summary(&two_attempts()));
    tracing::debug!(
        target: "busbar::request",
        probe = %Counted(Arc::clone(&renders)),
        "off"
    );
    assert!(
        events.take().is_empty(),
        "nothing reaches the console when off"
    );
    assert_eq!(
        renders.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a disabled field is never formatted"
    );
    // The default level is unchanged: info still reaches the console.
    tracing::info!(target: "busbar::proxy::engine", "kept");
    assert_eq!(events.take().len(), 1);

    // ON: a bare level, the busbar prefix, or the summary's target alone.
    for rust_log in ["debug", "busbar=debug", "warn,busbar::request=debug"] {
        set(Some(rust_log));
        assert!(enabled(), "RUST_LOG={rust_log} enables the summary");
        assert!(Trail::start().is_some());
    }
    set(Some("debug,busbar::request=info"));
    assert!(!enabled(), "the summary can be turned off alone");

    // Every field, each a native value.
    set(Some("busbar::request=debug"));
    let attempts = two_attempts();
    finished(&summary(&attempts));
    let delivered = events.take();
    assert_eq!(delivered.len(), 1, "one summary per request");
    let (target, fields) = &delivered[0];
    assert_eq!(target, TARGET);
    for (name, want) in [
        ("message", ("fmt", "request finished")),
        ("request_id", ("u64", "20979")),
        ("unit_id", ("u64", "42")),
        ("plane", ("str", "llm")),
        ("ingress", ("str", "openai")),
        ("op", ("str", "chat")),
        ("requested", ("str", "gpt-4o")),
        ("pool", ("str", "gpt-4o")),
        ("key_id", ("str", "vk_0a1b")),
        ("governance", ("str", "admitted")),
        ("lane", ("str", "claude")),
        ("provider", ("str", "anthropic")),
        ("attempts", ("u64", "2")),
        (
            "tried",
            (
                "fmt",
                "openai-east(openai) 429 112ms retry:rate_limited, claude(anthropic) 200 840ms \
                 complete",
            ),
        ),
        ("walk", ("str", "done")),
        ("outcome", ("str", "completed")),
        ("status", ("u64", "200")),
        ("streamed", ("bool", "false")),
        ("cut", ("bool", "false")),
        ("latency_ms", ("u64", "958")),
        ("latency_us", ("u64", "958123")),
    ] {
        assert_eq!(get(fields, name), Some(want), "field {name}");
    }
    for absent in [
        "downgraded_to",
        "route_policy",
        "step",
        "reason",
        "walk_detail",
    ] {
        assert_eq!(
            get(fields, absent),
            None,
            "{absent} is omitted when unknown"
        );
    }
    for (name, _, _) in fields {
        assert!(
            ![
                "body",
                "headers",
                "header",
                "authorization",
                "api_key",
                "token",
                "secret"
            ]
            .contains(name),
            "the summary must never carry {name}"
        );
    }

    // A refusal names its step and reason, and no attempt renders as `-`.
    finished(&Summary {
        unit_id: 7,
        plane: "llm",
        governance: "refused",
        outcome: "refused",
        step: Some("admit"),
        reason: Some("over_budget"),
        status: 429,
        ..Summary::default()
    });
    let delivered = events.take();
    let fields = &delivered[0].1;
    assert_eq!(get(fields, "governance"), Some(("str", "refused")));
    assert_eq!(get(fields, "step"), Some(("str", "admit")));
    assert_eq!(get(fields, "reason"), Some(("str", "over_budget")));
    assert_eq!(get(fields, "tried"), Some(("fmt", "-")));
    assert_eq!(get(fields, "request_id"), None);

    // Back to the default: off again.
    set(None);
    assert!(!enabled());
    finished(&summary(&attempts));
    assert!(events.take().is_empty());
}
