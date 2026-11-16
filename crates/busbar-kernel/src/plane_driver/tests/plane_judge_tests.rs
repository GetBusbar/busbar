// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[tokio::test]
async fn without_a_judge_every_destination_is_internal_and_the_condition_is_the_registered_diagnostic(
) {
    let judge = PlaneJudge::unavailable();
    let verdict = judge
        .judge(
            "example.com",
            0,
            0,
            Instant::now() + std::time::Duration::from_secs(1),
        )
        .await;
    assert_eq!(verdict, DEST_INTERNAL);
    assert_eq!(
        crate::diagnostics::PLANE_JUDGE_UNAVAILABLE.slug,
        "plane-judge-unavailable",
        "the row a plane's JUDGE logs is the catalogue's, not free text"
    );
}

/// Every WARN line's `diag` field, in order.
#[derive(Clone, Default)]
struct DiagWarns(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for DiagWarns {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        struct Diag(Option<String>);
        impl tracing::field::Visit for Diag {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "diag" {
                    self.0 = Some(format!("{value:?}"));
                }
            }
        }
        let mut diag = Diag(None);
        event.record(&mut diag);
        if let Some(diag) = diag.0 {
            self.0.lock().unwrap().push(diag);
        }
    }
}

/// BUSBAR-7108: a deployment with no destination judge says so once, as the registered warning.
/// The latch is per process, so this runs where it is the first judge call (one process per test
/// under nextest).
#[tokio::test]
async fn a_missing_destination_judge_logs_busbar_7108_as_a_warning() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let warns = DiagWarns::default();
    let _guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(warns.clone()));
    let verdict = PlaneJudge::unavailable()
        .judge(
            "example.com",
            0,
            0,
            Instant::now() + std::time::Duration::from_secs(1),
        )
        .await;
    assert_eq!(verdict, DEST_INTERNAL);
    assert_eq!(
        *warns.0.lock().unwrap(),
        vec!["BUSBAR-7108".to_string()],
        "the missing judge is logged once, under its registered code"
    );
}
