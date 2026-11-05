// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::collections::BTreeMap;
use tracing::Instrument as _;
use tracing_subscriber::{layer::SubscriberExt as _, registry::LookupSpan};

type Fields = BTreeMap<String, String>;
#[derive(Clone, Default)]
struct Timings(Arc<Mutex<Vec<TimingRecord>>>);
type TimingRecord = (u64, Option<u64>, Fields);
struct Values<'a>(&'a mut Fields);
impl tracing::field::Visit for Values<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
}
impl<S: tracing::Subscriber + for<'a> LookupSpan<'a>> tracing_subscriber::Layer<S> for Timings {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut fields = Fields::new();
        attrs.record(&mut Values(&mut fields));
        ctx.span(id).unwrap().extensions_mut().insert(fields);
    }
    fn on_record(
        &self,
        id: &tracing::Id,
        values: &tracing::span::Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let span = ctx.span(id).unwrap();
        let mut ext = span.extensions_mut();
        values.record(&mut Values(ext.get_mut::<Fields>().unwrap()));
    }
    fn on_close(&self, id: tracing::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        let span = ctx.span(&id).unwrap();
        if span.name() == "forward_once" {
            self.0.lock().unwrap().push((
                id.into_u64(),
                span.parent().map(|p| p.id().into_u64()),
                span.extensions().get::<Fields>().unwrap().clone(),
            ));
        }
    }
}

#[tokio::test]
async fn request_timing_normal_retry_stream_and_cut_are_observed_by_the_pump() {
    use tracing::instrument::WithSubscriber as _;
    for way in ways() {
        for (members, expected, chunks) in [
            (
                vec!["ok"],
                vec!["complete"],
                &[b"hello far end".as_slice()][..],
            ),
            (vec!["ok"], vec!["complete"], CHUNKS),
            (vec!["overloaded", "ok"], vec!["retry", "complete"], CHUNKS),
            (vec!["cut"], vec!["cut"], CHUNKS),
        ] {
            let seen = Timings::default();
            let subscriber = tracing_subscriber::registry().with(seen.clone());
            async {
                let r = rig(way, BufferCaps::default(), Book::default());
                let (steps, far, caller) = (
                    TestUnits::passing(),
                    Far::new(&members, chunks),
                    Caller::default(),
                );
                let units = r.driver.unit(
                    &steps,
                    &far,
                    &caller,
                    arrival("/call", b"private request body"),
                    0,
                );
                let parent = tracing::debug_span!("timing_request", request_id = 99_u64);
                let _ = drive(&units).instrument(parent).await;
                assert_eq!(far.sent().len(), members.len());
                assert!(caller.text().starts_with("hello far end"));
            }
            .with_subscriber(subscriber)
            .await;
            let records = seen.0.lock().unwrap();
            assert_eq!(records.len(), expected.len(), "{way:?}: {records:?}");
            for (i, (_, parent, fields)) in records.iter().enumerate() {
                assert!(parent.is_some());
                assert_eq!(*parent, records[0].1);
                assert_eq!(fields["attempt"], (i + 1).to_string());
                assert_eq!(fields["unit_id"], "7");
                assert_eq!(fields["outcome"], expected[i]);
                assert_eq!(fields["first_token"], "unavailable");
                assert_eq!(
                    fields.get("retry_of_attempt"),
                    (i > 0).then(|| i.to_string()).as_ref()
                );
                let ready: u64 = fields["response_ready_us"].parse().unwrap();
                let body: u64 = fields["first_body_us"].parse().unwrap();
                let ended: u64 = fields["attempt_end_us"].parse().unwrap();
                assert!(ready <= body && body <= ended);
                assert_eq!(
                    fields.contains_key("producer_complete_us"),
                    expected[i] == "complete"
                );
                assert!(!fields.contains_key("cancelled_us"));
                assert!(!fields
                    .values()
                    .any(|v| v.contains("private request body") || v.contains("hello")));
            }
        }
    }
}

#[tokio::test]
async fn request_timing_a_stalled_stream_records_cancellation_without_completion() {
    use tracing::instrument::WithSubscriber as _;
    for way in ways() {
        let seen = Timings::default();
        let subscriber = tracing_subscriber::registry().with(seen.clone());
        async {
            let r = rig(way, BufferCaps::default(), Book::default());
            let (steps, far, caller) = (
                TestUnits::passing(),
                Far::new(&["ok"], CHUNKS).stating(Duration::from_millis(50)),
                Caller {
                    stall_after: Some(1),
                    ..Caller::default()
                },
            );
            let units = r
                .driver
                .unit(&steps, &far, &caller, arrival("/call", b"x"), 0);
            tokio::time::timeout(Duration::from_secs(10), drive(&units))
                .await
                .expect("the stated ceiling releases the stalled caller");
        }
        .with_subscriber(subscriber)
        .await;
        let records = seen.0.lock().unwrap();
        assert_eq!(records.len(), 1);
        let fields = &records[0].2;
        assert_eq!(fields["outcome"], "cancelled");
        assert_eq!(
            fields["cancel_reason"],
            reason_code(ReasonCode::DeadlineExceeded).to_string()
        );
        assert!(fields.contains_key("cancelled_us"));
        assert!(fields.contains_key("response_ready_us"));
        assert!(!fields.contains_key("producer_complete_us"));
    }
}
