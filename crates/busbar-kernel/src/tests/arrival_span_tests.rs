// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The arrival span's callsite: one per name, opened at the hot-path level with no fields, and none
//! for an empty name.

use std::sync::{Arc, Mutex};

use tracing_subscriber::layer::{Context, SubscriberExt as _};
use tracing_subscriber::Layer;

use super::ArrivalSpan;

/// One span opened: its name, its level and how many fields its callsite declares.
type OpenedSpan = (&'static str, tracing::Level, usize);

/// Every span opened under it.
#[derive(Clone, Default)]
struct Opened(Arc<Mutex<Vec<OpenedSpan>>>);

impl<S: tracing::Subscriber> Layer<S> for Opened {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _: &tracing::span::Id,
        _: Context<'_, S>,
    ) {
        let meta = attrs.metadata();
        self.0
            .lock()
            .unwrap()
            .push((meta.name(), *meta.level(), meta.fields().len()));
    }
}

#[test]
fn an_arrival_span_is_one_callsite_per_name_opened_at_the_hot_path_level() {
    let opened = Opened::default();
    let subscriber = tracing_subscriber::registry().with(opened.clone());
    tracing::subscriber::with_default(subscriber, || {
        let one = ArrivalSpan::named("arrival_span_test").expect("a name opens a span");
        let again = ArrivalSpan::named("arrival_span_test").expect("the same name");
        assert!(
            std::ptr::eq(one.site, again.site),
            "one callsite per name, never one per binding"
        );
        assert_eq!(one.name(), "arrival_span_test");
        let span = one.open();
        assert!(!span.is_none(), "an enabled subscriber sees it");
        drop(span);
    });
    assert_eq!(
        *opened.0.lock().unwrap(),
        vec![("arrival_span_test", crate::observability::HOTPATH_LEVEL, 0)],
        "the 1.5.5 entry span: its name, the hot-path level, no fields (skip_all)"
    );
}

/// RED: a claim that states no name opens no span.
#[test]
fn an_empty_name_opens_no_span() {
    assert!(ArrivalSpan::named("").is_none());
}

/// One span opened with its fields: its name and each field's value as written.
type Recorded = (&'static str, Vec<(&'static str, String)>);

/// Every span opened under it, with the values it opened with.
#[derive(Clone, Default)]
struct Values(Arc<Mutex<Vec<Recorded>>>);

/// A field visitor: every field's name and its value as written.
struct Seen<'a>(&'a mut Vec<(&'static str, String)>);

impl tracing::field::Visit for Seen<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name(), format!("{value:?}")));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push((field.name(), value.to_string()));
    }
}

impl<S: tracing::Subscriber> Layer<S> for Values {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _: &tracing::span::Id,
        _: Context<'_, S>,
    ) {
        let mut fields = Vec::new();
        attrs.record(&mut Seen(&mut fields));
        self.0
            .lock()
            .unwrap()
            .push((attrs.metadata().name(), fields));
    }
}

/// The spans an arrival opens under `spans`, by its claim, verb, raw path and head fields.
fn opened(
    spans: &super::EntrySpans,
    claim: u32,
    method: &str,
    path: &str,
    head: &[(&str, &str)],
) -> Vec<Recorded> {
    let values = Values::default();
    let subscriber = tracing_subscriber::registry().with(values.clone());
    tracing::subscriber::with_default(subscriber, || {
        let field = |name: &str| head.iter().find(|(n, _)| *n == name).map(|(_, v)| *v);
        drop(spans.open(claim, method, path, field));
    });
    let mut seen = Vec::new();
    seen.append(&mut values.0.lock().unwrap());
    seen
}

/// THE ENTRY SPAN AN ARRIVAL OPENS: the first fact of its verb the request meets,
/// in the snapshot's order (an entry fact by its head fields and its path pattern, a raw affix by
/// its affixes), else its routed claim's own. An entry fact that states no span ends the reading
/// with none; a named path segment is recorded, percent-decoded, as the span's field. A fact is no
/// routed claim: an arrival on its index opens nothing of its own.
#[test]
fn an_arrival_opens_the_first_fact_it_meets_else_its_claims_span() {
    use busbar_contract::abi::plane::{CLAIM_ENTRY, CLAIM_RAW_AFFIX};
    let spans = super::EntrySpans::of([
        ("POST", "/own", 0, "entry_span_test_own"),
        (
            "POST",
            "path:/{pool}/v1/m",
            CLAIM_ENTRY,
            "entry_span_test_named",
        ),
        (
            "POST",
            "field:x-a=S1 path:*/end",
            CLAIM_ENTRY,
            "entry_span_test_head_path",
        ),
        ("POST", "field:x-a=S1", CLAIM_ENTRY, ""),
        ("POST", "field:x-b", CLAIM_ENTRY, "entry_span_test_field"),
        ("POST", "path:/own/*", CLAIM_ENTRY, "entry_span_test_under"),
        ("POST", "/*/end", CLAIM_RAW_AFFIX, "entry_span_test_affix"),
        ("POST", "/*/signed", CLAIM_RAW_AFFIX, ""),
    ]);
    let name = |seen: Vec<Recorded>| seen.into_iter().map(|s| s.0).collect::<Vec<_>>();
    assert_eq!(
        name(opened(&spans, 0, "POST", "/own", &[])),
        vec!["entry_span_test_own"]
    );
    assert_eq!(
        name(opened(&spans, 0, "POST", "/own/x", &[])),
        vec!["entry_span_test_under"],
        "a fact is read ahead of the claim's own span"
    );
    assert_eq!(
        opened(&spans, 0, "POST", "/p%20q/v1/m", &[]),
        vec![("entry_span_test_named", vec![("pool", "p q".to_string())])],
        "a named segment is the span's field, percent-decoded"
    );
    assert_eq!(
        name(opened(&spans, 0, "POST", "/x/end", &[("x-a", "S1 rest")])),
        vec!["entry_span_test_head_path"]
    );
    assert!(
        opened(&spans, 0, "POST", "/own/x", &[("x-a", "S1 rest")]).is_empty(),
        "a fact that states no span ends the reading with none"
    );
    assert_eq!(
        name(opened(
            &spans,
            0,
            "POST",
            "/own/x",
            &[("x-a", "S2"), ("x-b", "")]
        )),
        vec!["entry_span_test_field"],
        "a value that does not start with the prefix is not met"
    );
    assert_eq!(
        name(opened(&spans, 0, "POST", "/z/end", &[])),
        vec!["entry_span_test_affix"]
    );
    assert!(
        opened(&spans, 1, "GET", "/own/x", &[]).is_empty(),
        "another verb"
    );
    assert_eq!(
        name(opened(&spans, 0, "POST", "/z/signed", &[])),
        vec!["entry_span_test_own"],
        "a raw affix stating no span is no fact: the reading passes it to the claim's own span"
    );
    assert!(
        opened(&spans, 1, "POST", "/q", &[]).is_empty(),
        "a fact routes none"
    );
}
