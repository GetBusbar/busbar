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

/// THE ENTRY SPAN AN ARRIVAL OPENS (status row 173): its routed claim's own where it states one,
/// else the first path fact (a raw-affix claim stating a span) of its verb whose affixes the raw
/// path matches, in the snapshot's order; none where neither states one. A raw affix is no routed
/// claim: an arrival on its index opens nothing of its own.
#[test]
fn an_arrival_opens_its_claims_span_else_the_first_path_fact_it_matches() {
    use busbar_contract::abi::plane::CLAIM_RAW_AFFIX;
    let spans = super::EntrySpans::of([
        ("POST", "/own", 0, "entry_span_test_own"),
        ("POST", "/prefix", 0, ""),
        ("POST", "/*/first", CLAIM_RAW_AFFIX, "entry_span_test_first"),
        (
            "POST",
            "/*/first",
            CLAIM_RAW_AFFIX,
            "entry_span_test_second",
        ),
        ("POST", "/*/stated", CLAIM_RAW_AFFIX, ""),
    ]);
    let names = |claim: u32, method: &str, path: &str| -> Vec<&'static str> {
        let opened = Opened::default();
        let subscriber = tracing_subscriber::registry().with(opened.clone());
        tracing::subscriber::with_default(subscriber, || {
            drop(spans.open(claim, method, path));
        });
        let seen = opened.0.lock().unwrap().clone();
        seen.into_iter().map(|o| o.0).collect()
    };
    assert_eq!(
        names(0, "POST", "/own/x/first"),
        vec!["entry_span_test_own"]
    );
    assert_eq!(
        names(1, "POST", "/prefix/m/first"),
        vec!["entry_span_test_first"]
    );
    assert!(
        names(1, "GET", "/prefix/m/first").is_empty(),
        "another verb"
    );
    assert!(names(1, "POST", "/prefix/m/other").is_empty(), "no affix");
    assert!(names(1, "POST", "/prefix/m/stated").is_empty(), "no name");
    assert!(
        names(2, "POST", "/x/y").is_empty(),
        "a raw affix routes none"
    );
}
