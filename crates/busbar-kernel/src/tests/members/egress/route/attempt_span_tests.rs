// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ATTEMPT SPAN (status row 173): a terminal's dispatch opens 1.5.5's `forward_once`, at the
//! hot-path level, naming the lane index of the member it dispatches to (v1.5.5
//! `proxy/engine/walk.rs:382`, `fields(lane = i)`; `docs/observability.md` l.162-174). 1.5.5
//! opened it around each degraded dispatch (a spill into a fallback pool, the least-bad bypass, a
//! queued slot) and around no attempt of the ordered walk, so the walk's own attempts open none.

use std::sync::{Arc, Mutex};

use tracing_subscriber::layer::SubscriberExt as _;

use super::harness::{ok_frames, route_token, Health, Script};
use super::{member, Node};
use crate::plane_driver::{FarEnd, Pick};
use busbar_contract::DestinationId;
use busbar_kernel_egress::pool::OnExhausted;

/// One span opened: its name, its level, and each field it recorded with its value.
type Opened = (&'static str, tracing::Level, Vec<(&'static str, String)>);

/// Every span opened under it.
#[derive(Clone, Default)]
struct SpanLog(Arc<Mutex<Vec<Opened>>>);

/// A field visitor: every field's name and its value as written.
struct Fields<'a>(&'a mut Vec<(&'static str, String)>);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name(), format!("{value:?}")));
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanLog {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _: &tracing::span::Id,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut fields = Vec::new();
        attrs.record(&mut Fields(&mut fields));
        let meta = attrs.metadata();
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((meta.name(), *meta.level(), fields));
    }
}

/// A three-member pool whose exhaustion terminal is `on_exhausted`, every member answering 200.
fn pool_of_three(on_exhausted: OnExhausted) -> Node {
    let mut node = Node::with_lanes(&["a", "b", "c"]);
    node.pool(
        "primary",
        vec![
            member(DestinationId::new(0), "a"),
            member(DestinationId::new(1), "b"),
            member(DestinationId::new(2), "c"),
        ],
    );
    node.tune("primary", |p| p.on_exhausted = on_exhausted);
    for lane in ["a", "b", "c"] {
        node.conns.script(lane, Script::Frames(ok_frames()));
    }
    node
}

/// The first attempt's pick, and the spans its attempt span opened, under a capturing subscriber.
fn first_attempt(node: &Node) -> (Pick, Vec<Opened>) {
    let log = SpanLog::default();
    let subscriber = tracing_subscriber::registry().with(log.clone());
    let egress = node.egress();
    let picked = tracing::subscriber::with_default(subscriber, || {
        node.rt.block_on(async {
            let token = route_token();
            let far = egress.unit(node.unit_route("primary"));
            let picked = far.member(&token, 1).await;
            drop(far.attempt_span(&token));
            picked
        })
    });
    let opened = log
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    (picked, opened)
}

/// THE LEAST-BAD BYPASS IS A TERMINAL'S DISPATCH: every member cooling down, the last resort takes
/// the soonest (destination 1) and its attempt opens `forward_once` at the hot-path level, naming
/// that member's lane index and nothing else. RED before the far end stated an attempt span: none
/// opened.
#[test]
fn a_least_bad_dispatch_opens_forward_once_naming_its_lane() {
    let node = pool_of_three(OnExhausted::LeastBad);
    for (destination, cooldown) in [(0, 300), (1, 10), (2, 120)] {
        node.breaker.set(
            DestinationId::new(destination),
            Health {
                cooldown,
                ..Health::default()
            },
        );
    }
    let (picked, opened) = first_attempt(&node);
    assert!(
        matches!(&picked, Pick::Member { name, .. } if name == "b"),
        "the last resort takes the soonest cooldown: {picked:?}"
    );
    assert_eq!(
        opened,
        vec![(
            "forward_once",
            crate::observability::HOTPATH_LEVEL,
            vec![("lane", "1".to_string())]
        )],
        "1.5.5's attempt span: its name, the hot-path level, its one field"
    );
}

/// THE ORDERED WALK'S OWN ATTEMPT IS NO TERMINAL'S DISPATCH: a healthy pool's first attempt opens
/// no span, as 1.5.5's walk opened none around it.
#[test]
fn the_walks_own_attempt_opens_no_attempt_span() {
    let node = pool_of_three(OnExhausted::LeastBad);
    let (picked, opened) = first_attempt(&node);
    assert!(
        matches!(&picked, Pick::Member { .. }),
        "a healthy pool takes a member: {picked:?}"
    );
    assert!(opened.is_empty(), "{opened:?}");
}
