// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-P9: the body a rewrite leaves is copied once, out of the plane's arena, and
//! that copy becomes the unit's body; it is not copied again into the unit. Every other part of a
//! projection is read in place, and a stage run projects into at most two arenas (Addendum B).
//! Counted by the dev-only stage probes (`busbar_contract::stage_probe`).

use super::*;
use busbar_contract::stage_probe::{Derive, Scope};

#[tokio::test]
async fn rewritten_body_copied_once() {
    let (_, g) = gate(None);
    let hooks = bound(
        vec![(
            Duration::from_millis(500),
            Arc::new(Rewriter {
                name: "rewriter",
                refuses_failed_rewrite: false,
            }),
        )],
        vec![(0, g)],
    );
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(hooks),
    );
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["ok"], &[b"done"]),
        Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/call", b"user:hello"), 0);

    let scope = Scope::open();
    assert!(matches!(drive(&units).await, Outcome::Completed));

    assert_eq!(r.projects().len(), 2, "the view, then the rewrite");
    let sent = far.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].body, b"user:COMPRESSED",
        "the attempt carries the body the rewrite left"
    );
    assert_eq!(
        scope.count(Derive::ProjectCopy),
        1,
        "the rewritten body is copied out of the arena once and moved into the unit"
    );
}

/// A rewrite hook answering a fixed conversation.
struct Rewrites {
    name: &'static str,
    turns: Vec<(&'static str, String)>,
}

#[async_trait::async_trait]
impl RoutingPolicy for Rewrites {
    async fn decide(
        &self,
        _: &RoutingRequest<'_>,
        _: &[Candidate<'_>],
        _: &RoutingContext<'_>,
        _: Duration,
    ) -> PolicyResult {
        Ok(RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        self.name
    }
    async fn transform(&self, _: &RoutingRequest<'_>, _: Duration) -> TransformOutcome {
        TransformOutcome::Rewrite(RewriteReply {
            messages: self
                .turns
                .iter()
                .map(|(role, content)| serde_json::json!({"role": role, "content": content}))
                .collect(),
            tools: vec![],
        })
    }
}

fn rewrites(
    name: &'static str,
    turns: &[(&'static str, &str)],
) -> (Duration, Arc<dyn RoutingPolicy>) {
    (
        Duration::from_millis(500),
        Arc::new(Rewrites {
            name,
            turns: turns.iter().map(|(r, t)| (*r, String::from(*t))).collect(),
        }),
    )
}

const RICH: &[u8] = b"sys=be brief\nuser=alice\nuser:hello\nassistant:hi";

#[tokio::test]
async fn a_unit_projects_into_two_arenas_and_copies_only_rewritten_bodies() {
    let hooks = bound(
        vec![
            rewrites("rw-1", &[("user", "first"), ("assistant", "one")]),
            rewrites("rw-2", &[("user", "second"), ("assistant", "two")]),
        ],
        Vec::new(),
    );
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(hooks),
    );
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["ok"], &[b"done"]),
        Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/rich", RICH), 0);

    let scope = Scope::open();
    assert!(matches!(drive(&units).await, Outcome::Completed));

    assert_eq!(r.projects().len(), 3, "the view, then each rewrite");
    let sent = far.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].body, b"user:second\nassistant:two");
    assert_eq!(
        scope.count(Derive::ProjectCopy),
        2,
        "only each rewritten body is copied out of an arena"
    );
    assert_eq!(
        scope.count(Derive::ProjectArena),
        2,
        "a stage run projects into at most two arenas, whatever its rewrite count"
    );
}

#[tokio::test]
async fn a_gate_first_gate_only_unit_copies_nothing_out_of_its_one_arena() {
    let (_, g) = gate(None);
    let mut r = rig_with_hooks(Way::Double, BufferCaps::default(), Book::default(), None);
    r.driver = r.driver.with_hooks(Arc::new(GatedBinder {
        gates: vec![(0, g)],
        rewrites: Vec::new(),
    }));
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["ok"], &[b"done"]),
        Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/call", b"user:hello"), 0);

    let scope = Scope::open();
    let _ = drive(&units).await;

    assert_eq!(r.projects().len(), 1, "the gates screen the one projection");
    assert_eq!(
        scope.count(Derive::ProjectCopy),
        0,
        "the gates read the arena"
    );
    assert_eq!(scope.count(Derive::ProjectArena), 1);
}

#[tokio::test]
async fn a_policy_only_unit_copies_nothing_out_of_its_arena() {
    let (seen, policy) = gate(None);
    let mut hooks = bound(Vec::new(), Vec::new());
    hooks.pool_policies.insert("pool-a".to_string(), policy);
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(hooks),
    );
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["ok"], &[b"done"]).naming_its_pool(),
        Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/rich", RICH), 0);

    let scope = Scope::open();
    let outcome = drive(&units).await;
    assert!(matches!(outcome, Outcome::Completed), "{outcome:?}");

    assert_eq!(
        *seen.lock().unwrap(),
        vec![vec![
            ("user".to_string(), "hello".to_string()),
            ("assistant".to_string(), "hi".to_string()),
        ]],
        "the policy judged the request's own turns"
    );
    assert_eq!(scope.count(Derive::ProjectCopy), 0);
    assert_eq!(scope.count(Derive::ProjectArena), 1);
}

#[tokio::test]
async fn a_short_answer_grows_one_arena_and_its_reuse_keeps_the_growth() {
    let big = "x".repeat(3000);
    let hooks = bound(
        vec![
            rewrites("rw-big", &[("user", big.as_str())]),
            rewrites("rw-small-1", &[("user", "small")]),
            rewrites("rw-small-2", &[("user", "smaller")]),
        ],
        Vec::new(),
    );
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(hooks),
    );
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["ok"], &[b"done"]),
        Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/call", b"user:hello"), 0);

    let scope = Scope::open();
    assert!(matches!(drive(&units).await, Outcome::Completed));

    assert_eq!(r.projects().len(), 4);
    assert_eq!(
        r.regrown().len(),
        1,
        "only the big rewrite answered SHORT; the grown arena was reused without one"
    );
    assert_eq!(far.sent()[0].body, b"user:smaller");
    assert_eq!(
        scope.count(Derive::ProjectArena),
        3,
        "the first arena, the spare, and the spare's one growth"
    );
}

#[tokio::test]
async fn a_one_mib_prompt_projects_borrowed() {
    let text = "a".repeat(1 << 20);
    let mut body = b"sys=s\nuser=u\nuser:".to_vec();
    body.extend_from_slice(text.as_bytes());
    let (seen, g) = gate(None);
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(bound(Vec::new(), vec![(0, g)])),
    );
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["ok"], &[b"done"]),
        Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/rich", &body), 0);

    let scope = Scope::open();
    let outcome = drive(&units).await;
    assert!(matches!(outcome, Outcome::Completed), "{outcome:?}");

    assert_eq!(r.regrown().len(), 1, "one SHORT answer, to about 2 MiB");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].len(), 1);
    assert_eq!(seen[0][0].0, "user");
    assert!(seen[0][0].1 == text, "the gate saw the whole turn text");
    assert_eq!(
        scope.count(Derive::ProjectCopy),
        0,
        "a long prompt is read in place, never copied"
    );
    assert_eq!(
        scope.count(Derive::ProjectArena),
        2,
        "the arena and its one growth"
    );
}

#[tokio::test]
async fn an_invalid_utf8_turn_is_the_one_lossy_copy() {
    let (seen, g) = gate(None);
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(bound(Vec::new(), vec![(0, g)])),
    );
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["ok"], &[b"done"]),
        Caller::default(),
    );
    let units = r.driver.unit(
        &steps,
        &far,
        &caller,
        arrival("/invalid-utf8", b"user:hello"),
        0,
    );

    let scope = Scope::open();
    let outcome = drive(&units).await;
    assert!(matches!(outcome, Outcome::Completed), "{outcome:?}");

    assert_eq!(
        *seen.lock().unwrap(),
        vec![vec![("user".to_string(), "caf\u{fffd} text".to_string())]],
        "the turn reads with today's lossy replacement"
    );
    assert_eq!(
        scope.count(Derive::ProjectCopy),
        1,
        "only the invalid turn text is copied, to replace its bad byte"
    );
}

/// Every counter increment, rendered `name{k=v,...}`.
#[derive(Clone, Default)]
struct Tally(Arc<Mutex<Vec<String>>>);

struct Tallied {
    key: String,
    into: Tally,
}

impl metrics::CounterFn for Tallied {
    fn increment(&self, value: u64) {
        self.into
            .0
            .lock()
            .unwrap()
            .extend((0..value).map(|_| self.key.clone()));
    }
    fn absolute(&self, _: u64) {}
}

impl metrics::Recorder for Tally {
    fn describe_counter(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_gauge(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_histogram(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn register_counter(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        let labels: Vec<String> = key
            .labels()
            .map(|l| format!("{}={}", l.key(), l.value()))
            .collect();
        metrics::Counter::from_arc(Arc::new(Tallied {
            key: format!("{}{{{}}}", key.name(), labels.join(",")),
            into: self.clone(),
        }))
    }
    fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::noop()
    }
    fn register_histogram(
        &self,
        _: &metrics::Key,
        _: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}

async fn tallied<F: std::future::Future>(tally: &Tally, future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(move |cx| metrics::with_local_recorder(tally, || future.as_mut().poll(cx)))
        .await
}

#[tokio::test]
async fn a_plane_asking_past_the_input_cap_is_refused_by_the_host() {
    let fault_words = format!(
        "refused:500:{}",
        busbar_contract::abi::plane::PROJECT_FAULT_MESSAGE
    )
    .into_bytes();
    for part in ["arena", "messages", "signals"] {
        for with_rewrite in [false, true] {
            let case = format!("{part} with_rewrite={with_rewrite}");
            let (seen, g) = gate(None);
            let hooks = if with_rewrite {
                bound(vec![rewrites("rw", &[("user", "COMPRESSED")])], Vec::new())
            } else {
                bound(Vec::new(), vec![(0, g)])
            };
            let r = rig_with_hooks(
                Way::Double,
                BufferCaps::default(),
                Book::default(),
                Some(hooks),
            );
            let (steps, far, caller) = (
                TestUnits::passing(),
                Far::new(&["ok"], &[b"done"]),
                Caller::default(),
            );
            let target = if with_rewrite {
                format!("/over-{part}-rw")
            } else {
                format!("/over-{part}")
            };
            let units = r
                .driver
                .unit(&steps, &far, &caller, arrival(&target, b"user:hello"), 0);

            let tally = Tally::default();
            let scope = Scope::open();
            let outcome = tallied(&tally, drive(&units)).await;

            let rendered = units.take_rendered().expect("the refusal is rendered");
            if with_rewrite {
                assert!(
                    matches!(outcome, Outcome::Failed(_, ReasonCode::HookVeto)),
                    "{case}: an unapplied rewrite is the shared 500: {outcome:?}"
                );
                assert_eq!(rendered.status, 500, "{case}");
                assert_eq!(rendered.body, fault_words, "{case}");
            } else {
                assert!(
                    matches!(outcome, Outcome::Failed(_, ReasonCode::DecodeFailed)),
                    "{case}: an over-cap view is unreadable, never unparseable: {outcome:?}"
                );
                assert_eq!(rendered.status, 400, "{case}");
                assert!(seen.lock().unwrap().is_empty(), "{case}: no gate judged it");
            }
            assert!(far.sent().is_empty(), "{case}: never dialled");
            assert_eq!(
                r.regrown(),
                vec![(4096, 64, 16)],
                "{case}: the re-call was handed the buffers it had, none resized"
            );
            assert_eq!(
                scope.count(Derive::ProjectArena),
                1 + u32::from(with_rewrite),
                "{case}: no arena grew"
            );
            let over: Vec<String> = tally
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|k| k.starts_with(busbar_kernel::snapshot::HOOK_PROJECT_OVER_CAP_TOTAL))
                .cloned()
                .collect();
            assert_eq!(
                over,
                vec![format!(
                    "{}{{part={part}}}",
                    busbar_kernel::snapshot::HOOK_PROJECT_OVER_CAP_TOTAL
                )],
                "{case}: counted once, by part"
            );
        }
    }
}
