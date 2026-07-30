//! Tests for the hook-metrics Prometheus renderer. Drive `render_text` directly (the pure half) so
//! the exposition format is asserted without a live hook or socket.

use super::*;
use std::collections::BTreeMap;

fn metric(name: &str, kind: &str, value: f64) -> HookMetric {
    HookMetric {
        name: name.to_string(),
        kind: kind.to_string(),
        value,
        labels: None,
        quantiles: None,
        buckets: None,
        estimated: None,
        ci_low: None,
        ci_high: None,
        help: None,
        label: None,
        unit: None,
        viz: None,
        max: None,
    }
}

fn labels(pairs: &[(&str, &str)]) -> Option<BTreeMap<String, String>> {
    Some(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
}

/// A counter renders with the verbatim name, an auto `hook` label, TYPE line, and the value.
#[test]
fn counter_renders_with_hook_label_and_verbatim_name() {
    let m = HookMetric {
        help: Some("tokens the hook saved".into()),
        labels: labels(&[("pool", "chat")]),
        ..metric("tokens_saved_total", "counter", 42.0)
    };
    let text = render_text(&[("headroom".to_string(), vec![m])]);
    assert!(text.contains("# TYPE tokens_saved_total counter"), "{text}");
    assert!(
        text.contains("# HELP tokens_saved_total tokens the hook saved"),
        "{text}"
    );
    // verbatim name + hook label FIRST + the hook's own label, exact value.
    assert!(
        text.contains("tokens_saved_total{hook=\"headroom\",pool=\"chat\"} 42\n"),
        "{text}"
    );
}

/// A histogram (quantiles) renders as a Prometheus SUMMARY: one line per quantile + `_count`.
#[test]
fn histogram_renders_as_summary() {
    let mut qs = BTreeMap::new();
    qs.insert("0.5".to_string(), 18.0);
    qs.insert("0.95".to_string(), 54.0);
    qs.insert("0.99".to_string(), 91.0);
    let m = HookMetric {
        quantiles: Some(qs),
        labels: labels(&[("pool", "chat")]),
        ..metric("compress_latency_us", "histogram", 1000.0)
    };
    let text = render_text(&[("headroom".to_string(), vec![m])]);
    assert!(
        text.contains("# TYPE compress_latency_us summary"),
        "{text}"
    );
    assert!(
        text.contains("compress_latency_us{hook=\"headroom\",pool=\"chat\",quantile=\"0.5\"} 18\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "compress_latency_us{hook=\"headroom\",pool=\"chat\",quantile=\"0.99\"} 91\n"
        ),
        "{text}"
    );
    // observation count from `value`
    assert!(
        text.contains("compress_latency_us_count{hook=\"headroom\",pool=\"chat\"} 1000\n"),
        "{text}"
    );
}

/// A histogram carrying native `buckets` renders as a Prometheus HISTOGRAM: cumulative
/// `name_bucket{le="…"}` rows in ascending `le` order, a synthesized `+Inf` bucket equal to the
/// total count when the hook omits it, and `name_count`. This is the shape `histogram_quantile()`
/// needs — the reason the wire carries buckets, not just quantiles.
#[test]
fn histogram_with_buckets_renders_as_native_histogram() {
    let mut bs = BTreeMap::new();
    bs.insert("0.5".to_string(), 3.0);
    bs.insert("1".to_string(), 7.0);
    let m = HookMetric {
        buckets: Some(bs),
        labels: labels(&[("pool", "chat")]),
        ..metric("headroom_compression_ratio", "histogram", 7.0)
    };
    let text = render_text(&[("headroom".to_string(), vec![m])]);
    assert!(
        text.contains("# TYPE headroom_compression_ratio histogram"),
        "buckets => histogram, not summary: {text}"
    );
    // finite bounds ascending, cumulative counts, hook label first.
    let lo = text
        .find("headroom_compression_ratio_bucket{hook=\"headroom\",pool=\"chat\",le=\"0.5\"} 3\n")
        .expect("0.5 bucket");
    let hi = text
        .find("headroom_compression_ratio_bucket{hook=\"headroom\",pool=\"chat\",le=\"1\"} 7\n")
        .expect("1 bucket");
    assert!(lo < hi, "buckets must be ascending by le: {text}");
    // +Inf synthesized to the total count (hook omitted it), then the count line.
    assert!(
        text.contains(
            "headroom_compression_ratio_bucket{hook=\"headroom\",pool=\"chat\",le=\"+Inf\"} 7\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("headroom_compression_ratio_count{hook=\"headroom\",pool=\"chat\"} 7\n"),
        "{text}"
    );
}

/// A hook cannot impersonate a first-party series: `busbar_`-prefixed names are dropped.
#[test]
fn busbar_prefix_is_reserved() {
    let text = render_text(&[(
        "evil".to_string(),
        vec![
            metric("busbar_engine_requests_total", "counter", 9.0),
            metric("legit_total", "counter", 1.0),
        ],
    )]);
    assert!(
        !text.contains("busbar_engine_requests_total"),
        "reserved name must be dropped: {text}"
    );
    assert!(text.contains("legit_total{hook=\"evil\"} 1\n"), "{text}");
}

/// Two hooks emitting the SAME metric name share one HELP/TYPE header and are separated only by the
/// `hook` label — the dimensional model that lets a dashboard query the bare name across hooks or
/// filter to one.
#[test]
fn two_hooks_same_name_share_header_split_by_label() {
    let a = (
        "hook_a".to_string(),
        vec![metric("proxy_compression_ratio_by_strategy", "gauge", 0.4)],
    );
    let b = (
        "hook_b".to_string(),
        vec![metric("proxy_compression_ratio_by_strategy", "gauge", 0.6)],
    );
    let text = render_text(&[a, b]);
    // exactly one TYPE line for the shared name
    assert_eq!(
        text.matches("# TYPE proxy_compression_ratio_by_strategy")
            .count(),
        1,
        "one TYPE header per name: {text}"
    );
    assert!(
        text.contains("proxy_compression_ratio_by_strategy{hook=\"hook_a\"} 0.4\n"),
        "{text}"
    );
    assert!(
        text.contains("proxy_compression_ratio_by_strategy{hook=\"hook_b\"} 0.6\n"),
        "{text}"
    );
}

/// A same-name entry of a DIFFERENT type is dropped (Prometheus forbids mixing types per name), so
/// the exposition stays valid rather than breaking the whole scrape.
#[test]
fn type_conflict_for_shared_name_is_dropped() {
    let a = ("a".to_string(), vec![metric("shared", "counter", 1.0)]);
    let b = ("b".to_string(), vec![metric("shared", "gauge", 2.0)]);
    let text = render_text(&[a, b]);
    assert_eq!(
        text.matches("# TYPE shared").count(),
        1,
        "one type only: {text}"
    );
    assert!(text.contains("# TYPE shared counter"), "first wins: {text}");
    // the gauge entry (b) is dropped; only the counter (a) renders
    assert!(text.contains("shared{hook=\"a\"} 1\n"), "{text}");
    assert!(
        !text.contains("hook=\"b\""),
        "conflicting-type entry dropped: {text}"
    );
}

/// Label values are Prometheus-escaped (quote / backslash / newline) so a value can't break the line.
#[test]
fn label_values_are_escaped() {
    let m = HookMetric {
        labels: labels(&[("k", "a\"b\\c")]),
        ..metric("x_total", "counter", 1.0)
    };
    let text = render_text(&[("h".to_string(), vec![m])]);
    assert!(text.contains(r#"k="a\"b\\c""#), "{text}");
}

/// A per-call unique hook name. `IN_FLIGHT` (`hooks/scrape.rs`) is process-global and keyed by hook
/// name, so a literal shared with any concurrently-running test in this binary makes an "the slot is
/// taken"/"the slot is free" assertion depend on test interleaving. A monotonic ticket -- not a clock
/// read, which is not monotonic under coarse timer resolution -- makes each claim this test makes
/// unambiguously its own.
fn unique_hook(base: &str) -> String {
    static TICKET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    format!(
        "{base}-{}",
        TICKET.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

/// `unique_hook` must actually be unique per call, and always prefixed by its base -- the
/// deterministic proof that the ticket mechanism does what `only_one_refresh_per_hook_can_be_in_flight`
/// (below) relies on to never collide with a sibling test running concurrently in this binary.
#[test]
fn unique_hook_never_repeats() {
    let a = unique_hook("x");
    let b = unique_hook("x");
    assert_ne!(a, b, "two calls must never return the same name");
    assert!(a.starts_with("x-") && b.starts_with("x-"), "{a} / {b}");
}

/// THE MANUFACTURED-COLLISION PROOF. `IN_FLIGHT` (`hooks/scrape.rs`) is one process-global set
/// keyed by hook name -- so two INDEPENDENT callers (in production: two scrapes; in this test
/// binary: two `#[test]` functions that happen to be scheduled concurrently) sharing the SAME
/// literal name genuinely interfere with each other's claim, even though each believes it owns an
/// exclusive slot. Force that interference deterministically with two threads and a barrier
/// (rather than hoping cargo's test scheduler happens to overlap two functions), then show
/// `unique_hook` makes the same two "callers" independent by construction.
#[test]
fn manufactured_collision_proves_the_shared_literal_hazard_and_the_fix() {
    use std::sync::{Arc, Barrier};

    // Part 1 -- THE HAZARD: two callers sharing one literal key DO interfere. This is exactly what
    // would happen if two separate #[test] functions each hardcoded "busy-hook" and the test
    // harness happened to run them at the same time -- one call's "I claimed the slot" assertion
    // would spuriously fail because a totally unrelated caller got there first.
    // A short HOLD after claiming (before releasing) forces genuine overlap regardless of
    // scheduling jitter around the barrier -- without it, a fast claim+release on one thread could
    // fully complete before the other even starts, hiding the very interference this test exists
    // to demonstrate.
    let hold = std::time::Duration::from_millis(100);

    let shared_key = "manufactured-collision-shared-literal";
    let barrier = Arc::new(Barrier::new(2));
    let results: Vec<bool> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    let claim = InFlight::claim(shared_key);
                    let won = claim.is_some();
                    std::thread::sleep(hold);
                    drop(claim);
                    won
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(
        results.iter().filter(|&&ok| ok).count(),
        1,
        "two callers racing on the SAME literal key must interfere -- exactly one claim wins: {results:?}"
    );

    // Part 2 -- THE FIX: the same two "callers", each through `unique_hook`, never share a key, so
    // neither can observe the other's claim -- both win independently, by construction.
    let barrier = Arc::new(Barrier::new(2));
    let results: Vec<bool> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let barrier = barrier.clone();
                scope.spawn(move || {
                    let key = unique_hook("manufactured-collision-caller");
                    barrier.wait();
                    let claim = InFlight::claim(&key);
                    let won = claim.is_some();
                    std::thread::sleep(hold);
                    drop(claim);
                    won
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(
        results.iter().all(|&ok| ok),
        "two callers on DISTINCT unique_hook keys must never interfere: {results:?}"
    );
}

/// THE SPAWN-STORM GUARD. A scrape fires a refresh for every STALE hook, and staleness does not
/// clear until the refresh COMPLETES -- so with staleness as the only gate, every scrape that lands
/// while a refresh is running spawns another one. Each refresh stages a copy of the plugin to disk,
/// `dlopen`s it, and runs its constructor, so a scrape interval shorter than a slow hook's status
/// round-trip compounds without bound: N monitoring replicas x every scrape x every hook.
///
/// The admission ticket is the in-flight claim. Asserted on the claim itself rather than through a
/// live scrape, because "how many tasks did a handler spawn" is not otherwise observable.
///
/// Keys are `unique_hook(..)`, not literals: `IN_FLIGHT` is one process-global set shared by every
/// test in this binary, so a literal claimed here could collide with the same literal claimed by a
/// concurrently-running sibling test and make these assertions depend on interleaving.
#[test]
fn only_one_refresh_per_hook_can_be_in_flight() {
    let busy = unique_hook("busy-hook");
    let other = unique_hook("other-hook");
    let panicky = unique_hook("panicky");

    let first = InFlight::claim(&busy).expect("the first scrape claims the slot");
    assert!(
        InFlight::claim(&busy).is_none(),
        "a second scrape landing mid-refresh must NOT spawn another plugin load"
    );
    // A different hook is unaffected -- the gate is per-hook, not a global one.
    let other_claim = InFlight::claim(&other).expect("a different hook claims independently");

    // Releasing lets the next scrape through, so a hook is never wedged out of refreshing.
    drop(first);
    let again = InFlight::claim(&busy).expect("the slot is free once the refresh finishes");
    drop(again);
    drop(other_claim);

    // And a PANICKING refresh must release too: `InFlight` is RAII, so unwinding drops the claim.
    let claimed = InFlight::claim(&panicky);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _held = claimed;
        panic!("refresh blew up mid-load");
    }));
    assert!(
        InFlight::claim(&panicky).is_some(),
        "a refresh that panicked must not wedge its hook out of ever refreshing again"
    );
}

/// A hook label may not shadow a label the renderer emits. Charset validity is not uniqueness:
/// `hook`, `le` and `quantile` all pass the wire's name check, and a duplicate label name is a
/// PARSE error, so one careless plugin would cost the whole `/metrics/hooks` exposition rather
/// than just its own sample. Both the histogram (`le`) and summary (`quantile`) arms are covered,
/// since they pass different `extra` sets.
#[test]
fn hook_labels_cannot_shadow_renderer_labels() {
    let shadowing = labels(&[("hook", "inner"), ("le", "oops"), ("quantile", "0.5")]);

    let mut hist = metric("chars_saved_total", "histogram", 3.0);
    hist.buckets = Some(BTreeMap::from([
        ("1".to_string(), 1.0),
        ("+Inf".to_string(), 3.0),
    ]));
    hist.labels = shadowing.clone();

    let mut summ = metric("latency_seconds", "summary", 2.0);
    summ.quantiles = Some(BTreeMap::from([("0.5".to_string(), 0.25)]));
    summ.labels = shadowing;

    let text = render_text(&[("compress".to_string(), vec![hist, summ])]);
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        for name in ["hook", "le", "quantile"] {
            // Count label-NAME occurrences, not substrings: `quantile=` contains `le=`.
            let n = line.matches(&format!("{{{name}=\"")).count()
                + line.matches(&format!(",{name}=\"")).count();
            assert!(
                n <= 1,
                "duplicate `{name}` makes the exposition unparseable: {line}"
            );
        }
    }
    // The renderer's own labels survive; the hook's shadowing copies are the ones dropped.
    assert!(text.contains(r#"hook="compress""#), "auto hook label kept");
    assert!(
        !text.contains(r#"hook="inner""#),
        "shadowing hook label dropped"
    );
    assert!(text.contains(r#"le="+Inf""#), "histogram bucket label kept");
    assert!(
        text.contains(r#"quantile="0.5""#),
        "summary quantile label kept"
    );
}
