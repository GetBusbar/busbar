use super::*;
use std::collections::BTreeMap;

fn render_text(hooks: &[(String, Vec<HookMetric>)]) -> String {
    crate::test_support::export_axis::lines(&families_of(hooks))
}

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

#[test]
fn counter_renders_with_hook_label_and_verbatim_name() {
    let m = HookMetric {
        help: Some("tokens the hook saved".into()),
        labels: labels(&[("pool", "chat")]),
        ..metric("tokens_saved_total", "counter", 42.0)
    };
    let text = render_text(&[("compress".to_string(), vec![m])]);
    assert!(text.contains("# TYPE tokens_saved_total counter"), "{text}");
    assert!(
        text.contains("# HELP tokens_saved_total tokens the hook saved"),
        "{text}"
    );

    assert!(
        text.contains("tokens_saved_total{hook=\"compress\",pool=\"chat\"} 42\n"),
        "{text}"
    );
}

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
    let text = render_text(&[("compress".to_string(), vec![m])]);
    assert!(
        text.contains("# TYPE compress_latency_us summary"),
        "{text}"
    );
    assert!(
        text.contains("compress_latency_us{hook=\"compress\",pool=\"chat\",quantile=\"0.5\"} 18\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "compress_latency_us{hook=\"compress\",pool=\"chat\",quantile=\"0.99\"} 91\n"
        ),
        "{text}"
    );

    assert!(
        text.contains("compress_latency_us_count{hook=\"compress\",pool=\"chat\"} 1000\n"),
        "{text}"
    );
}

#[test]
fn histogram_with_buckets_renders_as_native_histogram() {
    let mut bs = BTreeMap::new();
    bs.insert("0.5".to_string(), 3.0);
    bs.insert("1".to_string(), 7.0);
    let m = HookMetric {
        buckets: Some(bs),
        labels: labels(&[("pool", "chat")]),
        ..metric("rewriter_compression_ratio", "histogram", 7.0)
    };
    let text = render_text(&[("compress".to_string(), vec![m])]);
    assert!(
        text.contains("# TYPE rewriter_compression_ratio histogram"),
        "buckets => histogram, not summary: {text}"
    );

    let lo = text
        .find("rewriter_compression_ratio_bucket{hook=\"compress\",pool=\"chat\",le=\"0.5\"} 3\n")
        .expect("0.5 bucket");
    let hi = text
        .find("rewriter_compression_ratio_bucket{hook=\"compress\",pool=\"chat\",le=\"1\"} 7\n")
        .expect("1 bucket");
    assert!(lo < hi, "buckets must be ascending by le: {text}");

    assert!(
        text.contains(
            "rewriter_compression_ratio_bucket{hook=\"compress\",pool=\"chat\",le=\"+Inf\"} 7\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("rewriter_compression_ratio_count{hook=\"compress\",pool=\"chat\"} 7\n"),
        "{text}"
    );
}

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

    assert!(text.contains("shared{hook=\"a\"} 1\n"), "{text}");
    assert!(
        !text.contains("hook=\"b\""),
        "conflicting-type entry dropped: {text}"
    );
}

#[test]
fn label_values_are_escaped() {
    let m = HookMetric {
        labels: labels(&[("k", "a\"b\\c")]),
        ..metric("x_total", "counter", 1.0)
    };
    let text = render_text(&[("h".to_string(), vec![m])]);
    assert!(text.contains(r#"k="a\"b\\c""#), "{text}");
}

fn unique_hook(base: &str) -> String {
    static TICKET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    format!(
        "{base}-{}",
        TICKET.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

#[test]
fn unique_hook_never_repeats() {
    let a = unique_hook("x");
    let b = unique_hook("x");
    assert_ne!(a, b, "two calls must never return the same name");
    assert!(a.starts_with("x-") && b.starts_with("x-"), "{a} / {b}");
}

#[test]
fn manufactured_collision_proves_the_shared_literal_hazard_and_the_fix() {
    use std::sync::{Arc, Barrier};

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

    let other_claim = InFlight::claim(&other).expect("a different hook claims independently");

    drop(first);
    let again = InFlight::claim(&busy).expect("the slot is free once the refresh finishes");
    drop(again);
    drop(other_claim);

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
            let n = line.matches(&format!("{{{name}=\"")).count()
                + line.matches(&format!(",{name}=\"")).count();
            assert!(
                n <= 1,
                "duplicate `{name}` makes the exposition unparseable: {line}"
            );
        }
    }

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
