// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OBSERVATION SOURCE: the process recorder every emit site writes through the `metrics`
//! facade, read in exactly one shape — the export kind's scrape snapshot ([`Family`]s, the whole
//! recorder, kind then name). The kernel renders no exposition: the snapshot is handed to the
//! export plugin whose sink carries the `metrics` stream, and the bytes an operator scrapes are that
//! plugin's (`crate::export::scrape`).
//!
//! What it keeps is 1.5.5's recorder, observation for observation: counters (`u64`) and gauges
//! (`f64`) as atomics; a gauge nothing re-sets for the idle window drops out (counters and
//! distributions never do); every histogram as a SUMMARY — the 1.5.5 quantiles over a rolling window
//! of `buckets` summaries `width` apart, plus the sum and count of every sample ever recorded. Each
//! value is spelled as the export ABI carries it (`ScrapeSample::value`, the number's own `Display`)
//! and each label value and HELP text escaped as the ABI's `Family` states.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use busbar_contract::abi::export::{SCRAPE_KIND_COUNTER, SCRAPE_KIND_GAUGE, SCRAPE_KIND_SUMMARY};
use busbar_contract::export_calls::{Family, Sample};
use metrics::atomics::AtomicU64;
use metrics::{Counter, Gauge, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder};
use metrics::{SharedString, Unit};
use metrics_util::registry::{Generation, GenerationalStorage, Registry, Storage};
use metrics_util::storage::{AtomicBucket, Summary};

/// The quantiles every distribution reports (1.5.5's set).
const QUANTILES: [f64; 7] = [0.0, 0.5, 0.9, 0.95, 0.99, 0.999, 1.0];

/// One histogram's samples, each stamped with when it was recorded, until a drain folds them into
/// its distribution's window.
pub struct Samples(AtomicBucket<(f64, Instant)>);

impl HistogramFn for Samples {
    fn record(&self, value: f64) {
        self.0.push((value, Instant::now()));
    }
}

/// Counters and gauges are atomics; a histogram holds its stamped samples.
pub struct Stamped;

impl<K> Storage<K> for Stamped {
    type Counter = Arc<AtomicU64>;
    type Gauge = Arc<AtomicU64>;
    type Histogram = Arc<Samples>;
    fn counter(&self, _: &K) -> Self::Counter {
        Arc::new(AtomicU64::new(0))
    }
    fn gauge(&self, _: &K) -> Self::Gauge {
        Arc::new(AtomicU64::new(0))
    }
    fn histogram(&self, _: &K) -> Self::Histogram {
        Arc::new(Samples(AtomicBucket::new()))
    }
}

/// One distribution: the window's summaries (newest first, each with when its span begins) and
/// the running count and sum of every sample, never reset.
#[derive(Default)]
struct Rolling {
    buckets: Vec<(Instant, Summary)>,
    count: u64,
    sum: f64,
}

impl Rolling {
    /// Count `v` and place it in the summary whose span holds `at`, opening one when none does
    /// (aligned to the newest span, the oldest dropped past `n`); a sample older than every span
    /// is counted and summed only.
    fn add(&mut self, v: f64, at: Instant, width: Duration, n: u32) {
        self.count += 1;
        self.sum += v;
        let mut spans = self
            .buckets
            .iter_mut()
            .take_while(|(b, _)| at <= *b + width);
        if let Some((_, s)) = spans.find(|(b, _)| at >= *b && at < *b + width) {
            s.add(v);
            return;
        }
        if let Some(cutoff) = at.checked_sub(width * n) {
            self.buckets.retain(|(b, _)| *b > cutoff);
        }
        let mut s = Summary::with_defaults();
        s.add(v);
        let Some(&(first, _)) = self.buckets.first() else {
            self.buckets.push((at, s));
            return;
        };
        if at > first {
            let mut begin = first + width;
            while at < begin || at >= begin + width {
                begin += width;
            }
            self.buckets.truncate(n as usize - 1);
            self.buckets.insert(0, (begin, s));
        }
    }

    /// The merged summary of the spans still inside the window at `now`.
    fn window(&self, now: Instant, width: Duration, n: u32) -> Summary {
        let cutoff = now.checked_sub(width * n);
        let mut acc = Summary::with_defaults();
        for (_, s) in self
            .buckets
            .iter()
            .filter(|(b, _)| cutoff.is_none_or(|c| *b > c))
        {
            acc.merge(s)
                .expect("every summary is built with the same parameters");
        }
        acc
    }
}

/// THE RECORDER: what the emit sites write, the HELP text they describe, the distributions the
/// drains fold, and when each gauge last moved.
pub struct Source {
    registry: Registry<Key, GenerationalStorage<Stamped>>,
    help: Mutex<HashMap<String, String>>,
    distributions: Mutex<HashMap<Key, Rolling>>,
    gauges_seen: Mutex<HashMap<Key, (Generation, Instant)>>,
    width: Duration,
    buckets: u32,
    gauge_idle: Duration,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A name or label key with every character outside the data model's set (`[a-zA-Z_]` first, then
/// also digits; `:` too in a metric name) replaced by `_`.
fn sanitized(s: &str, colon: bool) -> String {
    let ok = |i: usize, c: char| {
        c.is_ascii_alphabetic() || c == '_' || (colon && c == ':') || (i > 0 && c.is_ascii_digit())
    };
    s.chars()
        .enumerate()
        .map(|(i, c)| if ok(i, c) { c } else { '_' })
        .collect()
}

/// A label value (`quotes`) or HELP text escaped as 1.5.5's recorder wrote it: a line feed as
/// `\n`, a double quote in a label value as `\"`, and a backslash that escapes none of those
/// doubled.
fn escaped(s: &str, quotes: bool) -> String {
    let (mut out, mut held) = (String::with_capacity(s.len()), false);
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '"' if quotes => {
                held = false;
                out.push_str("\\\"");
            }
            '\\' => {
                if held {
                    out.push_str("\\\\");
                }
                held = !held;
            }
            c => {
                if std::mem::take(&mut held) {
                    out.push_str("\\\\");
                }
                out.push(c);
            }
        }
    }
    if held {
        out.push_str("\\\\");
    }
    out
}

/// A series' labels as the snapshot carries them: a key repeated keeps its first place and its
/// last value.
fn labels_of(key: &Key) -> Vec<(String, String)> {
    let mut labels: Vec<(&str, &str)> = Vec::new();
    for l in key.labels() {
        match labels.iter_mut().find(|(k, _)| *k == l.key()) {
            Some(e) => e.1 = l.value(),
            None => labels.push((l.key(), l.value())),
        }
    }
    let sanitize = |(k, v): (&str, &str)| (sanitized(k, false), escaped(v, true));
    labels.into_iter().map(sanitize).collect()
}

/// The families being built: by kind then name, each family's series by their labels.
type Building = BTreeMap<(u8, String), BTreeMap<Vec<(String, String)>, Vec<Sample>>>;

/// One series' lines: `(suffix, extra label, value)` each.
fn put(out: &mut Building, kind: u8, key: &Key, lines: Vec<(&str, Option<String>, String)>) {
    let name = sanitized(key.name(), true);
    let labels = labels_of(key);
    let samples = lines.into_iter().map(|(suffix, quantile, value)| {
        let mut labels = labels.clone();
        labels.extend(quantile.map(|q| ("quantile".to_string(), q)));
        Sample {
            name: format!("{name}{suffix}"),
            labels,
            value,
        }
    });
    let series = out.entry((kind, name.clone())).or_default();
    series.insert(labels.clone(), samples.collect());
}

impl Source {
    /// A recorder whose distributions roll over `buckets` spans of `width`, and whose gauges drop
    /// out after `gauge_idle` without a set.
    #[must_use]
    pub fn new(width: Duration, buckets: std::num::NonZeroU32, gauge_idle: Duration) -> Self {
        Source {
            registry: Registry::new(GenerationalStorage::new(Stamped)),
            help: Mutex::default(),
            distributions: Mutex::default(),
            gauges_seen: Mutex::default(),
            width,
            buckets: buckets.get(),
            gauge_idle,
        }
    }

    /// Fold every histogram's parked samples into its distribution (one is opened for a
    /// histogram that has none yet).
    pub fn drain(&self) {
        let mut dists = lock(&self.distributions);
        for (key, h) in self.registry.get_histogram_handles() {
            let d = dists.entry(key).or_default();
            let (width, n) = (self.width, self.buckets);
            h.get_inner()
                .0
                .clear_with(|xs| xs.iter().for_each(|&(v, at)| d.add(v, at, width, n)));
        }
    }

    /// Whether the gauge `key` at `gen` is still exported: a gauge seen at the same generation for
    /// longer than the idle window is deleted instead.
    fn fresh(&self, key: &Key, gen: Generation) -> bool {
        let now = Instant::now();
        let mut seen = lock(&self.gauges_seen);
        let Some((g, at)) = seen.get_mut(key) else {
            seen.insert(key.clone(), (gen, now));
            return true;
        };
        if *g != gen {
            (*g, *at) = (gen, now);
            return true;
        }
        let idle = now.duration_since(*at) > self.gauge_idle && self.registry.delete_gauge(key);
        if idle {
            seen.remove(key);
        }
        !idle
    }

    /// THE SNAPSHOT the export kind's `scrape` reads: every family, counters then gauges then
    /// summaries, by name within a kind, each family's series by their labels — a summary series
    /// as its quantiles, `_sum` and `_count`.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Family> {
        self.drain();
        let mut out = Building::new();
        for (key, c) in self.registry.get_counter_handles() {
            let v = c.get_inner().load(Ordering::Acquire).to_string();
            put(&mut out, SCRAPE_KIND_COUNTER, &key, vec![("", None, v)]);
        }
        for (key, g) in self.registry.get_gauge_handles() {
            if self.fresh(&key, g.get_generation()) {
                let v = f64::from_bits(g.get_inner().load(Ordering::Acquire)).to_string();
                put(&mut out, SCRAPE_KIND_GAUGE, &key, vec![("", None, v)]);
            }
        }
        let now = Instant::now();
        for (key, d) in lock(&self.distributions).iter() {
            let window = d.window(now, self.width, self.buckets);
            let at = |q: f64| window.quantile(q).unwrap_or(0.0).to_string();
            let mut lines: Vec<_> = QUANTILES.map(|q| ("", Some(q.to_string()), at(q))).into();
            lines.push(("_sum", None, d.sum.to_string()));
            lines.push(("_count", None, d.count.to_string()));
            put(&mut out, SCRAPE_KIND_SUMMARY, key, lines);
        }
        let help = lock(&self.help);
        let family = |((kind, name), series): ((u8, String), BTreeMap<_, Vec<Sample>>)| Family {
            help: help.get(&name).cloned(),
            name,
            unit: None,
            kind,
            samples: series.into_values().flatten().collect(),
        };
        out.into_iter().map(family).collect()
    }

    fn describe(&self, name: &KeyName, help: &str) {
        let mut all = lock(&self.help);
        let entry = all.entry(sanitized(name.as_str(), true));
        entry.or_insert_with(|| escaped(help, false));
    }
}

/// The process recorder is the one leaked [`Source`] (`crate::metrics::init_with`); a test drives a
/// leaked one of its own through `metrics::with_local_recorder`.
impl Recorder for &'static Source {
    fn describe_counter(&self, name: KeyName, _: Option<Unit>, help: SharedString) {
        self.describe(&name, &help);
    }
    fn describe_gauge(&self, name: KeyName, _: Option<Unit>, help: SharedString) {
        self.describe(&name, &help);
    }
    fn describe_histogram(&self, name: KeyName, _: Option<Unit>, help: SharedString) {
        self.describe(&name, &help);
    }
    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        let key = key.to_retained();
        self.registry
            .get_or_create_counter(&key, |c| c.clone().into())
    }
    fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
        let key = key.to_retained();
        self.registry
            .get_or_create_gauge(&key, |g| g.clone().into())
    }
    fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
        let key = key.to_retained();
        self.registry
            .get_or_create_histogram(&key, |h| h.clone().into())
    }
}

#[cfg(test)]
#[path = "../tests/metrics_source_tests.rs"]
mod tests;
