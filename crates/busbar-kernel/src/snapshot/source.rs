// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

const QUANTILES: [f64; 7] = [0.0, 0.5, 0.9, 0.95, 0.99, 0.999, 1.0];

pub(super) const QUANTILE_LABEL: &str = "quantile";
const SUMMARY_SUM_SUFFIX: &str = "_sum";
const SUMMARY_COUNT_SUFFIX: &str = "_count";

pub struct Samples(AtomicBucket<(f64, Instant)>);

impl HistogramFn for Samples {
    fn record(&self, value: f64) {
        self.0.push((value, Instant::now()));
    }
}

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

fn sanitized(s: &str, colon: bool) -> String {
    let ok = |i: usize, c: char| {
        c.is_ascii_alphabetic() || c == '_' || (colon && c == ':') || (i > 0 && c.is_ascii_digit())
    };

    let mut out = zeroize::Zeroizing::new(String::with_capacity(s.len()));
    for (i, c) in s.chars().enumerate() {
        out.push(if ok(i, c) { c } else { '_' });
    }
    std::mem::take(&mut *out)
}

fn escaped(s: &str, quotes: bool) -> String {
    let capacity = s.len().checked_mul(2).expect("metric escape size overflow");
    let (mut out, mut held) = (
        zeroize::Zeroizing::new(String::with_capacity(capacity)),
        false,
    );
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
    std::mem::take(&mut *out)
}

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

struct Series {
    labels: Vec<(String, String)>,
    samples: Vec<Sample>,
}

impl Drop for Series {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.labels.zeroize();
    }
}

/// The families being built: by kind then displayed name, each series by its full raw recorder key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SnapshotName(String);

impl Drop for SnapshotName {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

type Building = BTreeMap<(u8, SnapshotName), BTreeMap<Key, Series>>;

fn put(out: &mut Building, kind: u8, key: &Key, lines: Vec<(&str, Option<String>, String)>) {
    let name = SnapshotName(sanitized(key.name(), true));
    let labels = zeroize::Zeroizing::new(labels_of(key));
    let samples = lines.into_iter().map(|(suffix, quantile, value)| {
        let mut sample_labels = (*labels).clone();
        sample_labels.extend(quantile.map(|q| (QUANTILE_LABEL.to_string(), q)));
        Sample {
            name: {
                let mut full =
                    zeroize::Zeroizing::new(String::with_capacity(name.0.len() + suffix.len()));
                full.push_str(&name.0);
                full.push_str(suffix);
                std::mem::take(&mut *full)
            },
            labels: sample_labels,
            value,
        }
    });
    let series = out.entry((kind, name.clone())).or_default();
    series.insert(
        key.clone(),
        Series {
            labels: (*labels).clone(),
            samples: samples.collect(),
        },
    );
}

impl Source {
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
            lines.push((SUMMARY_SUM_SUFFIX, None, d.sum.to_string()));
            lines.push((SUMMARY_COUNT_SUFFIX, None, d.count.to_string()));
            put(&mut out, SCRAPE_KIND_SUMMARY, key, lines);
        }
        let help = lock(&self.help);
        let family = |((kind, mut name), series): ((u8, SnapshotName), BTreeMap<Key, Series>)| {
            let mut series: Vec<_> = series.into_iter().collect();

            series.sort_by(|(a_key, a), (b_key, b)| {
                a.labels.cmp(&b.labels).then_with(|| a_key.cmp(b_key))
            });
            Family {
                help: help.get(&name.0).cloned(),
                name: std::mem::take(&mut name.0),
                unit: None,
                kind,
                samples: series
                    .into_iter()
                    .flat_map(|(_, mut s)| std::mem::take(&mut s.samples))
                    .collect(),
            }
        };
        out.into_iter().map(family).collect()
    }

    fn describe(&self, name: &KeyName, help: &str) {
        let mut all = lock(&self.help);
        let entry = all.entry(sanitized(name.as_str(), true));
        entry.or_insert_with(|| escaped(help, false));
    }
}

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
