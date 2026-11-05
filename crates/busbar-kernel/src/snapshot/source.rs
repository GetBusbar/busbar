// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

// Exclusive bins, with one final +Inf bin. These are not Prometheus cumulative buckets.
const REQUEST_BOUNDS_MS: [u64; 15] = [
    1, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000, 120_000,
];
const REQUEST_COUNT: &str = "busbar_request_phase_duration_count_total";
const REQUEST_SUM: &str = "busbar_request_phase_duration_sum_us_total";
const REQUEST_ERRORS: &str = "busbar_request_phase_errors_total";
const REQUEST_CLIENT_ERRORS: &str = "busbar_request_phase_client_errors_total";
const REQUEST_BIN: &str = "busbar_request_phase_duration_bin_total";
// The bank itself has 8192 histogram slots; bound this projection even for direct recorder users.
const REQUEST_SERIES_LIMIT: usize = 8192;
const DROP_REASONS: [&str; 4] = [
    "invalid_duration",
    "integer_overflow",
    "series_capacity",
    "boot_nonce_unavailable",
];

#[derive(Default)]
struct RequestDistribution {
    count: u64,
    errors: u64,
    client_errors: u64,
    sum_us: u64,
    bins: [u64; 16],
}

impl RequestDistribution {
    fn add(&mut self, seconds: f64, outcome: &str) -> Result<(), usize> {
        // Quantize the existing measured f64 seconds by truncating to whole microseconds. This
        // does not claim more precision than the input. u64::MAX rounds UP to 2^64 as f64: reject
        // equality too, rather than accepting Rust's saturating float-to-integer cast.
        if !matches!(outcome, "ok" | "exhausted" | "client_error" | "error") {
            return Err(0);
        }
        let micros = seconds * 1_000_000.0;
        if !seconds.is_finite() || seconds < 0.0 || micros >= u64::MAX as f64 {
            return Err(0);
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let micros = micros as u64;
        let count = self.count.checked_add(1).ok_or(1usize)?;
        let sum_us = self.sum_us.checked_add(micros).ok_or(1usize)?;
        let bin = REQUEST_BOUNDS_MS.partition_point(|bound| micros > bound * 1000);
        // bin <= count, so the successful count increment also proves this cannot overflow.
        self.bins[bin] += 1;
        self.count = count;
        self.sum_us = sum_us;
        // These subsets cannot overflow after the successful total-count increment. Both are
        // disjoint: errors is exhausted/error; client_errors is the existing client_error outcome.
        self.errors += u64::from(matches!(outcome, "exhausted" | "error"));
        self.client_errors += u64::from(outcome == "client_error");
        Ok(())
    }

    fn put(&self, out: &mut Building, key: &Key, nonce: &str) {
        let mut labels: Vec<_> = key.labels().cloned().collect();
        labels.push(metrics::Label::new("process_boot_nonce", nonce.to_owned()));
        for (name, value) in [
            (REQUEST_COUNT, self.count),
            (REQUEST_SUM, self.sum_us),
            (REQUEST_ERRORS, self.errors),
            (REQUEST_CLIENT_ERRORS, self.client_errors),
        ] {
            put(
                out,
                SCRAPE_KIND_COUNTER,
                &Key::from_parts(name, labels.clone()),
                vec![("", None, value.to_string())],
            );
        }
        for (i, value) in self.bins.iter().enumerate() {
            let bound = REQUEST_BOUNDS_MS
                .get(i)
                .map_or_else(|| "+Inf".to_string(), u64::to_string);
            let mut labels = labels.clone();
            labels.push(metrics::Label::new("upper_bound_ms", bound));
            put(
                out,
                SCRAPE_KIND_COUNTER,
                &Key::from_parts(REQUEST_BIN, labels),
                vec![("", None, value.to_string())],
            );
        }
    }
}

#[derive(Default)]
struct RequestDistributions {
    series: HashMap<Key, RequestDistribution>,
    dropped: [u64; 4],
}

impl RequestDistributions {
    fn add(&mut self, key: &Key, seconds: f64, outcome: &str, nonce_available: bool) {
        let reason = if !nonce_available {
            Some(3)
        } else if !self.series.contains_key(key) && self.series.len() >= REQUEST_SERIES_LIMIT {
            Some(2)
        } else {
            self.series
                .entry(key.clone())
                .or_default()
                .add(seconds, outcome)
                .err()
        };
        if let Some(reason) = reason {
            self.dropped[reason] = self.dropped[reason].saturating_add(1);
        }
    }

    fn put(&self, out: &mut Building, nonce: Option<&str>) {
        if let Some(nonce) = nonce {
            for (key, distribution) in &self.series {
                distribution.put(out, key, nonce);
            }
        }
        for (reason, count) in DROP_REASONS.iter().zip(self.dropped) {
            if count != 0 {
                let key = Key::from_parts(
                    crate::telemetry::REQUEST_PHASE_DROPPED,
                    vec![metrics::Label::new("reason", *reason)],
                );
                put(
                    out,
                    SCRAPE_KIND_COUNTER,
                    &key,
                    vec![("", None, count.to_string())],
                );
            }
        }
    }
}

struct ProcessEpoch {
    nonce: Option<String>,
    started: Instant,
}

fn process_epoch() -> &'static ProcessEpoch {
    static EPOCH: OnceLock<ProcessEpoch> = OnceLock::new();
    EPOCH.get_or_init(|| {
        let mut bytes = [0u8; 16];
        ProcessEpoch {
            nonce: getrandom::fill(&mut bytes)
                .ok()
                .map(|()| hex::encode(bytes)),
            started: Instant::now(),
        }
    })
}

fn process_boot_nonce() -> Option<&'static str> {
    process_epoch().nonce.as_deref()
}

/// Process generation and monotonic milliseconds since telemetry initialization. The epoch is
/// established once when the recorder is constructed, and survives app/exporter reloads.
pub fn process_generation() -> Option<(&'static str, u64)> {
    let epoch = process_epoch();
    Some((
        epoch.nonce.as_deref()?,
        u64::try_from(epoch.started.elapsed().as_millis()).unwrap_or(u64::MAX),
    ))
}

/// Bounded internal admin projection, independent of the public SDK/ABI.
pub struct RequestSnapshot {
    pub process_boot_nonce: String,
    pub uptime_ms: u64,
    pub captured_at_unix_ms: u64,
    pub identities: Vec<RequestIdentity>,
    pub omitted_identities: u64,
    /// invalid_duration, integer_overflow, series_capacity, boot_nonce_unavailable,
    /// histogram_capacity, unregistered_labels. The last two are independent atomic reads;
    /// coherence is guaranteed for each identity's count/sum/bins, not all drop counters.
    pub dropped: [u64; 6],
}

pub struct RequestIdentity {
    pub plane: String,
    pub phase: String,
    pub pool: String,
    pub ingress_protocol: String,
    pub count: u64,
    /// Existing exhausted/error outcomes; excludes client_error.
    pub errors: u64,
    pub client_errors: u64,
    pub sum_us: u64,
    pub bins: [u64; 16],
}

fn unix_millis(time: SystemTime) -> Option<u64> {
    u64::try_from(time.duration_since(UNIX_EPOCH).ok()?.as_millis()).ok()
}

fn request_labels(key: &Key) -> Option<[&str; 4]> {
    let mut values = [None; 4];
    for label in key.labels() {
        let index = ["plane", "phase", "pool", "ingress_protocol"]
            .iter()
            .position(|name| *name == label.key())?;
        if label.value().len() > 256 || values[index].replace(label.value()).is_some() {
            return None;
        }
    }
    let values = [values[0]?, values[1]?, values[2]?, values[3]?];
    matches!(values[1], "LlmProducerDrive" | "MountedResponseReady").then_some(values)
}

pub struct Source {
    registry: Registry<Key, GenerationalStorage<Stamped>>,
    help: Mutex<HashMap<String, String>>,
    distributions: Mutex<HashMap<Key, Rolling>>,
    request_distributions: Mutex<RequestDistributions>,
    process_boot_nonce: Option<&'static str>,
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
            request_distributions: Mutex::default(),
            process_boot_nonce: process_boot_nonce(),
            gauges_seen: Mutex::default(),
            width,
            buckets: buckets.get(),
            gauge_idle,
        }
    }

    pub fn drain(&self) {
        let mut dists = lock(&self.distributions);
        let mut requests = lock(&self.request_distributions);
        for (key, h) in self.registry.get_histogram_handles() {
            if key.name() == crate::telemetry::REQUEST_PHASE_DURATION {
                let outcome = key
                    .labels()
                    .find(|label| label.key() == "outcome")
                    .map_or("", |label| label.value());
                // Each outcome has a bounded bank slot, but all outcomes fold into one cohort.
                let cohort = Key::from_parts(
                    crate::telemetry::REQUEST_PHASE_DURATION,
                    key.labels()
                        .filter(|label| label.key() != "outcome")
                        .cloned()
                        .collect::<Vec<_>>(),
                );
                h.get_inner().0.clear_with(|xs| {
                    for &(seconds, _) in xs {
                        requests.add(&cohort, seconds, outcome, self.process_boot_nonce.is_some());
                    }
                });
                continue;
            }
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
        // One captured set supplies count, sum, and all exclusive bins, even while another
        // exporter drains concurrently. Rolling-window expiration never affects these totals.
        lock(&self.request_distributions).put(&mut out, self.process_boot_nonce);
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

    /// Select at most 32 stable lexical identities without constructing the generic scrape.
    pub fn request_snapshot(&self, limit: usize) -> Option<RequestSnapshot> {
        self.process_boot_nonce?;
        self.drain();
        let state = lock(&self.request_distributions);
        let captured_at_unix_ms = unix_millis(SystemTime::now())?;
        let limit = limit.min(32);
        let mut selected: Vec<([&str; 4], &RequestDistribution)> = Vec::with_capacity(limit);
        for (key, distribution) in &state.series {
            let Some(labels) = request_labels(key) else {
                continue;
            };
            let position = selected
                .binary_search_by(|(held, _)| held.cmp(&labels))
                .unwrap_or_else(|i| i);
            if position < limit {
                if selected.len() == limit {
                    selected.pop();
                }
                selected.insert(position, (labels, distribution));
            }
        }
        let (nonce, uptime_ms) = process_generation()?;
        let bank_dropped = crate::telemetry::request_phase_dropped();
        Some(RequestSnapshot {
            process_boot_nonce: nonce.to_string(),
            uptime_ms,
            captured_at_unix_ms,
            omitted_identities: (state.series.len() - selected.len()) as u64,
            dropped: [
                state.dropped[0],
                state.dropped[1],
                state.dropped[2],
                state.dropped[3],
                bank_dropped[0],
                bank_dropped[1],
            ],
            identities: selected
                .into_iter()
                .map(|(labels, d)| RequestIdentity {
                    plane: labels[0].to_string(),
                    phase: labels[1].to_string(),
                    pool: labels[2].to_string(),
                    ingress_protocol: labels[3].to_string(),
                    count: d.count,
                    errors: d.errors,
                    client_errors: d.client_errors,
                    sum_us: d.sum_us,
                    bins: d.bins,
                })
                .collect(),
        })
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

#[cfg(test)]
#[path = "../tests/request_distribution_tests.rs"]
mod request_distribution_tests;
