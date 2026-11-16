// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin metrics: D_METRIC declarations and METRIC observations recorded under `kind` and `instance` (IF §12.17).
//!
//! Every kind's metrics are recorded as `<name>{kind=<kind word>, instance=<instance name>, <declared labels>}`.
//! There is no `plugin` label: no snapshot carries a stamp name, a module or a former name (I2). Series are keyed by
//! the configured instance **name**, so they survive a reconfigure. Each metric holds at most
//! [`MAX_LABEL_SETS`] label sets per instance; the excess is dropped and audited `plugin_metric_cardinality` once.
//! Hook metrics are served at SCOPE_HOOKS, every other kind's at SCOPE_METRICS. Summaries keep sum, count, min and
//! max. The decoder of METRIC records is `abi::host::decode_metrics` (H1); this module takes its decoded fields.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

use busbar_plugin_abi::records::metric::{
    MX_ADD, MX_COUNTER, MX_GAUGE, MX_OBSERVE, MX_SET, MX_SUMMARY,
};
use busbar_plugin_abi::types::KindCode;

use crate::snapshot::observe::{INSTANCE_LABEL, KIND_LABEL};

/// The most label sets one metric holds per instance (IF §12.17).
pub const MAX_LABEL_SETS: usize = 256;
/// The most label keys one declaration names.
pub(crate) const MAX_LABEL_KEYS: usize = 8;
/// The most bytes of one label value core keeps (cut at a char boundary).
pub(crate) const LABEL_VALUE_MAX: usize = 64;
/// The audit reason written the first time an instance's metric passes [`MAX_LABEL_SETS`].
pub(crate) const CARDINALITY_REASON: &str = "plugin_metric_cardinality";

/// Where a kind's metrics are served.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// SCOPE_METRICS: every kind but hook.
    Metrics,
    /// SCOPE_HOOKS: today's `/metrics/hooks`.
    Hooks,
}

impl Scope {
    #[must_use]
    pub fn of(kind: KindCode) -> Self {
        if kind == KindCode::Hook {
            Self::Hooks
        } else {
            Self::Metrics
        }
    }
}

/// One decoded D_METRIC item: `MetricDecl { id, kind }`, the name and the label keys.
#[derive(Clone, Copy, Debug)]
pub struct MetricDeclIn<'a> {
    pub id: u32,
    pub kind: u32,
    pub name: &'a str,
    pub label_keys: &'a [&'a str],
}

/// Why a describe's metric declarations were refused (the caller answers DescribeInvalid).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclareError {
    /// The name is not `[a-z_][a-z0-9_]{0,63}`.
    Name,
    /// `kind` is not MX_COUNTER, MX_GAUGE or MX_SUMMARY.
    Kind,
    /// More than `MAX_LABEL_KEYS` label keys.
    LabelCount,
    /// A label key is not `[a-z_][a-z0-9_]{0,63}`, or repeats.
    LabelKey,
    /// A label key is `kind` or `instance`, which core writes.
    ReservedLabel,
    /// Two declarations share an id.
    DuplicateId,
    /// Two declarations share a name.
    DuplicateName,
}

/// What became of one observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed {
    Recorded,
    /// No declaration has this id.
    Undeclared,
    /// The op does not fit the declared kind (ADD on a counter, SET on a gauge, OBSERVE on a summary).
    WrongOp,
    /// Not finite, or a negative counter increment.
    BadValue,
    /// The label values do not match the declared keys.
    LabelCount,
    /// A new label set past [`MAX_LABEL_SETS`]: dropped. `first` = this was the metric's first drop for the
    /// instance (the one that was audited).
    Capped {
        first: bool,
    },
}

/// One series' value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Value {
    Counter(f64),
    Gauge(f64),
    Summary {
        sum: f64,
        count: u64,
        min: f64,
        max: f64,
    },
}

/// One label set of a family: `kind`, `instance`, then the declared keys in order.
#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    pub labels: Vec<(String, String)>,
    pub value: Value,
}

/// One metric name of one type, across every instance in the scope.
#[derive(Clone, Debug, PartialEq)]
pub struct Family {
    pub name: String,
    /// MX_COUNTER, MX_GAUGE or MX_SUMMARY.
    pub kind: u32,
    pub samples: Vec<Sample>,
}

fn valid_word(s: &str) -> bool {
    let b = s.as_bytes();
    matches!(b.first(), Some(c) if c.is_ascii_lowercase() || *c == b'_')
        && b.len() <= 64
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

fn cut(value: &str) -> &str {
    if value.len() <= LABEL_VALUE_MAX {
        return value;
    }
    let mut at = LABEL_VALUE_MAX;
    while !value.is_char_boundary(at) {
        at -= 1;
    }
    &value[..at]
}

struct Series {
    kind: u32,
    keys: Box<[Box<str>]>,
    sets: BTreeMap<Box<[Box<str>]>, Value>,
    capped: bool,
}

#[derive(Default)]
struct Book {
    /// id -> metric name, from the current describe.
    ids: HashMap<u32, Box<str>>,
    /// name -> series, kept across describes while the name stays declared with the same kind and keys.
    series: BTreeMap<Box<str>, Series>,
}

/// One instance's metrics, by its configured name. The adapter keeps the `Arc` and records into it.
pub struct InstanceMetrics {
    kind: KindCode,
    name: Box<str>,
    book: Mutex<Book>,
}

impl InstanceMetrics {
    fn lock(&self) -> std::sync::MutexGuard<'_, Book> {
        self.book.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Installs a describe's declarations. A series whose name is still declared with the same kind and keys keeps
    /// its values (reconfigure); one that changed starts empty; one no longer declared is dropped. All or nothing:
    /// a refused list changes nothing.
    pub fn declare(&self, decls: &[MetricDeclIn<'_>]) -> Result<(), DeclareError> {
        check(decls)?;
        let mut book = self.lock();
        let mut old = std::mem::take(&mut book.series);
        book.ids.clear();
        for d in decls {
            let keys: Box<[Box<str>]> = d.label_keys.iter().map(|k| Box::from(*k)).collect();
            let series = match old.remove(d.name) {
                Some(s) if s.kind == d.kind && s.keys == keys => s,
                _ => Series {
                    kind: d.kind,
                    keys,
                    sets: BTreeMap::new(),
                    capped: false,
                },
            };
            book.ids.insert(d.id, d.name.into());
            book.series.insert(d.name.into(), series);
        }
        Ok(())
    }

    /// Records one METRIC observation: `MetricObs { id, op, value }` and the label values, in declared key order.
    pub fn observe(&self, id: u32, op: u32, value: f64, labels: &[&str]) -> Observed {
        let mut book = self.lock();
        let Book { ids, series } = &mut *book;
        let Some(series) = ids.get(&id).and_then(|name| series.get_mut(name)) else {
            return Observed::Undeclared;
        };
        let fits = matches!(
            (series.kind, op),
            (MX_COUNTER, MX_ADD) | (MX_GAUGE, MX_SET) | (MX_SUMMARY, MX_OBSERVE)
        );
        if !fits {
            return Observed::WrongOp;
        }
        if !value.is_finite() || (series.kind == MX_COUNTER && value < 0.0) {
            return Observed::BadValue;
        }
        if labels.len() != series.keys.len() {
            return Observed::LabelCount;
        }
        let set: Box<[Box<str>]> = labels.iter().map(|v| Box::from(cut(v))).collect();
        if !series.sets.contains_key(&set) && series.sets.len() >= MAX_LABEL_SETS {
            let first = !series.capped;
            series.capped = true;
            drop(book);
            if first {
                self.cardinality_capped(id);
            }
            return Observed::Capped { first };
        }
        let slot = series.sets.entry(set).or_insert(match series.kind {
            MX_COUNTER => Value::Counter(0.0),
            MX_GAUGE => Value::Gauge(0.0),
            _ => Value::Summary {
                sum: 0.0,
                count: 0,
                min: f64::INFINITY,
                max: f64::NEG_INFINITY,
            },
        });
        match slot {
            Value::Counter(v) => *v += value,
            Value::Gauge(v) => *v = value,
            Value::Summary {
                sum,
                count,
                min,
                max,
            } => {
                *sum += value;
                *count += 1;
                *min = min.min(value);
                *max = max.max(value);
            }
        }
        Observed::Recorded
    }

    #[cold]
    fn cardinality_capped(&self, id: u32) {
        let kind = self.kind.word();
        tracing::warn!(
            kind,
            instance = &*self.name,
            metric_id = id,
            max_label_sets = MAX_LABEL_SETS,
            "plugin metric passed its label-set cap; new label sets are dropped"
        );
        crate::audit::auditlog::record_plugin_refusal(
            crate::audit::auditlog::PluginRefusal::Op,
            kind,
            &self.name,
            CARDINALITY_REASON,
        );
    }
}

fn check(decls: &[MetricDeclIn<'_>]) -> Result<(), DeclareError> {
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for d in decls {
        if !valid_word(d.name) {
            return Err(DeclareError::Name);
        }
        if !matches!(d.kind, MX_COUNTER | MX_GAUGE | MX_SUMMARY) {
            return Err(DeclareError::Kind);
        }
        if d.label_keys.len() > MAX_LABEL_KEYS {
            return Err(DeclareError::LabelCount);
        }
        let mut keys = HashSet::new();
        for k in d.label_keys {
            if *k == KIND_LABEL || *k == INSTANCE_LABEL {
                return Err(DeclareError::ReservedLabel);
            }
            if !valid_word(k) || !keys.insert(*k) {
                return Err(DeclareError::LabelKey);
            }
        }
        if !ids.insert(d.id) {
            return Err(DeclareError::DuplicateId);
        }
        if !names.insert(d.name) {
            return Err(DeclareError::DuplicateName);
        }
    }
    Ok(())
}

/// Core's plugin metrics recorder: every instance's metrics, by (kind, configured instance name).
#[derive(Default)]
pub struct Recorder {
    instances: Mutex<Table>,
}

/// Every instance's metrics, by (kind, configured instance name).
type Table = HashMap<(KindCode, Box<str>), Arc<InstanceMetrics>>;

impl Recorder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Table> {
        self.instances
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The instance's metrics (cold: at open). The same name gets the same metrics across reconfigures.
    pub fn instance(&self, kind: KindCode, name: &str) -> Arc<InstanceMetrics> {
        Arc::clone(self.lock().entry((kind, name.into())).or_insert_with(|| {
            Arc::new(InstanceMetrics {
                kind,
                name: name.into(),
                book: Mutex::new(Book::default()),
            })
        }))
    }

    /// `instance` then `declare`.
    pub fn declare(
        &self,
        kind: KindCode,
        name: &str,
        decls: &[MetricDeclIn<'_>],
    ) -> Result<Arc<InstanceMetrics>, DeclareError> {
        check(decls)?;
        let metrics = self.instance(kind, name);
        metrics.declare(decls)?;
        Ok(metrics)
    }

    /// Drops an instance the operator removed from config (a reconfigure that keeps the name keeps its series).
    pub fn forget(&self, kind: KindCode, name: &str) {
        self.lock().remove(&(kind, name.into()));
    }

    /// Applies a reload (FU2, B32): keeps the series of every (kind, name) in `live`, whatever its config became, and
    /// drops every other instance's series at once, so the next scrape no longer carries them. A name dropped here
    /// and opened again later starts from zero. Equivalent to `forget` for each instance the reload no longer names.
    pub fn reconfigure(&self, live: &[(KindCode, &str)]) {
        self.lock()
            .retain(|(kind, name), _| live.iter().any(|(k, n)| k == kind && *n == &**name));
    }

    /// Every family in `scope`, ordered by name, then type; samples ordered by instance, then label values.
    #[must_use]
    pub fn snapshot(&self, scope: Scope) -> Vec<Family> {
        let mut instances: Vec<Arc<InstanceMetrics>> = self
            .lock()
            .values()
            .filter(|m| Scope::of(m.kind) == scope)
            .map(Arc::clone)
            .collect();
        instances.sort_by(|a, b| (a.kind.word(), &a.name).cmp(&(b.kind.word(), &b.name)));
        let mut families: BTreeMap<(String, u32), Vec<Sample>> = BTreeMap::new();
        for inst in &instances {
            let book = inst.lock();
            for (name, series) in &book.series {
                let samples = families
                    .entry((String::from(&**name), series.kind))
                    .or_default();
                for (values, value) in &series.sets {
                    let mut labels = Vec::with_capacity(2 + values.len());
                    labels.push((String::from(KIND_LABEL), String::from(inst.kind.word())));
                    labels.push((String::from(INSTANCE_LABEL), String::from(&*inst.name)));
                    for (k, v) in series.keys.iter().zip(values.iter()) {
                        labels.push((String::from(&**k), String::from(&**v)));
                    }
                    samples.push(Sample {
                        labels,
                        value: *value,
                    });
                }
            }
        }
        families
            .into_iter()
            .map(|((name, kind), samples)| Family {
                name,
                kind,
                samples,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HITS: MetricDeclIn<'static> = MetricDeclIn {
        id: 1,
        kind: MX_COUNTER,
        name: "hits_total",
        label_keys: &["route"],
    };

    fn sample<'a>(f: &'a [Family], name: &str) -> &'a Family {
        f.iter().find(|f| f.name == name).expect("family")
    }

    /// C-METRIC: declared metrics are labelled kind + instance, never plugin, and survive a reconfigure of the
    /// same instance name.
    #[test]
    fn declared_metrics_survive_reconfigure() {
        let r = Recorder::new();
        let m = r
            .declare(KindCode::Store, "main", &[HITS])
            .expect("declare");
        assert_eq!(m.observe(1, MX_ADD, 2.0, &["a"]), Observed::Recorded);
        let again = r
            .declare(KindCode::Store, "main", &[HITS])
            .expect("redeclare");
        assert!(Arc::ptr_eq(&m, &again));
        assert_eq!(again.observe(1, MX_ADD, 3.0, &["a"]), Observed::Recorded);
        let snap = r.snapshot(Scope::Metrics);
        let hits = sample(&snap, "hits_total");
        assert_eq!(hits.samples.len(), 1);
        assert_eq!(hits.samples[0].value, Value::Counter(5.0));
        assert_eq!(
            hits.samples[0].labels,
            vec![
                ("kind".into(), "store".into()),
                ("instance".into(), "main".into()),
                ("route".into(), "a".into()),
            ]
        );
        assert!(snap
            .iter()
            .flat_map(|f| &f.samples)
            .all(|s| s.labels.iter().all(|(k, _)| k != "plugin")));
    }

    /// A changed declaration starts the series empty; an undeclared one is gone.
    #[test]
    fn a_changed_declaration_resets_its_series() {
        let r = Recorder::new();
        let m = r
            .declare(KindCode::Store, "main", &[HITS])
            .expect("declare");
        m.observe(1, MX_ADD, 2.0, &["a"]);
        let gauge = MetricDeclIn {
            kind: MX_GAUGE,
            ..HITS
        };
        m.declare(&[gauge]).expect("redeclare");
        assert!(sample(&r.snapshot(Scope::Metrics), "hits_total")
            .samples
            .is_empty());
        m.declare(&[]).expect("nothing");
        assert!(r.snapshot(Scope::Metrics).is_empty());
    }

    /// `kind` and `instance` are core's labels: a declaration naming one is refused (DescribeInvalid).
    #[test]
    fn reserved_and_malformed_declarations_are_refused() {
        let r = Recorder::new();
        for (keys, want) in [
            (&["kind"][..], DeclareError::ReservedLabel),
            (&["instance"][..], DeclareError::ReservedLabel),
            (&["Bad"][..], DeclareError::LabelKey),
            (&["a", "a"][..], DeclareError::LabelKey),
            (
                &["a", "b", "c", "d", "e", "f", "g", "h", "i"][..],
                DeclareError::LabelCount,
            ),
        ] {
            let d = MetricDeclIn {
                label_keys: keys,
                ..HITS
            };
            assert_eq!(r.declare(KindCode::Auth, "x", &[d]).err(), Some(want));
        }
        let bad_name = MetricDeclIn {
            name: "9lives",
            ..HITS
        };
        assert_eq!(
            r.declare(KindCode::Auth, "x", &[bad_name]).err(),
            Some(DeclareError::Name)
        );
        let bad_kind = MetricDeclIn { kind: 9, ..HITS };
        assert_eq!(
            r.declare(KindCode::Auth, "x", &[bad_kind]).err(),
            Some(DeclareError::Kind)
        );
        let twin = MetricDeclIn {
            name: "other",
            ..HITS
        };
        assert_eq!(
            r.declare(KindCode::Auth, "x", &[HITS, twin]).err(),
            Some(DeclareError::DuplicateId)
        );
    }

    /// 256 label sets per metric per instance; the 257th is dropped, and only the first drop is audited.
    #[test]
    fn label_sets_are_capped_per_instance() {
        let r = Recorder::new();
        let m = r
            .declare(KindCode::Export, "out", &[HITS])
            .expect("declare");
        for i in 0..MAX_LABEL_SETS {
            let v = i.to_string();
            assert_eq!(m.observe(1, MX_ADD, 1.0, &[v.as_str()]), Observed::Recorded);
        }
        assert_eq!(
            m.observe(1, MX_ADD, 1.0, &["new"]),
            Observed::Capped { first: true }
        );
        assert_eq!(
            m.observe(1, MX_ADD, 1.0, &["newer"]),
            Observed::Capped { first: false }
        );
        assert_eq!(m.observe(1, MX_ADD, 1.0, &["0"]), Observed::Recorded);
        let other = r
            .declare(KindCode::Export, "out2", &[HITS])
            .expect("declare");
        assert_eq!(other.observe(1, MX_ADD, 1.0, &["new"]), Observed::Recorded);
        assert_eq!(
            sample(&r.snapshot(Scope::Metrics), "hits_total")
                .samples
                .len(),
            MAX_LABEL_SETS + 1
        );
    }

    /// Hook metrics are served at SCOPE_HOOKS only; summaries keep sum, count, min and max.
    #[test]
    fn hooks_scope_and_summaries() {
        let r = Recorder::new();
        let lat = MetricDeclIn {
            id: 4,
            kind: MX_SUMMARY,
            name: "latency_ms",
            label_keys: &[],
        };
        let h = r.declare(KindCode::Hook, "gate", &[lat]).expect("declare");
        for v in [3.0, 1.0, 8.0] {
            assert_eq!(h.observe(4, MX_OBSERVE, v, &[]), Observed::Recorded);
        }
        assert!(r.snapshot(Scope::Metrics).is_empty());
        let snap = r.snapshot(Scope::Hooks);
        assert_eq!(
            sample(&snap, "latency_ms").samples[0].value,
            Value::Summary {
                sum: 12.0,
                count: 3,
                min: 1.0,
                max: 8.0
            }
        );
    }

    /// Observations that do not fit their declaration are dropped, not recorded.
    #[test]
    fn misfit_observations_are_dropped() {
        let r = Recorder::new();
        let m = r
            .declare(KindCode::Secret, "vault", &[HITS])
            .expect("declare");
        assert_eq!(m.observe(2, MX_ADD, 1.0, &["a"]), Observed::Undeclared);
        assert_eq!(m.observe(1, MX_SET, 1.0, &["a"]), Observed::WrongOp);
        assert_eq!(m.observe(1, MX_ADD, -1.0, &["a"]), Observed::BadValue);
        assert_eq!(m.observe(1, MX_ADD, f64::NAN, &["a"]), Observed::BadValue);
        assert_eq!(m.observe(1, MX_ADD, 1.0, &[]), Observed::LabelCount);
        let long = "x".repeat(100);
        assert_eq!(
            m.observe(1, MX_ADD, 1.0, &[long.as_str()]),
            Observed::Recorded
        );
        let snap = r.snapshot(Scope::Metrics);
        assert_eq!(
            sample(&snap, "hits_total").samples[0].labels[2].1.len(),
            LABEL_VALUE_MAX
        );
    }
}
