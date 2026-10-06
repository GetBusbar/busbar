// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HOST side of the uniform observability envelope (DECISIONS #85).
//!
//! Every plugin response is `{ result, metrics[], diagnostics[] }`. The plugin REPORTS; **the host
//! VALIDATES, BOUNDS and DECIDES.** This module is where the loader hands what a plugin reported to
//! whatever the host installed to decide about it — and it is the reason the arrangement is not just
//! "a plugin writes to a counter with extra steps".
//!
//! ## Why the loader does not decide
//!
//! The loader is host-side TCB, but it is not the engine: it has no metrics recorder, no diagnostics
//! catalogue, and no opinion about what a metric named `x_total` should become. Those live in the
//! kernel. So the loader collects, and the kernel INSTALLS a [`PluginObserver`] that validates and
//! folds. Exactly the shape `hostlog` already uses for the log bridge one module over: the
//! loader owns the crossing, the host owns the meaning.
//!
//! A host that installs nothing gets the safe behaviour: the back-channel is read off the wire and
//! DROPPED. That is what every existing test binary and `--validate` run does, and it is why adding
//! the envelope could not change what a non-engine caller of this crate observes.
//!
//! ## What a plugin can and cannot do through here
//!
//! It can SAY it observed something. It cannot make anything happen. The names, the values, the
//! label cardinality, the diagnostic codes and the strings are all a CLAIM the installed observer
//! is free to bound, rewrite or refuse — and the kernel's observer does refuse: a metric name in the
//! reserved `busbar_` namespace, a diagnostic code that is not in the catalogue, a non-finite value,
//! a label key outside the charset. None of that is reachable from the plugin's side.
//!
//! ## The #11 equivalence this makes true
//!
//! A COMPILED-IN plugin could always reach the process-global `metrics` recorder directly, while the
//! same crate built as a dropped-in `cdylib` links its OWN recorder and silently loses every
//! counter — so DECISIONS #11's "compiled-in ≡ dropped-in" was asserted and false for anything
//! observable. With reporting routed through here from BOTH builds, the two produce the same
//! exposition because they take the same path, not because anyone remembered to keep them in step.

use busbar_contract::abi::mechanism::observe::Envelope;

/// What the HOST does with what a plugin reported.
///
/// Implemented by the engine and installed once, at boot, via [`install_plugin_observer`]. Receives
/// the RAW entries exactly as they came off the wire — deliberately not parsed here, because
/// validating is the host's job and a loader that pre-parsed would be deciding which entries are
/// worth showing the thing whose job that is.
pub trait PluginObserver: Send + Sync {
    /// Fold one call's back-channel.
    ///
    /// `plugin` is the loaded plugin's display name (the provenance label every folded metric and
    /// diagnostic is attributed to — a plugin cannot forge it, because it never sends it). `kind` is
    /// the plugin kind bound at load, so the observer can apply a per-kind POLICY: the host DECIDES,
    /// and what it decides is allowed to differ between kinds even though the wire does not.
    ///
    /// Called on the host's ONE observer thread, never on the plugin call's: the call hands its
    /// back-channel to the bounded intake ([`INTAKE_BOUND`]) and returns at once (ARCHITECT ruling
    /// ENVELOPE-ALL 2026-10-03: the hot path never stalls on the observer).
    fn observe(
        &self,
        plugin: &str,
        kind: &str,
        metrics: &[serde_json::Value],
        diagnostics: &[serde_json::Value],
    );

    /// `observations` back-channels were DROPPED at the intake, which was full: the host counts
    /// them (its drop-count metric), never waits for room.
    fn dropped(&self, observations: u64);
}

/// The most back-channels the intake holds for the observer thread; past it a back-channel is
/// dropped and counted ([`PluginObserver::dropped`]), never waited on.
pub const INTAKE_BOUND: usize = 4096;

/// One call's back-channel, owned, on its way to the observer thread.
struct Observation {
    plugin: String,
    kind: String,
    metrics: Vec<serde_json::Value>,
    diagnostics: Vec<serde_json::Value>,
}

/// THE OBSERVER INTAKE: a bounded queue the plugin calls hand their back-channels to without
/// waiting, drained by one thread into the installed observer.
struct Intake {
    tx: std::sync::mpsc::SyncSender<Observation>,
    /// Back-channels queued, and back-channels the observer has had: equal once it caught up.
    sent: std::sync::atomic::AtomicU64,
    #[cfg_attr(not(test), allow(dead_code))]
    done: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Back-channels dropped at a full intake, not yet reported to the observer.
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

static INTAKE: std::sync::OnceLock<Option<Intake>> = std::sync::OnceLock::new();

/// The intake, started on first use once an observer is installed; `None` with no observer (the
/// back-channel is dropped, the safe state the module doc describes) or no thread to drain it.
fn intake() -> Option<&'static Intake> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    let observer = *OBSERVER.get()?;
    INTAKE
        .get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::sync_channel::<Observation>(INTAKE_BOUND);
            let done = Arc::new(AtomicU64::new(0));
            let dropped = Arc::new(AtomicU64::new(0));
            let (d, x) = (done.clone(), dropped.clone());
            std::thread::Builder::new()
                .name("busbar-plugin-observe".into())
                .spawn(move || {
                    for o in rx {
                        observer.observe(&o.plugin, &o.kind, &o.metrics, &o.diagnostics);
                        // Counted only after the observer had it: a back-channel dropped while
                        // this one was folded is reported here, the intake being full then.
                        let lost = x.swap(0, Ordering::AcqRel);
                        if lost > 0 {
                            observer.dropped(lost);
                        }
                        d.fetch_add(1, Ordering::Release);
                    }
                })
                .ok()?;
            Some(Intake {
                tx,
                sent: AtomicU64::new(0),
                done,
                dropped,
            })
        })
        .as_ref()
}

/// Hand one back-channel to the intake: queued when there is room, else dropped and counted. Never
/// blocks the calling plugin call.
fn enqueue(
    plugin: &str,
    kind: &str,
    metrics: &[serde_json::Value],
    diagnostics: &[serde_json::Value],
) {
    use std::sync::atomic::Ordering;
    let Some(intake) = intake() else {
        return;
    };
    let observation = Observation {
        plugin: plugin.to_string(),
        kind: kind.to_string(),
        metrics: metrics.to_vec(),
        diagnostics: diagnostics.to_vec(),
    };
    // Counted before the send: the observer thread may finish it before `try_send` returns.
    intake.sent.fetch_add(1, Ordering::AcqRel);
    if intake.tx.try_send(observation).is_err() {
        intake.sent.fetch_sub(1, Ordering::AcqRel);
        intake.dropped.fetch_add(1, Ordering::AcqRel);
    }
}

/// Wait (at most ten seconds) until the observer has had every back-channel queued so far: what a
/// reader of what the observer was handed waits for, the intake being asynchronous.
#[cfg(test)]
pub(crate) fn settle() {
    use std::sync::atomic::Ordering;
    let Some(Some(intake)) = INTAKE.get() else {
        return;
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while intake.done.load(Ordering::Acquire) < intake.sent.load(Ordering::Acquire)
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// The installed observer, or `None` — see the module doc for why "none" is a correct, safe state
/// rather than a misconfiguration.
///
/// A `&'static dyn` rather than an `Arc`: there is exactly one for the life of the process, it is
/// installed before any plugin loads, and a refcount bump per plugin call buys nothing.
static OBSERVER: std::sync::OnceLock<&'static dyn PluginObserver> = std::sync::OnceLock::new();

/// Install the host's observer. Idempotent-by-refusal: the FIRST install wins and a later one is
/// ignored, returning `false`.
///
/// `OnceLock` rather than a swappable cell on purpose, and the same posture the metrics recorder and
/// the push export sinks already take: a config apply that re-pointed where plugin telemetry went
/// mid-flight would make an exposition mean two different things across one scrape. Restart to
/// re-point.
pub fn install_plugin_observer(observer: &'static dyn PluginObserver) -> bool {
    OBSERVER.set(observer).is_ok()
}

/// Hand one decoded envelope's back-channel to the installed observer's intake, if any. A no-op when
/// the envelope is bare, so the common case costs one pair of `is_empty` checks and no call at all.
pub(crate) fn fold<R>(plugin: &str, kind: &str, envelope: &Envelope<R>) {
    if envelope.is_bare() {
        return;
    }
    enqueue(plugin, kind, &envelope.metrics, &envelope.diagnostics);
}

/// Hand already-decoded entries to the installed observer, if any: the memory ABI's envelope, made
/// the same JSON entries the cold wire carries ([`EnvelopeObserver`]).
pub(crate) fn fold_entries(
    plugin: &str,
    kind: &str,
    metrics: &[serde_json::Value],
    diagnostics: &[serde_json::Value],
) {
    if metrics.is_empty() && diagnostics.is_empty() {
        return;
    }
    enqueue(plugin, kind, metrics, diagnostics);
}

/// THE MEMORY ABI'S ENVELOPE, INTO THE HOST'S OBSERVABILITY (DECISIONS #85, OWNER-LOCKED: every
/// plugin response's metrics and diagnostics reach the host; ARCHITECT ruling ENVELOPE 2026-10-03).
/// The dispatcher ingests a door's envelope as checked entries that name the Statement by index
/// ([`crate::dispatch::Metric`], [`crate::dispatch::Diagnostic`]); this sink names them by what the
/// Statement declares — a metric by its family's name, kind and label keys, a diagnostic by its
/// declared id — and hands them to the installed [`PluginObserver`], the one fold every plugin's
/// back-channel takes, under the plugin's name and kind. A log record is not an observation: it goes
/// to the plugin's own log. EVERY door the dispatcher binds, of every kind, reports through one of
/// these, standing before the sink its binder gave ([`Self::before`]; ARCHITECT ruling ENVELOPE-ALL
/// 2026-10-03: #85 is uniform), so no binder can leave an envelope unobserved.
pub struct EnvelopeObserver {
    plugin: String,
    kind: &'static str,
    families: Vec<busbar_contract::abi::mechanism::rendering::ReadFamily>,
    /// The binder's own sink, handed every entry first (the plugin log, a kind's own reading).
    then: Option<std::sync::Arc<dyn crate::dispatch::EnvelopeSink>>,
}

impl std::fmt::Debug for EnvelopeObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvelopeObserver")
            .field("plugin", &self.plugin)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl EnvelopeObserver {
    /// The sink for `plugin`, of `kind`, whose Statement renders as `stated`. A rendering that does
    /// not read back names no family, so no metric of it is folded (the dispatcher already refused
    /// such a door at its load).
    #[must_use]
    pub fn of(plugin: &str, kind: &'static str, stated: &[u8]) -> Self {
        let families = busbar_contract::abi::mechanism::rendering::read(stated)
            .map(|r| r.families)
            .unwrap_or_default();
        Self::with_families(plugin, kind, families)
    }

    /// The sink for `plugin`, of `kind`, whose Statement declares `families`.
    #[must_use]
    pub fn with_families(
        plugin: &str,
        kind: &'static str,
        families: Vec<busbar_contract::abi::mechanism::rendering::ReadFamily>,
    ) -> Self {
        Self {
            plugin: plugin.to_string(),
            kind,
            families,
            then: None,
        }
    }

    /// [`Self::with_families`], handing every entry to `then` (the binder's sink) as well.
    #[must_use]
    pub fn before(
        then: std::sync::Arc<dyn crate::dispatch::EnvelopeSink>,
        plugin: &str,
        kind: &'static str,
        families: Vec<busbar_contract::abi::mechanism::rendering::ReadFamily>,
    ) -> Self {
        Self {
            then: Some(then),
            ..Self::with_families(plugin, kind, families)
        }
    }
}

impl crate::dispatch::EnvelopeSink for EnvelopeObserver {
    fn metric(&self, m: crate::dispatch::Metric<'_>) {
        use busbar_contract::abi::mechanism::door::{FAMILY_COUNTER, FAMILY_GAUGE};
        if let Some(then) = &self.then {
            then.metric(m);
        }
        let Some(family) = self.families.get(m.family as usize) else {
            return;
        };
        let kind = match family.kind {
            FAMILY_COUNTER => "counter",
            FAMILY_GAUGE => "gauge",
            _ => "histogram",
        };
        let mut metric = busbar_contract::abi::mechanism::observe::PluginMetric::new(
            &family.name,
            kind,
            m.value,
        );
        for (key, value) in family.label_keys.iter().zip(m.labels) {
            metric = metric.label(key, String::from_utf8_lossy(value));
        }
        let Ok(entry) = serde_json::to_value(metric) else {
            return;
        };
        fold_entries(&self.plugin, self.kind, &[entry], &[]);
    }

    fn diag(&self, d: crate::dispatch::Diagnostic<'_>) {
        use busbar_contract::abi::mechanism::call::{DIAG_LOG, DIAG_LOG_DROPPED};
        use busbar_contract::abi::mechanism::observe::{DiagLevel, PluginDiagnostic};
        if let Some(then) = &self.then {
            then.diag(d);
        }
        if d.id == DIAG_LOG || d.id == DIAG_LOG_DROPPED {
            return;
        }
        let level = match d.severity {
            0 => DiagLevel::Info,
            1 => DiagLevel::Warn,
            _ => DiagLevel::Error,
        };
        let diagnostic = PluginDiagnostic::new(
            String::from_utf8_lossy(d.name),
            level,
            String::from_utf8_lossy(d.text),
        );
        let Ok(entry) = serde_json::to_value(diagnostic) else {
            return;
        };
        fold_entries(&self.plugin, self.kind, &[], &[entry]);
    }

    fn dropped(&self, why: crate::dispatch::Dropped) {
        match &self.then {
            Some(then) => then.dropped(why),
            None => {
                tracing::debug!(plugin = %self.plugin, ?why, "a plugin envelope entry was dropped");
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE FIRST-PARTY METRIC NAMESPACE (K9a S1). A plugin's signed manifest DECLARES the series it
// emits (`declares.metrics`). The loader GRANTS those declarations at open to a first-party plugin
// — one admitted through the LINKED door, or dropped in and signed by the busbar release key — and
// the host's observer asks [`first_party_series`] per entry: a granted entry may use a reserved
// `busbar_*` name and renders as declared, without the `plugin=` label. Nothing is granted to any
// other plugin, which therefore keeps the envelope's rule whatever it declares.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The granted series, by the plugin's host-assigned name. Written at open, read per fold.
static GRANTS: std::sync::RwLock<
    Option<
        std::collections::HashMap<
            String,
            Vec<busbar_contract::abi::mechanism::observe::SeriesDecl>,
        >,
    >,
> = std::sync::RwLock::new(None);

/// The HOST's own series — installed once by the composition root, which is the one place that
/// names the host's metric catalog. A first-party claim on one of them is refused at open: two
/// writers of one series is a merge nobody could read back apart.
static HOST_SERIES: std::sync::OnceLock<fn(&str) -> bool> = std::sync::OnceLock::new();

/// Install the host's series predicate. The first install wins; a later one returns `false`.
pub fn install_host_series(is_host_series: fn(&str) -> bool) -> bool {
    HOST_SERIES.set(is_host_series).is_ok()
}

/// Grant `plugin`'s declared series, when it is `first_party`. A claim on a series the host
/// emits, or on one another plugin was already granted, is refused naming both; a plugin that is
/// not first-party is granted nothing (and refused nothing — it keeps today's rule).
pub fn grant_series(
    plugin: &str,
    first_party: bool,
    declared: &[busbar_contract::abi::mechanism::observe::SeriesDecl],
) -> Result<(), String> {
    if !first_party {
        return Ok(());
    }
    FIRST_PARTY
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(Default::default)
        .insert(plugin.to_string());
    if declared.is_empty() {
        return Ok(());
    }
    let is_host = HOST_SERIES.get().copied().unwrap_or(|_| false);
    let mut guard = GRANTS.write().unwrap_or_else(|e| e.into_inner());
    let grants = guard.get_or_insert_with(Default::default);
    for d in declared {
        if is_host(&d.name) {
            return Err(format!(
                "plugin '{plugin}' declares the series '{}', which the host itself emits",
                d.name
            ));
        }
        let owner = grants.iter().find(|(p, s)| *p != plugin && s.contains(d));
        if let Some((owner, _)) = owner {
            return Err(format!(
                "plugin '{plugin}' declares the series '{}', already granted to plugin '{owner}'",
                d.name
            ));
        }
    }
    grants.insert(plugin.to_string(), declared.to_vec());
    Ok(())
}

/// Every plugin opened FIRST-PARTY (linked door, or signed by the release key), by its
/// host-assigned name — recorded at open by [`grant_series`] whatever it declares (K9c).
static FIRST_PARTY: std::sync::RwLock<Option<std::collections::HashSet<String>>> =
    std::sync::RwLock::new(None);

/// Was `plugin` opened first-party? What the host's observer asks before it renders a
/// diagnostic the plugin raised as the host renders its own: the catalogue's line, no provenance
/// label (K9c — the first-party namespace of S1, for diagnostics).
pub fn first_party(plugin: &str) -> bool {
    let guard = FIRST_PARTY.read().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().is_some_and(|s| s.contains(plugin))
}

/// Is `name` of type `kind` a series granted to `plugin`? What the host's observer asks of each
/// reported entry before it applies the reserved-namespace rule and the `plugin=` label.
pub fn first_party_series(plugin: &str, name: &str, kind: &str) -> bool {
    let guard = GRANTS.read().unwrap_or_else(|e| e.into_inner());
    let granted = guard.as_ref().and_then(|g| g.get(plugin));
    granted.is_some_and(|s| s.iter().any(|d| d.name == name && d.kind == kind))
}

/// The counters granted to `plugin` as its SHED counters (K9b): its first-party declarations
/// marked `shed`, of type `counter` — what the host counts on when it sheds a delivery for it.
pub fn shed_series(plugin: &str) -> Vec<String> {
    let guard = GRANTS.read().unwrap_or_else(|e| e.into_inner());
    let granted = guard
        .as_ref()
        .and_then(|g| g.get(plugin))
        .into_iter()
        .flatten();
    let shed = granted.filter(|d| d.shed && d.kind == "counter");
    shed.map(|d| d.name.clone()).collect()
}

/// THE ONE recording observer for this crate's whole test binary.
///
/// It has to be one, and shared, because [`install_plugin_observer`] is deliberately a
/// process-global `OnceLock` — the engine installs exactly one observer for the life of the process
/// and a config apply may not re-point it mid-flight. A test module that installed its own would
/// therefore either win the race and silently blind every other module, or lose it and assert over
/// an empty log. Both failure modes look like a passing test.
///
/// So the recorder lives here, next to the seam it observes, and every test module that needs to see
/// what the host was handed goes through [`testing::exclusive`].
#[cfg(test)]
pub(crate) mod testing {
    use super::PluginObserver;

    /// One fold as the host received it: `(plugin, kind, metrics, diagnostics)`.
    pub(crate) type Fold = (
        String,
        String,
        Vec<serde_json::Value>,
        Vec<serde_json::Value>,
    );

    struct Recording;

    static FOLDS: std::sync::Mutex<Vec<Fold>> = std::sync::Mutex::new(Vec::new());
    /// Serializes the tests that read [`FOLDS`]. `cargo test` runs a binary's tests concurrently and
    /// the log is process-global, so without this a test reads its neighbour's folds — which is
    /// exactly what it looks like when the seam is broken, and therefore the one confusion a test
    /// about this seam must not have.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// What [`Recording`] was told was dropped at the intake.
    pub(crate) static DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// While set, [`Recording`] holds every back-channel it is handed until it is cleared: an
    /// observer slower than the plugins reporting to it.
    pub(crate) static HOLD: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    impl PluginObserver for Recording {
        fn dropped(&self, observations: u64) {
            DROPPED.fetch_add(observations, std::sync::atomic::Ordering::SeqCst);
        }

        fn observe(
            &self,
            plugin: &str,
            kind: &str,
            metrics: &[serde_json::Value],
            diagnostics: &[serde_json::Value],
        ) {
            while HOLD.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            FOLDS.lock().unwrap_or_else(|e| e.into_inner()).push((
                plugin.to_string(),
                kind.to_string(),
                metrics.to_vec(),
                diagnostics.to_vec(),
            ));
        }
    }

    /// Take EXCLUSIVE use of the fold log for the rest of the caller's test, installing the shared
    /// recorder on first use and clearing whatever a previous test left behind. Hold the returned
    /// guard for as long as you intend to read [`folds`].
    pub(crate) fn exclusive() -> std::sync::MutexGuard<'static, ()> {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            assert!(
                super::install_plugin_observer(&Recording),
                "the test binary's first install must win — something else installed an observer \
                 first and every fold assertion below would be reading an empty log"
            );
        });
        let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        // The intake is asynchronous: what an earlier test handed it lands before the log clears.
        super::settle();
        FOLDS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        guard
    }

    /// Forget the folds so far, for a holder of the [`exclusive`] guard whose setup folded.
    pub(crate) fn clear(_held: &std::sync::MutexGuard<'static, ()>) {
        super::settle();
        FOLDS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Every fold since the caller took its [`exclusive`] guard.
    pub(crate) fn folds() -> Vec<Fold> {
        // Everything handed to the intake so far has reached the observer before the log is read.
        super::settle();
        FOLDS.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[cfg(test)]
#[path = "tests/observe_tests.rs"]
mod tests;
