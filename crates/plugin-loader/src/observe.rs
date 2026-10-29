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
/// Implemented by the engine and installed once, at boot, on the dispatcher's [`Observing`]
/// ([`Observing::install_observer`]). Receives
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

    /// The host refused, or flagged, the instance `instance` of `kind` while it bound
    /// ([`BindRefusal`]): the host audits it on the plugin's behalf. Called at once on the binding
    /// thread, never through the intake: it is evidence, and the intake may drop.
    fn refused(&self, kind: &str, instance: &str, refusal: BindRefusal<'_>);
}

/// A REFUSAL THE HOST MADE WHILE AN INSTANCE BOUND (owner rule: every refusal is audited and
/// explained; nothing silent). Every word is the host's or one the plugin's Statement declared, so
/// nothing the plugin says at run time becomes structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindRefusal<'a> {
    /// The host's connection table refused the need at Statement index `need` when the instance
    /// declared it at `open` or `refresh`, for `reason`: `target_unresolved`, `program_malformed`,
    /// or the table's own word ([`conn_reason`]).
    Need {
        /// The need's Statement index.
        need: u32,
        /// Why, in one host word.
        reason: &'static str,
    },
    /// The instance's `open` or `refresh` answered with the diagnostic its Statement declares as
    /// `code`, at warn or error: it loaded, flagged.
    Open {
        /// The declared diagnostic id.
        code: &'a str,
    },
    /// Another op of the instance answered with the diagnostic its Statement declares as `code`,
    /// at ERROR: a refusal the plugin met while serving (an IdP destination it refused, say).
    Op {
        /// The declared diagnostic id.
        code: &'a str,
    },
}

/// A refusal of the host's connection table as one host word.
#[must_use]
pub const fn conn_reason(e: busbar_contract::conn::ConnError) -> &'static str {
    use busbar_contract::conn::ConnError;
    match e {
        ConnError::Pending => "pending",
        ConnError::Timeout => "timeout",
        ConnError::Closed => "closed",
        ConnError::NotOwner => "not_owner",
        ConnError::UndeclaredNeed => "undeclared",
        ConnError::Refused => "refused",
        ConnError::Fault => "fault",
        ConnError::Unarmed => "unarmed",
        ConnError::CredentialUnavailable => "credential_unavailable",
        ConnError::AuthRefused => "auth_refused",
        ConnError::AuthFailed => "auth_failed",
        // `ConnError` is non-exhaustive; a cause this host does not name is the host failing the
        // call, as the connection services answer it.
        _ => "fault",
    }
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
    /// The test that reported it ([`testing::scope`], read on the reporting thread): the test
    /// binary's one recorder files each fold under it.
    #[cfg(test)]
    scope: u64,
}

/// THE OBSERVER INTAKE: a bounded queue the plugin calls hand their back-channels to without
/// waiting, drained by one thread into the installed observer.
struct Intake {
    tx: std::sync::mpsc::SyncSender<Observation>,
    /// Back-channels queued, and back-channels the observer has had: equal once it caught up.
    counts: std::sync::Arc<IntakeCounts>,
}

/// What an intake has been handed, what its observer has had, and what it dropped not yet reported.
#[derive(Default)]
struct IntakeCounts {
    sent: std::sync::atomic::AtomicU64,
    #[cfg_attr(not(test), allow(dead_code))]
    done: std::sync::atomic::AtomicU64,
    dropped: std::sync::atomic::AtomicU64,
}

/// THE HOST'S OBSERVABILITY FOR ONE DISPATCHER: the observer the host installed on it, the host's
/// own series predicate, and the bounded intake that hands the observer every back-channel.
///
/// Held by the dispatcher ([`crate::dispatch::Dispatcher::observing`]) and reached by every door it
/// binds through that door's envelope sink, never through a process-global: the kernel installs
/// Rust code into no static seam of the loader (`door-only` static-seam rule, `BUSBAR-1.6.0.md`
/// l.1475-1478 and l.1543). The composition root installs onto the process's one dispatcher.
///
/// Installs are first-wins and one-way, the posture the metrics recorder and the push export sinks
/// take: a config apply that re-pointed where plugin telemetry went mid-flight would make an
/// exposition mean two different things across one scrape. Restart to re-point.
pub struct Observing {
    observer: std::sync::OnceLock<&'static dyn PluginObserver>,
    host_series: std::sync::OnceLock<fn(&str) -> bool>,
    intake: std::sync::OnceLock<Option<Intake>>,
}

impl std::fmt::Debug for Observing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observing")
            .field("observer", &self.observer.get().is_some())
            .field("host_series", &self.host_series.get().is_some())
            .finish_non_exhaustive()
    }
}

impl Default for Observing {
    /// Nothing installed: every back-channel is dropped, the safe state the module doc describes.
    /// In this crate's own test binary the shared recorder (`testing`) stands installed instead,
    /// so every dispatcher a test builds folds into the one log its readers serialize over.
    fn default() -> Self {
        let observing = Self {
            observer: std::sync::OnceLock::new(),
            host_series: std::sync::OnceLock::new(),
            intake: std::sync::OnceLock::new(),
        };
        #[cfg(test)]
        let _ = observing.observer.set(&testing::RECORDING);
        observing
    }
}

impl Observing {
    /// Install the host's observer. Idempotent-by-refusal: the FIRST install wins and a later one
    /// is ignored, returning `false`.
    pub fn install_observer(&self, observer: &'static dyn PluginObserver) -> bool {
        self.observer.set(observer).is_ok()
    }

    /// Install the host's series predicate (the composition root names the host's metric catalog).
    /// The first install wins; a later one returns `false`.
    pub fn install_host_series(&self, is_host_series: fn(&str) -> bool) -> bool {
        self.host_series.set(is_host_series).is_ok()
    }

    /// Hand a refusal the host made while `instance` of `kind` bound to the installed observer, at
    /// once ([`PluginObserver::refused`]). With none installed (a test binary, `--validate`) there is
    /// no chain to write it to.
    pub fn refused(&self, kind: &str, instance: &str, refusal: BindRefusal<'_>) {
        if let Some(observer) = self.observer.get() {
            observer.refused(kind, instance, refusal);
        }
    }

    /// Whether the host itself emits the series `name`: `false` with no predicate installed.
    fn is_host_series(&self, name: &str) -> bool {
        self.host_series.get().is_some_and(|is| is(name))
    }

    /// The intake, started on first use once an observer is installed; `None` with no observer
    /// (the back-channel is dropped) or no thread to drain it.
    fn intake(&self) -> Option<&Intake> {
        use std::sync::atomic::Ordering;
        use std::sync::Arc;
        let observer = *self.observer.get()?;
        self.intake
            .get_or_init(|| {
                let (tx, rx) = std::sync::mpsc::sync_channel::<Observation>(INTAKE_BOUND);
                let counts = Arc::new(IntakeCounts::default());
                let c = Arc::clone(&counts);
                std::thread::Builder::new()
                    .name("busbar-plugin-observe".into())
                    .spawn(move || {
                        for o in rx {
                            #[cfg(test)]
                            testing::OBSERVING.store(o.scope, Ordering::SeqCst);
                            observer.observe(&o.plugin, &o.kind, &o.metrics, &o.diagnostics);
                            // Counted only after the observer had it: a back-channel dropped while
                            // this one was folded is reported here, the intake being full then.
                            let lost = c.dropped.swap(0, Ordering::AcqRel);
                            if lost > 0 {
                                observer.dropped(lost);
                            }
                            c.done.fetch_add(1, Ordering::Release);
                        }
                    })
                    .ok()?;
                #[cfg(test)]
                testing::INTAKES
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(Arc::downgrade(&counts));
                Some(Intake { tx, counts })
            })
            .as_ref()
    }

    /// Hand one back-channel to the intake: queued when there is room, else dropped and counted.
    /// Never blocks the calling plugin call.
    fn enqueue(
        &self,
        plugin: &str,
        kind: &str,
        metrics: &[serde_json::Value],
        diagnostics: &[serde_json::Value],
    ) {
        use std::sync::atomic::Ordering;
        let Some(intake) = self.intake() else {
            return;
        };
        let observation = Observation {
            plugin: plugin.to_string(),
            kind: kind.to_string(),
            metrics: metrics.to_vec(),
            diagnostics: diagnostics.to_vec(),
            #[cfg(test)]
            scope: testing::scope(),
        };
        // Counted before the send: the observer thread may finish it before `try_send` returns.
        intake.counts.sent.fetch_add(1, Ordering::AcqRel);
        if intake.tx.try_send(observation).is_err() {
            intake.counts.sent.fetch_sub(1, Ordering::AcqRel);
            intake.counts.dropped.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Hand one decoded envelope's back-channel to the installed observer's intake, if any. A
    /// no-op when the envelope is bare, so the common case costs one pair of `is_empty` checks and
    /// no call at all.
    pub(crate) fn fold<R>(&self, plugin: &str, kind: &str, envelope: &Envelope<R>) {
        if envelope.is_bare() {
            return;
        }
        self.enqueue(plugin, kind, &envelope.metrics, &envelope.diagnostics);
    }

    /// Hand already-decoded entries to the installed observer, if any: the memory ABI's envelope,
    /// made the same JSON entries the cold wire carries ([`EnvelopeObserver`]).
    pub(crate) fn fold_entries(
        &self,
        plugin: &str,
        kind: &str,
        metrics: &[serde_json::Value],
        diagnostics: &[serde_json::Value],
    ) {
        if metrics.is_empty() && diagnostics.is_empty() {
            return;
        }
        self.enqueue(plugin, kind, metrics, diagnostics);
    }
}

/// Wait (at most ten seconds) until every intake's observer has had every back-channel queued so
/// far: what a reader of what the observer was handed waits for, the intake being asynchronous.
#[cfg(test)]
pub(crate) fn settle() {
    use std::sync::atomic::Ordering;
    let live: Vec<_> = testing::INTAKES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter_map(std::sync::Weak::upgrade)
        .collect();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    for counts in live {
        while counts.done.load(Ordering::Acquire) < counts.sent.load(Ordering::Acquire)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
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
    /// The host's observability of the dispatcher the door is bound on.
    observing: std::sync::Arc<Observing>,
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
    pub fn of(
        observing: std::sync::Arc<Observing>,
        plugin: &str,
        kind: &'static str,
        stated: &[u8],
    ) -> Self {
        let families = busbar_contract::abi::mechanism::rendering::read(stated)
            .map(|r| r.families)
            .unwrap_or_default();
        Self::with_families(observing, plugin, kind, families)
    }

    /// The sink for `plugin`, of `kind`, whose Statement declares `families`.
    #[must_use]
    pub fn with_families(
        observing: std::sync::Arc<Observing>,
        plugin: &str,
        kind: &'static str,
        families: Vec<busbar_contract::abi::mechanism::rendering::ReadFamily>,
    ) -> Self {
        Self {
            observing,
            plugin: plugin.to_string(),
            kind,
            families,
            then: None,
        }
    }

    /// [`Self::with_families`], handing every entry to `then` (the binder's sink) as well.
    #[must_use]
    pub fn before(
        observing: std::sync::Arc<Observing>,
        then: std::sync::Arc<dyn crate::dispatch::EnvelopeSink>,
        plugin: &str,
        kind: &'static str,
        families: Vec<busbar_contract::abi::mechanism::rendering::ReadFamily>,
    ) -> Self {
        Self {
            then: Some(then),
            ..Self::with_families(observing, plugin, kind, families)
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
        self.observing
            .fold_entries(&self.plugin, self.kind, &[entry], &[]);
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
        self.observing
            .fold_entries(&self.plugin, self.kind, &[], &[entry]);
    }

    fn refused(&self, instance: &str, refusal: BindRefusal<'_>) {
        self.observing.refused(self.kind, instance, refusal);
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

/// What one plugin name was granted: its declared series, and how many of its first-party
/// instances hold the grant ([`SeriesGrant`]). A name is in the table exactly while one of its
/// first-party instances is live (THE DESIGN `docs/design/BUSBAR-1.6.0.md` §11.12 H2: a
/// per-instance host registry lets go with its instance).
#[derive(Debug, Default)]
struct Granted {
    holders: usize,
    series: Vec<busbar_contract::abi::mechanism::observe::SeriesDecl>,
}

/// The granted series and the first-party names, by the plugin's host-assigned name. Written at
/// open and at an instance's last drop, read per fold.
static GRANTS: std::sync::RwLock<Option<std::collections::HashMap<String, Granted>>> =
    std::sync::RwLock::new(None);

/// One first-party instance's hold on its plugin's grant ([`grant_series`]): dropped with the
/// instance, and the grant goes with its last holder. So a first-party plugin replaced by a third
/// party of the same name keeps no grant, and a series a removed plugin declared is free for the
/// plugin that replaces it, with no restart.
#[derive(Debug)]
#[must_use = "the grant lasts only while it is held"]
pub struct SeriesGrant {
    plugin: Option<String>,
}

impl Drop for SeriesGrant {
    fn drop(&mut self) {
        let Some(plugin) = self.plugin.take() else {
            return;
        };
        let mut guard = GRANTS.write().unwrap_or_else(|e| e.into_inner());
        let Some(grants) = guard.as_mut() else {
            return;
        };
        if let Some(g) = grants.get_mut(&plugin) {
            g.holders = g.holders.saturating_sub(1);
            if g.holders == 0 {
                grants.remove(&plugin);
            }
        }
    }
}

/// Grant `plugin`'s declared series, when it is `first_party`, for as long as the returned
/// [`SeriesGrant`] is held (the instance's life). A claim on a series the host emits (the
/// predicate the composition root installed on `observing`, the one place that names the host's
/// metric catalog: two writers of one series is a merge nobody could read back apart), or on one
/// another LIVE plugin holds, is refused naming both; a plugin that is not first-party is granted
/// nothing (and refused nothing — it keeps today's rule).
pub fn grant_series(
    observing: &Observing,
    plugin: &str,
    first_party: bool,
    declared: &[busbar_contract::abi::mechanism::observe::SeriesDecl],
) -> Result<SeriesGrant, String> {
    if !first_party {
        return Ok(SeriesGrant { plugin: None });
    }
    let mut guard = GRANTS.write().unwrap_or_else(|e| e.into_inner());
    let grants = guard.get_or_insert_with(Default::default);
    for d in declared {
        if observing.is_host_series(&d.name) {
            return Err(format!(
                "plugin '{plugin}' declares the series '{}', which the host itself emits",
                d.name
            ));
        }
        let owner = grants
            .iter()
            .find(|(p, g)| *p != plugin && g.series.contains(d));
        if let Some((owner, _)) = owner {
            return Err(format!(
                "plugin '{plugin}' declares the series '{}', already granted to plugin '{owner}'",
                d.name
            ));
        }
    }
    let granted = grants.entry(plugin.to_string()).or_default();
    granted.holders += 1;
    granted.series = declared.to_vec();
    Ok(SeriesGrant {
        plugin: Some(plugin.to_string()),
    })
}

/// Is a FIRST-PARTY instance of `plugin` (linked door, or signed by the release key) live, by its
/// host-assigned name — granted at open by [`grant_series`] whatever it declares (K9c)? What the
/// host's observer asks before it renders a diagnostic the plugin raised as the host renders its
/// own: the catalogue's line, no provenance label (K9c — the first-party namespace of S1, for
/// diagnostics).
pub fn first_party(plugin: &str) -> bool {
    let guard = GRANTS.read().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().is_some_and(|g| g.contains_key(plugin))
}

/// Is `name` of type `kind` a series granted to `plugin`? What the host's observer asks of each
/// reported entry before it applies the reserved-namespace rule and the `plugin=` label.
pub fn first_party_series(plugin: &str, name: &str, kind: &str) -> bool {
    let guard = GRANTS.read().unwrap_or_else(|e| e.into_inner());
    let granted = guard.as_ref().and_then(|g| g.get(plugin));
    granted.is_some_and(|g| g.series.iter().any(|d| d.name == name && d.kind == kind))
}

/// The counters granted to `plugin` as its SHED counters (K9b): its first-party declarations
/// marked `shed`, of type `counter` — what the host counts on when it sheds a delivery for it.
pub fn shed_series(plugin: &str) -> Vec<String> {
    let guard = GRANTS.read().unwrap_or_else(|e| e.into_inner());
    let granted = guard
        .as_ref()
        .and_then(|g| g.get(plugin))
        .into_iter()
        .flat_map(|g| g.series.iter());
    let shed = granted.filter(|d| d.shed && d.kind == "counter");
    shed.map(|d| d.name.clone()).collect()
}

/// THE ONE recording observer for this crate's whole test binary.
///
/// It has to be one, and shared: every [`Observing`] this test binary builds (one per dispatcher)
/// stands with it installed, so a test reads what any door it bound folded, on whichever
/// dispatcher, in one log — and every test module that needs to see what the host was handed goes
/// through [`testing::exclusive`].
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

    pub(super) struct Recording;

    /// The recorder every [`super::Observing`] of this test binary stands with.
    pub(super) static RECORDING: Recording = Recording;

    /// Every intake this test binary started, for [`super::settle`].
    pub(super) static INTAKES: std::sync::Mutex<Vec<std::sync::Weak<super::IntakeCounts>>> =
        std::sync::Mutex::new(Vec::new());

    /// Every fold the recorder was handed, filed under the test that reported it (its scope).
    static FOLDS: std::sync::Mutex<Vec<(u64, Fold)>> = std::sync::Mutex::new(Vec::new());

    /// The scope of the observation the intake thread is handing the recorder now: set by that
    /// one thread before each `observe`, read inside it.
    pub(crate) static OBSERVING: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    /// The next test scope [`exclusive`] hands out; `0` is no test's.
    static NEXT_SCOPE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    std::thread_local! {
        /// THIS TEST'S SCOPE: the key its folds are filed and read under. `cargo test` runs each
        /// test on a thread of its own, and a back-channel is handed to the intake on the thread
        /// that reported it, so what a test's own sinks report carries its scope, and what every
        /// other test of the binary folds concurrently (any door it drives with a non-bare
        /// envelope, the guard serializing only the readers) carries another or none. Busbar
        /// status row 118: a reader that counted the whole log saw 10 where its sink folded 1.
        static SCOPE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    /// The calling thread's test scope (`0` outside an [`exclusive`] holder).
    pub(crate) fn scope() -> u64 {
        SCOPE.with(std::cell::Cell::get)
    }
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

    /// Every refusal [`Recording`] was handed: `(kind, instance, refusal)`, owned.
    pub(crate) type Refused = (String, String, String);

    /// Every refusal the recorder was handed, in order; a test reads its own by its instance label.
    static REFUSED: std::sync::Mutex<Vec<Refused>> = std::sync::Mutex::new(Vec::new());

    /// The refusals handed for `instance`, the refusal rendered with `{:?}`.
    pub(crate) fn refused(instance: &str) -> Vec<Refused> {
        REFUSED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(_, i, _)| i == instance)
            .cloned()
            .collect()
    }

    impl PluginObserver for Recording {
        fn dropped(&self, observations: u64) {
            DROPPED.fetch_add(observations, std::sync::atomic::Ordering::SeqCst);
        }

        fn refused(&self, kind: &str, instance: &str, refusal: super::BindRefusal<'_>) {
            REFUSED.lock().unwrap_or_else(|e| e.into_inner()).push((
                kind.to_string(),
                instance.to_string(),
                format!("{refusal:?}"),
            ));
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
            let scope = OBSERVING.load(std::sync::atomic::Ordering::SeqCst);
            FOLDS.lock().unwrap_or_else(|e| e.into_inner()).push((
                scope,
                (
                    plugin.to_string(),
                    kind.to_string(),
                    metrics.to_vec(),
                    diagnostics.to_vec(),
                ),
            ));
        }
    }

    /// THE TEST BINARY'S OWN [`super::Observing`], for a test that folds with no dispatcher.
    pub(crate) fn observing() -> std::sync::Arc<super::Observing> {
        static ONE: std::sync::OnceLock<std::sync::Arc<super::Observing>> =
            std::sync::OnceLock::new();
        std::sync::Arc::clone(ONE.get_or_init(Default::default))
    }

    /// Take EXCLUSIVE use of the fold log for the rest of the caller's test, giving the calling
    /// thread a fresh test scope ([`scope`]) and clearing whatever a previous test left behind.
    /// Hold the returned guard for as long as you intend to read [`folds`].
    pub(crate) fn exclusive() -> std::sync::MutexGuard<'static, ()> {
        let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fresh = NEXT_SCOPE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        SCOPE.with(|s| s.set(fresh));
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

    /// Every fold THIS TEST reported (its [`scope`]) since it took its [`exclusive`] guard, or last
    /// [`clear`]ed: never a fold another test of the binary reported meanwhile.
    pub(crate) fn folds() -> Vec<Fold> {
        let mine = scope();
        assert_ne!(mine, 0, "read the fold log under an `exclusive` guard");
        // Everything handed to the intake so far has reached the observer before the log is read.
        super::settle();
        FOLDS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(s, _)| *s == mine)
            .map(|(_, f)| f.clone())
            .collect()
    }
}

#[cfg(test)]
#[path = "tests/observe_tests.rs"]
mod tests;
