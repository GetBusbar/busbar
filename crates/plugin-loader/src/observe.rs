// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::observe::{Envelope, PluginDiagnostic, PluginMetric};

pub trait PluginObserver: Send + Sync {
    /// An envelope's reported entries, verbatim: the JSON the plugin's reply carried.
    fn observe(
        &self,
        plugin: &str,
        kind: &str,
        metrics: &[serde_json::Value],
        diagnostics: &[serde_json::Value],
    );

    /// One metric an instance reported on its back-channel, off a family its Statement declares:
    /// the entry itself, in the published shape of an envelope's `metrics` entries. The observer
    /// treats it as it treats that entry's JSON form in a one-entry [`PluginObserver::observe`].
    fn metric(&self, plugin: &str, kind: &str, metric: PluginMetric);

    /// One diagnostic an instance raised on its back-channel: the entry itself, in the published
    /// shape of an envelope's `diagnostics` entries, treated as its JSON form in a one-entry
    /// [`PluginObserver::observe`] is.
    fn diagnostic(&self, plugin: &str, kind: &str, diagnostic: PluginDiagnostic);

    fn dropped(&self, observations: u64);

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

        _ => "fault",
    }
}

pub const INTAKE_BOUND: usize = 4096;

struct Observation {
    plugin: std::sync::Arc<str>,
    kind: &'static str,
    entries: Entries,

    #[cfg(test)]
    scope: u64,
}

/// What one observation carries to the observer: moved in, moved on, never copied.
enum Entries {
    /// An envelope's reported entries, as its reply carried them.
    Reported {
        metrics: Vec<serde_json::Value>,
        diagnostics: Vec<serde_json::Value>,
    },
    /// One back-channel metric. Boxed so an intake slot stays the size it was: the intake holds
    /// [`INTAKE_BOUND`] slots for as long as it runs.
    Metric(Box<PluginMetric>),
    /// One back-channel diagnostic, boxed for the same reason.
    Diagnostic(Box<PluginDiagnostic>),
}

struct Intake {
    tx: std::sync::mpsc::SyncSender<Observation>,

    counts: std::sync::Arc<IntakeCounts>,
}

/// What an intake has been handed, what its observer has had, and what it dropped not yet reported.
#[derive(Default)]
struct IntakeCounts {
    sent: std::sync::atomic::AtomicU64,
    done: std::sync::atomic::AtomicU64,
    dropped: std::sync::atomic::AtomicU64,
}

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
    pub fn install_observer(&self, observer: &'static dyn PluginObserver) -> bool {
        self.observer.set(observer).is_ok()
    }

    pub fn install_host_series(&self, is_host_series: fn(&str) -> bool) -> bool {
        self.host_series.set(is_host_series).is_ok()
    }

    pub fn refused(&self, kind: &str, instance: &str, refusal: BindRefusal<'_>) {
        if let Some(observer) = self.observer.get() {
            observer.refused(kind, instance, refusal);
        }
    }

    fn is_host_series(&self, name: &str) -> bool {
        self.host_series.get().is_some_and(|is| is(name))
    }

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
                        // A drop can land after the last queued item was handled, so the count is
                        // also reported when the wait for the next item times out.
                        loop {
                            let received = rx.recv_timeout(std::time::Duration::from_secs(1));
                            let disconnected = matches!(
                                received,
                                Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
                            );
                            let handled = received.is_ok();
                            if let Ok(o) = received {
                                #[cfg(test)]
                                testing::OBSERVING.store(o.scope, Ordering::SeqCst);
                                match o.entries {
                                    Entries::Reported {
                                        metrics,
                                        diagnostics,
                                    } => observer.observe(
                                        &o.plugin,
                                        o.kind,
                                        &metrics,
                                        &diagnostics,
                                    ),
                                    Entries::Metric(metric) => {
                                        observer.metric(&o.plugin, o.kind, *metric);
                                    }
                                    Entries::Diagnostic(diagnostic) => {
                                        observer.diagnostic(&o.plugin, o.kind, *diagnostic);
                                    }
                                }
                            }

                            let lost = c.dropped.swap(0, Ordering::AcqRel);
                            if lost > 0 {
                                observer.dropped(lost);
                            }
                            if handled {
                                c.done.fetch_add(1, Ordering::Release);
                            }
                            if disconnected {
                                break;
                            }
                        }
                    })
                    .map_err(|e| {
                        tracing::warn!(
                            error = %e,
                            "the plugin observation worker could not start; plugin metrics and diagnostics are lost"
                        );
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

    /// Hand one observation to the intake: its plugin name shared, its entries moved, never copied.
    fn enqueue(&self, plugin: &std::sync::Arc<str>, kind: &'static str, entries: Entries) {
        use std::sync::atomic::Ordering;
        let Some(intake) = self.intake() else {
            return;
        };
        let observation = Observation {
            plugin: std::sync::Arc::clone(plugin),
            kind,
            entries,
            #[cfg(test)]
            scope: testing::scope(),
        };

        intake.counts.sent.fetch_add(1, Ordering::AcqRel);
        if intake.tx.try_send(observation).is_err() {
            intake.counts.sent.fetch_sub(1, Ordering::AcqRel);
            intake.counts.dropped.fetch_add(1, Ordering::AcqRel);
        }
    }

    pub(crate) fn fold<R>(
        &self,
        plugin: &std::sync::Arc<str>,
        kind: &'static str,
        envelope: Envelope<R>,
    ) {
        if envelope.is_bare() {
            return;
        }
        self.enqueue(
            plugin,
            kind,
            Entries::Reported {
                metrics: envelope.metrics,
                diagnostics: envelope.diagnostics,
            },
        );
    }

    /// One back-channel metric, handed to the intake as the entry it is: no JSON is built here and
    /// none is parsed by the observer.
    pub(crate) fn fold_metric(
        &self,
        plugin: &std::sync::Arc<str>,
        kind: &'static str,
        metric: PluginMetric,
    ) {
        self.enqueue(plugin, kind, Entries::Metric(Box::new(metric)));
    }

    /// One back-channel diagnostic, handed to the intake as the entry it is.
    pub(crate) fn fold_diagnostic(
        &self,
        plugin: &std::sync::Arc<str>,
        kind: &'static str,
        diagnostic: PluginDiagnostic,
    ) {
        self.enqueue(plugin, kind, Entries::Diagnostic(Box::new(diagnostic)));
    }
}

#[cfg(test)]
pub(crate) fn settle() {
    use std::sync::atomic::Ordering;
    let live: Vec<_> = testing::INTAKES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter_map(std::sync::Weak::upgrade)
        .collect();
    // At least 10 s across every intake, as 1 ms polls counted rather than clocked.
    let mut polls = 10_000_u32;
    for counts in live {
        while counts.done.load(Ordering::Acquire) < counts.sent.load(Ordering::Acquire) && polls > 0
        {
            std::thread::sleep(std::time::Duration::from_millis(1));
            polls -= 1;
        }
    }
}

pub struct EnvelopeObserver {
    observing: std::sync::Arc<Observing>,
    plugin: std::sync::Arc<str>,
    kind: &'static str,
    families: Vec<busbar_contract::abi::mechanism::rendering::ReadFamily>,

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

    #[must_use]
    pub fn with_families(
        observing: std::sync::Arc<Observing>,
        plugin: &str,
        kind: &'static str,
        families: Vec<busbar_contract::abi::mechanism::rendering::ReadFamily>,
    ) -> Self {
        Self {
            observing,
            plugin: std::sync::Arc::from(plugin),
            kind,
            families,
            then: None,
        }
    }

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
        let mut metric = PluginMetric::new(&family.name, kind, m.value);
        for (key, value) in family.label_keys.iter().zip(m.labels) {
            metric = metric.label(key, String::from_utf8_lossy(value));
        }
        self.observing.fold_metric(&self.plugin, self.kind, metric);
    }

    fn diag(&self, d: crate::dispatch::Diagnostic<'_>) {
        use busbar_contract::abi::mechanism::call::{DIAG_LOG, DIAG_LOG_DROPPED};
        use busbar_contract::abi::mechanism::observe::DiagLevel;
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
        self.observing
            .fold_diagnostic(&self.plugin, self.kind, diagnostic);
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

/// What one plugin name was granted: its declared series, and how many of its first-party
/// instances hold the grant ([`SeriesGrant`]). A name is in the table exactly while one of its
/// first-party instances is live (THE DESIGN `docs/design/BUSBAR-1.6.0.md` §11.12 H2: a
/// per-instance host registry lets go with its instance).
#[derive(Debug, Default)]
struct Granted {
    holders: usize,
    series: Vec<busbar_contract::abi::mechanism::observe::SeriesDecl>,
}

static GRANTS: std::sync::RwLock<Option<foldhash::HashMap<busbar_contract::kept::Text, Granted>>> =
    std::sync::RwLock::new(None);

/// One first-party instance's hold on its plugin's grant ([`grant_series`]): dropped with the
/// instance, and the grant goes with its last holder. So a first-party plugin replaced by a third
/// party of the same name keeps no grant, and a series a removed plugin declared is free for the
/// plugin that replaces it, with no restart.
#[derive(Debug)]
#[must_use = "the grant lasts only while it is held"]
pub struct SeriesGrant {
    plugin: Option<busbar_contract::kept::Text>,
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
            return Err(crate::cold::observe::host_series_refused(plugin, &d.name));
        }
        let owner = grants
            .iter()
            .find(|(p, g)| *p != plugin && g.series.iter().any(|held| held.name == d.name));
        if let Some((owner, _)) = owner {
            return Err(crate::cold::observe::series_taken_refused(
                plugin, &d.name, owner,
            ));
        }
    }
    let name = busbar_contract::kept::off_path::text(plugin);
    let granted = grants.entry(name.clone()).or_default();
    granted.holders += 1;
    granted.series = declared.to_vec();
    Ok(SeriesGrant { plugin: Some(name) })
}

pub fn first_party(plugin: &str) -> bool {
    let guard = GRANTS.read().unwrap_or_else(|e| e.into_inner());
    guard.as_ref().is_some_and(|g| g.contains_key(plugin))
}

pub fn first_party_series(plugin: &str, name: &str, kind: &str) -> bool {
    let guard = GRANTS.read().unwrap_or_else(|e| e.into_inner());
    let granted = guard.as_ref().and_then(|g| g.get(plugin));
    granted.is_some_and(|g| g.series.iter().any(|d| d.name == name && d.kind == kind))
}

pub fn shed_series(plugin: &str) -> Vec<String> {
    crate::cold::observe::shed_series(plugin)
}

/// `read` over the series `plugin` was granted (none when it holds no grant), under the grants'
/// read lock.
pub(crate) fn with_granted_series<T>(
    plugin: &str,
    read: impl FnOnce(&[busbar_contract::abi::mechanism::observe::SeriesDecl]) -> T,
) -> T {
    let guard = GRANTS.read().unwrap_or_else(|e| e.into_inner());
    let granted = guard.as_ref().and_then(|g| g.get(plugin));
    read(granted.map_or(&[][..], |g| g.series.as_slice()))
}

#[cfg(test)]
pub(crate) mod testing {
    use super::PluginObserver;

    pub(crate) type Fold = (
        String,
        String,
        Vec<serde_json::Value>,
        Vec<serde_json::Value>,
    );

    pub(super) struct Recording;

    pub(super) static RECORDING: Recording = Recording;

    pub(super) static INTAKES: std::sync::Mutex<Vec<std::sync::Weak<super::IntakeCounts>>> =
        std::sync::Mutex::new(Vec::new());

    static FOLDS: std::sync::Mutex<Vec<(u64, Fold)>> = std::sync::Mutex::new(Vec::new());

    pub(crate) static OBSERVING: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    static NEXT_SCOPE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    std::thread_local! {
        /// THIS TEST'S SCOPE: the key its folds are filed and read under. `cargo test` runs each
        /// test on a thread of its own, and a back-channel is handed to the intake on the thread
        /// that reported it, so what a test's own sinks report carries its scope, and what every
        /// other test of the binary folds concurrently (any door it drives with a non-bare
        /// envelope, the guard serializing only the readers) carries another or none. Busbar
        /// Counting the whole log would include entries outside this sink's scope.
        static SCOPE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    pub(crate) fn scope() -> u64 {
        SCOPE.with(std::cell::Cell::get)
    }

    /// Files this thread's folds under `scope`: a thread a test spawns takes
    /// the test's scope from `scope()` so its folds are read back by it.
    pub(crate) fn enter(scope: u64) {
        SCOPE.with(|s| s.set(scope));
    }

    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(crate) static DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    pub(crate) static HOLD: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    pub(crate) type Refused = (String, String, String);

    static REFUSED: std::sync::Mutex<Vec<Refused>> = std::sync::Mutex::new(Vec::new());

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

        /// A back-channel metric, recorded as the one-entry fold its JSON form is.
        fn metric(
            &self,
            plugin: &str,
            kind: &str,
            metric: busbar_contract::abi::mechanism::observe::PluginMetric,
        ) {
            let entry = serde_json::to_value(metric).expect("a metric entry renders as JSON");
            self.observe(plugin, kind, &[entry], &[]);
        }

        /// A back-channel diagnostic, recorded as the one-entry fold its JSON form is.
        fn diagnostic(
            &self,
            plugin: &str,
            kind: &str,
            diagnostic: busbar_contract::abi::mechanism::observe::PluginDiagnostic,
        ) {
            let entry =
                serde_json::to_value(diagnostic).expect("a diagnostic entry renders as JSON");
            self.observe(plugin, kind, &[], &[entry]);
        }
    }

    pub(crate) fn observing() -> std::sync::Arc<super::Observing> {
        static ONE: std::sync::OnceLock<std::sync::Arc<super::Observing>> =
            std::sync::OnceLock::new();
        std::sync::Arc::clone(ONE.get_or_init(Default::default))
    }

    pub(crate) fn exclusive() -> std::sync::MutexGuard<'static, ()> {
        let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let fresh = NEXT_SCOPE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        SCOPE.with(|s| s.set(fresh));

        super::settle();
        FOLDS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        guard
    }

    pub(crate) fn clear(_held: &std::sync::MutexGuard<'static, ()>) {
        super::settle();
        FOLDS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    pub(crate) fn folds() -> Vec<Fold> {
        let mine = scope();
        assert_ne!(mine, 0, "read the fold log under an `exclusive` guard");

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
