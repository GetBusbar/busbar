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

use busbar_plugin::cold::observe::Envelope;

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
    /// Called on the calling thread, inline, after the response decodes and before the `result` is
    /// handed back. Must not block: a slow observer is a slow plugin call.
    fn observe(
        &self,
        plugin: &str,
        kind: &str,
        metrics: &[serde_json::Value],
        diagnostics: &[serde_json::Value],
    );
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

/// Whether a host observer has been installed — for a boot cell that wants to say so, and for the
/// tests that prove the un-installed path drops rather than panics.
pub fn observer_installed() -> bool {
    OBSERVER.get().is_some()
}

/// Hand one decoded envelope's back-channel to the installed observer, if any. A no-op when the
/// envelope is bare, so the common case costs one pair of `is_empty` checks and no call at all.
pub(crate) fn fold<R>(plugin: &str, kind: &str, envelope: &Envelope<R>) {
    if envelope.is_bare() {
        return;
    }
    if let Some(obs) = OBSERVER.get() {
        obs.observe(plugin, kind, &envelope.metrics, &envelope.diagnostics);
    }
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

    impl PluginObserver for Recording {
        fn observe(
            &self,
            plugin: &str,
            kind: &str,
            metrics: &[serde_json::Value],
            diagnostics: &[serde_json::Value],
        ) {
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
    #[must_use]
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
        FOLDS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        guard
    }

    /// Every fold since the caller took its [`exclusive`] guard.
    pub(crate) fn folds() -> Vec<Fold> {
        FOLDS.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[cfg(test)]
#[path = "tests/observe_tests.rs"]
mod tests;
