// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S END of the plugin observability envelope (DECISIONS #85) — where *the plugin REPORTS;
//! the host VALIDATES, BOUNDS and DECIDES* stops being a sentence and becomes code.
//!
//! `plugin-loader` reads `{ result, metrics[], diagnostics[] }` off every plugin response and hands
//! the two arrays to whatever the host installed. This module is what the host installs.
//!
//! ## One validator, for every kind
//!
//! The entries are validated by [`crate::hooks::wire::parse_status_metrics`] — the SAME function,
//! not a copy of it. That function is the 1.5.5 hook validator, byte for byte: it caps entries at 64
//! and labels at 8, enforces `^[a-z][a-z0-9_]{0,63}$` on every name and label key, requires every
//! number to be finite, sanitizes and length-bounds every string, and DROPS a malformed entry whole
//! while its siblings survive. #85 says hook's path is the model; using the model means calling it,
//! not reimplementing it beside it.
//!
//! *(Its name still says `hook` because it still lives under `hooks::wire`. Moving it to a neutral
//! home is a rename owed once the hook module is folded — the hook kind is a 1.6.0 FUNCTIONAL FIXED
//! POINT, so relocating its code is a thing to do deliberately and not as a rider on this.)*
//!
//! ## What the host REFUSES, and why each refusal exists
//!
//! * **The reserved `busbar_` namespace.** A plugin metric whose name starts with `busbar_` is
//!   dropped, so no plugin can impersonate a first-party series or type-conflict with one. Lifted
//!   verbatim from `hooks::scrape`'s stated invariants.
//! * **An unregistered diagnostic code.** A `BUSBAR-NNNN` code is a PROMISE the host made — it
//!   resolves to a catalogue entry saying what the condition means and what to do. Only the host can
//!   make that promise, so a code the catalogue does not hold is dropped rather than logged with a
//!   banner that leads an operator nowhere.
//! * **Anything the validator drops.** Non-finite values, out-of-charset names, over-cap labels.
//!
//! ## Where this lives
//!
//! A submodule of [`crate::metrics`], because deciding what a plugin is allowed to have put into the
//! recorder is that module's business and this is installed from its `configure`. The file is at
//! `src/observe.rs` regardless — a module's home in the tree says what it belongs to; its home on
//! disk says nothing.
//!
//! ## Per-kind POLICY is the host's, and it is allowed to differ
//!
//! The ABI is uniform — every kind's response carries the same two arrays through the same seam.
//! What the host DOES with them is the host's decision, and #85 says so in those words. Today the
//! decision differs in exactly one place, and deliberately: see [`KernelPluginObserver::observe`]'s
//! `hook` arm, which stands down the METRICS fold for that kind — diagnostics fold for every kind.

use busbar_plugin_loader::observe::PluginObserver;

/// The provenance label every folded metric carries: which loaded plugin reported it.
///
/// Attached by the HOST from the loaded handle, never read off the wire, so a plugin can neither
/// omit it nor attribute its samples to a different plugin. Same role — and the same shape — as the
/// automatic `hook="<name>"` label `hooks::scrape` puts on every hook-reported series.
pub const PLUGIN_LABEL: &str = "plugin";

/// The metric-name prefix a plugin may not write into. See the module doc.
const RESERVED_PREFIX: &str = "busbar_";

/// Whether the host will expose a plugin-reported series under this NAME — the one rule, for both
/// ABI lanes.
///
/// It exists as a named function rather than as two inline checks because the COLD lane (a JSON
/// envelope, folded in [`fold_metrics`]) and the HOT lane (a plane calling the host's `metrics_emit`
/// slot) are two call conventions for one rule, and the rule is the thing #85 is about: a plugin
/// REPORTS, and the host decides what it is allowed to have said. Two copies of this predicate would
/// be two answers to "may a plugin write `busbar_http_requests_total`", and the lane a plugin
/// happened to use would decide which answer it got.
///
/// Rejects an empty name, a name outside `^[a-z][a-z0-9_]{0,63}$` (these become Prometheus
/// identifiers, so the charset is structural — it is also what stops a plugin holding a read-only
/// view of request content from smuggling it into a scrape), and anything in the reserved
/// [`RESERVED_PREFIX`] namespace.
pub(crate) fn admits_metric_name(name: &str) -> bool {
    crate::hooks::wire::valid_metric_name(name) && !name.starts_with(RESERVED_PREFIX)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE CARDINALITY BUDGET — the second question both lanes ask, after the name.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Distinct SERIES NAMES one plugin may register, for the life of the process.
///
/// A name check bounds what a series may be CALLED; it does not bound how MANY there are. A plugin
/// emitting `req_0_total`, `req_1_total`, … passes every charset rule ever written and still grows
/// the recorder's registry without limit — and a Prometheus registry never shrinks, so by the time
/// an operator notices, the memory is already gone and a restart is the only remedy. That is a
/// resource exhaustion reachable from an untrusted plugin, which is the class the dep-wall and the
/// capability-ABI exist to close everywhere else.
///
/// 64 is [`crate::hooks::wire::MAX_HOOK_METRICS`]'s number, deliberately: that is the per-reply cap a
/// hook has lived inside since 1.5.0, so it is a bound a real plugin has already been shown to fit.
pub(crate) const MAX_SERIES_PER_PLUGIN: usize = 64;

/// Distinct LABEL SETS one plugin may register under ONE series name.
///
/// The multiplicative half of the same problem: a bounded set of names with an unbounded set of
/// label values is the classic Prometheus cardinality explosion, and a plugin that labels by
/// request id gets there in one busy minute. 32 distinct dimensions of one series is generous for
/// the per-strategy / per-model breakdowns the label vocabulary exists for.
pub(crate) const MAX_LABEL_SETS_PER_SERIES: usize = 32;

/// One plugin's registered series and, per series, the label sets seen under it.
#[derive(Default)]
struct Budget {
    series: std::collections::HashMap<String, std::collections::HashSet<u64>>,
}

/// The host's cardinality ledger, keyed by the plugin the HOST attributed the sample to.
///
/// Process-global and never pruned on its own, and that is bounded by construction: plugins come
/// from the signed plugin directory, each holds at most
/// [`MAX_SERIES_PER_PLUGIN`] × [`MAX_LABEL_SETS_PER_SERIES`] eight-byte fingerprints, and the whole
/// structure is a few hundred kilobytes at the ceiling. (A `prune` on config reload, the shape
/// `hooks::scrape::prune_absent` already has, is OWED for the case of an operator churning plugin
/// NAMES across reloads — the ledger would retain a dead plugin's budget for the process lifetime.)
static LEDGER: std::sync::RwLock<Option<std::collections::HashMap<String, Budget>>> =
    std::sync::RwLock::new(None);

/// Fingerprint one label set, so the budget can count DISTINCT sets without keeping their bytes.
///
/// Takes BYTES, not a parsed map, because the two lanes present labels differently and only one of
/// them presents them in a form the host understands: the cold lane hands over a validated
/// `BTreeMap` (see [`fingerprint_pairs`]), while the hot lane hands over an opaque packed blob the
/// ABI explicitly says the host does not interpret. Bounding cardinality does not require
/// understanding the labels — only telling two label sets apart — so the hot lane gets its budget
/// enforced BEFORE its label encoding is designed, rather than after the first explosion.
///
/// `DefaultHasher` is right here and its instability across Rust releases is not a defect: nothing
/// persists a fingerprint, compares one across processes, or makes a decision from its value. A
/// collision costs one label set its own budget slot, never a refusal of a set that should pass.
fn fingerprint(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// Fingerprint a validated label map — the cold lane's form. Sorted already (`BTreeMap`), so the
/// canonical rendering below is order-stable and two identical label sets fingerprint identically
/// however the plugin ordered them on the wire.
fn fingerprint_pairs(labels: Option<&std::collections::BTreeMap<String, String>>) -> u64 {
    let Some(labels) = labels else {
        return fingerprint(&[]);
    };
    let mut canonical = String::new();
    for (k, v) in labels {
        canonical.push_str(k);
        canonical.push('\u{1}');
        canonical.push_str(v);
        canonical.push('\u{2}');
    }
    fingerprint(canonical.as_bytes())
}

/// **THE SECOND QUESTION, asked identically by both ABI lanes.** May `plugin` register a sample
/// under `series` with this label set?
///
/// `true` for a BOUNDED emitter, forever: a label set already inside the budget is admitted every
/// time it is seen, so a plugin that reports the same shape on every call never runs out. `false`
/// the moment a NEW series or a NEW label set would take it past a ceiling — and it stays `false`
/// for that new shape, rather than evicting an established one, because evicting would make a
/// well-behaved series flap in and out of the exposition to make room for a misbehaving one.
///
/// REFUSAL, not silent truncation. The hot lane returns the refusal to the plane as a status; the
/// cold lane cannot (the plugin has already answered), so [`fold_metrics`] says so in the operator's
/// log instead. Either way the operator learns that telemetry is being dropped, which is the thing a
/// silent cap never tells them.
pub(crate) fn admits_cardinality(plugin: &str, series: &str, label_fingerprint: u64) -> bool {
    let mut guard = LEDGER.write().unwrap_or_else(|e| e.into_inner());
    let ledger = guard.get_or_insert_with(std::collections::HashMap::new);
    // `entry` costs a `String` per call even when the plugin is already known. That is the honest
    // price of the borrow checker here — a `get_mut`-then-`insert` pair that avoided it is the
    // `map_entry` anti-pattern, and the two-branch version that satisfies both does not borrow-check
    // — and it is affordable: this runs on a telemetry fold, never on the request path.
    let budget = ledger.entry(plugin.to_string()).or_default();
    match budget.series.get_mut(series) {
        Some(sets) => {
            if sets.contains(&label_fingerprint) {
                return true;
            }
            if sets.len() >= MAX_LABEL_SETS_PER_SERIES {
                return false;
            }
            sets.insert(label_fingerprint);
            true
        }
        None => {
            if budget.series.len() >= MAX_SERIES_PER_PLUGIN {
                return false;
            }
            budget.series.insert(
                series.to_string(),
                std::iter::once(label_fingerprint).collect(),
            );
            true
        }
    }
}

/// Forget one plugin's budget.
///
/// `#[cfg(test)]` because nothing in production calls it YET, and an `allow(dead_code)` on a
/// production function is a claim that something will use it later, which nothing checks. What is
/// owed is the PRUNE named in [`LEDGER`]'s doc — the shape `hooks::scrape::prune_absent` already
/// has, run on config reload so a plugin removed or renamed stops holding a ceiling for the life of
/// the process. When that lands, this loses its attribute and gains a caller.
///
/// Until then it is what this module's own tests use to stay independent of one another: the ledger
/// is process-global by design, so a test that did not clear its plugin's budget would inherit
/// whatever a neighbour spent.
#[cfg(test)]
pub(crate) fn forget_cardinality(plugin: &str) {
    let mut guard = LEDGER.write().unwrap_or_else(|e| e.into_inner());
    if let Some(ledger) = guard.as_mut() {
        ledger.remove(plugin);
    }
}

/// The hot lane's entry to the budget: an OPAQUE packed label blob, fingerprinted without being
/// interpreted. See [`fingerprint`] for why that is enough.
pub(crate) fn admits_cardinality_opaque(plugin: &str, series: &str, labels: &[u8]) -> bool {
    admits_cardinality(plugin, series, fingerprint(labels))
}

/// The kernel's observer: validates what a plugin reported, bounds it, and folds it into THIS
/// process's recorder and diagnostics path.
///
/// Zero-sized. It holds no state because it owns none: the recorder it writes to is the
/// process-global one ([`crate::metrics`]) and the catalogue it resolves against is static.
pub struct KernelPluginObserver;

/// Install the kernel's observer into the loader. Idempotent-by-refusal — the first install wins;
/// returns whether THIS call was the one that installed it.
///
/// Called once at boot, BEFORE any plugin loads, so nothing a plugin reports during its own
/// construction is lost. Deliberately not gated on whether a metrics recorder is installed: the
/// recorder install is `export.prometheus`'s business, the `metrics` facade macros are a no-op
/// without one, and the DIAGNOSTICS half must work either way.
pub fn install() -> bool {
    busbar_plugin_loader::observe::install_plugin_observer(&KernelPluginObserver)
}

impl PluginObserver for KernelPluginObserver {
    fn observe(
        &self,
        plugin: &str,
        kind: &str,
        metrics: &[serde_json::Value],
        diagnostics: &[serde_json::Value],
    ) {
        // ── THE ONE PER-KIND POLICY DIFFERENCE, and it is a FREEZE, not an oversight. ──
        //
        // The hook kind reports its metrics through `status.metrics`, which `hooks::scrape` caches
        // per hook on a TTL and renders on the SEPARATE `/metrics/hooks` exposition. That path is
        // 1.5.5's, unchanged, and hooks are a 1.6.0 functional fixed point: their ABI may move,
        // their behaviour may not.
        //
        // A hook CAN now put samples on the envelope — the wire is uniform, that is the point — but
        // folding them here would give hook metrics a SECOND path with a DIFFERENT freshness (every
        // call, instead of once per TTL) and a DIFFERENT exposition (`/metrics`, not
        // `/metrics/hooks`). Either would be an observable behaviour change to a frozen kind. So the
        // host's decision for this kind is: the envelope's METRICS are carried and NOT folded. When
        // the freeze lifts, this arm is what changes — one place, named.
        //
        // The freeze is about metrics and covers nothing else. A hook's DIAGNOSTICS have no second
        // path — `hooks::scrape` knows no diagnostic, and a 1.5.5 hook had no way to raise one — so
        // silencing them here would not preserve any frozen behaviour, it would only drop the one
        // banner the host promises to look up and emit. They are folded for every kind, first.
        fold_diagnostics(plugin, diagnostics);
        if kind == busbar_plugin::cold::kind::HOOK {
            return;
        }
        fold_metrics(plugin, metrics);
    }
}

/// Validate, bound and emit one call's metrics into the process recorder.
///
/// A COUNTER is folded as a DELTA (`increment`), not as a level (`absolute`). That is the contract
/// `busbar_plugin_sdk::ExportHandler::drain_observations` states — a drain hands over what happened
/// since the last drain — and it is what makes the two builds of one plugin agree: a compiled-in
/// build and a dropped-in build both report increments, so the exposition is the sum of the same
/// events either way. Reading a counter as a level instead would make the last drain win and lose
/// every sample a slow scrape interval skipped over.
fn fold_metrics(plugin: &str, raw: &[serde_json::Value]) {
    if raw.is_empty() {
        return;
    }
    // THE ONE VALIDATOR (see the module doc). Everything after this line is working with entries
    // that are already name-checked, finite, bounded and sanitized.
    for m in crate::hooks::wire::parse_status_metrics(raw) {
        // THE FIRST-PARTY NAMESPACE (K9a S1): a series the loader GRANTED this plugin at open — a
        // first-party plugin's declared series, of its declared type — is the host's to render as
        // declared: it may be reserved, and it carries no provenance label.
        let granted = busbar_plugin_loader::observe::first_party_series(plugin, &m.name, &m.kind);
        if !granted && !admits_metric_name(&m.name) {
            // Reserved first-party namespace — a plugin cannot impersonate a `busbar_*` series.
            // (The charset half is already guaranteed by the validator; naming both through one
            // predicate is what keeps the two ABI lanes answering the same question.)
            continue;
        }
        // THE SECOND QUESTION (see `admits_cardinality`). A name check bounds what a series may be
        // CALLED; only this bounds how many there are, and a Prometheus registry never shrinks.
        if !admits_cardinality(plugin, &m.name, fingerprint_pairs(m.labels.as_ref())) {
            // The plugin has already answered, so there is no status to refuse it with — say so in
            // the operator's log instead, ONCE per plugin, because the whole failure mode is a
            // plugin emitting without limit and a per-sample line would be the same flood in
            // another channel.
            warn_cardinality_once(plugin, &m.name);
            continue;
        }
        let labels = labels_for((!granted).then_some(plugin), &m);
        match m.kind.as_str() {
            "counter" => {
                // A COUNTER DELTA CANNOT BE NEGATIVE, and the validator does not say so — it
                // guarantees finite, not non-negative. A plugin reporting `-1` is either confused or
                // probing; either way the answer is to drop the sample, never to wrap it into an
                // enormous positive delta, which is what an unguarded `as u64` does to a negative
                // float and which a dashboard reads as a counter reset plus a spike.
                if m.value < 0.0 {
                    continue;
                }
                // Saturating by construction: the guard above excludes the negative side and `as`
                // on a float clamps at the top, so an absurd claim costs that sample's accuracy and
                // nothing else.
                metrics::counter!(m.name.clone(), labels).increment(m.value as u64);
            }
            "gauge" => metrics::gauge!(m.name.clone(), labels).set(m.value),
            "histogram" => metrics::histogram!(m.name.clone(), labels).record(m.value),
            // `parse_status_metrics` admits exactly these three, so this is unreachable rather than
            // a silent drop — but written as a drop, because an unreachable arm that panics is a
            // plugin-triggered abort waiting for the day the validator's vocabulary widens.
            _ => {}
        }
    }
}

/// Plugins already warned about exceeding their cardinality budget — the latch behind
/// [`warn_cardinality_once`].
static WARNED: std::sync::RwLock<Option<std::collections::HashSet<String>>> =
    std::sync::RwLock::new(None);

/// Tell the operator ONCE per plugin that its telemetry is being refused, and name the series that
/// tripped it so they have somewhere to start. Latched because the condition that triggers it is,
/// by definition, a plugin emitting without limit.
fn warn_cardinality_once(plugin: &str, series: &str) {
    let mut guard = WARNED.write().unwrap_or_else(|e| e.into_inner());
    let warned = guard.get_or_insert_with(std::collections::HashSet::new);
    if !warned.insert(plugin.to_string()) {
        return;
    }
    tracing::warn!(
        plugin = %plugin,
        series = %series,
        max_series = MAX_SERIES_PER_PLUGIN,
        max_label_sets = MAX_LABEL_SETS_PER_SERIES,
        "plugin exceeded its metric cardinality budget; further new series or label sets from it \
         are refused (established ones keep reporting)"
    );
}

/// The label set for one folded sample: the host's provenance label first (none for a granted
/// first-party series), then the plugin's own.
///
/// A plugin label that would SHADOW the provenance one is dropped — charset validity is not
/// uniqueness, and a duplicate label name is a parse error that costs the whole scrape rather than
/// the one sample. Exactly the rule `hooks::scrape::render_labels` applies, and for exactly that
/// reason.
fn labels_for(plugin: Option<&str>, m: &crate::hooks::wire::HookMetric) -> Vec<metrics::Label> {
    let provenance = plugin.map(|p| metrics::Label::new(PLUGIN_LABEL, p.to_string()));
    let mut labels: Vec<metrics::Label> = provenance.into_iter().collect();
    if let Some(own) = &m.labels {
        for (k, v) in own {
            if k == PLUGIN_LABEL {
                continue;
            }
            labels.push(metrics::Label::new(k.clone(), v.clone()));
        }
    }
    labels
}

/// Resolve and emit one call's diagnostics.
///
/// A plugin NAMES a code; the host is what looks it up and emits it. A code the catalogue does not
/// hold is dropped: a `BUSBAR-NNNN` banner is a promise that pasting it into the docs lands on an
/// entry, and a plugin cannot be allowed to mint that promise.
fn fold_diagnostics(plugin: &str, raw: &[serde_json::Value]) {
    if raw.is_empty() {
        return;
    }
    for entry in raw.iter().take(MAX_PLUGIN_DIAGNOSTICS) {
        // Parsed per ENTRY, so one malformed diagnostic costs that diagnostic and not the batch —
        // the same fail-open discipline `parse_status_metrics` applies to a metric entry.
        let Ok(d) =
            serde_json::from_value::<busbar_plugin::cold::observe::PluginDiagnostic>(entry.clone())
        else {
            continue;
        };
        let Some(diag) = resolve_code(&d.code) else {
            continue;
        };
        // The message and every field value are plugin-controlled strings headed for an operator's
        // log, so they are sanitized and capped exactly as a metric's help text is. A plugin holding
        // a read-only view of request content must not be able to spill it into the log through a
        // diagnostic field.
        let message = crate::hooks::wire::sanitize_cap(&d.message, MAX_DIAG_MESSAGE_CHARS);
        let fields = d
            .fields
            .iter()
            .take(MAX_DIAG_FIELDS)
            .filter(|(k, _)| crate::hooks::wire::valid_metric_name(k))
            .map(|(k, v)| {
                format!(
                    "{k}={}",
                    crate::hooks::wire::sanitize_cap(v, MAX_DIAG_FIELD_CHARS)
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        // Emitted through `tracing` with the SAME `diag = "BUSBAR-NNNN"` field the in-tree
        // `diag_warn!` macro attaches, so a plugin's diagnostic is indistinguishable from a
        // first-party one in an operator's log pipeline — which is the point: the operator does not
        // care which object the code came out of, only what it means. The `plugin` field says which.
        //
        // The LEVEL is the plugin's claim, clamped by the catalogue: a plugin cannot report a
        // `BenignRecurring` condition at `error` and page somebody at 3am.
        let banner = diag.banner();
        match clamp_level(d.level, diag.severity) {
            busbar_plugin::cold::observe::DiagLevel::Error => {
                tracing::error!(diag = %banner, plugin = %plugin, fields = %fields, "{message}")
            }
            busbar_plugin::cold::observe::DiagLevel::Warn => {
                tracing::warn!(diag = %banner, plugin = %plugin, fields = %fields, "{message}")
            }
            busbar_plugin::cold::observe::DiagLevel::Info => {
                tracing::info!(diag = %banner, plugin = %plugin, fields = %fields, "{message}")
            }
            busbar_plugin::cold::observe::DiagLevel::Debug => {
                tracing::debug!(diag = %banner, plugin = %plugin, fields = %fields, "{message}")
            }
        }
    }
}

/// Per-response cap on diagnostics, the diagnostics twin of `MAX_HOOK_METRICS`. A plugin that raises
/// more than this many conditions in one call is not diagnosing, it is flooding.
const MAX_PLUGIN_DIAGNOSTICS: usize = 16;
/// Per-diagnostic caps on the operator-facing strings.
const MAX_DIAG_MESSAGE_CHARS: usize = 300;
/// Per-field value cap, the same bound a metric label value carries.
const MAX_DIAG_FIELD_CHARS: usize = 64;
/// Per-diagnostic cap on structured fields.
const MAX_DIAG_FIELDS: usize = 8;

/// Resolve a reported `BUSBAR-NNNN` code against the catalogue. `None` for anything that is not a
/// well-formed banner or is not registered.
fn resolve_code(code: &str) -> Option<&'static crate::diagnostics::Diagnostic> {
    let n: u16 = code.strip_prefix("BUSBAR-")?.parse().ok()?;
    crate::diagnostics::by_code(n)
}

/// Clamp a plugin's claimed level to what the catalogue says the condition is worth.
///
/// A `Fatal`/`Actionable` entry may be reported at any level the plugin likes; a `BenignRecurring`
/// one is capped at `debug`, because the catalogue has already decided that condition does not need
/// an operator. The level is a plugin's OPINION about its own severity, and an opinion that could
/// raise the catalogue's own classification would let a plugin page an operator by asserting it.
fn clamp_level(
    claimed: busbar_plugin::cold::observe::DiagLevel,
    severity: crate::diagnostics::Severity,
) -> busbar_plugin::cold::observe::DiagLevel {
    use crate::diagnostics::Severity;
    use busbar_plugin::cold::observe::DiagLevel;
    match severity {
        Severity::BenignRecurring => DiagLevel::Debug,
        Severity::Actionable | Severity::Fatal => claimed,
    }
}

#[cfg(test)]
#[path = "tests/observe_tests.rs"]
mod tests;
