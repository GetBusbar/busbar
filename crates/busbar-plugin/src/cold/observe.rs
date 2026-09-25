// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **uniform observability envelope** every plugin response rides in — DECISIONS #85.
//!
//! ## The defect this closes
//!
//! Before this module the export ABI was an effect-free ONE-WAY WIRE: [`crate::cold::export::ExportResponse::Delivered`]
//! is a UNIT variant, and the COLD tier has no host-callback vtable (that is HOT/plane only), so a
//! sink could not report the metrics it produced or the diagnostics it raised. Every real sink
//! produces host-side effects the wire could not carry — a file sink increments rotate/drop counters
//! and raises five registered diagnostics; a webhook sink's POST must ride the host's SSRF-guarded
//! egress; a prometheus sink renders a process-global recorder.
//!
//! **That was never an export problem.** The HOOK kind already had this back-channel — a hook's
//! `status` reply carries a raw `metrics` array the engine validates, bounds and folds into the
//! `/metrics/hooks` exposition. One kind having a back-channel and another not is exactly the
//! divergence DECISIONS #3 bans: *a plugin is a plugin — two universal rules, identical for every
//! kind*.
//!
//! ## The rule
//!
//! Every kind's response is [`Envelope`] = `{ result, metrics[], diagnostics[] }`. `result` is the
//! kind-specific answer (a `StoreResponse`, an `ExportResponse`, a `HookReply`, …); the other two
//! are UNIVERSAL and mean the same thing for every kind.
//!
//! **The plugin REPORTS; the host VALIDATES, BOUNDS and DECIDES.** A plugin never mutates a host
//! counter and never performs a host-owned effect (PART 4 Axis 3: the host always owns the
//! SSRF/pin/breaker/meter chokepoint). What a plugin puts here is a CLAIM. The host is what decides
//! whether the claim is well-formed, whether it is within bounds, and what — if anything — happens
//! as a result. A plugin that reports a metric named `busbar_anything` has reported it; the host is
//! what refuses to expose it.
//!
//! ## Why the arrays are RAW `serde_json::Value`, not typed
//!
//! Deliberate, and lifted from the shape this generalizes: a hook's `status.metrics` has always
//! been a raw array validated downstream. If the wire carried `Vec<PluginMetric>` then ONE malformed
//! entry would fail the WHOLE response decode — a plugin that fumbled one telemetry line would lose
//! its `result` too. Telemetry must never be able to cost the answer. So the wire carries raw
//! entries, the host parses each one liberally, and a malformed entry is DROPPED WHOLE while its
//! siblings survive. [`PluginMetric`] and [`PluginDiagnostic`] are the PUBLISHED SHAPES an author
//! builds against and a host parses into; they are not the wire's decode unit.
//!
//! ## Closing the #11 hole
//!
//! DECISIONS #11 asserts compiled-in ≡ dropped-in. It was FALSE for anything observable: a
//! COMPILED-IN plugin could reach the process-global `metrics` recorder, while the same crate built
//! as a dropped-in `cdylib` links its own recorder and silently loses every counter. Under the
//! envelope that reach is not representable from either build — both REPORT, the host folds — so the
//! equivalence becomes true rather than asserted.
//!
//! ## THE GAP THIS ENVELOPE DOES NOT CLOSE: it is plugin→host, one way
//!
//! Recorded here rather than anywhere else because this is the module an author reads when they ask
//! "how do I find out what happened", and the honest answer has a hole in it.
//!
//! The envelope carries what a plugin OBSERVED. It carries nothing in the other direction, and there
//! is a real thing the host knows and the plugin does not: **the host owns the admission gate, so
//! the host is what SHEDS a plugin's batch.** When a sink is saturated the host drops the delivery
//! and counts it; the sink is never called, so it cannot report the drop, cannot reconcile its own
//! counters against what actually shipped, and cannot tell a quiet period from a shed one. The same
//! is true of every other host-owned refusal a plugin would want to know about — an egress the host
//! declined to open, a metric this module's own bounds refused.
//!
//! That is an ABI GAP, not a bug in any of the code below, and closing it is a separate design: a
//! host→plugin notification has to answer where it is delivered (a sink that was never called has no
//! call to ride), whether it is ordered against deliveries, and what a plugin is permitted to do in
//! response. None of those questions is settled, and inventing an answer inside a one-way wire would
//! produce exactly the kind of half-shape #85 exists to remove.
//!
//! ## Where this will live
//!
//! Here, beside the other cold-lane shapes (`export.rs`, `hook.rs`, `endpoint.rs`), because that is
//! where its siblings are. Under #83 (*contract = shapes*) and #84 (contract and the SDK MERGE into
//! one zero-dependency plugin-contract crate) this module's destination is that crate. Moving it is
//! a rename, not a redesign — nothing here names the kernel, the ledger, or any kind.

use serde::{Deserialize, Serialize};

/// The uniform observability envelope — the ONE response shape, every kind (#85).
///
/// `result` is the kind-specific answer; `metrics` and `diagnostics` are universal and carry what
/// the plugin OBSERVED while producing it. Both are `#[serde(default)]` + skipped when empty, so the
/// common case (a plugin with nothing to report) costs exactly the two bytes of the `result` key's
/// object wrapper and nothing else.
///
/// # Wire form
///
/// ```json
/// {"result":{"Streams":["logs"]},"metrics":[{"name":"x_total","type":"counter","value":1}]}
/// ```
///
/// The `result` key holds whatever the kind's own response enum serializes to, BYTE FOR BYTE — this
/// type adds a wrapper, never a second copy of a kind's semantics. That is what lets one generic
/// seam (`plugin-loader`'s `transport_call_status`) carry every kind's back-channel without a single
/// per-kind branch.
///
/// # Versioning
///
/// Wrapping a kind's response is a PAYLOAD-schema change for that kind, not a TRANSPORT one: the six
/// `extern "C"` signatures, the ptr+len rule and the status codes are all untouched, so
/// [`crate::cold::TRANSPORT_VERSION`] does NOT move (see its doc for the axis split, and
/// `SetLogSinkFn` for the same argument applied to a seventh symbol). Each kind that adopts the
/// envelope bumps ITS OWN payload constant, and the loader keeps the kind's FLOOR where it was —
/// a plugin built before the envelope declares the older version in its signed manifest and the
/// loader reads its bare response exactly as it always did. No published artifact is refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope<R> {
    /// The kind-specific answer.
    pub result: R,
    /// Metrics the plugin OBSERVED while producing `result`. Raw entries, each shaped like
    /// [`PluginMetric`]; the host validates and bounds them (see this module's doc for why the wire
    /// is not `Vec<PluginMetric>`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<serde_json::Value>,
    /// Diagnostics the plugin RAISED while producing `result`. Raw entries, each shaped like
    /// [`PluginDiagnostic`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<serde_json::Value>,
}

impl<R> Envelope<R> {
    /// The envelope for a plugin with nothing to report — the overwhelmingly common case, and the
    /// one every default SDK dispatch takes.
    pub fn bare(result: R) -> Envelope<R> {
        Envelope {
            result,
            metrics: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    /// Whether this envelope carries anything on the back-channel at all.
    pub fn is_bare(&self) -> bool {
        self.metrics.is_empty() && self.diagnostics.is_empty()
    }
}

/// One plugin-reported metric sample — the PUBLISHED SHAPE of an entry in [`Envelope::metrics`].
///
/// **This is the hook kind's frozen metric shape, generalized to every kind and NOT otherwise
/// changed.** Field for field, serde attribute for serde attribute, it is the type a hook's
/// `status.metrics` entries have always deserialized into (`busbar-kernel`'s `hooks::wire::HookMetric`,
/// which is now an alias of the host-side twin of this type). That is deliberate and load-bearing:
/// the hook kind is a FUNCTIONAL FIXED POINT for 1.6.0 — its ABI may move, its behaviour may not —
/// so the one shape that already solved "a plugin reports, the host bounds and folds" is the shape
/// every other kind adopts, rather than a second idiom invented beside it.
///
/// Modeled as an ARRAY of these (not a name→value map) precisely so several entries can share a
/// `name` and differ by `labels` — the per-dimension breakdown a flat map cannot carry.
///
/// Anti-exfiltration holds STRUCTURALLY on the host side: `name` and label KEYS are charset-enforced,
/// every string is sanitized and length-bounded, every number must be finite. A plugin granted a
/// read-only view of request content cannot smuggle it out through a metric name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginMetric {
    /// The series name: `^[a-z][a-z0-9_]{0,63}$` (counters SHOULD end `_total`).
    pub name: String,
    /// `counter` (monotonic over the plugin's lifetime), `gauge` (a point-in-time level), or
    /// `histogram` (a distribution reported via `quantiles` or `buckets`).
    #[serde(rename = "type")]
    pub kind: String,
    /// The scalar value. Required for counter/gauge; for a histogram it is the observation COUNT.
    #[serde(default)]
    pub value: f64,
    /// Prometheus-style dimensions. Keys `^[a-z][a-z0-9_]{0,63}$`, values sanitized and bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<std::collections::BTreeMap<String, String>>,
    /// A `type: histogram` reported as a SUMMARY — precomputed quantiles keyed by a probability in
    /// `[0,1]` as a string (`"0.95"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantiles: Option<std::collections::BTreeMap<String, f64>>,
    /// A `type: histogram` reported as a native Prometheus histogram — keys are `le` upper bounds as
    /// strings (`"0.5"`, `"+Inf"`), values the CUMULATIVE count at or below that bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buckets: Option<std::collections::BTreeMap<String, f64>>,
    /// PROVENANCE: `true` marks this value an ESTIMATE rather than a directly measured fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated: Option<bool>,
    /// Confidence interval for an estimated value (finite; `ci_low <= ci_high` or both dropped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci_low: Option<f64>,
    /// The upper end of that interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci_high: Option<f64>,
    /// Human display name (a UI falls back to `name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// A display label, sanitized and bounded like `help`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Display unit token (`"ms"`, `"$"`, `"%"`, …) — bounded and sanitized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Rendering hint: `number` | `gauge` | `counter` | `sparkline` | `histogram` (else dropped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viz: Option<String>,
    /// Gauge normalization ceiling (finite, else dropped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

impl PluginMetric {
    /// A counter sample — the shape nearly every plugin reports and the one an author should reach
    /// for first. Everything optional is left unset, which is also what keeps the wire small.
    pub fn counter(name: impl Into<String>, value: f64) -> PluginMetric {
        PluginMetric::new(name, "counter", value)
    }

    /// A gauge sample.
    pub fn gauge(name: impl Into<String>, value: f64) -> PluginMetric {
        PluginMetric::new(name, "gauge", value)
    }

    /// A sample of an explicitly-named type. Prefer [`counter`](PluginMetric::counter) /
    /// [`gauge`](PluginMetric::gauge); this is the arm a histogram reporter uses before attaching
    /// its `quantiles` or `buckets`.
    pub fn new(name: impl Into<String>, kind: impl Into<String>, value: f64) -> PluginMetric {
        PluginMetric {
            name: name.into(),
            kind: kind.into(),
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

    /// Attach one Prometheus-style dimension. The host drops a key outside the metric-name charset
    /// and caps the pair count, so calling this more times than the host allows costs the excess
    /// pairs, never the sample.
    #[must_use]
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> PluginMetric {
        self.labels
            .get_or_insert_with(std::collections::BTreeMap::new)
            .insert(key.into(), value.into());
        self
    }

    /// Attach a HELP string.
    #[must_use]
    pub fn help(mut self, help: impl Into<String>) -> PluginMetric {
        self.help = Some(help.into());
        self
    }
}

/// How loud a [`PluginDiagnostic`] is. A plain enum with pinned snake_case wire tokens; an
/// unrecognized level is clamped by the host rather than rejected, on exactly the reasoning
/// [`crate::cold::log_level`] gives — a newer plugin inventing a level must not lose the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagLevel {
    /// Something failed and an operator must act.
    Error,
    /// Something degraded; the node kept serving.
    Warn,
    /// Worth recording, needs no action.
    Info,
    /// Detail for a diagnosis in progress.
    Debug,
}

impl DiagLevel {
    /// The stable snake_case wire token — the SAME spelling serde emits, rendered without a JSON
    /// round-trip so a host log line can name it directly.
    pub const fn as_token(self) -> &'static str {
        match self {
            DiagLevel::Error => "error",
            DiagLevel::Warn => "warn",
            DiagLevel::Info => "info",
            DiagLevel::Debug => "debug",
        }
    }
}

/// One diagnostic a plugin RAISED — the PUBLISHED SHAPE of an entry in [`Envelope::diagnostics`].
///
/// ## Why a CODE and not a free-text line
///
/// A plugin already has a way to emit free text: the optional `busbar_set_log_sink` symbol bridges a
/// plugin's own `tracing` records into the host's subscriber. That channel is a LOG, and it is not
/// this. busbar's diagnostics are a CATALOGUE — every operator-facing warning carries a stable
/// `BUSBAR-NNNN` code an operator pastes into the docs to land on an entry saying what it means and
/// what to do. A code is a promise the host made, so only the host can make it: a plugin NAMES a
/// code, and the host is what looks it up, refuses one that is not in its registry, and emits
/// through its own diagnostic path. That is the same REPORT/VALIDATE/DECIDE split the metrics half
/// has, applied to the other kind of operator-facing output.
///
/// `message` and `fields` are for the operator's log. **They must not carry request content** — a
/// plugin that puts a prompt in a diagnostic field has exfiltrated it into the operator's log, so the
/// host bounds and sanitizes both exactly as it bounds a metric's strings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginDiagnostic {
    /// The catalogue code, as the host spells it (`"BUSBAR-1234"`). A code the host's registry does
    /// not hold is DROPPED — a plugin cannot mint a diagnostic busbar has not documented.
    pub code: String,
    /// How loud it is. Defaults to [`DiagLevel::Warn`], which is the level the overwhelming majority
    /// of the catalogue sits at, so a minimal entry is `{"code":"BUSBAR-1234"}`.
    #[serde(default = "default_level")]
    pub level: DiagLevel,
    /// The operator-facing line. Bounded and sanitized by the host.
    #[serde(default)]
    pub message: String,
    /// Structured fields for the line (`path`, `error`, …). Keys and values are both bounded and
    /// sanitized by the host; a `BTreeMap` so the rendered order is deterministic and a log line is
    /// diffable between two runs.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub fields: std::collections::BTreeMap<String, String>,
}

/// The level an entry that omits `level` is read at. A free function because `#[serde(default = …)]`
/// takes a path, not an expression.
fn default_level() -> DiagLevel {
    DiagLevel::Warn
}

impl PluginDiagnostic {
    /// Raise a diagnostic at [`DiagLevel::Warn`] — the catalogue's ordinary level.
    pub fn warn(code: impl Into<String>, message: impl Into<String>) -> PluginDiagnostic {
        PluginDiagnostic::new(code, DiagLevel::Warn, message)
    }

    /// Raise a diagnostic at an explicit level.
    pub fn new(
        code: impl Into<String>,
        level: DiagLevel,
        message: impl Into<String>,
    ) -> PluginDiagnostic {
        PluginDiagnostic {
            code: code.into(),
            level,
            message: message.into(),
            fields: std::collections::BTreeMap::new(),
        }
    }

    /// Attach one structured field. Never request content — see this type's doc.
    #[must_use]
    pub fn field(mut self, key: impl Into<String>, value: impl Into<String>) -> PluginDiagnostic {
        self.fields.insert(key.into(), value.into());
        self
    }
}

/// What a plugin accumulated on the back-channel during ONE call, before it is serialized into an
/// [`Envelope`].
///
/// The AUTHOR-SIDE collector: a plugin builds one of these, the SDK folds it into the envelope, and
/// the plugin never touches the wire. Its own type rather than a bare pair of `Vec`s so the two
/// arrays are always carried and named together — a plugin that grew a diagnostics path and forgot
/// the metrics one is a plugin whose half of the envelope silently disappears.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Observations {
    /// Metrics observed during this call.
    pub metrics: Vec<PluginMetric>,
    /// Diagnostics raised during this call.
    pub diagnostics: Vec<PluginDiagnostic>,
}

impl Observations {
    /// Nothing to report — what a plugin with no back-channel returns, and the default every kind's
    /// handler trait carries so an existing plugin compiles untouched.
    pub fn none() -> Observations {
        Observations::default()
    }

    /// Whether there is anything to carry.
    pub fn is_empty(&self) -> bool {
        self.metrics.is_empty() && self.diagnostics.is_empty()
    }

    /// Record one metric.
    #[must_use]
    pub fn metric(mut self, m: PluginMetric) -> Observations {
        self.metrics.push(m);
        self
    }

    /// Record one diagnostic.
    #[must_use]
    pub fn diagnostic(mut self, d: PluginDiagnostic) -> Observations {
        self.diagnostics.push(d);
        self
    }

    /// Wrap a kind-specific `result` in the envelope these observations belong to.
    ///
    /// Serializing here — rather than letting the wire carry `Vec<PluginMetric>` — is what makes one
    /// malformed entry cost that entry and nothing else on the host side (see this module's doc). An
    /// entry that will not serialize at all is dropped here, for the same reason: a plugin's
    /// telemetry must never be able to cost it its answer.
    pub fn into_envelope<R>(self, result: R) -> Envelope<R> {
        Envelope {
            result,
            metrics: self
                .metrics
                .into_iter()
                .filter_map(|m| serde_json::to_value(m).ok())
                .collect(),
            diagnostics: self
                .diagnostics
                .into_iter()
                .filter_map(|d| serde_json::to_value(d).ok())
                .collect(),
        }
    }
}

/// One metric SERIES a plugin's signed manifest DECLARES it emits (`declares.metrics[]`) — the
/// FIRST-PARTY METRIC NAMESPACE (K9a S1).
///
/// A declaration is a claim the HOST grants or ignores; it never widens what an undeclared entry
/// may do. The host grants it only to a plugin admitted through the LINKED door or dropped in and
/// signed by the busbar release key: such a plugin may claim a reserved `busbar_*` name, and an
/// entry it reports under a granted name, of the declared `type`, renders exactly as declared —
/// the name as written and no `plugin=` provenance label. Every other plugin keeps the envelope's
/// rule (the reserved prefix refused, the `plugin=` label added) whatever it declares, and a claim
/// on a series the host itself emits is refused at open rather than merged into the host's.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SeriesDecl {
    /// The series name exactly as it renders (Prometheus charset).
    pub name: String,
    /// `counter` | `gauge` | `histogram` — the same tokens a [`PluginMetric`]'s `type` carries. An
    /// entry of another type under this name is not the declared series and is not granted.
    #[serde(rename = "type")]
    pub kind: String,
    /// THE SHED COUNTER (K9b, export ABI minor 7): a `counter` the HOST increments by one for every
    /// delivery it SHEDS for this sink at the sink's in-flight bound. A shed delivery never reaches
    /// the sink, so the sink cannot count it itself — the one fact of its own the host must report
    /// for it. Absent (`false`) on every declaration made before the flag existed, and skipped when
    /// false, so their canonical bytes — and signatures — are unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shed: bool,
}

impl SeriesDecl {
    /// A declared series `name` of type `kind`.
    pub fn new(name: impl Into<String>, kind: impl Into<String>) -> SeriesDecl {
        SeriesDecl {
            name: name.into(),
            kind: kind.into(),
            shed: false,
        }
    }

    /// The same declaration, marked the sink's shed counter (see [`SeriesDecl::shed`]).
    #[must_use]
    pub fn shed(mut self) -> SeriesDecl {
        self.shed = true;
        self
    }
}

/// One `BUSBAR-NNNN` diagnostic a plugin's signed manifest DECLARES it raises
/// (`declares.diagnostics[]`) — PLUGIN DIAGNOSTICS (K9a S3).
///
/// The host registers a first-party plugin's declarations into its diagnostics catalogue through
/// the same seam a linked plane's owned codes take, before anything reads the catalogue, so a
/// [`PluginDiagnostic`] the plugin reports under the code resolves exactly as a built-in one does:
/// same code, same catalogue entry, same severity clamp. The fields are the catalogue entry's, one
/// for one; a declaration whose code is already in the catalogue, whose class (`code / 1000`) is not
/// one of the host's, or whose severity is not a severity token refuses the boot naming the plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticDecl {
    /// The numeric code (`1001` renders `BUSBAR-1001`); its thousands digit is its class.
    pub code: u16,
    /// Stable kebab-case anchor (the docs fragment).
    pub slug: String,
    /// Short human title.
    pub title: String,
    /// `benign_recurring` | `actionable` | `fatal` — the catalogue's severity tokens.
    pub severity: String,
    /// What the condition means.
    pub summary: String,
    /// What an operator should do.
    pub action: String,
    /// The version the code was introduced in.
    pub since: String,
}

#[cfg(test)]
#[path = "tests/observe_tests.rs"]
mod tests;
