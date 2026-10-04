// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **export** payload schema (kind = [`crate::abi::cold::kind::EXPORT`]) that rides the kind-neutral `call`.
//!
//! ## One transport, every export op
//!
//! A `kind: export` plugin is a telemetry SINK behind the frozen six-symbol C ABI — the seam that
//! carries the engine's observability streams OUT to an external backend (the frozen vocabulary is
//! [`ExportStream`]). Like every other kind it exports the SAME six neutral symbols ([`crate::abi::cold::symbol`]) at
//! `busbar_abi() == TRANSPORT_VERSION`; only its manifest `kind` and its own tiny request enum
//! ([`ExportRequest`]) distinguish it. Every op rides the ONE `busbar_call` as an op-discriminated
//! JSON envelope — the variant IS the op-code, so the C symbol set never grows.
//!
//! ## The ops
//!
//! - `streams` — asked ONCE at load: which observability streams does THIS instance carry? The
//!   engine retains the answer and only routes deliveries for streams the plugin declared.
//! - `deliver` — hand one already-serialized batch for a declared stream to the sink. The payload is
//!   carried as an opaque [`serde_json::Value`] the engine built; the export ABI adds the envelope,
//!   never a second copy of the batch semantics.
//! - `routes` / `http_endpoint` — the sink's HTTP surface (see [`crate::abi::cold::endpoint`]).
//! - `status` — what the sink has to report when the host renders its exposition (additive).

use crate::abi::cold::endpoint::{EndpointRequest, EndpointResponse};
use crate::abi::export::{CheckPhase, ExportStream};
use crate::abi::mechanism::route::Route;
use serde::{Deserialize, Serialize};

/// The export-plugin PAYLOAD schema version (the signed manifest's `abi_version` for `kind: export`).
/// v1: the initial `streams`/`deliver` wire. v2 (1.5.3): the PROJECTION GRAMMAR — the [`ExportStream`]
/// vocabulary was expanded and the `audit` stream REMOVED (an auditor is a projection made of other
/// streams, not a data type), so a v1 sink that declared `audit` no longer has a stream to declare.
/// A REMOVED wire token is a breaking payload change, so the floor moves rather than accepting a
/// token the engine can no longer route. This is the per-kind PAYLOAD axis, NOT the transport axis
/// — an export plugin exports the SAME six neutral symbols ([`crate::abi::cold::symbol`]) as every other kind, at
/// `busbar_abi() == TRANSPORT_VERSION`. Named the same way [`crate::abi::cold::SECRET_ABI_VERSION`] is, so the loader floor and the SDK's declared version share one
/// const and cannot silently drift apart.
///
/// v2 -> v3 (1.6.0, DECISIONS #85 — THE OBSERVABILITY ENVELOPE): an export response is now
/// [`crate::abi::cold::observe::Envelope`]`<ExportResponse>` — `{ result, metrics[], diagnostics[] }` —
/// instead of a bare `ExportResponse`. **This is the bump #85 called for and the only one it
/// required.**
///
/// WHY THIS KIND AND WHY ONLY THIS KIND, so nobody has to reconstruct the reasoning later:
///
/// * `export` is where the defect was. [`ExportResponse::Delivered`] is a UNIT variant and the cold
///   tier has no host-callback vtable, so a sink could not report the metrics it produced or the
///   diagnostics it raised — which is precisely what made the four `busbar-export-*` crates
///   unbuildable without losing operator-visible surfaces.
/// * It costs nothing to bump. There is no published export plugin, and `DynExport::deliver` has no
///   production caller, so widening this window refuses nobody and changes no shipped behaviour.
/// * The other four cold kinds do NOT move here, and not because the envelope is export-only — the
///   envelope TYPE and the host seam that folds it are kind-NEUTRAL and already carry every kind
///   (see `plugin-loader`'s `decode_response`, which is generic over the kind's response type). They
///   do not move because each carries a cost this change has no mandate to pay: the store's
///   `ABI_VERSION` is coupled to `plugin-loader`'s `STORE_ABI_WITH_NEW_OPS` (=5), so bumping 4->5
///   would silently switch every v5 store onto the eight neutral plane-record verbs — a behaviour
///   change disguised as a version bump; `hook` and `secret` have SINGLE-POINT supported windows
///   (`[N, N]`), so bumping either refuses every existing plugin of that kind unless the window is
///   widened to `[1, N]` in the same breath, and `hook` is a 1.6.0 FUNCTIONAL FIXED POINT whose
///   behaviour may not move at all. Adopting the envelope on each of those is a one-line change to
///   that kind's constant once those costs are accepted; it is not a redesign.
///
/// THE FLOOR STAYS AT 2. A sink built before the envelope answers a BARE `ExportResponse` and keeps
/// loading: the loader's decoder accepts both shapes and they are disjoint (every response variant
/// is externally tagged by its Rust variant name, and none of them is named `result`). That is the
/// same per-kind ADAPTER the store's usage-ledger ops already run on, not a permanent wire fork —
/// when this kind's floor rises past 3 the bare arm is dead code and is deleted.
pub const EXPORT_ABI_VERSION: u32 = 3;

/// The export ABI's MINOR — the count of ADDITIVE host seams on top of [`EXPORT_ABI_VERSION`].
///
/// THE POLICY. [`EXPORT_ABI_VERSION`] moves only on a BREAKING payload change (a removed or
/// renamed token, a re-tagged variant) and the loader refuses a manifest outside its supported
/// window. This minor moves on every ADDITIVE change to what a sink and the host may say to each
/// other — a new op, a new response variant, a new manifest declaration — and is never a refusal
/// reason in either direction: a sink built at an older minor answers `STATUS_UNSUPPORTED` to an op
/// it cannot decode (the host reads that as the op's documented "nothing to say" answer, the
/// `routes`/`status` precedent) and never states a declaration it does not know, and a host at an
/// older minor never asks the newer op. The same append-only discipline [`crate::abi::ABI_MINOR`] holds
/// for the HOT lane's `repr(C)` structs, applied to this kind's JSON.
///
/// 0: `streams` / `deliver` / `routes` / `http_endpoint` / `status` (the v3 surface).
/// 1 (K9a S1): the FIRST-PARTY METRIC NAMESPACE — a manifest's `declares.metrics`
///   ([`crate::abi::cold::observe::SeriesDecl`]).
/// 2 (K9a S2): the `validate` op ([`ExportRequest::Validate`] / [`ExportResponse::Validated`]).
/// 3 (K9a S3): PLUGIN DIAGNOSTICS — a manifest's `declares.diagnostics`
///   ([`crate::abi::cold::observe::DiagnosticDecl`]).
/// 4 (K9a S4): the DESTINATION HANDLE — a manifest's `declares.destinations`, the host-executed
///   [`HostOp`]s a delivery may answer with ([`ExportResponse::Host`]), and the op that resumes it
///   with their [`HostResult`]s ([`ExportRequest::Resume`]).
/// 5 (K9a S5): the EGRESS CARRIER — [`HostOp::Http`] / [`HostResult::Http`]: the host performs a
///   sink's outbound HTTP request through its own egress.
/// 6 (K9a S6): the RECORDER SNAPSHOT — [`ExportRequest::Scrape`] hands a sink the host recorder's
///   samples as [`MetricFamily`]s; the sink answers the exposition it renders
///   ([`ExportResponse::Exposition`]).
/// 7 (K9b): the SHED COUNTER — a declared series may be marked `shed`
///   ([`crate::abi::cold::observe::SeriesDecl::shed`]): the host counts on it each delivery it sheds for
///   the sink, which the sink is never called for and so cannot count.
/// 8 (K9c): the START op ([`ExportRequest::Start`] / [`ExportResponse::Started`]) — the host
///   starts feeding the sink and it states its in-flight admission; the CHECK op
///   ([`ExportRequest::Check`], at a [`CheckPhase`]) — the sink's checks across every instance of
///   its module while the host validates the configuration; and [`HostOp::Admit`] — the host's egress policy asked of a
///   target without carrying anything to it.
/// 9 (K9c): the check op's [`CheckPhase`] — asked among the operational limits' checks, or after
///   them, so a sink's lines keep their place among the configuration's errors.
/// 10 (K9e-2): the BINARY egress body — [`HostOp::HttpBinary`] carries a request whose body is
///   octets (hex on the wire) — and the sink's DECLARED EGRESS POLICY (a manifest's
///   `declares.egress`: `open-web` | `collector`), which the host applies to every request the sink
///   asks it to admit or carry.
pub const EXPORT_ABI_MINOR: u32 = 10;

/// An export operation, serialized as the `call` request payload. One self-describing enum keeps the
/// C ABI to a single `call` symbol; the `op` tag is the op-code. Serialized with the op as a JSON tag
/// so a plugin matches on it directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ExportRequest {
    /// `streams` — which [`ExportStream`]s does this instance carry? Asked once at load; the reply is
    /// [`ExportResponse::Streams`].
    Streams,
    /// `deliver` — hand one batch for `stream` to the sink. `payload` is the engine-built batch as an
    /// opaque JSON value. Reply: [`ExportResponse::Delivered`].
    Deliver {
        /// The declared stream this batch belongs to.
        stream: ExportStream,
        /// The already-serialized batch (opaque to the ABI; built by the engine).
        payload: serde_json::Value,
    },
    /// `routes` — asked ONCE at load: which HTTP [`Route`]s does this instance serve? The engine
    /// collision-checks + namespace-confines the answer, then mounts them (see the `endpoint`
    /// module doc). Reply: [`ExportResponse::Routes`]. ADDITIVE: an older sink that cannot decode this
    /// op declares no routes (the loader treats the undecodable-variant signal as "no HTTP surface").
    Routes,
    /// `http_endpoint` — dispatch one inbound HTTP request matched to a registered route of THIS
    /// plugin. Fires only for a matched plugin route, off the data-plane hot path; the engine already
    /// enforced the route's declared auth. Reply: [`ExportResponse::Endpoint`].
    ///
    /// `#[serde(rename = "http_endpoint")]` pins the wire op tag to its ORIGINAL spelling — the Rust
    /// identifier is neutralized (`Endpoint`, not `HttpEndpoint`) but the byte on the wire is
    /// unchanged, so no plugin (any language) sees a break.
    #[serde(rename = "http_endpoint")]
    Endpoint {
        /// The host-built inbound request (bounded headers, no raw `Authorization`).
        request: EndpointRequest,
    },
    /// `status` — asked by the host when it RENDERS its own exposition (a `/metrics` scrape): what
    /// does this sink have to report right now? The sink answers the metrics and diagnostics it
    /// observed since it last reported, and the host validates, bounds and folds them exactly as it
    /// folds the observability envelope (#85) — so a sink contributes to `/metrics` even between
    /// deliveries, the way a hook's `HookStatus.metrics` does. Reply: [`ExportResponse::Status`].
    ///
    /// ADDITIVE, and why that needs no [`EXPORT_ABI_VERSION`] bump: a sink built before this op
    /// cannot decode it and answers `STATUS_UNSUPPORTED`, which the host reads as "nothing to
    /// report" and keeps the sink loaded — the precedent is [`ExportRequest::Routes`].
    Status,
    /// `validate` — asked by the host while it VALIDATES the configuration (`--validate`, boot, a
    /// config apply): are `settings`, as the operator wrote them for the `instance` named, a
    /// configuration this sink accepts? Reply: [`ExportResponse::Validated`] — every problem, each
    /// a complete operator-facing line the host reports VERBATIM among the configuration's errors,
    /// so a sink's settings errors surface at the same moment and in the same words a built-in
    /// module's do (`export.<instance>.settings: …`).
    ///
    /// ADDITIVE (export ABI minor 2): a sink built before the op answers `STATUS_UNSUPPORTED`,
    /// which the host reads as "nothing to report" — its settings meet the sink at `open`, as they
    /// always did.
    Validate {
        /// The `export:` instance name the settings belong to (for the sink's own error lines).
        instance: String,
        /// The instance's `settings:` block exactly as configured.
        // settings-leak-lint: allow — PLUGIN ABI WIRE STRUCT, and OUTBOUND: the `validate` request
        // the host serializes INTO the sink's `busbar_call` so the sink can judge the settings it
        // will be opened with. It is never part of an admin response; key names alone could not
        // be validated.
        settings: serde_json::Value,
    },
    /// `resume` — the host performed the [`HostOp`]s a `deliver` (or an earlier `resume`) answered
    /// with ([`ExportResponse::Host`]), and hands back one [`HostResult`] per op, in order, under
    /// the `token` the sink chose. The sink answers as it would have answered the delivery —
    /// [`ExportResponse::Delivered`] — or with more ops (the host bounds the rounds).
    ///
    /// This is how a COLD sink has the host act for it without a host-callback vtable: the sink
    /// never opens a path or dials a socket, it ASKS, and the host executes under its own rules and
    /// reports what happened (export ABI minor 4). A sink that never answers `Host` never sees it.
    Resume {
        /// The token the sink's `Host` answer carried, echoed so a sink serving concurrent
        /// deliveries can tell whose ops these were.
        token: u64,
        /// One result per op, in the order the ops were asked.
        results: Vec<HostResult>,
    },
    /// `scrape` — the host's RECORDER SNAPSHOT (K9a S6): every metric family the host recorder
    /// holds right now — counters, gauges, histograms and quantile summaries — in the stable shape
    /// [`MetricFamily`], for the sink to RENDER its exposition from. Reply:
    /// [`ExportResponse::Exposition`]. The host serves what the sink rendered; the recorder stays
    /// the host's, so a dropped-in sink renders the same samples a linked one does.
    Scrape {
        /// The families, in the recorder's own order.
        families: Vec<MetricFamily>,
    },
    /// `start` — asked ONCE, when the host starts feeding the sink (after it is opened, before its
    /// first delivery), at the moment the host starts its own built-in sinks. The sink may answer
    /// [`ExportResponse::Host`] first (e.g. [`HostOp::Admit`] its target), and finishes with
    /// [`ExportResponse::Started`]: whether it takes deliveries this run, and its in-flight
    /// admission (K9c, export ABI minor 8). A sink built before the op answers
    /// `STATUS_UNSUPPORTED`: live, at the host's default admission.
    Start,
    /// `check` — asked while the host VALIDATES the configuration, AFTER its limits are checked:
    /// every instance of this sink's module, in configuration order, for the checks that read
    /// across instances or belong to that phase. Reply: [`ExportResponse::Validated`] — each line
    /// reported verbatim among the configuration's validation errors (K9c, export ABI minor 8).
    Check {
        /// `(instance name, settings as configured)`, in configuration order.
        instances: Vec<(String, serde_json::Value)>,
        /// Which point of the validation asks: among the operational limits' checks, or after them.
        /// Absent on the wire: [`CheckPhase::Instances`].
        #[serde(default)]
        phase: CheckPhase,
    },
}

/// One metric FAMILY of the host recorder's snapshot (K9a S6): its name, its type, its help text,
/// and its samples in order — the unit a text exposition is made of.
///
/// STABLE AND LOSSLESS. `kind` is the exposition's own type token (`counter` | `gauge` |
/// `histogram` | `summary` | `untyped`); a histogram's `_bucket` / `_sum` / `_count` series and a
/// summary's `quantile` series are SAMPLES of their family, carried as the recorder wrote them. A
/// sample's value is the recorder's own spelling of the number, so rendering the snapshot back in
/// the text format reproduces the host's exposition byte for byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricFamily {
    /// The family name, as its `# TYPE` line spells it.
    pub name: String,
    /// `counter` | `gauge` | `histogram` | `summary` | `untyped`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The `# HELP` text, when the recorder has one (as written: escaped, one line).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// The samples, in order.
    #[serde(default)]
    pub samples: Vec<MetricSample>,
}

/// One SAMPLE line of a [`MetricFamily`] (K9a S6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricSample {
    /// The series name — the family name, or it with `_bucket` / `_sum` / `_count`.
    pub name: String,
    /// The labels in order, each value as the exposition writes it (escaped), `le` / `quantile`
    /// included where the recorder wrote them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<(String, String)>,
    /// The value, in the recorder's own spelling.
    pub value: String,
}

/// One act a sink asks the HOST to perform for it (K9a S4): the host executes it under its own
/// rules and hands the outcome back on [`ExportRequest::Resume`].
///
/// A DESTINATION is named by the settings key the sink's manifest declares
/// (`declares.destinations`): the host resolves the key against the OPERATOR's settings for the
/// instance and opens the path found there itself — so a sink can write only where the operator's
/// configuration pointed a declared destination, and never names a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HostOp {
    /// Append `data` to the destination (opened for append, created if absent, per write — the
    /// file an external rotator moved is not written through a stale handle). When `rotate_at` is
    /// set and the destination already holds at least that many bytes, the host rotates it first
    /// (as [`HostOp::Rotate`] with `keep`), under the same per-destination lock as the write.
    Write {
        /// The declared destination (a settings key).
        destination: String,
        /// The bytes to append, as UTF-8.
        data: String,
        /// Rotate first when the destination holds at least this many bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rotate_at: Option<u64>,
        /// Archives a rotation keeps (`<path>.1` … `<path>.<keep>`).
        #[serde(default = "default_keep")]
        keep: u32,
    },
    /// Rotate the destination by rename: drop `<path>.<keep>`, shift `<path>.<i>` to
    /// `<path>.<i+1>`, then rename `<path>` to `<path>.1`. A failed step is reported, never
    /// escalated into truncating the live file.
    Rotate {
        /// The declared destination (a settings key).
        destination: String,
        /// Archives kept.
        #[serde(default = "default_keep")]
        keep: u32,
    },
    /// Flush the destination to stable storage.
    Flush {
        /// The declared destination (a settings key).
        destination: String,
    },
    /// Ask the host's egress POLICY whether it would carry a request to `url` (K9c): nothing is
    /// sent. [`HostResult::Done`] when it would, [`HostResult::Failed`] with step `refused` and the
    /// policy's words when it would not.
    Admit {
        /// The target URL.
        url: String,
    },
    /// Perform one outbound HTTP request through the HOST's egress (K9a S5) — its URL policy (the
    /// SSRF and cloud-metadata refusal), its TLS, its timeouts. The sink never dials; a request the
    /// policy refuses is a [`HostResult::Failed`] with step `refused`.
    Http(HttpRequest),
    /// [`HostOp::Http`] whose `body` is OCTETS, spelled as lowercase hex (K9e-2, export ABI minor
    /// 10) — a wire format that is not text (a protobuf payload) rides the same carrier, under the
    /// same policy, answered the same way. A body that is not hex is a `request` failure.
    HttpBinary(HttpRequest),
}

/// An outbound HTTP request a sink asks the host to carry (K9a S5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    /// The method, e.g. `POST`.
    pub method: String,
    /// The target URL.
    pub url: String,
    /// Request headers, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    /// The request body, as UTF-8.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body: String,
    /// The end-to-end deadline in milliseconds; `0` is the host's default ceiling.
    #[serde(default)]
    pub timeout_ms: u64,
}

/// What the far end answered a carried [`HttpRequest`] (K9a S5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    /// The response status.
    pub status: u16,
    /// The response body as UTF-8 (lossy), read up to the host's cap.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body: String,
}

fn default_keep() -> u32 {
    9
}

/// What the host did with one [`HostOp`] (K9a S4), handed back in order on
/// [`ExportRequest::Resume`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum HostResult {
    /// The op completed. `rotation` is present when a rotation ran as part of it.
    Done {
        /// The rotation that ran first, if one did.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rotation: Option<Rotation>,
    },
    /// The far end answered a carried [`HostOp::Http`].
    Http(HttpResponse),
    /// The op did not complete: `step` names which host act failed (`destination` — no such
    /// destination was granted; `open`; `append`; `flush`; `refused` — the host's egress policy
    /// refused the request, or this host carries none; `request` — the request failed in flight),
    /// `error` says why.
    Failed {
        /// The host act that failed.
        step: String,
        /// Why, in the host's words.
        error: String,
        /// The rotation that ran before the failure, if one did.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rotation: Option<Rotation>,
    },
}

/// What a rotation did (K9a S4): where the live file went, whether that rename happened, and every
/// step that failed on the way — so a sink reports each the way it chooses, and nothing is lost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rotation {
    /// `<path>.1` — where the live file was renamed to.
    pub archive: String,
    /// Whether the live file was renamed (false: the host keeps APPENDING to it rather than
    /// truncating recorded data).
    pub renamed: bool,
    /// Every failed step, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub faults: Vec<RotationFault>,
}

/// One failed step of a [`Rotation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationFault {
    /// `retention` (dropping the oldest archive) | `shift` (moving an archive up) | `rename` (the
    /// live file to `<path>.1`).
    pub step: String,
    /// The file the step acted on.
    pub from: String,
    /// Where it was going, for `shift` and `rename`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Why it failed.
    pub error: String,
}

/// The success payload for an export `call`, matched to the request variant. A module-level FAILURE (a
/// sink that genuinely errored) rides `STATUS_ERR` with a UTF-8 message, NOT here.
///
/// UNLIKE [`ExportRequest`] (`op`-tagged, snake_case), this type carries NO `#[serde(...)]` attribute,
/// so it serializes with serde's default externally-tagged representation — the same externally-tagged
/// shape the auth reply carries, and for the same reason: this is JSON over the frozen C-ABI
/// transport, so a tagging change is a wire-breaking change, not a cosmetic one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportResponse {
    /// `streams` — the streams this instance carries.
    Streams(Vec<ExportStream>),
    /// `deliver` — the batch was accepted by the sink (nothing to read back).
    Delivered,
    /// `routes` — the HTTP routes this instance serves (collected once at load).
    Routes(Vec<Route>),
    /// `http_endpoint` — the plugin's response to a dispatched inbound request, relayed verbatim.
    ///
    /// `#[serde(rename = "Http")]` pins the externally-tagged wire key to its ORIGINAL spelling (this
    /// type carries no `#[serde(...)]` container attribute, so the default tag is the bare variant
    /// name — renaming the Rust identifier to `Endpoint` would otherwise flip the wire key from
    /// `"Http"` to `"Endpoint"`).
    #[serde(rename = "Http")]
    Endpoint(EndpointResponse),
    /// `status` — what the sink observed since it last reported, in the observability envelope's
    /// own entry shapes (`crate::abi::cold::observe::PluginMetric` /
    /// `PluginDiagnostic` as JSON values), so the host runs them through the SAME validator and fold
    /// it runs the envelope's arrays through. Either list may be empty or absent on the wire.
    Status {
        /// Metric entries (validated, bounded and folded by the host; never trusted as-is).
        #[serde(default)]
        metrics: Vec<serde_json::Value>,
        /// Diagnostic entries (a code the host's catalogue does not hold is dropped by the host).
        #[serde(default)]
        diagnostics: Vec<serde_json::Value>,
    },
    /// `validate` — every problem with the settings, one complete operator-facing line each;
    /// empty when the sink accepts them.
    Validated(Vec<String>),
    /// `deliver` / `resume` — the sink needs the host to act first: perform `ops` in order, then
    /// [`ExportRequest::Resume`] with `token` and their results.
    Host {
        /// The sink's own correlation token, echoed on the resume.
        token: u64,
        /// The acts, in order.
        ops: Vec<HostOp>,
    },
    /// `start` — the sink has started (K9c): whether it takes deliveries this run, and the
    /// admission the host holds it to.
    Started {
        /// `false`: the sink takes nothing this run (it refused its own configuration at start
        /// and said so); the host routes it no delivery.
        live: bool,
        /// Deliveries it may have in flight at once; `0` is the host's default.
        #[serde(default)]
        inflight: u64,
        /// The name its admission gate is counted under when it sheds; empty is the host's.
        #[serde(default)]
        gate: String,
    },
    /// `scrape` — the exposition the sink rendered from the snapshot, and its content type.
    Exposition {
        /// The `content-type` the host serves the body under.
        content_type: String,
        /// The rendered exposition.
        body: String,
    },
}

#[cfg(test)]
#[path = "tests/export_tests.rs"]
mod tests;
