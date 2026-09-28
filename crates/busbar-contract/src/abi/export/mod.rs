// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT KIND'S ABI: its version and its table (the design's locked plugin ABI: one
//! mechanism, every shape in `abi/`). M0 landed the skeleton; this is M3-SHAPES
//! (`abi-v2-perkind.md` B.5): `deliver`, `scrape`, `status`, `check` and `serve`, and the frozen
//! [`ExportStream`] tail. NOTHING dispatches through this yet (M3-wire, after M1).
//!
//! **ARCHITECT REVIEW RULING (fresh-Opus M3-SHAPES review, 2026-09-28), folded in on top of the
//! first landing:**
//! 2. `scrape`'s rendered-exposition buffer is HOST-owned and lives in [`ScrapeIn`]
//!    (`buf`/`cap`), never a plugin-owned pointer in `out`: the host zeroes `out` before the call,
//!    so nothing the plugin needs may live there. [`ScrapeOut`] carries `written`/`needed`: too
//!    small a `cap` means the plugin writes nothing, sets `needed`, and the host re-invokes ONCE
//!    with a bigger buffer.
//! 3. Off-path plugin-owned results ([`ServeOut::body`], [`StatusOut::status`],
//!    [`CheckOut::findings`]) are documented as memory class (iv): held live under `head.lease`
//!    until `release(lease)`.
//!
//! **SECOND REVIEW PASS (ARCHITECT ruling, 2026-09-28), folded in on the same landing:**
//! - [`Tail::routes`] carries [`Route`] entries (`path`, `method`, `auth`), not bare path
//!   strings: none/key/admin auth cannot be read off a path alone.
//! - [`ScrapeSample`] carries its own `name` and [`ScrapeLabel`] key/value pairs (not
//!   value-only, family-shared keys): a histogram's `_bucket`/`_sum`/`_count` legs and a
//!   summary's `quantile` legs need their own series name and their own `le`/`quantile` label,
//!   and `value` is the recorder's own string spelling, not `f64` — so the exposition `scrape`
//!   renders can reproduce the host's byte for byte.
//! - [`CheckIn`] carries `instances`/`instances_len` ([`CheckInstance`]): the OLD
//!   `Check{instances}` exists precisely for checks that read across every instance of a sink's
//!   module.
//!
//! B.5, transcribed:
//! - **Tail:** `streams[]`, pinned to the OLD `ExportStream::ALL` order
//!   (`abi/cold/export.rs`: metrics, logs, traces, costs, decisions, events, identity, prompts,
//!   completions — `decisions` is a FROZEN wire word, unchanged by this move).
//! - `deliver{stream u8, batch jsonl}` — built at batch time with the `fields:` projection applied
//!   KERNEL-side (never in this kind's shapes: the batch a plugin receives is already projected).
//! - `scrape(families)` over the host snapshot service.
//! - `status` (1.5.5 blob), `check`, `serve`.
//! - **Listener.** `/metrics` is served on the data listener through the export route exception,
//!   confined to `/metrics` or `/exports/<name>/*`, the reserved paths and the 64-header cap.
//!   `/metrics/hooks` stays a core route. (Kernel routing; not a new shape here.)
//! - **Behaviour.** Webhook and otlp use driver tickets (the shared mechanism's
//!   [`Ticket`](super::mechanism::ticket::Ticket) `drive`/`DriveIn` lifecycle slot, not a new
//!   export op). The `Host` and `Started` 1.5.5 response variants are retired: `deliver` answers
//!   only READY/PENDING/FAILED/REFUSED/FAULT, with no host-op round trip and no separate `start`.
//!
//! ASSUMPTIONS (M3-SHAPES, noted for the SLOT-LOG; none are money- or customer-visible, so none is
//! an owner question):
//! - `deliver` is OFF-PATH, `may_pend`, [`DeadlineClass::WriteBehind`](super::mechanism::call::DeadlineClass::WriteBehind)
//!   (a sink write, coalesced like a store batch write, never on a request's critical path).
//! - `scrape` is REQUEST-PATH (P) — `/metrics` is answered per HTTP request — `may_pend`,
//!   [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call).
//! - `status` and `check` are OFF-PATH (O), not `may_pend` (fast, in-memory).
//! - `serve` is OFF-PATH (O) per B.4's hook precedent for a plugin's own HTTP surface, `may_pend`,
//!   [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call).
//! - No Statement tail beyond `streams[]` is stated for export; `check`'s phases (`limits` /
//!   `instances`, 1.5.5 `CheckPhase`) are carried as a `u32` `in` field rather than a new type.

use super::mechanism::call::{AbiStr, Blob, InHead, Op, OutHead};

pub mod validate;
use super::mechanism::door::KindTailHead;
use super::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

/// The export kind's ABI version: v1.5.5 shipped `2` (`EXPORT_ABI_VERSION`), so 1.6.0 ships `3`.
pub const ABI_VERSION: u32 = 3;

/// [`InHead::op`] values the export kind adds after the shared lifecycle, in table order.
///
/// # Examples
/// ```
/// use busbar_contract::abi::export::{slot, SLOTS};
/// use busbar_contract::abi::mechanism::lifecycle::LIFECYCLE_SLOTS;
/// assert_eq!(slot::DELIVER, LIFECYCLE_SLOTS + 0);
/// assert_eq!(slot::SCRAPE, LIFECYCLE_SLOTS + 1);
/// assert_eq!(slot::STATUS, LIFECYCLE_SLOTS + 2);
/// assert_eq!(slot::CHECK, LIFECYCLE_SLOTS + 3);
/// assert_eq!(slot::SERVE, LIFECYCLE_SLOTS + 4);
/// assert_eq!(SLOTS, LIFECYCLE_SLOTS + 5);
/// ```
pub mod slot {
    use super::LIFECYCLE_SLOTS;

    /// `deliver`.
    pub const DELIVER: u32 = LIFECYCLE_SLOTS;
    /// `scrape`.
    pub const SCRAPE: u32 = LIFECYCLE_SLOTS + 1;
    /// `status`.
    pub const STATUS: u32 = LIFECYCLE_SLOTS + 2;
    /// `check`.
    pub const CHECK: u32 = LIFECYCLE_SLOTS + 3;
    /// `serve`.
    pub const SERVE: u32 = LIFECYCLE_SLOTS + 4;
}

/// How many slots the export kind's whole table holds (the lifecycle plus its five own ops).
pub const SLOTS: u32 = LIFECYCLE_SLOTS + 5;

/// The export kind's ops table. Leads with the shared [`OpsHead`]; kind op `k` is at slot index
/// [`LIFECYCLE_SLOTS`]` + k` ([`slot`]).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ops {
    /// The lifecycle.
    pub head: OpsHead,
    /// Hand one already-projected batch for a declared stream to the sink. OFF-PATH, `may_pend`,
    /// [`DeadlineClass::WriteBehind`](super::mechanism::call::DeadlineClass::WriteBehind). In
    /// [`DeliverIn`], out [`OutHead`] (nothing to read back).
    pub deliver: Option<Op>,
    /// Render the host recorder's snapshot as this sink's exposition text. REQUEST-PATH,
    /// `may_pend`, [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call). In
    /// [`ScrapeIn`], out [`ScrapeOut`].
    pub scrape: Option<Op>,
    /// What the sink has to report when the host renders its status exposition. OFF-PATH, not
    /// `may_pend`. In [`InHead`], out [`StatusOut`] (the 1.5.5 status blob, unchanged).
    pub status: Option<Op>,
    /// The sink's own configuration/operational checks. OFF-PATH, not `may_pend`. In
    /// [`CheckIn`], out [`CheckOut`].
    pub check: Option<Op>,
    /// The sink's own HTTP surface (`/exports/<name>/*`). OFF-PATH, `may_pend`,
    /// [`DeadlineClass::Call`](super::mechanism::call::DeadlineClass::Call). In [`ServeIn`], out
    /// [`ServeOut`].
    pub serve: Option<Op>,
}

/// `deliver`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DeliverIn {
    /// The head.
    pub head: InHead,
    /// The dedupe/replay id the kernel mints, one per batch (the same discipline as the store's
    /// additive writes).
    pub op_id: [u8; 16],
    /// Which declared [`ExportStream`] this batch belongs to.
    pub stream: u8,
    /// Alignment padding.
    pub _reserved: [u8; 7],
    /// The already-projected batch, JSON LINES (`fields:` already applied kernel-side).
    pub batch: Blob,
}

/// One stream an export sink can carry OUT of the engine — pinned to the OLD `ExportStream::ALL`
/// order (`abi/cold/export.rs`). Frozen wire words; `decisions` is one of them.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportStream {
    /// `metrics`.
    Metrics = 0,
    /// `logs`.
    Logs = 1,
    /// `traces`.
    Traces = 2,
    /// `costs`.
    Costs = 3,
    /// `decisions` — a FROZEN wire word (`ExportDefCfg` `streams:` token since 1.5.5).
    Decisions = 4,
    /// `events`.
    Events = 5,
    /// `identity`.
    Identity = 6,
    /// `prompts`.
    Prompts = 7,
    /// `completions`.
    Completions = 8,
}

impl ExportStream {
    /// Every stream, in the frozen `ExportStream::ALL` order.
    pub const ALL: [ExportStream; 9] = [
        ExportStream::Metrics,
        ExportStream::Logs,
        ExportStream::Traces,
        ExportStream::Costs,
        ExportStream::Decisions,
        ExportStream::Events,
        ExportStream::Identity,
        ExportStream::Prompts,
        ExportStream::Completions,
    ];
}

/// [`ScrapeFamily::kind`]: a counter.
pub const SCRAPE_KIND_COUNTER: u8 = 0;
/// [`ScrapeFamily::kind`]: a gauge.
pub const SCRAPE_KIND_GAUGE: u8 = 1;
/// [`ScrapeFamily::kind`]: a histogram (`_bucket`/`_sum`/`_count` legs as separate
/// [`ScrapeSample`]s).
pub const SCRAPE_KIND_HISTOGRAM: u8 = 2;
/// [`ScrapeFamily::kind`]: a summary (`quantile` legs as separate [`ScrapeSample`]s).
pub const SCRAPE_KIND_SUMMARY: u8 = 3;
/// [`ScrapeFamily::kind`]: untyped.
pub const SCRAPE_KIND_UNTYPED: u8 = 4;

/// One label on a [`ScrapeSample`]: a key AND its value, ARCHITECT review ruling (fresh-Opus
/// M3-SHAPES review, parity item) — a value-only array cannot carry a histogram's `le` or a
/// summary's `quantile` label, which is exactly what makes the 1.5.5 exposition losslessly
/// reproducible.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScrapeLabel {
    /// The label key.
    pub key: AbiStr,
    /// The label value.
    pub value: AbiStr,
}

/// One sample of a [`ScrapeFamily`]'s snapshot: its own series name (a histogram's `_bucket`/
/// `_sum`/`_count` and a summary's `quantile` legs are each their own named series), its labels
/// and its value as the recorder's OWN STRING SPELLING (not `f64` — ARCHITECT review ruling:
/// re-rendering a re-parsed float would not reproduce the host's exposition byte for byte).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScrapeSample {
    /// This sample's own series name (the family name, or the family name plus its `_bucket`/
    /// `_sum`/`_count` suffix).
    pub name: AbiStr,
    /// This sample's labels.
    pub labels: *const ScrapeLabel,
    /// How many.
    pub labels_len: usize,
    /// The recorder's own spelling of the value, unchanged.
    pub value: AbiStr,
}

/// One metric family of the host recorder's snapshot, handed to `scrape` so the sink can render
/// its own exposition.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScrapeFamily {
    /// The family name.
    pub name: AbiStr,
    /// Its help text.
    pub help: AbiStr,
    /// Its unit; absent = none.
    pub unit: AbiStr,
    /// [`SCRAPE_KIND_COUNTER`] | [`SCRAPE_KIND_GAUGE`] | [`SCRAPE_KIND_HISTOGRAM`] |
    /// [`SCRAPE_KIND_SUMMARY`] | [`SCRAPE_KIND_UNTYPED`].
    pub kind: u8,
    /// Alignment padding.
    pub _reserved: [u8; 7],
    /// The samples, each carrying its own labels (ARCHITECT review ruling: labels moved onto the
    /// sample, not shared at the family level, so a histogram/summary series keeps its `le`/
    /// `quantile` label).
    pub samples: *const ScrapeSample,
    /// How many.
    pub samples_len: usize,
}

/// `scrape`'s `in`. ARCHITECT review ruling 2 (fresh-Opus M3-SHAPES review, 2026-09-28): the
/// rendered-exposition buffer is HOST-owned and lives here, in the `in` (request-path results are
/// host buffers, never a plugin-owned pointer in `out`; the host zeroes `out` before the call, so
/// nothing the plugin needs may live there).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScrapeIn {
    /// The head.
    pub head: InHead,
    /// The host recorder's WHOLE snapshot (the SEH fix-forward ruling, 2026-09-27) — every
    /// family, not filtered to this instance's Statement — in the 1.5.5 recorder's render order,
    /// kind-then-name.
    pub families: *const ScrapeFamily,
    /// How many.
    pub families_len: usize,
    /// The host-owned buffer the plugin renders its exposition text into.
    pub buf: *mut u8,
    /// `buf`'s capacity, in bytes.
    pub cap: usize,
}

/// `scrape`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScrapeOut {
    /// The head.
    pub head: OutHead,
    /// How many bytes the plugin wrote into [`ScrapeIn::buf`].
    pub written: usize,
    /// `0` unless `written == 0` because `buf` was too small: the byte length the plugin needed.
    /// The host re-invokes ONCE with a buffer at least this large.
    pub needed: usize,
}

/// `status`'s `out`. OFF-PATH: `status` is a plugin-owned result, memory class (iv) — live under
/// `head.lease` until `release(lease)` (ARCHITECT review ruling 3).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StatusOut {
    /// The head.
    pub head: OutHead,
    /// The 1.5.5 status JSON, unchanged, as a [`super::mechanism::call::BLOB_JSON`] blob, under
    /// `head.lease` (off-path JSON-as-payload is allowed here per the mechanism's one JSON rule).
    pub status: Blob,
}

/// [`CheckIn::phase`]: among the operational limits' checks (a bound this sink's instances
/// share) — the OLD `CheckPhase::Limits`.
pub const CHECK_PHASE_LIMITS: u32 = 0;
/// [`CheckIn::phase`]: after the limits, each instance's own settings — the OLD
/// `CheckPhase::Instances` (the 1.5.5 default).
pub const CHECK_PHASE_INSTANCES: u32 = 1;

/// One instance `check` may read across, at [`CHECK_PHASE_INSTANCES`] (ARCHITECT review ruling,
/// fresh-Opus M3-SHAPES review, parity item: the OLD `Check{instances}` exists precisely for
/// checks that read across every instance of a sink's module, not only the one being called).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CheckInstance {
    /// The instance's name.
    pub name: AbiStr,
    /// The instance's settings blob.
    pub settings: Blob,
}

/// `check`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CheckIn {
    /// The head.
    pub head: InHead,
    /// [`CHECK_PHASE_LIMITS`] | [`CHECK_PHASE_INSTANCES`].
    pub phase: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// Every instance of this sink's module (meaningful mainly at
    /// [`CHECK_PHASE_INSTANCES`]).
    pub instances: *const CheckInstance,
    /// How many.
    pub instances_len: usize,
}

/// `check`'s `out`. OFF-PATH: `findings` is a plugin-owned result, memory class (iv) — live under
/// `head.lease` until `release(lease)` (ARCHITECT review ruling 3).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CheckOut {
    /// The head.
    pub head: OutHead,
    /// The sink's check findings, as a [`super::mechanism::call::BLOB_JSON`] blob, under
    /// `head.lease` (so they keep their place among the configuration's other errors, the 1.5.5
    /// `CheckPhase` ordering).
    pub findings: Blob,
}

/// `serve`'s `in`: one HTTP request dispatched to this sink's own routes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServeIn {
    /// The head.
    pub head: InHead,
    /// The HTTP method.
    pub method: AbiStr,
    /// The path, confined to `/metrics` or `/exports/<name>/*`.
    pub path: AbiStr,
    /// The raw query string; absent = none.
    pub query: AbiStr,
    /// Header name/value pairs, interleaved (`name`, `value`, `name`, `value`, …); capped at 64
    /// pairs (the 64-header cap).
    pub headers: *const AbiStr,
    /// How many `AbiStr` entries `headers` holds (twice the header count).
    pub headers_len: usize,
    /// The request body; absent = none.
    pub body: Blob,
}

/// `serve`'s `out`. OFF-PATH: the response is a plugin-owned result, memory class (iv) — the
/// headers and body live under `head.lease` until `release(lease)` (ARCHITECT review ruling 3).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServeOut {
    /// The head.
    pub head: OutHead,
    /// The HTTP status code.
    pub status_code: u16,
    /// Alignment padding.
    pub _reserved: [u8; 6],
    /// Response header name/value pairs, interleaved, under `head.lease` until `release(lease)`
    /// (an off-path list, memory class iv).
    pub headers_out: *const AbiStr,
    /// How many `AbiStr` entries `headers_out` holds.
    pub headers_out_len: usize,
    /// The response body, under `head.lease` until `release(lease)` (memory class iv).
    pub body: Blob,
}

/// [`Route::auth`]: no auth required before `serve` — OLD `RouteAuth::None`.
pub const ROUTE_AUTH_NONE: u32 = 0;
/// [`Route::auth`]: a data-plane key required before `serve` — OLD `RouteAuth::Key`.
pub const ROUTE_AUTH_KEY: u32 = 1;
/// [`Route::auth`]: admin auth required, reachable only on the admin listener — OLD
/// `RouteAuth::Admin`.
pub const ROUTE_AUTH_ADMIN: u32 = 2;

/// One HTTP route this instance serves via `serve` (ARCHITECT review ruling, fresh-Opus
/// M3-SHAPES review, parity item): `{path, method}` is the collision key the kernel checks at
/// load; `auth` is enforced by the kernel BEFORE `serve` is ever called.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Route {
    /// The path, confined to `/metrics` or `/exports/<name>/*`.
    pub path: AbiStr,
    /// The HTTP method.
    pub method: AbiStr,
    /// [`ROUTE_AUTH_NONE`] | [`ROUTE_AUTH_KEY`] | [`ROUTE_AUTH_ADMIN`].
    pub auth: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// The export kind's Statement tail: the streams this instance carries and the routes it serves.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Tail {
    /// The head.
    pub head: KindTailHead,
    /// This instance's declared streams, as [`ExportStream`] bytes.
    pub streams: *const u8,
    /// How many.
    pub streams_len: usize,
    /// The HTTP routes this instance serves via `serve` (ARCHITECT review ruling: 1.5.5 asked
    /// each instance at load, e.g. the `Routes` op; here it is a Statement fact).
    pub routes: *const Route,
    /// How many.
    pub routes_len: usize,
}

/// The export kind's [`super::mechanism::lifecycle::CancelOut::disposition`] vocabulary.
///
/// ASSUMPTION (M3-SHAPES): B.5 states no cancel disposition vocabulary. `deliver`, `scrape` and
/// `serve` are the `may_pend` ops; the dispositions below cover all three uniformly (a batch/
/// exposition/response either landed or did not — a telemetry sink has no partial-delivery
/// concept of its own, unlike a chunked streaming reply's own disposition vocabulary).
pub mod cancel {
    /// The pending op was aborted before it produced anything (deliver: the batch was not
    /// accepted; scrape/serve: no bytes were written to the host buffer).
    pub const ABORTED: u32 = 0;
    /// The op had already completed when the cancel arrived (a race with the deadline); its
    /// result stands.
    pub const RACED_TO_COMPLETION: u32 = 1;
}
