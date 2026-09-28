// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT KIND'S ABI: its version and its table (the design's locked plugin ABI: one
//! mechanism, every shape in `abi/`). M0 landed the skeleton; this is M3-SHAPES
//! (`abi-v2-perkind.md` B.5): `deliver`, `scrape`, `status`, `check` and `serve`, and the frozen
//! [`ExportStream`] tail. NOTHING dispatches through this yet (M3-wire, after M1).
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

/// One label value applied to a [`ScrapeSample`], in the family's declared `label_keys` order.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScrapeSample {
    /// The label values, in the family's declared key order.
    pub label_vals: *const AbiStr,
    /// How many.
    pub label_vals_len: usize,
    /// The recorder's own value, as it will render (a histogram's `_bucket`/`_sum`/`_count` and a
    /// summary's `quantile` legs are samples of their family, carried as the recorder wrote them).
    pub value: f64,
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
    /// Its label keys, in order.
    pub label_keys: *const AbiStr,
    /// How many.
    pub label_keys_len: usize,
    /// [`super::mechanism::door::FAMILY_COUNTER`] | [`super::mechanism::door::FAMILY_GAUGE`] |
    /// [`super::mechanism::door::FAMILY_HISTOGRAM`].
    pub kind: u8,
    /// Alignment padding.
    pub _reserved: [u8; 7],
    /// The samples.
    pub samples: *const ScrapeSample,
    /// How many.
    pub samples_len: usize,
}

/// `scrape`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScrapeIn {
    /// The head.
    pub head: InHead,
    /// The host recorder's snapshot, filtered to the families this instance's Statement declared.
    pub families: *const ScrapeFamily,
    /// How many.
    pub families_len: usize,
}

/// `scrape`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScrapeOut {
    /// The head.
    pub head: OutHead,
    /// The rendered exposition text, into the host's buffer (`out.exposition.len` is the
    /// capacity; the plugin writes at most that many bytes, the request-path buffer discipline).
    pub exposition: Blob,
}

/// `status`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StatusOut {
    /// The head.
    pub head: OutHead,
    /// The 1.5.5 status JSON, unchanged, as a [`super::mechanism::call::BLOB_JSON`] blob (off-path
    /// JSON-as-payload is allowed here per the mechanism's one JSON rule).
    pub status: Blob,
}

/// [`CheckIn::phase`]: among the operational limits' checks (a bound this sink's instances
/// share) — the OLD `CheckPhase::Limits`.
pub const CHECK_PHASE_LIMITS: u32 = 0;
/// [`CheckIn::phase`]: after the limits, each instance's own settings — the OLD
/// `CheckPhase::Instances` (the 1.5.5 default).
pub const CHECK_PHASE_INSTANCES: u32 = 1;

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
}

/// `check`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CheckOut {
    /// The head.
    pub head: OutHead,
    /// The sink's check findings, as a [`super::mechanism::call::BLOB_JSON`] blob (so they keep
    /// their place among the configuration's other errors, the 1.5.5 `CheckPhase` ordering).
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

/// `serve`'s `out`.
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
    /// The response body.
    pub body: Blob,
}

/// The export kind's Statement tail: the streams this instance carries.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Tail {
    /// The head.
    pub head: KindTailHead,
    /// This instance's declared streams, as [`ExportStream`] bytes.
    pub streams: *const u8,
    /// How many.
    pub streams_len: usize,
}

/// The export kind's [`super::mechanism::lifecycle::CancelOut::disposition`] vocabulary.
///
/// ASSUMPTION (M3-SHAPES): B.5 states no cancel disposition vocabulary. `deliver`, `scrape` and
/// `serve` are the `may_pend` ops; the dispositions below cover all three uniformly (a batch/
/// exposition/response either landed or did not — there is no partial-delivery concept for a
/// telemetry sink, unlike plane's `ok_partial`).
pub mod cancel {
    /// The pending op was aborted before it produced anything (deliver: the batch was not
    /// accepted; scrape/serve: no bytes were written to the host buffer).
    pub const ABORTED: u32 = 0;
    /// The op had already completed when the cancel arrived (a race with the deadline); its
    /// result stands.
    pub const RACED_TO_COMPLETION: u32 = 1;
}
