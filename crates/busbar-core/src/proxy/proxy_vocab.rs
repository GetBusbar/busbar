// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL proxy vocabulary that STAYS in `busbar-core` once the LLM engine moves to the
//! `busbar-llm` plane (1.6.0 money-path Phase 3-4 C). Everything here is dialect-blind: the capped
//! upstream-body read, the tight upstream-buffer cap, the hook-content ceiling knob, the fire-and-
//! forget STAGE usage-tap primitives, and the agnostic ingress-error shaper. Core's own staying call
//! sites (`egress_auth`, `egress::seam`, `preflight`, `auth`, `config`, `appbuild`) name these at
//! their historical `crate::proxy::*` paths (re-exported from `proxy/mod.rs`), and the relocated
//! engine names them across the crate boundary as `busbar_core::proxy::*` — neither reaches for a
//! dialect, so the plane can be dropped from the build without taking any of this with it.

// THE CAPPED READ and its `ReadEnd` outcome live in the neutral `busbar-substrate` crate (both
// core's egress/auth paths and the relocated proxy engine read upstream bodies this way, and a plane
// crate names them without reaching into core). Re-exported here so every core `crate::proxy::{
// read_capped, ReadEnd}` call site resolves unchanged.
pub use busbar_substrate::proxy::{read_capped, ReadEnd};

/// Upper bound on a buffered UPSTREAM ERROR body (4xx/5xx envelopes). Operator-tunable via
/// `limits.upstream_error_body_max_bytes` (defaults to 256 KiB). A function (not a `const`) so the
/// process-wide installed value is read at each use site; falls back to the historical default when
/// the limits aren't installed (e.g. unit tests).
pub fn max_upstream_buffered_bytes() -> usize {
    crate::limits::upstream_error_body_max_bytes()
}

// The hook-content ceiling (the default, the process-global slot's setter, and the reader) now lives
// in the neutral `busbar_substrate::proxy` so the relocated hook-projection enforcer names it without
// reaching into `busbar-core`. Re-exported here so every core `crate::proxy::{
// DEFAULT_HOOK_CONTENT_MAX_BYTES, set_hook_content_max_bytes, hook_content_max_bytes}` call site
// (`config`, `appbuild`) resolves unchanged.
pub use busbar_substrate::proxy::{
    hook_content_max_bytes, set_hook_content_max_bytes, DEFAULT_HOOK_CONTENT_MAX_BYTES,
};

// THE PER-REQUEST STAGE SHAPE CAPTURE relocated DOWN to `busbar_substrate::proxy::proxy_vocab`
// (App-retype WEDGE 2e), so a plane crate builds the shape without reaching into `busbar-core`.
// Re-exported here so every core `crate::proxy::StageShape` call site — and core's own
// `fire_stage_taps` below, which takes `&StageShape` — resolves unchanged.
pub use busbar_substrate::proxy::proxy_vocab::StageShape;

// App-retype WEDGE 3 (THE FLIP): core's `fire_stage_taps` + `spawn_bounded_tap` (and their
// `AdmissionGate`-backed 1024-permit `tap_inflight` cap) are RETIRED. Every tap fan-out — the LLM
// engine's stage/global taps AND core's own auth-denial tap — now fires through the neutral
// `busbar_substrate::proxy::proxy_vocab::{fire_stage_taps, spawn_bounded_tap}`, which owns the ONE
// shared 1024-permit gate. Keeping a second core-side gate would split the cap into two independent
// 1024 semaphores (the exact hazard WEDGE 2e parked this on core to avoid); with the pipeline flipped,
// the single shared gate lives in the substrate and this core pair is dead, so it is deleted rather
// than left to drift. The saturation metrics (`busbar_tap_notifications_dropped_total` +
// `busbar_admission_denied_total{gate="tap"}`) are emitted byte-identically by the substrate twin.

// THE GATE-REJECTION MARKER + tagger relocated DOWN to `busbar_substrate::proxy::proxy_vocab`
// (App-retype WEDGE 2e), so a plane crate tags/reads the marker without reaching into `busbar-core`.
// Re-exported here so every core `crate::proxy::{GateRejected, gate_rejected}` call site resolves
// unchanged.
pub use busbar_substrate::proxy::proxy_vocab::{gate_rejected, GateRejected};

// THE AGNOSTIC INGRESS-ERROR SHAPER and its neutral fallback envelope RELOCATED DOWN to
// `busbar_substrate::proxy` (the extracted `busbar-llm` native-ingress path shapes an ingress error
// through the neutral ABI); re-exported here at their historical `crate::proxy::{ingress_error,
// agnostic_error_envelope}` paths so every in-core caller is unchanged. They name no dialect —
// `proto::decl_for` reads whatever registry the resident planes populated — and the fallback is
// neutral, so both survive the LLM plane being dropped from the build.
pub use busbar_substrate::proxy::{agnostic_error_envelope, ingress_error};
