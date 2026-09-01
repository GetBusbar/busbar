// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE→CORE FACADE — the one, narrow, `pub` re-export surface the extracted LLM engine reaches
//! DOWN into `busbar-core` through once it lives in `busbar-llm`.
//!
//! ## Why this module exists (1.6.0 money-path relocation, Phase 0)
//!
//! The LLM proxy money path (the egress engine, the ingress-native finish/audit tail, the failover
//! disposition halves, the breaker admission FSM) still physically lives in `busbar-core`, but it is
//! being relocated into `busbar-llm`. Once relocated, the engine calls DOWN into core across the
//! crate boundary — the ALLOWED plane→core edge (`busbar-llm` normal-depends on `busbar-core`). For
//! that edge to compile, the neutral primitives the engine drives must be reachable as `pub`.
//!
//! Rather than blanket-`pub` those internal types (which would widen the whole crate's API surface and
//! be hard to walk back), every primitive keeps its TIGHT declared visibility (`pub(crate)` on the
//! trait / struct / fn) and is surfaced here through a single `pub use` re-export. The declared
//! visibility is unchanged, so nothing new leaks through the ordinary `crate::` paths and the
//! `private_interfaces` discipline is untouched — this facade is the ONLY externally-visible path to
//! these items, so Phase 6 can tighten the surface back to exactly what the relocated engine consumes
//! by editing this one file.
//!
//! NOTHING in core consumes this module: the engine has not moved yet (Phases 2–5). It is a pure,
//! behavior-neutral visibility lift wired ahead of the move, per the migration law (wire the seam in
//! place, THEN relocate — no commit both moves files and changes behavior).

// ── the breaker admission FSM the engine drives (store) ──────────────────────────────────────────
// `LaneRuntime` carries the whole admission surface — `try_admit`, `try_admit_breaker`, `classify`,
// the outcome-recording write path — as trait methods, so re-exporting the trait exposes them all;
// `Admit` is the held-resources token `try_admit` returns.
pub use crate::store::{Admit, LaneRuntime};

// ── the failover disposition halves the engine records through (failover) ────────────────────────
// The LLM-shaped halves that stay over `crate::store::LaneRuntime` + `crate::breaker`: the
// breaker-only `walk` spelling and the `record_outcome` / `record_success` disposition writers. The
// candidate/stage/refusal/order/walk_with FAMILY is already `pub` at `busbar_substrate::failover`.
pub use crate::failover::{record_outcome, record_success, walk};

// ── the ingress-native finish / audit tail the gauntlet drive calls (ingress) ────────────────────
// The post-admission finish terminals — metrics record + request-log/audit-chain append + the
// conditional non-2xx refund. `finish_admitted` is the charged-admission terminal the native drive
// path ends on; `finish_rejected` is the pre-charge turn-away terminal.
pub use crate::ingress::{finish_admitted, finish_rejected};

// ── the neutral egress engine the outbound leg is built from (proxy) ─────────────────────────────
// Already `pub` at `crate::proxy` (re-exported there from `busbar_substrate::egress::engine`);
// surfaced here too so the engine's whole DOWN edge names one facade path.
pub use crate::proxy::{
    egress_request, install_proxy_tunnel_if_configured, EgressClient, EgressClientSpec,
    EgressConnector, EgressError,
};

// ── the money-path lowering primitives the LLM plane drives DOWN (1.6.0 money-path Phase 3-4 A) ────
// The lane/pool lowering that relocates into `busbar-llm` in Commit C builds the egress leg from these
// neutral primitives. Each keeps its declared visibility (`pub`, lifted from `pub(crate)` in Commit A)
// and is surfaced here so the plane→core edge names ONE facade path. None carries dialect vocabulary,
// so the plane-grep meter is unmoved. NOTHING in core consumes this section — the engine has not moved
// (wire the seam in place, THEN relocate).
//
// ── the boot egress-client + target-table build (proxy) ──────────────────────────────────────────
pub use crate::proxy::{build_egress_client, build_egress_targets, host_from_base, EgressTarget};
// ── the outbound credential resolve + boot prebuild + SSRF posture (egress_auth) ─────────────────
pub use crate::egress_auth::{prebuild_auth, resolve, CredentialProvider, MetadataSsrfPolicy};
// ── the per-shard upstream client fan-out + the active-probe schedule (state / health) ───────────
pub use crate::health::ProbeSchedule;
pub use crate::state::UpstreamClients;
// ── the neutral lane-protocol-name resolver the lowering keys egress targets on (proto) ──────────
pub use crate::proto::lane_protocol_name;
