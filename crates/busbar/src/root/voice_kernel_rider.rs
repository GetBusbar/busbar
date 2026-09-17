// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DORMANT VOICE KERNEL-LOOP SESSION RIDER — the fourth WITNESS on the generic bridge, and the
//! first of the two SESSION planes (voice, duplex) onto the unified kernel loop's session admit.
//!
//! This module onboards the VOICE session-open onto the unified kernel loop the SAME way MCP/A2A/LLM
//! did (DECISIONS #28), but on the SESSION seat rather than the one-shot one: as a THIN VERBATIM RIDER
//! over the plane-neutral bridge [`crate::root::gauntlet_kernel::open_gauntlet_via_kernel`].
//! [`admit_voice_session_via_kernel`] drives the SAME voice `GauntletPlane` — the `SessionGauntlet` in
//! `busbar-voice`'s `topology/mod.rs`, whose `verify_destination` refuses a denied upstream model and
//! whose `drive` is UNREACHABLE on the session path — through `busbar_kernel::teller::open_unit` (the
//! governance-to-admit hand-back, no Route, no settling exit) instead of the substrate `admit_open`.
//!
//! MONEY STAYS EXACTLY PLANE-SIDE, AFTER THE GATE. The voice session's reserve-on-admit
//! (`cost_reserve`, `topology/mod.rs`'s `open_admitted_session` / the D2 lease) and its per-turn
//! settle (`TurnMeter` `cost_settle` / `meter_ledger`) fire only AFTER `run_gauntlet_session` clears —
//! never inside the admit gate. This kernel admit is EMPTY by construction (`Admission::ZeroHold`, no
//! exit-settle, no `bind_book`, `Evidence::default`), so the two admit paths overlap the plane's money
//! in ZERO places: a refused open costs zero bytes and zero charge on both, and an admitted open moves
//! no money on either — the plane's reserve/turn-settle are the sole authority, unchanged.
//!
//! DORMANT — DUAL-PATH, AUTHORITY NOT FLIPPED. The shipped voice authority stays
//! `busbar_substrate::plane_host::run_gauntlet_session` (reached by `topology/mod.rs`'s `begin_session`
//! and by `mount.rs`'s `ws_accept` → `accept_gauntlet`). This rider is built and shadow-proven
//! byte-identical here, but the one-line flip — registering the kernel session runner under the voice
//! capability key at the composition root ([`crate::root::gauntlet_install::flip_session_to_kernel`]),
//! which covers BOTH session planes through the ONE `admit_open` seat `run_gauntlet_session` consults —
//! waits on the fleet-box money oracle and the owner (DECISIONS #29). The plane's `capability_key`
//! stays `None`, so with nothing registered every session path rides the substrate loop, byte-identical
//! to the shipped release.
//!
//! WHY `#[cfg(any(test, feature = "test-harness"))]`. Like `gauntlet_kernel`/`a2a_kernel_rider`, the
//! rider is a re-point of an existing call, not a new production surface. Compiling it (and its shadow
//! proof) test/harness-only keeps zero ship surface AND zero dead-code while the authority is dormant.
//!
//! PLANE-NEUTRALITY. The bridge names no plane: `open_gauntlet_via_kernel`, `GauntletPlane`,
//! `PlaneAnswer` and `PlaneInFlight` carry no `voice` noun. This module is the ONLY place the voice
//! rider names voice, and it does so only to point the neutral bridge at the voice session gate.

use axum::response::Response;
use busbar_substrate::plane_host::{Admitted, GauntletPlane, GauntletRequest};

use crate::root::gauntlet_kernel::open_gauntlet_via_kernel;

/// OPEN a voice session through the UNIFIED kernel loop and return at the door — the dormant
/// kernel-loop twin of the shipped `run_gauntlet_session` admit the voice plane reaches through
/// `begin_session` (`topology/mod.rs`) and `accept_gauntlet` (`mount.rs`).
///
/// A one-line delegation to the plane-neutral session bridge: the voice `SessionGauntlet` rides it with
/// ZERO new bridge code. On a pass the door admitted at `Admission::ZeroHold` (nothing settled) and the
/// caller opens its own carrier next — its `cost_reserve` and per-turn `cost_settle` stay plane-side,
/// AFTER this gate. On a refusal the plane's OWN finished response comes back verbatim. The flip is
/// re-pointing the shipped call to this function (via the composition-root session-runner registry);
/// nothing else changes, because the voice gate's `verify_destination` is byte-identical on both loops.
///
/// (`result_large_err`: the `Err` is the plane's OWN finished refusal `Response`, carried BY VALUE so
/// refusal shaping stays byte-identical to the substrate `run_gauntlet_session` — the same type that
/// path returns un-boxed.)
#[allow(clippy::result_large_err)]
pub(crate) fn admit_voice_session_via_kernel(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
) -> Result<Admitted, Response> {
    open_gauntlet_via_kernel(req, plane)
}

#[cfg(test)]
#[path = "tests/voice_kernel_rider.rs"]
mod tests;
