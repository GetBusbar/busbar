// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DORMANT DUPLEX KERNEL-LOOP SESSION RIDER — the fifth and LAST WITNESS on the generic bridge,
//! completing all five planes' (mcp, a2a, llm, voice, duplex) dormant onboarding, and the second of the
//! two SESSION planes onto the unified kernel loop's session admit.
//!
//! This module onboards the DUPLEX WS-accept session-open onto the unified kernel loop the SAME way the
//! four siblings did (DECISIONS #28), on the SESSION seat: as a THIN VERBATIM RIDER over the
//! plane-neutral bridge [`crate::root::gauntlet_kernel::open_gauntlet_via_kernel`].
//! [`admit_duplex_session_via_kernel`] drives the SAME duplex gate `GauntletPlane` — the open-pass gate
//! `busbar_substrate::ingress::duplex_ws`'s `accept_gauntlet` runs, whose `verify_destination` refuses a
//! denied destination BEFORE any socket binds and whose `drive` is UNREACHABLE on the session path —
//! through `busbar_kernel::teller::open_unit` (governance-to-admit, no Route, no settling exit) instead
//! of the substrate `admit_open`.
//!
//! MONEY STAYS EXACTLY PLANE-SIDE, AFTER THE GATE. The duplex session's reserve-on-admit and per-frame
//! settle happen INSIDE `on_socket` — AFTER `accept_gauntlet` admitted and BEFORE the pump reads a byte
//! — never inside the admit gate. This kernel admit is EMPTY by construction (`Admission::ZeroHold`, no
//! exit-settle, no `bind_book`, `Evidence::default`), so the two admit paths overlap the plane's money
//! in ZERO places: a refused accept binds no socket and charges nothing on both, and an admitted accept
//! moves no money on either — the plane's post-admit reserve/per-frame settle are the sole authority,
//! unchanged.
//!
//! DORMANT — DUAL-PATH, AUTHORITY NOT FLIPPED. The shipped duplex authority stays
//! `busbar_substrate::plane_host::run_gauntlet_session` (reached by `duplex_ws.rs`'s `accept_gauntlet`).
//! This rider is built and shadow-proven byte-identical here, but the one-line flip — registering the
//! kernel session runner under the duplex capability key at the composition root
//! ([`crate::root::gauntlet_install::flip_session_to_kernel`]), the SAME `admit_open` seat
//! `run_gauntlet_session` consults for BOTH session planes — waits on the fleet-box money oracle and the
//! owner (DECISIONS #29). The gate's `capability_key` stays `None`, so with nothing registered every
//! session path rides the substrate loop, byte-identical to the shipped release.
//!
//! WHY `#[cfg(any(test, feature = "test-harness"))]`. Like `gauntlet_kernel`/`a2a_kernel_rider`, the
//! rider is a re-point of an existing call, not a new production surface. Compiling it (and its shadow
//! proof) test/harness-only keeps zero ship surface AND zero dead-code while the authority is dormant.
//!
//! PLANE-NEUTRALITY. The bridge names no plane: `open_gauntlet_via_kernel`, `GauntletPlane`,
//! `PlaneAnswer` and `PlaneInFlight` carry no `duplex` noun. This module is the ONLY place the duplex
//! rider names duplex, and it does so only to point the neutral bridge at the duplex session gate.

use axum::response::Response;
use busbar_substrate::plane_host::{Admitted, GauntletPlane, GauntletRequest};

use crate::root::gauntlet_kernel::open_gauntlet_via_kernel;

/// OPEN a duplex WS session through the UNIFIED kernel loop and return at the door — the dormant
/// kernel-loop twin of the shipped `run_gauntlet_session` admit the duplex plane reaches through
/// `accept_gauntlet` (`busbar_substrate::ingress::duplex_ws`).
///
/// A one-line delegation to the plane-neutral session bridge: the duplex gate rides it with ZERO new
/// bridge code. On a pass the door admitted at `Admission::ZeroHold` (nothing settled) and
/// `accept_gauntlet` accepts the upgrade next — the session's reserve-on-admit and per-frame settle stay
/// plane-side, AFTER this gate, inside `on_socket`. On a refusal the plane's OWN finished response comes
/// back verbatim and no socket binds. The flip is re-pointing the shipped call to this function (via the
/// composition-root session-runner registry); nothing else changes, because the duplex gate's
/// `verify_destination` is byte-identical on both loops.
///
/// (`result_large_err`: the `Err` is the plane's OWN finished refusal `Response`, carried BY VALUE so
/// refusal shaping stays byte-identical to the substrate `run_gauntlet_session` — the same type that
/// path returns un-boxed.)
#[allow(clippy::result_large_err)]
pub(crate) fn admit_duplex_session_via_kernel(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
) -> Result<Admitted, Response> {
    open_gauntlet_via_kernel(req, plane)
}

#[cfg(test)]
#[path = "tests/duplex_kernel_rider.rs"]
mod tests;
