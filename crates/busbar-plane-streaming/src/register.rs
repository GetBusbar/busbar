//! The composition-root wiring for the streaming plane — the plane side of it.
//!
//! **S1 IS LIVE.** The switchover this module was staged for has landed: `busbar-plane-voice` is
//! DELETED and `crates/busbar/src/root/registry.rs` registers THIS plane, under THIS plane's key
//! ([`CAP_KEY`] = `"streaming"`). There is no longer a `"voice"` registration for a `"streaming"` one
//! to collide with, which is exactly the condition the staging note below waited on. S2–S4 still
//! describe edges that are not flipped; each says so where it stands.
//!
//! ## S1 — DISPATCH (register the plane under its capability key)
//!
//! Today the composition root registers a plane with `registry.register(Arc::new(Plane::EMPTY))` and
//! the teller loop reaches a plane's units through the one `ProductionUnits` impl (see
//! `crates/busbar/src/root/registry.rs::register_all` and `crates/busbar/src/root/kernel.rs`). The #26
//! dispatch seam replaces the fixed reach with `ProductionUnits::register_units(key, impl)` keyed by
//! capability. The streaming plane's ONE kernel-side touch is the additive registration of its units
//! under its key:
//!
//! ```ignore
//! // in register_all(), guarded by the streaming feature, mirroring the plane-voice edge:
//! #[cfg(feature = "plane-streaming")]
//! planes.push(Arc::new(busbar_plane_streaming::StreamingPlane::EMPTY) as Arc<dyn Plugin>);
//! // and, once #26 lands, the units-table touch keyed by this plane's capability key:
//! units.register_units(busbar_plane_streaming::CAP_KEY, streaming_units);
//! ```
//!
//! **DONE — and it had to be a REPLACEMENT, not an addition.** This plane's claims ARE the deleted
//! voice adapter's claims (`ws` + `http`), so registering `"streaming"` ALONGSIDE a `"voice"` plane
//! would have tripped the boot's claim-overlap check. The reframe (#18: the plane is streaming, voice
//! is a dialect) is a SWITCHOVER — the `"streaming"` registration REPLACED the `"voice"` one — and the
//! switchover pass moved the cells it owns with it (`units_voice`, the registry rows, `main.rs`'s boot
//! guard, which now reads this plane's own [`CAP_KEY`] rather than a `"voice"` string literal).
//!
//! ## S2 — MONEY-BOOK (settle end-of-turn)
//!
//! The streaming cost model is: reserve a hold on ADMIT (the `admit` fact set names the lane, the
//! response ceiling and the priced input span), and SETTLE it END-OF-TURN, once per completed turn
//! (#23), against the `meter` locators the terminal `response.done` produces. That is exactly the
//! per-unit meter the llm plane already settles through the cost seam (`busbar-caps::hold::Hold::settle`
//! / `busbar-core::plane_host::cost_host::settle_lease`): a streaming turn is the unit, and its
//! `Progress::Terminal` is where the settle fires. The conformance rig proves the reserve→turns→settle
//! shape end to end. No new arithmetic is added here — the plane names locators, the cost unit settles.
//!
//! ## S3 — HOST-CAPS (serve the ingress without opening a socket)
//!
//! The plane opens NO socket (#7): its whole closure is pure. The duplex WebSocket ingress, the TLS
//! termination and the SSE/duplex reframe are the composition root's host seams — the same
//! `busbar-transport-ws` edge the `plane-voice` feature pulls (`busbar-voice?/runtime` arms the neutral
//! full-duplex WS transport; the plane SELECTS `Transport::WebSocket` and the host opens it). The
//! `plane-streaming` feature forwards to that same transport edge; the plane holds no socket plumbing.
//!
//! ## S4 — HOT-ABI / SDK (compiled-in AND dropped-in)
//!
//! [`StreamingPlane`] is a `Plugin` + `Plane` + `SessionPlane` with a const `PlaneMeta`, so it registers
//! the same way whether it is compiled into the binary (the `planes.push` edge above) or dropped in
//! through the plane SDK's `PlaneDecl` export. The SDK export edge is the plugin-sdk's, added the day
//! the switchover pass owns the registration; the plane's own surface needs nothing further for it.

use busbar_contract::plugin::Plugin;
use std::sync::Arc;

use crate::StreamingPlane;

/// The plane's capability key — the key the #26 dispatch seam will register this plane's units under,
/// and the audience a streaming session's capability is minted for. The one identity that is this
/// plane's own: `"streaming"`, never `"voice"`.
pub const CAP_KEY: &str = <StreamingPlane as busbar_contract::plane::PlaneMeta>::KEY;

/// The plane value the composition root registers, as the `Arc<dyn Plugin>` `register_all` pushes.
///
/// Real, callable code — the plane side of S1/S4 is complete. The root calls this under the
/// `plane-streaming` feature (see this module's header for the exact edge and why it is not flipped
/// live yet).
#[must_use]
pub fn plane_for_root() -> Arc<dyn Plugin> {
    Arc::new(StreamingPlane::EMPTY) as Arc<dyn Plugin>
}
