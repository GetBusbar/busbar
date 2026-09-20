//! The composition-root wiring for the streaming plane — the plane side of it.
//!
//! [`StreamingPlane`] is a `Plugin` + `Plane` + `SessionPlane` with a const `PlaneMeta`, so it
//! registers the same way whether it is compiled into the binary (the composition root pushes
//! [`plane_for_root`] under the `plane-streaming` feature) or dropped in through the plane SDK's
//! `PlaneDecl` export. The plane's whole closure is pure — it opens no socket, reads no file, reads no
//! clock other than the one the context hands it — so its capability key ([`CAP_KEY`]) is the one
//! identity that is its own: `"streaming"`, never `"voice"` (voice is one dialect it speaks, not its
//! name).

use busbar_contract::plugin::Plugin;
use std::sync::Arc;

use crate::StreamingPlane;

/// The plane's capability key — the key this plane's units register under, and the audience a
/// streaming session's capability is minted for. The one identity that is this plane's own:
/// `"streaming"`, never `"voice"`.
pub const CAP_KEY: &str = <StreamingPlane as busbar_contract::plane::PlaneMeta>::KEY;

/// The plane value the composition root registers, as the `Arc<dyn Plugin>` `register_all` pushes.
#[must_use]
pub fn plane_for_root() -> Arc<dyn Plugin> {
    Arc::new(StreamingPlane::EMPTY) as Arc<dyn Plugin>
}
