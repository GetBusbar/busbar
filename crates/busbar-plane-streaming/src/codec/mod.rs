// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VOICE DUPLEX CODECS — the pure half of the voice protocol plugin.
//!
//! `busbar-voice` held two things behind one name: these codecs — the plane-4 duplex/session
//! intermediate representation (media frames, control, events, tools, session config, usage), the
//! shared duplex reader/writer over it, the Gemini Live dialect and the Twilio Media Streams
//! grammar — and the runtime that carries them over a live socket (the axum mount, the WebSocket
//! accept, the tokio session tasks, the telephony dial, the HTTPS token minter). The plane crate
//! `busbar-plane-streaming` adapts the codecs and must not link the runtime: a plane is a PURE kind
//! whose whole transitive closure is scanned, and the runtime put `hyper`, `reqwest`, `axum`,
//! `tokio-tungstenite` and a socket-capable `tokio` in it. (`busbar-plane-voice` was that adapter's
//! earlier spelling and was DELETED into `busbar-plane-streaming` at `fbead1a31`, #18/#83.)
//!
//! So the codecs live here, naming only the plugin contract (`busbar-contract`, for the base64 media
//! transcode, the billing carrier and its reserved unit names) plus serde and `bytes`.
//! `busbar-voice` depends on this crate and re-exports every module that moved under
//! its old path, so `busbar_voice::ir::…` and `busbar_voice::topology::twilio::…` resolve exactly
//! what they always did. The split is a MOVE: no item changed shape crossing it.

/// THE REGISTRY KEY THE STREAMING PLANE IS KNOWN BY — the string the composition root flips
/// onto the unified kernel loop's session admit
/// (`busbar_kernel::plane_host::register_session_runner`) and the same string the voice session
/// gauntlet reports from its `GauntletPlane::capability_key`.
///
/// Named ONCE, here, on the pure side of the split, because the plane's `capability_key` and the
/// composition-root FLIP must reference the SAME literal or a swap could drift onto two. It agrees
/// with `busbar-voice`'s `PLANE_DECLARATION.key` (`"streaming"`). `busbar-voice` re-exports it as
/// `busbar_voice::PLANE_KEY`, the one stable path the `busbar` binary names.
pub const PLANE_KEY: &str = "streaming";

pub mod ir;

/// The one topology module that is a GRAMMAR rather than a dial: it keeps its `topology::` parent
/// so its in-crate path is the one the runtime half still spells, and the move is invisible to
/// every caller.
///
/// UNGATED. This crate declares NO features on purpose (a plane compiled two ways is two planes),
/// so there is no feature to gate this on — and none is needed: the grammar is a total function
/// from a frame to an IR event and back, pulling nothing beyond `serde`/`bytes` (both already
/// unconditional here), so making it unconditional adds no dependency and no I/O to this pure
/// kind's closure. The legacy engine's own `#[cfg(feature = "runtime")]` on the module that
/// re-exports it is what keeps that engine's Twilio path OFF by default — this module simply exists
/// for it to reach, always, the same way `codec::ir` always does.
pub mod topology {
    pub mod twilio;
}
