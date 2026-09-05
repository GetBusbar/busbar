// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VOICE DUPLEX CODECS — the pure half of the voice protocol plugin.
//!
//! `busbar-voice` held two things behind one name: these codecs — the plane-4 duplex/session
//! intermediate representation (media frames, control, events, tools, session config, usage), the
//! shared duplex reader/writer over it, the Gemini Live dialect and the Twilio Media Streams
//! grammar — and the runtime that carries them over a live socket (the axum mount, the WebSocket
//! accept, the tokio session tasks, the telephony dial, the HTTPS token minter). The plane crate
//! `busbar-plane-voice` adapts the codecs and must not link the runtime: a plane is a PURE kind
//! whose whole transitive closure is scanned, and the runtime put `hyper`, `reqwest`, `axum`,
//! `tokio-tungstenite` and a socket-capable `tokio` in it.
//!
//! So the codecs live here, naming only the pure half of the neutral ABI
//! (`busbar-substrate-values`, for the base64 media transcode and the billing carrier) plus serde
//! and `bytes`. `busbar-voice` depends on this crate and re-exports every module that moved under
//! its old path, so `busbar_voice::ir::…` and `busbar_voice::topology::twilio::…` resolve exactly
//! what they always did. The split is a MOVE: no item changed shape crossing it.

pub mod ir;

/// The one topology module that is a GRAMMAR rather than a dial: it keeps its `topology::` parent
/// so its in-crate path is the one the runtime half still spells, and the move is invisible to
/// every caller.
///
/// BEHIND THE SAME `runtime` GATE IT WAS BEHIND BEFORE THE MOVE, and that is the whole reason this
/// crate declares a feature at all. `busbar_voice::topology` is gated on `runtime` (OFF by default),
/// so this grammar and its six tests were compiled out of the default build and out of the owning
/// plugin's own test binary. A move must not change what compiles or what runs, so the gate travels
/// with the module: `busbar-voice`'s `runtime` forwards here, and the `#[cfg]` resolves to exactly
/// the answer it resolved to before. The grammar itself needs nothing from the runtime — it is a
/// total function from a frame to an IR event and back — but "it could be ungated" is a separate
/// decision from "it moved", and only one of them is being made here.
#[cfg(feature = "runtime")]
pub mod topology {
    pub mod twilio;
}
