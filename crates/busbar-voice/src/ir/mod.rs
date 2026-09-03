// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE-4 DUPLEX / SESSION IR — the plane's OWN vocabulary (skeleton).
//!
//! These are the nouns that live ONLY in `busbar-voice`
//! (`docs/design/plane4-duplex-session.md` §7.2): the four-layer duplex/session IR and its
//! reader/writer pair. Per `plane4-duplex-session.md` §2.1 "pass-through is still an IR" — the layers differ in HOW MUCH the IR
//! reshapes the wire, from full normalization (tool-call) to identity (media):
//!
//! | Layer | Concern | Posture | Module |
//! |---|---|---|---|
//! | 1 | tool-call | FULL normalization (the moat) | [`tool`] |
//! | 2 | control / config | translatable, cross-dialect only | [`control`] |
//! | 3 | media / audio-frame | VERBATIM byte-relay = identity IR | [`media`] |
//! | 4 | usage / rate-limit | EXTRACTION only, not client-facing | [`usage`] |
//!
//! The IR is the plane's OWN — a busbar-owned mirror of the duplex event schema, `codec: None` while
//! OpenAI Realtime is the only dialect (the A2A rule, §1.4: a superset IR is earned at the SECOND wire
//! format and not before). It is NOT and does not extend `busbar-llm`'s chat IR — the load-bearing
//! delta is a client→server event vocabulary ([`event::IrClientEvent`]) the LLM `IrStreamEvent`
//! structurally lacks (`plane4-duplex-session.md` §1.2).
//!
//! SKELETON: every type below is a STUB. No reader/writer body, no pump, no session store — bodies are
//! `todo!()` or minimal. The shapes mirror `plane4-duplex-session.md` §2.2–2.6.

pub mod codec;
pub mod config;
pub mod control;
pub mod event;
pub mod media;
pub mod tool;
pub mod usage;

pub use codec::gemini::GeminiLiveCodec;
pub use codec::{DecodeState, DuplexReader, DuplexWriter, OpenAiRealtimeCodec, WireEvent};
pub use config::{MaxOutputTokens, SessionConfig};
pub use control::{Eagerness, IrDuplexControl, IrVad};
pub use event::{IrClientEvent, IrServerEvent};
pub use media::{truncate_point_ms, AudioFormat, IrAudioFrame, UpDown};
pub use tool::{CallRef, IrDuplexTool};
pub use usage::IrDuplexUsage;
