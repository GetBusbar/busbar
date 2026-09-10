// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE-4 DUPLEX / SESSION IR — the plane's OWN vocabulary.
//!
//! These are the nouns that live ONLY in the voice plugin
//! (`docs/design/plane4-duplex-session.md`): the four-layer duplex/session IR and its
//! reader/writer pair. Per `plane4-duplex-session.md` "pass-through is still an IR" — the layers differ in HOW MUCH the IR
//! reshapes the wire, from full normalization (tool-call) to identity (media):
//!
//! | Layer | Concern | Posture | Module |
//! |---|---|---|---|
//! | 1 | tool-call | FULL normalization (the moat) | [`tool`] |
//! | 2 | control / config | translatable, cross-dialect only | [`control`] |
//! | 3 | media / audio-frame | VERBATIM byte-relay = identity IR | [`media`] |
//! | 4 | usage / rate-limit | EXTRACTION only, not client-facing | [`usage`] |
//!
//! The IR is the plane's OWN — a cross-dialect SUPERSET both dialects (OpenAI Realtime + Gemini Live)
//! read and write, earned at the plane's second wire format (the A2A rule: a superset IR is earned
//! at the SECOND wire format and not before). `DECLS` stays `codec: None` because the plane realizes that
//! superset as these shared IR types, not the LLM `DialectCodec` facade. It is NOT and does not extend
//! `busbar-llm`'s chat IR — the load-bearing delta is a client→server event vocabulary
//! ([`event::IrClientEvent`]) the LLM `IrStreamEvent` structurally lacks (`plane4-duplex-session.md`).
//!
//! Every dialect codec implements the reader/writer pair over these types; the shapes mirror
//! `plane4-duplex-session.md`. Only [`GeminiLiveCodec`] still lives beside the IR — its own line moves
//! it out the way the OpenAI Realtime reader already went, into the plane's dialect module.

pub mod codec;
pub mod config;
pub mod control;
pub mod event;
pub mod media;
pub mod tool;
pub mod usage;

pub use codec::gemini::GeminiLiveCodec;
pub use codec::{DecodeState, DuplexReader, DuplexWriter, WireEvent, WireRef};
pub use config::{MaxOutputTokens, SessionConfig};
pub use control::{Eagerness, IrDuplexControl, IrVad};
pub use event::{IrClientEvent, IrServerEvent};
pub use media::{truncate_point_ms, AudioFormat, IrAudioFrame, UpDown};
pub use tool::{CallRef, IrDuplexTool};
pub use usage::IrDuplexUsage;
