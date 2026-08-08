// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PROTOCOL LAYER: the JSON-RPC 2.0 parsing surface, and CATALOGUE assembly on top of it.
//!
//! MCP speaks JSON-RPC 2.0 over three transports (stdio, SSE, streamable HTTP). Two methods carry
//! the whole plane: `tools/list` is the CATALOGUE and `tools/call` is the DISPATCH. Those are the
//! project's words for them and they are used here in preference to discovery/invocation.
//!
//! ## Sans-io, on purpose
//!
//! Nothing in this module opens a socket, spawns a child or awaits anything. The transports differ
//! only in how bytes arrive; what those bytes MEAN is identical across all three, and that meaning
//! is the part worth pinning against a hostile peer. So the layer is a pure function of bytes in:
//! [`framing`] cuts a byte stream into frames, [`jsonrpc`] turns one frame into a typed message,
//! [`correlator`] matches a reply to the request it answers, [`spec`] is the MCP method payloads in
//! OUR structs, and [`catalogue`] assembles many upstreams' tool lists into the one list a caller is
//! authorized to see. A transport drives them; it does not reimplement them.
//!
//! ## Our structs, never a vendor's generated types
//!
//! [`spec`] mirrors the MCP specification by hand. That is a locked ruling and the reason is that a
//! generated type drags the generator's schema decisions into our wire permanently: what it chose to
//! make optional, how it spells a variant, which unknown fields it silently drops. Mirroring costs a
//! struct and buys the freedom to keep our own wire when the spec moves.
//!
//! ## The peer is adversarial
//!
//! Every parse in here is a security boundary. An upstream MCP server is exactly the untrusted
//! external thing the trust lifecycle exists for, and a caller of busbar-as-server is a caller. So
//! the rule throughout is fail-closed and never guess: an unparseable frame is an error, not a
//! best-effort reconstruction; an unrecognised correlation is an error, not a default; a name that
//! could mean two things is refused rather than resolved.

// NO PRODUCTION CALLER YET, deliberately, exactly as the trust lifecycle landed ahead of its own.
// This is the protocol layer the transports (stdio child supervision, SSE, streamable HTTP) and the
// engine's server direction both drive; those are later increments and both of them need this shape
// settled and pinned first. Landing the parsing surface with its hostile-input suite ahead of a
// caller is the point, not an accident of sequencing.
#![cfg_attr(not(test), allow(dead_code))]

pub(crate) mod catalogue;
pub(crate) mod correlator;
pub(crate) mod framing;
pub(crate) mod jsonrpc;
pub(crate) mod spec;
