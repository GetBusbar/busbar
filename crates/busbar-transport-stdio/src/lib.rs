// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stdio transport: a duplex, framed byte pump over a process's own stdin/stdout, or over a
//! spawned child process's pipes.
//!
//! This crate carries exactly the byte-level behaviour the architecture's stdio row names: one
//! frame per line (bytes split on `0x0A`), a single write lock per connection, and the
//! process/child lifecycle. It carries no protocol meaning at all — no JSON-RPC, no ids, no
//! correlation table. That meaning belongs to whichever plane rides this transport; this crate
//! only ever sees and returns opaque bytes.
//!
//! ## What "Unit 0" is here
//!
//! [`busbar_contract::Unit0Trigger::FirstMessage`]: the first framed line on the channel opens the
//! session's first unit, exactly as the architecture's stdio row states (`SESSION` / `SESSION_BOUND`
//! / Unit 0 = true / true / first message).
//!
//! ## The connection side-table, and why `Conn` cannot hold the reader directly
//!
//! [`busbar_contract::wire::Conn`] is a sealed, opaque handle: a plugin (and a transport crate,
//! which is reviewed in-tree but still built against the same contract surface) can only read its
//! `id()` and `peer()`. The actual reader/writer/child-process state therefore lives in this
//! transport's own side table, keyed by `Conn::id()` — never inside the `Conn` itself. Every method
//! below (`frames`, `write`, `close`, `upgrade`, `unit0_refusal`) looks the state up by id.
//!
//! ## The lower-layer boundary (placeholder, see the crate's own report)
//!
//! stdio composes over nothing (`COMPOSES_OVER` is empty): it is either the process's own
//! stdin/stdout, or a spawned child's pipes. A dial target reaches it as
//! [`busbar_contract::UpstreamAddress::Program`], which spells the three things a spawn needs and a
//! single opaque string could not: the absolute path, the argument vector, and the environment. The
//! security posture of the 1.5.5-era MCP stdio client is kept exactly — no shell, an absolute path
//! only, `env_clear()` before anything the destination declared is set — so a child inherits
//! nothing the deployment did not write down.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod conn;
mod transport;

pub use conn::StaticConfig;
pub use transport::StdioTransport;

#[cfg(test)]
#[path = "tests/battery.rs"]
mod battery;
