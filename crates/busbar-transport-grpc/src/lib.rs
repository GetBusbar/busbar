// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The gRPC transport: unary and multiplexed streams over HTTP/2, byte-blind.
//!
//! This crate carries exactly the byte-level behaviour the architecture's grpc row names: the
//! session opens at the first message (`Unit0Trigger::FirstMessage`), a connection multiplexes
//! many concurrent calls (each one `StreamId`), and the `grpc-status` trailer is read as the
//! transport's own terminal status leg (`StatusClass` at `StatusAt::Terminal`) — reported as a
//! synthetic, zero-length terminal frame on the reading (client) side, never as a judgement about
//! what the call's messages meant. It carries no protobuf meaning at all: see `codec::RawCodec`.
//!
//! ## Two placeholders this crate's own report names plainly
//!
//! 1. **The lower-layer boundary.** The architecture composes `grpc` OVER `http` (itself over
//!    `tcp`/`tls`). The `tcp`/`tls`/`http` transport crates are owned by a different agent and out
//!    of reach here. So `listen`/`accept`/`dial` build and drive the HTTP/2 connection directly
//!    ([`hyper`] + [`hyper_util`], not `tonic::transport` — see `server.rs`'s header for why),
//!    resolving the host itself rather than going through the resolve-then-pin SSRF guard used
//!    elsewhere in the codebase (`busbar_substrate::net_guard`), which lives in a crate this one
//!    may not depend on.
//! 2. **The fixed RPC path.** gRPC names every call `/package.Service/Method`; a byte-blind
//!    transport has no plane-supplied value for that, so every call this crate opens or serves
//!    answers to one fixed path (`server::RPC_PATH`). See `server.rs`'s header.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod client;
mod codec;
mod conn;
mod server;
mod transport;

pub use conn::StaticConfig;
pub use transport::GrpcTransport;

#[cfg(test)]
#[path = "tests/battery.rs"]
mod battery;
