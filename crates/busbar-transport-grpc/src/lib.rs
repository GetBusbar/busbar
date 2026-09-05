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
//! ## The lower layer
//!
//! The architecture composes `grpc` OVER `http` (itself over `tcp`/`tls`), and this crate opens no
//! socket: it is built [`GrpcTransport::over`] a lower transport, which binds, accepts and dials,
//! and drives HTTP/2 ([`hyper`] + [`hyper_util`], not `tonic::transport` — see `server.rs`'s header
//! for why) over the stream that layer gives up. Two things follow. The composed chain an arrival
//! reports is the one it actually stands on. And no name is resolved here, so the resolve-then-pin
//! network guard sits in front of the dial — in the trust unit, once for every carrier — rather
//! than inside each one.
//!
//! The RPC path is the destination's: `UpstreamAddress::Grpc` names the method every call this
//! connection opens is dialled against, so two plane operations can reach two upstream methods. A
//! destination naming none falls back to `server::RPC_PATH`, the only path a byte-blind transport
//! can serve on its own.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod client;
mod codec;
mod conn;
mod server;
mod transport;

pub use transport::GrpcTransport;

#[cfg(test)]
#[path = "tests/battery.rs"]
mod battery;
