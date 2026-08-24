// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral wire-format NAMES the plane spine and the served-card boundary compare against.
//!
//! These are the canonical spellings of the wire formats busbar's mounted planes speak. They live
//! in the neutral substrate because a plane crate names them without reaching into `busbar-core`,
//! and because a literal spelled per site is how two answers that must agree start to differ. The
//! plane spine (`busbar_core::plane`) re-exports them unchanged.

/// THE WIRE FORMAT both mounted planes speak: JSON-RPC 2.0. Named once, here, because it is read
/// twice as a `wire_format_names` entry and once more by the error-shaping boundary, which
/// decides that a refusal on a mounted plane is a JSON-RPC error object rather than a vendor
/// envelope. A literal spelled per site is how those two answers start to differ.
pub const WIRE_JSONRPC: &str = "jsonrpc";

/// THE SECOND WIRE FORMAT THE A2A PLANE SPEAKS: A2A's HTTP+JSON binding, where the REQUEST LINE
/// names the operation rather than a body member. Named once, here, because it is read three ways
/// and all three must agree — as a `wire_format_names` entry, as the
/// `busbar_core::transport::Transport::HttpJson` label, and (upper-cased by
/// `a2a::serve::servable_bindings`) as the `protocolBinding` a served agent card advertises. The
/// card spelling is `HTTP+JSON`, so this is that string lower-cased and nothing else.
pub const WIRE_HTTP_JSON: &str = "http+json";

/// The A2A specification's gRPC binding, as a wire-format name. Lower-case here and upper-cased
/// once, by `busbar_core::a2a::serve::servable_bindings`, into the `GRPC` an agent card advertises
/// — so the card cannot claim a binding the plane does not list, which is the whole reason that
/// function reads this list rather than writing one of its own.
pub const WIRE_GRPC: &str = "grpc";
