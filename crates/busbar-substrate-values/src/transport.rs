// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `Transport` axis — RELOCATED to `busbar-contract-transport` (1.6.0 non-core transport
//! hand-over). `Transport` is NOT on the wire (its derive carries no `Serialize`/`Deserialize` and
//! no `repr`); only [`Transport::name`]'s returned strings are frozen
//! ("http"/"websocket"/"stdio" plus the `WIRE_JSONRPC`/`WIRE_HTTP_JSON`/`WIRE_GRPC` constants in
//! [`super::plane`]), so re-exporting the type at this historical path changes no byte a caller
//! reads. Every existing `busbar_substrate_values::transport::…` / `busbar_substrate::transport::…`
//! call site resolves unchanged through this re-export.
pub use busbar_contract_transport::transport::Transport;
#[cfg(any(feature = "dispatch", feature = "runtime"))]
pub use busbar_contract_transport::transport::UpstreamWireKind;
