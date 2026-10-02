// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `grpc` door, dropped in: the one exported symbol, forwarding to the same door a compiled-in
//! row holds. `tests/conformance.rs` loads it beside the linked image and drives both the same way.

busbar_contract::export_door!(busbar_transport_grpc::door::door);
