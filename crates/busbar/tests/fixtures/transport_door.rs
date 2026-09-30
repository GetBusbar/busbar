// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The root's dropped-in transport proofs' fixture: the linked socket-framing door behind the plugin
//! shape's one `export_door!` line, built as this crate's example `cdylib` and `dlopen`ed by the
//! tests. The test build links the door WITHOUT its export, so no test binary carries a second door
//! symbol.

busbar_contract::export_door!(busbar_transport_tcp::linked::door);
