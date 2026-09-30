// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport both-ways fixture, DROPPED IN: its door behind the plugin shape's one
//! `export_door!` line, built as this crate's example `cdylib` and `dlopen`ed by the test. The test
//! build links the fixture WITHOUT its export, so the test binary carries no second door symbol.

busbar_contract::export_door!(busbar_transport_tcp::linked::door);
