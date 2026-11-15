// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport fixture's cdylib: its door, exported.

mod transport_door;

busbar_contract::export_door!(transport_door::door);
