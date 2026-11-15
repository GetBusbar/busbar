// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store fixture's cdylib: its door, exported.

mod store_door;

busbar_contract::export_door!(store_door::door);
