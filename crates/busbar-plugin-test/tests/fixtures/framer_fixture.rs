// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stream framer fixture's cdylib: its door, exported.

mod framer_door;

busbar_contract::export_door!(framer_door::door);
