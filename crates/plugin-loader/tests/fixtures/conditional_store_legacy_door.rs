// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "conditional_store_fixture.rs"]
mod witness;

busbar_contract::export_door!(witness::legacy::door);
