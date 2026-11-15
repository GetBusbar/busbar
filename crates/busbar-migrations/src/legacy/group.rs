// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Trusted logical grouping for a streaming physical archive. The external
//! index owns protected group keys and charges their bytes plus each member
//! index before allocation. Payloads are lent one row at a time, never retained.
pub struct LogicalGroup {
    pub family: [u8; 16],
    pub key: busbar_contract::Secret<Vec<u8>>,
}
