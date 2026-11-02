// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![deny(unsafe_code)]

pub use busbar_stub_auth_verify::*;

#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_stub_auth_verify::door::door);
}
