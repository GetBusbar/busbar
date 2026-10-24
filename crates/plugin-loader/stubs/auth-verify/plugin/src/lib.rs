// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `admin-tokens` admin-auth module as a droppable `kind: auth` plugin: the logic crate
//! re-exported whole, and its door (`busbar_auth_admin_tokens::door::door`) exported as this image's
//! ONE symbol, `busbar_plugin_door` (`export_door!`, THE DESIGN §11.4). The logic crate holds no
//! `unsafe` and exports nothing, so a build that links it carries no door symbol.
#![deny(unsafe_code)]

pub use busbar_stub_auth_verify::*;

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_stub_auth_verify::door::door);
}
