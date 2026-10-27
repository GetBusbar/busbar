// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **`tcp` transport as a droppable busbar plugin**: the `cdylib` a signed tarball of the wire
//! carries (`kind: transport`, key `tcp`). The logic crate is re-exported whole, and its door
//! (`busbar_transport_tcp::door::door`) is exported as this image's ONE symbol,
//! `busbar_plugin_door` (`export_door!`, THE DESIGN §11.4), so the library carries exactly the door
//! a busbar build links.
//!
//! This crate is `deny`, not `forbid`: the export macro's `#[unsafe(no_mangle)]` is the one
//! reviewed exemption (a `forbid` cannot be lifted for it). No other `unsafe` exists here.

#![deny(unsafe_code)]

pub use busbar_stub_transport::*;

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_stub_transport::door::door);
}
