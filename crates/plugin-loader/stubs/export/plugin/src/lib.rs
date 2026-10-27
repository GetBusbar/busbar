// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **request-log FILE sink as a droppable busbar plugin** — the `cdylib` a signed tarball of the
//! sink carries (`kind: export`, alias `request-log-file`): the logic crate re-exported whole, and
//! its door (`busbar_export_file::door`) exported as this image's ONE symbol, `busbar_plugin_door`
//! (`export_door!`, THE DESIGN §11.4). The logic crate is `#![forbid(unsafe_code)]` and exports
//! nothing, so a build that links it carries no door symbol. Pack it with `busbar-plugin-pack --kind
//! export --alias request-log-file --declares-file export-file/declares.json`.
//!
//! This crate is `deny`, not `forbid`: the export macro's `#[unsafe(no_mangle)]` is the one
//! reviewed exemption (a `forbid` cannot be lifted for it). No other `unsafe` exists here.

#![deny(unsafe_code)]

pub use busbar_stub_export::*;

/// The exported door, behind `dropped-in` (the cdylib build only): the macro's `#[no_mangle]` symbol is
/// the one exemption.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_stub_export::door);
}
