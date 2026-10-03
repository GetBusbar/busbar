// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `plane-door` both-ways fixture as a dropped-in `cdylib`: the one export, over the same
//! function the linked door is. `build.rs` writes the line from the `plane-door` row of
//! `[package.metadata.busbar.both-ways]`, so no source here names the plugin.

include!(concat!(env!("OUT_DIR"), "/plane_door_export.rs"));
