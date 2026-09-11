// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONFIG VALUE GRAMMAR, on the half of the substrate that SURVIVES.
//!
//! A config section's shapes are a PURE value family: serde structs and enums over `busbar-api`
//! leaves, their `Default`s and their pure accessors. They open no socket, no file, no process and
//! read no environment, so under the substrate's retirement they belong here and not beside the
//! egress engine. `busbar-substrate` re-exports every module below at its historical
//! `busbar_substrate::config::` path, so no reader in or out of the tree changes a spelling and no
//! wire form moves a byte.

pub mod groups;
