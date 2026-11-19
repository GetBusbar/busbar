// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind code and the names shared by every kind.
//!
//! These names are core's own. Until the old plugin interface is deleted they are still defined inside `abi/`;
//! this module is their one path for every caller, and their definitions move here when `abi/` goes
//! (`K0-HOMES.md`). Nothing here is part of the plugin interface.

pub use crate::abi::mechanism::kind::{AUTH, EXPORT, PLANE, STORE};
pub use crate::abi::mechanism::{
    check, endpoint, extensions, rendering, KindCode, MECHANISM_VERSION,
};
