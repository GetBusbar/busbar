// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shorthand ("sugar") words of a settings statement.
//!
//! These names are core's own. Until the old plugin interface is deleted they are still defined inside `abi/`;
//! this module is their one path for every caller, and their definitions move here when `abi/` goes
//! (`K0-HOMES.md`). Nothing here is part of the plugin interface.

pub use crate::abi::mechanism::door::{
    FAMILY_COUNTER, FAMILY_GAUGE, MARK_ONE_INSTANCE, MARK_WORD_HOOK, MARK_WORD_ISSUED_ID_PREFIX,
    REWRITE_ALIAS, REWRITE_SUGAR, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE, REWRITE_SUGAR_SHOWN,
    SECTION_CONSUMED, SECTION_DECLARING, SECTION_REQUIRED, SECTION_SELECTS, SUGAR_ROLE_FILL,
    SUGAR_ROLE_PATH,
};
pub use crate::abi::mechanism::kind;
