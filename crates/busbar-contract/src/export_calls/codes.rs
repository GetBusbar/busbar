// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export vocabulary core keeps: fields, phases, scrape kinds.
//!
//! These names are core's own. Until the old plugin interface is deleted they are still defined inside `abi/`;
//! this module is their one path for every caller, and their definitions move here when `abi/` goes
//! (`K0-HOMES.md`). Nothing here is part of the plugin interface.

pub use crate::abi::export::validate::HARD_MAX_ROUTES;
pub use crate::abi::export::{
    slot, CheckPhase, ExportField, CHECK_PHASE_INSTANCES, CHECK_PHASE_LIMITS, SCRAPE_KIND_COUNTER,
    SCRAPE_KIND_GAUGE, SCRAPE_KIND_SUMMARY,
};
