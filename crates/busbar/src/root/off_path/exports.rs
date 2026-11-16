// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export axis's off-path code: the module list config validation reads, ordered once per
//! validation, never per request.

use crate::root::loader::export_axis::ExportRows;

/// Every export module config may name, in the migration table's 1.5.5 order (`export_modules`);
/// a module the table does not list follows, in registration order.
pub(crate) fn linked_modules(rows: Option<ExportRows<'_>>) -> Vec<String> {
    let mut modules = rows.map(|r| r.linked_modules()).unwrap_or_default();
    let order = crate::root::migration_table::export_order();
    modules.sort_by_key(|m| {
        order
            .iter()
            .position(|o| *o == m.as_str())
            .unwrap_or(usize::MAX)
    });
    modules
}
