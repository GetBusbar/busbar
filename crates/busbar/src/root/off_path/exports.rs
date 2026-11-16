// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export axis's off-path code: the module list config validation reads, built once per
//! validation, never per request.

use crate::root::loader::export_axis::ExportRows;

/// Every export module config may name, in registration order. (The 1.5.5 migration table that once
/// fixed an order ahead of it is retired with the migrate flags.)
pub(crate) fn linked_modules(rows: Option<ExportRows<'_>>) -> Vec<String> {
    rows.map(|r| r.linked_modules()).unwrap_or_default()
}
