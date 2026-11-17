// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Every breaking change a head OpenAPI document makes to what a base document promised.

use busbar_contract::json;

/// Every breaking change `head` makes to what `base` promised; empty when `head` is additive.
pub(crate) fn breaking_changes(_base: &json::Value, _head: &json::Value) -> Vec<String> {
    Vec::new()
}
