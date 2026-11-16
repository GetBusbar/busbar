// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin error envelope: 1.5.5's `{"error":{"code","message"}}` with the ADMIN-API-1.6 section 1.2
//! additions (`reason`, `request_id`, `retryable`, `details`), plus the catalog code as a top-level
//! `code` (owner decision 2026-11-12).

/// The admin error envelope around one code and one message.
#[must_use]
pub fn envelope_of(code: &str, message: &str) -> String {
    busbar_kernel::admin::gate::admin_envelope_body(code, message)
}

#[cfg(test)]
#[path = "tests/refusal.rs"]
mod tests;
