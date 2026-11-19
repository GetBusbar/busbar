// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth vocabulary core keeps: styles, facts, scope fields.
//!
//! These names are core's own. Until the old plugin interface is deleted they are still defined inside `abi/`;
//! this module is their one path for every caller, and their definitions move here when `abi/` goes
//! (`K0-HOMES.md`). Nothing here is part of the plugin interface.

pub use crate::abi::auth::{
    is_no_member_auth_field, is_scope_field, retry_after_of, scope_extensions, slot,
    IDENTITY_HAS_TTL, STYLE_ENDPOINT_FROM_CREDENTIAL, STYLE_ENDPOINT_TOKEN_URL,
    STYLE_NEEDS_HEADERS,
};
