// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SETTINGS DOCUMENT READ WITH GUARDED STRINGS: configure-time JSON, parsed once per validate,
//! open or refresh through the protected reader's masked view ([`super::protected_json`]).

use serde_json::Value;

use super::JsonReplyError;
use crate::plugin_settings::guarded_reader::{document, SettingsValue};

/// Read a configuration document with guarded strings, rejecting duplicate top-level members.
/// Schema and value policy belong to the caller. Nested objects retain last-duplicate-wins
/// semantics. Entire input validation and serde's ordinary nesting bound apply.
pub fn settings_document(body: &[u8]) -> Result<SettingsValue, JsonReplyError> {
    document(body, true).map_err(JsonReplyError::from)
}

impl super::Cred {
    /// Take a credential setting out of a parsed settings document, wiping the string where it
    pub fn take(v: &mut Value) -> Option<Self> {
        let Value::String(s) = v else {
            return None;
        };
        let bytes = crate::secure::SecureVec::from(core::mem::take(s).into_bytes());
        *v = Value::Null;
        Some(Self::from_bytes(bytes))
    }
}
