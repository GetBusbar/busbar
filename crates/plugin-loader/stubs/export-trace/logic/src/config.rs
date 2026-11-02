// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::{Deserialize, Serialize};

/// `settings:` of an `export.<name>.module: otlp` instance.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OtlpSettings {
    /// OTLP/HTTP traces endpoint URL (e.g. `http://localhost:4318/v1/traces`) — REQUIRED. When an
    /// `otlp` export instance is present busbar exports its spans there.
    pub url: String,
}

impl OtlpSettings {
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_value(serde_json::from_slice(bytes)?)
    }
}
