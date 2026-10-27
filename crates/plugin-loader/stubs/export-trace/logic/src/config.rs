// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `settings:` of an `export.<name>.module: otlp` instance — the home of the retired
//! `observability.otlp_url` since 1.5.3, and the sink's own shape now that the sink is this plugin.
//! The same serde the host's configuration grammar uses, so a settings error reads exactly as it
//! always has (`export.<name>.settings: unknown field …` / `missing field `url``).

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
    /// The settings `bytes` hold, refused in the configuration grammar's words (`unknown field …`,
    /// `missing field `url``), as 1.5.x read them from the configuration's own value.
    ///
    /// # Errors
    /// The bytes are not JSON, or not this shape.
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_value(serde_json::from_slice(bytes)?)
    }
}
