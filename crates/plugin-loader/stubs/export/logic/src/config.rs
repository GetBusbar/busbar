// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `settings:` grammar of an `export.<name>.module: request-log-file` instance — config grammar,
//! tracked by the config-schema gate here, where the sink that reads it lives.

use serde::{Deserialize, Serialize};

/// `settings:` of an `export.<name>.module: request-log-file` instance.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileSettings {
    /// The JSONL file path each request-log line is appended to — REQUIRED.
    pub path: String,
    /// Optional size (MiB) at which the file is rotated (best-effort; absent ⇒ never rotate).
    #[serde(default)]
    pub rotate_mb: Option<u64>,
    /// How many archives the host keeps when it rotates the file (the host's `keep`, read beside
    /// `path`): `0` truncates in place; unset, the manifest's `declares.keep`.
    #[serde(default)]
    pub keep: Option<u32>,
}
