// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The receipt a 1.5.5 file-overlay import once left beside the Store overlay. The importer is gone
//! (the boot's migrator folds a 1.5.5 overlay into config.yaml); only the receipt's shape stays, so the
//! serve gate can still tell an already-imported Store from one that holds un-imported settings.

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::config) struct Receipt {
    #[allow(dead_code)]
    pub(in crate::config) version: u32,
    pub(in crate::config) source_sha256: [u8; 32],
    #[allow(dead_code)]
    pub(in crate::config) overlay_sha256: [u8; 32],
}
