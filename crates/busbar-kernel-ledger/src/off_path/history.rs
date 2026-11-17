// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A card entry's metering identity, spelled into the owned `pricing_version` field a unit
//! checkpoint's count rows carry: once per checkpoint, never per request.

use crate::cost::EntryId;

impl EntryId {
    /// The exact entry identity as a metering row's existing `pricing_version` field.
    pub fn metering_version(&self) -> String {
        format!("{}{self}", Self::METERING_VERSION_PREFIX)
    }
}
