// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTION TABLE'S SECOND KIND OF ENTRY (deletion plan E2, half B): the boot hand-over only. No need is
//! served natively yet.

use busbar_contract::storage::StorageSource;

use super::native_dial::NativeCarrier;

/// The carriers the root assigned at boot and the account every native dial's framer session is charged to.
pub(crate) struct Natives {
    pub(crate) carriers: Vec<NativeCarrier>,
    pub(crate) storage: StorageSource,
}
