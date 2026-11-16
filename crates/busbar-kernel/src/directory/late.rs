// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`LateDirectory`]: the directory a `HostNeeds` is built over before the store it reads exists (the same reason
//! as `plugin_records::LateRecords`): every DIRECTORY Need answers `Unavailable` until the boot installs the one
//! directory, once, after the store opens and before the first 2c instance.

use std::sync::{Arc, OnceLock};

use busbar_plugin_abi::host_side::caller::Caller;
use busbar_plugin_abi::host_side::needs::{DirNeed, NeedErr, NeedOut};

use super::PluginDirectory;

/// The directory that is not there yet.
pub struct LateDirectory<D: PluginDirectory> {
    slot: Arc<OnceLock<D>>,
}

impl<D: PluginDirectory> Clone for LateDirectory<D> {
    fn clone(&self) -> Self {
        Self {
            slot: Arc::clone(&self.slot),
        }
    }
}

impl<D: PluginDirectory> Default for LateDirectory<D> {
    fn default() -> Self {
        Self {
            slot: Arc::new(OnceLock::new()),
        }
    }
}

impl<D: PluginDirectory> LateDirectory<D> {
    /// The directory every clone answers through from now on. The first install stays: false = one was installed.
    pub fn install(&self, directory: D) -> bool {
        self.slot.set(directory).is_ok()
    }
}

impl<D: PluginDirectory> PluginDirectory for LateDirectory<D> {
    async fn apply(
        &self,
        who: &Caller<'_>,
        n: DirNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> Result<(), NeedErr> {
        match self.slot.get() {
            Some(directory) => directory.apply(who, n, res).await,
            None => Err(NeedErr::Unavailable),
        }
    }
}
