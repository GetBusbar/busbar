// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::overlay::OverlayDoc;
use std::sync::{Arc, Mutex};

#[path = "overlay_import.rs"]
pub(super) mod import;

/// What the serve gate finds in this Store about a 1.5.5 file overlay: an import receipt a former
/// release left, a 1.6 overlay, or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyImportState {
    /// RECEIPT present: a 1.5.5 file overlay was imported into this Store (its source digest).
    Imported([u8; 32]),
    /// RECEIPT absent and HEAD present: the Store already holds a 1.6 overlay.
    StoreOverlayPresent,
    /// RECEIPT and HEAD absent: nothing was ever imported.
    Empty,
}

pub struct OverlayStore {
    native: super::overlay_native::NativeOverlay,
    unpublished: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for OverlayStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OverlayStore(configured Store)")
    }
}

impl OverlayStore {
    pub fn from_core(
        core: Arc<crate::persistence::facade::CoreStore>,
    ) -> Result<Arc<Self>, String> {
        let observed = Arc::new(Mutex::new(None));
        let native = super::overlay_native::NativeOverlay::new(core, observed)?;
        Ok(Arc::new(Self {
            native,
            unpublished: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    pub fn core_store_handle(&self) -> Result<Arc<crate::persistence::facade::CoreStore>, String> {
        Ok(self.native.core_store_handle())
    }

    /// The configured Store loses its state with the process (`BackendInfo.durability == Ephemeral`).
    /// The same fact BUSBAR-8016 (`appbuild`) and the overlay serve gate read, from the same
    /// `CoreStore`, so the three cannot disagree.
    pub fn is_ephemeral(&self) -> bool {
        self.native.core_store_handle().info().durability
            == busbar_contract::persistence::Durability::Ephemeral
    }

    /// Read-only: whether this Store holds a 1.5.5 import receipt, a 1.6 overlay, or neither.
    pub async fn legacy_import_state_async(&self) -> Result<LegacyImportState, String> {
        self.native.legacy_import_state().await
    }

    pub async fn read_bytes_async(&self) -> Result<Option<Vec<u8>>, String> {
        self.native.read_bytes().await
    }

    pub async fn read_required_async(&self) -> Result<Option<OverlayDoc>, String> {
        self.native.read_required().await
    }

    pub async fn reopen_for_reload_async(&self) -> Result<(Arc<Self>, Option<OverlayDoc>), String> {
        let (native, doc) = self.native.reopen().await?;
        Ok((
            Arc::new(Self {
                native,
                unpublished: std::sync::atomic::AtomicBool::new(false),
            }),
            doc,
        ))
    }

    pub(super) async fn update_async(
        &self,
        edit: impl FnOnce(&mut OverlayDoc) + Send,
    ) -> Result<(), String> {
        self.ensure_published()?;
        self.native.update(edit).await
    }

    pub fn require_reload(&self) {
        self.native.require_reload();
        self.unpublished
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn ensure_published(&self) -> Result<(), String> {
        if self.unpublished.load(std::sync::atomic::Ordering::Acquire) {
            return Err("config overlay has a confirmed unpublished generation; reload before further mutation".into());
        }
        Ok(())
    }

    pub fn display(&self) -> &'static str {
        "configured Store"
    }
}

#[cfg(test)]
#[path = "tests/overlay_bytes_tests.rs"]
mod overlay_bytes_tests;
#[cfg(test)]
#[path = "tests/overlay_native_fault_tests.rs"]
pub(in crate::config) mod tests;
#[cfg(test)]
#[path = "tests/version_gate_tests.rs"]
mod version_gate_tests;
