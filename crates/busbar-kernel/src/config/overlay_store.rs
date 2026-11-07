// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::overlay::OverlayDoc;
use std::sync::{Arc, Mutex};

#[path = "overlay_import.rs"]
pub(super) mod import;

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

    pub async fn import_once_async(
        &self,
        source_sha256: [u8; 32],
        doc: &OverlayDoc,
    ) -> Result<bool, String> {
        self.native.import_once(source_sha256, doc).await
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
