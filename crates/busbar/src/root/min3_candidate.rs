// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native lifetime custody attached to the exact published App.
//!
//! Physical slots retain request dispatchers, but the complete owner also retains the
//! invocation registrations and opened ports which authorize those dispatchers.

use std::sync::Arc;

pub(crate) struct NativeGeneration {
    pub(crate) native: Arc<super::min3_boot::Booted>,
    pub(crate) services: Arc<super::serve::Services>,
}

impl std::fmt::Debug for NativeGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeGeneration")
            .field("config_version", &self.native.config_version)
            .finish_non_exhaustive()
    }
}

/// Retain the real initial owners after native boot and before App publication.
/// Initial workers keep their existing explicit shutdown owner in main.
pub(crate) fn install_initial(
    app: &mut busbar_kernel::state::App,
    native: Arc<super::min3_boot::Booted>,
    services: Arc<super::serve::Services>,
) -> Result<(), String> {
    if native.config_version != app.config_version {
        return Err("native generation belongs to another configuration".into());
    }
    if services.kernel().is_none() {
        return Err("native generation requires actual serving services".into());
    }
    let mut config = app
        .config_projection
        .as_ref()
        .and_then(|value| value.downcast_ref::<super::door_steps::DoorConfig>())
        .ok_or("native generation has no root configuration projection")?
        .clone();
    if config.native_generation.is_some() {
        return Err("native generation already installed on candidate".into());
    }
    config.native_generation = Some(Arc::new(NativeGeneration { native, services }));
    app.config_projection = Some(Arc::new(config));
    Ok(())
}
