// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export axis's off-path code: the export pumps' lifecycle (open, start, stop), never per
//! request.

use std::sync::Arc;

use crate::root::exports::ports::Exports;

/// The export pumps' lifecycle, off the request path: [`Exports::new`] once per start (`min3_boot`),
/// [`Exports::calls`] once when `main` opens the export registry, [`Exports::start`] once, and
/// [`Exports::stop_until`] once at shutdown. The per-event append stays in `exports::ports`.
impl Exports {
    pub(crate) fn new(
        doors: Vec<(String, Arc<busbar_plugin_loader::export_pump::PortDoor>)>,
    ) -> Result<Self, String> {
        let mut owned = std::collections::BTreeMap::new();
        for (name, door) in doors {
            if owned.insert(name.clone(), door).is_some() {
                return Err(format!("duplicate opened export instance `{name}`"));
            }
        }
        Ok(Self { doors: owned })
    }

    pub(crate) fn calls(
        &self,
    ) -> std::collections::BTreeMap<String, Arc<dyn busbar_contract::export_calls::ExportCalls>>
    {
        self.doors
            .iter()
            .map(|(name, door)| {
                (
                    name.clone(),
                    Arc::clone(door) as Arc<dyn busbar_contract::export_calls::ExportCalls>,
                )
            })
            .collect()
    }

    pub(crate) fn start(&self) -> Result<(), String> {
        for door in self.doors.values() {
            door.start()?;
        }
        Ok(())
    }

    pub(crate) fn stop_until(
        self,
        deadline: std::time::Instant,
    ) -> Vec<(String, busbar_plugin_loader::export_pump::StopReport)> {
        for door in self.doors.values() {
            door.begin_drain(deadline);
        }
        self.doors
            .into_iter()
            .map(|(name, door)| (name, door.stop_until(deadline)))
            .collect()
    }
}
