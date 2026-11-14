// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

pub(super) use crate::root::off_path::serve_observations::parse;

/// Carries only root-owned policy, selected after normal member authorization.
pub(super) struct UnitBinding<'a> {
    pub served: &'a ServedPlane,
    pub live: &'a DoorLive,
    pub unit: busbar_contract::UnitKey,
    pub selected_member: OnceLock<&'a str>,
}
impl<'a> UnitBinding<'a> {
    pub fn selected(&self, member: &str) -> bool {
        if self.selected_member.get().is_some_and(|old| *old != member) {
            return false;
        }
        let Some((member, policy)) = self.live.observations.get_key_value(member) else {
            return true;
        };
        let Some(caller) = self.served.live.plugin.service_caller() else {
            return false;
        };
        let _ = self.selected_member.set(member.as_str());
        self.served
            .kernel
            .register_observation_unit(
                &caller,
                self.unit,
                Arc::clone(&self.served.money),
                policy.clone(),
            )
            .is_ok()
    }
}
impl Drop for UnitBinding<'_> {
    fn drop(&mut self) {
        if let Some(caller) = self.served.live.plugin.service_caller() {
            self.served
                .kernel
                .unregister_observation_unit(&caller, self.unit);
        }
    }
}
