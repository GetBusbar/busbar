// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plane section's own `pools:` as native walks over the seat's registrations (#108; the
//! route-classes K2 amendment, PM option B). The 1.5.5 door read the same pools.
use super::*;

/// One section pool: its member entries in configured order, its `on_exhausted.fallback_pool`
/// and its `member_granted` flag. Root reads it from the plane's section; it grants nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SectionPool {
    pub members: Vec<String>,
    pub fallback: Option<String>,
    pub member_granted: bool,
}

impl RequestRoutes {
    /// Root lends the seat's section pools before publishing its routes. A name that aliases the
    /// registration pool or a catalog selector, an empty pool, a member that is not one of the
    /// seat's walked registrations, or a fallback outside the section refuses.
    pub fn with_section_pools(
        mut self,
        pools: BTreeMap<String, SectionPool>,
    ) -> Result<Self, AdmissionError> {
        for (name, pool) in &pools {
            if name.is_empty()
                || name.chars().any(char::is_control)
                || *name == self.instance
                || self
                    .registration
                    .as_ref()
                    .is_some_and(|registration| registration.pool == *name)
                || self
                    .catalog
                    .as_ref()
                    .is_some_and(|catalog| catalog.select(name).is_some())
                || pool.members.is_empty()
                || pool.members.iter().any(|member| {
                    !self.registration.as_ref().is_some_and(|registration| {
                        registration
                            .members
                            .iter()
                            .any(|walked| &*walked.upstream == member)
                    })
                })
                || pool
                    .fallback
                    .as_ref()
                    .is_some_and(|fallback| fallback == name || !pools.contains_key(fallback))
            {
                return Err(AdmissionError::Route);
            }
        }
        // A consuming builder cannot preserve a seal that was previously minted from this object.
        self.identity = Arc::new(());
        self.section_pools = pools;
        Ok(self)
    }

    /// Whether `key` may route over section pool `name`.
    fn section_pool_admits(
        &self,
        key: &VirtualKey,
        selection: Option<&SelectedResources>,
        name: &str,
    ) -> bool {
        self.section_pools.contains_key(name) && self.scope_admits(key, selection, name)
    }

    /// The selected pool and its fallback must both be granted (`DoorPools::granted_known`).
    pub(super) fn section_walk_admits(
        &self,
        key: &VirtualKey,
        selection: Option<&SelectedResources>,
        name: &str,
    ) -> bool {
        std::iter::once(name)
            .chain(
                self.section_pools
                    .get(name)
                    .and_then(|pool| pool.fallback.as_deref()),
            )
            .all(|pool| self.section_pool_admits(key, selection, pool))
    }

    /// Whether `key` may reach `member` (an entry name) of section pool `name`.
    pub(super) fn section_member_admits(
        &self,
        key: &VirtualKey,
        selection: Option<&SelectedResources>,
        name: &str,
        member: &str,
    ) -> bool {
        self.section_pools
            .get(name)
            .is_some_and(|pool| pool.members.iter().any(|listed| listed == member))
            && self.section_pool_admits(key, selection, name)
    }

    /// Each section pool the key may walk, with only the members it may reach.
    pub(super) fn section_grants(
        &self,
        key: &VirtualKey,
        selection: Option<&SelectedResources>,
        grants: &mut BTreeMap<String, Vec<String>>,
    ) {
        for (name, pool) in &self.section_pools {
            if !self.section_walk_admits(key, selection, name) {
                continue;
            }
            let members: Vec<_> = pool
                .members
                .iter()
                .filter(|member| self.section_member_admits(key, selection, name, member))
                .map(|member| format!("{}{PLANE_LANE_SEP}{member}", self.instance))
                .filter(|lane| selection.is_none_or(|selected| selected.grants_member(name, lane)))
                .collect();
            if !members.is_empty() {
                grants.insert(name.clone(), members);
            }
        }
    }
}
