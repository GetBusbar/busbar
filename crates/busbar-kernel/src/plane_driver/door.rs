// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::plane_driver::registry::PlaneDecl;

pub(crate) use crate::off_path::plane_door::canonical_sources;
pub use crate::off_path::plane_door::{fold, judge_provider, DoorOwned, DoorRow, DoorSection};

pub(crate) fn row(decl: &PlaneDecl) -> Option<&'static DoorRow> {
    decl.door
}

#[must_use]
pub fn is_door(decl: &PlaneDecl) -> bool {
    decl.door.is_some()
}

#[must_use]
pub fn consumed_sections(decl: &PlaneDecl) -> &'static [&'static str] {
    row(decl).map_or(&[], |d| d.reg.consumes.as_slice())
}

#[must_use]
pub fn streaming_content_types(decl: &PlaneDecl) -> &'static [&'static str] {
    row(decl).map_or(&[], |d| d.reg.streaming_content_types.as_slice())
}

#[must_use]
pub fn provider_keys(
    decls: &[&'static PlaneDecl],
) -> Option<&'static busbar_contract::provider_keys::ProviderKeys> {
    (decls.iter())
        .filter_map(|d| d.door)
        .find_map(|d| d.reg.provider_keys.as_ref())
}

pub(crate) fn wire_formats(decl: &PlaneDecl) -> &'static [&'static str] {
    row(decl).map_or(&[], |d| d.reg.dialects.as_slice())
}

pub(crate) fn provider_dialects(decl: &PlaneDecl) -> &'static [&'static str] {
    row(decl).map_or(&[], |d| d.provider_dialects)
}

/// A door plane's runtime slot for one generation: its section, and what its `open` faces the world
/// with over that section and the deployment's public base URL.
#[derive(Debug, Clone)]
pub struct DoorSlot {
    /// The section, as written.
    pub section: DoorSection,
    /// Its claims (mounted by their literal prefix) and its audience.
    pub facing: busbar_contract::plane_calls::DoorFacing,
    /// Whether this serving slot's facing answered. A refused candidate retains its prior
    /// successful slot; without one, this is `false` and `facing` is the empty default.
    /// `/healthz` on a deployment with no model lanes reads it ([`opened`]).
    pub opened: bool,
}

#[must_use]
pub fn opened(slot: &dyn std::any::Any) -> bool {
    slot.downcast_ref::<DoorSlot>().is_none_or(|s| s.opened)
}

pub(crate) fn admission(
    slot: &dyn std::any::Any,
) -> Option<crate::plane_driver::dispatch::PlaneAdmission> {
    let (audience, resource_metadata) =
        slot.downcast_ref::<DoorSlot>()?.facing.admission.clone()?;
    Some(crate::plane_driver::dispatch::PlaneAdmission {
        audience,
        resource_metadata,
    })
}

#[cfg(test)]
pub fn listed<'a>(
    slots: &'a std::collections::BTreeMap<
        &'static str,
        std::sync::Arc<dyn std::any::Any + Send + Sync>,
    >,
    key: Option<&'a busbar_contract::records::VirtualKey>,
) -> Vec<&'a str> {
    listed_matching(slots, key, None).collect()
}

/// The names `plane`'s door slots list that `key` may see, in plane registration order.
pub fn listed_for_plane<'a>(
    slots: &'a std::collections::BTreeMap<
        &'static str,
        std::sync::Arc<dyn std::any::Any + Send + Sync>,
    >,
    key: Option<&'a busbar_contract::records::VirtualKey>,
    plane: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    listed_matching(slots, key, Some(plane))
}

fn listed_matching<'a>(
    slots: &'a std::collections::BTreeMap<
        &'static str,
        std::sync::Arc<dyn std::any::Any + Send + Sync>,
    >,
    key: Option<&'a busbar_contract::records::VirtualKey>,
    plane: Option<&'a str>,
) -> impl Iterator<Item = &'a str> + 'a {
    let registered = crate::plane_driver::registry::plane_decls();
    let door_slot = |(k, s): (
        &'a &'static str,
        &'a std::sync::Arc<dyn std::any::Any + Send + Sync>,
    )| { s.downcast_ref::<DoorSlot>().map(|slot| (*k, slot)) };
    // Registered doors in registration order, then any door slot no registered plane names (in key
    // order): the order the listing has always had.
    let in_order = registered
        .iter()
        .filter_map(move |d| slots.get_key_value(d.key))
        .filter_map(door_slot);
    let unregistered = slots
        .iter()
        .filter(move |(k, _)| !registered.iter().any(|d| d.key == **k))
        .filter_map(door_slot);
    in_order
        .chain(unregistered)
        .filter_map(move |(_, slot)| {
            let door = slot.section.door?;
            if plane.is_some_and(|plane| door.reg.key != plane) {
                return None;
            }
            let kind = door.reg.scope_kinds.first();
            Some(
                slot.facing
                    .listed
                    .iter()
                    .map(String::as_str)
                    .filter(move |name| match (key, kind) {
                        (Some(key), Some(kind)) => key.scope_allowed(kind, name),
                        _ => true,
                    }),
            )
        })
        .flatten()
}

pub(crate) const OPENAPI_COMPONENTS: &str = "components";

/// The door's stated admin OpenAPI blob, as the plane registered it.
pub(crate) fn admin_openapi(decl: &PlaneDecl) -> Option<&'static [u8]> {
    row(decl).and_then(|d| d.reg.admin_openapi)
}

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
