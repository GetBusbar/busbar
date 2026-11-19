// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::export_calls::{ExportAxis, Probed};

use crate::root::loader::export_axis::ExportRows;

#[path = "export_ports.rs"]
pub(crate) mod ports;

/// The root's export axis.
#[derive(Debug)]
pub struct RootExports;

pub static EXPORTS: RootExports = RootExports;

fn rows() -> Option<ExportRows<'static>> {
    let registry = crate::root::linked::dropped()?;
    Some(ExportRows::new(
        registry,
        crate::root::dispatch::dispatcher(),
    ))
}

/// The generation's images and the identity `module` names in them (DES-NATIVE-FIRST-PARTY r3 §3.1): a word the
/// read's images resolve is answered from that image entry's signer alone, never ORed with a door row. `None`: the
/// read carries no images, or they do not resolve the word, and (until WP4 deletes it) the door row answers.
fn native<'r>(
    module: &str,
    read: Option<&'r (dyn std::any::Any + Send + Sync)>,
) -> Option<(&'r busbar_plugin_loader::instance::Images, String)> {
    let images = &read?
        .downcast_ref::<crate::root::boot::images::FileImages>()?
        .images;
    let identity = images.identity_of(module)?;
    Some((images, identity))
}

impl ExportAxis for RootExports {
    fn probe(
        &self,
        module: &str,
        instance: &str,
        settings: &busbar_contract::plugin_settings::ResolvedSettings,
    ) -> Option<Probed> {
        rows()?.probe(module, instance, settings)
    }

    fn check(
        &self,
        module: &str,
        phase: u32,
        instances: &[(String, &busbar_contract::plugin_settings::ResolvedSettings)],
    ) -> Option<Vec<String>> {
        rows()?.check(module, phase, instances)
    }

    fn linked(&self, module: &str, read: Option<&(dyn std::any::Any + Send + Sync)>) -> bool {
        match native(module, read) {
            Some((images, identity)) => images.linked(&identity),
            None => rows().is_some_and(|r| r.linked(module)),
        }
    }

    fn first_party(&self, module: &str, read: Option<&(dyn std::any::Any + Send + Sync)>) -> bool {
        match native(module, read) {
            Some((images, identity)) => images.first_party(&identity),
            None => rows().is_some_and(|r| r.first_party(module)),
        }
    }

    fn one_instance(&self, module: &str) -> bool {
        rows().is_some_and(|r| r.one_instance(module))
    }

    /// Every export module config may name, linked or dropped in, in the migration table's 1.5.5
    /// order (`export_modules`); a module the table does not list follows, in registration order.
    fn linked_modules(&self) -> Vec<String> {
        crate::root::off_path::exports::linked_modules(rows())
    }

    fn routes(&self, module: &str) -> Vec<busbar_contract::route::Route> {
        rows().map(|r| r.routes(module)).unwrap_or_default()
    }

    fn public_routes(&self, module: &str) -> Vec<String> {
        rows().map(|r| r.public_routes(module)).unwrap_or_default()
    }

    fn persistent_routes(&self, module: &str) -> Vec<String> {
        rows()
            .map(|r| r.persistent_routes(module))
            .unwrap_or_default()
    }

    fn secret_refs(&self, module: &str) -> Vec<String> {
        use busbar_contract::plugin_rows::PluginRows;
        crate::root::linked::dropped()
            .map(|registry| registry.secret_slots(module))
            .unwrap_or_default()
    }

    fn reference_fields(&self, module: &str) -> Vec<String> {
        use busbar_contract::plugin_rows::PluginRows;
        crate::root::linked::dropped()
            .map(|registry| registry.reference_slots(module))
            .unwrap_or_default()
    }
}
