// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::export_calls::{ExportAxis, Probed};

#[path = "export_ports.rs"]
pub(crate) mod ports;

/// The root's export axis. Every export sink is a MIN-3 image: a module word is answered from the
/// read's admitted images (their signer and linkage), and the export instance itself is opened by the
/// boot walk (`min3_boot`) and pumped through `busbar_plugin_loader::export_pump`.
#[derive(Debug)]
pub struct RootExports;

pub static EXPORTS: RootExports = RootExports;

/// The generation's images and the identity `module` names in them (DES-NATIVE-FIRST-PARTY r3 §3.1).
/// `None`: the read carries no images, or they do not resolve the word.
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
        _module: &str,
        _instance: &str,
        _settings: &busbar_contract::plugin_settings::ResolvedSettings,
    ) -> Option<Probed> {
        None
    }

    fn check(
        &self,
        _module: &str,
        _phase: u32,
        _instances: &[(String, &busbar_contract::plugin_settings::ResolvedSettings)],
    ) -> Option<Vec<String>> {
        None
    }

    fn linked(&self, module: &str, read: Option<&(dyn std::any::Any + Send + Sync)>) -> bool {
        native(module, read).is_some_and(|(images, identity)| images.linked(&identity))
    }

    fn first_party(&self, module: &str, read: Option<&(dyn std::any::Any + Send + Sync)>) -> bool {
        native(module, read).is_some_and(|(images, identity)| images.first_party(&identity))
    }

    fn one_instance(&self, _module: &str) -> bool {
        false
    }

    fn linked_modules(&self) -> Vec<String> {
        Vec::new()
    }

    fn routes(&self, _module: &str) -> Vec<busbar_contract::route::Route> {
        Vec::new()
    }

    fn public_routes(&self, _module: &str) -> Vec<String> {
        Vec::new()
    }

    fn persistent_routes(&self, _module: &str) -> Vec<String> {
        Vec::new()
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
