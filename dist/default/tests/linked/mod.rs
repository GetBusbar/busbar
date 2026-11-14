// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(dead_code)]

use busbar_kernel::plane_driver::registry::{plane_decls, PlaneDecl};

include!(concat!(env!("OUT_DIR"), "/test_linked.rs"));
include!(concat!(env!("OUT_DIR"), "/test_linked_secrets.rs"));

pub fn install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        busbar_kernel::plane_driver::registry::install_planes(door_rows());
        busbar_kernel::preflight::install_linked_rows(busbar_kernel::preflight::RootInstall {
            secret_axis: Some(secret_rows()),
            ..Default::default()
        });
    });
}

/// The test-linked secret sources on one axis, as the root links its own: what a test's references
/// are read through (the source shorthand their Statements declare).
pub fn secret_rows() -> &'static busbar_plugin_loader::secret_calls::SecretRows {
    static ROWS: std::sync::OnceLock<busbar_plugin_loader::secret_calls::SecretRows> =
        std::sync::OnceLock::new();
    ROWS.get_or_init(|| {
        let mut rows = busbar_plugin_loader::secret_calls::SecretRows::new(dispatcher, || None);
        for &(door, declares) in TEST_LINKED_SECRETS {
            rows.link(door)
                .unwrap_or_else(|e| panic!("a test-linked secret source states itself: {e}"));
            if let Some(json) = declares {
                rows.declare_linked(door, json)
                    .unwrap_or_else(|e| panic!("a test-linked secret source declares: {e}"));
            }
        }
        rows
    })
}

fn dispatcher() -> std::sync::Arc<busbar_plugin_loader::dispatch::Dispatcher> {
    use busbar_plugin_loader::dispatch::{DispatchConfig, Dispatcher};
    static ONE: std::sync::OnceLock<std::sync::Arc<Dispatcher>> = std::sync::OnceLock::new();
    ONE.get_or_init(|| {
        let dispatcher = std::sync::Arc::new(Dispatcher::with_services(
            DispatchConfig::default(),
            std::sync::Arc::new(busbar_kernel::host_services::KernelServices::new()),
            busbar_kernel::host_services::caller_binding(),
        ));
        let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
        dispatcher
    })
    .clone()
}

fn door_rows() -> &'static [&'static PlaneDecl] {
    static ROWS: std::sync::OnceLock<Vec<&'static PlaneDecl>> = std::sync::OnceLock::new();
    ROWS.get_or_init(|| {
        TEST_LINKED_DOORS
            .iter()
            .map(|&(label, door)| fold_door(label, door))
            .collect()
    })
}

fn fold_door(
    label: &str,
    door: busbar_contract::abi::mechanism::door::DoorFn,
) -> &'static PlaneDecl {
    use busbar_plugin_loader::dispatch::kinds::plane::{linked_probe, registration};
    let reg = registration(linked_probe(
        door,
        label,
        busbar_contract::services::test_caller_binding(),
    ))
    .unwrap_or_else(|e| panic!("the test-linked door `{label}` binds: {e}"));
    busbar_kernel::plane_driver::door::fold(reg)
        .unwrap_or_else(|e| panic!("the test-linked door `{label}` folds: {e}"))
}

pub fn linked_count() -> usize {
    TEST_LINKED_DOORS.len()
}

pub fn planes() -> &'static [&'static PlaneDecl] {
    install();
    plane_decls()
}

pub fn declaring(what: &str, pred: impl Fn(&PlaneDecl) -> bool) -> &'static PlaneDecl {
    let hits: Vec<&'static PlaneDecl> = planes().iter().copied().filter(|d| pred(d)).collect();
    match hits.as_slice() {
        [one] => one,
        [] => panic!(
            "no test-linked plane declares {what}: the planes this test binary links are the \
             crates listed in `[package.metadata.busbar.test-linked] planes` (crates/busbar/\
             Cargo.toml); registered keys: {:?}",
            planes().iter().map(|d| d.key).collect::<Vec<_>>()
        ),
        many => panic!(
            "{} test-linked planes declare {what} ({:?}); an address must name exactly one",
            many.len(),
            many.iter().map(|d| d.key).collect::<Vec<_>>()
        ),
    }
}

pub fn owning(section: &str) -> &'static PlaneDecl {
    declaring(&format!("the `{section}:` config section"), |d| {
        d.config_section == section || d.owned_config_sections.contains(&section)
    })
}

pub fn fallback() -> &'static PlaneDecl {
    declaring("itself the fallback plane", |d| d.fallback)
}

pub fn door_section(decl: &PlaneDecl) -> &'static str {
    decl.owned_config_sections
        .first()
        .copied()
        .unwrap_or(decl.config_section)
}

pub fn doors() -> &'static [(&'static str, busbar_contract::abi::mechanism::door::DoorFn)] {
    TEST_LINKED_DOORS
}
