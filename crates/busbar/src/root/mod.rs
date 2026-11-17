// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod adapters;
pub mod admission;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod auth_bindings;
pub mod boot;
/// The boot's configuration reader rules and its one application build.
pub(crate) mod boot_app;
pub mod card_history;
pub mod cli;
// The one cold module (LINT-RULES LR-167): refusal text and rare first-sight paths the request-path
// modules beside it call out of line.
pub(crate) mod cold;
pub mod connector;
pub mod credentials;
pub(crate) mod export_observer;
pub(crate) mod min3_admin_auth;
pub(crate) mod min3_auth;
pub(crate) mod min3_outbound_auth;
pub(crate) mod native_refusals;
pub(crate) mod provisioning;
pub(crate) mod provisioning_mount;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod dispatch;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod door_steps;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod doors;
pub mod durability;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod egress_ports;
pub mod exit;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod exports;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod hooks;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod inbound;
#[cfg(all(test, linked_every_plane_door))]
#[path = "tests/inbound.rs"]
mod inbound_tests;
pub(crate) mod ingress_context;
pub mod kernel;
pub mod keyset;
pub mod linked;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod listener;
pub(crate) mod listener_native;
pub(crate) mod loader;
pub(crate) mod measurements;
/// The migrate-on-boot seam: step 1 (the stamp) and step 5 (the write and re-exec).
pub(crate) mod migrate;
/// Migrate-on-boot steps 4 and 5S/5C: core's records step over the opened store.
pub(crate) mod migrate_records;
/// The boot's MIN-3 registry: Need handlers, image admission, the boot walk (ROOT-BOOT).
pub(crate) mod min3_boot;
/// Native lifetime custody attached to the exact published App.
pub(crate) mod min3_candidate;
pub(crate) mod min3_candidate_secrets;
pub(crate) mod min3_framers;
pub(crate) mod min3_listener_plan;
pub(crate) mod min3_physical;
pub(crate) mod min3_provider_catalog;
pub(crate) mod min3_provider_plan;
pub(crate) mod min3_selected_policy;
/// K9: each MIN-3 plane seat's egress walk and channel carrier, composed at boot from the configured upstreams.
pub(crate) mod plane_seats;
/// The HTTP mount of the MIN-3 plane instances: their data routes onto `PortDriver::serve`.
pub(crate) mod port_mount;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod model_egress;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod observe;
// The request-path modules' code that runs off the request path: once per configuration, generation
// or process lifecycle, never per request.
pub(crate) mod off_path;

// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod plane_node;
pub mod plugin_fetch;
pub mod policy;
pub mod principal_transition;
// ADMIN-API-1.6 §3.5: `records.user` and `records.labels`, configured at boot.
pub(crate) mod records_capture;
pub mod registry;
// busbar:request-path
pub(crate) mod native_secrets;
/// The launch variables 1.6.0 retired: the BUSBAR-3029 "set but ignored" notice.
pub(crate) mod retired_env;
pub(crate) mod secret_custody;
pub(crate) mod secret_grammar;
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod serve;
pub mod settings_public;
pub mod shutdown;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
#[cfg(test)]
pub mod transports;
pub mod units_admin;
pub mod userinfo;

#[cfg(test)]
#[path = "tests/admin_plugin_admission.rs"]
mod admin_plugin_admission;

#[cfg(test)]
#[path = "tests/oracle_source_pins.rs"]
mod oracle_source_pins;

#[cfg(test)]
#[path = "tests/product_pin_aliases.rs"]
mod product_pin_aliases;

#[cfg(test)]
#[path = "tests/product_pin_former_names.rs"]
mod product_pin_former_names;

#[cfg(test)]
#[path = "tests/records_capture.rs"]
mod records_capture_tests;

#[cfg(test)]
pub(crate) static PUBLISHING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
pub(crate) use crate::test_common::plugins as test_plugins;

#[cfg(test)]
#[path = "tests/store_double.rs"]
pub(crate) mod store_double;

#[cfg(test)]
#[path = "tests/linked_door_root.rs"]
mod linked_door_root;

#[cfg(test)]
#[path = "tests/plane_registry.rs"]
pub(crate) mod test_plane_registry;

#[cfg(test)]
#[path = "tests/real_store.rs"]
pub(crate) mod real_store;

#[cfg(test)]
include!(concat!(env!("OUT_DIR"), "/context_test_sources.rs"));
#[cfg(test)]
owner_test_sources!(root_stdio);
#[cfg(test)]
owner_test_sources!(root_http);

pub(crate) mod selected_report;
#[cfg(test)]
mod selected_report_tests;
