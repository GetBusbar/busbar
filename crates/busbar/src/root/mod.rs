// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(dead_code)]

pub mod adapters;
pub mod admission;
pub mod auth_bindings;
pub mod boot;
pub mod card_history;
pub mod card_store;
pub mod cli;
pub mod config_migrate;
pub mod connector;
pub mod credentials;
pub mod dispatch;
pub mod door_steps;
pub mod doors;
pub mod durability;
pub mod egress_ports;
pub mod exports;
pub mod hooks;
pub mod inbound;
#[cfg(all(test, linked_every_plane_door))]
#[path = "tests/inbound.rs"]
mod inbound_tests;
pub mod kernel;
pub mod keyset;
pub mod linked;
pub mod listener;
pub(crate) mod loader;
pub mod migration_table;
pub mod model_egress;
pub mod observe;

pub mod plane_node;
pub mod plugin_fetch;
pub mod policy;
pub mod registry;
pub mod serve;
pub mod settings_public;
pub mod shutdown;
pub mod transports;
#[cfg(feature = "root-admin")]
pub mod units_admin;
pub mod userinfo;

#[cfg(test)]
#[path = "tests/admin_plugin_admission.rs"]
mod admin_plugin_admission;

#[cfg(test)]
pub(crate) static PUBLISHING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
#[path = "tests/doors_refresh.rs"]
mod doors_refresh;

#[cfg(test)]
#[path = "tests/scoped_framing.rs"]
mod scoped_framing_tests;

#[cfg(test)]
#[path = "tests/inbound_reload.rs"]
mod inbound_reload_tests;

#[cfg(test)]
#[path = "tests/test_plugins.rs"]
pub(crate) mod test_plugins;

#[cfg(test)]
#[path = "tests/store_double.rs"]
pub(crate) mod store_double;

#[cfg(test)]
#[path = "tests/linked_door_root.rs"]
mod linked_door_root;

#[cfg(test)]
#[path = "tests/plane_registry.rs"]
pub(crate) mod test_plane_registry;
