// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![deny(unsafe_code)]

#[doc(hidden)]
pub use busbar_plugin_loader::{
    auth_door, dispatch, plugin_library_filename, sign, store_v3, LinkedPlugin, PluginRegistry,
};

pub mod alloc_counter;

pub mod auth_axis;

#[allow(unsafe_code)]
pub mod conformance;

pub mod conformance_host;

pub mod https_conns;

#[allow(unsafe_code)]
pub mod root_door_fixtures;

pub mod services_double;

pub mod stand_in;

pub mod tcp_conns;

pub mod test_issuer;

#[allow(unsafe_code)]
pub mod test_support;

pub mod warn_capture;
