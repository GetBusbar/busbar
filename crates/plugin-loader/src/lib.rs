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
pub mod auth_axis;
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
pub mod auth_door;

pub mod boot;

#[deny(unsafe_code)]
mod cold;

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
pub mod durable;
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
#[deny(unsafe_code)]
pub mod export_axis;
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
pub mod export_door;
#[deny(unsafe_code)]
pub mod fetch;
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
mod ffi_thread;
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
#[deny(unsafe_code)]
pub mod highwater;
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
pub mod hook_door;
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
#[deny(unsafe_code)]
mod host;
pub mod migration_secrets;
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
#[deny(unsafe_code)]
pub mod observe;
#[deny(unsafe_code)]
pub mod open_once;
#[deny(unsafe_code)]
pub mod registry;
#[deny(unsafe_code)]
pub mod release_trust;

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
#[deny(unsafe_code)]
pub mod secret_calls;

#[cfg(test)]
#[path = "tests/needs_restated.rs"]
mod needs_restated;

#[cfg(test)]
#[path = "tests/ordinary_load_negatives.rs"]
mod ordinary_load_negatives;

#[cfg(test)]
#[path = "tests/sdk_registration_tests.rs"]
mod sdk_registration_tests;

#[cfg(feature = "pack")]
#[deny(unsafe_code)]
pub mod integer_token;
#[deny(unsafe_code)]
pub mod settings_schema;
pub mod sign;
mod stage;
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
pub mod store_v4;
#[deny(unsafe_code)]
pub mod tarball;

// MIN-3 (ABI-MIN3-INTERFACE §4.3, §8.8, §11): the frozen request encoders and answer decoders, the ports and
// adapters the kernel consumes, admission, the stamp scan, refusals and instances. Wave-0 stubs (W0-ABI);
// each wave-1 owner replaces the stubs in its own files.
#[deny(unsafe_code)]
pub mod adapters;
#[deny(unsafe_code)]
pub mod admit;
#[deny(unsafe_code)]
pub mod answer;
mod chains;
#[deny(unsafe_code)]
#[deny(unsafe_code)]
pub mod instance;
#[deny(unsafe_code)]
#[deny(unsafe_code)]
pub mod refusal;
#[deny(unsafe_code)]
pub mod scan;
#[deny(unsafe_code)]
pub mod watchdog;

/// The safe test host (SDK-SAFE-TEST-HOST): tests load and drive plugins with no `unsafe`.
#[cfg(any(test, feature = "test-support"))]
pub mod test_host;

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
#[deny(unsafe_code)]
pub mod rows;

pub use sign::EgressPolicy;

impl LinkedPlugin {
    #[cfg(test)]
    pub fn first_party_door(
        kind: &str,
        name: &str,
        alias: &str,
        door: busbar_contract::abi::mechanism::door::DoorFn,
    ) -> Self {
        let mut row = LinkedPlugin::door_of_kind(kind, name, door);
        row.manifest.alias = alias.into();
        row
    }
}

pub use fetch::{fetch_plugins, FetchOutcome, FetchSpec};
pub use highwater::{HighWaterMarks, HIGH_WATER_FILE};
pub use registry::{
    inventory as inventory_tarballs, scan_and_validate, supported_abi, InventoryEntry, LinkedEntry,
    LinkedPlugin, LoadablePlugin, PluginRegistry, SkippedPlugin,
};
#[cfg(any(test, feature = "test-support"))]
pub use stage::keep_door;
pub use stage::{install_native_load_guard, sweep_dead_staging, NativeLoadGuard};

pub fn intern_name(name: &str) -> &'static str {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static INTERNED: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let set = INTERNED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = set.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(existing) = guard.get(name) {
        return existing;
    }

    let leaked: &'static str = Box::leak(name.to_string().into_boxed_str());
    guard.insert(leaked);
    leaked
}

#[cfg(test)]
thread_local! {
    /// TEST-ONLY: how many library unloads THIS THREAD has routed through [`stage::dlclose_on_worker`]. An
    /// unload that happens by an implicit field/local drop instead runs the image's `.fini_array` on
    /// whatever thread dropped it, and a caller thread that later retires is the crash `ffi_thread`
    /// documents — a property no assertion on a returned value can see. Counting the routed unloads
    /// is what makes it observable.
    ///
    /// THREAD-LOCAL, not a global atomic: libtest runs siblings in parallel, and a sibling that
    /// loaded and unloaded a plugin between a global counter's two samples would satisfy a "went up"
    /// assertion while the path under test unloaded on the caller's thread — a test that passes in
    /// the red state. `dlclose_on_worker` is called on the routing thread (only the drop moves to
    /// the worker), so a per-thread count sees exactly this caller's unloads and nobody else's.
    pub(crate) static UNLOADS_ON_WORKER: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "test-support"))]
pub fn plugin_library_filename(crate_snake: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        format!("{crate_snake}.dll")
    }
    #[cfg(target_os = "macos")]
    {
        format!("lib{crate_snake}.dylib")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        format!("lib{crate_snake}.so")
    }
}

#[cfg(any(test, feature = "test-support"))]
fn is_library_file(file: &str) -> bool {
    if cfg!(target_os = "windows") {
        let b = file.as_bytes();
        return b.len() >= 4 && b[b.len() - 4..].eq_ignore_ascii_case(b".dll");
    }
    let ext = if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    };
    file.ends_with(ext)
}

#[cfg(any(test, feature = "test-support"))]
pub fn list_plugin_files(dir: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        if path.is_file() && is_library_file(file) {
            out.push(file.to_string());
        }
    }
    out.sort();
    out
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
#[deny(unsafe_code)]
mod tests;

#[cfg(test)]
#[path = "tests/export_conformance_tests.rs"]
mod export_conformance_tests;

#[cfg(test)]
#[path = "tests/both_ways.rs"]
#[deny(unsafe_code)]
mod both_ways;

#[cfg(test)]
#[path = "tests/open_dropped_image_tests.rs"]
#[deny(unsafe_code)]
mod open_dropped_image_tests;

#[cfg(test)]
#[path = "tests/auth_verify_conformance_tests.rs"]
mod auth_verify_conformance_tests;

#[cfg(test)]
#[path = "../tests/fixtures/dispatch_test_plugin.rs"]
mod dispatch_test_plugin;

#[cfg(test)]
#[path = "tests/dispatch_tests.rs"]
mod dispatch_tests;

#[cfg(test)]
use neutral_plane as plane_door_plugin;

#[cfg(test)]
#[path = "tests/dispatch_kind_secret_export_tests.rs"]
mod dispatch_kind_secret_export_tests;

#[cfg(test)]
#[path = "tests/dispatch_kind_transport_tests.rs"]
mod dispatch_kind_transport_tests;

#[cfg(test)]
#[path = "tests/confined_kind_ops_tests.rs"]
mod confined_kind_ops_tests;

#[cfg(test)]
#[path = "tests/dispatch_kind_plane_tests.rs"]
mod dispatch_kind_plane_tests;

#[cfg(test)]
#[path = "tests/dispatch_kind_hook_tests.rs"]
mod dispatch_kind_hook_tests;

#[cfg(test)]
#[path = "tests/dispatch_kind_auth_tests.rs"]
mod dispatch_kind_auth_tests;

#[cfg(test)]
#[path = "tests/door_both_ways.rs"]
mod door_both_ways;

#[cfg(test)]
#[path = "tests/secret_door_conformance_tests.rs"]
mod secret_door_conformance_tests;

#[cfg(test)]
#[path = "tests/transport_door_conformance_tests.rs"]
mod transport_door_conformance_tests;

#[cfg(test)]
#[path = "tests/transport_door_tests.rs"]
mod transport_door_tests;

#[cfg(test)]
#[path = "tests/hook_door_conformance_tests.rs"]
mod hook_door_conformance_tests;

#[cfg(test)]
#[path = "tests/conformance_auth_form_tests.rs"]
mod conformance_auth_form_tests;

#[cfg(test)]
#[path = "tests/conformance_auth_unjudged_tests.rs"]
mod conformance_auth_unjudged_tests;

#[cfg(test)]
#[path = "tests/conformance_export_unjudged_tests.rs"]
mod conformance_export_unjudged_tests;

#[cfg(test)]
#[path = "tests/conformance_ready_after_no_ticket_tests.rs"]
mod conformance_ready_after_no_ticket_tests;

#[cfg(test)]
#[path = "tests/conformance_ready_result_tests.rs"]
mod conformance_ready_result_tests;

#[cfg(test)]
#[path = "tests/neutral_plane.rs"]
mod neutral_plane;

#[cfg(test)]
#[path = "tests/neutral_plane_identity_tests.rs"]
mod neutral_plane_identity_tests;

#[cfg(test)]
#[path = "tests/ordinary_plane_registry.rs"]
mod ordinary_plane_registry;

#[cfg(test)]
#[path = "tests/ordinary_plane_lending.rs"]
mod ordinary_plane_lending;

#[cfg(test)]
#[path = "tests/ordinary_suite_dispatch_tests.rs"]
mod ordinary_suite_dispatch_tests;

#[cfg(test)]
#[path = "tests/ordinary_auth_short.rs"]
mod ordinary_auth_short;

#[cfg(test)]
#[path = "tests/ordinary_suite_hook_ticket_tests.rs"]
mod ordinary_suite_hook_ticket_tests;

#[cfg(test)]
#[path = "tests/neutral_store.rs"]
mod neutral_store;

#[cfg(test)]
#[path = "tests/neutral_secret.rs"]
mod neutral_secret;

#[cfg(test)]
#[path = "tests/neutral_rotating_secret.rs"]
mod neutral_rotating_secret;

#[cfg(test)]
#[path = "tests/neutral_export.rs"]
mod neutral_export;

#[cfg(test)]
#[path = "tests/ordinary_plane_ack_drive.rs"]
mod ordinary_plane_ack_drive;

#[cfg(test)]
#[path = "tests/ordinary_plane_lifecycle.rs"]
mod ordinary_plane_lifecycle;

#[cfg(test)]
#[path = "tests/ordinary_plane_sessions_actual.rs"]
mod ordinary_plane_sessions_actual;

#[cfg(test)]
#[path = "tests/ordinary_plane_deadline.rs"]
mod ordinary_plane_deadline;

#[cfg(test)]
#[path = "tests/ordinary_plane_fault_outputs.rs"]
mod ordinary_plane_fault_outputs;

#[cfg(test)]
#[path = "tests/ordinary_declared_metadata.rs"]
mod ordinary_declared_metadata;

#[cfg(test)]
#[path = "tests/retired_store_fixture.rs"]
mod retired_store_fixture;

#[cfg(test)]
#[path = "tests/neutral_transport.rs"]
mod neutral_transport;

#[cfg(test)]
#[path = "tests/neutral_auth.rs"]
mod neutral_auth;
