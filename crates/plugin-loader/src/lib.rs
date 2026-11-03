// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![deny(unsafe_code)]

use libloading::Library;
use std::path::Path;

pub mod auth_axis;
#[allow(unsafe_code)]
pub mod auth_door;

pub mod boot;

#[allow(unsafe_code)]
pub mod dispatch;

pub mod durable;
pub mod export_axis;
#[allow(unsafe_code)]
pub mod export_door;
pub mod fetch;
#[allow(unsafe_code)]
mod ffi_thread;
pub mod highwater;
#[allow(unsafe_code)]
pub mod hook_door;
mod host;
pub mod observe;
pub mod open_once;
pub mod registry;
pub mod release_trust;

#[allow(unsafe_code)]
pub mod secret_calls;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/needs_restated.rs"]
mod needs_restated;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/ordinary_load_negatives.rs"]
mod ordinary_load_negatives;

pub mod settings_schema;
pub mod sign;
#[allow(unsafe_code)]
mod stage;
pub mod store_adapter;
#[allow(unsafe_code)]
pub mod store_v3;
pub mod tarball;

pub mod rows;

pub use sign::EgressPolicy;

impl LinkedPlugin {
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

#[allow(unsafe_code)]
pub(crate) fn dlopen_on_worker(path: &std::ffi::OsStr) -> Result<Library, String> {
    // SAFETY (unchanged from the direct call this replaces): loading an operator-placed library runs
    // its init code, which is the same trust as compiling it in. Callers apply the trust gate first.
    match ffi_thread::on_plugin_thread(|| {
        ffi_thread::debug_assert_permanent("dlopen");
        unsafe { Library::new(path) }
    }) {
        Ok(r) => r.map_err(|e| e.to_string()),

        Err(_) => Err("the library's initializer panicked while loading".to_string()),
    }
}

pub(crate) fn dlclose_on_worker(lib: Library) {
    #[cfg(test)]
    UNLOADS_ON_WORKER.with(|n| n.set(n.get() + 1));
    let _ = ffi_thread::on_plugin_thread(move || {
        ffi_thread::debug_assert_permanent("dlclose");
        drop(lib);
    });
}

#[cfg(test)]
thread_local! {
    /// TEST-ONLY: how many library unloads THIS THREAD has routed through [`dlclose_on_worker`]. An
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

pub fn list_plugin_files(dir: &Path) -> Vec<String> {
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
mod tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/export_conformance_tests.rs"]
mod export_conformance_tests;

#[cfg(test)]
#[path = "tests/both_ways.rs"]
mod both_ways;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/auth_verify_conformance_tests.rs"]
mod auth_verify_conformance_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "../tests/fixtures/dispatch_test_plugin.rs"]
mod dispatch_test_plugin;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/dispatch_tests.rs"]
mod dispatch_tests;

#[cfg(test)]
use actual_mcp as plane_door_plugin;


#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/dispatch_kind_secret_export_tests.rs"]
mod dispatch_kind_secret_export_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/dispatch_kind_transport_tests.rs"]
mod dispatch_kind_transport_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/dispatch_kind_plane_tests.rs"]
mod dispatch_kind_plane_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/dispatch_kind_store_tests.rs"]
mod dispatch_kind_store_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/stub_store_plane_tests.rs"]
mod stub_store_plane_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/dispatch_kind_hook_tests.rs"]
mod dispatch_kind_hook_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/dispatch_kind_auth_tests.rs"]
mod dispatch_kind_auth_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/door_both_ways.rs"]
mod door_both_ways;

#[cfg(test)]
#[path = "tests/store_door_conformance_tests.rs"]
mod store_door_conformance_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/secret_door_conformance_tests.rs"]
mod secret_door_conformance_tests;

#[cfg(test)]
#[path = "tests/transport_door_conformance_tests.rs"]
mod transport_door_conformance_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/transport_door_tests.rs"]
mod transport_door_tests;

#[cfg(test)]
#[path = "tests/hook_door_conformance_tests.rs"]
mod hook_door_conformance_tests;



#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/conformance_auth_form_tests.rs"]
mod conformance_auth_form_tests;





#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/conformance_auth_unjudged_tests.rs"]
mod conformance_auth_unjudged_tests;

// The retired datagram harness tested its own string renderer and script judge.
// Actual transport behavior remains owned by the product tests.


#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/conformance_export_unjudged_tests.rs"]
mod conformance_export_unjudged_tests;









#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/conformance_ready_result_tests.rs"]
mod conformance_ready_result_tests;









#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/https_timeout_tests.rs"]
mod https_timeout_tests;


#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/stand_in_tests.rs"]
mod stand_in_tests;


#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/actual_mcp.rs"]
mod actual_mcp;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/actual_mcp_identity_tests.rs"]
mod actual_mcp_identity_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/ordinary_plane_registry.rs"]
mod ordinary_plane_registry;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/ordinary_plane_lending.rs"]
mod ordinary_plane_lending;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/ordinary_suite_dispatch_tests.rs"]
mod ordinary_suite_dispatch_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/ordinary_auth_short.rs"]
mod ordinary_auth_short;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/ordinary_suite_hook_ticket_tests.rs"]
mod ordinary_suite_hook_ticket_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/actual_store.rs"]
mod actual_store;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/actual_env_secret.rs"]
mod actual_env_secret;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/actual_exports.rs"]
mod actual_exports;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/store_memory_facts_actual.rs"]
mod store_memory_facts_actual;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/ordinary_plane_ack_drive.rs"]
mod ordinary_plane_ack_drive;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/ordinary_plane_lifecycle.rs"]
mod ordinary_plane_lifecycle;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/ordinary_plane_sessions_actual.rs"]
mod ordinary_plane_sessions_actual;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/ordinary_plane_deadline.rs"]
mod ordinary_plane_deadline;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/ordinary_plane_fault_outputs.rs"]
mod ordinary_plane_fault_outputs;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/ordinary_declared_metadata.rs"]
mod ordinary_declared_metadata;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/store_lifecycle_actual.rs"]
mod store_lifecycle_actual;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/store_actual_opid_tests.rs"]
mod store_actual_opid_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/store_actual_pending_tests.rs"]
mod store_actual_pending_tests;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/actual_rewrap_contracts.rs"]
mod actual_rewrap_contracts;
