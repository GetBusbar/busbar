// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub mod boot;

#[deny(unsafe_code)]
mod cold;

// Each submodule but the path-pinned `durable_documents` (its unsafe is registered in unsafe.yaml) denies unsafe code.
mod off_path;

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
pub mod export_pump;
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
#[deny(unsafe_code)]
mod host;
pub mod migration_secrets;
#[deny(unsafe_code)]
pub mod open_once;
#[deny(unsafe_code)]
pub mod registry;
#[deny(unsafe_code)]
pub mod release_trust;

#[cfg(test)]
#[path = "tests/artifact_verifier_parity.rs"]
mod artifact_verifier_parity;
#[cfg(feature = "pack")]
#[deny(unsafe_code)]
pub mod integer_token;
// Ungated (no `pack` dependency: it reads the stamp and header only): the root's admission and inspect
// judge whether an upload is a native image with `is_native`. `jsonschema` stays behind `pack`.
#[deny(unsafe_code)]
pub mod pack_native;
#[deny(unsafe_code)]
pub mod settings_schema;
pub mod sign;
mod stage;
#[deny(unsafe_code)]
pub mod tarball;
/// Authority-bound canonical release verification.
pub mod verification;

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
#[cfg(target_os = "linux")]
#[deny(unsafe_code)]
pub mod inspect;
#[deny(unsafe_code)]
pub mod instance;
#[deny(unsafe_code)]
pub mod refusal;
#[deny(unsafe_code)]
pub mod scan;
mod upstream_paths;
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

pub use fetch::{fetch_plugins, FetchOutcome, FetchSpec};
pub use highwater::{HighWaterMarks, HIGH_WATER_FILE};
pub use registry::{
    inventory as inventory_tarballs, scan_and_validate, supported_abi, InventoryEntry,
    LoadablePlugin, PluginRegistry, SkippedPlugin,
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
#[path = "tests/both_ways.rs"]
#[deny(unsafe_code)]
mod both_ways;

#[cfg(test)]
#[path = "tests/ordinary_plane_registry.rs"]
mod ordinary_plane_registry;

/// Process-owned MIN-3 resources.
pub mod process;

mod reopen;
