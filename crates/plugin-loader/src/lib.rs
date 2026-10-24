// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN LOADER: discovery, trust and the registry ([`registry`], [`sign`], [`tarball`]); the
//! ONE loading path and the ONE dispatcher of the memory ABI ([`dispatch`]: `load_linked` /
//! `load_dropped`), through which every store, secret, auth, hook and export plugin loads,
//! compiled in or dropped in (`BUSBAR-1.6.0.md` THE DESIGN §11). Every plane and every transport
//! loads through its door too.
//!
//! No plugin of any kind loads through a JSON lane or the HOT `#[repr(C)]` decl lane: both are gone
//! (row 84), with the handshake they shared (`busbar_abi`, `busbar_plugin_kind`).
//!
//! UNSAFE CODE (`BUSBAR-1.6.0.md` THE DESIGN §2: "transport, loader, store and export crates are
//! `#![deny(unsafe_code)]` with a reviewed allow-list"): denied for the whole crate. THE REVIEWED
//! ALLOW-LIST is every `#[allow(unsafe_code)]` below and the two named functions: the modules that
//! cross the memory ABI (the dispatcher, the doors and axes that lend it memory, the plugin thread,
//! the staging `memfd`, the published conformance suite) and their tests; `dlopen_on_worker`
//! (`Library::new`); `boot`'s secret wipe (a volatile write). A new `unsafe` anywhere else does
//! not compile until it is added here, by name, for review.
#![deny(unsafe_code)]

use libloading::Library;
use std::path::Path;

pub mod auth_axis;
#[allow(unsafe_code)] // REVIEWED: lends the auth door its request lines, body and result buffers
pub mod auth_door;
/// THE BOOT STAGES the loader owns: what config uses, Discover, Select and the one load
/// (`BUSBAR-1.6.0.md` THE DESIGN, §3).
pub mod boot;
/// THE PUBLISHED CONFORMANCE SUITE (TODO ABI-b4): what every real plugin repo runs against the busbar
/// commit it pins, linked and dropped in, through the one loader. Behind `conformance`: a plugin's
/// dev-dependency turns it on; no busbar build ships it. This crate's own tests drive the shipped
/// transport row through it too (`transport_door_conformance_tests`).
#[cfg(any(test, feature = "conformance"))]
#[allow(unsafe_code)] // REVIEWED: the published suite drives raw doors and plants faults
pub mod conformance;
/// THE ONE DISPATCHER of the memory ABI (`BUSBAR-1.6.0.md` THE DESIGN, §11): one loader path, one
/// crossing, tickets, wakes, deadlines and the watchdog, generic over the kind.
#[allow(unsafe_code)] // REVIEWED: THE ONE DISPATCHER: every crossing of the memory ABI
pub mod dispatch;
/// THE ONE DURABLE-WRITE OWNER: the whole-file publish (temp, fsync, rename, fsync the holding
/// directory) every durable file write in busbar goes through — the loader's own (fetched artifacts,
/// the high-water marks, plugin log directories) and, through `busbar_kernel::durable`, the
/// kernel's and the admin surface's. It lives here because the loader is the lowest host-only crate
/// every writer links (Part 2 #33: the loader names `busbar-contract` alone, so it cannot reach a
/// kernel crate for it). Host-only: no plugin image links this crate, so its temp-name counter is
/// one per process.
pub mod durable;
pub mod export_axis;
#[allow(unsafe_code)] // REVIEWED: lends the export door its batch
pub mod export_door;
pub mod fetch;
#[allow(unsafe_code)] // REVIEWED: the plugin thread every crossing and `dlopen` runs on
mod ffi_thread;
pub mod highwater;
#[allow(unsafe_code)] // REVIEWED: lends the hook door its frame
pub mod hook_door;
mod host;
/// NEVER SHIPPED: the framed connection-table stand-in with in-process far ends (`test-support`,
/// and the published conformance suite's `far_ends`), for a build that cannot link the process's
/// connector. No TLS library: TLS stays in the connector.
#[cfg(any(test, feature = "test-support", feature = "conformance"))]
pub mod https_conns;
pub mod observe;
pub mod open_once;
pub mod registry;
/// THE SECRET AXIS over the one dispatcher: every admitted secret plugin, linked or dropped in.
#[allow(unsafe_code)] // REVIEWED: lends the secret door its names and result buffers
pub mod secret_calls;
// The former `busbar-plugin-sign` crate, folded in whole (DECISIONS #33): signature verify +
// trust evaluation is the loader's OWN job, not a crate the loader reaches for. Pure data +
// policy, no I/O -- the I/O that acts on its verdicts is `tarball`, `fetch` and `registry`.
/// TEST ONLY: a real door restated with one stream need (the bind tests' subject; no plugin).
#[cfg(test)]
#[allow(unsafe_code)] // TEST ONLY: raw doors and crossings
#[path = "tests/needs_restated.rs"]
mod needs_restated;
pub mod sign;
#[allow(unsafe_code)] // REVIEWED: the staged image's `memfd` and its file descriptors
mod stage;
/// NEVER SHIPPED: the facts the test connection tables stand in for, read from data
/// (`stand_in.json`), so no Rust source of this crate names a transport.
#[cfg(any(test, feature = "test-support", feature = "conformance"))]
pub mod stand_in;
pub mod store_adapter;
#[allow(unsafe_code)] // REVIEWED: lends the store door its request (`Lend`)
pub mod store_v3;
pub mod tarball;
/// TEST ONLY: the test connection table. Also the published conformance suite's (`conformance`):
/// a plugin repo names this crate only as a dev-dependency, so it reaches no shipped closure.
#[cfg(any(test, feature = "test-support", feature = "conformance"))]
pub mod tcp_conns;
/// TEST ONLY: a local token issuer (an ES256 key, its JWKS, signed tokens) for the tests of a host
/// that loads a token-verifying auth plugin (`test-support`).
#[cfg(any(test, feature = "test-support"))]
pub mod test_issuer;
/// TEST ONLY: the fake-call store harness the kernel's minting tests share with this crate's own.
/// Compiled for this crate's tests and under the `test-support` feature, which only
/// busbar-kernel's `[dev-dependencies]` edge turns on; never in a shipped build.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[path = "tests/test_support.rs"]
pub mod test_support;

/// TEST ONLY: the composition root's door fixtures (status row 195): doors built by the contract's
/// door macro, whose expansion writes `unsafe`, kept here so the `forbid(unsafe_code)` root holds no
/// such expansion. Under `test-support`, which only the root's `[dev-dependencies]` turns on.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[allow(unsafe_code)] // TEST ONLY: plugin_door! fixtures the composition root's tests drive
#[path = "../tests/fixtures/root_door_fixtures.rs"]
pub mod root_door_fixtures;

/// THE REGISTRY AS THE KERNEL READS IT (the contract's `PluginRows`).
pub mod rows;

pub use sign::EgressPolicy;

impl LinkedPlugin {
    /// A FIRST-PARTY memory-ABI plugin a build links: `name` aliased `alias`, of `kind`, at this
    /// loader's one version of the kind, published by busbar — the manifest its release tarball
    /// states — over its `door` (`plugin_door!`): the same door its `cdylib` exports.
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
pub use stage::sweep_dead_staging;

/// THE LOADER RE-EXPORTS NO CONTRACT TYPE (BOOT-LOOP step 3, ruling R2). A type the contract owns
/// is named from `busbar_contract::abi::*`, the crate that owns it; the loader path to it does not
/// compile. Each block below is one former loader re-export, and each must stay a compile error.
///
/// ```compile_fail
/// use busbar_plugin_loader::EndpointRequest;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::EndpointResponse;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::Route;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::RouteAuth;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::RouteMethod;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::CheckPhase;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::ExportField;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::ExportStream;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HostResult;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HttpRequest;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HttpResponse;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::ColdEntry;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HotDeclStr;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HotPlaneDecl;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HotHostVtable;
/// ```
/// ```compile_fail
/// use busbar_plugin_loader::HotStatusClass;
/// ```
pub mod contract_types_are_named_from_the_contract {}

/// INTERN a plugin name into a stable `&'static str`, reusing one allocation per unique name.
///
/// The hook routing seam and `DynAuth` carry `name: &'static str`, and a name string used to be
/// `Box::leak`ed on EVERY open — but hook and auth opens run per config/plugin reload, per `push_configure`, per
/// `fetch_status` (every Prometheus `/metrics/hooks` scrape refresh), per `fetch_schema`, and per
/// `resolve_on_error_chain`, so the leak was per-CALL and unbounded over the process lifetime, driven
/// by routine external scraping. Interning bounds it to ONE leak per DISTINCT plugin name for the life
/// of the process: a repeated open of the same plugin reuses the interned `&'static str`.
pub fn intern_name(name: &str) -> &'static str {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static INTERNED: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let set = INTERNED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = set.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(existing) = guard.get(name) {
        return existing;
    }
    // First sighting of this name: leak it ONCE, then remember it so future opens reuse this alloc.
    let leaked: &'static str = Box::leak(name.to_string().into_boxed_str());
    guard.insert(leaked);
    leaked
}

/// `dlopen` on a worker that never retires. Mapping an image RUNS ITS ELF `.init_array` — that is
/// plugin code, on whatever thread called it, and it is as capable of arming the plugin's
/// `pthread_key` TLS destructor as any ABI symbol, so it runs where every routed crossing runs
/// (`ffi_thread`).
#[allow(unsafe_code)] // REVIEWED: `Library::new`, behind the trust gate
pub(crate) fn dlopen_on_worker(path: &std::ffi::OsStr) -> Result<Library, String> {
    // SAFETY (unchanged from the direct call this replaces): loading an operator-placed library runs
    // its init code, which is the same trust as compiling it in. Callers apply the trust gate first.
    match ffi_thread::on_plugin_thread(|| {
        ffi_thread::debug_assert_permanent("dlopen");
        unsafe { Library::new(path) }
    }) {
        Ok(r) => r.map_err(|e| e.to_string()),
        // An init constructor that PANICKED into us. Vanishingly rare, but the rendezvous must
        // produce a value rather than resume an unwind on a worker whose thread must not die.
        Err(_) => Err("the library's initializer panicked while loading".to_string()),
    }
}

/// `dlclose` on a worker that never retires. Unmapping runs the image's `.fini_array` — plugin code
/// again — and doing it on a caller thread would hand that thread plugin TLS at the exact moment the
/// image is going away, which is the crash in its purest form.
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

/// The platform-native filename for a store plugin built from `crate_name` (e.g. `store_sqlite_plugin`
/// → `libbusbar_store_sqlite_plugin.so` / `.dylib` / `busbar_...dll`). Used to resolve `store: <name>`
/// against the plugins directory.
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

/// Is `file` a dynamic-library name for this platform (by extension)?
///
/// THE COMPARISON FOLLOWS THE FILESYSTEM'S OWN CASE RULE, which is not the same rule everywhere.
/// NTFS is case-INSENSITIVE: `FOO.DLL` and `foo.dll` name the same file, `LoadLibrary` opens either,
/// and an artifact arriving from a Windows build system or an unzip commonly carries an uppercase
/// extension. A case-SENSITIVE `ends_with(".dll")` therefore reports "no plugins installed" for a
/// directory that plainly holds one — a silent omission from the operator-facing inventory
/// (`GET /admin/plugins`), which is the surface an operator uses to answer "did my install land".
/// On unix the extension is part of the name and `.SO` is a DIFFERENT file from `.so`, so folding
/// case there would make this claim a file is a library on the strength of a name the loader would
/// not resolve. One question, each platform's own answer.
fn is_library_file(file: &str) -> bool {
    if cfg!(target_os = "windows") {
        // BYTES, not a `&str` slice: `file[file.len() - 4..]` panics when byte `len - 4` is not a
        // char boundary, and a filename is arbitrary UTF-8 — a plugins directory holding one
        // non-ASCII name would take down the inventory scan. `.dll` is ASCII, so the byte-suffix
        // comparison answers exactly the same question with no boundary to land inside.
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

/// List the dynamic-library FILENAMES in `dir` (sorted), WITHOUT opening any of them - the pure,
/// side-effect-free directory scan. It NEVER `dlopen`s a library, so an untrusted plugin's
/// init/constructor code cannot run just from enumerating the directory; the trust gate is applied by
/// the caller, per file, so no library's code runs until it passes trust. A missing directory is an
/// empty list.
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

/// DECISIONS #11's real test: ONE crate built both ways must be observationally identical. Declared
/// at the crate root rather than under `export` because it is not a test OF the export seam — it is
/// a test of the equivalence the two build shapes are supposed to have, and the export kind is
/// merely the first one with real plugins that can prove it (ARCHITECT ruling EXP2-PROOF
/// 2026-10-03: the spec's working proof of the plugin model, on the export kind's door registries).
#[cfg(test)]
#[allow(unsafe_code)] // TEST ONLY: raw doors and crossings
#[path = "tests/export_conformance_tests.rs"]
mod export_conformance_tests;

/// The both-ways harness (DECISIONS #2 rule (1)): one plugin registered through the
/// linked door and the dropped-in door, its rows and its opened instance compared.
#[cfg(test)]
#[path = "tests/both_ways.rs"]
mod both_ways;

/// No rlib the test binary links exports `busbar_plugin_door` (the fat-LTO duplicate-symbol guard).
#[cfg(test)]
#[path = "tests/door_symbol_tests.rs"]
mod door_symbol_tests;

/// `kind: auth` through both doors — the auth kind's first both-ways witness (#2, steps (1)-(5)): the
/// compiled-in twin and the `cdylib`'s `busbar_call` put one wire, and the linked and dropped-in rows
/// open one module.
#[cfg(test)]
#[path = "tests/auth_conformance_tests.rs"]
mod auth_conformance_tests;

/// `kind: auth` through both doors on the memory ABI, VERIFY VERDICTS: the token cases driven to
/// every verdict (identify, reject, pass) over a second real auth plugin, one row and one answer
/// either way.
#[cfg(test)]
#[path = "tests/auth_verify_conformance_tests.rs"]
mod auth_verify_conformance_tests;

/// The dispatcher through both doors: one script, LINKED and DROPPED, byte-identical, and a RED
/// arm per mechanism rule.
/// The dispatcher's test plugin, compiled in: the LINKED door of `dispatch_tests` (the same
/// source is the `dispatch_test_plugin` example `cdylib`, the DROPPED door).
#[cfg(test)]
#[allow(unsafe_code)] // TEST ONLY: raw doors and crossings
#[path = "../tests/fixtures/dispatch_test_plugin.rs"]
mod dispatch_test_plugin;

#[cfg(test)]
#[allow(unsafe_code)] // TEST ONLY: raw doors and crossings
#[path = "tests/dispatch_tests.rs"]
mod dispatch_tests;

/// The plane door's test plugin, compiled in: the LINKED door of `plane_conformance_tests` (the
/// same source is the `plane_door_plugin` example `cdylib`, the DROPPED door).
#[cfg(test)]
#[path = "../tests/fixtures/plane_door_plugin.rs"]
mod plane_door_plugin;

/// `kind: plane`: the plane door both ways, the plane kind's one version, and the refusal of a
/// plane with no door.
#[cfg(test)]
#[allow(unsafe_code)] // TEST ONLY: raw doors and crossings
#[path = "tests/plane_conformance_tests.rs"]
mod plane_conformance_tests;

/// The secret and export kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[allow(unsafe_code)] // TEST ONLY: raw doors and crossings
#[path = "tests/dispatch_kind_secret_export_tests.rs"]
mod dispatch_kind_secret_export_tests;

/// The transport kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[allow(unsafe_code)] // TEST ONLY: raw doors and crossings
#[path = "tests/dispatch_kind_transport_tests.rs"]
mod dispatch_kind_transport_tests;

/// The plane kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[allow(unsafe_code)] // TEST ONLY: raw doors and crossings
#[path = "tests/dispatch_kind_plane_tests.rs"]
mod dispatch_kind_plane_tests;

/// The store kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[allow(unsafe_code)] // TEST ONLY: raw doors and crossings
#[path = "tests/dispatch_kind_store_tests.rs"]
mod dispatch_kind_store_tests;

/// The hook kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[allow(unsafe_code)] // TEST ONLY: raw doors and crossings
#[path = "tests/dispatch_kind_hook_tests.rs"]
mod dispatch_kind_hook_tests;

/// The auth kind's answer checks, through the dispatcher's `Kind` adapter.
#[cfg(test)]
#[allow(unsafe_code)] // TEST ONLY: raw doors and crossings
#[path = "tests/dispatch_kind_auth_tests.rs"]
mod dispatch_kind_auth_tests;

/// The both-ways harness on the memory ABI (TODO ABI-b4): one door loaded LINKED and DROPPED IN
/// through the one dispatcher, one script, two transcripts compared.
#[cfg(test)]
#[allow(unsafe_code)] // TEST ONLY: raw doors and crossings
#[path = "tests/door_both_ways.rs"]
mod door_both_ways;

/// `kind: store` through both doors on the memory ABI: get/put identical, a broken store refused.
#[cfg(test)]
#[path = "tests/store_door_conformance_tests.rs"]
mod store_door_conformance_tests;

/// `kind: secret` through both doors on the memory ABI: resolve identical, a broken one refused.
#[cfg(test)]
#[allow(unsafe_code)] // TEST ONLY: raw doors and crossings
#[path = "tests/secret_door_conformance_tests.rs"]
mod secret_door_conformance_tests;

/// `kind: transport` over the REAL shipped carrier, both ways: the linked door against the pinned
/// cdylib, through the published suite's carrier script, equal folds and exact crossing counts.
#[cfg(test)]
#[path = "tests/transport_door_conformance_tests.rs"]
mod transport_door_conformance_tests;

/// A dropped-in transport door through the registry, and the refusal of a library with no door.
#[cfg(test)]
#[path = "tests/transport_door_tests.rs"]
mod transport_door_tests;

/// `kind: hook` through both doors on the memory ABI: decide identical, a broken one refused.
#[cfg(test)]
#[path = "tests/hook_door_conformance_tests.rs"]
mod hook_door_conformance_tests;
